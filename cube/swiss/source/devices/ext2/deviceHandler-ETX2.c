/* deviceHandler-EXT2.c
 * EXT2/3/4 filesystem device handler for Swiss-GC.
 *
 * Uses the libext2 devoptab layer from libogc2 to expose EXT2 partitions
 * as standard POSIX paths (e2sda:/, e2sdb:/, ...).  All file I/O goes
 * through the normal C library (fopen / fread / fwrite / stat / readdir)
 * which libext2 intercepts via newlib's devoptab mechanism.
 *
 * Partition detection: on init we read the MBR via the raw DISC_INTERFACE
 * and look for a Linux partition (type 0x83) in the primary partition
 * table.  The first one found is mounted.  If no partition table is
 * present (sector 0 does not carry the 0x55AA MBR signature) we attempt
 * to mount the whole device at sector 0 — useful for raw / single-
 * partition images.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <errno.h>

#include <ogc/dvd.h>
#include <ogc/machine/processor.h>
#include <sdcard/card_cmn.h>
#include <sdcard/card_io.h>
#include <sdcard/gcsd.h>
#include <ext2.h>          /* EXT2_Mount / EXT2_Unmount from libext2       */
#include <ogc/dvd.h>       /* __io_gcode, DVD_ReadAbs for GCLoader/CubeODE */

#include "deviceHandler.h"
#include "patcher.h"
#include "swiss.h"
#include "dvd.h"
#include "gui/FrameBufferMagic.h"
#include "gui/IPLFontWrite.h"
#include "swiss.h"
#include "main.h"
#include "util.h"
#include "files.h"
#include "ata.h"

/* ------------------------------------------------------------------ */
/* MBR / GPT partition-table helpers                                   */
/* ------------------------------------------------------------------ */

/* Byte-swap a 32-bit little-endian value on this big-endian CPU */
static inline uint32_t le32(uint32_t v) {
    return ((v & 0xFF000000u) >> 24) | ((v & 0x00FF0000u) >> 8) |
           ((v & 0x0000FF00u) <<  8) | ((v & 0x000000FFu) << 24);
}

/* Byte-swap a 64-bit little-endian value */
static inline uint64_t le64(uint64_t v) {
    return ((uint64_t)le32((uint32_t)(v >> 32))) |
           ((uint64_t)le32((uint32_t)(v & 0xFFFFFFFFu)) << 32);
}

/* Standard PC MBR partition entry (16 bytes, on-disk layout) */
typedef struct {
    uint8_t  status;
    uint8_t  chs_start[3];
    uint8_t  type;
    uint8_t  chs_end[3];
    uint32_t lba_start;   /* little-endian */
    uint32_t lba_size;    /* little-endian */
} __attribute__((packed)) mbr_part_entry;

typedef struct {
    uint8_t        bootstrap[446];
    mbr_part_entry partitions[4];
    uint8_t        signature[2];  /* 0x55, 0xAA */
} __attribute__((packed)) mbr_t;

/* GPT header (sector 1) — we only need a few fields */
typedef struct {
    uint8_t  signature[8];   /* "EFI PART" */
    uint8_t  revision[4];
    uint32_t header_size;
    uint32_t header_crc32;
    uint32_t reserved;
    uint64_t my_lba;
    uint64_t alternate_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    uint8_t  disk_guid[16];
    uint64_t partition_entry_lba;  /* usually 2 */
    uint32_t num_partition_entries;
    uint32_t size_of_partition_entry;  /* usually 128 */
    uint32_t partition_entry_array_crc32;
} __attribute__((packed)) gpt_header_t;

/* GPT partition entry (128 bytes on disk) */
typedef struct {
    uint8_t  type_guid[16];
    uint8_t  unique_guid[16];
    uint64_t start_lba;   /* little-endian */
    uint64_t end_lba;     /* little-endian */
    uint64_t attributes;
    uint8_t  name[72];    /* UTF-16LE, ignored */
} __attribute__((packed)) gpt_entry_t;

#define MBR_SIGNATURE_0  0x55
#define MBR_SIGNATURE_1  0xAA

/* Linux filesystem GUID: 0FC63DAF-8483-4772-8E79-3D69D8477DE4 (mixed-endian) */
static const uint8_t LINUX_FS_GUID[16] = {
    0xAF, 0x3D, 0xC6, 0x0F,  /* first 4 bytes LE */
    0x83, 0x84,              /* next 2 bytes LE */
    0x72, 0x47,              /* next 2 bytes LE */
    0x8E, 0x79,              /* next 2 bytes BE */
    0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4  /* remaining BE */
};

/*
 * Scan GPT partition table (sectors 1+) and return the LBA start of the
 * first Linux filesystem partition.  Returns 0 if none found.
 *
 * We allocate a 2-sector buffer: sector 1 = GPT header, sector 2 = first
 * partition entries sector (holds 4 entries at 128 bytes each).
 * For SD cards with a small number of partitions this is sufficient.
 */
static sec_t find_gpt_linux_partition(const DISC_INTERFACE *disc)
{
    /* Read GPT header (sector 1) + first entries sector (sector 2) */
    uint8_t *buf = (uint8_t *)memalign(32, 512 * 2);
    if (!buf) return 0;

    sec_t result = 0;

    if (!disc->readSectors((DISC_INTERFACE *)disc, 1, 2, buf))
        goto done;

    gpt_header_t *hdr = (gpt_header_t *)buf;
    if (memcmp(hdr->signature, "EFI PART", 8) != 0)
        goto done;

    uint32_t entry_size  = le32(hdr->size_of_partition_entry);
    uint32_t num_entries = le32(hdr->num_partition_entries);
    if (entry_size == 0 || entry_size > 512 || num_entries == 0)
        goto done;

    /* Entries start at sector 2 in our buffer (offset 512) */
    uint8_t *entries = buf + 512;
    uint32_t entries_in_buf = 512 / entry_size;
    if (num_entries > entries_in_buf)
        num_entries = entries_in_buf;  /* only check first sector's worth */

    for (uint32_t i = 0; i < num_entries; i++) {
        gpt_entry_t *e = (gpt_entry_t *)(entries + i * entry_size);
        /* Skip empty entries (all-zero GUID) */
        uint8_t zero[16] = {0};
        if (memcmp(e->type_guid, zero, 16) == 0)
            continue;
        if (memcmp(e->type_guid, LINUX_FS_GUID, 16) == 0) {
            result = (sec_t)le64(e->start_lba);
            break;
        }
    }

done:
    free(buf);
    return result;
}

/*
 * Check whether a partition starting at lba_start actually contains an
 * ext2/3/4 filesystem by reading the superblock magic number directly.
 * The ext2 superblock lives at byte offset 1024 from the partition start
 * (= sector lba_start+2 for 512-byte sectors); the magic 0xEF53 is at
 * offset 0x38 within the superblock (little-endian).
 */
static bool partition_has_ext2(const DISC_INTERFACE *disc, sec_t lba_start)
{
    uint8_t *buf = (uint8_t *)memalign(32, 512);
    if (!buf) return false;
    bool ok = false;
    if (disc->readSectors((DISC_INTERFACE *)disc, lba_start + 2, 1, buf))
        ok = (buf[0x38] == 0x53 && buf[0x39] == 0xEF);
    free(buf);
    return ok;
}

/*
 * Probe sector 0 for MBR or GPT and return the LBA start sector of the
 * first partition that contains a valid ext2/3/4 superblock.
 * Returns 0 if nothing is found.
 */
static sec_t find_ext2_partition(const DISC_INTERFACE *disc)
{
    mbr_t *mbr = (mbr_t *)memalign(32, sizeof(mbr_t));
    if (!mbr) return 0;

    sec_t result = 0;

    if (!disc->readSectors((DISC_INTERFACE *)disc, 0, 1, mbr)) {
        ext2_last_mount_err = -10;
        goto done;
    }

    if (mbr->signature[0] != MBR_SIGNATURE_0 ||
        mbr->signature[1] != MBR_SIGNATURE_1) {
        ext2_last_mount_err = -11;
        goto done;
    }

    /* GPT protective MBR */
    for (int i = 0; i < 4; i++) {
        if (mbr->partitions[i].type == 0xEE) {
            free(mbr);
            result = find_gpt_linux_partition(disc);
            if (result == 0)
                ext2_last_mount_err = -13;
            return result;
        }
    }

    /* Always record partition types for diagnostics */
    ext2_last_part_types =
        ((uint32_t)mbr->partitions[0].type << 24) |
        ((uint32_t)mbr->partitions[1].type << 16) |
        ((uint32_t)mbr->partitions[2].type <<  8) |
         (uint32_t)mbr->partitions[3].type;

    /* Probe each partition for the ext2 superblock magic.
     * We ignore the type byte — mkfs.ext2 does not update it, so it may
     * read as FAT32, NTFS, or anything else the user originally set. */
    for (int i = 0; i < 4; i++) {
        sec_t lba = (sec_t)le32(mbr->partitions[i].lba_start);
        if (lba == 0)
            continue;
        if (partition_has_ext2(disc, lba)) {
            result = lba;
            break;
        }
    }

    if (result == 0)
        ext2_last_mount_err = -12;

done:
    free(mbr);
    return result;
}

/* ------------------------------------------------------------------ */
/* Per-device state — stores mount status and devoptab name            */
/* ------------------------------------------------------------------ */

typedef struct {
    bool       mounted;
    const char *devname;         /* e.g. "e2sda" (no colon)    */
    char        root[16];        /* e.g. "e2sda:/"              */
    device_info info;
} ext2_state;

/* One state block per physical device */
static ext2_state state_sd_a  = { .devname = "e2sda",  .root = "e2sda:/"  };
static ext2_state state_sd_b  = { .devname = "e2sdb",  .root = "e2sdb:/"  };
static ext2_state state_sd_c  = { .devname = "e2sdc",  .root = "e2sdc:/"  };
static ext2_state state_ata_a = { .devname = "e2ataa", .root = "e2ataa:/" };
static ext2_state state_ata_b = { .devname = "e2atab", .root = "e2atab:/" };
static ext2_state state_ata_c = { .devname = "e2atac", .root = "e2atac:/" };
static ext2_state state_gcldr = { .devname = "e2gcldr", .root = "e2gcldr:/" };

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static ext2_state *state_for(file_handle *file)
{
    DEVICEHANDLER_INTERFACE *dev = file->device;
    if (dev == &__device_ext2_sd_a)  return &state_sd_a;
    if (dev == &__device_ext2_sd_b)  return &state_sd_b;
    if (dev == &__device_ext2_sd_c)  return &state_sd_c;
    if (dev == &__device_ext2_ata_a) return &state_ata_a;
    if (dev == &__device_ext2_ata_b) return &state_ata_b;
    if (dev == &__device_ext2_ata_c) return &state_ata_c;
    if (dev == &__device_ext2_gcldr) return &state_gcldr;
    return NULL;
}

/*
 * Return a pointer to the disc interface for a device.
 * SD card adapters are identified by file->name[2] == 's' or similar;
 * we look it up via the device pointer instead.
 */
static const DISC_INTERFACE *disc_for(file_handle *file)
{
    DEVICEHANDLER_INTERFACE *dev = file->device;
    if (dev == &__device_ext2_sd_a)  return &__io_gcsda;
    if (dev == &__device_ext2_sd_b)  return &__io_gcsdb;
    if (dev == &__device_ext2_sd_c)  return &__io_gcsd2;
    if (dev == &__device_ext2_ata_a) return &__io_ataa;
    if (dev == &__device_ext2_ata_b) return &__io_atab;
    if (dev == &__device_ext2_ata_c) return &__io_atac;
    if (dev == &__device_ext2_gcldr) return &__io_gcode;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* deviceHandler interface                                             */
/* ------------------------------------------------------------------ */

device_info *deviceHandler_EXT2_info(file_handle *file)
{
    ext2_state *st = state_for(file);
    if (!st || !st->mounted) return NULL;

    struct statvfs vfs;
    if (statvfs(st->root, &vfs) != 0) return NULL;

    st->info.freeSpace  = (u64)vfs.f_bfree  * vfs.f_frsize;
    st->info.totalSpace = (u64)vfs.f_blocks * vfs.f_frsize;
    st->info.metric     = true;
    return &st->info;
}

/*
 * Mount the EXT2 partition.  Called once when Swiss selects this device.
 */
s32 deviceHandler_EXT2_init(file_handle *file)
{
    ext2_state *st = state_for(file);
    if (!st) { file->status = -1; return EIO; }

    /* Tear down any previous mount on this slot */
    if (st->mounted) {
        EXT2_Unmount(st->devname);
        st->mounted = false;
    }

    const DISC_INTERFACE *disc = disc_for(file);
    if (!disc) { file->status = -1; return EIO; }

    /* Initialise hardware before probing sectors */
    if (!disc->startup((DISC_INTERFACE *)disc) ||
        !disc->isInserted((DISC_INTERFACE *)disc)) {
        file->status = -1;
        return ENODEV;
    }

    sec_t start = find_ext2_partition(disc);
    ext2_last_mount_sector = (unsigned long long)start;
    /* If scan returned 0 the diagnostic code is already in ext2_last_mount_err
     * (-10=readSectors fail, -11=bad MBR sig, -12=no 0x83, -13=no GPT GUID).
     * Do NOT call EXT2_Mount with sector 0 or it overwrites the useful code. */
    if (start == 0) {
        print_debug("EXT2 [%s]: partition scan failed err=%d\n",
                    st->devname, ext2_last_mount_err);
        file->status = -1;
        return EIO;
    }
    print_debug("EXT2 [%s]: partition start sector = %llu\n",
                st->devname, (unsigned long long)start);

    if (!EXT2_Mount(st->devname, disc, start)) {
        print_debug("EXT2 [%s]: EXT2_Mount failed\n", st->devname);
        file->status = -1;
        return EIO;
    }

    st->mounted  = true;
    file->status = 0;
    return 0;
}

s32 deviceHandler_EXT2_makeDir(file_handle *dir)
{
    return mkdir(dir->name, 0755);
}

s32 deviceHandler_EXT2_readDir(file_handle *ffile, file_handle **dir, u32 type)
{
    DIR *dp = opendir(ffile->name);
    if (!dp) return -1;

    int num_entries = 1, i = 1;
    *dir = calloc(num_entries, sizeof(file_handle));
    concat_path((*dir)[0].name, ffile->name, "..");
    (*dir)[0].fileType = IS_SPECIAL;
    (*dir)[0].device   = ffile->device;

    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;

        /* Determine type; fall back to stat() if d_type is DT_UNKNOWN */
        bool is_dir = (entry->d_type == DT_DIR);
        if (entry->d_type == DT_UNKNOWN) {
            char tmp[PATHNAME_MAX];
            struct stat st;
            concat_path(tmp, ffile->name, entry->d_name);
            if (stat(tmp, &st) == 0)
                is_dir = S_ISDIR(st.st_mode);
        }

        if (type != (u32)-1 && (is_dir ? type != IS_DIR : type != IS_FILE))
            continue;

        if (i == num_entries) {
            ++num_entries;
            *dir = reallocarray(*dir, num_entries, sizeof(file_handle));
        }
        memset(&(*dir)[i], 0, sizeof(file_handle));

        if (concat_path((*dir)[i].name, ffile->name, entry->d_name) < PATHNAME_MAX) {
            struct stat st;
            if (stat((*dir)[i].name, &st) == 0) {
                (*dir)[i].size      = (u32)st.st_size;
                (*dir)[i].fileType  = is_dir ? IS_DIR : IS_FILE;
                (*dir)[i].blockSize = (u16)st.st_blksize;
                (*dir)[i].device    = ffile->device;
                ++i;
            }
        }
    }
    closedir(dp);
    return i;
}

s32 deviceHandler_EXT2_statFile(file_handle *file)
{
    struct stat st;
    if (stat(file->name, &st) != 0) return -1;
    file->size     = (u32)st.st_size;
    file->fileType = S_ISDIR(st.st_mode) ? IS_DIR : IS_FILE;
    return 0;
}

s64 deviceHandler_EXT2_seekFile(file_handle *file, s64 where, u32 type)
{
    if      (type == DEVICE_HANDLER_SEEK_SET) file->offset = where;
    else if (type == DEVICE_HANDLER_SEEK_CUR) file->offset += where;
    else if (type == DEVICE_HANDLER_SEEK_END) file->offset = file->size + where;
    return file->offset;
}

s32 deviceHandler_EXT2_readFile(file_handle *file, void *buffer, u32 length)
{
    if (!file->fp) {
        file->fp = fopen(file->name, "rb");
        if (!file->fp) return -1;

        /* Populate size if not already known */
        if (!file->size) {
            struct stat st;
            if (stat(file->name, &st) == 0)
                file->size = (u32)st.st_size;
        }
    }

    FILE *fp = (FILE *)file->fp;
    if (fseeko(fp, (off_t)file->offset, SEEK_SET) != 0) return -1;

    size_t n = fread(buffer, 1, length, fp);
    file->offset += (s64)n;
    return (s32)n;
}

s32 deviceHandler_EXT2_writeFile(file_handle *file, const void *buffer, u32 length)
{
    if (!file->fp) {
        /* Open for writing; create if necessary, preserve existing content */
        file->fp = fopen(file->name, file->offset == 0 ? "wb" : "r+b");
        if (!file->fp) {
            /* "r+b" fails if the file doesn't exist — create it */
            file->fp = fopen(file->name, "wb");
            if (!file->fp) return -1;
        }
    }

    FILE *fp = (FILE *)file->fp;
    if (fseeko(fp, (off_t)file->offset, SEEK_SET) != 0) return -1;

    size_t n = fwrite(buffer, 1, length, fp);
    file->offset += (s64)n;

    /* Keep file->size up to date */
    if (file->offset > (s64)file->size)
        file->size = (u32)file->offset;

    return (s32)n;
}

s32 deviceHandler_EXT2_closeFile(file_handle *file)
{
    int ret = 0;
    if (file && file->fp) {
        ret = fclose((FILE *)file->fp);
        file->fp = NULL;
    }
    return ret;
}

s32 deviceHandler_EXT2_deleteFile(file_handle *file)
{
    deviceHandler_EXT2_closeFile(file);
    return unlink(file->name);
}

s32 deviceHandler_EXT2_renameFile(file_handle *file, char *name)
{
    deviceHandler_EXT2_closeFile(file);
    int ret = rename(file->name, name);
    if (ret == 0 || errno == ENOENT)
        strncpy(file->name, name, PATHNAME_MAX - 1);
    return ret;
}

s32 deviceHandler_EXT2_deinit(file_handle *file)
{
    deviceHandler_EXT2_closeFile(file);
    ext2_state *st = state_for(file);
    if (st && st->mounted) {
        EXT2_Unmount(st->devname);
        st->mounted = false;
    }
    return 0;
}

char *deviceHandler_EXT2_status(file_handle *file)
{
    static char errbuf[64];
    if (file->status == 0) return NULL;
    snprintf(errbuf, sizeof(errbuf),
             "EXT2 fail e=%d s=%llu pt=%02X%02X%02X%02X",
             ext2_last_mount_err,
             (unsigned long long)ext2_last_mount_sector,
             (unsigned)(ext2_last_part_types >> 24) & 0xFF,
             (unsigned)(ext2_last_part_types >> 16) & 0xFF,
             (unsigned)(ext2_last_part_types >>  8) & 0xFF,
             (unsigned)(ext2_last_part_types      ) & 0xFF);
    return errbuf;
}

/* ------------------------------------------------------------------ */
/* Hardware detect functions                                           */
/* ------------------------------------------------------------------ */

/*
 * Reuse the FAT handler's probe logic — the hardware is the same.
 * We declare the symbols as extern rather than duplicating the code.
 */
extern bool deviceHandler_FAT_test_sd_a(void);
extern bool deviceHandler_FAT_test_sd_b(void);
extern bool deviceHandler_FAT_test_sd_c(void);
extern bool deviceHandler_FAT_test_ata_a(void);
extern bool deviceHandler_FAT_test_ata_b(void);
extern bool deviceHandler_FAT_test_ata_c(void);

/* ------------------------------------------------------------------ */
/* Initial file handles (root directory for each device)              */
/* ------------------------------------------------------------------ */

static file_handle initial_ext2_sd_a  = { .name = "e2sda:/",  .fileType = IS_DIR, .device = &__device_ext2_sd_a  };
static file_handle initial_ext2_sd_b  = { .name = "e2sdb:/",  .fileType = IS_DIR, .device = &__device_ext2_sd_b  };
static file_handle initial_ext2_sd_c  = { .name = "e2sdc:/",  .fileType = IS_DIR, .device = &__device_ext2_sd_c  };
static file_handle initial_ext2_ata_a = { .name = "e2ataa:/", .fileType = IS_DIR, .device = &__device_ext2_ata_a };
static file_handle initial_ext2_ata_b = { .name = "e2atab:/", .fileType = IS_DIR, .device = &__device_ext2_ata_b };
static file_handle initial_ext2_ata_c = { .name = "e2atac:/", .fileType = IS_DIR, .device = &__device_ext2_ata_c };
static file_handle initial_ext2_gcldr = { .name = "e2gcldr:/", .fileType = IS_DIR, .device = &__device_ext2_gcldr };

/* ------------------------------------------------------------------ */
/* DEVICEHANDLER_INTERFACE instances                                   */
/* ------------------------------------------------------------------ */

DEVICEHANDLER_INTERFACE __device_ext2_sd_a = {
    .deviceUniqueId     = DEVICE_ID_P,
    .hwName             = "SD Card Adapter",
    .deviceName         = "SD Card - Slot A (EXT2)",
    .deviceDescription  = "SD(HC/XC) Card - Supported File System(s): EXT2, EXT3, EXT4",
    .deviceTexture      = {TEX_SDSMALL, 59, 78, 64, 80},
    .features           = FEAT_READ | FEAT_WRITE | FEAT_BOOT_DEVICE |
                          FEAT_CONFIG_DEVICE | FEAT_AUTOLOAD_DOL | FEAT_THREAD_SAFE,
    .location           = LOC_MEMCARD_SLOT_A,
    .initial            = &initial_ext2_sd_a,
    .test               = deviceHandler_FAT_test_sd_a,
    .info               = deviceHandler_EXT2_info,
    .init               = deviceHandler_EXT2_init,
    .makeDir            = deviceHandler_EXT2_makeDir,
    .readDir            = deviceHandler_EXT2_readDir,
    .statFile           = deviceHandler_EXT2_statFile,
    .seekFile           = deviceHandler_EXT2_seekFile,
    .readFile           = deviceHandler_EXT2_readFile,
    .writeFile          = deviceHandler_EXT2_writeFile,
    .closeFile          = deviceHandler_EXT2_closeFile,
    .deleteFile         = deviceHandler_EXT2_deleteFile,
    .renameFile         = deviceHandler_EXT2_renameFile,
    .hideFile           = NULL,   /* EXT2 has no hidden-file attribute */
    .setupFile          = NULL,   /* Direct disc emulation not supported */
    .deinit             = deviceHandler_EXT2_deinit,
    .emulated           = NULL,
    .status             = deviceHandler_EXT2_status,
};

DEVICEHANDLER_INTERFACE __device_ext2_sd_b = {
    .deviceUniqueId     = DEVICE_ID_Q,
    .hwName             = "SD Card Adapter",
    .deviceName         = "SD Card - Slot B (EXT2)",
    .deviceDescription  = "SD(HC/XC) Card - Supported File System(s): EXT2, EXT3, EXT4",
    .deviceTexture      = {TEX_SDSMALL, 59, 78, 64, 80},
    .features           = FEAT_READ | FEAT_WRITE | FEAT_BOOT_DEVICE |
                          FEAT_CONFIG_DEVICE | FEAT_AUTOLOAD_DOL | FEAT_THREAD_SAFE,
    .location           = LOC_MEMCARD_SLOT_B,
    .initial            = &initial_ext2_sd_b,
    .test               = deviceHandler_FAT_test_sd_b,
    .info               = deviceHandler_EXT2_info,
    .init               = deviceHandler_EXT2_init,
    .makeDir            = deviceHandler_EXT2_makeDir,
    .readDir            = deviceHandler_EXT2_readDir,
    .statFile           = deviceHandler_EXT2_statFile,
    .seekFile           = deviceHandler_EXT2_seekFile,
    .readFile           = deviceHandler_EXT2_readFile,
    .writeFile          = deviceHandler_EXT2_writeFile,
    .closeFile          = deviceHandler_EXT2_closeFile,
    .deleteFile         = deviceHandler_EXT2_deleteFile,
    .renameFile         = deviceHandler_EXT2_renameFile,
    .hideFile           = NULL,
    .setupFile          = NULL,
    .deinit             = deviceHandler_EXT2_deinit,
    .emulated           = NULL,
    .status             = deviceHandler_EXT2_status,
};

DEVICEHANDLER_INTERFACE __device_ext2_sd_c = {
    .deviceUniqueId     = DEVICE_ID_R,
    .hwName             = "SD Card Adapter",
    .deviceName         = "SD Card - SD2SP2 (EXT2)",
    .deviceDescription  = "SD(HC/XC) Card - Supported File System(s): EXT2, EXT3, EXT4",
    .deviceTexture      = {TEX_SDSMALL, 59, 78, 64, 80},
    .features           = FEAT_READ | FEAT_WRITE | FEAT_BOOT_DEVICE |
                          FEAT_CONFIG_DEVICE | FEAT_AUTOLOAD_DOL | FEAT_THREAD_SAFE,
    .location           = LOC_SERIAL_PORT_2,
    .initial            = &initial_ext2_sd_c,
    .test               = deviceHandler_FAT_test_sd_c,
    .info               = deviceHandler_EXT2_info,
    .init               = deviceHandler_EXT2_init,
    .makeDir            = deviceHandler_EXT2_makeDir,
    .readDir            = deviceHandler_EXT2_readDir,
    .statFile           = deviceHandler_EXT2_statFile,
    .seekFile           = deviceHandler_EXT2_seekFile,
    .readFile           = deviceHandler_EXT2_readFile,
    .writeFile          = deviceHandler_EXT2_writeFile,
    .closeFile          = deviceHandler_EXT2_closeFile,
    .deleteFile         = deviceHandler_EXT2_deleteFile,
    .renameFile         = deviceHandler_EXT2_renameFile,
    .hideFile           = NULL,
    .setupFile          = NULL,
    .deinit             = deviceHandler_EXT2_deinit,
    .emulated           = NULL,
    .status             = deviceHandler_EXT2_status,
};

DEVICEHANDLER_INTERFACE __device_ext2_ata_a = {
    .deviceUniqueId     = DEVICE_ID_S,
    .hwName             = "IDE-EXI",
    .deviceName         = "IDE-EXI - Slot A (EXT2)",
    .deviceDescription  = "IDE/PATA HDD - Supported File System(s): EXT2, EXT3, EXT4",
    .deviceTexture      = {TEX_HDD, 104, 73, 104, 76},
    .features           = FEAT_READ | FEAT_WRITE | FEAT_BOOT_DEVICE |
                          FEAT_CONFIG_DEVICE | FEAT_AUTOLOAD_DOL | FEAT_THREAD_SAFE,
    .location           = LOC_MEMCARD_SLOT_A,
    .initial            = &initial_ext2_ata_a,
    .test               = deviceHandler_FAT_test_ata_a,
    .info               = deviceHandler_EXT2_info,
    .init               = deviceHandler_EXT2_init,
    .makeDir            = deviceHandler_EXT2_makeDir,
    .readDir            = deviceHandler_EXT2_readDir,
    .statFile           = deviceHandler_EXT2_statFile,
    .seekFile           = deviceHandler_EXT2_seekFile,
    .readFile           = deviceHandler_EXT2_readFile,
    .writeFile          = deviceHandler_EXT2_writeFile,
    .closeFile          = deviceHandler_EXT2_closeFile,
    .deleteFile         = deviceHandler_EXT2_deleteFile,
    .renameFile         = deviceHandler_EXT2_renameFile,
    .hideFile           = NULL,
    .setupFile          = NULL,
    .deinit             = deviceHandler_EXT2_deinit,
    .emulated           = NULL,
    .status             = deviceHandler_EXT2_status,
};

DEVICEHANDLER_INTERFACE __device_ext2_ata_b = {
    .deviceUniqueId     = DEVICE_ID_T,
    .hwName             = "IDE-EXI",
    .deviceName         = "IDE-EXI - Slot B (EXT2)",
    .deviceDescription  = "IDE/PATA HDD - Supported File System(s): EXT2, EXT3, EXT4",
    .deviceTexture      = {TEX_HDD, 104, 73, 104, 76},
    .features           = FEAT_READ | FEAT_WRITE | FEAT_BOOT_DEVICE |
                          FEAT_CONFIG_DEVICE | FEAT_AUTOLOAD_DOL | FEAT_THREAD_SAFE,
    .location           = LOC_MEMCARD_SLOT_B,
    .initial            = &initial_ext2_ata_b,
    .test               = deviceHandler_FAT_test_ata_b,
    .info               = deviceHandler_EXT2_info,
    .init               = deviceHandler_EXT2_init,
    .makeDir            = deviceHandler_EXT2_makeDir,
    .readDir            = deviceHandler_EXT2_readDir,
    .statFile           = deviceHandler_EXT2_statFile,
    .seekFile           = deviceHandler_EXT2_seekFile,
    .readFile           = deviceHandler_EXT2_readFile,
    .writeFile          = deviceHandler_EXT2_writeFile,
    .closeFile          = deviceHandler_EXT2_closeFile,
    .deleteFile         = deviceHandler_EXT2_deleteFile,
    .renameFile         = deviceHandler_EXT2_renameFile,
    .hideFile           = NULL,
    .setupFile          = NULL,
    .deinit             = deviceHandler_EXT2_deinit,
    .emulated           = NULL,
    .status             = deviceHandler_EXT2_status,
};

DEVICEHANDLER_INTERFACE __device_ext2_ata_c = {
    .deviceUniqueId     = DEVICE_ID_U,
    .hwName             = "M.2 Loader",
    .deviceName         = "M.2 Loader (EXT2)",
    .deviceDescription  = "M.2 SATA SSD - Supported File System(s): EXT2, EXT3, EXT4",
    .deviceTexture      = {TEX_M2LOADER, 112, 54, 112, 56},
    .features           = FEAT_READ | FEAT_WRITE | FEAT_BOOT_DEVICE |
                          FEAT_CONFIG_DEVICE | FEAT_AUTOLOAD_DOL | FEAT_THREAD_SAFE,
    .location           = LOC_SERIAL_PORT_1,
    .initial            = &initial_ext2_ata_c,
    .test               = deviceHandler_FAT_test_ata_c,
    .info               = deviceHandler_EXT2_info,
    .init               = deviceHandler_EXT2_init,
    .makeDir            = deviceHandler_EXT2_makeDir,
    .readDir            = deviceHandler_EXT2_readDir,
    .statFile           = deviceHandler_EXT2_statFile,
    .seekFile           = deviceHandler_EXT2_seekFile,
    .readFile           = deviceHandler_EXT2_readFile,
    .writeFile          = deviceHandler_EXT2_writeFile,
    .closeFile          = deviceHandler_EXT2_closeFile,
    .deleteFile         = deviceHandler_EXT2_deleteFile,
    .renameFile         = deviceHandler_EXT2_renameFile,
    .hideFile           = NULL,
    .setupFile          = NULL,
    .deinit             = deviceHandler_EXT2_deinit,
    .emulated           = NULL,
    .status             = deviceHandler_EXT2_status,
};

/* ------------------------------------------------------------------ */
/* EXT2 on GCLoader / CubeODE (DVD bay ODE)                           */
/* ------------------------------------------------------------------ */

/* Forward declarations from gcloader support code */
extern int gcloaderWriteFrags(u32 discNum, file_frag *fragList, u32 totFrags);
extern int gcloaderWriteDiscNum(u32 discNum);

/*
 * Test: reuse the GCLoader detection logic exactly.
 */
static bool deviceHandler_EXT2_gcldr_test(void)
{
    return deviceHandler_GCLoader_test();
}

/*
 * setupFile: build the EXT2 block fragment list and write it to GCLoader
 * hardware registers so it can stream the disc image as DVD data.
 *
 * This mirrors gcloaderSetupFile() in deviceHandler-gcloader.c but uses
 * getFragments() which now has an EXT2-aware branch that calls
 * EXT2_GetFragments() from libext2 to walk the inode block map.
 */
static s32 deviceHandler_EXT2_gcldr_setupFile(file_handle *file, file_handle *file2,
                                               ExecutableFile *filesToPatch, int numToPatch)
{
    file_frag *disc1FragList = NULL, *disc2FragList = NULL;
    u32 disc1Frags = 0, disc2Frags = 0;

    /* Build disc 1 fragment list from EXT2 block map */
    if (!getFragments(DEVICE_CUR, file, &disc1FragList, &disc1Frags, 0, 0, UINT32_MAX))
        goto fail;

    /* Build disc 2 fragment list if present */
    if (file2) {
        if (devices[DEVICE_CUR]->quirks & QUIRK_GCLOADER_NO_DISC_2)
            goto fail;

        if (!getFragments(DEVICE_CUR, file2, &disc2FragList, &disc2Frags, 1, 0, UINT32_MAX))
            goto fail;

        if (devices[DEVICE_PATCHES] == devices[DEVICE_CUR]) {
            file2->fileBase = (u32)installPatch2(disc2FragList, (disc2Frags + 1) * sizeof(file_frag)) | ((u64)disc2Frags << 32);
            file->fileBase  = (u32)installPatch2(disc1FragList, (disc1Frags + 1) * sizeof(file_frag)) | ((u64)disc1Frags << 32);
        }
    }

    /* Write fragment lists to GCLoader hardware */
    if (gcloaderWriteFrags(1, disc2FragList, disc2Frags))
        goto fail;

    if (gcloaderWriteFrags(0, disc1FragList, disc1Frags))
        goto fail;

    if (gcloaderWriteDiscNum(0))
        goto fail;

    free(disc2FragList);
    free(disc1FragList);

    if (file2 && file2->meta)
        memcpy(VAR_DISC_2_ID, &file2->meta->diskId, sizeof(VAR_DISC_2_ID));
    memcpy(VAR_DISC_1_ID, &GCMDisk, sizeof(VAR_DISC_1_ID));

    file->status = STATUS_MAPPED;
    return 1;

fail:
    free(disc2FragList);
    free(disc1FragList);
    return 0;
}

/*
 * readFile: once a game is STATUS_MAPPED, reads go through DVD_ReadAbs
 * (GCLoader streams from its fragment map).  Otherwise fall back to
 * normal EXT2 file I/O (e.g. reading DOLs or config files).
 */
static s32 deviceHandler_EXT2_gcldr_readFile(file_handle *file, void *buffer, u32 length)
{
    if (file->status == STATUS_MAPPED) {
        s32 bytes_read = DVD_ReadAbs((dvdcmdblk *)file->other, buffer, length, file->offset);
        if (bytes_read > 0) file->offset += bytes_read;
        return bytes_read;
    }
    return deviceHandler_EXT2_readFile(file, buffer, length);
}

/*
 * Init: same as other EXT2 devices -- scan the MBR for a Linux (0x83)
 * partition and mount it.  The underlying block device is __io_gcode,
 * which libogc2 provides as the raw GCLoader / GCode DVD-connector
 * block interface (512-byte sectors, same as any other DISC_INTERFACE).
 */
static s32 deviceHandler_EXT2_gcldr_init(file_handle *file)
{
    ext2_state *st = state_for(file);
    if (!st) { file->status = -1; return EIO; }

    if (st->mounted) {
        EXT2_Unmount(st->devname);
        st->mounted = false;
    }

    const DISC_INTERFACE *disc = &__io_gcode;

    /* Do NOT call disc->startup() here. __io_gcode is shared with the
     * GCLoader FAT layer which has already initialised the DVD interface.
     * Calling startup() again issues DVD_Reset() which disrupts it and
     * causes subsequent readSectors() calls to fail silently. */
    if (!disc->isInserted((DISC_INTERFACE *)disc)) {
        file->status = -1;
        return ENODEV;
    }

    sec_t start = find_ext2_partition(disc);
    ext2_last_mount_sector = (unsigned long long)start;
    if (start == 0) {
        print_debug("EXT2 [%s]: partition scan failed err=%d\n",
                    st->devname, ext2_last_mount_err);
        file->status = -1;
        return EIO;
    }
    print_debug("EXT2 [%s]: partition start sector = %llu\n",
                st->devname, (unsigned long long)start);

    if (!EXT2_Mount(st->devname, disc, start)) {
        print_debug("EXT2 [%s]: EXT2_Mount failed\n", st->devname);
        file->status = -1;
        return EIO;
    }

    st->mounted  = true;
    file->status = 0;
    return 0;
}

DEVICEHANDLER_INTERFACE __device_ext2_gcldr = {
    .deviceUniqueId     = DEVICE_ID_V,
    .hwName             = "GC Loader",
    .deviceName         = "GC Loader (EXT2)",
    .deviceDescription  = "GC Loader / CubeODE - Supported File System(s): EXT2, EXT3, EXT4",
    .deviceTexture      = {TEX_GCLOADER, 115, 72, 120, 76},
    .features           = FEAT_READ | FEAT_WRITE | FEAT_BOOT_GCM | FEAT_BOOT_DEVICE |
                          FEAT_CONFIG_DEVICE | FEAT_AUTOLOAD_DOL | FEAT_THREAD_SAFE |
                          FEAT_HYPERVISOR,
    .emulable           = EMU_READ,
    .location           = LOC_DVD_CONNECTOR,
    .initial            = &initial_ext2_gcldr,
    .test               = deviceHandler_EXT2_gcldr_test,
    .info               = deviceHandler_EXT2_info,
    .init               = deviceHandler_EXT2_gcldr_init,
    .makeDir            = deviceHandler_EXT2_makeDir,
    .readDir            = deviceHandler_EXT2_readDir,
    .statFile           = deviceHandler_EXT2_statFile,
    .seekFile           = deviceHandler_EXT2_seekFile,
    .readFile           = deviceHandler_EXT2_gcldr_readFile,
    .writeFile          = deviceHandler_EXT2_writeFile,
    .closeFile          = deviceHandler_EXT2_closeFile,
    .deleteFile         = deviceHandler_EXT2_deleteFile,
    .renameFile         = deviceHandler_EXT2_renameFile,
    .hideFile           = NULL,
    .setupFile          = deviceHandler_EXT2_gcldr_setupFile,
    .deinit             = deviceHandler_EXT2_deinit,
    .emulated           = deviceHandler_GCLoader_emulated,
    .status             = deviceHandler_EXT2_status,
};
