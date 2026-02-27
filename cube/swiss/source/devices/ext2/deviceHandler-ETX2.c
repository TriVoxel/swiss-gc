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
#include <ogc/dvd.h>       /* __io_gcode DISC_INTERFACE for GCLoader/CubeODE */

#include "deviceHandler.h"
#include "gui/FrameBufferMagic.h"
#include "gui/IPLFontWrite.h"
#include "swiss.h"
#include "main.h"
#include "util.h"
#include "files.h"
#include "ata.h"

/* ------------------------------------------------------------------ */
/* MBR / partition-table helpers                                       */
/* ------------------------------------------------------------------ */

/* Standard PC MBR partition entry (little-endian, 16 bytes) */
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

#define MBR_SIGNATURE_0  0x55
#define MBR_SIGNATURE_1  0xAA
#define PART_TYPE_LINUX  0x83   /* ext2/3/4, also used for other Linux fs */

/*
 * Read MBR sector and return the LBA start of the first Linux (0x83)
 * partition.  Returns 0 on error or if none is found (caller then tries
 * mounting the whole device at sector 0).
 */
static sec_t find_ext2_partition(const DISC_INTERFACE *disc)
{
    /* Sector buffer must be 32-byte aligned for some DMA controllers */
    mbr_t *mbr = (mbr_t *)memalign(32, sizeof(mbr_t));
    if (!mbr) return 0;

    sec_t result = 0;

    if (!disc->readSectors((DISC_INTERFACE *)disc, 0, 1, mbr))
        goto done;

    /* Validate MBR signature */
    if (mbr->signature[0] != MBR_SIGNATURE_0 ||
        mbr->signature[1] != MBR_SIGNATURE_1)
        goto done;  /* No partition table — caller will try sector 0 */

    for (int i = 0; i < 4; i++) {
        if (mbr->partitions[i].type == PART_TYPE_LINUX &&
            mbr->partitions[i].lba_start != 0) {
            /* MBR is little-endian; PowerPC is big-endian — swap manually */
            uint32_t le = mbr->partitions[i].lba_start;
            result = (sec_t)(((le & 0xFF000000u) >> 24) |
                             ((le & 0x00FF0000u) >>  8) |
                             ((le & 0x0000FF00u) <<  8) |
                             ((le & 0x000000FFu) << 24));
            break;
        }
    }

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

    /* Find the Linux partition; fall back to whole-device if none found */
    sec_t start = find_ext2_partition(disc);
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
    if (file->status == 0) return NULL;
    return "Could not mount EXT2 partition "
           "(check mkfs.ext2 -b 1024 -I 128, and that the partition type is 0x83)";
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

/*
 * Test: reuse the GCLoader detection logic exactly.  deviceHandler_GCLoader_test()
 * checks DVDDriveInfo for the GCLoader magic and sets hardware-specific feature
 * flags on __device_gcloader.  We only need the bool return value here.
 */
static bool deviceHandler_EXT2_gcldr_test(void)
{
    return deviceHandler_GCLoader_test();
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

    sec_t start = find_ext2_partition(disc);
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
    .features           = FEAT_READ | FEAT_WRITE | FEAT_BOOT_DEVICE |
                          FEAT_CONFIG_DEVICE | FEAT_AUTOLOAD_DOL | FEAT_THREAD_SAFE,
    .location           = LOC_DVD_CONNECTOR,
    .initial            = &initial_ext2_gcldr,
    .test               = deviceHandler_EXT2_gcldr_test,
    .info               = deviceHandler_EXT2_info,
    .init               = deviceHandler_EXT2_gcldr_init,
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
