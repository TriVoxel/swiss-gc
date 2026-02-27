/* deviceHandler-EXT2.h
 * EXT2/3/4 filesystem device handler for Swiss-GC.
 *
 * Supports SD card adapters (Slot A/B, SD2SP2) and IDE-EXI / M.2 Loader
 * hardware via the libext2 driver from libogc2.  Each physical device
 * appears in the device list under a separate "e2*:/" devoptab path so
 * that a FAT and an EXT2 partition on the same SD card can both be
 * available simultaneously without conflict.
 *
 * Usage:
 *   The device shows up in Swiss's device list as e.g.
 *   "SD Card - Slot A (EXT2)".  Format the target partition on a PC with:
 *
 *       mkfs.ext2 -b 1024 -I 128 /dev/sdXN
 *
 *   GameCube has 24 MB RAM; 1 KB blocks keep bitmaps small.
 *   EXT3/EXT4 partitions also work (journal is not replayed on mount).
 */

#ifndef DEVICE_HANDLER_EXT2_H
#define DEVICE_HANDLER_EXT2_H

#include "../deviceHandler.h"

/* ------------------------------------------------------------------ */
/* Device interface instances — one per physical device slot           */
/* ------------------------------------------------------------------ */

/* SD card adapters (SDGecko / SD2SP1 / SD2SP2) */
extern DEVICEHANDLER_INTERFACE __device_ext2_sd_a;  /* Slot A / SD2SP1 */
extern DEVICEHANDLER_INTERFACE __device_ext2_sd_b;  /* Slot B           */
extern DEVICEHANDLER_INTERFACE __device_ext2_sd_c;  /* SD2SP2           */

/* IDE-EXI / M.2 Loader */
extern DEVICEHANDLER_INTERFACE __device_ext2_ata_a; /* Slot A           */
extern DEVICEHANDLER_INTERFACE __device_ext2_ata_b; /* Slot B           */
extern DEVICEHANDLER_INTERFACE __device_ext2_ata_c; /* M.2 / SP1        */

/* GCLoader / CubeODE (DVD bay ODE with EXT2 storage) */
extern DEVICEHANDLER_INTERFACE __device_ext2_gcldr;

/* ------------------------------------------------------------------ */
/* Handler function prototypes                                         */
/* ------------------------------------------------------------------ */

device_info *deviceHandler_EXT2_info(file_handle *file);
s32          deviceHandler_EXT2_makeDir(file_handle *dir);
s32          deviceHandler_EXT2_readDir(file_handle *ffile,
                                        file_handle **dir, u32 type);
s32          deviceHandler_EXT2_statFile(file_handle *file);
s64          deviceHandler_EXT2_seekFile(file_handle *file,
                                         s64 where, u32 type);
s32          deviceHandler_EXT2_readFile(file_handle *file,
                                         void *buffer, u32 length);
s32          deviceHandler_EXT2_writeFile(file_handle *file,
                                          const void *buffer, u32 length);
s32          deviceHandler_EXT2_closeFile(file_handle *file);
s32          deviceHandler_EXT2_deleteFile(file_handle *file);
s32          deviceHandler_EXT2_renameFile(file_handle *file, char *name);
s32          deviceHandler_EXT2_deinit(file_handle *file);
char        *deviceHandler_EXT2_status(file_handle *file);

#endif /* DEVICE_HANDLER_EXT2_H */
