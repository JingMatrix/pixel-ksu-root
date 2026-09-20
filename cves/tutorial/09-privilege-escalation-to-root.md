# From Kernel Write Primitive to Root

An arbitrary write into kernel memory is not privilege. It becomes privilege only when it lands on the exact bytes the kernel consults when it decides whether a syscall may proceed. On a modern Android kernel there are at least four such decisions, taken by four independent mechanisms, and a chain that satisfies three of them produces a process that looks rooted in `id` output and still cannot open the file it was written to open. Understanding which bytes matter — and how to derive their addresses on a device you cannot rebuild — is the whole of the terminal step.

Two of those decisions are taken against one object and therefore form a single gate. The first gate is `struct cred`, which holds both the discretionary identity (uid/gid) and the capability sets, checked independently of uid. The second is the mandatory access control label, which on Android lives in the LSM blob hanging off that same `struct cred` and is evaluated against a policy that additionally has a global enforcing switch. The third is the seccomp filter attached to the task, evaluated before any of the others and indifferent to privilege.

## The object that decides

Every task points at its credentials through two `const` pointers in `task_struct`, `real_cred` and `cred`, described in the kernel's own [credentials documentation](https://www.kernel.org/doc/html/latest/security/credentials.html): the first is the objective identity others see when they act on the task, the second is the subjective identity the task acts with. They are usually the same pointer. The object itself, in [Linux 6.1's include/linux/cred.h](https://github.com/torvalds/linux/blob/v6.1/include/linux/cred.h), begins with a refcount and then eight 32-bit identity words in a fixed order — `uid`, `gid`, `suid`, `sgid`, `euid`, `egid`, `fsuid`, `fsgid` — followed by `securebits`, then five capability sets (`cap_inheritable`, `cap_permitted`, `cap_effective`, `cap_bset`, `cap_ambient`), then optional keyring pointers, then the LSM pointer `security`, and after it `user`, `user_ns`, `ucounts` and `group_info`.

Three consequences follow.

First, on a build that does not randomize structure layout the eight identity words are contiguous, so a single 32-byte write of zeroes converts a process to uid 0 in every sense the VFS and the signal code care about. That contiguity is a property of the build, not of the type: `struct cred` is declared `__randomize_layout`, and under `CONFIG_RANDSTRUCT` the premise does not hold at all.

Second, uid 0 is not by itself authority. Capability checks read `cap_effective` directly; a task with uid 0 and an empty effective set fails every `capable()` call, so it is the capability fill — not the uid — that makes `capable(CAP_SYS_ADMIN)` succeed and `mount` proceed. The first gate is therefore two decisions rather than one: the identity words and the capability sets are consulted by different code, and satisfying one says nothing about the other. Securebits do something different. [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) documents the five sets alongside the `SECBIT_NOROOT`, `SECBIT_NO_SETUID_FIXUP`, `SECBIT_KEEP_CAPS` and `SECBIT_NO_CAP_AMBIENT_RAISE` flags, and those flags govern the capability transitions the kernel performs on your behalf at `execve` and at `setuid` — the uid-0 shortcuts in [`cap_bprm_creds_from_file()` and `cap_emulate_setxuid()` in security/commoncap.c](https://github.com/torvalds/linux/blob/v6.1/security/commoncap.c), both of which are guarded by `issecure()` tests. Zeroing `securebits` guarantees none of those restrictions is in force, so the shortcuts still apply the next time the process execs a helper or drops to another uid. Nothing in the immediate process needs it, which is why it is easy to omit; it belongs in the same write as the identity edit because the `issecure()` tests those shortcuts are guarded by are consulted at the next `execve` or `setuid`, not at the moment the credential is patched.

Third, both uid 0 and the capability sets are relative to `cred->user_ns`. `capable()` is literally `ns_capable(&init_user_ns, cap)` in [kernel/capability.c](https://github.com/torvalds/linux/blob/v6.1/kernel/capability.c), so a chain that begins inside a user namespace can produce a perfect-looking `/proc/self/status` — uid 0, `CapEff` all ones — and still fail `may_init_module()` with `EPERM`, because the capability is held in the wrong namespace. If `cred->user_ns` is not `&init_user_ns`, it has to be made so, which is a fourth pointer write. `cat /proc/self/uid_map` and `ls -l /proc/self/ns/user` answer which namespace you are in before any write goes out: the initial namespace maps `0 0 4294967295`. Note also that `group_info` sits past `security` and is untouched by the identity write, so supplementary groups survive it intact — the same field KernelSU's App Profile manipulates when it removes `inet` from a granted root process.

The older textbook answer, `commit_creds(prepare_kernel_cred(NULL))`, is a call primitive rather than a write primitive, and it has been deliberately dismantled. Commit [5a17f040fa33, "cred: Do not default to init_cred in prepare_kernel_cred()"](https://github.com/torvalds/linux/commit/5a17f040fa33), merged for 6.2, makes a NULL argument return NULL with a `WARN_ON_ONCE`, explicitly because the NULL shorthand was a convenient ROP target. On a kernel with that patch, and on any kernel where control-flow integrity makes a two-call ROP chain expensive, the practical route is a data-only edit of the `cred` object.

### Deriving the layout

Do not copy offsets out of a tutorial. The general procedure for recovering types and symbols from a device you cannot rebuild is in [07-read-write-primitives.md](07-read-write-primitives.md), "Aiming a primitive needs the target's own offsets", and [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md), "Recovering structure layout and symbols without rebuilding the kernel": pull the target's own BTF with `adb pull /sys/kernel/btf/vmlinux` and run the host-side tools against it, or reconstruct a symbolized ELF from the shipped image when BTF is unavailable. What is specific to this section is which fields to look for and which configuration options move them.

Four things reshape `struct cred` between builds:

1. `CONFIG_DEBUG_CREDENTIALS` inserts three fields (`subscribers`, `put_addr`, `magic`) ahead of `uid`.
2. `CONFIG_KEYS` inserts `jit_keyring` and four `struct key *` pointers ahead of `security`.
3. `usage` became `atomic_long_t`, 4 bytes to 8, which shifts every field after it — including the entire identity block.
4. The capability type changed representation in 6.3, from `__u32 cap[2]` to `struct { u64 val; }`, in commit [f122a08b197d, "capability: just use a 'u64' instead of a 'u32[2]' array"](https://github.com/torvalds/linux/commit/f122a08b197d076ccf136c73fae0146875812a88). Both are 8 bytes wide, so this one does not move anything; it changes how the value is composed, and it dates any code that builds a capability set out of two 32-bit halves.

On top of those, `__randomize_layout` means a `CONFIG_RANDSTRUCT` build has a per-build order that no declaration and no other device can tell you.

The tool that answers all of this in one line is pahole against the target's own BTF. On a recent BTF it floods stderr with `WARNING: BTF_KIND_DECL_TAG for unknown BTF id`, so redirect it:

```
adb pull /sys/kernel/btf/vmlinux ./target-btf
pahole -F btf -C cred ./target-btf 2>/dev/null
```

Here is the answer for an arm64 GKI 6.1 build, trimmed to the fields that matter:

```
struct cred {
        atomic_t                   usage;                /*     0     4 */
        kuid_t                     uid;                  /*     4     4 */
        kgid_t                     gid;                  /*     8     4 */
        ...
        unsigned int               securebits;           /*    36     4 */
        kernel_cap_t               cap_inheritable;      /*    40     8 */
        ...
        void *                     security;             /*   120     8 */
```

And here is the same struct on a 7.1 kernel:

```
struct cred {
        atomic_long_t              usage;                /*     0     8 */
        kuid_t                     uid;                  /*     8     4 */
        kgid_t                     gid;                  /*    12     4 */
        ...
        unsigned int               securebits;           /*    40     4 */
        /* XXX 4 bytes hole, try to pack */
        kernel_cap_t               cap_inheritable;      /*    48     8 */
        ...
        struct key *               request_key_auth;     /*   120     8 */
        void *                     security;             /*   128     8 */
        struct user_struct *       user;                 /*   136     8 */
        struct user_namespace *    user_ns;              /*   144     8 */
        struct ucounts *           ucounts;              /*   152     8 */
        struct group_info *        group_info;           /*   160     8 */
```

Every offset in the first excerpt except `usage`'s is wrong for the second, and the failures are instructive rather than merely off-by-something. The 32-byte identity zeroing aimed at `cred + 4` clears the upper half of `usage` and then `uid` through `fsuid`, leaving `fsgid` intact. The five capability words written at `cred + 40` overwrite `securebits`, four bytes of padding and only four of the five sets, leaving `cap_ambient` at offset 80 untouched. Worst, the LSM pointer read from `cred + 120` returns `request_key_auth`, so the SELinux SID write described below is dispatched through a keyring pointer into whatever happens to follow a `struct key`.

Run the same command for `task_struct` (for `cred`, `real_cred`, `comm`, `tasks`, `thread_node`, `tgid`, `seccomp`, `atomic_flags`), for `task_security_struct` (the SID fields) and for `lsm_blob_sizes` (`lbs_cred`). The legitimate conclusion from any of these outputs is narrow but exact: on this build, and only this build, these are the byte offsets.

## Finding the cred that matters

The offset of `cred` inside `task_struct` is useless without the address of your own `task_struct`. On arm64 the kernel keeps `current` in `SP_EL0`, which userspace cannot read, so the address has to come from somewhere else. Three routes recur:

1. Leak it from an object you already control. Many kernel objects store a back-pointer to the creating or owning task; the CVE-2023-20938 binder exploit walked `binder_node -> binder_proc -> tsk -> cred` for exactly this reason, as described in Google's [analysis of that bug](https://androidoffsec.withgoogle.com/posts/attacking-android-binder-analysis-and-exploitation-of-cve-2023-20938/).
2. Walk the task list. `init_task` is a static symbol at a fixed offset from the kernel text base, and thread-group leaders hang off its `tasks` list head — that list is what `for_each_process()` iterates, and it contains leaders only. Non-leader threads are not on it; they are on their `signal->thread_head` list via `task_struct.thread_node`. The identifier to match on is therefore `tgid`, the value `getpid()` returns, and not `pid` and not `comm`: both `comm` and `prctl(PR_SET_NAME)` are per-thread, so an exploit running on a non-leader thread that names itself and then walks `tasks` will never find the record it named. Two rules keep the walk from hanging or panicking the kernel. It must be bounded by a node count rather than by arriving back at the anchor, because a loop whose only exit is `init_task` does not terminate at all if one `tasks` pointer is stale, or is read in the window where a task is being unlinked and the list is momentarily inconsistent. And every pointer read out of the list must be range-checked against the kernel's address range before it is followed, because following it means issuing a read through the primitive at whatever value came back, and a garbage address faults in kernel context rather than returning an error to you. [`cves/lib/root/taskscan.h`](../lib/root/taskscan.h) and its implementation are a worked version of both, with `lib_find_task_by_tgid()` as the entry point.
3. Scan for the marker directly. Set an improbable `comm` string, search kernel memory for it with a read primitive, then subtract the BTF-derived delta between `comm` and `cred`. This one does find the thread that set the name, which is its advantage over route 2.

Routes 2 and 3 both depend on defeating KASLR first, which is the subject of [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md).

Finding the leader is usually enough, because `cred` is shared: `task_struct.cred` on the leader points at the same object every thread of the process uses, so one identity edit elevates all of them. The seccomp state described later is not shared, and finding the leader does not give you the thread you are running on. Getting from leader to thread means following `signal` to `signal_struct.thread_head` and walking `thread_node`. The offsets for all of this come from the same dump:

```
pahole -F btf -C task_struct ./target-btf 2>/dev/null | grep -E 'tasks|tgid;|comm\[|thread_node|signal;|cred;'
```

### Verifying the cred before writing it

The identity write is irreversible and lands wherever you point it, so the candidate has to be confirmed before a byte goes out, not after. Two independent properties are cheap to check through the read half of the primitive:

- Read `candidate_cred + CRED_UID_OFF` and require it to equal `getuid()`. A `cred` that does not currently hold your pre-exploit uid is not your `cred`.
- Read `candidate_task + TASK_COMM_OFF` and require it to equal the improbable string you set with `prctl(PR_SET_NAME)`. A 16-byte string you chose is not going to appear on an unrelated task.

Both must hold. The first alone matches every other process running as the same uid; the second alone matches a task you have identified but says nothing about which `cred` its pointer leads to. Afterwards, `/proc/self/status` is the post-write oracle, because its `Uid` and `CapEff` lines are rendered from the live credential rather than from your copy of it. The general form of this rule — never let a write be the verification step — is in [10-survivability-and-measurement.md](10-survivability-and-measurement.md). [`cves/lib/root/cred.c`](../lib/root/cred.c) is the worked example: `lib_patch_cred_identity()` writes the five capability words and then reads all five back, failing the whole patch if any one differs.

### Editing the object versus swapping the pointer

Threads share a `struct cred`. Patching the object in place elevates every thread of the process, which is usually what you want, but the write is also visible to code running concurrently on another CPU.

Patching the pointer instead — redirecting `task->cred` and `task->real_cred` at `init_cred`, a static object whose address follows from the text base — is two 8-byte writes rather than a dozen. What it skips is the two `get_cred()` calls a legitimate credential change would have performed, and that is a liability rather than a saving. `init_cred` is declared with `.usage = ATOMIC_INIT(4)` in [kernel/cred.c](https://github.com/torvalds/linux/blob/v6.1/kernel/cred.c), and `exit_creds()` in the same file issues `put_cred()` on both `real_cred` and `cred`. Every task that exits holding the swapped pointers therefore decrements `init_cred.usage` by two against no matching increment; a handful of runs drives it to zero and the kernel frees a static object. The mitigation is to inflate `init_cred.usage` with a write of its own before the swap, or to arrange that the swapped process never exits. The failure mode is worth naming because it is easy to miss: the panic arrives during credential teardown, after the run that appeared to succeed, not at the moment of the write.

The swap also changes your SELinux label. `init_cred`'s LSM blob was initialized by `cred_init_security()` to `SECINITSID_KERNEL`, which renders as `u:r:kernel:s0`, so a process that adopts `init_cred` adopts that SID as well — a bonus or a surprise depending on what the next section leads you to expect. `cat /proc/self/attr/current` after the swap says which domain you actually landed in.

The in-place edit is easier to verify, because the bytes can be read back through the same primitive and compared against what was written.

Older exploits reached the same place along a cheaper road, but the road led to a primitive rather than to root. The Project Zero writeup of [Bad Binder (CVE-2019-2215)](https://projectzero.google/2019/11/bad-binder-android-in-wild-exploit.html) — a `binder_thread` use-after-free reachable through epoll, exploited in the wild before disclosure — overwrote `addr_limit` in `thread_info` with `0xFFFFFFFFFFFFFFFE`, after which ordinary `read`/`write` on a pipe reached all of kernel memory. The credential edit still followed; what one write bought was arbitrary kernel read/write, not privilege. That technique is unavailable on any arm64 kernel from v5.11 onward, which removed the per-task address limit in commit [3d2403fd10a1, "arm64: uaccess: remove set_fs()"](https://github.com/torvalds/linux/commit/3d2403fd10a1dbb359b154af41ffed9f2a7520e8); the broader cleanup across architectures is the one [LWN covered in 2020](https://lwn.net/Articles/832121/). Its removal raised the cost of building the primitive, not the cost of the escalation that consumes it, and primitive construction belongs to [07-read-write-primitives.md](07-read-write-primitives.md).

## The second gate: SELinux

Android runs SELinux in enforcing mode system-wide, and its documentation is explicit that the MAC layer constrains privileged processes too: "software must typically run as the root user account to write to raw block devices... However, SELinux can be used to label these devices so the process assigned the root privilege can write to only those specified in the associated policy" ([Android SELinux concepts](https://source.android.com/docs/security/features/selinux/concepts)). This is why *confined root* and *unconfined root* are different outcomes. A uid-0 process still labelled `u:r:untrusted_app:s0` cannot mount, cannot ptrace outside its domain, cannot write most of `/sys`, and cannot execute a file it just dropped in `/data`.

The per-process label lives in the LSM blob attached to the credential. [security/selinux/include/objsec.h](https://github.com/torvalds/linux/blob/v6.1/security/selinux/include/objsec.h) defines it:

```c
struct task_security_struct {
	u32 osid;		/* SID prior to last execve */
	u32 sid;		/* current SID */
	u32 exec_sid;		/* exec SID */
	u32 create_sid;		/* fscreate SID */
	u32 keycreate_sid;	/* keycreate SID */
	u32 sockcreate_sid;	/* fscreate SID */
} __randomize_layout;
```

The closing annotation is the part that matters for what follows. The SID patch described two paragraphs below puts two words at fixed positions inside that blob, and a declaration marked `__randomize_layout` does not promise that `osid` and `sid` are the first two words on the build in front of you. Take their positions from `pahole -F btf -C task_security_struct` on the target's own BTF, for the same reason given below for `selinux_state`.

The blob is reached as `cred->security + selinux_blob_sizes.lbs_cred`. That trailing term is easy to get wrong: `lbs_cred` is initialized to `sizeof(struct task_security_struct)`, but [`lsm_set_blob_size()` in security/security.c](https://github.com/torvalds/linux/blob/v6.1/security/security.c) rewrites each module's requested size into that module's *offset* within the shared blob during LSM initialization. Where SELinux is the only blob-using LSM the value ends up zero; on a stacked configuration it does not. Read the global rather than assuming, which means two derivations: `pahole -F btf -C lsm_blob_sizes ./target-btf 2>/dev/null` gives `lbs_cred`'s offset inside the structure (it is the first member, offset 0, on current kernels), and the symbol lookup below gives the structure's address. The read through the primitive is then one 32-bit load at `selinux_blob_sizes + 0`.

Patching `sid` and `osid` to the SID of an unconfined domain is the surgical option. SIDs are not compile-time constants — they are allocated when policy is loaded, so the number differs per boot and per policy. The robust way to obtain one is to copy it: use the same task walk that found your own record to find a task already running in the domain you want, read its blob, and write those two words into yours. Textual contexts are visible without any kernel read (`cat /proc/1/attr/current`, `id -Z`, `ps -AZ`), so the target domain can be chosen before any primitive exists; only the numeric SID has to be lifted from memory.

The blunt option is the global switch. [security/selinux/include/security.h](https://github.com/torvalds/linux/blob/v6.1/security/selinux/include/security.h) declares `struct selinux_state selinux_state;`, near the head of which sits `bool enforcing`, guarded by `#ifdef CONFIG_SECURITY_SELINUX_DEVELOP` and read through `enforcing_enabled()`. In 6.1 it is not the first member: a `bool disabled` under `CONFIG_SECURITY_SELINUX_DISABLE` precedes it, and the whole structure is declared `__randomize_layout`. Three properties make it a good target anyway. It is a plain global, so its address is a fixed offset from the text base and needs no object-graph leak. It is one byte. And it is consulted at denial time, not at cache-fill time — [`avc_denied()` in security/selinux/avc.c](https://github.com/torvalds/linux/blob/v6.1/security/selinux/avc.c) checks `enforcing_enabled(state)` before returning `-EACCES` — so flipping it takes effect immediately with no AVC flush.

That same function then calls `avc_update_node(..., AVC_CALLBACK_GRANT, ...)` before returning 0, which means denials that occur while permissive are written back into the AVC as grants. Those cached grants outlive the flip: restoring `enforcing` re-enables the check for tuples that are decided afresh, but a node already in the cache is consulted before the check is reached. They are bounded by two things, LRU reclaim when the cache exceeds its threshold, and `avc_ss_reset()`, which `avc_flush()`es the whole cache on a policy reload. Only the second is something a resident exploit can trigger deliberately. The AVC's own counters are readable from selinuxfs, subject to policy:

```
cat /sys/fs/selinux/avc/hash_stats       # entries, buckets, longest chain
cat /sys/fs/selinux/avc/cache_stats      # per-CPU: lookups hits misses allocations reclaims frees
cat /sys/fs/selinux/avc/cache_threshold  # node count at which reclaim starts
```

`cache_stats` exists only with `CONFIG_SECURITY_SELINUX_AVC_STATS`; `hash_stats` is unconditional.

Check the field before you rely on it, and take its offset from the same place you take every other offset. `enforcing` exists only if `CONFIG_SECURITY_SELINUX_DEVELOP` is set, which [security/selinux/Kconfig](https://github.com/torvalds/linux/blob/v6.1/security/selinux/Kconfig) defaults to `y`; when it is unset, `enforcing_enabled()` compiles to `return true` and your write changes nothing. Grepping a `bpftool btf dump file <btf> format c` listing for the field name answers existence and nothing else, because that dump is declaration order rather than layout. pahole answers both questions at once:

```
pahole -F btf -C selinux_state ./target-btf 2>/dev/null
```

```
struct selinux_state {
        bool                       enforcing;            /*     0     1 */
        bool                       initialized;          /*     1     1 */
        bool                       policycap[15];        /*     2    15 */
        ...
```

On that build `enforcing` happens to be at offset 0. On a 6.1 kernel built with `CONFIG_SECURITY_SELINUX_DISABLE=y` a `bool disabled` precedes it and the answer is 1; under `CONFIG_RANDSTRUCT` it is whatever that build chose. If `/proc/config.gz` exists (`CONFIG_IKCONFIG_PROC`), `zcat /proc/config.gz | grep SELINUX` confirms the configuration side of the question directly.

### Deriving the addresses

Every kernel address this section depends on — `init_task`, `init_cred`, `selinux_state`, `selinux_blob_sizes` — is described as a fixed offset from the text base. The offsets are link-time properties of one build, and they are produced by subtraction, not by assumption. Reconstruct a symbolized ELF from the shipped kernel image with the tooling introduced in [07-read-write-primitives.md](07-read-write-primitives.md), then read the symbol table:

```
vmlinux-to-elf boot-kernel vmlinux.elf
readelf -sW vmlinux.elf | grep -wE '_text|init_task|init_cred|selinux_state|selinux_blob_sizes'
```

The link-time offset of any symbol is its address minus the address of `_text`, and its runtime address is that offset plus the text base leaked at runtime (the subject of [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md)). On one shipped Pixel image of the `android14-6.1` branch, `_text` is `0xffffffdbc3a00000` and the subtraction yields `INIT_TASK_OFF = 0x201f640`, `SELINUX_ENFORCING_OFF = 0x225a420`, `SELINUX_BLOB_SIZES_OFF = 0x15ceb88`; the same derivation on another device's image of the same branch gives `0x225b448` for `selinux_state`. The numbers are per-image in the strongest sense — same vendor, same kernel branch, different offset — which is why [`cves/lib/root/selinux_state.h`](../lib/root/selinux_state.h) carries its `LIB_SELINUX_ENFORCING_OFF` as an overridable macro with the build it was measured on named in the comment, rather than baking it in, and why the harvested values live per target under `data/live/<device>-<build>/offsets.report`.

### What the flip does not do

Note what the global switch does *not* buy. The Kconfig help text describes the supported path — toggling `/sys/fs/selinux/enforce` — as available "if permitted by the policy", that is, gated on the `security { setenforce }` permission. A kernel write bypasses that check but not its consequences: the switch is global, every process on the device becomes unconfined, `getenforce` reports `Permissive` to anyone who asks, and audit keeps logging denials that are no longer denials. A single patched SID is invisible by comparison.

Verification here does not require a privileged readback:

```
getenforce                      # Enforcing | Permissive
cat /sys/fs/selinux/enforce     # 1 | 0
id -Z                           # u:r:untrusted_app:s0:c123,c256,c512,c768
cat /proc/self/attr/current     # the same, read from the live cred's blob
dmesg | grep 'avc: '            # denials, with scontext/tcontext/tclass
```

`getenforce` and `id -Z` work unprivileged on a stock device. `dmesg` usually does not, because `dmesg_restrict` and SELinux both stand in the way; on Android the fallback is `logcat -b main -s auditd` or, after a crash, the pstore console log discussed in [03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md). The policy itself can be queried offline with `sesearch` and `seinfo` from [SETools](https://github.com/SELinuxProject/setools), against the device's `/sys/fs/selinux/policy` (root-only) or a `plat_sepolicy.cil` extracted from the system image:

```
sesearch --allow -s untrusted_app -c file -p execute policy.bin
seinfo -t policy.bin | grep -i su
```

A word on hardware-backed defences: on some vendor kernels the `cred` object is protected by a hypervisor, so a write that appears to succeed is reverted or panics the device. Project Zero's account of [CVE-2021-0920](https://projectzero.google/2022/08/the-quantum-state-of-linux-kernel.html) notes the in-the-wild exploit had to "bypass Samsung RKP to elevate to root". Read back after writing, always.

## The third gate: seccomp

Android application processes inherit a seccomp-bpf filter installed by zygote, and seccomp is evaluated on syscall entry before capability or LSM checks. A uid-0, unconfined process still under that filter is blocked from whatever the filter blocks.

Check first whether there is a filter at all. On chains launched from a shell rather than from an app, `/proc/self/status` usually reports `Seccomp: 0`, and a write spent on a filter that does not exist is a write spent for nothing.

The relevant state is per-task, not per-cred, and it comes from two different sources that must agree with each other:

- The structure offsets come from BTF: `task_struct.thread_info.flags`, `task_struct.atomic_flags`, and `task_struct.seccomp` with its `mode`, `filter_count` and `filter` members.
- The bit numbers do not. `TIF_SECCOMP` is a macro in the architecture's header — [arch/arm64/include/asm/thread_info.h](https://github.com/torvalds/linux/blob/v6.1/arch/arm64/include/asm/thread_info.h), where it is 11 — and `PFA_NO_NEW_PRIVS` is 0 in [include/linux/sched.h](https://github.com/torvalds/linux/blob/v6.1/include/linux/sched.h). BTF contains no macro definitions, so a reader who looks there will find `flags` and no way to learn which bit of it to clear. Both must be read from the same source tree as the target build.

`TIF_SECCOMP` is also architecture-scoped. Architectures that select `CONFIG_GENERIC_ENTRY` — x86, riscv, s390, loongarch — moved the syscall-entry work flags into a separate `thread_info.syscall_work` word and test `SYSCALL_WORK_SECCOMP` there instead. arm64 does not select it, and still uses `TIF_SECCOMP` at bit 11 in current mainline, but the distinction decides which field you are editing and is worth confirming per target rather than assuming.

Clearing the flag bit and zeroing `seccomp.mode`, `seccomp.filter_count` and `seccomp.filter` is the usual edit. Because all of this is per-thread, it must be repeated for every thread that will issue filtered syscalls — unlike the credential, which is shared and is patched once.

`no_new_privs` deserves its own treatment, because it is not a seccomp detail. With the bit set, `execve` honours neither setuid bits nor file capabilities, so a privileged process cannot hand its privilege to a helper by exec at all. SELinux enforces the same constraint on domain transitions: [`check_nnp_nosuid()` in security/selinux/hooks.c](https://github.com/torvalds/linux/blob/v6.1/security/selinux/hooks.c) refuses a transition to a different SID under NNP unless the policy enables the `nnp_nosuid_transition` policy capability and allows `process2 { nnp_transition }` between the old and new contexts, or the new SID is a bounded subset of the old one. That is why "labelling the helper so policy permits the transition", in the closing section below, is not sufficient on its own: with NNP set, the label is necessary and not enough. Clearing the bit is what makes a later exec able to gain privilege.

The observable is free and unprivileged:

```
grep -E '^(Uid|Gid|Groups|CapEff|CapBnd|NoNewPrivs|Seccomp|Seccomp_filters)' /proc/self/status
cat /proc/sys/kernel/cap_last_cap        # 40 on 6.1: CAP_CHECKPOINT_RESTORE
```

`Seccomp: 0` means disabled, `2` means filter mode. `CapEff` is the effective set as a hex mask, and it is rendered from the live `cred`, so it is an independent oracle rather than a re-read of your own write. "The write returned success" and "the write took effect" are different claims; verify the second.

The mask to write is itself derived rather than quoted. `cap_last_cap` is the highest capability the running kernel knows; the full set is `(1 << (cap_last_cap + 1)) - 1`, so 40 gives 41 bits and `0x1ffffffffff`. That is the value [`cves/lib/root/cred.h`](../lib/root/cred.h) defines as `CAP_FULL`, and it changes whenever the kernel gains a capability, which is why the read is worth doing on the target rather than copying the constant.

Decoding a mask to names is a host-side or userdebug convenience, not something available where it is most wanted: `capsh` ships with libcap and is not present on a production Android image. On device the reader has `/proc/self/status` and either decodes by hand against `capabilities(7)` or pulls the mask to a workstation:

```
capsh --decode=000001ffffffffff
capsh --print | grep -A5 Securebits
```

The second command is the only readback for securebits there is — `/proc/self/status` does not expose them. It prints `Securebits: 00/0x0/1'b0 (no-new-privs=0)` followed by a line per bit (`secure-noroot`, `secure-no-suid-fixup`, `secure-keep-caps`, `secure-no-ambient-raise`), each marked locked or unlocked, and its `no-new-privs` field covers the NNP check as well.

## The ceiling: loading a module

Once a process is uid 0 with full capabilities and an unconfined label, the remaining escalation is to put code in the kernel permanently, which on Linux means `init_module` or `finit_module`. That path is gated four times, and the errno tells you which gate you hit:

- `EPERM` — [`may_init_module()` in kernel/module/main.c](https://github.com/torvalds/linux/blob/v6.1/kernel/module/main.c) requires `CAP_SYS_MODULE` and `modules_disabled` unset. The capability is checked with plain `capable()`, so it must be held in the initial user namespace; see the namespace discussion above if `CapEff` looks right and this still fails. `/proc/sys/kernel/modules_disabled` is one-way: once set to 1 it cannot be cleared from userspace.
- `EACCES` — the SELinux hook, and the two syscalls take different paths to it. `init_module` copies the image from userspace and reaches `security_kernel_load_data(LOADING_MODULE)` -> `selinux_kernel_load_data()`. `finit_module` reads it through `kernel_read_file_from_fd()`, which calls `security_kernel_read_file(file, READING_MODULE)` -> `selinux_kernel_read_file()`. Both land in `selinux_kernel_module_from_file()`, which branches on whether it was given a file. For `init_module` (`file == NULL`) it performs `avc_has_perm(sid, sid, SECCLASS_SYSTEM, SYSTEM__MODULE_LOAD, NULL)` — source and target both the caller's own SID. For `finit_module` the target is the module file's inode SID: `avc_has_perm(sid, isec->sid, SECCLASS_SYSTEM, SYSTEM__MODULE_LOAD, &ad)`, preceded by an `fd { use }` check when the file was opened by a different domain. This is a practical failure rather than a subtlety. A `.ko` dropped in `/data/local/tmp` is labelled `shell_data_file`, and unconfined root still needs `allow <your domain> shell_data_file:system module_load` in policy. Check the file's label and the rule before spending the attempt:

  ```
  ls -Z mymodule.ko
  sesearch --allow -s <your domain> -t shell_data_file -c system -p module_load policy.bin
  chcon u:object_r:<permitted type>:s0 mymodule.ko
  ```

  Both halves of that check fix an ordering. Because `init_module` is decided with the caller's own SID as source and target, the label has to be right before the load is attempted, which puts the SELinux step ahead of the module step. Because `finit_module` additionally consults the module file's inode SID, the same argument extends to the object label — and that one the credential edit does not touch at all, so it has to be set deliberately.
- `EKEYREJECTED` — signature enforcement. [`module_sig_check()` in kernel/module/signing.c](https://github.com/torvalds/linux/blob/v6.1/kernel/module/signing.c) classifies three underlying conditions as non-fatal-in-principle: `-ENODATA` ("unsigned module"), `-ENOKEY` ("module with unavailable key") and `-ENOPKG` ("module with unsupported crypto"). If `is_module_sig_enforced()` is true it logs the reason with `pr_notice` and returns `-EKEYREJECTED` for all three, so the caller never sees the original errno and the three cases are distinguishable only from that log line, read through `dmesg` or the pstore console log. If enforcement is off, none of them is returned at all: the module loads and taints the kernel with `TAINT_UNSIGNED_MODULE`, bit 13, which shows up as `E` in `/proc/sys/kernel/tainted`. Any other signature error — unparseable signature, verification failure, allocation failure — is fatal regardless of enforcement and is returned as itself.
- `ENOEXEC` — vermagic or ELF structure. Every policy gate passed; the image is the wrong build.

The AOSP common-kernel [arm64 gki_defconfig for android14-6.1](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/configs/gki_defconfig) sets `CONFIG_MODULE_SIG=y` and not `CONFIG_MODULE_SIG_FORCE` — it is also where `CONFIG_DEBUG_INFO_BTF=y` comes from, which is why the target has BTF to pull in the first place. A defconfig is not the shipped kernel, so read the live values:

```
cat /sys/module/module/parameters/sig_enforce     # Y or N
cat /proc/sys/kernel/modules_disabled             # 0 or 1
cat /proc/sys/kernel/tainted                      # bit 13 (value 8192) = E, unsigned module loaded
cat /proc/version                                 # banner, including the build's -g<sha>
modinfo -F vermagic ./mymodule.ko                 # must match the target exactly
lsmod                                             # what the kernel already accepted
```

Both `sig_enforce` and `modules_disabled` are one-way switches from userspace, and the same argument applies to each. `sig_enforce` is declared `module_param(sig_enforce, bool_enable_only, 0644)` in [kernel/module/signing.c](https://github.com/torvalds/linux/blob/v6.1/kernel/module/signing.c): the `bool_enable_only` setter permits false-to-true and refuses true-to-false, so even uid 0 cannot relax it through sysfs. `modules_disabled` is a plain `int` global whose sysctl entry sets both `extra1` and `extra2` to `SYSCTL_ONE`, so `proc_dointvec_minmax` accepts the value 1 and nothing else: it can be set and never cleared. A kernel write can clear both, because both are ordinary writable data once you are addressing them directly — which is the reason to keep the write primitive alive after the `cred` edit rather than discarding it.

## How rooting frameworks structure the grant

Exploitation ends at "this process is privileged"; a rooted device is a different deliverable, because the privileged process exits. Both mainstream frameworks solve it by keeping a persistent privileged component plus a policy decision point, and they differ in where that component lives.

Magisk keeps it in userspace. Its [architecture documentation](https://github.com/topjohnwu/Magisk/blob/master/docs/details.md) describes `magiskd` launching from a patched ramdisk at `post-fs-data`, and rather than disabling SELinux it injects domains into the live policy: "The new domain `magisk` is effectively permissive, which is what `magiskd` and all root shell will run in." Since Android 8.0 a client cannot reach the daemon's socket directly; executing the `magisk` binary, labelled `magisk_exec`, triggers a type transition into `magisk_client`, and only that domain may talk to the daemon, which evaluates per-uid policy and forks the shell.

KernelSU keeps it in the kernel. Its documentation states that it "works in kernel mode and grants root permission to userspace apps directly in kernel space" ([What is KernelSU](https://kernelsu.org/guide/what-is-kernelsu.html)). The control channel needs no new device node and no new syscall: the driver places a kprobe on the reboot syscall and watches for a magic argument pair, and when it sees `KSU_INSTALL_MAGIC1`/`KSU_INSTALL_MAGIC2` (`0xDEADBEEF`, `0xCAFEBABE`) it queues task work that creates an anon-inode file and copies the resulting descriptor back through the caller's fourth argument ([kernel/supercall/supercall.c](https://github.com/tiann/KernelSU/blob/main/kernel/supercall/supercall.c), constants in [uapi/supercall.h](https://github.com/tiann/KernelSU/blob/main/uapi/supercall.h)). Everything afterwards is `ioctl` on that descriptor — `KSU_IOCTL_GET_INFO` is `_IOR('K', 2, struct ksu_get_info_cmd)`. [`cves/lib/root/kernelsu.c`](../lib/root/kernelsu.c) is a client for exactly that handshake, which is how "is a kernel-resident grant service already installed" gets answered rather than assumed.

Granting root is the edit described earlier, applied deliberately. The [App Profile documentation](https://kernelsu.org/guide/app-profile.html) covers customizing "the UID, GID, and groups for the root process after executing `su`" — its own example removes the `inet` supplementary group so the granted shell cannot open sockets, which is the `group_info` field the identity write leaves alone — restricting capabilities, and choosing the SELinux domain, "in typical scenarios... a SELinux domain with unrestricted access, such as `u:r:ksu:s0`", switchable to a confined one. On capabilities the page's own example is `CAP_DAC_READ_SEARCH`, and its wording is precise in a way worth preserving: a uid-0 process that lacks "the `CAP_DAC_READ_SEARCH` capability or higher" cannot freely read files. The qualifier carries the weight. `CAP_DAC_OVERRIDE` bypasses read, write and execute permission checks on files in its own right, so a uid-0 process that keeps it can still read effectively any file on the device with `CAP_DAC_READ_SEARCH` dropped. Partial root of that kind means dropping the DAC-bypass group as a whole, not one member of it.

Both designs treat cred replacement and domain assignment as a *service* with an authorization check in front of it, rather than as a one-shot. A chain that reaches unconfined root has earned the right to install such a component; the remaining work — placing a helper somewhere executable, making it visible from the mount namespaces that will call it, and labelling it so policy permits the transition — is a separate problem with its own failure modes, and the `no_new_privs` constraint above is one of them.

## Instruments

- `adb pull /sys/kernel/btf/vmlinux` then `pahole -F btf -C <struct> ./target-btf 2>/dev/null` — member offsets, sizes and padding holes for one structure, from the target's own type information. The only reliable way to derive `cred`, `task_struct`, `task_security_struct`, `lsm_blob_sizes` and `selinux_state` offsets. The stderr redirect suppresses `BTF_KIND_DECL_TAG for unknown BTF id` warnings on newer BTF. Present when `CONFIG_DEBUG_INFO_BTF=y`, which GKI sets; SELinux may deny app and shell domains read access on a production device.
- `vmlinux-to-elf boot-kernel vmlinux.elf` then `readelf -sW vmlinux.elf | grep -wE '_text|init_task|init_cred|selinux_state|selinux_blob_sizes'` — link-time symbol addresses from a stripped Android kernel image, reconstructed from its embedded kallsyms. Subtract `_text` for the offset to add to a leaked text base. Host-side, no device privilege.
- `grep -E '^(Uid|Gid|Groups|CapEff|CapBnd|NoNewPrivs|Seccomp|Seccomp_filters)' /proc/self/status` — identity, capability sets, supplementary groups, NNP and seccomp mode, rendered from the live `cred` and `task_struct`. Unprivileged, on device. It does not report securebits.
- `cat /proc/sys/kernel/cap_last_cap` — the highest capability this kernel knows; the full mask is `(1 << (n + 1)) - 1`. Unprivileged.
- `capsh --decode=<mask>` and `capsh --print` — capability names from a mask, and the only readback for securebits and NNP. Part of libcap: a host-side or userdebug instrument, not present on a stock Android image; on device, pull the mask and decode it elsewhere.
- `cat /proc/self/uid_map`, `ls -l /proc/self/ns/user` — which user namespace the process is in, which decides whether uid 0 and `CapEff` mean anything to `capable()`. Unprivileged.
- `getenforce`, `cat /sys/fs/selinux/enforce`, `id -Z`, `cat /proc/self/attr/current`, `ps -AZ` — global enforcing state and per-process contexts. Unprivileged on stock Android.
- `cat /sys/fs/selinux/avc/cache_stats` and `/sys/fs/selinux/avc/hash_stats` — per-CPU AVC lookups, hits, misses, allocations, reclaims and frees, and the live node count. Readable from selinuxfs subject to policy; `cache_stats` requires `CONFIG_SECURITY_SELINUX_AVC_STATS`.
- `sesearch --allow -s <domain> -t <type> -c <class> -p <perm>`, `seinfo -t` (SETools) — what a domain is actually allowed against a given type, so you can choose a target SID, or a directory for a `.ko`, before you have a primitive. Runs against `/sys/fs/selinux/policy` (root) or an extracted `plat_sepolicy.cil` (host).
- `ls -Z <file>` and `chcon <context> <file>` — the object label the `finit_module` AVC check is made against, and the way to change it.
- `dmesg | grep 'avc: '` / `logcat -b main -s auditd` — denial records with scontext, tcontext and tclass. `dmesg` usually restricted at low privilege; logcat is the Android fallback.
- `echo 'p:peek <func> v=@0x<addr>:u8' > /sys/kernel/tracing/kprobe_events` then enable the event, set `tracing_on=1`, trigger the function and read `trace` — reads memory at an absolute kernel address at probe time, per the [kprobetrace documentation](https://docs.kernel.org/trace/kprobetrace.html). Needs write access to tracefs, which on Android means root or a debug build; if the event write returns `EINVAL`, drop the type suffix and use the bare `@ADDR` form. This is the fallback readback when there is no debugfs and no BPF.
- `cat /sys/module/module/parameters/sig_enforce`, `/proc/sys/kernel/modules_disabled`, `/proc/sys/kernel/tainted`, `cat /proc/version`, `modinfo -F vermagic`, `lsmod` — module-loading gates, the taint flag an unsigned load leaves behind, and the exact build identity you must match. Unprivileged reads.
- `insmod` errno triage — `EPERM` (capability in the wrong namespace, or `modules_disabled`), `EACCES` (SELinux `system module_load`, against the caller's SID for `init_module` and the file's inode SID for `finit_module`), `EKEYREJECTED` (signature enforcement on, with the reason in the kernel log), `ENOEXEC` (vermagic or format). Requires the load attempt itself, which requires root.

## Grounded in this project

The credential edit is implemented in `cves/lib/root/cred.c` and `cves/lib/root/cred.h`, which perform the writes in order — identity words, securebits, the five capability sets with a verifying read-back that fails the whole patch on any mismatch, then the seccomp defang — and expose the SID patch separately as `lib_patch_cred_sid()`, taking the blob offset as a parameter rather than assuming zero. The offsets and bit indices it needs are macros with per-target defaults, overridable at build time, which is the form every per-build constant takes here. The global enforcing flip is `cves/lib/root/selinux_state.h`, which resolves `selinux_state` as a text-base-relative offset carried per target and uses `/sys/fs/selinux/enforce` as its unprivileged oracle; the harvested offsets themselves live in `data/live/<device>-<build>/offsets.report`, one file per shipped kernel. The task-list walk is `cves/lib/root/taskscan.c`, whose entry point `lib_find_task_by_tgid()` matches on `tgid` for the reason given above and implements the bounded-iteration and pointer-range-check rules. Turning a one-shot privileged process into a durable, reachable one is `cves/lib/root/handoff.c`, and `cves/lib/root/kernelsu.c` performs the reboot-magic handshake that detects an already-installed kernel-resident grant service. Two complete chains assemble these pieces. `cves/cve-2026-43499-ghostlock/root.c` locates the task from `init_task`'s neighbour with the `tgid` walk as its fallback, sets both SELinux identifiers in the blob to the kernel's own rather than copying them off another task, clears the thread flag, `no_new_privs` and the filter mode, count and pointer on that same task, and writes the zero byte over the global enforcing flag last, before releasing the pre-forked child it elevated. `cves/cve-2026-43049-ffwheel/ffroot_w.c` reaches unconfined uid 0 in two writes, ordered by what each one unlocks: the credential edit goes first because the administrative capability it grants is what opens the pagemap interface the second write needs in order to aim the enforcing byte, and the module load goes last because the AVC check it faces is made against the caller's own SID, so it passes only once the enforcing byte is down.

## See also

- [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) — every address used here is text-base-relative or reached from a leaked pointer, and the symbol-recovery tooling the derivation above depends on.
- [07-read-write-primitives.md](07-read-write-primitives.md) — how the write this section consumes is built, why a primitive that can also read is worth much more than one that cannot, and where the `addr_limit` technique belongs.
- [03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md) — reading the panic when a credential or SID write lands on the wrong bytes, or when a swapped `init_cred` refcount underflows a run later.
- [10-survivability-and-measurement.md](10-survivability-and-measurement.md) — keeping the device alive after the edit, and treating the verification steps above as measurements rather than assertions.
- [11-case-studies.md](11-case-studies.md) — these steps in the context of complete chains.
- [12-further-reading-and-glossary.md](12-further-reading-and-glossary.md) — the broader reading list.
