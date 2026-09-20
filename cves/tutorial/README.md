# Kernel Exploitation: Theory and Methodology

Twelve files trace one path: from a published CVE record to a process running as uid 0 on a device
whose kernel you cannot rebuild, and back down again to a machine that still boots afterwards. The
treatment is methodological rather than a walkthrough of a single chain — each technique is stated
as a mechanism, cited to the research paper, kernel commit or source file that establishes it, so
that the reasoning applies to bugs not discussed here. Concepts come with the instrument that
observes them on real hardware: the sections on slab behaviour name the `pahole`, BTF and sysfs
queries that answer a layout question, the section on races names the kprobe and `trace_clock`
setup that measures a window, and every section ends with an inventory of its commands, what
privilege each needs and what conclusion each licenses. Worked examples are arm64 and Android GKI
6.1, because that is where the constraints bite hardest — locked bootloader, SELinux enforcing, no
debug build, no KASAN — but the mechanisms are Linux ones. The case-study file takes two finished
chains through the same eight questions, so that the preceding techniques can be seen composed
rather than isolated.

Read roughly in order: later sections assume the vocabulary and the instruments of earlier ones.
Each file nevertheless carries its own citations, its own instrument list and its own
cross-references, so entering in the middle costs only some backtracking.

Spelling follows Oxford style throughout, and anything added to these files should match it: the
`-ize` ending on the verbs that take it and on their derivatives — randomize, symbolize,
neutralize, initialization — with British forms elsewhere (behaviour, catalogue, labelled,
defence), and `analyse` and `paralyse` keeping the `-yse` of their Greek root. Architecture names
follow the kernel's own usage: `arm64` for the port and the `arch/arm64` tree, AArch64 for the
execution state the Arm architecture defines, `aarch64` in toolchain triples and tool names, and
capitals only inside identifiers such as `CONFIG_ARM64_VA_BITS`. Quoted material is reproduced
exactly as its source spells it — commit subjects, paper and CVE-record titles, kernel log lines
and command output — because those strings are usually what you search for; a commit subject
written with `initialisation` is searched for that way. Emphasis is italic, never bold.

1. [Vulnerability Discovery and Patch Triage](01-vulnerability-discovery-and-patch-triage.md) —
   where kernel CVE records come from now that the kernel is its own CNA, why an NVD version range
   describes a source tree rather than the build in your hand, and how to get from a CVE id to the
   commit that changed the code through the vulns repository's `.sha1` and `.dyad` files. The
   presence question is then settled empirically against a shipped image: the banner's `-g<sha>`
   tested for ancestry in an ACK clone, string and symbol-shape tests on a pulled kernel, kprobe
   acceptance as a probe, and syzbot as a continuous source of candidates.

2. [Reachability and Attack Surface Mapping](02-reachability-and-attack-surface.md) — the four
   independent gates a candidate bug must clear before one instruction of the vulnerable function
   runs on your behalf: DAC on uids and supplementary groups, SELinux down to per-`ioctl` extended
   permissions, the seccomp filter of the domain you are actually in, and in-code `capable()` tests
   and feature gates. Each is answered by measurement rather than inference — `ls -lZ` for the
   object half, `sesearch` over a policy pulled off the device for the rule, AVC denials read from
   `logcat` or pstore for the verdict.

3. [Crash Triage and Root-Cause Analysis](03-crash-triage-and-root-cause-analysis.md) — reading the
   arm64 oops that a developing primitive produces: decoding the ESR word into an exception class
   and fault status code, what the translation level says about the magnitude of a bad pointer, and
   which `BRK` immediates mark a self-inflicted trap from CFI, KASAN or UBSAN rather than a memory
   fault. It covers retrieving the log across the panic-reboot from `console-ramoops-0`,
   symbolizing under KASLR with `decode_stacktrace.sh` and `faddr2line`, and separating a crash
   that confirms the bug from a crash that confirms a typo.

4. [Defeating KASLR and Building Information Leaks](04-kaslr-and-information-leaks.md) — what arm64
   randomizes and with how much entropy (the image, the module region), what it leaves fixed (the
   linear map, whose constancy is itself a usable primitive), and a taxonomy of leak classes from
   uninitialized-memory disclosure to timing side channels. The recovery instruments are here too:
   the tracefs `trace_marker` address leak, why `/proc/kallsyms` prints a column of zeros under
   `kptr_restrict`, `pagemap` PFNs, and reconstructing symbols with `vmlinux-to-elf` and layouts
   with `pahole -F btf` when the device gives up neither.

5. [Heap Grooming and Spraying](05-heap-grooming-and-spraying.md) — SLUB as the attacker sees it:
   the per-CPU freelist's LIFO ordering, where `s->offset` puts the free pointer and what that
   means for reading back a freed object, cache merging and aliasing, and the `GFP_KERNEL_ACCOUNT`
   split that puts sprayable objects in a different cache from the vulnerable one. It catalogues
   the spray vehicles and the pressure-tuning that makes a reclaim land, and names the observation
   tools for each fact — `/proc/slabinfo` and `/sys/kernel/slab` where privilege permits, BTF for
   object size, drgn's slab helpers on a reference device.

6. [Cross-Cache Attacks](06-cross-cache-attacks.md) — what to do when the victim object's cache
   contains nothing worth corrupting: return the slab page to the buddy allocator and let a
   different cache, or a raw page consumer, take it, so the dangling pointer changes type without
   the bug changing. The mechanics are the per-CPU pagesets, slab order and the `min_partial`
   discard gate, plus the RCU-deferred free that moves a `struct file` page to an `rcuop` CPU you
   did not choose, and the verification step that turns a probabilistic reclaim into a bounded one.

7. [From a Bug to a Read/Write Primitive](07-read-write-primitives.md) — the six properties that
   define a primitive (domain, granularity, repeatability, side effects, preconditions,
   verifiability), a taxonomy from bug class to the primitive it naturally yields, and the
   promotion chains that trade a narrow primitive for a general one — a single uninitialized
   `pipe_buffer` flag, or a write into a page table that reaches physical memory with no kernel
   address at all. Every offset it uses is derived from the target's own BTF, with the failure
   modes of that read (`ENOENT` versus `EACCES`) told apart.

8. [Triggering Races Reliably](08-triggering-races-reliably.md) — the check-then-use shapes that
   recur in practice (double fetch, identity checks over a reusable namespace, lifetime races), and
   the discipline of taking scheduling choice away from the machine: CPU pinning, window widening
   with `userfaultfd` and FUSE, and the deferral mechanisms that separate the instant a race is won
   from the instant the memory is reclaimable. Measurement comes first — kprobes with a
   `common_pid` filter and a global `trace_clock` to time the window before trying to hit it — and
   results are reported as a hit rate rather than pass or fail.

9. [From Kernel Write Primitive to Root](09-privilege-escalation-to-root.md) — the four decisions a
   kernel makes about a syscall and the bytes behind each: the identity words and capability sets
   in `struct cred`, the SELinux label in the LSM blob hanging off it, the global enforcing switch,
   and the seccomp filter that ignores privilege entirely. It covers finding your own `cred` from a
   primitive, why `commit_creds(prepare_kernel_cred(NULL))` no longer works, what `user_ns` does to
   a perfect-looking `/proc/self/status`, and the ceiling beyond a data-only edit: loading a module,
   and the `insmod` errno triage that says which gate refused.

10. [Survivability, Stabilization, and Treating Exploitation as an Experiment](10-survivability-and-measurement.md)
    — the object-graph debt a use-after-free leaves behind (a list entry, a refcount somebody holds,
    a registered callback, a timer that has not fired) and the choice between repairing those
    references and neutralizing the paths that would follow them. The second half treats a chain as
    an experiment: bounding failure in time, logging through the panic with `O_SYNC`, per-stage
    success rates and how to compose them, and why the harness is part of the exploit rather than
    scaffolding around it.

11. [Case Studies: Techniques Applied End to End](11-case-studies.md) — two chains, GhostLock
    (CVE-2026-43499) and FFWheel (CVE-2026-43049), each taken through the same eight questions in
    the same order: what the defect is, what privilege and interface reach it, where kernel
    addresses come from, how memory is arranged, what primitive the bug yields and how it is made
    usable, how that primitive becomes root and what happens to SELinux, what keeps the device alive
    afterwards, and how reliable the result is. Both start from an unprivileged shell and end at
    uid 0, so the comparison is between two answers to one set of problems; a closing section sets
    them side by side and isolates the difference that costs the most, between a chain that can
    verify its state before an irreversible commitment and one that commits blind. The instrument it
    introduces is `tools/pagetrace`, which tags page allocation and free tracepoints by phase and
    scores a reclaim by frame number.

12. [Further Reading and Glossary](12-further-reading-and-glossary.md) — an annotated bibliography
    grouped by what each source is for, with notes on which parts have aged and which have not,
    covering the kernel's own documentation, Project Zero, LWN's defender-side accounts, kernelCTF
    exploits and the fuzzing infrastructure. The glossary defines the vocabulary used across the
    preceding eleven sections and pairs each term with the command that observes it on a device.
