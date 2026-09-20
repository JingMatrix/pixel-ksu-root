# Heap Grooming and Spraying

A use-after-free or a slab overflow is, on its own, a statement about one address. It becomes a capability only when you decide what occupies that address at the moment the bug fires. That decision is made entirely before the bug is triggered, by arranging allocations so that the memory in question holds an object you chose. The arrangement is the technique; the bug is the trigger.

Everything below assumes the SLUB allocator, which is what ships on essentially every modern Linux distribution and every Android kernel.

## What SLUB does with an allocation

Each `kmem_cache` owns a set of slabs — contiguous page runs, usually order 0 to order 3 — carved into fixed-size objects. Free objects inside a slab are threaded into a singly linked list whose `next` pointer is stored *inside the free object itself*, at byte offset `s->offset`.

Where that offset falls decides what a read-back of a freed object shows you and how far an overflow has to reach before it touches allocator metadata. `calculate_sizes()` in `mm/slub.c` sets, for an ordinary cache, `s->offset = ALIGN_DOWN(s->object_size / 2, sizeof(void *))` — the middle of the object. For `kmalloc-256` that is `ALIGN_DOWN(128, 8) = 128`: the first 128 bytes of a freed `kmalloc-256` object are stale contents, and the allocator word sits at +128. The exception is a cache carrying `SLAB_TYPESAFE_BY_RCU`, `SLAB_POISON`, a constructor, or a redzoned object smaller than a pointer, where the same function takes the other branch and sets `s->offset = size`, placing the pointer immediately *after* the object. That is why a linear overflow into a `SLAB_TYPESAFE_BY_RCU` cache such as `filp` runs into the neighbouring object rather than into a freelist word, and why the read-back plan that works on `kmalloc-256` does not transfer there.

Read the number rather than recompute it. `pahole -C kmem_cache /sys/kernel/btf/vmlinux` locates the `offset` member within `struct kmem_cache` (on a current kernel, at byte 40, with `object_size` at 28), and on a rooted reference device drgn reads the value directly:

```
>>> find_slab_cache(prog, "kmalloc-256").offset
(unsigned int)128
```

The fast path is per-CPU. `struct kmem_cache_cpu` holds a `freelist` pointer into the currently active slab, plus a per-CPU partial list. Allocation pops the head of `c->freelist`. A free of an object belonging to the active slab on the same CPU pushes it back onto the head. When the active slab's freelist runs dry the allocator pulls from the per-CPU partial list, then from the node partial list, and only then asks the page allocator for a fresh slab.

Two consequences drive everything else:

1. The per-CPU freelist is LIFO. Free an object and immediately allocate the same size on the same CPU, and you get the same memory back. No mainline hardening option changes that ordering; what the later mitigations change is *which cache* a given call site lands in, which is a different attack on the same methodology and is covered under freelist hardening below.
2. The per-CPU part means CPU affinity is part of the technique. A free on CPU 2 and a reclaim on CPU 5 traverse a slower, less predictable path. Pinning both sides with `sched_setaffinity(2)` turns a probabilistic reclaim into a near-deterministic one — but assert the pin rather than assume it, with `sched_getcpu()` called on both the free and the reclaim side and `Cpus_allowed_list` read from `/proc/self/status`. Android confines app and shell processes to cpuset cgroups, so `sched_setaffinity()` can succeed against a mask the cpuset then narrows, leaving you on a CPU you did not choose. [06-cross-cache-attacks.md](06-cross-cache-attacks.md) develops what the per-CPU structures mean once whole pages rather than objects are the unit.

To look at cache geometry on a machine you control:

```
# cat /proc/slabinfo | head -5
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : ...
kmalloc-1k           1184       1184       1024        32            8 : ...
```

[slabinfo(5)](https://man7.org/linux/man-pages/man5/slabinfo.5.html) defines the columns — "objperslab: The number of objects stored in each slab", "pagesperslab: The number of pages allocated for each slab" — and states the permissions: "Only root can read ... the /proc/slabinfo file." Those two columns give the two numbers a groom is built from: how many objects you must allocate to force a fresh slab, and how large a page run that slab is. [06-cross-cache-attacks.md](06-cross-cache-attacks.md) works the arithmetic through for page-granularity attacks. [slabtop(1)](https://man7.org/linux/man-pages/man1/slabtop.1.html) (`slabtop -s c`, sort by cache size) is the same data live, with the same privilege requirement, and on Android neither is readable from an app or `adb shell` uid.

The richer view is sysfs: `/sys/kernel/slab/kmalloc-1k/` exposes one value per file. `object_size`, `objs_per_slab`, `order`, `cpu_partial` and `aliases` each have a `What:` stanza in [Documentation/ABI/testing/sysfs-kernel-slab](https://github.com/torvalds/linux/blob/v6.6/Documentation/ABI/testing/sysfs-kernel-slab), which is the authority for what each one means. The kernel's [SLUB documentation](https://www.kernel.org/doc/html/v6.6/mm/slub.html) is a different document and covers a different set of things: the `slub_debug` boot parameter and its per-cache toggles, and the `slabinfo` userspace tool, which is built out of the tree (`gcc -o slabinfo tools/mm/slabinfo.c`) and whose `slabinfo -a` prints the merge sets. Most of `/sys/kernel/slab/<cache>/` is mode 0400, so this too is a rooted-device instrument; `aliases` in particular returns `Permission denied` to a normal uid.

[drgn](https://drgn.readthedocs.io/) walks the allocator live rather than summarizing it. [`drgn.helpers.linux.slab`](https://drgn.readthedocs.io/en/latest/helpers.html#module-drgn.helpers.linux.slab) provides `find_slab_cache`, `for_each_slab_cache`, `slab_cache_for_each_allocated_object` and `slab_object_info`; the last takes an address and reports which cache owns it and whether the object is allocated or free, which is the fastest way to confirm that a spray object landed in the cache you believed it would. The prerequisites are steeper than "root": drgn needs `CONFIG_PROC_KCORE` for the live-kernel target *and* a `vmlinux` with DWARF debuginfo matching the running build. `CONFIG_PROC_KCORE` does not appear in the arm64 `gki_defconfig` this tutorial targets, and GKI release images ship no DWARF, so drgn is a reference-device instrument, not a target one. On a locked target the substitute is to derive offsets from BTF (below) and confirm them with a kprobe read, which [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) develops. On a crash dump instead of a live kernel, `crash` with a matching `vmlinux` gives the same picture via `kmem -S <cache>`.

On a locked production device almost none of this is available at low privilege — the symlink listing under `/sys/kernel/slab/` is the exception, since the link targets are readable even when the files are not. The honest fallback is to derive the geometry offline from a kernel with the same configuration — Android's GKI images make this practical, since the binary kernel for a given release is published — and then verify on-device indirectly, by timing (see PSPRAY below) or by reading back sprayed content through whatever interface allocated it.

## Mapping an object to a cache

An allocation of *n* bytes goes to the smallest `kmalloc-N` cache with `N >= n`, so the first question about any candidate object is its exact size on your target, not on your build machine. Kernels expose that without any debug build, because modern kernels ship BTF.

```
$ pahole -C msg_msg /sys/kernel/btf/vmlinux
struct msg_msg {
	struct list_head           m_list;               /*     0    16 */
	long int                   m_type;               /*    16     8 */
	size_t                     m_ts;                 /*    24     8 */
	struct msg_msgseg *        next;                 /*    32     8 */
	void *                     security;             /*    40     8 */

	/* size: 48, cachelines: 1, members: 5 */
	/* last cacheline: 48 bytes */
};
```

The conclusion is in the `size:` line, not the member list: a `msgsnd()` of *n* payload bytes allocates `48 + n`, so a 16-byte payload is a 64-byte allocation and lands in `kmalloc-cg-64`, while a 208-byte payload is the last one that still fits `kmalloc-cg-256`.

[BTF](https://docs.kernel.org/bpf/btf.html) encodes every struct's size and every member's bit offset for the running kernel, and `/sys/kernel/btf/vmlinux` is world-readable on kernels built with `CONFIG_DEBUG_INFO_BTF`, which includes Android GKI. [pahole(1)](https://manpages.debian.org/testing/dwarves/pahole.1.en.html) takes an ELF or raw BTF file and renders one type with offsets, holes and total size; it does not take a C header, so pass the sysfs file itself. A separate and frequently confused invocation, `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` ([bpftool-btf(8)](https://manpages.debian.org/unstable/bpftool/bpftool-btf.8.en.html)), generates a C header for compiling BPF programs against; it is not an input to `pahole`. The layout you get this way is exact — it is what the kernel you are attacking was compiled with, not an approximation from source. Derive every offset this way rather than copying a number from a writeup: a 48-byte header on one kernel is a 40-byte header on another that dropped a field.

What BTF does *not* tell you is the GFP flags of an allocation, and those decide the cache as much as the size does. Since kernel 5.14, allocations carrying `GFP_KERNEL_ACCOUNT` are served from a separate `kmalloc-cg-*` set ([commit 494c1dfe855e, "mm: memcg/slab: create a new set of kmalloc-cg-<n> caches"](https://github.com/torvalds/linux/commit/494c1dfe855ec1f70f89552fce5eadf4a1717552)). `msg_msg` moved to `kmalloc-cg` in that change, which silently invalidated a generation of exploits and forced researchers to find sprays that share the accounted caches — Exodus Intelligence's [netfilter use-after-free writeup](https://blog.exodusintel.com/2022/12/19/linux-kernel-exploiting-a-netfilter-use-after-free-in-kmalloc-cg/) walks through exactly that search, landing on System V messages plus `time_namespace` objects.

The kernel will answer the flags question directly if you ask it. The `kmem/kmalloc` tracepoint carries `gfp_flags`, and since 6.1 its format string prints the derived verdict as `accounted=true/false`, computed in `include/trace/events/kmem.h` from `__GFP_ACCOUNT`. On a rooted reference device, filter it by size so the trace is not swamped, then run the syscall under test:

```
# cd /sys/kernel/tracing
# echo 'bytes_req >= 630 && bytes_req <= 650' > events/kmem/kmalloc/filter
# echo 1 > events/kmem/kmalloc/enable
# cat trace_pipe &
# ./make-a-pipe            # in another shell
  make-a-pipe-4812 [003] ..... 913.204117: kmalloc: call_site=alloc_pipe_info+0x6c/0x220 \
    ptr=000000009c3a1e77 bytes_req=640 bytes_alloc=1024 \
    gfp_flags=GFP_KERNEL_ACCOUNT|__GFP_ZERO node=-1 accounted=true
```

`bytes_req=640` with `bytes_alloc=1024` and `accounted=true` is the whole answer: this allocation goes to `kmalloc-cg-1k`. When tracing is unavailable — a locked target, or a kernel with tracefs restricted — the offline fallback is `objdump -d` around the symbol in a recovered `vmlinux`, reading the immediate loaded into the flags argument, or the source for the matching release.

The `kmalloc-cg-*` split is not unconditional, and a technique built on the assumption that an accounted and an unaccounted object can never collide will mislead you on a kernel where they can. `new_kmalloc_cache()` in `mm/slab_common.c` assigns `kmalloc_caches[KMALLOC_CGROUP][i] = kmalloc_caches[KMALLOC_NORMAL][i]` when `mem_cgroup_kmem_disabled()`, so with `CONFIG_MEMCG_KMEM=n` — it is selected by `CONFIG_MEMCG`, which Android GKI sets — or with `cgroup.memory=nokmem` on the kernel command line, `kmalloc-cg-N` and `kmalloc-N` are literally the same `kmem_cache`, and a pairing that looks impossible on paper works. Check with `ls /sys/kernel/slab/ | grep '^kmalloc-cg-'` or `grep kmalloc-cg /proc/slabinfo`: an empty result means the two families are aliased, not that accounting is absent.

Cache boundaries are also architecture-dependent, and the derivation matters more than any single remembered number. `arch/arm64/include/asm/cache.h` defines `ARCH_DMA_MINALIGN`; `include/linux/slab.h` promotes it to `ARCH_KMALLOC_MINALIGN` when it exceeds 8, and sets `KMALLOC_MIN_SIZE` and `KMALLOC_SHIFT_LOW` from that; and `__kmalloc_index()` in the same header creates `kmalloc-96` only when `KMALLOC_MIN_SIZE <= 32` and `kmalloc-192` only when `KMALLOC_MIN_SIZE <= 64`, with `create_kmalloc_caches()` applying the same two conditionals. On the Android GKI 6.1 arm64 tree this project targets, `ARCH_DMA_MINALIGN` is 64 — lowered from the mainline 128 by an Android-specific patch — so `KMALLOC_MIN_SIZE` is 64 and the general ladder is 64, 128, 192, 256, 512, 1k and up, with no `kmalloc-8`, `-16`, `-32` or `-96` at all. An exploit that targets `kmalloc-96` because a writeup said so is targeting a cache that does not exist on this device; the 80-byte object it was aiming at lands in `kmalloc-128` here.

That boundary moved again upstream: 6.5 decoupled the two macros, so mainline arm64 now has `ARCH_DMA_MINALIGN` 128 alongside `ARCH_KMALLOC_MINALIGN` 8 and therefore does have the small caches. Treat the ladder as version- and branch-specific. On a rooted reference device, `ls /sys/kernel/slab/ | grep '^kmalloc-' | sort -t- -k2 -n` prints it; offline, `grep -rn ARCH_DMA_MINALIGN arch/arm64/include/asm/cache.h` in the matching source tree gives the input. [Michael S and Vitaly Nikolenko](https://duasynt.com/blog/linux-kernel-heap-feng-shui-2022) observe the exploitation consequence of a truncated ladder on Android/arm64, where the smallest general-purpose cache they found was `kmalloc-128`: fewer caches means each one is busier, and reclaim there collides constantly with unrelated kernel allocations.

## Merging, aliasing, and what the cache names hide

`kmem_cache_create()` does not necessarily create a cache. `find_mergeable()` looks for an existing cache with compatible size, alignment and flags, and if it finds one the "new" cache is an alias sharing the same slabs. Two mergeable driver caches of the same size therefore hand each other's objects adjacency for free.

What they do *not* get is `kmalloc()` traffic. `slab_unmergeable()` in `mm/slab_common.c` rejects any cache with a non-zero `usersize`, and `create_kmalloc_cache()` passes `usersize = size` unconditionally for every `kmalloc-N`, so the general-purpose caches are permanently outside every merge set. On kernels from 6.2 that `usersize` test is wrapped in `#ifdef CONFIG_HARDENED_USERCOPY`, so strictly it is the hardened-usercopy build that makes it stick; Android GKI sets `CONFIG_HARDENED_USERCOPY=y`, and on 6.1 and earlier the test is unconditional, so on this target it holds either way. A second, independent mechanism produces the same outcome: `new_kmalloc_cache()` sets `refcount = -1` on the `KMALLOC_NORMAL` caches when `CONFIG_MEMCG_KMEM` is enabled, and `slab_unmergeable()` rejects a negative refcount too.

`SLAB_ACCOUNT` blocks merging from the other direction, by putting a cache in a different flag-compatibility class: this is why `cred_jar` stopped being reachable by a `kmalloc-192` overflow, and why attacking `struct cred` now requires a cross-cache approach, as in Will's [six-byte cross-cache overflow against cred](https://www.willsroot.io/2022/08/reviving-exploits-against-cred-struct.html).

The consequence for exploitation is narrower than "a driver bug is a `kmalloc-256` bug". A mergeable driver cache joins an anonymous merge set named for its size and flags — `:0000256` for a plain 256-byte cache, `:A-0000256` for a `SLAB_ACCOUNT` one, `:a-0000256` for `SLAB_RECLAIM_ACCOUNT`, per `create_unique_id()` in `mm/slub.c` — together with other mergeable driver caches. Generic `kmalloc()` sprays are not in that set. So the search is for a *sprayable object that lives in the same merge set*, and if there is none, the answer is cross-cache work at page granularity ([06-cross-cache-attacks.md](06-cross-cache-attacks.md)).

`/proc/slabinfo` hides all of this, because only one name from a merge set appears. The symlinks in `/sys/kernel/slab/` are where you read it, and on a kernel that merges at all — a desktop distribution, or any build with `CONFIG_SLAB_MERGE_DEFAULT=y` — the three commands below each support a different conclusion:

```
$ ls -l /sys/kernel/slab/ | grep -c -- '-> '
181                                    # this many caches are merged away
$ ls -l /sys/kernel/slab/ | grep -- '-> kmalloc'
                                       # empty: nothing merges into a kmalloc cache
$ ls -l /sys/kernel/slab/ | grep -- '-> :0000256'
biovec-16 -> :0000256
key_jar -> :0000256
sgpool-8 -> :0000256
xe_sched_job -> :0000256
```

The second command returning nothing is the load-bearing result: on any modern kernel it is empty, which is the `usersize` rule above observed rather than asserted. The third names the merge set a 256-byte mergeable cache actually joins, and its members are candidate spray vehicles for a bug in any one of them. `cat /sys/kernel/slab/:0000256/aliases` gives the same count numerically, but note that most files under `/sys/kernel/slab/` are mode 0400, so the symlink listing is the version that works from a normal uid while the `aliases` read is not.

A real directory rather than a symlink tells you the cache is isolated and that any adjacency you want must be manufactured at page granularity. `slab_nomerge` on the kernel command line disables merging globally, which is how you test on a merging kernel whether a technique depends on it (the boot parameter is listed in the [kernel parameter documentation](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html)).

### When nothing merges

On the target this tutorial is written against, every entry is a real directory. `slab_nomerge` is a `bool` in `mm/slab_common.c` initialized to `!IS_ENABLED(CONFIG_SLAB_MERGE_DEFAULT)`, and the arm64 `gki_defconfig` for `android14-6.1` carries `# CONFIG_SLAB_MERGE_DEFAULT is not set`. Merging is therefore off from the first cache creation onward, with no command-line argument involved; `slab_merge` is the only thing that turns it back on. Confirm it rather than inherit it:

```
$ zcat /proc/config.gz | grep SLAB_MERGE
# CONFIG_SLAB_MERGE_DEFAULT is not set
$ ls -l /sys/kernel/slab/ | grep -c -- '-> '
0
$ tr ' ' '\n' < /proc/cmdline | grep -E 'slab_(no)?merge'
```

A zero from the second command and no output from the third mean `find_mergeable()` returns `NULL` for every call, so `kmem_cache_create()` really does create a cache each time and every subsystem's objects sit alone in their own slabs.

That decides which of the recipes above still carry weight.

- The `usersize` and `refcount = -1` arguments stop being load-bearing. They explain why `kmalloc-N` resists merging on a kernel that merges at all; here nothing merges, so the conclusion they support — a generic `kmalloc()` spray cannot reach a dedicated driver cache — holds for a broader reason and needs no derivation from flags.
- The search for a same-merge-set spray vehicle has nothing to enumerate. For a bug in a dedicated cache, "which other cache shares these slabs" has one answer, none, and the decision goes straight to cross-cache work at page granularity ([06-cross-cache-attacks.md](06-cross-cache-attacks.md)). Reading the `/sys/kernel/slab/` symlinks is still how you establish that, but the expected result is an empty listing rather than a set to choose from, and an empty listing is a finding rather than a failed command.
- What remains is same-cache selection *within* the generic ladder, which merging never governed. When the vulnerable allocation is itself a `kmalloc()`, the victim and any vehicle from the object catalogue below share a cache whenever their sizes round to the same `kmalloc-N` and their accounting matches. The `kmalloc-cg` split and the `KMALLOC_MIN_SIZE` ladder derived above are what decide that pairing, and neither depends on merging.
- The merge-set reading still applies to published work and to lab machines. A write-up that reads `/sys/kernel/slab/:A-0000128` is working on a kernel where merging is on, as is a distribution kernel used as a reference device or a Cuttlefish image built from a defconfig that sets `CONFIG_SLAB_MERGE_DEFAULT`. Counts like the 181 above come from those, not from a phone, which is the usual reason a merge set named in a writeup cannot be found on the target.

## Freelist hardening, and what it actually stops

Two mainline changes shape what you can do to allocator metadata directly; two later ones change which cache you land in, which breaks the same techniques by a different route.

`CONFIG_SLAB_FREELIST_HARDENED` stores the free pointer obfuscated ([commit 2482ddec670f, "mm: add SLUB free list pointer obfuscation"](https://github.com/torvalds/linux/commit/2482ddec670fb83717d129012bc558777cb159f7), Kees Cook; the review thread is on [kernel-hardening](https://openwall.com/lists/kernel-hardening/2017/07/26/5)). `freelist_ptr()` in `mm/slub.c` computes it as:

```c
return (void *)((unsigned long)ptr ^ s->random ^
		swab((unsigned long)kasan_reset_tag((void *)ptr_addr)));
```

The byte swap is the part that makes the construction work rather than an implementation detail. `ptr` and `ptr_addr` are both slab-aligned addresses in the same slab, so they agree in their low bits; a plain `ptr ^ s->random ^ ptr_addr` would cancel those bits and expose the low bits of `s->random` directly to anyone who could read one stored freelist word. `swab()` moves `ptr_addr`'s low bits to the top of the word before the XOR, destroying the correlation. That is why it was added in 5.7 ([commit 1ad53d9fa3f6, "slub: improve bit diffusion for freelist ptr obfuscation"](https://github.com/torvalds/linux/commit/1ad53d9fa3f6168ebcf48a50e08b170432da2257)). The consequence stands: because the storage address is part of the key, the same pointer value encodes differently in different slots, a leaked value is not portable, and a blind overwrite corrupts the list into an unmapped address rather than a chosen one.

To observe it rather than take it on faith, confirm `CONFIG_SLAB_FREELIST_HARDENED=y` in `/proc/config.gz`, then on a test kernel free two objects of the same cache into different slots and read both stored words back through a spray whose read-back covers `s->offset`. The same `next` pointer appears as two unrelated values. The relocation of that word from the object's edge to its middle ([commit 3202fa62fb43, "slub: relocate freelist pointer to middle of object"](https://github.com/torvalds/linux/commit/3202fa62fb43087387c65bfa9c100feffac74aa6)) is the change that put it at the `s->offset` derived earlier, and it means a small linear overflow from the preceding object no longer reaches the pointer at all.

`CONFIG_SLAB_FREELIST_RANDOM` shuffles the initial free order of a newly created slab using a per-cache pre-computed sequence and a random starting position ([commit 210e7a43fa90, "mm: SLUB freelist randomization"](https://github.com/torvalds/linux/commit/210e7a43fa905bccafa9bb5966fba1d71f33eb8b), Thomas Garnier). It defeats the old plan of "allocate a fresh slab, assume object *i* neighbours object *i+1*". It does not touch the LIFO reuse order of freed objects, which is why the modern methodology is built on free-then-immediately-reclaim rather than on predicting positions in a virgin slab.

Two later mainline mechanisms attack the methodology from the other side. Neither touches LIFO reuse; both change which cache a call site lands in, which is enough to break a victim/attacker pairing outright.

- `CONFIG_RANDOM_KMALLOC_CACHES` (6.6, [commit 3c6152940584, "Randomized slab caches for kmalloc()"](https://github.com/torvalds/linux/commit/3c6152940584290668b35fa0800026f6a1ae05fe), GONG Ruiqi) creates `RANDOM_KMALLOC_CACHES_NR = 15` extra never-merged copies of each `kmalloc-N` alongside the original, and picks among the 16 by hashing the *caller's code address* against a per-boot seed. The choice is static per call site and re-randomized each boot. A free from the vulnerable subsystem and an allocation from your spray syscall are different call sites, so by default they no longer share a cache — and because the seed is per boot, you cannot pre-compute a call site that collides. The copies are named `kmalloc-rnd-01-64` and so on, so `ls /sys/kernel/slab/ | grep -c '^kmalloc-rnd'` is non-zero only when the feature is compiled in.
- `CONFIG_SLAB_BUCKETS` and `kmem_buckets` (6.11, [commit 67f2df3b82d0, "mm/slab: Plumb kmem_buckets into __do_kmalloc_node()"](https://github.com/torvalds/linux/commit/67f2df3b82d091ed095d0e47e1f3a9d3e18e4e41) and [commit b32801d1255b, "mm/slab: Introduce kmem_buckets_create() and family"](https://github.com/torvalds/linux/commit/b32801d1255be1da62ea8134df3ed9f3331fba12), Kees Cook) lets a subsystem request its own private set of `kmalloc-N` buckets. It defaults to on when `CONFIG_SLAB_FREELIST_HARDENED` is set. The first users are the classic universal sprays: [commit d73778e4b867](https://github.com/torvalds/linux/commit/d73778e4b86755d527a0c6b249cde846770b2f66) gives `memdup_user()` dedicated buckets, which covers `setxattr` and every other copy-a-user-buffer-into-the-kernel path, and [commit 734bbc1c97ea](https://github.com/torvalds/linux/commit/734bbc1c97ea7e46e0e53b087de16c87c03bd65f) does the same for `alloc_msg()`. Where these are enabled, a user-controlled buffer and a kernel object of the same size no longer share slabs.

Check what your target actually enables rather than assuming:

```
$ zcat /proc/config.gz | grep -E 'SLAB_FREELIST|SLAB_MERGE|HARDENED_USERCOPY|SLAB_BUCKETS|RANDOM_KMALLOC'
```

`/proc/config.gz` exists only with `CONFIG_IKCONFIG_PROC`; Android GKI usually has it. Without it, the published defconfig for the matching GKI branch is the fallback, and `strings` over the kernel image plus the banner in `dmesg` identifies which branch that is (patch identification is covered in [01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md)).

## The grooming sequence

The general method, independent of bug class:

1. Choose a victim/attacker pair in the same cache. The victim is the object the bug corrupts or frees; the attacker object is one whose contents you control and whose corruption is useful. They must be size-compatible, GFP-compatible, and both reachable from your privilege level.
2. Quiet and warm the cache. Allocate enough attacker objects that partial slabs are full and the next allocation comes from a predictable place. This is defragmentation: you are removing the kernel's pre-existing holes so that yours are the only ones left.
3. Create the hole. Free the victim (or let the bug free it), ideally pinned to one CPU so the object lands at the head of that CPU's freelist.
4. Reclaim. Allocate attacker objects immediately, in the same context, with content chosen so that the object is self-identifying.
5. Verify before you act. Read back which sprayed object changed. A spray that cannot be read back turns a probabilistic placement into a blind write, and a blind write into a stranger's memory is a delayed panic rather than a clean failure.

Step 5 is what separates the published exploits that work from the ones that work sometimes. In the corCTF *Fire of Salvation* [writeup](https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html), the sprayed `msg_msg` reports its own corruption: inflating `m_ts` makes a subsequent `MSG_COPY` read return neighbouring memory, so the exploit learns both that it hit and what it hit.

`MSG_COPY` itself is conditional, which makes this the step most likely to be missing on a real target. `prepare_copy()` in `ipc/msg.c` sits inside `#ifdef CONFIG_CHECKPOINT_RESTORE`; without that option `msgrcv(..., MSG_COPY)` returns an error instead of data, so the verification never runs. `CONFIG_CHECKPOINT_RESTORE` is absent from the arm64 `gki_defconfig`, so on an Android target assume it is off until `zcat /proc/config.gz | grep CHECKPOINT_RESTORE` says otherwise. Where it is off, the non-destructive read-back has to come from elsewhere: receive the message destructively and give up re-use of that object, or pick a vehicle whose read-back is unconditional — a keyring payload read with `keyctl_read(2)`, or an anon VMA name read out of `/proc/self/maps`.

Page-level shaping obeys the same measure-then-act rule. Andrey Konovalov's [packet socket exploit](https://projectzero.google/2017/05/exploiting-linux-kernel-via-packet.html) for CVE-2017-7308 allocates 512 `packet_sock` objects to exhaust `kmalloc-2048`, drains the buddy allocator with 1024 order-3 blocks, then places the ring buffer and forces a *fresh* slab so that a `packet_sock` lands immediately after it. Will's cred overflow grooms the buddy allocator directly: drain `cred_jar` by forking, allocate a thousand order-0 pages, free alternate ones to fragment, then spray `clone()`d creds into the resulting gaps.

## The object catalogue

The vehicles below recur because each controls size, content, or lifetime in a way generic allocations do not.

- `msg_msg` (System V messages). Elastic across the whole ladder from `kmalloc-cg-64` to `kmalloc-cg-4k`, chained through `msg_msgseg` for larger payloads, with the 48-byte kernel-written header derived above. Content is yours after the header, and lifetime is yours, since a queued, unread message persists. Accounted since 5.14, so it lives in `kmalloc-cg-*` and cannot be paired with an unaccounted victim. The non-destructive `MSG_COPY` read-back is conditional on `CONFIG_CHECKPOINT_RESTORE`, as above.
- `pipe_buffer` arrays. `pahole -C pipe_buffer /sys/kernel/btf/vmlinux` gives the element size and the reason for it: `page` (8), `offset` and `len` (4 each), `ops` (8), `flags` (4), a 4-byte hole, `private` (8) — "size: 40, ... sum holes: 4". Both allocation sites use `GFP_KERNEL_ACCOUNT` (`alloc_pipe_info()` and `pipe_resize_ring()` in `fs/pipe.c`), so since 5.14 the array lands in `kmalloc-cg-*`, not the unaccounted family — the same split described above for `msg_msg`, and the reason a `kmalloc-192` victim can never be paired with a `pipe_buffer` spray. The derivation: a default pipe holds 16 entries, `16 * 40 = 640` bytes, so `kmalloc-cg-1k`; `fcntl(fd, F_SETPIPE_SZ, ...)` moves it, with two pages giving `2 * 40 = 80` bytes — `kmalloc-cg-96` on x86, but `kmalloc-cg-128` on the arm64 GKI 6.1 ladder derived above, which has no 96-byte cache — and four pages giving 160 bytes, `kmalloc-cg-192`. Alexander Popov's [measurements](https://a13xp0p0v.github.io/2026/04/20/pipe-buffer-experiments.html) document two operational hazards. The per-user soft page limit, `PIPE_DEF_BUFFERS * INR_OPEN_CUR` = `16 * 1024` = 16384 pages and readable at `/proc/sys/fs/pipe-user-pages-soft`, means that after roughly 16384/16 = 1024 default-size pipes the kernel silently creates subsequent ones smaller, so a spray's size targeting quietly degrades unless each pipe is resized immediately after creation. And closing a pipe whose `page` pointer you corrupted returns a foreign page to the allocator, so a corrupted pipe must never be closed. Corrupting `page`/`offset`/`len` yields read and write, which [Interrupt Labs](https://www.interruptlabs.co.uk/articles/pipe-buffer) describes in detail and [07-read-write-primitives.md](07-read-write-primitives.md) takes up.
- `sk_buff` data buffers. A datagram queued on a unix socket pair and never read holds a `kmalloc`ed buffer with your bytes in it; reading it frees the buffer and undoes the placement. The size you request is not the size allocated — `skb_shared_info` sits at the tail of the same allocation — so derive the effective object size from the target kernel rather than from the `send()` length. Google's [CVE-2021-22555 writeup](https://github.com/google/security-research/blob/master/pocs/linux/cve-2021-22555/writeup.md) uses exactly this to forge `msg_msg` headers and then `pipe_buffer` objects at the same address.
- `setxattr`. Arbitrary size, fully controlled content, no kernel-written header — the ideal spray in every respect but one: the allocation is freed before the syscall returns. Vitaly Nikolenko's [universal heap spray](https://duasynt.com/blog/linux-kernel-heap-spray) fixes that by placing the user buffer across a page boundary and registering `userfaultfd` on the second page, so `copy_from_user()` stalls mid-copy and the allocation is held for as long as the fault handler sleeps.
- `add_key` / `user_key_payload`. A keyring payload holds your bytes behind a fixed header, and it persists until the key is revoked, which is the property you want when a freed object must *stay* occupied. `pahole -C user_key_payload /sys/kernel/btf/vmlinux` gives the header exactly: `callback_head rcu` at 0 (16 bytes), `unsigned short datalen` at 16, a 6-byte hole forced by the `__aligned(8)` on the flexible array, and `data[]` at 24 — "size: 24". So a payload of `datalen = N - 24` bytes fills `kmalloc-N` precisely: 232 bytes for `kmalloc-256`, 1000 for `kmalloc-1k`. Read it back with `keyctl_read(2)`, which `key_type_user` supports unconditionally (`key_type_logon` deliberately does not). The limits are the per-user quotas, readable rather than guessed: `/proc/sys/kernel/keys/maxkeys` and `maxbytes`, with current consumption in `/proc/key-users`. On Android, `add_key` is denied to several app domains by SELinux policy, so check reachability first ([02-reachability-and-attack-surface.md](02-reachability-and-attack-surface.md)).
- `prctl(PR_SET_VMA_ANON_NAME)`. Described by Cherie-Anne Lee in [prctl anon_vma_name: An Amusing Linux Kernel Heap Spray](https://starlabs.sg/blog/2023/07-prctl-anon_vma_name-an-amusing-linux-kernel-heap-spray/) (STAR Labs, July 2023). `anon_vma_name_alloc()` in `mm/madvise.c` allocates `struct_size(anon_name, name, strlen + 1)` with plain `GFP_KERNEL`, and `pahole -C anon_vma_name` shows the header is a single 4-byte `kref`, so the allocation is `4 + strlen + 1`. Two constraints decide whether it is usable at all. `kernel/sys.c` caps the name at `ANON_VMA_NAME_MAX_LEN = 80` including the terminator, and rejects any byte outside printable ASCII, additionally excluding the characters in `ANON_VMA_NAME_INVALID_CHARS` (`\`, backtick, `$`, `[`, `]`). So the vehicle tops out at 84 bytes and cannot carry NUL bytes or kernel pointers — only printable text. `CONFIG_ANON_VMA_NAME` is the prerequisite; Android GKI sets it. On the arm64 GKI 6.1 ladder that size range covers `kmalloc-64` and `kmalloc-128` and nothing else, and its actual advantage over `msg_msg` there is not that it is smaller but that it is *unaccounted*, reaching `kmalloc-64`/`-128` where `msg_msg` can only reach `kmalloc-cg-64`/`-128`. The content is readable back through `/proc/self/maps`, which makes it one of the few vehicles with an unconditional read-back. It is cited as motivation for the `kmem_buckets` work described under freelist hardening above.

`userfaultfd` and FUSE belong in a different category: they do not spray, they *pace*. Both let userspace stall a kernel thread inside `copy_from_user()`, which widens a race window or freezes an allocation mid-flight — the mechanism behind the `setxattr` trick above.

The restriction that killed the `userfaultfd` version is specific. `UFFD_USER_MODE_ONLY` ([LWN](https://lwn.net/Articles/835373/)) registers a region that handles user-mode faults *only*, and explicitly refuses to handle a fault taken in kernel mode. A `copy_from_user()` stall is by definition a kernel-mode fault, so under that flag the stall the technique depends on never reaches your handler; the fault fails instead. Together with the `vm.unprivileged_userfaultfd` sysctl gating access at all, that is why a FUSE filesystem whose read handler simply sleeps has replaced it as the general-purpose stall ([FUSE for Linux Exploitation 101](https://exploiter.dev/blog/2022/FUSE-exploit.html)): the kernel blocks waiting on your userspace daemon, with no fault-mode distinction to trip over.

Check both directly. `sysctl vm.unprivileged_userfaultfd` returns 0 when unprivileged use is off. For FUSE on Android, the question is whether SELinux policy lets your domain open `/dev/fuse`, and that is answered off the device: SETools is not present on Android, so pull the binary policy to a workstation and query it there.

```
$ adb shell su -c 'cat /sys/fs/selinux/policy' > policy
$ sesearch --allow -s untrusted_app -t fuse_device -c chr_file policy
allow untrusted_app fuse_device:chr_file { read write open ioctl ... };
```

The dump step is the fragile one. `sel_open_policy()` checks `security { read_policy }` against `SECINITSID_SECURITY`, so a root shell in a domain that lacks that permission gets `EACCES` regardless of uid, which is the normal case on a production build. The fallbacks are the precompiled binary policy shipped on the image and, where the vendor ships none, a CIL recompile of the same fragments init compiles at boot; [02-reachability-and-attack-surface.md](02-reachability-and-attack-surface.md) owns both, including the exact paths and `secilc` invocation. `sesearch` comes from the `setools` package and needs the object class, since without one the query matches nothing useful. A matching rule means the open will pass MAC (DAC on `/dev/fuse` still applies); no output means it will not. With no policy in hand at all, the unprivileged equivalent is to attempt the `open()` and read the resulting `avc: denied` line out of `logcat` or `dmesg`. Race pacing proper is [08-triggering-races-reliably.md](08-triggering-races-reliably.md).

## Tuning pressure rather than maximizing it

A spray has two failure modes and they pull in opposite directions.

Too little pressure and the target memory is never yours: the freed object gets taken by unrelated kernel activity and the partial slab never empties. Where the technique needs a whole slab page returned to the buddy allocator, a live object on the page is only one of three reasons it can stay put, and not the usual one. A slab with zero live objects is still not freed while it is the CPU's active slab; while it sits frozen on the per-CPU partial list, since `put_cpu_partial()` defers `__unfreeze_partials()` until `cpu_partial_slabs` is exceeded; or while the node partial list is still at or below `min_partial`, where `discard_slab()` is never reached. Groom a slab to zero live objects and see no page released, and one of those three is why.

The thresholds are readable — `cat /sys/kernel/slab/<cache>/{cpu_partial,min_partial}` — and [06-cross-cache-attacks.md](06-cross-cache-attacks.md) derives both formulas from `set_cpu_partial()` and walks the `put_cpu_partial()` → `__unfreeze_partials()` → `discard_slab()` path in full. Confirm that a page actually left by sampling `/proc/buddyinfo` before and after the drain, rather than inferring it from the free count.

Too much pressure and you destroy the conditions you need. `MemAvailable` is a heuristic estimate exported for userspace and triggers nothing; reclaim runs off watermarks. `kswapd` wakes when a zone's free pages fall below its `low` watermark, and direct reclaim happens in the allocating task itself when an allocation cannot be satisfied above `min`. Reclaim evicts file-backed pages, and the exploit's own text is file-backed, so a spray sized to the last megabyte can fault the exploit out of memory in the middle of the window it built. On Android, the low-memory killer reaches your process before the kernel OOM killer does. And every allocation you make is noise in the same allocator you are trying to predict, so a larger spray is a less precise one.

Each of those is observable. `/proc/zoneinfo` gives per-zone `free` against `min`, `low` and `high`, which is the comparison that actually decides reclaim. `pgscan_direct` and `pgsteal_direct` in `/proc/vmstat` rising across the spray is evidence that direct reclaim ran in your own task rather than in `kswapd`, and `/proc/pressure/memory` gives the stall signal. For self-eviction specifically, watch `majflt` — field 12 of `/proc/self/stat` — during the spray: a rising major-fault count means the exploit's own pages are being evicted and faulted back in. `mlock()` is the obvious escape and is generally not available; check `ulimit -l`, or `Max locked memory` in `/proc/self/limits`, which is 64 KB on this project's target and so cannot protect a spray of any useful size.

These are not the same knob at different settings. Releasing a slab page back to the buddy allocator requires *quiet* — no other allocation from that cache during the drain — while reclaiming the released page requires *pressure*. A single "spray harder" parameter cannot satisfy both, which is why cross-cache sequences separate the two phases explicitly.

Measure rather than guess. The instruments are cheap and mostly unprivileged:

```
$ grep -E 'MemAvailable|MemFree' /proc/meminfo
$ cat /proc/buddyinfo
Node 0, zone   Normal   1823   1104    412    121     33     9    2    0   0   0   0
```

[/proc/buddyinfo](https://man7.org/linux/man-pages/man5/proc_buddyinfo.5.html) gives, per zone, the count of free blocks at each order — column *i* is the number of free `2^i * PAGE_SIZE` blocks. Sample it before, during and after a spray: the order-0 column collapsing while higher orders hold means you are consuming from existing free lists; higher-order columns going to zero means you have fragmented the zone and an order-3 slab allocation will now fail or trigger compaction. Judge those counts against the watermarks in `/proc/zoneinfo` and the PSI stall percentages in `/proc/pressure/memory` (`CONFIG_PSI`), which together mark the crossing from "allocating" into "causing reclaim". Size the spray to leave headroom above the low watermark rather than to a constant, and re-derive that budget at run time — the right number on a 4 GB device is wrong on a 12 GB one. [06-cross-cache-attacks.md](06-cross-cache-attacks.md) takes the page allocator's own structures, including `/proc/pagetypeinfo` and the per-CPU page lists, further than this section needs.

For timing rather than capacity, PSPRAY ([Lee et al., USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/lee-yoochan)) shows that allocation latency leaks allocator state: the allocation that exhausts a slab and forces a new one from the page allocator is measurably slower than the ones before it. Timing your own probe allocations tells you where in a slab you are, so the vulnerable object can be placed deliberately instead of hopefully. The paper reports success rates across ten real vulnerabilities rising from 56.1% to 97.92% on average. The same principle applies to any grooming step you can instrument: turning "assume it worked" into "measure whether it worked" is the subject of [10-survivability-and-measurement.md](10-survivability-and-measurement.md).

Where root is available on a test device, the ground truth is a tracepoint rather than an inference. `/sys/kernel/tracing/events/kmem/` carries `kmalloc`, `kmem_cache_alloc`, `kfree` and `mm_page_alloc`; the filtered `kmem/kmalloc` example above shows the actual allocations a spray produces and the ones the kernel makes alongside them.

To aggregate rather than stream, use the tracepoint again rather than a kprobe on `kmem_cache_alloc`. The two do not see the same traffic: on 6.1, `kmalloc()` reaches the allocator through `__kmalloc`, `__kmalloc_node` and `kmalloc_trace` in `mm/slab_common.c`, not through `kmem_cache_alloc` in `mm/slub.c`, so a probe on `kmem_cache_alloc` counts dedicated-cache allocations only and reports nothing at all for every `kmalloc`-based spray in this section — a silent zero that reads like "my spray is not allocating".

```
# bpftrace -e 'tracepoint:kmem:kmalloc { @[args.bytes_alloc] = count(); }'
Attaching 1 probe...
^C
@[128]: 1204
@[192]: 3310
@[1024]: 8192      <- the pipe_buffer spray
```

The size histogram is the conclusion: 8192 allocations of `bytes_alloc=1024` is the 8192-pipe spray landing where it was aimed, and the counts at other sizes are the concurrent kernel noise the groom competes with. Prerequisites are root, `CONFIG_BPF_SYSCALL`, and BTF if you add struct field accesses; to cover dedicated caches as well, add `kprobe:kmem_cache_alloc` and `kprobe:__kmalloc` as separate probes and keep straight which call paths each one sees. None of this is available on a locked device at low privilege, but it is how a grooming strategy gets validated on an unlocked one before it is shipped blind — and a kprobe with a memory-dereference argument ([kprobetrace](https://docs.kernel.org/trace/kprobetrace.html)) is the fallback read primitive when debugfs and `/proc/kallsyms` are restricted, which [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) develops.

For catching the corruption itself on a debug build, KASAN gives precise reports with allocation and free stacks; KFENCE ([documentation](https://docs.kernel.org/dev-tools/kfence.html)) is the sampling variant designed to be enabled in production kernels, and `gki_defconfig` does enable it (`CONFIG_KFENCE=y`, `CONFIG_KFENCE_SAMPLE_INTERVAL=500`), so a `BUG: KFENCE: use-after-free` in a device log is a real signal that your grooming freed something you did not intend to. The counters at `/sys/kernel/debug/kfence/stats` are a different matter: they need `CONFIG_DEBUG_FS` and a mounted debugfs, and production Android has neither, so on a target the report in `dmesg` or pstore is the only KFENCE output you will see. Reading those reports is [03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md).

## Instruments

- `cat /proc/slabinfo`, `slabtop -s c` — cache inventory: object size, `objperslab`, `pagesperslab`, as defined in [slabinfo(5)](https://man7.org/linux/man-pages/man5/slabinfo.5.html). Root only; unavailable to a shell or app uid on Android.
- `cat /sys/kernel/slab/<cache>/{object_size,objs_per_slab,order,cpu_partial,aliases}` — per-cache geometry and merge count, defined in `Documentation/ABI/testing/sysfs-kernel-slab`. Needs `CONFIG_SYSFS` with SLUB sysfs support built in and sysfs mounted; most files are mode 0400, so root.
- `ls -l /sys/kernel/slab/ | grep -- '-> '` — which caches are aliases of which, readable without root because it is the symlinks and not their contents. Empty on GKI, where `# CONFIG_SLAB_MERGE_DEFAULT is not set` leaves `slab_nomerge` true; `zcat /proc/config.gz | grep SLAB_MERGE` is the direct check. `slabinfo -a` reports the same merge sets but is a userspace tool built out of tree from `tools/mm/slabinfo.c` and is not present on a device; read the symlinks directly there.
- `pahole -C <struct> /sys/kernel/btf/vmlinux` — one struct's size, member offsets and padding, for the exact running kernel. World-readable with `CONFIG_DEBUG_INFO_BTF`, which Android GKI sets. `pahole` takes an ELF or BTF file, not a C header.
- `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` — generates a C header for compiling BPF programs against the running kernel. Not an input to `pahole`.
- `drgn` with `drgn.helpers.linux.slab` (`find_slab_cache`, `slab_object_info`) — live walk of caches and per-object allocation state. Needs root, `CONFIG_PROC_KCORE` and a DWARF `vmlinux` matching the build; `CONFIG_PROC_KCORE` is absent from the arm64 `gki_defconfig` and GKI images ship no DWARF, so this is a reference-device instrument. On a locked target, derive offsets from BTF and confirm them with a kprobe read ([04](04-kaslr-and-information-leaks.md)).
- `crash -S vmlinux vmcore`, `kmem -S <cache>` — the same picture from a crash dump. Needs a dump and a `vmlinux` with symbols.
- `zcat /proc/config.gz | grep -E 'SLAB_|RANDOM_KMALLOC|CHECKPOINT_RESTORE'` — which hardening options and optional features are compiled in. Needs `CONFIG_IKCONFIG_PROC`; otherwise use the matching published defconfig, naming the branch so the result can be re-checked.
- `ls /sys/kernel/slab/ | grep -c '^kmalloc-rnd'` — non-zero only when `CONFIG_RANDOM_KMALLOC_CACHES` is built in. `ls /sys/kernel/slab/ | grep '^kmalloc-cg-'` — empty means the accounted and unaccounted families are aliased.
- `ls /sys/kernel/slab/ | grep '^kmalloc-' | sort -t- -k2 -n` — the actual `kmalloc` ladder on this target, which is architecture- and version-dependent.
- `cat /proc/buddyinfo`, `/proc/zoneinfo`, `/proc/vmstat`, `/proc/pressure/memory` — free blocks by order; per-zone `free` against `min`/`low`/`high`; `pgscan_direct`/`pgsteal_direct` as evidence direct reclaim ran; PSI stall percentages. Usually unprivileged; SELinux policy may restrict on Android.
- `awk '{print $12}' /proc/self/stat`, `/proc/self/limits` — major faults taken during a spray (self-eviction), and whether `mlock` has any headroom to prevent it.
- `echo 1 > /sys/kernel/tracing/events/kmem/kmalloc/enable; cat /sys/kernel/tracing/trace_pipe` — every kmalloc with `call_site`, `bytes_req`, `bytes_alloc`, `gfp_flags` and the derived `accounted=`. Root, tracefs mounted; filter on `bytes_req` first.
- `bpftrace -e 'tracepoint:kmem:kmalloc { @[args.bytes_alloc] = count(); }'` — allocation size histogram covering the `kmalloc` path. Root plus `CONFIG_BPF_SYSCALL`; BTF only if you dereference structs. A `kprobe:kmem_cache_alloc` sees dedicated caches only and reports zero for `kmalloc` traffic.
- `/sys/kernel/tracing/kprobe_events` with `+OFFS($arg1)` fetch syntax — read memory at a probe point when no debugger is available. Root.
- `sysctl vm.unprivileged_userfaultfd`; `adb shell su -c 'cat /sys/fs/selinux/policy' > policy` then `sesearch --allow -s <domain> -t fuse_device -c chr_file policy` — whether the stall primitives are reachable from your privilege level. `sesearch` comes from `setools` and runs on a workstation, not on the device, and needs an object class. The dump is gated by `security { read_policy }` and commonly fails even as root; use the image's precompiled policy or a CIL recompile instead ([02](02-reachability-and-attack-surface.md)), or attempt the open and read the `avc: denied` line from `logcat` or `dmesg`.
- `vmlinux-to-elf` (`vmlinux-to-elf boot.img vmlinux.elf`) — recover a symbolized ELF from a stripped or compressed Android kernel image, so `objdump -d` can show an allocation site's GFP flags. No target privilege; operates on the image.
- KASAN reports in `dmesg` — needs a debug build. KFENCE is on in production GKI (`CONFIG_KFENCE=y`) and reports through `dmesg` and pstore; its `/sys/kernel/debug/kfence/stats` counters need `CONFIG_DEBUG_FS` and a mounted debugfs, which production Android does not have.

## Grounded in this project

The spray vehicles described above are implemented as parameterized modules under `cves/lib/spray/`: `keyspray.h`/`keyspray.c` (keyring payloads, for reclaims that must stay occupied), `skbspray.h` (queued unread unix datagrams), `notifyspray.h` (filesystem-notification events, which reach small caches that message queues cannot, and which must be drained continuously rather than fired once), `sockpool.h` (the phased fill/hole/refill pool, sprayed in parallel across CPUs), and `physspray.h` with `forge_place.h` (linear-map spraying, where the budget is computed from free memory at run time for exactly the headroom reason described above). `cves/lib/addr/zoneguess.h` encodes where an unprivileged process's locked pages actually cluster, and `cves/lib/rw/slabpage.h` is the verify-before-you-write check that turns a hoped-for placement into a confirmed one.

## See also

- [01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md) — identifying the kernel build whose layout you are deriving
- [02-reachability-and-attack-surface.md](02-reachability-and-attack-surface.md) — whether a given spray syscall is reachable from your domain at all
- [03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md) — reading the panic a mis-aimed spray produces
- [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) — reading back sprayed content to recover addresses
- [06-cross-cache-attacks.md](06-cross-cache-attacks.md) — when the victim and attacker objects cannot share a cache
- [07-read-write-primitives.md](07-read-write-primitives.md) — what the reclaimed object is turned into
- [08-triggering-races-reliably.md](08-triggering-races-reliably.md) — pacing with userfaultfd and FUSE
- [09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md) — why `cred_jar` isolation shapes the grooming above
- [10-survivability-and-measurement.md](10-survivability-and-measurement.md) — measuring spray hit rates instead of assuming them
- [11-case-studies.md](11-case-studies.md) — grooming sequences in full context
- [12-further-reading-and-glossary.md](12-further-reading-and-glossary.md) — allocator terminology
