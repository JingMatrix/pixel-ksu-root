# Cross-Cache Attacks

A use-after-free is only as useful as the object that lands in the freed slot. The classical
technique — free the vulnerable object, immediately allocate something interesting of the same
size, and let the allocator hand back the same address — depends on an assumption that modern
kernels work hard to break: that the attacker can get an *interesting* object into the *same*
kmem_cache as the *vulnerable* one. When the vulnerable object lives in a dedicated cache with
nothing worth corrupting in it, or when accounting has split the generic caches so that the
sprayable object sits in `kmalloc-cg-256` while the bug is in `kmalloc-256`, same-cache reuse
has nowhere to go.

The way out is to stop working at the object level. Slab caches do not own memory permanently;
they borrow pages from the page allocator and give them back when a slab is completely empty.
If the page holding the dangling pointer's object is returned to the buddy allocator and then
handed to a *different* cache — or to a subsystem that allocates raw pages — the dangling
pointer now overlaps whatever the new owner put there. The object type at the far end of the
pointer changes; the bug does not. That exchange is the cross-cache attack, and the unit of
exchange is the page rather than the object slot.

The systematization in CROSS-X (CCS 2025) — [free
PDF](https://hacking.kaist.ac.kr/pubs/2025/kim:crossx.pdf), formally
[10.1145/3719027.3765152](https://dl.acm.org/doi/10.1145/3719027.3765152), which the ACM
Digital Library serves only to browsers — states the causal chain plainly: cache separation
moved the useful objects out of reach, and cross-cache attacks are the response, exploiting
"the internal mechanism of physical page recycling in the page allocator — a subsystem beneath
the SLUB allocator." Public exploits reached this conclusion first, by necessity. Jann Horn's
[2021 Project Zero writeup](https://projectzero.google/2021/10/how-simple-linux-kernel-memory.html)
walks through draining SLUB's per-CPU structures to push a `struct pid` page back to the page
allocator; Seth Jenkins' [CVE-2022-42703
analysis](https://projectzero.google/2022/12/exploiting-CVE-2022-42703-bringing-back-the-stack-attack.html)
frees every object on an `anon_vma` slab page and reclaims it with sprayed pipe buffers; the
[CVE-2022-29582 writeup](https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/)
converts a `filp` slab page into `kmalloc-512`.

## Reading the configuration off the device, not off the defconfig

Almost every statement below about how the target behaves is a statement about how it was
built. The published `gki_defconfig` is evidence about the GKI *branch*; a vendor kernel is that
branch plus fragments, and the shipped image is the only authority on itself. Check it:

```
zcat /proc/config.gz | grep -E 'SLAB_MERGE|SLAB_FREELIST|SHUFFLE_PAGE|RCU_NOCB|RCU_LAZY|RCU_TRACE|KFENCE|KASAN|DEBUG_INFO_BTF|PAGE_OWNER|SLUB_DEBUG|SLUB_STATS|CONFIG_CMA'
```

This depends on `CONFIG_IKCONFIG_PROC`, which android14-6.1's arm64
[gki_defconfig](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/configs/gki_defconfig)
sets alongside `CONFIG_IKCONFIG`. `kernel/configs.c` creates the file with `S_IFREG | S_IRUGO`,
so it is world-readable: this is one of the few allocator-relevant instruments an unprivileged
Android shell gets for free.

A defconfig cannot answer the runtime half at all, because several of these are switched by the
boot command line rather than by the build:

```
cat /proc/cmdline
```

`rcu_nocbs=`, `rcutree.enable_rcu_lazy=`, `page_owner=on`, `kasan.mode=`, `slab_nomerge` and
`slub_debug=` all appear here, and where the two sources disagree the command line wins. Run
both before trusting any claim in this section on a particular device.

## Knowing which caches you are between

Cache identification — which cache a given allocation lands in, how to recover a struct's layout
from BTF, how the `kmalloc-cg-*` split works, and whether the kernel merges caches at all — is
the subject of [05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md), and its
`pahole` and symlink recipes are the ones to use. Two numbers matter here that do not matter
there: how many objects fill one slab, and what page order that slab occupies. Both decide the
shape of the groom.

With root, `/proc/slabinfo` gives them per cache:

```
# cat /proc/slabinfo
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables ...
kmalloc-256              2624       2656      256          32             2 : tunables ...
```

The two load-bearing fields on that row are `objperslab` = 32 and `pagesperslab` = 2: filling
one slab of this cache takes 32 allocations, and the slab is a two-page run, so order 1. The
columns are defined in [slabinfo(5)](https://man7.org/linux/man-pages/man5/slabinfo.5.html) and
emitted by `print_slabinfo_header()`/`cache_show()` in
[mm/slab_common.c](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/mm/slab_common.c).
Read them off the row for your victim cache rather than from any writeup, since both vary with
kernel version, config and architecture.

The privilege is worth stating precisely, because two different failures look similar. The whole
`/proc/slabinfo` block in `mm/slab_common.c` (lines 1163-1312) is guarded by
`#if defined(CONFIG_SLAB) || defined(CONFIG_SLUB_DEBUG)`, and inside it `SLABINFO_RIGHTS` is
`0600` under `#ifdef CONFIG_SLAB` and `0400` otherwise. The write bit belongs to the SLAB
allocator's tunable-writing interface, not to SLUB debugging. On a SLUB kernel — every Android
GKI target this section addresses — the file is mode 0400: root-readable, never writable. On a
kernel built with neither `CONFIG_SLAB` nor `CONFIG_SLUB_DEBUG` the file is not created at all.
So `Permission denied` means the file exists and you lack root, while `No such file or
directory` means the kernel does not expose slab statistics at all and no privilege will change
that.

`/sys/kernel/slab/<cache>/` exposes the same geometry one value per file — `object_size`,
`slab_size`, `order`, `objs_per_slab`, `cpu_partial`, `min_partial`, `partial`, `cpu_slabs`.
GKI builds sysfs, so a missing directory is not a config question: the read files are declared
`SLAB_ATTR_RO(...)`, which expands to `__ATTR_RO_MODE(_name, 0400)` in
[mm/slub.c](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/mm/slub.c),
and `min_partial` and `cpu_partial` are `SLAB_ATTR(...)` = `__ATTR_RW_MODE(_name, 0600)`. What
stands between a shell uid and these files is the 0400 mode plus SELinux, not a missing
`CONFIG_SYSFS`. Treat a failed read as an SELinux and privilege result, and check whether the
directory is *listable* before concluding anything about the build.

If neither interface is readable, part of the derivation can be done offline and part cannot.
BTF gives you `s->object_size` — the size the cache was created with — and, for an object with
no dedicated cache, which `kmalloc-*` bucket that size falls into. It does not give you the
stride objects actually sit at, and it does not give you the slab's page order.

```
adb pull /sys/kernel/btf/vmlinux vmlinux.btf
pahole -C struct_name vmlinux.btf
```

(`bpftool btf dump file vmlinux.btf format c` generates a C header and is a different tool for a
different job; `file` there is the bpftool subcommand, not a struct name. 05 covers the
distinction and carries a worked `pahole` capture.) The `size:` line is the answer BTF gives.
For `msg_msg` that capture reads `/* size: 48, cachelines: 1, members: 5 */` under a member list
of five offsets and no holes. Forty-eight is `object_size`; a 48-byte `kmalloc` lands in
`kmalloc-cg-64`, whose stride is 64, so even in the simplest case the number BTF gives you and
the number a groom needs differ.

Getting from `object_size` to `s->size` is two alignment steps in `calculate_sizes()`:
`size = ALIGN(size, sizeof(void *))` first, then `size = ALIGN(size, s->align)`, where `s->align`
comes from `calculate_alignment()` in `mm/slab_common.c` and is at least `arch_slab_minalign()`.
A cache created with `SLAB_HWCACHE_ALIGN` takes `max(align, cache_line_size())`, which on arm64
rounds the stride up to 64 or 128 bytes; `filp_cachep` is created exactly that way in
[fs/file_table.c](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/fs/file_table.c)
(`kmem_cache_create("filp", sizeof(struct file), 0, SLAB_HWCACHE_ALIGN | SLAB_PANIC |
SLAB_ACCOUNT, NULL)`), so `sizeof(struct file)` is materially smaller than the distance between
two `struct file`s. Redzone, poison and track padding add more whenever `slub_debug` is active
for that cache.

The page order cannot be derived from the struct at all. `calculate_order()` depends on
`num_present_cpus()` at cache-creation time and on the `slub_min_objects` and `slub_max_order`
boot parameters, so it must be read rather than computed:
`cat /sys/kernel/slab/<cache>/{object_size,slab_size,order,objs_per_slab}` on a rooted device of
the same model, or the `pagesperslab` column of `/proc/slabinfo`. A BTF-only derivation gives a
lower bound on the stride and nothing at all about the order.

The two SLUB tuning parameters come from the source for the exact kernel you are attacking, and
both changed across versions. In 6.1, `set_cpu_partial()` picks a number of *objects* purely
from object size — 6 when `s->size >= PAGE_SIZE`, 24 at `>= 1024`, 52 at `>= 256`, otherwise
120 — and `min_partial` is `ilog2(s->size) / 2` clamped between `MIN_PARTIAL` (5) and
`MAX_PARTIAL` (10). What that object count becomes is the subject of the reservation arithmetic
below, and is the single most common way a groom copied from an older writeup misfires.

One Android-specific consequence of the defconfig is worth extracting here: it contains
`# CONFIG_SLAB_MERGE_DEFAULT is not set`, and `slab_nomerge` is initialized as
`!IS_ENABLED(CONFIG_SLAB_MERGE_DEFAULT)`, so caches are not merged on GKI. On a desktop
distribution where merging is on, one generic cache may serve several kernel structures at once
and same-cache reuse is cheap; on Android that shortcut is gone, which pushes more bugs onto the
cross-cache path in the first place. 05 covers how to read merge sets out of the
`/sys/kernel/slab/` symlinks, which is also why Horn's post reads `/sys/kernel/slab/:A-0000128`.

## Getting the page out of the cache

SLUB does not return a page to the buddy allocator merely because its objects are free. Which of
four things happens on a free depends on where the slab is, and only two of the four ever reach
`discard_slab()`. The decision is made in `__slab_free()`, `put_cpu_partial()` and
`__unfreeze_partials()` in mm/slub.c:

1. Free into the currently active slab, `c->slab`, on the same CPU. The object is pushed onto
   `c->freelist` and the page never moves. This is the fast path and the one a naive "allocate
   many, free many" groom mostly hits.
2. Free into a slab already parked on the per-CPU partial list. Those slabs are *frozen*, so
   `__slab_free()` takes the `was_frozen` branch, records `stat(s, FREE_FROZEN)` and returns.
   Emptying such a slab completely does nothing at all until something unfreezes it.
3. Free the *first* object of a *full* slab. `new.inuse` is still non-zero but `prior` is NULL,
   so the condition `(!new.inuse || !prior) && !was_frozen` holds, and with
   `kmem_cache_has_cpu_partial(s) && !prior` the slab is frozen and handed to
   `put_cpu_partial()`, which pushes it onto the per-CPU partial list. Only when
   `oldslab->slabs >= s->cpu_partial_slabs` does that function hand the whole existing chain to
   `__unfreeze_partials()`, which walks it, unfreezes each slab, and calls `discard_slab()` on
   those that are empty *and* satisfy `n->nr_partial >= s->min_partial`. Everything else goes
   onto the node partial list.
4. Free the *last* in-use object of a slab that is on the node partial list. `new.inuse` reaches
   zero with `was_frozen` clear, `__slab_free()` takes the list lock, and
   `if (unlikely(!new.inuse && n->nr_partial >= s->min_partial)) goto slab_empty;` leads
   straight to `remove_partial()` and `discard_slab()`. No per-CPU overflow is involved.

`discard_slab()` is where the page leaves SLUB, and the gate on both routes to it is the same
inequality: `n->nr_partial >= s->min_partial`. The node keeps at least `min_partial` partial
slabs in reserve and only surrenders pages above that line.

Two families of technique fall out of that structure. The older, "partial free" style —
Horn's, and the `filp` groom in the CVE-2022-29582 writeup — reserves slabs up front and then
frees one object from each, walking route 3 until the per-CPU partial list overflows and the
node list is pushed past `min_partial`. CROSS-X identifies why this stopped working: between
5.15 and 6.1 the size relationship between the per-CPU slab cap and `min_partial` reversed for
about half the generic caches (their Table 1: `kmalloc-16` goes from 30 > 5 to 1 < 5,
`kmalloc-1024` from 6 > 5 to 3 < 5), and where the cap is below `min_partial` the per-node list
can never overflow, so the vulnerable slab stays on it rather than being discarded.

The reservation arithmetic for that style is where a formula copied from an older writeup does
real damage. The classic figure is `objs_per_slab * (cpu_partial + 1)` objects, and it was right
before 5.17, when the per-CPU partial list was capped by an accumulated free-object count
(`page->pobjects`) compared against `s->cpu_partial`. Freeing one object from a full slab added
that slab to the list and raised `pobjects` by exactly one, so for this particular groom
`cpu_partial` behaved as a slab count. [Commit b47291ef02b0, "mm, slub: change percpu partial
accounting from objects to
pages"](https://github.com/torvalds/linux/commit/b47291ef02b0bee85ffb7efd6c336060ad1fe1a4)
(Vlastimil Babka, 5.17) removed `pobjects` and made the accounting precise in slabs.
`s->cpu_partial` still holds an object target, but `slub_set_cpu_partial()` converts it with
`nr_slabs = DIV_ROUND_UP(nr_objects * 2, oo_objects(s->oo))` into `s->cpu_partial_slabs`, and
`put_cpu_partial()` compares `oldslab->slabs` against that, never against `cpu_partial`. The
correct reservation on 6.1 is therefore `objs_per_slab * (cpu_partial_slabs + 1)`.

The difference is about an order of magnitude. Take a 256-byte cache on an order-1 slab.
`set_cpu_partial()` takes the `s->size >= 256` arm, so `nr_objects = 52`. The slab holds
`oo_objects(s->oo) = 8192 / 256 = 32` objects, so `cpu_partial_slabs = DIV_ROUND_UP(52 * 2, 32) =
4`, and the reservation is `32 * (4 + 1) = 160` objects — against the `32 * (52 + 1) = 1696` the
pre-5.17 formula asks for. Each input is readable on your own target: `s->size` and
`objs_per_slab` from `/sys/kernel/slab/<cache>/{slab_size,objs_per_slab}` (0400) or the
`objsize`/`objperslab` columns of `/proc/slabinfo` — `cache_show()` prints `s->size` in the
`objsize` column, so that column is the stride and not `object_size` — and `nr_objects` from the
`set_cpu_partial()` size ladder quoted above. The one number not to use directly is the sysfs
`cpu_partial` file: `cpu_partial_show()` returns `s->cpu_partial`, which is in objects, and
there is no sysfs file for `cpu_partial_slabs`. It has to be recomputed from the size ladder and
`objs_per_slab`.

CROSS-X's *Complete Free* strategy fixes this by making the gate true before the vulnerable slab
ever migrates. It first populates `ceil(min_partial / cpu_partial_slabs) * cpu_partial_slabs`
slabs, which both defragments the cache and gives it enough material to fill the node partial
list; frees one object from each of those, so the per-CPU list overflows and migration fills the
node list to `min_partial`; then completely empties the vulnerable slab, which freezes it onto
the now-empty per-CPU partial list; then overflows that list again. The vulnerable slab reaches
`__unfreeze_partials()` empty, the node list is already at `min_partial`, and it is discarded.
CROSS-X reports this as the first strategy generalizable to all SLUB caches, with success rates
"above 99% in idle conditions and 85% in busy conditions across all caches except one."

The deciding quantity is readable while the groom runs, one line per batch:

```
cat /sys/kernel/slab/<cache>/{partial,cpu_slabs,slabs,min_partial,objs_per_slab,order}
```

`partial` is `n->nr_partial` summed over nodes — the number the discard gate compares against
`min_partial` — and `cpu_slabs` counts the active slab plus the per-CPU partial chain. Watching
`partial` climb to `min_partial` and stop is the groom's first phase working; watching `slabs`
drop is a page actually leaving. All of these are mode 0400. Note that the per-slab free
counters (`free_slab`, `cpu_partial_drain`, `deactivate_empty`) live under `CONFIG_SLUB_STATS`,
which the arm64 `gki_defconfig` does not set, so on a stock GKI kernel they are absent and the
standing counts above are what you have.

### Watching the page leave

The kernel's page tracepoints, declared in
[include/trace/events/kmem.h](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/trace/events/kmem.h),
give a PFN-level account of the exchange:

```
cd /sys/kernel/tracing
echo 'order==1' > events/kmem/mm_page_free/filter
echo 1 > events/kmem/mm_page_free/enable
echo 1 > events/kmem/mm_page_alloc/enable
echo 1 > events/kmem/mm_page_alloc_zone_locked/enable
echo 1 > events/kmem/mm_page_pcpu_drain/enable
cat trace_pipe
```

Those four events each carry a `pfn` field: `mm_page_free` prints
`page=%p pfn=0x%lx order=%d`, `mm_page_alloc` adds `migratetype=%d gfp_flags=%s`,
`mm_page_alloc_zone_locked` adds `percpu_refill=%d`, and `mm_page_pcpu_drain` prints
`pfn`, `order` and `migratetype` (kmem.h lines 137-266). `kmem_cache_free` is a different
shape — `call_site=%pS ptr=%p name=%s`, lines 115-135 — with no PFN at all; it is what ties an
object free to a named cache, which is the other half of the picture and the reason to enable it
separately rather than alongside these.

The pair of lines that decides a cross-cache attempt has this shape (field order fixed by the
`TP_printk` formats above; values illustrative):

```
  groom-5231  [003] d..1. 4812.663214: mm_page_free: page=00000000d2f41a07 pfn=0x8a3f21 order=1
  spray-5232  [003] d..1. 4812.663388: mm_page_alloc: page=00000000d2f41a07 pfn=0x8a3f21 order=1 migratetype=0 gfp_flags=GFP_KERNEL
```

Read left to right: task name and pid, the CPU in brackets, the latency flags, the timestamp,
then the event and its fields. The conclusion is mechanical. Same `pfn`, same `order`, and the
same CPU column on both lines means the page your groom surrendered is the page your spray got
back, and the exchange landed. A different `pfn` on the alloc side, or no alloc line carrying
that `pfn` at all, means the reclaim missed and no write should be attempted — the page is
somewhere else and the address you were about to corrupt belongs to someone. This is ground
truth obtained without going through the exploit primitive at all, which makes it the right
instrument for the development loop. It needs tracefs and write access to the `enable` files, so
it belongs to a rooted or engineering device, not to the shipped exploit.

## What the page allocator does with a surrendered slab

The freed slab page does not go straight onto a buddy free list. Linux keeps per-CPU pagesets
(PCP) in front of the buddy allocator, one list per `(migratetype, order)` pair, for orders up
to `PAGE_ALLOC_COSTLY_ORDER` (3). The relevant code in
[mm/page_alloc.c](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/mm/page_alloc.c)
is short and decides most of the timing work in a cross-cache exploit:

- `free_unref_page_commit()` does `list_add(&page->pcp_list, &pcp->lists[pindex])` — insertion
  at the *head* — then increments `pcp->count`.
- `__rmqueue_pcplist()` takes `list_first_entry(list, struct page, pcp_list)` — removal from the
  *head*.
- When `pcp->count >= high`, `free_pcppages_bulk()` runs and removes pages with
  `list_last_entry()`, the *oldest* entries, handing them to `__free_one_page()` and emitting
  `trace_mm_page_pcpu_drain()`.

Head insert plus head removal is LIFO, and that LIFO ordering is why a cross-cache reclaim lands
at all: the next same-order, same-migratetype page request on that CPU gets back the page you
just freed. The qualifier matters as much as the rule, because it holds only while the page
stays on the PCP list, and a cross-cache groom creates precisely the conditions that kick it
off.

`free_unref_page_commit()` computes

```
free_high = (pcp->free_factor && order && order <= PAGE_ALLOC_COSTLY_ORDER);
high = nr_pcp_high(pcp, zone, free_high);
if (pcp->count >= high)
        free_pcppages_bulk(zone, nr_pcp_free(pcp, high, batch, free_high), pcp, pindex);
```

`nr_pcp_high()` returns 0 when `free_high` is set, which makes `pcp->count >= high`
unconditionally true, and `nr_pcp_free()` then returns `pcp->count` — the entire PCP list is
pushed into the buddy allocator on that one free. `pcp->free_factor` is incremented by
`nr_pcp_free()` on each batched free and only halved (`pcp->free_factor >>= 1`) on an
allocation, so a burst of order>=1 frees with no allocations in between — which is exactly what
surrendering slabs looks like — reliably ends up in this path. The operational consequences are
concrete: interleave an allocation of the same order between frees, or surrender one slab at a
time, to keep `free_factor` at zero.

Two further reasons a surrendered page may not be at the head when you come back for it. First,
`nr_pcp_high()` caps `high` to `pcp->batch << 2` while `ZONE_RECLAIM_ACTIVE` is set on the zone,
and a large reclaim spray is a good way to drive the zone into reclaim, so the drain threshold
moves down under you. Second, once a page reaches the buddy lists the LIFO property is gone:
`__free_one_page()` chooses `add_to_free_list_tail()` when `buddy_merge_likely()` predicts the
higher-order buddy will also be freed, and `shuffle_pick_tail()` can pick the tail as well.

The check for all of this is unprivileged:

```
grep -A3 'cpu:' /proc/zoneinfo
```

`/proc/zoneinfo` is mode 0444 and prints `cpu: N`, `count:`, `high:` and `batch:` per CPU per
zone. Sample it before and after a free batch. `count` collapsing toward zero while
`mm_page_pcpu_drain` lines appear in `trace_pipe` is the `free_high` drain happening, and is the
difference between a reclaim that lands and one that does not. The sizing of these lists is
governed by the `percpu_pagelist_high_fraction` sysctl, [documented in
admin-guide/sysctl/vm](https://docs.kernel.org/admin-guide/sysctl/vm.html). When the list is
empty on the allocation side, `get_populated_pcp_list()` calls `rmqueue_bulk()` to pull a whole
`batch` from the zone's `free_area` under `zone->lock`, which is a different and much less
predictable source; PCPLost ([NDSS
2026](https://www.ndss-symposium.org/wp-content/uploads/2026-f862-paper.pdf)) analyses both
directions.

Three further practical constraints follow, and each has an instrument.

### Migratetype must match

Slab pages for ordinary kmalloc caches are unmovable; anonymous user pages are movable and land
on a different PCP list entirely. A reclaim spray built out of plain `mmap()`ed anonymous memory
therefore does not compete for the page you just freed *on the fast path*, while pipe buffers,
page tables and packet-ring pages do. Two exceptions keep that from being a universal rule.
Caches carrying `SLAB_RECLAIM_ACCOUNT` — the `kmalloc-rcl-*` set, `dentry`, `inode` — get
`__GFP_RECLAIMABLE` added to `s->allocflags` in `calculate_sizes()` and allocate
MIGRATE_RECLAIMABLE, not MIGRATE_UNMOVABLE. And when the UNMOVABLE free lists are exhausted —
the fragmented, memory-pressured state a large spray creates — `__rmqueue_fallback()` walks the
`fallbacks[MIGRATE_UNMOVABLE] = { MIGRATE_RECLAIMABLE, MIGRATE_MOVABLE }` table and
`steal_suitable_fallback()` can convert whole pageblocks, at which point movable memory very
much does compete.

Verify rather than assume: `mm_page_alloc` carries a `migratetype=` field, so enable it while
running your intended reclaim primitive and read the value. The integer needs decoding, and on
android14-6.1 it does not decode the way a mainline-based writeup would say, because
`CONFIG_CMA=y` puts `MIGRATE_CMA` inside the enum:

```
pahole -C migratetype vmlinux.btf
bpftool btf dump file vmlinux.btf format c | grep -A12 'enum migratetype'
```

On this kernel that gives UNMOVABLE=0, MOVABLE=1, RECLAIMABLE=2, CMA=3, so `MIGRATE_PCPTYPES`
is 4 rather than 3 and CMA has a PCP list of its own. A kernel built without `CONFIG_CMA`
numbers everything above RECLAIMABLE differently.

### Order must match, or the page is gone

The buddy allocator coalesces: an order-1 block freed next to a free order-1 buddy becomes one
order-2 block and disappears from the order-1 free list. Cross-cache between caches of
*different* slab order is correspondingly harder, and CROSS-X says why in its discussion
section: objects from caches of different orders can perform the reclaim, but they "require
additional strategies for precise page-level heap grooming ... to trigger necessary splitting or
merging (for different orders)." The paper's separate finding that different-order caches
produce negligible *interference* — "pages of different orders are retrieved from different
freelists within the page allocators, preventing interference with each other" — is about noise,
not about difficulty, and points the opposite way: a different-order cache is a poor competitor
and a poor partner for the same reason.

Confirming which order your reclaim primitive actually uses is a tracepoint question, not a
`/proc/buddyinfo` question. An allocation of order 0-3 is normally served by
`__rmqueue_pcplist()` and touches no buddy free list, so buddyinfo does not move; only a PCP
refill reaches the buddy allocator, and `rmqueue_bulk()` pulls `pcp->batch` pages at once,
splitting higher-order blocks so that column *k+1* falls while lower columns rise. On a live
device it is also far too noisy to attribute a single allocation to. Ask the event directly:

```
cd /sys/kernel/tracing
echo 'order>0' > events/kmem/mm_page_alloc/filter
echo 1 > events/kmem/mm_page_alloc/enable
cat trace_pipe
```

and run the reclaim primitive in isolation under that filter. `mm_page_alloc`'s `order=` field
is the answer, with the order-0 background cut away.

The three proc files remain useful, re-scoped to what they honestly show: the standing
distribution of free blocks before a groom, not the effect of one allocation. `/proc/buddyinfo`
has no header, so the column mapping has to be supplied:

```
Node 0, zone   Normal   3129   1832    611    142     29      7      1      0      0      0      0
```

Eleven columns, one per order, left to right from order 0 to order `MAX_ORDER - 1` (10 on a 4K
arm64 build), each counting free blocks *of that order*. So this zone holds 611 free order-2
blocks. `/proc/pagetypeinfo` breaks the same data down by migratetype, and `/proc/zoneinfo`
prints the per-CPU `count`/`high`/`batch` discussed above. buddyinfo and zoneinfo are mode 0444;
pagetypeinfo is 0400.

### CPU must match

The PCP list is per-CPU. A page freed on CPU 3 is only cheaply reachable from CPU 3. Pin both
halves with `sched_setaffinity()` (or `taskset` when testing by hand); SLUBStick states the
reason directly — "Since both the slab and buddy allocator maintain per-CPU lists, CPU migration
may introduce noise."

## RCU-deferred frees, and why they move the page to another CPU

The CPU-affinity rule assumes you control which CPU performs the free. Frequently you do not,
because the free is deferred through RCU.

Two distinct mechanisms get confused. The first is object-level: a subsystem calls `call_rcu()`
on the object itself, so the `kmem_cache_free()` happens in a callback after a grace period. In
6.1, `struct file` is freed this way —
[fs/file_table.c](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/fs/file_table.c)
does `call_rcu(&f->f_rcuhead, file_free_rcu)` — even though `filp_cachep` is created without any
RCU flag. The second is slab-level: a cache created with `SLAB_TYPESAFE_BY_RCU` has its *slab
page* freeing deferred, via `call_rcu(&slab->rcu_head, rcu_free_slab)` in `free_slab()`, while
object slots inside the slab are reused immediately. The kernel's [rculist_nulls
documentation](https://docs.kernel.org/RCU/rculist_nulls.html) spells out the reader-side
contract that flag implies: an object "can be reused very very fast (before the end of RCU grace
period)", so a lockless lookup must re-check the key after taking a reference. For an exploit
the consequence is the mirror image — the slot comes back fast, the page does not.

Either way, the work that actually returns the page runs from an RCU callback, and callbacks
need not run on the CPU that queued them. With `CONFIG_RCU_NOCB_CPU=y` and `rcu_nocbs=` on the
command line, callbacks are offloaded to `rcuo`/`rcuop`/`rcuog` kthreads, which the
[per-CPU kthreads
documentation](https://docs.kernel.org/admin-guide/kernel-per-CPU-kthreads.html) describes as
existing to "offload RCU callbacks from the corresponding CPU" and which can be pinned
elsewhere. So for an RCU-deferred victim the reclaim must be scheduled twice over: after the
grace period and the callback, and on the CPU where the callback ran, because that is whose PCP
list received the page. Three instruments make that actionable.

### Waiting for the grace period

`membarrier(MEMBARRIER_CMD_GLOBAL, 0, 0)` calls `synchronize_rcu()` in
`kernel/sched/membarrier.c` when `num_online_cpus() > 1`, is unprivileged, and blocks until a
grace period has elapsed. That is the standard userspace way to guarantee a deferred free has at
least been queued to a callback list before the reclaim spray starts. The one caveat is in the
same switch statement: the command returns `-EINVAL` when `tick_nohz_full_enabled()`, and is
masked out of `MEMBARRIER_CMD_QUERY`'s result in that case. GKI sets `CONFIG_NO_HZ` but not
`CONFIG_NO_HZ_FULL`, so on an Android target it is available; query first if you are unsure.

### Finding the callback CPU cheaply

The `rcu:*` tracepoints would name the CPU, but they are compiled behind `CONFIG_RCU_TRACE`,
which the GKI defconfig does not set. Before reaching for a kprobe, ask the scheduler:

```
ps -A -o pid,psr,comm | grep -E 'rcuo|rcuog'
taskset -p <pid>
```

`psr` is the CPU each offload kthread last ran on, and `taskset -p` prints its affinity mask.
That is unprivileged and answers the question for the system as a whole. Use a kprobe only to
confirm that the callback for *your* victim runs there, with the syntax from the [kprobe-based
event tracing documentation](https://docs.kernel.org/trace/kprobetrace.html):

```
echo 'p:ffree file_free_rcu' > /sys/kernel/tracing/kprobe_events
echo 1 > /sys/kernel/tracing/events/kprobes/ffree/enable
cat /sys/kernel/tracing/trace
```

The CPU column is the third field, in brackets:

```
     rcuop/2-37    [002] d.h2. 5109.884417: ffree: (file_free_rcu+0x0/0x64)
```

Read a few hundred of these and you know which processors actually run that callback on your
device, and whether they are the ones you pinned to. The same interface with the `@ADDR` fetch
argument reads kernel memory at a probe point, which is the substitute for drgn or crash on a
device where neither is available.

### Knowing whether you are waiting on a grace period or a timer

The Android GKI defconfig sets `CONFIG_RCU_LAZY=y` with `CONFIG_RCU_LAZY_DEFAULT_OFF=y`. Where
lazy RCU is on, a non-urgent `call_rcu()` callback is not bounded by the grace period but by
`LAZY_FLUSH_JIFFIES`, which `kernel/rcu/tree_nocb.h` defines as `10 * HZ` — ten seconds. Which
regime you are in is one read:

```
cat /sys/module/rcutree/parameters/enable_rcu_lazy
```

`kernel/rcu/tree.c` declares `static bool enable_rcu_lazy __read_mostly =
!IS_ENABLED(CONFIG_RCU_LAZY_DEFAULT_OFF);` with `module_param(enable_rcu_lazy, bool, 0444)`, so
the file is world-readable and reflects both the build default and any
`rcutree.enable_rcu_lazy=` on the command line. `N` means `membarrier()` is a sufficient wait;
`Y` means the callback may sit for up to ten seconds unless something calls `call_rcu_hurry()`
in the meantime, and a reclaim spray issued immediately after the free is spraying into a window
that has not opened yet.

## Choosing what reclaims the page

A reclaim object is judged on three properties, which CROSS-X names as spray capability, minimal
interference, and useful primitives: you must be able to allocate many of them on demand, they
must not themselves churn the allocator in ways that destroy the layout, and once corrupted they
must give you something. The public corpus has converged on a small set.

- Page tables. Allocating a page table is a direct order-0 page allocation, and a corrupted PTE
  is an immediate physical-memory read/write. This is the target in
  [SLUBStick (USENIX Security
  2024)](https://www.usenix.org/conference/usenixsecurity24/presentation/maar-slubstick) and the
  whole point of [Dirty
  Pagetable](https://yanglingxi1993.github.io/dirty_pagetable/dirty_pagetable.html) by Nicolas Wu
  and Ye Zhang, which demonstrates the technique on Pixel devices.
- Pipe buffers. The cross-cache-specific fact is that the array's slab order is chosen by the
  pipe's size: the [D3CTF d3kcache writeup](https://github.com/arttnba3/D3CTF2023_d3kcache)
  resizes pipes to 64 entries specifically so the allocation comes from order-3 pages and
  matches the vulnerable cache's order, against the order-2 pages a smaller pipe would use.
  Everything else about the vehicle — the 40-byte element layout, the `F_SETPIPE_SZ` size
  ladder, the `pipe-user-pages-soft` degradation hazard, and the rule that a corrupted pipe must
  never be closed — is in 05's object catalogue. Jenkins' CVE-2022-42703 exploit reclaims with
  them.
- Raw page-allocator consumers. Two are worth knowing on this target, and both are asserted from
  the code rather than from a published exploit that uses them for cross-cache reclaim.
  `PF_PACKET` rings: `packet_set_ring()` in `net/packet/af_packet.c` fills its `pg_vec` from
  `alloc_one_pg_vec_page()`, which calls `__get_free_pages(gfp_flags, order)` directly with the
  order derived from the caller's block size, and `PACKET_TX_RING` frames are written by
  userspace through the socket's `mmap()`. It requires `CAP_NET_RAW` — `packet_create()` starts
  with `if (!ns_capable(net->user_ns, CAP_NET_RAW)) return -EPERM;` — so on Android it is not
  reachable from an app or shell uid without help. The dma-buf system heap: `system_heap.c`
  allocates through `alloc_largest_available()` with `orders[] = {ORDER_1M, ORDER_64K,
  ORDER_FOR_PAGE_SIZE}`, which on a 4K kernel is orders 8, 4 and 0. Two qualifications follow
  from that code. It goes through `dmabuf_page_pool_alloc()`, a per-heap page cache that is
  consulted before the buddy allocator, so a freshly surrendered page is only reachable once the
  pool is dry. And orders 8 and 4 are above `PAGE_ALLOC_COSTLY_ORDER`, so those allocations
  bypass the PCP lists entirely — only the order-0 arm competes for a page you just freed
  through them.
- Ordinary sprayable objects in another cache. STAR Labs' [file-based DirtyCred container
  escape](https://starlabs.sg/blog/2023/07-a-new-method-for-container-escape-using-file-based-dirtycred/)
  (Choo Yi Kai, July 2023) mentions in passing that its author's superseded first attempt "made
  use of a bunch of cross-cache sprays and ultimately overwriting the destructor of an `sk_buff`
  struct"; the published technique is the file-based one, not the `sk_buff` route. Their
  [`prctl` anon_vma_name
  spray](https://starlabs.sg/blog/2023/07-prctl-anon_vma_name-an-amusing-linux-kernel-heap-spray/)
  is presented partly as a way to *avoid* needing a cross-cache step for small caches, which is a
  fair reminder that the cheapest cross-cache attack is the one you do not have to do.

That last point deserves weight. kylebot's [CVE-2022-1786
writeup](https://blog.kylebot.net/2022/10/16/CVE-2022-1786/) — an io_uring invalid-free that won
the first full kernelCTF bounty — deliberately stays inside `kmalloc-256`, grooming
`timerfd_ctx` against `msg_msgseg` within a single slab page and hijacking the freelist there.
Same-cache reuse, when the caches line up, is strictly more reliable than anything in this
section. Reach for the page allocator when the object you need is not in the cache you can
corrupt, not before.

Google's [kernelCTF submission
archive](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf) is the
largest public corpus of working exploits with writeups attached, and is the best place to see
which combinations of vulnerable cache, reclaim object and grooming strategy people actually
land.

## Probabilism, and the verification step that bounds it

Every published measurement agrees on the shape of the problem. SLUBStick describes the prior
art as having "a success rate of only 40 %, with failure scenarios often resulting in a system
crash," and raises it by adding a timing side channel that distinguishes an allocation served
from the per-CPU freelist from one that required a fresh slab — the same observation [PSPRAY
(USENIX Security
2023)](https://www.usenix.org/conference/usenixsecurity23/presentation/lee-yoochan) made for
in-cache attacks. Its measured rates are 99.3-99.9% for single-page slabs and 82.1-93.5% for
multi-page slabs, falling to 70.5% with CPU pinning removed and 53.8% under external
`stress-ng` noise; those breakdowns are in Table 1 ("Success rate of triggering the recycling
and reclamation process for generic caches") of the [paper
PDF](https://www.usenix.org/system/files/usenixsecurity24-maar-slubstick.pdf), not on
the [presentation
page](https://www.usenix.org/conference/usenixsecurity24/presentation/maar-slubstick), which
carries only the abstract. CROSS-X reports above 99% idle and 85% busy "across all caches except
one." PCPLost reports above 90% in most scenarios. The numbers cluster high under laboratory
conditions and degrade under load.

The general argument for reading before writing is made in
[07-read-write-primitives.md](07-read-write-primitives.md) under "Read before you write" and in
[10-survivability-and-measurement.md](10-survivability-and-measurement.md) under "Composing
probabilistic stages safely": a blind write has no abort branch, so the exploit's success
probability is permanently the setup's landing probability. Three things are specific to this
technique.

The unit of a miss is a page, not an object slot. A same-cache reuse that misses corrupts
another object of the same type in a cache you were already perturbing; a cross-cache miss
corrupts whatever subsystem now owns that page, and the panic arrives seconds later in a stack
trace with no relationship to your exploit. The blast radius is larger and the evidence is
worse.

The verification token belongs in the reclaim payload. Compose the sprayed object so that it
names the page it was built for — write the page's own address, or a random token, into an inert
field — then read it back through a primitive that does not depend on the placement being
correct, and only proceed if the token matches. This is cheaper here than in the general case,
because the reclaim object is chosen by you and usually has a spare field.

When measuring rather than exploiting, take the privileged ground truth instead of the token. A
reader that inspects the placed page directly gives a per-attempt answer with no race and no
attempt budget, and is the only honest way to compare two grooming strategies.

Three readers answer that, with different prerequisites. `/proc/kpageflags` is a seekable
array indexed by PFN, created with `S_IRUSR` in `fs/proc/page.c`: seek to `pfn * 8`, read one
`u64`, and test `KPF_SLAB` (bit 7) and `KPF_BUDDY` (bit 10) to learn whether the page you
surrendered is still a slab page, has reached the buddy lists, or has been re-typed into
something else. `/proc/kpagecount` sits beside it with the same mode and gives the map count.
Neither needs a boot-parameter change, which is what makes them the fallback when `page_owner`
is out of reach. `page_owner` itself, [documented under
mm/page_owner](https://docs.kernel.org/mm/page_owner.html), records the allocation stack and
order for every page and answers "who owns this PFN" authoritatively through
`/sys/kernel/debug/page_owner`; `CONFIG_PAGE_OWNER=y` is already in the GKI defconfig, so the
only obstacles are `page_owner=on` on the command line and access to debugfs — decisive on
anything you can boot yourself, unavailable on a locked bootloader. The third reader answers the
other half of the question: `/proc/self/pagemap` maps a user virtual address to its PFN, which is
the frame number the first two are then asked about. A placement measurement needs both halves —
the frame a reclaim object landed on, and what that frame currently is — so on a device where
pagemap is blind the other two readers have nothing to index. It is
`CAP_SYS_ADMIN`-gated and the capability is snapshotted when the file is opened;
[04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) has the gating rule and
the PFN-to-address arithmetic. That gate is why pagemap belongs to the privileged measurement
path here and why the exploit path falls back on guessing a physical band.

## What the mitigations change

`SLAB_FREELIST_RANDOM` randomizes the initial free order of a newly created slab.
`SLAB_FREELIST_HARDENED` is a different mechanism with a different target: it obfuscates the
stored free pointer (`ptr ^ s->random ^ ptr_addr`) and adds pointer-validity and double-free
checks, and has no effect on the order objects are handed out in. Both are set in the GKI
defconfig, and 05's "Freelist hardening, and what it actually stops" covers what each one
actually prevents. Neither touches page recycling. Cache separation (`kmalloc-cg-*`, dedicated
caches, disabled merging) is what made cross-cache necessary, not what stops it.

The mitigation aimed squarely at this technique is `CONFIG_SLAB_VIRTUAL`, proposed by Matteo
Rizzo and Jann Horn in September 2023 and covered by [LWN](https://lwn.net/Articles/944647/). It
backs slabs with virtual memory and guarantees that "once a virtual address is used for a slab
cache it's never reused for anything except for other slabs in that cache," which removes the
exchange entirely for attacks that depend on a virtual address being re-typed. It has not landed
in mainline, and PCPLost reports over 90% reliability against it, because a physical page freed
by one cache can still be re-handed to another even when the virtual address is not. Treat it as
a constraint on technique rather than an end to the class.

`CONFIG_SHUFFLE_PAGE_ALLOCATOR=y`, also in the GKI defconfig, randomizes free-list order at
initialization; it perturbs the starting layout, not the runtime LIFO behaviour the attack relies
on, and its module parameter (`/sys/module/page_alloc/parameters/shuffle`) is mode `0400`.

KFENCE is compiled into GKI (`CONFIG_KFENCE=y`, 500 ms sample interval, 63 objects). Being a
[sampling detector](https://docs.kernel.org/dev-tools/kfence.html) it will not catch a
cross-cache attack systematically, but during development an occasional KFENCE report in `dmesg`
naming your own free/alloc pattern is a free correctness check on the groom. `CONFIG_KASAN=y`
with `CONFIG_KASAN_HW_TAGS=y` is present too — MTE-based KASAN built in but inert unless enabled
at boot via `kasan.mode=`, so a kernel where you *can* enable it turns a silent miss into a
labelled report.

## Instruments

- `zcat /proc/config.gz | grep -E 'SLAB_|SHUFFLE_PAGE|RCU_NOCB|RCU_LAZY|KFENCE|KASAN|BTF|PAGE_OWNER'`
  and `cat /proc/cmdline` — the build and the runtime half of every configuration claim in this
  section. config.gz is world-readable when `CONFIG_IKCONFIG_PROC` is set, which GKI does; the
  command line wins where the two disagree.
- `cat /proc/slabinfo` — cache inventory with `objperslab` and `pagesperslab`. Mode 0400 on a
  SLUB kernel, and absent entirely without `CONFIG_SLAB` or `CONFIG_SLUB_DEBUG`, so `No such
  file` and `Permission denied` mean different things.
- `slabtop` — live, sorted view of the same data while a groom runs; root.
- `cat /sys/kernel/slab/<cache>/{object_size,slab_size,order,objs_per_slab,partial,cpu_slabs,slabs,min_partial,cpu_partial}`
  — per-cache geometry and the live `n->nr_partial` the discard gate compares against
  `min_partial`. `SLAB_ATTR_RO` = mode 0400, so root plus SELinux, not a config question.
  `cpu_partial` here is in *objects*; the per-CPU list is capped in slabs by
  `cpu_partial_slabs`, which sysfs does not export.
- `ls -l /sys/kernel/slab` — symlinks to a `:A-…` directory mean cache merging is active; one
  directory per cache means it is not. Readable without root because the link targets are.
- `adb pull /sys/kernel/btf/vmlinux` then `pahole -C <struct> vmlinux.btf` — a struct's size
  (`s->object_size`) and member offsets for a kernel you cannot rebuild; needs
  `CONFIG_DEBUG_INFO_BTF=y`, which Android GKI sets, and is unprivileged if SELinux permits the
  read. It does not give the object stride or the slab order.
  `bpftool btf dump file vmlinux.btf format c` is a separate tool for generating C headers, and
  is also how to dump `enum migratetype` to decode a tracepoint's `migratetype=` field.
- `vmlinux-to-elf` ([marin-m/vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf)) plus
  `readelf`/`objdump` — recovers symbols from a stripped or compressed kernel image when
  `/proc/kallsyms` is restricted; host-side, needs the boot image.
- `echo 1 > /sys/kernel/tracing/events/kmem/{mm_page_free,mm_page_alloc,mm_page_alloc_zone_locked,mm_page_pcpu_drain}/enable`
  then `cat trace_pipe` — PFN-level ground truth for whether a freed slab page was reclaimed by
  your spray. All four carry `pfn` and `order`; `mm_page_alloc` adds `migratetype` and
  `gfp_flags`. `mm_page_alloc_zone_locked` is the event whose `percpu_refill=1` marks a
  PCP-eligible bulk refill; the test for a PCP *hit* is the absence of any
  `mm_page_alloc_zone_locked` line beside the `mm_page_alloc`. Needs tracefs write access.
- `echo 'order>0' > .../events/kmem/mm_page_alloc/filter` — the way to learn which page order a
  reclaim primitive really allocates at, run in isolation. `/proc/buddyinfo` cannot answer this,
  because orders 0-3 are served from the PCP lists without touching a buddy free list.
- `echo 1 > .../events/kmem/kmem_cache_free/enable` — ties an object free to a named cache
  (`call_site`, `ptr`, `name`). It carries no PFN; the page events above do.
- `echo 'p:name <func>' > /sys/kernel/tracing/kprobe_events` — control-flow observation, and with
  `@ADDR` fetch arguments an arbitrary kernel read; needs `CONFIG_KPROBES` (set in GKI) and
  tracefs. The bracketed CPU column of the output is how you learn which processor ran an RCU
  callback when `rcu:*` tracepoints are compiled out.
- `ps -A -o pid,psr,comm | grep -E 'rcuo|rcuog'` and `taskset -p <pid>` — which CPU each RCU
  offload kthread last ran on, and its affinity mask. Unprivileged, and the cheap answer before
  reaching for the kprobe above.
- `membarrier(MEMBARRIER_CMD_GLOBAL, 0, 0)` — unprivileged, blocks until an RCU grace period has
  elapsed (`synchronize_rcu()` in `kernel/sched/membarrier.c`); returns `-EINVAL` under
  `nohz_full`, which GKI does not enable.
- `cat /sys/module/rcutree/parameters/enable_rcu_lazy` — mode 0444. `Y` means a non-urgent
  callback is bounded by `LAZY_FLUSH_JIFFIES` (`10 * HZ`, ten seconds) rather than by the grace
  period.
- `grep -A3 'cpu:' /proc/zoneinfo` — per-CPU pageset `count`/`high`/`batch` before and after a
  free batch; `count` collapsing means a `free_high` drain emptied the list into the buddy
  allocator. Mode 0444.
- `cat /proc/buddyinfo`, `/proc/pagetypeinfo` — standing distribution of free blocks by order
  (eleven unheaded columns, order 0 to `MAX_ORDER - 1`) and the same split by migratetype.
  buddyinfo is 0444; pagetypeinfo is 0400.
- `/proc/kpageflags` and `/proc/kpagecount` — seek to `pfn * 8`, read a `u64`; `KPF_SLAB` is bit
  7 and `KPF_BUDDY` bit 10, which together say whether a surrendered page is still slab, has
  reached the buddy lists, or has been re-typed. Mode 0400 (`S_IRUSR` in `fs/proc/page.c`), no
  boot parameter required.
- `page_owner=on` on the kernel command line plus `cat /sys/kernel/debug/page_owner` —
  allocation stack and order per page. `CONFIG_PAGE_OWNER=y` is already in the GKI defconfig, so
  the obstacles are the command line and debugfs access, not the build.
- `/proc/self/pagemap` — virtual to physical mapping, and the only way to name the frame the
  PFN-indexed readers above are asked about; `CAP_SYS_ADMIN`-gated, with the gating rule in
  [04](04-kaslr-and-information-leaks.md).
- `drgn` and `crash` — script or walk live kernel structures; need root, `/proc/kcore` and debug
  info, so in practice a lab kernel rather than a shipping device.
- `dmesg` / `logcat`, and `cat /sys/fs/pstore/console-ramoops-0` after a reboot — the KFENCE or
  KASAN report, or the panic backtrace from a cross-cache miss that landed on someone else's
  object.
- `taskset` / `sched_setaffinity()` — pin groom and reclaim to one CPU, since PCP lists are
  per-CPU; unprivileged.

## Grounded in this project

The owned-victim form of this technique is implemented in
`cves/lib/spray/crosscache/crosscache.c` and `cves/lib/spray/crosscache/crosscache.h`, whose
`README.md` states the four steps (groom, acquire the address, surrender the page, refill from a
different cache) and separates the owned-victim family from the foreign-victim case where an
RCU-deferred kernel free makes the address unknowable and the timing unchoosable.
`cves/lib/spray/physspray.h` and `cves/lib/addr/zoneguess.h` cover the adjacent problem of
placing chosen content at a *guessed* kernel address when `/proc/self/pagemap` returns zeros, and
`cves/lib/rw/kprobe_read.c` implements the kprobe `@ADDR` read described above. The measurement
discipline — why a privileged reader is the judge, why rounds within a run are not independent
samples, and why variants must be interleaved — is written up in `docs/CROSSCACHE-MEASUREMENT.md`
and driven by `runner/recipes/crosscache-bench.toml`.

## See also

- [Heap Grooming and Spraying](05-heap-grooming-and-spraying.md) — cache identification, BTF
  layout recovery, merging and aliasing, the object catalogue, and freelist hardening.
- [From a Bug to a Read/Write Primitive](07-read-write-primitives.md) — what to do with the page
  once it has been re-typed, and the read primitive the verification step needs.
- [Triggering Races Reliably](08-triggering-races-reliably.md) — CPU pinning, scheduling, and
  waiting for a deferred free to actually happen.
- [Defeating KASLR and Building Information Leaks](04-kaslr-and-information-leaks.md) — where the
  addresses used to name a placed page come from.
- [Crash Triage and Root-Cause Analysis](03-crash-triage-and-root-cause-analysis.md) — reading the
  panic that a missed placement produces.
- [Survivability, Stabilization, and Treating Exploitation as an Experiment](10-survivability-and-measurement.md)
  — measuring a probabilistic step instead of reasoning about it.
- [Case Studies: Techniques Applied End to End](11-case-studies.md) — cross-cache steps in
  complete chains.
- [Further Reading and Glossary](12-further-reading-and-glossary.md)
