# tools/pagetrace — what a kernel allocation really takes, and where a freed slab page goes

`pagetrace` answers the questions a cross-cache attempt lives or dies on, with
measurements instead of source reading:

- *what order and migratetype does this allocation actually take?* — not what
  the GFP flags in the source suggest, but what `mm_page_alloc` reports on the
  device;
- *does freeing these objects return whole slabs to the buddy allocator?* —
  and how many, how fast, and *by which task on which CPU*;
- *did my reclaim spray take the page the discard just released?* — answered
  by PFN, not by a proxy oracle.

It is a standalone research instrument. It allocates and frees objects any
unprivileged process may allocate and free, and it exploits nothing.

## Why it exists

Every cross-cache in [cves/](../../cves/README.md) rests on three claims that
are easy to get wrong from source and expensive to get wrong in practice: which
*order* the vehicle allocates, which *migratetype* it lands in, and whether the
victim's page ever reaches the buddy allocator at all. The
[CVE-2026-46242](../../cves/cve-2026-46242-badepoll/README.md) chain spent a
long time blocked on a blocker that turned out not to exist, because two of
those three claims were wrong in the source comments and the third had never
been measured. Specifically, on panther:

- the reclaim vehicle was documented as an order-1 allocation "matching the
  filp slab order". It is *order-3* (`kmalloc-8k` is `8192 4 8` — 4 objects,
  8 pages), so it never bid for the freed order-1 block at all;
- pipe data pages were written off as `MIGRATE_MOVABLE` because `pipe_write()`
  uses `GFP_HIGHUSER`. `__GFP_MOVABLE` belongs to `GFP_HIGHUSER_MOVABLE`; pipe
  pages come back `migratetype=0`, *unmovable*, so the disqualification was
  void;
- "no filp slab ever discards" and "6 of 12 victim pages freed" were both in
  the tree at once, from two different proxy oracles, neither of which measured
  a page release.

`/proc/slabinfo` cannot settle any of this — its `active_slabs` moves by ±1
against a 1900-slab background — and `/proc/pagetypeinfo` cannot either, because
unmovable order-0 and order-1 both read 0 in every state on this device. The
kmem tracepoints can, so this tool drives them.

## Mechanism

The probe writes its own phase names into tracefs
[`trace_marker`](pagetrace.c#L38), which land in the same ring buffer as the
kmem tracepoints. Every page event is therefore attributable to the phase it
happened in, and pages are followed across phases by *PFN*:

- `kmem:mm_page_alloc` / `kmem:mm_page_free` give `pfn`, `order` and
  `migratetype` — the page-level truth;
- `kmem:kmalloc` / `kmem:kmem_cache_alloc` give `bytes_alloc` and a symbolic
  `call_site`, which is how an allocation is attributed to a cache
  (`call_site=__alloc_file` with `bytes_alloc=320` is `filp` on this build);
- an order-N block at PFN *P* covers *P..P+2^N-1*, so
  [`analyze.py`](analyze.py) scores a reclaim hit as *any* allocation whose
  block covers a page the discard released.

Arming `events/kmem/*/enable` needs *root* — under tracefs only `tracing_on`,
`trace`, `trace_marker` and `buffer_size_kb` are `0666` (gid 3012
`readtracefs`) on this device. The *probe* still runs as the shell uid, which is
the context the CVE work cares about; only the tracepoint arming is privileged.

## Modes

```sh
tools/pagetrace/pagetrace.sh class pipe 512          # what does a pipe page take?
tools/pagetrace/pagetrace.sh class skb 256           # ... an AF_UNIX 7808-byte send?
tools/pagetrace/pagetrace.sh class inotify 400       # ... an inotify event?
tools/pagetrace/pagetrace.sh drain 20000 6000 6000   # do whole filp slabs discard?
tools/pagetrace/pagetrace.sh place 6000 400 4 4000   # can I discard slabs I chose?
tools/pagetrace/pagetrace.sh reclaim 6000 400 4 k256 3000   # does the spray take one?
```

`place` and `reclaim` first hold a *pool* of filp objects to exhaust the
cache's free slots (at rest, panther's `filp` carries ~3045 free objects across
1600 slabs), so that the subsequent fill has to allocate *fresh* slabs. The fill
must exceed one slab: SLUB never discards the per-cpu *active* slab, so a
25-object fill leaves its slab installed as `c->page` and nothing is returned.

## What it measures on panther (`panther-CP2A.260705.006`)

Each row below is the core result of one of the [modes](#modes) above, reproduced
by re-running that mode on the device; the figures are representative of repeated
runs (ranges are given where a run-to-run spread is the point).

| question | answer |
|---|---|
| pipe data page | `order=0 migratetype=0` (*unmovable*), `gfp_flags=GFP_HIGHUSER\|__GFP_ACCOUNT`, 512/512 |
| AF_UNIX send of 7808 B | `bytes_alloc=8192` → `kmalloc-8k`, backed by `order=3 migratetype=0` |
| inotify event, ~200-byte name | `bytes_alloc=256`, kmalloc-256 *+651 objects with `filp` +69* — a content-controlled kmalloc-256 source that allocates no `struct file` |
| 20 000 filp objects opened then closed | 678 slabs returned to buddy (`filp` 1601 → 2281 → 1603), corroborated by 773–1127 order-1 `mm_page_free` events against a *0-event idle baseline* |
| targeted discard, pool 6000 | *66%, 75%, 83% and 100%* of the slabs we placed, across runs, PFN-matched |
| who discards, and when | an *`rcuop/N` kthread on an unpredictable CPU* — `rcuop/4` observed on cpu1, cpu3 and cpu6, sometimes the process itself — at an unpredictable latency, from ~0 s to ~4 s after the close, usually in a batch ~1 ms wide |
| system's own filp allocation rate | ~338/s at idle, so a 25-slot slab filled in a ~50 µs loop expects *0.017* foreign arrivals |
| order-0 pipe spray vs the discarded pages | *0 hits / 189 986 pages*, against 20 of 20 slabs confirmed discarded |
| order-1 kmalloc-256 spray, all 8 CPUs | *0 hits / 29 004 pages*, against 12 of 16 slabs confirmed discarded — and no discarded page was re-allocated by *anyone*, at any order, within the window |

The last row is the current, measured statement of the
[CVE-2026-46242](../../cves/cve-2026-46242-badepoll/README.md) blocker, and it
is not the one the chain was written against.

## Building

```sh
aarch64-linux-gnu-gcc -static -O1 -o pagetrace tools/pagetrace/pagetrace.c
```

A statically linked glibc binary is enough — the probe is syscalls, `malloc` and
`printf`. `pagetrace.sh` builds it on demand (`CC_AARCH64` overrides the
compiler, `PAGETRACE_BIN` the output path) and pushes it itself.
