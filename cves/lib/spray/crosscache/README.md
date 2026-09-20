# Cross-cache

Taking a page away from the allocator cache that owns it and getting it back from a
different one, with bytes of our choosing in it.

A [slab allocator](https://docs.kernel.org/mm/slub.html) hands out objects of one size from
pages it keeps per cache. An exploit that can corrupt an object in cache A often cannot
reach anything worth corrupting *inside* cache A — but if the page holding that object is
returned to the page allocator and handed out again to cache B, then a corruption aimed at
A's object lands on B's contents. The page is the unit of exchange, and the technique is
the sequence that makes the exchange happen on purpose.

Four steps, in every implementation here. Groom, by allocating enough objects of the victim
cache that one page belongs to us alone, with nothing of the kernel's on it. Acquire the
address, which here comes from a futex-hash timing side channel and so needs no
memory-corruption primitive at all. Surrender the page, by freeing every object on it so
that the cache releases it. Then refill immediately from a *different* cache, at a size
that takes a fresh page, carrying content we choose; if it takes the page just released,
the exchange worked.

That last step is a race against every other allocation on the device, which is why it is
measured rather than assumed — see `runner/recipes/crosscache-bench.toml`.

## Two families, and they are not interchangeable

Which family applies is decided by the bug, not by preference.

### Owned victim — the methods in this directory

The object whose page is taken is one *we* allocated. We choose when it is freed, and we
can learn its address before freeing it, which makes the whole sequence schedulable: every
step happens when we say.

Both methods below are of this family. They return the page's address, so a consumer can be
moved from one to the other and the only thing that changes is how often the refill lands.

| method | what it does differently | when it applies |
|---|---|---|
| `swap` | takes the page with filler bytes, reads the address, then exchanges it a second time for the real payload | the caller owns the victim and can free it on its own schedule |
| `direct` | reads the address while the victim is still alive, composes the payload, then gives the page up once | the same, plus the address must be readable before the free |
| `stream` | same as `direct`, refilled over a connection-oriented socket instead of a datagram, `nspray` independent sockets each sent once (`CC_STREAM_MULTI`, on by default) | the receiving allocator only shapes correctly behind a stream send's own path |
| `pipe-bare` | refills with real `pipe_buffer` arrays over a stream hold, no shaping pass, the leak run in a forked child so the groom that builds the drain/reclaim pools never shares a process with it | the consumer wants a kernel object at the page, not its own bytes, and supplies no `compose` |

`pipe-bare` measures 0/30 landed in each of two independent bench runs (60 rounds total,
`--method pipe-bare --nspray 64`), with the drain/reclaim pools built in the caller's process
before the leak's own fork (see `crosscache.c`). It is modeled on a configuration with
rounds=0, reconstructed through this shared method interface as a separate implementation
from a caller's own proven shape/drain/reclaim sequence, which instead calls
`crosscache_leak_base_stream()` directly. Treat its own number as what this reconstruction
measures, not as the proven sequence's result.

The difference exists because a payload worth checking has to name the page it was composed
for. Otherwise every payload is byte-identical wherever it lands, and a successful
placement cannot be told apart from the previous one. `direct` solves that by reading the
address early; `swap` reads it late and therefore needs the page to change hands twice, the
second exchange being the one that must land. Which lands more often is an empirical
question for the bench recipe. Choose `swap` unless the address is needed before the free.

`stream` exists because a caller with two reclaims -- a fake `file_operations` table and a
pipe-buffer-array reclaim, both built through this module -- was proven on hardware to need a
connection-oriented socket for the hold/refill step, not a datagram. `swap` and `direct` use
a datagram there because that is what a foreign-victim consumer with no other constraint
needs (a single, discretely-held message it can locate later); nothing established that a
datagram reclaims a freed `mm_struct`-order page as well as a stream one does, for either
landing rate or the specific allocator path taken. `stream` keeps that proven choice
available to any caller that needs it, rather than defaulting every caller to whichever
vehicle the newest consumer happened to want.

`crosscache_leak_base_stream()` is the same choice at the leak-only layer: the groom and the
hold, with the reclaim left to the caller. A caller's own pipe-buffer-cache shaping, draining
and reclaiming (a `shape_pipe_cache()`-style function with its own `PIPE_SHAPE_ROUNDS`-style
repeat) stays in the caller rather than moving into `crosscache_pipe_reclaim()`, because that
function only shapes once and has no equivalent repeat count here -- and because none of that
machinery touches the `mm_struct` cache the leak depends on.

### Foreign victim — not here, and not portable to here

The object was freed by the *kernel*, on its own schedule. Typically the free is
[RCU](https://docs.kernel.org/RCU/whatisRCU.html)-deferred, and the deferred work runs on a
processor the caller does not choose. Three things the owned-victim family relies on are
all absent: the address is never learned, so the payload cannot name its page; the free
cannot be timed, so there is no moment to refill into; and success cannot be confirmed by
reading the page, because there is no address to read, only a weaker and inverted oracle to
search with afterwards.

A method in that position cannot return a page address, so it cannot implement this
interface, and making it look as though it does would misdescribe what it produces. A
consumer whose objects live in a `SLAB_TYPESAFE_BY_RCU` cache, where the page discard is
itself deferred, is such a case: its cross-cache step reports evidence that the page moved
rather than returning a page it owns. It shares the name and almost none of the mechanism.

## Using it

```c
static void compose(void *page, size_t len, uintptr_t base, void *user)
{
        /* ... fill the payload; it must record `base` somewhere inert ... */
        crosscache_stamp_self(page, len, MY_SELFNAME_OFF, base);
}

struct crosscache_request req = {
        .cfg = CROSSCACHE_CFG_PANTHER_61,
        .compose = compose, .user = NULL,
        .send_bytes = 0x8000, .nspray = 1,
};
uintptr_t base = crosscache_place_with(crosscache_method_named("swap"), &req);
/* ... use the page ... */
crosscache_cleanup();
```

The refill allocations still hold the page when the placement call returns. Release them
with `crosscache_cleanup()`, but not before anything that needs to read the page has done
so, because which of the refill allocations took it is not knowable from outside.

## Where the difficulty is

Not in the code. The groom and the refill are mechanical; what decides whether a placement
lands is the state of the page allocator at one instant, which is shared with everything
else running. That is why the knobs that matter are timing and count — how many refill
allocations are fired, what is freed just before them, which processor the sequence is
pinned to — and why changing any of them is worth measuring rather than reasoning about.

The free and the refill in `cc_clone_leak_child()`'s own leaked process are pinned to the
same processor (`CC_LEAK_PIN`, on by default) for exactly this reason: that child's `_exit()`
is what frees the target page, synchronously, on whichever CPU the scheduler had it running
on, and a refill pinned to a different one is racing a free it cannot see land. Every child
in the same groom pins itself for the same reason.

`stream`'s own socket structure -- whether the `nspray` refill attempts are `nspray`
independent sockets, each sent once (`CC_STREAM_MULTI`), or one socket sent to `nspray` times
in a row -- is a real, modest lever. Measured against a matched baseline, independent sockets
hold a consistent edge over the repeated-single-socket form; `CC_STREAM_MULTI` defaults on for
that reason, with `=0` reaching the single-socket form for comparison. It is a minor effect
next to the one below.

The dominant variable in this whole module is not a socket structure or a timing choice at
all: it is whether the buddy allocator currently holds any free blocks above order 3, readable
directly from `/proc/buddyinfo` (root; the columns are free block counts at order 0, 1, 2,
...). `mm/page_alloc.c`'s `__rmqueue_smallest()` checks order 3's own free list first and only
climbs to a higher order and splits it when order 3 is empty or under pressure --
`CONFIG_SHUFFLE_PAGE_ALLOCATOR=y` (confirmed on this kernel via `/proc/config.gz`) means a
large *standing* pool of already-free order-3 blocks is randomized at runtime, so competing
against thousands of them for one specific just-freed page is a weak position. A freshly split
block, taken because nothing was waiting in order 3 already, lands on a just-freed target far
more reliably.

Reading and forcing that state is `cves/lib/base/compaction.h`, not specific to this module --
any consumer that reclaims a page at a specific order can use it. Two triggers force the
favorable state, at different privilege levels, both wired into this bench via `--compact` and
`--compact-madvise N`:

- **`lib_compact_root()`** (root, write-only `/proc/sys/vm/compact_memory`) forces a
  synchronous, system-wide compaction pass. From a depleted state (orders above 3 empty), this
  reclaim's landing rate moves from the teens/twenties percent to consistently near-total.
- **`lib_compact_madvise(mb)`** (`madvise(ptr, len, MADV_COLLAPSE)` on a throwaway anonymous
  mapping) needs no privilege and forces synchronous compaction of that one mapping through the
  same kcompactd path. From the same depleted baseline, landing roughly doubles -- weaker than
  the root trigger because it reaches only the mapping it is given, not the whole system's
  fragmentation. A single call succeeds up to roughly 64MB and fails with `ENOMEM` above that;
  repeating it once the state is already compacted adds little further.

`bench_round()` prints `lib_buddyinfo_sum_ge(4)` every round, and `bench_series()` prints the
full `lib_buddyinfo_line()` before and after each series, so a run's own log carries the
allocator state a verdict depended on, not just the verdict.

Three further instruments exist for measuring the allocator's own state directly, each a
port of a specific published technique rather than a guess wearing its name:

- **`cves/lib/base/cycles.h`** (`lib_cycles()`) and **`bench/crosscache.c --calibrate-signal
  N`** transcribe SLUBStick's own published timing side channel
  ([USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/maar-slubstick),
  `isec-tugraz/SLUBStick`): a cycle counter, not wall-clock time; a probe built from the same
  object the real reclaim uses, grown one per iteration; the raw consecutive-delta series
  printed, not tested against an invented threshold — their own threshold is specific to
  their target and its sign is a speed-up, not a slow-down, so nothing here assumes either
  the value or the direction transfers. Measured on this device (panther, 256 and 8192
  samples): no separable signal at any window size — `CNTVCT_EL0` here ticks at 24.576MHz
  (~40.7ns/tick), and the PMU cycle counter that would give finer resolution is not
  EL0-readable on this device (a userspace read SIGILLs). This channel is not usable here.
- **`bench/crosscache.c --pcp-trial N --pcp-order O --pcp-spray-n S`** transcribes
  PCP-massaging's grooming loop
  ([Migliorelli et al., NDSS 2026](https://www.ndss-symposium.org/ndss-paper/cross-cache-attacks-for-the-linux-kernel-via-pcp-massaging/),
  reference implementation `x0prc/PCP-LOST`): alloc, free, adaptively re-groom while
  measuring reuse, spray an unrelated cache, re-measure. Their own reference implementation's
  timing oracle runs inside a kernel module (`ktime_get_ns()` around `alloc_pages()`
  directly); there is no unprivileged version of it published. This bench already runs
  privileged for its own judge, so it substitutes the same ground truth their module reports
  — a real PFN, via the already-existing `lib_pagemap_pfn()` — for the module, and needs the
  same root. Their `msg_msg` spray for the unrelated cache does not port: SysV IPC is not
  configured on this device, so an AF_UNIX send stands in for it. Measured on this device:
  97% final overlap at order 0 (their own experiment's order), 0-3% at order 3 (`mm_struct`'s
  own order) across a spray-count sweep — order-dependent, not tunable into working at order 3
  by any spray value tried.
- **`bench/crosscache.c --pspray-calibrate N --pspray-warmup C`** transcribes Pspray's
  slow-path detector ([Lee et al., USENIX Security 2023](https://www.usenix.org/system/files/usenixsecurity23-lee-yoochan.pdf));
  no source release accompanies the paper, so this is ported from the public artifact that
  reuses the same detector, `MPI-SysSec/Heap-Localization`'s
  `real-world/spatial_cross_cache_attack/exploit.localization.c`. Every iteration times its
  own allocation (a pre-created socketpair's `send()`, standing in for their `msgsnd()` into a
  pre-created SysV queue — same "timed span is exactly one allocation call" property, SysV IPC
  again not being configured here), keeps a running mean over every timing seen so far, and
  prints each post-warmup iteration's margin against that mean; their own fixed threshold
  (margin > 2000 x86 RDTSC cycles) is not applied, for the same reason `--calibrate-signal`
  does not apply SLUBStick's. Measured on this device across two independent 8192-iteration
  runs: unlike `--calibrate-signal`, this one shows a real, reproducible bimodal split — a
  main cluster under roughly 250 ticks and a handful (5-7 per run, clustered late in each run
  rather than spread evenly) of clearly separated outliers 2-4x higher, matching the paper's
  own finding that a fresh slab from the page allocator costs far more than reusing a partial
  one. This channel is visible on this device, at generic sizes that resolve to an order-0 or
  order-1 page fragment -- but not at order 3. Traced against the real kernel source
  (`net/unix/af_unix.c`, `net/core/skbuff.c`, v6.1.157) rather than guessed at: the `stream`
  method's own send (`unix_stream_sendmsg`) chunks a large payload per `SKB_MAX_HEAD(0) +
  UNIX_SKB_FRAGS_SZ` (36544B on this kernel), and even the exact byte count that collapses
  this to ONE clean order-3 `alloc_pages()` call and nothing else (computed by hand from that
  arithmetic) still shows no split -- a smooth, gapless spread instead (p50=226, p90=496,
  p99=1303, max=7328).

  Root-caused with `cves/lib/trace/evthist.h`'s `mm_page_alloc_zone_locked` ground truth (see
  below): the same 36544-byte send does not touch the buddy allocator's zone lock a fixed
  number of times. Two consecutive, identical calls measured 7 zone-locked events and then 0
  -- the per-CPU pageset sometimes had an order-3 page ready (no zone lock at all) and
  sometimes did not. Pspray's clean binary signal comes from SLUB's own small, discrete
  fast/medium/slow-path menu for sub-page objects; a raw order-3 page request bypasses SLUB
  entirely, and its zone-lock hit count is a variable quantity (0, or several), not a binary
  one -- so timing it naturally produces a continuous spread, not two clusters. This is a
  measured fact, not an inferred one. Pspray does not extend to order 3 on this device.
  `--pspray-bytes N` selects the send size; `--pspray-calibrate` alone prints a Tukey-fence
  outlier rate (Q3+1.5*IQR over the post-warmup samples, this run's own split point, not a
  portable constant) alongside the raw series.

- **`cves/lib/trace/evthist.h`** is not a port of a published technique -- it counts a real
  kernel tracepoint (`mm_page_alloc_zone_locked`) through the tracing interface's own
  histogram trigger (`hist:key=order`), reading the cumulative per-order hitcount before and
  after a span of interest and taking the difference. Unlike a dynamic kprobe (`fnprobe.h`),
  this needs no `kprobe_events` registration -- the event already exists -- and unlike
  streaming `trace_pipe`, a hist trigger is a running counter with no ring buffer to overflow
  or drain. This is what root-caused the Pspray result above, and what the `CC_FRAG_BYTES`
  finding right below was tested with.

`CC_FRAG_BYTES` is an env var this module's own `cc_frag_len()` reads, overriding
`order_size*2` for every method that calls it (`direct`, `swap`, `stream`,
`crosscache_content_reclaim`). `order_size*2` does not send a single order-matched fragment
for order 3: it sends extra order-1/order-2 fragments alongside the order-3 one. The extra
fragments are not waste to trim: an isolated, exact-fragment-only send does not deterministically
touch the zone lock (`evthist` measures 0 or several zone-locked events for identical calls),
so it does not reliably reach the buddy free area a just-freed target page would be in, while
the extra order-1/order-2 activity in the default size appears to force the order-3 request
through that same zone lock consistently instead of occasionally being satisfied from an
unrelated, already-cached per-CPU page. Landing rate confirms the direction: the exact-fragment
size measures lower than the default, not higher. `CC_FRAG_BYTES` stays as a research knob; the
default formula is unchanged.

None of the four instruments decides anything on its own. Each prints what it measured;
picking a parameter or a threshold from that output is a step this module leaves to the
caller.

## A consumer that leaks its own address first

A caller that must resolve its own `mm_struct` address before it can also place a forge here
runs two KernelSnitch instances back to back in one process, against the identical
`mm_struct`/order-3 class. Every ordinary bench round measures this module in isolation,
which is a different condition from that. `bench/crosscache.c --precede-leak 1` runs the same
unrelated leak immediately before every round's own placement, so the two conditions can be
measured against each other directly instead of inferred — see the flag's note in
`runner/stages/bench.crosscache@6.1/stage.toml`.
