# tools/pagetrace — what an allocation really takes, and where a freed slab page goes

`pagetrace` answers the questions a cross-cache attempt lives or dies on, by measurement
rather than by reading source. What order and migratetype does an allocation actually take,
as opposed to what its allocation flags suggest? Does freeing a set of objects return whole
slabs to the buddy allocator, and if so how many, how quickly, and by which task on which
processor? And did a reclaim spray take the very page a discard just released — answered by
frame number, not by a proxy.

It is a standalone research instrument. It allocates and frees objects any unprivileged
process may allocate and free, and it exploits nothing.

## Why it exists

Every cross-cache in [cves/](../../cves/README.md) rests on three claims that are easy to
get wrong from source and expensive to get wrong in practice: which order the reclaim
vehicle allocates in, which migratetype it lands in, and whether the victim's page ever
reaches the buddy allocator at all.

None of the three is safely inferred. An allocation's order follows from the size class the
allocator actually assigns, not from the shape of the request; a page's migratetype follows
from the exact allocation-flag combination, and neighbouring combinations differ in the
movability bit; and whether a page is released at all depends on the allocator's own
bookkeeping rather than on how many objects were freed. A chain written against the
inferred answer can spend a long time blocked on a constraint that does not exist.

The obvious observation points do not settle any of it either. The slab listing moves by a
slab or two against a background of many hundred, and the page-type listing reads zero in
every state for the orders that matter here. The kernel's
[memory tracepoints](https://docs.kernel.org/trace/ftrace.html) do settle it, so this tool
drives them.

## Mechanism

The probe writes its own phase names into `trace_marker`, which land in the same ring
buffer as the memory tracepoints. Every page event is therefore attributable to the phase
it happened in, and pages are followed across phases by frame number.

The page allocation and free tracepoints give the frame number, the order and the
migratetype, which is the page-level truth. The slab tracepoints give the allocated size
and a symbolic call site, which is how an allocation is attributed to a particular cache.
Because an order-N block starting at a given frame covers the whole run of frames above it,
the analysis scores a reclaim hit as any allocation whose block covers a page the discard
released, rather than demanding an exact frame match.

Arming the tracepoints needs root. Within tracefs only the tracing switch, the formatted
trace, the marker and the buffer size are group-accessible to the shell user. The probe
itself still runs as the shell uid, which is the context the exploit work cares about; only
the arming is privileged.

## Modes

```sh
tools/pagetrace/pagetrace.sh class pipe 512          # what does a pipe page take?
tools/pagetrace/pagetrace.sh class skb 256           # ... a large AF_UNIX send?
tools/pagetrace/pagetrace.sh class inotify 400       # ... an inotify event?
tools/pagetrace/pagetrace.sh drain 20000 6000 6000   # do whole slabs discard?
tools/pagetrace/pagetrace.sh place 6000 400 4 4000   # can I discard slabs I chose?
tools/pagetrace/pagetrace.sh reclaim 6000 400 4 k256 3000   # does the spray take one?
```

The `place` and `reclaim` modes first hold a pool of victim objects, to exhaust the cache's
free slots so that the fill which follows has to allocate fresh slabs. The fill must exceed
one slab's worth: the allocator never discards the per-processor active slab, so a fill
smaller than one slab leaves its slab installed and returns nothing.

## Reading a run

A run is interpreted in one direction only. A discard confirmed by frame number is
evidence; a discard inferred from a count of freed objects is not. A spray that reports no
hit against a set of confirmed discarded pages is a real negative result about that
vehicle, and the useful follow-up question is whether any allocation at any order took
those pages inside the window — which the same capture answers, because the tracepoints see
every allocation rather than only the tool's own.

Latency and locality are part of the answer rather than noise. A page released by a
deferred-free kernel thread appears on whichever processor that thread happens to run on,
at a delay the tool does not control, and a spray that assumes the releasing processor is
its own will miss for reasons that have nothing to do with its size or timing. This is why
the capture records which task on which processor performed each free.

## Building

```sh
aarch64-linux-gnu-gcc -static -O1 -o pagetrace tools/pagetrace/pagetrace.c
```

A statically linked binary is enough, since the probe is syscalls and the C library's
allocator and formatted output. `pagetrace.sh` builds it on demand — the compiler and
output path are overridable through the environment — and pushes it itself.
