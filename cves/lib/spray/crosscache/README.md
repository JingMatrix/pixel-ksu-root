# Cross-cache

Taking a page away from the allocator cache that owns it and getting it back
from a different one, with bytes of our choosing in it.

A slab allocator hands out objects of one size from pages it keeps per cache.
An exploit that can corrupt an object of cache A often cannot reach anything
worth corrupting *in* cache A — but if the page holding that object is returned
to the page allocator and handed out again to cache B, then a corruption aimed
at A's object lands on B's contents. The page is the unit of exchange, and the
technique is the sequence that makes the exchange happen on purpose.

Four steps, in every implementation here:

1. Groom. Allocate enough objects of the victim cache that one page belongs
   to us alone, with nothing else of the kernel's on it.
2. Acquire the address. Learn where that page is. Here that comes from a
   futex-hash timing side channel (`lib/leak/futex_scan.h`), which needs no
   memory-corruption primitive at all.
3. Surrender the page. Free every object on it, so the cache releases the
   page to the page allocator.
4. Refill. Immediately allocate from a *different* cache, of a size that
   takes a fresh page, carrying content we choose. If it takes the page we just
   released, the exchange worked.

Step 4 is a race against every other allocation on the device, which is why
this is measured rather than assumed — see `runner/recipes/crosscache-bench.toml`.

## Two families, and they are not interchangeable

Which family applies is decided by the bug, not by preference.

### Owned victim — the methods in this directory

The object whose page is taken is one *we* allocated. We choose when it is
freed, and we can learn its address before freeing it. This makes the sequence
schedulable: every step happens when we say.

Both methods below are this family. They return the page's address, so a
consumer can be moved from one to the other and the only thing that changes is
how often the refill lands.

| method | what it does differently | when it applies |
|---|---|---|
| `swap` | takes the page with filler bytes, reads the address, then exchanges it a second time for the real payload | the caller owns the victim and can free it on its own schedule |
| `direct` | reads the address while the victim is still alive, composes the payload, then gives the page up once | the same, plus the address must be readable before the free |

The difference exists because a payload worth checking has to name the page it
was composed for — otherwise every payload is byte-identical wherever it lands
and a successful placement cannot be told from the previous one. `direct` solves
that by reading the address early. `swap` reads it late and therefore needs the
page to change hands twice, the second exchange being the one that must land.

Which lands more often is an empirical question;
`runner/recipes/crosscache-bench.toml` measures it. Choose `swap` unless the
address is needed before the free.

### Foreign victim — not here, and not portable to here

The object was freed by the *kernel*, on its own schedule. Typically it is
RCU-deferred, and the deferred free runs on a processor the caller does not
choose. Three things that the owned-victim family relies on are all absent:

- the address is never learned, so the payload cannot name its page;
- the free cannot be timed, so there is no moment to refill *into*;
- success cannot be confirmed by reading the page, because there is no address
  to read — only searched for afterwards, with a weaker, inverted oracle.

A method in that position cannot return a page address, so it cannot implement
this interface, and making it look as though it does would misdescribe what it
produces. `cves/cve-2026-46242-badepoll` is such a consumer: its objects live in
a `SLAB_TYPESAFE_BY_RCU` cache whose page discard is itself RCU-deferred, and
its cross-cache step reports *evidence that the page moved*, not a page it owns.
It shares the name and almost none of the mechanism.

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

The refill allocations still hold the page when `crosscache_place_with` returns.
Release them with `crosscache_cleanup()` — but not before anything that needs to
read the page has done so, because which of `nspray` allocations took it is not
knowable from outside.

## Where the difficulty is

Not in the code. The groom and the refill are mechanical; what decides whether a
placement lands is the state of the page allocator at one instant, which is
shared with everything else running. That is why the knobs that matter are
timing and count — how many refill allocations are fired, what is freed just
before them, which processor the sequence is pinned to — and why changing any of
them is worth measuring rather than reasoning about.
