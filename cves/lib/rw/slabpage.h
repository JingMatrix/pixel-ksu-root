/* lib/rw/slabpage.h -- deciding whether a page is the one a reclaim aimed at.
 *
 * A cross-cache reclaim frees a page from one allocator cache and hopes the
 * next allocation of a different size takes it. Hope is not a result, so before
 * anything writes through the page it has to be checked, and the check is the
 * difference between a technique and a coin flip: a wrong page is not a miss,
 * it is an arbitrary write into a stranger's memory.
 *
 * The page descriptor answers the question directly, given a read primitive.
 * Four properties together are conclusive:
 *
 *   The allocator flag says the page belongs to the slab allocator at all.
 *   The head flag says it is the first page of a multi-page allocation, which
 *     is what a reclaim of a higher-order page must land on.
 *   A tail page's back-pointer names the head, with the low bit set. This is
 *     what rules out a page that merely looks plausible.
 *   The cache pointer names the cache the reclaim expected.
 *
 * The last is the one that matters most and is also the easiest to get wrong:
 * where the descriptor keeps it differs between kernel interfaces, so it comes
 * from the target description and is never assumed.
 *
 * Reading these costs several accesses through whatever primitive is installed,
 * which is why this is a gate run once before a write rather than a check
 * repeated inside a loop.
 */
#ifndef LIB_RW_SLABPAGE_H
#define LIB_RW_SLABPAGE_H

#include <stdint.h>

#include "krw.h"

/* What the check observed, so a caller can report why a page was rejected
 * rather than only that it was. */
struct lib_slabpage_report {
	uint64_t descriptor;     /* page descriptor address examined        */
	uint64_t flags;          /* its flags word                          */
	uint64_t tail_flags;     /* the following descriptor's flags word   */
	uint64_t compound_head;  /* the following descriptor's back-pointer */
	uint64_t slab_cache;     /* the cache the page claims               */
	uint64_t want_cache;     /* the cache the caller expected           */
	int      order;          /* allocation order read from the tail     */
};

/* Is the page aliased by `direct` the head of an order-`want_order` allocation
 * belonging to `want_cache`? Returns 1 if all four properties hold, 0 if any
 * does not, -1 if a read failed. `out` may be NULL. */
int lib_slabpage_check(const struct krw *rw, uint64_t direct,
                       uint64_t want_cache, int want_order,
                       struct lib_slabpage_report *out);

/* Address of the cache slot for one (row, bucket) of the allocator's size
 * table, as a physmap alias. A caller reads it to learn which cache an
 * allocation of a given size and accounting class comes from. */
uint64_t lib_slabpage_cache_slot(uint64_t caches_direct, int row, int bucket);

#endif /* LIB_RW_SLABPAGE_H */
