/* lib/addr/physlayout.c -- see physlayout.h. */
#include "physlayout.h"

#include <string.h>

#include "../target.h"
#include "physmap.h"

/* Extent of memory, as the linear map spans it. */
#define MEMORY_SPAN (DIRECT_MAP_END - DIRECT_MAP_BASE)

int lib_physlayout_load(const struct krw *rw, struct lib_physlayout *out,
			uint64_t memstart_addr, uint64_t voffset_addr,
			uint64_t image_begin, uint64_t image_end)
{
	uint64_t image_phys;

	memset(out, 0, sizeof(*out));
	if (!krw_read(rw, k_direct_raw(memstart_addr), &out->memstart, sizeof(out->memstart)) ||
	    !krw_read(rw, k_direct_raw(voffset_addr), &out->image_voffset,
		      sizeof(out->image_voffset)))
		return -1;

	/* Both are page-granular by construction; anything else means the read
	 * returned something that is not the value being looked for. */
	if (!out->memstart || (out->memstart & (PAGE_SIZE - 1)) ||
	    (out->image_voffset & (PAGE_SIZE - 1)))
		return -1;
	if (image_begin < out->image_voffset)
		return -1;

	image_phys = image_begin - out->image_voffset;
	if (image_phys < out->memstart || image_phys - out->memstart >= MEMORY_SPAN)
		return -1;

	out->image_begin = image_begin;
	out->image_end = image_end;
	return 0;
}

int lib_phys_of(const struct lib_physlayout *l, uint64_t kaddr, uint64_t *out)
{
	uint64_t addr = lib_untag(kaddr);
	uint64_t phys;

	if (addr >= DIRECT_MAP_BASE && addr < DIRECT_MAP_END)
		phys = l->memstart + addr - DIRECT_MAP_BASE;
	else if (addr >= l->image_begin && addr < l->image_end &&
		 addr >= l->image_voffset)
		phys = addr - l->image_voffset;
	else
		return -1;

	if (phys < l->memstart || phys - l->memstart >= MEMORY_SPAN)
		return -1;
	*out = phys;
	return 0;
}

int lib_page_of_phys(const struct lib_physlayout *l, uint64_t phys,
		     uint64_t *page_desc, uint32_t *page_offset)
{
	uint64_t delta;

	if (phys < l->memstart)
		return -1;
	delta = phys - l->memstart;
	if (delta >= MEMORY_SPAN)
		return -1;
	*page_desc = VMEMMAP_START + (delta / PAGE_SIZE) * STRUCT_PAGE_SIZE;
	*page_offset = (uint32_t)(phys & (PAGE_SIZE - 1));
	return 0;
}
