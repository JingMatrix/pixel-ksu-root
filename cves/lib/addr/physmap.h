/* lib/addr/physmap.h -- converting between physical frames, kernel addresses
 * and page descriptors.
 *
 * The linear map is not randomised on this architecture, which has two
 * consequences everything here rests on: a physical frame has a fixed kernel
 * address, and a page descriptor is a fixed function of the frame number. So
 * these conversions are arithmetic rather than lookups, and they are available
 * before a chain has any read primitive at all.
 *
 * The descriptor array is indexed from the first frame of memory, not from
 * zero, so a frame number taken from a raw source must have that base
 * subtracted before it is used as an index. Omitting the subtraction yields an
 * address that is plausible and wrong.
 *
 * The range check exists for the same reason the conversions do: a pointer read
 * out of a disturbed structure is only safe to follow if it lies in this
 * window, and checking is cheap where the alternative is a fault.
 *
 * Bases come from the target description.
 */
#ifndef LIB_PHYSMAP_H
#define LIB_PHYSMAP_H

#ifndef PAGE_OFFSET
#define PAGE_OFFSET      0xFFFFFF8000000000ULL  /* linear map base            */
#endif
#ifndef PHYS_OFFSET
#define PHYS_OFFSET      0x80000000ULL          /* start of RAM (PA)          */
#endif
#ifndef DIRECT_MAP_BASE
#define DIRECT_MAP_BASE  PAGE_OFFSET            /* alias of PAGE_OFFSET        */
#endif
#ifndef VMEMMAP_START
#define VMEMMAP_START    0xfffffffe00000000ULL  /* struct page array base     */
#endif
#ifndef STRUCT_PAGE_SIZE
#define STRUCT_PAGE_SIZE 0x40ULL                /* sizeof(struct page)         */
#endif
#ifndef PHYS_OFFSET_PFN
#define PHYS_OFFSET_PFN  (PHYS_OFFSET >> 12)    /* start_pfn (0x80000)         */
#endif
#ifndef PAGE_SHIFT
#define PAGE_SHIFT       12                     /* 4K pages                    */
#endif
#ifndef DIRECT_MAP_END
#define DIRECT_MAP_END   0xffffff9000000000ULL  /* linear map end (device fact)*/
#endif

/* PFN <-> linear-map VA (both directions) */
static inline unsigned long long lib_pfn_to_va(unsigned long long pfn)
{
	return ((pfn << 12) - PHYS_OFFSET) | PAGE_OFFSET;
}
static inline unsigned long long lib_va_to_pfn(unsigned long long va)
{
	return (((va & ~PAGE_OFFSET) + PHYS_OFFSET) >> 12);
}

/* linear-map VA -> struct page* (vmemmap). Used for pipe_buffer.page etc.
 * vmemmap is indexed from start_pfn, so subtract it (the pfn_to_vmemmap bug). */
static inline unsigned long long lib_va_to_page(unsigned long long va)
{
	unsigned long long pfn = lib_va_to_pfn(va);
	return VMEMMAP_START + (pfn - PHYS_OFFSET_PFN) * STRUCT_PAGE_SIZE;
}

/* a raw /proc/<pid>/pagemap PFN (PA-0-relative) -> struct page* */
static inline unsigned long long lib_pagemap_pfn_to_page(unsigned long long pfn)
{
	return VMEMMAP_START + (pfn - PHYS_OFFSET_PFN) * STRUCT_PAGE_SIZE;
}

/* The same conversions keyed on the linear-map base as a named device fact
 * rather than on the page offset. The two coincide on the interfaces served
 * here, and keeping one named source for the range-checked forms below is what
 * stops them drifting apart if they ever stop coinciding. */
static inline unsigned long long lib_direct_to_page(unsigned long long addr)
{
	unsigned long long pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
	return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}
static inline unsigned long long lib_page_to_direct(unsigned long long page)
{
	unsigned long long pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
	return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}
/* is this a linear-map (physmap) pointer? range check, [base, end) */
static inline int lib_is_direct_ptr(unsigned long long v)
{
	return v >= DIRECT_MAP_BASE && v < DIRECT_MAP_END;
}

#endif
