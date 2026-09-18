/* pagemap.h — /proc/<pid>/pagemap VA->PFN reader, shared across CVEs.
 *
 * Reads a virtual address's page-table entry out of /proc/<pid>/pagemap and
 * returns its physical frame number, and (via physmap.h) the linear-map kernel
 * VA of that frame. This is the exact-page oracle: it tells you *where* a page
 * a process owns actually landed in physical memory.
 *
 * NEEDS CAP_SYS_ADMIN. Since kernel 4.0, an unprivileged reader gets the PFN
 * field zeroed out (present bit and flags still show), so these helpers return
 * 0 for a caller without CAP_SYS_ADMIN. This is a root/oracle helper only —
 * the unprivileged page-placement path is lib/addr/zoneguess.h (upper-Normal-zone
 * guess), which needs no pagemap at all.
 *
 * No device-specific constants live here; the PA<->VA conversion is delegated
 * to physmap.h (lib_pfn_to_va), where the linear-map bases are defined.
 */
#ifndef LIB_PAGEMAP_H
#define LIB_PAGEMAP_H

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "physmap.h"   /* lib_pfn_to_va, PHYS/PAGE bases */

/* PFN of the page backing `va` in process `pid`, or 0 if not present
 * (also 0 without CAP_SYS_ADMIN, and 0 if the page is swapped/absent). */
static unsigned long long lib_pagemap_pfn(int pid, unsigned long long va)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/pagemap", pid);
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;

	unsigned long long ent = 0;
	unsigned long long idx = (va / 4096) * 8;
	ssize_t n = pread(fd, &ent, sizeof(ent), (off_t)idx);
	close(fd);
	if (n != (ssize_t)sizeof(ent))
		return 0;

	if (!(ent >> 63))            /* bit 63: page present            */
		return 0;
	if (ent & (1ULL << 62))      /* bit 62: swapped -> no PFN        */
		return 0;

	return ent & ((1ULL << 55) - 1);   /* bits 0..54: PFN           */
}

/* Linear-map kernel VA of the page backing `va` in process `pid`, or 0 if
 * not present / unprivileged. Reuses physmap.h's PFN->VA conversion. */
static unsigned long long lib_pagemap_page_va(int pid, unsigned long long va)
{
	unsigned long long pfn = lib_pagemap_pfn(pid, va);
	if (!pfn)
		return 0;
	return lib_pfn_to_va(pfn);
}

#endif /* LIB_PAGEMAP_H */
