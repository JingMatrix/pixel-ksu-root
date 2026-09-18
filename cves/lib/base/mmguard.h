/* lib/base/mmguard.h -- keeping a process usable while its own address space
 * describes something the kernel must not walk.
 *
 * A chain that corrupts the structure the kernel uses to describe its own
 * mappings gains a read primitive and loses the ability to fault. Two things go
 * wrong after that, and neither is about the corruption itself:
 *
 * A page that was resident when the structure was forged may be reclaimed
 * afterwards. Clean, file-backed pages -- the process's own code -- are the
 * first to go, and a large allocation is exactly what makes the kernel look for
 * them. Re-entering one is then a fault that cannot be resolved, which ends the
 * process at the instruction it was executing.
 *
 * And the structure is not private. Anything permitted to read this process's
 * mappings walks it, on its own schedule, in its own context. On a system where
 * a service polls every process for accounting, that walk is a matter of
 * seconds and its failure is not survivable.
 *
 * Both are answered before the corruption, not after: make the pages resident,
 * and close the mappings to everyone else. Neither call can undo a fault that
 * has already happened.
 *
 * Header-only, libc only, no device constant.
 */
#ifndef LIB_BASE_MMGUARD_H
#define LIB_BASE_MMGUARD_H

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

/* Touch every page of every mapping this process can already read, so none of
 * them needs a fault later.
 *
 * Locking them would be better and is usually not available: the locked-memory
 * limit on a sandboxed process is far below what it maps, and raising it needs
 * a privilege the caller does not have yet. Touching is what is left. It removes
 * the cold-page case -- the one a large allocation creates -- and does not
 * promise residency beyond that, so it belongs immediately before the step that
 * can no longer fault.
 *
 * It is not only code. A page of .bss, of the heap, or of a thread stack that
 * has never been written is just as absent, and the first store to it is the
 * same unserviceable fault. Anything the caller will touch afterwards has to be
 * touched here, which is why this walks every mapping rather than the image.
 *
 * `skip_larger_than` leaves out mappings above a size, for the caller that has
 * just populated gigabytes on purpose and does not want them walked again; 0
 * means walk everything. Write-only and special kernel mappings are skipped --
 * they either cannot be read or must not be.
 *
 * Returns the number of pages touched, or 0 if the mappings could not be read.
 */
static inline unsigned long long lib_prefault_self(unsigned long long skip_larger_than)
{
	FILE *f = fopen("/proc/self/maps", "r");
	if (!f)
		return 0;

	static char line[512];
	unsigned long long touched = 0;
	while (fgets(line, sizeof line, f)) {
		unsigned long long lo, hi;
		char perms[8], path[256];
		path[0] = 0;
		int n = sscanf(line, "%llx-%llx %7s %*s %*s %*s %255s",
			       &lo, &hi, perms, path);
		if (n < 3 || perms[0] != 'r')
			continue;
		/* [vvar] faults on read on some kernels, and a mapped device is not
		 * ours to fault in. Named anonymous regions ([heap], [stack], [anon:*])
		 * are exactly what we do want. */
		if (path[0] == '/' && strncmp(path, "/dev/", 5) == 0)
			continue;
		if (strcmp(path, "[vvar]") == 0 || strcmp(path, "[vsyscall]") == 0)
			continue;
		if (skip_larger_than && (hi - lo) > skip_larger_than)
			continue;
		madvise((void *)(uintptr_t)lo, (size_t)(hi - lo), MADV_WILLNEED);
		for (unsigned long long a = lo; a < hi; a += 4096) {
			volatile unsigned char v = *(volatile unsigned char *)(uintptr_t)a;
			(void)v;
			touched++;
		}
	}
	fclose(f);
	return touched;
}

/* Gate this process's /proc entries behind ptrace access, so another process
 * cannot read the mappings.
 *
 * The caller's own read is unaffected: the access check returns success for a
 * caller in the same thread group before it consults this flag at all, so a
 * chain that reads its own mappings as its primitive keeps working.
 *
 * This raises the bar rather than closing the door -- a reader holding the
 * ptrace capability still passes -- so it reduces the exposure, it does not end
 * it. Returns 0 on success, -1 with errno set.
 */
static inline int lib_hide_own_mm(void)
{
	return prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

#endif /* LIB_BASE_MMGUARD_H */
