/* compaction.h — buddy-allocator state and compaction control (header-only).
 *
 * Whether the buddy allocator holds any free blocks above a given order is
 * the dominant variable this project's cross-cache reclaims measured
 * (cves/lib/spray/crosscache/README.md, "Where the difficulty is"): an
 * order-N request is served from a large, runtime-randomized standing pool
 * when nothing sits above order N, or from a freshly split block when
 * something does, and a freshly split block lands on a just-freed target far
 * more reliably. These functions read that state and can force it, for any
 * consumer that reclaims a page at a specific order, not only crosscache.
 *
 *   lib_buddyinfo_line()   the raw Node 0 /proc/buddyinfo line
 *   lib_buddyinfo_sum_ge() free block count at order >= min_order
 *   lib_compact_root()     force a synchronous, system-wide compaction pass
 *   lib_compact_madvise()  the root-free equivalent, one mapping at a time
 *
 * Unlike procinfo.h's own parsers, /proc/buddyinfo is root-only on this
 * device; lib_compact_root() needs root for the same reason lib_buddyinfo_*
 * do. lib_compact_madvise() needs neither.
 */
#ifndef LIB_COMPACTION_H
#define LIB_COMPACTION_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* /proc/buddyinfo's Node 0 line reads e.g.
 *   Node 0, zone   Normal  82258  54394  18049   3737      0      0      0
 * -- free block COUNTS at order 0, 1, 2, ..., behind a text header of
 * varying token count. `buf` receives the line with its trailing newline
 * stripped. Returns 0, or -1 if the file could not be read. */
static inline int lib_buddyinfo_line(char *buf, size_t sz)
{
	FILE *f = fopen("/proc/buddyinfo", "re");
	int ok;

	if (!f)
		return -1;
	ok = fgets(buf, (int)sz, f) != NULL;
	fclose(f);
	if (ok) {
		size_t n = strlen(buf);

		if (n && buf[n - 1] == '\n')
			buf[n - 1] = '\0';
	}
	return ok ? 0 : -1;
}

/* Free block count at order >= min_order, summed across whatever orders
 * /proc/buddyinfo reports. Every whitespace-separated token that does not
 * parse as a bare integer is skipped as part of the text header, rather than
 * assuming a fixed skip count, so this survives a header shape it does not
 * otherwise depend on. Returns -1 if the file could not be read at all. */
static inline long lib_buddyinfo_sum_ge(int min_order)
{
	char line[256];
	char *save = NULL;
	long sum = 0;
	int order = 0;

	if (lib_buddyinfo_line(line, sizeof(line)) != 0)
		return -1;
	for (char *tok = strtok_r(line, " \t", &save); tok;
	     tok = strtok_r(NULL, " \t", &save)) {
		char *end;
		long v = strtol(tok, &end, 10);

		if (end == tok || *end != '\0')
			continue;   /* not a bare integer -- part of the text header */
		if (order >= min_order)
			sum += v;
		order++;
	}
	return sum;
}

/* echo 1 > /proc/sys/vm/compact_memory -- a synchronous, system-wide
 * compaction pass. Root. No return value: a caller checks the effect through
 * lib_buddyinfo_sum_ge(), which is ground truth, rather than this call's own
 * success. */
static inline void lib_compact_root(void)
{
	FILE *f = fopen("/proc/sys/vm/compact_memory", "we");

	if (!f)
		return;
	fputs("1", f);
	fclose(f);
}

#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25   /* not in every NDK's <sys/mman.h> yet, though the kernel has it */
#endif

/* The root-free equivalent: mmap and touch an mb-megabyte anonymous region,
 * then madvise(MADV_COLLAPSE) it, forcing synchronous compaction of that one
 * mapping through the same kcompactd path a privileged trigger uses. Needs
 * no capability. Weaker than lib_compact_root(), because it reaches only the
 * mapping it is given, not the whole system's fragmentation, and the kernel
 * caps a single call's mapping size -- this does not retry at a smaller size
 * on failure, so a caller sweeping this value sees that failure directly.
 * Returns the raw madvise() return value, or -1 with errno set by mmap() if
 * the mapping itself could not be made. */
static inline int lib_compact_madvise(size_t mb)
{
	size_t len = mb * 1024 * 1024;
	void *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	int rc;

	if (p == MAP_FAILED)
		return -1;
	for (size_t i = 0; i < len; i += 4096)
		((volatile unsigned char *)p)[i] = 1;
	rc = madvise(p, len, MADV_COLLAPSE);
	munmap(p, len);
	return rc;
}

#endif /* LIB_COMPACTION_H */
