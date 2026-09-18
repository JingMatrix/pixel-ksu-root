/* physspray.c — see physspray.h. No device constants; the forged template is
 * the caller's, and the sizing is read live from /proc/meminfo. */
#define _GNU_SOURCE
#include "physspray.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define LIB_PHYSSPRAY_PAGE 4096ULL

unsigned long long lib_physspray_budget_from_kb(unsigned long long mem_avail_kb,
					       unsigned shares)
{
	if (!mem_avail_kb)
		return 0;
	if (!shares)
		shares = 1;

	/* Dynamic headroom: a floor OR a fraction of MemAvailable, whichever is
	 * larger, left free. Spray the rest. Falls back to half if headroom would
	 * exceed what is available (tiny-mem boot). */
	unsigned long long headroom_kb = mem_avail_kb / LIB_PHYSSPRAY_HEADROOM_DIV;
	if (headroom_kb < LIB_PHYSSPRAY_HEADROOM_KB)
		headroom_kb = LIB_PHYSSPRAY_HEADROOM_KB;
	unsigned long long budget_kb =
		mem_avail_kb > headroom_kb ? mem_avail_kb - headroom_kb
					   : mem_avail_kb / 2;
	budget_kb /= shares;
	unsigned long long bytes = budget_kb * 1024ULL;
	if (bytes > LIB_PHYSSPRAY_MAX_BYTES)
		bytes = LIB_PHYSSPRAY_MAX_BYTES;
	if (bytes < LIB_PHYSSPRAY_MIN_BYTES)
		bytes = LIB_PHYSSPRAY_MIN_BYTES;
	return bytes;
}

unsigned long long lib_physspray_budget_bytes(void)
{
	unsigned long long mem_avail_kb = 0;
	FILE *mi = fopen("/proc/meminfo", "r");
	if (mi) {
		char line[256];
		while (fgets(line, sizeof(line), mi)) {
			unsigned long long v;
			if (sscanf(line, "MemAvailable: %llu kB", &v) == 1) {
				mem_avail_kb = v;
				break;
			}
		}
		fclose(mi);
	}
	return lib_physspray_budget_from_kb(mem_avail_kb, 1);
}

void *lib_physspray(size_t bytes, const void *tmpl, size_t tmpl_len)
{
	if (!tmpl || tmpl_len == 0 || tmpl_len > LIB_PHYSSPRAY_PAGE)
		return NULL;

	/* whole pages only */
	size_t len = bytes & ~(size_t)(LIB_PHYSSPRAY_PAGE - 1);
	if (len == 0)
		return NULL;

	void *m = mmap(NULL, len, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (m == MAP_FAILED)
		return NULL;

	/* Build one page (zero-padded when the template is short), then replicate
	 * so every physical page under the mapping carries the identical forge. */
	unsigned char page[LIB_PHYSSPRAY_PAGE];
	memset(page, 0, sizeof(page));
	memcpy(page, tmpl, tmpl_len);

	for (size_t off = 0; off + LIB_PHYSSPRAY_PAGE <= len; off += LIB_PHYSSPRAY_PAGE)
		memcpy((char *)m + off, page, LIB_PHYSSPRAY_PAGE);

	/* Best-effort: keep the spray resident. A failure here is not fatal --
	 * the pages may just be reclaimable under pressure. */
	(void)mlock(m, len);

	return m;
}
