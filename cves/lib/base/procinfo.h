/* procinfo.h — /proc text parsers shared across CVEs (header-only).
 *
 * Root-free parsers for sizing a spray off free RAM or waiting on a SLUB cache
 * to drain/refill. They read plain-shell /proc nodes and carry no device
 * constants (all values are read at runtime).
 *
 *   lib_meminfo()            free and total memory
 *   lib_slabinfo_row()       one allocator cache's row, whole
 *   lib_slabinfo()           the three columns most callers want
 *   lib_proc_status_field()  one named field of a process status file
 *
 * /proc/zoneinfo (Node 0 zone Normal spanned pages) is parsed by
 * lib_zone_normal_spanned() in cves/lib/addr/zoneguess.h. /proc/buddyinfo
 * (root-only on this device, unlike the parsers here) and compaction control
 * are in cves/lib/base/compaction.h.
 */
#ifndef LIB_PROCINFO_H
#define LIB_PROCINFO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* /proc/meminfo -> MemTotal / MemAvailable in kB. Either out pointer may be
 * NULL. Returns 0 once MemTotal was found (the always-present field), -1 if the
 * node is unreadable or MemTotal is absent. */
static inline int lib_meminfo(unsigned long long *total_kb,
			      unsigned long long *avail_kb)
{
	FILE *f = fopen("/proc/meminfo", "r");
	if (!f) return -1;
	char line[256];
	unsigned long long total = 0, avail = 0;
	int have_total = 0;
	while (fgets(line, sizeof(line), f)) {
		unsigned long long v;
		if (sscanf(line, "MemTotal: %llu kB", &v) == 1) {
			total = v; have_total = 1;
		} else if (sscanf(line, "MemAvailable: %llu kB", &v) == 1) {
			avail = v;
		}
	}
	fclose(f);
	if (!have_total) return -1;
	if (total_kb) *total_kb = total;
	if (avail_kb) *avail_kb = avail;
	return 0;
}

/* One row of /proc/slabinfo, whole.
 *
 * The allocator publishes, per cache: how many objects are live, how many
 * exist, the object stride, how many fit a slab, how many pages a slab is, and
 * how many slabs are active. Different techniques want different columns --
 * sizing a spray needs the stride, waiting for a cache to drain needs the live
 * count, judging whether a page was released needs the slab count -- so the row
 * is returned whole rather than in one of several near-identical readers.
 *
 * The name is matched as a complete field, so a cache does not match one whose
 * name it is a prefix of. Any output pointer may be NULL.
 *
 * Returns 0 on a matched, parsed row; -1 if the file is unreadable or the cache
 * is absent. Absence is a normal answer: a cache that has never allocated is
 * not listed, and on some configurations the accounted caches are aliased onto
 * the plain ones and do not appear under their own names at all. */
struct lib_slab_row {
	unsigned long long active_objs;
	unsigned long long num_objs;
	unsigned long long objsize;
	unsigned long long objperslab;
	unsigned long long pagesperslab;
	unsigned long long active_slabs;
	unsigned long long num_slabs;
};

static inline int lib_slabinfo_row(const char *name, struct lib_slab_row *out)
{
	FILE *f = fopen("/proc/slabinfo", "re");
	char line[512];
	size_t len = strlen(name);
	int found = 0;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		struct lib_slab_row r;
		const char *sd;

		/* A complete field: the name followed by a space, so "kmalloc-256"
		 * does not match "kmalloc-2k". */
		if (strncmp(line, name, len) || line[len] != ' ')
			continue;
		memset(&r, 0, sizeof(r));
		if (sscanf(line + len, "%llu %llu %llu %llu %llu",
			   &r.active_objs, &r.num_objs, &r.objsize,
			   &r.objperslab, &r.pagesperslab) != 5)
			break;
		/* The slab counts live in a trailing section rather than in the
		 * fixed columns, so they are located by its label. */
		sd = strstr(line, "slabdata");
		if (sd)
			sscanf(sd, "slabdata %llu %llu", &r.active_slabs, &r.num_slabs);
		if (out)
			*out = r;
		found = 1;
		break;
	}
	fclose(f);
	return found ? 0 : -1;
}

/* The three columns most callers want, without a structure. Any pointer may be
 * NULL. Returns 0 on success, -1 otherwise. */
static inline int lib_slabinfo(const char *name,
			       unsigned long long *active_objs,
			       unsigned long long *objsize,
			       unsigned long long *pagesperslab)
{
	struct lib_slab_row r;

	if (lib_slabinfo_row(name, &r))
		return -1;
	if (active_objs)  *active_objs  = r.active_objs;
	if (objsize)      *objsize      = r.objsize;
	if (pagesperslab) *pagesperslab = r.pagesperslab;
	return 0;
}

/* One named field of a process status file, as an integer.
 *
 * These files are a list of `Name:<tab>value` lines whose order and membership
 * vary by kernel configuration, so a reader locates a field by name rather than
 * by position. Where a field carries several numbers, the first is taken.
 *
 * The base is the caller's to state and is not guessable: identity fields are
 * decimal while the capability and signal masks are bare hexadecimal with
 * leading zeros. Letting the parser decide would read a mask like `000001ff...`
 * as octal and stop at the first digit past 7, yielding a small number instead
 * of a mask -- a wrong answer that looks like a plausible one.
 *
 * `pid` may be 0 for the calling process. Returns 0 on success, -1 if the file
 * is unreadable or the field is absent. */
static inline int lib_proc_status_field(int pid, const char *field, int base,
					long long *out)
{
	char path[64], line[512];
	size_t len = strlen(field);
	FILE *f;
	int found = 0;

	if (pid > 0)
		snprintf(path, sizeof(path), "/proc/%d/status", pid);
	else
		snprintf(path, sizeof(path), "/proc/self/status");
	f = fopen(path, "re");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, field, len) || line[len] != ':')
			continue;
		if (out)
			*out = strtoll(line + len + 1, NULL, base);
		found = 1;
		break;
	}
	fclose(f);
	return found ? 0 : -1;
}

#endif
