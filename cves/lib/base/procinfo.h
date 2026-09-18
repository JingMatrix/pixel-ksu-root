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
 *   lib_proc_read_small()    a whole small /proc node into a buffer
 *   lib_proc_pids_by_cmdline() every pid whose cmdline mentions a string
 *   lib_proc_task_text()     one text node of a task (comm, wchan, stack, ...)
 *   lib_proc_task_state()    the scheduler state letter of a task
 *   lib_proc_task_prio()     the task's raw kernel prio (p->prio)
 *
 * /proc/zoneinfo (Node 0 zone Normal spanned pages) is parsed by
 * lib_zone_normal_spanned() in cves/lib/addr/zoneguess.h. /proc/buddyinfo
 * (root-only on this device, unlike the parsers here) and compaction control
 * are in cves/lib/base/compaction.h.
 */
#ifndef LIB_PROCINFO_H
#define LIB_PROCINFO_H

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

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

/* Read a whole small /proc node into `buf`, NUL-terminated. Returns the byte
 * count, or -1. These nodes have no size, so a short read is normal and the
 * caller sizes the buffer for what it expects. */
static inline ssize_t lib_proc_read_small(const char *path, char *buf,
					  size_t len)
{
	int fd;
	ssize_t n;

	if (!buf || len == 0)
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, len - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	return n;
}

/* Every pid whose /proc/<pid>/cmdline mentions `tag`, into `out` (at most
 * `max`). Returns how many were written.
 *
 * This is how a watcher finds a process it did not fork, and the only link that
 * survives what these payloads do to themselves: a payload that daemonizes
 * (setsid, reparented to init) shares neither process group nor parent with its
 * loader, but a child forked without exec inherits the loader's argv, so the
 * cmdline still names them both. */
static inline int lib_proc_pids_by_cmdline(const char *tag, int *out, int max)
{
	DIR *pd;
	struct dirent *e;
	int n = 0;

	if (!tag || !out || max <= 0)
		return 0;
	pd = opendir("/proc");
	if (!pd)
		return 0;
	while ((e = readdir(pd)) && n < max) {
		char path[64], buf[512];
		ssize_t len;
		ssize_t i;

		if (e->d_name[0] < '0' || e->d_name[0] > '9')
			continue;
		snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
		len = lib_proc_read_small(path, buf, sizeof(buf));
		if (len <= 0)
			continue;
		/* argv arrives NUL-separated; joining it makes one searchable
		 * string rather than just argv[0]. */
		for (i = 0; i < len; i++)
			if (buf[i] == '\0')
				buf[i] = ' ';
		if (strstr(buf, tag))
			out[n++] = atoi(e->d_name);
	}
	closedir(pd);
	return n;
}

/* One text node of a task -- "comm", "wchan", "stack", "sched", "stat" --
 * NUL-terminated in `buf`. Returns the byte count, or -1. A trailing newline is
 * removed for the single-line nodes; multi-line ones are left as they are. */
static inline ssize_t lib_proc_task_text(int tid, const char *node, char *buf,
					 size_t len)
{
	char path[96];
	ssize_t n;

	snprintf(path, sizeof(path), "/proc/%d/%s", tid, node);
	n = lib_proc_read_small(path, buf, len);
	if (n > 0 && buf[n - 1] == '\n' && !memchr(buf, '\n', (size_t)n - 1)) {
		buf[n - 1] = '\0';
		n--;
	}
	return n;
}

/* Value of a line-anchored "key : N" in a /proc text block, or -1. */
static inline int lib_proc_kv_int(const char *buf, const char *key)
{
	size_t klen = strlen(key);
	const char *p = buf;

	while ((p = strstr(p, key))) {
		if (p == buf || p[-1] == '\n') {
			const char *c = strchr(p, ':');

			if (c)
				return atoi(c + 1);
		}
		p += klen;
	}
	return -1;
}

/* The scheduler state letter (R/S/D/...) from /proc/<tid>/stat, or '?'. Field 3
 * is read from the right, because field 2 is "(comm)" and a comm may hold both
 * spaces and parentheses. */
static inline char lib_proc_task_state(int tid)
{
	char buf[1024], *r;

	if (lib_proc_task_text(tid, "stat", buf, sizeof(buf)) < 0)
		return '?';
	r = strrchr(buf, ')');
	if (!r || !r[1])
		return '?';
	return r[2] ? r[2] : '?';
}

/* The task's raw kernel prio (p->prio: 100..139 for a normal task), or -1.
 * Directly comparable to a forged rt_mutex_waiter's prio field. */
static inline int lib_proc_task_prio(int tid)
{
	char buf[16384];

	if (lib_proc_task_text(tid, "sched", buf, sizeof(buf)) < 0)
		return -1;
	return lib_proc_kv_int(buf, "prio");
}

#endif
