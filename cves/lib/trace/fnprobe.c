/* Watching a kernel function through the tracing interface. */
#include "fnprobe.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *fp_dir(void)
{
	static const char *const candidates[] = {
		"/sys/kernel/tracing", "/sys/kernel/debug/tracing",
	};

	for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
		if (access(candidates[i], R_OK | W_OK) == 0)
			return candidates[i];
	}
	return NULL;
}

static int fp_write(const char *rel, const char *text, int append)
{
	const char *dir = fp_dir();
	char path[256];
	int fd, flags = O_WRONLY | O_CLOEXEC | (append ? O_APPEND : O_TRUNC);
	ssize_t n;

	if (!dir)
		return -1;
	snprintf(path, sizeof(path), "%s/%s", dir, rel);
	fd = open(path, flags);
	if (fd < 0)
		return -1;
	n = write(fd, text, strlen(text));
	close(fd);
	return n == (ssize_t)strlen(text) ? 0 : -1;
}

/* A fetched pointer is masked in a record unless this is relaxed; clear()
 * puts it back. */
static void fp_kptr(const char *value)
{
	int fd = open("/proc/sys/kernel/kptr_restrict", O_WRONLY | O_CLOEXEC);

	if (fd >= 0) {
		ssize_t ignored = write(fd, value, strlen(value));

		(void)ignored;
		close(fd);
	}
}

/* The probes this module armed, so clear() can disable them: the interface
 * refuses to remove a probe that is still enabled. */
#define FP_MAX_PROBES 8
static char fp_armed[FP_MAX_PROBES][64];
static int fp_narmed;

int lib_fnprobe_available(void)
{
	const char *dir = fp_dir();
	char path[256];

	if (!dir)
		return 0;
	snprintf(path, sizeof(path), "%s/kprobe_events", dir);
	return access(path, W_OK) == 0;
}

static int fp_arm(char kind, const char *name, const char *spec)
{
	char line[512], enable[256];

	if (fp_narmed >= FP_MAX_PROBES || strlen(name) >= sizeof(fp_armed[0]))
		return -1;
	if (snprintf(line, sizeof(line), "%c:%s %s\n", kind, name, spec)
	    >= (int)sizeof(line))
		return -1;
	fp_kptr("0\n");
	if (fp_write("kprobe_events", line, 1) != 0)
		return -1;
	snprintf(fp_armed[fp_narmed++], sizeof(fp_armed[0]), "%s", name);
	snprintf(enable, sizeof(enable), "events/kprobes/%s/enable", name);
	return fp_write(enable, "1\n", 0);
}

int lib_fnprobe_arm(const char *name, const char *spec)
{
	return fp_arm('p', name, spec);
}

int lib_fnprobe_arm_return(const char *name, const char *spec)
{
	return fp_arm('r', name, spec);
}

int lib_fnprobe_start(void)
{
	if (fp_write("trace", "", 0) != 0)
		return -1;
	return fp_write("tracing_on", "1\n", 0);
}

int lib_fnprobe_stop(void)
{
	return fp_write("tracing_on", "0\n", 0);
}

/* A record reads
 *     <comm>-<pid> [cpu] flags  <seconds>.<micros>: <name>: (sym+0x0/0x40) k=v
 * so the timestamp is the token ending in ':' that parses as a decimal number,
 * and the event name is the token after it. Anything else is a header line. */
static int fp_split(const char *line, char *name, size_t nsz, double *ts)
{
	const char *p = line;

	while (*p) {
		if (*p >= '0' && *p <= '9' && (p == line || p[-1] == ' ')) {
			char *end;
			double v = strtod(p, &end);

			if (end > p && *end == ':' &&
			    memchr(p, '.', (size_t)(end - p))) {
				const char *q = end + 1, *colon;
				size_t len;

				while (*q == ' ')
					q++;
				colon = strchr(q, ':');
				if (!colon)
					return -1;
				len = (size_t)(colon - q);
				if (!len || len >= nsz)
					return -1;
				memcpy(name, q, len);
				name[len] = '\0';
				*ts = v;
				return 0;
			}
		}
		p++;
	}
	return -1;
}

int lib_fnprobe_each(int (*fn)(const char *name, double ts, const char *line,
			       void *ctx), void *ctx)
{
	const char *dir = fp_dir();
	char path[256], line[1024], name[64];
	FILE *f;
	int seen = 0;

	if (!dir)
		return -1;
	snprintf(path, sizeof(path), "%s/trace", dir);
	f = fopen(path, "re");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		double ts;

		if (line[0] == '#' || fp_split(line, name, sizeof(name), &ts) != 0)
			continue;
		seen++;
		if (fn && fn(name, ts, line, ctx))
			break;
	}
	fclose(f);
	return seen;
}

int lib_fnprobe_field(const char *line, const char *key, unsigned long long *out)
{
	char pat[64];
	const char *p;

	if (snprintf(pat, sizeof(pat), "%s=", key) >= (int)sizeof(pat))
		return -1;
	p = strstr(line, pat);
	if (!p)
		return -1;
	*out = strtoull(p + strlen(pat), NULL, 0);
	return 0;
}

void lib_fnprobe_clear(void)
{
	char enable[256];
	int i;

	fp_write("tracing_on", "0\n", 0);
	for (i = 0; i < fp_narmed; i++) {
		snprintf(enable, sizeof(enable), "events/kprobes/%s/enable",
			 fp_armed[i]);
		fp_write(enable, "0\n", 0);
	}
	fp_narmed = 0;
	fp_write("trace", "", 0);
	fp_write("kprobe_events", "\n", 0);
	fp_kptr("1\n");
}
