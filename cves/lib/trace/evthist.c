/* Counting a static tracepoint through its own histogram trigger. */
#include "evthist.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *eh_dir(void)
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

static int eh_write(const char *rel, const char *text)
{
	char path[256];
	int fd;
	ssize_t n;

	const char *dir = eh_dir();

	if (!dir)
		return -1;
	snprintf(path, sizeof(path), "%s/%s", dir, rel);
	fd = open(path, O_WRONLY | O_CLOEXEC | O_TRUNC);
	if (fd < 0)
		return -1;
	n = write(fd, text, strlen(text));
	close(fd);
	return n == (ssize_t)strlen(text) ? 0 : -1;
}

int lib_evthist_available(const char *subsys, const char *event)
{
	const char *dir = eh_dir();
	char path[256];

	if (!dir)
		return 0;
	snprintf(path, sizeof(path), "%s/events/%s/%s/hist", dir, subsys, event);
	return access(path, R_OK) == 0;
}

int lib_evthist_arm(const char *subsys, const char *event, const char *key)
{
	char rel[256], line[64];

	if (snprintf(rel, sizeof(rel), "events/%s/%s/trigger", subsys, event)
	    >= (int)sizeof(rel))
		return -1;
	if (snprintf(line, sizeof(line), "hist:key=%s\n", key) >= (int)sizeof(line))
		return -1;
	if (eh_write(rel, line) != 0)
		return -1;
	if (snprintf(rel, sizeof(rel), "events/%s/%s/enable", subsys, event)
	    >= (int)sizeof(rel))
		return -1;
	if (eh_write(rel, "1\n") != 0)
		return -1;
	return eh_write("tracing_on", "1\n");
}

/* A hist file reads:
 *   { order:          3 } hitcount:        128
 * one line per distinct key value seen so far, in no guaranteed order, plus a
 * header and a "Totals:" footer this does not need. A value never seen has no
 * line at all -- absence means 0, not a read failure. */
int lib_evthist_read(const char *subsys, const char *event, long key_value,
                      unsigned long long *out)
{
	const char *dir = eh_dir();
	char path[256], line[256], want[32];
	FILE *f;

	if (!dir || !out)
		return -1;
	snprintf(path, sizeof(path), "%s/events/%s/%s/hist", dir, subsys, event);
	f = fopen(path, "re");
	if (!f)
		return -1;
	/* The kernel right-pads the value to some field width this does not
	 * assume ("order:          3"); matching only "<value> }" with a space
	 * before it, not the padding's exact shape, is what a value at any
	 * width still satisfies. */
	snprintf(want, sizeof(want), "%ld }", key_value);
	*out = 0;
	while (fgets(line, sizeof(line), f)) {
		char *val = strstr(line, want);
		char *hp;

		if (!val || val == line || val[-1] != ' ')
			continue;
		hp = strstr(line, "hitcount:");
		if (!hp)
			continue;
		*out = strtoull(hp + strlen("hitcount:"), NULL, 10);
		break;
	}
	fclose(f);
	return 0;
}

void lib_evthist_clear(const char *subsys, const char *event, const char *key)
{
	char rel[256], line[64];

	if (snprintf(rel, sizeof(rel), "events/%s/%s/enable", subsys, event)
	    < (int)sizeof(rel))
		eh_write(rel, "0\n");
	if (snprintf(rel, sizeof(rel), "events/%s/%s/trigger", subsys, event)
	    < (int)sizeof(rel) &&
	    snprintf(line, sizeof(line), "!hist:key=%s\n", key) < (int)sizeof(line))
		eh_write(rel, line);
}
