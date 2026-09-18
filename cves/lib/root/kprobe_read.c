/* root/kprobe_read.c -- see kprobe_read.h. */
#define _GNU_SOURCE
#include "kprobe_read.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char *kp_trace_dir(void)
{
	struct stat st;
	if (stat("/sys/kernel/tracing/kprobe_events", &st) == 0)
		return "/sys/kernel/tracing";
	return "/sys/kernel/debug/tracing";
}

static int kp_wfile(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");
	if (!f) return -1;
	int rc = fputs(content, f) == EOF ? -1 : 0;
	fclose(f);
	return rc;
}

static void kp_clear(const char *T)
{
	char p[160];
	snprintf(p, sizeof p, "%s/events/kprobes/enable", T); kp_wfile(p, "0");
	snprintf(p, sizeof p, "%s/tracing_on", T);            kp_wfile(p, "0");
	snprintf(p, sizeof p, "%s/kprobe_events", T);         kp_wfile(p, "");
	snprintf(p, sizeof p, "%s/trace", T);                 kp_wfile(p, "");
}

/* Shared body. `pid` is the common_pid filter; `trigger` (may be NULL) makes
 * the traced call locally, otherwise we wait up to `timeout_ms` for another
 * process to make it. */
static unsigned long long kp_fetch(const char *ename, const char *func,
				const char *argspec, const char *field,
				int pid, void (*trigger)(void), int timeout_ms)
{
	const char *T = kp_trace_dir();
	char p[192], line[512];

	kp_clear(T);

	snprintf(p, sizeof p, "%s/kprobe_events", T);
	{
		FILE *f = fopen(p, "w");
		if (!f) return 0;
		int n = fprintf(f, "p:%s %s %s\n", ename, func, argspec);
		int bad = (n < 0);
		fclose(f);
		if (bad) return 0;
	}

	snprintf(p, sizeof p, "%s/events/kprobes/%s/filter", T, ename);
	{
		FILE *f = fopen(p, "w");
		if (f) { fprintf(f, "common_pid==%d\n", pid); fclose(f); }
	}

	snprintf(p, sizeof p, "%s/trace", T);                            kp_wfile(p, "");
	snprintf(p, sizeof p, "%s/events/kprobes/%s/enable", T, ename);  kp_wfile(p, "1");
	snprintf(p, sizeof p, "%s/tracing_on", T);                       kp_wfile(p, "1");

	char needle[64];
	snprintf(needle, sizeof needle, " %s=", field);
	char tracep[192];
	snprintf(tracep, sizeof tracep, "%s/trace", T);

	if (trigger) {
		trigger();
		usleep(50000);
	} else {
		/* Another process makes the call; poll until it lands. Reading
		 * `trace` is a non-consuming snapshot, so this can be re-read. */
		for (int waited = 0; waited < timeout_ms; waited += 50) {
			usleep(50000);
			FILE *f = fopen(tracep, "r");
			int seen = 0;
			if (f) {
				while (fgets(line, sizeof(line), f))
					if (strstr(line, needle)) { seen = 1; break; }
				fclose(f);
			}
			if (seen) break;
		}
	}

	snprintf(p, sizeof p, "%s/tracing_on", T);                       kp_wfile(p, "0");
	snprintf(p, sizeof p, "%s/events/kprobes/%s/enable", T, ename);  kp_wfile(p, "0");

	unsigned long long val = 0;
	FILE *f = fopen(tracep, "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			char *hit = strstr(line, needle);
			if (hit) val = strtoull(hit + strlen(needle), NULL, 0);
		}
		fclose(f);
	}
	snprintf(p, sizeof p, "%s/kprobe_events", T); kp_wfile(p, "");
	return val;
}

/* Arm a pid-filtered kprobe and leave it running, so the caller can unblock the
 * other process (which then makes the traced call) BEFORE harvesting -- for a
 * traced call that races the arm if armed and polled in one step. Pair with
 * lib_kprobe_harvest. Returns 0 on success, -1 on failure. */
int lib_kprobe_arm_pid(const char *ename, const char *func,
			const char *argspec, int pid)
{
	const char *T = kp_trace_dir();
	char p[192];
	kp_clear(T);
	snprintf(p, sizeof p, "%s/kprobe_events", T);
	{
		FILE *f = fopen(p, "w");
		if (!f) return -1;
		int n = fprintf(f, "p:%s %s %s\n", ename, func, argspec);
		int bad = (n < 0);
		fclose(f);
		if (bad) return -1;
	}
	snprintf(p, sizeof p, "%s/events/kprobes/%s/filter", T, ename);
	{ FILE *f = fopen(p, "w"); if (f) { fprintf(f, "common_pid==%d\n", pid); fclose(f); } }
	snprintf(p, sizeof p, "%s/trace", T);                           kp_wfile(p, "");
	snprintf(p, sizeof p, "%s/events/kprobes/%s/enable", T, ename); kp_wfile(p, "1");
	snprintf(p, sizeof p, "%s/tracing_on", T);                      kp_wfile(p, "1");
	return 0;
}

/* Harvest a kprobe armed by lib_kprobe_arm_pid: poll `trace` for `field` up to
 * timeout_ms, then disable and tear the probe down. Returns the last matching
 * value, or 0 if none arrived. */
unsigned long long lib_kprobe_harvest(const char *ename, const char *field,
			int timeout_ms)
{
	const char *T = kp_trace_dir();
	char p[192], line[512], needle[64], tracep[192];
	snprintf(needle, sizeof needle, " %s=", field);
	snprintf(tracep, sizeof tracep, "%s/trace", T);
	for (int waited = 0; waited < timeout_ms; waited += 50) {
		usleep(50000);
		FILE *f = fopen(tracep, "r");
		int seen = 0;
		if (f) {
			while (fgets(line, sizeof(line), f))
				if (strstr(line, needle)) { seen = 1; break; }
			fclose(f);
		}
		if (seen) break;
	}
	snprintf(p, sizeof p, "%s/tracing_on", T);                      kp_wfile(p, "0");
	snprintf(p, sizeof p, "%s/events/kprobes/%s/enable", T, ename); kp_wfile(p, "0");
	unsigned long long val = 0;
	FILE *f = fopen(tracep, "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			char *hit = strstr(line, needle);
			if (hit) val = strtoull(hit + strlen(needle), NULL, 0);
		}
		fclose(f);
	}
	snprintf(p, sizeof p, "%s/kprobe_events", T); kp_wfile(p, "");
	return val;
}

unsigned long long lib_kprobe_fetch_self(const char *ename, const char *func,
				const char *argspec, const char *field,
				void (*trigger)(void))
{
	return kp_fetch(ename, func, argspec, field, getpid(), trigger, 0);
}

unsigned long long lib_kprobe_fetch_pid(const char *ename, const char *func,
				const char *argspec, const char *field,
				int pid, int timeout_ms)
{
	return kp_fetch(ename, func, argspec, field, pid, NULL, timeout_ms);
}

int lib_kprobe_peek_self(const char *ename, unsigned long long addr, unsigned long long *out, int n)
{
	const char *T = kp_trace_dir();
	char p[512], line[1024], argbuf[400] = "";

	kp_clear(T);

	for (int i = 0; i < n; i++) {
		char one[64];
		snprintf(one, sizeof one, " w%d=@%#llx:x64", i,
			 (unsigned long long)addr + (unsigned long long)i * 8);
		strncat(argbuf, one, sizeof(argbuf) - strlen(argbuf) - 1);
	}
	snprintf(p, sizeof p, "%s/kprobe_events", T);
	{
		FILE *f = fopen(p, "w");
		if (!f) return 0;
		int rc = fprintf(f, "p:%s __arm64_sys_getpid%s\n", ename, argbuf);
		fclose(f);
		if (rc < 0) return 0;
	}
	snprintf(p, sizeof p, "%s/events/kprobes/%s/filter", T, ename);
	{ FILE *f = fopen(p, "w"); if (f) { fprintf(f, "common_pid==%d\n", getpid()); fclose(f); } }

	snprintf(p, sizeof p, "%s/trace", T);                           kp_wfile(p, "");
	snprintf(p, sizeof p, "%s/events/kprobes/%s/enable", T, ename); kp_wfile(p, "1");
	snprintf(p, sizeof p, "%s/tracing_on", T);                      kp_wfile(p, "1");

	syscall(SYS_getpid);
	usleep(50000);

	snprintf(p, sizeof p, "%s/tracing_on", T);                      kp_wfile(p, "0");
	snprintf(p, sizeof p, "%s/events/kprobes/%s/enable", T, ename); kp_wfile(p, "0");

	int got = 0;
	snprintf(p, sizeof p, "%s/trace", T);
	FILE *f = fopen(p, "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			int this_got = 0;
			unsigned long long tmp[8];
			for (int i = 0; i < n; i++) {
				char needle[16]; snprintf(needle, sizeof needle, " w%d=", i);
				char *hit = strstr(line, needle);
				if (!hit) break;
				tmp[i] = strtoull(hit + strlen(needle), NULL, 0);
				this_got++;
			}
			if (this_got == n) { memcpy(out, tmp, n * sizeof(*out)); got = 1; }
		}
		fclose(f);
	}
	snprintf(p, sizeof p, "%s/kprobe_events", T); kp_wfile(p, "");
	return got;
}
