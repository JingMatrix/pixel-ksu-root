/* lib/trace/hwbp.h -- counting executions of a kernel instruction with the
 * processor's debug registers.
 *
 * Answers one question about a running stock kernel: did THIS instruction
 * execute, and how many times? A system-wide execute breakpoint is programmed
 * into the debug registers on a kernel virtual address, and the count is read
 * back whenever the caller asks.
 *
 * Why not tracing: under the load a race harness generates, the platform's own
 * trace daemon disables kprobes out from under the measurement -- the counter
 * resets and the reading is silently lost, which is worse than no reading
 * because it is indistinguishable from the path not running. A hardware
 * breakpoint lives in the CPU rather than in the tracing subsystem, so nothing
 * userspace does can switch it off. On a build where kprobe registration panics
 * outright it is the only counter available at all.
 *
 * What it cannot do: it counts, and only counts. There are no arguments, no
 * registers, no stack -- a tripwire on a program counter. It is also
 * SYSTEM-WIDE: every task that executes the address is counted, so a path the
 * rest of the system also walks needs the count read as a delta across a window
 * whose other end the caller controls, not as an absolute.
 *
 * arm64 has six breakpoint registers per CPU, so six addresses at once.
 *
 * Root only (a kernel-address breakpoint is privileged), header-only, libc plus
 * the perf uapi headers.
 */
#ifndef LIB_TRACE_HWBP_H
#define LIB_TRACE_HWBP_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

#define LIB_HWBP_MAX_ADDR 6    /* arm64 breakpoint registers per CPU */
#define LIB_HWBP_MAX_CPU  64

struct lib_hwbp_point {
	char name[64];             /* what the caller called it, for the log */
	uint64_t addr;
	int fd[LIB_HWBP_MAX_CPU];
	int nopen;                 /* CPUs that accepted the breakpoint */
	uint64_t total;            /* hits since the last reset */
	uint64_t last;             /* total at the previous sample */
};

struct lib_hwbp {
	struct lib_hwbp_point pt[LIB_HWBP_MAX_ADDR];
	int n;
	int ncpu;
};

static inline int lib_hwbp_perf_open(struct perf_event_attr *a, int pid, int cpu)
{
	return (int)syscall(SYS_perf_event_open, a, pid, cpu, -1, 0);
}

/* Arm `n` execute breakpoints, one per address, on every CPU that accepts one.
 * An address the kernel refuses opens no descriptors and is reported with
 * nopen == 0 rather than silently counting zero. Returns the number of points
 * that armed on at least one CPU, so 0 means nothing is being measured. */
static inline int lib_hwbp_open(struct lib_hwbp *h, const char *const *names,
				const uint64_t *addrs, int n)
{
	memset(h, 0, sizeof(*h));
	h->ncpu = (int)sysconf(_SC_NPROCESSORS_CONF);
	if (h->ncpu > LIB_HWBP_MAX_CPU)
		h->ncpu = LIB_HWBP_MAX_CPU;
	if (n > LIB_HWBP_MAX_ADDR)
		n = LIB_HWBP_MAX_ADDR;
	h->n = n;

	int armed = 0;
	for (int a = 0; a < n; a++) {
		struct lib_hwbp_point *p = &h->pt[a];
		struct perf_event_attr at;

		snprintf(p->name, sizeof(p->name), "%s",
			 names && names[a] ? names[a] : "?");
		p->addr = addrs[a];
		for (int c = 0; c < LIB_HWBP_MAX_CPU; c++)
			p->fd[c] = -1;
		if (!p->addr)
			continue;

		memset(&at, 0, sizeof(at));
		at.type = PERF_TYPE_BREAKPOINT;
		at.size = sizeof(at);
		at.bp_type = HW_BREAKPOINT_X;
		at.bp_addr = p->addr;
		at.bp_len = HW_BREAKPOINT_LEN_4;
		at.sample_period = 0;
		at.disabled = 1;
		at.exclude_kernel = 0;   /* the address IS a kernel address */
		at.exclude_hv = 1;
		at.exclude_user = 1;     /* kernel-only keeps the count clean */
		for (int c = 0; c < h->ncpu; c++) {
			int fd = lib_hwbp_perf_open(&at, -1, c);

			if (fd < 0)
				continue;
			p->fd[c] = fd;
			p->nopen++;
		}
		if (p->nopen)
			armed++;
	}
	return armed;
}

/* Zero every counter and start counting. The window a caller measures is from
 * here to the next read. */
static inline void lib_hwbp_start(struct lib_hwbp *h)
{
	for (int a = 0; a < h->n; a++) {
		for (int c = 0; c < h->ncpu; c++) {
			if (h->pt[a].fd[c] < 0)
				continue;
			ioctl(h->pt[a].fd[c], PERF_EVENT_IOC_RESET, 0);
			ioctl(h->pt[a].fd[c], PERF_EVENT_IOC_ENABLE, 0);
		}
		h->pt[a].total = 0;
		h->pt[a].last = 0;
	}
}

/* Sample every counter without stopping it, summing the per-CPU descriptors.
 * Each point's `total` is the count since the start and `last` the value at the
 * previous sample, so a caller reports either a running total or the delta for
 * this window. */
static inline void lib_hwbp_sample(struct lib_hwbp *h)
{
	for (int a = 0; a < h->n; a++) {
		uint64_t total = 0;

		h->pt[a].last = h->pt[a].total;
		for (int c = 0; c < h->ncpu; c++) {
			uint64_t v = 0;

			if (h->pt[a].fd[c] < 0)
				continue;
			if (read(h->pt[a].fd[c], &v, sizeof(v)) == sizeof(v))
				total += v;
		}
		h->pt[a].total = total;
	}
}

static inline uint64_t lib_hwbp_delta(const struct lib_hwbp *h, int i)
{
	return h->pt[i].total - h->pt[i].last;
}

static inline void lib_hwbp_close(struct lib_hwbp *h)
{
	for (int a = 0; a < h->n; a++) {
		for (int c = 0; c < h->ncpu; c++) {
			if (h->pt[a].fd[c] < 0)
				continue;
			ioctl(h->pt[a].fd[c], PERF_EVENT_IOC_DISABLE, 0);
			close(h->pt[a].fd[c]);
			h->pt[a].fd[c] = -1;
		}
		h->pt[a].nopen = 0;
	}
	h->n = 0;
}

#endif /* LIB_TRACE_HWBP_H */
