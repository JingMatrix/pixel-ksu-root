/* lib/trace/hwwatch.h -- observing WHO reads or writes one kernel address, and
 * WHEN, with the processor's watchpoint registers.
 *
 * A hardware watchpoint is programmed on a data address and set to sample every
 * access. Each access the CPU takes to that address produces a perf record whose
 * fields carry the kernel PC that made the access and the time it happened. So a
 * caller learns not that the address was touched some fraction of the time (what
 * a poll of the value would say), but each individual touch: which code did it
 * and when, live, without stopping the accessor.
 *
 * Why this over reading the value on a timer: the value read on a timer is a
 * time-average -- it answers "what is usually here", which for an object that is
 * written and read microseconds apart is not the question. The watchpoint fires
 * ON the access, so a read by the walk and a write by the vehicle are each their
 * own dated event, and the PC on each separates the code under study from the
 * foreign traffic that also touches a reused address.
 *
 * What it cannot do: the sample carries the accessing PC and the time, not the
 * VALUE moved. Whether a given write placed OUR object is not in the record;
 * that still comes from the writer's own log or a register decode a caller adds.
 *
 * arm64 has four watchpoint registers per CPU, separate from the breakpoint
 * (execute) registers lib/trace/hwbp.h uses, so the two can run at once.
 *
 * Root only (a kernel-address watchpoint is privileged), header-only, libc plus
 * the perf uapi headers.
 */
#ifndef LIB_TRACE_HWWATCH_H
#define LIB_TRACE_HWWATCH_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

#define LIB_HWWATCH_MAX_CPU 64
/* One metadata page + a power-of-two data area. 8 data pages hold a burst of
 * accesses between drains; overflow is counted (PERF_RECORD_LOST), not hidden. */
#ifndef LIB_HWWATCH_DATA_PAGES
#define LIB_HWWATCH_DATA_PAGES 8
#endif

/* One access to the watched address. When the watch was opened with a stack
 * depth, `chain`/`chain_n` hold the kernel call chain at the access (return
 * addresses, innermost first, context markers already dropped); they are valid
 * only for the duration of the callback. */
struct lib_hwwatch_sample {
	uint64_t ip;          /* kernel PC that made the access */
	uint64_t time;        /* perf clock, comparable across this run's samples */
	uint64_t addr;        /* the accessed address (== the watch address) */
	const uint64_t *chain;
	int chain_n;
};

struct lib_hwwatch {
	int fd[LIB_HWWATCH_MAX_CPU];
	void *ring[LIB_HWWATCH_MAX_CPU];   /* mmap: 1 meta page + data pages */
	int ncpu;
	long pgsz;
	size_t map_len;
	uint64_t addr;
	int max_stack;                     /* call-chain depth requested, 0 = none */
	uint64_t lost;                     /* samples the kernel dropped on overflow */
};

typedef void (*lib_hwwatch_cb)(const struct lib_hwwatch_sample *s, void *ctx);

static inline int lib_hwwatch_perf_open(struct perf_event_attr *a, int cpu)
{
	return (int)syscall(SYS_perf_event_open, a, -1, cpu, -1, 0);
}

/* Arm a sampling watchpoint on `addr` (`len` bytes: 1/2/4/8) for `rw`
 * (HW_BREAKPOINT_R, _W or _RW) on every CPU that accepts it, each with its own
 * ring buffer. `max_stack` > 0 also records the kernel call chain at each access,
 * capped at that depth; 0 records only the accessing PC. Returns the number of
 * CPUs armed; 0 means nothing is watched. */
static inline int lib_hwwatch_open(struct lib_hwwatch *w, uint64_t addr, int len,
				   int rw, int max_stack)
{
	memset(w, 0, sizeof(*w));
	for (int c = 0; c < LIB_HWWATCH_MAX_CPU; c++)
		w->fd[c] = -1;
	w->addr = addr;
	w->max_stack = max_stack;
	w->pgsz = sysconf(_SC_PAGESIZE);
	w->map_len = (size_t)w->pgsz * (1 + LIB_HWWATCH_DATA_PAGES);
	w->ncpu = (int)sysconf(_SC_NPROCESSORS_CONF);
	if (w->ncpu > LIB_HWWATCH_MAX_CPU)
		w->ncpu = LIB_HWWATCH_MAX_CPU;

	struct perf_event_attr at;
	int armed = 0;
	for (int c = 0; c < w->ncpu; c++) {
		memset(&at, 0, sizeof(at));
		at.type = PERF_TYPE_BREAKPOINT;
		at.size = sizeof(at);
		at.bp_type = rw;
		at.bp_addr = addr;
		at.bp_len = len;
		/* Sample every access, and record who and when. */
		at.sample_period = 1;
		at.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TIME |
				 PERF_SAMPLE_ADDR;
		if (max_stack > 0) {
			at.sample_type |= PERF_SAMPLE_CALLCHAIN;
			at.sample_max_stack = (uint16_t)max_stack;
			at.exclude_callchain_user = 1;  /* kernel frames only */
		}
		at.disabled = 1;
		at.exclude_kernel = 0;   /* the address IS a kernel address */
		at.exclude_hv = 1;
		at.exclude_user = 1;     /* kernel accesses only keep it clean */
		at.precise_ip = 0;

		int fd = lib_hwwatch_perf_open(&at, c);
		if (fd < 0)
			continue;
		void *m = mmap(NULL, w->map_len, PROT_READ | PROT_WRITE,
			       MAP_SHARED, fd, 0);
		if (m == MAP_FAILED) {
			close(fd);
			continue;
		}
		w->fd[c] = fd;
		w->ring[c] = m;
		armed++;
	}
	return armed;
}

static inline void lib_hwwatch_start(struct lib_hwwatch *w)
{
	for (int c = 0; c < w->ncpu; c++) {
		if (w->fd[c] < 0)
			continue;
		ioctl(w->fd[c], PERF_EVENT_IOC_RESET, 0);
		ioctl(w->fd[c], PERF_EVENT_IOC_ENABLE, 0);
	}
}

/* Drain one CPU's ring, calling `cb` for each access sample. Records that wrap
 * the ring end are reassembled into `scratch` before decoding. */
static inline void lib_hwwatch_drain_cpu(struct lib_hwwatch *w, int c,
					 lib_hwwatch_cb cb, void *ctx)
{
	struct perf_event_mmap_page *meta = w->ring[c];
	char *data = (char *)w->ring[c] + w->pgsz;
	size_t dsz = w->map_len - (size_t)w->pgsz;

	uint64_t head = meta->data_head;
	__sync_synchronize();                 /* read head before the records */
	uint64_t tail = meta->data_tail;

	/* PERF_CONTEXT_* markers sit at the very top of the u64 range, well above
	 * any kernel text address, so a call-chain entry at or above this is a
	 * marker (kernel/user boundary), not a return address. */
	const uint64_t CONTEXT_MIN = (uint64_t)-4095;

	char scratch[4096];
	uint64_t chain[256];
	while (tail < head) {
		struct perf_event_header hdr;
		size_t off = tail % dsz;
		/* The header may itself wrap; copy it byte-wise through the mask. */
		for (size_t i = 0; i < sizeof(hdr); i++)
			((char *)&hdr)[i] = data[(off + i) % dsz];
		if (hdr.size == 0 || hdr.size > sizeof(scratch)) {
			tail += hdr.size ? hdr.size : sizeof(hdr);
			continue;
		}
		for (size_t i = 0; i < hdr.size; i++)
			scratch[i] = data[(off + i) % dsz];
		tail += hdr.size;

		if (hdr.type == PERF_RECORD_LOST) {
			/* struct: perf_event_header, u64 id, u64 lost */
			uint64_t lost;
			memcpy(&lost, scratch + sizeof(hdr) + sizeof(uint64_t),
			       sizeof(lost));
			w->lost += lost;
			continue;
		}
		if (hdr.type != PERF_RECORD_SAMPLE)
			continue;

		/* Body order follows the PERF_SAMPLE_* bit order: IP, TIME, ADDR,
		 * then (if requested) CALLCHAIN as a u64 count and that many IPs. */
		const char *p = scratch + sizeof(hdr);
		const char *end = scratch + hdr.size;
		struct lib_hwwatch_sample s;
		memset(&s, 0, sizeof(s));
		if (p + 24 > end)
			continue;
		memcpy(&s.ip, p, 8);   p += 8;
		memcpy(&s.time, p, 8); p += 8;
		memcpy(&s.addr, p, 8); p += 8;
		if (w->max_stack > 0 && p + 8 <= end) {
			uint64_t nr;
			memcpy(&nr, p, 8); p += 8;
			int kept = 0;
			for (uint64_t i = 0; i < nr && p + 8 <= end &&
					     kept < (int)(sizeof(chain) / 8);
			     i++, p += 8) {
				uint64_t e;
				memcpy(&e, p, 8);
				if (e >= CONTEXT_MIN)
					continue;   /* boundary marker */
				chain[kept++] = e;
			}
			s.chain = chain;
			s.chain_n = kept;
		}
		if (cb)
			cb(&s, ctx);
	}

	__sync_synchronize();                 /* records read before releasing */
	meta->data_tail = head;
}

/* Drain every CPU's ring in one pass. Call periodically so a burst does not
 * overflow (overflow is counted in w->lost, not silently lost). */
static inline void lib_hwwatch_drain(struct lib_hwwatch *w, lib_hwwatch_cb cb,
				     void *ctx)
{
	for (int c = 0; c < w->ncpu; c++) {
		if (w->fd[c] < 0)
			continue;
		lib_hwwatch_drain_cpu(w, c, cb, ctx);
	}
}

static inline void lib_hwwatch_close(struct lib_hwwatch *w)
{
	for (int c = 0; c < w->ncpu; c++) {
		if (w->fd[c] < 0)
			continue;
		ioctl(w->fd[c], PERF_EVENT_IOC_DISABLE, 0);
		if (w->ring[c])
			munmap(w->ring[c], w->map_len);
		close(w->fd[c]);
		w->fd[c] = -1;
		w->ring[c] = NULL;
	}
}

#endif /* LIB_TRACE_HWWATCH_H */
