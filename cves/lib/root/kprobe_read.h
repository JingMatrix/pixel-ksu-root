/* lib/root/kprobe_read.h -- reading kernel state through a dynamic probe.
 *
 * A process that is already privileged can install a probe on a kernel function
 * and have it record chosen values whenever that function runs. That is an
 * observation instrument, not an exploitation primitive, and it is how this
 * tree establishes ground truth: what an address actually holds, what a
 * structure field actually is, whether a step actually reached the code it
 * aimed at.
 *
 * Two shapes, because there are two kinds of question:
 *
 *   Follow an argument. The probe names a register and an offset, so a field of
 *   a structure the traced function was passed is captured without knowing its
 *   address in advance.
 *
 *   Read an address. The probe names a literal address, for something already
 *   located by other means.
 *
 * Every probe is filtered to one process. An unfiltered probe on a busy
 * function fills the buffer with unrelated hits and loses the one that matters.
 * Where the caller triggers the probe itself, the triggering call must be one
 * that genuinely enters the kernel -- several are answered from userspace after
 * the first use and would never fire.
 */
#ifndef LIB_ROOT_KPROBE_READ_H
#define LIB_ROOT_KPROBE_READ_H

#include <stdint.h>

/* Arm a kprobe named `ename` on `func` with ftrace dynamic-arg spec `argspec`
 * (e.g. "priv=+0xd8(%x0):x64"), filtered to this process's own pid, call
 * `trigger` (expected to make the traced call fire, e.g. an ioctl() on a
 * pipe this process owns), then parse `field` back out of the trace buffer
 * as hex. `ename` must be unique per concurrent call site. Returns 0 on any
 * failure (missing symbol, filter rejected, no hit within the settle
 * window). */
unsigned long long lib_kprobe_fetch_self(const char *ename, const char *func,
				const char *argspec, const char *field,
				void (*trigger)(void));

/* Same, but filtered to ANOTHER process's pid, with no local trigger: the
 * traced call is made by that process (e.g. a forked victim looping ioctl()
 * on its own pipe while this root parent resolves its pipe_inode_info).
 * Polls the trace buffer for up to `timeout_ms` for the first hit. Returns 0
 * if none arrives -- so a victim that died, or never reached its trigger
 * loop, is a clean failure rather than a hang. */
unsigned long long lib_kprobe_fetch_pid(const char *ename, const char *func,
				const char *argspec, const char *field,
				int pid, int timeout_ms);

/* Split arm/harvest for a traced call that RACES a combined arm+poll (fires
 * within the tens of ms the arm's tracefs writes take): arm first, unblock the
 * other process so it makes the call while armed, then harvest. `ename` must be
 * unique and match between the two. arm returns 0/-1; harvest returns the last
 * value or 0. */
int lib_kprobe_arm_pid(const char *ename, const char *func,
			const char *argspec, int pid);
unsigned long long lib_kprobe_harvest(const char *ename, const char *field,
			int timeout_ms);

/* Read `n` consecutive 8-byte words starting at literal kernel address
 * `addr`, filtered to this process's own pid, triggered by
 * syscall(SYS_getpid). Fills out[0..n-1] (n <= 8). Returns 0 on any failure
 * (all n fields must be present in the same trace line to count as a hit). */
int lib_kprobe_peek_self(const char *ename, unsigned long long addr, unsigned long long *out, int n);

#endif /* LIB_ROOT_KPROBE_READ_H */
