/* lib/base/cpu.h -- processor affinity, in the two forms a chain needs.
 *
 * Where a step runs decides whether it wins: a free and a reclaim that must
 * share a per-processor cache have to run on the same processor, and two halves
 * of a race have to run on different ones. So affinity is part of a technique,
 * not an optimisation, and the distinction that matters is what a failure to
 * set it means.
 *
 *   lib_pin_cpu()      requests a processor and reports whether it got it. For
 *                      a step where the wrong processor costs a retry.
 *   lib_pin_cpu_hard() additionally confirms the move took effect before
 *                      returning. For a step where the wrong processor means
 *                      the technique is running against unrelated memory.
 *
 * The second is not the first with a check bolted on: setting affinity only
 * schedules a migration, so a caller that must be on the processor before its
 * next instruction has to observe the move, not request it.
 *
 * Header-only, libc only, no device constant: the processor count is read at
 * run time.
 */
#ifndef LIB_BASE_CPU_H
#define LIB_BASE_CPU_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <sched.h>
#include <unistd.h>

/* Processors the caller may run on. Returns at least 1. */
static inline int lib_cpu_count(void)
{
	long n = sysconf(_SC_NPROCESSORS_ONLN);
	return n > 0 ? (int)n : 1;
}

/* Request `cpu`. Returns 0 on success, -1 with errno set otherwise. A negative
 * `cpu` is a no-op success, so a caller with an unset preference needs no
 * branch of its own. */
static inline int lib_pin_cpu(int cpu)
{
	cpu_set_t set;

	if (cpu < 0)
		return 0;
	if (cpu >= CPU_SETSIZE) {
		errno = ERANGE;
		return -1;
	}
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

/* Request `cpu` and confirm the caller is running there before returning.
 * Returns 0 on success, -1 with errno set if the request failed or the move
 * did not take effect. */
static inline int lib_pin_cpu_hard(int cpu)
{
	if (cpu < 0 || cpu >= CPU_SETSIZE || cpu >= lib_cpu_count()) {
		errno = ERANGE;
		return -1;
	}
	if (lib_pin_cpu(cpu) != 0)
		return -1;
	if (sched_getcpu() != cpu) {
		errno = EAGAIN;
		return -1;
	}
	return 0;
}

/* Release any affinity restriction, returning the caller to every processor. */
static inline int lib_unpin_cpu(void)
{
	cpu_set_t set;
	int n = lib_cpu_count();

	CPU_ZERO(&set);
	for (int i = 0; i < n && i < CPU_SETSIZE; i++)
		CPU_SET(i, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

/* Confirm every processor in [first, last] can actually be pinned to, then
 * restore the caller's original affinity. A chain that assigns roles to
 * processors uses this once at startup so an impossible assignment is a clean
 * refusal instead of a step that silently runs on the wrong core.
 * Returns 0 if all of them are reachable, -1 with errno set otherwise. */
static inline int lib_cpus_reachable(int first, int last)
{
	cpu_set_t original, requested;
	int error = 0;

	if (sched_getaffinity(0, sizeof(original), &original) != 0)
		return -1;
	for (int cpu = first; cpu <= last; cpu++) {
		CPU_ZERO(&requested);
		CPU_SET(cpu, &requested);
		if (sched_setaffinity(0, sizeof(requested), &requested) != 0 ||
		    sched_getcpu() != cpu) {
			error = errno ? errno : EINVAL;
			break;
		}
	}
	if (sched_setaffinity(0, sizeof(original), &original) != 0 && !error)
		error = errno;
	if (error) {
		errno = error;
		return -1;
	}
	return 0;
}

#endif /* LIB_BASE_CPU_H */
