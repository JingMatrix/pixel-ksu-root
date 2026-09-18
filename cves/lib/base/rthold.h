/* lib/base/rthold.h -- taking a processor away from whatever is running on it.
 *
 * A race between a kernel path and a userspace one can sometimes be ordered by
 * stopping the userspace side at a chosen moment. Ordinary scheduling pressure
 * does not do that: a thread competing for the processor lengthens the tail of
 * a distribution and leaves its body alone. A real-time thread does, because it
 * preempts what is running there, in the kernel included, so whatever was in
 * flight stays in flight until it yields the processor back.
 *
 * What that buys is a pause of a known length at an unknown point. It does not
 * choose where the pause falls, so it widens an interval rather than aiming at
 * one, and a caller that needs a particular instant still needs a signal for
 * it. It also costs whatever else wanted that processor, so the hold belongs
 * around a window and not around a run.
 *
 * Requires the privilege to set a real-time policy; without it the thread still
 * runs, at ordinary priority, and holds nothing.
 */
#ifndef LIB_RTHOLD_H
#define LIB_RTHOLD_H

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>

#include "clock.h"
#include "cpu.h"

/* Become a real-time thread on `cpu`. Returns 0, or -1 when the policy was
 * refused, which a caller should report rather than ignore: the difference
 * between holding a processor and not is the whole point. */
static inline int lib_rthold_enter(int cpu, int priority)
{
	struct sched_param sp;

	lib_pin_cpu(cpu);
	sp.sched_priority = priority > 0 ? priority : 2;
	return sched_setscheduler(0, SCHED_FIFO, &sp);
}

/* Hold the processor for `hold_us`, then give it back for the rest of
 * `period_us`. One call is one cycle, so a caller decides how long to keep
 * cycling and on what condition to stop. A hold as long as the period starves
 * the processor outright, which the kernel's real-time throttle will eventually
 * break; leave it room. */
static inline void lib_rthold_cycle(int period_us, int hold_us)
{
	int64_t next = lib_now_ns() + (int64_t)period_us * 1000;

	lib_busy_delay((int64_t)hold_us * 1000);
	lib_sleep_until(next);
}

/* Hold until `flag` is set by another thread, then for `after_us` longer. The
 * flag has to come from somewhere the held processor cannot block -- a thread
 * frozen mid-syscall may be holding a lock the signal would have travelled
 * through. */
static inline void lib_rthold_until(volatile int *flag, int after_us)
{
	while (!*flag)
		lib_cpu_relax();
	lib_busy_delay((int64_t)after_us * 1000);
}

#endif /* LIB_RTHOLD_H */
