/* lib/base/clock.h -- monotonic time, and the three ways a chain waits.
 *
 * Race work needs a clock that never steps and three distinct waits, each with
 * a different cost and a different precision:
 *
 *   lib_sleep_until()  yields the processor until an absolute deadline. Cheap,
 *                      but the wake is only as precise as the scheduler.
 *   lib_spin_until()   holds the processor to an absolute deadline. Expensive,
 *                      and precise to the granularity of the clock read.
 *   lib_busy_delay()   the same, expressed as a duration rather than a deadline.
 *
 * A window that must be hit within microseconds is spun to; a window seconds
 * away is slept to, optionally with a short spin at the end. Choosing wrongly
 * costs either precision or a core.
 *
 * Header-only and dependency-free apart from libc. No device constant here: the
 * clock's granularity is whatever the platform provides and is never assumed.
 */
#ifndef LIB_BASE_CLOCK_H
#define LIB_BASE_CLOCK_H

#include <errno.h>
#include <stdint.h>
#include <time.h>

#ifndef LIB_NSEC_PER_SEC
#define LIB_NSEC_PER_SEC 1000000000LL
#endif

/* Spin hint: tells the processor this loop is waiting, so it may lower the
 * issue rate rather than burning a full pipeline on a re-read. */
static inline void lib_cpu_relax(void)
{
#if defined(__aarch64__) || defined(__arm__)
	__asm__ __volatile__("yield" ::: "memory");
#elif defined(__x86_64__) || defined(__i386__)
	__asm__ __volatile__("pause" ::: "memory");
#else
	__asm__ __volatile__("" ::: "memory");
#endif
}

/* Nanoseconds on a clock that never steps. Returns 0 only if the platform has
 * no monotonic clock, which no supported platform does; a caller that treats 0
 * as an error is therefore safe without a separate status. */
static inline int64_t lib_now_ns(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (int64_t)ts.tv_sec * LIB_NSEC_PER_SEC + (int64_t)ts.tv_nsec;
}

/* Hold the processor until `deadline_ns`. Returns immediately if already past. */
static inline void lib_spin_until(int64_t deadline_ns)
{
	while (lib_now_ns() < deadline_ns)
		lib_cpu_relax();
}

/* Hold the processor for `ns` from now. */
static inline void lib_busy_delay(int64_t ns)
{
	if (ns > 0)
		lib_spin_until(lib_now_ns() + ns);
}

/* Yield the processor until `deadline_ns`, restarting across interruptions so
 * a signal does not shorten the wait. Returns immediately if already past. */
static inline void lib_sleep_until(int64_t deadline_ns)
{
	struct timespec target;

	if (deadline_ns <= lib_now_ns())
		return;
	target.tv_sec = (time_t)(deadline_ns / LIB_NSEC_PER_SEC);
	target.tv_nsec = (long)(deadline_ns % LIB_NSEC_PER_SEC);
	while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &target, NULL) == EINTR)
		;
}

#endif /* LIB_BASE_CLOCK_H */
