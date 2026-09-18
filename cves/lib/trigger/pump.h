/* lib/trigger/pump.h -- flood a callback across every CPU not otherwise
 * pinned, for a window with no userspace signal to gate on.
 *
 * Some free-then-reuse windows are internal to one kernel function's own
 * critical section -- microseconds wide, over before anything surfaces to
 * userspace that a caller could wait on. A userspace-visible event that
 * looks like it brackets the window (a close notification, a stop
 * notification) is frequently queued BEFORE the window even opens, not
 * after: it is easy to build a trigger that reliably arrives too late by
 * construction, having gated on exactly the wrong signal. A userspace-side
 * disconnect notification, for instance, can depend on driver state a
 * caller never confirmed reaching, while the kernel-side teardown call that
 * actually produces the window runs unconditionally on the same failure
 * path -- gating on the former misses the window; an entry probe on the
 * latter does not.
 *
 * Density in place of a signal is the only thing userspace has left: run the
 * same operation continuously, for as long as the window could plausibly
 * still be open, on every CPU the kernel's own worker might land on. That
 * last part matters and is easy to get backwards -- same-CPU execution
 * cannot help here. A short, uninterrupted piece of kernel code runs to
 * completion before or after anything else scheduled on that one CPU, never
 * during it, so a pump sharing a CPU with the kworker it is racing never
 * actually overlaps it. This is why lib_pump_start() spans multiple CPUs by
 * default instead of picking one.
 *
 * A runtime gate (an earlier, reliable signal that the window is now
 * *plausible*, even if not exactly when it opens -- a flag the caller sets
 * when its own responder starts the countdown to the driver's timeout that
 * will eventually open the window) lets each thread start its own clock
 * from that moment
 * instead of from process start, which matters: pumping the full budget
 * from t=0 spends most of it before the window opens, or worse, well after
 * it has already closed and the freed allocation been reoccupied by
 * something unrelated -- exposure bought for nothing. Pass NULL to start
 * immediately if no such signal exists.
 */
#ifndef LIB_TRIGGER_PUMP_H
#define LIB_TRIGGER_PUMP_H

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include "../base/clock.h"
#include "../base/cpu.h"

#ifndef LIB_PUMP_MAX_THREADS
#define LIB_PUMP_MAX_THREADS 64
#endif

struct lib_pump {
	pthread_t threads[LIB_PUMP_MAX_THREADS];
	int n;
	volatile int stop;
	volatile unsigned long sent;
	void (*send_one)(void *ctx);
	void *ctx;
	long ms;
	const volatile int *gate;
};

struct lib_pump__targ { struct lib_pump *p; int cpu; };

static void *lib_pump__thread(void *arg_)
{
	struct lib_pump__targ *a = (struct lib_pump__targ *)arg_;
	struct lib_pump *p = a->p;
	int cpu = a->cpu;
	int64_t deadline;

	free(a);
	lib_pin_cpu(cpu);
	if (p->gate)
		while (!*p->gate && !p->stop)
			lib_cpu_relax();
	/* Each thread's clock starts independently, at whatever instant IT
	 * notices the gate -- microseconds apart across threads at worst, and
	 * simpler and race-free compared with sharing one deadline computed by
	 * whichever thread gets there first. */
	deadline = lib_now_ns() + p->ms * 1000000LL;
	while (!p->stop && lib_now_ns() < deadline) {
		p->send_one(p->ctx);
		__sync_fetch_and_add(&p->sent, 1UL);
	}
	return NULL;
}

/* Start the pump. One thread per CPU in [0, lib_cpu_count()) by default,
 * skipping any CPU listed in avoid[0..navoid-1] (CPUs this process already
 * pinned other threads to -- sharing one with the pump buys no coverage and
 * only adds contention).
 *
 *   explicit_cpu >= 0   overrides everything: one thread, that CPU only --
 *                       a focused measurement, not the default coverage
 *                       strategy. avoid[]/threads are ignored.
 *   threads > 0         that many threads instead of one-per-CPU, cycling
 *                       CPUs modulo the CPU count if it exceeds them, and
 *                       NOT filtered by avoid[] -- an explicit count is the
 *                       caller's to spend as asked.
 *   gate                see the file header. NULL starts immediately.
 *
 * send_one/ctx are called from every pump thread concurrently; ctx must be
 * safe for that (typically: read-only, or itself atomic/lock-free, matching
 * the shape of the write primitive most callers pass in). Returns the
 * number of threads actually started. */
static inline int lib_pump_start(struct lib_pump *p, void (*send_one)(void *ctx),
				 void *ctx, long ms, int explicit_cpu, int threads,
				 const int *avoid, int navoid,
				 const volatile int *gate)
{
	int ncpu = lib_cpu_count(), i, want;

	p->n = 0;
	p->stop = 0;
	p->sent = 0;
	p->send_one = send_one;
	p->ctx = ctx;
	p->ms = ms;
	p->gate = gate;

	if (explicit_cpu >= 0) {
		struct lib_pump__targ *a = malloc(sizeof(*a));

		if (!a)
			return 0;
		a->p = p;
		a->cpu = explicit_cpu;
		if (pthread_create(&p->threads[0], NULL, lib_pump__thread, a) == 0)
			p->n = 1;
		else
			free(a);
		return p->n;
	}

	want = threads > 0 ? threads : ncpu;
	if (want > LIB_PUMP_MAX_THREADS)
		want = LIB_PUMP_MAX_THREADS;
	for (i = 0; i < want; i++) {
		int cpu = i % ncpu, j, skip = 0;
		struct lib_pump__targ *a;

		if (threads <= 0)
			for (j = 0; j < navoid; j++)
				if (avoid[j] == cpu) { skip = 1; break; }
		if (skip)
			continue;
		a = malloc(sizeof(*a));
		if (!a)
			continue;
		a->p = p;
		a->cpu = cpu;
		if (pthread_create(&p->threads[p->n], NULL, lib_pump__thread, a) == 0)
			p->n++;
		else
			free(a);
	}
	return p->n;
}

/* Signal every thread to stop and join them all. Safe to call even if
 * lib_pump_start() started zero threads (p->n == 0). */
static inline void lib_pump_stop_and_join(struct lib_pump *p)
{
	int i;

	p->stop = 1;
	for (i = 0; i < p->n; i++)
		pthread_join(p->threads[i], NULL);
}

#endif /* LIB_TRIGGER_PUMP_H */
