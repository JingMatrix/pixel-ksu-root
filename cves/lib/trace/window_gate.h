/* lib/trace/window_gate.h - acting inside a kernel function's own window.
 *
 * Some windows are internal to one kernel function: an object is freed near
 * its start and the structure pointing at it is only cleared at its end, so a
 * syscall arriving in between reaches memory that is free but still reachable.
 * Such a window is microseconds to milliseconds wide and nothing signals it to
 * userspace, so the only way in is an entry probe on the function itself.
 *
 * Two rules decide whether this works at all:
 *
 *   1. The thread that WATCHES must not run on the processor that executes the
 *      window. Kernel work dispatched by schedule_work() runs on the
 *      dispatching processor, and on one processor that code runs to
 *      completion before or after a userspace thread, never during it. A
 *      watcher there competes with the very event it waits for.
 *
 *   2. The thread that ACTS must be SCHED_FIFO and BLOCKED, never SCHED_FIFO
 *      and spinning. A realtime thread spinning on the processor that runs the
 *      window starves it, and the record never arrives. Blocked, it costs
 *      nothing until the wake, which on a PREEMPT kernel preempts the running
 *      kernel thread -- which is how a userspace allocation can land inside
 *      the window, on that processor's own SLUB freelist, where the object the
 *      window freed actually is.
 *
 * So: the actor pins to the processor the window runs on, takes realtime
 * priority, and blocks here; the watcher pins elsewhere at normal priority and
 * releases it.
 */
#ifndef LIB_WINDOW_GATE_H
#define LIB_WINDOW_GATE_H

#include <pthread.h>
#include <stdint.h>

struct lib_window_gate {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	volatile int open;
	volatile int stop;
	int64_t record_ns;          /* tracing-clock stamp carried by the record */
	int64_t open_ns;            /* when the watcher acted on it */
	int watch_cpu;
	int budget_ms;
	char name[24];
	pthread_t watcher;
	int watcher_live;
};

/* Arm an entry probe named `name` on `sym` and select a comparable tracing
 * clock. Returns 0, or -1 (nothing is armed). */
int lib_window_gate_arm(struct lib_window_gate *g, const char *name,
			const char *sym);

/* Start the watcher on `cpu`, giving up after budget_ms. It reads the probe
 * stream, so nothing else may read it at the same time. Returns 0 or -1. */
int lib_window_gate_watch(struct lib_window_gate *g, int cpu, int budget_ms);

/* Block until the window opens. Returns 0 when it did, -1 if the gate was
 * stopped first. The caller should already be pinned and at its final
 * priority: everything after this returns is inside the window. */
int lib_window_gate_wait(struct lib_window_gate *g);

/* Release anyone blocked without the window having opened. */
void lib_window_gate_stop(struct lib_window_gate *g);

/* Join the watcher and disable the probe. */
void lib_window_gate_close(struct lib_window_gate *g);

/* How long the record took to reach userspace, in microseconds, or -1 if the
 * record carried no usable timestamp. This is the latency that cannot be
 * reduced by doing less work after the wake, so it is reported apart from it. */
int64_t lib_window_gate_delivery_us(const struct lib_window_gate *g);

#endif /* LIB_WINDOW_GATE_H */
