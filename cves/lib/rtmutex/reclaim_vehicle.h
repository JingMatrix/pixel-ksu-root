/* lib/rtmutex/reclaim_vehicle.h -- the reclaim-vehicle contract.
 *
 * A reclaim vehicle is the syscall that re-occupies a freed rt_mutex_waiter's
 * kernel stack slot with attacker bytes. More than one syscall can do this on
 * a given kernel, and which one is best is a property of the target, not of
 * the exploit: a struct that copies in one call, a version floor, a stack
 * frame's distance from the freed slot -- all differ per build. Naming each
 * candidate as a vehicle and selecting between them at run time, rather than
 * writing one and hoping, is what lets a target that fails vehicle A still
 * root through vehicle B, and what lets a new candidate be added without
 * touching the code that selects or drives the existing ones.
 *
 * Two shapes of vehicle exist, and it is a property of the vehicle, not a
 * choice made where it is driven:
 *
 *   unlock_first = 0   the copy blocks holding the overlay on the kernel
 *                      stack, so the reclaim has to be sprayed BEFORE the
 *                      chain that dereferences the freed waiter is released.
 *   unlock_first = 1   the copy returns immediately, so the reclaim has to
 *                      be sprayed AFTER that chain releases and the walk
 *                      that dereferences the waiter is already in flight --
 *                      spraying first would occupy the slot too early and
 *                      let something else reclaim it first.
 *
 * A vehicle also declares the page geometry it entails (the layout its own
 * copy writes, which the reclaimed page's own contents have to match) and an
 * optional precondition check: a per-target or per-build fact that predicts
 * whether the vehicle can work at all before the race is attempted.
 */
#ifndef LIB_RTMUTEX_RECLAIM_VEHICLE_H
#define LIB_RTMUTEX_RECLAIM_VEHICLE_H

#include <stddef.h>

/*
 * A precondition check's verdict.
 *
 *   OK       nothing to report.
 *   WARN     a prediction about kernel-side behaviour, not a bound on this
 *            process's own memory: the vehicle may still be attempted, and
 *            its own outcome is the authoritative answer.
 *   REFUSE   a bound this process cannot cross without corrupting its own
 *            memory, or a placement that provably cannot reach the target at
 *            all. Never attempt the vehicle when this is returned.
 */
enum lib_reclaim_gate {
  LIB_RECLAIM_GATE_OK,
  LIB_RECLAIM_GATE_WARN,
  LIB_RECLAIM_GATE_REFUSE,
};

struct lib_reclaim_vehicle {
  const char *name;           /* the selectable name (case-insensitive)     */
  const char *marker;         /* NAME_GATE_FAIL / NAME_UNVERIFIED prefix    */
  /* How much of the waiter the vehicle's own copy completes: "full" writes
   * both rb_node pairs plus task and lock, "narrow" only task and lock, so
   * the sprayed page supplies the rest. Compared case-insensitively; any
   * value that is not "narrow" is full. */
  const char *page_geometry;
  int unlock_first;           /* see file header                           */
  /* Whether this vehicle's own fire() sets the shared vehicle_in_call to its
   * seq for the duration of its copy (main.c). Only meaningful in the
   * unlock_first=0 shape -- an unlock_first=1 copy returns before anything
   * could observe it in flight -- and even then only true for a vehicle
   * whose fire() actually does it: a gate that waits on this must check it
   * per vehicle, not assume every 0 does, or a vehicle that never sets it
   * spins out its whole budget and skips every arm. */
  int publishes_in_call;
  /* NULL if the vehicle has no precondition to check. msg is a caller-owned
   * buffer of at least msglen bytes, filled with the one-line reason behind
   * a WARN or REFUSE verdict. */
  enum lib_reclaim_gate (*gate_check)(char *msg, size_t msglen);
  void (*fire)(void);         /* run the vehicle's own reclaim race         */
};

/* Runs a vehicle's precondition check, or reports OK with an empty message
 * if it declares none. */
static inline enum lib_reclaim_gate lib_reclaim_vehicle_check(
    const struct lib_reclaim_vehicle *v, char *msg, size_t msglen) {
  if (!v->gate_check) {
    if (msglen) {
      msg[0] = '\0';
    }
    return LIB_RECLAIM_GATE_OK;
  }
  return v->gate_check(msg, msglen);
}

#endif /* LIB_RTMUTEX_RECLAIM_VEHICLE_H */
