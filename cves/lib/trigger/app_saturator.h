/* lib/trigger/app_saturator.h -- occupying a target app's binder thread pool
 * from outside its process.
 *
 * A transaction sent to a process whose thread pool is genuinely busy stays
 * queued rather than being answered immediately, which is what widens the
 * gap between "sent" and "delivered" enough to act inside. A same-process
 * self-call cannot create that condition: Android's ContentResolver takes a
 * documented local-provider fast path for a same-process call, dispatched
 * as a direct method call without ever reaching /dev/binder. Occupying the
 * pool for real needs calls that originate outside the target's own
 * process.
 *
 * This runs a small embedded dex through a forked app_process, whose own
 * job is to make enough concurrent, blocking cross-process calls into the
 * target to occupy its pool for a chosen duration, then hold the process
 * open rather than exit -- exiting early closes its binder fd out from
 * under its own still-in-flight blocked calls.
 */
#ifndef LIB_APP_SATURATOR_H
#define LIB_APP_SATURATOR_H

#include <stddef.h>
#include <sys/types.h>

/* Write `dex_len` bytes of `dex` to `dex_path` and fork+exec app_process
 * against `class_name`, passing `threads` and `hold_ms` as its first two
 * arguments. Returns the child's pid, or -1 on failure. The caller kills it
 * explicitly once done with it -- it does not exit on its own until its own
 * hold duration elapses. */
pid_t lib_app_saturator_launch(const char *dex_path, const unsigned char *dex,
			       size_t dex_len, const char *class_name,
			       int threads, int hold_ms);

#endif /* LIB_APP_SATURATOR_H */
