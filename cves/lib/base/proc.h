/* lib/base/proc.h -- bounded child lifecycle.
 *
 * A chain forks helpers constantly: a process whose address space is the object
 * being sprayed, a victim that must be running when a window opens, a half that
 * holds a reference until told to let go. Two rules govern all of them.
 *
 * First, a wait must be bounded. A helper that reached a corrupted structure
 * may never return, and an unbounded wait turns that into a hung run with no
 * diagnosis rather than a reported failure.
 *
 * Second, termination must be escalating and confirmed. A polite signal is
 * ignored by a process stuck in the kernel, so the sequence is: ask, wait a
 * little, insist, wait again, and report whether the process is actually gone.
 * The distinction matters because a helper that is still alive is still holding
 * whatever reference the next step assumes it released.
 *
 * Header-only, libc only, no device constant.
 */
#ifndef LIB_BASE_PROC_H
#define LIB_BASE_PROC_H

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "clock.h"

/* Raise a soft resource limit to its hard ceiling. Best effort: a chain that
 * wants many descriptors or many processes asks for the headroom and carries on
 * with whatever it got, because the useful amount is not knowable in advance
 * and a refusal is not by itself fatal. */
static inline void lib_raise_limit(int resource)
{
	struct rlimit rl;

	if (getrlimit(resource, &rl) == 0 && rl.rlim_cur != rl.rlim_max) {
		rl.rlim_cur = rl.rlim_max;
		setrlimit(resource, &rl);
	}
}

/* Headroom for a spray that holds one descriptor per sprayed object. */
static inline void lib_raise_nofile(void)
{
	lib_raise_limit(RLIMIT_NOFILE);
}

/* Headroom for a spray that holds one process per sprayed address space. */
static inline void lib_raise_nproc(void)
{
	lib_raise_limit(RLIMIT_NPROC);
}

/* Reap `pid`, waiting at most `timeout_ms`. Returns 1 and stores the status if
 * it exited, 0 if it is still running when the budget runs out, -1 on error. */
static inline int lib_wait_timed(pid_t pid, int *status, int timeout_ms)
{
	int64_t deadline = lib_now_ns() + (int64_t)timeout_ms * 1000000;

	for (;;) {
		int st = 0;
		pid_t r = waitpid(pid, &st, WNOHANG);
		if (r == pid) {
			if (status)
				*status = st;
			return 1;
		}
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (lib_now_ns() >= deadline)
			return 0;
		lib_sleep_until(lib_now_ns() + 1000000);
	}
}

/* Ask `pid` to exit, insist if it does not, and confirm it is gone. Returns 1
 * if it was reaped, 0 if it outlived both signals, -1 on error. `grace_ms` is
 * how long the polite signal is given before the forceful one; each stage gets
 * the same budget. */
static inline int lib_terminate(pid_t pid, int *status, int grace_ms)
{
	int r;

	if (pid <= 0)
		return -1;
	kill(pid, SIGTERM);
	r = lib_wait_timed(pid, status, grace_ms);
	if (r != 0)
		return r;
	kill(pid, SIGKILL);
	return lib_wait_timed(pid, status, grace_ms);
}

#endif /* LIB_BASE_PROC_H */
