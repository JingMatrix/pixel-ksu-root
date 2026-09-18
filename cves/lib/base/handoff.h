/* lib/base/handoff.h -- a bounded wait on a flag one process sets for
 * another.
 *
 * A multi-process chain often needs one side to know a specific step in
 * another process has completed, without a lock either side could be
 * holding through the moment that matters. A flag in memory both processes
 * map, set atomically by the side that reaches the step and polled by the
 * side waiting on it, answers that without depending on scheduling order.
 *
 * The wait still needs a bound: a watched process that dies before setting
 * the flag would otherwise hang its waiter forever, so this also reaps that
 * process non-blockingly on every poll and reports an early death as
 * distinct from a timeout.
 */
#ifndef LIB_HANDOFF_H
#define LIB_HANDOFF_H

#include <stdatomic.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Wait for `*flag` to become nonzero, or `watch` to exit early, or timeout.
 * Returns 0 if the flag was seen, -1 on timeout or the watched child dying
 * first. `watch` may be <= 0 to skip the exit check, for a waiter that is
 * not the watched process's own parent and so cannot reap it. `what` names
 * what is being waited for, in the message a timeout or early death
 * prints. */
static inline int lib_wait_flag(atomic_int *flag, pid_t watch, int timeout_ms,
				const char *what)
{
	int waited = 0;

	while (waited < timeout_ms) {
		if (atomic_load(flag))
			return 0;
		if (watch > 0) {
			int status;
			pid_t w = waitpid(watch, &status, WNOHANG);

			if (w == watch) {
				printf("wait_flag: %s died before signalling (%s)\n",
				       what, WIFSIGNALED(status) ? "killed" : "exited");
				return -1;
			}
		}
		usleep(2000);
		waited += 2;
	}
	printf("wait_flag: timed out waiting for %s\n", what);
	return -1;
}

#endif /* LIB_HANDOFF_H */
