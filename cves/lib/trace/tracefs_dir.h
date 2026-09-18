/* lib/trace/tracefs_dir.h -- resolve the tracing filesystem's mount point.
 *
 * The interface is mounted at one of two paths depending on kernel config.
 * Every module in this directory that reads or writes a control file under
 * it resolves the mount the same way, once, rather than repeating the
 * candidate list.
 */
#ifndef LIB_TRACE_TRACEFS_DIR_H
#define LIB_TRACE_TRACEFS_DIR_H

#include <stddef.h>
#include <unistd.h>

static inline const char *lib_tracefs_dir(void)
{
	static const char *const candidates[] = {
		"/sys/kernel/tracing", "/sys/kernel/debug/tracing",
	};

	for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
		if (access(candidates[i], R_OK | W_OK) == 0)
			return candidates[i];
	}
	return NULL;
}

#endif /* LIB_TRACE_TRACEFS_DIR_H */
