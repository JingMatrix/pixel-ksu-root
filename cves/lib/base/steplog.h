/* lib/base/steplog.h -- a record of how far a run got, that outlives the run.
 *
 * A chain that can fault the kernel loses its standard output at exactly the
 * moment that output is worth reading: the process dies with the machine, and
 * the terminal keeps whatever was already flushed, which is usually nothing.
 * The console log the device saves across a reset does not help either, because
 * it holds what the KERNEL printed, not what the exploit knew.
 *
 * So a step is written to a file on the device, opened for synchronous writes,
 * one short line per point the run passes. After a reset the file is still
 * there and says which step was the last to complete -- which is the difference
 * between knowing a shot failed and knowing where.
 *
 * Keep the lines short and the steps few. This costs a synchronous write each
 * time, which is a real cost on the very paths that are being timed, so a step
 * belongs at a phase boundary and never inside a window.
 */
#ifndef LIB_STEPLOG_H
#define LIB_STEPLOG_H

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int lib_steplog_fd = -1;

/* Open (and truncate) the step file. Returns 0, or -1 with the log disabled,
 * which is not fatal: a run without a step file still runs. */
static inline int lib_steplog_open(const char *path)
{
	lib_steplog_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_SYNC | O_CLOEXEC, 0600);
	return lib_steplog_fd < 0 ? -1 : 0;
}

/* One line, written through to the device before returning. */
static inline void lib_steplog(const char *fmt, ...)
{
	char line[256];
	va_list ap;
	int n;

	if (lib_steplog_fd < 0)
		return;
	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line) - 1, fmt, ap);
	va_end(ap);
	if (n <= 0)
		return;
	if ((size_t)n >= sizeof(line) - 1)
		n = (int)sizeof(line) - 2;
	line[n++] = '\n';
	{
		ssize_t ignored = write(lib_steplog_fd, line, (size_t)n);

		(void)ignored;
	}
}

static inline void lib_steplog_close(void)
{
	if (lib_steplog_fd >= 0)
		close(lib_steplog_fd);
	lib_steplog_fd = -1;
}

#endif /* LIB_STEPLOG_H */
