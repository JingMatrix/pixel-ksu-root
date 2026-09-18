/* lib/base/file.h -- whole-file reads and writes.
 *
 * Almost every fact a chain gathers before it touches the kernel comes out of a
 * small pseudo-file: a counter, a single line, a table to scan. The awkward
 * part is never the parsing, it is that a short read is normal there — these
 * files are generated on demand, so one read() returning less than asked is not
 * an error and not end of file. Each function here loops until the file says it
 * is done, and reports the total.
 *
 * Header-only, libc only, no device constant.
 */
#ifndef LIB_BASE_FILE_H
#define LIB_BASE_FILE_H

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* Read until `len` bytes or end of file, restarting across interruptions.
 * Returns the byte count, or -1 with errno set. */
static inline ssize_t lib_read_full(int fd, void *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		ssize_t n = read(fd, (char *)buf + done, len - done);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		done += (size_t)n;
	}
	return (ssize_t)done;
}

/* Write all `len` bytes, restarting across interruptions and short writes.
 * Returns 0 on success, -1 with errno set. */
static inline int lib_write_full(int fd, const void *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		ssize_t n = write(fd, (const char *)buf + done, len - done);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		done += (size_t)n;
	}
	return 0;
}

/* Read a whole file into `buf` as text, terminated and with trailing newlines
 * and terminators stripped. `cap` includes the terminator. Returns the length
 * on success, -1 if the file is unreadable, empty, or larger than `cap` - 1. */
static inline ssize_t lib_read_text(const char *path, char *buf, size_t cap)
{
	int fd;
	ssize_t n;

	if (cap < 2)
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = lib_read_full(fd, buf, cap - 1);
	close(fd);
	if (n <= 0 || (size_t)n >= cap)
		return -1;
	buf[n] = '\0';
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\0'))
		buf[--n] = '\0';
	return n;
}

/* First line of a file, terminated, newline stripped. Returns 0 on success,
 * -1 if the file is unreadable or empty; `buf` is emptied on failure so a
 * caller may ignore the status and test the string. */
static inline int lib_read_first_line(const char *path, char *buf, size_t cap)
{
	char *nl;

	if (cap == 0)
		return -1;
	buf[0] = '\0';
	if (lib_read_text(path, buf, cap) < 0) {
		buf[0] = '\0';
		return -1;
	}
	nl = strchr(buf, '\n');
	if (nl)
		*nl = '\0';
	return buf[0] ? 0 : -1;
}

/* Write a string to a file, creating nothing: the target is expected to exist,
 * as pseudo-files do. Returns 0 on success, -1 with errno set. */
static inline int lib_write_text(const char *path, const char *data)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	int rc;

	if (fd < 0)
		return -1;
	rc = lib_write_full(fd, data, strlen(data));
	close(fd);
	return rc;
}

#endif /* LIB_BASE_FILE_H */
