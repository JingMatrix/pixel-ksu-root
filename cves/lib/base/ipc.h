/* lib/base/ipc.h -- a one-line handshake between the halves of a chain.
 *
 * A chain split across processes has to pass a few resolved values between
 * them: an address one half discovered, a descriptor number, a go-ahead. The
 * shape that suits this is a line of text on a descriptor the two already
 * share, because it has the properties the alternatives lack:
 *
 *   - a blocking read wakes the instant the peer writes, where polling a file
 *     adds latency to a window that is often the point of the exercise;
 *   - nothing survives the run, where a file left in a world-writable place is
 *     both a leftover from the previous attempt and a channel anyone can write;
 *   - the peer's exit closes the descriptor, so a half that dies is an end of
 *     file rather than a wait that never ends.
 *
 * A read may return a partial line even though the peer wrote it in one call —
 * atomicity is promised for the write, not the read — so the reader here
 * assembles the line a byte at a time. These messages are a few dozen bytes;
 * the cost does not matter and the correctness does.
 *
 * lib_ipc_poll_line() serves the case where the waiting half must keep doing
 * something while it waits: a process feeding a trigger in a loop cannot block,
 * so it asks for a line with a timeout and resumes its loop on 0.
 *
 * Header-only, libc only, no device constant.
 */
#ifndef LIB_BASE_IPC_H
#define LIB_BASE_IPC_H

#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Read one newline-terminated line into `buf`, terminated, newline stripped.
 * Returns 0 on success, -1 on end of file or error before a newline. */
static inline int lib_ipc_read_line(int fd, char *buf, size_t cap)
{
	size_t n = 0;

	while (n + 1 < cap) {
		char c;
		ssize_t r = read(fd, &c, 1);
		if (r <= 0)
			return -1;
		if (c == '\n')
			break;
		buf[n++] = c;
	}
	buf[n] = '\0';
	return 0;
}

/* Write `line` followed by a newline, looping over a partial write. Returns 0
 * on success, -1 on error or if the line does not fit the internal buffer. */
static inline int lib_ipc_write_line(int fd, const char *line)
{
	char buf[256];
	int len = snprintf(buf, sizeof(buf), "%s\n", line);
	size_t off = 0;

	if (len < 0 || (size_t)len >= sizeof(buf))
		return -1;
	while (off < (size_t)len) {
		ssize_t w = write(fd, buf + off, (size_t)len - off);
		if (w <= 0)
			return -1;
		off += (size_t)w;
	}
	return 0;
}

/* Wait up to `ms` for a line without blocking past it. Returns 1 when a line
 * was read, 0 on timeout (call again), -1 on end of file or error. The peer
 * writes one short line in one call, so once the descriptor reports readable
 * the whole line is there. */
static inline int lib_ipc_poll_line(int fd, char *buf, size_t cap, int ms)
{
	struct pollfd pf = { .fd = fd, .events = POLLIN, .revents = 0 };
	int r = poll(&pf, 1, ms);

	if (r < 0)
		return -1;
	if (r == 0)
		return 0;
	return lib_ipc_read_line(fd, buf, cap) == 0 ? 1 : -1;
}

#endif /* LIB_BASE_IPC_H */
