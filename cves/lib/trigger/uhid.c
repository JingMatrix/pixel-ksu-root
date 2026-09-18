/* lib/trigger/uhid.c - see lib/trigger/uhid.h. Self-contained: depends only on libc and the
 * kernel uapi <linux/uhid.h>; no exploit globals, no device constants. */
#include "uhid.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int lib_uhid_open(void)
{
	return open("/dev/uhid", O_RDWR | O_CLOEXEC);
}

int lib_uhid_send(int fd, const struct uhid_event *ev)
{
	ssize_t n = write(fd, ev, sizeof(*ev));
	return n == (ssize_t)sizeof(*ev) ? 0 : -1;
}

int lib_uhid_create2(int fd, const char *name, const char *phys,
                     const char *uniq, unsigned bus, unsigned vendor,
                     unsigned product, unsigned version,
                     const unsigned char *rdesc, size_t rdesc_len)
{
	struct uhid_event ev;

	if (rdesc_len > sizeof(ev.u.create2.rd_data)) {
		errno = EINVAL;
		return -1;
	}

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_CREATE2;
	if (name)
		snprintf((char *)ev.u.create2.name, sizeof(ev.u.create2.name),
		         "%s", name);
	if (phys)
		snprintf((char *)ev.u.create2.phys, sizeof(ev.u.create2.phys),
		         "%s", phys);
	if (uniq)
		snprintf((char *)ev.u.create2.uniq, sizeof(ev.u.create2.uniq),
		         "%s", uniq);
	if (rdesc_len && rdesc)
		memcpy(ev.u.create2.rd_data, rdesc, rdesc_len);
	ev.u.create2.rd_size = (unsigned short)rdesc_len;
	ev.u.create2.bus = (unsigned short)bus;
	ev.u.create2.vendor = vendor;
	ev.u.create2.product = product;
	ev.u.create2.version = version;

	return lib_uhid_send(fd, &ev);
}

int lib_uhid_run_until_close(int fd, int (*answer)(const unsigned char *out),
                             int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int waited = 0;
	const int slice = 50;

	while (timeout_ms < 0 || waited < timeout_ms) {
		struct uhid_event ev;
		int r = poll(&pfd, 1, slice);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0) {
			waited += slice;
			continue;
		}
		if (read(fd, &ev, sizeof(ev)) != (ssize_t)sizeof(ev))
			return -1;

		if (ev.type == UHID_OUTPUT) {
			if (answer && answer(ev.u.output.data) < 0)
				return -1;
		} else if (ev.type == UHID_GET_REPORT) {
			struct uhid_event rp;
			memset(&rp, 0, sizeof(rp));
			rp.type = UHID_GET_REPORT_REPLY;
			rp.u.get_report_reply.id = ev.u.get_report.id;
			rp.u.get_report_reply.err = EIO;
			lib_uhid_send(fd, &rp);
		} else if (ev.type == UHID_CLOSE) {
			return 1;
		}
	}
	return 0;
}
