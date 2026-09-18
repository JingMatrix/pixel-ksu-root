/* lib/trigger/binder.c -- see binder.h. */
#include "binder.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

/* A command followed by its transaction record, as the kernel expects to find
 * them in the write buffer: adjacent, with no padding between. */
struct lib_binder_txn_cmd {
	uint32_t cmd;
	struct binder_transaction_data t;
} __attribute__((packed));

int lib_binder_open(const char *path)
{
	struct binder_version v;
	int fd = open(path, O_RDWR | O_CLOEXEC | O_NONBLOCK);

	if (fd < 0)
		return -1;
	memset(&v, 0, sizeof(v));
	if (ioctl(fd, BINDER_VERSION, &v) < 0) {
		close(fd);
		return -1;
	}
	/* The mapping is read-only and never touched by the client: its purpose
	 * is to give the kernel an address range to place transaction buffers
	 * in. Without it every transaction is rejected. */
	if (mmap(NULL, LIB_BINDER_MAP_BYTES, PROT_READ,
		 MAP_PRIVATE | MAP_NORESERVE, fd, 0) == MAP_FAILED) {
		close(fd);
		return -1;
	}
	return fd;
}

int lib_binder_set_max_threads(int fd, uint32_t n)
{
	return ioctl(fd, BINDER_SET_MAX_THREADS, &n);
}

int lib_binder_talk(int fd, const void *wbuf, size_t wlen,
		    void *rbuf, size_t rlen, size_t *consumed)
{
	struct binder_write_read x;
	int r;

	memset(&x, 0, sizeof(x));
	x.write_size = wlen;
	x.write_buffer = (binder_uintptr_t)wbuf;
	x.read_size = rlen;
	x.read_buffer = (binder_uintptr_t)rbuf;
	r = ioctl(fd, BINDER_WRITE_READ, &x);
	if (consumed)
		*consumed = x.read_consumed;
	return r;
}

static int lib_binder_command(int fd, uint32_t cmd)
{
	return lib_binder_talk(fd, &cmd, sizeof(cmd), NULL, 0, NULL);
}

int lib_binder_enter_looper(int fd)
{
	return lib_binder_command(fd, BC_ENTER_LOOPER);
}

int lib_binder_register_looper(int fd)
{
	return lib_binder_command(fd, BC_REGISTER_LOOPER);
}

int lib_binder_thread_exit(int fd)
{
	return ioctl(fd, BINDER_THREAD_EXIT, 0);
}

int lib_binder_become_context_manager(int fd)
{
	struct flat_binder_object f;

	memset(&f, 0, sizeof(f));
	if (ioctl(fd, BINDER_SET_CONTEXT_MGR_EXT, &f) == 0)
		return 0;
	return ioctl(fd, BINDER_SET_CONTEXT_MGR, 0);
}

/* The permission word carried by an offered object. Every bit below the
 * scheduling-policy field is set, which is what a node offered for general use
 * carries; nothing here depends on the exact value beyond it being accepted. */
#define LIB_BINDER_OBJECT_FLAGS 0x7f

size_t lib_binder_put_node(void *buf, binder_size_t *off, uint64_t cookie)
{
	struct flat_binder_object *f = buf;

	memset(f, 0, sizeof(*f));
	f->hdr.type = BINDER_TYPE_BINDER;
	f->flags = LIB_BINDER_OBJECT_FLAGS | FLAT_BINDER_FLAG_ACCEPTS_FDS;
	f->binder = cookie;
	f->cookie = cookie;
	if (off)
		*off = 0;
	return sizeof(*f);
}

size_t lib_binder_put_handle(void *buf, binder_size_t *off, uint32_t handle)
{
	struct flat_binder_object *f = buf;

	memset(f, 0, sizeof(*f));
	f->hdr.type = BINDER_TYPE_HANDLE;
	f->flags = LIB_BINDER_OBJECT_FLAGS;
	f->handle = handle;
	if (off)
		*off = 0;
	return sizeof(*f);
}

static int lib_binder_transact(int fd, uint32_t cmd, uint32_t handle, uint32_t code,
			       int oneway, const void *data, size_t dlen,
			       const void *offsets, size_t olen,
			       void *rbuf, size_t rlen, size_t *consumed)
{
	struct lib_binder_txn_cmd w;

	memset(&w, 0, sizeof(w));
	w.cmd = cmd;
	w.t.target.handle = handle;
	w.t.code = code;
	w.t.flags = oneway ? TF_ONE_WAY : 0;
	w.t.data_size = dlen;
	w.t.offsets_size = olen;
	w.t.data.ptr.buffer = (binder_uintptr_t)data;
	w.t.data.ptr.offsets = (binder_uintptr_t)offsets;
	return lib_binder_talk(fd, &w, sizeof(w), rbuf, rlen, consumed);
}

int lib_binder_send(int fd, uint32_t handle, int oneway,
		    const void *data, size_t dlen,
		    const void *offsets, size_t olen,
		    void *rbuf, size_t rlen, size_t *consumed)
{
	return lib_binder_transact(fd, BC_TRANSACTION, handle, 1, oneway,
				   data, dlen, offsets, olen,
				   rbuf, rlen, consumed);
}

int lib_binder_transact_code(int fd, uint32_t handle, uint32_t code, int oneway,
			     const void *data, size_t dlen,
			     const void *offsets, size_t olen,
			     void *rbuf, size_t rlen, size_t *consumed)
{
	return lib_binder_transact(fd, BC_TRANSACTION, handle, code, oneway,
				   data, dlen, offsets, olen,
				   rbuf, rlen, consumed);
}

int lib_binder_wait_reply(int fd, void *rbuf, size_t rlen, size_t *consumed,
			  int timeout_ms)
{
	int waited = 0;

	while (waited < timeout_ms) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int pr = poll(&pfd, 1, 20);

		if (pr > 0) {
			uint32_t empty = 0;

			if (lib_binder_talk(fd, &empty, 0, rbuf, rlen, consumed) == 0)
				return 0;
			if (errno != EAGAIN)
				return -1;
		}
		waited += 20;
	}
	errno = ETIMEDOUT;
	return -1;
}

int lib_binder_reply(int fd, const void *data, size_t dlen,
		     const void *offsets, size_t olen)
{
	return lib_binder_transact(fd, BC_REPLY, 0, 0, 0, data, dlen,
				   offsets, olen, NULL, 0, NULL);
}

void lib_binder_parse(const void *buf, size_t len, struct lib_binder_rx *out)
{
	const unsigned char *b = buf;
	size_t i = 0;

	memset(out, 0, sizeof(*out));
	while (i + sizeof(uint32_t) <= len) {
		uint32_t cmd;

		memcpy(&cmd, b + i, sizeof(cmd));
		i += sizeof(cmd);
		switch (cmd) {
		case BR_NOOP:
		case BR_SPAWN_LOOPER:
		case BR_TRANSACTION_COMPLETE:
			break;
		case BR_INCREFS:
		case BR_ACQUIRE:
		case BR_RELEASE:
		case BR_DECREFS:
			i += 2 * sizeof(binder_uintptr_t);
			break;
		case BR_DEAD_REPLY:
		case BR_DEAD_BINDER:
			out->dead = 1;
			break;
		case BR_FAILED_REPLY:
			out->failed = 1;
			break;
		case BR_TRANSACTION:
		case BR_REPLY: {
			const struct binder_transaction_data *td;

			if (i + sizeof(*td) > len)
				return;
			td = (const void *)(b + i);
			i += sizeof(*td);
			out->got_transaction = 1;
			/* Pull the first handle out of the descriptor list:
			 * this is how a participant learns of a node created by
			 * someone else. */
			if (td->offsets_size && td->data.ptr.offsets &&
			    td->data.ptr.buffer) {
				const binder_size_t *of =
					(const void *)(uintptr_t)td->data.ptr.offsets;
				size_t n = td->offsets_size / sizeof(binder_size_t);

				for (size_t k = 0; k < n; k++) {
					const struct flat_binder_object *f =
						(const void *)((uintptr_t)td->data.ptr.buffer + of[k]);
					if (f->hdr.type == BINDER_TYPE_HANDLE ||
					    f->hdr.type == BINDER_TYPE_WEAK_HANDLE)
						out->handle = f->handle;
				}
			}
			break;
		}
		default:
			/* An unfamiliar record has an unknown length, so the
			 * rest of the stream cannot be located. Stop rather
			 * than desynchronise. */
			return;
		}
	}
}

int lib_binder_recv(int fd, void *rbuf, size_t rlen, struct lib_binder_rx *out)
{
	size_t consumed = 0;
	uint32_t empty = 0;

	if (lib_binder_talk(fd, &empty, 0, rbuf, rlen, &consumed) < 0 && errno != EAGAIN)
		return -1;
	lib_binder_parse(rbuf, consumed, out);
	return (int)consumed;
}
