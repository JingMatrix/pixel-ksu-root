/* lib/trigger/binder.h -- a minimal client for the kernel's binder transport.
 *
 * Binder is a message transport with kernel-managed object lifetimes: a process
 * registers a node, the kernel hands other processes a handle to it, and every
 * transaction is a buffer plus a list of embedded object descriptors the kernel
 * translates on the way across. Lifetime bugs in that translation are reachable
 * from any process that can open a binder device, which is why a chain here
 * needs a client of its own rather than the framework's.
 *
 * What a client has to get right, and what this module therefore owns:
 *
 *   Opening. A device is unusable until its version has been queried and a
 *   buffer has been mapped; the kernel rejects transactions before both.
 *
 *   The command stream. Reads and writes share one request carrying two
 *   buffers, and the reply is a stream of variable-length records. A reader
 *   that does not know every record's length desynchronises on the first
 *   unfamiliar one and misreads everything after it, so the parser here stops
 *   at anything it does not recognise rather than guessing a length.
 *
 *   Object descriptors. Sending a node and sending a handle differ only in a
 *   type field and which union member is set, and getting that wrong is a
 *   silently dropped object rather than an error.
 *
 * What stays with the exploit: the process topology, who talks to whom in what
 * order, and when each participant exits. That is the technique; this is the
 * transport.
 *
 * No device or kernel-build constant lives here.
 */
#ifndef LIB_TRIGGER_BINDER_H
#define LIB_TRIGGER_BINDER_H

#include <stddef.h>
#include <stdint.h>

#include <linux/android/binder.h>

/* Size of the buffer a client maps. Read-only and never written by the client;
 * the kernel allocates transaction buffers inside it. */
#ifndef LIB_BINDER_MAP_BYTES
#define LIB_BINDER_MAP_BYTES (128 * 1024)
#endif

/* What one read of the command stream yielded. `handle` is the first object
 * handle found in an incoming transaction's descriptor list, which is how a
 * participant learns of a node it did not create. */
struct lib_binder_rx {
	int      got_transaction;  /* an incoming transaction or reply was seen */
	int      dead;             /* the far end is gone                      */
	int      failed;           /* the kernel reported the send failed      */
	uint32_t handle;           /* first handle in the descriptor list      */
};

/* Open a binder device and make it usable: query the version, map the buffer.
 * Returns the descriptor, or -1 with errno set. */
int lib_binder_open(const char *path);

/* Announce how many threads the kernel may ask this process to spawn. Advisory:
 * a failure is not fatal, and the caller may ignore the result. */
int lib_binder_set_max_threads(int fd, uint32_t n);

/* One command-stream exchange: write `wlen` bytes of commands, read up to
 * `rlen` bytes of replies. Either side may be empty. `consumed` receives the
 * reply byte count. Returns 0 on success, -1 with errno set. */
int lib_binder_talk(int fd, const void *wbuf, size_t wlen,
                    void *rbuf, size_t rlen, size_t *consumed);

/* Enter the command loop, so the kernel may deliver transactions here. */
int lib_binder_enter_looper(int fd);

/* Offer to take additional transactions on this thread. */
int lib_binder_register_looper(int fd);

/* Become the context manager: the process every handle 0 resolves to. Tries the
 * extended form first, then the original. Returns 0 on success, -1 otherwise —
 * a busy result is normal while a previous manager's release is still pending,
 * so a caller that expects to take the role retries. */
int lib_binder_become_context_manager(int fd);

/* Compose an object descriptor into `buf` and record its position in `off`.
 * Both return the descriptor's size. A node descriptor offers an object this
 * process owns; a handle descriptor passes on a reference to someone else's. */
size_t lib_binder_put_node(void *buf, binder_size_t *off, uint64_t cookie);
size_t lib_binder_put_handle(void *buf, binder_size_t *off, uint32_t handle);

/* Send a transaction to `handle`, carrying `dlen` bytes with `olen` bytes of
 * descriptor offsets, and read whatever comes back into `rbuf`.
 *
 * `oneway` picks the property that decides whether a lifetime defect on the
 * receiving side is reachable at all: a one-way transaction is complete once it
 * is queued, while a synchronous one keeps the sender's record alive until the
 * reply arrives, which is what gives a concurrent teardown something to race.
 *
 * Returns 0 on success, -1 with errno set. */
int lib_binder_send(int fd, uint32_t handle, int oneway,
                    const void *data, size_t dlen,
                    const void *offsets, size_t olen,
                    void *rbuf, size_t rlen, size_t *consumed);

/* The same, with an explicit AIDL transaction code instead of the fixed 1
 * lib_binder_send() uses. A synthetic peer of our own only ever needs to know
 * "a transaction arrived"; a real platform interface (ActivityManager,
 * ServiceManager) dispatches on the code, so a caller reaching one names it
 * here rather than through a raw request. See lib/trigger/amclient.h for a
 * client built on this. */
int lib_binder_transact_code(int fd, uint32_t handle, uint32_t code, int oneway,
                             const void *data, size_t dlen,
                             const void *offsets, size_t olen,
                             void *rbuf, size_t rlen, size_t *consumed);

/* For a caller that needs the reply rather than tolerating its absence.
 * lib_binder_open()'s fd is non-blocking, and the kernel can finish
 * processing a request's write half while still returning -1/EAGAIN from the
 * same ioctl because nothing was ready to read back yet -- confirmed on
 * hardware to be a real, not-rare timing gap, not a failure. A one-way send
 * that nobody replies to tolerates that (see lib_binder_send()'s own doc);
 * a synchronous call whose caller wants the answer needs the answer, so this
 * retries the read half (an empty write, matching lib_binder_recv()'s own
 * pattern) until data arrives or `timeout_ms` elapses. Returns 0, or -1 with
 * errno set (ETIMEDOUT on the deadline). */
int lib_binder_wait_reply(int fd, void *rbuf, size_t rlen, size_t *consumed,
                          int timeout_ms);

/* Send a reply to the transaction this thread is currently handling. */
int lib_binder_reply(int fd, const void *data, size_t dlen,
                     const void *offsets, size_t olen);

/* Read the command stream and interpret it into `out`. Returns the number of
 * reply bytes read, or -1 with errno set. */
int lib_binder_recv(int fd, void *rbuf, size_t rlen, struct lib_binder_rx *out);

/* Interpret an already-read reply buffer. Exposed separately for a caller that
 * batches its own reads. Stops at the first unrecognised record rather than
 * guessing its length. */
void lib_binder_parse(const void *buf, size_t len, struct lib_binder_rx *out);

/* Leave the command loop on this thread. This is the operation a lifetime
 * defect in the teardown path is reached through, so it is named rather than
 * left as a raw request at the call site. */
int lib_binder_thread_exit(int fd);

#endif /* LIB_TRIGGER_BINDER_H */
