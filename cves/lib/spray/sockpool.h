/* lib/spray/sockpool.h -- a pool of socket pairs, sprayed in phases by several
 * processors at once.
 *
 * A spray that has to win a race is not simply "send a lot". Three properties
 * decide whether the freed memory is taken, and the single-shot form has none
 * of them:
 *
 *   Parallelism. One processor sending in a loop is slower than the window is
 *   wide. Several processors sending concurrently is what makes the spray
 *   faster than the thing it is racing.
 *
 *   Phases. A spray is usually three separate operations against the same pool,
 *   at different times: fill it so the allocator is warm and its free lists are
 *   short; empty selected entries so there are holes of exactly the right size
 *   waiting; and, once the race has freed the target, fill again so the content
 *   lands. Collapsing these into one loses the ordering that makes the third
 *   land at all.
 *
 *   Holding. A queued, unread message keeps its kernel buffer. Reading it back
 *   frees the buffer and undoes the placement, so the pool is held until the
 *   chain is finished with it.
 *
 * The size of each message is the caller's: it has to match the allocator cache
 * the freed object came from, and that is a property of the object, not of the
 * spray.
 *
 * What the buffer contains is also the caller's. This module moves bytes; it
 * has no opinion about them and embeds no offsets.
 */
#ifndef LIB_SPRAY_SOCKPOOL_H
#define LIB_SPRAY_SOCKPOOL_H

#include <stddef.h>

/* The byte a warming message carries. Exposed because a caller that drains an
 * entry to inspect it has to know what the warming messages ahead of its
 * content look like. */
#ifndef LIB_SOCKPOOL_WARM_BYTE
#define LIB_SOCKPOOL_WARM_BYTE 0x6e
#endif

/* Largest number of sending workers. More than one per processor adds
 * contention rather than throughput. */
#ifndef LIB_SOCKPOOL_MAX_WORKERS
#define LIB_SOCKPOOL_MAX_WORKERS 8
#endif

struct lib_sockpool_pair {
	int tx;  /* the sending end: queues buffers    */
	int rx;  /* the receiving end: releases them   */
};

struct lib_sockpool {
	struct lib_sockpool_pair *pairs;
	int count;
	int sock_type;    /* stream by default; datagram where message boundaries matter */
	int first_cpu;    /* processor the first worker pins to; -1 leaves affinity alone */
	int max_workers;  /* 0 takes the default */
};

/* What one phase does to every entry of the pool. */
enum lib_sockpool_phase {
	/* Queue `repeats` single-byte messages, so the pool holds small
	 * allocations and the allocator's free lists are short. */
	LIB_SOCKPOOL_WARM = 0,
	/* Drain those messages, leaving holes of the size they occupied. */
	LIB_SOCKPOOL_PUNCH,
	/* Queue `repeats` full-size messages carrying the caller's content. */
	LIB_SOCKPOOL_FILL,
};

/* Create `count` socket pairs. Returns 0, or -1 with errno set and nothing
 * left open. */
int lib_sockpool_open(struct lib_sockpool *p, int count);

/* Close every pair and release the pool. Safe on a zeroed structure. */
int lib_sockpool_close(struct lib_sockpool *p);

/* Run one phase across the pool with up to `max_workers` threads, each taking
 * entries from a shared cursor so a slow processor does not hold the phase up.
 * `payload`/`len` are used by the filling phase only. `repeats` is how many
 * messages each entry gets.
 *
 * Returns the number of operations that failed -- 0 meaning the phase completed
 * as asked. A failure count is returned rather than a status because a spray is
 * a statistical instrument: a few refusals are normal and do not invalidate it,
 * while a large count means the pool was never filled and the caller should not
 * believe what follows. */
int lib_sockpool_run(struct lib_sockpool *p, enum lib_sockpool_phase phase,
                     const void *payload, size_t len, int repeats);

/* Receive exactly `len` bytes from one entry, on the calling thread.
 *
 * This is how a spray is read for a result rather than driven: the kernel may
 * have written into a buffer that was reclaimed, and draining it is the only
 * way to see what it wrote. Draining also frees the buffer, so an entry read
 * this way is no longer holding anything -- which is why it is a separate,
 * deliberate call and not part of a phase.
 *
 * Returns 0 if the whole amount arrived, -1 otherwise. */
int lib_sockpool_drain(struct lib_sockpool *p, int index, void *buf, size_t len);

#endif /* LIB_SPRAY_SOCKPOOL_H */
