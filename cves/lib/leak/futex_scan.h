/* Recovering an object's kernel address from futex-hash timing.
 *
 * The kernel hashes a waiter's identity -- the address space it belongs to and
 * the address being waited on -- into a fixed table of buckets. Two waiters that
 * land in the same bucket contend on that bucket's lock, and the contention is
 * measurable from userspace as a slower wake.
 *
 * That gives an address without any memory-corruption primitive. Collect a set
 * of user addresses that all hash to one bucket, then search the kernel's linear
 * map for the address-space address that would put them there: only the true one
 * makes every member of the set agree. The search runs in userspace against a
 * model of the kernel's own hash, so it costs nothing but processor time.
 *
 * Two steps, separated because a caller may want them in different processes:
 * building the collision set is timing-sensitive and benefits from isolation,
 * while the search is pure computation and parallelises.
 */
#ifndef LIB_FUTEX_SCAN_H
#define LIB_FUTEX_SCAN_H

#include <stdatomic.h>
#include <stdint.h>

/* How many colliding addresses the set needs before the search can be trusted.
 * Each one roughly halves the chance that a wrong candidate satisfies them all,
 * so this is the confidence of the answer rather than a tuning knob. */
#ifndef LIB_FUTEX_COLLISION_GOAL
#define LIB_FUTEX_COLLISION_GOAL 8
#endif

/* Shared between the two steps, and across a process boundary when the caller
 * puts them in different processes -- so it holds no pointers into either. */
struct kernelsnitch_state {
	atomic_int pile_started;
	atomic_int found;
	atomic_int collisions_ready;
	uint64_t   mm_address;
	uint64_t   collision_addresses[LIB_FUTEX_COLLISION_GOAL];
	uint32_t   hash_size;
	uint32_t   collision_count;
};

/* What the search is looking for, and where.
 *
 * The object's size and its slab's span decide the stride the search walks; the
 * linear map's bounds decide how far. All four are device facts, passed in so
 * this module never assumes the target its caller was built for. */
struct lib_futex_scan_cfg {
	uint64_t object_size;   /* stride within a slab                    */
	uint64_t slab_bytes;    /* stride between slabs                    */
	uint64_t map_begin;     /* first linear-map address to consider    */
	uint64_t map_end;       /* one past the last                       */
	uint64_t coarse_bytes;  /* alignment each worker's range starts on */
};

/* Fill `shared` with a set of user addresses that share one bucket.
 *
 * `futex_map` is a large readable/writable mapping the candidates are taken
 * from; it must be big enough that candidates spread across the table. The
 * caller has already set `shared->hash_size`.
 *
 * Timing is the measurement, so this is worth running where nothing else of the
 * caller's is competing. Returns 0 when the full set was found. */
int lib_futex_collisions_build(struct kernelsnitch_state *shared,
                               unsigned char *futex_map);

/* Search the linear map for the address that explains the collision set.
 *
 * Pure computation over `workers` threads; no syscalls into the object being
 * located and nothing written. Returns the address, or 0 if the search
 * finished without a candidate that satisfies every member of the set. */
uint64_t lib_futex_scan_object(struct kernelsnitch_state *shared, int workers,
                               const struct lib_futex_scan_cfg *cfg);

#endif /* LIB_FUTEX_SCAN_H */
