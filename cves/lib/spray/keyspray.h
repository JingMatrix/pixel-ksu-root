/* lib/spray/keyspray.h -- filling freed kernel memory with chosen bytes, on a
 * kernel with no System-V IPC.
 *
 * A keyring payload is an allocation of the caller's size holding the caller's
 * bytes, and it lives until the keyring is cleared. That makes it the reclaim
 * vehicle of choice where a freed object has to STAY occupied: unlike a queued
 * message or an extended attribute, nothing frees it behind your back, so the
 * placement can be read back and checked rather than assumed.
 *
 * Two properties are the caller's to get right, and this module does not guess
 * at either. The allocation must come from the same cache the freed object did,
 * which fixes the payload length -- lib_keyspray_init() takes the cache size and
 * works it out. And the copied bytes do not start at the beginning of the
 * allocation: the kernel's own header comes first, so an offset into the OBJECT
 * is not an offset into the payload. lib_keyspray_at() does that arithmetic.
 *
 * The keys are held until lib_keyspray_release(), which is also what a caller
 * must not forget: a spray left behind is kernel memory left pinned, and the
 * per-user key quota will refuse the next one.
 */
#ifndef LIB_KEYSPRAY_H
#define LIB_KEYSPRAY_H

#include <stddef.h>

/* sizeof(struct user_key_payload): an rcu_head and a length, then the data. */
#define LIB_KEYSPRAY_HEADER 24

/* The largest object this vehicle can fill, and the smallest. Below the header
 * there is no room for content at all. */
#define LIB_KEYSPRAY_MIN_OBJECT (LIB_KEYSPRAY_HEADER + 8)

/* How many placements can be read back afterwards. Beyond this the spray still
 * places, it just stops recording where. */
#define LIB_KEYSPRAY_KEPT 8192

struct lib_keyspray {
	unsigned char *payload;   /* the bytes every allocation carries */
	size_t len;               /* payload length: object size minus header */
	size_t object_size;       /* the cache this fills */
	unsigned long placed;     /* allocations that succeeded */
	unsigned long refused;    /* allocations the kernel refused */
	unsigned seq;             /* descriptions must differ, or a key updates */
	long *kept;               /* what was placed, for reading back */
	unsigned long nkept;
	/* Distinguishes this instance's descriptions from another lib_keyspray
	 * run in the SAME process: both default to "ks-<pid>-<seq>", and two
	 * instances' seq counters both start at 0, so without this a caller
	 * running two sprays at once (different object sizes, one process)
	 * collides on description and add_key() treats the second as an UPDATE
	 * of the first's key instead of a new one. Left at '\0' (zeroed struct),
	 * the description string is plain "ks-<pid>-<seq>". Set once, before
	 * lib_keyspray_init(). */
	char tag;
};

/* Prepare a spray for `object_size`-byte objects. Returns 0, or -1 if the size
 * cannot be reached with this vehicle (errno EINVAL) or memory ran out. */
int lib_keyspray_init(struct lib_keyspray *s, size_t object_size);

/* Write `n` bytes at offset `obj_off` INTO THE OBJECT, translating for the
 * kernel header. Returns 0, or -1 if that offset is inside the header or past
 * the end. */
int lib_keyspray_at(struct lib_keyspray *s, size_t obj_off, const void *src, size_t n);

/* One allocation. Returns 0 on success, -1 otherwise. */
int lib_keyspray_once(struct lib_keyspray *s);

/* `n` allocations, stopping early only on repeated refusal. Returns how many
 * landed. */
unsigned long lib_keyspray_burst(struct lib_keyspray *s, unsigned long n);

/* Drop every key this process holds, freeing the memory the spray pinned, and
 * free the payload. Safe to call twice. */
void lib_keyspray_release(struct lib_keyspray *s);

#endif /* LIB_KEYSPRAY_H */
