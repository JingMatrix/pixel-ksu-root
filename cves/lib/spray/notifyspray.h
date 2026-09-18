/* lib/spray/notifyspray.h -- content-controlled kernel allocations through
 * filesystem-change notifications.
 *
 * Reclaiming a freed object with chosen bytes needs an interface that copies
 * caller-supplied content into a kernel allocation of a size the caller
 * controls. Message queues give that for larger sizes, but not for the small
 * ones -- and the object a chain wants is often small.
 *
 * Filesystem-change notification does. Each queued event is one allocation, and
 * it holds the name of the file the event was about, which the caller chose by
 * creating a file with that name. The allocation's size follows from the name's
 * length, which makes the size selectable within a range.
 *
 * Two properties are what make this usable rather than merely possible.
 *
 *   The queue is capped per instance. Left undrained, it fills within moments
 *   and every later event is discarded -- so allocation stops long before the
 *   moment the chain is aiming at. Draining converts a front-loaded burst into
 *   continuous pressure that is still running when it is needed. This is the
 *   difference between the technique working and not, not a refinement.
 *
 *   Several instances watching the same directory each queue their own copy of
 *   every event, so one filesystem operation produces as many allocations as
 *   there are watchers.
 *
 * The bytes are the caller's. What content makes a valid fabricated object, and
 * where within the allocation it has to land, is the consuming chain's problem:
 * the kernel writes a header ahead of the name, so a caller placing a value at
 * a chosen offset works backwards from that displacement.
 */
#ifndef LIB_SPRAY_NOTIFYSPRAY_H
#define LIB_SPRAY_NOTIFYSPRAY_H

#include <stddef.h>

/* Watching instances. More multiplies each filesystem operation into more
 * allocations, at the cost of descriptors and of drain time. */
#ifndef LIB_NOTIFYSPRAY_WATCHERS
#define LIB_NOTIFYSPRAY_WATCHERS 64
#endif

struct lib_notifyspray {
	int *watchers;
	int count;
	const char *dir;   /* directory the events are generated in */
};

/* Create the watching instances on `dir`. Returns the number created, which may
 * be fewer than asked for if descriptors run out -- a smaller spray, not a
 * failure. Returns -1 only if none could be created. */
int lib_notifyspray_open(struct lib_notifyspray *s, const char *dir, int count);

/* Close every instance and release the structure. */
void lib_notifyspray_close(struct lib_notifyspray *s);

/* Generate `rounds` filesystem operations whose names carry `namelen` bytes of
 * `name`, each producing two allocations per watching instance.
 *
 * The name is the payload, and its constraints are the technique's real limit:
 * it may contain no path separator and no terminator, so content with either
 * byte in it cannot be placed this way. Returns the number of allocations
 * generated. */
long lib_notifyspray_fire(struct lib_notifyspray *s, const char *name,
                          size_t namelen, int rounds);

/* Read and discard everything queued, freeing those allocations and making room
 * for more. Called between rounds; without it the spray stops early. */
void lib_notifyspray_drain(struct lib_notifyspray *s);

#endif /* LIB_SPRAY_NOTIFYSPRAY_H */
