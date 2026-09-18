/* lib/root/input_dev_find.h -- locating registered input devices by name.
 *
 * A driver bug that frees an input device's backing object while the device
 * stays registered leaves a live /dev/input/eventN that faults whatever later
 * opens it. The device itself is on the kernel's global input_dev list, so a
 * privileged observer can find it there by the name it registered under, and
 * then a single field write (input_dev->users != 0, which makes
 * input_open_device skip ->open) defuses the open path without a function call.
 *
 * Reads are through the kprobe observation instrument (lib/root/kprobe_read.h),
 * so the caller must already be privileged; nothing here writes. Offsets are the
 * kernel's own (measure with BTF): the list-node inside input_dev, the name
 * pointer, and the list head's runtime address (resolve from kallsyms).
 */
#ifndef LIB_ROOT_INPUT_DEV_FIND_H
#define LIB_ROOT_INPUT_DEV_FIND_H

#include <string.h>
#include "kprobe_read.h"

/* Walk `list_head` (the runtime address of input_dev_list) and collect into
 * out[0..max) the address of every input_dev whose ->name begins with `prefix`.
 * node_off is input_dev.node, name_off is input_dev.name (a char*). Returns the
 * count found. Bounded to a sane number of list steps. */
static inline int lib_input_dev_find_by_name(unsigned long long list_head,
		unsigned node_off, unsigned name_off, const char *prefix,
		unsigned long long *out, int max)
{
	int n = 0, plen = (int)strlen(prefix);
	/* Compare only a prefix that fits WITHIN the name string: reading whole words
	 * past the string end can fault an @addr fetcharg (the read then fails for
	 * that device and it is silently skipped). Cap at 16 bytes / 2 words -- long
	 * enough to be unique, short enough to stay inside any real device name. */
	int cmplen = plen < 16 ? plen : 16;
	int nwords = (cmplen + 7) / 8;
	unsigned long long node = 0;
	if (!lib_kprobe_peek_self("idfl", list_head, &node, 1))
		return 0;
	for (int i = 0; i < 1024 && node && node != list_head && n < max; i++) {
		unsigned long long idev = node - node_off;
		unsigned long long name_ptr = 0, w[2] = {0};
		char nm[16];
		if (lib_kprobe_peek_self("idfn", idev + name_off, &name_ptr, 1) && name_ptr &&
		    lib_kprobe_peek_self("idfs", name_ptr, w, nwords)) {
			memcpy(nm, w, sizeof w);
			if (!strncmp(nm, prefix, (size_t)cmplen))
				out[n++] = idev;
		}
		unsigned long long next = 0;
		if (!lib_kprobe_peek_self("idfx", node, &next, 1))
			break;
		node = next;
	}
	return n;
}

#endif /* LIB_ROOT_INPUT_DEV_FIND_H */
