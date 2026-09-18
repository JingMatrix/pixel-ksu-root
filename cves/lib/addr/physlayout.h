/* lib/addr/physlayout.h -- converting kernel addresses to physical ones, using
 * the kernel's own recorded values.
 *
 * A primitive that reaches memory by physical address needs to know where a
 * given kernel address lives physically, and two different regions answer that
 * differently:
 *
 *   The linear map is a straight offset from the start of memory, so the
 *   conversion is a subtraction.
 *   The kernel image sits elsewhere, at a displacement the kernel records for
 *   itself; the conversion there is a different subtraction.
 *
 * Both displacements are read from the kernel rather than assumed, because both
 * vary with how the system booted. Reading them is why this needs a read
 * primitive and cannot be pure arithmetic like the linear-map conversions.
 *
 * Every conversion is range-checked in both directions. This layer exists to be
 * used when a chain is about to write, and an address that converts to a
 * plausible-looking frame outside memory is exactly the input that turns a
 * controlled write into an uncontrolled one.
 */
#ifndef LIB_ADDR_PHYSLAYOUT_H
#define LIB_ADDR_PHYSLAYOUT_H

#include <stdint.h>

#include "../rw/krw.h"

/* The two displacements, read once and then used for every conversion. */
struct lib_physlayout {
	uint64_t memstart;        /* physical address memory begins at        */
	uint64_t image_voffset;   /* kernel address minus physical, for the image */
	uint64_t image_begin;     /* runtime bounds of the image region        */
	uint64_t image_end;
};

/* Read the displacements and check they are self-consistent: page-aligned, and
 * placing the image inside memory. Returns 0 on success, -1 if a read failed or
 * a value was implausible -- which is a reason to stop, not to proceed with a
 * guess. `memstart_addr` and `voffset_addr` are where the kernel records them. */
int lib_physlayout_load(const struct krw *rw, struct lib_physlayout *out,
                        uint64_t memstart_addr, uint64_t voffset_addr,
                        uint64_t image_begin, uint64_t image_end);

/* Physical address of a kernel address, or -1 if it is in neither region or
 * converts outside memory. */
int lib_phys_of(const struct lib_physlayout *l, uint64_t kaddr, uint64_t *out);

/* Page descriptor and in-page offset for a physical address, or -1 if it lies
 * outside memory. */
int lib_page_of_phys(const struct lib_physlayout *l, uint64_t phys,
                     uint64_t *page_desc, uint32_t *page_offset);

/* Strip a pointer's tag. A pointer read out of the kernel may carry one in its
 * top byte; the address it names is the same either way. */
static inline uint64_t lib_untag(uint64_t v)
{
	return (uint64_t)((int64_t)(v << 8) >> 8);
}

#endif /* LIB_ADDR_PHYSLAYOUT_H */
