/* lib/rw/nameblob.h -- kernel read and write through a redirected buffer
 * descriptor.
 *
 * The technique, in three steps.
 *
 * A shared-memory region's name is copied whole into a fixed-size kernel
 * buffer. If that buffer's backing object has been made to overlap a file
 * descriptor's buffer descriptor -- by whatever means the consuming chain
 * has -- then writing a name writes that descriptor, and the descriptor says
 * where reads and writes of the file land and how long they are. Setting it to
 * an arbitrary address and length turns an ordinary read or write of the file
 * into a read or write of that address.
 *
 * Two properties of the name interface shape the implementation:
 *
 *   A name is a C string, so the copy stops at the first zero byte, and an
 *   address containing one cannot be written in a single pass. It can be
 *   written in several: set the whole blob first, then re-set successively
 *   shorter prefixes, each terminating exactly where a zero byte belongs.
 *   Bytes past a terminator are left from the previous pass, so the descriptor
 *   ends up holding every byte the caller asked for.
 *
 *   The driver prefixes every stored name, so a field the caller wants at a
 *   given offset in the kernel buffer must be placed that many bytes earlier in
 *   the blob.
 *
 * A read is expressed as a page pointer plus a file offset rather than as an
 * address directly, because the descriptor names a page and the read names a
 * position within it; the two are chosen so the position is fixed and the page
 * pointer carries the caller's address.
 *
 * Every access re-composes the descriptor, so this primitive is correct but
 * slow -- roughly a hundred name settings per access, each taking a global lock
 * inside the driver. A consumer that needs throughput uses it once, to install
 * a faster primitive, and then stops using it. A consumer that polls in the
 * middle of a race must not use it at all.
 */
#ifndef LIB_RW_NAMEBLOB_H
#define LIB_RW_NAMEBLOB_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "krw.h"

/* Write `len` bytes of `blob` into the kernel buffer behind the region's name,
 * including any zero bytes. Returns 0 on success, -1 on failure. */
int lib_nameblob_set(int fd, const unsigned char *blob, size_t len);

/* Read `len` bytes from `addr` through a redirected descriptor. Returns the
 * byte count, or -1. */
ssize_t lib_nameblob_read(int fd, uintptr_t addr, void *out, size_t len);

/* Write `len` bytes to `addr` through a redirected descriptor. Returns the byte
 * count, or -1. */
ssize_t lib_nameblob_write(int fd, uintptr_t addr, const void *data, size_t len);

/* The same pair as a typed read/write contract, so a consumer can hand this
 * primitive wherever any other is accepted. */
struct krw lib_krw_nameblob(int fd);

#endif /* LIB_RW_NAMEBLOB_H */
