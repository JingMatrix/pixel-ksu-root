/* lib/base/bytes.h -- reading and writing fixed-width values in a byte buffer.
 *
 * A fabricated kernel object is composed in a plain byte buffer at offsets the
 * target description names, then handed to a primitive. Composing it with
 * pointer casts invites two faults that are invisible until the device is
 * holding the result: an unaligned access, and a stray assumption about the
 * layout of the composing process rather than the target. Going through memcpy
 * has neither property and costs nothing once compiled.
 *
 * Header-only, libc only, no device constant.
 */
#ifndef LIB_BASE_BYTES_H
#define LIB_BASE_BYTES_H

#include <stdint.h>
#include <string.h>

static inline void lib_put64(void *buf, size_t off, uint64_t v)
{
	memcpy((char *)buf + off, &v, sizeof(v));
}
static inline void lib_put32(void *buf, size_t off, uint32_t v)
{
	memcpy((char *)buf + off, &v, sizeof(v));
}
static inline uint64_t lib_get64(const void *buf, size_t off)
{
	uint64_t v;
	memcpy(&v, (const char *)buf + off, sizeof(v));
	return v;
}
static inline uint32_t lib_get32(const void *buf, size_t off)
{
	uint32_t v;
	memcpy(&v, (const char *)buf + off, sizeof(v));
	return v;
}

/* Value of one hexadecimal digit, or -1 if it is not one. */
static inline int lib_hex_digit(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Ordering comparator for 64-bit values, for sorting a sample of timings.
 * Written as two comparisons rather than a subtraction, which would overflow. */
static inline int lib_cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

#endif /* LIB_BASE_BYTES_H */
