/* lib/leak/futex_bucket.h -- which hash bucket a futex address falls in.
 *
 * The kernel hashes a futex's identity -- the address space it belongs to, the
 * page within it, and the offset into that page -- and uses the result to pick
 * one bucket of a global table. Two futexes in the same bucket share a lock, so
 * an operation on one is measurably slower while the other is contended. That
 * makes the bucket index observable from userspace, and the hash invertible
 * enough to learn something about its inputs -- which is the basis of every
 * technique in this tree that recovers an address-space identifier without
 * reading kernel memory.
 *
 * For that to work the model here must agree with the kernel exactly. Three
 * things have to match, and each is a separate way to be wrong:
 *
 *   The mixing function, reproduced below.
 *   The key: the address-space pointer, the page-aligned address, and the
 *     in-page offset, in that order, with the offset also used as the seed.
 *   The table size, which is a power of two on one kernel interface and an
 *     unrounded multiple of the processor count on another. A mismatch here
 *     produces plausible-looking indices that are simply wrong, which is the
 *     failure mode hardest to notice.
 *
 * Header-only and dependency-free, so any consumer can model a bucket without
 * taking on a search strategy it does not want. What to do with the model --
 * how many collisions to gather, how to time them, how to scan -- is the
 * consumer's, because that is where the techniques genuinely differ.
 */
#ifndef LIB_LEAK_FUTEX_BUCKET_H
#define LIB_LEAK_FUTEX_BUCKET_H

#include <stdint.h>
#include <string.h>
#include <unistd.h>

#ifndef LIB_FUTEX_PAGE_SIZE
#define LIB_FUTEX_PAGE_SIZE 4096U
#endif

/* Buckets per processor, and the kernel interface whose sizing rule to apply.
 * The default is the interface that rounds up. */
#ifndef LIB_FUTEX_PER_CPU
#define LIB_FUTEX_PER_CPU 256U
#endif
#ifndef LIB_KMI
#define LIB_KMI 61
#endif

static inline uint32_t lib_rol32(uint32_t v, unsigned int n)
{
	return (v << (n & 31)) | (v >> ((-n) & 31));
}

/* The kernel's hash over four words with a seed. Written out rather than
 * factored into mixing macros: this is a transcription of something that must
 * match exactly, and a transcription is easier to check than a paraphrase. */
static inline uint32_t lib_jhash_4words(const uint32_t w[4], uint32_t seed)
{
	uint32_t a = UINT32_C(0xdeadbeef) + 16 + seed;
	uint32_t b = a;
	uint32_t c = a;

	a += w[0];
	b += w[1];
	c += w[2];

	a -= c; a ^= lib_rol32(c, 4);  c += b;
	b -= a; b ^= lib_rol32(a, 6);  a += c;
	c -= b; c ^= lib_rol32(b, 8);  b += a;
	a -= c; a ^= lib_rol32(c, 16); c += b;
	b -= a; b ^= lib_rol32(a, 19); a += c;
	c -= b; c ^= lib_rol32(b, 4);  b += a;

	a += w[3];

	c ^= b; c -= lib_rol32(b, 14);
	a ^= c; a -= lib_rol32(c, 11);
	b ^= a; b -= lib_rol32(a, 25);
	c ^= b; c -= lib_rol32(b, 16);
	a ^= c; a -= lib_rol32(c, 4);
	b ^= a; b -= lib_rol32(a, 14);
	c ^= b; c -= lib_rol32(b, 24);

	return c;
}

/* The identity the kernel hashes, in its own field order. */
struct lib_futex_key {
	uint64_t mm;       /* the address space the mapping belongs to */
	uint64_t address;  /* page-aligned user address                */
	uint32_t offset;   /* offset within that page                  */
	uint32_t pad;
};

/* Size of the table, by the rule of the selected kernel interface. */
static inline uint32_t lib_futex_table_size(void)
{
	long cpus;
	uint32_t size, rounded;

#if LIB_KMI >= 66
	cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (cpus <= 0)
		cpus = 1;
	return (uint32_t)cpus * LIB_FUTEX_PER_CPU;
#else
	/* The possible-processor count, not the online one: the table is sized
	 * at boot from what the system could bring up. */
	cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (cpus <= 0)
		cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (cpus <= 0)
		cpus = 1;
	size = (uint32_t)cpus * LIB_FUTEX_PER_CPU;
	for (rounded = 1; rounded < size; rounded <<= 1)
		;
	return rounded;
#endif
}

/* Bucket index of `user_address` in address space `mm`, for a table of
 * `table_size` buckets. */
static inline uint32_t lib_futex_bucket(uint64_t user_address, uint64_t mm,
					uint32_t table_size)
{
	struct lib_futex_key key;
	uint32_t w[4];

	key.mm = mm;
	key.address = user_address & ~(uint64_t)(LIB_FUTEX_PAGE_SIZE - 1);
	key.offset = (uint32_t)(user_address & (LIB_FUTEX_PAGE_SIZE - 1));
	key.pad = 0;
	/* The seed is the in-page offset, and only the first four words of the
	 * key are hashed -- the padding is never read. */
	memcpy(w, &key, sizeof(w));
	return lib_jhash_4words(w, key.offset) & (table_size - 1);
}

#endif /* LIB_LEAK_FUTEX_BUCKET_H */
