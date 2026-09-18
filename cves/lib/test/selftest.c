/* lib/test/selftest.c -- checks the library's pure logic on the host.
 *
 * Most of this library only means anything against a running kernel, and cannot
 * be tested away from one. But a specific and important part of it is pure
 * arithmetic over values the target description supplies -- address
 * conversions, hash models, field tables, buffer composition -- and that part is
 * both testable anywhere and exactly where a silent mistake is most costly: a
 * conversion that is wrong by a page produces a plausible address, and the first
 * sign of it is a device that has already been written to.
 *
 * So the rule this file follows is: anything that can be checked without a
 * kernel is checked here, and anything that cannot is left to the gates and to
 * hardware. A check that needs a device is not approximated with a mock,
 * because a mock of a kernel tests the mock.
 *
 * Build and run on the workstation:
 *     cc -I.. -o selftest lib/test/selftest.c && ./selftest
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* A concrete description, so the checks run against real values rather than the
 * standalone defaults every module carries. Any build's header serves; override
 * it to check another. The consistency rules below hold for every build, so a
 * description that fails them is wrong regardless of which one it is. */
#ifndef TARGET_HEADER
#define TARGET_HEADER "../targets/panther-CP2A.260705.006/target.h"
#endif

#include "../addr/physmap.h"
#include "../base/bytes.h"
#include "../base/outcome.h"
#include "../base/procinfo.h"
#include "../leak/futex_bucket.h"
#include "../target.h"

static int failures;
static int checks;

#define CHECK(cond, fmt, ...)                                                 \
	do {                                                                  \
		checks++;                                                     \
		if (!(cond)) {                                                \
			printf("  FAIL %s:%d " fmt "\n", __func__, __LINE__,   \
			       ##__VA_ARGS__);                                \
			failures++;                                           \
		}                                                             \
	} while (0)

/* ------------------------------------------------------------ address model
 *
 * The conversions are each other's inverses over the whole linear map, and the
 * page-descriptor index is measured from the first frame of memory rather than
 * from zero. Both are the kind of thing that is right for the values a
 * developer tries by hand and wrong at the edges. */
static void test_address_model(void)
{
	unsigned long long first = PHYS_OFFSET_PFN;
	unsigned long long probes[] = {
		first, first + 1, first + 0x1000, first + 0x100000,
		first + ((DIRECT_MAP_END - DIRECT_MAP_BASE) >> PAGE_SHIFT) - 1,
	};

	for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
		unsigned long long pfn = probes[i];
		unsigned long long va = lib_pfn_to_va(pfn);
		unsigned long long back = lib_va_to_pfn(va);

		CHECK(back == pfn, "frame %#llx round-tripped to %#llx", pfn, back);
		CHECK(va >= DIRECT_MAP_BASE, "frame %#llx mapped below the linear map", pfn);
	}

	/* A descriptor is indexed from the first frame, so the first frame's
	 * descriptor is the base of the array and nothing lands below it. */
	CHECK(lib_pagemap_pfn_to_page(first) == VMEMMAP_START,
	      "first frame's descriptor is not the array base");
	CHECK(lib_va_to_page(lib_pfn_to_va(first)) == VMEMMAP_START,
	      "descriptor of the first frame's address is not the array base");

	/* The two spellings of the same conversion must agree, which is the
	 * whole reason both exist. */
	for (unsigned long long pfn = first; pfn < first + 64; pfn += 7) {
		CHECK(lib_va_to_page(lib_pfn_to_va(pfn)) ==
		      lib_pagemap_pfn_to_page(pfn),
		      "conversions disagree at frame %#llx", pfn);
		CHECK(lib_page_to_direct(lib_direct_to_page(lib_pfn_to_va(pfn))) ==
		      lib_pfn_to_va(pfn),
		      "descriptor round trip lost frame %#llx", pfn);
	}

	/* The range test is what stands between a disturbed pointer and a
	 * dereference, so its boundaries are exact, not approximate. */
	CHECK(lib_is_direct_ptr(DIRECT_MAP_BASE), "base rejected");
	CHECK(lib_is_direct_ptr(DIRECT_MAP_END - 1), "last address rejected");
	CHECK(!lib_is_direct_ptr(DIRECT_MAP_END), "one past the end accepted");
	CHECK(!lib_is_direct_ptr(DIRECT_MAP_BASE - 1), "one before the base accepted");
	CHECK(!lib_is_direct_ptr(0), "a null pointer accepted");
	CHECK(!lib_is_direct_ptr(KIMAGE_TEXT_BASE), "an image address accepted");
}

/* --------------------------------------------------------------- byte model
 *
 * A fabricated object is composed at offsets the target names, including
 * unaligned ones. Going through memcpy is what makes that safe; this checks it
 * is also correct. */
static void test_byte_model(void)
{
	unsigned char buf[64];
	uint64_t big = UINT64_C(0x0123456789abcdef);
	uint32_t small = 0xfeedface;

	memset(buf, 0, sizeof(buf));
	for (size_t off = 0; off + 8 <= sizeof(buf); off++) {
		lib_put64(buf, off, big);
		CHECK(lib_get64(buf, off) == big, "64-bit round trip failed at %zu", off);
	}
	for (size_t off = 0; off + 4 <= sizeof(buf); off++) {
		lib_put32(buf, off, small);
		CHECK(lib_get32(buf, off) == small, "32-bit round trip failed at %zu", off);
	}

	/* A write must touch its own bytes and no others. */
	memset(buf, 0xaa, sizeof(buf));
	lib_put64(buf, 8, big);
	CHECK(buf[7] == 0xaa && buf[16] == 0xaa, "a write ran past its field");

	CHECK(lib_hex_digit('0') == 0 && lib_hex_digit('9') == 9, "decimal digits");
	CHECK(lib_hex_digit('a') == 10 && lib_hex_digit('F') == 15, "hex digits");
	CHECK(lib_hex_digit('g') < 0 && lib_hex_digit(' ') < 0, "non-digits accepted");

	/* The comparator orders rather than subtracts, so it cannot overflow --
	 * which is the mistake it exists to avoid. */
	uint64_t lo = 0, hi = UINT64_MAX;
	CHECK(lib_cmp_u64(&lo, &hi) < 0 && lib_cmp_u64(&hi, &lo) > 0,
	      "comparator overflowed on the extremes");
	CHECK(lib_cmp_u64(&lo, &lo) == 0, "equal values not reported equal");
}

/* ------------------------------------------------------------- bucket model
 *
 * The model must match the kernel exactly, so what is checkable here is its
 * internal consistency: the table size is a power of two where the interface
 * rounds, every index is inside the table, and the inputs that are supposed to
 * matter do. */
static void test_bucket_model(void)
{
	uint32_t size = lib_futex_table_size();
	uint64_t mm = UINT64_C(0xffffff8012345000);
	uint32_t seen_distinct = 0;
	uint32_t first;

#if LIB_KMI < 66
	CHECK(size && (size & (size - 1)) == 0,
	      "table size %" PRIu32 " is not a power of two", size);
#endif
	CHECK(size >= LIB_FUTEX_PER_CPU, "table size %" PRIu32 " below one processor's share", size);

	first = lib_futex_bucket(0x1000, mm, size);
	for (uint64_t addr = 0x1000; addr < 0x1000 + 4096 * 64; addr += 4096) {
		uint32_t b = lib_futex_bucket(addr, mm, size);

		CHECK(b < size, "index %" PRIu32 " outside a table of %" PRIu32, b, size);
		if (b != first)
			seen_distinct++;
	}
	CHECK(seen_distinct > 0, "every page hashed to one bucket");

	/* The address space is an input: the same address in two of them must
	 * not be assumed to collide. */
	CHECK(lib_futex_bucket(0x1000, mm, size) !=
	      lib_futex_bucket(0x1000, mm + 0x400, size) ||
	      size < 4,
	      "the address space did not affect the index");

	/* The in-page offset is an input twice over -- as a field and as the
	 * seed -- so two offsets in one page must be able to differ. */
	CHECK(lib_futex_bucket(0x1000, mm, size) != lib_futex_bucket(0x1008, mm, size) ||
	      size < 4,
	      "the in-page offset did not affect the index");
}

/* ------------------------------------------------------- target description
 *
 * The description is the one source of device facts, so the checks here are
 * that its parts agree with each other. A description that contradicts itself
 * is the failure that produces plausible wrong addresses. */
static void test_target_description(void)
{
	CHECK(DIRECT_MAP_END > DIRECT_MAP_BASE, "the linear map is empty or inverted");
	CHECK((P0_PHYS_OFFSET & (PAGE_SIZE - 1)) == 0, "memory does not start on a page");
	CHECK(PHYS_OFFSET_PFN == (PHYS_OFFSET >> PAGE_SHIFT), "frame number disagrees with the base");

	/* The allocator table's shape has to admit the rows and buckets the
	 * description selects, or a slot address reads past the end. */
	CHECK(KMALLOC_CGROUP_TYPE < KMALLOC_CACHE_TYPES, "accounted row outside the table");
	CHECK(KMALLOC_NORMAL_TYPE < KMALLOC_CACHE_TYPES, "plain row outside the table");
	CHECK(KMALLOC_PIPE_INDEX < KMALLOC_BUCKETS, "selected bucket outside a row");
	CHECK(KMALLOC_CACHE_SLOTS == KMALLOC_CACHE_TYPES * KMALLOC_BUCKETS,
	      "slot count disagrees with the table's shape");

	/* The identity block is contiguous and lands inside the record. */
	CHECK(CRED_UID_OFF + CRED_ID_BLOCK_BYTES <= CRED_SECURITY_OFF,
	      "the identity block overlaps the security pointer");
	CHECK(CRED_SECUREBITS_OFF >= CRED_UID_OFF + CRED_ID_BLOCK_BYTES,
	      "the secure bits fall inside the identity block");
	CHECK(CRED_CAPS_OFF + CRED_CAP_WORDS * 8 <= CRED_SIZE,
	      "the capability sets run past the end of the record");
	CHECK(CRED_SECURITY_OFF < CRED_SIZE, "the security pointer is outside the record");

	/* The capability offsets the named indices produce are the contiguous
	 * run the description claims. */
	CHECK(CRED_CAP_OFF(CRED_CAP_INHERITABLE) == CRED_CAPS_OFF, "first set misplaced");
	CHECK(CRED_CAP_OFF(CRED_CAP_AMBIENT) == CRED_CAPS_OFF + 4 * 8, "last set misplaced");

	/* Every capability bit fits the mask, and the mask is not everything --
	 * a full-ones mask would mean the count was never applied. */
	CHECK(CAP_FULL != UINT64_MAX && CAP_FULL != 0, "the capability mask is degenerate");

	/* The flag bits are distinct positions inside one word. */
	CHECK(PG_SLAB_BIT != PG_HEAD_BIT, "the two page flags name one bit");
	CHECK(PG_SLAB_BIT < 64 && PG_HEAD_BIT < 64, "a page flag is outside the word");

	/* A structure's named fields lie inside it. These are guarded because a
	 * description states only the layouts it has actually measured, and a
	 * check on a fact nobody claims would be checking a default. */
#ifdef EVENTPOLL_SIZE
	CHECK(EP_OFF_OVFLIST < EVENTPOLL_SIZE, "the overflow field is outside the record");
	CHECK(EP_OFF_REFS < EVENTPOLL_SIZE, "the reference field is outside the record");
	CHECK(EPITEM_OFF_EVENT < EPITEM_SIZE, "the event field is outside the item");
#endif
#ifdef FILE_SIZE
	CHECK(FILE_OFF_PRIVATE_DATA < FILE_SIZE, "the private pointer is outside the file");
	CHECK(FILE_SIZE <= FILP_OBJ_SIZE, "the record does not fit its allocation");
#endif
#ifdef PIPE_BUFFER_OFF_PRIVATE
	CHECK(PIPE_BUFFER_OFF_PRIVATE < PIPE_BUFFER_SIZE, "a pipe entry field is outside the entry");
#endif

	/* The page descriptor's fields lie inside it, and the array is indexed
	 * by that size. */
	CHECK(STRUCT_SLAB_CACHE_OFF < STRUCT_PAGE_SIZE, "the cache pointer is outside the descriptor");
	CHECK(STRUCT_PAGE_COMPOUND_HEAD_OFF < STRUCT_PAGE_SIZE, "the back-pointer is outside the descriptor");
}

/* ------------------------------------------------------- process status reader
 *
 * The base is the caller's to state because the fields do not agree on one. A
 * capability mask has leading zeros and hexadecimal digits, so reading it with
 * an inferred base stops at the first digit past seven and returns a small
 * number that looks like a legitimate answer. This checks the reader against
 * the calling process's own values, which are known independently. */
static void test_status_reader(void)
{
	long long pid = -1, mask = -1, missing = -1;

	CHECK(lib_proc_status_field(0, "Pid", 10, &pid) == 0, "own identifier not readable");
	CHECK(pid == (long long)getpid(), "reported identifier %lld is not our own %d",
	      pid, (int)getpid());

	/* A capability mask has tens of bits set. Read with an inferred base the
	 * leading zeros make it octal and parsing stops at the first digit past
	 * seven, yielding a very small number -- which is why the check is on the
	 * magnitude and not merely on being non-zero. */
	CHECK(lib_proc_status_field(0, "CapBnd", 16, &mask) == 0, "capability mask not readable");
	CHECK(mask > 0xffff, "capability mask read as %#llx, too small to be one", mask);

	CHECK(lib_proc_status_field(0, "NoSuchFieldHere", 10, &missing) == -1,
	      "an absent field was reported as found");

	/* A name must match a whole field, not a prefix of one. */
	CHECK(lib_proc_status_field(0, "Pi", 10, &missing) == -1,
	      "a prefix of a field name matched");
}

/* ------------------------------------------------------------------ outcomes
 *
 * The four outcomes have to stay distinct: collapsing two of them is the
 * mistake the vocabulary exists to prevent, and it is silent. */
static void test_outcomes(void)
{
	int all[] = { LIB_OUTCOME_PASS, LIB_OUTCOME_MISS,
		      LIB_OUTCOME_PRECONDITION_FAIL, LIB_OUTCOME_REFUSED,
		      LIB_OUTCOME_USAGE };

	for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
		for (size_t j = i + 1; j < sizeof(all) / sizeof(all[0]); j++)
			CHECK(all[i] != all[j], "outcomes %zu and %zu share a value", i, j);
	CHECK(LIB_OUTCOME_PASS == 0, "success is not the zero status");
}

int main(void)
{
	struct { const char *name; void (*fn)(void); } tests[] = {
		{ "address model",      test_address_model },
		{ "byte model",         test_byte_model },
		{ "bucket model",       test_bucket_model },
		{ "target description", test_target_description },
		{ "status reader",      test_status_reader },
		{ "outcomes",           test_outcomes },
	};

	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		int before = failures;

		tests[i].fn();
		printf("%-20s %s\n", tests[i].name,
		       failures == before ? "ok" : "FAILED");
	}
	if (failures)
		printf("\n%d of %d checks failed\n", failures, checks);
	else
		printf("\nall %d checks passed\n", checks);
	return failures != 0;
}
