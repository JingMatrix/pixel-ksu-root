/* Which kmem_cache actually owns a kernel pointer -- read out of the slab's
 * own struct page/struct slab, not guessed from /proc/slabinfo names.
 *
 * /proc/slabinfo's names are not a reliable guide to what a caller's own
 * allocation actually used: diffing it across a live event is too coarse a
 * signal at low object counts against a cache's own background churn, and
 * can read as a flat 0 delta even while a kprobe alloc/free count over the
 * identical window proves the allocations are real and staying outstanding.
 * Checking more candidate cache names does not resolve that; asking the
 * kernel directly does, which is what this does.
 *
 * A slab page's struct page is reinterpreted as struct slab once SLUB owns
 * it, and struct slab::slab_cache (offset verified against this kernel's own
 * BTF, not assumed) names the exact struct kmem_cache -- whose own ::size
 * and ::name settle the question outright. lib/addr/physmap.h's
 * lib_va_to_page() already does the PFN/vmemmap arithmetic (the linear map
 * is constant on this device); this only adds the two kprobe reads past it.
 *
 * Needs root (lib_kprobe_read) and a linear-map pointer -- a kmalloc()
 * return value qualifies; a vmalloc one does not.
 *
 *   slabname <hex-kernel-address>
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "../lib/addr/physmap.h"
#include "../lib/rw/kprobe_read.h"

/* Verified against this kernel's own BTF (data/live/<target>/btf-vmlinux):
 *   struct slab -- slab_cache (a struct kmem_cache *) at offset 24.
 *   struct kmem_cache -- size (unsigned int) at offset 24, name
 *   (const char *) at offset 96.
 * Re-derive with `pahole -C slab` / `pahole -C kmem_cache` before reusing
 * this on a different kernel -- these are not stable across versions. */
#define SLAB_CACHE_OFF   24
#define KMEM_CACHE_SIZE_OFF 24
#define KMEM_CACHE_NAME_OFF 96

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <hex-kernel-address>\n", argv[0]);
		return 2;
	}
	if (!lib_kprobe_read_available()) {
		fprintf(stderr, "kprobe read unavailable (need root + tracefs)\n");
		return 1;
	}

	uint64_t addr = strtoull(argv[1], NULL, 16);
	if (!lib_is_direct_ptr(addr)) {
		fprintf(stderr, "0x%" PRIx64 " is not in the linear map "
				"[0x%llx, 0x%llx)\n", addr, DIRECT_MAP_BASE, DIRECT_MAP_END);
		return 1;
	}

	uint64_t page = lib_va_to_page(addr);
	printf("addr=0x%" PRIx64 " struct page/slab=0x%" PRIx64 "\n", addr, page);

	uint64_t cache = 0;
	if (lib_kprobe_read64(page + SLAB_CACHE_OFF, &cache) != 0) {
		fprintf(stderr, "read slab_cache FAILED\n");
		return 1;
	}
	printf("slab_cache=0x%" PRIx64 "\n", cache);
	if (!cache) {
		printf("slab_cache is NULL -- this page is not (or no longer) a "
		       "SLUB slab page (freed back to the buddy allocator, or "
		       "never one)\n");
		return 0;
	}

	uint64_t size = 0, name_ptr = 0;
	if (lib_kprobe_read64(cache + KMEM_CACHE_SIZE_OFF, &size) != 0) {
		fprintf(stderr, "read kmem_cache->size FAILED\n");
		return 1;
	}
	/* size is a 32-bit field; the read is 64 bits wide, so the upper 32
	 * bits are the next field over and must be masked off. */
	size &= 0xffffffffULL;
	lib_kprobe_read64(cache + KMEM_CACHE_NAME_OFF, &name_ptr);

	char namebuf[64] = {0};
	if (name_ptr) {
		uint64_t words[8];
		size_t n = sizeof(namebuf) - 1 < LIB_KPROBE_MAX_WORDS * 8 ?
			   sizeof(namebuf) - 1 : LIB_KPROBE_MAX_WORDS * 8;
		size_t nwords = (n + 7) / 8;
		if (lib_kprobe_read(name_ptr, words, nwords) == 0)
			for (size_t i = 0; i < n; i++)
				namebuf[i] = ((char *)words)[i];
	}
	printf("kmem_cache: size=%" PRIu64 " name=\"%s\"\n", size, namebuf);
	return 0;
}
