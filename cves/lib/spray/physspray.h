/* lib/spray/physspray.h -- making a guessed kernel address hold chosen content.
 *
 * The linear map is not randomised on this architecture, so every physical page
 * has a fixed kernel address -- including the pages behind ordinary anonymous
 * memory. A process that fills a large amount of such memory with one repeated
 * structure therefore makes that structure appear at a great many kernel
 * addresses at once, and a guess only has to land on any of them.
 *
 * The hit rate is the fraction of usable memory covered, and nothing else, so
 * the size is chosen from what is actually free at the moment of the attempt
 * rather than from a constant. Memory is locked, which is what keeps the pages
 * from being reclaimed and the content from moving -- and also why the amount
 * left free matters: locked pages cannot be evicted, so too large a spray
 * invites the process itself to be killed.
 *
 * The structure is the caller's; this module only replicates it.
 */
#ifndef LIB_PHYSSPRAY_H
#define LIB_PHYSSPRAY_H

#include <stddef.h>

/* The size is chosen from what is free at the moment of the attempt, because
 * the hit rate is the fraction of usable memory covered and nothing else.
 *
 * Headroom left free is a floor plus a fraction of what is available, so it
 * scales with the device and still guards a small one. Locked pages cannot be
 * evicted, so too little headroom does not degrade performance -- it gets the
 * process killed. */
#ifndef LIB_PHYSSPRAY_HEADROOM_KB
#define LIB_PHYSSPRAY_HEADROOM_KB   400000ULL       /* >=~400MB free, always     */
#endif
#ifndef LIB_PHYSSPRAY_HEADROOM_DIV
#define LIB_PHYSSPRAY_HEADROOM_DIV  6ULL            /* + ~1/6 of MemAvailable    */
#endif
/* Safety bounds only: MAX is a sanity ceiling (rarely reached; the headroom is
 * the real governor), MIN keeps a useful floor when memory is tight. */
#ifndef LIB_PHYSSPRAY_MAX_BYTES
#define LIB_PHYSSPRAY_MAX_BYTES     (3584ULL << 20)
#endif
#ifndef LIB_PHYSSPRAY_MIN_BYTES
#define LIB_PHYSSPRAY_MIN_BYTES     (64ULL << 20)
#endif

/* Size a safe spray from /proc/meminfo: MemAvailable minus headroom (or half of
 * it when memory is tight), clamped to [MIN_BYTES, MAX_BYTES]. Returns 0 only if
 * /proc/meminfo is unreadable / has no MemAvailable. */
/* Size a safe spray from a MemAvailable reading: minus headroom (or half when
 * tight), split 'shares' ways, clamped to [MIN,MAX]. 'shares' is how many
 * processes will spray from the same pool -- pass 1 for a lone sprayer. Two
 * cooperating sprayers must each ask for a share AND both size from a reading
 * taken BEFORE either sprayed: a second process that re-reads /proc/meminfo
 * after its sibling took the memory sees a drained figure and silently sizes
 * itself down to the floor, destroying its coverage. */
unsigned long long lib_physspray_budget_from_kb(unsigned long long mem_avail_kb,
					       unsigned shares);

/* lib_physspray_budget_from_kb() against a live /proc/meminfo read, shares = 1.
 * Only correct for a lone sprayer (see above). */
unsigned long long lib_physspray_budget_bytes(void);

/* Size a spray that leaves AT LEAST keep_free_kb of MemAvailable behind, for a
 * consumer that must keep touching its own (unlocked) code/data AFTER the spray:
 * on a device where mlock is capped near zero (RLIMIT_MEMLOCK tiny), the spray's
 * anonymous pages stay resident, but driving MemAvailable to the floor lets the
 * kernel reclaim the consumer's clean, file-backed code pages -- and if that
 * code is re-entered when the process's mm can no longer be walked (e.g. a
 * forged maple tree), the refault is unserviceable and kills the run. Leaving a
 * real MemAvailable margin is the only lever when mlock is unavailable. Returns
 * (avail - keep_free) clamped to [MIN_BYTES, MAX_BYTES], or MIN_BYTES if the
 * margin would leave nothing. */
unsigned long long lib_physspray_budget_leaving(unsigned long long mem_avail_kb,
						unsigned long long keep_free_kb);

/* mmap+mlock 'bytes' of anonymous memory (rounded down to a whole number of
 * 4096-byte pages) and fill every page with 'tmpl' (tmpl_len<=4096; a short
 * template is zero-padded to the page). Returns the mapping, or NULL on error.
 * The mapping is held until the process exits; unmap with munmap(ptr, bytes)
 * (rounded the same way) if a caller wants to release it early. */
void *lib_physspray(size_t bytes, const void *tmpl, size_t tmpl_len);

#endif
