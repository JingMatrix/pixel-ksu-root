/* lib/rw/kreader_kprobe.h -- the kprobe/tracefs read as a struct lib_kreader.
 *
 * Selected through lib/rw/kreader_target.h; a consumer includes that, not this.
 * Build with lib/rw/kprobe_read.c.
 */
#ifndef LIB_RW_KREADER_KPROBE_H
#define LIB_RW_KREADER_KPROBE_H

#include <string.h>

#include "kprobe_read.h"
#include "kread.h"

/* One arm/enable/fire/harvest/disarm cycle per call, so a caller reading many
 * fields of one object puts a lib_kread_window in front of this. Word-granular
 * underneath -- a probe fetches 64-bit words -- so a shorter or unaligned
 * request is served out of a whole-word read. */
static inline int lib_kreader_kprobe_read(void *ctx, uint64_t addr, void *out,
					  size_t len)
{
	uint64_t words[LIB_KPROBE_MAX_WORDS];
	uint64_t base = addr & ~(uint64_t)7;
	size_t skew = (size_t)(addr - base);
	size_t need = (skew + len + 7) / 8;

	(void)ctx;
	if (need == 0 || need > LIB_KPROBE_MAX_WORDS)
		return -1;
	if (lib_kprobe_read(base, words, need) != 0)
		return -1;
	memcpy(out, (const unsigned char *)words + skew, len);
	return 0;
}

static inline int lib_kreader_kprobe_open(struct lib_kreader *r)
{
	(void)r;
	return lib_kprobe_read_available() ? 0 : -1;
}

static inline void lib_kreader_kprobe_close(struct lib_kreader *r)
{
	(void)r;
}

static inline struct lib_kreader *lib_kreader_kprobe(void)
{
	static struct lib_kreader r = {
		.name = "kprobe/tracefs",
		.open = lib_kreader_kprobe_open,
		.close = lib_kreader_kprobe_close,
		.read = lib_kreader_kprobe_read,
		.ctx = NULL,
		.max_read = LIB_KPROBE_MAX_WORDS * 8,
	};

	return &r;
}

#endif /* LIB_RW_KREADER_KPROBE_H */
