/* lib/rw/kread.h -- the shape of a kernel read, and a read-ahead window over it.
 *
 * A kernel read is a callback -- `read(ctx, addr, out, len)` returning 0 on
 * success -- so anything above it (a task-list walk, a structure dump, a
 * classification) is written once and driven by whichever primitive a target
 * has: a kprobe/tracefs read, a BPF perf-event read, a chain's own R/W.
 * Addresses are runtime kernel VAs, read as-is.
 *
 * The window exists because those primitives are not equally cheap. One
 * kprobe read is an arm/enable/fire/harvest/disarm cycle that patches kernel
 * text through a stop_machine rendezvous on every online CPU; issuing one per
 * struct field turns a walk of ten threads into hundreds of them, which is slow
 * and, under enough churn, has wedged this project's own hardware outright. The
 * window turns a run of small ascending reads of one object into one wide read
 * plus buffer copies -- the same access pattern the caller already has, at a
 * fraction of the cost.
 *
 * It is a snapshot, not a cache of live memory: everything served from one
 * window was read at one instant. Flush it whenever a fresh view is wanted (a
 * new sampling pass, a new object), and the reads within a pass then describe
 * one consistent moment rather than a smear across several.
 */
#ifndef LIB_RW_KREAD_H
#define LIB_RW_KREAD_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef int (*lib_kread_cb)(void *ctx, uint64_t addr, void *out, size_t len);

static inline int lib_kread64(lib_kread_cb rd, void *ctx, uint64_t addr,
			      uint64_t *out)
{
	return rd(ctx, addr, out, 8);
}

/* ── one primitive behind one interface ──────────────────────────────────── */
/*
 * Which primitive a target has is a property of the target, not of the code
 * that reads. A consumer that branches on it grows one branch per backend in
 * every function, and two targets whose observations are assembled by different
 * branches are no longer comparable -- which defeats the point of observing
 * both. So the choice is made once, in lib/rw/kreader_target.h, and everything
 * above it sees only this: a name to print, an open/close pair, and a read.
 *
 * `read` and `ctx` are the lib_kread_cb pair, usable directly and equally as
 * the underlying read of a lib_kread_window.
 */
struct lib_kreader {
	const char *name;
	int (*open)(struct lib_kreader *r);   /* 0 on success */
	void (*close)(struct lib_kreader *r);
	lib_kread_cb read;
	void *ctx;
	/* Most bytes one call may ask for. Primitives differ by an order of
	 * magnitude here -- a kprobe carries 96 words of fetch arguments, a BPF
	 * program reads one fixed span per run -- and asking for more than a
	 * primitive serves is not a short read, it is a failed one. A caller
	 * that batches (a read-ahead window) sizes itself from this rather than
	 * from a constant that happens to suit one target. */
	size_t max_read;
};

/* Most bytes a window can hold: the widest single read any primitive here
 * serves (96 words, one kprobe's fetch-argument budget). A window is sized from
 * its reader's own max_read, not from this. */
#ifndef LIB_KREAD_WINDOW_BYTES
#define LIB_KREAD_WINDOW_BYTES 768
#endif

struct lib_kread_window {
	lib_kread_cb rd;
	void *ctx;
	uint64_t base;   /* VA of buf[0]; valid only when len != 0 */
	size_t len;      /* bytes held */
	size_t span;     /* bytes fetched per miss */
	unsigned long hits, misses;
	unsigned char buf[LIB_KREAD_WINDOW_BYTES];
};

static inline void lib_kread_window_init(struct lib_kread_window *w,
					 lib_kread_cb rd, void *ctx,
					 size_t span)
{
	memset(w, 0, sizeof(*w));
	w->rd = rd;
	w->ctx = ctx;
	if (span == 0 || span > LIB_KREAD_WINDOW_BYTES)
		span = LIB_KREAD_WINDOW_BYTES;
	if (span < 8)
		span = 8;
	w->span = span & ~(size_t)7; /* whole words: a batched read's unit */
}

/* Drop the snapshot. The next read fetches a fresh window. */
static inline void lib_kread_window_flush(struct lib_kread_window *w)
{
	w->base = 0;
	w->len = 0;
}

/* A lib_kread_cb served from the window. Pass the window itself as ctx. */
static inline int lib_kread_window_cb(void *wctx, uint64_t addr, void *out,
				      size_t len)
{
	struct lib_kread_window *w = wctx;

	if (len == 0)
		return 0;
	if (w->len && addr >= w->base && addr + len <= w->base + w->len) {
		memcpy(out, w->buf + (addr - w->base), len);
		w->hits++;
		return 0;
	}
	/* A request wider than the window cannot be served from one, so it goes
	 * straight through rather than silently splitting into several reads of
	 * different instants. */
	if (len > w->span)
		return w->rd(w->ctx, addr, out, len);
	w->misses++;
	w->base = addr & ~(uint64_t)7;
	w->len = w->span;
	if (w->rd(w->ctx, w->base, w->buf, w->len) != 0) {
		/* A wide read can fail where the caller's narrow one would have
		 * succeeded -- it reaches further, and the far end may be
		 * unmapped. The window is an optimisation and must never lose a
		 * read that the primitive could serve, so fall back to asking
		 * for exactly what was wanted. */
		w->len = 0;
		return w->rd(w->ctx, addr, out, len);
	}
	if (addr + len > w->base + w->len) {
		w->len = 0;
		return w->rd(w->ctx, addr, out, len);
	}
	memcpy(out, w->buf + (addr - w->base), len);
	return 0;
}

#endif /* LIB_RW_KREAD_H */
