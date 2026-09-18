/* lib/rw/kreader_bpf.h -- the BPF perf-event read as a struct lib_kreader.
 *
 * Selected through lib/rw/kreader_target.h; a consumer includes that, not this.
 * Build with lib/rw/bpf_read.c.
 */
#ifndef LIB_RW_KREADER_BPF_H
#define LIB_RW_KREADER_BPF_H

#include <fcntl.h>
#include <unistd.h>

#include "bpf_read.h"
#include "kread.h"

static struct lib_bpf_read lib_kreader_bpf_state;

static inline int lib_kreader_bpf_read_cb(void *ctx, uint64_t addr, void *out,
					  size_t len)
{
	struct lib_bpf_read *b = ctx;

	return lib_bpf_read(b, addr, out, len) == (long)len ? 0 : -1;
}

static inline int lib_kreader_bpf_open(struct lib_kreader *r)
{
	/* kptr_restrict has to be lowered for a kallsyms address to read as
	 * anything but zeroes, and this reader is the only reason a consumer
	 * needs that -- so it belongs to the reader, not to the consumer. */
	int fd = open("/proc/sys/kernel/kptr_restrict", O_WRONLY | O_CLOEXEC);

	if (fd >= 0) {
		ssize_t wr = write(fd, "0\n", 2);

		(void)wr;
		close(fd);
	}
	return lib_bpf_read_open((struct lib_bpf_read *)r->ctx);
}

static inline void lib_kreader_bpf_close(struct lib_kreader *r)
{
	lib_bpf_read_close((struct lib_bpf_read *)r->ctx);
}

static inline struct lib_kreader *lib_kreader_bpf(void)
{
	static struct lib_kreader r = {
		.name = "BPF perf-event",
		.open = lib_kreader_bpf_open,
		.close = lib_kreader_bpf_close,
		.read = lib_kreader_bpf_read_cb,
		.ctx = &lib_kreader_bpf_state,
		/* One program run reads one fixed span; a longer request is
		 * refused outright, not served short. */
		.max_read = LIB_BPF_READ_CAP,
	};

	return &r;
}

#endif /* LIB_RW_KREADER_BPF_H */
