/* lib/root/cred_image.c -- see cred_image.h. */
#include "cred_image.h"

#include <string.h>

#include "../target.h"

#ifndef CRED_UID_OFF
#define CRED_UID_OFF        4
#endif
#ifndef CRED_ID_BLOCK_BYTES
#define CRED_ID_BLOCK_BYTES 32
#endif
#ifndef CRED_SECUREBITS_OFF
#define CRED_SECUREBITS_OFF 36
#endif
#ifndef CRED_CAPS_OFF
#define CRED_CAPS_OFF       40
#endif
#ifndef CRED_CAP_WORDS
#define CRED_CAP_WORDS      5
#endif

const struct lib_cred_field lib_cred_identity_fields[] = {
	{ CRED_UID_OFF,        CRED_ID_BLOCK_BYTES },
	{ CRED_SECUREBITS_OFF, sizeof(uint32_t) },
	{ CRED_CAPS_OFF,       CRED_CAP_WORDS * sizeof(uint64_t) },
};
const size_t lib_cred_identity_field_count =
	sizeof(lib_cred_identity_fields) / sizeof(lib_cred_identity_fields[0]);

/* Upper bound on a record read in one call. Large enough for the records this
 * serves; a caller asking for more is a mistake, not a case to handle. */
#ifndef LIB_CRED_IMAGE_MAX
#define LIB_CRED_IMAGE_MAX 512
#endif

int lib_read_stable(const struct krw *rw, kdirect_t addr, void *out,
		    size_t len, int repeats, size_t skip)
{
	unsigned char first[LIB_CRED_IMAGE_MAX];
	unsigned char again[LIB_CRED_IMAGE_MAX];

	if (len > sizeof(first) || repeats < 1 || skip > len)
		return -1;
	if (!krw_read(rw, addr, first, len))
		return -1;
	for (int i = 1; i < repeats; i++) {
		if (!krw_read(rw, addr, again, len))
			return -1;
		if (memcmp(first + skip, again + skip, len - skip))
			return -1;
	}
	memcpy(out, first, len);
	return 0;
}

int lib_cred_image_apply(const struct krw *rw, kdirect_t cred,
			 const unsigned char *image, size_t len,
			 const struct lib_cred_field *fields, size_t nfields)
{
	for (size_t i = 0; i < nfields; i++) {
		if (fields[i].offset + fields[i].length > len)
			return -1;
		if (!krw_write(rw, kd_add(cred, (int64_t)fields[i].offset),
			       image + fields[i].offset, fields[i].length))
			return -1;
	}
	return 0;
}

int lib_cred_image_verify(const struct krw *rw, kdirect_t cred,
			  const unsigned char *image, size_t len,
			  const struct lib_cred_field *fields, size_t nfields,
			  int repeats)
{
	unsigned char observed[LIB_CRED_IMAGE_MAX];

	if (len > sizeof(observed))
		return -1;
	/* The leading reference count is excluded: it changes under normal use,
	 * and requiring it to hold still would reject every read. */
	if (lib_read_stable(rw, cred, observed, len, repeats, sizeof(uint64_t)))
		return -1;
	for (size_t i = 0; i < nfields; i++) {
		if (fields[i].offset + fields[i].length > len)
			return -1;
		if (memcmp(observed + fields[i].offset, image + fields[i].offset,
			   fields[i].length))
			return -1;
	}
	return 0;
}

int lib_cred_image_commit(const struct krw *rw, kdirect_t cred,
			  const unsigned char *image, size_t len,
			  const struct lib_cred_field *fields, size_t nfields,
			  int repeats)
{
	if (lib_cred_image_apply(rw, cred, image, len, fields, nfields))
		return -1;
	if (lib_cred_image_verify(rw, cred, image, len, fields, nfields, repeats))
		return -2;
	return 0;
}
