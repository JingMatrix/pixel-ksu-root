/* lib/root/cred_image.h -- editing a credential as a whole image, reversibly.
 *
 * A credential is a small record and a chain that changes it usually wants
 * three things the field-at-a-time form does not give:
 *
 *   To decide the whole change up front. Read the record, compose the image it
 *   should have, then apply. That way the change is reviewable before anything
 *   is written, and the same image can be re-applied if a verify fails.
 *
 *   To write only what it meant to change. A record contains a reference count
 *   and pointers owned by the kernel; writing those back, even unchanged, races
 *   whoever is updating them. So an edit names the fields it touches, and the
 *   rest of the image is never written.
 *
 *   To put it back. A run that modifies a credential and then fails has left
 *   the kernel in a state nothing will repair on its own, so it keeps the
 *   original image and restores it.
 *
 * Reads that decide a write are taken more than once and compared. A live
 * credential can be caught mid-update, and a single read can return a value
 * that was never coherent; agreement across repeats is what makes the write
 * safe. Disagreement is reported rather than retried silently, because a
 * credential that will not settle is a reason to stop.
 *
 * Offsets come from the target description.
 */
#ifndef LIB_ROOT_CRED_IMAGE_H
#define LIB_ROOT_CRED_IMAGE_H

#include <stddef.h>
#include <stdint.h>

#include "../rw/krw.h"

/* One contiguous run of bytes an edit is allowed to touch. */
struct lib_cred_field {
	size_t offset;
	size_t length;
};

/* The fields an identity change writes: the eight identity words, the secure
 * bits, and the five capability sets. Everything else in the record is left
 * alone. */
extern const struct lib_cred_field lib_cred_identity_fields[];
extern const size_t lib_cred_identity_field_count;

/* Read `len` bytes at `addr` `repeats` times and return them only if every read
 * agreed. Returns 0 on agreement, -1 if a read failed or the reads disagreed.
 *
 * `skip` is a byte count at the start of the record to exclude from the
 * comparison: a record's leading reference count changes under normal use, and
 * comparing it would reject every read of a live object. */
int lib_read_stable(const struct krw *rw, kdirect_t addr, void *out,
                    size_t len, int repeats, size_t skip);

/* Write the named fields of `image` to the record at `addr`. Returns 0 on
 * success, -1 on the first failed write. */
int lib_cred_image_apply(const struct krw *rw, kdirect_t cred,
                         const unsigned char *image, size_t len,
                         const struct lib_cred_field *fields, size_t nfields);

/* Read the record back and compare the named fields against `image`. Returns 0
 * if they match, -1 if they do not or the read was not stable. */
int lib_cred_image_verify(const struct krw *rw, kdirect_t cred,
                          const unsigned char *image, size_t len,
                          const struct lib_cred_field *fields, size_t nfields,
                          int repeats);

/* Apply and verify in one step, so a caller cannot forget the second half.
 * Returns 0 on success, -1 if the write failed, -2 if it succeeded but the
 * read-back disagreed -- a distinction worth keeping, because the second case
 * means the kernel was modified and the run must not simply exit. */
int lib_cred_image_commit(const struct krw *rw, kdirect_t cred,
                          const unsigned char *image, size_t len,
                          const struct lib_cred_field *fields, size_t nfields,
                          int repeats);

#endif /* LIB_ROOT_CRED_IMAGE_H */
