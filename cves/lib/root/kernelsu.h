/* lib/root/kernelsu.h -- is a controllable privilege daemon present?
 *
 * The daemon is reached not through a device node but through an unusual
 * argument to an ordinary system call, which the driver recognises and answers
 * with a descriptor. A second call on that descriptor reports its version and
 * two state bits: whether the requesting application is authorised, and whether
 * control is currently live.
 *
 * Both bits matter and they fail differently. Without authorisation the daemon
 * is present but will refuse; without live control it is present and authorised
 * but not yet able to act. Reporting them separately is what lets a caller tell
 * "not installed" from "installed and not ready", which need different
 * responses.
 */
#ifndef LIB_ROOT_KERNELSU_H
#define LIB_ROOT_KERNELSU_H

struct lib_ksu_info {
  unsigned int version;
  unsigned int flags;
  unsigned int features;
  unsigned int uapi_version;
};

/*
 * Returns 0 on success (a controllable KernelSU is present and prints the
 * version/flags line to stdout), 13 if the driver fd is unavailable, 14 if the
 * control check fails. The two failure values are distinct because they call
 * for different responses: no descriptor means the driver is absent, while a
 * failed check means it is present and not usable yet. `out` receives the
 * queried information on success; pass NULL to ignore it.
 */
int lib_verify_kernelsu_control(struct lib_ksu_info *out);

#endif /* LIB_ROOT_KERNELSU_H */
