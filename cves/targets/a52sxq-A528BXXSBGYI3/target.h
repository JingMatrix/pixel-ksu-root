/* targets/a52sxq-A528BXXSBGYI3/target.h -- committed, not resolver-composed.
 *
 * Committed because this kernel's release string is
 * 5.4.254-qgki-28575149-abA528BXXSBGYI3, whose "-abA528BXXSBGYI3" does not
 * match effective_target_header()'s "-ab(\d+)" pattern, so composition
 * would emit no kernel-image include.
 */
#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "a52sxq-A528BXXSBGYI3-app"
#else
#define BUILD_VARIANT_LABEL "a52sxq-A528BXXSBGYI3-root-umh"
#endif

#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT \
  "samsung/a52sxqeea/a52sxq:14/UP1A.231005.007/A528BXXSBGYI3:user/release-keys"
#endif

/* The kernel image these offsets describe, as its banner names it. A payload is
 * valid for an IMAGE, not for a phone, which is why the payload artifacts are
 * named per interface (artifacts/exploits/...-qgki-5.4-A528BXXSBGYI3.so) rather
 * than per device. Anything checking that a binary belongs to the kernel it is
 * about to run against compares this, not the codename in the label above. */
#ifndef TARGET_KERNEL_ID
#define TARGET_KERNEL_ID "5.4.254-qgki-28575149-abA528BXXSBGYI3"
#endif

/* KERNEL_VERSION(5,4,254) = (5<<16)|(4<<8)|254. Read at run time by
 * tcp_gate_check() (fops_tcp.c), which WARNs below 5.14 because struct
 * tcp_zerocopy_receive has no msg_control/msg_controllen there. */
#ifndef KERNEL_VERSION_CODE
#define KERNEL_VERSION_CODE 0x0504feULL
#endif

#include "../kernel/a52sxq-A528BXXSBGYI3.h"
#include "../kmi/qgki-5.4.h"

/* Registering a kprobe on this build panics the device almost instantly
 * regardless of which function is probed, commit_creds included, and there
 * is no /proc/kcore or /dev/mem. So any tool that would read kernel memory
 * here must NOT use the kprobe/tracefs path; the vehicle monitor selects its
 * /proc-only backend on this flag. */
#ifndef TARGET_KPROBE_READ_UNSAFE
#define TARGET_KPROBE_READ_UNSAFE 1
#endif

/* ROOT_METHOD_CRED_PATCH panics this device at lib_patch_cred_identity(),
 * consistent with -- not established as caused by -- Samsung KDP marking
 * cred_jar slab pages read-only (see ../kernel/a52sxq-A528BXXSBGYI3.h).
 * ROOT_UMH_SCRATCH_OFF=0x6000 is clear of the fake file_operations table,
 * and ROOT_METHOD_UMH_WORKQUEUE reaches root on this device end to end
 * (uid=0, context=u:r:kernel:s0), per the root oracle. */
#ifndef ROOT_METHOD
#define ROOT_METHOD ROOT_METHOD_UMH_WORKQUEUE
#endif
#ifndef ROOT_UMH_SCRATCH_OFF
#define ROOT_UMH_SCRATCH_OFF 0x6000
#endif

/* No DEFEX safeplace config here: su_daemon.c (defex_samsung.h) is a
 * target-independent build (runner/stages/handoff.suhelper/stage.toml,
 * uses_target_header = false) that never sees this file, so it resolves
 * its own shadow path at runtime instead. */

#endif /* OFFSET_H */
