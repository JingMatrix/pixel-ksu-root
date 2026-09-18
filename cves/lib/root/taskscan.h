/* lib/root/taskscan.h -- finding a task record by the identifier it reports.
 *
 * The kernel keeps its tasks on a circular list anchored at the first one. A
 * walk follows it, reading the identifiers and name of each record, until the
 * wanted one appears or the ring closes.
 *
 * Two rules make the walk safe on a live list. It is bounded by a node count
 * rather than by reaching the anchor, because a corrupted link would otherwise
 * mean walking forever. And every pointer read out of the list is range-checked
 * before it is followed, because a link that is not a kernel address sends the
 * walk into arbitrary memory -- and this walk exists precisely in situations
 * where the list may have been disturbed.
 *
 * Offsets come from the target description.
 */
#ifndef LIB_ROOT_TASKSCAN_H
#define LIB_ROOT_TASKSCAN_H

#include "../rw/krw.h"

#ifndef TASK_TASKS_OFF
#define TASK_TASKS_OFF 0x550
#endif
#ifndef TASK_PID_OFF
#define TASK_PID_OFF   0x630
#endif
#ifndef TASK_TGID_OFF
#define TASK_TGID_OFF  0x634
#endif
#ifndef TASK_COMM_OFF
#define TASK_COMM_OFF  0x848
#endif
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN  16
#endif

struct lib_task_match {
  uint32_t pid;
  uint32_t tgid;
  char comm[TASK_COMM_LEN + 1];
  int iters;             /* nodes walked before the match / giving up */
  uint64_t last_entry;   /* last list entry inspected */
};

/*
 * Returns the physmap alias of the matching task_struct (kd_val), or 0 if none
 * found within the 4096-node walk cap. `init_task_tasks_image` is the image VA
 * of &init_task.tasks (INIT_TASK + TASK_TASKS_OFF); `slide` must be known so the
 * slid list-head sentinel can be computed. `out` receives the match/diagnostic
 * fields when non-NULL.
 */
uint64_t lib_find_task_by_tgid(
    const struct krw *rw, const struct kslide *slide,
    uint64_t init_task_tasks_image, uint32_t want_tgid,
    struct lib_task_match *out);

#endif /* LIB_ROOT_TASKSCAN_H */
