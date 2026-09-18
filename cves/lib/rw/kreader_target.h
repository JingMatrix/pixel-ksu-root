/* lib/rw/kreader_target.h -- the kernel read this target has, as a
 * struct lib_kreader.
 *
 * This file is the ONE place that knows which primitive a target can use, and
 * it exists so that no consumer has to. A build whose target description sets
 * TARGET_KPROBE_READ_UNSAFE -- kprobe registration panics it, and it has no
 * /proc/kcore -- gets the BPF perf-event reader; every other build gets the
 * kprobe/tracefs reader. Both are fault-safe (a bad address returns an error,
 * never a fault) and neither ever writes.
 *
 * The stage manifest compiles the matching backend .c alongside: lib/rw/
 * bpf_read.c for the first, lib/rw/kprobe_read.c for the rest.
 */
#ifndef LIB_RW_KREADER_TARGET_H
#define LIB_RW_KREADER_TARGET_H

#include "kread.h"

#ifdef TARGET_KPROBE_READ_UNSAFE
#include "kreader_bpf.h"
#else
#include "kreader_kprobe.h"
#endif

static inline struct lib_kreader *lib_kreader_target(void)
{
#ifdef TARGET_KPROBE_READ_UNSAFE
	return lib_kreader_bpf();
#else
	return lib_kreader_kprobe();
#endif
}

#endif /* LIB_RW_KREADER_TARGET_H */
