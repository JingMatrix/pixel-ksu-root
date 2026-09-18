#ifndef LIB_TIMING_H
#define LIB_TIMING_H

#include <stddef.h>   /* size_t — a device-free standard typedef, no constants */

/*
 * timing.h -- header-only cycle-timing helpers.
 *
 * rdtsc_begin() / rdtsc_end() return a monotonically-increasing cycle
 * counter suitable for fence-bracketed micro-benchmarks (e.g. cache /
 * SLUB timing side channels). The "begin" variant fences so that no
 * earlier work leaks past the read; the "end" variant fences so that no
 * later work is pulled before the read.
 *
 * Dependency-free: no libc headers, no device constants. On arm64 the
 * source is the virtual counter cntvct_el0 bracketed by isb; the counter
 * frequency (cntfrq_el0 on arm64, or the TSC rate on x86) is left to the
 * caller to read at runtime -- nothing here bakes in a CPU frequency.
 *
 * Public names rdtsc_begin / rdtsc_end are preserved for drop-in use by
 * existing exploit code.
 */

/*
 * Arch selection. Prefer explicit overrides (__ARM / __INTEL / __AMD) so a
 * caller can force AMD's APERF path; otherwise auto-detect from the
 * compiler's target macros. Every branch is #ifndef-guarded so this header
 * coexists with an exploit TU that already #defined one of these.
 */
#if !defined(__ARM) && !defined(__INTEL) && !defined(__AMD)
#  if defined(__aarch64__) || defined(__arm__)
#    define __ARM
#  elif defined(__x86_64__) || defined(__i386__)
#    define __INTEL
#  else
#    define __INTEL
#  endif
#endif

#ifndef RDPRU
#  define RDPRU ".byte 0x0f, 0x01, 0xfd"
#endif
#ifndef RDPRU_ECX_MPERF
#  define RDPRU_ECX_MPERF 0
#endif
#ifndef RDPRU_ECX_APERF
#  define RDPRU_ECX_APERF 1
#endif

static inline size_t rdtsc_begin(void)
{
#if defined(__INTEL)
    unsigned long a, d;
    asm volatile("mfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    a = (d << 32) | a;
    asm volatile("lfence");
    return a;
#elif defined(__AMD)
    unsigned long low_a, high_a;
    asm volatile("mfence");
    asm volatile(RDPRU : "=a"(low_a), "=d"(high_a) : "c"(RDPRU_ECX_APERF));
    unsigned long aval = ((low_a) | (high_a) << 32);
    asm volatile("lfence");
    return aval;
#elif defined(__ARM)
    unsigned long long vct;
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(vct));
    asm volatile("isb" ::: "memory");
    return (size_t)vct;
#else
#  error "timing.h: no arch selected (define __ARM, __INTEL, or __AMD)"
#endif
}

static inline size_t rdtsc_end(void)
{
#if defined(__INTEL)
    unsigned long a, d;
    asm volatile("lfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    a = (d << 32) | a;
    asm volatile("mfence");
    return a;
#elif defined(__AMD)
    unsigned long low_a, high_a;
    asm volatile("lfence");
    asm volatile(RDPRU : "=a"(low_a), "=d"(high_a) : "c"(RDPRU_ECX_APERF));
    unsigned long aval = ((low_a) | (high_a) << 32);
    asm volatile("mfence");
    return aval;
#elif defined(__ARM)
    unsigned long long vct;
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(vct));
    asm volatile("isb" ::: "memory");
    return (size_t)vct;
#else
#  error "timing.h: no arch selected (define __ARM, __INTEL, or __AMD)"
#endif
}

#endif /* LIB_TIMING_H */
