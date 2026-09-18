/* lib/base/cycles.h -- the ARM64 counterpart of x86's RDTSC.
 *
 * SLUBStick's own published timing side channel (isec-tugraz/SLUBStick,
 * in exploits/userspace) reads the x86 cycle counter directly around each
 * probe, not wall-clock time -- a wall clock's own overhead and jitter are
 * large next to the single-digit-nanosecond differences the signal lives in.
 * `CNTVCT_EL0`, the ARM generic timer's virtual count register, is that same
 * primitive on this architecture: a monotonic counter readable from EL0 with
 * one instruction, which is what `clock_gettime()`'s own vDSO fast path reads
 * before converting it to a timespec -- so this skips exactly the conversion
 * and call overhead a probe this fine-grained cannot afford, without doing
 * anything the kernel does not already trust userspace to do.
 *
 * `CNTFRQ_EL0` gives the counter's own frequency, for a caller that wants a
 * time unit rather than a raw count; nothing here requires converting, since
 * a difference of counts is already the right unit for comparing one poll
 * against another.
 *
 * Both registers are unconditionally readable from EL0 on every Linux target
 * this tree runs on: the kernel's own timekeeping depends on it, so a target
 * where reading them faulted could not run a vDSO clock at all.
 */
#ifndef LIB_BASE_CYCLES_H
#define LIB_BASE_CYCLES_H

#include <stdint.h>

/* The `isb` first is not decoration: without it, a counter read can be
 * reordered by the CPU ahead of the code before it, which for a probe whose
 * whole point is "what ran between two reads" defeats the read. SLUBStick's
 * own RDTSC wrapper uses `cpuid` for the equivalent ordering barrier before
 * the counter read; `isb` is what does that on this architecture. */
static inline uint64_t lib_cycles(void)
{
	uint64_t v;
	__asm__ volatile("isb" ::: "memory");
	__asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
	return v;
}

/* The counter's own tick rate, in Hz -- constant for the life of the system,
 * so a caller reads it once and reuses it rather than calling this per
 * sample. */
static inline uint64_t lib_cycles_hz(void)
{
	uint64_t v;
	__asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
	return v;
}

#endif /* LIB_BASE_CYCLES_H */
