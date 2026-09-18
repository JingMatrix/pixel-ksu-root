/* Reading kernel memory from a process that is already privileged.
 *
 * The tracing interface can fetch words from a literal kernel address into a
 * trace record when a probe fires. A privileged process therefore has an
 * arbitrary kernel read without any memory-corruption primitive at all: probe a
 * syscall it is about to make, ask for the words it wants, make the call, read
 * them back.
 *
 * This is an instrument, not an exploitation step. It exists so that a run which
 * has already reached root can state what is at an address as ground truth --
 * to check what an unprivileged primitive claimed, or to settle a question that
 * would otherwise need one. Nothing here escalates anything.
 *
 * Every probe is removed and the interface restored on the way out. A probe left
 * enabled changes the timing of everything that runs afterwards on that boot,
 * and timing is what most measurement here is about.
 */
#ifndef LIB_KPROBE_READ_H
#define LIB_KPROBE_READ_H

#include <stddef.h>
#include <stdint.h>

/* Read `count` 64-bit words starting at kernel address `addr`.
 *
 * Returns 0 on success, -1 otherwise. Requires root and a mounted tracing
 * interface; both are reported as failure rather than assumed. `count` is
 * bounded by how many fetch arguments one probe may carry. */
int lib_kprobe_read(uint64_t addr, uint64_t *out, size_t count);

/* One word, for the common case. Returns 0 on success. */
int lib_kprobe_read64(uint64_t addr, uint64_t *out);

/* Is the interface usable at all: privileged, mounted, and accepting probes?
 * Checked once so a caller can fail a precondition cleanly instead of
 * discovering it round by round. */
int lib_kprobe_read_available(void);

#endif /* LIB_KPROBE_READ_H */
