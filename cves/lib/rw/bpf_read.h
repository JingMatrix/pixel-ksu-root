/* lib/rw/bpf_read.h -- arbitrary kernel-memory read for root, via a BPF program
 * on a perf event.
 *
 * Where the kprobe/tracefs read path is unusable -- a build that panics on
 * kprobe registration, no /proc/kcore, no /dev/mem -- a BPF program attached to
 * a software perf event reads kernel memory with bpf_probe_read(). No kernel
 * text is patched, so nothing can wedge or fault the kernel: an unreadable
 * address returns an error, never a panic. It needs root (the bpf() syscall and
 * the perf event) and CONFIG_BPF_SYSCALL.
 *
 * Mechanism: one BPF_MAP_TYPE_ARRAY holds the target address and a scratch
 * output region; the program looks the entry up, bpf_probe_read()s a fixed span
 * from the target into it, records the read's return code, and bumps a
 * sequence counter. The program runs on each tick of a PERF_COUNT_SW_CPU_CLOCK
 * event bound to the caller, so burning CPU makes it fire; the read waits for
 * the sequence to advance, so it never returns a stale span.
 *
 * Lifecycle: open() once, read()/read64() as needed, close() at the end.
 * open() returning non-zero means no reader was made (bpf/perf denied or
 * absent) and the caller should fall back.
 */
#ifndef LIB_RW_BPF_READ_H
#define LIB_RW_BPF_READ_H

#include <stddef.h>
#include <stdint.h>

/* Bytes read per program run, and the largest read this serves: one run reads
 * one fixed span, so a longer request is REFUSED (-1), never split. A caller
 * that wants more asks in pieces of its own, and owns the fact that the pieces
 * come from different instants. */
#define LIB_BPF_READ_CAP 256

struct lib_bpf_read {
  int map_fd;
  int prog_fd;
  int perf_fd;
  int running;
};

/* Set up the map, program and perf event. 0 on success; on failure the struct
 * is left closed and the caller falls back to another read path. */
int lib_bpf_read_open(struct lib_bpf_read *b);

/* Read `len` (<= LIB_BPF_READ_CAP) bytes at kernel address `kaddr` into `out`.
 * Returns the number of bytes the program reported reading (== len on success),
 * or -1 if the program did not run or the probe faulted. */
long lib_bpf_read(struct lib_bpf_read *b, uint64_t kaddr, void *out, size_t len);

/* Convenience: one 64-bit word. Returns 0 on success, -1 on failure. */
int lib_bpf_read64(struct lib_bpf_read *b, uint64_t kaddr, uint64_t *out);

void lib_bpf_read_close(struct lib_bpf_read *b);

#endif /* LIB_RW_BPF_READ_H */
