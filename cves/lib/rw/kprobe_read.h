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

/* One call is one kprobe arm/enable/fire/harvest/disarm cycle -- several sysfs
 * round trips and a real kernel-side (un)registration (arch_arm_kprobe() on
 * arm64 patches text via a stop_machine_cpuslocked() rendezvous across every
 * online CPU), not a cheap operation. Reading N consecutive words with N
 * calls to lib_kprobe_read64() costs N such cycles fired back to back with
 * nothing to pace them; reading them with one lib_kprobe_read(addr, out, N)
 * call costs exactly one. Prefer the batched form whenever the addresses are
 * contiguous (an array, adjacent struct fields), both for the time and
 * because serial re-arming has been observed to be unreliable under no
 * delay, and on this project's own hardware to be able to wedge the kernel
 * outright under enough churn. 96 leaves headroom under the kernel's own
 * per-probe fetch-arg ceiling (MAX_TRACE_ARGS, kernel/trace/trace_probe.h),
 * which is 128, chosen to leave that headroom rather than batch as many
 * words per call as the kernel ceiling technically allows. */
#define LIB_KPROBE_MAX_WORDS 96

/* Read `count` 64-bit words starting at kernel address `addr`.
 *
 * Returns 0 on success, -1 otherwise. Requires root and a mounted tracing
 * interface; both are reported as failure rather than assumed. `count` must
 * not exceed LIB_KPROBE_MAX_WORDS -- how many fetch arguments one probe may
 * carry. */
int lib_kprobe_read(uint64_t addr, uint64_t *out, size_t count);

/* One word, for the common case. Returns 0 on success. */
int lib_kprobe_read64(uint64_t addr, uint64_t *out);

/* Retry a read up to `tries` times, `delay_ns` apart. Arming and disarming
 * register state with the kernel, so a call made immediately after another
 * can run ahead of that registration settling and come back short of a real
 * failure but short of the true content too -- a caller whose next step
 * depends on the answer cannot leave that ambiguous with a genuine absence.
 * Returns 0 as soon as one attempt succeeds, -1 if every one does. */
int lib_kprobe_read_retry(uint64_t addr, uint64_t *out, size_t count,
			  int tries, int64_t delay_ns);

/* Is the interface usable at all: privileged, mounted, and accepting probes?
 * Checked once so a caller can fail a precondition cleanly instead of
 * discovering it round by round. */
int lib_kprobe_read_available(void);

/* A session keeps one probe armed across many polls of the SAME address, for
 * a caller that needs to sample it repeatedly until it changes (a poll
 * loop). Re-triggering an already-armed probe is a plain breakpoint trap --
 * it does not repeat the kernel-side text patch (arm64's arch_arm_kprobe/
 * arch_disarm_kprobe both go through aarch64_insn_patch_text(), which
 * synchronises every online CPU via stop_machine_cpuslocked()) -- so a
 * session turns N arm/disarm cycles into 1, at the cost of a plain
 * trace-buffer clear per poll instead (independent of kprobe registration,
 * costs nothing under stop_machine). A poll loop built on lib_kprobe_read()
 * instead pays a full arm/disarm every tick: measured on this project's own
 * hardware to be able to freeze the kernel outright (a physical power-cycle,
 * not just a lost root) from this churn alone, no other concurrent load
 * needed. Use this for "poll the same address until X"; keep
 * lib_kprobe_read()/_retry() for one-off reads. */
struct lib_kprobe_session {
	int armed;
	size_t count;
};

/* Arm once for `count` consecutive words at `addr`. Returns 0 on success. */
int lib_kprobe_session_arm(struct lib_kprobe_session *s, uint64_t addr, size_t count);

/* Fire the already-armed probe again and read its latest words. `count` must
 * match what was passed to lib_kprobe_session_arm(). Cheap: a trace-buffer
 * clear and one syscall, no kprobe (de)registration. Returns 0 on success,
 * -1 if this particular fire did not land (retry by calling again -- still
 * far cheaper than a fresh arm). */
int lib_kprobe_session_poll(struct lib_kprobe_session *s, uint64_t *out, size_t count);

/* Disarm. Safe to call on a session that never armed successfully, and
 * leaves it disarmed either way. */
void lib_kprobe_session_close(struct lib_kprobe_session *s);

#endif /* LIB_KPROBE_READ_H */
