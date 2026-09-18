/* Watching a kernel function from a process that is already privileged.
 *
 * The tracing interface records a line every time a named function is entered,
 * with whichever of its arguments the probe asks for. That answers the question
 * an exploit cannot answer about itself: did the path run, on which object, and
 * how far apart in time were two events that a race has to fit between.
 *
 * This is an instrument, not an exploitation step. It states what the kernel
 * did, so a measurement is read rather than inferred, and nothing here
 * escalates anything.
 *
 * A probe costs timing. Arming one changes the cost of the path it sits on, so
 * a measurement taken with probes armed describes a kernel with probes armed —
 * which is the right frame for "did this happen" and the wrong one for "how
 * often does this win". Every probe is removed and the interface restored by
 * lib_fnprobe_clear(), which belongs on every exit path.
 */
#ifndef LIB_FNPROBE_H
#define LIB_FNPROBE_H

#include <stdint.h>

/* Privileged, mounted, and accepting probes? Checked once, so a caller can
 * fail a precondition cleanly instead of discovering it probe by probe. */
/* The tracing directory this module resolved, or NULL if neither mount is
 * writable. Callers that read a control file directly use this rather than
 * guessing at the path. */
const char *lib_fnprobe_dir(void);

int lib_fnprobe_available(void);

/* Install one probe and enable it. `name` is the event name its records carry;
 * `spec` is the tracing interface's own grammar for what follows the name:
 *
 *   lib_fnprobe_arm("hre", "hidraw_report_event hid=%x0");
 *
 * Returns 0, or -1 with the interface left as it was found. */
int lib_fnprobe_arm(const char *name, const char *spec);

/* The same, on the function's RETURN rather than its entry. The distinction is
 * the difference between "the teardown started" and "the teardown finished",
 * which is the only way to say on which side of a free an event fell when the
 * freeing function does other work first. */
int lib_fnprobe_arm_return(const char *name, const char *spec);

/* Empty the buffer and begin recording; stop recording, leaving the buffer
 * readable. Both return 0 or -1. */
int lib_fnprobe_start(void);
int lib_fnprobe_stop(void);

/* Walk the records in the order the kernel wrote them, which is the order the
 * events happened in. The callback receives the event name, the record's
 * timestamp in seconds, and the whole line; returning non-zero ends the walk.
 * Returns the number of records visited, or -1. */
int lib_fnprobe_each(int (*fn)(const char *name, double ts, const char *line,
			       void *ctx), void *ctx);

/* Read one `key=value` field out of a record line, decimal or hexadecimal,
 * because the interface prints a fetched argument either way depending on the
 * type the probe declared. Returns 0 on success. */
int lib_fnprobe_field(const char *line, const char *key, unsigned long long *out);

/* Stop one probe recording, without removing it or disturbing the others. A
 * probe on a hot path drowns a reader of the live stream in records it has
 * already used; turning it off once it has served its purpose is what keeps the
 * stream's latency usable. */
/* Select the tracing clock, e.g. "mono" (CLOCK_MONOTONIC, the source
 * lib_now_ns() reads). clear() restores the default. */
int lib_fnprobe_set_clock(const char *name);

/* Nanoseconds from the timestamp of the record `at` points into, where `at` is
 * the " <name>: " that identifies it. Comparable with lib_now_ns() only when
 * the clock is "mono". Returns 0, or -1 if the record is not shaped so. */
int lib_fnprobe_record_ns(const char *at, int64_t *out);

int lib_fnprobe_disable(const char *name);

/* Open the live record stream. A read on it blocks until a record exists and
 * returns as soon as one does, which is how a process learns that a kernel
 * function ran without asking the kernel anything else -- useful when the
 * ordinary way of noticing an event travels through a lock the caller may
 * itself be holding. Returns a descriptor to read, or -1.
 *
 * The stream CONSUMES what it returns, so a caller that also wants to walk the
 * records afterwards must choose one or the other. */
int lib_fnprobe_stream(void);

/* Remove every probe and restore everything this module changed, including the
 * pointer masking a readable argument needs relaxed. */
void lib_fnprobe_clear(void);

#endif /* LIB_FNPROBE_H */
