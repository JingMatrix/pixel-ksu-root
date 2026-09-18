/* Counting a static tracepoint through the tracing interface's own histogram
 * trigger, instead of streaming and parsing `trace_pipe`.
 *
 * A dynamic kprobe (fnprobe.h) can watch any function, but a kernel event
 * that already has a TRACE_EVENT() -- mm_page_alloc_zone_locked, say -- needs
 * no kprobe at all: it lives under events/<subsys>/<name>/ already, and a
 * `hist:key=<field>` trigger written to that event's own `trigger` file turns
 * it into a running, per-value counter the kernel maintains for you. Reading
 * that counter before and after a span of interest, and taking the
 * difference, answers "did this field take this value while I was watching"
 * exactly, with no ring buffer to drain, no wraparound to lose events to, and
 * no timestamp parsing to get wrong -- the count is authoritative for as long
 * as the trigger stays armed.
 *
 * This does not touch dynamic kprobes or `kprobe_events`; fnprobe.h and this
 * module can be armed at the same time without conflict.
 */
#ifndef LIB_EVTHIST_H
#define LIB_EVTHIST_H

/* Privileged, mounted, and does this event exist? */
int lib_evthist_available(const char *subsys, const char *event);

/* Arms a `hist:key=<key>` trigger on subsys/event and turns tracing on.
 * Returns 0, or -1 with nothing left armed. Call lib_evthist_clear() when
 * done, on every exit path -- the interface keeps counting, across process
 * exits, until told to stop. */
int lib_evthist_arm(const char *subsys, const char *event, const char *key);

/* Reads back the CURRENT cumulative hitcount for one value of the key this
 * was armed with. A key value never seen is 0, not an error -- returns 0 with
 * *out set to 0 in that case, and -1 only if the event/hist file itself could
 * not be read at all. */
int lib_evthist_read(const char *subsys, const char *event, long key_value,
                      unsigned long long *out);

/* Disables the event and removes the trigger this armed. Safe to call even
 * if arm() was never called or already failed. */
void lib_evthist_clear(const char *subsys, const char *event, const char *key);

#endif /* LIB_EVTHIST_H */
