/* Kernel reads through the tracing interface, for an already-privileged run. */
#include "kprobe_read.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../base/clock.h"

#define KP_NAME      "libpeek"
#define KP_MAX_WORDS LIB_KPROBE_MAX_WORDS

static const char *kp_tracing_dir(void)
{
	static const char *const candidates[] = {
		"/sys/kernel/tracing", "/sys/kernel/debug/tracing",
	};

	for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
		if (access(candidates[i], R_OK | W_OK) == 0)
			return candidates[i];
	}
	return NULL;
}

static int kp_write(const char *dir, const char *rel, const char *text, int append)
{
	char path[256];
	int fd, flags = O_WRONLY | O_CLOEXEC | (append ? O_APPEND : O_TRUNC);
	ssize_t n;

	snprintf(path, sizeof(path), "%s/%s", dir, rel);
	fd = open(path, flags);
	if (fd < 0)
		return -1;
	n = write(fd, text, strlen(text));
	close(fd);
	return n == (ssize_t)strlen(text) ? 0 : -1;
}

/* Undo everything, including the pointer masking the fetch needed relaxed.
 * Called on every exit path, successful or not. */
static void kp_restore(const char *dir)
{
	char path[256];

	snprintf(path, sizeof(path), "events/kprobes/" KP_NAME "/enable");
	kp_write(dir, path, "0\n", 0);
	kp_write(dir, "tracing_on", "0\n", 0);
	kp_write(dir, "trace", "", 0);
	/* Remove this module's own probe by name. Clearing the whole file fails
	 * with EBUSY whenever any other probe is enabled, which would leave
	 * KP_NAME registered and make the next arm collide with itself. */
	kp_write(dir, "kprobe_events", "-:kprobes/" KP_NAME "\n", 1);
	{
		int fd = open("/proc/sys/kernel/kptr_restrict", O_WRONLY | O_CLOEXEC);

		if (fd >= 0) {
			ssize_t ignored = write(fd, "1\n", 2);

			(void)ignored;
			close(fd);
		}
	}
}

/* Build the probe description.
 *
 * The fetch is attached to a syscall this process is about to make, so the
 * probe fires exactly when wanted rather than whenever the kernel happens to
 * reach a busy function. `with_type` selects between the two spellings of a
 * literal fetch: kernels differ on whether a size suffix is accepted, and one
 * of the two is rejected outright rather than misread. */
static int kp_arm(const char *dir, uint64_t addr, size_t count, int with_type)
{
	/* Up to LIB_KPROBE_MAX_WORDS fetch args, each "w<i>=@0x...:x64" (~29
	 * bytes worst case) plus the fixed "p:libpeek __arm64_sys_getpid"
	 * prefix and a newline -- 3072 leaves ample headroom. */
	char spec[3072];
	size_t used;
	int fd;

	used = (size_t)snprintf(spec, sizeof(spec), "p:" KP_NAME " __arm64_sys_getpid");
	for (size_t i = 0; i < count; i++) {
		int n = snprintf(spec + used, sizeof(spec) - used, " w%zu=@0x%llx%s", i,
				 (unsigned long long)(addr + i * sizeof(uint64_t)),
				 with_type ? ":x64" : "");

		if (n < 0 || (size_t)n >= sizeof(spec) - used)
			return -1;
		used += (size_t)n;
	}
	if (used + 1 >= sizeof(spec))
		return -1;
	spec[used++] = '\n';
	spec[used] = '\0';

	fd = open("/proc/sys/kernel/kptr_restrict", O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		ssize_t ignored = write(fd, "0\n", 2);

		(void)ignored;
		close(fd);
	}
	/* Only this module's probe, so a caller that has other probes armed --
	 * a gate, a counter -- keeps them across a read. */
	kp_write(dir, "kprobe_events", "-:kprobes/" KP_NAME "\n", 1);
	return kp_write(dir, "kprobe_events", spec, 1);
}

/* Pull the fetched words out of the one record the probe produced. */
static int kp_harvest(const char *dir, uint64_t *out, size_t count)
{
	/* One record carries every fetch of the batch: ~23 bytes each after a
	 * ~75-byte header (measured: 811 bytes at 32 words, 1547 at 64). A
	 * line shorter than the widest record truncates it, and every word
	 * past the cut is missing rather than wrong, so the parse fails
	 * whole. Size it from the word ceiling, not a round number. */
	char path[256], line[128 + LIB_KPROBE_MAX_WORDS * 32];
	FILE *f;
	int found = 0;

	snprintf(path, sizeof(path), "%s/trace", dir);
	f = fopen(path, "re");
	if (!f)
		return -1;
	while (!found && fgets(line, sizeof(line), f)) {
		if (!strstr(line, " " KP_NAME ":"))
			continue;
		found = 1;
		for (size_t i = 0; i < count; i++) {
			char key[16];
			const char *at;

			snprintf(key, sizeof(key), "w%zu=", i);
			at = strstr(line, key);
			if (!at) {
				found = 0;
				break;
			}
			out[i] = (uint64_t)strtoull(at + strlen(key), NULL, 0);
		}
	}
	fclose(f);
	return found ? 0 : -1;
}

int lib_kprobe_read(uint64_t addr, uint64_t *out, size_t count)
{
	const char *dir = kp_tracing_dir();
	char enable[256];
	int armed = 0;
	int result = -1;

	if (!dir || !out || !count || count > KP_MAX_WORDS)
		return -1;

	/* Try the sized spelling first and fall back to the bare one; which is
	 * accepted is a property of the kernel, not of the address. */
	for (int with_type = 1; with_type >= 0 && !armed; with_type--)
		armed = kp_arm(dir, addr, count, with_type) == 0;
	if (!armed) {
		kp_restore(dir);
		return -1;
	}

	snprintf(enable, sizeof(enable), "events/kprobes/" KP_NAME "/enable");
	if (kp_write(dir, "trace", "", 0) || kp_write(dir, enable, "1\n", 0) ||
	    kp_write(dir, "tracing_on", "1\n", 0)) {
		kp_restore(dir);
		return -1;
	}

	/* The libc wrapper answers this from its own cache after the first real
	 * call, so the syscall is made directly or the probe never fires. */
	(void)syscall(__NR_getpid);

	result = kp_harvest(dir, out, count);
	kp_restore(dir);
	return result;
}

int lib_kprobe_read64(uint64_t addr, uint64_t *out)
{
	return lib_kprobe_read(addr, out, 1);
}

int lib_kprobe_read_retry(uint64_t addr, uint64_t *out, size_t count,
			  int tries, int64_t delay_ns)
{
	int t;

	for (t = 0; t < tries; t++) {
		if (t && delay_ns > 0)
			lib_sleep_until(lib_now_ns() + delay_ns);
		if (lib_kprobe_read(addr, out, count) == 0)
			return 0;
	}
	return -1;
}

int lib_kprobe_read_available(void)
{
	const char *dir = kp_tracing_dir();
	int ok;

	if (geteuid() != 0 || !dir)
		return 0;
	/* Arm a probe carrying no fetch, which tests exactly what a caller needs
	 * to know -- the interface is mounted, writable, and accepting probes --
	 * without needing an address that is known to be mapped. */
	kp_write(dir, "kprobe_events", "-:kprobes/" KP_NAME "\n", 1);
	ok = kp_write(dir, "kprobe_events", "p:" KP_NAME " __arm64_sys_getpid\n", 1) == 0;
	kp_restore(dir);
	return ok;
}

int lib_kprobe_session_arm(struct lib_kprobe_session *s, uint64_t addr, size_t count)
{
	const char *dir = kp_tracing_dir();
	char enable[256];
	int with_type, armed = 0;

	if (!s)
		return -1;
	s->armed = 0;
	s->count = count;
	if (!dir || !count || count > KP_MAX_WORDS)
		return -1;
	for (with_type = 1; with_type >= 0 && !armed; with_type--)
		armed = kp_arm(dir, addr, count, with_type) == 0;
	if (!armed) {
		kp_restore(dir);
		return -1;
	}
	snprintf(enable, sizeof(enable), "events/kprobes/" KP_NAME "/enable");
	if (kp_write(dir, "trace", "", 0) || kp_write(dir, enable, "1\n", 0) ||
	    kp_write(dir, "tracing_on", "1\n", 0)) {
		kp_restore(dir);
		return -1;
	}
	s->armed = 1;
	return 0;
}

int lib_kprobe_session_poll(struct lib_kprobe_session *s, uint64_t *out, size_t count)
{
	const char *dir = kp_tracing_dir();

	if (!s || !s->armed || !dir || !out || count != s->count)
		return -1;
	/* A plain ring-buffer clear -- independent of kprobe registration
	 * state, costs nothing under stop_machine -- keeps kp_harvest's
	 * first-match scan correct against this fire only, the same
	 * invariant lib_kprobe_read() itself relies on. */
	if (kp_write(dir, "trace", "", 0))
		return -1;
	(void)syscall(__NR_getpid);
	return kp_harvest(dir, out, count);
}

void lib_kprobe_session_close(struct lib_kprobe_session *s)
{
	const char *dir = kp_tracing_dir();

	if (s)
		s->armed = 0;
	if (dir)
		kp_restore(dir);
}
