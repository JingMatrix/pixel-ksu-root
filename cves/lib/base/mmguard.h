/* lib/base/mmguard.h -- keeping a process usable while its own address space
 * describes something the kernel must not walk.
 *
 * A chain that corrupts the structure the kernel uses to describe its own
 * mappings gains a read primitive and loses the ability to fault. Two things go
 * wrong after that, and neither is about the corruption itself:
 *
 * A page that was resident when the structure was forged may be reclaimed
 * afterwards. Clean, file-backed pages -- the process's own code -- are the
 * first to go, and a large allocation is exactly what makes the kernel look for
 * them. Re-entering one is then a fault that cannot be resolved, which ends the
 * process at the instruction it was executing.
 *
 * And the structure is not private. Anything permitted to read this process's
 * mappings walks it, on its own schedule, in its own context. On a system where
 * a service polls every process for accounting, that walk is a matter of
 * seconds and its failure is not survivable.
 *
 * Both are answered before the corruption, not after: make the pages resident,
 * and close the mappings to everyone else. Neither call can undo a fault that
 * has already happened.
 *
 * Making the pages resident is itself an access to every one of them, and that
 * is the third thing that goes wrong. The list of mappings is a snapshot, and a
 * mapping listed in it is gone if another thread unmapped it in between -- a
 * thread that exits unmaps its own stack, so a process that has just retired a
 * pool of threads is walking a list that is still changing. The touch then
 * faults on an address that was readable when it was listed, and in a process
 * that has installed a handler to survive later faults, that handler is what
 * receives it: the walk dies at a page that was never the point. So the walk
 * guards its own accesses and skips what it cannot touch.
 *
 * Header-only, libc only, no device constant.
 */
#ifndef LIB_BASE_MMGUARD_H
#define LIB_BASE_MMGUARD_H

#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* ---- accesses that are allowed to fail ------------------------------------
 *
 * An access inside a guarded region reports a fault to its caller instead of
 * raising one, so a caller walking addresses it does not fully control can skip
 * what it cannot touch. The guard is installed for a region rather than per
 * access, because installing it costs two system calls while an access costs one
 * instruction.
 *
 * A fault that is not one of these accesses is handed to whatever handler was
 * installed before, so a process that survives faults by parking still parks.
 * One thread at a time, and no nesting: the region is described by a single
 * jump buffer.
 *
 * The handler deliberately does not ask for the alternate signal stack. It only
 * jumps, so it needs no stack of its own, and leaving that stack unentered keeps
 * it in reserve for a handler that does need it.
 */
static sigjmp_buf lib_faultskip_env;
static volatile sig_atomic_t lib_faultskip_armed;
static pid_t lib_faultskip_tid;
static struct sigaction lib_faultskip_prev_segv, lib_faultskip_prev_bus;
static int lib_faultskip_installed;

static void lib_faultskip_dispatch(int sig, siginfo_t *si, void *uc)
{
	if (lib_faultskip_armed && (long)lib_faultskip_tid == syscall(SYS_gettid)) {
		lib_faultskip_armed = 0;
		siglongjmp(lib_faultskip_env, 1);
	}
	const struct sigaction *prev = (sig == SIGBUS) ? &lib_faultskip_prev_bus
						      : &lib_faultskip_prev_segv;
	if ((prev->sa_flags & SA_SIGINFO) && prev->sa_sigaction) {
		prev->sa_sigaction(sig, si, uc);
		return;
	}
	if (!(prev->sa_flags & SA_SIGINFO) && prev->sa_handler &&
	    prev->sa_handler != SIG_DFL && prev->sa_handler != SIG_IGN) {
		prev->sa_handler(sig);
		return;
	}
	/* Nothing to hand it to. Returning would re-execute the faulting
	 * instruction for as long as the process lives, so stop here instead. */
	for (;;)
		pause();
}

/* Open and close a guarded region. Returns 0 if the guard is in place; the
 * accessors below still perform the access when it is not, unguarded. */
static inline int lib_faultskip_begin(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = lib_faultskip_dispatch;
	/* SA_ONSTACK matters even though this handler never runs on the alternate
	 * stack itself: a caller that has already forged its own address space
	 * relies on EVERY handler from that point on accepting delivery on the
	 * altstack it installed, because a fault there can be a stack-growth fault
	 * the kernel cannot service on the process's ordinary stack once find_vma
	 * fails -- and a signal the kernel cannot deliver at all kills the process
	 * outright, which is the one outcome that guarantee exists to prevent.
	 * Installing this handler without the flag breaks that guarantee for as
	 * long as this handler is the one in place, which is exactly the window a
	 * fault is most likely to land in. Requesting it here is free when no
	 * altstack is configured -- the kernel ignores the flag in that case -- so
	 * every caller gets it for nothing and the one that needs it gets what it
	 * asked for. */
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGSEGV, &sa, &lib_faultskip_prev_segv))
		return -1;
	if (sigaction(SIGBUS, &sa, &lib_faultskip_prev_bus)) {
		sigaction(SIGSEGV, &lib_faultskip_prev_segv, NULL);
		return -1;
	}
	lib_faultskip_tid = (pid_t)syscall(SYS_gettid);
	lib_faultskip_armed = 0;
	lib_faultskip_installed = 1;
	return 0;
}

static inline void lib_faultskip_end(void)
{
	if (!lib_faultskip_installed)
		return;
	lib_faultskip_armed = 0;
	lib_faultskip_installed = 0;
	sigaction(SIGSEGV, &lib_faultskip_prev_segv, NULL);
	sigaction(SIGBUS, &lib_faultskip_prev_bus, NULL);
}

/* Read one byte, for its side effect of making the page resident. 0 if the page
 * was touched, -1 if the access faulted. */
static inline int lib_touch(const void *p)
{
	if (sigsetjmp(lib_faultskip_env, 1))
		return -1;
	lib_faultskip_armed = 1;
	volatile unsigned char v = *(const volatile unsigned char *)p;
	(void)v;
	lib_faultskip_armed = 0;
	return 0;
}

/* Read eight bytes. 0 with *out set, or -1 if the access faulted. */
static inline int lib_peek64(const void *p, unsigned long long *out)
{
	if (sigsetjmp(lib_faultskip_env, 1))
		return -1;
	lib_faultskip_armed = 1;
	unsigned long long v = *(const volatile unsigned long long *)p;
	lib_faultskip_armed = 0;
	if (out)
		*out = v;
	return 0;
}

/* Touch every page of every mapping this process can already read, so none of
 * them needs a fault later.
 *
 * Locking them would be better and is usually not available: the locked-memory
 * limit on a sandboxed process is far below what it maps, and raising it needs
 * a privilege the caller does not have yet. Touching is what is left. It removes
 * the cold-page case -- the one a large allocation creates -- and does not
 * promise residency beyond that, so it belongs immediately before the step that
 * can no longer fault.
 *
 * It is not only code. A page of .bss, of the heap, or of a thread stack that
 * has never been written is just as absent, and the first store to it is the
 * same unserviceable fault. Anything the caller will touch afterwards has to be
 * touched here, which is why this walks every mapping rather than the image.
 *
 * `skip_larger_than` leaves out mappings above a size, for the caller that has
 * just populated gigabytes on purpose and does not want them walked again; 0
 * means walk everything. Write-only and special kernel mappings are skipped --
 * they either cannot be read or must not be.
 *
 * Every access is guarded, so a mapping that the snapshot lists and that is no
 * longer there costs the pages it covers and nothing more. `skipped_out`, when
 * given, receives how many pages could not be touched -- a count that is
 * normally zero and is worth reporting when it is not.
 *
 * Returns the number of pages touched, or 0 if the mappings could not be read.
 */
static inline unsigned long long lib_prefault_self_counted(
		unsigned long long skip_larger_than, unsigned long long *skipped_out)
{
	if (skipped_out)
		*skipped_out = 0;
	FILE *f = fopen("/proc/self/maps", "r");
	if (!f)
		return 0;

	static char line[512];
	unsigned long long touched = 0, skipped = 0;
	int guarded = lib_faultskip_begin() == 0;
	while (fgets(line, sizeof line, f)) {
		unsigned long long lo, hi;
		char perms[8], path[256];
		path[0] = 0;
		int n = sscanf(line, "%llx-%llx %7s %*s %*s %*s %255s",
			       &lo, &hi, perms, path);
		if (n < 3 || perms[0] != 'r')
			continue;
		/* [vvar] faults on read on some kernels, and a mapped device is not
		 * ours to fault in. Named anonymous regions ([heap], [stack], [anon:*])
		 * are exactly what we do want. */
		if (path[0] == '/' && strncmp(path, "/dev/", 5) == 0)
			continue;
		if (strcmp(path, "[vvar]") == 0 || strcmp(path, "[vsyscall]") == 0)
			continue;
		if (skip_larger_than && (hi - lo) > skip_larger_than)
			continue;
		madvise((void *)(uintptr_t)lo, (size_t)(hi - lo), MADV_WILLNEED);
		for (unsigned long long a = lo; a < hi; a += 4096) {
			if (lib_touch((const void *)(uintptr_t)a) == 0)
				touched++;
			else
				skipped++;
		}
	}
	if (guarded)
		lib_faultskip_end();
	fclose(f);
	if (skipped_out)
		*skipped_out = skipped;
	return touched;
}

static inline unsigned long long lib_prefault_self(unsigned long long skip_larger_than)
{
	return lib_prefault_self_counted(skip_larger_than, NULL);
}

/* Gate this process's /proc entries behind ptrace access, so another process
 * cannot read the mappings.
 *
 * The caller's own read is unaffected: the access check returns success for a
 * caller in the same thread group before it consults this flag at all, so a
 * chain that reads its own mappings as its primitive keeps working.
 *
 * This raises the bar rather than closing the door -- a reader holding the
 * ptrace capability still passes -- so it reduces the exposure, it does not end
 * it. Returns 0 on success, -1 with errno set.
 */
static inline int lib_hide_own_mm(void)
{
	return prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

#endif /* LIB_BASE_MMGUARD_H */
