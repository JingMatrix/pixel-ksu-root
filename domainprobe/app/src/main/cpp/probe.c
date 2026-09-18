/* SPDX-License-Identifier: Apache-2.0
 *
 * domainprobe — what a given Android SELinux domain can actually reach.
 *
 * The point is the DOMAIN, not the code: the same syscall that fails from
 * u:r:shell:s0 may succeed from u:r:untrusted_app:s0, and an isolated service
 * runs in u:r:isolated_app:s0 with almost nothing. Each probe runs in-process
 * so it is judged in the caller's own domain; running a pushed binary from
 * adb would answer for shell instead, which is the question we already know
 * the answer to.
 *
 * Adding a probe is one row in PROBES[]. Keep each one cheap, read-only where
 * possible, and reporting errno rather than interpreting it.
 */
/* Two builds from one source: a JNI library the app loads (so probes run in
 * u:r:untrusted_app*:s0 and, via the isolated service, u:r:isolated_app:s0),
 * and a standalone aarch64 binary the host pushes (so the same probes run in
 * u:r:shell:s0 and, under run-as, u:r:runas_app:s0). Four domains, one probe
 * table -- which is the point, since a finding is only meaningful next to the
 * domains where it differs. */
#ifdef DOMAINPROBE_MAIN
#  include <stdlib.h>
#  define LOGI(...) do { printf(__VA_ARGS__); putchar('\n'); } while (0)
#else
#  include <android/log.h>
#  include <jni.h>
#  define TAG "domainprobe"
#  define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#endif
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <grp.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <unistd.h>

/* Socket-option numbers used by the kmalloc-256 vehicle probes, defined locally
 * so we can build the request bytes by hand and dodge the <linux/in.h> vs
 * <netinet/in.h> struct clashes. */
#ifndef IP_ADD_MEMBERSHIP
#define IP_ADD_MEMBERSHIP 35
#endif
#ifndef IP_MSFILTER
#define IP_MSFILTER 41
#endif
#ifndef IPV6_HOPOPTS
#define IPV6_HOPOPTS 54
#endif
#ifndef IPV6_DSTOPTS
#define IPV6_DSTOPTS 59
#endif
#ifndef SO_ATTACH_FILTER
#define SO_ATTACH_FILTER 26
#endif

#define ASHMEM_NAME_LEN 256
#define __ASHMEMIOC     0x77
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])
#define ASHMEM_GET_NAME _IOR(__ASHMEMIOC, 2, char[ASHMEM_NAME_LEN])
#define ASHMEM_SET_SIZE _IOW(__ASHMEMIOC, 3, size_t)

/* One line per finding. res: 2 info (clickable), 1 reachable, 0 denied, -1 n/a. */
struct out { char *buf; size_t cap; size_t len; };

/* Read a text file into a bounded buffer for an INFO row's content. */
static void slurp_file(const char *path, char *out, size_t cap)
{
	out[0] = 0;
	int fd = open(path, O_RDONLY);
	if (fd < 0) return;
	size_t off = 0; ssize_t n;
	while (off + 1 < cap && (n = read(fd, out + off, cap - off - 1)) > 0) off += (size_t)n;
	out[off] = 0;
	close(fd);
}

/* raw content producer: append text straight into o->buf (no INFO framing) */
static void out_puts(struct out *o, const char *s)
{
	size_t n = strlen(s);
	if (o->len + n + 1 >= o->cap) n = o->cap - o->len - 1;
	if ((ssize_t)n > 0) { memcpy(o->buf + o->len, s, n); o->len += n; o->buf[o->len] = 0; }
}


static void emit(struct out *o, const char *name, int res, const char *fmt, ...)
{
	char detail[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(detail, sizeof(detail), fmt, ap);
	va_end(ap);
	const char *verdict = res == 2 ? "INFO     " : (res > 0 ? "REACHABLE" : (res == 0 ? "denied   " : "n/a      "));
	LOGI("%-28s %s  %s", name, verdict, detail);
	if (o->len + 1 < o->cap) {
		int n = snprintf(o->buf + o->len, o->cap - o->len,
				 "%-28s %s  %s\n", name, verdict, detail);
		if (n > 0)
			o->len += (size_t)n < o->cap - o->len ? (size_t)n : o->cap - o->len - 1;
	}
}

/* A readable text node becomes an INFO row: summary is its size, the content is
 * the file itself (capped), shown on tap. */
/* Cheap readability check -- INFO row, content read on tap via content_file(). */
static void probe_text(struct out *o, const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) { emit(o, path, 0, "errno=%d (%s)", errno, strerror(errno)); return; }
	close(fd);
	emit(o, path, 2, "readable");
}

/* /proc/slabinfo prints the cache name with %-17s, so names longer than 17
 * chars push every following column out of line. content_slabinfo() re-emits the
 * same numbers in fixed-width columns; the run only marks the row readable. */
static void content_slabinfo(struct out *o)
{
	static char tb[262144];
	int fd = open("/proc/slabinfo", O_RDONLY);
	if (fd < 0) { out_puts(o, "(slabinfo unreadable)\n"); return; }
	size_t off = 0; ssize_t n;
	while (off + 1 < sizeof(tb) && (n = read(fd, tb + off, sizeof(tb) - off - 1)) > 0) off += (size_t)n;
	tb[off] = 0; close(fd);
	char hdr[200];
	snprintf(hdr, sizeof(hdr), "%-30s %8s %8s %7s %5s %5s : tunables %5s %5s %5s : slabdata %8s %8s %8s\n",
		"# name", "active", "num", "objsize", "obj/s", "pg/s", "limit", "batch", "shared", "actv_sl", "num_sl", "avail");
	out_puts(o, hdr);
	char *line = tb, *nl;
	while ((nl = strchr(line, '\n'))) {
		*nl = 0;
		char nm[64]; unsigned long ao, no, as2, ns, sa; unsigned os, ops, pps, lim, bat, shr;
		int c = sscanf(line, "%63s %lu %lu %u %u %u : tunables %u %u %u : slabdata %lu %lu %lu",
			nm, &ao, &no, &os, &ops, &pps, &lim, &bat, &shr, &as2, &ns, &sa);
		if (c == 12) {
			char row[256];
			snprintf(row, sizeof(row), "%-30s %8lu %8lu %7u %5u %5u : tunables %5u %5u %5u : slabdata %8lu %8lu %8lu\n",
				nm, ao, no, os, ops, pps, lim, bat, shr, as2, ns, sa);
			out_puts(o, row);
		}
		line = nl + 1;
	}
}
static void probe_slabinfo(struct out *o)
{
	int fd = open("/proc/slabinfo", O_RDONLY);
	if (fd < 0) { emit(o, "/proc/slabinfo", 0, "errno=%d (%s)", errno, strerror(errno)); return; }
	close(fd);
	emit(o, "/proc/slabinfo", 2, "readable");
}
/* Generic file content producer for the readable-file INFO rows. */
static void content_file(struct out *o, const char *path)
{
	if (!strcmp(path, "/proc/slabinfo")) { content_slabinfo(o); return; }
	static char tb[262144];
	slurp_file(path, tb, sizeof(tb));
	out_puts(o, tb[0] ? tb : "(empty or unreadable)\n");
}


/* --- device nodes ------------------------------------------------------- */

static void probe_open(struct out *o, const char *path, int flags)
{
	int fd = open(path, flags);
	int e = errno;
	if (fd >= 0)
		emit(o, path, 1, "opened");
	else
		emit(o, path, 0, "errno=%d (%s)", e, strerror(e));
	if (fd >= 0)
		close(fd);
}

/* --- the ashmem question that blocks the CVE-2026-46242 reclaim ---------
 *
 * ashmem_area_cache is order-1 (objsize 312, 26 per slab) and 256 of those
 * bytes are the area name, which is why it is the widest content-controlled
 * order-1 vehicle on this device. The open question is whether the name is
 * copied as BYTES or as a C STRING: set_name() in the kernel uses
 * strncpy_from_user() + strcpy() in the implementations we have seen, which
 * would stop at the first NUL and make the name useless for carrying a kernel
 * pointer. This writes a name with an embedded NUL and reads it back to find
 * out, which is the only way to be sure on this build. */
static void probe_ashmem_name(struct out *o)
{
	char name[ASHMEM_NAME_LEN], back[ASHMEM_NAME_LEN];
	int fd = open("/dev/ashmem", O_RDWR);
	if (fd < 0) {
		emit(o, "ashmem name bytes", 0, "open errno=%d (%s)", errno, strerror(errno));
		return;
	}
	memset(name, 'A', sizeof(name));
	name[8] = '\0';                 /* the byte that decides it */
	name[9] = 'B';
	name[sizeof(name) - 1] = '\0';
	if (ioctl(fd, ASHMEM_SET_NAME, name) < 0) {
		emit(o, "ashmem name bytes", 0, "SET_NAME errno=%d (%s)", errno, strerror(errno));
		close(fd);
		return;
	}
	memset(back, 0, sizeof(back));
	if (ioctl(fd, ASHMEM_GET_NAME, back) < 0) {
		emit(o, "ashmem name bytes", 1, "SET_NAME ok, GET_NAME errno=%d", errno);
		close(fd);
		return;
	}
	/* If byte 9 survived, the copy is byte-wise and NUL is carryable. */
	emit(o, "ashmem name bytes", 1,
	     "byte[9] after NUL = 0x%02x -> %s; a kernel pointer with a zero byte is %s",
	     (unsigned char)back[9], back[9] == 'B' ? "BYTE-WISE" : "NUL-TERMINATED",
	     back[9] == 'B' ? "carryable" : "NOT carryable");
	close(fd);
}

/* --- binary-safe xattr on the app's own data dir ------------------------
 * f2fs_xattr_entry is order-1 (objsize 204) and the value is binary-safe. It is
 * NOT a reclaim vehicle: fs/f2fs/xattr.c allocates from that cache only as a
 * scratch buffer inside lookup_all_xattrs(), which frees it before returning.
 * The row stays because binary-safe user data reaching the kernel is worth
 * knowing per domain -- just do not mistake a surviving value for a surviving
 * object. */
static void probe_xattr(struct out *o, const char *dir)
{
	char path[512], val[8] = { 0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00 };
	char back[8];
	/* Always emit this row -- the isolated/zygote domains pass no writable dir,
	 * and silently skipping the row there made their probe SET one shorter than
	 * every other domain's (65 vs 66). Report the absence as its own verdict so
	 * the denominator is identical across domains. */
	if (!dir || !*dir) {
		emit(o, "xattr binary-safe", -1, "no writable dir in this domain");
		return;
	}
	snprintf(path, sizeof(path), "%s/dp_xattr_probe", dir);
	int fd = open(path, O_CREAT | O_WRONLY, 0600);
	if (fd < 0) {
		emit(o, "xattr binary-safe", 0, "create errno=%d (%s)", errno, strerror(errno));
		return;
	}
	close(fd);
	if (setxattr(path, "user.dp", val, sizeof(val), 0) < 0) {
		emit(o, "xattr binary-safe", 0, "setxattr errno=%d (%s)", errno, strerror(errno));
		unlink(path);
		return;
	}
	memset(back, 0xff, sizeof(back));
	ssize_t n = getxattr(path, "user.dp", back, sizeof(back));
	emit(o, "xattr binary-safe", 1, "len=%zd zero-bytes=%s (slab obj is transient)", n,
	     (n == (ssize_t)sizeof(val) && !memcmp(back, val, sizeof(val))) ? "YES" : "no");
	unlink(path);
}

/* --- socket families ----------------------------------------------------
 *
 * The sharpest part of the domain delta: sepolicy hands out socket CREATE per
 * class, so which netlink protocol families (and AF_PACKET, PF_KEY) a domain
 * may open separates shell/app (almost none) from system_server/network_stack
 * (all of them). The create check fires on socket() alone, so opening one and
 * closing it is the whole test -- no bind, no traffic. */
static void probe_socket(struct out *o, const char *name, int domain, int type, int protocol)
{
	int fd = socket(domain, type, protocol);
	int e = errno;
	if (fd >= 0) {
		emit(o, name, 1, "created");
		close(fd);
	} else {
		emit(o, name, e == EACCES ? 0 : -1, "errno=%d (%s)", e, strerror(e));
	}
}

/* Syscalls are probed in a forked child.
 *
 * The app domain runs under a seccomp filter, and a syscall outside its
 * allowlist does not return an errno -- the kernel raises SIGSYS and the
 * process dies. add_key does exactly that here. A probe harness that calls it
 * inline takes the whole app down and loses every result after it, so the call
 * is isolated: the child reports rc/errno through a pipe, and if it never
 * reports, the parent recovers the signal from waitpid and says so. That is
 * itself the answer -- "killed by SIGSYS" means blocked by seccomp, which is a
 * different and stronger denial than EACCES from SELinux. */
/* Async-signal-safe: exit with a marker the parent reads as "seccomp-blocked",
 * without invoking the default (tombstone-writing) SIGSYS disposition. */
static void sigsys_exit(int sig) { (void)sig; _exit(97); }

static void probe_syscall(struct out *o, const char *name, long nr,
			  long a0, long a1, long a2, long a3, long a4, long a5)
{
	int pfd[2];
	if (pipe(pfd) < 0) {
		emit(o, name, -1, "pipe failed");
		return;
	}
	pid_t pid = fork();
	if (pid < 0) {
		emit(o, name, -1, "fork failed");
		close(pfd[0]); close(pfd[1]);
		return;
	}
	if (pid == 0) {
		close(pfd[0]);
		/* Catch the seccomp SIGSYS ourselves and exit with a marker, so a
		 * blocked syscall does NOT raise the default debuggerd handler -- that
		 * would write a tombstone which ActivityManager attributes to the app
		 * and, across every domain's probes, eventually kills it. */
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = sigsys_exit;
		sigemptyset(&sa.sa_mask);
		sigaction(SIGSYS, &sa, NULL);
		long r = syscall(nr, a0, a1, a2, a3, a4, a5);
		long rep[2] = { r, r < 0 ? errno : 0 };
		write(pfd[1], rep, sizeof(rep));
		_exit(0);
	}
	close(pfd[1]);
	long rep[2] = { 0, 0 };
	ssize_t got = read(pfd[0], rep, sizeof(rep));
	close(pfd[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	if (got != (ssize_t)sizeof(rep)) {
		if (WIFEXITED(status) && WEXITSTATUS(status) == 97)
			emit(o, name, 0, "SIGSYS: blocked by seccomp");
		else if (WIFSIGNALED(status))
			emit(o, name, 0, "killed by signal %d (%s)", WTERMSIG(status),
			     WTERMSIG(status) == SIGSYS ? "SIGSYS: blocked by seccomp" : "died");
		else
			emit(o, name, -1, "no result from child");
		return;
	}
	if (rep[0] >= 0)
		emit(o, name, 1, "ok rc=%ld", rep[0]);
	else
		emit(o, name, 0, "errno=%ld (%s)", rep[1], strerror((int)rep[1]));
}

/* --- SELinux policy, queried directly ------------------------------------
 *
 * The DirtySepolicy technique (LSPosed/DirtySepolicy): selinuxfs answers policy
 * questions without root, so a domain that can open these nodes can read the
 * loaded policy rather than infer it from what syscalls succeed. Two things are
 * worth asking:
 *
 *   - can this domain reach the interfaces at all (access/create/context)?
 *   - does a context validate?  /sys/fs/selinux/context canonicalises a context
 *     string and rejects one whose type is not in the loaded policy, so writing
 *     a candidate context tells you whether that type EXISTS -- which is how a
 *     userspace root solution that patched sepolicy (adding an su/magisk type)
 *     is detected from an unprivileged domain.
 */
static int read_small_int(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	char b[32] = {0};
	ssize_t n = read(fd, b, sizeof(b) - 1);
	close(fd);
	return n > 0 ? atoi(b) : -1;
}

/* security_compute_av over /sys/fs/selinux/access: ask the loaded policy whether
 * (scon, tcon, class, perm) is allowed, without performing the operation. The
 * answer is a property of the policy, the same from any caller; the interface
 * itself is reachable only from domains sepolicy grants security:compute_av, so
 * the row doubles as a reachability test (denied from untrusted_app) and a
 * policy read (allow/deny) where it is reachable. */
static void probe_selinux_av(struct out *o, const char *name, const char *scon,
			     const char *tcon, const char *cls, const char *perm)
{
	char path[256];
	snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/index", cls);
	int ci = read_small_int(path);
	snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/perms/%s", cls, perm);
	int pb = read_small_int(path);
	if (ci < 0 || pb < 0) { emit(o, name, -1, "selinuxfs class table unreadable"); return; }
	unsigned av = 1u << (pb - 1);
	int fd = open("/sys/fs/selinux/access", O_RDWR);
	if (fd < 0) { emit(o, name, -1, "compute_av denied errno=%d (%s)", errno, strerror(errno)); return; }
	char q[300];
	int ql = snprintf(q, sizeof(q), "%s %s %u %x", scon, tcon, (unsigned)ci, av);
	if (write(fd, q, ql) < 0) { int e = errno; close(fd); emit(o, name, -1, "write errno=%d (%s)", e, strerror(e)); return; }
	char r[256] = {0};
	lseek(fd, 0, SEEK_SET);
	ssize_t n = read(fd, r, sizeof(r) - 1);
	close(fd);
	if (n <= 0) { emit(o, name, -1, "no av reply"); return; }
	unsigned allowed = 0;
	sscanf(r, "%x", &allowed);
	int ok = (allowed & av) != 0;
	emit(o, name, ok ? 1 : 0, ok ? "allow" : "deny");
}

static void probe_selinux_validate(struct out *o, const char *name, const char *ctx)
{
	int fd = open("/sys/fs/selinux/context", O_RDWR);
	if (fd < 0) {
		emit(o, name, -1, "selinuxfs errno=%d (%s)", errno, strerror(errno));
		return;
	}
	ssize_t w = write(fd, ctx, strlen(ctx) + 1);
	int e = errno;
	close(fd);
	if (w >= 0)
		emit(o, name, 1, "context valid");
	else
		emit(o, name, 0, "errno=%d (%s)", e, strerror(e));
}

/* --- mount namespace --------------------------------------------------
 *
 * What effectively separates a classic isolated_app from a native-zygote
 * (zygote_next) process: the classic one is forked into the app's mount
 * namespace, the native one into init's global namespace, where the whole
 * system's mounts -- and any a root module added -- are visible. The namespace
 * id and the number of mount entries make that difference legible per domain. */
/* FNV-1a over a canonicalised mountinfo view, so peers whose mount tree is the
 * same collapse to one entry. */
static unsigned long long fnv1a(const char *s)
{
	unsigned long long h = 1469598103934665603ULL;
	for (; *s; s++) { h ^= (unsigned char)*s; h *= 1099511628211ULL; }
	return h;
}

#define DP_MAXP 6000
#define DP_MAXV 256           /* distinct mount views tracked */
#define DP_MAXMNT 1024        /* mounts per view carried for the diff */
#define DP_DIFFMAX 80         /* diff lines printed per non-base view */
#define DP_REFS 3             /* views a diff may be taken against */
#define DP_PVBUDGET (1 << 20) /* cap on emitted peer-view detail bytes */

/* --- on-demand content for the mount/proc INFO rows ---------------------
 * These do the expensive reads; the probe run only emits cheap summaries and
 * the app calls one of these (probe_content) when an INFO row is tapped. */
static void content_mountns(struct out *o)
{
	static char mi[262144];
	slurp_file("/proc/self/mountinfo", mi, sizeof(mi));
	out_puts(o, mi[0] ? mi : "(mountinfo empty or unreadable)\n");
}

/* One row per visible process, shared by the pid table and the peer-mount
 * views (never both at once, so one table serves).
 *
 * NAME is the FULL process name: /proc/<pid>/comm is capped at 15 characters,
 * which turns com.google.android.gms.persistent into "id.gms.persist" and makes
 * the peer lists unreadable. argv[0] from /proc/<pid>/cmdline carries the whole
 * name -- app processes rename theirs to the package/process name, native ones
 * keep their path -- so that is the name, and comm is only the fallback.
 *
 * comm is the fallback, printed in [brackets] so a 15-character stem is never
 * mistaken for a full name: it is all there is when cmdline is empty (kernel
 * threads, zombies) or unreadable (no AID_READPROC for that pid). cmdline is not
 * infallible either -- an app process taken from the zygote's USAP pool can be
 * left with the pooled process's argv, cut to the length of its new name -- but
 * comm is no better a witness there (it is a thread name, renamed at will), so
 * the full name wins and the odd stale one is worth more than a truncated stem. */
struct proctab {
	int n;
	int pid[DP_MAXP];
	int uid[DP_MAXP];
	char name[DP_MAXP][96];
	char ctx[DP_MAXP][96];
};
static struct proctab g_pt;

/* argv[0] from /proc/<pid>/cmdline. Returns 0 when there is nothing to read. */
static int proc_cmdname(int pid, char *out, size_t cap)
{
	char path[64], b[256];
	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
	int fd = open(path, O_RDONLY);
	if (fd < 0) return 0;
	/* procfs hands cmdline over in short reads (it copies out of the target's
	 * mm page by page), so a single read() can cut a name mid-way -- loop. */
	ssize_t n, off = 0;
	while (off < (ssize_t)sizeof(b) - 1 && (n = read(fd, b + off, sizeof(b) - 1 - off)) > 0) off += n;
	close(fd);
	if (off <= 0) return 0;
	b[off] = 0;
	/* argv[0] ends at the first NUL -- except where a process rewrote its whole
	 * command line into one space-joined string (Chromium-style zygotes), so stop
	 * at whitespace too and keep the name rather than the arguments. */
	size_t l = strcspn(b, " \t\n");
	if (!l) return 0;
	if (l >= cap) l = cap - 1;
	memcpy(out, b, l);
	out[l] = 0;
	return 1;
}

/* Enumerate /proc into g_pt (pid/uid/name/context). Returns the count. */
static int enum_pids(void)
{
	DIR *d = opendir("/proc");
	g_pt.n = 0;
	if (!d) return -1;
	struct dirent *e;
	while ((e = readdir(d)) && g_pt.n < DP_MAXP) {
		if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
		int i = g_pt.n, pid = atoi(e->d_name);
		char path[80]; struct stat st;
		g_pt.pid[i] = pid;
		snprintf(path, sizeof(path), "/proc/%d", pid);
		g_pt.uid[i] = stat(path, &st) == 0 ? (int)st.st_uid : -1;
		if (!proc_cmdname(pid, g_pt.name[i], sizeof(g_pt.name[i]))) {
			char comm[32] = "";
			snprintf(path, sizeof(path), "/proc/%d/comm", pid);
			int cf = open(path, O_RDONLY);
			if (cf >= 0) { ssize_t cn = read(cf, comm, sizeof(comm) - 1); close(cf);
				if (cn > 0) { comm[cn] = 0; char *nl = strchr(comm, '\n'); if (nl) *nl = 0; } }
			snprintf(g_pt.name[i], sizeof(g_pt.name[i]), "[%s]", comm[0] ? comm : "?");
		}
		char pctx[96] = "-";
		snprintf(path, sizeof(path), "/proc/%d/attr/current", pid);
		int af = open(path, O_RDONLY);
		if (af >= 0) { ssize_t an = read(af, pctx, sizeof(pctx) - 1); close(af);
			if (an > 0) { pctx[an] = 0; char *z = strchr(pctx, '\n'); if (z) *z = 0; } }
		snprintf(g_pt.ctx[i], sizeof(g_pt.ctx[i]), "%s", pctx);
		g_pt.n++;
	}
	closedir(d);
	return g_pt.n;
}

static void content_procpids(struct out *o)
{
	if (enum_pids() < 0) { out_puts(o, "(cannot open /proc)\n"); return; }
	int wc = 4, wu = 3;
	for (int i = 0; i < g_pt.n; i++) {
		int lc = (int)strlen(g_pt.name[i]); if (lc > wc && lc <= 64) wc = lc;
		char ub[16]; int lu = snprintf(ub, sizeof(ub), "%d", g_pt.uid[i]); if (lu > wu) wu = lu;
	}
	static char row[512];
	out_puts(o, "# NAME is argv[0] from /proc/<pid>/cmdline, the full process name; [brackets]\n"
		    "# mark a fallback to the 15-character comm, all there is when cmdline is empty\n"
		    "# (kernel threads, zombies) or unreadable (no AID_READPROC for that pid).\n");
	snprintf(row, sizeof(row), "%-6s %-*s %-*s %s\n", "PID", wu, "UID", wc, "NAME", "CONTEXT");
	out_puts(o, row);
	for (int i = 0; i < g_pt.n; i++) {
		snprintf(row, sizeof(row), "%-6d %-*d %-*s %s\n", g_pt.pid[i], wu, g_pt.uid[i], wc, g_pt.name[i], g_pt.ctx[i]);
		out_puts(o, row);
	}
}

/* --- mountinfo, canonicalised -------------------------------------------
 * A mountinfo line is
 *   id parent maj:min root mountpoint opts [propagation...] - fstype src sopts
 * where id, parent and the propagation ids are per-namespace counters: two
 * processes with an identical mount tree disagree on every one of them. Keeping
 * them means every peer looks distinct, which from root (where all ~1000 peers
 * are readable) produced megabytes of near-identical text. Drop the ids, keep
 * the propagation TYPE (shared/master/... is a real property), and what is left
 * is the mount itself -- so identical views group, and the ones that differ can
 * be shown as a diff instead of another whole tree. */
static int canon_line(char *line, char *out, size_t cap)
{
	char *save = NULL, *f[6], *t, prop[64];
	size_t pl = 0;
	for (int i = 0; i < 6; i++) {
		f[i] = strtok_r(i ? NULL : line, " ", &save);
		if (!f[i]) return 0;
	}
	prop[0] = 0;
	while ((t = strtok_r(NULL, " ", &save)) && strcmp(t, "-")) {
		char *c = strchr(t, ':');
		if (c) *c = 0;                          /* shared:34 -> shared */
		int n = snprintf(prop + pl, sizeof(prop) - pl, "%s%s", pl ? "," : "", t);
		if (n > 0 && pl + (size_t)n < sizeof(prop)) pl += (size_t)n; else break;
	}
	if (!t) return 0;                               /* no "-" separator: not mountinfo */
	char *fstype = strtok_r(NULL, " ", &save);
	char *src = strtok_r(NULL, " ", &save);
	char *sopts = strtok_r(NULL, " ", &save);
	snprintf(out, cap, "%s %s %s %s %s %s %s", f[4], f[3], f[2], f[5],
		 pl ? prop : "-", fstype ? fstype : "-", src ? src : "-");
	if (sopts) {
		size_t l = strlen(out);
		snprintf(out + l, cap - l, " %s", sopts);
	}
	return 1;
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Canonicalise a whole mountinfo blob, sorted. Sorted because mountinfo is in
 * mount order, which is a namespace's history rather than its contents: two
 * processes that mounted the same things in a different order would otherwise be
 * two views whose diff is empty. It also reads better -- the tree comes out by
 * mountpoint. Returns the mount count. */
static int canon_view(const char *raw, char *out, size_t cap)
{
	static char scratch[262144];
	static char *lp[DP_MAXMNT];
	char line[1024], c[1024];
	size_t sl = 0, ol = 0;
	int n = 0;
	out[0] = 0;
	for (const char *p = raw; *p && n < DP_MAXMNT; ) {
		const char *nl = strchr(p, '\n');
		size_t len = nl ? (size_t)(nl - p) : strlen(p);
		if (len && len < sizeof(line)) {
			memcpy(line, p, len); line[len] = 0;
			if (canon_line(line, c, sizeof(c))) {
				size_t cl = strlen(c);
				if (sl + cl + 1 < sizeof(scratch)) {
					memcpy(scratch + sl, c, cl + 1);
					lp[n++] = scratch + sl;
					sl += cl + 1;
				}
			}
		}
		if (!nl) break;
		p = nl + 1;
	}
	qsort(lp, n, sizeof(lp[0]), cmp_str);
	for (int i = 0; i < n; i++) {
		size_t cl = strlen(lp[i]);
		if (ol + cl + 2 >= cap) { n = i; break; }
		memcpy(out + ol, lp[i], cl); ol += cl;
		out[ol++] = '\n'; out[ol] = 0;
	}
	return n;
}

static const char *CANON_FIELDS[8] = {
	"mountpoint", "root", "dev", "opts", "propagation", "fstype", "source", "superopts"
};

/* Hash of the first three canonical fields (mountpoint root dev): the mount's
 * identity. A mount whose options or propagation changed is then recognised as
 * the SAME mount changed, not one removed and one added -- which matters because
 * a namespace that only turned its mounts from shared to slave otherwise reads
 * as sharing nothing with the base view. */
static unsigned long long ident_hash(const char *line)
{
	unsigned long long h = 1469598103934665603ULL;
	int sp = 0;
	for (const char *p = line; *p; p++) {
		if (*p == ' ' && ++sp == 3) break;
		h ^= (unsigned char)*p; h *= 1099511628211ULL;
	}
	return h;
}

/* Split a blob into lines in place, hashing each line whole and by identity
 * (the diff compares hashes, so a view costs one integer compare per line). */
static int split_lines(char *buf, char **lines, unsigned long long *hash,
		       unsigned long long *ident, int max)
{
	int n = 0;
	for (char *p = buf; *p && n < max; ) {
		char *nl = strchr(p, '\n');
		if (nl) *nl = 0;
		if (*p) { lines[n] = p; hash[n] = fnv1a(p); ident[n] = ident_hash(p); n++; }
		if (!nl) break;
		p = nl + 1;
	}
	return n;
}

/* Index of x in h, or -1. */
static int find_hash(const unsigned long long *h, int n, unsigned long long x)
{
	for (int i = 0; i < n; i++) if (h[i] == x) return i;
	return -1;
}

static int canon_fields(char *buf, char *f[8])
{
	char *save = NULL;
	int n = 0;
	for (; n < 8; n++) { f[n] = strtok_r(n ? NULL : buf, " ", &save); if (!f[n]) break; }
	for (int i = n; i < 8; i++) f[i] = "-";
	return n;
}

/* "~ /mountpoint  propagation: shared -> master" -- only the fields that moved. */
static void emit_change(struct out *o, const char *was, const char *now)
{
	char wb[1024], nb[1024], row[1400];
	char *wf[8], *nf[8];
	snprintf(wb, sizeof(wb), "%s", was);
	snprintf(nb, sizeof(nb), "%s", now);
	canon_fields(wb, wf);
	canon_fields(nb, nf);
	int rl = snprintf(row, sizeof(row), "~ %s", nf[0]);
	for (int i = 1; i < 8 && rl > 0 && rl < (int)sizeof(row); i++) {
		if (!strcmp(wf[i], nf[i])) continue;
		int n = snprintf(row + rl, sizeof(row) - rl, "  %s: %s -> %s", CANON_FIELDS[i], wf[i], nf[i]);
		if (n < 0 || rl + n >= (int)sizeof(row)) break;
		rl += n;
	}
	out_puts(o, row);
	out_puts(o, "\n");
}

/* The peer mount views: who shares each one, and how each differs from the one
 * most processes are in. The full tree is printed once (for the majority view);
 * every other view is its diff against that, which is the part that says
 * something -- and keeps this row a few KB instead of the multi-MB dump that
 * made it unusable from root. */
static void content_peermnt(struct out *o)
{
	static char raw[262144], base[262144], vcanon[262144];
	static char refbuf[DP_REFS][262144];
	static char *refl[DP_REFS][DP_MAXMNT], *vl[DP_MAXMNT];
	static unsigned long long refh[DP_REFS][DP_MAXMNT], refi[DP_REFS][DP_MAXMNT];
	static unsigned long long vh[DP_MAXMNT], vi[DP_MAXMNT];
	static int nref[DP_REFS], refview[DP_REFS];
	static unsigned long long vfp[DP_MAXV];
	static int vrep[DP_MAXV], vcount[DP_MAXV], vmnt[DP_MAXV], vhead[DP_MAXV];
	static int vplus[DP_MAXV], vminus[DP_MAXV], vchg[DP_MAXV], vref[DP_MAXV], order[DP_MAXV];
	static char vwho[DP_MAXV][192];
	static int pnext[DP_MAXP];
	static char det_buf[DP_PVBUDGET];
	char pp[64], hdr[512];

	if (enum_pids() < 0) { out_puts(o, "(cannot open /proc)\n"); return; }
	int me = getpid(), npeer = 0, nv = 0, capped = 0;

	for (int i = 0; i < g_pt.n; i++) {
		if (g_pt.pid[i] == me) continue;
		snprintf(pp, sizeof(pp), "/proc/%d/mountinfo", g_pt.pid[i]);
		int fd = open(pp, O_RDONLY);
		if (fd < 0) continue;
		close(fd);
		npeer++;
		slurp_file(pp, raw, sizeof(raw));
		if (!raw[0]) continue;                  /* readable but empty (kernel thread) */
		int mounts = canon_view(raw, vcanon, sizeof(vcanon));
		unsigned long long h = fnv1a(vcanon);
		int v = -1;
		for (int k = 0; k < nv; k++) if (vfp[k] == h) { v = k; break; }
		if (v < 0) {
			if (nv >= DP_MAXV) { capped++; continue; }
			v = nv++;
			vfp[v] = h; vrep[v] = g_pt.pid[i]; vcount[v] = 0;
			vmnt[v] = mounts; vhead[v] = -1; vplus[v] = vminus[v] = vchg[v] = 0;
		}
		vcount[v]++;
		pnext[i] = vhead[v]; vhead[v] = i;
	}
	if (npeer == 0) { out_puts(o, "(no peer mountinfo readable from this domain)\n"); return; }
	if (nv == 0) { out_puts(o, "(peer mountinfo readable but empty from this domain)\n"); return; }

	/* most-shared view first: it is the base, printed in full */
	for (int i = 0; i < nv; i++) order[i] = i;
	for (int i = 0; i < nv; i++)
		for (int k = i + 1; k < nv; k++)
			if (vcount[order[k]] > vcount[order[i]]) { int t = order[i]; order[i] = order[k]; order[k] = t; }

	for (int v = 0; v < nv; v++) {
		size_t wl = 0; int shown = 0;
		vwho[v][0] = 0;
		for (int i = vhead[v]; i >= 0 && shown < 5; i = pnext[i]) {
			int n = snprintf(vwho[v] + wl, sizeof(vwho[v]) - wl, "%s%d:%s",
					 wl ? " " : "", g_pt.pid[i], g_pt.name[i]);
			if (n < 0 || wl + (size_t)n >= sizeof(vwho[v])) { vwho[v][wl] = 0; break; }
			wl += (size_t)n; shown++;
		}
		if (vcount[v] > shown && wl + 20 < sizeof(vwho[v]))
			snprintf(vwho[v] + wl, sizeof(vwho[v]) - wl, " +%d more", vcount[v] - shown);
	}

	/* Reference views: the few most-shared ones. Every other view is diffed
	 * against whichever of them it is closest to, not always against view 1 --
	 * on a rooted device view 1 is init's tree and every app namespace differs
	 * from it in the same ~100 lines, which is that same diff repeated a hundred
	 * times. Against the app-namespace reference the same view is a handful of
	 * lines, which is what the row is for. */
	int nrefs = nv < DP_REFS ? nv : DP_REFS;
	for (int r = 0; r < nrefs; r++) {
		refview[r] = order[r];
		snprintf(pp, sizeof(pp), "/proc/%d/mountinfo", vrep[order[r]]);
		slurp_file(pp, raw, sizeof(raw));
		canon_view(raw, refbuf[r], sizeof(refbuf[r]));
		if (r == 0) snprintf(base, sizeof(base), "%s", refbuf[0]);   /* kept intact to print */
		nref[r] = split_lines(refbuf[r], refl[r], refh[r], refi[r], DP_MAXMNT);
	}

	/* per-view detail, built aside so the index table can carry its diff counts */
	struct out det = { det_buf, sizeof(det_buf), 0 };
	det_buf[0] = 0;
	for (int oi = 0; oi < nv; oi++) {
		int v = order[oi];
		vref[v] = 0;
		if (oi == 0) {
			snprintf(hdr, sizeof(hdr), "\n===== view 1/%d · %d pid%s · %d mounts · base, shown in full =====\n  %s\n\n",
				 nv, vcount[v], vcount[v] == 1 ? "" : "s", vmnt[v], vwho[v]);
			out_puts(&det, hdr);
			out_puts(&det, base);
			continue;
		}
		snprintf(pp, sizeof(pp), "/proc/%d/mountinfo", vrep[v]);
		slurp_file(pp, raw, sizeof(raw));
		canon_view(raw, vcanon, sizeof(vcanon));
		int nvl = split_lines(vcanon, vl, vh, vi, DP_MAXMNT);   /* split in place */
		int best = -1, bestcost = 0;
		for (int r = 0; r < nrefs; r++) {
			if (refview[r] == v) continue;
			int a = 0, m = 0, c = 0;
			for (int i = 0; i < nvl; i++) {
				int j = find_hash(refi[r], nref[r], vi[i]);
				if (j < 0) a++;
				else if (refh[r][j] != vh[i]) c++;
			}
			for (int i = 0; i < nref[r]; i++) if (find_hash(vi, nvl, refi[r][i]) < 0) m++;
			if (best < 0 || a + m + c < bestcost) {
				best = r; bestcost = a + m + c;
				vplus[v] = a; vminus[v] = m; vchg[v] = c;
			}
		}
		if (best < 0) continue;                 /* cannot happen: nv > 1 here */
		vref[v] = best;
		int rp = 0;                             /* reference's position in the table */
		for (int i = 0; i < nv; i++) if (order[i] == refview[best]) { rp = i + 1; break; }
		snprintf(hdr, sizeof(hdr), "\n===== view %d/%d · %d pid%s · %d mounts · +%d/-%d/~%d vs view %d =====\n  %s\n",
			 oi + 1, nv, vcount[v], vcount[v] == 1 ? "" : "s", vmnt[v],
			 vplus[v], vminus[v], vchg[v], rp, vwho[v]);
		out_puts(&det, hdr);
		int printed = 0;
		for (int i = 0; i < nvl && printed < DP_DIFFMAX; i++) {
			int j = find_hash(refi[best], nref[best], vi[i]);
			if (j < 0) { out_puts(&det, "+ "); out_puts(&det, vl[i]); out_puts(&det, "\n"); printed++; }
			else if (refh[best][j] != vh[i]) { emit_change(&det, refl[best][j], vl[i]); printed++; }
		}
		for (int i = 0; i < nref[best] && printed < DP_DIFFMAX; i++)
			if (find_hash(vi, nvl, refi[best][i]) < 0) { out_puts(&det, "- "); out_puts(&det, refl[best][i]); out_puts(&det, "\n"); printed++; }
		int total = vplus[v] + vminus[v] + vchg[v];
		if (total > printed) {
			snprintf(hdr, sizeof(hdr), "  (%d more differing mount%s)\n",
				 total - printed, total - printed == 1 ? "" : "s");
			out_puts(&det, hdr);
		}
	}

	snprintf(hdr, sizeof(hdr),
		 "READABLE PEER MOUNT VIEWS\n%d peer%s readable · %d distinct view%s%s\n"
		 "grouped on the mount tree itself: per-namespace mount/parent/propagation\n"
		 "ids are dropped, so views that differ only in numbering are one view.\n"
		 "fields: mountpoint root dev opts propagation fstype source superopts\n"
		 "diff: +added / -removed / ~changed mounts, against the listed nearest view\n\n"
		 "%5s %6s %7s %18s  %s\n",
		 npeer, npeer == 1 ? "" : "s", nv, nv == 1 ? "" : "s",
		 capped ? " (view table full, some peers ungrouped)" : "",
		 "view", "pids", "mounts", "diff", "processes");
	out_puts(o, hdr);
	for (int oi = 0; oi < nv; oi++) {
		int v = order[oi];
		char d[32];
		if (oi == 0) {
			snprintf(d, sizeof(d), "base");
		} else {
			int rp = 0;
			for (int i = 0; i < nv; i++) if (order[i] == refview[vref[v]]) { rp = i + 1; break; }
			snprintf(d, sizeof(d), "+%d/-%d/~%d vs %d", vplus[v], vminus[v], vchg[v], rp);
		}
		snprintf(hdr, sizeof(hdr), "%5d %6d %7d %18s  %s\n", oi + 1, vcount[v], vmnt[v], d, vwho[v]);
		out_puts(o, hdr);
	}
	out_puts(o, det_buf);
	if (det.len + 1 >= det.cap) out_puts(o, "\n(detail truncated -- content budget reached)\n");
}

/* Cheap mount/proc summaries -- no heavy reads. Content for the INFO rows is
 * produced only on tap, by probe_content(). */
static void probe_mounts(struct out *o)
{
	char link[64] = {0};
	ssize_t n = readlink("/proc/self/ns/mnt", link, sizeof(link) - 1);
	if (n > 0) { link[n] = 0; emit(o, "mount namespace", 2, "%s", link); }
	else emit(o, "mount namespace", -1, "readlink errno=%d (%s)", errno, strerror(errno));

	DIR *d = opendir("/proc");
	if (!d) { emit(o, "proc visible pids", -1, "opendir errno=%d (%s)", errno, strerror(errno)); return; }
	int pids = 0, peers = 0, me = getpid();
	struct dirent *e;
	while ((e = readdir(d))) {
		if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
		int pid = atoi(e->d_name); pids++;
		if (pid == me) continue;
		char pp[64]; snprintf(pp, sizeof(pp), "/proc/%d/mountinfo", pid);
		int fd = open(pp, O_RDONLY);        /* readable? -- open/close only, no read */
		if (fd >= 0) { peers++; close(fd); }
	}
	closedir(d);
	{ char s[48]; snprintf(s, sizeof(s), "%d pids", pids); emit(o, "proc visible pids", 2, "%s", s); }
	if (peers > 0) { char s[48]; snprintf(s, sizeof(s), "%d peers", peers); emit(o, "peer mountinfo readable", 2, "%s", s); }
	else emit(o, "peer mountinfo readable", 0, "0 peers");

	int fd = open("/proc/1/status", O_RDONLY);
	if (fd >= 0) { emit(o, "/proc/1 status", 1, "readable"); close(fd); }
	else emit(o, "/proc/1 status", 0, "errno=%d (%s)", errno, strerror(errno));
}

/* EACCES (SELinux create denial) reads as a clean "denied"; anything else is an
 * error in the probe's own setup. */
static int socket_errno_verdict(int e) { return e == EACCES ? 0 : -1; }

/* Like probe_open but with a distinct row name, so two rows can test the same
 * path with different flags (e.g. /dev/kmsg read vs write). */
static void probe_open_named(struct out *o, const char *name, const char *path, int flags)
{
	int fd = open(path, flags);
	if (fd >= 0) { emit(o, name, 1, "opened"); close(fd); }
	else { int e = errno; emit(o, name, e == EACCES ? 0 : e == ENOENT ? 0 : -1, "errno=%d (%s)", e, strerror(e)); }
}

/* --- held kmalloc-256 spray vehicles (CVE-2026-46242 write-forge delivery) ----
 *
 * The write forge needs an order-1 (kmalloc-256) allocation whose bytes we
 * control, HELD (not transient), to reclaim a freed filp page and lay down a
 * fake struct file. From u:r:shell:s0 the only one that works is an inotify
 * name, and it is single-tile + no 0x00/0x2f. These rows say, per domain,
 * whether a better (arbitrary-byte, 0x00-clean, two-pointer) vehicle is open --
 * i.e. whether a richer domain (system_server?) is where the forge is deliverable.
 * None of these raise SIGSYS (they are socket ops with ordinary errno), so no
 * fork isolation is needed. */
static void probe_km256_vehicles(struct out *o)
{
	/* IP_MSFILTER: struct ip_sf_socklist = 8 + 4*numsrc bytes, held, content =
	 * the source addresses (arbitrary 4-byte values incl 0x00). Needs an existing
	 * membership first, and is capped at net.ipv4.igmp_max_msf sources -- default
	 * 10 -> 48 bytes -> kmalloc-64, too small for the filp page. Report the cap. */
	{
		int s = socket(AF_INET, SOCK_DGRAM, 0), cap = read_small_int("/proc/sys/net/ipv4/igmp_max_msf");
		if (s < 0) {
			emit(o, "IP_MSFILTER", socket_errno_verdict(errno), "socket errno=%d (%s)", errno, strerror(errno));
		} else {
			/* join 239.1.2.3 on loopback so the source-filter path is reachable */
			struct { uint32_t grp, iface; } mreq = { inet_addr("239.1.2.3"), htonl(INADDR_LOOPBACK) };
			int joined = setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0;
			int numsrc = 60;                       /* 8 + 240 = 248 -> kmalloc-256 if uncapped */
			size_t reqlen = 16 + (size_t)numsrc * 4;
			uint32_t *req = calloc(1, reqlen);
			req[0] = inet_addr("239.1.2.3"); req[1] = 0; req[2] = 1; req[3] = numsrc;
			int r = setsockopt(s, IPPROTO_IP, IP_MSFILTER, req, reqlen), e = errno;
			free(req);
			if (r == 0)
				emit(o, "IP_MSFILTER", 1, "reached numsrc=%d obj=%zuB kmalloc-%s (cap igmp_max_msf=%d)",
				     numsrc, 8 + (size_t)numsrc * 4, (8 + (size_t)numsrc * 4) > 128 ? "256" : "64", cap);
			else
				emit(o, "IP_MSFILTER", e == EACCES ? 0 : e == ENOBUFS ? 0 : -1,
				     "errno=%d (%s) joined=%d cap igmp_max_msf=%d -> max obj=%dB kmalloc-64",
				     e, strerror(e), joined, cap, 8 + (cap > 0 ? cap : 10) * 4);
			close(s);
		}
	}

	/* IPv6 extension-header options: struct ipv6_opt_hdr kmalloc'd and HELD in
	 * np->opt, content is the TLV blob (arbitrary bytes incl 0x00) -> a clean
	 * two-pointer kmalloc-256 vehicle IF reachable. Setting them needs CAP_NET_RAW
	 * (shell/app lack it -> EPERM); system_server has CAP_NET_ADMIN/RAW. */
	{
		static const struct { const char *name; int opt; } v6[] = {
			{ "IPV6_DSTOPTS", IPV6_DSTOPTS }, { "IPV6_HOPOPTS", IPV6_HOPOPTS },
		};
		for (unsigned i = 0; i < 2; i++) {
			int s = socket(AF_INET6, SOCK_DGRAM, 0);
			if (s < 0) { emit(o, v6[i].name, socket_errno_verdict(errno), "socket errno=%d (%s)", errno, strerror(errno)); continue; }
			unsigned char opt[240];
			memset(opt, 0x41, sizeof(opt));
			opt[0] = 0; opt[1] = (sizeof(opt) / 8) - 1;   /* next-hdr, hdr-ext-len */
			opt[2] = 1; opt[3] = sizeof(opt) - 4;          /* PadN covering the rest */
			int r = setsockopt(s, IPPROTO_IPV6, v6[i].opt, opt, sizeof(opt)), e = errno;
			if (r == 0)
				emit(o, v6[i].name, 1, "reached obj=%zuB kmalloc-256, arbitrary bytes (two-pointer vehicle)", sizeof(opt));
			else
				emit(o, v6[i].name, (e == EPERM || e == EACCES) ? 0 : -1,
				     "errno=%d (%s)%s", e, strerror(e), e == EPERM ? " (needs CAP_NET_RAW)" : "");
			close(s);
		}
	}

	/* SO_ATTACH_FILTER: the classic-BPF program is kmalloc'd; content is
	 * constrained to valid opcodes (only the 4-byte k immediate is free), so it is
	 * a poor forge vehicle, but its reachability per domain is worth recording. */
	{
		int sv[2];
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0) {
			struct sock_filter code[] = { { 0x06, 0, 0, 0xffffffff } };  /* BPF_RET|K, accept */
			struct sock_fprog prog = { 1, code };
			int r = setsockopt(sv[0], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)), e = errno;
			emit(o, "SO_ATTACH_FILTER", r == 0 ? 1 : (e == EACCES ? 0 : -1),
			     r == 0 ? "attached (k-immediate only, weak vehicle)" : "errno=%d (%s)", e, strerror(e));
			close(sv[0]); close(sv[1]);
		} else {
			emit(o, "SO_ATTACH_FILTER", -1, "socketpair errno=%d (%s)", errno, strerror(errno));
		}
	}

	/* unix-dgram queued skb: fully controlled bytes, HELD in the rcv queue, but
	 * skb_shared_info (~320B) is appended to the linear data so the smallest skb
	 * data buffer is kmalloc-512+, never kmalloc-256. Recorded so the floor is
	 * visible rather than re-derived. */
	{
		int sv[2];
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0) {
			char buf[192];
			memset(buf, 0x41, sizeof(buf));
			int r = send(sv[0], buf, sizeof(buf), MSG_DONTWAIT), e = errno;
			emit(o, "unix-dgram skb", r > 0 ? 1 : -1,
			     r > 0 ? "queued %d B (skb data floor kmalloc-512, not 256)" : "send errno=%d (%s)", r > 0 ? r : e, strerror(e));
			close(sv[0]); close(sv[1]);
		} else {
			emit(o, "unix-dgram skb", -1, "socketpair errno=%d (%s)", errno, strerror(errno));
		}
	}
}

static void run_all(struct out *o, const char *files_dir)
{
	char ctx[128] = "?";
	int fd = open("/proc/self/attr/current", O_RDONLY);
	if (fd >= 0) { ssize_t n = read(fd, ctx, sizeof(ctx) - 1); if (n > 0) ctx[n] = 0; close(fd); }
	{
		gid_t gs[32]; int ng = getgroups(32, gs);
		char gb[256]; int gp = 0;
		for (int i = 0; i < ng && gp < (int)sizeof(gb) - 8; i++)
			gp += snprintf(gb + gp, sizeof(gb) - gp, "%s%d", i ? "," : "", (int)gs[i]);
		if (ng <= 0) { gb[0] = '-'; gb[1] = 0; }
		emit(o, "selinux context", -1, "%s uid=%d gid=%d groups=%s",
		     ctx, getuid(), getgid(), gb);
	}
	probe_mounts(o);

	/* the CVE-2026-46242 reclaim vehicles */
	probe_open(o, "/dev/ashmem", O_RDWR);
	probe_ashmem_name(o);
	probe_xattr(o, files_dir);                 /* always emits (see probe_xattr) */
	probe_km256_vehicles(o);                   /* held kmalloc-256 spray sources */

	/* IPC and DMA nodes */
	probe_open(o, "/dev/binder", O_RDWR);
	probe_open(o, "/dev/hwbinder", O_RDWR);
	probe_open(o, "/dev/vndbinder", O_RDWR);
	probe_open(o, "/dev/dma_heap/system", O_RDONLY);
	probe_open(o, "/dev/dma_heap/system-uncached", O_RDONLY);
	probe_open(o, "/dev/ion", O_RDONLY);

	/* GPU: the widest kernel LPE surface on Android, and per-vendor */
	probe_open(o, "/dev/mali0", O_RDWR);              /* Arm Mali (this device) */
	probe_open(o, "/dev/kgsl-3d0", O_RDWR);           /* Qualcomm Adreno */
	probe_open(o, "/dev/nvhost-gpu", O_RDWR);         /* Tegra */

	/* HID / input injection */
	probe_open(o, "/dev/uhid", O_RDWR);
	probe_open(o, "/dev/uinput", O_RDWR);

	/* kernel-info leaks */
	probe_open(o, "/dev/kmsg", O_RDONLY);
	probe_open_named(o, "/dev/kmsg (write)", "/dev/kmsg", O_WRONLY);  /* kernel log injection */
	probe_open(o, "/proc/kcore", O_RDONLY);             /* kernel memory image (absent on this build) */
	probe_open(o, "/proc/kallsyms", O_RDONLY);
	probe_open(o, "/proc/config.gz", O_RDONLY);
	{
		static char ver[512];
		slurp_file("/proc/version", ver, sizeof(ver));
		if (ver[0]) { /* summarise to the release token, full string on click */
			char sm[96]; int i = 0;
			/* "Linux version X.Y.Z-... " -> "X.Y.Z-..." up to first space after version */
			const char *vp = ver;
			for (int k = 0; k < 2 && *vp; k++) { while (*vp && *vp != ' ') vp++; if (*vp) vp++; }
			while (vp[i] && vp[i] != ' ' && i < (int)sizeof(sm) - 1) { sm[i] = vp[i]; i++; }
			sm[i] = 0;
			emit(o, "/proc/version", 2, "%s", sm[0] ? sm : "readable");
		} else {
			probe_open(o, "/proc/version", O_RDONLY);
		}
	}
	probe_open(o, "/proc/self/pagemap", O_RDONLY);
	probe_open(o, "/sys/kernel/notes", O_RDONLY);
	/* The tracefs KASLR leak is a pair: writing trace_marker plants a kernel
	 * pointer, reading trace_pipe_raw recovers it. The write is world-open;
	 * the readback is gated to group readtracefs (gid 3012), which shell has
	 * and no app domain does -- so the leak is shell-only. Probe both. */
	probe_open(o, "/sys/kernel/tracing/trace_marker", O_WRONLY);
	probe_open(o, "/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw", O_RDONLY);
	probe_slabinfo(o);
	probe_text(o, "/proc/pagetypeinfo");
	probe_text(o, "/proc/vmallocinfo");

	/* other nodes */
	probe_open(o, "/dev/fuse", O_RDWR);
	probe_open(o, "/dev/random", O_RDONLY);

	/* SELinux policy, queried directly (DirtySepolicy) */
	probe_text(o, "/sys/fs/selinux/enforce");
	probe_open(o, "/sys/fs/selinux/policy", O_RDONLY);
	probe_open(o, "/sys/fs/selinux/access", O_RDWR);
	probe_open(o, "/sys/fs/selinux/create", O_RDWR);
	probe_open(o, "/sys/fs/selinux/context", O_RDWR);
	probe_selinux_validate(o, "selinux type magisk", "u:object_r:magisk_file:s0");
	probe_selinux_validate(o, "selinux type ksu", "u:object_r:ksu_file:s0");
	/* policy reads: whether these domain->target permissions are allowed. */
	probe_selinux_av(o, "av system_server execmem", "u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem");
	probe_selinux_av(o, "av zygote execmem", "u:r:zygote:s0", "u:r:zygote:s0", "process", "execmem");
	probe_selinux_av(o, "av zygote->magisk memfd", "u:r:zygote:s0", "u:object_r:magisk_file:s0", "file", "execute");

	/* socket families -- the create-permission delta between domains */
	probe_socket(o, "netlink_route",          AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	probe_socket(o, "netlink_xfrm",           AF_NETLINK, SOCK_RAW, 6  /* XFRM */);
	probe_socket(o, "netlink_netfilter",      AF_NETLINK, SOCK_RAW, 12 /* NETFILTER */);
	probe_socket(o, "netlink_tcpdiag",        AF_NETLINK, SOCK_RAW, 4  /* SOCK_DIAG */);
	probe_socket(o, "netlink_generic",        AF_NETLINK, SOCK_RAW, 16 /* GENERIC */);
	probe_socket(o, "netlink_kobject_uevent", AF_NETLINK, SOCK_RAW, 15 /* KOBJECT_UEVENT */);
	probe_socket(o, "packet_socket",          AF_PACKET,  SOCK_RAW, 0);
	probe_socket(o, "key_socket",             15 /* PF_KEY */, SOCK_RAW, 2 /* PF_KEY_V2 */);
	probe_socket(o, "netlink_audit",          AF_NETLINK, SOCK_RAW, 9  /* AUDIT */);
	probe_socket(o, "alg_socket",             38 /* AF_ALG */,    SOCK_SEQPACKET, 0);
	probe_socket(o, "vsock_socket",           40 /* AF_VSOCK */,  SOCK_STREAM, 0);
	probe_socket(o, "bluetooth_socket",       31 /* AF_BLUETOOTH */, SOCK_RAW, 1 /* HCI */);
	probe_socket(o, "raw_inet_socket",        2  /* AF_INET */,   SOCK_RAW, 255);

	probe_syscall(o, "memfd_create", __NR_memfd_create, (long)"dp", 0, 0, 0, 0, 0);
	probe_syscall(o, "userfaultfd", __NR_userfaultfd, 0, 0, 0, 0, 0, 0);
	probe_syscall(o, "add_key(user)", __NR_add_key,
		      (long)"user", (long)"dp", (long)"x", 1, -2 /* KEY_SPEC_SESSION */, 0);
	/* Sized to land the payload in kmalloc-256: add_key(user) kmallocs datalen
	 * bytes for the payload, held until the key is revoked -- an arbitrary-byte
	 * two-pointer forge vehicle IF the domain is allowed keyrings at all. */
	{
		static char kpay[240];
		memset(kpay, 0x41, sizeof(kpay));
		probe_syscall(o, "add_key(user 240B)", __NR_add_key,
			      (long)"user", (long)"dp256", (long)kpay, (long)sizeof(kpay), -2, 0);
	}
	probe_syscall(o, "keyctl", __NR_keyctl, 0 /* GET_KEYRING_ID */, -2, 0, 0, 0, 0);
#ifdef __NR_mq_open
	probe_syscall(o, "mq_open", __NR_mq_open, (long)"/dp", 0102 /* O_CREAT|O_RDWR */, 0600, 0, 0, 0);
#endif
#ifdef __NR_msgget
	probe_syscall(o, "msgget(sysvipc)", __NR_msgget, 0 /* IPC_PRIVATE */, 0600, 0, 0, 0, 0);
#endif
#ifdef __NR_io_uring_setup
	{
		/* io_uring_params must be a valid, zeroed struct (~120 bytes) or the
		 * syscall faults before the capability check. */
		static char ioup[256];
		memset(ioup, 0, sizeof(ioup));
		probe_syscall(o, "io_uring_setup", __NR_io_uring_setup, 1, (long)ioup, 0, 0, 0, 0);
	}
#endif
#ifdef __NR_perf_event_open
	{
		struct perf_event_attr pea;
		memset(&pea, 0, sizeof(pea));
		pea.type = PERF_TYPE_SOFTWARE;
		pea.size = sizeof(pea);
		pea.config = PERF_COUNT_SW_CPU_CLOCK;
		pea.disabled = 1;
		pea.exclude_kernel = 1;
		pea.exclude_hv = 1;
		/* pid 0, cpu -1: measure this thread. A valid attr reaches
		 * perf_event_paranoid / SELinux instead of faulting on a NULL attr. */
		probe_syscall(o, "perf_event_open", __NR_perf_event_open, (long)&pea, 0, -1, -1, 0, 0);
	}
#endif
#ifdef __NR_bpf
	{
		union bpf_attr ba;
		memset(&ba, 0, sizeof(ba));
		ba.map_type = BPF_MAP_TYPE_HASH;
		ba.key_size = 4;
		ba.value_size = 4;
		ba.max_entries = 1;
		probe_syscall(o, "bpf(MAP_CREATE)", __NR_bpf, BPF_MAP_CREATE, (long)&ba, sizeof(ba), 0, 0, 0);
	}
#endif
	probe_syscall(o, "ptrace(TRACEME)", __NR_ptrace, 0 /* PTRACE_TRACEME */, 0, 0, 0, 0, 0);
#ifdef __NR_process_vm_readv
	{
		/* Read 8 bytes from our own address space: valid iovecs and pid, so
		 * the result reflects seccomp/SELinux, not a NULL-pointer fault. */
		static char pvbuf[8];
		struct iovec liov = { pvbuf, sizeof(pvbuf) };
		struct iovec riov = { pvbuf, sizeof(pvbuf) };
		probe_syscall(o, "process_vm_readv", __NR_process_vm_readv,
			      (long)getpid(), (long)&liov, 1, (long)&riov, 1, 0);
	}
#endif
#ifdef __NR_pidfd_open
	probe_syscall(o, "pidfd_open", __NR_pidfd_open, (long)getpid(), 0, 0, 0, 0, 0);
#endif
	probe_syscall(o, "unshare(NEWUSER)", __NR_unshare, 0x10000000 /* CLONE_NEWUSER */, 0, 0, 0, 0, 0);
#ifdef __NR_landlock_create_ruleset
	probe_syscall(o, "landlock", __NR_landlock_create_ruleset, 0, 0,
		      1 /* LANDLOCK_CREATE_RULESET_VERSION */, 0, 0, 0);
#endif

}

/* Produce the content for one INFO row, on demand (the app calls this when a
 * row is tapped). Reads happen here, not during the probe run. */
static void probe_content(struct out *o, const char *name, const char *dir)
{
	(void)dir;
	if (!strcmp(name, "mount namespace"))            content_mountns(o);
	else if (!strcmp(name, "proc visible pids"))     content_procpids(o);
	else if (!strcmp(name, "peer mountinfo readable")) content_peermnt(o);
	else if (name[0] == '/')                          content_file(o, name);
	else out_puts(o, "(no content for this row)\n");
}

/* Content is delivered over binder, whose single transaction is limited to ~1MB.
 * So the app pages it: it asks for [offset, offset+len) and repeats until a short
 * read. We regenerate the (possibly multi-MB) content once, cache it by name in
 * this process, and slice the cache -- the reads happen once, not per chunk. */
static char g_cbuf[3407872];
static size_t g_clen;
static char g_cname[192];
__attribute__((unused)) static void probe_content_chunk(struct out *o, const char *name, int offset, int len)
{
	if (strcmp(g_cname, name) != 0) {
		struct out c = { g_cbuf, sizeof(g_cbuf), 0 };
		g_cbuf[0] = 0;
		probe_content(&c, name, "");
		g_clen = c.len;
		snprintf(g_cname, sizeof(g_cname), "%s", name);
	}
	if (len < 0 || offset < 0 || (size_t)offset >= g_clen) return;   /* empty => EOF */
	size_t avail = g_clen - (size_t)offset;
	size_t take = (size_t)len < avail ? (size_t)len : avail;
	if (o->len + take + 1 >= o->cap) take = (o->cap > o->len + 1) ? o->cap - o->len - 1 : 0;
	memcpy(o->buf + o->len, g_cbuf + (size_t)offset, take);
	o->len += take; o->buf[o->len] = 0;
}

/* For domains reached through a one-shot channel that cannot be re-entered per
 * tap (the native zygote binder, system_server): produce every INFO row's
 * content once, framed as \x1e name \x1f content, appended after the rows. The
 * app attaches these to their rows; re-enterable domains fetch lazily instead. */
__attribute__((unused)) static void append_content_blocks(struct out *o)
{
	static const char *names[] = {
		"mount namespace", "proc visible pids", "peer mountinfo readable",
		"/proc/version", "/proc/slabinfo", "/proc/pagetypeinfo",
		"/proc/vmallocinfo", "/sys/fs/selinux/enforce",
	};
	for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		char h[64]; snprintf(h, sizeof(h), "\x1e%s\x1f", names[i]);
		out_puts(o, h);
		probe_content(o, names[i], "");
	}
}

#if defined(DOMAINPROBE_MAIN)
int main(int argc, char **argv)
{
	static char buf[3407872];
	struct out o = { buf, sizeof(buf), 0 };
	buf[0] = 0;
	/* argv[1], when given, is a writable directory for the xattr probe --
	 * /data/local/tmp for shell, the app's data dir under run-as. */
	if (argc > 2 && !strcmp(argv[1], "--content")) {
		/* single INFO item, read on demand: dpcli --content <name> [dir] */
		probe_content(&o, argv[2], argc > 3 ? argv[3] : "/data/local/tmp");
		fwrite(o.buf, 1, o.len, stdout);
		fflush(stdout);
		return 0;
	}
	run_all(&o, argc > 1 ? argv[1] : "/data/local/tmp");
	fflush(stdout);
	return 0;
}

#elif defined(DOMAINPROBE_NATIVESVC)
/* libmain.so: what the framework loads for an android:nativeService component.
 * On Android 17 that isolated process is forked from the native (secondary)
 * zygote, so the probe here answers for that context. The framework calls
 * ANativeService_onCreate(); we run the probe once, then register a binder --
 * defined through libbinder_ndk resolved at runtime -- that returns the report
 * over transaction 1, which the app reads with IShellProbe.run(). (ZygoteNext
 * technique, after Demo / XiaoTong6666's ZygoteNextProbe.) */
#include <dlfcn.h>
#include <dlfcn.h>

typedef struct AIBinder_Class AIBinder_Class;
typedef struct AIBinder AIBinder;
typedef struct AParcel AParcel;
typedef void (*oncreate_fn)(void *);
typedef void (*ondestroy_fn)(void *);
typedef int (*ontransact_fn)(AIBinder *, uint32_t, const AParcel *, AParcel *);
typedef AIBinder_Class *(*class_define_fn)(const char *, oncreate_fn, ondestroy_fn, ontransact_fn);
typedef AIBinder *(*aibinder_new_fn)(const AIBinder_Class *, void *);
typedef int (*write_string_fn)(AParcel *, const char *, int32_t);
typedef int (*write_int32_fn)(AParcel *, int32_t);
typedef bool (*str_alloc_fn)(void *, int32_t, char **);
typedef int (*read_string_fn)(const AParcel *, void *, str_alloc_fn);
typedef int (*read_int32_fn)(const AParcel *, int32_t *);

static class_define_fn g_class_define;
static aibinder_new_fn g_aibinder_new;
static write_string_fn g_write_string;
static write_int32_fn g_write_int32;
static read_string_fn g_read_string;
static read_int32_fn g_read_int32;
static const AIBinder_Class *g_class;
static char g_report[3407872];
static size_t g_report_len;

static void cls_create(void *a) { (void)a; }
static void cls_destroy(void *a) { (void)a; }

/* Allocator for AParcel_readString: point it at a fixed buffer for the row name. */
static char g_argname[256];
static bool argname_alloc(void *sd, int32_t size, char **buf)
{
	(void)sd;
	if (size < 1 || size > (int32_t)sizeof(g_argname)) { *buf = NULL; return size < 1; }
	*buf = g_argname;
	return true;
}
static int cls_transact(AIBinder *b, uint32_t code, const AParcel *in, AParcel *out)
{
	(void)b;
	if (code == 16777114 || !g_write_string || !g_write_int32) return 0;  /* destroy() */
	/* code 3 = contentChunk(name, offset, len): the app pages content in slices
	 * that fit a binder transaction. Read the args and return one slice. */
	if (code == 3 && g_read_string && g_read_int32) {
		g_argname[0] = 0;
		int32_t off = 0, len = 0;
		g_read_string(in, NULL, argname_alloc);
		g_read_int32(in, &off);
		g_read_int32(in, &len);
		static char cb[600000];
		struct out co = { cb, sizeof(cb), 0 }; cb[0] = 0;
		probe_content_chunk(&co, g_argname, off, len);
		if (g_write_int32(out, 0) != 0) return -22;
		return g_write_string(out, cb, (int32_t)co.len) == 0 ? 0 : -22;
	}
	if (g_write_int32(out, 0) != 0) return -22;             /* no exception */
	int rc = g_write_string(out, g_report, (int32_t)g_report_len);  /* code 1 run() */
	return rc == 0 ? 0 : -22;
}
static AIBinder *onbind(void *s, uint64_t t, const char *a, const char *d)
{
	(void)s; (void)t; (void)a; (void)d;
	return (g_aibinder_new && g_class) ? g_aibinder_new(g_class, NULL) : NULL;
}

__attribute__((visibility("default"))) void ANativeService_onCreate(void *service)
{
	struct out o = { g_report, sizeof(g_report), 0 };
	g_report[0] = 0;
	run_all(&o, "");   /* cheap rows only -- a >1MB binder reply would fail */
	g_report_len = o.len;

	void *ndk = dlopen("libbinder_ndk.so", RTLD_NOW);
	if (ndk) {
		g_class_define = (class_define_fn)dlsym(ndk, "AIBinder_Class_define");
		g_aibinder_new = (aibinder_new_fn)dlsym(ndk, "AIBinder_new");
		g_write_string = (write_string_fn)dlsym(ndk, "AParcel_writeString");
		g_write_int32 = (write_int32_fn)dlsym(ndk, "AParcel_writeInt32");
		g_read_string = (read_string_fn)dlsym(ndk, "AParcel_readString");
		g_read_int32 = (read_int32_fn)dlsym(ndk, "AParcel_readInt32");
		if (g_class_define)
			g_class = g_class_define("dev.pixelksu.domainprobe.IShellProbe",
						 cls_create, cls_destroy, cls_transact);
	}
	void *android = dlopen("libandroid.so", RTLD_NOW);
	if (android) {
		void *set_bind = dlsym(android, "ANativeService_setOnBindCallback");
		if (set_bind)
			((void (*)(void *, void *))set_bind)(service, (void *)&onbind);
	}
}

#else
JNIEXPORT jstring JNICALL
Java_dev_pixelksu_domainprobe_Probe_run(JNIEnv *env, jclass cls, jstring filesDir)
{
	static char buf[3407872];
	struct out o = { buf, sizeof(buf), 0 };
	const char *dir = filesDir ? (*env)->GetStringUTFChars(env, filesDir, NULL) : NULL;
	buf[0] = 0;
	run_all(&o, dir);
	if (dir)
		(*env)->ReleaseStringUTFChars(env, filesDir, dir);
	return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jstring JNICALL
Java_dev_pixelksu_domainprobe_Probe_content(JNIEnv *env, jclass cls, jstring filesDir, jstring nameStr)
{
	(void)cls;
	static char cbuf[3407872];
	struct out o = { cbuf, sizeof(cbuf), 0 };
	cbuf[0] = 0;
	const char *dir = filesDir ? (*env)->GetStringUTFChars(env, filesDir, NULL) : NULL;
	const char *name = nameStr ? (*env)->GetStringUTFChars(env, nameStr, NULL) : "";
	probe_content(&o, name, dir ? dir : "");
	if (dir) (*env)->ReleaseStringUTFChars(env, filesDir, dir);
	if (nameStr) (*env)->ReleaseStringUTFChars(env, nameStr, name);
	return (*env)->NewStringUTF(env, cbuf);
}

JNIEXPORT jstring JNICALL
Java_dev_pixelksu_domainprobe_Probe_contentChunk(JNIEnv *env, jclass cls, jstring nameStr, jint offset, jint len)
{
	(void)cls;
	static char chunk[600000];
	struct out o = { chunk, sizeof(chunk), 0 };
	chunk[0] = 0;
	const char *name = nameStr ? (*env)->GetStringUTFChars(env, nameStr, NULL) : "";
	probe_content_chunk(&o, name, offset, len);
	if (nameStr) (*env)->ReleaseStringUTFChars(env, nameStr, name);
	return (*env)->NewStringUTF(env, chunk);
}
#endif
