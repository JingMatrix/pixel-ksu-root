// hwbp.c — count executions of KERNEL instructions via perf_event hardware
// breakpoints (CPU debug registers), independent of ftrace/tracefs. Root only.
//
//   hwbp <hex_addr[,hex_addr...]> <seconds> [cmd...]
//
// Sets a system-wide HW_BREAKPOINT_X on each <addr> across all CPUs, runs for
// <seconds> (or until [cmd] finishes), and prints the total hit count for each
// address. One or more comma-separated addresses may be given so several points
// in the same code path are measured against a single workload run (the walk
// bisect in docs/A52S-GHOSTLOCK-WALK-BISECT.md relies on this: entry vs trylock
// vs requeue in one exploit run). arm64 has 6 HW breakpoint registers per CPU,
// so up to 6 addresses at once.
//
// Answers, on a stock kernel where kprobes/ftrace are unavailable: did this
// exact instruction execute, and how many times?
//
// The counters themselves are cves/lib/trace/hwbp.h, shared with the exploit
// tree's own instruments (cve-2026-43499-ghostlock/vehicle_monitor.c arms the
// same points around a live run) so that a number this tool prints and a number
// a bench run reports come from one implementation.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../../cves/lib/trace/hwbp.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <hexaddr[,hexaddr...]> <seconds> [cmd...]\n",
                argv[0]);
        return 2;
    }
    uint64_t addrs[LIB_HWBP_MAX_ADDR];
    const char *names[LIB_HWBP_MAX_ADDR];
    char labels[LIB_HWBP_MAX_ADDR][32];
    int naddr = 0;
    for (char *tok = strtok(argv[1], ","); tok && naddr < LIB_HWBP_MAX_ADDR;
         tok = strtok(NULL, ",")) {
        addrs[naddr] = strtoull(tok, NULL, 16);
        snprintf(labels[naddr], sizeof(labels[naddr]), "%#llx",
                 (unsigned long long)addrs[naddr]);
        names[naddr] = labels[naddr];
        naddr++;
    }
    int secs = atoi(argv[2]);

    struct lib_hwbp h;
    if (lib_hwbp_open(&h, names, addrs, naddr) == 0) {
        fprintf(stderr, "no breakpoint fds opened — kernel HW bp not permitted\n");
        return 1;
    }
    for (int a = 0; a < h.n; a++)
        fprintf(stderr, "armed HW bp @ 0x%llx on %d/%d cpus\n",
                (unsigned long long)h.pt[a].addr, h.pt[a].nopen, h.ncpu);
    lib_hwbp_start(&h);

    pid_t child = -1;
    if (argc > 3) {
        child = fork();
        if (child == 0) { execvp(argv[3], &argv[3]); _exit(127); }
    }
    if (child > 0) { int st; waitpid(child, &st, 0); }
    else sleep(secs);

    lib_hwbp_sample(&h);
    for (int a = 0; a < h.n; a++)
        printf("HITS 0x%llx = %llu\n", (unsigned long long)h.pt[a].addr,
               (unsigned long long)h.pt[a].total);
    lib_hwbp_close(&h);
    return 0;
}
