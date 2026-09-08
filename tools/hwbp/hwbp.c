// hwbp.c — count executions of a KERNEL instruction via a perf_event hardware
// breakpoint (CPU debug registers), independent of ftrace/tracefs. Root only.
//
//   hwbp <hex_kernel_addr> <seconds> [cmd...]
// Sets a system-wide HW_BREAKPOINT_X on <addr> across all CPUs, runs for
// <seconds> (or until [cmd] finishes), prints total hit count. Used to answer:
// does binder_send_failed_reply (the from_parent walk) actually execute during
// the race harness.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

static int perf_open(struct perf_event_attr*a,int pid,int cpu){
    return syscall(SYS_perf_event_open,a,pid,cpu,-1,0);
}
int main(int argc,char**argv){
    if(argc<3){ fprintf(stderr,"usage: %s <hexaddr> <seconds> [cmd...]\n",argv[0]); return 2; }
    uint64_t addr=strtoull(argv[1],NULL,16);
    int secs=atoi(argv[2]);
    int ncpu=(int)sysconf(_SC_NPROCESSORS_CONF);

    struct perf_event_attr a; memset(&a,0,sizeof a);
    a.type=PERF_TYPE_BREAKPOINT; a.size=sizeof a;
    a.bp_type=HW_BREAKPOINT_X; a.bp_addr=addr; a.bp_len=HW_BREAKPOINT_LEN_4;
    a.sample_period=0; a.disabled=1;
    a.exclude_kernel=0; a.exclude_hv=1; a.exclude_user=1; // kernel-only

    int fds[64]; int n=0;
    for(int c=0;c<ncpu && c<64;c++){
        int fd=perf_open(&a,-1,c);   // system-wide on cpu c
        if(fd<0){ if(c==0) fprintf(stderr,"perf_event_open(cpu0) failed: %s (errno=%d)\n",strerror(errno),errno);
                  continue; }
        fds[n++]=fd;
    }
    if(!n){ fprintf(stderr,"no breakpoint fds opened — kernel HW bp on this addr not permitted\n"); return 1; }
    printf("armed HW bp @ 0x%llx on %d/%d cpus\n",(unsigned long long)addr,n,ncpu);

    for(int i=0;i<n;i++){ ioctl(fds[i],PERF_EVENT_IOC_RESET,0); ioctl(fds[i],PERF_EVENT_IOC_ENABLE,0); }

    pid_t child=-1;
    if(argc>3){ child=fork(); if(child==0){ execvp(argv[3],&argv[3]); _exit(127); } }
    if(child>0){ int st; waitpid(child,&st,0); }
    else sleep(secs);

    uint64_t total=0;
    for(int i=0;i<n;i++){ ioctl(fds[i],PERF_EVENT_IOC_DISABLE,0); uint64_t v=0; if(read(fds[i],&v,sizeof v)==sizeof v) total+=v; close(fds[i]); }
    printf("HITS=%llu\n",(unsigned long long)total);
    return 0;
}
