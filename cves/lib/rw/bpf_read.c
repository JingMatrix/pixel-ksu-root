/* lib/rw/bpf_read.c -- see bpf_read.h. */
#define _GNU_SOURCE
#include "bpf_read.h"

#include <errno.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Map value layout, in bytes:
 *   [0 .. 8)   target address    (written by the reader before each read)
 *   [8 .. 12)  sequence counter  (bumped by the program every run)
 *   [12 .. 16) last probe rc     (bpf_probe_read return of the last run)
 *   [16 .. 16 + CAP) output span  (the bytes read from the target)  */
#define OFF_TARGET 0
#define OFF_SEQ    8
#define OFF_RC     12
#define OFF_OUT    16
#define VAL_SIZE   (OFF_OUT + LIB_BPF_READ_CAP)

static long sys_bpf(int cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

/* One eBPF instruction. dst_reg is the low nibble of the reg byte, src_reg the
 * high nibble, matching struct bpf_insn's bitfields. */
struct bpf_insn_lit {
  uint8_t code;
  uint8_t regs;
  int16_t off;
  int32_t imm;
};

int lib_bpf_read_open(struct lib_bpf_read *b) {
  memset(b, 0, sizeof(*b));
  b->map_fd = b->prog_fd = b->perf_fd = -1;

  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_type = BPF_MAP_TYPE_ARRAY;
  attr.key_size = 4;
  attr.value_size = VAL_SIZE;
  attr.max_entries = 1;
  b->map_fd = (int)sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
  if (b->map_fd < 0) {
    lib_bpf_read_close(b);
    return -1;
  }

  /* r0 = lookup(map, &key0); if !r0 exit.
   * target = *(u64*)(r0 + OFF_TARGET);
   * rc = probe_read(r0 + OFF_OUT, CAP, target);  store rc at OFF_RC;
   * seq at OFF_SEQ += 1; return 0.
   *
   * The jump target index accounts for the 64-bit map-fd load taking two
   * instruction slots. */
#define I(c, d, s, o, i) \
  { .code = (c), .regs = (uint8_t)(((s) << 4) | ((d) & 0xf)), .off = (o), .imm = (i) }
  struct bpf_insn_lit prog[] = {
      I(0x62, 10, 0, -4, 0),            /* *(u32*)(fp-4) = 0  (map key) */
      I(0xbf, 2, 10, 0, 0),             /* r2 = fp */
      I(0x07, 2, 0, 0, -4),             /* r2 = fp - 4 */
      I(0x18, 1, 1, 0, b->map_fd),      /* r1 = map (lddw, 2 slots) */
      I(0, 0, 0, 0, 0),
      I(0x85, 0, 0, 0, 1),              /* call bpf_map_lookup_elem */
      I(0x15, 0, 0, 11, 0),             /* if r0 == 0 goto exit (+11) */
      I(0xbf, 6, 0, 0, 0),              /* r6 = r0 */
      I(0x79, 3, 6, OFF_TARGET, 0),     /* r3 = *(u64*)(r6 + target) */
      I(0xbf, 1, 6, 0, 0),              /* r1 = r6 */
      I(0x07, 1, 0, 0, OFF_OUT),        /* r1 = r6 + OFF_OUT (dst) */
      I(0xb7, 2, 0, 0, LIB_BPF_READ_CAP), /* r2 = CAP */
      I(0x85, 0, 0, 0, 4),              /* call bpf_probe_read(dst, size, src) */
      I(0x63, 6, 0, OFF_RC, 0),         /* *(u32*)(r6 + rc) = r0 */
      I(0x61, 1, 6, OFF_SEQ, 0),        /* r1 = *(u32*)(r6 + seq) */
      I(0x07, 1, 0, 0, 1),              /* r1 += 1 */
      I(0x63, 6, 1, OFF_SEQ, 0),        /* *(u32*)(r6 + seq) = r1 */
      I(0xb7, 0, 0, 0, 0),              /* r0 = 0 */
      I(0x95, 0, 0, 0, 0),              /* exit */
  };
#undef I

  char log[2048];
  log[0] = '\0';
  memset(&attr, 0, sizeof(attr));
  attr.prog_type = BPF_PROG_TYPE_PERF_EVENT;
  attr.insns = (uint64_t)(uintptr_t)prog;
  attr.insn_cnt = sizeof(prog) / sizeof(prog[0]);
  attr.license = (uint64_t)(uintptr_t) "GPL";
  attr.log_level = 1;
  attr.log_size = sizeof(log);
  attr.log_buf = (uint64_t)(uintptr_t)log;
  b->prog_fd = (int)sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
  if (b->prog_fd < 0) {
    lib_bpf_read_close(b);
    return -1;
  }

  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 50000; /* fires after ~50us of the caller's CPU time */
  b->perf_fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (b->perf_fd < 0) {
    lib_bpf_read_close(b);
    return -1;
  }
  if (ioctl(b->perf_fd, PERF_EVENT_IOC_SET_BPF, b->prog_fd) < 0 ||
      ioctl(b->perf_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    lib_bpf_read_close(b);
    return -1;
  }
  b->running = 1;
  return 0;
}

long lib_bpf_read(struct lib_bpf_read *b, uint64_t kaddr, void *out,
                  size_t len) {
  if (!b->running || len == 0 || len > LIB_BPF_READ_CAP) {
    return -1;
  }
  uint8_t val[VAL_SIZE];
  uint32_t key = 0;
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.map_fd = b->map_fd;
  attr.key = (uint64_t)(uintptr_t)&key;
  attr.value = (uint64_t)(uintptr_t)val;
  if (sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) < 0) {
    return -1;
  }
  uint32_t seq0;
  memcpy(&seq0, val + OFF_SEQ, 4);

  memcpy(val + OFF_TARGET, &kaddr, 8);
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = b->map_fd;
  attr.key = (uint64_t)(uintptr_t)&key;
  attr.value = (uint64_t)(uintptr_t)val;
  attr.flags = 0;
  if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0) {
    return -1;
  }

  /* Burn CPU so the software CPU-clock event ticks and the program runs;
   * stop once the sequence advances (a fresh read landed) or the budget is
   * spent. */
  uint32_t seq1 = seq0;
  int32_t rc = -1;
  for (int spin = 0; spin < 400 && seq1 == seq0; spin++) {
    for (volatile long i = 0; i < 200000; i++) {
    }
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = b->map_fd;
    attr.key = (uint64_t)(uintptr_t)&key;
    attr.value = (uint64_t)(uintptr_t)val;
    if (sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) < 0) {
      return -1;
    }
    memcpy(&seq1, val + OFF_SEQ, 4);
  }
  if (seq1 == seq0) {
    return -1; /* program never ran */
  }
  memcpy(&rc, val + OFF_RC, 4);
  if (rc != 0) {
    return -1; /* probe faulted (unmapped/bad address) */
  }
  memcpy(out, val + OFF_OUT, len);
  return (long)len;
}

int lib_bpf_read64(struct lib_bpf_read *b, uint64_t kaddr, uint64_t *out) {
  return lib_bpf_read(b, kaddr, out, 8) == 8 ? 0 : -1;
}

void lib_bpf_read_close(struct lib_bpf_read *b) {
  if (b->perf_fd >= 0) {
    ioctl(b->perf_fd, PERF_EVENT_IOC_DISABLE, 0);
    close(b->perf_fd);
    b->perf_fd = -1;
  }
  if (b->prog_fd >= 0) {
    close(b->prog_fd);
    b->prog_fd = -1;
  }
  if (b->map_fd >= 0) {
    close(b->map_fd);
    b->map_fd = -1;
  }
  b->running = 0;
}
