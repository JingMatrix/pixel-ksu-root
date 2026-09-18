/* lib/rw/slotcheck.h -- read a kernel pointer slot through an independent
 * primitive and classify its current value.
 *
 * A chain that overwrites a function-pointer slot usually checks its own work
 * THROUGH the thing it just forged: open the device again and see whether the
 * new descriptor behaves. That answer is circular. A walk that never wrote and
 * a read primitive that cannot reach are the same observation there, and a run
 * that reports the second when the first happened sends the next session after
 * the wrong half of the chain.
 *
 * This asks the question from outside. Given any kernel read and the value the
 * slot holds now, it reports one of four verdicts. A genuine value means the
 * slot is currently restored; it cannot say whether an earlier write landed.
 *
 * The genuine value is the caller's to supply, because only the caller knows
 * what the slot is: a symbol address resolved from kallsyms, a value captured
 * before the race, or a constant from a target header.
 */
#ifndef LIB_RW_SLOTCHECK_H
#define LIB_RW_SLOTCHECK_H

#include <stddef.h>
#include <stdint.h>

enum lib_slot_verdict {
  LIB_SLOT_UNREADABLE = 0,  /* the read primitive could not reach the slot   */
  LIB_SLOT_ZERO,            /* readable and empty -- not the genuine value   */
  LIB_SLOT_GENUINE,         /* currently holds the supplied genuine value   */
  LIB_SLOT_FOREIGN,         /* currently holds a different non-zero value    */
};

/* Read `slot` and classify it. `read` returns 0 on success, like every reader
 * in this tree; `expected` is the genuine value, 0 when the caller does not
 * know it (every non-zero value then reads as FOREIGN). `out` receives what
 * was read, when the caller wants to print it. */
static inline enum lib_slot_verdict lib_slot_check(
    int (*read)(void *ctx, uintptr_t addr, void *out, size_t len), void *ctx,
    uint64_t slot, uint64_t expected, uint64_t *out) {
  uint64_t value = 0;

  if (out) {
    *out = 0;
  }
  if (!read || read(ctx, (uintptr_t)slot, &value, sizeof(value)) != 0) {
    return LIB_SLOT_UNREADABLE;
  }
  if (out) {
    *out = value;
  }
  if (!value) {
    return LIB_SLOT_ZERO;
  }
  return value == expected ? LIB_SLOT_GENUINE : LIB_SLOT_FOREIGN;
}

static inline const char *lib_slot_verdict_name(enum lib_slot_verdict v) {
  switch (v) {
    case LIB_SLOT_UNREADABLE: return "unreadable";
    case LIB_SLOT_ZERO:       return "zero";
    case LIB_SLOT_GENUINE:    return "genuine (current value)";
    case LIB_SLOT_FOREIGN:    return "FOREIGN (current value)";
  }
  return "?";
}

/* The `fops` member of a struct miscdevice, for the common case of checking a
 * miscdevice's operations pointer: int minor, const char *name, then fops. A
 * fixed LP64 ABI fact, not a per-build one. */
#define LIB_MISCDEVICE_FOPS_OFF 0x10

#endif /* LIB_RW_SLOTCHECK_H */
