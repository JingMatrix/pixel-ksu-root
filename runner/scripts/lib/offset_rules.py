#!/usr/bin/env python3
"""One implementation of every derivation rule in offset-maps.txt.

Two callers need the same answers from different inputs:

  offset_report.py        a rooted device's kallsyms/BTF/Image, diffed against
                          the committed target.h
  derive_offsets.py       a public boot.img alone, with no target.h to diff

If each carried its own copy of "SLIDE_LOGGERS_0_1_OFF is loggers + 8", the two
would drift and the offline path would quietly disagree with the live one on a
build nobody has rooted — the exact build where nothing would catch it. So the
rules live here and the table lives in offset-maps.txt; both callers read both.

Every resolver returns `(value, note)`. `value is None` means unresolved, and
`note` says why in the terms of the source that failed. No resolver guesses:
a rule that cannot prove its answer returns None rather than a plausible one.
"""
import os
import re
import struct

MAPS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "offset-maps.txt")

_SECTION = re.compile(r"^\[(\w+)\]$")


def load_maps(path=MAPS):
    """offset-maps.txt -> {section: "row\\nrow\\n..."} with comments stripped."""
    out, cur = {}, None
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _SECTION.match(line)
            if m:
                cur = m.group(1)
                out.setdefault(cur, [])
            elif cur:
                out[cur].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


# ------------------------------------------------------------------ BTF ----

def btf_from_image(img, syms, kbase=None):
    """The kernel's own BTF, sliced out of the Image.

    CONFIG_DEBUG_INFO_BTF links the blob into the image between __start_BTF and
    __stop_BTF, and those are ordinary symbols. So the struct layouts a rooted
    device serves as /sys/kernel/btf/vmlinux are already in any boot.img: on
    panther the slice is byte-identical (md5) to the file harvested off the
    phone. STRUCTMAP therefore needs no device either -- only SLABMAP still
    does, since a slab stride is a runtime fact and not in the image at all.

    Returns the blob, or None with a reason.
    """
    a, b = syms.get("__start_BTF"), syms.get("__stop_BTF")
    if a is None or b is None:
        return None, "__start_BTF/__stop_BTF absent — CONFIG_DEBUG_INFO_BTF off?"
    base = kbase if kbase is not None else syms.get("_text")
    if base is None:
        return None, "no _text to measure the BTF symbols against"
    lo, hi = a - base, b - base
    if not (0 <= lo < hi <= len(img)):
        return None, f"BTF span {lo:#x}..{hi:#x} outside a {len(img):#x}-byte Image"
    blob = img[lo:hi]
    if blob[:2] != b"\x9f\xeb":
        return None, f"no BTF magic at {lo:#x} — wrong base, or a stripped image"
    return blob, ""


# ------------------------------------------------------------ STRUCTMAP ----

def struct_field(entry, btf):
    """MACRO  struct.path[|struct.path...]  ->  field offset, or struct size.

    Alternatives exist for the same reason SYMMAP has them: a field can be
    renamed or re-nested across kernel versions. rt_mutex_waiter is the case
    that forced it -- 6.6 folded the rb_node, prio and deadline into an
    rt_waiter_node, so `tree_entry` became `tree.entry` and everything after
    it moved 0x20. A path with no dot names the struct itself and yields its
    size.
    """
    macro, paths = entry.split()
    last = ""
    for path in paths.split("|"):
        try:
            off, extra = btf.resolve(path)
        except ValueError as e:
            last = f"{path}: {e}"
            continue
        return (extra if off is None else off), ""
    return None, last or f"{macro}: no path resolved"


# --------------------------------------------------------------- SYMMAP ----

def sym(entry, syms, text):
    """MACRO  symbol[|alt...]  addend  ->  image offset of symbol + addend."""
    _macro, names, addend = entry.split()
    for name in names.split("|"):
        if name in syms:
            return syms[name] - text + int(addend, 0), ""
    return None, f"{names.replace('|', ' / ')} absent — static or inlined"


# --------------------------------------------------------------- PTRMAP ----

def _u64(img, off):
    if off < 0 or off + 8 > len(img):
        return None
    return struct.unpack_from("<Q", img, off)[0]


def _amount(tok, known):
    """A rule field that is either a literal or the name of another macro."""
    try:
        return int(tok, 0), ""
    except ValueError:
        if tok in known:
            return known[tok], ""
        return None, f"{tok} unknown — it is a struct offset, so it comes from " \
                     f"BTF (harvest-live.sh) or a same-KMI header (--defines)"


def ptr(entry, img, known, kbase):
    """Chase a pointer in .data to reach a symbol no table exposes.

    MACRO deref   <base-macro> <byte-off>    the word at base+off, as an offset
    MACRO findptr <target-macro> <back-off>  the unique word pointing at target

    `known` supplies the base macro's value: the committed header when
    diffing, the freshly derived offsets when bootstrapping.

    Either offset may itself be a macro name rather than a literal. It has to
    be: the one deref in the table walks file_operations.compat_ioctl, which
    sits at 0x58 on android14-6.1 and 0x50 on android15-6.6, so a literal here
    silently reads the wrong slot on half the fleet.
    """
    _macro, rule, ref, arg = entry.split()
    arg, note = _amount(arg, known)
    if arg is None:
        return None, note
    base = known.get(ref)
    if base is None:
        return None, f"{ref} unknown — resolve it before this row"

    if rule == "deref":
        word = _u64(img, base + arg)
        if word is None:
            return None, f"{ref}+{arg:#x} out of range"
        if word < kbase or word - kbase >= len(img):
            return None, f"{ref}+{arg:#x} is {word:#x} — not a text pointer"
        return word - kbase, ""

    if rule == "findptr":
        want = kbase + base
        hits = [i for i in range(0, len(img) - 8, 8)
                if struct.unpack_from("<Q", img, i)[0] == want]
        if len(hits) != 1:
            return None, f"{len(hits)} words point at {ref}, need exactly 1"
        return hits[0] - arg, ""

    return None, f"unknown rule {rule}"


# --------------------------------------------------------------- CODEMAP ---

BRK_WARN = 0xD4210000            # brk #0x800 -- arm64 WARN_ON/BUG trap
_SPAN_CAP = 0x800                # how far into a function either rule looks


def _u32(img, off):
    if off < 0 or off + 4 > len(img):
        return 0
    return struct.unpack_from("<I", img, off)[0]


def _cbz_target(w):
    """CBZ Xt, label -> (Rt, signed byte displacement), or None."""
    if (w & 0xFF000000) != 0xB4000000:      # sf=1, CBZ (64-bit)
        return None
    imm = (w >> 5) & 0x7FFFF
    if imm & (1 << 18):
        imm -= 1 << 19
    return w & 0x1F, imm * 4


def _adrp_page(w, pc):
    """ADRP Xd, page -> (Rd, page address), or None."""
    if (w & 0x9F000000) != 0x90000000:
        return None
    imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return w & 0x1F, (pc & ~0xFFF) + (imm << 12)


def _add_imm(w):
    """ADD Xd, Xn, #imm (LSL 0) -> (Rd, Rn, imm), or None."""
    if (w & 0xFF800000) != 0x91000000:
        return None
    return w & 0x1F, (w >> 5) & 0x1F, (w >> 10) & 0xFFF


def code(entry, img, syms, text):
    """Offsets only the instruction stream carries.

    MACRO cbz-to-warn <symbol> <span>  -> offset WITHIN symbol
    MACRO self-addr   <symbol> 0       -> offset within the IMAGE

    Both anchor on something the compiler cannot move without changing the
    meaning, and both demand a unique match, so a build that reshapes the
    function yields UNRESOLVED instead of a wrong offset.
    """
    _macro, rule, name, arg = entry.split()
    arg = int(arg, 0)
    if name not in syms:
        return None, f"{name} absent from kallsyms"
    start = syms[name] - text
    limit = min(_SPAN_CAP, len(img) - start)

    if rule == "cbz-to-warn":
        # The arm taken when an inlined helper returned NULL and the kernel
        # complains. Anchoring on the WARN rather than counting `bl`s survives
        # a helper being inlined or not, and it self-validates: no brk, no
        # answer. This locates the CVE-2026-64560 race branch without
        # hand-disassembly.
        found = []
        for i in range(0, limit, 4):
            cbz = _cbz_target(_u32(img, start + i))
            if not cbz or cbz[0] != 0:        # cbz x0 -- the NULL-return test
                continue
            tgt = i + cbz[1]
            if not 0 <= tgt < limit:
                continue
            if any(_u32(img, start + tgt + k * 4) == BRK_WARN for k in range(arg)):
                found.append(tgt)
        if len(found) != 1:
            return None, (f"{len(found)} `cbz x0` arms reach a brk in {name}, "
                          f"need exactly 1")
        return found[0], ""

    if rule == "self-addr":
        # _THIS_IP_ is the address of a label inside the function, which the
        # compiler materialises as adrp+add. Exactly one such pair computes an
        # address that lands back inside the function it sits in, so "points at
        # itself" identifies it without knowing the instruction schedule.
        span = _func_span(syms, name, limit)
        regs, found = {}, []
        for i in range(0, span, 4):
            w = _u32(img, start + i)
            adrp = _adrp_page(w, start + i)
            if adrp:
                regs[adrp[0]] = adrp[1]
                continue
            add = _add_imm(w)
            if add and add[1] in regs:
                val = regs[add[1]] + add[2]
                if start <= val < start + span:
                    found.append(val)
        if len(found) != 1:
            return None, (f"{len(found)} adrp/add pairs in {name} point into "
                          f"{name}, need exactly 1")
        return found[0], ""

    return None, f"unknown rule {rule}"


# -------------------------------------------------------------- STACKMAP ---
#
# Constants that are neither a symbol offset nor a struct field, but a relation
# between two kernel stack frames. One rule so far: where the freed
# rt_mutex_waiter lands inside core_sys_select()'s stack_fds, which is what the
# pselect reclaim vehicle has to aim at (PSELECT_WAITER_WORD_SHIFT).
#
# It is a per-BUILD fact, not a per-version one: the landing word is set by the
# compiler's frame layout and by whether do_futex survived inlining, so two
# builds of the same kernel version can differ, and one of them can be
# unusable. That is exactly why it has to be derived per target rather than
# inherited from a sibling flavour.

# The two paths, from the syscall wrapper down to the frame that matters. Both
# are entered from invoke_syscall's single `blr x8` (one call site for every
# syscall, its own frame fixed), so the wrappers start at the same SP and the
# common part cancels when the two are subtracted.
_FUTEX_CHAIN = ("__arm64_sys_futex", "do_futex", "futex_wait_requeue_pi")
_SELECT_CHAIN = ("__arm64_sys_pselect6", "core_sys_select")
# waiter is the 3rd argument of rt_mutex_wait_proxy_lock(lock, to, waiter) and
# the 2nd of rt_mutex_cleanup_proxy_lock(lock, waiter). Two independent
# witnesses for one slot; disagreement means the read is wrong, not merely
# unlucky, so the rule refuses rather than picking one.
_WAITER_WITNESSES = (("rt_mutex_wait_proxy_lock", 2),
                     ("rt_mutex_cleanup_proxy_lock", 1))
# Witnesses for the stack_fds pointer, tried in order. get_fd_set() carries it
# as an argument where the compiler kept the helper out of line; where the
# helper was inlined the same pointer is the destination of the user copy that
# helper performs, so the copy routine witnesses it just as well. Both are
# identified the same way -- the one sp-relative register live at every call --
# so a build that inlines one of them is read rather than refused.
_FDS_WITNESSES = (("get_fd_set", 2), ("__arch_copy_from_user", 0),
                  ("_copy_from_user", 0))
_FRAME_SCAN = 0x40           # bytes of prologue to read for the frame size


def _sub_sp_imm(w):
    """SUB sp, sp, #imm (LSL 0) -> imm, or None."""
    if (w & 0xFF8003FF) != 0xD10003FF:      # sf=1, Rd=sp, Rn=sp
        return None
    return (w >> 10) & 0xFFF


def _stp_pre_sp(w):
    """STP Xt, Xt2, [sp, #-imm]! -> imm (the frame it opens), or None."""
    if (w & 0xFFC003E0) != 0xA98003E0:      # 64-bit STP pre-index, Rn=sp
        return None
    imm = (w >> 15) & 0x7F
    if imm & 0x40:
        imm -= 0x80
    return -imm * 8 if imm < 0 else None


def _mov_reg(w):
    """MOV Xd, Xn (ORR Xd, XZR, Xn) -> (Rd, Rn), or None.

    A stack address is materialised once with `add Xn, sp, #imm` and then moved
    into the argument register at each call site, so tracking the copy is what
    makes an argument-position read possible at all.
    """
    if (w & 0xFFE0FFFF) != 0xAA0003E0:
        return None
    return w & 0x1F, (w >> 16) & 0x1F


def _bl_target(w, pc):
    """BL label -> absolute target, or None."""
    if (w & 0xFC000000) != 0x94000000:
        return None
    imm = w & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return pc + imm * 4


def _frame_of(img, syms, name, text):
    """Static bytes the prologue subtracts from sp.

    Every frame in both chains is one static adjustment; a build that allocated
    dynamically (alloca, a VLA) would not be readable this way, and returning
    None here is the honest answer rather than a plausible number.
    """
    start = syms[name] - text
    total = 0
    for i in range(0, _FRAME_SCAN, 4):
        w = _u32(img, start + i)
        v = _sub_sp_imm(w)
        if v is None:
            v = _stp_pre_sp(w)
        if v is not None:
            total += v
        if _bl_target(w, 0) is not None:
            break
    return total or None


def _callee_addrs(syms, callee):
    """Every address a call to <callee> can land on.

    LTO and ICF rename a local into `name.NNNNN`, and a link-time clone is the
    symbol the call site actually targets, so matching the bare name alone
    misses the call entirely. Accepting the suffixed forms reads such a build
    instead of reporting it unresolvable.
    """
    return {a for n, a in syms.items()
            if n == callee or n.startswith(callee + ".")}


def _sp_slots_at_calls(img, syms, text, fn, callee, span):
    """For each `bl <callee>` in <fn>, the sp-relative registers live there.

    Returns a list of {reg: sp offset} snapshots, one per call site.
    """
    start = syms[fn] - text
    want = _callee_addrs(syms, callee)
    snaps, regs = [], {}
    for i in range(0, span, 4):
        w = _u32(img, start + i)
        add = _add_imm(w)
        if add and add[1] == 31:            # add Xd, sp, #imm
            regs[add[0]] = add[2]
            continue
        if add:                             # add Xd, Xn, #imm
            # A buffer inside a larger stack object is reached as base+offset,
            # so a displacement from a register that already holds a stack
            # address is still a stack address.
            if add[1] in regs:
                regs[add[0]] = regs[add[1]] + add[2]
            else:
                regs.pop(add[0], None)
            continue
        mov = _mov_reg(w)
        if mov:
            if mov[1] in regs:
                regs[mov[0]] = regs[mov[1]]
            else:
                regs.pop(mov[0], None)
            continue
        tgt = _bl_target(w, syms[fn] + i)
        if tgt is not None and tgt in want:
            snaps.append(dict(regs))
    return snaps


def stack(entry, img, syms, text):
    """MACRO stack-overlay <first_word>  -> a SIGNED word index.

    PSELECT_WAITER_WORD_SHIFT = landing_word - first_word, where

        landing = ((-sum(futex frames)  + waiter slot)
                 - (-sum(select frames) + stack_fds slot)) / 8

    and first_word is the index the payload's word map starts at
    (runner/stages/entry.ghostlock@6.1/stage.toml, [pselect_map]).
    """
    parts = entry.split()
    if len(parts) != 3:
        return None, "expected: MACRO stack-overlay <first_word>"
    _macro, rule, first_word = parts[0], parts[1], int(parts[2], 0)
    if rule != "stack-overlay":
        return None, f"unknown rule {rule}"

    # Both chains must be real calls. A link that was inlined away (PGO does
    # this to do_futex on some vendor builds) changes the frame sum, and the
    # landing word computed from the declared chain would be wrong -- so say so
    # instead of answering.
    for chain in (_FUTEX_CHAIN, _SELECT_CHAIN):
        for caller, callee in zip(chain, chain[1:]):
            if caller not in syms or callee not in syms:
                return None, f"{caller} or {callee} absent from kallsyms"
            span = _func_span(syms, caller, _SPAN_CAP)
            if not _sp_slots_at_calls(img, syms, text, caller, callee, span) \
               and not any(_bl_target(_u32(img, syms[caller] - text + i),
                                      syms[caller] + i) == syms[callee]
                           for i in range(0, span, 4)):
                return None, (f"{caller} does not call {callee} -- the chain is "
                              f"inlined here, so the frame sum does not apply")

    frames = {}
    for name in _FUTEX_CHAIN + _SELECT_CHAIN:
        f = _frame_of(img, syms, name, text)
        if f is None:
            return None, f"no static frame adjustment found in {name}"
        frames[name] = f

    # The waiter slot, from two independent argument positions.
    span = _func_span(syms, _FUTEX_CHAIN[-1], _SPAN_CAP)
    seen = set()
    for callee, argreg in _WAITER_WITNESSES:
        for snap in _sp_slots_at_calls(img, syms, text, _FUTEX_CHAIN[-1],
                                       callee, span):
            if argreg in snap:
                seen.add(snap[argreg])
    if len(seen) != 1:
        return None, (f"{len(seen)} candidate waiter slots in "
                      f"{_FUTEX_CHAIN[-1]}, need exactly 1")
    waiter_slot = seen.pop()

    # stack_fds is the `bits` pointer, the one sp-relative register live at
    # every get_fd_set call. x29 is excluded: it is the frame pointer, live
    # everywhere, and would always be a second candidate.
    span = _func_span(syms, _SELECT_CHAIN[-1], _SPAN_CAP)
    fds_slot, witness = None, None
    for cand, argreg in _FDS_WITNESSES:
        if not _callee_addrs(syms, cand):
            continue
        snaps = _sp_slots_at_calls(img, syms, text, _SELECT_CHAIN[-1], cand,
                                   span)
        seen = {snap[argreg] for snap in snaps if argreg in snap}
        if not seen and snaps:
            # The argument was not materialised in a form this reader follows.
            # Fall back to the register that holds an sp offset at EVERY call
            # site, which is what a pointer kept live across them looks like.
            # x29 is excluded: the frame pointer qualifies everywhere and would
            # always be a second candidate.
            common = None
            for snap in snaps:
                here = {(r, o) for r, o in snap.items() if r != 29}
                common = here if common is None else (common & here)
            if common and len(common) == 1:
                seen = {common.pop()[1]}
        if not seen:
            continue
        if len(seen) != 1:
            return None, (f"{len(seen)} candidate stack_fds slots from {cand} "
                          f"in {_SELECT_CHAIN[-1]}, need exactly 1")
        fds_slot, witness = seen.pop(), cand
        break
    if fds_slot is None:
        return None, (f"no witness for stack_fds in {_SELECT_CHAIN[-1]}; tried "
                      + ", ".join(c for c, _ in _FDS_WITNESSES))

    waiter_abs = -sum(frames[n] for n in _FUTEX_CHAIN) + waiter_slot
    fds_abs = -sum(frames[n] for n in _SELECT_CHAIN) + fds_slot
    delta = waiter_abs - fds_abs
    if delta % 8:
        return None, f"waiter lands {delta} bytes from stack_fds, not word-aligned"
    landing = delta // 8
    note = ("waiter at sp+%#x, stack_fds at sp+%#x, lands on word %d"
            % (waiter_slot, fds_slot, landing))
    return landing - first_word, note


def _func_span(syms, name, cap):
    """Distance to the next symbol, capped — the function's extent."""
    here = syms[name]
    later = [a for a in syms.values() if a > here]
    return min(cap, min(later) - here) if later else cap
