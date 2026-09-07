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


def _func_span(syms, name, cap):
    """Distance to the next symbol, capped — the function's extent."""
    here = syms[name]
    later = [a for a in syms.values() if a > here]
    return min(cap, min(later) - here) if later else cap
