#!/usr/bin/env python3
"""Re-derive committed target.h offsets from a live device and diff them.

A wrong offset does not crash: the write lands in mapped RAM and does nothing,
which presents as a shot that runs to completion without escalating, over and
over. This turns that silent failure into a diff.

Four sources, in order of what they can prove:

  SYMMAP    kallsyms          symbol addresses. Rot every build.
  STRUCTMAP BTF               struct field offsets, measured per build from BTF.
  SLABMAP   /proc/slabinfo    slab strides. A struct's *size* is not its slab
                              stride; KernelSnitch walks the stride, so BTF is
                              the wrong source and slabinfo is the right one.
  PTRMAP    Image             offsets no symbol table exposes — static/inlined
                              symbols reached by chasing a pointer in .data.
  CODEMAP   Image             branch offsets *inside* a function, for kprobe
                              oracles.

The five tables come from lib/offset-maps.txt and the rules that read them from
lib/offset_rules.py, both shared with the offline path
(tools/pixel-image/derive_offsets.py) so the two cannot answer differently.

Inputs via env: KS (kallsyms), TH (target.h or /dev/null), BTF, IMG, SLABINFO.
SYMMAP/STRUCTMAP/SLABMAP/PTRMAP/CODEMAP override the corresponding section of
offset-maps.txt; leave them unset, which is what harvest-live.sh does.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import offset_rules  # noqa: E402  (needs the path insert above)

W = 34          # macro column width
RULE = "-" * 76


def load_kallsyms(path):
    syms = {}
    with open(path, errors="replace") as fh:
        for line in fh:
            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                continue
            addr, _type, name = parts[0], parts[1], parts[2].strip()
            # module symbols carry a trailing "\t[module]"; vmlinux only here
            if name.endswith("]"):
                continue
            try:
                syms.setdefault(name, int(addr, 16))
            except ValueError:
                continue
    return syms


def load_target_h(path):
    """Every numeric #define, hex or decimal, with or without a ULL suffix."""
    offs = {}
    if path == "/dev/null" or not os.path.exists(path):
        return offs
    pat = re.compile(r"^#define\s+(\w+)\s+(0x[0-9a-fA-F]+|\d+)[UL]{0,3}\s*(?:/[/*].*)?$")
    with open(path, errors="replace") as fh:
        for line in fh:
            m = pat.match(line.strip())
            if m:
                offs.setdefault(m.group(1), int(m.group(2), 0))
    return offs


class Verdict:
    def __init__(self):
        self.mismatch = self.missing = 0

    def emit(self, macro, derived, committed, note=""):
        d = f"{derived:#x}" if derived is not None else "-"
        c = f"{committed:#x}" if committed is not None else "-"
        if derived is None:
            self.missing += 1
            print(f"{macro:<{W}} {d:>12} {c:>12}  UNRESOLVED ({note})")
        elif committed is None:
            print(f"{macro:<{W}} {d:>12} {c:>12}  NEW (absent from target.h)")
        elif derived == committed:
            print(f"{macro:<{W}} {d:>12} {c:>12}  match")
        else:
            self.mismatch += 1
            print(f"{macro:<{W}} {d:>12} {c:>12}  "
                  f"MISMATCH (delta {derived - committed:+#x})")


def section(title, note=None):
    print()
    print(f"== {title} ==")
    if note:
        print(f"   {note}")
    print(f"{'macro':<{W}} {'derived':>12} {'committed':>12}  verdict")
    print(RULE)


# --------------------------------------------------------------------------

def do_symmap(spec, syms, committed, v, derived):
    """Rule and table both live elsewhere; see lib/offset-maps.txt [SYMMAP]."""
    text = syms["_text"]
    section("symbols (kallsyms)")
    for entry in spec.strip().splitlines():
        macro = entry.split()[0]
        val, note = offset_rules.sym(entry, syms, text)
        if val is not None:
            derived[macro] = val
        v.emit(macro, val, committed.get(macro), note)


def do_structmap(spec, btf_path, committed, v, derived):
    """MACRO  struct.field[.field...]"""
    section("struct fields (BTF)",
            "KMI stability is an assumption; BTF is the measurement.")
    if not btf_path or not os.path.exists(btf_path):
        print("(no BTF captured — skipped)")
        return
    from btf_offsets import Btf
    btf = Btf(btf_path)
    for entry in spec.strip().splitlines():
        macro = entry.split()[0]
        val, note = offset_rules.struct_field(entry, btf)
        if val is not None:
            derived[macro] = val
        v.emit(macro, val, committed.get(macro), note)


SLAB_FIELDS = {"objsize": 3, "objperslab": 4, "pagesperslab": 5}


def do_slabmap(spec, path, committed, v):
    """MACRO  <cache-name>  objsize|objperslab|pagesperslab

    sizeof(struct mm_struct) is 0x3c0 but its slab stride is 0x400; KernelSnitch
    strides the slab, so committing the BTF size silently breaks the mm_struct
    leak (see the note above MM_STRUCT_SZ in target.h).
    """
    section("slab strides (/proc/slabinfo)",
            "a struct's size is not its slab stride.")
    rows = {}
    if path and os.path.exists(path):
        for line in open(path, errors="replace"):
            f = line.split()
            if len(f) > 5 and f[1].isdigit():
                rows[f[0]] = f
    if not rows:
        print("(no slabinfo captured — skipped)")
        return
    for entry in spec.strip().splitlines():
        macro, cache, field = entry.split()
        row = rows.get(cache)
        if row is None:
            v.emit(macro, None, committed.get(macro), f"no {cache} cache on this build")
            continue
        v.emit(macro, int(row[SLAB_FIELDS[field]]), committed.get(macro))


def do_ptrmap(spec, img, committed, v, kbase, derived):
    """Rule and table both live elsewhere; see lib/offset-maps.txt [PTRMAP].

    The base macro is looked up in the committed header first — the report is
    checking that header, so it must chase the pointers that header names — and
    falls back to what this run derived when the header does not carry it.
    """
    section("pointer-derived (Image)",
            "static/inlined symbols; kallsyms and BTF cannot see these.")
    if img is None:
        print("(no Image captured — run runner/scripts/dump-boot-image.sh)")
        return
    known = dict(derived)
    known.update(committed)
    for entry in spec.strip().splitlines():
        macro = entry.split()[0]
        val, note = offset_rules.ptr(entry, img, known, kbase)
        v.emit(macro, val, committed.get(macro), note)


def do_codemap(spec, img, syms, committed, v):
    """Rule and table both live elsewhere; see lib/offset-maps.txt [CODEMAP]."""
    section("code offsets (Image)",
            "kprobe oracles and _THIS_IP_; hand-derived offsets rot silently.")
    if img is None:
        print("(no Image captured — run runner/scripts/dump-boot-image.sh)")
        return
    text = syms["_text"]
    for entry in spec.strip().splitlines():
        macro = entry.split()[0]
        val, note = offset_rules.code(entry, img, syms, text)
        v.emit(macro, val, committed.get(macro), note)


def do_stackmap(spec, img, syms, committed, v):
    """Rule and table both live elsewhere; see lib/offset-maps.txt [STACKMAP]."""
    section("stack overlay (Image)",
            "where the freed rt_mutex_waiter lands in stack_fds; per build, "
            "not per kernel version.")
    if img is None:
        print("(no Image captured — run runner/scripts/dump-boot-image.sh)")
        return
    text = syms["_text"]
    for entry in spec.strip().splitlines():
        macro = entry.split()[0]
        val, note = offset_rules.stack(entry, img, syms, text)
        v.emit(macro, val, committed.get(macro), note)


def main():
    syms = load_kallsyms(os.environ["KS"])
    committed = load_target_h(os.environ["TH"])
    for extra in os.environ.get("TH_EXTRA", "").split(":"):
        if extra:
            committed.update(load_target_h(extra))

    text = syms.get("_text")
    if not text:
        print("FATAL: _text missing or zero in kallsyms.")
        print("       kptr_restrict was not lifted; the dump is useless.")
        return 1

    img_path = os.environ.get("IMG", "")
    img = open(img_path, "rb").read() if img_path and os.path.exists(img_path) else None
    kbase = committed.get("KIMAGE_TEXT_BASE", 0xFFFFFFC008000000)

    print(f"_text  = {text:#018x}   ({len(syms)} vmlinux symbols)")
    print(f"Image  = {'%d bytes' % len(img) if img else 'ABSENT'}"
          f"      KIMAGE_TEXT_BASE = {kbase:#x}")

    maps = offset_rules.load_maps()
    spec = lambda name: os.environ.get(name, "").strip() or maps.get(name, "")

    v = Verdict()
    # SYMMAP and STRUCTMAP both feed PTRMAP, which chases ashmem_fops at
    # file_operations.compat_ioctl. On a target with no committed header yet,
    # this run is the only place either value can come from.
    derived = {}
    if spec("SYMMAP"):
        do_symmap(spec("SYMMAP"), syms, committed, v, derived)
    if spec("STRUCTMAP"):
        do_structmap(spec("STRUCTMAP"), os.environ.get("BTF", ""), committed, v,
                     derived)
    if spec("SLABMAP"):
        do_slabmap(spec("SLABMAP"), os.environ.get("SLABINFO", ""), committed, v)
    if spec("PTRMAP"):
        do_ptrmap(spec("PTRMAP"), img, committed, v, kbase, derived)
    if spec("CODEMAP"):
        do_codemap(spec("CODEMAP"), img, syms, committed, v)
    if spec("STACKMAP"):
        do_stackmap(spec("STACKMAP"), img, syms, committed, v)

    print()
    print(RULE)
    print(f"{v.mismatch} mismatch, {v.missing} unresolved")
    if v.missing and img is None:
        print("Some rows need the kernel Image: runner/scripts/dump-boot-image.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main())
