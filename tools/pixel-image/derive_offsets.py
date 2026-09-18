#!/usr/bin/env python3
# Derive the symbol half of a target.h from a kernel Image alone.
#
# Stage 3 of tools/pixel-image, and the other end of harvest-live.sh: same
# tables (runner/scripts/lib/offset-maps.txt), same rules (offset_rules.py),
# different source. harvest-live.sh needs a rooted device; this needs a public
# boot.img, so it runs for a build nobody has touched yet.
#
# It covers four of the five sections. SYMMAP, PTRMAP and CODEMAP read the
# image directly; STRUCTMAP reads the kernel's own BTF, which CONFIG_DEBUG_INFO_BTF
# links into that same image between __start_BTF and __stop_BTF -- the very bytes
# a rooted device serves as /sys/kernel/btf/vmlinux. Only SLABMAP is genuinely
# out of reach: a slab stride is a runtime fact, not a fact about the image.
#
#   derive_offsets.py --image Image --target panther-CP2A.260705.006
#   derive_offsets.py --image Image --compare cves/targets/<t>/target.h
#   derive_offsets.py --image Image --kallsyms data/live/<t>/kallsyms.txt
#
# Exit: 0 every row resolved (and, with --compare, every row agrees); 2 otherwise.
import argparse
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "runner", "scripts", "lib"))

import offset_rules  # noqa: E402  (needs the path insert above)

# KIMAGE_TEXT_BASE is not one constant across the fleet: android14-6.1 links
# at 0xffffffc008000000 and android15-6.6 at 0xffffffc080000000. A recovered
# symbol table carries it as `_text`, so read it rather than assume it.


def kallsyms_from_image(path):
    """Recover the symbol table the stripped Image still carries.

    vmlinux-to-elf reconstructs it from the kernel's built-in name table; on
    panther it returned 98630 symbols, every one agreeing with the table read
    off the rooted device.
    """
    if not shutil.which("kallsyms-finder"):
        sys.exit("[!] kallsyms-finder not on PATH — pip install vmlinux-to-elf, "
                 "or pass --kallsyms")
    r = subprocess.run(["kallsyms-finder", path], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        sys.exit("[!] kallsyms-finder failed:\n" + (r.stderr or "").strip())
    return r.stdout


def load_syms(text):
    syms = {}
    for line in text.splitlines():
        f = line.split(maxsplit=2)
        if len(f) < 3:
            continue
        name = f[2].strip()
        if name.endswith("]"):          # module symbol; vmlinux only here
            continue
        try:
            syms.setdefault(name, int(f[0], 16))
        except ValueError:
            pass
    return syms


def load_committed(path):
    import re
    pat = re.compile(r"^#define\s+(\w+)\s+(0x[0-9a-fA-F]+|\d+)[UL]{0,3}\s*(?:/[/*].*)?$")
    out = {}
    for line in open(path, errors="replace"):
        m = pat.match(line.strip())
        if m:
            out.setdefault(m.group(1), int(m.group(2), 0))
    return out


def derive(img, syms, maps, kbase, seed=None):
    """Every Image-backed row. Returns [(macro, value, note)].

    STRUCTMAP is resolved first and its values feed `known`, because PTRMAP
    chases ashmem_fops at file_operations.compat_ioctl -- a struct offset, and
    one that differs by flavour. Emitting it last keeps the output shaped like a
    committed header, symbols before layouts.
    """
    text = syms["_text"]
    rows, known, struct_rows = [], dict(seed or {}), []

    blob, why = offset_rules.btf_from_image(img, syms, kbase)
    btf = None
    if blob is not None:
        from btf_offsets import Btf
        btf = Btf(blob)
    for entry in maps.get("STRUCTMAP", "").splitlines():
        macro = entry.split()[0]
        if btf is None:
            struct_rows.append((macro, None, why))
            continue
        val, note = offset_rules.struct_field(entry, btf)
        if val is not None:
            known.setdefault(macro, val)
        struct_rows.append((macro, val, note))

    for entry in maps.get("SYMMAP", "").splitlines():
        macro = entry.split()[0]
        val, note = offset_rules.sym(entry, syms, text)
        if val is not None:
            known[macro] = val
        rows.append((macro, val, note))

    # PTRMAP chases pointers whose base comes from SYMMAP above, so it has to
    # run second and read what that pass derived -- not a committed header,
    # which for a new build does not exist yet.
    for entry in maps.get("PTRMAP", "").splitlines():
        macro = entry.split()[0]
        val, note = offset_rules.ptr(entry, img, known, kbase)
        if val is not None:
            known[macro] = val
        rows.append((macro, val, note))

    for entry in maps.get("CODEMAP", "").splitlines():
        macro = entry.split()[0]
        val, note = offset_rules.code(entry, img, syms, text)
        if val is not None:
            known[macro] = val
        rows.append((macro, val, note))

    # STACKMAP last, and kept apart from the rest: its values are signed word
    # indices, not addresses, so they are emitted as decimal without the ULL an
    # offset carries. A negative shift is a legitimate answer.
    stack_rows = []
    for entry in maps.get("STACKMAP", "").splitlines():
        macro = entry.split()[0]
        val, note = offset_rules.stack(entry, img, syms, text)
        if val is not None:
            known[macro] = val
        stack_rows.append((macro, val, note))

    return rows + struct_rows, stack_rows


def emit_header(rows, target, image, nsym, kbase, stack_rows=None):
    w = max(len(m) for m, _, _ in rows)
    print("// %s — symbol offsets derived offline" % (target or "<target>"))
    print("// Image: %s" % os.path.basename(image))
    print("// Source: tools/pixel-image/derive_offsets.py, from")
    print("//   runner/scripts/lib/offset-maps.txt (%d recovered symbols)." % nsym)
    print("// Re-derive with the same command; confirm against a rooted device")
    print("// with runner/scripts/harvest-live.sh, which checks these same rows.")
    print()
    print("#define KIMAGE_TEXT_BASE %#xULL" % kbase)
    print()
    for macro, val, note in rows:
        if val is None:
            print("// UNRESOLVED %s — %s" % (macro, note))
        else:
            print("#define %-*s %#010xULL" % (w, macro, val))
    for macro, val, note in stack_rows or []:
        if val is None:
            print("// UNRESOLVED %s — %s" % (macro, note))
        else:
            print()
            print("// %s" % note)
            print("#define %s %d" % (macro, val))
    print()
    print("// Not derivable from an Image: the slab strides (/proc/slabinfo,")
    print("// e.g. MM_STRUCT_SZ) and the memory map (/proc/iomem). A slab stride")
    print("// is a runtime fact; harvest-live.sh reads it on a rooted device.")


def emit_compare(rows, committed):
    w = max(len(m) for m, _, _ in rows)
    bad = unres = 0
    print("%-*s %12s %12s  verdict" % (w, "macro", "derived", "committed"))
    print("-" * (w + 40))
    for macro, val, note in rows:
        c = committed.get(macro)
        d = "-" if val is None else "%#x" % val
        cs = "-" if c is None else "%#x" % c
        if val is None:
            unres += 1
            verdict = "UNRESOLVED (%s)" % note
        elif c is None:
            verdict = "NEW (absent from target.h)"
        elif val == c:
            verdict = "match"
        else:
            bad += 1
            verdict = "MISMATCH (delta %+#x)" % (val - c)
        print("%-*s %12s %12s  %s" % (w, macro, d, cs, verdict))
    print("-" * (w + 40))
    print("%d mismatch, %d unresolved" % (bad, unres))
    return bad + unres


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", required=True, help="raw arm64 Image (boot_image.py output)")
    ap.add_argument("--kallsyms", help="use this symbol table instead of recovering one")
    ap.add_argument("--target", help="<codename>-<build>, for the header comment")
    ap.add_argument("--compare", help="diff against this committed target.h")
    ap.add_argument("--defines", action="append", default=[], metavar="HEADER",
                    help="seed struct offsets from a header on the same KMI; "
                         "repeatable. PTRMAP needs file_operations.compat_ioctl, "
                         "which no Image carries — the KMI declares it stable, "
                         "and harvest-live.sh proves it per build from BTF.")
    ap.add_argument("--kbase", type=lambda x: int(x, 0), metavar="ADDR",
                    help="link-time text base; defaults to _text from the "
                         "symbol table. Give it when --kallsyms is a live "
                         "capture, whose addresses are slid.")
    a = ap.parse_args()

    img = open(a.image, "rb").read()
    text = open(a.kallsyms, errors="replace").read() if a.kallsyms \
        else kallsyms_from_image(a.image)
    syms = load_syms(text)
    if "_text" not in syms:
        sys.exit("[!] no _text in the symbol table — wrong file, or "
                 "kptr_restrict was not lifted when it was captured")

    seed = {}
    for h in a.defines:
        seed.update(load_committed(h))
    if a.compare:
        # The header under test is also the best source for the struct offsets
        # PTRMAP needs, and using it cannot mask a bad symbol offset: those come
        # from the Image either way.
        seed.update(load_committed(a.compare))
    kbase = a.kbase if a.kbase is not None else syms["_text"]

    rows, stack_rows = derive(img, syms, offset_rules.load_maps(), kbase, seed)
    if a.compare:
        return 2 if emit_compare(rows + stack_rows,
                                 load_committed(a.compare)) else 0
    emit_header(rows, a.target, a.image, len(syms), kbase, stack_rows)
    return 2 if any(v is None for _, v, _ in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
