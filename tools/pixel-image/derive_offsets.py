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
import gzip
import os
import re
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

    vmlinux-to-elf reconstructs it from the kernel's built-in name table
    embedded at build time, so it names the same addresses a rooted device
    would report for that same build -- neither is an approximation of the
    other.
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


def image_config(img):
    """Read the kernel's embedded IKCONFIG, failing closed if it is absent."""
    start = img.find(b"IKCFG_ST")
    end = img.find(b"IKCFG_ED", start + 8) if start >= 0 else -1
    if start < 0 or end < 0:
        raise ValueError("Image has no complete IKCONFIG payload")
    try:
        raw = gzip.decompress(img[start + 8:end])
    except OSError as e:
        raise ValueError(f"cannot decompress embedded IKCONFIG: {e}") from e
    values = {}
    for line in raw.decode("ascii", "replace").splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            k, v = line.split("=", 1)
            values[k] = v
    return values


def derive_vmemmap_start(img, syms, kbase, seed):
    """Compute VMEMMAP_START using the memory.h profile identified by Image.

    Linux has changed the arm64 virtual layout formulas between these source
    families. The banner selects a known profile; unsupported banners fail
    closed instead of inheriting another version's arithmetic.
    """
    try:
        cfg = image_config(img)
        va_bits = int(cfg["CONFIG_ARM64_VA_BITS"])
        page_shift = next((n for n, key in ((12, "CONFIG_ARM64_4K_PAGES"),
                                            (14, "CONFIG_ARM64_16K_PAGES"),
                                            (16, "CONFIG_ARM64_64K_PAGES"))
                           if cfg.get(key) == "y"), None)
        if page_shift is None:
            raise ValueError("Image config does not select a supported arm64 page size")
        if cfg.get("CONFIG_SPARSEMEM_VMEMMAP") != "y":
            raise ValueError("Image does not enable CONFIG_SPARSEMEM_VMEMMAP")

        banner = re.search(rb"Linux version ([^\s]+)", img)
        if not banner:
            raise ValueError("Image has no Linux version banner")
        release = banner.group(1).decode("ascii", "replace")
        if release.startswith("5.4.") and "qgki" in release:
            profile = "qgki-5.4"
        elif release.startswith("6.1.") and "android14" in release:
            profile = "android14-6.1"
        elif release.startswith("6.6.") and "android15" in release:
            profile = "android15-6.6"
        else:
            raise ValueError(f"unsupported arm64 memory.h profile for {release}")

        blob, why = offset_rules.btf_from_image(img, syms, kbase)
        if blob is not None:
            from btf_offsets import Btf
            btf = Btf(blob)
            tid = btf.by_name.get("page")
            if tid is None:
                raise ValueError("Image BTF has no struct page")
            struct_page_size = btf.types[tid]["size"]
            size_source = "Image BTF"
        else:
            struct_page_size = seed.get("STRUCT_PAGE_SIZE")
            if not struct_page_size:
                raise ValueError(f"{why}; pass --defines with the matching KMI header "
                                 "to supply STRUCT_PAGE_SIZE")
            size_source = "matching KMI header"

        if va_bits < 32 or va_bits > 48 or struct_page_size <= 0:
            raise ValueError(f"implausible config/layout: VA_BITS={va_bits}, "
                             f"sizeof(struct page)={struct_page_size}")
        mask = (1 << 64) - 1
        max_shift = (struct_page_size - 1).bit_length()
        if profile != "qgki-5.4" and max_shift != 6:
            raise ValueError(f"{profile} memory.h fixes STRUCT_PAGE_MAX_SHIFT=6, "
                             f"but sizeof(struct page)={struct_page_size}")
        if profile == "qgki-5.4":
            # qgki-5.4 sizes vmemmap from the linear-map range and reserves
            # an additional 2 MiB below it.
            va_bits_min = min(va_bits, 48)
            page_offset = (-(1 << va_bits)) & mask
            page_end = (-(1 << (va_bits_min - 1))) & mask
            shift = page_shift - max_shift
            if shift <= 0:
                raise ValueError("struct page is too large for the configured page size")
            vmemmap_size = (page_end - page_offset) >> shift
            start = (-vmemmap_size - (2 << 20)) & mask
        elif profile == "android14-6.1":
            # This Image's layout reserves vmemmap at the top of the address
            # space. VMEMMAP_SHIFT = VA_BITS - (PAGE_SHIFT -
            # STRUCT_PAGE_MAX_SHIFT); VMEMMAP_START is the sign-extended
            # negative size. ARM64 fixes STRUCT_PAGE_MAX_SHIFT at 6. Keep the
            # span from that architectural bound, not sizeof(struct page): the
            # latter sizes the real descriptor, while the former sizes the
            # reserved virtual region.
            shift = page_shift - 6
            if shift <= 0:
                raise ValueError("invalid STRUCT_PAGE_MAX_SHIFT for page size")
            vmemmap_shift = va_bits - shift
            vmemmap_size = 1 << vmemmap_shift
            start = (-vmemmap_size) & mask
        else:
            # android15-6.6 memory.h: PAGE_OFFSET = -(1 << VA_BITS),
            # VMEMMAP_START = -(1 << (VA_BITS - VMEMMAP_SHIFT)).
            shift = page_shift - 6
            if shift <= 0:
                raise ValueError("invalid STRUCT_PAGE_MAX_SHIFT for page size")
            page_offset = (-(1 << va_bits)) & mask
            page_end = (-(1 << (min(va_bits, 48) - 1))) & mask
            vmemmap_size = (page_end - page_offset) >> shift
            start = (-(1 << (va_bits - shift))) & mask
        return start, (f"profile={profile}, VA_BITS={va_bits}, PAGE_SHIFT={page_shift}, "
                       f"sizeof(struct page)={struct_page_size} ({size_source}), "
                       f"VMEMMAP_SIZE={vmemmap_size:#x}")
    except (KeyError, ValueError, OSError) as e:
        return None, str(e)


def load_committed(path, _seen=None):
    """Every macro a committed header states, following its #includes.

    A target.h is only half a description: it carries the symbol offsets of one
    build and includes the interface header that carries every structure offset.
    Reading the target alone recovers none of the layout rows, and a comparison
    that cannot see a value cannot disagree with it -- following the include is
    what gives those rows a verdict.

    Includes are followed relative to the including file, once per path, so a
    header that includes itself or is reached twice cannot loop. The first
    definition of a macro wins, matching the #ifndef guards the headers use.
    """
    import re
    pat = re.compile(r"^#define\s+(\w+)\s+(0x[0-9a-fA-F]+|\d+)[UL]{0,3}\s*(?:/[/*].*)?$")
    inc = re.compile(r'^#include\s+"([^"]+)"')
    path = os.path.abspath(path)
    if _seen is None:
        _seen = set()
    if path in _seen:
        return {}
    _seen.add(path)
    out, nested = {}, []
    for line in open(path, errors="replace"):
        line = line.strip()
        m = pat.match(line)
        if m:
            out.setdefault(m.group(1), int(m.group(2), 0))
            continue
        m = inc.match(line)
        if m:
            nested.append(os.path.join(os.path.dirname(path), m.group(1)))
    for n in nested:
        if os.path.exists(n):
            for k, v in load_committed(n, _seen).items():
                out.setdefault(k, v)
    return out


def derive(img, syms, maps, kbase, seed=None, vmlinux=None):
    """Every Image-backed row. Returns [(macro, value, note)].

    STRUCTMAP is resolved first and its values feed `known`, because PTRMAP
    chases ashmem_fops at file_operations.compat_ioctl -- a struct offset, and
    one that differs by flavour. Emitting it last keeps the output shaped like a
    committed header, symbols before layouts.

    `vmlinux`, if given, backs STRUCTMAP with pahole_offsets.Pahole instead of
    the Image's own BTF, for a kernel built without CONFIG_DEBUG_INFO_BTF --
    see that module. Its resolve() has the same shape as Btf.resolve(), so
    everything downstream (offset_rules.struct_field, the loop below) uses
    whichever backend answered without a special case for which one it was.
    """
    text = syms["_text"]
    rows, known, struct_rows = [], dict(seed or {}), []

    vmemmap_start, vmemmap_note = derive_vmemmap_start(img, syms, kbase, known)
    rows.append(("VMEMMAP_START", vmemmap_start, vmemmap_note))
    if vmemmap_start is not None:
        known["VMEMMAP_START"] = vmemmap_start

    btf, why = None, None
    if vmlinux:
        from pahole_offsets import Pahole
        btf = Pahole(vmlinux)
    else:
        blob, why = offset_rules.btf_from_image(img, syms, kbase)
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

    # JTMAP's `at-offset` form needs a macro SYMMAP/PTRMAP already resolved,
    # so it runs after both.
    for entry in maps.get("JTMAP", "").splitlines():
        macro = entry.split()[0]
        val, note = offset_rules.jump_table(entry, img, syms, text, known)
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
    # indices or byte offsets, not addresses, so they are emitted as decimal
    # without the ULL an offset carries. A negative value is a legitimate
    # answer.
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
            if macro == "VMEMMAP_START":
                print("// Derived: %s" % note)
            print("#define %-*s %#010xULL" % (w, macro, val))
    for macro, val, note in stack_rows or []:
        if val is None:
            print("// UNRESOLVED %s — %s" % (macro, note))
        else:
            print()
            print("// %s" % note)
            print("#define %s %d" % (macro, val))
    print()
    print("// VMEMMAP_START comes from the embedded kernel config and struct page")
    print("// size (Image BTF, or a matching KMI header when BTF is absent).")
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
    ap.add_argument("--vmlinux", metavar="PATH",
                    help="resolve STRUCTMAP from this vmlinux's DWARF "
                         "(pahole_offsets.Pahole) instead of the Image's own "
                         "BTF, for a kernel built without "
                         "CONFIG_DEBUG_INFO_BTF. Any vmlinux built from "
                         "matching source with debug info; this tool does "
                         "not care where it came from and never prints its "
                         "path.")
    a = ap.parse_args()

    img = open(a.image, "rb").read()
    text = open(a.kallsyms, errors="replace").read() if a.kallsyms \
        else kallsyms_from_image(a.image)
    syms = load_syms(text)
    if "_text" not in syms:
        sys.exit("[!] no _text in the symbol table — wrong file, or "
                 "kptr_restrict was not lifted when it was captured")
    # Index every real address of a repeated local symbol, not just the one
    # `syms` kept; see offset_rules._DUPLICATE_ADDRS.
    offset_rules.load_duplicate_addrs_from_text(text)

    seed = {}
    for h in a.defines:
        seed.update(load_committed(h))
    if a.compare:
        # The header under test is also the best source for the struct offsets
        # PTRMAP needs, and using it cannot mask a bad symbol offset: those come
        # from the Image either way.
        seed.update(load_committed(a.compare))
    kbase = a.kbase if a.kbase is not None else syms["_text"]

    rows, stack_rows = derive(img, syms, offset_rules.load_maps(), kbase, seed,
                              vmlinux=a.vmlinux)
    if a.compare:
        return 2 if emit_compare(rows + stack_rows,
                                 load_committed(a.compare)) else 0
    emit_header(rows, a.target, a.image, len(syms), kbase, stack_rows)
    return 2 if any(v is None for _, v, _ in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
