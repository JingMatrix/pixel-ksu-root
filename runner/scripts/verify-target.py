#!/usr/bin/env python3
"""Check a committed target description against the kernel it describes.

A target description is a table of facts about one kernel build, transcribed by
hand or generated once and then edited. Nothing about a wrong entry is visible
at build time: an offset that names the wrong field, or a flag position that
names a different flag, compiles exactly as well as a right one and fails only
on a device, as a step that never succeeds rather than as an error.

This compares the description against the kernel's own embedded type
information, which is the same data a running kernel serves and is carried
inside the image itself. Three kinds of fact are checkable that way:

    structure offsets    a named field's position
    structure sizes      a whole record's size
    enumerator values    flag positions and table indices

What the map says about each is in runner/scripts/lib/offset-maps.txt, so a fact
is checked because it was declared checkable there, not because this script
knows about it.

Facts outside those three kinds are reported as unchecked rather than silently
passed: symbol addresses need a symbol table, and chosen values -- where a
fabricated object is placed within a page, how many attempts to make -- are not
properties of the kernel at all and have nothing to check against.

    runner/scripts/verify-target.py <target>
    runner/scripts/verify-target.py <target> --btf <blob>

Exit status is 0 when every checkable fact agrees, 1 when any disagrees, and 2
when the description or the type information could not be read.
"""
import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "runner", "scripts", "lib"))
from btf_offsets import Btf  # noqa: E402

MAPS = os.path.join(ROOT, "runner", "scripts", "lib", "offset-maps.txt")


def read_map():
    """Section name -> list of rows, each a list of fields."""
    out, section = {}, None
    with open(MAPS) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                out.setdefault(section, [])
                continue
            if section:
                out[section].append(line.split())
    return out


def macros_of(target):
    """Every macro the composed description defines, with its value.

    The compiler does the composing, so a description spread across a build
    header and an interface header is read exactly as the payload sees it --
    including which layer's value wins.
    """
    header = os.path.join(ROOT, "cves", "targets", target, "target.h")
    if not os.path.exists(header):
        sys.exit(f"verify-target: no description for {target}")
    cc = os.environ.get("CC", "cc")
    try:
        out = subprocess.run([cc, "-E", "-dM", "-x", "c", header],
                             capture_output=True, text=True, cwd=ROOT).stdout
    except OSError as exc:
        sys.exit(f"verify-target: cannot run {cc}: {exc}")
    macros = {}
    for line in out.splitlines():
        m = re.match(r"#define ([A-Za-z_]\w*) (.+)$", line)
        if m:
            macros[m.group(1)] = m.group(2).strip()
    return macros


def as_int(text):
    """A macro's value as an integer, or None if it is not a plain one."""
    text = text.strip().rstrip("ULul")
    try:
        return int(text, 0)
    except ValueError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--btf", help="type information blob; defaults to the target's live capture")
    ap.add_argument("--quiet", action="store_true", help="print only disagreements")
    args = ap.parse_args()

    btf_path = args.btf or os.path.join(ROOT, "data", "live", args.target, "btf-vmlinux")
    if not os.path.exists(btf_path):
        sys.exit(f"verify-target: no type information for {args.target}\n"
                 f"  looked for {os.path.relpath(btf_path, ROOT)}\n"
                 f"  capture one with runner/scripts/harvest-live.sh, or pass --btf")

    btf = Btf(open(btf_path, "rb").read())
    maps = read_map()
    macros = macros_of(args.target)

    agree, disagree, absent = [], [], []

    def check(macro, want, what):
        if macro not in macros:
            absent.append((macro, what, "not defined by the description"))
            return
        got = as_int(macros[macro])
        if got is None:
            absent.append((macro, what, f"value {macros[macro]!r} is not a plain number"))
            return
        if got == want:
            agree.append((macro, want, what))
        else:
            disagree.append((macro, got, want, what))

    for row in maps.get("STRUCTMAP", []):
        macro, specs = row[0], row[1]
        for spec in specs.split("|"):
            try:
                off, size = btf.resolve(spec)
            except ValueError:
                continue
            # A row naming a structure rather than a field asks for its size;
            # the resolver reports that as a null offset.
            if off is None:
                check(macro, size, f"sizeof({spec})")
            else:
                check(macro, off, spec)
            break
        else:
            absent.append((macro, specs, "no such field in this kernel"))

    for row in maps.get("SIZEMAP", []):
        macro, sname = row[0], row[1]
        try:
            _, size = btf.resolve(sname)
        except ValueError as exc:
            absent.append((macro, sname, str(exc)))
            continue
        check(macro, size, f"sizeof({sname})")

    for row in maps.get("ENUMMAP", []):
        macro, ename = row[0], row[1]
        try:
            check(macro, btf.enumerator(ename), ename)
        except ValueError as exc:
            absent.append((macro, ename, str(exc)))

    if not args.quiet:
        for macro, want, what in agree:
            print(f"  ok        {macro:32s} {what} = {want:#x}")
    for macro, what, why in absent:
        print(f"  unchecked {macro:32s} {what}: {why}")
    for macro, got, want, what in disagree:
        print(f"  DISAGREES {macro:32s} {what}: description says {got:#x}, "
              f"the kernel says {want:#x}")

    print(f"\n{args.target}: {len(agree)} agree, {len(disagree)} disagree, "
          f"{len(absent)} unchecked")
    return 1 if disagree else 0


if __name__ == "__main__":
    sys.exit(main())
