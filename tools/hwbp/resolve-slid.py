#!/usr/bin/env python3
"""resolve-slid — turn a kernel symbol (+offset) into a runtime-slid address for
hwbp, using a KASLR base leaked live by the exploit.

The unslid symbol address comes from a build's kallsyms; the runtime address is
that symbol's offset-from-_text added to the base the payload leaks
(`slide-kaslr-tracefs-ok base=<hex>` in its log; see cves/lib/kaslr). Feed the
result to tools/hwbp/hwbp.

  resolve-slid.py --kallsyms data/live/<t>/kallsyms.txt --base 0x<leaked_text> \
      rt_mutex_adjust_prio_chain+0x14c rt_mutex_adjust_prio_chain+0

Prints one slid hex address per symbol[+off] argument, comma-joined on the last
line so it can be passed straight to hwbp:

  hwbp "$(resolve-slid.py ... | tail -1)" 20 <cmd>
"""
import argparse
import sys


def load_syms(path):
    syms = {}
    for line in open(path, errors="replace"):
        f = line.split(maxsplit=2)
        if len(f) >= 3:
            syms.setdefault(f[2].strip(), int(f[0], 16))
    return syms


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kallsyms", required=True)
    ap.add_argument("--base", required=True,
                    help="leaked runtime _text base (hex), from the payload log")
    ap.add_argument("targets", nargs="+", help="symbol or symbol+0xOFF")
    args = ap.parse_args()

    syms = load_syms(args.kallsyms)
    if "_text" not in syms:
        sys.exit("[!] no _text in kallsyms")
    text = syms["_text"]
    base = int(args.base, 16)

    slid = []
    for t in args.targets:
        name, _, offs = t.partition("+")
        off = int(offs, 0) if offs else 0
        if name not in syms:
            sys.exit(f"[!] symbol not found: {name}")
        addr = base + (syms[name] - text) + off
        print(f"{t:40s} unslid={syms[name] + off:#x}  slid={addr:#x}",
              file=sys.stderr)
        slid.append(f"{addr:#x}")
    print(",".join(slid))
    return 0


if __name__ == "__main__":
    sys.exit(main())
