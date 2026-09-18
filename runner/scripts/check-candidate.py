#!/usr/bin/env python3
# Does a candidate CVE's file even exist on this project's fleet, before
# spending effort porting it?
#
# tools/cve-monitor/cve_monitor.py surfaces fresh CVEs from outside the
# project. Before building a chain for one, settle the cheap question first:
# does the file its fix touches exist at all in the exact kernel commit each
# supported build runs? A driver added upstream after a branch's history
# already diverged from it was never pulled in -- absent, not merely
# unpatched -- and no marker will ever find it there. CVE-2026-89624 is the
# case this was written for: hid-universal-pidff.c (added upstream 2025-02-01)
# 404s at both commits panther's tracked builds run, while hid-core.c resolves
# fine at the same commits -- so the bug class recurs, but that CVE does not
# port.
#
# Reuses vuln_status.probe_file(), the same exact-commit source fetch a
# recorded CVE's verdict is read from, over every kernel in data/targets.json
# rather than one target at a time.
#
#   check-candidate.py --path drivers/hid/hid-universal-pidff.c
#   check-candidate.py --path drivers/hid/hid-cp2112.c \
#       --within "cp2112_probe" --fixed-when-present "some_fixed_token"
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import vuln_status  # noqa: E402


def fleet_kernels():
    devices = vuln_status.load(os.path.join(vuln_status.ROOT, "data", "targets.json"))["devices"]
    by_kernel = {}
    for d in devices:
        by_kernel.setdefault(d["kernel"], set()).add(d["codename"])
    return by_kernel


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--path", required=True, help="file the candidate's fix touches")
    ap.add_argument("--within", help="string identifying the region to check")
    ap.add_argument("--lines-after", type=int, default=8)
    ap.add_argument("--fixed-when-present", help="string only a fixed tree has there")
    args = ap.parse_args()

    marker = None
    if args.fixed_when_present:
        marker = {"fixed_when_present": args.fixed_when_present}
        if args.within:
            marker["within"] = args.within
            marker["lines_after"] = args.lines_after

    any_present = False
    for krel, codenames in sorted(fleet_kernels().items()):
        exists, verdict = vuln_status.probe_file(krel, args.path, marker)
        who = ",".join(sorted(codenames))
        if not exists:
            print("ABSENT     %-58s %s" % (krel, who))
            continue
        any_present = True
        print("%-10s %-58s %s" % (verdict or "PRESENT", krel, who))

    if not any_present:
        print("\n%s does not exist on any tracked build -- nothing to port" % args.path)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
