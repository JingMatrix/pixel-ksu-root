#!/usr/bin/env python3
"""Is a vulnerability still present on a device?

A fix comes into existence at a moment and spreads from there, so the two
directions are not symmetric and must not be treated as one:

  BACKWARD is sound.   A kernel built before the fix existed cannot contain it.
                       So can a kernel on a branch that still lacked the fix at
                       a later point than this one -- a stable branch does not
                       un-apply a fix, so anything at or below a point known to
                       be vulnerable is vulnerable too.

  FORWARD is not.      A kernel built after the fix landed upstream may or may
                       not carry it: a branch picks up backports on its own
                       schedule. panther's CP2A.260705.006 is the standing
                       example -- the build is dated four months after the
                       CVE-2026-43049 fix reached the ACK and its kernel does
                       not have it.

So this deduces "still vulnerable" and never deduces "fixed" from age alone. A
kernel it cannot place is UNKNOWN, and the caller is told how to settle it:
fetch that build's kernel and read the function, which is one command and needs
no device.

Verdicts read out of a kernel's own source are recorded in data/vulns.json and
always win. Everything else is inference from them.

  vuln_status.py --cve CVE-2026-43049 --target panther-CP2A.260705.006
  vuln_status.py --cve CVE-2026-43499 --kernel 6.1.162-...-ab15810641
  vuln_status.py --cve CVE-2026-43049 --target <t> --derive     # settle UNKNOWN
  vuln_status.py --list
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys

# lib -> scripts -> runner -> repository root
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))
VULNS = os.path.join(ROOT, "data", "vulns.json")
TARGETS = os.path.join(ROOT, "data", "targets.json")

VULNERABLE, FIXED, UNKNOWN = "vulnerable", "fixed", "unknown"


class Verdict:
    """A verdict and the evidence for it, so a caller can print its reasoning."""

    def __init__(self, state, why, how_to_settle=None):
        self.state, self.why, self.how_to_settle = state, why, how_to_settle

    def __str__(self):
        return "%s — %s" % (self.state, self.why)


def load(path):
    with open(path) as f:
        return json.load(f)


def kmi_of(krel):
    """The kernel interface a release belongs to. Ordering is only meaningful
    inside one of these: a fix can be in 6.6 and not yet in 6.1."""
    m = re.match(r"(\d+)\.(\d+)\..*android(\d+)", krel or "")
    return "android%s-%s.%s" % (m.group(3), m.group(1), m.group(2)) if m else ""


def ack_build(krel):
    """The Android build number a kernel was produced by. Monotonic in time, so
    it orders two kernels on the same interface."""
    m = re.search(r"-ab(\d+)", krel or "")
    return int(m.group(1)) if m else None


def build_date(build_id):
    """The date a Pixel build id names: the six digits after the first dot are
    YYMMDD. Returns None for an id that does not carry one."""
    m = re.match(r"[A-Z0-9]+\.(\d{2})(\d{2})(\d{2})\.", build_id or "")
    if not m:
        return None
    try:
        return datetime.date(2000 + int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def target_facts(target):
    """(kernel, build) for a codename-build, from data/targets.json."""
    for d in load(TARGETS).get("devices", []):
        if "%s-%s" % (d["codename"], d["build"]) == target:
            return d.get("kernel"), d.get("build")
    return None, None


def describes(cve_id, data=None):
    """Is there anything recorded about this CVE?

    A stage naming a CVE this file says nothing about is not thereby suspect --
    it is simply outside what has been established, and the gate has no opinion
    to offer. Callers check this before asking for a verdict, so that adding the
    first record for a CVE is what turns the gate on for it, rather than every
    stage being refused until every CVE is written up."""
    return cve_id in (data or load(VULNS)).get("cves", {})


def decide(cve_id, krel, build_id=None, data=None, target=None):
    """The verdict for one CVE on one kernel, with its reasoning."""
    data = data or load(VULNS)
    cve = data.get("cves", {}).get(cve_id)
    if not cve:
        return Verdict(UNKNOWN, "%s is not described in data/vulns.json" % cve_id)

    recorded = cve.get("kernels", {})

    # 1. A verdict read out of this kernel's own source. Nothing beats it.
    if krel in recorded:
        r = recorded[krel]
        return Verdict(r["verdict"], "recorded for this kernel, read from its "
                                     "%s on %s" % (r.get("method", "source"),
                                                   r.get("checked", "?")))

    kmi, ab = kmi_of(krel), ack_build(krel)

    # 2. Ordering against kernels on the SAME interface whose verdict is known.
    if kmi and ab is not None:
        same = [(ack_build(k), k, v["verdict"]) for k, v in recorded.items()
                if kmi_of(k) == kmi and ack_build(k) is not None]
        vuln_abs = [a for a, _, s in same if s == VULNERABLE]
        if vuln_abs and ab <= max(vuln_abs):
            newest = max(vuln_abs)
            return Verdict(VULNERABLE,
                           "older than ab%d on %s, which still carries it; a "
                           "branch does not un-apply a fix" % (newest, kmi))

    # 3. A build cut before the fix existed cannot contain it. The kernel in a
    #    build is at most as new as the build, so this direction is safe.
    fix = cve.get("fix", {})
    appeared = fix.get("ack", {}).get("committed") or fix.get("authored")
    bd = build_date(build_id)
    if bd and appeared:
        first = datetime.date.fromisoformat(appeared)
        if bd < first:
            return Verdict(VULNERABLE,
                           "build dated %s, before the fix existed (%s)"
                           % (bd.isoformat(), first.isoformat()))

    # 4. Placed by nothing. Say so, and say how to settle it.
    hint = None
    if target:
        hint = ("read the fix out of this build's own kernel:\n"
                "  runner/scripts/lib/vuln_status.py --cve %s --target %s --derive"
                % (cve_id, target))
    return Verdict(UNKNOWN,
                   "no verdict recorded for %s, and it is newer than every "
                   "kernel that is recorded" % (krel or "this kernel"), hint)


def derive(cve_id, target, record=True):
    """Settle an UNKNOWN by reading the fix out of that build's own kernel.

    Fetches only the boot partition out of the OTA (an HTTP range read, tens of
    MB of a multi-GB image), unpacks the kernel, and looks for the marker the
    CVE record names. Needs no device and no root."""
    import tempfile
    data = load(VULNS)
    cve = data["cves"][cve_id]
    mark = cve["fix"]["marker"]
    codename, _, build = target.partition("-")

    tools = os.path.join(ROOT, "tools", "pixel-image")
    with tempfile.TemporaryDirectory() as tmp:
        boot, image = os.path.join(tmp, "boot.img"), os.path.join(tmp, "Image")
        url = subprocess.run([sys.executable, os.path.join(tools, "ota_index.py"),
                              "--device", codename, "--build", build, "--url-only"],
                             capture_output=True, text=True).stdout.strip().splitlines()
        if not url:
            return Verdict(UNKNOWN, "no OTA published for %s" % target)
        for cmd in ([sys.executable, os.path.join(tools, "partial_boot.py"), url[0], boot],
                    [sys.executable, os.path.join(ROOT, "runner", "scripts", "lib",
                                                  "boot_image.py"), boot, image]):
            if subprocess.run(cmd, capture_output=True, text=True).returncode:
                return Verdict(UNKNOWN, "could not obtain a kernel for %s" % target)
        krel = _banner(image)
        src = _source_at(krel, mark["path"])
        if src is None:
            return Verdict(UNKNOWN, "could not read %s for %s" % (mark["path"], krel))
        state = FIXED if _marker_present(src, mark) else VULNERABLE
        if record:
            cve["kernels"][krel] = {"verdict": state,
                                    "checked": datetime.date.today().isoformat(),
                                    "method": "source"}
            with open(VULNS, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
        return Verdict(state, "read from %s of %s" % (mark["path"], krel))


def _banner(image):
    out = subprocess.run(["strings", "-a", image], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith("Linux version "):
            return line.split()[2]
    return ""


def _source_at(krel, path):
    """The file as that kernel has it, from the Android common tree."""
    import base64
    import urllib.request
    sha = re.search(r"-g([0-9a-f]+)", krel or "")
    if not sha:
        return None
    url = ("https://android.googlesource.com/kernel/common/+/%s/%s?format=TEXT"
           % (sha.group(1), path))
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            return base64.b64decode(r.read()).decode("utf-8", "replace")
    except Exception:
        return None


def probe_file(krel, path, marker=None):
    """Read a file out of one kernel's exact commit, with no data/vulns.json
    entry required. For a candidate CVE that isn't recorded yet: does the file
    its fix touches even exist on this build, and if a marker is given, is the
    fix in it? Returns (exists, verdict_or_None)."""
    src = _source_at(krel, path)
    if src is None:
        return False, None
    if marker is None:
        return True, None
    return True, (FIXED if _marker_present(src, marker) else VULNERABLE)


def _marker_present(src, mark):
    """Is the fix in this source? The marker names a region and a string that
    only a fixed tree has there."""
    needle = mark["fixed_when_present"]
    if "within" in mark:
        i = src.find(mark["within"])
        if i < 0:
            return False
        window = "\n".join(src[i:].splitlines()[:mark.get("lines_after", 8)])
        return needle in window
    if "function" in mark:
        i = src.find(mark["function"])
        if i < 0:
            return False
        end = src.find("\n}", i)
        return needle in src[i:end if end > 0 else len(src)]
    return needle in src


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cve")
    ap.add_argument("--target", help="<codename>-<build>")
    ap.add_argument("--kernel", help="kernel release, if not derivable from --target")
    ap.add_argument("--build", help="build id, if not derivable from --target")
    ap.add_argument("--derive", action="store_true",
                    help="settle an unknown by reading that build's own kernel")
    ap.add_argument("--list", action="store_true", help="what is described and recorded")
    a = ap.parse_args()

    if a.list:
        data = load(VULNS)
        for cid, c in sorted(data["cves"].items()):
            print("%s  (%s) — fix authored %s" % (cid, c["chain"], c["fix"]["authored"]))
            for k, v in sorted(c["kernels"].items()):
                print("    %-11s %s" % (v["verdict"], k))
        return 0

    if not a.cve:
        ap.error("--cve is required")
    krel, build = a.kernel, a.build
    if a.target and not (krel and build):
        k, b = target_facts(a.target)
        krel, build = krel or k, build or b
        if not krel:
            print("no data/targets.json row for %s" % a.target, file=sys.stderr)

    if a.derive:
        if not a.target:
            ap.error("--derive needs --target")
        v = derive(a.cve, a.target)
    else:
        v = decide(a.cve, krel, build, target=a.target)

    print("%s on %s: %s" % (a.cve, a.target or krel, v))
    if v.how_to_settle:
        print(v.how_to_settle)
    return 0 if v.state != UNKNOWN else 3


if __name__ == "__main__":
    sys.exit(main())
