#!/usr/bin/env python3
# Resolve a Pixel codename+build to its public full-OTA URL.
#
# partial_boot.py takes a URL and there was no way to find one: the index at
# developers.google.com/android/ota renders its table only after the terms are
# acknowledged, and an unacknowledged GET returns a 70 KB page shell with zero
# download links. The acknowledgement is a cookie, so one GET with it set
# returns the whole table -- ~2000 builds across every Pixel.
#
#   ota_index.py                                   every build, page order
#   ota_index.py --device panther                  one device
#   ota_index.py --device panther --build CP2A.260705.006 --url-only
#   ota_index.py --page saved.html                 parse a saved page, no network
import argparse
import json
import re
import sys
import urllib.request

INDEX = "https://developers.google.com/android/ota"
# Two TOS walls share one cookie; sending both is what the page's own
# acknowledge button does.
COOKIE = "devsite_wall_acks=nexus-image-tos,nexus-ota-tos"
UA = "Mozilla/5.0 (X11; Linux x86_64)"

# <codename>-ota-<build>-<8 hex>.zip. The build is lowercased in the URL and
# the trailing hex is a content hash, so neither is guessable -- the index is
# the only way to learn it.
LINK = re.compile(
    r"https://dl\.google\.com/dl/android/aosp/"
    r"([a-z0-9_]+)-ota-([a-z0-9._]+)-([0-9a-f]{8})\.zip")


def fetch(url=INDEX):
    req = urllib.request.Request(url, headers={"Cookie": COOKIE, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def parse(html):
    """Every OTA link on the page, de-duplicated, in page order."""
    seen, out = set(), []
    for m in LINK.finditer(html):
        url = m.group(0)
        if url in seen:
            continue
        seen.add(url)
        out.append({"codename": m.group(1), "build": m.group(2).upper(), "url": url})
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--device", help="codename, e.g. panther")
    ap.add_argument("--build", help="build id, e.g. CP2A.260705.006 (case-insensitive)")
    ap.add_argument("--page", help="parse this saved HTML instead of fetching")
    ap.add_argument("--save", help="write the fetched HTML here")
    ap.add_argument("--url-only", action="store_true", help="print URLs alone")
    ap.add_argument("--json", action="store_true", dest="as_json")
    a = ap.parse_args()

    html = open(a.page, encoding="utf-8", errors="replace").read() if a.page else fetch()
    if a.save:
        open(a.save, "w", encoding="utf-8").write(html)

    rows = parse(html)
    if not rows:
        # A shell page parses cleanly to nothing, which is not the same as a
        # device having no builds -- say so rather than reporting "no match".
        sys.exit("[!] no OTA links on that page — the terms wall was not "
                 "acknowledged, or the page layout changed")
    if a.device:
        rows = [r for r in rows if r["codename"] == a.device]
    if a.build:
        rows = [r for r in rows if r["build"].upper() == a.build.upper()]
    if not rows:
        sys.exit("[!] no build matches — check the codename and build id "
                 "(ro.product.device / ro.build.id)")

    if a.as_json:
        print(json.dumps(rows, indent=1))
    elif a.url_only:
        for r in rows:
            print(r["url"])
    else:
        for r in rows:
            print("%-10s %-20s %s" % (r["codename"], r["build"], r["url"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
