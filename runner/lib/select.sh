# shellcheck shell=bash
#
# select.sh — resolve the connected device to an exploit payload and KMI.
#
# Exploitation is keyed to the kernel image: the KMI always comes from the
# running kernel, while the payload offsets are chosen by codename+build because
# devices on the same kernel can still need different offsets. Requires the
# globals: MANIFEST (path to targets.json), ART (artifacts dir). Sets:
# TARGET_CODENAME BUILD KREL KMI EXPLOIT_FILE EXPLOIT_PATH.
#
# Selection order, most specific first:
#   1. exact codename + build
#   2. codename (any build)
#   3. any device on the same kernel prefix
#   4. kernel-only: derive KMI from uname, no known payload (graceful fallback)
#
# A candidate row is rejected, not returned, when its KMI disagrees with the
# running kernel. Rule 2 matches on codename ALONE, so a device we know on one
# build resolves to that row's payload on any other -- including one across a
# kernel-flavour boundary, where the offsets describe a different kernel
# entirely. raven is the live case: it is listed on android14-6.1, and a
# raven still on the android13-5.10 build would otherwise be handed 6.1
# offsets and have `ksud late-load --kmi android14-6.1` asked of a 5.10
# kernel. The KASLR gate would most likely refuse the payload before it wrote
# anything, but "most likely" is not what a fallback should rest on.
# The recipe a bare run takes. Declared once, by the manifest that claims
# default = true, so promoting another chain is one edit there.
default_recipe() {
  python3 "$REPO/runner/scripts/resolve-recipe.py" --print-default
}

# The manifest's target key is codename-build, but "build" is not one fixed
# property across vendors: on Pixel it is ro.build.display.id (== ro.build.id,
# e.g. CP2A.260705.006), while a Samsung display.id is the platform build with
# the firmware version appended (UP1A.231005.007.A528BXXSBGYI3) and the key uses
# only the firmware version, which is ro.build.version.incremental
# (A528BXXSBGYI3). So the key cannot be built from one property; this looks the
# device up in the manifest by codename and whichever build candidate a row
# matches, and echoes that row's canonical codename-build. Falls back to
# codename-display.id when no row matches, so the caller's own "unknown target"
# gate still fires with a sensible name.
canonical_target() {
  local code build incr krel
  code=$(getprop ro.product.device)
  build=$(getprop ro.build.display.id)
  incr=$(getprop ro.build.version.incremental)
  krel=$(ash uname -r | tr -d '\r')
  python3 - "$MANIFEST" "$code" "$build" "$incr" "$krel" <<'PY'
import json, sys
mf, code, build, incr, krel = sys.argv[1:6]
rows = json.load(open(mf))["devices"]
cands = [b for b in (build, incr) if b]
for e in rows:
    if e["codename"] != code:
        continue
    want = e.get("kernel", "").split("-ab")[0]
    if e["build"] in cands or (want and krel.startswith(want)):
        print("%s-%s" % (e["codename"], e["build"]))
        break
else:
    print("%s-%s" % (code, build))
PY
}

resolve_target() {
  TARGET_CODENAME=$(getprop ro.product.device)
  BUILD=$(getprop ro.build.display.id)
  KREL=$(ash uname -r | tr -d '\r')

  local sel
  sel=$(python3 - "$MANIFEST" "$TARGET_CODENAME" "$BUILD" "$KREL" <<'PY'
import json, re, sys
mf, code, build, krel = sys.argv[1:5]
data = json.load(open(mf))
devices = data["devices"]
payloads = data.get("payloads", {})

def kmi_of(k):
    m = re.match(r"(\d+)\.(\d+)\..*android(\d+)", k)
    return "android%s-%s.%s" % (m.group(3), m.group(1), m.group(2)) if m else ""

def emit(e):
    f = payloads.get(e["payload"], {}).get("file", e["payload"] + ".so")
    # cols 3/4 are the manifest's canonical codename-build, which is the target
    # key -- not the device's own build string, which a Samsung device reports
    # with the platform build prepended (see canonical_target()).
    print(f, e["kmi"], e["codename"], e["build"])

running = kmi_of(krel)

for pred in (lambda e: e["codename"] == code and e["build"] == build,
             lambda e: e["codename"] == code,
             lambda e: krel.startswith(e["kernel"].split("-g")[0])):
    for e in devices:
        if not pred(e):
            continue
        # `running` is empty only if uname is unparseable; then there is
        # nothing to contradict and the row stands.
        if running and e["kmi"] != running:
            continue
        # A row describes one kernel image, and a payload is addresses in that
        # image. The codename and codename-prefix predicates above exist so a
        # build that is not listed can still be served -- but only by a row for
        # the kernel it is actually running. Compared up to the build number,
        # so a rebuild of the same source tree still matches; the -g sha is
        # part of the comparison because a different sha is a different image.
        want = e.get("kernel", "").split("-ab")[0]
        if want and not krel.startswith(want):
            continue
        emit(e)
        sys.exit(0)
print("UNKNOWN", running)
PY
  ) || return 1

  EXPLOIT_FILE=$(printf '%s\n' "$sel" | awk '{print $1}')
  # KMI and EXPLOIT_PATH are consumed by the entrypoint and runner/lib/exploit.sh.
  # shellcheck disable=SC2034
  KMI=$(printf '%s\n' "$sel" | awk '{print $2}')
  # shellcheck disable=SC2034
  EXPLOIT_PATH="$ART/exploits/$EXPLOIT_FILE"

  [ "$EXPLOIT_FILE" = UNKNOWN ] && return 2

  # A matched row carries the canonical codename-build (cols 3/4); adopt it so
  # logging and the target key agree with the manifest rather than the device's
  # own build string, which differs on Samsung (see canonical_target()).
  TARGET_CODENAME=$(printf '%s\n' "$sel" | awk '{print $3}')
  BUILD=$(printf '%s\n' "$sel" | awk '{print $4}')
  return 0
}
