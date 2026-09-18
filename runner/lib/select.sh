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

def emit(payload_key, kmi):
    f = payloads.get(payload_key, {}).get("file", payload_key + ".so")
    print(f, kmi)

running = kmi_of(krel)

for pred in (lambda e: e["codename"] == code and e["build"] == build,
             lambda e: e["codename"] == code,
             lambda e: krel.startswith(e["kernel"].split("-g")[0])):
    for e in devices:
        if not pred(e):
            continue
        # `running` is empty only if uname is unparseable; then there is
        # nothing to contradict and the row stands, as it did before.
        if running and e["kmi"] != running:
            continue
        emit(e["payload"], e["kmi"])
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
  return 0
}
