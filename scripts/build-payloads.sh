#!/usr/bin/env bash
#
# build-payloads.sh — compile the exploit payloads and the target-independent
# helper from the vendored source under ./exploit.
#
# Exploitation is keyed to the concrete kernel image, so one payload is built
# per unique offset group in data/targets.json (the "payloads" map), not one
# per device — many Pixel models share an offset group. The su-daemon helper
# resolves everything at runtime and is target-independent, so it is built once.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPLOIT="$ROOT/exploit"
TARGETS="$ROOT/data/targets.json"
OUT="$ROOT/artifacts/exploits"
HELPER="$ROOT/artifacts/cve-helper"

mkdir -p "$OUT"

# Locate an Android NDK. ANDROID_NDK_HOME wins; otherwise pick the
# highest-versioned NDK under $ANDROID_HOME/ndk.
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  ndk_root="${ANDROID_HOME:-}/ndk"
  if [ -n "${ANDROID_HOME:-}" ] && [ -d "$ndk_root" ]; then
    latest="$(find "$ndk_root" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -V | tail -1)"
    [ -n "$latest" ] && ANDROID_NDK_HOME="$ndk_root/$latest"
  fi
fi
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  echo "error: set ANDROID_NDK_HOME (or ANDROID_HOME with an ndk/ subdirectory)" >&2
  exit 1
fi
export ANDROID_NDK_HOME
echo "NDK=$ANDROID_NDK_HOME"

# Read the offset groups from the payloads map: build-from target and output file.
mapfile -t rows < <(python3 - "$TARGETS" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
for group, info in data["payloads"].items():
    print(group, info["build_from"], info["file"])
PY
)

if [ "${#rows[@]}" -eq 0 ]; then
  echo "error: no payload groups found in $TARGETS" >&2
  exit 1
fi

helper_built=""
for row in "${rows[@]}"; do
  read -r group build_from file <<<"$row"
  echo "== payload $group (from $build_from) =="

  make -C "$EXPLOIT" TARGET="$build_from" all release >/dev/null

  cp "$EXPLOIT/build/$build_from/cve-2026-43499-app.release.so" "$OUT/$file"

  # The helper is target-independent; build it once from the first group.
  if [ -z "$helper_built" ]; then
    cp "$EXPLOIT/build/$build_from/cve-2026-43499-root" "$HELPER"
    helper_built=1
  fi

  printf '   -> %s (%s bytes)\n' "$file" "$(stat -c%s "$OUT/$file")"
done

echo "helper: $HELPER"
echo "done. payloads:"
ls -1 "$OUT"
