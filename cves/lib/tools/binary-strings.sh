#!/usr/bin/env bash
# binary-strings.sh -- decide whether a fix is present in a shipped userspace
# component from the strings it was compiled with. Runs on a workstation.
#
# Many userspace fixes add a bounds check whose failure path logs a message. The
# message is a string constant, so its presence in the binary is a
# disassembly-free discriminator for the check itself. It is also a clean one:
# adding a string is exactly what the fix did, and a build without the fix
# cannot contain it.
#
# The test has three outcomes rather than two, because a component may simply
# not have the feature compiled in. That is neither patched nor vulnerable, and
# reporting it as either is wrong -- so the caller may name a feature marker
# whose absence means the defect does not apply to this build at all.
#
# Nothing is executed. The binary is copied out read-only and scanned.
#
# Verdict is both printed and returned: 0 fixed, 1 unfixed, 2 inconclusive,
# 3 not applicable.
#
# Usage:
#   binary-strings.sh -m <on-device path> -a <fix marker> [-g <feature marker>] [-v <version regex>] [-S serial]
#   binary-strings.sh -f <local file>     -a ...
set -euo pipefail

SERIAL=""; DEVPATH=""; LOCAL=""; FIX=""; GUARD=""; VERRE=""
while getopts "S:m:f:a:g:v:" opt; do
  case "$opt" in
    S) SERIAL="$OPTARG" ;;
    m) DEVPATH="$OPTARG" ;;
    f) LOCAL="$OPTARG" ;;
    a) FIX="$OPTARG" ;;
    g) GUARD="$OPTARG" ;;
    v) VERRE="$OPTARG" ;;
    *) echo "usage: $0 (-m <device path> | -f <local file>) -a <fix marker> [-g <feature marker>] [-v <version regex>] [-S serial]" >&2; exit 2 ;;
  esac
done
[ -n "$FIX" ] || { echo "$0: -a is required" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -z "$LOCAL" ]; then
  [ -n "$DEVPATH" ] || { echo "$0: give -m or -f" >&2; exit 2; }
  ADB="adb"; [ -n "$SERIAL" ] && ADB="adb -s $SERIAL"
  $ADB get-state >/dev/null 2>&1 || { echo "no device (use -f to read a local file instead)" >&2; exit 2; }
  echo "device : $($ADB shell getprop ro.product.device | tr -d '\r')"
  echo "patch  : $($ADB shell getprop ro.build.version.security_patch | tr -d '\r')"
  $ADB pull "$DEVPATH" "$WORK/bin" >/dev/null 2>&1 \
    || { echo "could not read $DEVPATH" >&2; exit 2; }
  LOCAL="$WORK/bin"
else
  echo "file   : $LOCAL (offline)"
fi

[ -n "$VERRE" ] && {
  V=$(strings "$LOCAL" | grep -m1 -E "$VERRE" || true)
  [ -n "$V" ] && echo "version: $V"
}
echo

if [ -n "$GUARD" ]; then
  present=$(strings "$LOCAL" | grep -ciE "$GUARD" || true)
  echo "feature markers : $present"
  if [ "$present" -eq 0 ]; then
    echo
    echo "verdict: NOT APPLICABLE -- the feature is not compiled into this build"
    exit 3
  fi
fi

fixed=$(strings "$LOCAL" | grep -c -- "$FIX" || true)
echo "fix markers     : $fixed"
echo

if [ "$fixed" -gt 0 ]; then
  echo "verdict: PATCHED"
  exit 0
fi
echo "verdict: UNPATCHED"
exit 1
