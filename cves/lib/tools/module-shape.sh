#!/usr/bin/env bash
# module-shape.sh -- decide whether a fix is present from the compiled shape of
# one function in a kernel module. Runs on a workstation.
#
# Where a fix changes which function a call site targets, or adds a lock around
# one, the symbol table says nothing: both functions exist in every build, and
# only this call site changed. That is a property of compiled code, so the test
# has to read the code -- which means pulling the module and disassembling it.
#
# Nothing is loaded, triggered or modified. The module is copied to a readable
# place, pulled, and analysed on the workstation; the copy is removed afterwards.
#
# The caller supplies the enclosing symbol and two patterns, and picks how they
# are compared:
#
#   by presence (default)  the pre-fix pattern appears in one compilation, the
#                          post-fix pattern in the other. Exactly one matching
#                          is a verdict.
#   by order (-o)          both patterns appear either way, and what changed is
#                          which comes first -- a lock taken before the work it
#                          protects, say. The post-fix pattern preceding the
#                          reference pattern is the verdict.
#
# Both or neither is reported as inconclusive rather than guessed at: a pattern
# can be absent because the code was inlined, which is not evidence either way.
#
# Verdict is both printed and returned: 0 fixed, 1 unfixed, 2 inconclusive.
#
# Usage:
#   module-shape.sh -m <on-device path> -s <symbol> -b <pre-fix regex> -a <post-fix regex> [-o] [-S serial]
#   module-shape.sh -f <local .ko>      -s <symbol> -b ...            -a ...
set -euo pipefail

SERIAL=""; DEVPATH=""; LOCAL=""; SYM=""; BEFORE=""; AFTER=""; ORDERED=0
while getopts "S:m:f:s:b:a:o" opt; do
  case "$opt" in
    S) SERIAL="$OPTARG" ;;
    m) DEVPATH="$OPTARG" ;;
    f) LOCAL="$OPTARG" ;;
    s) SYM="$OPTARG" ;;
    b) BEFORE="$OPTARG" ;;
    a) AFTER="$OPTARG" ;;
    o) ORDERED=1 ;;
    *) echo "usage: $0 (-m <device path> | -f <local .ko>) -s <symbol> -b <pre-fix> -a <post-fix> [-o] [-S serial]" >&2; exit 2 ;;
  esac
done
[ -n "$SYM" ] && [ -n "$BEFORE$AFTER" ] || { echo "$0: -s, and at least one of -b/-a, are required" >&2; exit 2; }

for t in nm objdump; do
  command -v "aarch64-linux-gnu-$t" >/dev/null 2>&1 \
    || { echo "missing aarch64-linux-gnu-$t (install the cross binutils)" >&2; exit 2; }
done
NM=aarch64-linux-gnu-nm
OBJDUMP=aarch64-linux-gnu-objdump

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -z "$LOCAL" ]; then
  [ -n "$DEVPATH" ] || { echo "$0: give -m or -f" >&2; exit 2; }
  ADB="adb"; [ -n "$SERIAL" ] && ADB="adb -s $SERIAL"
  $ADB get-state >/dev/null 2>&1 || { echo "no device (use -f to read a local module instead)" >&2; exit 2; }
  echo "device : $($ADB shell getprop ro.product.device | tr -d '\r')"
  echo "patch  : $($ADB shell getprop ro.build.version.security_patch | tr -d '\r')"
  echo "kernel : $($ADB shell cat /proc/version | tr -d '\r')"
  STAGE=/data/local/tmp/module_shape.ko
  $ADB shell "su -c 'cp $DEVPATH $STAGE && chmod 666 $STAGE'" \
    || { echo "could not read $DEVPATH as root" >&2; exit 2; }
  $ADB pull "$STAGE" "$WORK/m.ko" >/dev/null
  $ADB shell "rm -f $STAGE" >/dev/null 2>&1 || true
  LOCAL="$WORK/m.ko"
else
  echo "module : $LOCAL (offline)"
fi

VERMAGIC=$(strings "$LOCAL" | grep -m1 '^vermagic=' | sed 's/^vermagic=//' || true)
[ -n "$VERMAGIC" ] && echo "build  : $VERMAGIC"
echo

# Locate the enclosing symbol by name, never by a fixed address: a function
# moves between builds, and its name does not.
ADDR_SIZE=$($NM --defined-only -S "$LOCAL" 2>/dev/null | awk -v s="$SYM" '$4==s{print $1, $2}')
[ -n "$ADDR_SIZE" ] || { echo "verdict: INCONCLUSIVE -- no symbol $SYM (renamed upstream?)" >&2; exit 2; }
START=$((16#$(echo "$ADDR_SIZE" | awk '{print $1}')))
END=$((START + 16#$(echo "$ADDR_SIZE" | awk '{print $2}')))

DISASM=$($OBJDUMP -d --no-show-raw-insn -j .text \
          --start-address=$START --stop-address=$END "$LOCAL" 2>/dev/null)

echo "$SYM:"
echo "$DISASM" | grep -nE "${BEFORE:-\$^}|${AFTER:-\$^}" | sed 's/^/  /' || true
echo

if [ "$ORDERED" -eq 1 ]; then
  # Both patterns occur either way; the verdict is which comes first.
  first_ref=$(echo "$DISASM"  | grep -nE "$BEFORE" | head -1 | cut -d: -f1 || true)
  first_new=$(echo "$DISASM"  | grep -nE "$AFTER"  | head -1 | cut -d: -f1 || true)
  if [ -n "$first_new" ] && { [ -z "$first_ref" ] || [ "$first_new" -lt "$first_ref" ]; }; then
    echo "verdict: PATCHED -- the post-fix pattern precedes the reference"
    exit 0
  elif [ -n "$first_ref" ]; then
    echo "verdict: UNPATCHED -- the reference is reached first"
    exit 1
  else
    echo "verdict: INCONCLUSIVE -- neither pattern is present; read $SYM by hand"
    exit 2
  fi
fi

pre=0; post=0
[ -n "$BEFORE" ] && pre=$(echo "$DISASM"  | grep -cE "$BEFORE" || true)
[ -n "$AFTER"  ] && post=$(echo "$DISASM" | grep -cE "$AFTER"  || true)

if [ "$post" -gt 0 ] && [ "$pre" -eq 0 ]; then
  echo "verdict: PATCHED"
  exit 0
elif [ "$pre" -gt 0 ] && [ "$post" -eq 0 ]; then
  echo "verdict: UNPATCHED"
  exit 1
else
  echo "verdict: INCONCLUSIVE (pre=$pre post=$post) -- read $SYM by hand"
  exit 2
fi
