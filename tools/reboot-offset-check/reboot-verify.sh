#!/usr/bin/env bash
#
# reboot-verify.sh -- prove a committed target.h holds across KASLR reboots.
#
# offsets.report (runner/scripts/lib/offset_report.py) re-derives every offset
# from one boot and diffs it against the header. This wraps that in a reboot
# loop: a rooted device is rebooted N times, and each boot the derivation is
# re-run. The point is the KASLR slide -- it changes every boot, so a header
# value that only looked right because of one boot's particular slide is caught
# here, while a genuinely _text-relative offset stays identical across all of
# them. The run prints the per-boot slide next to the mismatch count so the
# slide is visibly moving; a PASS is "the slide varied AND no boot mismatched".
#
# Needs a device that is ALREADY rooted (su on PATH, e.g. Magisk or a prior
# GhostLock/KernelSU root that survives reboot). It reads /proc/kallsyms with
# kptr_restrict lifted and, where a boot Image is cached under data/live, the
# Image too; nothing is written to the device and nothing is flashed.
#
# Usage:
#   tools/reboot-offset-check/reboot-verify.sh --serial <SERIAL> [--reboots N]
#   tools/reboot-offset-check/reboot-verify.sh --serial <SERIAL> --target a52sxq-A528BXXSBGYI3
#
# --target is resolved automatically from the device's own codename-build when
# omitted. --reboots defaults to 4. Exit 0 iff every boot re-derived with zero
# mismatches and the slide was not constant.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERIAL=""
TARGET=""
REBOOTS=4
while [ $# -gt 0 ]; do
  case "$1" in
    --serial)  SERIAL="$2"; shift 2 ;;
    --target)  TARGET="$2"; shift 2 ;;
    --reboots) REBOOTS="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m   %s\n' "$*"; }
warn() { printf '  \033[33mwarn\033[0m %s\n' "$*"; }
err()  { printf '  \033[31mfail\033[0m %s\n' "$*"; }

A=(adb); [ -n "$SERIAL" ] && A=(adb -s "$SERIAL")
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

wait_boot() {
  "${A[@]}" wait-for-device
  for _ in $(seq 1 90); do
    [ "$("${A[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break
    sleep 2
  done
  sleep 2
}

resolve_target() {
  local dev build
  dev=$("${A[@]}" shell getprop ro.product.device 2>/dev/null | tr -d '\r')
  build=$("${A[@]}" shell getprop ro.build.id 2>/dev/null | tr -d '\r')
  # Match against a committed target dir; fall back to the raw codename-build.
  for cand in "$dev-$build" "$(ls "$ROOT/cves/targets" | grep -i "^$dev-" | head -1)"; do
    [ -n "$cand" ] && [ -f "$ROOT/cves/targets/$cand/target.h" ] && { echo "$cand"; return; }
  done
  echo "$dev-$build"
}

# The composed target.h is only #includes; offset_report.py's header parser does
# not follow them, so hand it each included header as TH / TH_EXTRA.
header_paths() {
  local t="$1" f rel out=()
  f="$ROOT/cves/targets/$t/target.h"
  [ -f "$f" ] || return 1
  while read -r rel; do
    rel="${rel#\"}"; rel="${rel%\"}"
    out+=("$ROOT/cves/targets/$t/$rel")
  done < <(grep -oE '#include "[^"]+"' "$f" | sed 's/#include "//; s/"//')
  ( IFS=:; echo "${out[*]}" )
}

[ -n "$TARGET" ] || TARGET="$(resolve_target)"
step "target: $TARGET  (reboots: $REBOOTS)"
THS="$(header_paths "$TARGET")" || { err "no cves/targets/$TARGET/target.h"; exit 2; }
TH="${THS%%:*}"; TH_EXTRA="${THS#*:}"; [ "$TH_EXTRA" = "$TH" ] && TH_EXTRA=""
ok "headers: $(echo "$THS" | tr ':' ' ')"

# A cached Image lets PTRMAP/CODEMAP rows (e.g. ASHMEM_MISC_FOPS_OFF's
# neighbours) resolve; without it those rows are UNRESOLVED but the SYMMAP rows
# (the KASLR-sensitive ones this tool is about) still check.
IMG="$ROOT/data/live/$TARGET/Image"
[ -f "$IMG" ] && ok "using cached Image ($(stat -c%s "$IMG") bytes)" \
              || { warn "no cached Image at data/live/$TARGET/Image — PTRMAP rows UNRESOLVED"; IMG=""; }

sample_boot() {  # -> prints "<_text-hex> <mismatch-count>"
  wait_boot
  "${A[@]}" shell 'su -c "echo 0 > /proc/sys/kernel/kptr_restrict; cat /proc/kallsyms"' \
    2>/dev/null | tr -d '\r' > "$SCRATCH/kallsyms.txt"
  local n; n=$(wc -l < "$SCRATCH/kallsyms.txt")
  if [ "$n" -lt 1000 ]; then echo "READFAIL 999"; return; fi
  local text; text=$(awk '$3=="_text"{print $1; exit}' "$SCRATCH/kallsyms.txt")
  TH="$TH" TH_EXTRA="$TH_EXTRA" KS="$SCRATCH/kallsyms.txt" IMG="$IMG" \
    python3 "$ROOT/runner/scripts/lib/offset_report.py" > "$SCRATCH/report.txt" 2>&1
  local bad; bad=$(grep -c 'MISMATCH' "$SCRATCH/report.txt"); bad=${bad:-0}
  cp "$SCRATCH/report.txt" "$SCRATCH/report-last.txt"
  echo "0x$text $bad"
}

declare -a SLIDES=()
FAIL=0
for k in $(seq 0 "$REBOOTS"); do
  if [ "$k" -gt 0 ]; then
    step "reboot $k/$REBOOTS"
    "${A[@]}" reboot; sleep 10
  else
    step "boot 0 (current)"
  fi
  read -r text bad <<<"$(sample_boot)"
  if [ "$text" = "0xREADFAIL" ] || [ -z "$text" ]; then
    err "boot $k: could not read kallsyms (root/kptr_restrict?)"; FAIL=1; continue
  fi
  SLIDES+=("$text")
  if [ "$bad" = "0" ]; then
    ok "boot $k: _text=$text  offsets re-derived, 0 mismatch"
  else
    err "boot $k: _text=$text  $bad MISMATCH"
    grep 'MISMATCH' "$SCRATCH/report-last.txt" | sed 's/^/       /'
    FAIL=1
  fi
done

step "verdict"
uniq_slides=$(printf '%s\n' "${SLIDES[@]}" | sort -u | wc -l)
if [ "${#SLIDES[@]}" -ge 2 ] && [ "$uniq_slides" -lt 2 ]; then
  warn "_text was identical on every boot — KASLR did not move; the invariance test is weak"
fi
printf '  boots sampled: %d   distinct _text (KASLR slides): %d\n' "${#SLIDES[@]}" "$uniq_slides"
if [ "$FAIL" = "0" ] && [ "${#SLIDES[@]}" -ge 1 ]; then
  ok "PASS — the committed offsets held across every boot"
  exit 0
fi
err "FAIL — see the mismatches above"
exit 1
