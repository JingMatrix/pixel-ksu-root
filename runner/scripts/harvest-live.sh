#!/usr/bin/env bash
#
# harvest-live.sh — capture everything a *currently rooted* device can tell us,
# while it can still tell us. Root here is per-boot — nothing is flashed and
# nothing persists — and every source below needs it, so all of it is gone the
# moment the device reboots.
#
# Captures, per device, into data/live/<codename>-<build>/:
#   kallsyms.txt      full symbol table with kptr_restrict temporarily lifted
#   offsets.report    every committed offset re-derived from kallsyms, BTF and
#                     the Image, and diffed against target.h  <-- the point
#   btf-vmlinux       /sys/kernel/btf/vmlinux (every struct field offset, exact)
#   config.gz         running-kernel config
#   iomem.txt         "Kernel code" line -> ground truth for P0_KERNEL_PHYS_LOAD
#   Image             the running kernel itself (runner/scripts/dump-boot-image.sh);
#                     resolves offsets kallsyms and BTF cannot see
#   slabinfo.txt      which cache an object lives in -> reclaim strategy
#   dmesg.txt         ring buffer, wraps, gone on reboot; holds race WARNs
#   console-ramoops   previous boot's console; holds the panic if a shot lost
#   pmsg-ramoops      previous boot's logcat
#   env.txt           codename, build, kernel release, uptime, SPL
#
# Usage: runner/scripts/harvest-live.sh [--serial SERIAL]   (all devices if omitted)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTROOT="$ROOT/data/live"
SERIAL="${SERIAL:-}"
[ "${1:-}" = "--serial" ] && SERIAL="$2"

step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m   %s\n' "$*"; }
warn() { printf '  \033[33mwarn\033[0m %s\n' "$*"; }
err()  { printf '  \033[31mfail\033[0m %s\n' "$*"; }

# The five derivation tables used to sit here as heredocs. They now live in
# lib/offset-maps.txt, read by offset_report.py below and by the offline
# tools/pixel-image/derive_offsets.py — one table, so a rule fixed for a
# rooted device is the same rule the never-rooted build gets.

harvest_one() {
  local S="$1" A=(adb -s "$1")
  local dev build krel spl uptime out

  dev=$("${A[@]}" shell getprop ro.product.device 2>/dev/null | tr -d '\r')
  build=$("${A[@]}" shell getprop ro.build.id 2>/dev/null | tr -d '\r')
  krel=$("${A[@]}" shell uname -r 2>/dev/null | tr -d '\r')
  spl=$("${A[@]}" shell getprop ro.build.version.security_patch 2>/dev/null | tr -d '\r')
  uptime=$("${A[@]}" shell cat /proc/uptime 2>/dev/null | tr -d '\r' | cut -d' ' -f1)
  [ -n "$dev" ] || { err "$S: unreachable"; return 1; }

  step "$dev ($build) — kernel $krel, uptime ${uptime}s"

  if ! "${A[@]}" shell 'su -c id' 2>/dev/null | grep -q 'uid=0'; then
    err "no root on $dev — nothing to harvest, run ./pixel-ksu-root first"
    return 1
  fi
  ok "root confirmed"

  out="$OUTROOT/$dev-$build"; mkdir -p "$out"
  local btime
  btime=$("${A[@]}" shell 'grep -m1 btime /proc/stat' 2>/dev/null | tr -d '\r' | awk '{print $2}')
  { echo "codename=$dev"; echo "build=$build"; echo "kernel=$krel"
    echo "btime=$btime"
    echo "security_patch=$spl"; echo "uptime_at_harvest=$uptime"
    echo "harvested=$(date -Iseconds)"; } > "$out/env.txt"

  # --- kallsyms. kptr_restrict=2 zeroes every address even for root, so lift it
  # for the dump and put it back immediately. This is the whole ballgame: it
  # yields exact per-build symbol addresses with no boot.img parsing.
  local prev
  prev=$("${A[@]}" shell 'su -c "cat /proc/sys/kernel/kptr_restrict"' 2>/dev/null | tr -d '\r')
  "${A[@]}" shell "su -c 'echo 0 > /proc/sys/kernel/kptr_restrict'" >/dev/null 2>&1
  "${A[@]}" shell 'su -c "cat /proc/kallsyms"' 2>/dev/null | tr -d '\r' > "$out/kallsyms.txt"
  "${A[@]}" shell "su -c 'echo ${prev:-2} > /proc/sys/kernel/kptr_restrict'" >/dev/null 2>&1
  local now
  now=$("${A[@]}" shell 'su -c "cat /proc/sys/kernel/kptr_restrict"' 2>/dev/null | tr -d '\r')
  [ "$now" = "${prev:-2}" ] && ok "kallsyms $(wc -l < "$out/kallsyms.txt") symbols (kptr_restrict restored to $now)" \
                            || warn "kptr_restrict is $now, expected ${prev:-2} — RESTORE MANUALLY"

  # --- everything else that needs root
  "${A[@]}" shell 'su -c "cat /sys/kernel/btf/vmlinux"' 2>/dev/null > "$out/btf-vmlinux" \
    && ok "BTF $(stat -c%s "$out/btf-vmlinux" 2>/dev/null) bytes (all struct offsets, exact)"
  "${A[@]}" shell 'su -c "cat /proc/config.gz"' 2>/dev/null > "$out/config.gz"
  "${A[@]}" shell 'su -c "grep -i \"Kernel code\" /proc/iomem"' 2>/dev/null | tr -d '\r' > "$out/iomem.txt"
  ok "iomem: $(cat "$out/iomem.txt")"
  # slabinfo: which cache a UAF object lands in decides the whole reclaim
  # strategy (posix_timers_cache is dedicated, not kmalloc).
  "${A[@]}" shell 'su -c "cat /proc/slabinfo"' 2>/dev/null | tr -d '\r' > "$out/slabinfo.txt"
  # dmesg is a ring buffer and it wraps; a WARN is often the only proof a race
  # fired, and it is gone on reboot.
  "${A[@]}" shell 'su -c "dmesg"' 2>/dev/null | tr -d '\r' > "$out/dmesg.txt"
  ok "slabinfo + dmesg ($(wc -l < "$out/dmesg.txt") lines)"
  for f in console-ramoops-0 pmsg-ramoops-0 dmesg-ramoops-0; do
    "${A[@]}" shell "su -c 'cat /sys/fs/pstore/$f'" 2>/dev/null | tr -d '\r' > "$out/$f" || true
    [ -s "$out/$f" ] && ok "pstore $f ($(wc -l < "$out/$f") lines)" || rm -f "$out/$f"
  done
  if [ -s "$out/console-ramoops-0" ] && \
     grep -qE 'Kernel panic|Internal error' "$out/console-ramoops-0"; then
    warn "previous boot PANICKED — trace preserved:"
    grep -nE 'Internal error|pc : |Kernel panic - not syncing|Comm: ' \
      "$out/console-ramoops-0" | head -5 | sed 's/^/       /'
  fi

  # --- the payoff: re-derive every target.h offset and diff it
  local th="$ROOT/cves/targets/$dev-$build/target.h"
  if [ ! -f "$th" ]; then
    warn "no committed target.h at cves/targets/$dev-$build/ — report is informational"
    th=/dev/null
  fi
  # the Image is what resolves PTRMAP/CODEMAP; needs root, so do it here
  "$ROOT/runner/scripts/dump-boot-image.sh" --serial "$S" >/dev/null 2>&1 \
    && ok "Image $(stat -c%s "$out/Image" 2>/dev/null) bytes" \
    || warn "no boot Image — PTRMAP/CODEMAP rows will be UNRESOLVED"

  TH="$th" TH_EXTRA="$ROOT/cves/targets/$dev-$build/cve64560.h" \
  KS="$out/kallsyms.txt" BTF="$out/btf-vmlinux" IMG="$out/Image" \
  SLABINFO="$out/slabinfo.txt" \
    python3 "$ROOT/runner/scripts/lib/offset_report.py" > "$out/offsets.report" 2>&1
  local bad unres
  bad=$(grep -c 'MISMATCH' "$out/offsets.report" 2>/dev/null); bad=${bad:-0}
  unres=$(grep -c 'UNRESOLVED' "$out/offsets.report" 2>/dev/null); unres=${unres:-0}
  sed 's/^/    /' "$out/offsets.report"
  [ "$bad" = "0" ] && ok "offsets.report: no mismatches" \
                   || err "offsets.report: $bad MISMATCH — committed target.h is wrong for this build"
  [ "$unres" = "0" ] || warn "offsets.report: $unres UNRESOLVED — a derivation rule needs updating"
  ok "captured to data/live/$dev-$build/"
}

mkdir -p "$OUTROOT"
if [ -n "$SERIAL" ]; then
  harvest_one "$SERIAL"
else
  mapfile -t serials < <(adb devices | awk '/\tdevice$/{print $1}')
  [ "${#serials[@]}" -gt 0 ] || { err "no devices"; exit 1; }
  for s in "${serials[@]}"; do harvest_one "$s"; done
fi
