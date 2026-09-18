#!/usr/bin/env bash
#
# dump-boot-image.sh — pull the *running* kernel's own `Image` off the device.
#
# For an arm64 Image, file offset == symbol address - _text. So this file turns
# every kallsyms symbol into a readable instruction stream on the host, which is
# the only way to get two classes of offset:
#
#   * static/inlined symbols — the `NO-SYMBOL` rows in offsets.report
#     (ashmem_compat_ioctl, ashmem_misc, copy_splice_read). Invisible to both
#     kallsyms and BTF; plainly visible here.
#   * branch offsets inside a function, e.g. the CVE-2026-64560 race branch at
#     posix_cpu_timer_del+0x128.
#
# Requires root: the partition is brw------- root:root,
# u:object_r:boot_block_device:s0, and shell (uid 2000) gets EACCES. For a first
# root on a new build, offsets come from the public OTA instead — see
# tools/pixel-image/README.md.
#
# ~64 MiB over adb, ~5 s on USB. Cached per <codename>-<build>; --force re-pulls.
#
# Usage: runner/scripts/dump-boot-image.sh [--serial SERIAL] [--force]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTROOT="$ROOT/data/live"
SERIAL="${SERIAL:-}"
FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --serial) SERIAL="$2"; shift 2 ;;
    --force)  FORCE=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m   %s\n' "$*"; }
warn() { printf '  \033[33mwarn\033[0m %s\n' "$*"; }
err()  { printf '  \033[31mfail\033[0m %s\n' "$*"; }

dump_one() {
  local S="$1" A=(adb -s "$1")
  local dev build slot part size out tmp

  dev=$("${A[@]}" shell getprop ro.product.device 2>/dev/null | tr -d '\r')
  build=$("${A[@]}" shell getprop ro.build.id 2>/dev/null | tr -d '\r')
  [ -n "$dev" ] || { err "$S: unreachable"; return 1; }
  step "$dev ($build) — boot image"

  out="$OUTROOT/$dev-$build"
  if [ -s "$out/Image" ] && [ "$FORCE" = "0" ]; then
    ok "already have $out/Image ($(stat -c%s "$out/Image") bytes) — --force to re-pull"
    return 0
  fi

  if ! "${A[@]}" shell 'su -c id' 2>/dev/null | grep -q 'uid=0'; then
    err "no root on $dev — the boot partition is root-only, run ./pixel-ksu-root first"
    return 1
  fi

  # A/B devices carry _a/_b; a non-A/B device has a bare "boot".
  slot=$("${A[@]}" shell getprop ro.boot.slot_suffix 2>/dev/null | tr -d '\r')
  part="/dev/block/by-name/boot$slot"
  size=$("${A[@]}" shell "su -c 'blockdev --getsize64 $part'" 2>/dev/null | tr -d '\r')
  case "$size" in
    ''|*[!0-9]*) err "cannot size $part on $dev (slot='${slot:-none}')"; return 1 ;;
  esac
  ok "active slot '${slot:-none}' -> $part ($((size / 1024 / 1024)) MiB)"

  mkdir -p "$out"
  tmp=$(mktemp "${TMPDIR:-/tmp}/bootimg.XXXXXX")
  # exec-out, not shell: no CRLF mangling on the binary stream.
  if ! "${A[@]}" exec-out "su -c 'dd if=$part bs=1M'" > "$tmp" 2>/dev/null; then
    err "dd failed"; rm -f "$tmp"; return 1
  fi
  if [ "$(stat -c%s "$tmp")" -lt "$size" ]; then
    err "short read: got $(stat -c%s "$tmp") of $size bytes"; rm -f "$tmp"; return 1
  fi
  ok "pulled $(stat -c%s "$tmp") bytes"

  local ks=()
  [ -s "$out/kallsyms.txt" ] && ks=(--kallsyms "$out/kallsyms.txt") \
    || warn "no kallsyms.txt yet — run harvest-live.sh first to get the identity verified"
  if python3 "$ROOT/runner/scripts/lib/boot_image.py" "$tmp" "$out/Image" "${ks[@]}" \
       2>&1 | sed 's/^/       /'; then
    ok "Image -> data/live/$dev-$build/Image"
  else
    err "unpack failed"; rm -f "$tmp"; return 1
  fi
  rm -f "$tmp"
}

mkdir -p "$OUTROOT"
if [ -n "$SERIAL" ]; then
  dump_one "$SERIAL"
else
  mapfile -t serials < <(adb devices | awk '/\tdevice$/{print $1}')
  [ "${#serials[@]}" -gt 0 ] || { err "no devices"; exit 1; }
  for s in "${serials[@]}"; do dump_one "$s"; done
fi
