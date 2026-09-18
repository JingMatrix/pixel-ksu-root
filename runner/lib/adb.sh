# shellcheck shell=bash
#
# adb.sh — adb transport wrappers and device-state primitives.
#
# All device interaction is driven over `adb shell` from the host, so control
# flow and logs stay on the host side. Requires the globals set by the
# entrypoint: SERIAL, DEV_TMP, DEV_TEMP_SU, SETTLE_SECS and RUNLOG.

ADB=(adb)
[ -n "${SERIAL:-}" ] && ADB=(adb -s "$SERIAL")

ash()   { "${ADB[@]}" shell "$@"; }
asu()   { ash "$DEV_TEMP_SU -c \"$*\""; }            # run a command as root via temp su
apush() { "${ADB[@]}" push "$1" "$2" 2>&1 | tail -1 | tee_log; }

# Push, then verify by md5: a stale or short on-device binary fails silently, and
# the classifier can only read it as REFUSED. adb push can be a no-op or leave a
# short file (device full, interrupted transfer, a file another run left
# read-only), and none of those fail loudly. The run stops if the copies differ.
apush_verified() {
  local src="$1" dst="$2" want got
  apush "$src" "$dst"
  # Flush to flash. adb push lands in the page cache, not on disk; a stage that
  # PANICS the kernel (this whole hunt does) is an unclean reboot that discards
  # anything unwritten, reverting dst to whatever the last sync left there -- a
  # STALE binary. Since the runner reboots between shots, an unsynced push is
  # silently rolled back and every shot runs the old bytes. sync makes it durable.
  ash "sync" 2>/dev/null
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

# How long to keep waiting for a device that has gone away. Every shot in this
# tree may panic the kernel, and a panic reboot is a cold boot: the transport is
# absent for as long as that takes, which on an encrypted /data is minutes. The
# alternative -- giving up as soon as adb stops answering -- turns one lost race
# into a run that spends its whole budget in seconds, because every step after it
# fails instantly against a device that is not there and is recorded as a shot
# that never ran.
ADB_PATIENCE="${ADB_PATIENCE:-900}"

# Block until the transport answers again, or the patience budget runs out.
# Waiting is reported so a long boot does not read as a hang. Bounded by elapsed
# wall time, not by iterations, so a transport that fails instantly (adb server
# restarting, device in fastboot) is waited out at the same rate as one that
# blocks.
wait_device() {
  local budget="${1:-$ADB_PATIENCE}" start now waited=0 next=60 said=0
  alive && return 0
  start="$(date +%s)"
  log "  device gone (reboot or panic) — waiting up to ${budget}s for it to come back"
  said=1
  while :; do
    timeout 10 "${ADB[@]}" wait-for-device >/dev/null 2>&1
    if alive; then
      waited=$(( $(date +%s) - start ))
      log "  device back after ${waited}s"
      return 0
    fi
    sleep 1
    now="$(date +%s)"; waited=$(( now - start ))
    [ "$waited" -ge "$budget" ] && break
    if [ "$waited" -ge "$next" ]; then
      log "  still waiting for the device (${waited}s of ${budget}s)"
      next=$(( next + 60 ))
    fi
  done
  warn "device did not reappear within ${budget}s"
  return 1
}

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
  wait_device || return 1
  local i
  # shellcheck disable=SC2034  # loop counter only
  for i in $(seq 1 "${BOOT_WAIT:-240}"); do
    [ "$(getprop sys.boot_completed)" = "1" ] && return 0
    # The device can vanish again while booting -- a second panic, a USB
    # re-enumeration -- and a poll that fails for that reason is not a boot that
    # failed. Wait the transport back and keep polling.
    alive || wait_device || return 1
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
  wait_device || return 1
  local i
  for i in $(seq 1 "${BOOT_WAIT:-240}"); do
    # Write a token and read it back: proves the shell answers and /data is
    # mounted writable, which is all a shot needs.
    if [ "$(ash "echo rdy > $DEV_TMP/.ready 2>/dev/null; cat $DEV_TMP/.ready 2>/dev/null; rm -f $DEV_TMP/.ready" 2>/dev/null | tr -d '\r\n')" = "rdy" ]; then
      return 0
    fi
    alive || wait_device || return 1
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

# Fixed persistent-su install locations, shared by every root probe in this
# tree (root_su() below, install.sh's teardown_root_su()). A bare `su` is
# deliberately not part of this shared list: it resolves through whatever is
# first on PATH, which can be a transient shadow rather than a persistent
# install -- a caller that means "any su, including a PATH-resolved one"
# appends it itself.
SU_CANDIDATE_PATHS="/system/bin/su /product/bin/su /system/xbin/su /system_ext/bin/su /debug_ramdisk/su"

# Resolve an su on the device that answers as root, or empty. Probe common
# Android locations and the shell PATH rather than assuming one manager path.
# Retry briefly because a just-loaded manager may install its su after the
# driver comes up. Used by steps that need root they did not obtain themselves.
root_su() {
  local i su
  for i in $(seq 1 "${1:-1}"); do
    for su in $SU_CANDIDATE_PATHS su; do
      # Bounded, not a bare ash call: this is also called from the abort/
      # interrupt path (pixel-ksu-root's _abort(), exploit.sh's
      # kill_remote_payload()) to kill a stalled payload -- exactly the
      # moment a wedged kernel (a task stuck in kprobe (de)registration's
      # stop_machine rendezvous, see cves/lib/rw/kprobe_read.h) makes this
      # same probe hang forever. A timeout here cannot rescue that wedge --
      # nothing userspace can -- but it keeps the abort/kill path itself
      # from hanging on top of it instead of returning failure and letting
      # the caller give up cleanly.
      if timeout 5 "${ADB[@]}" shell "$su -c id" 2>/dev/null | strip | grep -q 'uid=0'; then
        printf '%s' "$su"; return 0
      fi
    done
    [ "$i" -lt "${1:-1}" ] && sleep 1
  done
  return 1
}

# Wait for an su that answers as root, patiently, and print its path.
#
# root_su probes once and is right to: it is also called from the abort path,
# where hanging is worse than failing. A shot loop is the opposite case. Root
# here is per-boot and arrives late -- after a reboot the transport answers well
# before the manager has started its daemon -- so the first probes legitimately
# find nothing, and treating that as "no root on this device" abandons a run over
# a few seconds of boot. Logs go to stderr: callers read stdout for the su path.
# The budget covers the wait for ROOT; a device that is away is waited out
# separately, at ADB_PATIENCE, because "no transport" and "no su yet" are
# different things to be patient about.
ROOT_WAIT="${ROOT_WAIT:-120}"
wait_root() {
  local budget="${1:-$ROOT_WAIT}" start now waited=0 su said=0
  wait_device >&2 || return 1
  start="$(date +%s)"
  while :; do
    if su="$(root_su 1 2>/dev/null)"; then
      [ "$said" = 1 ] && log "  root answered after $(( $(date +%s) - start ))s" >&2
      printf '%s' "$su"; return 0
    fi
    alive || wait_device >&2 || return 1
    now="$(date +%s)"; waited=$(( now - start ))
    [ "$waited" -ge "$budget" ] && return 1
    if [ "$said" = 0 ]; then
      log "  no su answers yet — waiting up to ${budget}s for root to come back" >&2
      said=1
    fi
    sleep 2
  done
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
