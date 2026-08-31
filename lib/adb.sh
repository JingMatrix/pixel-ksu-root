# shellcheck shell=bash
#
# adb.sh — adb transport wrappers and device-state primitives.
#
# All device interaction is driven over `adb shell` from the host, so control
# flow and logs stay on the host side. Requires the globals set by the
# entrypoint: SERIAL, DEV_SU, RUNLOG.

ADB=(adb)
[ -n "${SERIAL:-}" ] && ADB=(adb -s "$SERIAL")

ash()   { "${ADB[@]}" shell "$@"; }
asu()   { ash "$DEV_SU -c \"$*\""; }                 # run a command as root via temp su
apush() { "${ADB[@]}" push "$1" "$2" 2>&1 | tail -1 | tee_log; }
alive() { "${ADB[@]}" get-state >/dev/null 2>&1; }

# Boot identity, for deciding whether a derived KASLR base is still valid.
#
# NOT /proc/sys/kernel/random/boot_id: the Phase A KASLR oracle repoints that
# sysctl's .data at a known kernel address and reads the leaked pointer back out
# of the procfs file (exploit/src/fops.c:restore_slide_boot_id). Sampled while
# redirected — or before the restore lands — it returns attacker-pointed memory,
# not a boot id, so a *correct* base gets discarded and Phase A runs again for
# nothing. Measured on panther 2026-08-31: boot_id read ee78cef3 -> d029a1c5 ->
# ee78cef3 across one uninterrupted 2-day uptime.
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
  for i in $(seq 1 40); do
    [ "$(getprop sys.boot_completed)" = "1" ] && return 0
    sleep 3
  done
  return 1
}

have_root() { asu id 2>/dev/null | strip | grep -q 'uid=0'; }

# KernelSU driver version via the get_version syscall. This needs NO root and
# still answers after late-load enforces SELinux and tears down the temp-su
# daemon, so it is the authority on whether the module is resident. Empty or 0
# means not loaded. $1 is the on-device ksud path.
ksu_version() {
  ash "$1 debug version 2>/dev/null" | strip \
    | grep -oE 'Kernel Version:[[:space:]]*[0-9]+' | grep -oE '[0-9]+$'
}
ksu_loaded() { local v; v=$(ksu_version "$1"); [ -n "$v" ] && [ "$v" != 0 ]; }
