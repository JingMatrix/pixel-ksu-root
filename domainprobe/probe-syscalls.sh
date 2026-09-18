#!/usr/bin/env bash
#
# probe-syscalls.sh — confirm one wrapper-less syscall in system_server per boot.
#
# system_server's seccomp is KILL-based, so calling a blocked syscall reboots the
# device (and erases logcat). This drives ONE syscall index per boot: it sets the
# toggle, triggers the system_server probe, and records either the "sc[i]" result
# (reached) or, if the device reboots without logging it, "SIGSYS-kill (blocked)".
#
# Usage:  ./probe-syscalls.sh [firstIndex] [lastIndex]      (default 0 13)
# The debug.dp.* props are non-persistent (reset on reboot) and are re-set each boot.
set -uo pipefail
PKG=dev.pixelksu.domainprobe
FIRST=${1:-0}; LAST=${2:-13}
# canonical order, matches JavaProbe scName[] / native run_all()
NAMES=(userfaultfd "add_key(user)" "add_key(user 240B)" keyctl mq_open "msgget(sysvipc)" \
       io_uring_setup perf_event_open "bpf(MAP_CREATE)" "ptrace(TRACEME)" \
       process_vm_readv pidfd_open "unshare(NEWUSER)" landlock)

boot() { adb wait-for-device; until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do sleep 3; done; sleep 3; }

for i in $(seq "$FIRST" "$LAST"); do
    boot
    adb shell setprop debug.dp.sctest 1
    adb shell setprop debug.dp.scidx "$i"
    adb logcat -c
    adb shell am start -n $PKG/.MainActivity >/dev/null 2>&1; sleep 3
    adb shell am broadcast -a $PKG.TELECOM -f 0x20 $PKG/.ProbeReceiver >/dev/null 2>&1
    row=""
    for t in $(seq 1 30); do
        # completed run?  grab the row.
        if adb shell true 2>/dev/null; then
            # the "SCONE <i> survived" breadcrumb is logged only if the syscall returned
            r=$(adb logcat -d -s domainprobe 2>/dev/null | sed -E 's/^.*domainprobe: //' | grep -m1 "SCONE $i survived")
            [ -n "$r" ] && { row="${NAMES[$i]}   $r"; break; }
        else
            row="sc[$i] ${NAMES[$i]}   SIGSYS-KILL (device rebooted) = BLOCKED"; break
        fi
        sleep 1
    done
    [ -z "$row" ] && row="sc[$i] ${NAMES[$i]}   no result in 30s (likely SIGSYS-kill / rebooting)"
    printf '%s\n' "$row" | tee -a /tmp/dp-syscall-results.txt
    adb reboot >/dev/null 2>&1   # fresh system_server for the next index (also recovers from a kill)
done
echo "--- all recorded in /tmp/dp-syscall-results.txt ---"
