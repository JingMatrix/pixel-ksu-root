# shellcheck shell=bash
#
# install.sh — derive ksud from the installed manager, late-load the module, verify.
#
# The kernelsu.ko is signature-locked to the manager built in the same release:
# ksud MUST come from the *installed* manager's APK. A mismatched copy loads the
# module but the module refuses to authorize the manager (no MANAGER flag bit),
# leaving the device with no usable root. Requires globals: MANAGER_PKG KMI
# DEV_TMP DEV_KSUD DEV_SU WORKDIR VERIFY_TRIES.

# Print the runtime uid of an installed package, empty if not installed.
manager_uid() {
  ash "pm list packages -U 2>/dev/null" | tr -d '\r' \
    | grep -E "package:$1 uid:[0-9]+" | grep -oE 'uid:[0-9]+' | head -1 | cut -d: -f2
}

# Auto-detect an installed KernelSU manager. A manager ships the ksud native
# library, so scan third-party packages and report the first whose APK contains
# lib/arm64-v8a/libksud.so. This pulls each candidate APK to inspect it host
# side, so it is slow; set MANAGER_PKG to skip it. Prints the package name.
detect_manager() {
  local pkg apk pkgs=()
  # Read the whole list up front. `adb shell` keeps stdin attached, so calling
  # ash inside a `while read ... done < <(...)` loop drains the package list on
  # the first iteration and the scan silently stops after one package.
  mapfile -t pkgs < <(ash "pm list packages -3 2>/dev/null" | tr -d '\r')
  for pkg in "${pkgs[@]}"; do
    pkg=${pkg#package:}
    [ -n "$pkg" ] || continue
    apk=$(ash "pm path $pkg 2>/dev/null" | tr -d '\r' | sed -n 's/^package://p' | head -1)
    [ -n "$apk" ] || continue
    "${ADB[@]}" pull "$apk" "$WORKDIR/probe.apk" >/dev/null 2>&1 </dev/null || continue
    if unzip -l "$WORKDIR/probe.apk" 'lib/arm64-v8a/libksud.so' >/dev/null 2>&1; then
      rm -f "$WORKDIR/probe.apk"
      printf '%s\n' "$pkg"
      return 0
    fi
    rm -f "$WORKDIR/probe.apk"
  done
  return 1
}

# Extract libksud.so from the manager's APK and stage it on the device as ksud.
derive_ksud() {
  local apk
  apk=$(ash "pm path $MANAGER_PKG 2>/dev/null" | tr -d '\r' | sed -n 's/^package://p' | head -1)
  [ -n "$apk" ] || { err "manager $MANAGER_PKG not installed — cannot derive a matching ksud"; return 1; }

  "${ADB[@]}" pull "$apk" "$WORKDIR/mgr.apk" >/dev/null 2>&1 || { err "cannot pull manager APK"; return 1; }
  unzip -o -q "$WORKDIR/mgr.apk" 'lib/arm64-v8a/libksud.so' -d "$WORKDIR" \
    || { err "manager APK has no lib/arm64-v8a/libksud.so"; return 1; }

  # KSUD_HOST keeps the extracted copy addressable for the rest of the run, so a
  # device copy destroyed later can be replaced without re-deriving it.
  KSUD_HOST="$WORKDIR/lib/arm64-v8a/libksud.so"
  apush_verified "$KSUD_HOST" "$DEV_KSUD" || return 1
  ash "chmod 755 $DEV_KSUD" 2>/dev/null
  ok "ksud (from manager): $(ash "$DEV_KSUD --version" | strip | tr -d '\r')"
}

# Stage ksud as root, late-load the module for the resolved KMI, verify it live.
install_ksu() {
  step "Stage ksud as root"
  # ksud was pushed before the exploit ran, and obtaining root can cost several
  # kernel panics. A panic reboots without flushing the filesystem, so a file
  # written shortly beforehand comes back the right SIZE with its data blocks
  # never committed -- all NUL. Staging that and loading it wastes a root that
  # was already won, silently: the loader prints nothing and the driver never
  # answers. So the copy is re-checked here, against the host bytes, and
  # replaced if the device's copy no longer matches.
  if [ -n "${KSUD_HOST:-}" ] && [ -f "$KSUD_HOST" ]; then
    local want got
    want="$(md5sum "$KSUD_HOST" 2>/dev/null | awk '{print $1}')"
    got="$(ash "md5sum $DEV_KSUD 2>/dev/null" | tr -d '\r' | awk '{print $1}')"
    if [ -n "$want" ] && [ "$want" != "$got" ]; then
      warn "  ksud on the device no longer matches the host copy (a panic reboot loses unflushed writes)"
      warn "  host $want / device ${got:-<absent>} — re-pushing"
      apush_verified "$KSUD_HOST" "$DEV_KSUD" || return 1
      ash "chmod 755 $DEV_KSUD" 2>/dev/null
    fi
  fi
  asu "cp $DEV_KSUD $DEV_TMP/ksud-staged && chmod 755 $DEV_TMP/ksud-staged && chown root:root $DEV_TMP/ksud-staged"
  local staged="$DEV_TMP/ksud-staged"
  asu "ls -l $staged" | strip | tee_log

  step "late-load (kmi=$KMI, package-name=$MANAGER_PKG)"
  # Capture the loader's own status and output. Piping it straight to tee_log
  # made $? the pipeline's, so a loader that never ran looked the same as one
  # that succeeded, and the run went on to blame the driver.
  local ll_out ll_rc
  # Capture first, strip second: `$?` after a pipeline is the LAST command's
  # status, so stripping inside the substitution would hand us strip's 0.
  ll_out="$(asu "$staged late-load --kmi $KMI --package-name $MANAGER_PKG" 2>&1)"
  ll_rc=$?
  ll_out="$(printf '%s' "$ll_out" | strip)"
  [ -n "$ll_out" ] && printf '%s\n' "$ll_out" | tee_log
  # A successful late-load says nothing, so silence is not news. It is only
  # worth reporting if the driver then fails to come up.
  if [ "$ll_rc" -ne 0 ]; then
    err "  late-load exited $ll_rc"
  fi

  # late-load daemonizes and enforces SELinux in its child, which tears down the
  # temp-su daemon. Verification therefore uses the get_version syscall from a
  # plain shell (no su), never the temporary-root daemon.
  step "Verify via kernel driver (get_version syscall, plain shell — no su)"
  local i ver raw=""
  for i in $(seq 1 "${VERIFY_TRIES:-30}"); do
    ver=$(ksu_version "$DEV_KSUD")
    if [ -n "$ver" ] && [ "$ver" != 0 ]; then
      ok "KernelSU driver live: version=$ver (try $i)"
      # KSU_VER is consumed by the entrypoint's report.
      # shellcheck disable=SC2034
      KSU_VER="$ver"
      return 0
    fi
    # A zero means the module is absent OR the probe itself could not run --
    # SELinux is enforcing again by now and root is gone. Capture the probe's
    # real output once so the two can be told apart. It is only PRINTED if the
    # run goes on to fail: on a good run the module simply is not resident yet
    # for a second or two, and saying so mid-load reads as an error.
    if [ "$i" = 1 ]; then
      raw="$(ash "$DEV_KSUD debug version 2>&1" | strip | head -3)"
      [ -n "$raw" ] || raw="(no output at all)"
    fi
    [ $(( i % 5 )) = 0 ] && log "  probe $i/${VERIFY_TRIES:-30}: version=${ver:-0}"
    sleep 1
  done
  err "  driver never reported a version in ${VERIFY_TRIES:-30} probes"
  [ -z "$ll_out" ] && err "  late-load itself printed nothing and exited $ll_rc"
  [ -n "$raw" ] && err "  last probe output: $raw"
  err "  module load errors, if the kernel logged any:"
  ash "dmesg 2>/dev/null | grep -iE 'kernelsu|ksu|module' | tail -5" | strip \
    | while read -r l; do [ -n "$l" ] && err "    $l"; done
  return 1
}

# --------------------------------------------------------------- teardown -----
# The exploit stages its temporary su at $SU_SHADOW_DIR/su, on a tmpfs it mounts
# over that apex bin dir (cves/cve-2026-43499-ghostlock/preload.c:ensure_su_mount),
# and it does so inside *adbd's* mount namespace so `adb shell` sees it. That directory precedes
# /system/bin in the shell PATH, so the temp su shadows every other `su` for the
# rest of the boot. Late-load tears the temp-su daemon down but leaves the binary
# and the mount behind. A plain `adb shell su` then execs an orphaned
# client whose daemon is gone and fails with "connect daemon: Permission denied",
# which reads as "root is broken" even though the driver is live and the manager
# has root. The tmpfs also hides the apex's real binaries (crosvm, virtmgr, vm,
# fd_server, ...), leaving AVF/Terminal broken until the mount is dropped.
#
# Requires globals: DEV_SU DEV_KSU_SU DEV_TMP SU_SHADOW_DIR.

# True while something is mounted over the apex bin dir. adb shell inherits
# adbd's mount namespace — the namespace holding the mount — so /proc/self is
# the correct view, and reading it needs no root.
su_shadow_mounted() {
  ash "grep -q ' $SU_SHADOW_DIR ' /proc/self/mountinfo" >/dev/null 2>&1
}

# Drop the staging mount and the dead temp-su leftovers. Best-effort: a failure
# here costs the user a stale `su` in PATH, not root, so it never fails the run.
#
# The su that answers as root at teardown must be a REAL, persistent su, never
# bare `su`: while the shadow is still up, bare `su` resolves through it to the
# exploit's temp su, whose daemon late-load is tearing down right now. It can
# still answer `id` for the moment its daemon is alive and then be dead by the
# umount a beat later ("su: connect daemon: Permission denied") -- and using the
# temp su to unmount the temp su is self-defeating anyway. So only the fixed
# paths are candidates: KernelSU's su and the debug-ramdisk su. ksud installs
# KernelSU's su a moment after the driver reports its version, so retry until it
# appears rather than falling back to the dying temp su. Empty when none answers.
teardown_root_su() {
  local i su
  for i in $(seq 1 10); do
    for su in "$DEV_KSU_SU" /debug_ramdisk/su; do
      if ash "$su -c id" 2>/dev/null | strip | grep -q 'uid=0'; then
        printf '%s' "$su"; return 0
      fi
    done
    sleep 1
  done
  return 1
}

teardown_staging() {
  step "Teardown exploit staging (drop the $SU_SHADOW_DIR PATH shadow)"

  local su
  su="$(teardown_root_su)" || {
    warn "no su answers as root at teardown — leaving staging in place"
    warn "  once KernelSU's su is up:  adb shell $DEV_KSU_SU -c 'umount $SU_SHADOW_DIR'"
    return 0
  }
  [ "$su" = "$DEV_KSU_SU" ] || log "  unmounting through $su"

  if ! su_shadow_mounted; then
    ok "no $SU_SHADOW_DIR shadow present"
  else
    # The exploit stacks a tmpfs over the apex bin dir, sometimes more than once.
    # The plain umount reports EBUSY while adbd still sits in the dir; the lazy
    # detach clears one layer, so loop until the dir is free. A failed pass is not
    # final -- with a working /system/bin/su in hand, EBUSY clears once adbd moves
    # on -- so on any remaining shadow just sleep 1s and try again. Output is only
    # worth showing if it is still shadowed at the end.
    local i out=""
    for i in $(seq 1 6); do
      su_shadow_mounted || break
      out="$(ash "$su -c 'umount $SU_SHADOW_DIR'" 2>&1 | strip)"
      su_shadow_mounted || break
      out="$(ash "$su -c 'umount -l $SU_SHADOW_DIR'" 2>&1 | strip)"
      su_shadow_mounted || break
      sleep 1
    done

    if su_shadow_mounted; then
      [ -n "$out" ] && warn "  last umount said: $out"
      warn "could not unmount $SU_SHADOW_DIR — 'adb shell su' will keep reaching the"
      warn "exploit's temp su. Clear it manually with:"
      warn "  adb shell $su -c 'umount $SU_SHADOW_DIR'"
    else
      ok "$SU_SHADOW_DIR shadow removed"
    fi
  fi

  # Dead weight once the daemon is gone: the local temp-su client, its socket
  # and its log (paths fixed in cves/cve-2026-43499-ghostlock/preload.c).
  local leftovers="$DEV_SU $DEV_TMP/temp_su.sock $DEV_TMP/su_daemon.log"
  ash "$su -c 'rm -f $leftovers'" >/dev/null 2>&1
  ash "rm -f $leftovers" >/dev/null 2>&1

  # Report the su a plain adb shell now resolves — this is how a user tests
  # root, so it is the check worth printing.
  local resolved
  resolved=$(ash 'command -v su 2>/dev/null' | strip | tr -d '\r')
  log "adb shell resolves su -> ${resolved:-<none>}"
  [ "$resolved" = "$SU_SHADOW_DIR/su" ] \
    && warn "'su' in adb shell still resolves to the exploit's temp su, not KernelSU's"
  return 0
}
