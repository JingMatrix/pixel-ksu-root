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
  local pkg apk
  while read -r pkg; do
    pkg=${pkg#package:}
    [ -n "$pkg" ] || continue
    apk=$(ash "pm path $pkg 2>/dev/null" | tr -d '\r' | sed -n 's/^package://p' | head -1)
    [ -n "$apk" ] || continue
    "${ADB[@]}" pull "$apk" "$WORKDIR/probe.apk" >/dev/null 2>&1 || continue
    if unzip -l "$WORKDIR/probe.apk" 'lib/arm64-v8a/libksud.so' >/dev/null 2>&1; then
      rm -f "$WORKDIR/probe.apk"
      printf '%s\n' "$pkg"
      return 0
    fi
    rm -f "$WORKDIR/probe.apk"
  done < <(ash "pm list packages -3 2>/dev/null" | tr -d '\r')
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

  apush "$WORKDIR/lib/arm64-v8a/libksud.so" "$DEV_KSUD"
  ash "chmod 755 $DEV_KSUD" 2>/dev/null
  ok "ksud (from manager): $(ash "$DEV_KSUD --version" | strip | tr -d '\r')"
}

# Stage ksud as root, late-load the module for the resolved KMI, verify it live.
install_ksu() {
  step "Stage ksud as root"
  asu "cp $DEV_KSUD $DEV_TMP/ksud-staged && chmod 755 $DEV_TMP/ksud-staged && chown root:root $DEV_TMP/ksud-staged"
  local staged="$DEV_TMP/ksud-staged"
  asu "ls -l $staged" | strip | tee_log

  step "late-load (kmi=$KMI, package-name=$MANAGER_PKG)"
  asu "$staged late-load --kmi $KMI --package-name $MANAGER_PKG" 2>&1 | strip | tee_log

  # late-load daemonizes and enforces SELinux in its child, which tears down the
  # temp-su daemon. Verification therefore uses the get_version syscall from a
  # plain shell (no su), never the temporary-root daemon.
  step "Verify via kernel driver (get_version syscall, plain shell — no su)"
  local i ver
  for i in $(seq 1 "${VERIFY_TRIES:-30}"); do
    ver=$(ksu_version "$DEV_KSUD")
    if [ -n "$ver" ] && [ "$ver" != 0 ]; then
      ok "KernelSU driver live: version=$ver (try $i)"
      # KSU_VER is consumed by the entrypoint's report.
      # shellcheck disable=SC2034
      KSU_VER="$ver"
      return 0
    fi
    log "  probe $i/${VERIFY_TRIES:-30}: version=${ver:-0}"; sleep 1
  done
  return 1
}

# --------------------------------------------------------------- teardown -----
# The exploit stages its temporary su at $SU_SHADOW_DIR/su, on a tmpfs it mounts
# over that apex bin dir (exploit/src/preload.c:ensure_su_mount), and it does so
# inside *adbd's* mount namespace so `adb shell` sees it. That directory precedes
# /system/bin in the shell PATH, so the temp su shadows every other `su` for the
# rest of the boot — deliberate while the exploit is driving, wrong afterwards:
# late-load tears the temp-su daemon down (docs/DESIGN.md §6.2) but leaves the
# binary and the mount behind. A plain `adb shell su` then execs an orphaned
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
teardown_staging() {
  step "Teardown exploit staging (drop the $SU_SHADOW_DIR PATH shadow)"

  if ! su_shadow_mounted; then
    ok "no $SU_SHADOW_DIR shadow present"
  else
    # The temp-su daemon died with late-load, so its su cannot serve this
    # umount: it has to go through KernelSU's own su. A repeated run can stack
    # mounts on the same dir, so unmount until the dir is clear.
    local i
    for i in $(seq 1 5); do
      ash "$DEV_KSU_SU -c 'umount $SU_SHADOW_DIR'" 2>&1 | strip | tee_log
      su_shadow_mounted || break
    done

    if su_shadow_mounted; then
      warn "could not unmount $SU_SHADOW_DIR — 'adb shell su' will keep reaching the"
      warn "orphaned temp su ('connect daemon: Permission denied') and the apex's own"
      warn "binaries stay hidden. Clear it manually with:"
      warn "  adb shell $DEV_KSU_SU -c 'umount $SU_SHADOW_DIR'"
      warn "A reboot also clears it — the shadow is a tmpfs, not a persistent change."
    else
      ok "$SU_SHADOW_DIR shadow removed"
    fi
  fi

  # Dead weight once the daemon is gone: the local temp-su client, its socket
  # and its log (paths fixed in exploit/src/preload.c). The exploit created them
  # as root, so a plain shell cannot unlink them all — go through su first, then
  # let the shell clear whatever it owns if su was unavailable.
  local leftovers="$DEV_SU $DEV_TMP/temp_su.sock $DEV_TMP/su_daemon.log"
  ash "$DEV_KSU_SU -c 'rm -f $leftovers'" >/dev/null 2>&1
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
