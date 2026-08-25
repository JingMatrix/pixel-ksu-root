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
