# shellcheck shell=bash
#
# install.sh — derive ksud from the installed manager, late-load the module, verify.
#
# The kernelsu.ko is signature-locked to the manager built in the same release:
# ksud MUST come from the *installed* manager's APK. A mismatched copy loads the
# module but the module refuses to authorize the manager (no MANAGER flag bit),
# leaving the device with no usable root. Requires globals: MANAGER_PKG KMI
# DEV_TMP DEV_KSUD DEV_TEMP_SU WORKDIR VERIFY_TRIES.

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

# Push a locally-built .ko (CUSTOM_KSU_MODULE) and load it with ksud's own
# `insmod` subcommand instead of deriving a module from the installed
# manager's late-load path. `insmod` runs none of late-load's boot-pipeline
# steps (init.rc stage scripts, module directory scan, sepolicy.rule
# loading) -- it only calls the same kallsyms-relocating loader late-load
# itself uses (ksuinit::load_module()) on the file handed to it, resolving
# undefined symbols against live kallsyms and retrying past a vermagic
# mismatch. That is the same driver-comes-up question this project verifies
# either way; a manager's own userspace features it might also install are
# out of scope for what a custom kernel-only module needs to prove.
install_ksu_custom_module() {
  step "Push custom KernelSU module ($CUSTOM_KSU_MODULE)"
  [ -f "$CUSTOM_KSU_MODULE" ] || { err "  file not found: $CUSTOM_KSU_MODULE"; return 1; }
  local dev_ko="$DEV_TMP/custom-kernelsu.ko"
  apush_verified "$CUSTOM_KSU_MODULE" "$dev_ko" || return 1

  # LATE_LOAD_STAGE_PATH (su.h): the fixed path su_daemon.c's --insmod
  # request (run_s25u_insmod(), same file) execs from -- install_ksu()'s own
  # late-load branch stages it here too, but that branch does not run for a
  # custom module, so it has to happen here instead.
  local staged="$DEV_TMP/ksud-late-load"
  asu "cp $DEV_KSUD $staged && chmod 755 $staged && chown root:root $staged"

  step "insmod ($(basename "$CUSTOM_KSU_MODULE")${CUSTOM_KSU_MODULE_PARAMS:+ $CUSTOM_KSU_MODULE_PARAMS})"
  # Same DEFEX-safeplace bypass install_ksu()'s late-load branch uses, and
  # for the identical reason (see that function's own comment): a fresh
  # execve of anything under /data/local/tmp, already as root, is denied by
  # Samsung's DEFEX on the one target that declares
  # properties.defex_shadow_path (task_defex_safeplace(),
  # security/samsung/defex_lsm/core/defex_main.c), which kills the calling
  # process (pstore: "DFEX Safeplace violation [task=sh ..., child=.../
  # ksud-manager, uid=0]", exit 137). asu's plain `su -c "<cmd>"` is exactly
  # that fresh execve and hits the check directly. su_daemon.c's own
  # --insmod request bind-mounts the staged ksud over
  # ENTRY_DEFEX_SHADOW_PATH inside a private mount namespace and execs from
  # there instead, the same way --late-load does; reaching it means calling
  # $DEV_TEMP_SU directly with this argv, not through asu.
  #
  # A crash inside insmod's module_init reaches a hard panic before pstore's
  # console-ramoops zone -- a fixed-size ring buffer, kept overwriting through
  # the whole panic-notifier/shutdown cascade after the initial oops. Whether
  # it still holds the crash's own head (PC/registers/call trace) by the time
  # that cascade stops depends on how long the cascade runs: a short one
  # leaves the head intact (possibly corrupted but legible), a long enough one
  # wraps the ring and overwrites it with trailing noise. Reading the live
  # kernel log during the window before the panic (dmesg/klogctl) depends on
  # CAP_SYSLOG and a syslog-read SELinux permission, neither of which is
  # granted by default to the domain --insmod's request runs under, so it is
  # no more trustworthy a channel than pstore without first proving that --
  # rather than spend a shot
  # proving it, the module writes its own diagnostic straight to a plain file
  # under $DEV_TMP with an fsync before reaching the call that crashes: an
  # ordinary file write under a path this whole install already reads and
  # writes freely, durable on storage (not just RAM) before the panic, so
  # $dbg_log below is just read back post-reboot like any other artifact.
  local dbg_log="$DEV_TMP/ksu-debug.log"
  ash "rm -f $dbg_log" >/dev/null 2>&1

  local il_out il_rc
  il_out="$(ash "DEFEX_SHADOW_PATH=${ENTRY_DEFEX_SHADOW_PATH:-} $DEV_TEMP_SU --insmod $dev_ko $CUSTOM_KSU_MODULE_PARAMS" 2>&1)"
  il_rc=$?

  local dbg_out
  dbg_out="$(ash "cat $dbg_log" 2>/dev/null)"
  if [ -n "$dbg_out" ]; then
    ok "  module diagnostic ($dbg_log):"
    printf '%s\n' "$dbg_out" | tee_log
  fi

  il_out="$(printf '%s' "$il_out" | strip)"
  [ -n "$il_out" ] && printf '%s\n' "$il_out" | tee_log
  if [ "$il_rc" -ne 0 ]; then
    err "  insmod exited $il_rc"
    return 1
  fi

  # --insmod loaded our module but ran NONE of ksud's userspace setup (the
  # working dir /data/adb/ksu, binaries, sepolicy) that the normal late-load
  # path does. Run --late-load now: ksud sees KSU already resident
  # (has_kernelsu() in late_load.rs), SKIPS the module load, and performs exactly
  # that setup, through the same DEFEX-safeplace bind-mount bypass (a plain
  # `su -c ksud` is killed: "[DEFEX] Safeplace violation ... child=.../ksud").
  # Without /data/adb/ksu the driver's do_persistent_allow_list() cannot create
  # /data/adb/ksu/.allowlist, so the manager reports "impossible to grant root".
  step "ksud userspace setup (--late-load; module already resident)"
  local late_load_kmi="${ENTRY_LATE_LOAD_KMI_OVERRIDE:-$KMI}"
  local sl_out sl_rc
  sl_out="$(ash "DEFEX_SHADOW_PATH=${ENTRY_DEFEX_SHADOW_PATH:-} LATE_LOAD_KMI=$late_load_kmi LATE_LOAD_MANAGER_PKG=$MANAGER_PKG $DEV_TEMP_SU --late-load" 2>&1)"
  sl_rc=$?
  sl_out="$(printf '%s' "$sl_out" | strip)"
  [ -n "$sl_out" ] && printf '%s\n' "$sl_out" | tee_log
  if ash "$DEV_TEMP_SU -c 'test -d /data/adb/ksu'" >/dev/null 2>&1; then
    ok "  /data/adb/ksu present — grant/allowlist can persist"
  else
    warn "  /data/adb/ksu still missing after --late-load (rc=$sl_rc) — manager may not grant root"
  fi
}

# Stage ksud as root, late-load the module for the resolved KMI, verify it live.
install_ksu() {
  if [ -n "${CUSTOM_KSU_MODULE:-}" ]; then
    install_ksu_custom_module || return 1
  else
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
    # LATE_LOAD_STAGE_PATH (cve-2026-43499-ghostlock/su.h): the exact path
    # su_daemon.c's own late-load path (run_s25u_late_load(), triggered below)
    # execs, manufacturer-agnostic. If this target's own recipe stage declares
    # properties.defex_shadow_path (ENTRY_DEFEX_SHADOW_PATH), that path gets
    # this bind-mounted over it first, inside a private mount namespace it
    # opens for itself -- not this shell's namespace, so nothing here needs to
    # mount or unmount anything either way.
    local staged="$DEV_TMP/ksud-late-load"
    asu "cp $DEV_KSUD $staged && chmod 755 $staged && chown root:root $staged"
    asu "ls -l $staged" | strip | tee_log
  
    step "late-load (kmi=$KMI, package-name=$MANAGER_PKG)"
    # A target whose recipe stage declares properties.defex_shadow_path is
    # naming a vendor LSM's own execve whitelist entry (Samsung's DEFEX
    # safeplace feature, security/samsung/defex_lsm/core/defex_main.c,
    # task_defex_safeplace(), on the only target that declares one so far)
    # that denies execve of anything outside that fixed, compiled-in
    # whitelist once the calling task is already root -- exactly this step.
    # Reaching it through asu's normal `su -c "<cmd>"` path hits that check
    # directly, since $staged is not on the whitelist.
    #
    # su_daemon.c's own client protocol already has the way around this:
    # serve_one() special-cases a request whose only argument is "--late-load"
    # (run_s25u_late_load(), ported from Root-My-Galaxy's S25U build) into
    # opening a private mount namespace, bind-mounting $staged onto
    # $ENTRY_DEFEX_SHADOW_PATH -- which *is* on the whitelist -- inside that
    # private namespace only, and exec'ing it from there. That bypass is real
    # (a genuine bind mount via the mount(2) syscall, not a shell/toybox
    # invocation) and self-contained (nothing outside its own namespace ever
    # sees the mount, so there is nothing for this script to clean up
    # afterward). su_daemon.c carries no knowledge of this path itself --
    # it is a single, target-independent build shared by every target
    # (runner/stages/handoff.suhelper/stage.toml) -- so it is handed over as
    # an env var on the su client's own environment, which the daemon
    # forwards from request to fork the same way it already does for a
    # normal command. Empty (a target with no such property) makes
    # run_s25u_late_load() skip the mount and exec $staged directly.
    #
    # Triggering run_s25u_late_load() at all means calling $DEV_TEMP_SU
    # directly with that one argument -- NOT through asu, whose
    # `-c "<cmd>"` wrapping sends a different argv shape that would not
    # match serve_one()'s check.
    #
    # LATE_LOAD_KMI/LATE_LOAD_MANAGER_PKG: ksud's own KMI auto-detect (called when
    # --kmi is omitted) reads a marker that only exists when the device
    # booted through a KernelSU-patched boot image -- never true here, since
    # this is the stock boot image, rooted live by the exploit -- so
    # auto-detect has nothing to find, and ksud reports that it could not get
    # the KMI from the boot image or its modules. Passing both explicitly,
    # the same way as DEFEX_SHADOW_PATH above, means ksud never has to guess.
    #
    # ENTRY_LATE_LOAD_KMI_OVERRIDE (properties.late_load_kmi_override) sends
    # ksud a *different* KMI than $KMI, the real one this run detected, on a
    # target whose actual KMI no manager release channel ships a module for
    # (qgki-5.4: see that stage's own comment). Empty on every other target,
    # so $KMI passes through unchanged.
    local late_load_kmi="${ENTRY_LATE_LOAD_KMI_OVERRIDE:-$KMI}"
    local ll_out ll_rc
    ll_out="$(ash "DEFEX_SHADOW_PATH=${ENTRY_DEFEX_SHADOW_PATH:-} LATE_LOAD_KMI=$late_load_kmi LATE_LOAD_MANAGER_PKG=$MANAGER_PKG $DEV_TEMP_SU --late-load" 2>&1)"
    ll_rc=$?
    ll_out="$(printf '%s' "$ll_out" | strip)"
    [ -n "$ll_out" ] && printf '%s\n' "$ll_out" | tee_log
    # A successful late-load says nothing, so silence is not news. It is only
    # worth reporting if the driver then fails to come up.
    if [ "$ll_rc" -ne 0 ]; then
      err "  late-load exited $ll_rc"
    fi
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
  # ll_out/ll_rc are late-load's own locals, declared only in install_ksu()'s
  # other branch -- unset here on a custom-module run, where there is no
  # late-load output to report on anyway.
  if [ -z "${CUSTOM_KSU_MODULE:-}" ]; then
    [ -z "$ll_out" ] && err "  late-load itself printed nothing and exited $ll_rc"
  fi
  [ -n "$raw" ] && err "  last probe output: $raw"
  err "  module load errors, if the kernel logged any:"
  ash "dmesg 2>/dev/null | grep -iE 'kernelsu|ksu|module' | tail -5" | strip \
    | while read -r l; do [ -n "$l" ] && err "    $l"; done
  # ksud's own diagnostics -- including init_module()'s real failure text,
  # which ksuinit reads back from /dev/kmsg and logs itself when the module
  # fails to load for any reason other than a vermagic mismatch -- go to
  # logcat under its own tag, never to dmesg (dmesg is kernel printk only;
  # this is a userspace app's log). The block above has never once shown
  # anything but unrelated wlan/icnss noise because of that mismatch.
  err "  ksud's own log (logcat tag \"KernelSU Next\"), if it said anything:"
  "${ADB[@]}" logcat -d -s "KernelSU Next:V" 2>/dev/null | tail -40 | strip \
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
# Requires globals: DEV_TEMP_SU DEV_TMP SU_SHADOW_DIR.

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
    for su in $SU_CANDIDATE_PATHS; do
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
    warn "  once the manager su is up:  adb shell <su-path> -c 'umount $SU_SHADOW_DIR'"
    return 0
  }
  log "  unmounting through $su"

  if ! su_shadow_mounted; then
    ok "no $SU_SHADOW_DIR shadow present"
  else
    # The exploit stacks a tmpfs over the apex bin dir, sometimes more than once.
    # The plain umount reports EBUSY while adbd still sits in the dir; the lazy
    # detach clears one layer, so loop until the dir is free. A failed pass is not
    # final -- with a working persistent su in hand, EBUSY clears once adbd moves
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
  local leftovers="$DEV_TEMP_SU $DEV_TMP/temp_su.sock $DEV_TMP/su_daemon.log"
  ash "$su -c 'rm -f $leftovers'" >/dev/null 2>&1
  ash "rm -f $leftovers" >/dev/null 2>&1

  # Report the su a plain adb shell now resolves — this is how a user tests
  # root, so it is the check worth printing.
  local resolved
  resolved=$(ash 'command -v su 2>/dev/null' | strip | tr -d '\r')
  log "adb shell resolves su -> ${resolved:-<none>}"
  [ "$resolved" = "$SU_SHADOW_DIR/su" ] \
    && warn "'su' in adb shell still resolves to the exploit's temporary su, not the manager's"

  # Restore SELinux to enforcing. The exploit left it permissive: on this build
  # enforcement branches on a vendor "enforcing shadow" int that KernelSU's own
  # setenforce (which writes selinux_state.enforcing) does not reach. Now that a
  # persistent root exists, the sanctioned path does it correctly -- `setenforce
  # 1` -> sel_write_enforce -> enforcing_set, the same code the vendor kernel's
  # own SELinux toggle uses, so it writes whatever field is authoritative. Runs
  # dead last: after insmod (which needed permissive) and every other root step.
  local enf
  enf="$(ash "$su -c getenforce" 2>/dev/null | strip)"
  if [ "$enf" = "Enforcing" ]; then
    ok "SELinux already enforcing"
  else
    ash "$su -c 'setenforce 1'" >/dev/null 2>&1
    enf="$(ash "$su -c getenforce" 2>/dev/null | strip)"
    if [ "$enf" = "Enforcing" ]; then
      ok "SELinux restored to enforcing"
    else
      warn "SELinux still ${enf:-unknown} after 'setenforce 1' — the sanctioned"
      warn "write did not reach the enforcing shadow; may need a direct kernel poke"
    fi
  fi
  return 0
}
