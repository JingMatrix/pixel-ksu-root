#!/usr/bin/env bash
# Self-contained CVE-2026-64560 diagnostic hunt for panther.
#
# Runs the bridge-diagnostic build of the 64560 exploit through the runner,
# then prints a digest that explains itself. Every shot either:
#   PANIC  lost the STAGE0 race -> phone reboots (this is normal, most shots)
#   PASS   derived the KASLR base (kernel_base=...) and reached the bridge
#   MISS   reached the bridge, all attempts missed
# The numbers that matter are the bridge-miss counters, which print ONLY on a
# shot that survived STAGE0 and reached the bridge stage:
#   open_fail   forged fops installed but the fake-table PAGE was reclaimed
#               before misc_open read f_op->open   (redirect landed, page died)
#   read_fail   open() gave a REAL ashmem fd -> the redirect reverted by
#               open() time                        (redirect didn't survive)
#   wrong_val   gadget fired but read the wrong address (a compute bug)
#
# Usage:
#   runner/scripts/hunt-cve64560.sh                # bounded: up to 8 reboots
#   PANIC_MAX=20 runner/scripts/hunt-cve64560.sh   # let it try harder (more reboots)
#   runner/scripts/hunt-cve64560.sh --digest-only logs/shots/<run>  # just re-digest
set -u
cd "$(dirname "$0")/../.."
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-/home/jing/Archives/Android/ndk/29.0.14206865}"
TARGET="${TARGET:-panther-CP2A.260705.006}"

digest() {  # $1 = shot dir
  local d="$1"
  echo; echo "================= DIGEST: $d ================="
  if [ -f "$d/index.tsv" ]; then
    echo "-- shot census --"; awk '{c[$3]++} END{for(k in c)printf "   %-7s %d\n",k,c[k]}' "$d/index.tsv"
  fi
  echo "-- shots that REACHED the bridge stage --"
  local reached=0 f
  for f in "$d"/*.log; do
    [ -e "$f" ] || continue
    grep -aqE 'MISC_BRIDGE_STAGE_BEGIN|opens=[0-9]+ open_fail=[0-9]+' "$f" 2>/dev/null && reached=$((reached+1))
  done
  echo "   $reached shot(s) reached the bridge (only these carry diag counters)"
  echo "-- final bridge-miss counters per bridge-reaching shot --"
  local f
  for f in "$d"/*.log; do
    [ -e "$f" ] || continue
    local last; last=$(grep -aoE 'opens=[0-9]+ open_fail=[0-9]+ read_fail=[0-9]+ wrong_val=[0-9]+' "$f" 2>/dev/null | tail -1)
    [ -n "$last" ] && printf "   %-22s %s\n" "$(basename "$f")" "$last"
  done
  echo "-- aggregate (max opens across bridge shots, sum of miss modes) --"
  for f in "$d"/*.log; do
    [ -e "$f" ] || continue
    grep -aoE 'opens=[0-9]+ open_fail=[0-9]+ read_fail=[0-9]+ wrong_val=[0-9]+' "$f" 2>/dev/null | tail -1
  done | awk '{split($1,o,"=");if(o[2]>mx)mx=o[2];for(i=2;i<=NF;i++){split($i,a,"=");s[a[1]]+=a[2]}}
    END{t=s["open_fail"]+s["read_fail"]+s["wrong_val"]
        printf "   max_opens=%d  open_fail=%d read_fail=%d wrong_val=%d\n",mx,s["open_fail"],s["read_fail"],s["wrong_val"]
        if(mx==0 && NR>0){
          print "   => GATE SHORT-CIRCUIT: bridge reached, but open_verified_bridge was"
          print "      NEVER called (opens=0). The ashmem_hook_probe gate returned"
          print "      \"real\" every attempt, i.e. a fresh /dev/ashmem open never picked"
          print "      up the forged fops. The redirect is not present in the probe window."
          print "      Root cause is PERSISTENCE/TIMING, upstream of fd validation."
        } else if(t>0){
          printf "   => open_fail %.0f%%  read_fail %.0f%%  wrong_val %.0f%%\n",100*s["open_fail"]/t,100*s["read_fail"]/t,100*s["wrong_val"]/t
          print "      open_fail=fops page reclaimed; read_fail=redirect reverted by open-time;"
          print "      wrong_val=gadget addressed wrong."
        } else print "   => no bridge-stage samples yet (every shot panicked in STAGE0)"}'
  echo "-- did any fresh open ever catch the hook? (ENODEV tell) --"
  local hooked=0
  for f in "$d"/*.log; do
    [ -e "$f" ] || continue
    grep -aqE 'MISC_BRIDGE_(LATE_)?HIT|MISC_BRIDGE_READ_PASS' "$f" 2>/dev/null && hooked=$((hooked+1))
  done
  echo "   $hooked shot(s) ever saw the bridge validate (a real HIT)"
  echo "-- to send me: the whole dir is small; run --"
  echo "   tar czf /tmp/hunt-$(basename "$d").tgz $d && echo made /tmp/hunt-$(basename "$d").tgz"
}

if [ "${1:-}" = "--digest-only" ]; then digest "$2"; exit 0; fi

echo "== building the diagnostic 64560 binary (instrumented) =="
make -C cves TARGET="$TARGET" RECIPE=cve64560 || { echo "build failed"; exit 1; }

echo "== launching bounded hunt (PANIC_MAX=${PANIC_MAX:-8} ROOT_MAX=${ROOT_MAX:-12}) =="
echo "   ctrl-C any time; the shots archived so far are still usable."
PANIC_MAX="${PANIC_MAX:-8}" ROOT_MAX="${ROOT_MAX:-12}" REFUSED_MAX="${REFUSED_MAX:-6}" \
  ./pixel-ksu-root --recipe cve64560 --target "$TARGET"
rc=$?

run=$(ls -1td logs/shots/*/ 2>/dev/null | head -1)
[ -n "$run" ] && digest "${run%/}"
echo; echo "runner exit=$rc"
exit "$rc"
