#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# pagetrace.sh — arm the kmem tracepoints, run pagetrace on the device, dump the
# ring buffer and hand it to analyze.py.
#
#   tools/pagetrace/pagetrace.sh class pipe 512
#   tools/pagetrace/pagetrace.sh drain 20000 6000 6000
#   tools/pagetrace/pagetrace.sh place 6000 400 4 4000
#   tools/pagetrace/pagetrace.sh reclaim 6000 400 4 k256 3000
#   tools/pagetrace/pagetrace.sh fate 6000 400 4 30000
#
# Arming the tracepoints needs root on the device: under tracefs only tracing_on,
# trace, trace_marker and buffer_size_kb are 0666 (gid 3012 readtracefs), while
# events/*/enable is 0600. So this expects a KernelSU `su` to be live. The probe
# ITSELF runs as the shell uid, which is the context the CVE work cares about.
#
# The arm/disarm steps are pushed as SCRIPTS and run with `su -c <path>`: a
# redirection written inside `su -c "...>..."` is performed by the calling shell,
# which is uid 2000, and every write silently fails with Permission denied.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN=${PAGETRACE_BIN:-/tmp/pagetrace}
DEV=/data/local/tmp/pagetrace
OUT=${PAGETRACE_OUT:-/tmp/pagetrace-$$.trace}
T=/sys/kernel/tracing

[ $# -ge 1 ] || { echo "usage: pagetrace.sh <mode> ..." >&2; exit 2; }

if [ "$(adb shell su -c id -u 2>/dev/null | tr -d '\r')" != "0" ]; then
  echo "pagetrace: tracefs events/*/enable needs root; no su on the device." >&2
  echo "           root it first (./pixel-ksu-root), then re-run." >&2
  exit 1
fi

[ -x "$BIN" ] || {
  echo "building $BIN" >&2
  ${CC_AARCH64:-aarch64-linux-gnu-gcc} -static -O1 -o "$BIN" "$HERE/pagetrace.c"
}
adb push "$BIN" "$DEV" >/dev/null
adb shell chmod 755 "$DEV"

# A class probe wants the slab tracepoints too. `fate` follows one page through
# the whole allocator, so it needs the buddy-side events as well: pcpu_drain
# fires when a page leaves a per-cpu list for the buddy freelists, and
# alloc_zone_locked fires when an allocation is served from those freelists
# rather than from a per-cpu list — which is exactly the distinction we are
# trying to make.
MODE=$1
case "$MODE" in
class) EVENTS="mm_page_alloc mm_page_free kmalloc kmem_cache_alloc" ;;
fate)  EVENTS="mm_page_alloc mm_page_free mm_page_alloc_zone_locked mm_page_pcpu_drain"
       shift; set -- place "$@" ;;
*)     EVENTS="mm_page_alloc mm_page_free" ;;
esac

# Allocations we care about are made in our own context, so they filter by comm
# at every order — an order filter here would drop the order-0 vehicles. Frees
# are the opposite: a slab is discarded from an rcuop kthread, never from us, so
# free events filter by order instead of by task.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
# In `fate` the question is who ELSE touches the page, so nothing is filtered by
# task — only by order, which keeps the volume low because order>0 traffic is
# rare on an idle device (measured: zero order-1 frees in 8 s).
if [ "$MODE" = fate ]; then
  FILTER='order > 0'
else
  FILTER='comm == "pagetrace"'
fi
cat > "$TMP/arm.sh" <<ARM
#!/system/bin/sh
echo 0 > $T/tracing_on
echo    > $T/trace
echo 32768 > $T/buffer_size_kb
for ev in $EVENTS; do
  echo '$FILTER' > $T/events/kmem/\$ev/filter
  echo 1 > $T/events/kmem/\$ev/enable
done
echo 'order > 0' > $T/events/kmem/mm_page_free/filter
echo 1 > $T/tracing_on
ARM
cat > "$TMP/disarm.sh" <<DIS
#!/system/bin/sh
echo 0 > $T/tracing_on
for ev in $EVENTS; do
  echo 0 > $T/events/kmem/\$ev/enable
  echo 0 > $T/events/kmem/\$ev/filter
done
cat $T/trace
echo 64 > $T/buffer_size_kb
DIS
adb push "$TMP/arm.sh" "$TMP/disarm.sh" /data/local/tmp/ >/dev/null
adb shell chmod 755 /data/local/tmp/arm.sh /data/local/tmp/disarm.sh

adb shell su -c /data/local/tmp/arm.sh
# PAGETRACE_AS_ROOT=1 runs the probe itself as root, for vehicles the shell
# domain is denied (ashmem is 0666 but SELinux refuses u:r:shell:s0). The
# measurement is the same; only the domain differs.
if [ "${PAGETRACE_AS_ROOT:-0}" = 1 ]; then
  adb shell su -c "$DEV $*"
else
  adb shell "$DEV" "$@"
fi
adb shell su -c /data/local/tmp/disarm.sh > "$OUT"
adb shell rm -f /data/local/tmp/arm.sh /data/local/tmp/disarm.sh

echo "trace: $OUT"
python3 "$HERE/analyze.py" "$OUT"
