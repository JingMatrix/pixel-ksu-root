#!/system/bin/sh
# symbol-shape.sh -- decide whether a fix is present from the shape of the
# kernel's symbol table. Runs on the device.
#
# Many fixes restructure a code path: a function is split, renamed, or gains a
# helper. That leaves a signature in the symbol table which can be read without
# triggering anything, freeing anything, or racing anything -- the safest
# presence test there is, and the one to reach for before any test that touches
# the defect itself.
#
# The caller supplies two symbol sets. Symbols that exist only before the fix,
# and symbols that exist only after it. The verdict follows from which set is
# present, and the case where both or neither appear is reported as inconclusive
# rather than guessed at -- a symbol can be absent because it was inlined, which
# is not evidence either way.
#
# Two ways to ask, because the symbol table is not always readable:
#
#   listing  read the exported symbol list directly. Needs privilege.
#   probe    try to install a dynamic probe on the name. The kernel accepts a
#            name it knows and rejects one it does not, which is the same
#            question answered through a different interface. The probe is
#            removed immediately and never enabled.
#
# Verdict is both printed and returned: 0 fixed, 1 unfixed, 2 inconclusive.
#
# Usage: symbol-shape.sh [listing|probe] -b "<pre-fix syms>" -a "<post-fix syms>" [-i "<informational>"]
set -u

T=/sys/kernel/tracing
[ -d "$T" ] || T=/sys/kernel/debug/tracing
K=/proc/kallsyms

METHOD=listing
case "${1:-}" in listing|probe) METHOD=$1; shift ;; esac

BEFORE=""; AFTER=""; INFO=""
while getopts "b:a:i:" opt; do
  case "$opt" in
    b) BEFORE="$OPTARG" ;;
    a) AFTER="$OPTARG" ;;
    i) INFO="$OPTARG" ;;
    *) echo "usage: $0 [listing|probe] -b \"<pre-fix>\" -a \"<post-fix>\" [-i \"<info>\"]" >&2; exit 2 ;;
  esac
done
[ -n "$BEFORE$AFTER" ] || { echo "$0: give at least one symbol set" >&2; exit 2; }

have_listing() { grep -qE " [tT] $1\$" "$K" 2>/dev/null; }

have_probe() {
  echo > "$T/kprobe_events" 2>/dev/null
  if echo "p:shape $1" > "$T/kprobe_events" 2>/dev/null; then
    echo > "$T/kprobe_events" 2>/dev/null
    return 0
  fi
  return 1
}

if [ "$METHOD" = listing ] && [ ! -r "$K" ]; then
  echo "the symbol list is unreadable here; rerun with: $0 probe ..."
  exit 2
fi
HAVE=have_$METHOD

echo "kernel: $(uname -r)"
echo "patch : $(getprop ro.build.version.security_patch 2>/dev/null)"
echo "method: $METHOD"
echo

pre=0; post=0
for s in $BEFORE; do
  if $HAVE "$s"; then echo "  present  $s   (pre-fix shape)"; pre=$((pre+1)); fi
done
for s in $AFTER; do
  if $HAVE "$s"; then echo "  present  $s   (post-fix shape)"; post=$((post+1)); fi
done
for s in $INFO; do
  if $HAVE "$s"; then echo "  present  $s"; else echo "  absent   $s"; fi
done
echo

if [ "$post" -gt 0 ] && [ "$pre" -eq 0 ]; then
  echo "verdict: PATCHED"
  exit 0
elif [ "$pre" -gt 0 ] && [ "$post" -eq 0 ]; then
  echo "verdict: UNPATCHED"
  exit 1
else
  echo "verdict: INCONCLUSIVE (pre=$pre post=$post) -- symbols may be inlined"
  [ "$METHOD" = listing ] && echo "         try: $0 probe ..."
  exit 2
fi
