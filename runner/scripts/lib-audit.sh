#!/usr/bin/env bash
# lib-audit.sh -- enforce the library's layering and comment rules.
#
# Repository tooling, like the rest of this directory. The library's own
# instruments -- the probes and observation helpers an exploit invokes -- are in
# cves/lib/tools/.
#
# The library is the reusable asset; each exploit is a thin orchestrator over
# it.  That only holds if the dependency arrow points one way and no module
# hardcodes a fact about one device or one bug.  This checks the four rules
# mechanically so a violation is a failed gate rather than a review comment.
#
#   L1  A module never includes a consumer's header.  Dependencies run
#       lib -> lib and exploit -> lib, never lib -> exploit.
#   L2  A device or kernel-build constant is a parameter or an #ifndef-guarded
#       macro with a documented fallback, never a bare #define.  A constant
#       that belongs to an algorithm rather than to a build is annotated
#       `audit-exempt` on its own line.
#   L3  A module's comments are consumer-agnostic: they describe the technique
#       and its contract, not which exploit happens to link it, nor the history
#       of how the code arrived.
#   L4  No dated or provenance commentary: a module is described by what it
#       does, not by when or from where it was written.
#
# lib/test is outside L1-L4: its job is to name concrete subjects and check
# them, which the rules above would forbid.
#
# Usage: runner/scripts/lib-audit.sh        (exit 0 clean, 1 on violations)
set -u

cd "$(dirname "$0")/../../cves" || exit 2

fail=0
report() { printf '%s: %s\n' "$1" "$2"; fail=1; }

# lib/test is excluded from the naming rules: a test has to name the subject it
# runs against, and a fixture that named nothing would be checking nothing.
files=$(find lib -path lib/test -prune -o \( -name '*.c' -o -name '*.h' \) -print | sort)

# L1 -- an include that escapes the library.
for f in $files; do
  grep -n '^[[:space:]]*#[[:space:]]*include[[:space:]]*"' "$f" |
  while IFS=: read -r line rest; do
    path=$(printf '%s' "$rest" | sed 's/.*"\(.*\)".*/\1/')
    case "$path" in
      */cve-*|cve-*|*/targets/*)
        report "$f:$line" "L1 includes a consumer path: $path" ;;
    esac
  done
done

# L2 -- an unguarded constant that looks like a kernel address or a struct
# offset.  A guarded one (#ifndef NAME / #define NAME ... / #endif) is the
# supported form: the target header overrides it, the fallback documents it.
for f in $files; do
  awk -v file="$f" '
    /^[[:space:]]*#[[:space:]]*ifndef[[:space:]]/ { guard++ }
    /^[[:space:]]*#[[:space:]]*endif/             { if (guard) guard-- }
    /^[[:space:]]*#[[:space:]]*define[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]+0x[0-9a-fA-F]{6,}/ {
      if (!guard && $0 !~ /audit-exempt/)
        printf "%s:%d\tL2 unguarded device constant: %s\n", file, NR, $2
    }
  ' "$f"
done | while IFS=$'\t' read -r loc msg; do report "$loc" "$msg"; done

# L3/L4 -- comment hygiene.  The scan is textual and deliberately narrow: a
# consumer directory name, a bug identifier, or a dated/provenance phrase
# appearing anywhere in a module is a violation regardless of context.
pat_consumer='cve-2026-[0-9]\{5\}\|CVE-2026-[0-9]\{5\}\|GhostLock\|ghostlock\|FFWheel\|ffwheel\|zombietick\|Zombietick\|badepoll\|BadEpoll\|frostbind\|Frostbind\|dirtyfrag\|DirtyFrag\|KernelSnitch\|panther\|blazer\|akita\|komodo\|tokay\|tegu\|frankel\|mustang\|rango'
pat_history='lifted\|Lifted\|verbatim\|reconciled\|Reconciled\|promoted to\|was reconciled\|byte-for-byte\|originally\|Originally\|historical\|formerly\|Formerly\|used to be\|MERGE CANDIDATE\|generated split\|Generated split'
for f in $files; do
  grep -n "$pat_consumer" "$f" | while IFS=: read -r line rest; do
    report "$f:$line" "L3 names a consumer or device: ${rest#"${rest%%[![:space:]]*}"}"
  done
  grep -n "$pat_history" "$f" | while IFS=: read -r line rest; do
    report "$f:$line" "L4 provenance or history: ${rest#"${rest%%[![:space:]]*}"}"
  done
done

if [ "$fail" -ne 0 ]; then
  echo "lib-audit: violations found" >&2
fi
exit "$fail"
