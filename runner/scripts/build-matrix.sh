#!/usr/bin/env bash
# build-matrix.sh -- build every (target, recipe) pair that resolves, and print
# one `<md5>  <recipe>/<target>/<artifact>` line per produced artifact.
#
# This is repository tooling and lives with the other scripts that build and
# resolve the tree. Instruments that an exploit itself invokes -- on a device or
# against a device -- live in cves/lib/tools/ instead, because they are part of
# the library, not part of the build.
#
# Purpose: a refactor that is meant to be behaviour-preserving must be shown to
# be so.  BUILD_TAG is pinned, which removes the compile timestamp from the
# payloads that embed one, so two builds of an unchanged tree are byte-equal and
# the output of this script is a stable fingerprint of the whole build matrix.
#
#   runner/scripts/build-matrix.sh > before.txt
#   ...change the tree...
#   runner/scripts/build-matrix.sh > after.txt
#   diff before.txt after.txt
#
# A pair whose composition the resolver refuses (a stage restricted to other
# targets, a recipe with no entry for the target's kernel flavour) is skipped;
# refusal is a declared property of the composition, not a build failure.
#
# Usage: runner/scripts/build-matrix.sh [-o OUTDIR_ROOT] [-t TAG] [recipe ...]
set -u

cd "$(dirname "$0")/../../cves" || exit 2

OUT_ROOT=""
TAG="MATRIX"
while getopts "o:t:" opt; do
  case "$opt" in
    o) OUT_ROOT="$OPTARG" ;;
    t) TAG="$OPTARG" ;;
    *) echo "usage: $0 [-o OUTDIR_ROOT] [-t TAG] [recipe ...]" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

if [ -z "$OUT_ROOT" ]; then
  OUT_ROOT="$(mktemp -d)"
  trap 'rm -rf "$OUT_ROOT"' EXIT
fi

recipes=("$@")
if [ ${#recipes[@]} -eq 0 ]; then
  for r in ../runner/recipes/*.toml; do recipes+=("$(basename "$r" .toml)"); done
fi

targets=()
for t in targets/*/target.h; do targets+=("$(basename "$(dirname "$t")")"); done

fail=0
for recipe in "${recipes[@]}"; do
  for target in "${targets[@]}"; do
    out="$OUT_ROOT/$recipe/$target"
    # `check` runs every resolver gate and builds nothing, so an unsupported
    # pair costs one resolve instead of a compile.
    if ! make -s TARGET="$target" RECIPE="$recipe" OUTDIR="$out" BUILD_TAG="$TAG" \
         check >/dev/null 2>&1; then
      continue
    fi
    if ! make -s TARGET="$target" RECIPE="$recipe" OUTDIR="$out" BUILD_TAG="$TAG" \
         >/dev/null 2>&1; then
      echo "BUILD-FAILED  $recipe/$target" >&2
      fail=1
      continue
    fi
    for artifact in "$out"/*; do
      case "$artifact" in *.mk) continue ;; esac
      [ -f "$artifact" ] || continue
      printf '%s  %s/%s/%s\n' \
        "$(md5sum "$artifact" | cut -d' ' -f1)" \
        "$recipe" "$target" "$(basename "$artifact")"
    done
  done
done | sort -k2

exit $fail
