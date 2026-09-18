#!/usr/bin/env bash
#
# build-payloads.sh — build CVE payload artifacts from the vendored source under
# cves/ into artifacts/. Argument-driven: configuration comes from flags, not the
# environment.
#
# Usage:
#   build-payloads.sh [--ndk PATH] [--recipe NAME | --all] [--target CODE]
#                     [--out DIR] [--helper-out PATH] [--build-tag TAG]
#                     [--list] [-h|--help]
#
#   --ndk PATH        Android NDK (else $ANDROID_NDK_HOME, else auto-detect)
#   --recipe NAME     build only this recipe (default: ghostlock, the ship payload)
#   --all             build every recipe / all CVEs (not just the default)
#   --target CODE     build only for this <codename-build> target
#   --out DIR         artifact output directory (default: artifacts/exploits)
#   --helper-out PATH su-daemon helper path (default: artifacts/cve-helper)
#   --build-tag TAG   pin BUILD_TAG (byte-reproducible 6.1 payloads)
#   --list            print the build matrix and exit (no build)
#
# By default it builds ghostlock, the ship payload, emitted per kernel-offset
# group (data/targets.json "payloads"). --all also builds every other recipe,
# once per target it declares; --recipe NAME builds just one and wins over --all.
# Each output filename is read from the resolved stage, so this needs no change
# when output names change.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CVES="$ROOT/cves"
TARGETS="$ROOT/data/targets.json"
OUT="$ROOT/artifacts/exploits"
HELPER="$ROOT/artifacts/cve-helper"
NDK=""; ONLY_RECIPE=""; ONLY_TARGET=""; BUILD_TAG=""; LIST=0; BUILD_ALL=0

usage() { sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^#\{0,1\} \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --ndk)        NDK="${2:?--ndk needs a path}"; shift 2 ;;
    --recipe)     ONLY_RECIPE="${2:?--recipe needs a name}"; shift 2 ;;
    --all)        BUILD_ALL=1; shift ;;
    --target)     ONLY_TARGET="${2:?--target needs a codename-build}"; shift 2 ;;
    --out)        OUT="${2:?--out needs a dir}"; shift 2 ;;
    --helper-out) HELPER="${2:?--helper-out needs a path}"; shift 2 ;;
    --build-tag)  BUILD_TAG="${2:?--build-tag needs a value}"; shift 2 ;;
    --list|-n)    LIST=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# Default to the ghostlock ship payload. --all clears the filter to build every
# recipe; an explicit --recipe wins over --all.
if [ -z "$ONLY_RECIPE" ] && [ "$BUILD_ALL" != 1 ]; then
  ONLY_RECIPE="ghostlock"
fi

# NDK: --ndk wins; otherwise fall back to the environment / SDK for convenience.
if [ -n "$NDK" ]; then
  export ANDROID_NDK_HOME="$NDK"
elif [ -z "${ANDROID_NDK_HOME:-}" ] && [ -n "${ANDROID_NDK_ROOT:-}" ]; then
  export ANDROID_NDK_HOME="$ANDROID_NDK_ROOT"
elif [ -z "${ANDROID_NDK_HOME:-}" ]; then
  ndk_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}/ndk"
  if [ -d "$ndk_root" ]; then
    latest="$(find "$ndk_root" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -V | tail -1)"
    [ -n "$latest" ] && export ANDROID_NDK_HOME="$ndk_root/$latest"
  fi
fi
if [ "$LIST" != 1 ]; then
  [ -n "${ANDROID_NDK_HOME:-}" ] || { echo "error: no NDK — pass --ndk PATH (or set ANDROID_NDK_HOME)" >&2; exit 1; }
  echo "NDK=$ANDROID_NDK_HOME"
fi

# Build matrix, one row per artifact to produce:
#   recipe <TAB> target <TAB> output-file <TAB> artifact-name <TAB> release?(0/1)
# Composed from runner/recipes/*, runner/stages/*, data/targets.json.
mapfile -t rows < <(python3 - "$ROOT" "$ONLY_RECIPE" "$ONLY_TARGET" <<'PY'
import json, sys, glob, os, tomllib

root, only_recipe, only_target = sys.argv[1], sys.argv[2], sys.argv[3]
with open(f"{root}/data/targets.json") as f:
    data = json.load(f)

# offset-group build targets per KMI, with the ship artifact name for each group
groups_by_kmi = {}
for g, i in data["payloads"].items():
    groups_by_kmi.setdefault(i["kmi"], []).append((i["build_from"], i["file"]))

def load_toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)

for rc in sorted(glob.glob(f"{root}/runner/recipes/*.toml")):
    name = os.path.basename(rc)[:-5]
    if only_recipe and name != only_recipe:
        continue
    entry = load_toml(rc).get("entry", {})  # {kmi: stage-id}
    for kmi, stage in entry.items():
        stp = f"{root}/runner/stages/{stage}/stage.toml"
        if not os.path.exists(stp):
            continue
        st = load_toml(stp)
        build = st.get("build", {})
        output = build.get("output")
        so = ".so" if build.get("form") == "preload-so" else ""  # linker appends .so
        if not output:
            continue
        rel = build.get("release", {}).get("output")
        restrict = st.get("targets")  # per-target restriction, or None
        # ghostlock is the only SHIP payload: built once per kernel-offset group
        # (data/targets.json "payloads"), named by the group's ship file, release
        # variant. Every other recipe is a research binary: built once, named by
        # its own output -- for its declared targets, or, if unrestricted, for a
        # representative target of its KMI.
        if name == "ghostlock":
            cands = [(bf, fil, "1" if rel else "0") for bf, fil in groups_by_kmi.get(kmi, [])]
        elif restrict:
            cands = [(t, output, "0") for t in restrict]
        else:
            gs = groups_by_kmi.get(kmi, [])
            cands = [(gs[0][0], output, "0")] if gs else []
        for target, art, isrel in cands:
            if only_target and target != only_target:
                continue
            src = (rel if (isrel == "1" and rel) else output) + so
            print("\t".join([name, target, src, art, isrel]))
PY
)

[ "${#rows[@]}" -gt 0 ] || { echo "no build matrix rows — check --recipe/--target" >&2; exit 1; }

if [ "$LIST" = 1 ]; then
  printf '%-16s %-28s %-26s -> %s\n' RECIPE TARGET OUTPUT ARTIFACT
  for row in "${rows[@]}"; do
    IFS=$'\t' read -r recipe target src art _ <<<"$row"
    printf '%-16s %-28s %-26s -> %s\n' "$recipe" "$target" "$src" "$art"
  done
  exit 0
fi

mkdir -p "$OUT"
helper_built=""
for row in "${rows[@]}"; do
  IFS=$'\t' read -r recipe target src art isrel <<<"$row"
  echo "== $recipe / $target =="
  goals="all"; [ "$isrel" = 1 ] && goals="all release"
  make -C "$CVES" TARGET="$target" RECIPE="$recipe" ${BUILD_TAG:+BUILD_TAG="$BUILD_TAG"} $goals >/dev/null
  cp "$CVES/build/$target/$src" "$OUT/$art"
  printf '   -> %s (%s bytes)\n' "$art" "$(stat -c%s "$OUT/$art")"

  # The su-daemon helper is target-independent; build it once (it ships with the
  # ghostlock goal set as cve-2026-43499-root).
  if [ -z "$helper_built" ] && [ -f "$CVES/build/$target/cve-2026-43499-root" ]; then
    cp "$CVES/build/$target/cve-2026-43499-root" "$HELPER"
    helper_built=1
    echo "   helper -> $HELPER"
  fi
done

echo "done. artifacts in $OUT:"
ls -1 "$OUT"
