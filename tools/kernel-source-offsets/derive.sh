#!/usr/bin/env bash
#
# derive.sh — struct-layout offsets from a kernel's own source + .config, for
# a build that has no BTF (CONFIG_DEBUG_INFO_BTF unset). cves/targets/README.md
# ("How offsets are harvested and verified") explains why every other offset
# in this tree comes from BTF or kallsyms; this is what to fall back to when
# a target has neither -- a vendor kernel, most commonly.
#
# The idea: struct layout (field order, size, alignment) is an ABI fact, not
# a codegen choice, so any conformant compiler for the target arch reproduces
# it byte-for-byte. The kernel already proves this every build, through
# arch/*/kernel/asm-offsets.c: a tiny translation unit that DEFINE()s each
# offset it needs as a ".ascii" string in the .s output, later grepped into a
# generated header. This script runs the same mechanism against a caller-
# supplied probe.c, using the exact compiler invocation Kbuild used for its
# own asm-offsets.c -- so the result is the same number BTF would have given,
# reproducible from the kernel source tree alone. See kbuild.h's DEFINE()
# macro for why the probe must go through it rather than a bare inline asm.
#
# Usage:
#   derive.sh --kdir DIR --out DIR --probe FILE.c
#             [--config FILE] [--cc CC] [--cross-compile PREFIX]
#             [--extra-include DIR ...] [--pre-target TARGET ...]
#             [--arch ARCH] [--asm-offsets PATH]
#
#   --kdir            Kernel source tree.
#   --out              Out-of-tree build dir (O=), created if missing. Reused
#                      across runs -- the kconfig/header generation is the
#                      slow part, and it does not change between probes.
#   --probe            The probe .c: includes the real kernel headers, calls
#                      DEFINE(NAME, offsetof(...)/sizeof(...)) once per fact
#                      wanted. include <linux/kbuild.h> for DEFINE().
#   --config            A captured `.config` (e.g. adb shell cat /proc/config.gz
#                      | gunzip, from the same build the probe targets) to
#                      seed --out with via olddefconfig. Skipped if --out
#                      already has a .config (repeat runs, or a config seeded
#                      by hand beforehand).
#   --extra-include     Repeatable. A directory the probe's #include path
#                      needs beyond what Kbuild already passes for
#                      arch/*/kernel/asm-offsets.c (e.g. kernel/locking or a
#                      security/*/include directory the probe reaches into
#                      for an internal struct).
#   --pre-target        Repeatable. A Kbuild target to build (under --out)
#                      before compiling the probe, for a generated header the
#                      probe's #includes need but arch/*/kernel/asm-offsets.c
#                      never pulls in itself -- e.g. security/selinux/flask.h
#                      is emitted only as a side effect of building an object
#                      that includes it, such as
#                      `--pre-target security/selinux/hooks.o`.
#   --cc, --cross-compile, --arch, --asm-offsets
#                      Toolchain and reference-target overrides; defaults are
#                      CC=clang, CROSS_COMPILE=aarch64-linux-gnu-, ARCH=arm64,
#                      arch/arm64/kernel/asm-offsets.s. Kbuild is always
#                      driven with LLVM=1 LLVM_IAS=1; neither is settable from
#                      the command line. The host compiler version need not
#                      match the kernel's own build toolchain, because struct
#                      layout is an ABI fact.
#
# On success, prints one `#define NAME 0x<hex>` line per DEFINE() in the
# probe, to stdout; a negative value prints as signed decimal.
#
# What this does NOT give you: symbol addresses (kallsyms or
# tools/pixel-image/derive_offsets.py already cover that without BTF either)
# and slab strides (a runtime fact -- harvest-live.sh, or /proc/slabinfo by
# hand). This is for struct field offsets and sizes only.
set -euo pipefail

ARCH=arm64
CC=clang
LLVM=1
LLVM_IAS=1
CROSS_COMPILE=aarch64-linux-gnu-
ASM_OFFSETS_REL=arch/arm64/kernel/asm-offsets.s
EXTRA_INCLUDES=()
PRE_TARGETS=()
KDIR= OUT= PROBE= CONFIG=

while [ $# -gt 0 ]; do
  case "$1" in
    --kdir) KDIR="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --probe) PROBE="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --extra-include) EXTRA_INCLUDES+=("$2"); shift 2 ;;
    --pre-target) PRE_TARGETS+=("$2"); shift 2 ;;
    --cc) CC="$2"; shift 2 ;;
    --cross-compile) CROSS_COMPILE="$2"; shift 2 ;;
    --arch) ARCH="$2"; shift 2 ;;
    --asm-offsets) ASM_OFFSETS_REL="$2"; shift 2 ;;
    -h|--help) sed -n '2,/^set -euo/{/^set -euo/!p}' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$KDIR" ] && [ -n "$OUT" ] && [ -n "$PROBE" ] || {
  echo "usage: derive.sh --kdir DIR --out DIR --probe FILE.c [...]" >&2
  exit 2
}
KDIR=$(cd "$KDIR" && pwd)
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
PROBE=$(cd "$(dirname "$PROBE")" && pwd)/$(basename "$PROBE")

MAKE_COMMON=(make -C "$KDIR" ARCH="$ARCH" O="$OUT" CC="$CC" LLVM="$LLVM" \
             LLVM_IAS="$LLVM_IAS" CROSS_COMPILE="$CROSS_COMPILE")

if [ -n "$CONFIG" ] && [ ! -f "$OUT/.config" ]; then
  cp "$CONFIG" "$OUT/.config"
fi
[ -f "$OUT/.config" ] || {
  echo "no $OUT/.config and no --config given -- seed one first" >&2
  exit 2
}

echo "== olddefconfig ==" >&2
"${MAKE_COMMON[@]}" olddefconfig >&2

echo "== prepare (generates headers; builds the kernel's own $ASM_OFFSETS_REL as a side effect) ==" >&2
"${MAKE_COMMON[@]}" prepare >&2

for t in "${PRE_TARGETS[@]+"${PRE_TARGETS[@]}"}"; do
  echo "== pre-target: $t ==" >&2
  "${MAKE_COMMON[@]}" "$t" >&2
done

# Capture the exact compiler invocation Kbuild used for its own asm-offsets.c,
# so the probe is compiled the identical way -- same defines, same generated
# headers, same hardening flags. Force a rebuild first: a cached file from
# `prepare` above would make V=1 print nothing. Re-running through `prepare`
# (rather than requesting $ASM_OFFSETS_REL directly) matters: the top
# Makefile does not recognise a bare `.s` path as a single-file build target
# on some kernel versions, and silently no-ops it via a stub makefile instead
# of erroring, which looks identical to "already up to date".
rm -f "$OUT/$ASM_OFFSETS_REL"
echo "== capturing the asm-offsets.c compile command ==" >&2
# Match on the known output path rather than the compiler name: Kbuild may
# invoke $(CC) by its bare name (PATH-resolved), not an absolute path, so
# grepping for "clang"/"gcc" specifically is not reliable across configs.
CMD=$("${MAKE_COMMON[@]}" V=1 prepare 2>&1 | \
      grep -m1 -F -- "-o $ASM_OFFSETS_REL ") || true
[ -n "$CMD" ] || {
  echo "could not capture a compile command from V=1 output" >&2
  exit 1
}

EXTRA_I=()
for d in "${EXTRA_INCLUDES[@]+"${EXTRA_INCLUDES[@]}"}"; do EXTRA_I+=(-I "$d"); done

# The captured command ends in Kbuild's own `-S -o <target>.s <target>.c` (or
# `-c -o <target>.o <target>.c` for a non-.s target); strip that trailing
# output/input pair so ours can replace it, keeping every flag before it
# (the -Wp,-MD,... dependency-file flag at the very front is left pointing at
# the original path -- harmless, its .d output is simply unused).
CMD_FLAGS="${CMD%% -S -o *}"
[ "$CMD_FLAGS" = "$CMD" ] && CMD_FLAGS="${CMD%% -c -o *}"
[ "$CMD_FLAGS" != "$CMD" ] || {
  echo "could not find a trailing '-S -o ...' or '-c -o ...' in the captured command" >&2
  exit 1
}

PROBE_S="$OUT/$(basename "${PROBE%.c}").s"
echo "== compiling the probe ==" >&2
# The captured flags include Kbuild's own relative `-I./include` etc, which
# are only correct resolved from $OUT -- that relativity is what `O=` builds
# on. Run from there. (KBUILD_MODNAME is already set by the captured
# command, to "asm_offsets"; left as-is rather than redefined.)
( cd "$OUT" && eval "$CMD_FLAGS" \
    "${EXTRA_I[@]+"${EXTRA_I[@]}"}" -S -o "$PROBE_S" "$PROBE" ) >&2

echo "== extracting DEFINE() output ==" >&2
OUT_LINES=$(grep -oP '(?<=\.ascii\t")->\K[A-Za-z0-9_]+ -?\d+' "$PROBE_S" || true)
[ -n "$OUT_LINES" ] || {
  echo "no DEFINE() output in $PROBE_S -- does the probe include <linux/kbuild.h> and call DEFINE()?" >&2
  exit 1
}
printf '%s\n' "$OUT_LINES" | \
  awk '{ v=$2+0; if (v<0) printf "#define %-30s %d\n", $1, v; \
         else printf "#define %-30s 0x%x\n", $1, v }'
