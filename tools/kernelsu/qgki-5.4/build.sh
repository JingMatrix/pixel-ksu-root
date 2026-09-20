#!/bin/bash
#
# build.sh -- thin entry point matching every other tools/*/build.sh in this
# project; the actual build logic lives in this directory's own Makefile,
# which takes KSU_DIR, KDIR and CLANG_BIN with no default of its own -- each
# names a path specific to the machine doing the build (a KernelSU checkout,
# a configured kernel output tree, a toolchain bin directory).
#
# The three defaults below are one developer's own checkout layout, kept
# here purely as a convenience so a bare ./build.sh has something to try.
# EDIT THESE to your own paths, or export/pass KSU_DIR/KDIR/CLANG_BIN
# yourself, in which case the values below are never used (the Makefile's
# `check` target still validates whichever paths end up in effect, and
# reports clearly which one is missing or wrong).
: "${KSU_DIR:=$HOME/Documents/Project/gki/common/KernelSU}"
: "${KDIR:=$HOME/Documents/Project/KernelBuilds/sm7325/out}"
: "${CLANG_BIN:=$HOME/Documents/Project/KernelBuilds/toolchains/clang/bin}"
export KSU_DIR KDIR CLANG_BIN
#
# Any argument here is forwarded to make as-is.
#
set -euo pipefail
exec make -C "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" "$@"
