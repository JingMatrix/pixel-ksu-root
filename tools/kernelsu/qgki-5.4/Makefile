# tools/kernelsu/qgki-5.4/Makefile -- builds a KernelSU-derived module as an
# out-of-tree module against a qgki-5.4 kernel's own configured build tree,
# using KernelSU's own kernel/Makefile convention: KDIR is the configured
# build OUTPUT directory (e.g. .../out, holding vmlinux/.config/Module.symvers
# already), not the bare source root, and KernelSU's kernel/Makefile derives
# everything else (M=/src=, the compile_commands.json target, the post-build
# check_symbol run against $(KDIR)/vmlinux) from that.
#
# A toolchain generic to most builds -- an Android NDK's LLVM prebuilt
# (clang+lld+llvm-ar/-nm/-objcopy/-strip), matching runner/scripts/
# build-payloads.sh's own toolchain source -- works against most qgki-5.4
# configs, but not every one: whenever a .config sets
# CONFIG_INIT_STACK_ALL_ZERO=y, that kernel's top-level Makefile
# unconditionally appends
# -enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang to
# KBUILD_CFLAGS, and only a clang release from around that flag's own
# introduction still accepts it -- a current NDK clang drops the flag and
# fails the build outright. This is a property of the target .config, not of
# KernelSU's own source, so there is no compat-macro fix for it: CLANG_BIN
# simply has to name a toolchain old enough to accept the flag when the
# target .config demands it, and any ordinary toolchain otherwise.
#
# KSU_DIR, KDIR and CLANG_BIN each name a path specific to the machine doing
# the build -- a KernelSU checkout, a configured kernel output tree, and a
# toolchain bin directory -- so none of them defaults to a path baked into
# this Makefile. Pass them on the command line or export them as environment
# variables:
#   make KSU_DIR=/path/to/KernelSU KDIR=/path/to/kernel/out CLANG_BIN=/path/to/clang/bin
# build.sh, the entry point beside this file, fills in one developer's own
# checkout layout as a convenience default when none of the three is set;
# invoking this Makefile directly has no such default.
# `check`, below, validates each one before the build starts and reports
# clearly which is missing or wrong, instead of failing deep inside
# KernelSU's own kernel/Makefile with no context.

KSU_DIR   ?=
KDIR      ?=
CLANG_BIN ?=

export PATH := $(CLANG_BIN):$(PATH)
export ARCH := arm64
export CLANG_TRIPLE := aarch64-linux-gnu-
export LLVM := 1
export LLVM_IAS := 1
export CROSS_COMPILE := $(CLANG_BIN)/llvm-

# KernelSU references plenty of kernel-internal symbols by design (SELinux's
# own avtab_*/hashtab_*/ebitmap_*/security_state, kallsyms_lookup_name,
# tasklist_lock, ...) that no EXPORT_SYMBOL ever covers -- ksud's own
# insmod/late-load loader (ksuinit::load_module()) resolves those manually
# against live /proc/kallsyms at load time instead, which is the whole
# reason that loader exists rather than a plain insmod. modpost's default
# policy is to hard-fail an external module over exactly this, so it has to
# be told to warn instead; kernel/tools/check_symbol.c (kernel/Makefile's
# own post-build step) is KernelSU's real validation for this module against
# this vmlinux, not modpost's.
export KBUILD_MODPOST_WARN := 1

# CONFIG_KSU=m, not =y: kernel/Kbuild's obj-$(CONFIG_KSU) += kernelsu.o
# substitutes into obj-m (loadable module, produces kernelsu.o via MODPOST +
# a real link step) or obj-y (built into this M= build's own built-in.a,
# archived, but never linked into a standalone .ko) depending on which one
# is set. An external-module (M=) build only packages obj-m into loadable
# output, so CONFIG_KSU=y compiles and archives the object but produces no
# kernelsu.ko; CONFIG_KSU=m is what this Makefile's `all` target needs.
# Other CONFIG_KSU_XXX flags go through KSU_CONFIG_EXTRA, each an ordinary
# make command-line variable that kernel/Kbuild's own
# ifeq($(CONFIG_KSU_XXX),y) checks read.
#
# CONFIG_KSU_DEBUG=y is the default here (core/init.c: allow_shell defaults to
# true under it) so uid 2000 (adb shell) is granted su by policy the instant
# the module loads -- no manager APK install or grant, and no allow_shell=1
# insmod parameter, required. Override to drop it (or add more) on the
# command line, e.g.:
#   make KSU_CONFIG_EXTRA="CONFIG_KSU_DISABLE_MANAGER=y"
#   make KSU_CONFIG_EXTRA=          # plain build, shell root needs a manager grant
KSU_CONFIG_EXTRA ?= CONFIG_KSU_DEBUG=y

.PHONY: all clean check
.DEFAULT_GOAL := all

check:
	@[ -n "$(KSU_DIR)" ] || { echo "error: KSU_DIR not set -- point it at a KernelSU checkout (make KSU_DIR=/path/to/KernelSU)" >&2; exit 1; }
	@[ -d "$(KSU_DIR)/kernel" ] || { echo "error: $(KSU_DIR)/kernel missing -- KSU_DIR=$(KSU_DIR) is not a KernelSU checkout" >&2; exit 1; }
	@[ -n "$(KDIR)" ] || { echo "error: KDIR not set -- point it at a configured kernel build output directory (make KDIR=/path/to/kernel/out)" >&2; exit 1; }
	@[ -f "$(KDIR)/vmlinux" ] || { echo "error: $(KDIR)/vmlinux missing -- kernel tree not configured/built, or KDIR=$(KDIR) is wrong" >&2; exit 1; }
	@[ -n "$(CLANG_BIN)" ] || { echo "error: CLANG_BIN not set -- point it at a clang toolchain bin directory (make CLANG_BIN=/path/to/clang/bin)" >&2; exit 1; }
	@[ -x "$(CLANG_BIN)/clang" ] || { echo "error: $(CLANG_BIN)/clang missing -- CLANG_BIN=$(CLANG_BIN) does not hold a clang toolchain" >&2; exit 1; }

# A base kernel built with CONFIG_MODVERSIONS=y makes scripts/Makefile.modpost
# pass modpost `-m` (emit a __versions section) and populate it with a CRC
# entry for every referenced symbol that vmlinux exports with one. This
# follows from the base kernel's own .config, not from anything an
# out-of-tree module's build settings control, so it cannot be suppressed
# from this Makefile; a populated section is harmless here because
# ksuinit::load_module() never reads it. kernel/tools/check_symbol.c (in the
# KernelSU tree) is what actually validates this module against this
# vmlinux: it warns on a populated __versions section instead of treating it
# as an error, and separately checks that every undefined symbol this module
# references actually exists in vmlinux -- see that file's own comment.
all: check
	$(MAKE) -C "$(KSU_DIR)/kernel" KDIR="$(KDIR)" CONFIG_KSU=m $(KSU_CONFIG_EXTRA) all
	cp -p "$(KSU_DIR)/kernel/kernelsu.ko" "$(CURDIR)/kernelsu.ko"
	@echo "-> $(CURDIR)/kernelsu.ko"

clean: check
	$(MAKE) -C "$(KSU_DIR)/kernel" KDIR="$(KDIR)" CONFIG_KSU=m clean
	rm -f "$(CURDIR)/kernelsu.ko"
