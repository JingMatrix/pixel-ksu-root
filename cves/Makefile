# pixel-ksu-root payloads Makefile
# Builds an exploit payload for Google Pixel devices from a selected RECIPE.
#
#   make TARGET=<codename-build>                  # default recipe: ghostlock
#   make TARGET=<codename-build> RECIPE=cve64560  # a different entry exploit
#   make TARGET=<codename-build> recipes          # list what is selectable
#   make TARGET=<codename-build> check            # run the gates, build nothing
#
# WHERE THE SOURCE LIST COMES FROM
# --------------------------------
# The source list is not in this file.  It is composed from:
#
#   runner/recipes/<RECIPE>.toml   names an ENTRY stage per kernel flavour
#   data/targets.json       says which flavour this TARGET is
#   runner/stages/<id>/stage.toml  says what that stage compiles, with what flags
#
# runner/scripts/resolve-recipe.py folds those three into the ART_* variables included
# below, and fails the build with a named ARCH-G* error if the composition is
# invalid (unknown recipe or stage, wrong kernel flavour, missing target facts).
# Adding a device is a target header plus a data/targets.json row; no build file
# changes.

API ?= 35
TARGET ?= frankel-CP2A.260705.006
RECIPE ?= ghostlock
OUTDIR ?= build/$(TARGET)

# Pin the build marker instead of __DATE__ " " __TIME__
# (cve-2026-43499-ghostlock/61/common.h:48, under the #ifndef at :47).  Only the
# 6.1 sources define BUILD_TAG, so this affects the 6.1 payloads only; the 6.6
# common.h has no such marker.  Empty by default, so ordinary builds are
# unchanged.  Set it to make the 6.1 payloads
# byte-reproducible:  make TARGET=... BUILD_TAG=REGRESSION
#
# Why that matters: the compile timestamp is baked into every 6.1 payload and
# a one-second delta perturbs the output through .rodata string merging, so an
# UNPINNED 6.1 build can never reproduce a stored hash.  Comparing two builds
# of the 6.1 set is only meaningful with BUILD_TAG pinned on both sides.
BUILD_TAG ?=

TARGET_HEADER := targets/$(TARGET)/target.h

# Locate an NDK the same way runner/scripts/build-payloads.sh does, so a
# per-target build needs no more setup than a full one.
ifeq ($(strip $(ANDROID_NDK_HOME)),)
  ANDROID_NDK_HOME := $(strip $(ANDROID_NDK_ROOT))
endif
ifeq ($(strip $(ANDROID_NDK_HOME)),)
  SDK_DIR := $(or $(strip $(ANDROID_HOME)),$(strip $(ANDROID_SDK_ROOT)))
  ifneq ($(strip $(SDK_DIR)),)
    ANDROID_NDK_HOME := $(shell find '$(SDK_DIR)/ndk' -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -V | tail -1)
  endif
endif

TARGET_CC := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(shell uname -s | tr A-Z a-z)-x86_64/bin/aarch64-linux-android$(API)-clang

ifeq ($(wildcard $(TARGET_CC)),)
$(error no Android NDK found. Set ANDROID_NDK_HOME, or ANDROID_HOME to an SDK with an ndk/ subdirectory. Looked for: $(TARGET_CC))
endif

# ---------------------------------------------------------------------------
# Recipe resolution
# ---------------------------------------------------------------------------
RESOLVER := ../runner/scripts/resolve-recipe.py
RECIPE_MK := $(OUTDIR)/.recipe.$(RECIPE).mk

# Re-resolve whenever any input to the decision changes.  wildcard, not a bare
# path, so a missing recipe/target header reaches the resolver's named gate
# instead of make's "No rule to make target".
RESOLVER_INPUTS := \
  $(RESOLVER) \
  ../data/targets.json \
  $(wildcard ../runner/recipes/*.toml) \
  $(wildcard ../runner/stages/*/stage.toml) \
  $(wildcard $(TARGET_HEADER))

RESOLVER_FLAGS :=
ifneq ($(BUILD_TAG),)
RESOLVER_FLAGS += --build-tag '$(BUILD_TAG)'
endif

RESOLVE := python3 $(RESOLVER) --target '$(TARGET)' --recipe '$(RECIPE)' $(RESOLVER_FLAGS)

$(RECIPE_MK): $(RESOLVER_INPUTS)
	@mkdir -p $(dir $@)
	@$(RESOLVE) --format make > $@.tmp || { rm -f $@.tmp; exit 1; }
	@mv -f $@.tmp $@

# Defaults so the first parse (before $(RECIPE_MK) exists) is well formed; the
# include below overrides all of them and make re-executes itself.
ARTIFACTS :=
GOAL_ALL :=
GOAL_RELEASE :=
RECIPE_ENTRY :=
RECIPE_KMI :=
RECIPE_STAGES :=
RECIPE_COMPOSED :=

ifeq ($(filter clean recipes,$(MAKECMDGOALS)),)
include $(RECIPE_MK)
endif

# One compile rule per resolved artifact.  The flag ORDER here is load-bearing:
# defines, cflags, includes, target defines, sources, ldflags.
define ARTIFACT_rule
$$(OUTDIR)/$$(ART_$(1)_OUT): $$(ART_$(1)_SRCS) $$(ART_$(1)_DEPS) | $$(OUTDIR)
	$$(TARGET_CC) $$(ART_$(1)_CFLAGS) $$(ART_$(1)_SRCS) $$(ART_$(1)_LDFLAGS) -o $$@
endef
$(foreach a,$(ARTIFACTS),$(eval $(call ARTIFACT_rule,$(a))))

goal_files = $(foreach a,$(1),$(OUTDIR)/$(ART_$(a)_OUT))

.DEFAULT_GOAL := all

.PHONY: all clean info release recipes check

all: $(call goal_files,$(GOAL_ALL))

release: $(call goal_files,$(GOAL_RELEASE))

$(OUTDIR):
	mkdir -p $@

# Run every build-time gate for this (TARGET, RECIPE) and produce no artifact.
check: $(RECIPE_MK)
	@$(RESOLVE) --format json >/dev/null
	@echo "ok: $(RECIPE) / $(TARGET) ($(RECIPE_KMI)) -> $(RECIPE_ENTRY)"

recipes:
	@echo "recipes (runner/recipes/*.toml):"
	@for r in ../runner/recipes/*.toml; do \
	  n=$$(basename $$r .toml); \
	  d=$$(sed -n 's/^description *= *"\(.*\)"/\1/p' $$r); \
	  printf '  %-12s %s\n' "$$n" "$$d"; \
	done
	@echo "stages (runner/stages/*/stage.toml):"
	@for s in ../runner/stages/*/stage.toml; do \
	  n=$$(basename $$(dirname $$s)); \
	  c=$$(sed -n 's/^status *= *"\(.*\)"/\1/p' $$s); \
	  printf '  %-24s %s\n' "$$n" "$$c"; \
	done

info:
	@echo "TARGET=$(TARGET)"
	@echo "RECIPE=$(RECIPE)  (kmi=$(RECIPE_KMI) composed=$(RECIPE_COMPOSED))"
	@echo "ENTRY=$(RECIPE_ENTRY)"
	@echo "STAGES=$(RECIPE_STAGES)"
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "OUTDIR=$(OUTDIR)"
	@echo "BUILD_TAG=$(BUILD_TAG)"
	@$(foreach a,$(ARTIFACTS),echo "  artifact $(ART_$(a)_REF) -> $(ART_$(a)_OUT)";)

clean:
	rm -rf $(OUTDIR)

# Convenience targets for common Pixel models.  RECIPE= passes through, since
# make forwards command-line variables to sub-makes.
pixel10profold:
	$(MAKE) TARGET=rango-CP2A.260705.006

pixel10pro:
	$(MAKE) TARGET=blazer-CP2A.260705.006

pixel10:
	$(MAKE) TARGET=frankel-CP2A.260705.006

pixel10proxl:
	$(MAKE) TARGET=mustang-CP2A.260705.006

pixel9profold:
	$(MAKE) TARGET=comet-CP2A.260705.006

pixel9pro:
	$(MAKE) TARGET=caiman-CP2A.260705.006

pixel9proxl:
	$(MAKE) TARGET=komodo-CP2A.260705.006

pixel9:
	$(MAKE) TARGET=tokay-CP2A.260705.006

pixel8pro:
	$(MAKE) TARGET=husky-CP2A.260705.006

pixel8:
	$(MAKE) TARGET=shiba-CP2A.260705.006

pixel8a:
	$(MAKE) TARGET=akita-CP2A.260805.005

pixel7a:
	$(MAKE) TARGET=lynx-CP2A.260705.006

pixel7pro:
	$(MAKE) TARGET=cheetah-CP2A.260705.006

pixel7:
	$(MAKE) TARGET=panther-CP2A.260705.006

pixel6a:
	$(MAKE) TARGET=bluejay-CP1A.260405.005
	$(MAKE) TARGET=bluejay-CP2A.260705.006

pixel6:
	$(MAKE) TARGET=oriole-CP2A.260705.006

pixel6pro:
	$(MAKE) TARGET=raven-CP2A.260705.006
