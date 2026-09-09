# cves/ — the exploit research

One kernel CVE per subdirectory — sources plus a README on the vulnerability it
exploits — over shared infrastructure.

```
cves/
  cve-2026-43499-ghostlock/   CVE-2026-43499 — GhostLock
  cve-2026-64560/             CVE-2026-64560 — posix-cpu-timer UAF
  cve-2026-64468/             CVE-2026-64468 — binder process-lifetime UAF
  kaslr/                      the write-free text-base leak, shared by all of them
  targets/                    per-device offset headers, 19 device-builds
  Makefile                    compiles one payload from a resolved recipe
```

Which CVE the repo currently roots with, and what each bug is in one line, is the
status table in the [root README](../README.md).

## Baseline vs. candidate: the promotion gate

One CVE at a time is the baseline — the chain the repo ships and is tested
against. Every other CVE in this tree is a candidate: a real exploit ported into
the same build-and-drive framework and held to the same description, driven by
the runner as a [hunt](../runner/README.md#23-recipes).

The distinction is a property the framework records and can check, not a claim a
README makes. Promotion asks whether a candidate's own chain produces the
terminal capability
[`CAP_SU`](../runner/stages/handoff.suhelper/stage.toml#L38), and it reads that
off [`[provides].caps`](../runner/stages/entry.cve64560@6.1/stage.toml#L203) —
what a shot has been *observed* to yield — never off the declared
`[properties].provides`. The two fields and the
[comment separating them](../runner/stages/entry.cve64560@6.1/stage.toml#L200)
are in [`../runner/README.md` §5](../runner/README.md#5-foreign-chain-contract).

Four things have to hold before a candidate becomes the baseline:

1. It drives its own chain to root on real hardware, repeatedly.
2. It delivers `CAP_SU` through the handoff contract — a capability the framework
   watches a stage produce.
3. It is composed, not opaque. A foreign chain is drivable — the runner will hunt
   with it — but a stage the tree cannot decompose into groom/bridge/rw/effect
   cannot be the thing everything else is built on. A candidate says which it is
   with [`composed`](../runner/stages/entry.cve64560@6.1/stage.toml#L34).
4. It resolves through the same target and addressing model: one target header,
   one resolver, one set of gates, not a second runtime fingerprint mechanism
   competing with the first.

Promotion then flips `default` between two recipes that already share the
resolver, the handoff, the target headers and the KASLR leak. There is no
parallel machinery to migrate.

## How a CVE plugs into this tree

A CVE joins by being described in three declarative inputs, which
[`../runner/scripts/resolve-recipe.py`](../runner/scripts/resolve-recipe.py)
folds into the `ART_*` make variables and into the runner's contract:

1. A recipe under [`../runner/recipes/`](../runner/recipes/) — one entry stage
   per kernel flavour plus any non-entry stages.
   [`ghostlock.toml`](../runner/recipes/ghostlock.toml#L22) pairs a 6.1 and a 6.6
   entry with the shared
   [`handoff.suhelper`](../runner/recipes/ghostlock.toml#L19);
   [`cve64560.toml`](../runner/recipes/cve64560.toml#L33) declares `stages = []`,
   its entry being a self-contained standalone binary with no handoff.
2. A stage manifest under [`../runner/stages/`](../runner/stages/).
3. A [target header](targets/README.md) for the per-build offsets. A stage that
   needs offsets no other exploit carries may restrict itself to the targets that
   have them —
   [`targets = ["panther-CP2A.260705.006"]`](../runner/stages/entry.cve64560@6.1/stage.toml#L32)
   on 64560's entry, the only build with a `cve64560.h`.

The manifest fields, the invocation shapes and the named `ARCH-G*` gates that
refuse an invalid composition are in
[`../runner/README.md`](../runner/README.md) §2 and §5; adding a device is in
[`targets/README.md`](targets/README.md).

## Building a payload

The [`Makefile`](Makefile) compiles one payload from a resolved recipe. The
source list is not written into it; it is composed from the recipe,
[`../data/targets.json`](../data/targets.json) and the stage manifests by the
resolver at
[`RESOLVER := ../runner/scripts/resolve-recipe.py`](Makefile#L70). Run from
`cves/`:

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk

make TARGET=panther-CP2A.260705.006                 # default recipe: ghostlock
make TARGET=panther-CP2A.260705.006 RECIPE=cve64560 # name a recipe explicitly
make TARGET=panther-CP2A.260705.006 recipes         # list selectable recipes/stages
make TARGET=panther-CP2A.260705.006 check           # run the gates, build nothing
make TARGET=panther-CP2A.260705.006 info            # show the resolved composition
```

Convenience targets map Pixel model names to codenames (`make pixel7`,
`make pixel10pro`, …), and `RECIPE=` passes through to them since make forwards
command-line variables to sub-makes.
[`../runner/scripts/build-payloads.sh`](../runner/scripts/build-payloads.sh)
builds the full shipped set. Output lands in `build/$(TARGET)/`.

Two build knobs:

- [`API`](Makefile#L23) (default 35) — the Android API level of the NDK
  toolchain.
- [`BUILD_TAG`](Makefile#L38) — pins the compile marker in place of
  `__DATE__ " " __TIME__` (the `#ifndef BUILD_TAG` at
  [`cve-2026-43499-ghostlock/61/common.h:47`](cve-2026-43499-ghostlock/61/common.h#L47))
  so the 6.1 payloads are byte-reproducible. It affects the 6.1 sources only —
  the 6.6 tree has no such marker — and is empty by default.

## License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0), inherited from the upstream [NebuSec](https://github.com/NebuSec/CyberMeowfia) GhostLock exploit. See
[`../NOTICE`](../NOTICE).
