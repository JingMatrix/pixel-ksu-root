# cves/ — the exploit research

One vulnerability per subdirectory — sources, plus a README on the bug it exploits — over
shared infrastructure. What each bug is, and how far it has been taken, is the status table
in the [root README](../README.md); this file is about how the directories relate to each
other.

```
cves/
  cve-2026-43499-ghostlock/   futex-PI stack-slot use-after-free
  cve-2026-43049-ffwheel/     uhid/hidpp failed-probe use-after-free
  cve-2026-46242-badepoll/    eventpoll close-versus-close use-after-free
  cve-2026-56945-roguewave/   BigOcean IOMMU fault-handler unlocked list walk
  cve-2026-56914-dirtydock/   GXP unlocked set_page_dirty() during unmap
  cve-2026-64468-frostbind/   binder process-lifetime use-after-free
  cve-2026-64560-zombietick/  POSIX CPU timer freed while queued
  cve-2026-93189-joyride/     hidraw use-after-free behind an unquiesced stop
  cve-2026-49881-telecom/     a component-name check that runs an app's code in system_server
  p0-465827985-stackjump/     a clipboard read past the end of a buffer in system_server
  cve-2026-28594-sealslip/    an unsealed memfd accepted where ashmem is expected
  cve-2026-28662-cookiejar/   a Wi-Fi Direct cookie copied without a length check
  cve-2026-43284-dirtyfrag/   an ESP sequence-word store into a pinned page-cache page
  lib/                        the shared exploitation library — lib/README.md
  targets/                    the offset headers — targets/README.md
  Makefile                    compiles one payload from a resolved recipe
```

## The three that are not kernel bugs

Three directories hold no kernel defect at all, and none of them roots anything on its own.
They are here because a kernel bug is only as reachable as the userspace context you can
reach it from, and enlarging that context is the same work by other means.

`cve-2026-49881-telecom/` is a privilege-domain pivot: a logic flaw in Telecom that runs an
app's code inside `system_server`, the most privileged unprivileged process on the system.
Its live probe is the third domain of [`../domainprobe`](../domainprobe); the directory
holds the writeup, the policy tool and the reachability it establishes.

`cve-2026-28594-sealslip/` is a size-mutation race in `libcutils`, where a forged, unsealed
[`memfd`](https://man7.org/linux/man-pages/man2/memfd_create.2.html) is accepted as a
size-sealed ashmem region and stays resizable while a consumer holds it. The investigation
closed it as denial of service only for an unprivileged attacker:
[SELinux](https://source.android.com/docs/security/features/selinux) admits an app's memfd
to a short list of system services, and none of the reachable consumers has an
out-of-bounds shape. It is kept for what it produced — a presence probe, an authoritative
SELinux reachability matrix, and a live consumer driver — which any future shared-memory
bug inherits rather than rebuilds.

`cve-2026-28662-cookiejar/` is a heap overflow in `wpa_supplicant`. Its interest is the
domain it runs in rather than the overflow itself: a bug whose trigger needs
`CAP_NET_ADMIN` is out of reach from a shell but not from the supplicant's own SELinux
domain. Presence is confirmed; reachability and exploitability are not yet attempted.

## Baseline and candidate: the promotion gate

One chain at a time is the baseline — the one the repo ships and is tested against. Every
other chain here is a candidate: a real exploit ported into the same build-and-drive
framework, held to the same description, and driven by the runner as a
[hunt](../runner/README.md#23-recipes).

The distinction is a property the framework records and can check, not a claim a README
makes. Promotion asks whether a candidate's own chain produces the terminal capability
`CAP_SU`, and it reads that off `[provides].caps` — what a shot has been *observed* to
yield — never off the declared `[properties].provides`. The two fields, and the reason
they are kept apart, are in [`../runner/README.md` §5](../runner/README.md#5-foreign-chain-contract).

Four things have to hold before a candidate becomes the baseline. It must drive its own
chain to root on real hardware, repeatably rather than once. It must deliver `CAP_SU`
through the handoff contract, which is a capability the framework watches a stage produce
rather than a line in a document. It must be composed rather than opaque: a foreign chain
is drivable, and the runner will hunt with it, but a stage that cannot be decomposed into
groom, bridge, read/write and effect is not something the rest of the tree can be built on,
and a candidate declares which it is. And it must resolve through the same target and
addressing model — one target header, one resolver, one set of gates — rather than
introducing a second fingerprinting mechanism to compete with the first.

Promotion then flips `default` between two recipes that already share the resolver, the
handoff, the target headers and the KASLR leak. There is no parallel machinery to migrate.

## How a bug plugs into this tree

A chain joins by being described in three declarative inputs, which
[`../runner/scripts/resolve-recipe.py`](../runner/scripts/resolve-recipe.py) folds into the
`ART_*` make variables and into the runner's contract.

A recipe under [`../runner/recipes/`](../runner/recipes/) names one entry stage per kernel
flavour, plus any non-entry stages: `ghostlock.toml` pairs a 6.1 and a 6.6 entry with the
shared `handoff.suhelper`, while a self-contained standalone binary declares no stages at
all. A stage manifest under [`../runner/stages/`](../runner/stages/) then says how that
entry is built and driven. Finally a [target header](targets/README.md) supplies the
per-build offsets; a stage that needs offsets no other exploit carries may restrict itself
to the builds that have them.

The manifest fields, the invocation shapes and the named gates that refuse an invalid
composition are in [`../runner/README.md`](../runner/README.md) §2 and §5. Adding a device
is [`targets/README.md`](targets/README.md).

## Building a payload

The [`Makefile`](Makefile) compiles one payload from a resolved recipe. The source list is
not written into it: it is composed from the recipe,
[`../data/targets.json`](../data/targets.json) and the stage manifests by the resolver.
Building needs an [NDK](https://developer.android.com/ndk) toolchain. Run from `cves/`:

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk

make TARGET=panther-CP2A.260705.006                   # the default recipe
make TARGET=panther-CP2A.260705.006 RECIPE=zombietick # name a recipe explicitly
make TARGET=panther-CP2A.260705.006 recipes           # list selectable recipes and stages
make TARGET=panther-CP2A.260705.006 check             # run the gates, build nothing
make TARGET=panther-CP2A.260705.006 info              # show the resolved composition
```

Convenience targets map Pixel model names to codenames (`make pixel7`, `make pixel10pro`,
and so on), and `RECIPE=` passes through to them, since make forwards command-line
variables to sub-makes.
[`../runner/scripts/build-payloads.sh`](../runner/scripts/build-payloads.sh) builds the
full shipped set. Output lands in `build/$(TARGET)/`.

Two build knobs are worth knowing. `API` selects the Android API level of the NDK
toolchain. `BUILD_TAG` pins the compile marker in place of `__DATE__ " " __TIME__`, which
is what makes a payload byte-reproducible; it is empty by default, and only the sources
that carry such a marker are affected.

## License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0), inherited from the upstream
[NebuSec](https://github.com/NebuSec/CyberMeowfia) GhostLock exploit. See
[`../NOTICE`](../NOTICE).
