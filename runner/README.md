# runner — the host machinery that drives an exploit

This directory is the framework. It turns a kernel CVE into per-boot root on a
stock, locked Pixel by composing a small set of declarative pieces — recipes,
stage manifests, one resolver — and driving the result through a single shot
loop that classifies, budgets and archives every attempt.

An operator picks a chain by naming a recipe, and the build assembles exactly
that or refuses with a named reason. Selection happens once, in
[scripts/resolve-recipe.py](scripts/resolve-recipe.py), and both
`make RECIPE=<name>` and `./pixel-ksu-root --recipe <name>` call it against the
same recipes and manifests, so build-time and run-time selection cannot drift
([resolve-recipe.py](scripts/resolve-recipe.py#L9)).

## 1. The pieces

```
../pixel-ksu-root         the runner executable: preflight, resolve, obtain root,
                          late-load kernelsu.ko, verify, teardown
lib/*.sh                  runner-internal modules: log, adb, select, exploit, install
recipes/<name>.toml       a composition: which entry per kernel flavour, what to build
stages/<id>/stage.toml    a stage manifest: build recipe, facts, properties, contract
scripts/resolve-recipe.py the one resolver — feeds both make and the runner
../data/targets.json      device -> kernel-flavour + offset-group table
../cves/Makefile          builds a payload from a resolved recipe (cwd = cves/)
```

Everything the runner does over the wire it does through `adb shell` from the
host, for deterministic control flow and full logs
([../pixel-ksu-root](../pixel-ksu-root#L9)). The libraries under [lib/](lib) are
the runner's own sourced modules, distinct from the standalone research
instruments under `../tools/`.

## 2. Stage and recipe model

### 2.1 Stages

A stage is one composable step, declared by a `stages/<id>/stage.toml` manifest.
A manifest carries:

- `kind` — the tree ships `entry` and `handoff` stages; `groom` / `probe` /
  `bridge` / `rw` / `effect` are design kinds the tree does not populate.
- `cve`, `kmi` — the CVE it exploits and the kernel flavour(s) it is valid for.
- `[build]` — how to compile it: `form` (`preload-so`, `static-exe`,
  `static-pie`), source list, include paths, cflags, output name. Source order is
  load-bearing: it fixes STT_FILE order and `.rodata` string-merge order, and
  therefore the output bytes, so the lists are not sorted
  ([entry.ghostlock@6.6](stages/entry.ghostlock@6.6/stage.toml#L25)).
- `[facts]` — the target-header macros the stage `requires` and `forbids`.
- `[properties]` — declared `provides` / `requires_caps` / `retains`
  capabilities, `panic_risk` indexed by `(pre_slide, post_slide)`, `retry_safe`,
  and `destructive` writes with their `restores`
  ([entry.ghostlock@6.6](stages/entry.ghostlock@6.6/stage.toml#L105)).
- `[invoke] [markers] [exit_map] [provides]` — the runner contract of
  [§5](#5-foreign-chain-contract).

The shipped stages:

| stage id | kind | cve | kmi | form | composed |
|---|---|---|---|---|---|
| [`entry.ghostlock@6.6`](stages/entry.ghostlock@6.6/stage.toml) | entry | CVE-2026-43499 | android15-6.6 | preload-so | yes |
| [`entry.ghostlock@6.1`](stages/entry.ghostlock@6.1/stage.toml) | entry | CVE-2026-43499 | android14-6.1 | preload-so | yes |
| [`entry.cve64560@6.1`](stages/entry.cve64560@6.1/stage.toml) | entry | CVE-2026-64560 | android14-6.1 | static-exe | [no](stages/entry.cve64560@6.1/stage.toml#L34) |
| [`handoff.suhelper`](stages/handoff.suhelper/stage.toml) | handoff | — | both | static-pie | yes |

[`handoff.suhelper`](stages/handoff.suhelper/stage.toml) declares no `cve`,
though its output name carries CVE-2026-43499
([handoff.suhelper](stages/handoff.suhelper/stage.toml#L6)). It is the one stage
that `provides = ["CAP_SU"]`
([handoff.suhelper](stages/handoff.suhelper/stage.toml#L38)) — the capability
that licenses the runner to install a module at all.

### 2.2 The two GhostLock source sets

GhostLock is two entry stages because the KMI differs:
[`@6.6`](stages/entry.ghostlock@6.6/stage.toml#L27) compiles the sources under
`../cves/cve-2026-43499-ghostlock/`,
[`@6.1`](stages/entry.ghostlock@6.1/stage.toml#L36) the mirror under `.../61/`
(the mechanism is in
[../cves/cve-2026-43499-ghostlock/README.md](../cves/cve-2026-43499-ghostlock/README.md)).
`[facts]` keeps them apart at build time: the `forbids` list on
[`@6.6`](stages/entry.ghostlock@6.6/stage.toml#L75) turns pairing a 6.1 target
header with the 6.6 source set into a build error rather than a silent macro
redefinition, and the mirrored `requires` on
[`@6.1`](stages/entry.ghostlock@6.1/stage.toml#L67) does the reverse.

### 2.3 Recipes

A recipe ([recipes/<name>.toml](recipes)) is a static, linear plan — not a DSL.
It names one entry stage per kernel flavour and any non-entry stages built
alongside it:

```toml
# recipes/ghostlock.toml
schema  = 1
name    = "ghostlock"
default = true
stages  = ["handoff.suhelper"]      # bare key: must precede the first [table]
[entry]
"android14-6.1" = "entry.ghostlock@6.1"
"android15-6.6" = "entry.ghostlock@6.6"
[goals]
all     = ["entry", "handoff.suhelper"]
release = ["entry:release"]
```

`make TARGET=<t>` with no `RECIPE=` resolves the recipe marked
[`default`](recipes/ghostlock.toml#L13).

[`recipes/cve64560.toml`](recipes/cve64560.toml) is one entry and no non-entry
stages ([`stages = []`](recipes/cve64560.toml#L33)). That is what makes a
`--recipe cve64560` run a **hunt** — with no stage providing `CAP_SU` there is no
handoff to install, so the runner detects no manager, derives no ksud and
late-loads nothing ([../pixel-ksu-root](../pixel-ksu-root#L344)). The product of
a hunt is the classified evidence in `../logs/shots/<run>/index.tsv`.

### 2.4 Resolution and build-time gates

[`scripts/resolve-recipe.py --target <codename-build> --recipe <name>`](scripts/resolve-recipe.py#L363)
reads the recipe, picks the entry for the target's kernel flavour (from
[`../data/targets.json`](../data/targets.json) via
[`device_kmi()`](scripts/resolve-recipe.py#L153)), loads every selected stage
manifest, runs the gates below, and emits `make` variables (`--format make`),
JSON (`--format json`), or the runner contract (`--format shell`). Any gate
exits non-zero with a named `ARCH-G*` error, so an invalid composition never
reaches a phone:

| gate | catches | source |
|---|---|---|
| `ARCH-G0-RECIPE` | unknown recipe | [resolve-recipe.py](scripts/resolve-recipe.py#L387) |
| `ARCH-G0-STAGE` | recipe names a stage id with no `stages/<id>/stage.toml` | [resolve-recipe.py](scripts/resolve-recipe.py#L464) |
| `ARCH-G0-TARGET` | unknown target (no `../cves/targets/<t>/`) | [resolve-recipe.py](scripts/resolve-recipe.py#L380) |
| `ARCH-G0-TARGETSET` | stage restricted to a target list, target not in it | [resolve-recipe.py](scripts/resolve-recipe.py#L505) |
| `ARCH-G0-SCHEMA` | manifest/recipe schema or a required key missing | [resolve-recipe.py](scripts/resolve-recipe.py#L474) |
| `ARCH-G0-INVOKE` | `--format shell` but the entry's `{invoke, markers}` contract is absent or unsatisfiable | [resolve-recipe.py](scripts/resolve-recipe.py#L235) |
| `ARCH-G1-KMI` | entry's kernel flavour does not match the target's | [resolve-recipe.py](scripts/resolve-recipe.py#L450) |
| `ARCH-G3-FACTS` | a required target fact absent from (or a forbidden one present in) the header | [resolve-recipe.py](scripts/resolve-recipe.py#L529) |
| `ARCH-G8-WRITER` | two selected stages claim the same output artifact | [resolve-recipe.py](scripts/resolve-recipe.py#L590) |
| `ARCH-G9-XSRC` | `../data/targets.json` and the target header disagree about the flavour | [resolve-recipe.py](scripts/resolve-recipe.py#L436) |

The schema gates exist because of a TOML footgun: a bare key written after a
`[table]` header silently becomes a member of that table. The resolver
whitelists the keys of every table
([`STAGE_KEYS`](scripts/resolve-recipe.py#L69),
[`RECIPE_KEYS`](scripts/resolve-recipe.py#L103)) and rejects strays, so a
`stages = [...]` misplaced under `[entry]` is a build error rather than a
silently disabled gate. `ARCH-G9-XSRC` uses a second, independent source: a set
of [`KMI_MARKERS`](scripts/resolve-recipe.py#L56) present in every android14-6.1
header and absent from every android15-6.6 header, so the header itself must
agree with the flavour [`../data/targets.json`](../data/targets.json) claims for
it. The per-device offset headers those gates read are documented in
[../cves/targets/README.md](../cves/targets/README.md).

## 3. Addressing model

The exploit works with three kernel address spaces, given three C types so a
mistake the runtime otherwise catches with a silent-zero predicate becomes a
compile error. They are defined in
[`../cves/cve-2026-43499-ghostlock/61/common.h`](../cves/cve-2026-43499-ghostlock/61/common.h#L201)
and implemented in
[`.../61/util.c`](../cves/cve-2026-43499-ghostlock/61/util.c):

```c
typedef struct { uint64_t v; } kimage_t;   /* link-time VA, KIMAGE_TEXT_BASE-relative */
typedef struct { uint64_t v; } kdirect_t;  /* physmap/linear alias — KASLR-free, always live */
typedef struct { uint64_t v; } krun_t;     /* slid runtime VA — needs a known slide */
```

A `kimage_t` is not live until either aliased or slid; a `kdirect_t` always is,
which is why the R/W primitives take that type and no other.

The slide is one owned value that carries how it was learned:

```c
enum kslide_state { SLIDE_UNKNOWN = 0, SLIDE_SUPPLIED, SLIDE_LEAKED, SLIDE_VERIFIED };
struct kslide { uint64_t base; uint64_t slide; enum kslide_state state; };
```

([common.h](../cves/cve-2026-43499-ghostlock/61/common.h#L208)). The conversions
live in [util.c](../cves/cve-2026-43499-ghostlock/61/util.c):

- [`k_direct(kimage_t)`](../cves/cve-2026-43499-ghostlock/61/util.c#L305) —
  total, KASLR-free; the physmap alias.
- [`k_run(const struct kslide *, kimage_t)`](../cves/cve-2026-43499-ghostlock/61/util.c#L315)
  — for an address you are about to touch; traps on an unknown slide.
- [`k_direct_to_run(...)`](../cves/cve-2026-43499-ghostlock/61/util.c#L336) — the
  inverse pair.
- [`k_image_raw(kimage_t)`](../cves/cve-2026-43499-ghostlock/61/util.c#L340) — a
  deliberate, greppable unslid placeholder that does not trap.

The base those types are slid by comes from the write-free tracefs leak and
nothing else — mechanism, cost and per-build offsets in
[../cves/kaslr/README.md](../cves/kaslr/README.md).

### 3.1 Why `k_run` traps but `k_image_raw` does not

The R/W primitives accept `kdirect_t` only. Passing a runtime VA where a physmap
alias is required is the mistake the runtime otherwise guards against with a
silent predicate,
[`is_direct_ptr`](../cves/cve-2026-43499-ghostlock/61/util.c#L902), whose failure
returns a zero indistinguishable from a real read (it gates every read and write
in [pipe.c](../cves/cve-2026-43499-ghostlock/61/pipe.c#L354)). Typing the
primitives on `kdirect_t` turns that runtime silent-zero into a compile error.

`k_run` cannot simply abort on an unknown slide, because a load-bearing idiom
paints addresses before the slide is known and refreshes them after:
[`put_fake_fops_table()`](../cves/cve-2026-43499-ghostlock/61/util.c#L388) fills
the fake fops slots with image addresses while the slide is still
`SLIDE_UNKNOWN`, and
[`refresh_fake_fops_text()`](../cves/cve-2026-43499-ghostlock/61/fops.c#L638)
rewrites them the instant it lands. Hence two functions:
[`k_run` traps on `SLIDE_UNKNOWN`](../cves/cve-2026-43499-ghostlock/61/util.c#L316),
because an unslid address written into a live kernel object lands in mapped RAM
with no visible effect and retries forever; `k_image_raw` is the explicit name
for a placeholder promised a later refresh. The `uintptr_t` helpers are thin
wrappers over this typed core
([common.h](../cves/cve-2026-43499-ghostlock/61/common.h#L195)).

## 4. Runner flow

[`../pixel-ksu-root`](../pixel-ksu-root) drives everything over `adb shell`. Its
flow:

1. Preflight — wait for the device, skipped only for a `--print-contract` with
   an explicit `TARGET`, which is a host-only question
   ([../pixel-ksu-root](../pixel-ksu-root#L283)).
2. Recipe selection — with `--recipe <name>` set,
   [`load_entry_contract()`](lib/exploit.sh#L185) calls
   [`resolve-recipe.py --format shell`](scripts/resolve-recipe.py#L636) and
   `eval`s the result, loading the entry's invoke/markers/exit-map/provides
   contract ([../pixel-ksu-root](../pixel-ksu-root#L308)). With no `--recipe` the
   runner reads no manifest and uses the
   [built-in `INVOKE_*` / `MARK_*` defaults in lib/exploit.sh](lib/exploit.sh#L131).
3. Handoff branch — [`chain_has_su`](lib/exploit.sh#L806) tests whether the
   selected chain's capability union contains `CAP_SU`. If it does, the runner
   detects the KernelSU manager, derives `ksud`, and early-exits if a module is
   already resident ([../pixel-ksu-root](../pixel-ksu-root#L327)). If not, the
   run is the hunt of [§2.3](#23-recipes).
4. Resolve target — codename, build, kernel release, kmi, and (for a root chain)
   the manager uid, via [`resolve_target()`](lib/select.sh#L16).
5. Stage the entry — a `device-exec` entry pushes the one static binary
   `make RECIPE=<r>` produced for this exact target
   ([../pixel-ksu-root](../pixel-ksu-root#L457)); a `helper-preload` entry pushes
   `cve-helper` plus the prebuilt `.so` that
   [`resolve_target()`](lib/select.sh#L16) picks from `artifacts/`
   ([../pixel-ksu-root](../pixel-ksu-root#L469)).
6. Obtain root — [`obtain_root()`](lib/exploit.sh#L983), below.
7. Install / verify / teardown — for a root chain,
   [`install_ksu`](lib/install.sh#L62) late-loads the signature-locked
   `kernelsu.ko`, then [`teardown_staging`](lib/install.sh#L184) drops the PATH
   shadow so `su` resolves to KernelSU's `su`, and the driver self-reports
   ([../pixel-ksu-root](../pixel-ksu-root#L634)).

### 4.1 The root loop

[`obtain_root()`](lib/exploit.sh#L983) is one loop. Each shot fires the entry and
asks the root oracle; the retries bound the main-route R/W race, which is the
thing that can reboot the phone ([lib/exploit.sh](lib/exploit.sh#L1019)).

The KASLR base is the one thing carried between shots. It is fixed for the
lifetime of a boot, so the first iteration on a boot spends a whole shot leaking
it — `KASLR_LEAK_ONLY=1`, a process of its own
([lib/exploit.sh](lib/exploit.sh#L1081)) — and later shots replay the cached value
through `KASLR_BASE`. The separate process is what leaves the racing process
arriving cold: the leak drains thousands of pages through the page allocator, and
the race that follows needs that allocator groomable for its order-3 reclaim
spray ([lib/exploit.sh](lib/exploit.sh#L1074)). Replay also requires the entry to
declare `accepts_base`: GhostLock does
([entry.ghostlock@6.1](stages/entry.ghostlock@6.1/stage.toml#L135)), the 64560
entry derives its slide in-process and reads no `KASLR_BASE`
([entry.cve64560@6.1](stages/entry.cve64560@6.1/stage.toml#L113)), so a
`--recipe cve64560` hunt leaks afresh on every shot.

Staleness is keyed on
[`/proc/stat btime`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/fs/proc/stat.c) via [`boot_epoch()`](lib/adb.sh#L51), never on [`boot_id`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/char/random.c):
that sysctl's `.data` is a pointer the exploit tree can repoint, so a sample
taken mid-flight can return attacker-pointed memory and throw away a correct base
([lib/adb.sh](lib/adb.sh#L43)). A btime change clears the cache and the next shot
re-leaks.

Root itself is never read out of a log. It is proved out of band by
[`have_root`](lib/adb.sh#L170) behind [`root_oracle`](lib/exploit.sh#L813), which
first checks that the chain declares `CAP_SU` at all — a hunt must not have a
leftover `$DEV_SU` from an earlier GhostLock run answer for it.

Before the first shot the runner checks the one precondition it can answer rather
than infer: that the rendered device command line is complete and holds no
unsubstituted `@PLACEHOLDER@`
([lib/exploit.sh](lib/exploit.sh#L1010)). Everything else is observed, not
guessed.

### 4.2 Shot classification

Every shot's device log is archived under `../logs/shots/<run>/` with an
`index.tsv` ([`archive_shot`](lib/exploit.sh#L364)), then classified by
[`classify_shot()`](lib/exploit.sh#L690) into one of eight outcomes, in
precedence order: `PANIC`, `HELD`, `PARKED`, `REFUSED`, `DIRTY`,
`PRECONDITION_FAIL`, `PASS`, `MISS` — with `RESTORED` a ledger annotation
carried alongside rather than a terminal state. The classifier is driven by the
`MARK_*` EREs from the manifest ([§5](#5-foreign-chain-contract)), not by
control flow, so a stage that starts emitting a marker is classified without
editing the shell ([lib/exploit.sh](lib/exploit.sh#L49)).

Nothing is inferred from timing or from an exit status the host cannot trust. No
arm routes a bare exit status: the loader's early bails return
`errno ? errno : <fixed>`, and those numbers guarantee nothing
([lib/exploit.sh](lib/exploit.sh#L728)).

Three properties of the budget matter:

- `REFUSED` has its own budget. A shot that produced no output in under
  `REFUSED_WALL` seconds never started (payload not pushed, wrong uid,
  `/data/local/tmp` cleared). Its response is settle-and-retry, rebooting only on
  a second refusal on the same boot — not a free retry that would loop forever on
  a deterministic cause ([lib/exploit.sh](lib/exploit.sh#L1153)).
- `PANIC` spends a boot, not an attempt. `ROOT_MAX` (default 12) counts
  classifiable attempts; a panic decrements its own `PANIC_MAX`
  ([lib/exploit.sh](lib/exploit.sh#L1136)). A separate cap on total shots keeps
  refusals and panics from spinning forever
  ([lib/exploit.sh](lib/exploit.sh#L1051)).
- A parked shot is not killed on the clock. A stage may park by design, because
  exiting would free its forged objects and panic. The deadline SIGKILLs only a
  shot proven hung by a stale `HEARTBEAT`
  ([lib/exploit.sh](lib/exploit.sh#L646)); with no heartbeat the shot is `PARKED`
  and the caller reboots deliberately. A stage announcing
  [`MARK_HELD`](lib/exploit.sh#L104) — a system-wide kernel hook held live in its
  own pages — is surfaced to the operator and never rebooted, because rebooting
  would free that page into a UAF ([lib/exploit.sh](lib/exploit.sh#L619)).

A stage that corrupts kernel state declares the writes in
`[properties].destructive` and the repairs in `restores`
([entry.ghostlock@6.6](stages/entry.ghostlock@6.6/stage.toml#L105)), and an
undischarged debt is a defect rather than a side effect: a `DIRTY` boot is
journalled to a per-boot dirty file via
[`mark_boot_dirty`](lib/exploit.sh#L468) so neither a later shot nor a later run
composes over damaged kernel state.

## 5. Foreign-chain contract

Some exploits cannot be decomposed into the stage kinds above — the tree has the
binary but not source structured as stages, or a monolith owns its groom,
bridge, R/W and effect inline. A **foreign chain** models such an exploit as an
opaque process behind a declared contract, so the runner drives it through the
same shot loop (budgets, `settle_boot`, per-shot archives,
[`classify_shot`](lib/exploit.sh#L690)) a composed chain gets, without composing
it into shared stages ([lib/exploit.sh](lib/exploit.sh#L119)).

Two invocation shapes, one manifest field. GhostLock is a `.so` dlopen'ed by
[`cve-helper --run-payload`](../cves/cve-2026-43499-ghostlock/su_daemon.c#L975);
CVE-2026-64560 is a static NDK binary with its own `main()`. Both are described
by four manifest tables, which
[`contract_of()`](scripts/resolve-recipe.py#L226) validates and flattens,
failing with a named `ARCH-G0-INVOKE` / `ARCH-G0-SCHEMA` gate rather than
delivering a malformed command line to a phone.

### `[invoke]` — how to run it

```toml
[invoke]
kind = "device-exec"                 # or "helper-preload"
artifact_source = "build"            # "build": cves/build/<target>/<output>
                                     # "runner": lib/select.sh picks from artifacts/
dest = "/data/local/tmp/cve64560-entry"
mode = "755"
command = "cd @DEV_TMP@; @DEV_ENTRY@ > @DEV_LOG@ 2>&1"
accepts_base = false                 # can a cached base be replayed into it?
```

`command` is a template with `@NAME@` placeholders that
[`render_invoke()`](lib/exploit.sh#L156) substitutes. Each invocation `kind`
allows a fixed placeholder set —
[`INVOKE_FORMS`](scripts/resolve-recipe.py#L91): `helper-preload` may use
`@DEV_HELPER@`/`@DEV_PAYLOAD@`, `device-exec` may use `@DEV_ENTRY@`, and both
share `@DEV_TMP@`, `@DEV_LOG@`, `@KASLR_ENV@`, `@CLIENT_UID@`, `@APP_UID@`. Any
other placeholder [fails the run](scripts/resolve-recipe.py#L259), so a typo can
never reach the phone. `accepts_base` and the presence of `@KASLR_ENV@`
[must agree](scripts/resolve-recipe.py#L266) — an entry either can be replayed
with a cached base or cannot, and the gate makes it say which.
`artifact_source = "build"` binds the binary that runs to the one
`make RECIPE=<r>` built for that target
([entry.cve64560@6.1](stages/entry.cve64560@6.1/stage.toml#L97)); `"runner"`
says the payload is a prebuilt `.so` chosen from `artifacts/`, so a device can
resolve to a payload built for a different codename on the same kernel
([entry.ghostlock@6.1](stages/entry.ghostlock@6.1/stage.toml#L126)).

### `[markers]` — how to classify a shot

```toml
[markers]
pass         = 'STAGE0_GATE_PASS slide=0x[0-9a-f]+ kernel_base=0x[0-9a-f]+'
gate_fail    = 'TARGET_PROFILE_GATE_FAIL'
restore_pass = '[A-Z][A-Z0-9_]*_RESTORE_PASS'
restore_bad  = '[A-Z][A-Z0-9_]*_(RESTORE_NOT_PROVEN|RESTORE_UNREACHABLE|RESTORE_FAIL)'
heartbeat    = '[A-Z][A-Z0-9_]*_HEARTBEAT[[:space:]]+seq=[0-9]+'
```

These fill the runner's overridable `MARK_*` EREs. `pass` is mandatory — it is
how [`classify_shot`](lib/exploit.sh#L735) knows a shot reached the stage's
goal, and the resolver
[rejects a manifest without it](scripts/resolve-recipe.py#L308). `gate_fail`
must be narrow: it maps to `PRECONDITION_FAIL`, which aborts the whole run, so a
manifest lists only genuinely permanent failures there and routes transient
preflight bails through the exit map to `REFUSED` instead — 64560 keeps
`gate_fail` to the single
[`TARGET_PROFILE_GATE_FAIL`](stages/entry.cve64560@6.1/stage.toml#L140). An
operator's environment `MARK_*` override wins over the manifest, which
[`_contract_set`](lib/exploit.sh#L176) records.

### `[exit_map]` — exit status → outcome

```toml
[exit_map]
"2" = "REFUSED"
"3" = "REFUSED"
```

An exit map may only name outcomes from the
[§4.2](#42-shot-classification) vocabulary
([`OUTCOMES`](scripts/resolve-recipe.py#L99)). It is a refinement consulted
only where a shot would otherwise score a bare `MISS`
([`exit_outcome`](lib/exploit.sh#L794) sits below every marker arm in
[`classify_shot`](lib/exploit.sh#L690)); markers always win. GhostLock's map is
[empty](stages/entry.ghostlock@6.1/stage.toml#L155) for the reason in
[§4.2](#42-shot-classification); 64560's
[is populated](stages/entry.cve64560@6.1/stage.toml#L188) because its binary is
a single writer with a fixed, documented set of exit codes. The map is a
refinement and not an oracle in a second sense too: `adb shell` forwards a
remote exit status only under the v2 shell protocol.

### `[provides]` — what a shot yields

```toml
[provides]
caps  = ["CAP_SLIDE"]                 # OBSERVED capability
field = 'kernel_base=0x[0-9a-f]+'     # the value inside the pass marker
label = "kernel_base"                 # how to report it
```

`provides.caps` is what a shot has actually been observed to yield, distinct
from `[properties].provides`, which is the declared capability graph the stage
would supply once composed
([entry.cve64560@6.1](stages/entry.cve64560@6.1/stage.toml#L81)). The resolver
unions `[properties].provides` across every selected stage into `CHAIN_CAPS`
([`contract_of`](scripts/resolve-recipe.py#L226)), and
[`chain_has_su`](lib/exploit.sh#L806) reads that union to decide whether the
chain can produce root at all.

`./pixel-ksu-root --recipe <name> --target <t> --print-contract` renders the
full resolved contract and the exact device command line, host-side, touching no
phone ([`print_contract`](lib/exploit.sh#L272)) — the check that a manifest says
what the runner will do.

## 6. How a candidate plugs in

Three steps, in order of what each one buys:

1. A `stages/entry.<cve>@<kmi>/stage.toml` and a `recipes/<cve>.toml` that names
   it — enough to build through the same resolver and gates as any other stage
   ([§2](#2-stage-and-recipe-model)).
2. The [§5](#5-foreign-chain-contract) contract — enough for
   `./pixel-ksu-root --recipe <cve>` to drive the binary as an opaque process on
   the hunt path of [§2.3](#23-recipes).
3. Composition into shared `groom`/`bridge`/`rw`/`effect`/`handoff` stages, so it
   reuses the addressing types, the restore ledger and the R/W primitive. Each
   manifest states whether it has got there with
   [`composed`](stages/entry.cve64560@6.1/stage.toml#L34).

The promotion gate that decides which chain the repo ships is in
[../cves/README.md](../cves/README.md).

### See also

- [../README.md](../README.md) — landing page, status record, quickstart
- [../cves/README.md](../cves/README.md) — the exploit research and the promotion gate
- [../cves/targets/README.md](../cves/targets/README.md) — shared offset headers
- [../cves/kaslr/README.md](../cves/kaslr/README.md) — the write-free KASLR leak
- The Makefile that consumes the resolver: [../cves/Makefile](../cves/Makefile)
