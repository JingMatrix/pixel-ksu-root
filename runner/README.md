# runner — the host machinery that drives an exploit

This directory is the framework. It turns a kernel bug into per-boot root on a stock,
locked Pixel by composing a small set of declarative pieces — recipes, stage manifests, one
resolver — and driving the result through a single shot loop that classifies, budgets and
archives every attempt.

An operator picks a chain by naming a recipe, and the build assembles exactly that or
refuses with a named reason. Selection happens once, in
[scripts/resolve-recipe.py](scripts/resolve-recipe.py), and both `make RECIPE=<name>` and
`./pixel-ksu-root --recipe <name>` call it against the same recipes and manifests, so
build-time and run-time selection cannot drift.

## 1. The pieces

```
../pixel-ksu-root         the runner executable: preflight, resolve, obtain root,
                          late-load kernelsu.ko, verify, teardown
lib/*.sh                  runner-internal modules: log, adb, select, exploit, install
recipes/<name>.toml       a composition: which entry per kernel flavour, what to build
stages/<id>/stage.toml    a stage manifest: build recipe, facts, properties, contract
scripts/resolve-recipe.py the one resolver — feeds both make and the runner
../data/targets.json      device → kernel flavour and offset group
../data/vulns.json        what is known about each bug, and which kernels still carry it
../cves/Makefile          builds a payload from a resolved recipe (cwd = cves/)
```

Everything the runner does over the wire it does through `adb shell` from the host, for
deterministic control flow and complete logs. The libraries under [lib/](lib) are the
runner's own sourced modules, distinct from the standalone research instruments under
`../tools/`.

## 2. Stage and recipe model

### 2.1 Stages

A stage is one composable step, declared by a `stages/<id>/stage.toml` manifest. A manifest
carries:

- `kind` — the tree ships `entry` and `handoff` stages; `groom`, `probe`, `bridge`, `rw`
  and `effect` are design kinds the tree does not yet populate.
- `cve`, `kmi` — the bug it exploits and the kernel flavour or flavours it is valid for.
- `[build]` — how to compile it: `form` (`preload-so`, `static-exe`, `static-pie`), source
  list, include paths, cflags, output name. Source order is load-bearing, because it fixes
  `STT_FILE` order and `.rodata` string-merge order and therefore the output bytes, so the
  lists are deliberately not sorted.
- `[facts]` — the target-header macros the stage `requires` and `forbids`.
- `[properties]` — declared `provides`, `requires_caps` and `retains` capabilities,
  `panic_risk` indexed by whether the slide is known, `retry_safe`, and `destructive`
  writes with their `restores`.
- `[invoke]`, `[markers]`, `[exit_map]`, `[provides]` — the runner contract of
  [§5](#5-foreign-chain-contract).

The shipped stages:

| stage id | kind | cve | kmi | form | composed |
|---|---|---|---|---|---|
| [`entry.ghostlock@6.6`](stages/entry.ghostlock@6.6/stage.toml) | entry | CVE-2026-43499 | android15-6.6 | preload-so | yes |
| [`entry.ghostlock@6.1`](stages/entry.ghostlock@6.1/stage.toml) | entry | CVE-2026-43499 | android14-6.1 | preload-so | yes |
| [`entry.zombietick@6.1`](stages/entry.zombietick@6.1/stage.toml) | entry | CVE-2026-64560 | android14-6.1 | static-exe | no |
| [`handoff.suhelper`](stages/handoff.suhelper/stage.toml) | handoff | — | both | static-pie | yes |

[`handoff.suhelper`](stages/handoff.suhelper/stage.toml) declares no `cve`, though its
output name carries one. It is the single stage that provides `CAP_SU`, the capability that
licenses the runner to install a module at all.

### 2.2 The two GhostLock entries

GhostLock is two entry stages because the module interface differs between kernel flavours.
Both compile the same sources; what differs is a build-time define and the facts each entry
holds the target description to. `[facts]` is what keeps them apart at build time: the 6.6
stage forbids the facts only a 6.1 description carries, and the 6.1 stage requires them, so
pairing the wrong description with an entry is a build error rather than a silent macro
redefinition. The mechanism itself is in
[../cves/cve-2026-43499-ghostlock/README.md](../cves/cve-2026-43499-ghostlock/README.md).

### 2.3 Recipes

A recipe under [recipes/](recipes) is a static, linear plan rather than a small language.
It names one entry stage per kernel flavour, and any non-entry stages built alongside it:

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

`make TARGET=<t>` with no `RECIPE=` resolves whichever recipe is marked `default`.

A recipe with `stages = []` is one entry and nothing else, and that is what makes such a
run a *hunt*: with no stage providing `CAP_SU` there is no handoff to install, so the
runner detects no manager, derives no `ksud` and late-loads nothing. The product of a hunt
is the classified evidence under `../logs/shots/<run>/`.

### 2.4 Resolution and build-time gates

`resolve-recipe.py --target <codename-build> --recipe <name>` reads the recipe, picks the
entry for the target's kernel flavour from [`../data/targets.json`](../data/targets.json),
loads every selected stage manifest, runs the gates below, and emits `make` variables,
JSON, or the runner contract. Any gate exits non-zero with a named `ARCH-G*` error, so an
invalid composition never reaches a phone:

| gate | catches |
|---|---|
| `ARCH-G0-RECIPE` | unknown recipe |
| `ARCH-G0-STAGE` | recipe names a stage id with no manifest |
| `ARCH-G0-TARGET` | unknown target |
| `ARCH-G0-TARGETSET` | stage restricted to a target list, target not in it |
| `ARCH-G0-SCHEMA` | manifest or recipe schema wrong, or a required key missing |
| `ARCH-G0-INVOKE` | the entry's invoke and marker contract is absent or unsatisfiable |
| `ARCH-G1-KMI` | entry's kernel flavour does not match the target's |
| `ARCH-G1-FIXED` | the stage's bug is fixed in the kernel this target runs |
| `ARCH-G1-UNVERIFIED` | the stage's bug has no verdict for this target's kernel |
| `ARCH-G3-FACTS` | a required target fact absent, or a forbidden one present |
| `ARCH-G8-WRITER` | two selected stages claim the same output artifact |
| `ARCH-G9-XSRC` | the target table and the target header disagree about the flavour |

A stage names the bug it exploits, and whether that bug is still present decides whether
the pairing is allowed. [`vuln_status.py`](scripts/lib/vuln_status.py) answers the
question, rather than a list of blessed kernels, because the two directions in time are not
symmetric.

Backward is sound: a kernel built before a fix existed cannot contain it, and neither can
one at or below a point on the same interface that is known to still carry it, since a
stable branch does not un-apply a fix. Forward is not: a branch picks up backports on its
own schedule, so a kernel newer than the fix may or may not have it. This is not a corner
case. A phone can ship a build stamped months after a fix reached the
[Android Common Kernel](https://source.android.com/docs/core/architecture/kernel/android-common)
and still run a kernel from before it, which is precisely the situation the shipped chains
exploit.

Three sources answer the question, strongest first, and only the first can conclude
`fixed`:

| source | from | can conclude |
|---|---|---|
| the kernel's own function | `../data/vulns.json`, read out of that kernel's source | `vulnerable` or `fixed` |
| kernel ordering | the build number, compared only within one interface | `vulnerable` |
| the build fingerprint | the date in the build id, against the date the fix existed | `vulnerable` |

The fingerprint is the weakest and the only one available before anything is downloaded,
which is exactly its job: a build stamped before the fix was authored cannot carry it, and
no image has to be fetched to know that. It bounds the kernel because a build ships a
kernel no newer than itself, and that bound runs one way only.

So the deduction concludes `vulnerable` and never concludes `fixed` from age. `fixed` comes
only from reading the kernel's own source, recorded in
[`../data/vulns.json`](../data/vulns.json) together with the marker that was looked for. A
kernel the tool cannot place is `unknown`, and the refusal names the single command that
settles it: `vuln_status.py --cve <id> --target <t> --derive` range-fetches that build's
boot partition, reads the function and records the verdict, with no device and no root
involved.

An allow-list of kernels gets this exactly backwards. It refuses the older builds that are
certainly vulnerable, and admits nothing it has not already seen.

The same ordering runs on the device. [`select.sh`](lib/select.sh) resolves a phone to a
target row by build, then by codename, then by kernel prefix — the fallbacks exist so an
unlisted build can still be served — and then requires the row's kernel to be the one the
phone is actually running, so the codename fallback cannot hand a newer build the payload
of an older kernel.

The schema gates exist because of a [TOML](https://toml.io/en/v1.0.0) footgun: a bare key
written after a `[table]` header silently becomes a member of that table. The resolver
whitelists the keys of every table and rejects strays, so a `stages = [...]` misplaced
under `[entry]` is a build error rather than a silently disabled gate. `ARCH-G9-XSRC` uses
a second, independent source: a set of markers present in every 6.1 header and absent from
every 6.6 header, so the header itself must agree with the flavour the target table claims
for it. The headers those gates read are documented in
[../cves/targets/README.md](../cves/targets/README.md).

## 3. Addressing model

An exploit here works with three kernel address spaces, given three C types so that a
mistake the runtime would otherwise catch with a silent-zero predicate becomes a compile
error instead:

```c
typedef struct { uint64_t v; } kimage_t;   /* link-time VA, relative to the text base */
typedef struct { uint64_t v; } kdirect_t;  /* linear-map alias — KASLR-free, always live */
typedef struct { uint64_t v; } krun_t;     /* slid runtime VA — needs a known slide */
```

A `kimage_t` is not live until it is either aliased or slid; a `kdirect_t` always is, which
is why the read/write primitives take that type and no other. The
[arm64 memory layout](https://docs.kernel.org/arch/arm64/memory.html) is what makes the
linear alias dependable: it tracks physical memory by a fixed offset, independently of
where the image was loaded.

The slide is one owned value that carries how it was learned:

```c
enum kslide_state { SLIDE_UNKNOWN = 0, SLIDE_SUPPLIED, SLIDE_LEAKED, SLIDE_VERIFIED };
struct kslide { uint64_t base; uint64_t slide; enum kslide_state state; };
```

The conversions are a small, deliberate set: a total and KASLR-free map to the linear
alias; a slide-dependent map for an address you are about to touch, which traps on an
unknown slide; the inverse of that pair; and an explicit, greppable placeholder that yields
an unslid address without trapping.

The base those types are slid by comes from the write-free tracefs leak and nothing else.
Mechanism and cost are in [../cves/lib/kaslr/README.md](../cves/lib/kaslr/README.md).

### 3.1 Why one conversion traps and the other does not

The read/write primitives accept a linear-map address only. Passing a runtime virtual
address where a linear alias is required is the mistake the runtime otherwise guards
against with a predicate whose failure returns a zero indistinguishable from a real read.
Typing the primitives turns that runtime silent zero into a compile error.

The slide-dependent conversion cannot simply abort on an unknown slide, because a
load-bearing idiom paints addresses before the slide is known and refreshes them after: a
forged operations table is filled with image addresses while the slide is still unknown,
and rewritten the instant it lands. Hence two functions rather than one. The conversion
traps on an unknown slide, because an unslid address written into a live kernel object
lands in mapped memory with no visible effect and then retries forever; the placeholder is
the explicit name for an address that has been promised a later refresh. The `uintptr_t`
helpers are thin wrappers over this typed core.

## 4. Runner flow

[`../pixel-ksu-root`](../pixel-ksu-root) drives everything over `adb shell`:

1. Preflight — wait for the device. Skipped only for `--print-contract` with an explicit
   target, which is a host-only question.
2. Recipe selection — with `--recipe <name>`, the runner asks the resolver for the shell
   form of the contract and evaluates it, loading the entry's invoke, marker, exit-map and
   provides tables. With no `--recipe` it reads no manifest and uses built-in defaults.
3. Handoff branch — the runner tests whether the selected chain's capability union contains
   `CAP_SU`. If it does, it detects the KernelSU manager, derives `ksud`, and exits early
   if a module is already resident. If it does not, the run is a hunt.
4. Resolve target — codename, build, kernel release, module interface, and, for a root
   chain, the manager uid.
5. Stage the entry — a `device-exec` entry pushes the one static binary that
   `make RECIPE=<r>` produced for this exact target; a `helper-preload` entry pushes the
   helper plus the prebuilt shared object chosen from `artifacts/`.
6. Obtain root — the loop below.
7. Install, verify, tear down — for a root chain, late-load the signature-locked
   `kernelsu.ko`, then drop the `PATH` shadow so `su` resolves to KernelSU's own, and let
   the driver self-report.

### 4.1 The root loop

Obtaining root is one loop. Each shot fires the entry and asks the root oracle; the retries
bound the read/write race, which is the thing that can reboot the phone.

The KASLR base is the one thing carried between shots. It is fixed for the lifetime of a
boot, so the first iteration on a boot spends a whole shot leaking it, in a process of its
own, and later shots replay the cached value. The separate process is not an accident of
structure: the leak drains a great many pages through the page allocator, and the race that
follows needs that allocator groomable for its own reclaim spray, so the racing process
must arrive cold. Replay also requires the entry to declare that it accepts a base.
GhostLock does; an entry that derives its slide in-process does not, and a hunt with such
an entry leaks afresh on every shot.

Staleness is keyed on the boot time reported by
[`/proc/stat`](https://docs.kernel.org/filesystems/proc.html), never on `boot_id`. That
sysctl's backing pointer is one the exploit tree can repoint, so a sample taken mid-flight
can return attacker-controlled memory and discard a correct base. A change in boot time
clears the cache and the next shot re-leaks.

Root itself is never read out of a log. It is proved out of band, behind an oracle that
first checks whether the chain declares `CAP_SU` at all, so that a leftover `su` from an
earlier run cannot answer for a hunt.

Before the first shot the runner checks the one precondition it can answer rather than
infer: that the rendered device command line is complete and holds no unsubstituted
placeholder. Everything else is observed rather than guessed.

### 4.2 Shot classification

Every shot's device log is archived under `../logs/shots/<run>/` with an index, then
classified into one of eight outcomes, in precedence order: `PANIC`, `HELD`, `PARKED`,
`REFUSED`, `DIRTY`, `PRECONDITION_FAIL`, `PASS`, `MISS`. `RESTORED` rides alongside as a
ledger annotation rather than a terminal state. The classifier is driven by the regular
expressions in the manifest ([§5](#5-foreign-chain-contract)) rather than by control flow,
so a stage that starts emitting a marker is classified without editing the shell.

Nothing is inferred from timing, or from an exit status the host cannot trust. No arm
routes a bare exit status: a loader's early bails return whatever `errno` happened to hold,
and those numbers guarantee nothing.

Three properties of the budget matter. A refusal has its own budget, because a shot that
produced no output almost immediately never started at all — payload not pushed, wrong uid,
temporary directory cleared — and the right response is to settle and retry, rebooting only
on a second refusal within the same boot, rather than to grant a free retry that would loop
forever on a deterministic cause. A panic spends a boot rather than an attempt: the attempt
budget counts classifiable attempts, a panic decrements its own separate budget, and a cap
on total shots keeps refusals and panics from spinning indefinitely. And a parked shot is
not killed on the clock, because a stage may park by design, exiting being the thing that
would free its forged objects and panic; the deadline kills only a shot proven hung by a
stale heartbeat, and a shot holding a system-wide kernel hook live in its own pages is
surfaced to the operator and never rebooted, since rebooting would free that page into a
use-after-free.

A stage that corrupts kernel state declares the writes as destructive and the repairs as
restores, and an undischarged debt is a defect rather than a side effect: a dirty boot is
journalled to a per-boot file, so that neither a later shot nor a later run composes over
damaged kernel state.

## 5. Foreign-chain contract

Some exploits cannot be decomposed into the stage kinds above — the tree has the binary but
not source structured as stages, or a monolith owns its groom, bridge, read/write and
effect inline. A *foreign chain* models such an exploit as an opaque process behind a
declared contract, so that the runner drives it through the same shot loop, with the same
budgets and per-shot archives, without composing it into shared stages.

There are two invocation shapes and one manifest field distinguishing them: a shared object
loaded by the helper, or a static binary with its own `main()`. Both are described by four
manifest tables, which the resolver validates and flattens, failing with a named gate
rather than delivering a malformed command line to a phone.

### `[invoke]` — how to run it

```toml
[invoke]
kind = "device-exec"                 # or "helper-preload"
artifact_source = "build"            # "build": cves/build/<target>/<output>
                                     # "runner": select.sh picks from artifacts/
dest = "/data/local/tmp/cve64560-entry"
mode = "755"
command = "cd @DEV_TMP@; @DEV_ENTRY@ > @DEV_LOG@ 2>&1"
accepts_base = false                 # can a cached base be replayed into it?
```

`command` is a template with `@NAME@` placeholders. Each invocation kind allows a fixed
placeholder set: the preload form may name the helper and the payload, the exec form may
name the entry, and both share the temporary directory, the log path, the KASLR
environment, the client and app uids, the derived `ksud`, the module interface and the
manager package. Any other placeholder fails the run, so a typo can never reach the phone.

The last three name what the operator chose and what the device resolved to. A stage that
loads KernelSU itself takes them through these placeholders rather than naming them,
because a manifest that spelled out a package name and a kernel flavour would be pinned to
one phone and one manager, and would try to load the wrong module on any other. They render
empty on a hunt that skipped manager detection, and a stage that uses them must read empty
as "do not attempt the load" rather than substitute a default.

Whether an entry accepts a cached base and whether its command line mentions the KASLR
environment must agree; the gate makes the manifest say which. `artifact_source = "build"`
binds the binary that runs to the one `make RECIPE=<r>` built for that target, while
`"runner"` says the payload is a prebuilt shared object chosen from `artifacts/`, so a
device can resolve to a payload built for a different codename on the same kernel.

### `[markers]` — how to classify a shot

```toml
[markers]
pass         = 'STAGE0_GATE_PASS slide=0x[0-9a-f]+ kernel_base=0x[0-9a-f]+'
gate_fail    = 'TARGET_PROFILE_GATE_FAIL'
restore_pass = '[A-Z][A-Z0-9_]*_RESTORE_PASS'
restore_bad  = '[A-Z][A-Z0-9_]*_(RESTORE_NOT_PROVEN|RESTORE_UNREACHABLE|RESTORE_FAIL)'
heartbeat    = '[A-Z][A-Z0-9_]*_HEARTBEAT[[:space:]]+seq=[0-9]+'
```

These fill the runner's overridable marker expressions. `pass` is mandatory — it is how the
classifier knows a shot reached the stage's goal — and the resolver rejects a manifest
without it. `gate_fail` must be narrow, because it maps to a precondition failure that
aborts the whole run: a manifest lists only genuinely permanent failures there and routes
transient preflight bails through the exit map to a refusal instead. An operator's
environment override wins over the manifest, and the runner records that it did.

### `[exit_map]` — exit status to outcome

```toml
[exit_map]
"2" = "REFUSED"
"3" = "REFUSED"
```

An exit map may only name outcomes from the [§4.2](#42-shot-classification) vocabulary. It
is a refinement consulted only where a shot would otherwise score a bare miss; markers
always win. A map is worth populating when the binary is a single writer with a fixed,
documented set of exit codes, and worth leaving empty otherwise. It is a refinement rather
than an oracle in a second sense as well: `adb shell` forwards a remote exit status only
under the v2 shell protocol.

### `[provides]` — what a shot yields

```toml
[provides]
caps  = ["CAP_SLIDE"]                 # OBSERVED capability
field = 'kernel_base=0x[0-9a-f]+'     # the value inside the pass marker
label = "kernel_base"                 # how to report it
```

`provides.caps` is what a shot has actually been observed to yield, and is deliberately
distinct from `[properties].provides`, the declared capability graph the stage would supply
once composed. The resolver unions the declared capabilities across every selected stage,
and the runner reads that union to decide whether the chain can produce root at all.

`./pixel-ksu-root --recipe <name> --target <t> --print-contract` renders the full resolved
contract and the exact device command line, host-side, touching no phone. It is the check
that a manifest says what the runner will do.

## 6. How a candidate plugs in

Three steps, in order of what each one buys. First, a stage manifest and a recipe that
names it, which is enough to build through the same resolver and gates as any other stage.
Second, the [§5](#5-foreign-chain-contract) contract, which is enough for
`./pixel-ksu-root --recipe <name>` to drive the binary as an opaque process on the hunt
path. Third, composition into shared groom, bridge, read/write, effect and handoff stages,
so that it reuses the addressing types, the restore ledger and the read/write primitive.
Each manifest states whether it has got that far.

The promotion gate that decides which chain the repo ships is in
[../cves/README.md](../cves/README.md).

### See also

- [../README.md](../README.md) — landing page, status record, quickstart
- [../cves/README.md](../cves/README.md) — the exploit research and the promotion gate
- [../cves/targets/README.md](../cves/targets/README.md) — the offset headers
- [../cves/lib/kaslr/README.md](../cves/lib/kaslr/README.md) — the write-free KASLR leak
- [../cves/Makefile](../cves/Makefile) — the Makefile that consumes the resolver
