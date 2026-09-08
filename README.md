# pixel-ksu-root

Root a stock, locked-bootloader Google Pixel from an unprivileged `adb shell`, using
a kernel CVE — no unlock, no flash, no vendor help.

A userspace-reachable CVE gives a short-lived kernel read/write primitive, which
late-loads a KernelSU module (`kernelsu.ko`) into the running GKI kernel; root is handed
to whichever KernelSU manager is already installed. Nothing touches a partition, so a
reboot is the uninstall. The flow runs from the host over `adb` through one executable,
[`./pixel-ksu-root`](pixel-ksu-root).

## Status

| CVE | the bug | where it stands |
|---|---|---|
| [CVE-2026-43499](cves/cve-2026-43499-ghostlock/README.md) — GhostLock | a futex PI walk follows an `rt_mutex_waiter` read out of a stack slot `pselect(2)` has re-occupied | works — hardware-verified on panther; the [`default`](runner/recipes/ghostlock.toml#L13) recipe, so a bare run takes it |
| [CVE-2026-64560](cves/cve-2026-64560/README.md) | a process-wide POSIX CPU timer is freed while still queued, because `posix_cpu_timer_del()` returns early once `de_thread()` has nulled `->sighand` | hunt only; builds for `panther-CP2A.260705.006` alone, and `CAP_SLIDE` is the only capability observed on hardware |
| [CVE-2026-64468](cves/cve-2026-64468/README.md) | [`binder_free_transaction()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/android/binder.c) dereferences `t->to_proc` without holding a reference on it | hunt only; the bug is unpatched on panther and the vulnerable read executes, but the race is lost on bare metal |
| [CVE-2026-46242](cves/cve-2026-46242-badepoll/README.md) — Bad Epoll | [`__ep_remove()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/fs/eventpoll.c) clears `file->f_ep` and keeps using the file, so a concurrent `__fput()` frees the eventpoll it is still writing through | hunt only; unpatched on panther, and the close-vs-close window **is won** there — 12 of 12 hunt shots PASS, ~1 win per 490k rounds (median 412k), about one every 36 s of racing, so the UAF write lands. Escalated: the orphaned epitem outlives its target and the dangling `struct file` is ours (`ORPHAN CONFIRMED`), which is the cross-cache's precondition; nothing consumes it yet. The only entry needing neither root nor a reboot |

A hunt is a recipe with no `CAP_SU` handoff: the runner classifies and archives shots
instead of reporting root ([runner/README.md §2.3](runner/README.md#23-recipes)). What a
chain must show to take the `default` recipe: [cves/README.md](cves/README.md).

## Quickstart

You need `adb` with the device authorized, a stock locked Pixel on a
[supported build](#supported-devices), a KernelSU manager installed (its APK supplies the
matching `ksud` and `kernelsu.ko`), and payloads [built](#building) under `artifacts/`.

```sh
./pixel-ksu-root --manager me.weishu.kernelsu        # one device, auto-detected
./pixel-ksu-root --serial 1A2B3C4D --manager me.weishu.kernelsu
./pixel-ksu-root --recipe cve64560                   # a hunt, not a root run
./pixel-ksu-root --recipe cve64560 --print-contract --target panther-CP2A.260705.006
./pixel-ksu-root --help                              # flags and budgets
```

It loops one shot at a time — leak the KASLR base or replay the one cached for this boot,
attempt root — then derives `ksud`, late-loads and verifies. It stops at root or when the
budget runs out, and refuses — non-zero, before touching the kernel — when any
precondition above is missing.

## Safety

The primitive is temporary and the module lives in RAM, so there is nothing to undo and
re-rooting is re-running the tool.

Rooting can panic the phone. Losing the R/W race the runner budgets reboots into the
clean stock state, and a won race can still leave PI state an unrelated kernel thread
faults on later ([the captured record](cves/cve-2026-43499-ghostlock/README.md#the-chain)).
The KASLR leak performs no kernel write.

The tool bundles no `ksud` or `.ko`, and the module checks the installed manager's
signature in-kernel. Outcome classification, budgets and the recovery loop:
[runner/README.md §4](runner/README.md#4-runner-flow).

## Building

`pixel-ksu-root` is a shell script; what you build are the payloads it pushes.

```sh
ANDROID_NDK_HOME=/path/to/ndk runner/scripts/build-payloads.sh   # all payloads + cve-helper
make -C cves TARGET=panther-CP2A.260705.006 RECIPE=ghostlock     # one target
make -C cves TARGET=panther-CP2A.260705.006 RECIPE=ghostlock check  # resolver gates only
```

## Layout

```
runner/                   host machinery: lib/, recipes/, stages/, scripts/ — runner/README.md
cves/                     the research, one directory per CVE — cves/README.md
  kaslr/                    the write-free tracefs kernel-text leak, shared by every CVE
  targets/<dev-build>/      shared per-device offset headers (target.h [+ cve64560.h])
  cve-2026-43499-ghostlock/ 6.6 sources in ./, 6.1 in ./61/
tools/                    standalone research instruments (not used at root time)
data/targets.json         device → kernel-flavour + offset-group table
data/live/<dev-build>/    harvested per-device kernel facts
artifacts/                built payloads the runner pushes (build-payloads.sh regenerates)
logs/                     per-run logs and per-shot archives
```

## Supported devices

[data/targets.json](data/targets.json) covers 19 device/build entries across 18 Pixel
models (bluejay on two builds), sharing 5 kernel-offset payloads — devices with the same
`vmlinux` reuse one. Every entry builds; only panther has been run on hardware. Which
device is in which payload group, and how to add one:
[cves/targets/README.md](cves/targets/README.md).

## More

- [runner/README.md](runner/README.md) — recipes, stages, the resolver, the addressing model, the runner loop.
- [cves/kaslr/README.md](cves/kaslr/README.md) — the write-free tracefs text-base leak, its cost, and its per-build offsets.
- [tools/](tools/) — [hwbp](tools/hwbp/README.md) (on-device instruction counter) and [pixel-image](tools/pixel-image/README.md) (OTA offset extraction).

## Attribution & license

GhostLock ([CVE-2026-43499](https://nebusec.ai/buglist/CVE-2026-43499/)) is by
[NebuSec](https://github.com/NebuSec/CyberMeowfia) — [*IonStack Part II —
GhostLock*](https://nebusec.ai/research/ionstack-part-2/), under
[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0). The [cves/](cves/README.md)
tree adds Pixel/aarch64 offsets and a KernelSU late-load daemon under the same terms.
The heap-pointer side channel is
[KernelSnitch](https://github.com/isec-tugraz/KernelSnitch), by Lukas Maar et al.,
TU Graz — [NDSS 2025](https://lukasmaar.github.io/papers/ndss25-kernelsnitch.pdf).
[KernelSU](https://github.com/tiann/KernelSU) and its variants supply the module and
manager model this tool loads into; the project is manager-agnostic and bundles no fork.
Full references: [NOTICE](NOTICE).
