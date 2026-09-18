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
| [CVE-2026-43049](cves/cve-2026-43049-ffwheel/README.md) — FFWheel | [`hidpp_probe()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/hid/hid-logitech-hidpp.c) publishes the input device with `hid_connect()` before `hidpp_ff_init()`, and returns the FF error without `hid_hw_stop()`, so `input_unregister_device()` is never called and the freed `struct uhid_device` stays reachable through `/dev/input/eventN` | reaches root on hardware — a deterministic UAF from an unprivileged shell to arbitrary kernel R/W (a `pipe_inode_info->bufs` redirect through the `ep_poll_callback` primitive), then an own-`cred` overwrite: uid 2000 to 0, no re-exec, verified externally via `ps`/`/proc/<pid>/status`. The `cred` and `pipe_inode_info` addresses are read out of `mm` by the same primitive (`mm->mm_mt.ma_root` → forged VMA → `/proc/self/maps`, walked by a reader/writer pair). `--recipe ffwheel` |
| [CVE-2026-46242](cves/cve-2026-46242-badepoll/README.md) — BadEpoll | [`__ep_remove()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/fs/eventpoll.c) clears `file->f_ep` and keeps using the file, so a concurrent `__fput()` frees the eventpoll it is still writing through | hunt + partial LPE — unpatched; ships a cross-process info leak and a reliable DoS. The arbitrary-read chain runs end to end but the read misses: no header-free order-1 cache is reachable to forge a `struct file` cleanly. Root not reached |
| [CVE-2026-56945](cves/cve-2026-56945-roguewave/README.md) — RogueWave | [`bigo_iommu_fault_handler()`](https://android.googlesource.com/kernel/google-modules/video/gchips/+/refs/heads/android-gs-pantah-6.1-android15-qpr2/bigo_iommu.c) walks BigOcean's `core->instances` list with no lock, on the documented (wrong) assumption that its only caller already holds one | confirmed by binary diff (fix wraps the walk in `mutex_lock`/`unlock`). Reachable and hardware-confirmed with no root: the public `AMediaCodec_createCodecByName("c2.google.av1.decoder")` API, from plain shell, drives `mediacodec_google` to open `/dev/bigocean`. Trigger attempts so far all safe, none yet reached the fault handler (confirmed via kprobe). Active direction |
| [CVE-2026-56914](cves/cve-2026-56914-dirtydock/README.md) — DirtyDock | [`gcip_iommu_mapping_unmap_buffer()`](https://android.googlesource.com/kernel/google-modules/gxp/gs201/+/refs/heads/android-gs-pantah-6.1-android15-qpr2/gcip-kernel-driver/drivers/gcip/gcip-iommu.c) marks a pinned DMA page dirty with the unlocked `set_page_dirty()` instead of `set_page_dirty_lock()`, racing a concurrent teardown of the buffer's backing memory | confirmed by binary diff; self-triggerable end to end via a direct ioctl harness (root-scaffolded — `/dev/gxp` needs it), and GoogleCamera hits the call site 30-50×/photo. Two racing strategies (memfd truncate; anon `munmap()`) disproven via a kprobe on `page->mapping`; timing not yet won |
| [CVE-2026-64468](cves/cve-2026-64468-frostbind/README.md) — Frostbind | [`binder_free_transaction()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/android/binder.c) dereferences `t->to_proc` without holding a reference on it | hunt only — unpatched and the vulnerable read runs, but the race is lost on bare metal (a foreign object wins the slot, then KCFI or a softlockup) |
| [CVE-2026-64560](cves/cve-2026-64560-zombietick/README.md) — Zombietick | a process-wide POSIX CPU timer is freed while still queued, because `posix_cpu_timer_del()` returns early once `de_thread()` has nulled `->sighand` | hunt only — panther-only build; only `CAP_SLIDE` reached, the bridge descriptor never validates |
| [CVE-2026-49881](cves/cve-2026-49881-telecom/README.md) — Telecom | `serviceClassExists()` in Telecom trusts a caller-supplied component name, so a bait app runs arbitrary Java inside `system_server` | research — unpatched on panther; a userspace domain pivot rather than a kernel bug, paired with `domainprobe/` to map what the reached domain can do |
| [P0 465827985](cves/p0-465827985-stackjump/README.md) — StackJump | a clipboard path in `system_server` reads past a buffer, leaking adjacent heap to a listening app | PoC builds and runs on panther; the leak has not been reproduced in ~80 stock-parameter attempts |
| [CVE-2026-28594](cves/cve-2026-28594-sealslip/README.md) — SealSlip | an unsealed `memfd` is accepted where ashmem is expected, so its size stays mutable while a consumer holds it | DoS-only for an unprivileged caller and SELinux-bounded; no AOSP uid-0 consumer is reachable. Kept for the instrument |
| [CVE-2026-28662](cves/cve-2026-28662-cookiejar/README.md) — CookieJar | a P2P2 PBMA cookie is copied into a fixed buffer without checking its length, overflowing the wpa_supplicant heap | documented, not yet chased — present on panther; a candidate first stage into CVE-2026-43501 |
| [CVE-2026-43284](cves/cve-2026-43284-dirtyfrag/README.md) — DirtyFrag | [`esp_input()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/net/ipv4/esp4.c) decrypts in place on its `skip_cow` path, so the ESN sequence-word store lands before the hash check, in whatever page-cache page is pinned in that fragment | closed — unpatched but unexploitable at any privilege: `skb_orphan_frags_rx()` copies the `MSG_ZEROCOPY` frags before `esp_input()` ever runs |

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
./pixel-ksu-root --recipe zombietick                 # a hunt, not a root run
./pixel-ksu-root --recipe zombietick --print-contract --target panther-CP2A.260705.006
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
clean stock state, and a won race can still leave state an unrelated thread faults on
later — PI state, and files holding the forged `file_operations` pointer
([Collateral](cves/cve-2026-43499-ghostlock/README.md#collateral)). The KASLR leak
performs no kernel write.

The tool bundles no `ksud` or `.ko`, and the module checks the installed manager's
signature in-kernel. Outcome classification, budgets and the recovery loop:
[runner/README.md §4](runner/README.md#4-runner-flow).

## Debugging a panic

`/sys/fs/pstore` is readable from a plain `adb shell` — sepolicy grants shell read on
pstore files (not on listing the directory), so a named file opens without root:

```sh
adb shell cat /sys/fs/pstore/console-ramoops-0   # previous boot's console: oops, trace, reset message
```

That is only the most recent boot. For older ones — a hunt reboots many times —
`dumpsys dropbox | grep SYSTEM_LAST_KMSG` keeps a compressed kmsg tail hundreds of boots
back, and `getprop sys.boot.reason.last` says panic vs clean reboot at a glance. The runner
does this for you: each run writes `logs/panic-<run>/console-ramoops-0.txt` and prints the
oops (`capture_panic_evidence()` in `pixel-ksu-root`).

To read an oops, start at the bootloader's `reset message:` line near the end of the
console log — it names the faulting task, symbol and PC without any parsing. Disassembling
the `Code:` words (faulting one in parentheses) pins the exact field and offset, and the
faulting address often byte-swaps to a recognisable string — a package name or a
`seq_printf` format — which marks a stale pointer into recycled memory rather than a wild
write. A fault minutes after a clean run is still that run's; the same shape recurring
across boots on different call paths is one dangling object, not several bugs — GhostLock's
ashmem collateral is one such recurring shape
([Collateral](cves/cve-2026-43499-ghostlock/README.md#collateral)).

### Everything else about the live device

`runner/scripts/harvest-live.sh` captures the rest. Kallsyms, BTF, config, `/proc/iomem`
and `dmesg` do need root; `/proc/slabinfo` and all of pstore do not, so the script is
still worth running on a phone that never rooted.

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
  lib/                      the shared exploitation library — cves/lib/README.md
  targets/<dev-build>/      shared per-device offset headers (target.h [+ cve64560.h])
  bench/                    instruments that measure a shared primitive
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
- [cves/lib/kaslr/README.md](cves/lib/kaslr/README.md) — the write-free tracefs text-base leak, its cost, and its per-build offsets.
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
