# pixel-ksu-root

Root a stock, locked-bootloader Google Pixel from an unprivileged `adb shell`, using a
kernel CVE — no unlock, no flash, no vendor help.

A userspace-reachable kernel bug yields a short-lived read/write primitive. That primitive
is spent late-loading a [KernelSU](https://kernelsu.org/) module into the running
[GKI](https://source.android.com/docs/core/architecture/kernel/generic-kernel-image)
kernel, after which root is handed to whichever KernelSU manager is already installed.
No partition is written, so a reboot is the uninstall. Everything runs from the host over
`adb` through a single executable, [`./pixel-ksu-root`](pixel-ksu-root).

## Status

| CVE | the bug | where it stands |
|---|---|---|
| [CVE-2026-43499](cves/cve-2026-43499-ghostlock/README.md) — GhostLock | a [futex](https://man7.org/linux/man-pages/man2/futex.2.html) PI walk follows an [`rt_mutex_waiter`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/locking/rtmutex_common.h) that [`remove_waiter()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/locking/rtmutex.c) left dangling, read out of a stack slot [`pselect(2)`](https://man7.org/linux/man-pages/man2/select.2.html) has re-occupied | roots, hardware-verified; the [`default`](runner/recipes/ghostlock.toml) recipe, so a bare run takes it |
| [CVE-2026-43049](cves/cve-2026-43049-ffwheel/README.md) — FFWheel | [`hidpp_probe()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/hid/hid-logitech-hidpp.c) publishes the input device before force-feedback init and returns the error without [`hid_hw_stop()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/hid/hid-core.c), so a freed [`struct uhid_device`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/hid/uhid.c) stays reachable through `/dev/input/eventN` | roots, hardware-verified; a use-after-free from an unprivileged shell to arbitrary kernel read/write, then an own-`cred` overwrite in place |
| [CVE-2026-93189](cves/cve-2026-93189-joyride/README.md) — Joyride | [`hid_hw_stop()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/hid/hid-core.c) never waits for input to stop, so a failed probe frees the [`struct hidraw`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/hid/hidraw.c) that [`hidraw_report_event()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/hid/hidraw.c) is still writing into on another processor | candidate successor; the path to the free is walked on hardware from an unprivileged shell through [`/dev/uhid`](https://docs.kernel.org/hid/uhid.html), and is open on builds that close both chains above |
| [CVE-2026-46242](cves/cve-2026-46242-badepoll/README.md) — BadEpoll | [`__ep_remove()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/fs/eventpoll.c) clears `file->f_ep` and keeps using the file, so a concurrent `__fput()` frees the [eventpoll](https://man7.org/linux/man-pages/man7/epoll.7.html) it is still writing through | partial; read and write chains both run end to end, but delivery across the slab boundary is unsolved |
| [CVE-2026-56945](cves/cve-2026-56945-roguewave/README.md) — RogueWave | [`bigo_iommu_fault_handler()`](https://android.googlesource.com/kernel/google-modules/video/gchips/+/refs/heads/android-gs-pantah-6.1-android15-qpr2/bigo_iommu.c) walks a driver-global instance list unlocked, on a documented and incorrect assumption about its caller | reachable without privilege through the public [`AMediaCodec`](https://developer.android.com/ndk/reference/group/media) API; the fault handler itself has not been entered |
| [CVE-2026-56914](cves/cve-2026-56914-dirtydock/README.md) — DirtyDock | [`gcip_iommu_mapping_unmap_buffer()`](https://android.googlesource.com/kernel/google-modules/gxp/gs201/+/refs/heads/android-gs-pantah-6.1-android15-qpr2/gcip-kernel-driver/drivers/gcip/gcip-iommu.c) dirties a [pinned](https://docs.kernel.org/core-api/pin_user_pages.html) DMA page with the unlocked [`set_page_dirty()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/mm/page-writeback.c) instead of its locking variant, racing teardown of the backing memory | triggerable end to end, though the device node is privilege-gated; two racing strategies disproven, timing not yet won |
| [CVE-2026-64468](cves/cve-2026-64468-frostbind/README.md) — Frostbind | [`binder_free_transaction()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/android/binder.c) dereferences `t->to_proc` without holding a reference | hunt; the vulnerable read runs, but the race is lost on bare metal |
| [CVE-2026-64560](cves/cve-2026-64560-zombietick/README.md) — Zombietick | a process-wide POSIX CPU timer is freed while still queued, because [`posix_cpu_timer_del()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/time/posix-cpu-timers.c) returns early once [`de_thread()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/fs/exec.c) has nulled `->sighand` | hunt; the KASLR stage lands, the bridge descriptor never validates |
| [CVE-2026-49881](cves/cve-2026-49881-telecom/README.md) — Telecom | Telecom trusts a caller-supplied component name and loads it with [`CONTEXT_INCLUDE_CODE`](https://developer.android.com/reference/android/content/Context#CONTEXT_INCLUDE_CODE), so a bait app runs arbitrary Java inside `system_server` | research; a userspace domain pivot rather than a kernel bug, paired with [`domainprobe/`](domainprobe/README.md) |
| [P0 465827985](cves/p0-465827985-stackjump/README.md) — StackJump | native code built without [stack-clash protection](https://developers.redhat.com/blog/2017/09/25/stack-clash-mitigation-gcc-background) lets a large frame step over a `system_server` thread's guard page | the overflow reproduces and crashes a binder thread reliably; the reporter's spray-based write does not, so the realised primitive is a read of the crash tombstone — a full [ASLR](https://source.android.com/docs/security/test/memory-safety) defeat for that process |
| [CVE-2026-28594](cves/cve-2026-28594-sealslip/README.md) — SealSlip | an unsealed [`memfd`](https://man7.org/linux/man-pages/man2/memfd_create.2.html) is accepted where ashmem is expected, so its size stays mutable while a consumer holds it | denial of service only for an unprivileged caller, and [SELinux](https://source.android.com/docs/security/features/selinux)-bounded; kept for the instrument |
| [CVE-2026-28662](cves/cve-2026-28662-cookiejar/README.md) — CookieJar | a Wi-Fi Direct cookie is copied into a fixed buffer with only a lower-bound check, overflowing the [`wpa_supplicant`](https://android.googlesource.com/platform/external/wpa_supplicant_8/+/b8d36c897dde9a2273fc5c850d5ea49ba42c55d9) heap | documented, not chased; a candidate first stage |
| [CVE-2026-43284](cves/cve-2026-43284-dirtyfrag/README.md) — DirtyFrag | [`esp_input()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/net/ipv4/esp4.c) decrypts in place, so the sequence-word store lands before the hash check, in whatever page-cache page the fragment pins | closed; unpatched but unexploitable at any privilege, because [`skb_orphan_frags_rx()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/skbuff.h) copies the frags first |

A chain that roots ends in a `CAP_SU` handoff. A chain that does not is a *hunt*: the
runner classifies and archives each shot rather than reporting success, which is how a
bug stays useful while its exploit is still speculative
([runner/README.md §2.3](runner/README.md#23-recipes)). What a chain must demonstrate
before it can take the `default` recipe is set out in [cves/README.md](cves/README.md).

## Quickstart

You need `adb` with the device authorized, a stock locked Pixel on a
[supported build](#supported-devices), a KernelSU manager installed — its APK supplies the
matching `ksud` and `kernelsu.ko` — and payloads [built](#building) under `artifacts/`.

```sh
./pixel-ksu-root --manager me.weishu.kernelsu        # one device, auto-detected
./pixel-ksu-root --serial 1A2B3C4D --manager me.weishu.kernelsu
./pixel-ksu-root --recipe zombietick                 # a hunt, not a root run
./pixel-ksu-root --recipe zombietick --print-contract --target panther-CP2A.260705.006
./pixel-ksu-root --help                              # flags and budgets
```

A run proceeds one shot at a time: leak the KASLR base or replay the one cached for this
boot, attempt root, then derive `ksud`, late-load and verify. It stops at root or when the
budget runs out, and refuses — non-zero, before touching the kernel — when any
precondition above is missing.

## Safety

The primitive is temporary and the module lives in RAM, so there is nothing to undo, and
re-rooting is simply re-running the tool.

Rooting can panic the phone. A lost race reboots into clean stock state, which the runner
budgets for; a won race can still leave state that an unrelated thread faults on later,
such as priority-inheritance chains or files holding a forged `file_operations` pointer
([Collateral](cves/cve-2026-43499-ghostlock/README.md#collateral)). The KASLR leak
performs no kernel write at all.

The tool bundles no `ksud` and no module, and the module checks the installed manager's
signature in-kernel. Outcome classification, budgets and the recovery loop are described
in [runner/README.md §4](runner/README.md#4-runner-flow).

## Debugging a panic

`/sys/fs/pstore` is readable from a plain `adb shell`: sepolicy grants shell read on
pstore files, though not on listing the directory, so a named file opens without root.

```sh
adb shell cat /sys/fs/pstore/console-ramoops-0   # previous boot's console
```

That is the most recent boot only. For older ones — a hunt reboots many times —
`dumpsys dropbox | grep SYSTEM_LAST_KMSG` keeps a compressed kmsg tail much further back,
and `getprop sys.boot.reason.last` distinguishes a panic from a clean reboot at a glance.
The runner does this for you: each run writes `logs/panic-<run>/console-ramoops-0.txt` and
prints the oops. The underlying mechanism is
[ramoops](https://docs.kernel.org/admin-guide/ramoops.html), a pstore backend that keeps
the console in a reserved region across a reset.

Reading an oops is easier from the end than the beginning. The bootloader's
`reset message:` line names the faulting task, symbol and program counter without any
parsing on your part. Disassembling the `Code:` words, with the faulting instruction in
parentheses, pins the exact field and offset. A faulting address that byte-swaps into a
recognisable string — a package name, a `seq_printf` format — marks a stale pointer into
recycled memory rather than a wild write. Timing is not evidence of innocence: a fault
minutes after a clean run still belongs to that run, and one shape recurring across boots
on different call paths is one dangling object rather than several bugs. GhostLock's
ashmem collateral is exactly such a recurring shape.

### Everything else about the live device

`runner/scripts/harvest-live.sh` captures the rest. Kallsyms,
[BTF](https://docs.kernel.org/bpf/btf.html), the kernel config, `/proc/iomem` and `dmesg`
need root; `/proc/slabinfo` and pstore do not, so the script is worth running on a phone
that has never been rooted.

## Building

`pixel-ksu-root` is a shell script; what you build are the payloads it pushes. An
[NDK](https://developer.android.com/ndk) toolchain does the compiling.

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
  targets/                  kernel, interface and per-build offset headers
  bench/                    instruments that measure a shared primitive
tools/                    standalone research instruments (not used at root time)
data/targets.json         device → kernel flavour and offset group
data/vulns.json           what is known about each bug, and which kernels still carry it
data/live/<dev-build>/    harvested per-device kernel facts
artifacts/                built payloads the runner pushes
logs/                     per-run logs and per-shot archives
```

## Supported devices

[data/targets.json](data/targets.json) covers most current Pixel models across several
builds, sharing a much smaller number of payloads: devices running the same `vmlinux`
reuse one set of offsets. Every listed entry composes and passes the resolver gates, but
hardware experience is confined to a single device. Which device belongs to which payload
group, and how to add one, is [cves/targets/README.md](cves/targets/README.md).

## More

- [runner/README.md](runner/README.md) — recipes, stages, the resolver, the addressing model, the runner loop.
- [cves/lib/README.md](cves/lib/README.md) — the shared exploitation library.
- [cves/lib/kaslr/README.md](cves/lib/kaslr/README.md) — the write-free text-base leak and what it costs.
- [tools/](tools/) — [hwbp](tools/hwbp/README.md), an on-device instruction counter, and [pixel-image](tools/pixel-image/README.md), which extracts offsets from a published OTA.

## Attribution & license

GhostLock ([CVE-2026-43499](https://nebusec.ai/buglist/CVE-2026-43499/)) is by
[NebuSec](https://github.com/NebuSec/CyberMeowfia) — [*IonStack Part II —
GhostLock*](https://nebusec.ai/research/ionstack-part-2/), under
[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0). The [cves/](cves/README.md)
tree adds Pixel/aarch64 offsets and a KernelSU late-load daemon under the same terms.
The heap-pointer side channel is
[KernelSnitch](https://github.com/isec-tugraz/KernelSnitch), by Lukas Maar et al. at
TU Graz, published at [NDSS 2025](https://lukasmaar.github.io/papers/ndss25-kernelsnitch.pdf).
[KernelSU](https://github.com/tiann/KernelSU) and its variants supply the module and
manager model this tool loads into; the project is manager-agnostic and bundles no fork.
Full references: [NOTICE](NOTICE).
