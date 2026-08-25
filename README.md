# pixel-ksu-root

An adb-driven tool that turns a stock, locked-bootloader Google Pixel into a KernelSU-rooted device without unlocking the bootloader or modifying the boot image. From the host it runs an unprivileged userspace kernel exploit on the device to obtain temporary kernel read/write, uses that primitive to patch a root credential, and then late-loads a KernelSU loadable kernel module (`kernelsu.ko`) into the running GKI kernel and hands control to whatever KernelSU manager (KernelSU, KernelSU-Next, SukiSU, or another variant) is already installed. It targets Android 17 Pixels on GKI 6.1 and 6.6 kernels and drives the entire flow over `adb shell` for deterministic sequencing and timestamped logs.

## How it works

### (a) Userspace kernel exploit → temporary kernel R/W

The device-side payload is the vendored full-chain LPE for CVE-2026-43499 ("GhostLock"), a futex/rtmutex priority-inheritance stack use-after-free in `kernel/locking/rtmutex.c`. On the requeue-PI rollback path, `remove_waiter()` clears `pi_blocked_on` on the requeuer (`current`) rather than on the actual waiter, leaving a dangling pointer into a freed kernel-stack slot that held an `rt_mutex_waiter`. The bug is reachable from an ordinary unprivileged process:

1. Three threads (`owner`, `waiter`, `consumer`) build a PI chain; the waiter parks on `FUTEX_WAIT_REQUEUE_PI`, the main thread fires `FUTEX_CMP_REQUEUE_PI`, and a `sched_setattr` from the consumer drives the rollback.
2. The freed stack slot is reclaimed by a controlled `pselect()`/`select()` (or a `TCP_ZEROCOPY_RECEIVE` route on some 6.1 targets) whose `fd_set` words land over the waiter struct, writing a forged flat `rt_mutex_waiter` so the dangling pointer walks attacker-controlled rb-tree and lock fields — a single controlled pointer-write primitive.
3. A KernelSnitch occupancy side channel (timing futex hash-table bucket collisions) recovers a kernel-heap/direct-map address to locate the slab page holding sprayed `mm_struct`/`sk_buff`/`pipe_buffer` objects.
4. The pointer-write overwrites `ashmem_miscs[0].fops` with a forged `file_operations` whose every slot points at a real, prototype-compatible kernel function (`configfs_bin_write_iter`, `configfs_read_iter`, `copy_splice_read`, `ashmem_ioctl`, `noop_llseek`, …), so forward-edge CFI is satisfied while `read`/`write`/`splice` on an ashmem fd yield a constrained kernel R/W.
5. That constrained primitive forges `pipe_buffer` structs on the leaked slab page (`page` pointed at any target via the `vmemmap`↔direct-map conversion, `ops = anon_pipe_buf_ops`, `PIPE_BUF_FLAG_CAN_MERGE`), so plain `read()`/`write()` on the pipe moves bytes to and from arbitrary kernel addresses — a stable arbitrary kernel R/W.

Root and SELinux state are then patched through the pipe primitive: the root-child task's `cred` is zeroed to uid/gid 0 with full capability sets, its SELinux `osid`/`sid` set to `SECINITSID_KERNEL`, seccomp cleared, and `selinux_state.enforcing` set to 0.

The exploit chain, the KASLR oracle, and the KernelSnitch side channel originate in NebuSec's *IonStack Part II — GhostLock* research (the `NebuSec/CyberMeowfia` PoC, Apache-2.0), adapted here for Pixel/aarch64. See [Attribution & License](#attribution--license).

### (b) Two-phase KASLR handling

Exactly one stage of the chain can panic the kernel: the KASLR slide derivation, which races a page it hopes it has reclaimed. Every other stage is retry-safe, and the kernel-text base is fixed for the lifetime of a single boot. The host flow splits on this property:

- **Phase A — derive the base (risky, once per boot).** The payload runs with no `KASLR_BASE` in its environment. The forged-waiter write repoints the `random_table` sysctl `ctl_table.data` at a known kernel-text pointer; reading `/proc/sys/kernel/random/boot_id` leaks it through `proc_do_uuid()`, and subtracting the image offset yields `_stext`/the KASLR base. `restore_slide_boot_id()` repairs the corrupted `ctl_table.data`. Because a lost race reboots the device, a wait-for-boot precedes every attempt and a liveness check classifies a disappearance as a panic. On success the device log emits `slide-kaslr-ok pid=<pid> base=<hex>`, and the base is pinned to the current boot.
- **Phase B — replay against the base (safe, retry until root).** The payload re-runs with `KASLR_BASE=0x<base>` exported. This path never panics and is looped until `id` reports `uid=0` through the temporary su.
- **Boot-id invalidation.** The captured base is valid only for the boot that produced it. Each Phase-B iteration compares the live `/proc/sys/kernel/random/boot_id` against the boot recorded at capture time; any change discards the base and returns to Phase A. An outer loop repeats derive→replay across reboots.

### (c) Kernel-driven target/payload selection and GKI/KMI reuse

The connected device is resolved against `data/targets.json` at runtime; nothing is device-hardcoded. Two independent resolutions occur:

- **Payload (offset group)** is selected by device codename + build, because same-kernel devices can require different offsets. Resolution is tiered: exact codename+build, then codename alone, then any entry on the same kernel prefix. If no payload resolves, the flow aborts rather than run a mismatched exploit.
- **KMI** is always taken from the running kernel (`uname -r`), either from the matched target entry or derived from the release string (e.g. `android14-6.1`).

The reuse of one payload across many devices follows from GKI/KMI structure. Every device on the same GKI build runs the byte-for-byte identical `vmlinux`, and struct-field offsets (`task_struct->cred`, `cred->uid`, …) are frozen for the life of a KMI branch by the KMI type contract and `MODVERSIONS` CRC enforcement. Absolute kernel symbol addresses, by contrast, are decided by the linker per `ab<NNN>` build, so the exploit's fixed offsets belong to one specific `vmlinux`; distinct kernel images therefore require distinct payloads even when their KMI matches. `data/targets.json` encodes exactly this: many devices deduplicate onto one payload keyed by kernel image, while a differing kernel image gets its own.

### (d) KernelSU LKM late-load with a manager-derived, signature-matched ksud

LKM late-load requires a GKI kernel (5.10+) with loadable-module support and a KMI-matched `.ko`. The KernelSU kernel module authenticates its manager by verifying the manager APK's v2 signature block in-kernel and comparing the SHA-256 of the signing certificate against a `KSU_EXPECTED_SIZE`/`KSU_EXPECTED_HASH` pair compiled into the `.ko`. The `kernelsu.ko` shipped inside a manager release and that manager's APK therefore share one signing identity; a mismatched ksud loads the driver but never sets the manager-authorization bit, leaving the device with no usable root.

The flow honors this binding: it resolves the installed manager's APK path (`pm path <manager package>`), pulls the APK, extracts `lib/arm64-v8a/libksud.so` as the ksud binary, and if no manager is installed it aborts. With temporary root held, that ksud is staged as a root-owned executable and invoked as `ksud late-load --kmi <kmi> --package-name <manager package>`. Late-load detects the current KMI, pulls `"{kmi}_kernelsu.ko"` from its embedded assets, performs manual symbol relocation (resolving each `SHN_UNDEF` symbol against `/proc/kallsyms`, rewriting entries to `SHN_ABS`), and calls `init_module(2)` on the patched buffer. It then runs the remaining boot pipeline init would (install ksud, restorecon, load `sepolicy.rule` and root profiles, run `post-fs-data`/stage scripts, mount the module overlay).

### (e) Syscall-based verification

Late-load daemonizes and re-enforces SELinux in its forked child, which tears down the exploit's temporary-su daemon; verification therefore must not go through su. Instead the loaded driver is queried directly through its syscall surface, reachable from a plain shell with no root: `ksud debug version` is polled and the reported kernel version parsed. A non-empty, non-zero version confirms the driver is resident and answering. The driver install path is the `reboot(2)` magic → install-fd → `KSU_IOCTL_GET_INFO` mechanism (`reboot(0xDEADBEEF, 0xCAFEBABE, 0, &fd)` installs an anonymous `[ksu_driver]` fd; `GET_INFO` returns `{version, flags, features, uapi_version}`), with the legacy `prctl(0xDEADBEEF, …)` channel probed as fallback. The same probe run at startup short-circuits the whole flow when the module is already resident for the current boot.

## Usage

### Prerequisites

- `adb` on the host, with the device authorized (USB debugging enabled).
- A stock Google Pixel with a **locked** bootloader, on a firmware/kernel covered by [Supported devices](#supported-devices). No unlock, no custom boot image.
- A KernelSU manager already installed (KernelSU, KernelSU-Next, SukiSU, or another variant). Its APK is the source of the matched ksud and its embedded `kernelsu.ko`.
- Prebuilt exploit payloads in `artifacts/exploits/` (see [Building payloads](#building-payloads)).

### Commands

```sh
# One device on adb; manager installed; payloads built.
bin/pixel-ksu-root
```

The driver resolves the device against `data/targets.json`, runs the two-phase KASLR flow, late-loads the module through the manager-derived ksud, and verifies via the driver syscall. It exits non-zero if no payload resolves for the device, if no manager is installed, or if verification never reports a live driver.

### Environment variables

- `KASLR_BASE=0x<hex>` — passed to the device payload during Phase B to replay against a fixed, already-derived per-boot base. Unset during Phase A so the payload derives the base itself.
- `ANDROID_NDK_HOME` — path to the Android NDK, required only when building payloads.
- `API` — Android API level for the NDK toolchain when building payloads (default 35).

## Project layout

```
pixel-ksu-root/
├── bin/                        Host driver entry point (adb-driven flow)
├── data/
│   └── targets.json            Device→payload and device→KMI resolution table
├── exploit/                    Vendored CVE-2026-43499 payload source
│   ├── Makefile                Per-target aarch64 NDK build
│   ├── src/                    android15-6.6 baseline source set
│   │   ├── main.c slide.c fops.c pipe.c root.c preload.c util.c
│   │   ├── su_daemon.c         Temporary-su helper spawned by the chain
│   │   ├── kernelsnitch/       Futex-hash occupancy side channel headers
│   │   └── targets/            Per device+build target.h (kernel offsets)
│   └── src/61/                 android14-6.1 source set (slide61.c, TCP route)
├── lib/                        Host-side shared shell/helper functions
├── scripts/
│   └── build-payloads.sh       Builds and deduplicates the payload set
├── artifacts/
│   └── exploits/               Built, deduplicated payload .so files
└── docs/                       Design and analysis notes
```

## Building payloads

`scripts/build-payloads.sh` wraps the per-target `exploit/Makefile` and emits the deduplicated payload set named in `data/targets.json` into `artifacts/exploits/`. It builds one `.so` per unique offset group (from that group's `build_from` target) rather than one per device.

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk   # must contain the aarch64 NDK toolchain
scripts/build-payloads.sh                       # builds every payload in data/targets.json
```

The Makefile selects the aarch64 NDK Clang toolchain from `ANDROID_NDK_HOME` and compiles a single target at a time; `API` (default 35) picks the `aarch64-linux-android<API>-clang` driver. The source set is chosen by kernel family — `android15-6.6` targets compile the `src/` baseline, `android14-6.1` targets compile `src/61/` — and each target's absolute kernel offsets come from `src/targets/<codename>-<build>/target.h`. To build a single target directly:

```sh
make -C exploit TARGET=husky-CP2A.260705.006
```

## Supported devices

`data/targets.json` lists **19 device/build entries covering 18 Pixel models** (bluejay appears on two firmware builds), grouped into **5 kernel-offset payloads**. Selection is by kernel image, so devices sharing a `vmlinux` deduplicate onto one payload; a differing kernel image gets its own.

| Payload | KMI | Built from | Devices |
|---|---|---|---|
| `android14-6.1-a` | android14-6.1 | bluejay-CP2A.260705.006 | oriole, raven, bluejay (CP2A), panther, cheetah, comet, shiba, husky, lynx, caiman |
| `android14-6.1-b` | android14-6.1 | komodo-CP2A.260705.006 | komodo, tegu, tokay |
| `android14-6.1-akita` | android14-6.1 | akita-CP2A.260805.005 | akita |
| `android14-6.1-cp1a` | android14-6.1 | bluejay-CP1A.260405.005 | bluejay (CP1A) |
| `android15-6.6` | android15-6.6 | blazer-CP2A.260705.006 | frankel, blazer, mustang, rango |

Devices on the shared `android14-6.1-a` kernel image (`6.1.157-android14-11-gbd23337e42e7-ab14791245`) span the Pixel 6/6 Pro/6a, 7/7 Pro/7a, 8/8 Pro, and 9/9 Pro/9 Pro XL/9 Pro Fold families; `android14-6.1-b` and `android14-6.1-akita` isolate models on the same KMI whose kernel build or offsets differ; `android15-6.6` covers the Pixel 10 family.

## Attribution & License

- **Exploit and technique — CVE-2026-43499 "GhostLock":** NebuSec (Nebula Security), *IonStack Part II — GhostLock*, released in the `NebuSec/CyberMeowfia` repository under **Apache-2.0**; discovery credited to NebuSec's VEGA tooling, disclosed 2026-07-07.
- **Pixel/aarch64 adaptation:** the vendored `exploit/` tree adds `android14-6.1` and `android15-6.6` target offsets and a KernelSU late-load daemon on top of the NebuSec exploit; it carries no separate license and inherits the upstream Apache-2.0 terms.
- **KernelSnitch side channel:** Lukas Maar et al., TU Graz (isec-tugraz), NDSS 2025.
- **KernelSU:** the KernelSU project and its variants provide the loadable kernel module, `ksud`, and the manager-authorization model this tool late-loads into.

Vendored source under `exploit/` retains its upstream license (Apache-2.0 for the NebuSec-derived exploit). This project is manager-agnostic: it late-loads whichever KernelSU variant's manager is installed and does not target or bundle any specific fork.

## References

### GhostLock / CVE-2026-43499

- [IonStack Part II: GhostLock — Nebula Security (research writeup)](https://nebusec.ai/research/ionstack-part-2/)
- [CVE-2026-43499 buglist entry — nebusec.ai](https://nebusec.ai/buglist/CVE-2026-43499/)
- [NebuSec/CyberMeowfia — PoC repo (Apache-2.0)](https://github.com/NebuSec/CyberMeowfia)
- [GhostLock CVE-2026-43499 — TuxCare](https://tuxcare.com/blog/ghostlock-cve/)
- [15-Year-Old GhostLock Flaw Enables Root — The Hacker News](https://thehackernews.com/2026/07/15-year-old-ghostlock-flaw-enables-root.html)
- [RHSB-2026-010 GhostLock — Red Hat](https://access.redhat.com/security/vulnerabilities/RHSB-2026-010)

### KernelSnitch

- [KernelSnitch: Side-Channel Attacks on Kernel Data Structures — NDSS 2025 paper (PDF)](https://lukasmaar.github.io/papers/ndss25-kernelsnitch.pdf)
- [KernelSnitch — NDSS Symposium page](https://www.ndss-symposium.org/ndss-paper/kernelsnitch-side-channel-attacks-on-kernel-data-structures/)
- [isec-tugraz/KernelSnitch — source](https://github.com/isec-tugraz/KernelSnitch)

### KernelSU LKM late-load and manager binding

- [KernelSU (upstream)](https://github.com/tiann/KernelSU)
- [`ksud` late-load path](https://github.com/tiann/KernelSU/blob/main/userspace/ksud/src/late_load.rs)
- [`init_module` loader and driver detection](https://github.com/tiann/KernelSU/blob/main/userspace/ksuinit/src/lib.rs)
- [Reboot-magic install-fd and kprobe](https://github.com/tiann/KernelSU/blob/main/kernel/supercall/supercall.c)
- [UAPI: magics, ioctl numbers, GET_INFO struct/flags](https://github.com/tiann/KernelSU/blob/main/uapi/supercall.h)
- [In-kernel APK v2 signature check](https://github.com/tiann/KernelSU/blob/main/kernel/manager/apk_sign.c)
- [Installation guide](https://kernelsu.org/guide/installation.html)
- [Module guide](https://kernelsu.org/guide/module.html)
- [Non-GKI integration (built-in/LKM background)](https://kernelsu.org/guide/how-to-integrate-for-non-gki.html)
- [Rescue from bootloop (LKM boot-image context)](https://kernelsu.org/guide/rescue-from-bootloop.html)
- [DeepWiki: installation and device support](https://deepwiki.com/tiann/KernelSU/6-installation-and-device-support)
- [KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next)
- [KernelSU-Next `apk_sign.rs`](https://github.com/KernelSU-Next/KernelSU-Next/blob/dev/userspace/ksud/src/apk_sign.rs)
- [KernelSU-Next releases](https://github.com/KernelSU-Next/KernelSU-Next/releases)
- [SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra)

### GKI / KMI

- [GKI versioning scheme — AOSP](https://source.android.com/docs/core/architecture/kernel/gki-versioning)
- [Generic Kernel Image (GKI) project — AOSP](https://source.android.com/docs/core/architecture/kernel/generic-kernel-image)
- [Maintain a stable kernel module interface — AOSP](https://source.android.com/docs/core/architecture/kernel/stable-kmi)
- [Android kernel ABI monitoring — AOSP](https://source.android.com/docs/core/architecture/kernel/abi-monitor)
- [Android common kernels — AOSP](https://source.android.com/docs/core/architecture/kernel/android-common)
- [Kernel modules overview — AOSP](https://source.android.com/docs/core/architecture/kernel/modules)
- [Android kernel FAQ — AOSP](https://source.android.com/docs/core/architecture/kernel/gki-faq)
- [ABI Monitoring for Android Kernels — kernel/build README](https://android.googlesource.com/kernel/build/+/ef535fd/abi/README.md)
- [kernel/common android14-6.1 tag — Git at Google](https://android.googlesource.com/kernel/common/+/refs/tags/android14-6.1-2025-03_r4)
- [Module Loading Internals — kernel-internals.org](https://kernel-internals.org/modules/module-loading-internals/)
- [Anatomy of the Linux loadable kernel module — terenceli](https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2018/06/02/linux-loadable-module)
- [module: put modversions in vermagic (LKML)](https://lkml.iu.edu/hypermail/linux/kernel/0805.1/0588.html)
- [Linux Kernel Module Licensing and Version Magic — embeddedpathashala](https://embeddedpathashala.com/linux-kernel-module-licensing/)
