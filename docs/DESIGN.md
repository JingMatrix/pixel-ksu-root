# pixel-ksu-root — Engineering Design

An adb-driven host tool that obtains temporary kernel read/write on a stock,
locked-bootloader Google Pixel through a userspace kernel exploit, late-loads a
KernelSU loadable kernel module (LKM) onto the running kernel, and hands control
to whatever KernelSU manager is installed. The tool is manager-agnostic: it
supports general KernelSU variants (KernelSU, KernelSU-Next, SukiSU, and other
forks) by binding to the manager already present on the device rather than to
any specific fork.

---

## 1. Threat and operating model

The tool operates against a device the operator physically holds and controls
over USB, with USB debugging enabled. It requires no unlock, no custom
recovery, and no modification of any partition on flash.

- **Bootloader:** locked. Verified Boot remains intact; no image is flashed.
- **Privilege at entry:** unprivileged app-context code (an in-app `.so`
  preload) and an `adb shell` session. No root, no vendor cooperation.
- **Persistence model:** none across a cold boot by this tool alone. Root is
  established for the lifetime of the current boot. The KernelSU module, once
  late-loaded, persists only for that boot; re-running the flow re-establishes
  it after a reboot. The tool writes nothing to a partition to survive reboot.
- **Kernel target:** Android 17 GKI kernels, KMI generations `android14-6.1`
  and `android15-6.6`, aarch64. The exploited flaw is CVE-2026-43499
  ("GhostLock"), a futex/rtmutex priority-inheritance stack use-after-free.
- **Control surface:** the entire flow is driven from the host over `adb shell`
  for deterministic sequencing and timestamped logs. Every device-side decision
  (payload selection, base capture, verification) is read back over adb from
  device-side log lines and syscall probes; nothing is inferred host-side.
- **Trust boundary the tool enforces:** the KernelSU driver authenticates its
  manager in-kernel by APK signature. The tool never supplies its own `ksud` or
  `.ko`; it uses the module keyed to the running KMI and the `ksud` extracted
  from the manager already installed on the device, so the kernel's own
  signature check is what authorizes root.

The operator is assumed to accept that the risky KASLR-derivation stage can
panic and reboot the device; the flow is built to make that the only stage that
can, and to recover from it automatically.

---

## 2. The exploit primitive chain

The vendored payload (`exploit/`, ported from NebuSec IonStack / CyberMeowfia,
Apache-2.0) is a full-chain unprivileged-to-root local privilege escalation
compiled to a per-offset-group `.so`. The chain below reflects the aarch64
Pixel port in `exploit/src/61/` (`main.c`, `slide61.c`, `fops.c`, `pipe.c`,
`root.c`, `kernelsnitch/`), which builds arbitrary kernel R/W through ashmem and
`pipe_buffer` and never touches `core_pattern`.

### 2.1 The bug — futex/rtmutex PI stack UAF (CVE-2026-43499)

`kernel/locking/rtmutex.c` mishandles the requeue-PI rollback path: on rollback,
`remove_waiter()` clears `pi_blocked_on` on the requeuer (`current`) rather than
on the actual waiter, leaving a dangling kernel pointer into a freed
kernel-stack slot that had held an `rt_mutex_waiter`. The flaw is reachable with
ordinary `futex(2)`. Three threads (`owner`, `waiter`, `consumer`) build a PI
chain; the waiter parks on `FUTEX_WAIT_REQUEUE_PI`, the main thread fires
`FUTEX_CMP_REQUEUE_PI`, and a `sched_setattr` from the consumer drives the
rollback (`main.c`).

### 2.2 Reclaim and forged `rt_mutex_waiter`

The freed stack slot is reclaimed by a controlled `pselect()`/`select()` whose
`fd_set` words land exactly over the former waiter struct (on some 6.1 targets a
`TCP_ZEROCOPY_RECEIVE` route is used instead). Because `fd_set` word *N* maps to
stack byte *N*·8, the payload writes a forged flat `rt_mutex_waiter` (6.1 layout:
`task`, `lock`, `wake_state|prio`, rb-tree nodes) into the fdset. The dangling
pointer then walks attacker-controlled rb-tree and lock fields, yielding a
single controlled pointer-write primitive when the PI chain unwinds.

### 2.3 KASLR base — P0 physical-alias slide oracle

The route compiled here (`slide61.c`) uses the controlled write to corrupt the
`random_table` sysctl's `ctl_table.data` pointer so it aims at a known
kernel-text global (`loggers[0][NF_LOG_TYPE_ULOG]`, i.e. `&nfulnl_logger`).
Reading `/proc/sys/kernel/random/boot_id` then leaks that kernel-text pointer
through `proc_do_uuid()`; subtracting the image offset for that symbol yields
`_stext` / the KASLR base. Writes are staged through a Project-Zero-style
physmap alias of the image (`P0_DATA_ALIAS_CONST`). This stage is the only one
that can panic: it races a page it expects to have reclaimed. The KASLR base is
fixed for the lifetime of one boot, so a caller caches it and only the first
derivation per boot risks the race. `restore_slide_boot_id()` repairs the
corrupted `ctl_table.data` afterward.

### 2.4 Heap-pointer leak — KernelSnitch side channel

`setup_kernelsnitch()` / `run_kernelsnitch_bruteforce()`
(`exploit/src/61/kernelsnitch/`, from TU Graz KernelSnitch, NDSS'25) time futex
hash-table bucket collisions — an occupancy side channel over a kernel container
data structure — to recover a kernel-heap / direct-map address. That address
locates the order-3 slab page holding sprayed `mm_struct` / `sk_buff` /
`pipe_buffer` objects. The technique is hardware-agnostic and runs from an
unprivileged, isolated process on aarch64.

### 2.5 CFI bypass — forged `file_operations` on ashmem

Using the pointer-write, the payload overwrites `ashmem_miscs[0].fops` (the
`miscdevice.fops` slot) to point at a forged `file_operations` built in the
P0-aliased controlled page. Every slot in the forged table points at a real,
CFI-valid kernel function with a compatible prototype (`configfs_bin_write_iter`,
`configfs_read_iter`, `generic_file_splice_read` / `copy_splice_read`,
`ashmem_ioctl`, `noop_llseek`), so forward-edge Control-Flow Integrity type
checks are satisfied. Driving `read` / `write` / `splice` on an ashmem fd
through these repurposed handlers yields a constrained kernel read/write against
`configfs`-style buffers (`fops.c`). `leak_kernel_base()` re-reads the
`ashmem_fops` pointers to confirm the slide.

### 2.6 Arbitrary kernel R/W — `pipe_buffer` corruption

With the constrained configfs primitive, the payload grooms pipes
(`F_SETPIPE_SZ`) and forges `pipe_buffer` structs on the leaked slab page: it
points `pipe_buffer.page` at any target through the `vmemmap`↔direct-map
conversion (`direct_to_page` / `page_to_direct`), sets `ops =
anon_pipe_buf_ops` and `PIPE_BUF_FLAG_CAN_MERGE`, then uses plain `read()` /
`write()` on the pipe to move bytes to and from arbitrary physical / direct-map
addresses (`pipe.c`, `pipe_phys_read/write`, `install_pipe_physrw`). The buffer
is saved and restored around each access. This route is non-panicking and is the
stable arbitrary kernel R/W the rest of the chain relies on.

### 2.7 Root and SELinux — credential / SID patching

`root.c` walks `init_task.tasks` to find the root-child task and, through the
pipe physrw primitive:

- zeroes `cred.uid/gid/euid/egid/...`, sets all five capability sets to
  `CAP_FULL`, and clears `securebits`;
- patches the SELinux blob so `cred->security` (`osid` / `sid`) is
  `SECINITSID_KERNEL`;
- clears seccomp (`TIF_SECCOMP`, `no_new_privs` / `PFA_*`,
  `seccomp.mode/filter`);
- writes `selinux_state.enforcing = 0` and verifies through
  `/sys/fs/selinux/enforce`.

The now-root child installs a temporary su and the higher-level flow exposes it
over a Unix socket, which is what the host uses to run privileged commands until
the KernelSU driver takes over.

### 2.8 Reliability

Every stage except the §2.3 slide is retry-safe; the pipe physrw route runs to
completion repeatedly without panic. The flow (Section 4) is structured around
exactly this split: isolate the one panic-prone stage, cache its result per
boot, and hammer the rest.

---

## 3. Two-phase KASLR control loop

The exploit has exactly one stage that can panic the kernel — the KASLR slide
derivation (§2.3). A lost slide race reboots the device. Everything after the
base is known ("main route") never panics and can be retried indefinitely. The
base is fixed for the lifetime of one boot. The control loop is built directly
on this asymmetry.

### 3.1 Phase A — derive the base (risky, once per boot)

The exploit is run with no `KASLR_BASE` in its environment. Because each shot may
reboot the device on a lost race, a wait-for-boot precedes every attempt and a
post-shot liveness check classifies a device disappearance as a panic/reboot.
On success the device-side log emits:

```
slide-kaslr-ok pid=<pid> base=<hex>
```

The host parses `base=<hex>` from that line and pins it to the current boot.
This is the only stage permitted to panic. A Phase-A shot occasionally yields
root directly; when it does, Phase B is skipped.

### 3.2 Phase B — replay against the base (safe, retry until root)

The exploit is re-run with `KASLR_BASE=0x<base>` exported in its environment.
This path never panics and is run in a loop until root is confirmed: the tool
runs `id` through the temporary su and requires `uid=0`. The root-success signal
that ends the loop is a confirmed `uid=0` from the temporary su.

### 3.3 boot_id invalidation rule

A captured base is valid only for the boot that produced it. At capture time the
host records `/proc/sys/kernel/random/boot_id`. Before each Phase-B iteration it
re-reads `/proc/sys/kernel/random/boot_id` and compares:

- **unchanged** → the base is still valid; continue Phase B.
- **changed, or the device is unreachable** → the base is stale; discard it and
  return control to Phase A to derive a fresh base against the new boot.

An outer cycle loop repeats derive→replay across reboots until root is held. The
recorded `boot_id` is the single source of truth for base validity; the tool
never reuses a base across a `boot_id` change.

---

## 4. Target and offset model

Selection is data-driven from `data/targets.json`. Nothing in the flow is
device-hardcoded.

### 4.1 The offset asymmetry (GKI + KMI)

Two kinds of offset behave oppositely, and the model treats them differently:

- **Struct-field offsets are KMI-stable.** The KMI freezes the type layout of
  every stable struct across an entire branch. With `gki_defconfig` fixed and
  the toolchain pinned, `task_struct->cred`, `cred->uid`, `mm_struct` fields,
  `pipe_buffer` layout, and the rest sit at identical byte offsets in every GKI
  build of a KMI generation. `MODVERSIONS` symbol CRCs enforce this: a silent
  layout change would move a CRC and break module loading, so it cannot happen
  within a branch. These offsets are safe to compile against branch-wide.
- **Kernel-symbol (address) offsets are keyed to the exact build.** The address
  of a function or global (`&nfulnl_logger`, `init_task`, `selinux_state`,
  `ashmem_miscs`) is fixed by the linker when that specific `vmlinux` is built.
  Any source or LTS-patch difference between builds shifts subsequent addresses.
  Two devices can share a KMI (so the same `.ko` loads) yet run different
  `vmlinux` builds with different symbol addresses. The exploit's absolute
  kernel addresses therefore belong to one concrete build.

### 4.2 Payload keyed to the build id; one payload per offset group

Symbol offsets are keyed to the GKI build id embedded in `uname -r` (the
`ab<NNN>` build number plus git hash uniquely name the `vmlinux`). Devices whose
symbol addresses coincide form one offset group and share a single payload
`.so`; the file is built from one representative device+build (`build_from` in
`data/targets.json`). This is why many Pixel devices on the same build collapse
to one payload — e.g. `android14-6.1-a` is built from `bluejay-CP2A.260705.006`
and covers the full set of `caiman`, `cheetah`, `comet`, `husky`, `lynx`,
`oriole`, `panther`, `raven`, `shiba`, and more on that build; `android14-6.1-b`
covers a distinct-offset subset (`komodo`, `tegu`, `tokay`); `akita` and the
`CP1A` `bluejay` each need their own group; `android15-6.6` covers the 6.6
devices. The payload map in `data/targets.json` is the authority.

### 4.3 Runtime resolution

Two independent resolutions occur against `data/targets.json`:

- **Payload (offset group)** is selected by device **codename + build**, since
  same-KMI devices can require different offsets. Resolution is tiered: exact
  codename+build match first, then codename alone, then any entry on the same
  kernel prefix. The result is the offset-group `.so` to run. If no payload
  resolves for the device, the flow aborts rather than run a mismatched exploit.
- **KMI** is always taken from the **running kernel** (`uname -r`) — from the
  matched entry's `kmi`, or derived directly from the release string (e.g.
  `android14-6.1`). The KMI is what late-load is told to load, because the `.ko`
  rides interface stability (vermagic + symbol CRC + struct layout constant
  across the KMI) while the payload rides binary identity.

---

## 5. Manager-derived, signature-matched `ksud`

The `kernelsu.ko` for a given release is signature-locked to the manager built
in that same release. The kernel module authenticates its manager in-kernel by
verifying the manager APK's v2 signature block (walking the ZIP EOCD → "APK Sig
Block 42" → signer block `0x7109871a`), computing SHA-256 of the signing
certificate, and comparing it to a compile-time `EXPECTED_SIZE` / `EXPECTED_HASH`
pair baked into the `.ko`. v1 and v3/v3.1 signatures are rejected so the check
cannot be downgraded.

Consequence: the `ksud` binary and the `.ko` must come from the same
build/signing identity as the installed manager. The tool therefore extracts
`ksud` from the **installed manager APK** — never a bundled or mismatched copy:

1. resolve the manager's on-device APK path with `pm path <manager package>`;
2. pull the APK;
3. unzip `lib/arm64-v8a/libksud.so` from it and push that as the `ksud` binary.

If no KernelSU manager is installed, the flow aborts. With a mismatched `ksud`
the module would load but the kernel would never set the manager-authorization
bit, leaving the device with a resident driver and no manager able to grant
root — a worse state than doing nothing. Binding `ksud` (and the module) to the
installed manager is what makes the tool manager-agnostic: whichever KernelSU
variant the operator installed is the one the kernel authorizes.

---

## 6. Late-load sequence and syscall-based verification

With temporary root held (§2.7, §3.2), the matched `ksud` is staged as a
root-owned executable and invoked:

```
ksud late-load --kmi <kmi> --package-name <manager package>
```

### 6.1 What late-load does

`late-load` daemonizes, checks whether the driver is already resident, and if
not: detects the current KMI, pulls `"{kmi}_kernelsu.ko"` from the manager's
embedded assets, and loads it. The loader parses the `.ko` ELF, finds every
`SHN_UNDEF` symbol, resolves each against `/proc/kallsyms` (kernel symbol name →
runtime address), rewrites those entries to `SHN_ABS`, and calls the
`init_module(2)` syscall on the patched buffer. This manual relocation is what
lets one prebuilt module (§4) bind to an already-running kernel it was not
linked against. After the module is live, late-load runs the remaining boot
pipeline init would normally run: installs `ksud`, applies `restorecon`, loads
SELinux `sepolicy.rule` and root-profile policies, runs `post-fs-data` /
late-load stage scripts, loads `system.prop`, and mounts the module overlay.

### 6.2 The SELinux / daemon-teardown consequence

Late-load re-enables SELinux enforcement in its forked child. The exploit had
set the kernel globally permissive and was serving the temporary su through a
root daemon (§2.7). Re-enforcement tears down that temporary-su daemon.
Therefore verification **must not** go through su — the su path is gone by the
time the driver is up. This is a hard ordering constraint, not a preference: any
check that depends on the exploit's daemon is invalid after late-load forks.

### 6.3 Verification via the driver syscall

Verification queries the loaded driver directly, over a bare syscall reachable
from a plain shell with no root:

```
ksud debug version
```

is polled and the reported kernel-driver version parsed. Under the hood the
driver exposes no global device node: a caller invokes the reboot-magic install
path (`reboot(magic1, magic2, 0, &out_fd)` with `magic1 = 0xDEADBEEF`,
`magic2 = 0xCAFEBABE`), the kernel installs an anonymous `[ksu_driver]` fd, and
`GET_INFO` ioctl on that fd returns `{version, flags, features, uapi_version}`.
A non-empty, non-zero version confirms the driver is resident and answering.
Because this is an unprivileged syscall probe rather than a call through su, it
survives late-load dismantling the temporary-root daemon (§6.2). Older forks are
also probed through the legacy `prctl(0xDEADBEEF, CMD_GET_VERSION, &version)`
channel as a fallback. The same syscall probe is run at startup, and
short-circuits the entire flow when the module is already resident for the
current boot.

---

## 7. Failure modes and detection

Every failure mode below is detected by the host from a device-side signal —
a log marker, a syscall probe result, or device liveness — never inferred.

| Failure | When | Detection | Response |
|---|---|---|---|
| Slide-race panic / reboot | Phase A (§2.3, §3.1) | post-shot liveness check finds the device gone; wait-for-boot | classify as panic, re-attempt Phase A on the fresh boot |
| No `slide-kaslr-ok` emitted | Phase A shot survives but fails to leak | absence of the `slide-kaslr-ok base=<hex>` line within the shot window | retry Phase A |
| Stale base | new boot between capture and replay | `/proc/sys/kernel/random/boot_id` changed vs. recorded value (§3.3) | discard base, return to Phase A |
| Main-route no-root | Phase B shot completes without escalating | `id` via temporary su does not report `uid=0` | loop Phase B (retry-safe, non-panicking) |
| Unsupported device / no offset group | target resolution (§4.3) | no payload resolves in `data/targets.json` for codename+build | abort before running any exploit |
| Manager not installed | pre-flight (§5) | `pm path <manager package>` returns nothing / no `libksud.so` | abort; refuse to proceed with a mismatched `ksud` |
| Signature-mismatched manager | after late-load | driver resident but manager-authorization bit never set; manager cannot grant root | surfaced as a resident-but-unauthorized driver; operator must install the matching manager |
| `init_module` load failure | late-load (§6.1) | KMI/vermagic or symbol-CRC mismatch rejects the `.ko`; driver never becomes resident | `ksud debug version` stays empty/zero; report load failure |
| Driver not resident post-load | verification (§6.3) | `ksud debug version` returns empty or zero (both new reboot-magic and legacy `prctl` paths) | report late-load failure; root not established this boot |
| Already rooted this boot | startup | `ksud debug version` returns non-zero at start | short-circuit; skip exploit and late-load |

The design goal is that no failure other than the isolated §2.3 slide can leave
the device in a worse state than before the run, and that every recoverable
failure routes deterministically back to the correct phase.

---

## Attribution

- **Exploit and technique:** NebuSec (Nebula Security), *IonStack Part II —
  GhostLock*, in the CyberMeowfia repository (Apache-2.0). CVE-2026-43499,
  disclosed 2026-07-07.
- **Pixel/aarch64 adaptation:** the vendored `exploit/` tree adds
  `android14-6.1` and `android15-6.6` target offsets and a KernelSU late-load
  daemon on top of the NebuSec exploit, under the same Apache-2.0 terms.
- **KernelSnitch side channel:** Lukas Maar et al., TU Graz (isec-tugraz),
  NDSS 2025.
