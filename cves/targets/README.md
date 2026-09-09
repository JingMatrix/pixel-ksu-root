# cves/targets/ — the shared per-device offset headers

Every exploit in this tree is offset-driven: the C is generic, and all that
changes between one Pixel and another is a table of kernel symbol addresses and
struct field layouts for that exact kernel build. Those tables live here, one
directory per `<codename>-<build>`, shared by every exploit built for the device.

```
cves/targets/
  panther-CP2A.260705.006/
    target.h        shared offsets: memory map, symbols, struct layouts
    cve64560.h      extra header, CVE-2026-64560 only (generated)
  komodo-CP2A.260705.006/
    target.h
  ...               19 device-build directories
```

A directory is selected by name. `make TARGET=<codename-build>` compiles against
`targets/$(TARGET)/target.h` — the build wires it in as
[`TARGET_HEADER := targets/$(TARGET)/target.h`](../Makefile#L40) and makes the
header a source dependency, so a missing directory is not a compile error but the
named [`ARCH-G0-TARGET`](../../runner/scripts/resolve-recipe.py#L24) gate. The
[runner](../../runner/README.md) resolves the same directory from the device's
fingerprint at run time. The two agree because the directory name is the key.

## What `target.h` contains

`target.h` describes exactly one kernel Image, entirely in link-time terms; KASLR
is applied at run time by the [text-base leak](../kaslr/README.md) and the header
never encodes a runtime base. Its sections, using
[`panther-CP2A.260705.006/target.h`](./panther-CP2A.260705.006/target.h) as the
worked example:

- Memory map. [`KIMAGE_TEXT_BASE`](./panther-CP2A.260705.006/target.h#L30) is the
  link-time text base — `0xffffffc008000000` on the android14-6.1 VA_BITS=39
  layout — from which every symbol offset is measured. Alongside it:
  [`P0_PAGE_OFFSET`](./panther-CP2A.260705.006/target.h#L32), the
  [KernelSnitch identity / direct-map window](./panther-CP2A.260705.006/target.h#L36),
  [`VMEMMAP_START`](./panther-CP2A.260705.006/target.h#L41), and the physical
  load address
  [`P0_KERNEL_PHYS_LOAD`](./panther-CP2A.260705.006/target.h#L35), ground-truthed
  from `/proc/iomem`.
- kmalloc / slab knobs. The real slab stride for [`mm_struct`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/mm_types.h) —
  [`MM_STRUCT_SZ 0x400`](./panther-CP2A.260705.006/target.h#L51), the
  `SLAB_HWCACHE_ALIGN`-rounded stride, not `sizeof` (0x3c0). The header spells out
  why: [KernelSnitch](https://github.com/isec-tugraz/KernelSnitch) walks candidates at the slab stride, so committing the BTF
  `sizeof` would misalign every candidate and the futex-hash collision check would
  never match. It also carries the kmalloc cache-type count, the cgroup row index,
  and the [pipe-buffer array's kmalloc index](./panther-CP2A.260705.006/target.h#L56).
- Kernel symbol offsets. [Image offsets from `KIMAGE_TEXT_BASE`](./panther-CP2A.260705.006/target.h#L30)
  for every symbol the exploits touch — [`ashmem_*`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/staging/android/ashmem.c), `configfs_*`, [`init_task`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/init/init_task.c),
  [`selinux_state`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/security/selinux/include/security.h), [`security_hook_heads`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/security/security.c), [`kmalloc_caches`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/mm/slab_common.c), [`anon_pipe_buf_ops`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/fs/pipe.c),
  the usermode-helper work item, the unbound workqueue. Each raw `*_OFF` macro has
  a companion [absolute macro](./panther-CP2A.260705.006/target.h#L87) defined as
  `KIMAGE_TEXT_BASE + *_OFF`, so the exploit code reads a whole address and never
  re-adds the base.
- Slide references. [`SLIDE_TRACE_MARK_IP_OFF`](./panther-CP2A.260705.006/target.h#L134)
  is the only offset the [text-base leak](../kaslr/README.md) reads, and all 19
  headers define it. The group also holds the boot_id sysctl pair —
  [`SLIDE_RANDOM_BOOT_ID_DATA_OFF`](./panther-CP2A.260705.006/target.h#L123), the
  `.data` pointer of [`random_table`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/char/random.c)'s boot_id entry, and
  [`SLIDE_SYSCTL_BOOTID_OFF`](./panther-CP2A.260705.006/target.h#L128), the buffer
  that pointer must hold — which
  [`restore_slide_boot_id()`](../cve-2026-43499-ghostlock/fops.c#L270) uses to
  write the pointer back, plus
  [`SLIDE_NFULNL_LOGGER_OFF`](./panther-CP2A.260705.006/target.h#L111) and
  `SLIDE_LOGGERS_0_1_OFF`. The GhostLock stage manifests require the derived
  `SLIDE_*_IMAGE` forms by name
  ([stage.toml#L74](../../runner/stages/entry.ghostlock@6.1/stage.toml#L74)), so a
  header that drops one fails `ARCH-G3-FACTS` at build time.
  `SLIDE_RANDOM_BOOT_ID_DATA_OFF` is also the cross-check for the 64560
  exploit's generated `DIRECT_BOOTID_PARENT`
  ([gen-cve64560-offsets.py#L81](../../runner/scripts/gen-cve64560-offsets.py#L81)).
- Struct field layouts (DWARF/BTF). Field offsets for
  [`rt_mutex_waiter`](./panther-CP2A.260705.006/target.h#L163),
  [`task_struct`](./panther-CP2A.260705.006/target.h#L213),
  [`cred`](./panther-CP2A.260705.006/target.h#L225),
  [`file_operations`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/fs.h), [`seccomp`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/seccomp.h), `mm_struct`, [`page`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/mm_types.h), and the workqueue structs —
  plus the [fake-object page layout](./panther-CP2A.260705.006/target.h#L155) the
  exploits build (`LOCK_OFF`, `FAKE_TASK_OFF`, `RIGHT_OFF`, …). These are the
  layout assumptions the exploit bakes in; the KMI declares them stable across a
  flavour, and [`offsets.report`](#how-offsets-are-harvested-and-verified) proves
  them per build.

The header also records its own provenance in a comment: panther's kernel is
[byte-identical (md5) to tegu's](./panther-CP2A.260705.006/target.h#L5), same CI
build, so the offsets are shared and were re-verified — every committed macro
re-derived from a live capture (regenerated via
[`harvest-live.sh`](../../runner/scripts/harvest-live.sh)) and diffed against the
header in the tracked
[`data/live/panther-CP2A.260705.006/offsets.report`](../../data/live/panther-CP2A.260705.006/offsets.report),
which ends `0 mismatch, 0 unresolved`.

## The offset-group model

Many Pixel devices ship the byte-identical GKI kernel, so they share every
offset. In [`data/targets.json`](../../data/targets.json) each row under `devices`
maps a `codename`+`build` to a `kmi` and a `payload`, and each entry under
`payloads` is one offset group: a single prebuilt `.so` compiled from the one
representative `<codename>-<build>` named in its `build_from` field, covering
every device whose kernel Image is byte-identical to it.

| payload | KMI | built from | devices in the group |
| --- | --- | --- | --- |
| `android14-6.1-a` | android14-6.1 | bluejay-CP2A.260705.006 | bluejay, caiman, cheetah, comet, husky, lynx, oriole, panther, raven, shiba (all CP2A) |
| `android14-6.1-b` | android14-6.1 | komodo-CP2A.260705.006 | komodo, tegu, tokay |
| `android14-6.1-akita` | android14-6.1 | akita-CP2A.260805.005 | akita |
| `android14-6.1-cp1a` | android14-6.1 | bluejay-CP1A.260405.005 | bluejay (CP1A) |
| `android15-6.6` | android15-6.6 | blazer-CP2A.260705.006 | blazer, frankel, mustang, rango |

Every device-build still has its own `targets/<codename>-<build>/target.h` even
when several devices point at one payload: the directory is how the build and the
runner find offsets by name, and the header is the correctness record for that
exact build (for a shared kernel, that its Image md5 matches the group's
`build_from`). The group table only says which prebuilt `.so` to send.

## `cve64560.h` — an exploit-specific extra header

[CVE-2026-64560](../cve-2026-64560/README.md) needs constants `target.h` does not
carry: link-time addresses for [`posix-cpu-timers`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/time/posix-cpu-timers.c) symbols and the exact
[`k_itimer`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/posix-timers.h) / [`cpu_timer`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/posix-timers.h) / [`timerqueue`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/timerqueue.h) struct layouts the UAF walks. Those live
in a separate [`cve64560.h`](./panther-CP2A.260705.006/cve64560.h) beside
`target.h`. It is present for `panther-CP2A.260705.006` only; for any other target
that recipe fails the
[`ARCH-G0-TARGETSET`](../../runner/scripts/resolve-recipe.py#L25) gate — the stage
is restricted to a target list, and other targets are not in it — at both build
and run time.

`cve64560.h` is generated, never hand-edited: it is emitted by
[`gen-cve64560-offsets.py`](../../runner/scripts/gen-cve64560-offsets.py) from a
live capture, and says so in its
[header comment with the exact regenerate command](./panther-CP2A.260705.006/cve64560.h#L1).
It carries [`LINK_*` link-time symbol addresses](./panther-CP2A.260705.006/cve64560.h#L16),
[`DIRECT_*` physmap aliases](./panther-CP2A.260705.006/cve64560.h#L43), and
[BTF-exact struct layouts](./panther-CP2A.260705.006/cve64560.h#L52) for that one
image.

## Adding a device

A device is a target header plus a `targets.json` row — no per-device build file
is ever added, exactly as the [Makefile states](../Makefile#L20):

0. Derive the symbol half of the header from the build's public OTA, before
   touching the device at all:

   ```sh
   URL=$(tools/pixel-image/ota_index.py --device <codename> --build <BUILD> --url-only)
   tools/pixel-image/partial_boot.py "$URL" boot.img
   runner/scripts/lib/boot_image.py boot.img Image
   tools/pixel-image/derive_offsets.py --image Image --target <codename>-<build> \
       ```

   That is every `*_OFF` in the [symbol](#what-targeth-contains) and slide
   groups, the two static symbols `PTRMAP` chases, and the struct layouts —
   the kernel's BTF is inside the image, between `__start_BTF` and
   `__stop_BTF`, and the slice is byte-identical to what a rooted device
   serves. Verified against panther and blazer at 0 mismatch, 0 unresolved on
   both KMIs
   ([tools/pixel-image](../../tools/pixel-image/README.md#what-it-is-checked-against)).
   What it cannot give you is `MM_STRUCT_SZ`: a slab stride is a property of
   the running allocator, which is what step 1 is for.
1. Get root on the device once (`./pixel-ksu-root --manager <pkg>`), then harvest
   while it is still rooted (below) — root is per-boot and every offset source
   vanishes on reboot. This both fills in the BTF/slabinfo half and re-derives
   what step 0 produced, so the offline answer is confirmed rather than trusted.
2. If its kernel is byte-identical to an existing group's `build_from` Image
   (same CI build, matching md5), create `targets/<codename>-<build>/target.h`
   reusing those offsets, record the shared provenance in the header comment, and
   add a `devices` row in [`targets.json`](../../data/targets.json) pointing at
   that group's `payload`.
3. If it is a new kernel build, write a fresh `target.h` from the harvested facts,
   add a new `payloads` entry with `build_from` set to this directory, and add the
   `devices` row pointing at it.

`SLIDE_TRACE_MARK_IP_OFF` needs no special handling any more: it is a
[`CODEMAP`](../../runner/scripts/lib/offset-maps.txt#L147) row like any other,
found by the `self-addr` rule rather than by hand-disassembly — see
[Deriving the offset for a new build](../kaslr/README.md#deriving-the-offset-for-a-new-build).

## How offsets are harvested and verified

Which macro comes from which source, and the arithmetic on top of it, is one
table: [`runner/scripts/lib/offset-maps.txt`](../../runner/scripts/lib/offset-maps.txt),
with one resolver per rule in
[`offset_rules.py`](../../runner/scripts/lib/offset_rules.py). The live path
below and the offline
[`derive_offsets.py`](../../tools/pixel-image/derive_offsets.py) both read it, so
a rule fixed for a rooted device is the same rule the never-rooted build gets.
Nothing about a derivation belongs in a header comment: an addend written only
in prose is one nobody can re-run, which is how `SLIDE_TRACE_MARK_IP_OFF` — the
one constant every root run consumes — went unchecked across all 19 targets.

[`harvest-live.sh`](../../runner/scripts/harvest-live.sh) captures, from a
currently-rooted device, everything needed to derive and check every offset, into
`data/live/<codename>-<build>/`. The large captures below (`kallsyms.txt`,
`btf-vmlinux`, `Image`, `dmesg.txt`) are regenerated by that script and are not
committed; what the repo tracks and a reader can open is the derivation payoff
[`offsets.report`](../../data/live/panther-CP2A.260705.006/offsets.report)
(below), alongside `config.gz`, `iomem.txt`, `slabinfo.txt` and `env.txt`:

- `kallsyms.txt` — the full symbol table. [`kptr_restrict=2`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/lib/vsprintf.c) zeroes every address
  even for root, so the script
  [lifts it for the dump and restores it immediately](../../runner/scripts/harvest-live.sh#L72),
  yielding exact per-build symbol addresses with no boot.img parsing. Source for
  every `*_OFF` symbol offset (the
  [`[SYMMAP]`](../../runner/scripts/lib/offset-maps.txt#L17) table).
- `btf-vmlinux` — [`/sys/kernel/btf/vmlinux`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/bpf/sysfs_btf.c), every struct field offset, exact.
  Source for the `task_struct` / `cred` / `file_operations` / … layouts (the
  [`[STRUCTMAP]`](../../runner/scripts/lib/offset-maps.txt#L55) table).
- `Image` — the running kernel, dumped by
  [`dump-boot-image.sh`](../../runner/scripts/dump-boot-image.sh). It resolves
  what kallsyms and BTF cannot see: static-symbol pointers chased through
  `ashmem_fops` (the [`[PTRMAP]`](../../runner/scripts/lib/offset-maps.txt#L129) table)
  and in-function branch offsets for kprobe oracles (the
  [`[CODEMAP]`](../../runner/scripts/lib/offset-maps.txt#L142) table).
- `slabinfo.txt` — the real slab stride each object lives at (the
  [`[SLABMAP]`](../../runner/scripts/lib/offset-maps.txt#L119) table), so
  `MM_STRUCT_SZ` is the walked stride, not `sizeof`.
- Plus `config.gz`, `iomem.txt`, `dmesg.txt`, pstore ramoops, and `env.txt`
  (codename, build, kernel release, SPL).

The five derivation tables themselves live in
[`lib/offset-maps.txt`](../../runner/scripts/lib/offset-maps.txt), shared with
the offline path so a rule fixed for a rooted device is the rule a never-rooted
build gets. The payoff is
[`offsets.report`](../../runner/scripts/harvest-live.sh#L119):
[`offset_report.py`](../../runner/scripts/lib/offset_report.py) re-derives every
committed `target.h` (and `cve64560.h`) offset from the capture and diffs it
against the header. A
[`MISMATCH`](../../runner/scripts/lib/offset_report.py#L89) means the committed
header is wrong for this build; an
[`UNRESOLVED`](../../runner/scripts/lib/offset_report.py#L81) means a derivation
rule needs updating, or a source like the Image was missing.

## See also

- [`../README.md`](../README.md) — the exploit tree and the promotion gate.
- [`../../runner/scripts/lib/offset-maps.txt`](../../runner/scripts/lib/offset-maps.txt) — the one derivation table both paths read.
- [`../../tools/pixel-image/README.md`](../../tools/pixel-image/README.md) — deriving a header from a public OTA, with no device.
- [`../kaslr/README.md`](../kaslr/README.md) — the text-base leak that consumes
  `SLIDE_TRACE_MARK_IP_OFF`, and how it is derived for a new build.
- [`../../runner/README.md`](../../runner/README.md) — the stage/recipe framework,
  the addressing model, and the target-set gate that reads these headers.
- [`../cve-2026-64560/README.md`](../cve-2026-64560/README.md) — the exploit that
  adds `cve64560.h`.
