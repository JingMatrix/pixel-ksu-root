# cves/targets/ — the per-build offset headers

Every exploit in this tree is offset-driven: the C is generic, and all that
changes between one device and another is a table of kernel symbol addresses and
struct field layouts for that exact kernel build. Those tables live here.

A target is described in two layers:

```
cves/targets/
  kmi/
    android14-6.1.h     geometry, structure layouts, slab parameters
    android15-6.6.h     the same, for the other kernel interface
  panther-CP2A.260705.006/
    target.h            what this build does not share + include of its interface
    cve64560.h          extra header for one exploit (generated)
  komodo-CP2A.260705.006/
    target.h
  ...                   19 build directories
```

A kernel interface fixes the address-space geometry, the structure layouts and
the slab parameters; a build fixes where the symbols landed. Every definition in
an interface header is `#ifndef`-guarded, so the interface supplies a default and
a build always overrides it. Three consequences:

- the include may sit anywhere in a build header (it is written last by
  convention, not by necessity);
- a build that diverges on one field states only that field;
- adding a device costs the values it genuinely has to measure, not a copy of
  the interface.

Symbol addresses come in two layers of their own: a build states each `*_OFF`
relative to the image base, and the interface header derives the absolute `*`
form. Exploit code reads whole addresses and never re-adds a base.

A directory is selected by name. `make TARGET=<codename-build>` compiles against
`targets/$(TARGET)/target.h`; the build wires it in as `TARGET_HEADER` and makes
the whole composed description — build header and every header it includes — a
source dependency, so a missing directory is not a compile error but the named
`ARCH-G0-TARGET` gate. The [runner](../../runner/README.md) resolves the same
directory from the device's fingerprint at run time. The two agree because the
directory name is the key.

## What the two layers contain

The interface header carries what a kernel interface fixes:

- Memory map. `KIMAGE_TEXT_BASE`, the link-time text base every symbol
  offset is measured from; the linear-map window `[DIRECT_MAP_BASE,
  DIRECT_MAP_END)`, which is both an address conversion and the range a pointer
  is validated against before it is dereferenced; and `VMEMMAP_START`, the base
  of the page-descriptor array. KASLR is resolved at run time and never encoded.
- Slab geometry. The allocated object stride of `mm_struct` — not its
  `sizeof`, because the structure ends in a flexible array and the cache is
  cacheline-aligned, and a side channel that walks candidates inside a slab
  strides by exactly this value. Also the kmalloc row index serving accounted
  allocations, the row count, and the kmalloc index a full-size pipe buffer
  array falls in.
- Absolute symbol addresses. The `*` form of every `*_OFF` a build states.
- Structure layouts. `task_struct`, `cred` and its security blob, `seccomp`,
  `file_operations`, `rt_mutex_waiter`, the page descriptor, the workqueue
  records, and the configfs buffer descriptor a name-blob write aims at.
- Chosen layouts. The intra-page offsets a chain writes its fabricated
  objects at. These are chosen rather than measured: what matters is only that
  the objects do not overlap and that each is aligned for its type.

A build header carries what the build fixes:

- its identity strings and kernel release code;
- its symbol offsets from the image base, and the slide references a text-base
  recovery reads or reaches through;
- anything it diverges from its interface on;
- constants only one exploit needs and only this build has measured.

Where an interface serves devices that all ship one kernel image, the symbol
table sits in the interface header too, and a build from a different image takes
precedence simply by stating its own `*_OFF` values.

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
exact build. The group table only says which prebuilt `.so` to send.

## `cve64560.h` — an exploit-specific extra header

[CVE-2026-64560](../cve-2026-64560-zombietick/README.md) needs constants `target.h` does not
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
[header comment with the exact regenerate command](./panther-CP2A.260705.006/cve64560.h).
It carries [`LINK_*` link-time symbol addresses](./panther-CP2A.260705.006/cve64560.h),
[`DIRECT_*` physmap aliases](./panther-CP2A.260705.006/cve64560.h), and
[BTF-exact struct layouts](./panther-CP2A.260705.006/cve64560.h) for that one
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
2. If its kernel is byte-identical to an existing group's `build_from` image,
   create `targets/<codename>-<build>/target.h` reusing those offsets and
   including the interface header, and add a `devices` row in
   [`targets.json`](../../data/targets.json) pointing at that group's `payload`.
   Where the interface header already carries the symbol table, the build header
   is its identity block and nothing else.
3. If it is a new kernel build, write a fresh `target.h` from the harvested facts,
   add a new `payloads` entry with `build_from` set to this directory, and add the
   `devices` row pointing at it.

`SLIDE_TRACE_MARK_IP_OFF` needs no special handling any more: it is a
[`CODEMAP`](../../runner/scripts/lib/offset-maps.txt#L147) row like any other,
found by the `self-addr` rule rather than by hand-disassembly — see
[Deriving the offset for a new build](../lib/kaslr/README.md#deriving-the-offset-for-a-new-build).

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
- [`../lib/kaslr/README.md`](../lib/kaslr/README.md) — the text-base leak that consumes
  `SLIDE_TRACE_MARK_IP_OFF`, and how it is derived for a new build.
- [`../../runner/README.md`](../../runner/README.md) — the stage/recipe framework,
  the addressing model, and the target-set gate that reads these headers.
- [`../cve-2026-64560-zombietick/README.md`](../cve-2026-64560-zombietick/README.md) — the exploit that
  adds `cve64560.h`.
