# cves/targets/ — the offset headers

Every exploit in this tree is offset-driven. The C is generic, and all that changes between
one device and another is a table of kernel symbol addresses and structure layouts for that
exact kernel build. Those tables live here.

A target is described in three layers, of which only the first two are files on disk:

```
cves/targets/
  kmi/
    android14-6.1.h               geometry, structure layouts, slab parameters
    android15-6.6.h               the same, for the other kernel interface
  kernel/
    android14-6.1-ab14791245.h    the symbol table of one kernel image
    android14-6.1-ab14691759.h
    android15-6.6-ab15266607.h
  panther-CP2A.260705.006/
    cve64560.h                    an extra header one exploit needs (generated)
```

A kernel interface fixes the address-space geometry, the structure layouts and the slab
parameters. A kernel image fixes where the symbols landed. A build then adds its identity
strings and whatever else it alone diverges on — which is usually nothing, in which case
the resolver composes the build header from the build's row in
[`data/targets.json`](../../data/targets.json) and hands that to the compiler, with no file
committed at all.

Every definition in an interface header is `#ifndef`-guarded, so the interface supplies a
default that a more specific layer always overrides. Three consequences follow. The include
may sit anywhere in a build header, written last by convention rather than necessity. A
build that diverges on one field states only that field. And adding a device costs the
values it genuinely has to measure, never a copy of the interface.

Symbol addresses come in two layers of their own: an image states each `*_OFF` relative to
the image base, and the interface header derives the absolute form. Exploit code reads
whole addresses and never re-adds a base.

A target is selected by name. `make TARGET=<codename-build>` compiles against that target's
composed description, and makes the whole composition — every header that goes into it — a
source dependency, so an unknown target is not a compile error but the named
`ARCH-G0-TARGET` gate. The [runner](../../runner/README.md) resolves the same target from
the device's fingerprint at run time. The two agree because the name is the key.

## What each layer contains

The interface header carries what a kernel interface fixes.

Its memory map gives the link-time text base every symbol offset is measured from, the
[linear-map](https://docs.kernel.org/arch/arm64/memory.html) window — which is both an
address conversion and the range a pointer is validated against before it is dereferenced —
and the base of the page-descriptor array. KASLR is resolved at run time and never encoded.

Its slab geometry gives the allocated object stride of `mm_struct`, which is not its
`sizeof`: the structure ends in a flexible array and the cache is cacheline-aligned, and a
side channel that walks candidates inside a slab strides by exactly this value. It also
gives the [kmalloc](https://docs.kernel.org/mm/slub.html) row serving accounted
allocations, the row count, and the row a full-size pipe buffer array falls in.

Then the absolute form of every symbol offset an image states; the layouts of
`task_struct`, `cred` and its security blob, `seccomp`, `file_operations`,
`rt_mutex_waiter`, the page descriptor, the workqueue records and the configfs buffer
descriptor a name-blob write aims at; and the intra-page offsets a chain writes its
fabricated objects at. That last group is chosen rather than measured: what matters is only
that the objects do not overlap and that each is aligned for its type.

A kernel-image header carries the symbol offsets from the image base, and the slide
reference a text-base recovery reads or reaches through. A build header, when one exists at
all, carries the identity strings and kernel release code, anything the build diverges from
its interface on, and constants only one exploit needs and only this build has measured.

## The offset-group model

Many Pixel devices ship the byte-identical GKI kernel, so they share every offset. Each row
under `devices` in [`data/targets.json`](../../data/targets.json) maps a codename and build
to an interface and a payload, and each entry under `payloads` is one offset group: a
single prebuilt shared object, compiled from the one representative build named in its
`build_from` field, covering every device whose kernel image is byte-identical to it.

A payload is named after its interface alone when it is that interface's only kernel image.
An interface that ships more than one image suffixes the minority images with their kernel
build number rather than an arbitrary letter, so the name states the fact it stands for
instead of an arrival order.

A device-build earns a committed directory of its own only when it has something genuinely
its own that the image and interface headers do not already supply — a tuning value rather
than an offset. None of the shipped builds need one. Where a per-device tuning knob has
been wanted in the past, the better answer has been an environment variable read at run
time, which keeps the difference out of the headers entirely.

## An exploit-specific extra header

[CVE-2026-64560](../cve-2026-64560-zombietick/README.md) needs constants the shared headers
do not carry: link-time addresses for
[`posix-cpu-timers`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/time/posix-cpu-timers.c)
symbols, and the exact
[`k_itimer`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/posix-timers.h),
`cpu_timer` and
[`timerqueue`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/timerqueue.h)
layouts the use-after-free walks. Those live in a separate `cve64560.h` beside the build's
other material. It exists for one build only; for any other target that recipe fails the
`ARCH-G0-TARGETSET` gate — the stage is restricted to a target list, and other targets are
not in it — at both build and run time.

`cve64560.h` is generated rather than hand-edited. It is emitted by
[`gen-cve64560-offsets.py`](../../runner/scripts/gen-cve64560-offsets.py) from a live
capture, and its header comment carries the exact command that regenerates it. It holds
link-time symbol addresses, their linear-map aliases, and
[BTF](https://docs.kernel.org/bpf/btf.html)-exact structure layouts for that one image.

## Adding a device

A device is a target row, and sometimes a kernel-image header. No per-device build file is
added as a matter of course.

Start offline, before touching the device at all. The symbol half of the description can be
derived from the build's public OTA:

```sh
URL=$(tools/pixel-image/ota_index.py --device <codename> --build <BUILD> --url-only)
tools/pixel-image/partial_boot.py "$URL" boot.img
runner/scripts/lib/boot_image.py boot.img Image
tools/pixel-image/derive_offsets.py --image Image --target <codename>-<build>
```

That yields every symbol offset in the symbol and slide groups, the static symbols the
pointer-chasing rules follow, and the structure layouts, because the kernel's BTF is inside
the image and the slice is byte-identical to what a rooted device serves. What it cannot
give you is the slab stride, which is a property of the running allocator rather than of
the image.

So the second step is to root the device once and harvest while it is still rooted, since
root is per-boot and every offset source vanishes on reboot. This fills in the allocator
half and re-derives what the offline step produced, so the offline answer is confirmed
rather than trusted.

Then, if the kernel is byte-identical to an existing group's representative image, add a
`devices` row naming that interface and pointing at the existing payload, and nothing else:
the resolver composes the header this build needs. If it is a new kernel image, add its
symbol table under `kernel/`, add a `payloads` entry whose `build_from` names this build,
and add the `devices` row pointing at it.

The slide reference the text-base leak consumes needs no special handling: it is an
ordinary row in the derivation table, found by a rule rather than by hand-disassembly. See
[Deriving the offset for a new build](../lib/kaslr/README.md).

## How offsets are harvested and verified

Which macro comes from which source, and the arithmetic on top of it, is one table:
[`runner/scripts/lib/offset-maps.txt`](../../runner/scripts/lib/offset-maps.txt), with one
resolver per rule in
[`offset_rules.py`](../../runner/scripts/lib/offset_rules.py). The live path and the
offline [`derive_offsets.py`](../../tools/pixel-image/derive_offsets.py) both read it, so a
rule fixed for a rooted device is the same rule a never-rooted build gets. Nothing about a
derivation belongs in a header comment: an addend written only in prose is one nobody can
re-run, which is how the single constant every root run consumes once went unchecked across
every target.

[`harvest-live.sh`](../../runner/scripts/harvest-live.sh) captures, from a currently-rooted
device, everything needed to derive and check every offset. The bulky captures are
regenerated rather than committed; what the repo tracks is the derivation payoff, alongside
the kernel config, the memory map, the slab listing and the device's identity strings.

The sources are complementary, and each answers something the others cannot:

- The kernel symbol table gives exact per-build symbol addresses with no image parsing.
  Pointer restriction zeroes every address even for root, so the script lifts it for the
  dump and restores it immediately afterwards.
- [BTF](https://docs.kernel.org/bpf/btf.html) gives every structure field offset exactly,
  which is what the layout macros are derived from.
- The kernel image itself resolves what neither of those can see: static symbols reachable
  only by chasing a pointer out of an exported operations table, and in-function branch
  offsets that probe-based oracles aim at.
- The slab listing gives the real stride each object lives at, so a walked stride is never
  confused with a `sizeof`.

The payoff is a report that re-derives every committed offset from the capture and diffs it
against the header. A mismatch means the committed header is wrong for this build; an
unresolved entry means a derivation rule needs updating, or that a source was missing from
the capture.

## See also

- [`../README.md`](../README.md) — the exploit tree and the promotion gate.
- [`../../runner/scripts/lib/offset-maps.txt`](../../runner/scripts/lib/offset-maps.txt) — the one derivation table both paths read.
- [`../../tools/pixel-image/README.md`](../../tools/pixel-image/README.md) — deriving a header from a public OTA, with no device.
- [`../lib/kaslr/README.md`](../lib/kaslr/README.md) — the text-base leak, and how its offset is derived for a new build.
- [`../../runner/README.md`](../../runner/README.md) — the stage and recipe framework, the addressing model, and the gates that read these headers.
- [`../cve-2026-64560-zombietick/README.md`](../cve-2026-64560-zombietick/README.md) — the exploit that adds the extra header.
