# tools/pixel-image — offsets from a build you have never touched

Every payload this repo builds is keyed to one kernel's exact symbol addresses, and the
[targets README](../../cves/targets/README.md) explains how one payload then serves every
device that shares an image. Those offsets have to come from somewhere. Once a device is
rooted the running kernel is readable directly, and the live path is authoritative — but
that path is a chicken-and-egg problem, because the boot partition is readable only by
root, which is the thing being obtained in the first place.

`pixel-image` breaks the cycle. It derives the offsets for a brand-new build from nothing
but its codename and build id, before any device on that build has been rooted. Four
stages, each feeding the next: an index lookup for the OTA URL, a range-fetch for the boot
image, an unpack to a raw kernel image, and a derivation to the symbol half of a target
description. It is a standalone research instrument rather than part of the runtime rooting
path.

## Stage 0 — codename and build to OTA URL

```
ota_index.py --device panther --build CP2A.260705.006 --url-only
```

The next stage takes a URL, and finding one is not trivial. The index at
[developers.google.com/android/ota](https://developers.google.com/android/ota) renders its
table only after its terms are acknowledged; an ordinary request returns a page shell
containing no download links at all, which parses cleanly to nothing and looks exactly like
a device with no builds. The acknowledgement is a cookie, and one request carrying it
returns the whole table.

The filename is the record: codename, build and a trailing content-derived hash. That hash
makes no URL guessable, and the build is lowercased along the way, so the index is the only
way to learn a URL — which is why fetching it is a stage rather than a footnote. A filter
that matches nothing exits non-zero, and a page that yields no links at all says so in
those words rather than reporting a failed match, because the two mean very different
things.

Chained, the whole bootstrap is four lines:

```sh
URL=$(tools/pixel-image/ota_index.py --device panther --build CP2A.260705.006 --url-only)
tools/pixel-image/partial_boot.py "$URL" boot.img
runner/scripts/lib/boot_image.py boot.img Image
tools/pixel-image/derive_offsets.py --image Image --target panther-CP2A.260705.006
```

## Why it fetches byte ranges

A Pixel full-OTA archive is multiple gigabytes; the boot partition inside it is a small
fraction of that, and the kernel image inside the partition is smaller still. Downloading
and unzipping wastes almost the entire transfer. The whole design of
[`partial_boot.py`](./partial_boot.py) is to fetch only the three spans that matter — the
archive's central-directory tail, the update payload's header and manifest, and the boot
partition's data operations — using HTTP
[range requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Range_requests),
so that the transfer is proportional to the kernel rather than to the OTA.

## Stage 1 — OTA URL to boot image

```
partial_boot.py <ota_url> <out_boot_img>
```

The script never issues a full request. Its two primitives are a `HEAD` for the total
length and an inclusive byte-range `GET`; everything else is a sequence of range reads, each
chosen from structure the previous read revealed.

It first locates the payload without a directory listing. A zip's index lives at its end, so
the script reads the tail, finds the end-of-central-directory record and follows it — via
the ZIP64 locator when the 32-bit offset is saturated — to the central directory, then walks
the entries. It asserts the payload entry is stored rather than deflated, because a
compressed payload could not be range-sliced at all; Pixel OTAs store it uncompressed. The
local file header is then read only to skip its variable-length fields and reach the first
payload byte.

Next it reads the [A/B update payload's
manifest](https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/update_metadata.proto),
after verifying the payload magic. The manifest is the map: it names every partition, its
install operations, and the block size those operations are expressed in. The absolute
offset of the payload's data section is computed once, so that each operation can be fetched
directly. This is why the parser depends on the update engine's generated protobuf schema.

Finally it reconstructs only the boot partition, replaying that partition's operations into
an output buffer. Zero-fill operations emit zeroes with no fetch; replace operations
range-fetch exactly their own length and copy or decompress it into place. Any other
operation type aborts the run, because delta operations reference a previous image the
script does not have, and a non-full OTA is better rejected than silently mis-assembled.

## Stage 2 — boot image to a raw arm64 kernel image

The boot partition is an Android boot image, not a kernel. Unpacking it is the job of
[`boot_image.py`](../../runner/scripts/lib/boot_image.py), which is shared with the live
path so that bootstrap and enrichment produce byte-identical images. It parses the
[boot image header](https://source.android.com/docs/core/architecture/bootloader/boot-image-header)
across its versions, resolving the page size and the kernel span, and decompresses the
kernel blob by magic — lz4 in either framing, gzip, xz or lzma — passing it through
untouched when it is already a raw image. Pixel GKI kernels are lz4-compressed, which is
where that dependency comes from.

A raw image is the goal because of one identity: for an arm64 image, a file offset equals
the symbol address minus the text base. That is what turns a symbol address into a readable
instruction stream on the host. When a symbol table is supplied, the unpacker does not
merely assume the identity: it samples text symbols, checks that each lands on a recognised
arm64 function prologue, and fails the unpack when too few do.

## Stage 3 — image to symbols to offsets

```
derive_offsets.py --image Image --target panther-CP2A.260705.006
derive_offsets.py --image Image --compare cves/targets/kernel/<image>.h
```

A stripped GKI image carries no symbol table, so the names come from
[`vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf), which reconstructs the
kernel's symbol table from its built-in name table. The addresses this recovers are not an
approximation of the live ones: they are the same numbers a rooted phone reports.

What turns symbols into a header is not in this directory. The table of which macro comes
from which symbol, and the arithmetic on top of it, lives in
[`runner/scripts/lib/offset-maps.txt`](../../runner/scripts/lib/offset-maps.txt), with the
rules that read it in
[`offset_rules.py`](../../runner/scripts/lib/offset_rules.py) — both shared with the live
harvest, which asks the same questions of a rooted device. Two paths, one table, so the
build nobody has rooted cannot get a different answer from the build somebody has.

The derivation covers every section that the image itself can answer:

| section | source | available offline |
| --- | --- | --- |
| symbols | the recovered symbol table | yes |
| pointers | pointers chased inside the image | yes |
| code | the instruction stream | yes |
| structures | BTF, sliced out of the same image | yes |
| slabs | the running allocator | no — a runtime fact |

The structure layouts need no device either. The kernel's
[BTF](https://docs.kernel.org/bpf/btf.html) is linked into the image between two ordinary
symbols, so the layouts a rooted phone serves through sysfs are already inside any boot
image, and the slice taken from an OTA image is byte-identical to the blob harvested from
the phone. This is the same measurement rather than a substitute for it. It also closes the
one pointer row that has to walk an operations table at a structure offset, since that
offset is now resolved from the image like everything else.

What is left genuinely needs the phone, for a reason no image can fix: a slab stride is a
property of the running allocator rather than of the kernel binary.

The text base is read rather than assumed — it is the text symbol in the recovered table —
and it is not one constant across kernel flavours. An override exists for the one case
where the supplied symbol table is a live capture, whose addresses are already slid.

### What it is checked against

`--compare` diffs the derived values against a committed header and exits non-zero on any
mismatch or unresolved row. It is run against a representative build on each kernel
interface, from images partial-fetched by stage 1, and both come back clean.

The baseline follows the header's includes, and it has to. A build's description holds the
symbol offsets of one image and includes the interface header holding every structure
offset, so reading the build's own file alone recovers none of the layout rows — and a
comparison that cannot see a value cannot disagree with it. Following the include puts all
of them under comparison.

The same header, re-derived by the live path from a rooted device, is committed as a tracked
report that also ends clean, so the offline comparison and the on-device harvest are two
independent derivations that agree.

Bringing the structure rows under that comparison is what exposed a layout group that had
been wrong in several headers: one kernel flavour folds part of `rt_mutex_waiter` into a
nested node type, which renames one field and moves every field after it. No code reads that
group — it is the record of the layout rather than an input to the exploit — and it had
carried the other flavour's values since the headers were written, because a device on that
flavour had never been harvested.

The stronger of the two checks is the one where the image fetched from the OTA is also
byte-identical to the one pulled off the rooted phone: the OTA and the device agree exactly,
so the whole symbol side of that description could have been written without ever touching
the device.

## Where the bootstrap ends and the live path takes over

`pixel-image` gets a build far enough to attempt a first root. The boundary is narrower than
it looks. Static and inlined symbols are not the offline path's weakness, because the
kernel's symbol table omits them on a rooted device too; they are chased through an exported
operations table in the image, which stage 1 hands over, and in-function branch targets come
out of the same image by disassembly.

What genuinely needs the phone is structure field offsets — when no image is at hand — and
slab strides. That is what the live path is for once a device is rooted: it pulls the
running image, captures BTF and the full symbol table with pointer restriction lifted, and
regenerates whole exploit-specific tables from that capture. `pixel-image` is the bootstrap;
the live path is the enrichment.

## Dependencies

- `python3` with the `payload_dumper` package, for the update metadata schema.
- `lz4` on `PATH` for stage 2, since GKI kernels are lz4-compressed.
- [`vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf) for stage 3.
- Nothing for stage 0 beyond the standard library and one regular expression: no HTML
  parser is involved.

## See also

- [cves/targets/README.md](../../cves/targets/README.md) — where the offsets land.
- [cves/README.md](../../cves/README.md) — the exploit research index.
- [runner/scripts/lib/offset-maps.txt](../../runner/scripts/lib/offset-maps.txt) — the one derivation table, shared with the live path.
- [runner/scripts/harvest-live.sh](../../runner/scripts/harvest-live.sh) — the same rows, asked of a rooted device.
- [tools/hwbp/README.md](../hwbp/README.md) — the sibling standalone instrument.
