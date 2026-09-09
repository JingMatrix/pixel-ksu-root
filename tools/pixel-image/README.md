# tools/pixel-image — offsets from a build you have never touched

Every payload this repo builds is keyed to one kernel's exact symbol addresses:
a device's [`target.h`](../../cves/targets/blazer-CP2A.260705.006/target.h) is a
table of file offsets into the running `Image`, and the
[targets README](../../cves/targets/README.md) explains how one payload serves
every device that shares a group. Those offsets have to come from *somewhere*.
Once a device is rooted the running kernel is readable directly and the live
path — [`dump-boot-image.sh`](../../runner/scripts/dump-boot-image.sh) plus
[`harvest-live.sh`](../../runner/scripts/harvest-live.sh) — is authoritative.
But that path is a chicken-and-egg: the boot partition is
`brw------- root:root`, so `dd`-ing it needs the root you are trying to obtain in
the first place ([dump-boot-image.sh:15-19](../../runner/scripts/dump-boot-image.sh#L15)).

`pixel-image` breaks the cycle. It derives the offsets for a brand-new build
from nothing but its codename and build id, before any device has been rooted.
Four stages, each feeding the next: an index lookup for the OTA URL, a
range-fetch for `boot.img`, an unpack to a raw `Image`, and a derivation to the
symbol half of a `target.h`. It is a standalone research instrument, not part of
the runtime rooting path (see the sibling [`hwbp`](../hwbp/README.md) tool and
the [cves index](../../cves/README.md)).

## Stage 0 — codename + build → OTA URL (`ota_index.py`)

```
ota_index.py --device panther --build CP2A.260705.006 --url-only
```

`partial_boot.py` takes a URL, and until now there was no way to find one. The
index at [developers.google.com/android/ota](https://developers.google.com/android/ota)
renders its table only after its terms are acknowledged; an ordinary `GET`
returns a 70 KB page shell containing *zero* download links, which parses
cleanly to nothing and looks exactly like a device with no builds. The
acknowledgement is a cookie
([`ota_index.py#L23`](./ota_index.py#L23)), and one `GET` carrying it returns
the whole table — 2067 builds across 49 devices in a single 666 KB response.

The filename is the record: `<codename>-ota-<build>-<8 hex>.zip`
([`ota_index.py#L29`](./ota_index.py#L29)). That trailing hash is content-derived
and the build is lowercased, so no URL is guessable — the index is the only way
to learn one, which is why fetching it is a stage rather than a footnote.
`--url-only` prints the bare URL for the next stage; a filter that matches
nothing exits non-zero, and a page that yields no links at all says so in those
words rather than reporting "no match"
([`ota_index.py#L70`](./ota_index.py#L70)).

Chained, the whole bootstrap is four lines:

```sh
URL=$(tools/pixel-image/ota_index.py --device panther --build CP2A.260705.006 --url-only)
tools/pixel-image/partial_boot.py "$URL" boot.img
runner/scripts/lib/boot_image.py boot.img Image
tools/pixel-image/derive_offsets.py --image Image --target panther-CP2A.260705.006
```

## Why it fetches byte ranges

A Pixel full-OTA `.zip` is multiple gigabytes; the `boot` partition inside it is
tens of megabytes; the kernel `Image` inside *that* is smaller still. A naive
"download and unzip" wastes almost all of the transfer. The whole design of
[`partial_boot.py`](./partial_boot.py) is to fetch only the three spans that
actually matter — the zip's central-directory tail, `payload.bin`'s
header+manifest, and the `boot` partition's data operations — using HTTP
`Range` requests, so the transfer is proportional to the kernel, not to the OTA
([partial_boot.py:2-4](./partial_boot.py#L2)).

## Stage 1 — OTA URL → `boot.img` (`partial_boot.py`)

```
partial_boot.py <ota_url> <out_boot_img>
```

The script never issues a full `GET`. Its two primitives are a `HEAD` for the
total length ([partial_boot.py:17-20](./partial_boot.py#L17)) and an inclusive
byte-range `GET` ([partial_boot.py:12-15](./partial_boot.py#L12)); everything
below is a sequence of range reads chosen from structure the previous read
revealed.

1. Locate `payload.bin` without a directory listing. A zip's index lives at
   its *end*, so the script reads the last ~64 KB, finds the End-Of-Central-
   Directory record (`PK\x05\x06`), and follows it — via the ZIP64 locator when
   the 32-bit offset is saturated
   ([partial_boot.py:26-34](./partial_boot.py#L26)) — to the central directory,
   then walks the entries for `payload.bin`
   ([partial_boot.py:37-45](./partial_boot.py#L37)). It asserts the entry is
   *stored*, not deflated ([partial_boot.py:48](./partial_boot.py#L48)): a
   compressed `payload.bin` could not be range-sliced, and Pixel OTAs store it
   uncompressed. The local file header is then read to skip past its
   variable-length name/extra fields to the first payload byte
   ([partial_boot.py:50-52](./partial_boot.py#L50)).

2. Read the A/B update payload's manifest. `payload.bin` is a
   Chromium-style A/B image; the script verifies its `CrAU` magic, reads the
   big-endian header to learn the manifest size, and parses the manifest as a
   [`DeltaArchiveManifest`](https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/update_metadata.proto) protobuf
   ([partial_boot.py:56-66](./partial_boot.py#L56)). The manifest is the map: it
   names every partition, its install operations, and the `block_size` those
   operations are expressed in. The absolute file offset of the payload's DATA
   section is computed once here as `data0`
   ([partial_boot.py:64](./partial_boot.py#L64)) so each operation can be
   fetched by `data0 + op.data_offset`. This is why the parser depends on
   `payload_dumper`'s generated protobuf schema
   ([partial_boot.py:8](./partial_boot.py#L8)).

3. Reconstruct only the `boot` partition. The script selects the single
   partition named `boot` ([partial_boot.py:69](./partial_boot.py#L69)) and
   replays its operations into an output buffer. `ZERO` ops emit zero-fill with
   no fetch; `REPLACE`, `REPLACE_BZ` and `REPLACE_XZ` range-fetch exactly their
   `data_length` bytes and, respectively, copy / bunzip2 / unxz them into place
   ([partial_boot.py:72-83](./partial_boot.py#L72)). Any other op type aborts —
   delta operations like `SOURCE_COPY` reference a *previous* image the script
   does not have, so a non-full OTA is rejected rather than silently
   mis-assembled ([partial_boot.py:82](./partial_boot.py#L82)). The assembled
   bytes are the `boot` partition image
   ([partial_boot.py:84-85](./partial_boot.py#L84)).

## Stage 2 — `boot.img` → raw arm64 `Image`

The `boot` partition is an Android boot image, not a kernel. Unpacking it is the
job of [`boot_image.py`](../../runner/scripts/lib/boot_image.py), shared with the
live path so both bootstrap and enrichment produce byte-identical `Image`s. It
parses the [`ANDROID!` header](https://android.googlesource.com/platform/system/tools/mkbootimg/) (v0–v4, resolving the page size and kernel span)
([boot_image.py:39-53](../../runner/scripts/lib/boot_image.py#L39)) and
decompresses the kernel blob by magic — lz4 legacy/frame, gzip, xz, or lzma, or
passes it through when it is already a raw `ARMd` Image
([boot_image.py:30-36](../../runner/scripts/lib/boot_image.py#L30),
[boot_image.py:56-70](../../runner/scripts/lib/boot_image.py#L56)). Pixel GKI
kernels are lz4-compressed, which is the `lz4` dependency this stage needs.

Why a raw `Image` is the goal: for an arm64 `Image`, **file offset == symbol
address − `_text`**
([boot_image.py:4-8](../../runner/scripts/lib/boot_image.py#L4)). That identity
is what turns a symbol address into a readable instruction stream on the host.
When a `kallsyms.txt` is supplied, `boot_image.py` does not merely assume the
identity — it samples up to 400 text symbols, checks each lands on a known arm64
prologue (`paciasp` / `bti c` / `pacibsp` / `autiasp`), and fails the unpack
below an 80% hit rate
([boot_image.py:13-15](../../runner/scripts/lib/boot_image.py#L13),
[boot_image.py:23-28](../../runner/scripts/lib/boot_image.py#L23),
[boot_image.py:143](../../runner/scripts/lib/boot_image.py#L143)).

## Stage 3 — `Image` → symbols → offsets (`derive_offsets.py`)

```
derive_offsets.py --image Image --target panther-CP2A.260705.006
derive_offsets.py --image Image --compare cves/targets/<t>/target.h
```

A stripped GKI `Image` carries no symbol table, so the names come from
[`vmlinux-to-elf` / `kallsyms-finder`](https://github.com/marin-m/vmlinux-to-elf)
(external), which reconstructs kallsyms from the kernel's built-in name table
([`derive_offsets.py#L35`](./derive_offsets.py#L35)). On panther it recovers
98630 symbols, and every one of them agrees with the table read off that phone
after it was rooted — the offline addresses are not an approximation of the live
ones, they are the same numbers.

What turns symbols into a header is not in this directory. The table of *which*
macro comes from *which* symbol, and the arithmetic on top of it, lives in
[`runner/scripts/lib/offset-maps.txt`](../../runner/scripts/lib/offset-maps.txt),
and the rules that read it in
[`offset_rules.py`](../../runner/scripts/lib/offset_rules.py) — both shared with
[`harvest-live.sh`](../../runner/scripts/harvest-live.sh), which asks the same
questions of a rooted device. Two paths, one table, so the build nobody has
rooted cannot get a different answer from the build somebody has.

`derive_offsets.py` covers the three Image-backed sections and says so:

| section | source | offline? |
| --- | --- | --- |
| [`SYMMAP`](../../runner/scripts/lib/offset-maps.txt#L17) | recovered kallsyms | yes |
| [`PTRMAP`](../../runner/scripts/lib/offset-maps.txt#L129) | pointers chased in the `Image` | yes, given `file_operations.compat_ioctl` |
| [`CODEMAP`](../../runner/scripts/lib/offset-maps.txt#L147) | the instruction stream | yes |
| [`STRUCTMAP`](../../runner/scripts/lib/offset-maps.txt#L55) | BTF, sliced out of the same `Image` | yes |
| [`SLABMAP`](../../runner/scripts/lib/offset-maps.txt#L119) | `/proc/slabinfo` | no — a runtime fact |

`STRUCTMAP` used to be the reason a device was still needed, and it is not.
`CONFIG_DEBUG_INFO_BTF` links the kernel's BTF into the image between
`__start_BTF` and `__stop_BTF`, which are ordinary symbols — so the struct
layouts a rooted phone serves as `/sys/kernel/btf/vmlinux` are already inside
any `boot.img`. Sliced out of panther's OTA image, that blob is **byte-identical
(md5)** to the one harvested off the rooted phone, so this is the same
measurement rather than a substitute for it
([`offset_rules.btf_from_image`](../../runner/scripts/lib/offset_rules.py#L47)).

That also closes `PTRMAP`'s one `deref`, which walks `ashmem_fops` at
`file_operations.compat_ioctl` — a struct offset, now resolved from the image
like everything else. `--defines <header>` remains for overriding a row by hand
([`derive_offsets.py`](./derive_offsets.py)).

What is left needs the phone for a reason no image can fix: a slab stride is a
property of the running allocator, not of the kernel binary.

`KIMAGE_TEXT_BASE` is read, not assumed: it is `_text` in the recovered table.
It is not one constant across the fleet — `0xffffffc008000000` on android14-6.1,
`0xffffffc080000000` on android15-6.6 — and `--kbase` overrides it for the one
case where the symbol table is a *live* capture, whose addresses are slid
([`derive_offsets.py#L168`](./derive_offsets.py#L168)).

### What it is checked against

`--compare` diffs the derived values against a committed header and exits
non-zero on any mismatch or unresolved row. Against the two devices with a
committed header on each KMI, from `Image`s partial-fetched by Stage 1:

| target | KMI | result |
| --- | --- | --- |
| `panther-CP2A.260705.006` | android14-6.1 | 83 rows, 0 mismatch, 0 unresolved |
| `blazer-CP2A.260705.006` | android15-6.6 | 83 rows, 0 mismatch, 0 unresolved |

The same panther header, re-derived by the live path from a rooted device
(regenerated via [`harvest-live.sh`](../../runner/scripts/harvest-live.sh)), is
committed as the tracked
[`data/live/panther-CP2A.260705.006/offsets.report`](../../data/live/panther-CP2A.260705.006/offsets.report),
which also ends `0 mismatch, 0 unresolved` — so the offline compare here and the
on-device harvest, two independent derivations, agree.

Adding the struct rows to that comparison immediately found four headers whose
`WAITER_*` group was wrong: 6.6 folded `rt_mutex_waiter`'s `rb_node`, `prio` and
`deadline` into an `rt_waiter_node`, so `tree_entry` became `tree.entry` and
every field after `pi_tree` moved by `0x20`. No code reads that group — it is the
record of the layout, and it had carried the 6.1 values since those headers were
written, because no 6.6 device has ever been harvested. The exploit's own
`FAKE_WAITER_*` group was right all along.

Panther is the stronger of the two, because its `Image` md5 also equals the one
`dump-boot-image.sh` pulled off the rooted phone: the OTA and the device agree
byte for byte, so the whole symbol side of that header could have been written
without ever touching it.

## Where the bootstrap ends and the live path takes over

`pixel-image` gets a build *far enough to attempt a first root*. The line is
not where it used to be. Static and inlined symbols — `ashmem_compat_ioctl`,
`ashmem_misc_fops` — were described here as beyond reach, but kallsyms omits
them on a *rooted* device too, so they were never the offline path's weakness:
[`PTRMAP`](../../runner/scripts/lib/offset-maps.txt#L129) chases them through
`ashmem_fops` in the `Image`, which Stage 1 hands over. In-function branch
targets are [`CODEMAP`](../../runner/scripts/lib/offset-maps.txt#L147), same
`Image`, same answer.

What genuinely needs the phone is narrower: BTF struct-field offsets and slab
strides. Those are why the *live* path exists once a device is rooted:
[`dump-boot-image.sh`](../../runner/scripts/dump-boot-image.sh) pulls the running
`Image` (which resolves inlined symbols and branch offsets by disassembly),
[`harvest-live.sh`](../../runner/scripts/harvest-live.sh) captures BTF and the
full kallsyms with `kptr_restrict` lifted, and
[`gen-cve64560-offsets.py`](../../runner/scripts/gen-cve64560-offsets.py)
regenerates a whole CVE-specific table from that capture. `pixel-image` is the
bootstrap; those three are the enrichment.

## Dependencies

- `python3` with the `payload_dumper` package (for
  `update_metadata_pb2`, [partial_boot.py:8](./partial_boot.py#L8)).
- `lz4` on `PATH` for Stage 2 (GKI kernels are lz4-compressed;
  [boot_image.py:30-36](../../runner/scripts/lib/boot_image.py#L30)).
- [`vmlinux-to-elf` / `kallsyms-finder`](https://github.com/marin-m/vmlinux-to-elf) for Stage 3 (external).
- Nothing for Stage 0: `urllib` and one regex, no HTML parser
  ([`ota_index.py`](./ota_index.py)).

## See also

- [cves/targets/README.md](../../cves/targets/README.md) — where the offsets land.
- [cves/README.md](../../cves/README.md) — the exploit research index.
- [runner/scripts/lib/offset-maps.txt](../../runner/scripts/lib/offset-maps.txt) — the one derivation table, shared with the live path.
- [runner/scripts/harvest-live.sh](../../runner/scripts/harvest-live.sh) — the same rows, asked of a rooted device.
- [tools/hwbp/README.md](../hwbp/README.md) — the sibling standalone instrument.
