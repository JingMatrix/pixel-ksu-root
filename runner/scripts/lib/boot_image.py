#!/usr/bin/env python3
"""Unpack an Android boot partition image into the raw arm64 `Image`.

For an arm64 `Image`, file offset == symbol address - _text, so every kallsyms
symbol becomes a byte offset into the running kernel's own code, on the host,
with nothing else to unpack. That is what lets us read instructions for offsets
that kallsyms and BTF cannot give us: static/inlined symbols, and branch offsets
inside a function.

Usage:
  boot_image.py <boot.img> <out-Image> [--kallsyms <kallsyms.txt>]

With --kallsyms it also *verifies* the offset identity above, instead of assuming
it: it samples text symbols, checks the word at (addr - _text) is a plausible
function prologue, and fails if the hit rate is poor.
"""
import struct
import subprocess
import sys

# arm64 function prologues seen on GKI (BTI/PAC builds). A sampled text symbol
# should start with one of these, or with a stack-frame setup.
PROLOGUES = {
    0xD503233F,  # paciasp
    0xD503245F,  # bti c
    0xD503237F,  # pacibsp
    0xD50323BF,  # autiasp (tail-merged, rare but valid)
}

DECOMPRESSORS = [
    (b"\x02\x21\x4c\x18", ["lz4", "-d", "-c"], "lz4 (legacy)"),
    (b"\x04\x22\x4d\x18", ["lz4", "-d", "-c"], "lz4 (frame)"),
    (b"\x1f\x8b", ["gzip", "-d", "-c"], "gzip"),
    (b"\xfd7zXZ", ["xz", "-d", "-c"], "xz"),
    (b"\x5d\x00\x00", ["xz", "-d", "-c", "--format=lzma"], "lzma"),
]


def parse_header(blob):
    """Return (kernel_offset, kernel_size, header_version)."""
    if blob[:8] != b"ANDROID!":
        raise SystemExit(f"not an Android boot image: magic {blob[:8]!r}")
    hv = struct.unpack_from("<I", blob, 40)[0]
    if hv >= 3:
        # v3/v4: page size is fixed at 4096, ramdisk follows the kernel
        kernel_size = struct.unpack_from("<I", blob, 8)[0]
        return 4096, kernel_size, hv
    # v0/v1/v2 carry an explicit page_size
    kernel_size = struct.unpack_from("<I", blob, 8)[0]
    page_size = struct.unpack_from("<I", blob, 36)[0]
    if page_size not in (2048, 4096, 8192, 16384, 32768, 65536):
        raise SystemExit(f"implausible page_size {page_size} in boot header v{hv}")
    return page_size, kernel_size, hv


def decompress(payload):
    if payload[0x38:0x3C] == b"ARMd":
        return payload, "none (already a raw Image)"
    for magic, cmd, label in DECOMPRESSORS:
        if payload.startswith(magic):
            try:
                out = subprocess.run(cmd, input=payload, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, check=False).stdout
            except FileNotFoundError:
                raise SystemExit(f"kernel is {label}-compressed but `{cmd[0]}` is not installed")
            if not out:
                raise SystemExit(f"{label} decompression produced nothing")
            return out, label
    raise SystemExit(f"unrecognised kernel compression, magic {payload[:8].hex()}")


def check_arm64(image):
    """Validate the arm64 Image header (Documentation/arm64/booting.rst)."""
    if image[0x38:0x3C] != b"ARMd":
        raise SystemExit(f"decompressed blob is not an arm64 Image "
                         f"(magic {image[0x38:0x3C]!r}, want b'ARMd')")
    image_size = struct.unpack_from("<Q", image, 0x10)[0]
    # image_size covers text+data+BSS, so it is >= the file we hold.
    if image_size < len(image):
        raise SystemExit(f"arm64 image_size {image_size:#x} < file size {len(image):#x}")
    return image_size


def verify_against_kallsyms(image, kallsyms_path, sample=400):
    """Prove `file offset == addr - _text` instead of assuming it."""
    text = None
    syms = []
    with open(kallsyms_path, errors="replace") as fh:
        for line in fh:
            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                continue
            addr, typ, name = parts[0], parts[1], parts[2].strip()
            if name.endswith("]"):          # module symbol
                continue
            if name == "_text":
                text = int(addr, 16)
            elif typ in "Tt":
                syms.append((name, int(addr, 16)))
    if not text:
        return None, "no _text in kallsyms (kptr_restrict was not lifted)"
    if text == 0:
        return None, "_text is zero (kptr_restrict was not lifted)"

    step = max(1, len(syms) // sample)
    checked = hits = 0
    for name, addr in syms[::step]:
        off = addr - text
        if off < 0 or off + 4 > len(image):
            continue
        checked += 1
        if struct.unpack_from("<I", image, off)[0] in PROLOGUES:
            hits += 1
    if not checked:
        return None, "no text symbol landed inside the Image"
    rate = hits / checked
    return rate, f"{hits}/{checked} sampled text symbols start with a known prologue"


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    src, dst = sys.argv[1], sys.argv[2]
    kallsyms = None
    if "--kallsyms" in sys.argv:
        kallsyms = sys.argv[sys.argv.index("--kallsyms") + 1]

    blob = open(src, "rb").read()
    koff, ksize, hv = parse_header(blob)
    print(f"boot header v{hv}, kernel at {koff:#x}, kernel_size {ksize:#x}")
    if koff + ksize > len(blob):
        raise SystemExit(f"truncated dump: need {koff + ksize:#x} bytes, have {len(blob):#x}")

    image, how = decompress(blob[koff:koff + ksize])
    print(f"kernel compression: {how}")
    image_size = check_arm64(image)
    print(f"arm64 Image ok: {len(image)} bytes on disk, image_size {image_size:#x} (incl. BSS)")

    if kallsyms:
        rate, detail = verify_against_kallsyms(image, kallsyms)
        if rate is None:
            print(f"offset identity UNVERIFIED: {detail}")
        elif rate < 0.80:
            raise SystemExit(f"offset identity FAILED: {detail} ({rate:.0%}) — "
                             f"this Image does not match that kallsyms")
        else:
            print(f"offset identity verified: {detail} ({rate:.0%})")

    open(dst, "wb").write(image)
    print(f"wrote {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
