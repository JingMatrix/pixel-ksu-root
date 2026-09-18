#!/usr/bin/env python3
# Partial extraction of boot.img from a remote Android OTA .zip using HTTP Range.
# Downloads only: zip central dir tail, payload.bin header+manifest, and the
# 'boot' partition's data operations — tens of MB, not the whole multi-GB OTA.
#
#   partial_boot.py <ota_url> <out_boot_img>
import sys, struct, io, bz2, lzma, urllib.request
from payload_dumper import update_metadata_pb2 as pb

URL, OUT = sys.argv[1], sys.argv[2]

def rng(a, b):  # inclusive byte range GET
    req = urllib.request.Request(URL, headers={"Range": f"bytes={a}-{b}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()

def size():
    req = urllib.request.Request(URL, method="HEAD")
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(r.headers["Content-Length"])

TOTAL = size()
print(f"[i] OTA size {TOTAL} bytes")

# --- 1. find payload.bin in the zip central directory ---
tail = rng(TOTAL - 65600, TOTAL - 1)
eocd = tail.rfind(b"PK\x05\x06")
assert eocd >= 0, "no EOCD"
cd_size, cd_off = struct.unpack("<II", tail[eocd+12:eocd+20])
# ZIP64?
z64 = tail.rfind(b"PK\x06\x06")
if cd_off == 0xffffffff and z64 >= 0:
    cd_off = struct.unpack("<Q", tail[z64+48:z64+56])[0]
    cd_size = struct.unpack("<Q", tail[z64+40:z64+48])[0]
cd = rng(cd_off, cd_off + cd_size - 1)
i = 0; payload = None
while i < len(cd) and cd[i:i+4] == b"PK\x01\x02":
    method, = struct.unpack("<H", cd[i+10:i+12])
    csize, = struct.unpack("<I", cd[i+20:i+24])
    nlen, elen, clen = struct.unpack("<HHH", cd[i+28:i+34])
    lho, = struct.unpack("<I", cd[i+42:i+46])
    name = cd[i+46:i+46+nlen]
    if name == b"payload.bin":
        payload = (method, csize, lho); break
    i += 46 + nlen + elen + clen
assert payload, "payload.bin not in central dir"
method, csize, lho = payload
assert method == 0, f"payload.bin not stored (method={method})"
# local header -> data start
lh = rng(lho, lho + 30 - 1)
lnlen, lelen = struct.unpack("<HH", lh[26:30])
pdata = lho + 30 + lnlen + lelen          # absolute offset of payload.bin bytes 0
print(f"[i] payload.bin @ zip offset {pdata}, size {csize}")

# --- 2. payload.bin header + manifest ---
hdr = rng(pdata, pdata + 4096 - 1)
assert hdr[:4] == b"CrAU", "bad payload magic"
ver, = struct.unpack(">Q", hdr[4:12])
manifest_size, = struct.unpack(">Q", hdr[12:20])
msig = struct.unpack(">I", hdr[20:24])[0] if ver >= 2 else 0
hlen = 24 if ver >= 2 else 20
man = rng(pdata + hlen, pdata + hlen + manifest_size - 1)
manifest = pb.DeltaArchiveManifest(); manifest.ParseFromString(man)
data0 = pdata + hlen + manifest_size + msig    # abs offset of DATA section
bs = manifest.block_size
print(f"[i] payload v{ver}, manifest {manifest_size}B, block_size {bs}, data@ {data0}")

# --- 3. reconstruct boot from its ops (full-OTA: REPLACE/_BZ/_XZ/ZERO) ---
boot = next((p for p in manifest.partitions if p.partition_name == "boot"), None)
assert boot, "no boot partition"
out = bytearray()
for op in boot.operations:
    dst = op.dst_extents[0].start_block * bs if op.dst_extents else len(out)
    if len(out) < dst: out += b"\x00" * (dst - len(out))
    if op.type == pb.InstallOperation.ZERO:
        for e in op.dst_extents: out += b"\x00" * (e.num_blocks * bs)
        continue
    blob = rng(data0 + op.data_offset, data0 + op.data_offset + op.data_length - 1)
    if op.type == pb.InstallOperation.REPLACE:      data = blob
    elif op.type == pb.InstallOperation.REPLACE_BZ: data = bz2.decompress(blob)
    elif op.type == pb.InstallOperation.REPLACE_XZ: data = lzma.decompress(blob)
    else: raise SystemExit(f"unhandled op type {op.type} (not a full OTA?)")
    out += data
open(OUT, "wb").write(out)
print(f"[+] wrote {OUT}: {len(out)} bytes (fetched only header+manifest+boot ops)")
