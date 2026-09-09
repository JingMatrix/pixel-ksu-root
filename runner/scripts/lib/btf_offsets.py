#!/usr/bin/env python3
"""Extract exact struct field offsets from a kernel's /sys/kernel/btf/vmlinux.

Symbol addresses rot every build; struct layouts are KMI-stable. BTF measures
the layout from the running kernel, for the exact build in front of you.

Paths may be nested and traverse anonymous structs/unions transparently:
  task_struct.pi_lock          cred.uid          k_itimer.it.head
  signal_struct.posix_cputimers.bases

Usage:
  btf_offsets.py <btf-file> <struct>[.field[.field...]] ...
  btf_offsets.py <btf-file> --dump <struct>      # every member
"""
import struct
import sys

KIND_INT, KIND_PTR, KIND_ARRAY = 1, 2, 3
KIND_STRUCT, KIND_UNION, KIND_ENUM = 4, 5, 6
# modifier kinds whose size_or_type points at the underlying type
KIND_TRANSPARENT = {8, 9, 10, 11, 18}       # typedef, volatile, const, restrict, type_tag
# variable-length payload after each btf_type, by kind
VLEN_STRIDE = {1: None, 3: None, 4: 12, 5: 12, 6: 8, 13: 8, 14: None,
               15: 12, 17: None, 19: 12}
FIXED_TAIL = {1: 4, 3: 12, 14: 4, 17: 4}


class Btf:
    def __init__(self, src):
        # A path, or the blob itself: the same bytes reach us either from
        # /sys/kernel/btf/vmlinux on a rooted device or sliced straight out of
        # a kernel Image (offset_rules.btf_from_image), and those are the same
        # bytes -- verified byte-identical on panther.
        blob = src if isinstance(src, (bytes, bytearray)) else open(src, "rb").read()
        magic, _ver, _flags, hdr_len = struct.unpack_from("<HBBI", blob, 0)
        if magic != 0xEB9F:
            sys.exit(f"not BTF: magic {magic:#x}")
        type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", blob, 8)
        types_base, strs_base = hdr_len + type_off, hdr_len + str_off
        strs = blob[strs_base:strs_base + str_len]

        def name(off):
            if off == 0:
                return ""
            return strs[off:strs.index(b"\0", off)].decode("utf-8", "replace")

        # id 0 is void; real types start at 1
        self.types = [None]
        self.by_name = {}
        off, end = types_base, types_base + type_len
        while off < end:
            name_off, info, size = struct.unpack_from("<III", blob, off)
            vlen, kind, kind_flag = info & 0xFFFF, (info >> 24) & 0x1F, (info >> 31) & 1
            off += 12
            members = None
            if kind in (KIND_STRUCT, KIND_UNION):
                members = []
                for i in range(vlen):
                    m_name, m_type, m_off = struct.unpack_from("<III", blob, off + i * 12)
                    # kind_flag=1 packs bitfield_size in the top 8 bits
                    members.append((name(m_name), m_type,
                                    (m_off & 0xFFFFFF) if kind_flag else m_off,
                                    (m_off >> 24) if kind_flag else 0))
                off += vlen * 12
            else:
                stride = VLEN_STRIDE.get(kind)
                off += FIXED_TAIL.get(kind, 0) if stride is None else vlen * stride
            nm = name(name_off)
            self.types.append({"name": nm, "kind": kind, "size": size,
                               "members": members})
            tid = len(self.types) - 1
            # keep the first *defined* struct/union of a given name; later
            # duplicates are forward declarations or anonymous variants
            if nm and members is not None and nm not in self.by_name:
                self.by_name[nm] = tid

    def strip(self, tid):
        """Follow typedef/const/volatile/restrict to the underlying type."""
        seen = 0
        while tid and self.types[tid]["kind"] in KIND_TRANSPARENT:
            tid = self.types[tid]["size"]      # size_or_type field
            seen += 1
            if seen > 16:
                break
        return tid

    def find_member(self, tid, want):
        """Bit offset of `want` in composite `tid`, descending anonymous members."""
        t = self.types[self.strip(tid)]
        if not t or t["members"] is None:
            return None
        for mname, mtype, bit_off, bf in t["members"]:
            if mname == want:
                return bit_off, bf, mtype
            if mname == "":                     # anonymous struct/union
                inner = self.find_member(mtype, want)
                if inner is not None:
                    return bit_off + inner[0], inner[1], inner[2]
        return None

    def resolve(self, spec):
        """'struct.a.b' -> (byte_offset, bitfield_size) or raise ValueError."""
        parts = spec.split(".")
        sname, fields = parts[0], parts[1:]
        tid = self.by_name.get(sname)
        if tid is None:
            raise ValueError(f"no such struct: {sname}")
        if not fields:
            return None, self.types[tid]["size"]
        bits, bf = 0, 0
        for f in fields:
            hit = self.find_member(tid, f)
            if hit is None:
                have = [m[0] for m in self.types[self.strip(tid)]["members"] or []][:8]
                raise ValueError(f"no field {f!r} (has: {', '.join(have)}...)")
            add, bf, tid = hit
            bits += add
        if bits % 8 and not bf:
            raise ValueError(f"{spec} is not byte-aligned ({bits} bits)")
        return bits // 8, bf


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    btf = Btf(sys.argv[1])
    args = sys.argv[2:]

    if args[0] == "--dump":
        for sname in args[1:]:
            tid = btf.by_name.get(sname)
            if tid is None:
                print(f"{sname}: NOT FOUND")
                continue
            t = btf.types[tid]
            kind = "union" if t["kind"] == KIND_UNION else "struct"
            print(f"{kind} {sname} (size {t['size']:#x} / {t['size']})")
            for mname, _mt, bit_off, bf in t["members"]:
                tag = f"  [bitfield {bf}b]" if bf else ""
                print(f"    {bit_off // 8:#07x}  {mname}{tag}")
            print()
        return

    for spec in args:
        try:
            off, extra = btf.resolve(spec)
        except ValueError as e:
            print(f"{spec:<44} {e}")
            continue
        if off is None:
            print(f"{spec:<44} size={extra:#x}")
        else:
            print(f"{spec:<44} {off:#07x}" + (f"  [bitfield {extra}b]" if extra else ""))


if __name__ == "__main__":
    main()
