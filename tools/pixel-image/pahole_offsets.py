#!/usr/bin/env python3
"""Extract struct field offsets from a vmlinux's DWARF debug info via pahole.

btf_offsets.py reads STRUCTMAP's facts from a kernel's own BTF
(CONFIG_DEBUG_INFO_BTF). A kernel built without that config has no BTF for
its Image or its /sys/kernel/btf/vmlinux to read -- this is the other way to
the same facts, from a vmlinux built from matching source with debug info
instead (any such vmlinux; this tool does not care where it came from, and
records nothing about its path or origin in what it prints). Exposes the
same resolve() as btf_offsets.Btf, so offset_rules.struct_field() and
derive_offsets.py use whichever backend is available without caring which
one answered.

Paths may be nested through named structs and unions (not anonymous ones --
plain `pahole -C` text output does not expose those as separately queryable
types):
  cred.uid          pool_workqueue.pool          rt_mutex_waiter.tree.entry

Usage:
  pahole_offsets.py <vmlinux> <struct>[.field[.field...]] ...
  pahole_offsets.py <vmlinux> --dump <struct>
"""
import re
import shutil
import subprocess
import sys

# "\ttype... name[N];  /*  off  size */" -- pahole -C's one-member-per-line
# text form. Bitfields and anonymous nested struct/union members print
# differently and simply do not match; resolve() then reports the field as
# absent rather than misreading one.
_MEMBER = re.compile(
    r"^\t(?P<type>.+?)\s+\**(?P<name>\w+)(?:\[\d+\])?;\s*"
    r"/\*\s*(?P<off>\d+)\s+(?P<size>\d+)\s*\*/\s*$"
)
_SIZE = re.compile(r"^\s*/\*\s*size:\s*(\d+),")
_NAMED_TYPE = re.compile(r"^(?:const\s+)?(?:struct|union)\s+(\w+)\s*\*?\s*$")


class Pahole:
    def __init__(self, vmlinux):
        if not shutil.which("pahole"):
            sys.exit("[!] pahole not on PATH")
        self.vmlinux = vmlinux
        self._cache = {}

    def _dump(self, struct_name):
        if struct_name in self._cache:
            return self._cache[struct_name]
        r = subprocess.run(["pahole", "-C", struct_name, self.vmlinux],
                            capture_output=True, text=True)
        info = None
        if r.returncode == 0 and r.stdout.strip():
            members, size = [], None
            for line in r.stdout.splitlines():
                m = _MEMBER.match(line)
                if m:
                    members.append((m.group("name"), m.group("type").strip(),
                                     int(m.group("off"))))
                    continue
                m = _SIZE.match(line)
                if m:
                    size = int(m.group(1))
            info = {"members": members, "size": size}
        self._cache[struct_name] = info
        return info

    def resolve(self, spec):
        """'struct.a.b' -> (byte_offset, 0), or raise ValueError.

        Matches btf_offsets.Btf.resolve()'s signature; the second element is
        always 0 -- pahole's text output does not carry bitfield widths the
        way BTF does, and no STRUCTMAP row needs one from this backend.
        """
        parts = spec.split(".")
        sname, fields = parts[0], parts[1:]
        info = self._dump(sname)
        if info is None:
            raise ValueError(f"no debug info for struct {sname}")
        if not fields:
            return None, info["size"]
        off = 0
        cur = info
        for i, f in enumerate(fields):
            hit = next((m for m in cur["members"] if m[0] == f), None)
            if hit is None:
                have = [m[0] for m in cur["members"]][:8]
                raise ValueError(f"no field {f!r} (has: {', '.join(have)}...)")
            _name, type_name, byte_off = hit
            off += byte_off
            if i == len(fields) - 1:
                return off, 0
            m = _NAMED_TYPE.match(type_name)
            if m is None:
                raise ValueError(
                    f"{f!r} ({type_name}) is not a named struct/union "
                    f"pahole -C can be re-queried for")
            cur = self._dump(m.group(1))
            if cur is None:
                raise ValueError(f"no debug info for {m.group(1)!r} ({spec})")
        return off, 0


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    pahole = Pahole(sys.argv[1])
    args = sys.argv[2:]

    if args[0] == "--dump":
        for sname in args[1:]:
            info = pahole._dump(sname)
            if info is None:
                print(f"{sname}: NOT FOUND")
                continue
            print(f"struct {sname} (size {info['size']:#x} / {info['size']})")
            for name, type_name, off in info["members"]:
                print(f"    {off:#07x}  {type_name} {name}")
            print()
        return 0

    status = 0
    for spec in args:
        try:
            off, extra = pahole.resolve(spec)
            print(f"{spec} = {extra if off is None else off:#x}")
        except ValueError as e:
            print(f"{spec}: {e}")
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
