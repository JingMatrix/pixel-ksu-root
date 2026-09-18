# tools/vehicle-scan — which reclaim vehicle a build can use

GhostLock's reclaim step needs a syscall whose own on-stack buffer overlaps the
freed `rt_mutex_waiter` with the whole forged waiter inside it. Whether any
syscall does is a per-build fact of two functions' frame sizes, not a property
of the device model. This tool measures it, in two modes:

- *scan* (default) judges the vehicles we already know;
- *discovery* (`--discover`) sweeps the call graph for ones we do not.

```
vehicle-scan.py --image data/live/<codename>-<build>/Image
vehicle-scan.py --image <Image> --kallsyms <kallsyms.txt>
vehicle-scan.py --image <Image> --discover [--all-syscalls] [--near 16]
```

With no `--kallsyms`, the symbol table is recovered from the stripped Image with
`kallsyms-finder` (`pip install vmlinux-to-elf`), so a public boot image is
enough — no device.

## The window

A single-copy vehicle survives `rb_erase` and bridges to the built page's
`fake_w0` iff its buffer holds the four fields the walk needs: the two `rb_node`
children (`waiter+0x08`/`+0x10`), `task` (`+0x30`) and `lock` (`+0x38`). With a
buffer of `B` bytes:

- *upper bound* `WAITER_OFF <= B - 0x40` — `lock` (the deepest field) plus its
  8 bytes must fit; the *same for both geometries*.
- *lower bound* `WAITER_OFF >= -8` for a *narrow* vehicle (writes `task`+`lock`
  only, children zeroed by the copy's `memset`, `parent_color` left to the
  frame), or `>= 0` for a *full* one (also writes `tree_parent = fake_w0`).

So the window is `[-8, B-0x40]` (narrow) or `[0, B-0x40]` (full); its width is
set by `B`. A bigger fixed struct is a wider window — `sigreturn`'s 512-byte
`user_fpsimd_state` is the widest at `[0, 448]`. `B` cannot be enlarged by the
attacker: the socket handlers guard `optlen` against the exact struct size
before the stack copy (`cmp optlen, #0x108; b.ne error`), and every
attacker-length copy goes to `kmalloc`/`memdup_sockptr` (heap), never the stack.

## The default scan

`USABLE` means the vehicle is geometrically placeable — it survives the dequeue
and its bridge fields land in the buffer. That is necessary, not always
sufficient: a placeable vehicle can still fail later in the chain walk (e.g.
`process-vm` on android14-6.1 lands `+24` USABLE and survives `rb_erase`, but
hits a second-hop `BUG_ON` — see `fops_process_vm.c`). `out (too positive)` and
`out (too negative)` say which bound the offset missed. The candidate set and
its per-vehicle buffer sizes and geometries live in
`offset_rules.scan_reclaim_vehicles()`; `tcp-zc` and `pselect` are not scanned
(`tcp-zc`'s offset is a fixed `-8` its getsockopt frame is chosen to hold, and
`pselect` places by fd-set word index, not a byte buffer).

## Discovery (`--discover`)

`offset_rules.discover_vehicles()` walks the static call graph from each syscall
entry, sums frames the way the committed chain rules do, and at every function
records each *fixed-size copy into a stack local* — a candidate reclaim buffer.
For each it computes the `WAITER_OFF` that buffer would land at and whether it
falls in a usable window, so a new build or a new family can be swept without
naming the chain by hand.

Indirect dispatches the static graph cannot follow — `sk_prot->setsockopt` and
friends — are seeded in `_DISCOVER_SEED_EDGES`, which is where the family
combinations live: one `setsockopt` entry reaches every protocol's own handler,
so both the IPv4 (`do_ip_setsockopt`) and IPv6 (`do_ipv6_setsockopt`) sides, and
the per-protocol frame in between, are walked and compared. `--all-syscalls`
walks from every `__arm64_sys_*` entry rather than the curated family set (much
slower). `--near N` also lists copies within `N` bytes of a window.

Discovery reports *candidates for human confirmation, not proven vehicles*:

- the offset is the *shortest* call path's, usually but not always the real one;
- it only catches copies whose size is a compile-time constant (an immediate, or
  a `memset(&buf, 0, imm)` before the copy) — a dynamic-length copy is usually a
  heap buffer, and a copy whose size it cannot pin is skipped;
- an in-window copy still has to *fail cleanly after the copy* and *survive the
  rest of the pi-chain walk*.

So a promising row is a lead to confirm with an `offset_rules` chain rule (the
same `chain_slot_delta` / `_mcast_delta` shape the committed vehicles use), not
a finished vehicle.
