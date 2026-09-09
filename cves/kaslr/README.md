# cves/kaslr — the write-free text-base leak

Every offset in [`../targets/`](../targets/README.md) is link-time, and the
running image is slid, so an exploit needs the kernel text base before it can use
one. Writing to
[`/sys/kernel/tracing/trace_marker`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/trace/trace.c)
makes the kernel store one of its own code addresses in a ring-buffer record, and
a raw read of that buffer hands the address back unmasked — three tracefs files
and some arithmetic, no bug and no race.

[`slide_tracefs.c`](slide_tracefs.c) is one file, compiled into both kernel
flavours' entry stages
([6.6](../../runner/stages/entry.ghostlock@6.6/stage.toml#L31),
[6.1](../../runner/stages/entry.ghostlock@6.1/stage.toml#L39)).

## Mechanism

`tracing_mark_write` reserves a [`TRACE_PRINT`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/trace/trace.h) record and stores `_THIS_IP_` —
its own code address, `tracing_mark_write+0x164` — into the record's
[`struct print_entry.ip`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/trace/trace_entries.h) field. The formatted view
(`/sys/kernel/tracing/trace`) renders that pointer through `%ps` as a symbol
name, but a raw read of [`/sys/kernel/tracing/per_cpu/cpuN/trace_pipe_raw`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/trace/trace.c) returns
the ring-buffer sub-page verbatim, with the 8-byte pointer still in it.
[`kptr_restrict`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/lib/vsprintf.c) does not apply: it governs `%pK`, and this value never passes
through a `%p` formatter ([`slide_tracefs.c#L11`](slide_tracefs.c#L11)).

The record layout is an 8-byte [`trace_entry`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/trace_events.h) header, then `ip` at +8, then the
marker string at +16, so the leaked pointer is always the 8 bytes immediately
preceding the marker in the raw page — which is how the scanner recovers it,
reading `page + i - 8` at the byte where the marker matches
([`slide_tracefs.c#L87`](slide_tracefs.c#L87)). Subtracting the image offset of
that IP gives the text base, in one line
([`slide_tracefs.c#L92`](slide_tracefs.c#L92)):

```
stext = leaked_ip - SLIDE_TRACE_MARK_IP_OFF
```

The result is exact and single-shot: no bruteforce, no candidate set.

Access is clean under both Android DAC and MAC. tracefs is mounted
`gid=readtracefs` (3012) and shell is in that group;
`per_cpu/cpu*/trace_pipe_raw` carries the same SELinux label
(`debugfs_tracing`) as `trace` and `tracing_on`, which shell already reads and
writes. The leak enables no ftrace event, which is what separates it from other
tracefs approaches — `set_event`, `events/*/enable`, `printk_formats` and
`instances/` are all denied to shell. The payload runs as uid 2000.

## Implementation

[`slide_leak_kernel_base_tracefs()`](slide_tracefs.c#L35), by line:

1. Open `per_cpu/cpu0/trace_pipe_raw` `O_RDONLY|O_NONBLOCK`
   ([`#L39`](slide_tracefs.c#L39)). Raw reads are per-CPU and consuming. cpu0 is
   the right buffer because the caller has already pinned there —
   [`pin_to_core(CORE)`](../cve-2026-43499-ghostlock/main.c#L188) with
   [`CORE 0`](../cve-2026-43499-ghostlock/common.h#L54).
2. Drain that buffer to `EAGAIN` first, so the fresh marker lands on top of a
   busy ring ([`#L49`](slide_tracefs.c#L49)).
3. Read `tracing_on`; if it is `0`, write `1` ([`#L55`](slide_tracefs.c#L55)).
   `tracing_mark_write` returns `-EBADF` when tracing is off, because
   [`ring_buffer_lock_reserve`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/trace/ring_buffer.c) yields NULL, so the marker has to be armed. This is
   best-effort and is the only write outside `trace_marker` itself.
4. Open `trace_marker` `O_WRONLY` and write the 14-byte marker
   [`"P0KASLR64PROBE"`](slide_tracefs.c#L36) ([`#L73`](slide_tracefs.c#L73)).
5. Read fresh pages and `memcmp`-scan for the marker, up to 400 attempts with a
   1 ms sleep on an empty read ([`#L80`](slide_tracefs.c#L80)).
6. Gate the value: `(ip >> 40) == 0xffffff`, a slid kernel-text pointer, and
   `(ip & 0xfff) == (SLIDE_TRACE_MARK_IP_OFF & 0xfff)`, the fixed page offset of
   the marker's own IP ([`#L90`](slide_tracefs.c#L90)). A value that fails the
   gate is warned about and discarded, never used.

On success the base goes into `kernel_slide` with provenance `SLIDE_LEAKED` and
the payload prints ([`#L108`](slide_tracefs.c#L108)):

```
slide-kaslr-tracefs-ok pid=<pid> base=<16 hex> slide=<16 hex> (write-free)
```

which is the line the runner's pass marker matches
([`exploit.sh#L89`](../../runner/lib/exploit.sh#L89), restated as stage data at
[`entry.ghostlock@6.6/stage.toml#L121`](../../runner/stages/entry.ghostlock@6.6/stage.toml#L121)).

## Cost

30–66 ms ([`exploit.sh#L16`](../../runner/lib/exploit.sh#L16),
[`exploit.sh#L1082`](../../runner/lib/exploit.sh#L1082)), with no kernel primitive,
no fork and no reclaimed page: it cannot panic.

The leak is unconditional in both entries — 6.6 at
[`main.c#L197`](../cve-2026-43499-ghostlock/main.c#L197), 6.1 at
[`61/main.c#L281`](../cve-2026-43499-ghostlock/61/main.c#L281) — and if it fails,
the run fails; there is nothing else to try. Two environment variables steer it:
`KASLR_BASE=0x…` supplies the base and skips the leak
([`main.c#L191`](../cve-2026-43499-ghostlock/main.c#L191)), and
`KASLR_LEAK_ONLY=1` returns after the leak instead of continuing into the
exploit ([`main.c#L207`](../cve-2026-43499-ghostlock/main.c#L207)). How the
runner uses the pair is in
[`runner/README.md` §4.1](../../runner/README.md#41-the-root-loop).

## Per-build offsets

`SLIDE_TRACE_MARK_IP_OFF` is the one per-build input, set once in each device's
[target header](../targets/README.md). Every device sharing a GKI build shares
the constant; three values cover the 19 targets:

| `SLIDE_TRACE_MARK_IP_OFF` | KMI | targets |
| --- | --- | --- |
| `0x001f0ac8` | android14-6.1 | akita, bluejay-CP2A, caiman, cheetah, comet, husky, komodo, lynx, oriole, panther, raven, shiba, tegu, tokay (14) |
| `0x001f4c8c` | android15-6.6 | blazer, frankel, mustang, rango (4) |
| `0x001f06fc` | android14-6.1 | bluejay-CP1A (1) |

Panther's is
[`target.h#L134`](../targets/panther-CP2A.260705.006/target.h#L134), with the
derivation in the comment above it
([`target.h#L129`](../targets/panther-CP2A.260705.006/target.h#L129)):
`tracing_mark_write@0x1f0964 + 0x164 = 0x1f0ac8`, harvested from that build's
kallsyms.

The definition and the declaration are both inside
`#ifdef SLIDE_TRACE_MARK_IP_OFF`
([`slide_tracefs.c#L10`](slide_tracefs.c#L10),
[`common.h#L508`](../cve-2026-43499-ghostlock/common.h#L508),
[`61/common.h#L584`](../cve-2026-43499-ghostlock/61/common.h#L584)) while the
call site is not, so a target header that omits the constant does not build.
There is no route to a base without it.

## Deriving the offset for a new build

The offset is the image offset of `tracing_mark_write`'s `_THIS_IP_` — the
`adrp`/`add` pair feeding the `str` into `print_entry.ip`:

```
SLIDE_TRACE_MARK_IP_OFF = (tracing_mark_write + 0x164) - _text
```

The `+0x164` is the part that is not a symbol, and it is the part that moves:
it is `0x15c` on android15-6.6. That is a compiler artifact, not a struct field
or a KMI guarantee, so it cannot be written down once — which is why it was a
hand-disassembly step, and why the three values in the table above had to be
derived one at a time.

It is now a rule. `_THIS_IP_` expands to the address of a label inside the
function, which the compiler materialises as `adrp`/`add`; in
`tracing_mark_write` exactly one such pair computes an address that lands back
inside `tracing_mark_write` itself. "Points at itself" identifies it without
knowing the instruction schedule, and demanding uniqueness means a build that
reshapes the function yields `UNRESOLVED` rather than a wrong base. That is the
`self-addr` rule
([`offset_rules.py#L193`](../../runner/scripts/lib/offset_rules.py#L193)),
written down once as a
[`CODEMAP`](../../runner/scripts/lib/offset-maps.txt#L147) row.

Both terms come out of the build's public `boot.img`, before any device on that
build has been rooted, via
[`tools/pixel-image`](../../tools/pixel-image/README.md): it looks the OTA URL
up, partial-fetches it, unpacks the boot image to a raw arm64 `Image`, and
derives this row along with every other. It reproduces `0x1f0ac8` on panther and
`0x1f4c8c` on blazer, each matching the value harvested from that build's
kallsyms — and because the same row now runs inside
[`harvest-live.sh`](../../runner/scripts/harvest-live.sh), the constant every
root run depends on is checked on every harvest instead of never.

## Checking it on a device

[`kaslr_marker.c`](./kaslr_marker.c) is the same logic as a self-contained shell
binary: it pins to cpu0 ([`#L28`](./kaslr_marker.c#L28)), carries the offset as a
literal ([`#L18`](./kaslr_marker.c#L18)), and prints `uid`, the leaked `ip`, its
low 12 bits and the derived base, warning when the low bits are wrong
([`#L56`](./kaslr_marker.c#L56)). Cross-check its answer against
`su -c 'grep " _text$" /proc/kallsyms'` on a rooted device.

## See also

- [`../targets/README.md`](../targets/README.md) — where `SLIDE_TRACE_MARK_IP_OFF` lives, and the offset-group model.
- [`../README.md`](../README.md) — the exploit tree.
- [`../../tools/pixel-image/README.md`](../../tools/pixel-image/README.md) — partial OTA extraction.
- [`../../runner/README.md`](../../runner/README.md) — the stage/recipe framework and the addressing model.
