# cves/lib/kaslr — the write-free text-base leak

Every offset in [`../../targets/`](../../targets/README.md) is link-time and the running
image is slid, so an exploit needs the kernel text base before it can use one. Writing to
[`trace_marker`](https://docs.kernel.org/trace/ftrace.html) makes the kernel store one of
its own code addresses in a ring-buffer record, and a raw read of that buffer hands the
address back unmasked. Three tracefs files and some arithmetic; no bug, and no race.

`slide_tracefs.c` is one file, compiled into the entry stage of both kernel flavours.

## Mechanism

The write handler behind `trace_marker` reserves a print record and stores `_THIS_IP_` —
its own code address — into the record's `ip` field. The formatted view under
`/sys/kernel/tracing/trace` renders that pointer through a symbol formatter, so it appears
as a name; a raw read of the per-CPU
[`trace_pipe_raw`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/trace/trace.c)
returns the ring-buffer sub-page verbatim, with the pointer still in it.
[`kptr_restrict`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/lib/vsprintf.c)
does not apply, because it governs the pointer-hiding format specifier and this value never
passes through a `%p` formatter at all.

The record layout is a fixed-size trace header, then `ip`, then the marker string, so the
leaked pointer is always the eight bytes immediately preceding the marker in the raw page.
That is how the scanner recovers it: find the marker, step back one pointer width.
Subtracting the image offset of that instruction gives the text base in one line.

```
stext = leaked_ip - SLIDE_TRACE_MARK_IP_OFF
```

The result is exact and single-shot: no brute force, and no candidate set to sift.

Access is clean under both Android's discretionary and mandatory access control. tracefs is
mounted with a group the shell user belongs to, and the raw per-CPU files carry the same
SELinux label as the `trace` and `tracing_on` files the shell already reads and writes.
What separates this from other tracefs approaches is that it enables no ftrace event:
event enabling, the format directories and the tracing instances are all denied to the
shell, and none of them is needed here.

## Implementation

The leak is a short, ordered sequence, and each step earns its place:

1. Open the raw per-CPU buffer non-blocking. Raw reads are per-CPU and consuming, and the
   buffer to read is the one belonging to the processor the caller has already pinned to.
2. Drain that buffer first, so that the fresh marker lands on top of a quiet ring rather
   than somewhere inside a busy one.
3. Read `tracing_on`, and enable it if it is off. The marker write fails outright when
   tracing is disabled, because the ring-buffer reservation returns nothing. This is
   best-effort, and it is the only write anywhere outside `trace_marker` itself.
4. Write the marker string to `trace_marker`.
5. Read fresh pages and scan for the marker, retrying briefly on an empty read.
6. Gate the recovered value before believing it. It must look like a slid kernel-text
   pointer, and its offset within the page must equal the known page offset of the
   marker's own instruction. A value that fails the gate is reported and discarded, never
   used.

On success the base is recorded together with its provenance — leaked, as opposed to
supplied or verified — and the payload prints a line that the runner's pass marker matches.

## Cost

Some tens of milliseconds, with no kernel primitive, no fork and no reclaimed page. It
cannot panic.

The leak is unconditional in both entry stages: if it fails, the run fails, because there
is nothing else to try. Two environment variables steer it. One supplies the base directly
and skips the leak; the other returns immediately after the leak instead of continuing into
the exploit. How the runner uses the pair is
[`runner/README.md` §4.1](../../../runner/README.md#41-the-root-loop).

## The per-build input

`SLIDE_TRACE_MARK_IP_OFF` is the one per-build constant, and it lives in the
[target description](../../targets/README.md) like any other offset. Every device sharing a
kernel image shares the value, so the number of distinct values is the number of images
rather than the number of devices.

Both the definition and the declaration sit inside a guard on that macro, while the call
site does not, so a target description that omits the constant fails to build. There is no
route to a base without it.

## Deriving the offset for a new build

The offset is the image offset of the marker handler's `_THIS_IP_` — the address-forming
instruction pair that feeds the store into the record's `ip` field:

```
SLIDE_TRACE_MARK_IP_OFF = (tracing_mark_write + delta) - _text
```

The delta is the part that is not a symbol, and it is the part that moves: it differs
between kernel flavours. It is a compiler artifact rather than a structure field or an
interface guarantee, so it cannot be written down once, which is why this used to be a
hand-disassembly step performed separately for every image.

It is now a rule. `_THIS_IP_` expands to the address of a label inside the function, which
the compiler materialises as an address-forming pair; within this function exactly one such
pair computes an address that lands back inside the function itself. Pointing at itself
identifies the instruction without knowing the compiler's instruction schedule, and
demanding uniqueness means that a build which reshapes the function yields an unresolved
result rather than a wrong base. That is the `self-addr` rule in
[`offset_rules.py`](../../../runner/scripts/lib/offset_rules.py), written down once as a
row in [`offset-maps.txt`](../../../runner/scripts/lib/offset-maps.txt).

Both terms come out of the build's public boot image, before any device on that build has
been rooted, through [`tools/pixel-image`](../../../tools/pixel-image/README.md): it looks
the OTA up, partial-fetches it, unpacks the boot image to a raw arm64 kernel image, and
derives this row along with every other. The live harvest re-derives the same constant
independently and records the comparison, so the one value every root run depends on is
checked on every harvest rather than never.

## Checking it on a device

`kaslr_marker.c` is the same logic as a self-contained shell binary. It pins itself to the
processor whose buffer it reads, carries the offset as a literal, and prints the leaked
instruction pointer, its page offset and the derived base, warning when the page offset is
not the expected one. Cross-check its answer against the kernel's own symbol table on a
rooted device:

```sh
su -c 'grep " _text$" /proc/kallsyms'
```

## See also

- [`../../targets/README.md`](../../targets/README.md) — where the constant lives, and the offset-group model.
- [`../README.md`](../README.md) — the shared exploitation library.
- [`../../../tools/pixel-image/README.md`](../../../tools/pixel-image/README.md) — partial OTA extraction.
- [`../../../runner/README.md`](../../../runner/README.md) — the stage and recipe framework, and the addressing model.
