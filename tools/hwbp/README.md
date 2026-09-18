# tools/hwbp — a kernel execution counter built from a hardware breakpoint

`hwbp` answers one question about a running stock kernel: *did this exact instruction
execute, and how many times?* It programs a system-wide execute breakpoint into the
processor's debug registers on a single kernel virtual address, runs a workload, and prints
how many times control flow crossed that address. It is a standalone research instrument
and takes no part in the rooting path.

## Why it exists

Exploit work needs a truthful, on-device answer to whether the vulnerable code path runs
under a given harness. The natural instrument is
[ftrace or kprobes](https://docs.kernel.org/trace/kprobes.html), but under the heavy binder
load a race harness generates, the platform's own trace daemon disables kprobes out from
under you: the counter resets and the measurement is silently lost. Silence of that kind is
worse than no measurement, because it is indistinguishable from the path not running.

A hardware execute breakpoint sidesteps the problem entirely. It lives in the processor's
debug registers rather than in the tracing subsystem, so nothing the trace daemon does can
touch it. Where a kprobe can dump arguments and registers, `hwbp` counts one instruction
and nothing else — a tripwire on a precise program counter that the platform cannot switch
off. That is what established, for
[CVE-2026-64468](../../cves/cve-2026-64468-frostbind/README.md), that the vulnerable read
inside
[`binder_free_transaction()`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/android/binder.c)
executes at all, and how often, while tracing was unavailable.

## Mechanism

The whole program is one
[`perf_event_open(2)`](https://man7.org/linux/man-pages/man2/perf_event_open.2.html)
configuration, repeated across every processor.

The event is a breakpoint rather than a software counter: an execute breakpoint one
instruction word long, which fires each time a core fetches and executes the instruction at
that address. It counts kernel execution only; since the address is a kernel virtual
address, excluding user and hypervisor merely keeps the count clean. It is system-wide and
per-processor, opened in the mode that watches all tasks on one core, so a kernel path is
seen wherever it happens to be scheduled — which is why the tool loops over every
configured core and sums the per-core descriptors at the end rather than opening a single
event.

The counters are zeroed and armed together, so that the measured window is exactly the
workload window. The workload is either a child process or a fixed sleep; scoping the count
to a child is the useful mode, because it lets you arm the breakpoint, run one race
attempt, and read the hits attributable to that attempt alone.

If the kernel refuses a breakpoint on the address — a non-executable or non-permitted
virtual address, for instance — no descriptors open, and the tool says so and exits
non-zero rather than printing a false zero.

## Build

A static aarch64 binary built with the [NDK](https://developer.android.com/ndk), so it
needs no on-device toolchain and no shared libraries:

```
aarch64-linux-android<API>-clang -O2 -static -o hwbp tools/hwbp/hwbp.c
```

It depends only on the `perf_event` and `hw_breakpoint` user-space headers, both of which
are in the NDK sysroot.

## Run

Root is required: a system-wide hardware breakpoint on a kernel address is privileged.

```
hwbp <hex_kernel_addr> <seconds> [cmd...]
```

The address is a runtime kernel virtual address, already slid — resolve it the same way an
exploit does, through the write-free leak described in
[cves/lib/kaslr/README.md](../../cves/lib/kaslr/README.md). The seconds argument says how
long to count when no command is given; when a command is present, the count is scoped to
that child's lifetime instead of to the timer. On start the tool reports the armed
breakpoint and how many cores accepted it, and on completion it prints the total.

## See also

- [cves/cve-2026-64468-frostbind/README.md](../../cves/cve-2026-64468-frostbind/README.md) — the bug whose vulnerable read this counter confirmed on-device.
- [tools/pixel-image/README.md](../pixel-image/README.md) — the sibling instrument that produces the per-build offsets you feed to `hwbp`.
- [cves/README.md](../../cves/README.md) — the exploit tree.
