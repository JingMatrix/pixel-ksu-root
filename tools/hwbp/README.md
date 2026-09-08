# tools/hwbp — kernel execution counter via a HW breakpoint

`hwbp` answers one question about a running stock kernel: *did this exact
instruction execute, and how many times?* It sets a system-wide
[`HW_BREAKPOINT_X`](hwbp.c#L33) — an execute breakpoint programmed into the
CPU debug registers — on a single kernel virtual address, runs a workload, and
prints the total number of times control flow crossed that address. It is a
standalone research instrument, not part of the rooting path.

## Why it exists

CVE work needs a truthful, on-device answer to "does the vulnerable code path
actually run under my harness." The natural tool is ftrace/kprobes, but under
the heavy binder load a race harness generates, the platform trace daemon
disables ftrace kprobes out from under you — the counter resets and the
measurement is silently lost.

A hardware execute breakpoint sidesteps that. It lives in the CPU's debug
registers, not in the ftrace subsystem, so nothing the trace daemon does touches
it. Where a kprobe can dump arguments and registers, `hwbp` counts one
instruction and nothing else: a tripwire on a precise PC that the platform
cannot switch off. For
[CVE-2026-64468](../../cves/cve-2026-64468/README.md) it is what showed that
[`binder_send_failed_reply`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/android/binder.c) and its [`binder_free_transaction`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/android/binder.c) read at `+0x1b8`
execute, and how often, while ftrace was unavailable.

## Mechanism

The whole program is one [`perf_event_open`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/events/core.c) configuration repeated across every
CPU:

- The event is a breakpoint, not a software counter:
  [`type = PERF_TYPE_BREAKPOINT`, `bp_type = HW_BREAKPOINT_X`,
  `bp_addr = addr`, `bp_len = HW_BREAKPOINT_LEN_4`](hwbp.c#L32-L33). An
  execute breakpoint of length 4 (one AArch64 instruction word) fires each time
  the core fetches and executes the instruction at `addr`.
- It counts kernel execution only:
  [`exclude_kernel = 0; exclude_hv = 1; exclude_user = 1`](hwbp.c#L35). The
  address is a kernel VA, so user and hypervisor exclusion simply keeps the
  count clean.
- It is system-wide, per-CPU. A breakpoint event is opened with
  [`pid = -1` on each CPU `c`](hwbp.c#L38-L39) via
  [`perf_event_open(attr, -1, cpu, -1, 0)`](hwbp.c#L22-L24). `pid=-1, cpu=c`
  is the "all tasks on this CPU" mode, so the count captures the instruction
  wherever it runs — a kernel path scheduled on any core is seen. The
  per-CPU fds are summed at the end, which is why the tool loops over all
  `_SC_NPROCESSORS_CONF` cores rather than opening a single event.
- The counters are zeroed and armed together
  ([`PERF_EVENT_IOC_RESET` then `PERF_EVENT_IOC_ENABLE`](hwbp.c#L47)), so the
  window measured is exactly the workload window.
- The workload is either a child process or a fixed sleep: with a `[cmd]`
  argument the tool [forks and `execvp`s it, then `waitpid`s](hwbp.c#L50-L51);
  with no command it [`sleep`s for `<seconds>`](hwbp.c#L52). Scoping the count
  to a child process is the useful mode — arm the breakpoint, run one race
  attempt, read the hits attributable to it.
- Finally each fd is disabled and read, the u64 hit counts are summed, and the
  total is printed as [`HITS=<n>`](hwbp.c#L56).

If the kernel refuses a breakpoint on the address (for example a non-executable
or non-permitted VA), no fds open and the tool
[reports that and exits non-zero](hwbp.c#L44) rather than printing a false zero.

## Build

Static aarch64 binary with the NDK, so it needs no on-device toolchain or
shared libraries:

```
aarch64-linux-android<API>-clang -O2 -static -o hwbp tools/hwbp/hwbp.c
```

It depends only on [`<linux/perf_event.h>`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/uapi/linux/perf_event.h) and [`<linux/hw_breakpoint.h>`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/uapi/linux/hw_breakpoint.h)
([included here](hwbp.c#L19-L20)), both in the NDK sysroot.

## Run

Root is required — a system-wide (`pid=-1`) hardware breakpoint on a kernel
address is privileged. The [usage](hwbp.c#L26) is:

```
hwbp <hex_kernel_addr> <seconds> [cmd...]
```

- `<hex_kernel_addr>` — the runtime kernel VA to watch (KASLR-slid; resolve it
  the same way the exploit does — see the write-free leak in
  [cves/kaslr/README.md](../../cves/kaslr/README.md)).
- `<seconds>` — how long to count when no command is given.
- `[cmd...]` — optional; when present the count is scoped to this child's
  lifetime instead of the timer.

On start it prints `armed HW bp @ 0x… on N/M cpus`
([here](hwbp.c#L45)); on completion, `HITS=<total>`.

## See also

- [cves/cve-2026-64468/README.md](../../cves/cve-2026-64468/README.md) — the CVE
  whose vulnerable read this counter confirmed on-device.
- [tools/pixel-image/README.md](../pixel-image/README.md) — the sibling
  instrument that produces the per-build kernel offsets you feed to `hwbp`.
- [cves/README.md](../../cves/README.md) — the exploit tree.
