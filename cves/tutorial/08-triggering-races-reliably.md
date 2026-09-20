# Triggering Races Reliably

A memory-safety bug reached through a single syscall is a function of its input. A race is a
function of a schedule instead: the input may be fixed and correct, and what decides the outcome
is the relative ordering of two instruction streams on two processors — an ordering chosen by the
scheduler, the interrupt controller, the cache hierarchy and whatever else the device happened to
be doing. Exploiting one means taking as much of that choice away from the machine as you can,
and then measuring what is left.

## The shape of a check-then-use bug

The recurring pattern is that a kernel path establishes a fact about some state, releases (or
never took) the synchronization that would keep the fact true, and then acts on it. Between the
two points an attacker with a second thread can invalidate the fact. Three variants cover most
of what turns up in practice.

1. Double fetch across the user/kernel boundary. The kernel copies a length or a type tag from
   userspace, validates it, then copies the same field again to use it. Pengfei Wang and
   co-authors surveyed this systematically in
   [How Double-Fetch Situations turn into Double-Fetch Vulnerabilities](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/wang-pengfei)
   (USENIX Security 2017), finding 90 double-fetch sites in the Linux kernel, 57 of them in
   drivers, and six previously unknown bugs, using a Coccinelle pattern match rather than
   dynamic analysis.
2. Identity checks over a reusable namespace. A privileged daemon receives an IPC call, learns
   the caller's PID, and asks the kernel a second question about that PID. Jann Horn's
   [Exploiting race conditions on (ancient) Linux](https://static.sched.com/hosted_files/lsseu2019/04/LSSEU2019%20-%20Exploiting%20race%20conditions%20on%20Linux.pdf)
   (Linux Security Summit EU 2019) describes this in Android's `hwservicemanager`, which called
   `getpidcon()` on the caller PID and ran an ACL check against the result. The caller exits, a
   privileged thread reuses the PID, and the check reads the wrong process's SELinux context.
3. Lifetime races. One path decides an object is alive and takes a pointer to it; another path
   runs the object's teardown. This is the family that produces use-after-free, and it is where
   most modern Android kernel races sit.

Variant 3 carries a consequence that is easy to miss when scoring runs. The instant the race is
won and the instant the memory becomes reclaimable are different instants, and the gap between
them is set by the free path's deferral mechanism, not by anything the attacker did. On Android
this is not a footnote: `struct file` is freed through `call_rcu()`, and the GKI defconfig sets
`CONFIG_RCU_NOCB_CPU=y` and `CONFIG_RCU_LAZY=y`, so the callback that actually frees the object
runs later, in a kthread, on a CPU you did not choose. A correctly won race can therefore show
zero reclaim hits — the spray arrived while the object was still queued behind a grace period.
[06-cross-cache-attacks.md](06-cross-cache-attacks.md), under "RCU-deferred frees, and why they
move the page to another CPU", works this out for the Android target including how to find the
callback CPU with a kprobe, since the `rcu:*` tracepoints are compiled out. The one check that
belongs here rather than there is whether the deferral on this boot is the lazy kind, because
that changes what your outcome vocabulary should be willing to call a miss:

```
cat /proc/cmdline | tr ' ' '\n' | grep -E 'rcu_nocbs|rcutree'
zcat /proc/config.gz | grep RCU_LAZY
```

Dirty COW (CVE-2016-5195) is the canonical worked example. The
[vulnerability details](https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails)
describe the mechanism: `__get_user_pages()` takes a write fault on a private read-only mapping,
the copy-on-write attempt does not produce a writable PTE, and the retry loop drops `FOLL_WRITE`
so the second attempt is treated as a read fault. A second thread calling
`madvise(MADV_DONTNEED)` on the same range in the intervening window tears down the PTE, so the
read-fault retry pulls the page straight out of the page cache — and the pending write, issued
through `/proc/self/mem` or `ptrace(PTRACE_POKEDATA)`, lands in the shared page rather than a
private copy. Linus Torvalds' fix,
[mm: remove gup_flags FOLL_WRITE games from __get_user_pages()](https://github.com/torvalds/linux/commit/19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619),
stops mutating `FOLL_WRITE` and introduces an internal `FOLL_COW` flag validated against the PTE
dirty bit. The commit message records the part that generalizes: the bug was ancient and
considered theoretical, and became practical only because the VM got more scalable. Race windows
widen on their own as kernels acquire finer locking. Solar Designer's
[oss-security announcement](https://seclists.org/oss-sec/2016/q4/204) is the disclosure, carrying
the Red Hat description and the reference set assembled on the day; a
[follow-up in the same thread](https://seclists.org/oss-sec/2016/q4/325) argues the separate
question of whether `/proc/self/mem` should be writable at all and whether Yama could gate it.

### Probing for the second fetch

To find the check/use pair on a kernel you cannot rebuild, the instrument is a pair of probes on
the function itself. Two rules apply to every recipe below and are not optional. Every probe is
filtered to one process where a filter is possible, because an unfiltered probe on a busy
function fills the buffer with unrelated hits and the one that matters is lost. And every probe
is removed and tracing restored on the way out, because a probe left enabled changes the timing
of every later step on that boot. A third detail is specific to fetch expressions: a fetched
pointer renders masked unless `kptr_restrict` is relaxed, so a recipe that skips it collects
zeros.

```
T=/sys/kernel/tracing
echo 0 > /proc/sys/kernel/kptr_restrict          # else fetched pointers print as 0
echo 'p:chk some_function len=+0x18(%x0)'  >> $T/kprobe_events
echo 'r:use some_function'                 >> $T/kprobe_events
echo "common_pid == $PID" > $T/events/kprobes/chk/filter
echo "common_pid == $PID" > $T/events/kprobes/use/filter
echo 1 > $T/events/kprobes/chk/enable; echo 1 > $T/events/kprobes/use/enable
echo 1 > $T/tracing_on; cat $T/trace
# teardown, on every exit path including the error ones
echo 0 > $T/events/kprobes/chk/enable; echo 0 > $T/events/kprobes/use/enable
echo > $T/kprobe_events; echo 1 > /proc/sys/kernel/kptr_restrict
```

A probe prints the contents of the memory its expression names at the instant the probe fires.
For an entry probe that is *before* the function's own load, not the value the load returned —
the two differ exactly when a second thread mutates the field in between, which is the thing
being hunted. The `r:` return probe marks where the call finished.

Detecting a double fetch therefore means probing the two load instructions, and that means
reading the disassembly. `%x0` holds the first argument only at function entry; the
[kprobetrace documentation](https://www.kernel.org/doc/html/latest/trace/kprobetrace.html) makes
the same restriction explicit for `$argN` ("only for the probe on function entry"), and the
compiler will have reused `x0` long before any interesting mid-function offset. A probe written
against `%x0` at `some_function+0x40` prints an unrelated dereference, and the reader concludes
"no double fetch" from a broken measurement. The procedure that works:

```
gdb -batch -ex 'disassemble some_function' vmlinux      # or
objdump -d --start-address=0xffffffc008abc000 --stop-address=0xffffffc008abc200 vmlinux
```

Find the two `ldr` instructions that load the field, note the base register each one uses at that
PC, and write the fetch expression against *that* register at *that* offset — `+0x18(%x19)` at
`some_function+0x3c`, not `+0x18(%x0)` at a guessed offset. Three things reject a mid-function
probe, all of them as `EINVAL` on the write to `kprobe_events`, which is the signal to move it:
arm64 instructions are four bytes and `arch_prepare_kprobe()` rejects any address not 4-byte
aligned; an address covered by an exception-table entry is rejected; and an instruction the arm64
kprobe decoder cannot single-step or simulate is rejected. On top of that the kernel maintains a
blacklist of functions where a probe would recurse, listed at
`/sys/kernel/debug/kprobes/blacklist` and described in the
[kprobes documentation](https://docs.kernel.org/trace/kprobes.html). Note also that arm64 in 6.1
does not select `HAVE_KPROBES_ON_FTRACE`, so there is no cheap ftrace-based fast path for entry
probes either: every kprobe here is a real `BRK` software breakpoint, and a probe armed during a
timing measurement is part of the timing.

`CONFIG_KPROBE_EVENTS` must be set, which it is on Android GKI, and arming a probe needs root
plus an SELinux domain permitted to write `kprobe_events`; plain `adb shell` at uid 2000 cannot.

### Getting the offset right

Writing `+0x18(%x0)` requires knowing that the field sits 0x18 bytes into the struct the first
argument points at. Do not copy that number from anywhere. Derive it from the kernel *in front
of you*:

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h   # then grep the struct
pahole -C binder_transaction vmlinux                                 # prints /* offset size */
```

`pahole` annotates every member with its byte offset and size, including holes, which is exactly
what a probe fetch expression needs. `/sys/kernel/btf/vmlinux` exists on stock Pixel GKI builds,
which set `CONFIG_DEBUG_INFO_BTF=y` in the
[GKI defconfig](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/configs/gki_defconfig).
The file is mode 0444, so DAC is not what gates it; on Android the SELinux label is, which is the
distinction [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) insists on.
Check it directly rather than assuming a privilege level:

```
ls -Z /sys/kernel/btf/vmlinux                              # the label that actually decides
sesearch --allow -s shell -t sysfs -c file ./policy        # against a pulled /sys/fs/selinux/policy
dmesg | grep avc                                           # a refusal will say so here
```

The offline fallback is to extract the kernel from the factory boot image and run `pahole` on
that, or, if the image is stripped and carries no BTF, recover an ELF with `vmlinux-to-elf` and
read offsets out of the disassembly.
[04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) and
[07-read-write-primitives.md](07-read-write-primitives.md) go further into layout recovery.

## Measuring the window before trying to hit it

A window you have not measured is a window you cannot tune. The cheapest measurement is two
kprobes and a timestamp difference, with one detail that is easy to get wrong: ftrace's default
`trace_clock` is `local`, a per-CPU counter not comparable across processors. An interval whose
two ends run on different CPUs — the normal case for a race — must use the global clock.

```
T=/sys/kernel/tracing
echo global > $T/trace_clock
echo 0 > /proc/sys/kernel/kptr_restrict
echo 'p:open  binder_transaction  t=%x0'            >> $T/kprobe_events
echo 'r:close binder_transaction'                   >> $T/kprobe_events
echo "common_pid == $PID" > $T/events/kprobes/open/filter
echo "common_pid == $PID" > $T/events/kprobes/close/filter
echo 1 > $T/events/kprobes/open/enable; echo 1 > $T/events/kprobes/close/enable
echo 1 > $T/tracing_on
# ... run the trigger ...
echo 0 > $T/events/kprobes/open/enable; echo 0 > $T/events/kprobes/close/enable
echo > $T/kprobe_events; echo 1 > /proc/sys/kernel/kptr_restrict; echo local > $T/trace_clock
```

`binder_transaction` is the busiest function on a running Android device — every app, every
`system_server` call and every HAL round trip passes through it — so the filter is what makes
this a measurement rather than a firehose. Pair each `close` with the `open` carrying the same
tid, taken from the `task-<tid>` field of the ftrace record header, not with the physically
preceding line. Unfiltered, the preceding `open` usually belongs to another process, and the
failure is recognizable: intervals that are implausibly short, or negative, because the two ends
came from different tasks. `cves/lib/tools/kprobe.sh` already encodes the filter, the
`kptr_restrict` relaxation and the teardown; use it rather than retyping them.

For a histogram without post-processing, bpftrace does it in one line, and is immune to the
pairing bug precisely because it keys the start timestamp on `@t[tid]`:

```
bpftrace -e 'kprobe:binder_transaction { @t[tid] = nsecs }
             kretprobe:binder_transaction /@t[tid]/ { @us[cpu] = hist((nsecs - @t[tid])/1000); delete(@t[tid]) }'
```

`hist()` prints a log2 bucket histogram on exit, keyed here by CPU, which matters on a
heterogeneous device for the reason given under scheduling below. The conclusion to draw is
about the *tail*, not the mean: a reclaim or a second thread needs the rare long execution.
The probe-free alternative elsewhere is `function_graph`
(`echo function_graph > $T/current_tracer`, `echo binder_transaction > $T/set_graph_function`),
which prints a duration column per call; the
[ftrace documentation](https://www.kernel.org/doc/html/latest/trace/ftrace.html) covers it
alongside the latency tracers (`irqsoff`, `preemptoff`, `wakeup`) and `tracing_max_latency`. It is
not available on this target. `function_graph` is layered on the ftrace function tracer, and
panther's config carries `# CONFIG_FUNCTION_TRACER is not set` — the same option that removes
`available_filter_functions`, as
[02-reachability-and-attack-surface.md](02-reachability-and-attack-surface.md) records — so the
tracer, its filter files and everything built on it are absent from the build rather than merely
gated by policy. Read `cat $T/available_tracers` before planning around any of them; on a kernel
without the function tracer the kprobe pair above and the bpftrace one-liner are the whole toolkit
for this measurement.

### From a window to a hit rate

A histogram is only actionable once it is connected to an expected number of attempts. The model
is crude and sufficient. If the victim path holds the exploitable state for a duration `W`, and
the attacker's invalidation arrives at a time roughly uniform over a retry period `T`, then each
attempt succeeds with probability `p ≈ W/T`, and `N` independent attempts win with probability
`1 - (1-p)^N`.

Carry one set of real numbers through. Say the 99th percentile of the histogram above is
`W = 3 µs`, and the attempt loop — trigger, invalidate, check, reset — costs `T = 300 µs`. Then
`p ≈ 1%`, even odds need `ln(0.5)/ln(0.99) ≈ 69` attempts, and 95% confidence of at least one win
needs `ln(0.05)/ln(0.99) ≈ 298`. At a hundred attempts a second that is a three-second campaign,
and no widening technique is worth the day. Shift one number and the picture inverts: if `W` is
200 ns and `T` is unchanged, `p ≈ 0.07%`, even odds need about a thousand attempts, and if each
loss costs a panic and a reboot, the same campaign is a week.

Each widening technique is then a claim about `W` in that arithmetic. A deliberate major fault
in the window takes `W` to hundreds of milliseconds. A nested synchronous transaction that never
replies takes `W` to seconds, which drives `p` to essentially 1 — and the useful consequence is
that the failures that remain are no longer timing failures at all. They are reclaim failures,
and they belong to [05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md) and
[06-cross-cache-attacks.md](06-cross-cache-attacks.md), not to this section. Knowing which of
the two kinds of failure you are looking at is most of what the arithmetic buys.

The threshold the histogram is read against is not a constant, and treating it as one is
the common mistake. What `W` has to exceed is the latency of the attacker's own free-plus-reclaim
sequence — the interval from the second thread issuing its invalidation to the reclaim landing —
which is a measured quantity on this device, not a remembered number of microseconds. Measure it
the same way, by bracketing that thread's own path with `CLOCK_MONOTONIC` timestamps or its own
probe pair. Only then does the victim-side histogram read as pass or fail,
because the comparison is between two measured distributions rather than between a distribution
and a remembered rule of thumb.

Every one of these instruments perturbs what it measures. A kprobe is a breakpoint plus a buffer
write on the path you are timing, so a window measured with probes armed is an *upper bound* on
the real one — the right frame for "does this path run at all" and the wrong frame for "how
often would I win", which has to be measured without probes, by outcome. Where you cannot arm
probes at all, wall-clock bracketing with `clock_gettime(CLOCK_MONOTONIC)` either side of the
syscall pair still bounds the window from outside.

## Widening the window

Six levers follow, of two kinds. A deliberate fault taken inside the critical section, a
saturated consumer, a nested call that never returns, and an interrupt raised on the processor
running the victim all lengthen the interval over which the vulnerable state is held; a
rendezvous with a calibrated delay, and a choice of affinity and scheduling class, decide instead
when and on which processor the second thread arrives within it. Both kinds move the same
arithmetic: the first raises `W`, and the second narrows the spread of arrival times that `T`
stands for.

### Stalling the use side on a fault

If the vulnerable path touches user memory while holding the state you want to invalidate, you
can stop it there. `userfaultfd` and FUSE both let a userspace process handle a page fault
synchronously, so a `copy_to_user()` or `copy_from_user()` inside the critical section blocks
for as long as you like. Jann Horn's LSS talk uses FUSE this way against a `struct file`
refcount overdecrement: start a `writev()` whose `iovec` array lives in a FUSE mapping, let
`import_iovec()` stall on the fault after the write-mode check has already passed, free the
file underneath it, reallocate, then resolve the fault.

What upstream did to `userfaultfd` is narrower than "removed it", and the difference is the whole
technique. Linux 5.2 added the `vm.unprivileged_userfaultfd` sysctl
([userfaultfd/sysctl: add vm.unprivileged_userfaultfd](https://github.com/torvalds/linux/commit/cefdca0a86be517bc390fc4541e3674b8e7803b0)),
under which 0 meant `CAP_SYS_PTRACE` or nothing. Linux 5.11 then loosened that into something
more precise
([userfaultfd: add user-mode only option to unprivileged_userfaultfd sysctl knob](https://github.com/torvalds/linux/commit/d0d4730ac2e404a5b0da9a87ef38c73e51cb1664),
described in LWN's
[Control over userfaultfd kernel-fault handling](https://lwn.net/Articles/835373/)): with the
sysctl at 0, an unprivileged caller must pass `UFFD_USER_MODE_ONLY`, and the call then succeeds.
User-mode faults remain interceptable — which is why Android can ship the sysctl at 0 and ART's
userfaultfd GC still works in every app. The single fault class that is removed is the kernel-mode
fault taken inside `copy_to_user()`/`copy_from_user()`, which is precisely the one this technique
stalls on.

Reading the sysctl alone does not tell you what your domain gets, because the answer also depends
on your capabilities. A ten-line probe distinguishes the three outcomes:

```c
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
	int a = syscall(__NR_userfaultfd, O_CLOEXEC);
	int ae = errno;
	int b = syscall(__NR_userfaultfd, O_CLOEXEC | UFFD_USER_MODE_ONLY);
	printf("plain=%d(%d) user_mode_only=%d(%d)\n", a, ae, b, b < 0 ? errno : 0);
	return 0;
}
```

Two file descriptors means unrestricted, and kernel faults are yours. `EPERM` then a descriptor
means user-mode only: `userfaultfd` is available but useless for stalling a kernel copy. Two
`EPERM`s means closed outright. Read `cat /proc/sys/vm/unprivileged_userfaultfd` alongside it for
the configured value, but treat the probe's answer as the operative one.

FUSE is the usual substitute, and its availability is a policy question rather than a yes/no
fact. Check it the same way:

```
ls -Z /dev/fuse
sesearch --allow -s untrusted_app -t fuse_device -c chr_file ./policy
sesearch --allow -s shell         -t fuse_device -c chr_file ./policy
```

against a policy pulled from `/sys/fs/selinux/policy`. An app does not need to mount anything:
`StorageManager.openProxyFileDescriptor()` hands it a FUSE-backed descriptor whose reads are
serviced by the app's own callback, with the mount performed by the system on its behalf
([StorageManager.java](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/os/storage/StorageManager.java)).
`adb shell` has no such route. [05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md)
covers the other use of the same stall — holding a `setxattr` allocation alive mid-copy — which is
a spray concern rather than a pacing one.

The fallback where both are closed is ordinary disk I/O. Map a file whose pages are not in the
page cache, arrange for the kernel to touch that mapping inside the critical section, and the
copy enters the block layer and sleeps. Horn's talk measures over one second of delay per major
fault under an adversarial scheduling setup, and more than 21 seconds across the 21 pages of a
`getdents()` buffer. Whether a fault actually went to disk is checkable without any privilege:
`getrusage(RUSAGE_SELF).ru_majflt`, or field 12 of `/proc/self/stat`, counts major faults. If
the counter does not move, your pages were still cached and the delay you thought you bought did
not happen.

### Saturating the consumer

When the "use" half is performed by a shared worker rather than a thread you control, you cannot
stall it directly, but you can make it late. A binder server with every looper thread already
blocked in a handler queues an incoming transaction on `binder_proc->todo` instead of dispatching
it, stretching the gap between "sent" and "delivered" from microseconds to however long you keep
the pool busy.

"Every looper thread" is a number, and you need it before saturation is a goal you can aim at,
because binder does not simply queue when threads are busy — it asks the process to spawn another
looper. When a thread returns from the read loop with no other spawn outstanding and no thread
waiting, the driver increments `proc->requested_threads` and returns `BR_SPAWN_LOOPER`, but only
while `proc->requested_threads_started < proc->max_threads`. `max_threads` comes from the
`BINDER_SET_MAX_THREADS` ioctl, and libbinder's `ProcessState` sets it to
`DEFAULT_MAX_BINDER_THREADS`, which is 15
([ProcessState.cpp](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/main/libs/binder/ProcessState.cpp)).
Fifteen spawned loopers plus the main thread is the ceiling for an ordinary app process, so
"saturated" means roughly sixteen concurrent calls held in handlers, not two.

The instrument that confirms it is binder's own statistics. Where debugfs is mounted these live
under `/sys/kernel/debug/binder/`; on production Android, where it is not, binderfs exposes the
same files under `/dev/binderfs/binder_logs/`. Two of them answer different halves of the
question. The per-process state file shows the threads and their transactions:

```
# cat /dev/binderfs/binder_logs/proc/4271
binder proc state:
proc 4271
context binder
  thread 4271: l 02 need_return 0 tr 0
  thread 4289: l 01 need_return 0 tr 0
    outgoing transaction 918273: 0000000000000000 from 4271:4289 to 1622:1701 code 1 flags 10 pri 0:120 r1 elapsed 8412ms
    incoming transaction 918270: 0000000000000000 from 5103:5103 to 4271:4289 code 3 flags 10 pri 0:120 r1 elapsed 8590ms
  ...
  pending transaction 918301: 0000000000000000 from 5103:5140 to 4271:0 code 3 flags 10 pri 0:120 r1 elapsed 120ms
```

The `l` word is the looper state bitmask, printed as two hex digits: `0x01` registered, `0x02`
entered, `0x04` exited, `0x08` invalid, `0x10` waiting, `0x20` in poll. A spawned looper idle in
the read loop reads `l 11` — registered plus waiting; the same thread inside a handler reads
`l 01`, because the waiting bit is what it just cleared. The absence of `0x10` across every
thread is the per-thread form of saturation. The transaction lines are the direct view of a parked
nested chain: a thread with both an `incoming transaction` and an `outgoing transaction` is one
whose handler issued a call of its own and is blocked in it, which is exactly the `from_parent`
chain described below, visible from userspace. `pending transaction` under the proc rather than
under a thread is work on `binder_proc->todo` that no looper has taken — the saturation you were
after. The `%pK` pointer column renders as zeros unless `kptr_restrict` is relaxed.

The counters come from the stats file instead, since `print_binder_proc_stats()` is what emits
them:

```
# cat /dev/binderfs/binder_logs/stats | sed -n '/^proc 4271$/,/^proc /p'
proc 4271
context binder
  threads: 16
  requested threads: 0+15/15
  ready threads 0
  free async space 519984
```

`requested threads: 0+15/15` is "none outstanding, fifteen started, cap fifteen", and
`ready threads 0` is "none waiting in the read loop". Those two lines together are the
definition of saturated. Access to both files is root-gated; `dumpsys` gives an unprivileged
shell a much coarser view.

Oneway transactions are a second, separate lever. They do not contend for the thread pool at all:
the driver queues them on `binder_node->async_todo` and releases one at a time as each completes,
so a node with an outstanding async transaction serializes every subsequent oneway call to it
regardless of how many loopers are idle. Filling `free async space` is the corresponding
saturation, and it shows up in the same stats line.

The saturating calls must originate *outside* the target's process. `ContentResolver` resolves a
same-process provider through `ActivityThread`'s `mLocalProviders` map, so `acquireProvider()`
returns the local `ContentProvider` instance and the call is a direct Java invocation that never
reaches `ContentProvider.Transport` or `/dev/binder`
([ActivityThread.java](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/app/ActivityThread.java)).
A self-call occupies nothing.

### Nesting synchronous IPC

A single synchronous transaction's critical section is as long as the server takes to answer —
not a quantity you control. A nested one is. Binder tracks in-flight synchronous calls on two
transaction stacks: the Android Offensive Security post
[Binder Internals](https://androidoffsec.withgoogle.com/posts/binder-internals/) describes how a
sender's new transaction takes `from_parent` pointing at the current top of its stack, a
receiver's takes `to_parent` pointing at the top of the receiving thread's, and a `BC_REPLY`
"pops the current top transaction of the sender's thread transaction stack" by setting
`thread->transaction_stack = in_reply_to->to_parent`. The driver's reply path then delivers the
reply onto the originating thread's `binder_thread->todo`
([binder.c](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/android/binder.c)),
which is why the chain unwinds in last-in-first-out order. So if A sends a synchronous
transaction to B and B's handler sends a second synchronous transaction to C, A's transaction
object stays live on the stack for the whole duration of the inner call — and C simply never
replies. The critical section is now as long as you want it.

The prose above names `from_parent` and `transaction_stack`; get their offsets from the kernel in
front of you rather than from the prose, and then watch the link form. `binder_transaction()` in
6.1 is `(struct binder_proc *proc, struct binder_thread *thread, ...)`, so `%x1` is the thread
whose stack is being pushed, and kprobe fetch expressions nest, which is what lets one probe
follow the pointer and read the field behind it:

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -A40 'struct binder_transaction {'
pahole -C binder_thread vmlinux        # TS = offset of transaction_stack
pahole -C binder_transaction vmlinux   # FP = offset of from_parent
echo "p:xn binder_transaction top=+${TS}(%x1):x64 parent=+${FP}(+${TS}(%x1)):x64" >> $T/kprobe_events
```

A `top` that is nonzero on entry means this call is nesting onto an existing chain, and the
`parent` it reads is the transaction the window is being held open across.

The same lever exists inside a single transaction. Moshe Kol's
[Racing Against the Lock: Exploiting Spinlock UAF in the Android Kernel](https://0xkol.github.io/assets/files/Racing_Against_the_Lock__Exploiting_Spinlock_UAF_in_the_Android_Kernel.pdf)
(JSOF Research Lab), on CVE-2022-20421, widens its window by padding a transaction with many
binder objects ahead of the one that matters, so the driver's object-translation loop spends
longer in the vulnerable state before reaching it. That bug is itself a lifetime race — a new
`binder_ref` created for a target process that is concurrently dying, leaving a dangling pointer
into a freed `binder_proc` — and the exploit succeeded on Galaxy S21 Ultra, S22 and Pixel 6 from
`untrusted_app`, four times out of five.

### Placing the second thread in time

Widening the window and scoring attempts are both useless if the second thread cannot be put
where the window is. Three mechanisms do that work, and none of them is a `sleep`.

The rendezvous comes first: two threads must begin their attempt from a common instant. Put a
flag in a `MAP_SHARED` page, have the follower spin on it with an acquire load, and have the
leader release-store it at the moment it is about to enter the syscall. A mutex or a pipe write
is the wrong primitive here for a specific reason — both park the waiter, so what you actually
get is the scheduler's wakeup latency, tens of microseconds of it and variable, substituted for
the offset you were trying to control. [`cves/lib/base/handoff.h`](../lib/base/handoff.h) is the
implementation in this tree, including the bound that keeps a waiter from hanging forever on a
process that died before setting its flag.

Delay injection comes second, because the rendezvous gives you offset zero and the window is
rarely there. `nanosleep()` cannot express the offsets a 3 µs window needs; measure its actual
floor on the device rather than assuming one:

```c
struct timespec req = { 0, 1 }, t0, t1;
clock_gettime(CLOCK_MONOTONIC, &t0);
for (int i = 0; i < 1000; i++) nanosleep(&req, NULL);
clock_gettime(CLOCK_MONOTONIC, &t1);
/* (t1 - t0) / 1000 is the real cost of asking for one nanosecond */
```

What remains is a busy loop, calibrated once against `clock_gettime(CLOCK_MONOTONIC)` and
thereafter reported in iterations rather than in nanoseconds — iterations are what you can
actually set, and the conversion drifts with frequency scaling and with which cluster the thread
landed on.

The sweep comes third, and it is what turns a delay knob into a setting. Run a fixed attempt
count at each value of a geometric ladder — 0, 100, 200, 400, 800, 1600 iterations — and tabulate
the three-way classification of the next section per value: too early, hit, too late. The shape
to look for is a plateau. A single spike at one value is noise, or it is a value that happens to
alias with some periodic activity; a run of adjacent values with similar hit rates is the window,
and its midpoint is the setting to keep, because it is the one furthest from both edges when the
device's timing shifts under thermal or load changes. The edges are also informative on their
own: a table that is all "too late" at every value means the delay range is wrong by orders of
magnitude, and a table with no ordering at all means the rendezvous is not working and each
attempt is starting from a different instant.

### Scheduler and priority

Pinning both sides of a race to known CPUs and then choosing their scheduling classes converts
"hope they interleave" into "they interleave because the scheduler cannot do otherwise".
`sched_setaffinity()` pins, and applies to kernel-mode execution too. `sched_setscheduler()`
with `SCHED_IDLE` makes a task that never preempts; with `SCHED_FIFO` it makes one that preempts
whatever is running on that processor, kernel code included, parking an in-flight syscall until
the real-time thread yields. Horn's mremap/fallocate exploit uses five pinned tasks across two
scheduling classes — `SCHED_NORMAL` and `SCHED_IDLE` — to hold a victim thread off a CPU across a
TLB-flush gap.

On Android, `sched_setaffinity()` does not do what the man page suggests it does, because the
requested mask is intersected with the task's cpuset before it is applied:
`__sched_setaffinity()` calls `cpuset_cpus_allowed()` and then `cpumask_and()`, so a partial
overlap silently narrows your mask and an empty intersection returns `EINVAL`. A background or
foreground app is typically confined to the little cluster and simply cannot pin either side of a
race to a big core. Read the constraint before designing around it:

```
cat /proc/self/cpuset                       # which cpuset group this task is in
cat /dev/cpuset/<group>/cpus                # the CPUs that group permits
grep Cpus_allowed_list /proc/self/status    # what the task actually ended up with
```

An `EINVAL` from `sched_setaffinity()` is the cpuset refusing, not an invalid mask, and the third
line is the only one that tells you what you got rather than what you asked for.

The device is also heterogeneous, which makes an unlabelled window measurement meaningless. The
same critical section on a little core and on a big core differs by a large factor, so a
histogram collected without recording the CPU is not a measurement of anything, and pinning the
two sides of a race to cores in different clusters changes the window and the attacker's own loop
rate at the same time. Read the split and then carry it through the measurement:

```
cat /sys/devices/system/cpu/cpu*/cpu_capacity
cat /sys/devices/system/cpu/cpufreq/policy*/related_cpus
```

Collect the window histogram per CPU — the ftrace record header carries a CPU column in brackets,
and the bpftrace one-liner above keys its histogram on `@us[cpu]` for the same reason. A window
quoted without its CPU cannot be compared against a later run.

Kernel mutexes do not disable preemption, so a task preempted while holding one produces a
priority inversion, and because a regular `struct mutex` has no priority inheritance the
inversion is unbounded — which is the property being exploited. Two facts qualify it. Mutexes
spin optimistically while the owner is on-CPU (`CONFIG_MUTEX_SPIN_ON_OWNER`, selected on SMP), so
a waiter does not necessarily sleep and the hold you engineered may not materialize as a blocked
thread at all; and spinlocks do disable preemption, so the same trick fails outright inside a
spinlock section. Which preemption model the kernel was built with therefore decides what is
possible:

```
zcat /proc/config.gz | grep -E 'CONFIG_PREEMPT(ION|_DYNAMIC|_VOLUNTARY|_RT|_NONE|_BUILD)?='
uname -v                                     # the version string carries PREEMPT / PREEMPT_RT
grep -o 'preempt=[a-z]*' /proc/cmdline       # only meaningful under PREEMPT_DYNAMIC
cat /sys/kernel/debug/sched/preempt          # the active model, in brackets
chrt -p <pid>                                # current policy and priority of a running task
taskset -pc <pid>                            # current CPU affinity mask
grep -i 'realtime priority' /proc/self/limits  # RLIMIT_RTPRIO; 0 means SCHED_FIFO needs CAP_SYS_NICE
```

Android GKI sets `CONFIG_PREEMPT=y` (full preemption) and does not set `CONFIG_PREEMPT_DYNAMIC`,
so on the target of this tutorial the compiled config is the answer, and the `preempt=` and
`/sys/kernel/debug/sched/preempt` reads are for kernels elsewhere: where `PREEMPT_DYNAMIC` is
set, the model is chosen at boot by `preempt=` and switchable at runtime, and the compiled config
tells you nothing at all. `/proc/config.gz` itself needs
`CONFIG_IKCONFIG_PROC`, which Pixel GKI builds carry. Read `RLIMIT_RTPRIO` from
`/proc/self/limits` rather than with `ulimit -r`: Android's shell is mksh, whose builtin prints
the same value unconditionally.

A real-time hold is also bounded by the kernel's own throttle:
`cat /proc/sys/kernel/sched_rt_runtime_us` against `sched_rt_period_us` gives the fraction of
each period a `SCHED_FIFO` task is allowed to monopolize (950000 of 1000000 by default), and
exceeding it gets the thread descheduled rather than the window widened.

### Interrupts

The most general technique in the literature is to make an interrupt land inside the window.
[ExpRace: Exploiting Kernel Races through Raising Interrupts](https://www.usenix.org/conference/usenixsecurity21/presentation/lee-yoochan)
(Yoochan Lee, Changwoo Min, Byoungyoung Lee, USENIX Security 2021) builds four vectors an
unprivileged process can raise on demand — the rescheduling IPI, the TLB shootdown IPI, the
`membarrier()` IPI, and hardware interrupts — and reports exploiting ten real races that were
otherwise unexploitable within 10 to 118 seconds each, against failure across 24 hours without
the technique.

Three of the four transfer to arm64; one does not.

- The rescheduling IPI exists and is raised the same way, by making a task runnable on another
  CPU. It lands on `IPI0`.
- The function-call IPI exists. `membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED)` is the way to
  raise it on demand: it goes through `smp_call_function_many()`, so it arrives as a generic
  function-call IPI on `IPI1`, not as a vector of its own. It returns `EPERM` unless the process
  has first called `membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0)` — the kernel
  checks `MEMBARRIER_STATE_PRIVATE_EXPEDITED_READY` on the mm and refuses otherwise. Fire the
  syscall without registering and nothing happens, with no way to tell whether the technique or
  the registration failed.
- Hardware interrupts exist and are raised the usual ways, by driving a device from userspace.
- The TLB-shootdown IPI does not exist. arm64 invalidates TLB entries with broadcast
  instructions — `__tlbi(vmalle1is)`, `__tlbi(vale1is)` and relatives, the `is` suffix being
  inner-shareable — so the invalidation is performed by hardware across the shareability domain
  with no IPI to raise and no counter that could move. The evidence is the instrument itself:
  arm64's IPI table has no TLB row.

Horn's
[Racing against the clock — hitting a tiny kernel race window](https://projectzero.google/2022/03/racing-against-clock-hitting-tiny.html)
applies the same idea with a deliberately expensive handler: instead of racing thread against
thread, it races one thread against a `timerfd` whose expiry handler must walk 50,000 waitqueue
entries, built by duplicating a file descriptor into an epoll instance many times. It also adds
a cache miss inside the window on purpose — another core dirties the target line with
`close(dup(fd))` just before the attempt — while warming the lines on the path outside the window
so nothing else stalls. With all three in place, the race in the UNIX-socket garbage collector
hits "somewhere around 30% if the proof of concept has been tuned for the specific machine", on
a desktop kernel built without `CONFIG_PREEMPT`; the same writeup's timing-offset sweep on a
Tiger Lake laptop puts up to about a third of attempts in the window at the best offset. The
30% is the race's per-attempt hit rate with the expensive handler and the deliberate cache miss
both enabled, not an end-to-end exploit success rate.

Whether your IPIs actually arrived is observable, and the rows are named. `/proc/interrupts` on
arm64 ends with a per-CPU IPI table emitted by `arch_show_interrupts()` in the enum's order:

```
IPI0     Rescheduling interrupts
IPI1     Function call interrupts
IPI2     CPU stop interrupts
IPI3     CPU stop (for crash dump) interrupts
IPI4     Timer broadcast interrupts
IPI5     IRQ work interrupts
IPI6     CPU wake-up interrupts
```

Sample it either side of a burst and read the per-CPU column, not the row total:

```
grep IPI /proc/interrupts > /tmp/a
<burst>
grep IPI /proc/interrupts > /tmp/b
diff /tmp/a /tmp/b
```

The conclusion is per-CPU: `IPI1` on CPU3 moved by N, so N function-call IPIs landed on the CPU
the victim is pinned to. If the counter does not move, the widening step is not happening and
tuning it further is wasted effort. Whether you can read the file at all is a policy question
with a direct check — `ls -Z /proc/interrupts`,
`sesearch --allow -s shell -t proc_interrupts -c file ./policy`, and `dmesg | grep avc` to
confirm a denial rather than infer one.

## Finding races in the first place

Most of the detectors below need a rebuilt kernel, which makes them tools for the analysis stage
rather than the exploitation stage: lockdep, KCSAN and generic KASAN are all absent from the GKI
defconfig. The KASAN qualifier is load-bearing: the arm64 `gki_defconfig` does set
`CONFIG_KASAN=y` together with `CONFIG_KASAN_HW_TAGS=y`, so the MTE-based variant is compiled
into a stock build, and two separate things keep it silent there. The command line can switch it
off with `kasan=off`, with `kasan.mode=` selecting only the sync, async or asymmetric execution
mode once it is on — both knobs documented in the
[KASAN documentation](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html), which also
records that the hardware tag-based mode requires arm64 with the Memory Tagging Extension. That
is the second gate and the one that usually decides: on a device that is not running with MTE
enabled, a `CONFIG_KASAN_HW_TAGS=y` build reports nothing whatever the command line says. What a
stock build has no trace of at all is the software-shadow `CONFIG_KASAN_GENERIC` instrumentation
that "a KASAN build" usually means. KFENCE is the detector that runs as shipped, and is worth
checking after every failed campaign, because GKI compiles it in (`CONFIG_KFENCE=y`,
`CONFIG_KFENCE_SAMPLE_INTERVAL=500`, `CONFIG_KFENCE_NUM_OBJECTS=63`).

```
zcat /proc/config.gz | grep -E 'KFENCE|KCSAN|PROVE_LOCKING|KASAN'
grep -m1 '^Features' /proc/cpuinfo            # an `mte` hwcap here, or HW_TAGS reports nothing
cat /proc/cmdline | tr ' ' '\n' | grep kasan  # kasan=off disables it; kasan.mode= picks the mode
cat /sys/module/kfence/parameters/sample_interval   # 500 ms on GKI
cat /sys/kernel/debug/kfence/stats                  # pool occupancy and hit counters
dmesg | grep -i kfence                              # after a failed campaign
```

At a 500 ms sample interval the per-allocation catch probability is tiny, so a KFENCE hit is luck
rather than a test, and its absence proves nothing. Its presence proves a great deal: a
`BUG: KFENCE: use-after-free` naming your victim cache is a free allocation-and-free stack trace
for the exact object the race is corrupting, and it is proof the race fired even on a run you
scored as a miss. The debugfs files need root, and debugfs may not be mounted on a user build,
in which case `dmesg` is the whole interface.

- lockdep (`CONFIG_PROVE_LOCKING`) builds a dependency graph over lock classes and reports
  inverse orderings and unsafe hardirq/softirq dependencies. It finds lock-order bugs, not
  missing locks. `/proc/lockdep_stats` shows allocated classes against the `MAX_LOCKDEP_KEYS`
  ceiling, and `/proc/lockdep` lists them — which is how you notice lockdep has silently stopped
  validating because it ran out. See the
  [lockdep design document](https://www.kernel.org/doc/html/latest/locking/lockdep-design.html).
- KCSAN (`CONFIG_KCSAN`) is a watchpoint-sampling data-race detector, documented at
  [kernel.org](https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html). Its runtime knobs
  are themselves race-widening parameters: `kcsan.udelay_task` and `kcsan.udelay_interrupt` set
  how long a thread stalls at a watchpoint so a conflicting access has time to appear, and
  `kcsan.skip_watch` sets sampling density. `/sys/kernel/debug/kcsan` accepts `on`, `off` and
  `!function_name` filters and prints statistics when read. A report names both accesses with
  stack traces; the "value changed" line is the strong form, meaning KCSAN saw the memory change
  under the watchpoint.
- [KTSAN](https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md) took the
  happens-before approach instead, adapting ThreadSanitizer's algorithm to the kernel with full
  shadow memory. Its own documentation gives the reason it stalled: the "significant complexity
  of the bug-detection algorithm when adapted to the Linux kernel and large CPU and RAM
  overheads". The [repository](https://github.com/google/ktsan) was archived in June 2022; KCSAN,
  which samples with watchpoints instead, is what survived.
- KASAN turns a lost race into a legible report, since a race-induced use-after-free surfaces as
  a splat carrying both allocation and free stacks — generic KASAN on a rebuilt kernel, or the
  HW_TAGS variant already compiled into GKI, on a device that runs with MTE enabled.
  Both it and KFENCE are covered from the crash side in
  [03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md).
- [rr](https://rr-project.org/) records and deterministically replays user-space processes. It
  cannot record the kernel and emulates a single core, so it is useless for the kernel half of a
  race — but the userspace half often lives in `system_server` or a HAL, and that half is
  recordable. Its chaos mode (`rr record -h`), described in
  [Introducing rr chaos mode](https://robert.ocallahan.org/2016/02/introducing-rr-chaos-mode.html),
  randomizes thread priorities and timeslice lengths and periodically starves low-priority
  threads outright — a userspace analogue of the scheduler tricks above, which reproduced
  intermittent failures that thousands of plain runs had missed.

## Why hit rate, not pass/fail

A race exploit is a Bernoulli trial, and treating it as a yes/no test throws away almost all
the information a run produces.

The first thing a harness must do is refuse a binary verdict. Horn's writeup classifies each
attempt three ways — too early, hit, too late — from observable side effects (`dup()` returning
`-1` versus a higher descriptor, `recvmsg()` returning data versus nothing). That turns a flat
failure into a signed error, and a signed error can be steered: consistently too early, add
delay by the sweep described above; straddling zero, you are already at the achievable optimum
and further tuning is noise. The classification has to be derived from something the attempt
itself produces, which is why it is worth spending design effort on a side effect that differs
between the two failure directions rather than settling for one that only distinguishes success.

A harness should also separate "the race ran and lost" from "a precondition is permanently
absent" and from "setup failed before anything was attempted". Folding a permanent wall into
ordinary misses is how a campaign spends ten thousand attempts on something that cannot happen;
folding setup failures into misses makes a working chain look like a low hit rate.

The second is to stop drawing conclusions from small samples. Two tools cover it: the rule of
three bounds the true rate after a run with no successes, and the Wilson score interval is what
to report for a nonzero one.
[10-survivability-and-measurement.md](10-survivability-and-measurement.md) carries the source and
the worked shape for the first, and the short version of both is that zero successes in ten
attempts is consistent with a technique that wins one run in four, and that comparing two
widening strategies means comparing intervals rather than point estimates. The number worth
having in mind here is how expensive that comparison is. To separate a 2% hit rate from a 5% one
at 95% confidence takes roughly 580 attempts per arm: at n = 600 the Wilson intervals are
[1.2%, 3.5%] around 0.02 and [3.5%, 7.1%] around 0.05, and they only just clear each other. On a
reboot-bound campaign at a few attempts per minute that is days of wall time for one comparison,
which is the practical argument for the next point.

The third is to find a proxy observable upstream of the win. A lost race on a phone costs a
panic and a reboot, so a campaign measured on wins alone runs at a few attempts per minute. The
step before the win — the vulnerable path reading the address you aimed it at, whether or not
the free had landed yet — is visible to a kprobe and costs nothing. Counting that over a few
hundred attempts, with the widening technique on and then off, answers "is the window opening
where I think it is" at a rate the reboot-bound measurement never could, and without a single
crash. The full-win rate is then measured separately, at low throughput, on a configuration the
proxy has already validated. What is specific to races is that such a proxy exists at all,
because the trace infrastructure can see the middle of a window userspace cannot.

## Instruments

- `echo 'p:name func arg=+OFF(%x0)' >> /sys/kernel/tracing/kprobe_events` — record a kernel
  function's entry and a chosen field of its argument. Needs root, `CONFIG_KPROBE_EVENTS`, and
  an SELinux domain permitted to write tracefs; not available to `adb shell` at uid 2000. Arm it
  with a `common_pid` filter and relax `kptr_restrict`, or the output is unusable.
- `echo 'common_pid == <pid>' > /sys/kernel/tracing/events/kprobes/<name>/filter` — restricts a
  probe to one task. Mandatory on any busy function; without it the record you want is buried.
- `echo 0 > /proc/sys/kernel/kptr_restrict` — makes fetched pointers render as values rather than
  zeros. Root; restore it on the way out.
- `cat /sys/kernel/debug/kprobes/blacklist` — the functions and intervals where a probe is
  refused. A rejected write to `kprobe_events` returns `EINVAL`; on arm64 the other causes are a
  non-4-byte-aligned address, an address inside an exception table, and an instruction the kprobe
  decoder will not simulate.
- `echo global > /sys/kernel/tracing/trace_clock` — makes timestamps comparable across CPUs,
  which per-CPU `local` clock timestamps are not. Required before measuring any cross-CPU
  interval. Root.
- `cat /sys/kernel/tracing/available_tracers` — which tracers the running build actually carries.
  `function_graph` plus `set_graph_function` would give a per-call duration column without probe
  expressions, but it needs `CONFIG_FUNCTION_GRAPH_TRACER` on top of the function tracer, and
  panther's config has `# CONFIG_FUNCTION_TRACER is not set`, so neither it nor the latency tracers
  are present here. Same tracefs access as the probes above.
- `bpftrace -e 'kprobe:f {...} kretprobe:f {...}'` with `hist()` — latency distribution of a
  critical section in one command, keyed on `tid` so pairing is correct and on `cpu` so the
  distribution is per-cluster. Root and a kernel with BPF and BTF; absent from stock Android
  userspace, usable on a device where you can push a static build.
- `bpftool btf dump file /sys/kernel/btf/vmlinux format c` — the running kernel's type
  definitions as C. Not present in Android userspace: push a static aarch64 build, or dump BTF
  host-side from a pulled `vmlinux`. BTF ships on Android GKI (`CONFIG_DEBUG_INFO_BTF=y`).
- `ls -Z /sys/kernel/btf/vmlinux` — the SELinux label, which is what decides access. The file is
  mode 0444, so a refusal is a policy refusal; confirm it with
  `sesearch --allow -s shell -t sysfs -c file` against a pulled policy, and with
  `dmesg | grep avc`.
- `pahole -C <struct> vmlinux` — byte offsets and sizes of every member, which is what a probe
  fetch expression needs. Host-side, against a vmlinux with BTF or DWARF; the offline fallback
  when `/sys/kernel/btf/vmlinux` is unreadable.
- `drgn -k` / `drgn -c vmcore` — scripted structure walking against a live kernel or a dump, which
  is the natural way to follow a binder transaction stack rather than reconstructing it from
  probe output. Not usable against the phone at any privilege: `drgn -k` reads the live kernel
  through `/proc/kcore`, and `CONFIG_PROC_KCORE` is unset in the arm64 `gki_defconfig`, so the file
  does not exist; GKI release images also ship no DWARF. It runs host-side against a crash dump, a
  Cuttlefish instance or a lab kernel built to match, which is where the ground truth a device-side
  probe gets checked against comes from.
- `vmlinux-to-elf` plus `objdump -d`, or `gdb -batch -ex 'disassemble <fn>'` — recover a
  symbolized ELF from a stripped kernel image and find the exact instruction and base register a
  mid-function probe must be written against. Host-side, no device privilege.
- A two-call `userfaultfd()` probe (plain, then `UFFD_USER_MODE_ONLY`) — distinguishes
  unrestricted from user-mode-only from closed, which reading
  `/proc/sys/vm/unprivileged_userfaultfd` alone does not. No privilege.
- `ls -Z /dev/fuse` plus `sesearch --allow -s <domain> -t fuse_device -c chr_file` — whether your
  domain can reach FUSE for a stall. Policy pulled from `/sys/fs/selinux/policy`.
- `getrusage(RUSAGE_SELF).ru_majflt`, or field 12 of `/proc/self/stat` — confirms a mapping
  access actually took a major fault and went to disk rather than hitting the page cache. No
  privilege.
- `/dev/binderfs/binder_logs/proc/<pid>` — a binder process's looper threads with their `l`
  state word and their outgoing/incoming/pending transactions, which is how a parked nested chain
  is confirmed from userspace. Root; `/sys/kernel/debug/binder/proc/<pid>` where debugfs is
  mounted.
- `/dev/binderfs/binder_logs/stats` — the `threads:` / `requested threads: A+B/MAX` /
  `ready threads` / `free async space` counters, which is how thread-pool saturation is verified
  against the 15-looper libbinder cap. Root.
- `cat /proc/self/cpuset`, `cat /dev/cpuset/<group>/cpus` and
  `grep Cpus_allowed_list /proc/self/status` — the cpuset that bounds `sched_setaffinity()`, and
  what the task actually got. Unprivileged; an `EINVAL` from `sched_setaffinity()` is this
  refusing.
- `cat /sys/devices/system/cpu/cpu*/cpu_capacity` and
  `/sys/devices/system/cpu/cpufreq/policy*/related_cpus` — the big/little split, without which a
  window measurement cannot be compared across runs. Unprivileged.
- `chrt -p <pid>`, `taskset -pc <pid>`, `grep -i 'realtime priority' /proc/self/limits` —
  scheduling policy, CPU affinity and whether `SCHED_FIFO` will be permitted at all. Unprivileged
  for own tasks; `SCHED_FIFO` needs `CAP_SYS_NICE` or a nonzero `RLIMIT_RTPRIO`. Read the limit
  from `/proc`, not with `ulimit -r`, which mksh answers unconditionally.
- `zcat /proc/config.gz | grep -E 'CONFIG_PREEMPT(ION|_DYNAMIC|_VOLUNTARY|_RT|_NONE|_BUILD)?='`,
  `uname -v`, and under `PREEMPT_DYNAMIC` also `grep -o 'preempt=[a-z]*' /proc/cmdline` and
  `/sys/kernel/debug/sched/preempt` — the kernel's preemption model, which decides whether
  preempting a lock holder is possible. Needs `CONFIG_IKCONFIG_PROC`; GKI is `CONFIG_PREEMPT=y`
  and not dynamic.
- `cat /proc/sys/kernel/sched_rt_runtime_us` — the real-time throttle ceiling that bounds how
  long a `SCHED_FIFO` hold can starve a CPU before the kernel breaks it. World-readable.
- `grep IPI /proc/interrupts` sampled before and after — `IPI0` rescheduling, `IPI1` function
  call (which is where `membarrier` expedited lands, after
  `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED`), `IPI2` CPU stop, `IPI5` IRQ work. Read the
  per-CPU column. Check access with `ls -Z /proc/interrupts`,
  `sesearch --allow -s shell -t proc_interrupts -c file`, and `dmesg | grep avc`.
- `cat /sys/kernel/debug/kfence/stats`, `/sys/module/kfence/parameters/sample_interval`, and
  `dmesg | grep -i kfence` — the one detector compiled into GKI. A report naming your victim
  cache is proof the race fired. Root, and debugfs may not be mounted on a user build.
- `CONFIG_PROVE_LOCKING` with `/proc/lockdep_stats` and `/proc/lockdep` — lock-order validation
  and whether the validator is still running or has exhausted its class table. Debug kernel.
- `CONFIG_KCSAN` with `/sys/kernel/debug/kcsan` and `kcsan.udelay_task` — sampling data-race
  detection, with an adjustable artificial delay at each watchpoint. Debug kernel.
- `rr record -h` — chaos-mode record-and-replay of the userspace side of a race. x86-64 or Apple
  silicon Linux host; user-space only, single-core emulation.

## Grounded in this project

The widening techniques described here are implemented as reusable modules rather than per-CVE
code. [`cves/lib/trigger/app_saturator.h`](../lib/trigger/app_saturator.h) and
[`cves/lib/trigger/app_saturator.c`](../lib/trigger/app_saturator.c) occupy a target app's
binder thread pool from outside its process, which is the consumer-saturation lever;
[`cves/lib/trigger/amclient.c`](../lib/trigger/amclient.c) is the ActivityManager client that
reaches an app process from an unprivileged shell in the first place, and
[`cves/lib/trigger/binder.c`](../lib/trigger/binder.c) is the transport underneath both.
[`cves/lib/base/rthold.h`](../lib/base/rthold.h) implements the `SCHED_FIFO` processor hold,
including the real-time throttle caveat, and [`cves/lib/trigger/pump.h`](../lib/trigger/pump.h)
covers the case where no userspace signal brackets the window at all and only multi-CPU density
is left. [`cves/lib/base/handoff.h`](../lib/base/handoff.h) is the bounded cross-process flag
that keeps a multi-process chain ordered without a lock either side could be holding, and is the
rendezvous primitive the placement subsection above describes.

The measurement side lives in [`cves/lib/trace/fnprobe.h`](../lib/trace/fnprobe.h) and
[`cves/lib/trace/interval.h`](../lib/trace/interval.h), which collect kprobe records into a
distribution of interval lengths rather than a single reading, and in
[`cves/lib/base/outcome.h`](../lib/base/outcome.h), which defines the PASS/MISS/WALL/REFUSED
vocabulary that keeps permanent walls and harness failures out of the hit-rate denominator.
[`cves/lib/tools/kprobe.sh`](../lib/tools/kprobe.sh) is the device-side probe driver that already
encodes the per-process filter, the `kptr_restrict` relaxation and the unconditional teardown.
Struct offsets for probe expressions are derived per build by
[`runner/scripts/lib/btf_offsets.py`](../../runner/scripts/lib/btf_offsets.py) rather than
hardcoded.

Two complete chains in this tree exercise the techniques above.
[FFWheel](../cve-2026-43049-ffwheel/README.md) is the case where the window is not the attacker's
to widen: the platform's own input reader opens the leaked event node a few milliseconds after
the free and fires the trigger, an ordering established by tracing an equivalent device that is
never freed rather than by racing it, so the free-and-reclaim sequence is sized against a window
a third party sets. Its reclaim carries the placement constraint the scheduling subsection
describes — the free and the spray run on the same processor with nothing between them, and where
the reclaim landed is read off the page frame numbers reported by the kernel's page-allocation
tracepoints rather than asserted — and it carries a proxy of the kind *Why hit rate, not
pass/fail* argues for: its write gadget exchanges a word in a page the attacking process also
maps, so a plain userspace read tells the exploit whether the gadget fired, without a kernel read
and without waiting to see whether the corrupting store did anything. That is what separates a
missed reclaim from a wrong address, and it is why only the outcome that left the kernel
untouched is retried.

[GhostLock](../cve-2026-43499-ghostlock/README.md) is the trigger-topology case. Its race is one
step of a longer chain, and the thread that creates the dangling state is not the thread that
fires the walk over it: a waiter is requeued out of `futex_wait_requeue_pi()` and its stack frame
is then overlaid by a `pselect()` of a chosen size, after which a separate thread issues
`sched_setattr()` against that waiter's thread id and the priority change drives the walk into
the forged node. Four threads run a fixed sequence, not two. It also supplies the outcome
vocabulary the same section asks for — preconditions that cannot hold on a given build fail a
named gate before the race is armed, so a target that could never have worked refuses itself at
no cost rather than entering the hit-rate denominator as a miss.

## See also

- [01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md)
  — where lockdep, KCSAN and syzkaller reports enter the pipeline, and how a race fix is
  recognized in a commit.
- [02-reachability-and-attack-surface.md](02-reachability-and-attack-surface.md) — whether the
  binder devices, tracefs and the other surfaces used here are reachable from your starting
  domain.
- [03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md) —
  reading the panic a lost race produces, and separating "the window never opened" from "the
  reclaim missed".
- [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) — resolving the
  addresses a probe or a trigger needs when `/proc/kallsyms` is restricted.
- [05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md) — what has to be ready to
  occupy the object the moment the race frees it, and the spray use of the same `userfaultfd`
  and FUSE stalls.
- [06-cross-cache-attacks.md](06-cross-cache-attacks.md) — the harder reclaim problem when the
  freed object's page leaves its slab cache entirely, and, under "RCU-deferred frees, and why
  they move the page to another CPU", why a won race can still reclaim nothing.
- [07-read-write-primitives.md](07-read-write-primitives.md) — converting the corrupted object a
  won race leaves behind into a usable read or write.
- [10-survivability-and-measurement.md](10-survivability-and-measurement.md) — the source for the
  rule of three, and the composition and reboot-budget arithmetic behind hit-rate campaigns.
- [11-case-studies.md](11-case-studies.md) — these techniques composed end to end.
- [12-further-reading-and-glossary.md](12-further-reading-and-glossary.md) — the wider literature
  on kernel concurrency bugs.
