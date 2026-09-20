# Survivability, Stabilization, and Treating Exploitation as an Experiment

An exploit that obtains uid 0 and then takes the machine down thirty seconds later has, from the operator's point of view, failed. The interesting part of this failure is that nothing went wrong with the primitive: the write landed, the credentials changed, the shell came back as root. What went wrong is that the bug left the kernel holding a reference to something the exploit destroyed, and some unrelated subsystem eventually followed it.

This is the part of exploit development least represented in proof-of-concept code and most represented in real tooling. It splits in two. Survivability is understanding what state the bug left broken and defusing the paths that would touch it before they run. Measurement is accepting that most kernel exploits have a success rate rather than a success, and building the apparatus that estimates it, attributes failures, and improves it.

## The debt the bug leaves behind

A use-after-free or a heap overflow changes memory. It also, almost always, changes the object graph. The freed object was not an island: it was on a list, it had a refcount somebody else held, it had a registered callback, it was the `private_data` of a file description that userspace can still `read()`, it owned a timer that has not yet fired, it was queued for RCU reclamation. When you reallocate that memory and fill it with a forged structure, every one of those references is now a reference to your forgery.

The canonical inventory of what can go wrong is in the Lexfo series on CVE-2017-11176, which ends with a section titled *Repair the Kernel* and the blunt observation that the step "is not optional as our exploit is still crashing the kernel upon exit" ([Lexfo, CVE-2017-11176 part 4](https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part4.html)). Two distinct repairs were needed there: a dangling `struct socket` pointer that the exit path would dereference, and corrupted hash-list entries introduced by the reallocation. The guiding principle in that writeup is worth stating on its own, because it generalizes: reset the minimum number of pointers needed to make the dangerous path harmless, and then "let the kernel do the 'normal' housekeeping (decrement refcounter, release objects, etc.)".

Project Zero's analysis of null-dereference exploitation makes the complementary point about what an oops costs you even when it does not panic: "Any locks that were locked at the moment of the oops stay locked, any refcounts remain taken, any memory otherwise temporarily allocated remains allocated" ([Exploiting null-dereferences in the Linux kernel](https://projectzero.google/2023/01/exploiting-null-dereferences-in-linux.html)). A machine that survived your oops is not a machine in a good state; it is a machine with a leaked mutex that the next process to take that path will block on forever.

### Recovering layout from the kernel you are attacking

To enumerate the references a given structure exposes you need its layout, and on a production kernel you cannot rebuild, BTF is the instrument. BTF is a compact type-description format for kernel objects — structs, members, offsets, the types those members have — specified in the kernel's own [BTF documentation](https://docs.kernel.org/bpf/btf.html). What makes it useful here is a separate mechanism: a kernel built with `CONFIG_DEBUG_INFO_BTF` embeds its blob and exports it through sysfs. `kernel/bpf/sysfs_btf.c` creates a binary attribute named `vmlinux` under a `btf` kobject with mode `0444` ([sysfs_btf.c, v6.1](https://github.com/torvalds/linux/blob/v6.1/kernel/bpf/sysfs_btf.c)), which is the `/sys/kernel/btf/vmlinux` that `bpftool` takes as its base BTF ([bpftool-btf(8)](https://github.com/libbpf/bpftool/blob/main/docs/bpftool-btf.rst)). Android GKI kernels set the config symbol; the device this tutorial targets has `CONFIG_DEBUG_INFO_BTF=y` in its own `/proc/config.gz`.

Check for the file first:

```
adb shell ls -lZ /sys/kernel/btf/vmlinux
```

`-Z` is worth the three keystrokes: it prints the SELinux label alongside the mode, and the label is what decides whether an unprivileged domain may read a file whose DAC mode says everyone may. The DAC answer is settled by the source above — `0444` — and the MAC answer is per-policy, so it is measured rather than assumed. This project's harvester reads the blob through `su` (`runner/scripts/harvest-live.sh`), so the unprivileged read is not something it has established on the target; see the policy recipe below for how to settle it on yours.

With the blob in hand, read layouts out of it. `pahole` reads BTF as well as DWARF and CTF and prints member offsets, sizes and padding holes, and with no file argument it looks for `/sys/kernel/btf/vmlinux` itself ([pahole(1), upstream dwarves](https://github.com/acmel/dwarves/blob/master/man-pages/pahole.1)):

```
$ pahole -C input_dev data/live/panther-CP2A.260705.006/btf-vmlinux
...
	spinlock_t                 event_lock;           /*   512     4 */

	/* XXX 4 bytes hole, try to pack */

	struct mutex               mutex;                /*   520    48 */
	unsigned int               users;                /*   568     4 */
	bool                       going_away;           /*   572     1 */
...
	bool                       inhibited;            /*  1568     1 */
```

The output is the struct rendered as C with `/* offset | size */` annotations on every member. What you are looking for is not one number but a class of members: every `struct list_head`, every `wait_queue_head_t`, every `struct kref` or `refcount_t`, every function-pointer table, every `struct timer_list`. Each is a reference somebody else holds into this object, and each is a candidate cause of a post-exploitation panic.

If your `pahole` predates BTF support, the fallback is `bpftool`'s raw dump, which prints each member's `bits_offset` straight out of the kernel's type information with no compiler in the loop:

```
$ bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -A60 "STRUCT 'input_dev'"
[68222] STRUCT 'input_dev' size=1608 vlen=53
	...
	'event_lock' type_id=121 bits_offset=4096
	'mutex' type_id=54 bits_offset=4160
	'users' type_id=48 bits_offset=4544
	'going_away' type_id=94 bits_offset=4576
	...
	'inhibited' type_id=94 bits_offset=12544
```

`bits_offset` is in bits, so `users` is at byte 568 — the same number `pahole` printed, arrived at without a toolchain in between. The `format c` dump (`bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`) is for compiling *against* the types, not for measuring them: BTF carries no alignment or packing attributes, so an `offsetof()` computed by a host compiler against the generated header can disagree with the kernel's own layout, and it disagrees silently. Treat `format c` as a source of names and `format raw` or `pahole` as the source of numbers.

Do not copy a field offset out of a writeup, including this one: GKI builds differ between KMI versions, vendor hooks change struct sizes, and a `struct mutex` is a different size under `CONFIG_DEBUG_MUTEXES`. Where the object is not in BTF at all — a vendor module's private struct — the fallback is recovering symbols from the shipped image with [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf), which rebuilds an analyzable ELF by parsing the embedded kallsyms table, and then reading the offset out of the disassembly of a function that touches the field. The tool takes a kernel image (`vmlinux`, `Image`, `zImage`, `kernel.bin`) and also accepts an Android `boot.img` directly when the image carries the `ANDROID!` or `UNCOMPRESSED_IMG` magic; it detects and unpacks gzip, LZ4, LZMA, XZ, bzip2, LZO and zstd on its own, so a compressed payload needs no preparation. Where its magic check rejects your boot image, unpack it first — `unpack_bootimg --boot_img boot.img --out .` from AOSP's `system/tools/mkbootimg` writes `boot.img-kernel`, and `magiskboot unpack boot.img` writes `kernel` — and hand the extracted kernel to `vmlinux-to-elf`.

## Neutralizing rather than repairing

Repairing a corrupted object means restoring it to a state where the normal code path works. Neutralizing means arranging for the dangerous code path not to run at all. Neutralization is usually cheaper and more reliable, because it needs one field rather than a consistent object, and because it does not require you to know what a consistent object looks like.

It is also the step where the field you write is not the only field that matters. The dangerous path has a prologue, and the prologue runs before the predicate you are aiming at. Enumerate every field the path touches between its entry and the early return, not just the one whose value you are choosing.

### The wait queue

A `wait_queue_head` is a spinlock and a `struct list_head`; on the target build that is `lock` at offset 0 (4 bytes), four bytes of padding, and `head` at offset 8 (16 bytes), for 24 bytes total. Waking it means walking that list and calling each entry's `func`.

The walk has an explicit empty-list case. `__wake_up_common` takes the first entry and compares it against the head before it iterates ([kernel/sched/wait.c, v6.1, lines 85-103](https://github.com/torvalds/linux/blob/v6.1/kernel/sched/wait.c#L85-L103)):

```c
	lockdep_assert_held(&wq_head->lock);
	...
		curr = list_first_entry(&wq_head->head, wait_queue_entry_t, entry);

	if (&curr->entry == &wq_head->head)
		return nr_exclusive;
```

That early return at lines 102-103 is stronger evidence for the neutralization than any argument about the loop body: the function returns before a single waiter is dereferenced. So if a freed object contains a wait queue that something will later wake, writing `head.next = head.prev = &head` — the address of the list head itself, which you know because you know the object's address and the field's offset — makes every future wake take that branch.

It is not one write, though. `lockdep_assert_held` on the first line is the reminder: every caller reaches `__wake_up_common` through `__wake_up_common_lock`, which takes `spin_lock_irqsave(&wq_head->lock, flags)` first. The lock word is at offset 0 of the same reallocated bytes. On arm64 that is a `qspinlock`, a 4-byte union whose all-zero value means unlocked; if your reclaim left non-zero bytes there, the waker spins on a lock nobody will ever release, and you have turned a panic into an unkillable D-state task, which the next section argues is the worse outcome. So the neutralization is two writes — zero the `lock` word, then set `head.next = head.prev = &head` — or, if you have reason to leave the lock alone, a read of those four bytes to confirm they are already zero before you unblock the consumer.

### The input device

`input_open_device` is the same shape with a longer prologue. It is declared `int input_open_device(struct input_handle *)` at `include/linux/input.h:412`, so its one argument is a handle and not the device; the body is at [drivers/input/input.c:625, v6.1](https://elixir.bootlin.com/linux/v6.1/source/drivers/input/input.c#L625):

```c
	struct input_dev *dev = handle->dev;
	int retval;

	retval = mutex_lock_interruptible(&dev->mutex);
	if (retval)
		return retval;

	if (dev->going_away) {
		retval = -ENODEV;
		goto out;
	}

	handle->open++;

	if (dev->users++ || dev->inhibited) {
		/* ... exit immediately and report success. */
		goto out;
	}

	if (dev->open) {
		retval = dev->open(dev);
```

The predicate worth aiming at is `dev->users++ || dev->inhibited`, because `||` short-circuits: a non-zero `users` means `inhibited` is never read, and `dev->open` — the driver callback that walks the freed device's internals — is never reached. On the target build that is a single 4-byte write at offset 568.

But three fields are dereferenced before that line, and all of them live in the same freed object. From the `pahole` output above: `mutex` at 520 (48 bytes), `users` at 568, `going_away` at 572. The mutex is taken first, so the one-field write is necessary and not sufficient — it assumes a still-acquirable `struct mutex` in the reallocated bytes. A sane unlocked mutex on this build is 48 zero bytes: `owner` (`atomic_long_t`, offset 0) zero meaning no holder, `wait_lock` (offset 8) zero, `osq` (offset 12) zero, and `wait_list` (offset 16, 16 bytes) self-referential. A garbage `owner` sends the open into `__mutex_lock`'s slowpath on a freed object, which is the same D-state hang the wait-queue case produces. The size is build-dependent: 48 bytes here because `CONFIG_DEBUG_MUTEXES` is not set on this kernel, larger where it is, which is the reason to read it out of BTF rather than off this page.

Then `going_away` at 572 is read before the predicate. If the reallocation happened to leave it non-zero the open returns `-ENODEV`, which is harmless, but it means a probe that shows opens returning early is not by itself proof that your `users` write is what caused it.

Apply the composition rule from later in this section — read back what you wrote, and read the fields the path depends on, through the same primitive, before you unblock the consumer. `cves/lib/root/input_neut.h` is the pattern: it issues the write in two idempotent passes and then reads every neutralized address back, counting how many confirm.

### The shape in general

The same structure appears all over the kernel, and finding it is a source-reading exercise with a specific question: what is the shallowest predicate on this object that makes the dangerous function return early, and what does the function touch on the way to it? Some recurring answers, each with its constraint:

- A list head made self-referential, so every iteration over it is empty. Check whether a lock guards the iteration, as above.
- A refcount raised so the object is never freed a second time. This leaks memory deliberately, which is the correct trade when the alternative is a double free — but the value depends on the type, and the type is one `pahole -C <struct> | grep <field>` away. A `refcount_t` is not a free-form counter: `REFCOUNT_MAX` is `INT_MAX` and `REFCOUNT_SATURATED` is `INT_MIN / 2` ([include/linux/refcount.h, v6.1, lines 116-117](https://github.com/torvalds/linux/blob/v6.1/include/linux/refcount.h#L116-L117)), and any increment whose result would go negative saturates and calls `refcount_warn_saturate()`, which is a `WARN`. Planting `INT_MAX` therefore plants exactly the signature [section 03](03-crash-triage-and-root-cause-analysis.md) teaches you to read as a mistake — a `WARN` in `refcount.c` means a refcount saturated rather than a use-after-free — and under `panic_on_warn` it is an immediate reboot. Pick a value that is large but far from saturation, something in the `0x10000000` range, and state the constraint to yourself explicitly: the value plus every increment the object will still receive must stay positive. A raw `atomic_t` or a `kref` has no saturation check, so any value works there, at the cost of a deliberately leaked object.
- A state or flags field set to the value that means "already handled", so the entry path short-circuits. `input_dev->users` above is the worked case.
- A function-pointer field set to a known-harmless kernel function. On a kernel with `CONFIG_CFI_CLANG` — which the target sets — "compatible signature" is not the test. The compiler emits a per-prototype type-hash check before every indirect call and a `BRK` on mismatch, so the substitute must have a prototype whose hash is identical to the one the call site expects; anything else dies with `Oops - CFI`, and under `panic_on_oops` that is an instant reboot rather than a diagnosable failure. That narrows the technique to substitutions within one function family — a `wait_queue_func_t` for a `wait_queue_func_t`, which is why `ep_poll_callback` is usable as a wait-queue callback and nothing outside that family is. [Section 03](03-crash-triage-and-root-cause-analysis.md) has the failure signature and the ESR decoding; check whether the constraint applies to your target by adding `CFI_CLANG` to the `/proc/config.gz` grep below.

### Confirming the early return on the kernel in front of you

Before you rely on any of these, confirm the early return exists in your kernel rather than in the version you read. A kprobe placed at the function tells you whether it is reached at all and with what arguments; the tracefs interface takes a probe definition, an enable, and a read ([Documentation/trace/kprobes](https://docs.kernel.org/trace/kprobes.html)).

The probe has to follow the same pointers the function does. `$arg1` here is a `struct input_handle *`, not a `struct input_dev *`, so reading a field of the device is a chained dereference through `handle->dev`. Derive both offsets first:

```
$ pahole -C input_handle btf-vmlinux | grep -w dev
	struct input_dev *         dev;                  /*    24     8 */
$ pahole -C input_dev btf-vmlinux | grep -wE 'users|going_away'
	unsigned int               users;                /*   568     4 */
	bool                       going_away;           /*   572     1 */
```

Then build the probe from those two numbers, not from a number in a writeup:

```
T=/sys/kernel/tracing
echo 'p:iod input_open_device users=+568(+24($arg1)):u32 away=+572(+24($arg1)):u8' > $T/kprobe_events
echo 1 > $T/events/kprobes/iod/enable
echo 1 > $T/tracing_on
cat $T/trace_pipe
```

If `/sys/kernel/tracing` is not populated, mount it (`mount -t tracefs none /sys/kernel/tracing`); on older or debugfs-only configurations the same interface is at `/sys/kernel/debug/tracing`.

Each line printed is one call, with the two fields as they were on entry. If the call arrives with `users=1` and nothing bad follows, the early return is real on this kernel; if the call arrives and the machine dies, your neutralization is aimed at the wrong predicate, and the `away` field distinguishes "my write short-circuited it" from "it bailed at `going_away` for its own reasons". Kprobes need root and `CONFIG_KPROBE_EVENTS`; without either, the fallback is static — disassemble the function out of a `vmlinux-to-elf` reconstruction with `objdump -d --start-address=... --stop-address=...` and read the branch yourself. `bpftrace -e 'kprobe:input_open_device { printf("%s %d\n", comm, pid); }'` gives the same observation with less ceremony where BPF is usable.

### How long you have

Ordering matters as much as the writes. The subsystem that will touch the freed object is frequently not under your control — an input reader thread, a service scanning `/proc/*/maps` for accounting, a workqueue draining on another CPU — and it gets there on its own schedule. Neutralization therefore belongs immediately after the primitive becomes usable and before anything slow.

That "on its own schedule" is a number, and it is measurable with the same instrument. Put one probe on the free and one on the first consumer, and take the difference:

```
T=/sys/kernel/tracing
echo global > $T/trace_clock
echo 'p:freed  input_dev_release dev=$arg1'      >> $T/kprobe_events
echo 'p:opened input_open_device dev=+24($arg1)' >> $T/kprobe_events
echo 1 > $T/events/kprobes/freed/enable
echo 1 > $T/events/kprobes/opened/enable
echo 1 > $T/tracing_on
cat $T/trace_pipe
```

The `trace_clock` line is not optional. ftrace's default clock is `local`, a per-CPU counter that is not comparable across processors, and the whole point of this measurement is that the two ends run on different CPUs — the free on yours, the consumer on whichever one the input thread woke up on. [Section 08](08-triggering-races-reliably.md) makes the same point for race windows and is where the statistics belong; this is the same instrument pointed at a different interval.

What comes back is pairs of lines that have to be read together — the shape is:

```
   kworker/u16:3-1287  [002] d..1.  9142.103551: freed:  (input_dev_release+0x4/0x40) dev=0xffffff8803a4c000
    InputReader-1042   [005] d..1.  9142.108274: opened: (input_open_device+0x4/0x120) dev=0xffffff8803a4c000
```

The bracketed number is the CPU, and here it differs between the two lines, which is exactly why the global clock was needed. The gap is `9142.108274 - 9142.103551`, about 4.7 ms, and the `dev=` values matching is what says these two lines are the same object rather than two unrelated flights.

One pair is not the answer. Run it a few hundred times and take a low percentile, not the median: the neutralization has to fit inside the shortest gap you will actually see, so the 5th percentile is the budget and the median is decoration. `cves/lib/trace/interval.h` collects the distribution from `trace_pipe` and documents the hazard that decides whether the numbers mean anything — records are paired by name in the order written, so when several flights can be in the air at once a sample may pair two different ones and the spread reads artificially low. Filter to one process, or key the pairing on the `dev=` value, before trusting the tail. This needs root and `CONFIG_KPROBE_EVENTS`.

## Bounding failure in time

A hang is worse than a crash. A crash produces a backtrace and a reboot; a hang produces a device that has to be power-cycled by hand and a stage that never reported anything. Every stage that can block indefinitely needs a deadline, and the deadline has to be enforced from somewhere that is still running.

In-process, the tool is an alarm plus a signal handler installed without `SA_RESTART`. The flag choice is the whole trick for a restartable call: with `SA_RESTART`, a blocked `read()` resumes after the handler returns and you have achieved nothing; without it, the call fails with `EINTR` and control returns to you ([signal(7)](https://man7.org/linux/man-pages/man7/signal.7.html)). A read-primitive built on a pipe will block forever if the redirect never landed, and turning that into a prompt, attributable failure is a four-line change:

```c
struct sigaction sa = {0};
sa.sa_handler = on_timeout;   /* sets a volatile sig_atomic_t flag */
sa.sa_flags   = 0;            /* deliberately no SA_RESTART */
sigaction(SIGALRM, &sa, NULL);
alarm(5);
```

The reach of that watchdog is bounded by what kind of sleep the thread is in, and the partition matters because this section's own neutralization failures land on the wrong side of it.

- *Interruptible sleep.* A `read()` on a pipe, a futex wait, a blocking `recvmsg` — the task is in `TASK_INTERRUPTIBLE`, a signal wakes it, and the `alarm()`-without-`SA_RESTART` recipe above delivers `EINTR` to your own code. This is the case the four lines cover.
- *The poll family.* `poll`, `select` and `epoll_wait` are never restarted after a handler runs; they return `EINTR` whether or not `SA_RESTART` was set. The flag is irrelevant there, so a stage blocked in `epoll_wait` is rescued by the alarm regardless of how the handler was installed.
- *Uninterruptible sleep.* A task in `TASK_UNINTERRUPTIBLE` — D state — does not take signals at all. A thread stuck in `__mutex_lock` on the corrupted mutex described above, or spinning on a garbage `qspinlock` word, is immune to `alarm()`, to `SIGKILL`, and to anything else you can send it. The only deadlines that apply are the out-of-process one, which kills the harness's patience rather than the task, and the kernel's own `hung_task_timeout_secs` / `hung_task_panic`.

That last row is the connection back to the neutralization section. A neutralization that writes the list head and leaves the lock word garbage does not produce a crash you can read; it produces a D-state consumer that your own watchdog cannot report, on a device that now has to be power-cycled. That is the concrete reason to verify the lock rather than only the list head.

Out of process, the harness needs its own wall-clock deadline per shot, and it must distinguish "ran long and was killed" from "produced nothing at all" — those imply different next actions.

The kernel has its own deadlines, and you should read them off the target before they surprise you ([Documentation for /proc/sys/kernel/](https://docs.kernel.org/admin-guide/sysctl/kernel.html)):

```
adb shell cat /proc/sys/kernel/panic_on_oops /proc/sys/kernel/panic_on_warn \
               /proc/sys/kernel/oops_limit \
               /proc/sys/kernel/hung_task_timeout_secs /proc/sys/kernel/hung_task_panic
```

`panic_on_oops` says whether a single oops ends the boot; `panic_on_warn` says whether a `WARN` does; `oops_limit`, default 10000, panics after that many oopses even when `panic_on_oops` is clear; `hung_task_timeout_secs` and `hung_task_panic` say how long a task can sit in D state before the kernel complains or panics.

Read those five numbers rather than assuming them, but expect the first to be 1 on an Android production kernel: the target this tutorial uses has `CONFIG_PANIC_ON_OOPS=y` and `CONFIG_PANIC_ON_OOPS_VALUE=1` in its `/proc/config.gz`. Where that holds, the distinction between oops and panic does not exist for you — one bad dereference is one reboot. That is a cost and also information, because it makes every failure loud. `panic_on_warn` deserves the same attention for a different reason: at 1, every refcount saturation, every `BUG_ON` softened to a `WARN`, and every KFENCE report becomes a reboot, which turns three of this section's own hazards from a log line into a lost boot.

## The sampler that changes your heap

KFENCE is in the instrument list below, but it belongs in the body because it is not only an observation tool — it is a hazard to the exploit, and an invisible one.

KFENCE diverts a small, randomly chosen fraction of slab allocations into a separate pool where each object "resides on a dedicated page, at either the left or right page boundaries selected at random", with the pages either side of it made guard pages ([KFENCE documentation](https://docs.kernel.org/dev-tools/kfence.html)). Two consequences follow for anything in this tutorial. An object that landed in that pool has no slab neighbours, so every adjacency technique in [section 05](05-heap-grooming-and-spraying.md) silently fails against it: there is nothing next to it to overflow into, and nothing to reclaim its slot. And a use-after-free on a KFENCE object is detected and reported rather than exploited, which under `panic_on_warn` is a reboot. A reader who sees an occasional death with no pattern and no reachable explanation has no way to attribute it to the sampler unless they know to look.

How often this happens is bounded by the sample interval, in milliseconds, exposed as a module parameter:

```
adb shell cat /sys/module/kfence/parameters/sample_interval
adb shell cat /sys/kernel/debug/kfence/stats
```

The parameter is registered with mode `0600` (`module_param_cb(sample_interval, ..., 0600)` in `mm/kfence/core.c`), so reading and writing it both need root; the stats file needs debugfs access. On the target build, `CONFIG_KFENCE=y` with `CONFIG_KFENCE_SAMPLE_INTERVAL=500` and `CONFIG_KFENCE_NUM_OBJECTS=63` — one candidate allocation every half second into a pool of 63 guarded objects. That is a low enough rate that it will not dominate a hit rate, and a high enough one that over a campaign of thousands of shots it will account for some of the deaths, so it is worth being able to name.

## Logging through the panic

When the machine dies mid-stage, stdout is gone. Buffered writes that never reached a file descriptor are gone; writes that reached the page cache but not the device are gone with it. The console log that survives the reset contains what the kernel printed, not what your exploit knew.

The kernel's half of that is pstore, and [section 03](03-crash-triage-and-root-cause-analysis.md) owns it: the ramoops RAM backend, which record to prefer and why, the SELinux asymmetry that lets you `cat` an exact filename while `ls` of the directory is denied, and the hazard that the next crash overwrites the records. Read it there. What belongs here is the pair of rules about your own half of the log.

The first is the phase-boundary rule. Write one short line per phase boundary to a file opened with `O_SYNC`, which makes each `write()` behave as though followed by `fsync()` — data and metadata are on the hardware before the call returns ([open(2)](https://man7.org/linux/man-pages/man2/open.2.html)). That cost is the reason the lines go at phase boundaries and never inside a timing-sensitive window: a synchronous write in the middle of a race window changes the race, so the instrument that was supposed to explain the failure becomes the cause of it. After the reboot, the file says which step was the last to complete.

The second is that `/dev/pmsg0` is a second channel for the case where the filesystem write is the thing that did not survive. `CONFIG_PSTORE_PMSG` "will export a character interface /dev/pmsg0 to log user space messages", and after the reset "data can be retrieved from /sys/fs/pstore/pmsg-ramoops-[ID]" ([fs/pstore/Kconfig, v6.1](https://github.com/torvalds/linux/blob/v6.1/fs/pstore/Kconfig)); `CONFIG_PSTORE_CONSOLE` in the same file is what makes `console-ramoops-0` carry the whole console stream rather than only the panic tail, and the RAM backend and the `dmesg-ramoops-N` record format are described in [Ramoops oops/panic logger](https://docs.kernel.org/admin-guide/ramoops.html). A write to `/dev/pmsg0` costs no filesystem at all, which is what makes it the right breadcrumb channel when the failure you are chasing might be storage-related. Read both back the way section 03 does, without assuming the root you are still trying to obtain:

```
adb shell cat /sys/fs/pstore/console-ramoops-0
adb shell cat /sys/fs/pstore/pmsg-ramoops-0
```

Which of these exist on your target is answerable directly: `zcat /proc/config.gz | grep -E 'PSTORE|KFENCE|KASAN|KPROBE_EVENTS|CFI_CLANG|DEBUG_MUTEXES'` when `CONFIG_IKCONFIG_PROC` is set. That one command tells you most of what your instrumentation budget is, and — with `CFI_CLANG` and `DEBUG_MUTEXES` in the pattern — most of what the neutralization section's constraints will be.

## Policy claims are measurable

"SELinux probably denies that" is not a finding. Every privilege claim in this section is a question with three cheap answers, and the same three work for any file:

```
adb shell ls -lZ <path>                       # DAC mode and the SELinux type
adb logcat -b events | grep avc               # the denial, if the access was attempted
adb shell dmesg | grep avc                    # same, where the audit goes to the kernel log
```

That settles the dynamic case: attempt the access and see whether a denial is logged against your domain and the object's type. For the static answer, pull the policy and query it on the host:

```
adb pull /sys/fs/selinux/policy
sesearch --allow -s shell -t <type> -c file ./policy
```

Use this before writing "usually" or "on most builds" anywhere. The three claims this section would otherwise have hedged are the read of `/sys/kernel/btf/vmlinux` (DAC `0444` from the source above, MAC per-policy, harvested here through `su` so the unprivileged case is unmeasured on this target), the `cat` of a named file under `/sys/fs/pstore` against the `ls` of its directory (section 03's asymmetry, checkable with `sesearch --allow -t pstorefs -c file`), and whether `bpftrace` can load a program at all from a shell domain, which is a policy question about `bpf` permissions and not a fact about Android in general.

## Success is a rate, not a result

An exploit that works four times in five is not "working with occasional failures"; it is an 80% exploit, and the number is the specification. The framing is standard in the reliability literature — reliability is "an exploit's failure rate", and a 90% reliable exploit fails one time in ten ([An Introduction to Exploit Reliability](https://blog.isosceles.com/an-introduction-to-exploit-reliability/)).

[Section 08](08-triggering-races-reliably.md) owns the statistics of a single stage: the four-way outcome vocabulary, why a point estimate cannot be compared against another point estimate, the Wilson score interval to report instead, the rule of three for a run with no observed failures (Hanley and Lippman-Hand, ["If nothing goes wrong, is everything all right? Interpreting zero numerators"](https://pubmed.ncbi.nlm.nih.gov/6827763/), *JAMA* 249(13):1743-1745, 1983 — with zero events in *N* trials the 95% upper bound on the rate is about 3/*N*, so "20 for 20" bounds the failure rate at roughly 15% rather than establishing determinism), and the trick of finding a proxy observable upstream of the win so that measurement does not cost a reboot per sample. `cves/lib/base/outcome.h` is the shared definition of the vocabulary for this project. What this section owns is what happens when several such stages are composed.

Before the composition, one methodological point that applies to the whole chain rather than to any one stage. A single run proves almost nothing, and the apparatus to copy is the one used in the academic work that reports reliability honestly: run the full chain a fixed large number of times, count a crash as a distinct outcome rather than a failure, and repeat across reboots to show the number is not an artifact of one boot's memory layout. Maar et al. run each technique 1000 times, mark system crashes explicitly, and "repeat the 1000 executions for 10 reboots, also demonstrating reliability between different reboots" ([When Good Kernel Defenses Go Bad, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/maar-kernel)). Reporting "100 % and 99.99 % reliability, respectively, with no crashes" is a claim you can only make with that apparatus behind it.

"An artifact of one boot's memory layout" is itself observable, which is what makes the across-reboots requirement more than a ritual. `/proc/buddyinfo` is mode 0444 and unprivileged, and a snapshot of it per shot shows the free-block counts per order that a spray is drawing from:

```
$ adb shell cat /proc/buddyinfo        # boot A, before the spray
Node 0, zone   Normal   3812   1190    402    118     31      6      1      0      0      0      0
$ adb shell cat /proc/buddyinfo        # boot B, before the spray
Node 0, zone   Normal   9044   2733    811    240     58     11      2      0      0      0      0
```

Two boots with order-0 free counts differing by more than a factor of two are two different grooming problems, and a hit rate measured on one does not transfer to the other. The root-only alternatives are `/proc/slabinfo` and `/proc/pagetypeinfo`, both mode 0400, which give the per-cache and per-migratetype views respectively. [Section 03](03-crash-triage-and-root-cause-analysis.md) explains what the columns mean and which instrument answers which allocator question.

## Composing stages, and which one to fix

A chain of stages with independent success probabilities multiplies, so a three-stage chain at 0.9, 0.5 and 0.8 is a 36% exploit. The usual next sentence — that the middle stage is the one to work on — does not follow from the product; it follows from the marginal gains, which are worth computing because they are not what intuition suggests:

| stage | current | driven to 1.0 | chain becomes | gain |
|---|---|---|---|---|
| A | 0.9 | 1.0 | 1.0 × 0.5 × 0.8 = 0.40 | +4 pp |
| B | 0.5 | 1.0 | 0.9 × 1.0 × 0.8 = 0.72 | +36 pp |
| C | 0.8 | 1.0 | 0.9 × 0.5 × 1.0 = 0.45 | +9 pp |

Measuring stages separately, with the later stages stubbed, is how you obtain the three numbers in the first column.

That table is still the wrong criterion on its own, because it prices every failure the same. A stage whose failure is a retriable miss costs one more shot; a stage whose failure is a panic costs a reboot, the boot's KASLR leak, and whatever heap state the campaign had built. Two stages with identical success probabilities are not equally worth fixing when one of them fails loudly.

Put the failure kinds into the model. Expected shots to first success is `1/p` where `p` is the product. Expected panics before first success is `P(panic per shot) / p`, since of the `1/p − 1` failing shots a fraction `P(panic)/(1−p)` are panics and the two factors cancel. Take the same chain under two distributions:

*Distribution I — every failure is a miss.* No stage panics. Expected shots to first success is `1/0.36 = 2.8`; expected reboots is zero. Fixing B to 0.9 takes the chain to 0.648 and the cost to 1.5 shots; fixing C to 1.0 takes it to 0.45 and 2.2 shots. B is the stage to fix, by the table above.

*Distribution II — stage C fails by panicking.* C is a blind write against a guessed address, so its 20% failure is a dead machine; A and B still fail as misses. Per shot, `P(pass) = 0.36` and `P(panic) = 0.9 × 0.5 × 0.2 = 0.09`, so expected reboots to first success is `0.09 / 0.36 = 0.25`. Now fix B to 0.9: `P(pass) = 0.648`, `P(panic) = 0.9 × 0.9 × 0.2 = 0.162`, and expected reboots is `0.162 / 0.648 = 0.25` — unchanged. It has to be, because the ratio reduces to `(1 − p_C) / p_C`; reboots per success depend only on the panicking stage, and no amount of work upstream of it moves that number. Fixing C to 1.0 takes expected reboots to zero. If a miss costs two seconds and a reboot costs sixty plus a re-leak, the baseline is about 21 seconds per success, fixing B is about 18, and fixing C is about 4.

So the same chain, with the same three probabilities, has a different stage worth fixing depending on how each stage fails. That is the reason the outcome vocabulary is not bookkeeping.

One assumption is doing work throughout: that the stages are independent. In practice they frequently are not, because a failed attempt does not leave the machine as it found it — a reclaim that missed has consumed the objects it sprayed and changed which slab the next attempt draws from, which is the entire subject of [section 05](05-heap-grooming-and-spraying.md) and [section 06](06-cross-cache-attacks.md). The symptom is a per-shot success probability that drifts within a boot and resets across one, and the check is the same one Maar et al. apply: compare the rate over the first hundred shots of a boot against the last hundred. Where it drifts, the product model is an approximation and the honest reporting unit is per-boot rather than per-shot.

## Composing probabilistic stages safely

Not every stage is a coin flip. An arbitrary read is idempotent and verifiable: you can perform it, check the result against something you already know, and perform it again. An arbitrary write is neither. A blind write to a guessed address is the one operation that converts a wrong guess into a dead machine, and it cannot be undone or checked afterwards.

The composition rule that follows is to never let a write be the verification step. Where a probabilistic stage has placed something at an address you believe you know, read that address back and compare it against a value you planted or a structure you can recognize — a magic word in a sprayed page, a `pipe_buffer` whose `->page` and `->len` have known values, a `cred` whose uid field still reads the pre-exploit uid — before the irreversible write goes out. The read turns a probabilistic stage into a deterministic one at the cost of one round trip, and it converts what would have been a panic into an ordinary retriable miss. In the cost model above, that is the transformation from Distribution II back to Distribution I.

Where no independent read exists, the alternative is to make the probabilistic stage itself deterministic with an oracle. SLUBStick is the clean demonstration: a cross-cache attack whose success is ordinarily a matter of luck becomes reliable when an allocator timing side channel tells the exploit whether the page it wants was actually recycled, "pushing the success rate to above 99 % for frequently used generic caches" ([SLUBStick, USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/maar-slubstick)). The structural lesson is the same one the read-verify rule expresses: reliability comes from adding an observation between the gamble and the commitment.

Some primitives are reliable for structural reasons rather than statistical ones, and it is worth knowing which category you are in. The Black Hat page-spray technique for Android argues its reliability from the absence of a constraint — "there is no limitation for spraying pages in the Linux kernel. Therefore, the technique gives us a reliable way to craft any data" ([Bad io_uring, Black Hat USA 2023](https://i.blackhat.com/BH-US-23/Presentations/US-23-Lin-bad_io_uring-wp.pdf)) — which is a different kind of claim from a measured hit rate and should be recorded as such.

## The harness is part of the exploit

Once success is a rate, a manual run is not an experiment, because it is not repeatable and it does not record its own conditions. What replaces it is a harness: a named configuration per chain that fixes the build, the stage order, and the environment; a driver that flashes or pushes the binary, verifies it actually arrived, runs one shot, classifies the outcome, collects the device-side logs including the ones written after the panic, reboots, and repeats until a budget is exhausted. Budgets matter separately per outcome class — a run that has consumed its panic budget is telling you something different from one that has consumed its attempt budget.

This is not an academic nicety; it is the difference between the exploit engineering that ships and the proof of concept that does not. The NCC Group Exploit Development Group's OffensiveCon 2023 talk on exploiting CVE-2022-0185, CVE-2022-0995 and CVE-2022-32250 makes the case explicitly: exploits used by consultants "need to be ultra-reliable and support many different OS variations and kernel versions", which calls for "a much more rigorous engineering process", including a heap analysis tool (libslub) and an automation platform for "mining, creation, deployment and scaling across many different environments" ([Exploit Engineering – Attacking the Linux Kernel](https://www.nccgroup.com/au/research-blog/offensivecon-2023-exploit-engineering-attacking-the-linux-kernel/)).

Two failure modes of ad hoc loops masquerade as low hit rates. The first is the stale binary: a push that was not synced before a panic-reboot reverts, and every subsequent shot runs the previous build. The defence is to hash the file on the device and compare it against the host after every push, unconditionally. The second is instrumentation left armed: a kprobe from the previous investigation is still enabled, and it changes the timing of every path it sits on, which is fatal when timing is what the stage depends on. A harness that removes its probes and restores `tracing_on` on every exit path, error paths included, is measuring the system; one that does not is measuring itself.

Boot identity is the third thing to record, because a KASLR base, a leaked address, or a groomed heap state is valid for exactly one boot. Keying cache staleness on the wrong identifier silently reuses a dead address, so key it on something that provably changes at boot. There are two candidates:

```
adb shell grep -m1 btime /proc/stat              # btime 1787984843
adb shell cat /proc/sys/kernel/random/boot_id    # a fresh UUID per boot
```

`boot_id` is exactly the kernel's per-boot identifier and is the obvious choice in general. This project keys on `btime` instead, for a reason specific to what its own chains do: the GhostLock stage relocates the pointer backing `/proc/sys/kernel/random/boot_id`, so sampled while the slide is in place the procfs file returns whatever that pointer now addresses rather than a boot id (`runner/lib/adb.sh`, `boot_epoch()`). Nothing in the exploit touches `btime`. The caveat on the other side is a mechanism one: `btime` is derived from wall-clock minus monotonic time, so an NTP correction or a `settimeofday` during a campaign changes it with no reboot, and the harness reads that as a false staleness verdict. Where both are trustworthy, sample both and treat a disagreement as a reason to invalidate the cache.

## Instruments

- `adb shell ls -lZ /sys/kernel/btf/vmlinux` — whether the target kernel carries its own type information, and under what label. The DAC mode is `0444` (`kernel/bpf/sysfs_btf.c`); whether an unprivileged domain may read it is an SELinux question, answered with the policy recipe above. Requires `CONFIG_DEBUG_INFO_BTF`, which GKI kernels set.
- `pahole -C <struct> <btf-blob>` — member offsets, sizes and padding holes for a struct on the exact kernel you are attacking. Host-side; with no file argument it reads `/sys/kernel/btf/vmlinux` on the local machine.
- `bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -A60 "STRUCT '<name>'"` — each member's `bits_offset` straight out of the kernel's type information, when pahole cannot read BTF. Divide by 8 for the byte offset. The `format c` variant is for compiling against the types; offsets computed from it are not authoritative, because BTF carries no alignment or packing attributes.
- `unpack_bootimg --boot_img boot.img --out .` (or `magiskboot unpack boot.img`), then `vmlinux-to-elf boot.img-kernel vmlinux.elf` and `readelf -sW` / `objdump -d` — symbols and disassembly for a stripped vendor image, recovered from the embedded kallsyms. Host-side. The extraction step is only needed when `vmlinux-to-elf` does not recognize the boot image directly; it handles the kernel's own compression itself.
- `echo 'p:<name> <fn> <f>=+OFF2(+OFF1($arg1)):u32' > /sys/kernel/tracing/kprobe_events` plus the matching `enable`, `echo 1 > tracing_on`, and a `trace_pipe` read — whether a function is reached, with what arguments, and what a chosen field contained on entry. Chain the dereference when the argument is a handle rather than the object. Needs root and `CONFIG_KPROBE_EVENTS`; mount tracefs if `/sys/kernel/tracing` is empty; remove the probe and restore `tracing_on` afterwards.
- `echo global > /sys/kernel/tracing/trace_clock` — required before any interval whose two ends may run on different CPUs, which includes every free-to-consumer measurement. The default `local` clock is per-CPU and its timestamps are not comparable.
- `bpftrace -e 'kprobe:<fn> { ... }'` — the same observation with less setup, where BPF and BTF are both usable. Needs root and a policy that grants the `bpf` permissions; check rather than assume.
- `cat /proc/sys/kernel/panic_on_oops /proc/sys/kernel/panic_on_warn /proc/sys/kernel/oops_limit /proc/sys/kernel/hung_task_timeout_secs` — how forgiving the target is about your mistakes, and whether a `WARN` costs you the boot. Readable unprivileged.
- `zcat /proc/config.gz | grep -E 'PSTORE|KFENCE|KASAN|KPROBE_EVENTS|CFI_CLANG|DEBUG_MUTEXES'` — which debugging, persistence and hardening features the shipped kernel was built with. Readable unprivileged when `CONFIG_IKCONFIG_PROC` is set.
- `open(path, O_WRONLY|O_CREAT|O_TRUNC|O_SYNC)` and one short line per phase — a progress record that survives the panic that ends the process. No privilege; costs a device write per line, so keep it out of timing windows.
- `adb shell cat /sys/fs/pstore/console-ramoops-0` (and `pmsg-ramoops-0`) — the console and userspace records from the previous boot. Needs `CONFIG_PSTORE_RAM` plus `CONFIG_PSTORE_CONSOLE` / `CONFIG_PSTORE_PMSG`, and a policy that permits reading the named file; listing the directory may be denied even where reading is not. See [section 03](03-crash-triage-and-root-cause-analysis.md).
- `ls -l /dev/pmsg0` — whether userspace has a persistent log channel of its own. Needs `CONFIG_PSTORE_PMSG` and write permission.
- `sigaction(SIGALRM, ...)` with `sa_flags = 0` plus `alarm(n)` — converts an indefinitely blocked interruptible syscall into a prompt `EINTR`. No privilege; `SA_RESTART` defeats it for restartable calls, is irrelevant for the `poll` family, and nothing rescues a task in D state.
- `cat /proc/buddyinfo` — free blocks per order, per zone; the cheapest per-shot record of how different two boots' allocator states were. Mode 0444, unprivileged. `/proc/slabinfo` and `/proc/pagetypeinfo` are the per-cache and per-migratetype views, both mode 0400 and root-only.
- `cat /sys/module/kfence/parameters/sample_interval` and `cat /sys/kernel/debug/kfence/stats` — whether the KFENCE sampler is active and how often it diverts an allocation onto its own guarded page, which is both a detector you may trip and a reason a grooming technique silently fails. The module parameter is registered `0600`, so root for both; needs `CONFIG_KFENCE` and debugfs access.

## Grounded in this project

The synchronous step log is `cves/lib/base/steplog.h`, which opens its file `O_SYNC` for exactly the reason above and documents why a step belongs at a phase boundary and never inside a window. The outcome vocabulary — pass, miss, permanent wall, refused-before-it-ran — is `cves/lib/base/outcome.h`, and the note there about collapsing a wall into a miss is the misattribution [section 08](08-triggering-races-reliably.md) describes. Wait-queue-style neutralization is implemented in `cves/lib/root/input_neut.h`, which defuses a freed `input_dev` by setting a single field so `input_open_device` short-circuits, and then reads every address back to confirm — the readback pattern this section recommends. `cves/lib/root/input_dev_find.h` locates the leaked devices on the kernel's global list. Both files state that the offsets are the caller's because they are per-kernel, and `input_dev_find.h` points at BTF as the way to obtain them. The interval-distribution measurement used to size the window between a free and its first consumer is `cves/lib/trace/interval.h`, built on `cves/lib/trace/fnprobe.h`. The probe-hygiene rules — every probe removed and tracing restored on the way out, every probe filtered to one process — are in `cves/lib/tools/kprobe.sh`. Boot-identity staleness is keyed on `/proc/stat` `btime` by `boot_epoch()` in `runner/lib/adb.sh`, which records why `boot_id` is unusable here. The `SIGALRM`-without-`SA_RESTART` watchdog around a blocking read primitive is in `cves/cve-2026-43049-ffwheel/ffroot_w.c`, and the problem of a process whose own address space has been forged, and which must therefore avoid faulting and avoid being scanned, is `cves/lib/base/mmguard.h`.

## See also

- [01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md) — establishing that the bug is present on the target before measuring anything about exploiting it.
- [03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md) — pstore mechanics, the CFI failure signature, and the allocator instruments this section only samples.
- [05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md) — the stage whose hit rate usually dominates the product, and where the independence assumption breaks.
- [06-cross-cache-attacks.md](06-cross-cache-attacks.md) — the most probabilistic stage in a typical chain, and the one most in need of a verifying read.
- [07-read-write-primitives.md](07-read-write-primitives.md) — why an arbitrary read composes safely ahead of an arbitrary write.
- [08-triggering-races-reliably.md](08-triggering-races-reliably.md) — the statistics of a single stage, and the interval measurements this section reuses.
- [09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md) — the irreversible writes that the verification discipline here is meant to protect.
- [11-case-studies.md](11-case-studies.md) — chains where the stabilization step is what made the difference.
- [12-further-reading-and-glossary.md](12-further-reading-and-glossary.md) — sources and terminology.
