# Case Studies: Techniques Applied End to End

The preceding sections each isolate one technique. A chain does not arrive isolated: it
arrives as a bug class, a reachability argument, an address problem, a placement problem, a
primitive, an escalation, a debt left in kernel memory that somebody has to pay before the
device is usable again, and a reliability record. Two chains in this repository have been
taken the whole way on hardware — each starts from an unprivileged shell and has ended at
uid 0 there — and they are worth reading side by side precisely because they solve the same
eight problems by different means. How firmly each is recorded as finished differs, and
differs in kind: one is carried as a composed, hardware-verified stage with no per-shot rate
recorded anywhere, the other as a stage still marked uncomposed whose own documentation
publishes a census of six roots in thirty-two attempts. Each study's reliability section
states its chain's record and where that record comes from.

They are examined here in the same order every time, so that a difference between them is
visible as a difference rather than as a change of subject: what the defect is, what
privilege and interface reach it, where kernel addresses come from, how memory is arranged,
what primitive the bug yields and how it is made usable, how that primitive becomes root and
what happens to SELinux, what keeps the device alive afterwards, and how reliable the result
is in the terms the documentation itself uses.

Two conventions, before either study. The codenames — GhostLock, FFWheel — are this
repository's own labels. Neither appears in the upstream commit, the CVE record or the
Android bulletin, so the CVE identifier is the name to use outside this tree. And the
repository appears here only as an illustration: every mechanism below is stated so that it
stands without opening a single file in this tree, and where a claim is specific to these
chains rather than general, it is attributed to the file that records it so a reader can
check it or discount it.

## The template, and the layout question that precedes both

Both chains aim a write at a byte offset inside a kernel structure, on a kernel they cannot
rebuild and whose headers they do not have. Neither can proceed without recovering that
layout first, and both recover it the same way: from the kernel's own
[BTF](https://docs.kernel.org/bpf/btf.html), pulled once and read on a workstation.

```
adb pull /sys/kernel/btf/vmlinux ./btf-vmlinux && pahole -C cred ./btf-vmlinux
```

The configuration requirement (`CONFIG_DEBUG_INFO_BTF=y`, which GKI sets) and the SELinux
caveat on reading the file from a device are in
[06-cross-cache-attacks.md](06-cross-cache-attacks.md#knowing-which-caches-you-are-between);
the reconstruction routes for a kernel that gives up neither symbols nor types are in
[04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md#recovering-structure-layout-and-symbols-without-rebuilding-the-kernel).
What the output licenses is the byte offset of every field on *that* build and the size class
the object falls into, and nothing about any other build — which is why both chains carry
their offsets as per-target data rather than as constants, and why
[07-read-write-primitives.md](07-read-write-primitives.md#aiming-a-primitive-needs-the-targets-own-offsets)
treats aiming as an offset problem before it is a write problem.

Size alone does not settle which cache an object lands in. Allocations tagged
`GFP_KERNEL_ACCOUNT` go to the separate `kmalloc-cg-*` set, reclaimable ones to
`kmalloc-rcl-*`, some types carry a dedicated cache, and SLUB merges compatible caches so one
visible name can cover several types
([05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md#merging-aliasing-and-what-the-cache-names-hide)).
The cheap checks — `/proc/slabinfo` and `/sys/kernel/slab/<cache>/aliases`, both root on a
production device, with the unprivileged symlink listing behind them — come before any
exploitation step. One of the two chains below sidesteps the question entirely, because its
victim object is too large for any general cache; that is a property of the object, and it is
established by the same `pahole` command.

## GhostLock — CVE-2026-43499

### The defect

`remove_waiter()` in `kernel/locking/rtmutex.c` is reached both from the slow-lock paths and,
as proxy-lock rollback, from `rt_mutex_start_proxy_lock()` under `futex_requeue()`. In the
second case `waiter::task` is not `current`. The red-black tree dequeue therefore ran without
the waiter task's own `pi_lock`, that task's `pi_blocked_on` was left dangling, and
`rt_mutex_adjust_prio_chain()` walked the wrong task. The dangling pointer is what makes this
exploitable rather than merely wrong: `futex_wait_requeue_pi()` allocates the
`rt_mutex_waiter` on the *waiting thread's kernel stack*, so the priority-inheritance chain
goes on naming a node in a frame that has since returned, and any later priority change
re-reads it.

`cves/cve-2026-43499-ghostlock/README.md` records the fix as
[`rtmutex: Use waiter::task in remove_waiter()`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=3bfdc63936dd4773109b7b8c280c0f3b5ae7d349),
[announced 2026-05-21](https://ratatoskr.run/linux-cve-announce/2026/05/17014263) and
backported to the stable branches; it is catalogued at
[OpenCVE](https://app.opencve.io/cve/CVE-2026-43499),
[Ubuntu](https://ubuntu.com/security/CVE-2026-43499),
[SUSE](https://www.suse.com/security/cve/CVE-2026-43499.html) and
[Oracle](https://linux.oracle.com/cve/CVE-2026-43499.html) at high severity, and the affected
range spans most of the kernel's history with priority inheritance in it. That range is not
the presence test. The same README states the discriminator directly: whether the shipped
kernel's own `remove_waiter()` reads the waiter's task field or `current`, read out of the
build rather than inferred from its version, because the Android Common Kernel backports on
its own schedule and carries this fix at a point upstream numbering would say it should not
be there yet. That is the general argument of
[01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md#deciding-whether-this-build-has-the-patch),
and the source-reading technique it needs is
[there too](01-vulnerability-discovery-and-patch-triage.md#reading-the-fix-out-of-the-builds-own-source).

### Reaching it

Nothing is required beyond ordinary syscalls: the README states that the whole sequence is
unprivileged — no capability, no device node, no special file. The reaching sequence is six
calls across four threads, and the futex operations are the interesting part only in that
they set up the dangling node; the rest is arranging for the frame to be re-occupied and for
a priority walk to happen.

```
thread W   futex(&f_pi_chain,  FUTEX_LOCK_PI)
thread O   futex(&f_pi_target, FUTEX_LOCK_PI)
thread W   futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, …, &f_pi_target)
main       futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, 1, &f_pi_target)
thread W   pselect(nfds, &in, &out, &ex, {1s}, NULL)
thread C   sched_setattr(waiter_tid, SCHED_BATCH nice 19)
```

A reachability argument this short is unusual and worth noticing for what it does *not*
contain: no group membership, no device label, no policy question. The four gates that
normally decide a candidate —
[02-reachability-and-attack-surface.md](02-reachability-and-attack-surface.md#discretionary-access-control-uids-aids-and-supplementary-groups)
and the sections after it — are all cleared by construction, because every interface involved
is one every process already has.

### Kernel addresses

The image base comes from the shared write-free tracefs leak, described in
`cves/lib/kaslr/README.md`, and is called unconditionally before anything else. Writing a
marker string to `trace_marker` makes the kernel's own write handler store `_THIS_IP_` — a
code address — into the print record it reserves; the formatted view under `trace` renders
that pointer through a symbol formatter, but a raw read of the per-CPU `trace_pipe_raw`
returns the ring-buffer sub-page verbatim with the pointer still in it.
`kptr_restrict` does not apply, because it governs the pointer-hiding format specifier and
this value never passes through one. The record layout is a fixed header, then `ip`, then the
marker string, so the leaked pointer is the eight bytes immediately preceding the marker in
the raw page, and the base is one subtraction away:

```
stext = leaked_ip - SLIDE_TRACE_MARK_IP_OFF
```

The same file records the properties that make this the leak of choice for both chains: it is
exact and single-shot rather than a candidate set to sift, it costs tens of milliseconds, it
enables no ftrace event (event enabling, the format directories and the tracing instances are
all denied to the shell, and none is needed), and it cannot panic. The recovered value is
gated before it is believed — it must look like a slid kernel-text pointer *and* its offset
within the page must equal the known page offset of the marker's own instruction — and a
value failing the gate is discarded rather than used. The leak class this belongs to, and the
other tracefs routes that do not survive policy, are in
[04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md#tracing-and-debug-subsystems).

The image base is not the only address this chain needs. The forged node names a lock, a task
and an operations table by absolute address, so the address of the page those objects will
occupy has to be known before its bytes are painted. That one comes from a timing side
channel on the futex hash, after
[KernelSnitch](https://lukasmaar.github.io/papers/ndss25-kernelsnitch.pdf) (NDSS 2025), which
recovers the kernel address of an object the exploit allocated itself, with no root and no
kernel primitive
([04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md#microarchitectural-side-channels)).
The block that object sits in is then freed and reclaimed by the spray below, so the
fabricated structures are written with absolute pointers into a page whose address is already
in hand. The same routine runs a second time later, for the page the pipe ring is steered
onto when the physical read/write is built.

### Arranging memory

There is no heap spray in the reclaim step. The freed object lives on a kernel stack, so what
has to be arranged is a *frame overlay*: `core_sys_select()` keeps its six descriptor-set
copies in a fixed on-stack buffer whenever they fit, so a `pselect` call sized to make them
fit turns descriptor-set word *N* into the corresponding word of a forged `rt_mutex_waiter`.
One routine paints that map — the exception set carries the task pointer, the fake lock
pointer and the value the walk compares against — and `sched_setattr` on the parked thread
drives the priority walk into it.

*N* is the whole trick, and the README is emphatic that it is not a kernel-version constant:
it is set by the compiler's frame layout for the two paths, so two builds of one version can
differ, and one of them can place the waiter outside the descriptor-set region altogether.
The value is computed from the build's own image as a difference of frame sums, with both
slots read from argument positions rather than guessed:

```
waiter       = sum(frames from invoke_syscall to futex_wait_requeue_pi) - waiter slot
fds          = sum(frames from invoke_syscall to core_sys_select)       - stack_fds slot
landing_word = (waiter - fds) / 8
```

Where a helper was inlined or renamed by link-time optimization the rule follows the clone,
and where a link in the chain was inlined away entirely it reports the value unresolved
rather than wrong. The basis for acting on that rule's answer for a build nobody has run is
narrow, and the README states it rather than assuming it: the rule reproduces the committed
shift on the one target that has been verified on hardware, and reports unresolved instead of
guessing where the derivation no longer describes the build. A wrong value is not a build
error but a panic at the moment of the
unlink, which is why the payload gates the resolved shift against the placement window
*before* the KASLR leak is taken: the word map runs from its first index to the lock index
and the painting routine reaches only the input sets, so a shift outside that range cannot
place the lock pointer at all, and the shot ends before the race is armed. A target whose
waiter lands outside the region refuses itself at no cost.

A second vehicle exists, the zero-copy receive descriptor in `do_tcp_getsockopt()`, which
gives contiguous control of the whole structure with no slide to derive. Its bound is a
version bound with no workaround: the two words that must carry the waiter's task and lock
pointers are fields added to that structure part-way through the kernel's history, and on an
older kernel the copy truncates, neither word is written, the walk follows whatever the
previous frame left behind, and the README records the result as a certain panic with no
tunable that helps. The runner refuses that pairing at build time with a named gate rather
than discovering it on the phone.

Separately from the frame, the chain does need a kernel page whose contents it controls,
because the forged node must point somewhere. The README describes reclaiming one through a
fork, a memfd and a run of socket fragments — an ordinary page-level placement of the kind
catalogued in
[05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md#the-object-catalogue) —
aimed at the block the side channel above named, which is what lets the sprayed bytes be
self-referential.

### The primitive

What the priority walk performs is a red-black tree unlink, not a store, and that is what
makes it usable. `struct rb_node` is three words — the packed parent-and-colour word at 0,
the right child at 8, the left child at 16 — which is a stable kernel fact, confirmable from
the header or from `pahole -C rb_node` rather than measured per build the way the waiter and
task field offsets are. Erasing a node with exactly one child performs exactly two stores:

```
mem[forged_parent + child_slot] = forged_child      /* the child pointer update */
mem[forged_child  + 0]          = forged_parent     /* the parent-and-colour word */
```

Both always land, and which of the two is payload and which is collateral is a property of
how the attacker fills the node rather than of the primitive. The forged node carries the
fake page in its parent-and-colour word and the address of the ashmem miscdevice's
`file_operations` pointer in a child slot. So it is the *parent-and-colour* store that
installs the forged operations table — the erase writes the erased node's parent word
verbatim into the object it takes for the child, which is the shared slot — while the
child-pointer store lands inside the attacker's own page. That word arrives with the colour
in its low bits, which is why the destination has to tolerate them: the fake page's address
must be aligned and the colour bit left clear for the installed pointer to be exact. Which
child slot holds the destination is a per-build detail rather than the general case: one
kernel flavour of this chain puts it in the right child at +8 and the other in the left child
at +16, and the erase reaches the same pair of stores either way.

The step that turns that into something usable is the one worth copying. Before anything
irreversible happens, the chain reads the miscdevice's operations pointer back and fails
unless it already equals the fake page, then proves both an 8-bit and a 64-bit write, with
read-back, through two forged handlers whose signatures are legal under
[control-flow integrity](https://source.android.com/docs/security/test/cfi). Only then does it
build the physical read/write over a pipe buffer, and that too must round-trip both widths
against a proof page in both directions before it returns. The promotion ladder — narrow and
verifiable first, general second, irreversible last — is
[07-read-write-primitives.md](07-read-write-primitives.md#promoting-a-primitive), and the
discipline of reading before writing is
[there too](07-read-write-primitives.md#read-before-you-write). Forging an operations table
and driving it through a legitimate interface is the pattern in
[07-read-write-primitives.md](07-read-write-primitives.md#forging-objects-through-legitimate-interfaces).

### Root, and SELinux

The install runs against a pre-forked child. It finds the task from
[`init_task`](https://docs.kernel.org/security/credentials.html)'s neighbour, falling back to
walking the task list by thread-group id — the choice of `tgid` as the match key, and the
bounded-iteration rules that make such a walk safe, are
[09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md#finding-the-cred-that-matters).
Every dereferenced address is a linear-map alias, and the library's address model is typed by
the space an address belongs to, so handing a primitive an image-relative or slid-runtime
address is a compile error rather than a fault on the device.

Three edits follow, and they map one-to-one onto the three gates that
[09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md#the-object-that-decides)
enumerates. The `cred` object is patched: uids, gids and securebits zeroed, all five
capability words filled and read back, and the SELinux object and subject identifiers set to
the kernel's. The task's seccomp state is cleared — the thread flag, no-new-privs, and the
filter mode, count and pointer
([the third gate](09-privilege-escalation-to-root.md#the-third-gate-seccomp)). And a zero byte
goes over the global SELinux enforcing flag
([the second](09-privilege-escalation-to-root.md#the-second-gate-selinux)).

Durability is a separate stage. The released child drops to uid and gid zero, writes zero to
the SELinux enforce node, and installs an embedded `su` helper: copied onto a tmpfs, labelled,
and launched as a daemon that listens on a Unix socket, authorizes callers by peer uid against
the client and app uids it was given, and hands them root shells, file descriptors, or a
KernelSU module late-load. That daemon is the stage that supplies `CAP_SU`. The general shape
— a one-shot privileged process converted into a reachable service — is
[09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md#how-rooting-frameworks-structure-the-grant).

### Keeping the device alive

The debt this chain leaves is the clearest example in either study of a corruption that is
*restored* and still not *repaired*. The forged write lands in the miscdevice's operations
pointer, which the whole system shares, and `misc_open()` copies that pointer into each new
`struct file`:

```c
const struct file_operations *new_fops = fops_get(c->fops);   /* our page */
...
file->f_op = new_fops;
```

Restoring the slot therefore repairs the *device* and not the *files*. Every open of the
ashmem device that happened while the slot was forged produced a file whose operations
pointer aims into the exploit's page for the life of that descriptor, and the README states
plainly that nothing in the chain can walk those files back. The page is a socket fragment:
it dies with the payload process, returns to the buddy allocator and is reused, and from that
moment each surviving file is a landmine. The faults are all one fault — something touched
the operations pointer — arriving as a close path putting the module reference, as a fresh
open taking one, and as the descriptor-info file in procfs calling through the table to print.
The last can fire long after the run reports success, by which time the page holds unrelated
data, which is why a faulting address that byte-swaps into a readable string is the signature
of this class rather than of a wild write
([03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md#telling-your-bug-from-their-bug)).

The chain bounds the exposure in two places and does not close it. The restore happens as
early as the sequence allows — the descriptor opened for verification captured the operations
table at `open()` and keeps it, so the shared slot only has to stay forged for that one call —
which shrinks the window to a few syscalls rather than the whole install. And the fake table's
module-owner word is zeroed at the end, because a put on a poisoned file calls `module_put()`
on whatever that word holds, and a zero there is the difference between a clean close and an
oops. The README names what would actually close it, and records it as not done: keeping the
page alive for the boot by handing its holder to the surviving `su` daemon instead of dropping
it on process exit, since a poisoned file is harmless while the page exists and the refresh
already points the operations the platform calls at the genuine ashmem functions. That is
neutralization rather than repair, in the sense of
[10-survivability-and-measurement.md](10-survivability-and-measurement.md#neutralizing-rather-than-repairing),
and it is the one piece of debt this chain leaves outstanding.

The operations pointer is not the only shared object the unlink is aimed at, and the stage
manifests are where that shows: each names two destructive targets and two restores. Besides
the miscdevice's operations pointer they name a kernel logger slot, because a second route to
the image base drives the same pair of stores at the `boot_id` sysctl's data pointer, so that
reading that procfs file returns kernel memory at a logger slot — which is also where the
other store of the pair lands.
The restores answer both — the logger slot is repaired, and the sysctl's data pointer is
repointed at the genuine value in the same early step that restores the operations slot,
gated on reading it back. The last step of the chain then re-reads the operations slot to
prove that restore held before it zeroes the fake table's module-owner word, so neither
repair is left assumed.

A won race can also panic later on a different path: the boost kthread can fault in the
priority-inheritance walk on state the exploit left behind, well after the racing thread
finished. Both classes of late fault are read out of the previous boot's console, which
[pstore/ramoops](https://docs.kernel.org/admin-guide/ramoops.html) preserves across the reboot
and which needs no root
([03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md#persistent-crash-storage)):

```
adb shell cat /sys/fs/pstore/console-ramoops-0
adb shell getprop sys.boot.reason.last
```

Policy grants shell read on pstore files but not on listing the directory, so a named file
opens and `ls` does not, and the boot-reason property separates a panic from a clean reboot
before anything is parsed.

### Reliability

The documentation's own terms are narrow and worth quoting rather than paraphrasing into a
number. The stage manifest records the entry as `composed; hardware-verified on panther`,
which is a statement about a composition having been driven to root on a device and not about
how often it does. No per-shot rate is recorded anywhere for this chain, and none should be
inferred from that phrasing; the other study below records the opposite pair, a manifest that
still says uncomposed and a measured rate.

What *is* documented is the structure that makes a failed shot readable. The payload runs each
attempt in a freshly forked process, up to a small fixed number of attempts, so that no thread
or futex state leaks between tries. The race is the step that drives the walk into the page
the reclaim built, and a lost race sends it elsewhere. The vehicle prints per-attempt call and
success counts, and those two numbers separate the two failure modes: no calls at all means
the consumer never reached the forged table and the placement did not take, while calls
without success means it was reached and the write did not verify. A signal always runs the
verification stage whatever the vehicle returned, because by then the write has already taken
effect system-wide and that stage is the only path that restores it. Finally, the payload
prints one resolved-configuration line per shot naming what it resolved and where each value
came from, and the runner asserts that this matches the request — which closes the gap where a
knob accepted on the command line is silently ignored by an artifact built before that knob
existed, a failure otherwise indistinguishable from success. Reporting in these terms rather
than as pass or fail is
[08-triggering-races-reliably.md](08-triggering-races-reliably.md#why-hit-rate-not-passfail)
and [10-survivability-and-measurement.md](10-survivability-and-measurement.md#success-is-a-rate-not-a-result).

## FFWheel — CVE-2026-43049

### The defect

`hidpp_probe()` publishes the device to userspace with `hid_connect()` and only then calls
`hidpp_ff_init()`. If force-feedback initialization fails, the probe returns that error on its
normal fallthrough and never reaches the label that would call `hid_hw_stop()`:

```c
    ret = hid_connect(hdev, connect_mask);          /* registers input_dev */
    if (ret) { ... goto hid_hw_init_fail; }

    if (hidpp->quirks & HIDPP_QUIRK_CLASS_G920) {
        ret = hidpp_ff_init(hidpp, &data);
        if (ret)
            hid_warn(...);                          /* the fix adds ret = 0 here */
    }

    hid_hw_close(hdev);
    return ret;                                     /* returns the FF error */
```

`hid_device_probe()` responds to the error by clearing the device's driver pointer, which
makes the later `hid_device_remove()` a no-op, so `input_unregister_device()` is never called.
The input device leaks permanently, and when the attacker closes `/dev/uhid` the
`struct uhid_device` behind it is freed while `/dev/input/eventN` still routes straight back to
it. `cves/cve-2026-43049-ffwheel/README.md` is careful about two things that look like the bug
and are not. The freed reports are a red herring: `hid_close_report()` memsets every report
enumeration and all consumers reach reports through it, so they walk empty lists and fail
cleanly. And the HID device itself survives, because connecting the input device set its parent
to the HID device and that child reference keeps the release from running — which is exactly
why `hid->driver_data` stays readable while pointing at memory the uhid release has already
freed:

```
open("/dev/input/eventN")
  -> hidinput_open -> hid_hw_open(hid) -> hid->ll_driver->open
  -> uhid_hid_open(hid):  uhid = hid->driver_data;        /* FREED */
                          uhid_queue_event(uhid, UHID_OPEN);
```

The fix is two lines — swallow the error so the probe succeeds and nothing leaks — landing
upstream as
[`f7a4c78bfeb3`](https://git.kernel.org/linus/f7a4c78bfeb320299c1b641500fe7761eadbd101) and
cherry-picked into the Android Common Kernel as
[`20130e92480a`](https://android.googlesource.com/kernel/common/+/20130e92480a) and
[`0e9b1ff406b1`](https://android.googlesource.com/kernel/common/+/0e9b1ff406b1). It is
catalogued at [OpenCVE](https://app.opencve.io/cve/CVE-2026-43049) and
[Ubuntu](https://ubuntu.com/security/CVE-2026-43049), and the Android advisory is the
[September 2026 bulletin](https://source.android.com/docs/security/bulletin/2026/2026-09-01),
which rates it high under human interface devices. As with the other chain, presence is read
out of each shipped kernel's own `hidpp_probe()` rather than inferred from a version. Both
READMEs record the same boundary: the newest builds carry both fixes, so the build a device is
on, not its model, is what decides whether either chain applies.

One structural note, because it is easy to misclassify this bug from its outcome. The
use-after-free is a lifetime error, not a race: `hidpp_ff_init()` opens by rejecting any device
that is not on a USB bus, and that test inspects the low-level driver, so for a virtual wheel
the failure is *deterministic*. The probabilism in this chain is entirely in the reclaim and
the address guess, not in reaching the free — which is the opposite arrangement to the
check-then-use shapes of
[08-triggering-races-reliably.md](08-triggering-races-reliably.md#the-shape-of-a-check-then-use-bug),
and worth separating when triaging a candidate.

### Reaching it

An unprivileged `adb shell`, through two facts about the interface. The shell user is in the
`uhid` group, so it may create a virtual device through
[`/dev/uhid`](https://docs.kernel.org/hid/uhid.html); and `hid_match_id()` compares only bus,
vendor and product, with nothing checking that a device claiming to be on a USB bus really is.
Group membership as the deciding gate is
[02-reachability-and-attack-surface.md](02-reachability-and-attack-surface.md#discretionary-access-control-uids-aids-and-supplementary-groups);
that both the DAC and the MAC answer have to be checked separately, and measured rather than
assumed, is
[the section after it](02-reachability-and-attack-surface.md#mandatory-access-control-selinux-domains-as-the-real-gate).

Reaching the vulnerable line then costs some protocol work, and the README is specific about
why each piece is load-bearing. The report descriptor must carry all three HID++ reports —
short, long and very long — or the probe never reaches the bug: reading the wheel's
configuration ends in setting autocentre, which sends more parameters than the long report can
hold, and the synchronous send selects the very long report for any such request, so without it
that send fails, configuration returns an error, and the probe takes the safe teardown path
with no bug at all. Answering the protocol is cheap, because the driver's matching compares
only two bytes of the report, so echoing them back is most of the work; unknown feature queries
are answered with a protocol error reply so the driver fails fast instead of blocking in its
wait. The front-end that does this is `cves/lib/trigger/uhid.c`, shared rather than
chain-specific.

### Kernel addresses

Three sources, each answering a different question.

The image base is the same write-free tracefs leak described above, which supplies the callback
and operations addresses the forged objects need.

The physical address space is reached by arithmetic rather than by a leak, because the
[linear map](https://docs.kernel.org/arch/arm64/memory.html) is not randomized — the property
that makes a frame number usable as an address at all, and the reason it is worth establishing
early
([04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md#the-linear-map-is-not-randomized-and-that-is-a-usable-fact)).
The README flags one correction as easy to get wrong: the
[pagemap](https://docs.kernel.org/admin-guide/mm/pagemap.html) interface reports frames relative
to physical address zero, while the page-descriptor array is indexed from the start of RAM, so
the physical offset of RAM has to be subtracted when converting a frame number into a
descriptor. The two conversions are not inverses of each other, and
[04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md#pfn-to-linear-va-to-struct-page)
works both through.

The process's own `mm_struct` address — the address the whole read chain starts from — comes
from the same futex-hash timing side channel the other chain uses, put to a different question:
there it names a page about to be reclaimed, here the address space object of the calling
process itself. It needs no root and no kernel primitive. The class it belongs to is
[04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md#microarchitectural-side-channels).
Everything else the chain needs — its own credential address, a real pipe's `pipe_inode_info` —
is *read* rather than leaked, through the primitive described below. The README records why:
both objects round up into a small slab cache, and every direct-leak avenue on this platform is
closed (the asynchronous I/O and performance interfaces are denied by SELinux, the kernel symbol
list is denied, System V IPC is not configured, and the side channel reaches only the address
space object).

### Arranging memory

`struct uhid_device` is large enough that its allocation bypasses the slab caches entirely and
is served by the page allocator, and the matching free returns it straight to the buddy
allocator. This is a page-level use-after-free: a plain `kfree` on the attacker's own processor,
with no [RCU](https://docs.kernel.org/RCU/whatisRCU.html) deferral to wait out and no
cross-cache step to arrange. The whole apparatus of
[06-cross-cache-attacks.md](06-cross-cache-attacks.md#what-the-page-allocator-does-with-a-surrendered-slab)
is therefore unnecessary here, which is itself the lesson: an object's size can remove a stage
from a chain, and it is worth checking before designing that stage.

The reclaim vehicle is a datagram left unread in a Unix-socket receive queue, sized so that
payload plus `skb_shared_info` exceeds the largest slab cache. It then takes the same
large-allocation path at the same order as the victim, with no headroom, so the payload offset
equals the structure offset and the whole object is attacker bytes. The README records the
alternatives as unusable rather than merely unchosen: the key-management and extended-attribute
paths refuse the sizes involved, and the pipe ring's content is a structure whose own fields land
on the wait queue.

Order and processor are the two constraints that survive.
[06-cross-cache-attacks.md](06-cross-cache-attacks.md#order-must-match-or-the-page-is-gone) and
[the section after it](06-cross-cache-attacks.md#cpu-must-match) give the general argument —
a free at or below `PAGE_ALLOC_COSTLY_ORDER` goes onto the per-CPU pageset, which is served
last-in-first-out, so a spray on another processor is drawing from a different list. What
FFWheel's README adds is the measurement for its own vehicle: scored by frame number against
the kernel's memory tracepoints, an unpinned spray takes the page essentially never, and a
same-processor spray with no delay takes it — *reliably* is the README's word, and the
end-to-end census in the reliability section below is what bounds it, with the reclaim landing
in 21 of 32 shots. Hence the spray fires with nothing at all between it and the close.

The window is short and not under the exploit's control, and the README establishes who owns it
by tracing non-destructively — creating the same device and never freeing it. The close event
the probe loop stops on, and therefore the moment the device is freed, arrives *before* the
leaked input node even appears; the platform's input reader takes that node as soon as it does
and holds it for good; a later open arrives with no matching close, and an open and close of the
exploit's own from the shell produces no close either. So the wake-up that runs the controlled
call belongs to that reader, a few milliseconds after the free, and the exploit's own open exists
only as a fallback for a node nobody else opens. Establishing who fires a trigger by observation
rather than by assumption, and placing the reclaiming allocation against it, is
[08-triggering-races-reliably.md](08-triggering-races-reliably.md#placing-the-second-thread-in-time);
measuring the interval before trying to hit it is
[the earlier section](08-triggering-races-reliably.md#measuring-the-window-before-trying-to-hit-it).

### The primitive

The queueing function running on the reclaimed page reaches a wake-up on the device's wait
queue, which walks a list calling each entry's function pointer with fully controlled arguments.
Under [control-flow integrity](https://clang.llvm.org/docs/ControlFlowIntegrity.html) the target
must be a genuine `wait_queue_func_t`, which constrains what can be called without preventing
the call — the distinction
[03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md#cfi-traps-and-what-they-actually-prove)
draws between a mitigation that stops an attack and one that narrows it. Marking the forged entry
exclusive and returning non-zero breaks the walk after exactly one call, so there is no second
iteration and no list removal, and the list-debugging checks never fire. The forged wait entry
lives entirely in the reclaim page:

```
  [waitq.lock]      = 0
  [waitq.head.next] = A                  /* the fake entry */
  [waitq.head.prev] = A
  [qlock]           = 0
  [head]            = 0                  /* newhead = 1 */
  [tail]            = 5                  /* head != tail -> the write branch */
  [A-24] flags   = WQ_FLAG_EXCLUSIVE
  [A-16] private = <argument for func>
  [A- 8] func    = <a CFI-valid wait_queue_func_t>
```

Pointing the callback at `ep_poll_callback` and forging the object graph it walks in the same
page turns that call into a write: its open-coded lockless list append is not covered by the
list-debugging checks and executes a store of a pointer into an attacker-chosen location. The
shape of the resulting primitive is what everything above it has to be designed around, and the
README states its two limits directly. The value stored is fixed — always a pointer into the
attacker's own page, never an arbitrary 64-bit value — and the store also clobbers the first two
words at that destination, so anything forged there must tolerate being overwritten. That second
limit is why the task's credential pointer cannot simply be redirected at a forged `struct cred`:
the identity fields would land inside the self-clobber. Every field the walk touches — in the
epoll item, the poll entry and the eventpoll object — is taken from the kernel's own BTF rather
than from a header read by eye.

Two promotions follow from that one store, and neither is the other's inverse.

A pointer-only write cannot install a page pointer into a pipe buffer, because that needs a real
page-descriptor address. So it redirects the buffer *array* pointer instead, aiming the pipe at a
slot crafted inside the attacker's own page, clear of the live fields of the structure sharing it,
with the pipe primed on its real array first so the ring position lands on the crafted slot after
the redirect. Read is then the kernel's own code doing the work: the slot holds a real page
descriptor and the genuine anonymous-pipe operations, so the next `read(2)` copies the chosen
physical page out verbatim. Write uses the merge fast path — with the slot marked mergeable, its
offset and length zeroed, and the ring primed so the position matches, `pipe_write()` copies
straight into the existing page with no allocation and no indirect call, the same primitive shape
as [Dirty Pipe](https://dirtypipe.cm4all.com/), with the payload landing at any byte offset of the
chosen physical page
([07-read-write-primitives.md](07-read-write-primitives.md#dirty-pipe-one-uninitialized-flag)).

The second promotion is the one that removes the need for a privileged probe anywhere in the
chain. The same store redirects the address space's
[maple tree](https://docs.kernel.org/core-api/maple_tree.html) root at a forged VMA; a
sufficiently aligned root is a single-entry tree returned verbatim, so the procfs map walker
treats it as one mapping and renders its file's path. That path walk takes no references and
makes no CFI-guarded indirect call, provided the forged dentries carry no operations table, the
file pointer is non-null and the mount namespace is readable:

```
mm->mm_mt.ma_root = &VMA
VMA:    vm_mm = mm, vm_file = &F, vm_ops = 0        (vm_start/vm_end = self-clobber)
F:      f_path = { mnt = &M.mnt, dentry = &D }, f_inode = &I
D:      d_name = { len = N, name = TARGET }, d_parent = &R, d_op = 0
R:      d_parent = &R (IS_ROOT), d_op = 0
M:      mnt_parent = &M, mnt.mnt_root = &R, mnt_ns = &NS (NS.seq = 1)
```

Reading `/proc/self/maps` then returns bytes from any chosen kernel address in that one line's
path field, repeatably, because the root still points at a page the reader owns: rewriting the
forged name and re-reading the file reads a different address. The path is rendered through the
kernel's escaping helper, which stops at a NUL and escapes some bytes, so the reader takes one
byte at a time and decodes it — and pointing the first read at the kernel's version banner makes
the read self-verifying, since its expected prefix is known. Building a read out of a write, and
insisting on a self-checking first read, is
[07-read-write-primitives.md](07-read-write-primitives.md#a-use-after-free-becomes-type-confusion-which-becomes-read-and-write)
and [the rule after it](07-read-write-primitives.md#read-before-you-write); forging an object
graph that a kernel routine will traverse on request is
[the pattern](07-read-write-primitives.md#forging-objects-through-legitimate-interfaces) the
whole forge rests on.

From there the traversal is ordinary: the address space's owning task yields the credential
pointer, and the task's open file table yields a pipe's private data. Each is verified without
root, and the verifications are chosen so that they cannot be satisfied by a wrong answer — the
credential's uid must read back as the process's own, and the pipe's ring size as the size the
process itself set
([09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md#verifying-the-cred-before-writing-it)).

### Root, and SELinux

Two writes, in an order fixed by a gate between them.

The first is a one-shot merge aimed at the writer's own `struct cred`, taking the process to uid
0 with full capabilities while leaving the reference count and pointers intact, so no re-exec is
needed. What it depends on is contiguity: the identity fields, the secure bits and the capability
words are one run, so the writer assembles that run as a single block — zeros from the
credential's uid offset up to its capability offset, then five all-ones capability words — and
the merge write copies the whole block in one operation. `cves/lib/root/cred.c` is the shared
definition of that layout rather than the thing performing the write; it makes the same edit as
separate writes with a capability read-back, for a chain holding an ordinary read/write pair.
Here verification is separate from the write rather than part of it: the process reads its own uid
back, and the capability half shows in the pagemap interface described next, which returns real
frame numbers only to a process that holds administrative capability.
Zeroing identity alone would produce uid 0 with *empty* capability sets, which is not enough to
load a module, so the capability write is not an optional extra — a point
[09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md#the-object-that-decides)
makes in general and
[the derivation section](09-privilege-escalation-to-root.md#deriving-the-layout) supplies the
offsets for. Editing the object in place rather than swapping the pointer is the choice
[09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md#editing-the-object-versus-swapping-the-pointer)
sets out, and here it is forced, since the write's self-clobber rules the swap out.

Administrative capability then unlocks the pagemap interface, which is what makes the second
write exact rather than guessed. The gating is a trap rather than a footnote: `pagemap_read()` in
`fs/proc/task_mmu.c` decides whether to show frame numbers from the credentials captured in the
descriptor's `f_cred` at `open()` time, so an in-place escalation that never re-execs keeps
whatever descriptor it already had, and a `/proc/self/pagemap` opened before the capability write
returns zeroed frame numbers forever. Re-open it afterwards and prove it by reading the
eight-byte entry for a page known to be resident.

The second write sets SELinux permissive on a page whose frame is now known exactly, which is what
permits module loading
([09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md#the-second-gate-selinux)
and [the ceiling](09-privilege-escalation-to-root.md#the-ceiling-loading-a-module)). The writer
then execs the manager's `ksud` to late-load KernelSU, and judges the result by asking the driver
rather than by the loader's exit status — a late-load can report success and leave no driver
resident, and a run that believed the status would discard a completed root. By that point the
process is root, so repeating the load costs nothing. The recipe declares `CAP_SU`, so the runner
recognizes the live driver and stops on the first success rather than rebooting into another shot.

### Keeping the device alive

Every run leaks, permanently until reboot, one input device, its HID input and the HID device
behind them, along with a live event node whose driver data dangles. System services open these
nodes, and if one of them closes a node the uhid close handler runs on freed memory; the README's
instruction is to treat a device that has run this as dirty.

While it still holds the kernel read/write, the writer performs two cleanups, and both are
neutralization rather than repair in the sense of
[10-survivability-and-measurement.md](10-survivability-and-measurement.md#neutralizing-rather-than-repairing).
It marks each leaked input device as already open, so the open path short-circuits before reaching
the driver and the input reader never enters the corrupt path — the
[input-device case](10-survivability-and-measurement.md#the-input-device) worked through there.
This must happen *before* the KernelSU load, because loading re-enforces SELinux and would deny
the list walk it needs; an ordering constraint between two cleanup steps is exactly the kind of
thing that only shows up once both work. And it zeroes the reader's forged tree root, whose
address the reader hands over, turning the forged tree into an empty one so that a later scan of
that maps file finds no mappings and cannot fault.

Two conditions persist for the life of the boot. Once a process's pipe buffer array has been
redirected it must never be killed, because releasing the pipe would call through the forged slots
and panic; both halves park, and are cleaned up only by rebooting. And the reader lives with a
forged mapping tree, which makes *any* fault in that process unserviceable — an evicted code page,
but equally a first touch of uninitialized data, of the heap, or of a thread stack. The guard
therefore walks every mapping and touches it, skipping the large spray that was already made
resident at allocation time; locking the pages would be better and is not available, because the
memory-lock limit for this user is far too small.

That walk is a failure mode in its own right, and the census below records what it cost: five of
32 shots ended inside it, faulting at the touch itself, with the walk not yet reported. The
mapping list it walks is a snapshot, so an address it lists can be unmapped before it is touched
— a thread that exits unmaps its own stack, and a process that has just retired a pool of threads
is walking a list that is still moving. The walk therefore performs its own accesses inside a
region where a fault is reported to the caller instead of raised, and a page it cannot touch is
skipped and counted rather than ending the attempt. Which mapping was responsible has not been
established. The same guard covers the post-redirect scan of the spray for the callback's
witness, where an untouchable page would otherwise cost the whole shot just as expensively.

The forged tree is also not private: a system process reading the reader's maps file for routine
accounting walks it and faults there, whether or not the chain is still live, so the guard makes
the process non-dumpable — which makes those files root-owned and gates them behind ptrace access
while leaving the process's own read working, since access is granted to a caller in the same
thread group before the dumpable flag is consulted.

### Reliability

This chain is recorded as a hunt rather than a certainty, and the two records it leaves are of
different kinds. Its stage manifest still carries `composed = false`; its README records root
reached on hardware and, unlike the other chain, publishes a census. Measured over 32 shots of
the shipped configuration, each on a fresh boot with a 1024 MB spray: 6 reached root, 14 fired
at a wrong page guess and left the kernel dead, and 12 missed with the kernel untouched.

A shot lands when the reclaim lands *and* the page guess is right, and the rate is their
product — the reclaim landing means the freed device page is returned to this processor's free
list and the first send of the spray takes it back, and the guess being right means the forged
wait queue points into one of the sprayed pages — and the census decomposes the same 32 shots
along both. The reclaim landed in 21 of them, meaning the wake walked something, the exploit's
page or not; in 7 of those 21 the guess named a sprayed page. The guess is therefore the larger
of the two losses by a wide margin, and it is the expensive one: a lost reclaim costs a shot, a
lost guess costs the boot. Five of the 32 were lost to neither term, in the residency walk
described above.

The part worth carrying away is that these are not independent axes. The spray buys guess coverage,
and the same spray is what leaves the allocator without the headroom the reclaim needs, so enlarging
it raises one term and lowers the other. The documented method is to tune one knob at a time — the
spray cap, the free-memory margin, or the address band the guess draws from — and to judge by the
runner's shot census rather than by a coverage figure computed a priori, which sees only one of the
two effects. Composing stages whose rates are coupled like this, and resisting the arithmetic that
assumes they are not, is
[10-survivability-and-measurement.md](10-survivability-and-measurement.md#composing-probabilistic-stages-safely).

The stage manifest scopes the probabilism further, and this is where the chain's design pays off.
The reader resolves the writer's forge page to its exact linear-map address by walking the writer's
page tables through its own arbitrary read, and verifies it against a magic value the writer
stamped, so the writer places deterministically and never writes at an unconfirmed page. The
remaining probabilistic step is the reader landing its *own* reclaim page — and the two outcomes are
not equally cheap: the manifest records that a reader miss is a clean read-miss while a uhid
reclaim-miss panics.

That last step has an oracle of its own. The guess cannot be checked by reading the page it
names, because that read is what the forge is being built for; it can be checked by a forge
placed somewhere else. Every template the reader
builds carries the same sixteen-byte marker, chosen to contain no NUL, at a fixed offset. A
cross-cache placement puts one such template at a page the side channel has already named — an
address with no guess in it — and that forge's path name is aimed at the guessed address plus
the marker's offset. One read of `/proc/self/maps` then settles the question before any wake is
pointed anywhere:

- the marker comes back: the guessed address is one of the sprayed pages, so every wake from
  here on walks a page this process owns, which makes the reader's retries as cheap as the
  writer's;
- other bytes come back: the guess is refuted and nothing was ever fired at it, so the shot ends
  as a miss with the kernel as it was;
- the real mappings come back: no redirect happened, the question went unasked, and the blind
  fire runs as before.

Asking is safe because the address is drawn from the linear map of present memory, which is
mapped: sixteen bytes read there are bytes, not a fault. It costs one groom and one probe per
shot, and it buys one question per shot rather than one per candidate — the placement is spent
by the read, and grooming another needs threads, which is an allocation that can no longer be
faulted in once the mapping tree is forged. The manifest ships the step enabled, and both it and
the README carry the same caveat, which belongs here too: the census above was taken without it,
and the census with it is owed.

Retry policy follows from the same asymmetry, and depends on a second, cheaper oracle. The lockless
append exchanges a pointer into the list head immediately before it performs the redirect write, and
both cells are in the forge page, so a half that also holds that page in userspace can read the first
one back and learn whether the callback ran there — without a kernel read, and without waiting to see
whether the redirect did anything. A page that has fired cannot fire again, because the
compare-and-exchange at the top requires the untouched value, so a retry re-stamps the page from the
template. The writer's page is reader-resolved and magic-verified, so every wake walks a page it owns
and a retry carries no new risk: a missed redirect costs one more probe, free and reclaim cycle
rather than the whole shot, and missing is the common case. The reader's page, while its guess stands
unconfirmed, is not in that position: only the reclaim-missed outcome is retryable, and that outcome
leaves the kernel untouched but draws again on the guess, converting misses into roots and panics in
whatever ratio the guess has, which is why its retry count is kept low. A guess the marker read has
confirmed puts the reader on the writer's footing for the rest of the shot.

Three things do not come from the target description and have to be re-established on each device:
the address band the guess draws from, the spray sizing, and the assumption the guess rests on, that
the linear map is not randomized. The first two trade against each other, the chain will still run
with another device's values and simply land less often, and a wrong band shows up as panics rather
than as a build error — a failure mode worth knowing before porting, since it is the one the build
gates cannot catch.

## What the two chains share, and where they part

The shared half is the library, and it is the part of this tree with a life beyond either bug.
`cves/lib/README.md` states the arrangement: each exploit directory is a thin orchestrator that owns
the defect, the topology that reaches it and the tuning that wins its race, and everything a second
exploit would otherwise reimplement lives in `cves/lib/`. Both chains draw on the write-free
text-base leak in `cves/lib/kaslr/`, the futex-hash side channel in `cves/lib/leak/kernelsnitch/`,
the linear-map arithmetic in `cves/lib/addr/physmap.h`, the pipe physical read/write in
`cves/lib/rw/pipe_rw.c`, the credential and capability patch in `cves/lib/root/cred.c`, and the
KernelSU detection in `cves/lib/root/kernelsu.c`. They also share the contract those modules are
written against: `cves/lib/rw/krw.h` defines a read, a write and the state they need, so a chain can
install a slow primitive, use it to build a fast one, and keep every consumer working across the
swap — and its addresses are typed by the space they belong to, so handing a primitive the wrong kind
of address fails at compile time instead of on the device.

Below that line they diverge at every step. One bug's object lives on a kernel stack, the other's in
a page-allocator block too large for any slab cache, so one reclaim is a frame overlay performed by
the attacker's own syscall and the other is a page reclaim racing a platform service that fires the
trigger a few milliseconds later. One primitive is a two-store tree unlink aimed at a
*system-shared* slot, the other a pointer-only store aimed into the attacker's *own* page. One ends
at a `su` daemon that supplies `CAP_SU` to an already-installed manager; the other loads a KernelSU
module itself and is judged by the driver. One leaves collateral that cannot be walked back at all;
the other leaves collateral that can be neutralized in place, in an order that matters. The
chain-specific halves reflect that: GhostLock additionally uses `cves/lib/rw/nameblob.c`,
`cves/lib/root/taskscan.c`, `cves/lib/root/handoff.c` and `cves/lib/trigger/ashmem.h`, while FFWheel
uses `cves/lib/trigger/uhid.c`, the spray vehicles under `cves/lib/spray/`, the address helpers under
`cves/lib/addr/`, `cves/lib/base/mmguard.h` and the input-device neutralization in
`cves/lib/root/`.

### The difference that costs the most

Set the two reliability sections beside each other and one distinction explains most of the gap
between them. The distinction itself is not something these two chains establish. That a
verifiable state before an irreversible commitment costs a failed attempt only a retry, while a
blind commitment costs the machine, is argued from the published cross-cache measurements in
[06-cross-cache-attacks.md](06-cross-cache-attacks.md#probabilism-and-the-verification-step-that-bounds-it)
— a blind write has no abort branch, so a chain's success probability is permanently its setup's
landing probability, and the unit of a miss is a page belonging to whatever subsystem now owns it.
The composition rule that follows, never let a write be the verification step, and the fallback
where no independent read exists, an oracle that makes the probabilistic stage deterministic, are
[10-survivability-and-measurement.md](10-survivability-and-measurement.md#composing-probabilistic-stages-safely).
What follows is two illustrations of that argument, not evidence for it.

GhostLock is the verifiable side. Its first corruption lands in a slot it can read back through an
ordinary file operation. It does read it back, and refuses to continue unless the value is already
the forged page; it then proves both widths of the resulting write, with read-back, before
promoting; it then proves the promoted physical read/write in both directions against a proof page
before returning it; and only then does it perform the irreversible credential and enforcing-flag
edits. Every commitment in that sequence is made against a primitive that has already answered a
question whose answer the exploit could not have faked.

FFWheel had the other problem, and what it did about it is the part worth reading. Its wake-up has
to be aimed at a page address it guessed, and the outcome of a wrong guess is not a miss but a
fault on a forged wait queue, with the kernel walking whatever happens to be at that address — no
amount of care afterwards helps, because the commitment has already been made. The chain bought
itself two oracles rather than tuning the guess. The writer's page stopped being a guess when the
reader resolved it by a page-table walk through its own arbitrary read and verified it against a
magic value the writer stamped; from then on the writer places deterministically and retries
freely. The reader's own page, the step that had nothing, is now put to a cross-cache-placed marker
read before any wake is aimed at it, which turns a refuted guess from a panic into an ordinary
miss. Both moves are the same rule applied twice — buy an oracle with a corruption you can verify,
then spend the irreversible ones behind it — which is the fallback the general treatment states,
reached here from the exploit's side rather than the measurement's. The caveat both the README
and the manifest carry belongs with it — the census quoted above was taken before the second oracle
existed, and the census with it is owed, so the published rate describes the configuration without
it.

Two cautions follow from reading both chains' documentation closely. First, an oracle answers the
question it was built for and no other. FFWheel's userspace-readable compare-and-exchange cell
reports whether the callback ran on a page the process holds; it does not report where a *future*
callback will run, which is why it makes retries cheap without making the guess safe, and why the
guess needed an oracle of its own rather than a better reading of that one. Second, a verification
is only as good as its forgery resistance: the credential check that the uid reads back as the
process's own, and the pipe check that the ring size matches the size the process itself set, are
chosen because a wrong object is unlikely to satisfy them, and a check that any object would
satisfy is decoration.

## Instruments

The instruments below are the ones this section introduces; everything else it uses is
cross-referenced at the end.

- Arm the kernel's page allocation and free tracepoints, write a phase name into `trace_marker` at
  every phase boundary so that each page event is attributable to a phase, follow pages across
  phases by frame number, and score a reclaim hit as any allocation whose order-*N* block covers a
  frame the discard released. That is the instrument; this tree implements it as `tools/pagetrace`.
  Arming the tracepoints needs root, while the probe itself runs as the unprivileged uid the
  exploit work cares about. A discard confirmed by frame number is evidence, a discard inferred
  from a count of freed objects is not, and a spray reporting no hit against confirmed-discarded
  pages is a real negative about that vehicle rather than a tuning problem. The cheaper observation
  points do not settle the question: the slab listing moves by a slab or two against a background
  of many hundred, and the page-type listing reads zero in every state for the relevant orders.
- Re-open `/proc/self/pagemap` after any in-place capability change, then read the eight-byte entry
  for a page you know is resident and check that bit 63 is set and bits 0–54 are non-zero. Frame
  numbers are shown or suppressed according to the credentials captured in the descriptor's
  `f_cred` at `open()` time (`pagemap_read()` in `fs/proc/task_mmu.c`), so a descriptor opened
  before the change returns zeros forever and reports no error while doing it. Unprivileged to
  open; the zeros are the failure signal.
- `adb shell getprop sys.boot.reason.last` — separates a panic from a clean reboot before any log is
  parsed, which is the first question to ask of a shot that did not report. Unprivileged.
- `adb shell cat /sys/fs/pstore/console-ramoops-0` — the previous boot's console, where both chains'
  late faults are read from. Unprivileged for a named file; listing the directory is denied, so open
  the file by name.

The remaining instruments these studies lean on are owned elsewhere. BTF layout recovery and the
cache-geometry interfaces are in
[06-cross-cache-attacks.md](06-cross-cache-attacks.md#knowing-which-caches-you-are-between); the
spray catalogue and `/proc/buddyinfo` in
[05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md#instruments); reading an oops out
of the previous boot in
[03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md#persistent-crash-storage)
and [10-survivability-and-measurement.md](10-survivability-and-measurement.md#logging-through-the-panic);
the `@ADDR` kprobe fetch used as a privileged ground-truth read in
[04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md#reading-a-literal-kernel-address-with-a-kprobe)
and [07-read-write-primitives.md](07-read-write-primitives.md#a-ground-truth-read-for-a-privileged-context);
the credential and SELinux readbacks in
[09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md#instruments); and the policy
queries that decide a reachability argument in
[02-reachability-and-attack-surface.md](02-reachability-and-attack-surface.md#establishing-reachability-on-a-kernel-you-cannot-rebuild).

## Grounded in this project

GhostLock is `cves/cve-2026-43499-ghostlock/`, whose README, stage manifests and payload sources are
between them the record for the claims made about it above: `main.c` holds the attempt loop and the
three route threads, `fops.c` the descriptor-set word map and the verification and restore, `util.c`
the fabricated waiter, lock, task and operations table — the three stores into the forged tree entry
there are what the primitive section is derived from — `pipe.c` the physical read/write, `root.c` the
credential, capability, securebits, SELinux and seccomp patching, and `su_daemon.c` the helper, the
daemon and the payload loader. The destructive targets and their restores are declared in the two
`runner/stages/entry.ghostlock@*/stage.toml` manifests. The two reclaim
vehicles are `fops_pselect.c` and `fops_tcp.c`, selected by a declared tunable rather than by an
`#ifdef`, and the placement-shift rule is a row in `runner/scripts/lib/offset-maps.txt` evaluated by
`runner/scripts/lib/offset_rules.py`. It is driven by `runner/recipes/ghostlock.toml`, which resolves
one of two entry stages by kernel flavour.

FFWheel is `cves/cve-2026-43049-ffwheel/`, likewise: `ffcompose.c` forks the two halves,
`ffread_mm.c` and `ffread_resolve.c` are the reader and its resolve pass, `ffroot_w.c` the writer,
`ffwheel_forge.h` the forged-page templates the halves share — including the marker the guess oracle
reads — `ksnitch_mm.h` the timing leak of the process's own `mm_struct`, and `ffanalyze.py` the
frame-number scoring of a reclaim hit. The oracle's placement is `cves/lib/spray/crosscache/`, and
`runner/stages/entry.ffwheel@6.1/stage.toml` is where it is switched on, where the
reboot-before-every-shot setup the census was measured under is declared, and where the composed
flag stands; the census itself is in the README. It is driven
by `runner/recipes/ffwheel.toml`; `runner/recipes/ffwheel-root.toml` is a separate,
root-required design check that confirms the forge, trigger and write primitive against a scratch
page, isolating a failure to address resolution rather than to the write path.

The shared modules both chains link are listed in `cves/lib/README.md`, which also states the two
rules that keep the library reusable: a module never includes a consumer's header, and a device or
kernel-build constant is a parameter or a guarded default rather than a bare definition, with
`runner/scripts/lib-audit.sh` checking both.

## See also

- [01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md) — why presence is read from the shipped binary rather than a version number, which both studies depend on.
- [02-reachability-and-attack-surface.md](02-reachability-and-attack-surface.md) — the gates that decide whether an unprivileged process reaches either interface.
- [03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md) — reading the panics these chains produce, and telling a self-inflicted trap from a memory fault.
- [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) — the tracefs leak both chains use, and the linear-map arithmetic one of them builds on.
- [05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md) — the reclaim vehicles and the pressure tuning behind them.
- [06-cross-cache-attacks.md](06-cross-cache-attacks.md) — the order, migratetype and processor constraints, and the step one of these chains does not need.
- [07-read-write-primitives.md](07-read-write-primitives.md) — the promotion ladders both studies walk.
- [08-triggering-races-reliably.md](08-triggering-races-reliably.md) — window measurement, and reporting a stage as a rate.
- [09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md) — what each chain does once it holds read and write.
- [10-survivability-and-measurement.md](10-survivability-and-measurement.md) — parking, neutralization, and composing probabilistic stages.
- [12-further-reading-and-glossary.md](12-further-reading-and-glossary.md) — the wider literature, and [the glossary](12-further-reading-and-glossary.md#glossary) for any term used above without definition.
