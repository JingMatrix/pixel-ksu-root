# P0-465827985 — StackJump, jumping the stack guard page into `system_server`

A native-code hardening gap in Android, reported by Jann Horn of Google Project Zero as
[issue 465827985](https://project-zero.issues.chromium.org/issues/465827985) and derestricted
with no fix at the disclosure deadline. It is neither a memory-corruption bug in one function
nor a kernel bug.

Android compiles native code without
[stack-clash protection](https://developers.redhat.com/blog/2017/09/25/stack-clash-mitigation-gcc-background),
the compiler feature that emits a probe per page as a large frame is allocated. So a function
with a large stack frame, entered while the stack pointer already sits near the bottom of the
stack, can advance the stack pointer *past* the guard page without ever touching it, and then
use unrelated virtual memory as stack. Driven far enough, that yields control of a
`system_server` binder thread's instruction pointer from an unprivileged shell.

This is a userspace instance of the classic
[Stack Clash](https://blog.qualys.com/vulnerabilities-threat-research/2017/06/19/the-stack-clash):
a guard page of a few kilobytes does not stop an attacker who advances the stack by more than
a page without writing into it. The mitigation has been standard in both major compilers for
years and is simply not enabled for Android's native build; enabling it by default has been
[requested upstream](http://www.mail-archive.com/llvm-bugs@lists.llvm.org/msg97146.html).

Like [the Telecom pivot](../cve-2026-49881-telecom/README.md), this earns a place in the tree
not because it roots anything by itself but because it moves an attacker from the shell
domain into `system_server`, which widens the userspace context every kernel hunt here is
reached from. It runs entirely as the shell user; root is never used, and using it would
defeat the point.

## Why the guard page is jumpable at all

The report identifies four preconditions, all of which hold on a stock device.

*Unbounded, cheap recursion over binder.* Android's synchronous IPC allows a synchronous
callback back into the caller, and that pair can be nested arbitrarily. Several shell-command
transactions on the activity manager each issue a synchronous file-opening callback, which is
permitted out of `system_server` because that callback's binder is explicitly marked as
allowing blocking calls. Answering each callback by issuing the next command drives the
recursion to any depth on the *same* server thread.

*Thread stacks share the address space with the heap and shared memory.* Non-main thread
stacks are placed in the same region as heap allocations and shared mappings, so "below the
stack" is memory an attacker can populate.

*A thin guard region.* A non-main thread that can run managed code has only a small guard
region at the bottom of its stack — small enough for a single large frame to clear.

*A large frame that spills a return address before initialising it.* A mount-registry
loading routine in the incremental filesystem service has a very large stack buffer and calls
a non-leaf function before initialising it, so a saved instruction pointer can be spilled
into — and later reloaded from — memory that now lies below the jumped guard page.

## The mechanism

First, drive the stack down: each nested level moves the target thread's stack pointer down
by a fixed amount, and the callback loop above recurses to an attacker-chosen depth.

Then jump the guard. The large frame is reached through the incremental service when its
mount cache is stale, which is forced by mounting an instance over an empty library directory
of an installed app. Entered with the stack pointer already near the bottom, the frame clears
the guard into the memory below.

Finally, land the jump in attacker memory and hijack it. Bitmap blobs sprayed through the
clipboard service place attacker-shared memory below the binder thread stacks; when a spilled
link register lands there, flipper threads overwrite it before it is reloaded, which gives
control of the program counter.

Why the shell and not an ordinary app: shell policy reaches almost every service, including
the incremental service, which by design mounts over empty application directories. An
untrusted app cannot reach the vulnerable routine this way, and the reporter did not get it
working from there.

## Status on the builds here

The primitive reproduces. At sufficient recursion depth the nesting overflows a
`system_server` binder thread and the transaction comes back reporting a dead object — the
thread crashed past its guard page. Stack-clash protection is not enabled on this build, and
the bug is live.

The depth the original proof of concept hardcodes is too shallow here. It was tuned for the
previous Android release; on this one that many levels never reach the guard, and the
vulnerable call simply returns normally. The controlled-jump window — recurse to just below
the depth at which the recursion crashes itself, then let the large frame tip it over — is a
few levels wide and has to be swept for, which is what the driver script does.

The reporter's spray-based leak does not reproduce here. Every overflow faults on an unmapped
page just below the guard, meaning the sprayed blobs never sit under the victim thread. That
is inherent rather than a tuning miss: nothing controls *where* the system process maps the
sprayed blobs, so spraying below the stack is the gamble the report settles for.

## A reliable information leak instead

The bug's dependable effect is the crash, so the redesigned path leaks from the crash rather
than from a spray landing. On this build the tombstone directory and its files are
world-readable, so the shell user can read them. One overflow — which is reliable at a
sufficient depth — makes the crash handler write a full dump of the faulting binder thread,
and the leak script extracts two things from it in one shot, with no root.

The first is the load base of every native library in the process, which is a complete
address-space randomisation defeat for `system_server`. The tombstone's memory map lists the
executable base of each library, and those bases differ from boot to boot, so this is a live
leak rather than a static fact.

The second is live pointers from the crash registers — stack, heap and code — along with the
dumped memory blocks around them.

This trades the reporter's racy write and program-counter hijack for a reliable *read*:
weaker in capability, far stronger in reliability, and it hands a follow-on exploit the
randomisation defeat it needs. The write path stays available in the driver, but is not
reproduced on this build.

## Files

- [`repro.cc`](repro.cc) — the proof of concept, ported from the report's own with the fixes
  below.
- `Android.mk` and `Application.mk` — the build inputs. Build with NDK 27.x: the binder
  parcel utility header this uses was removed in later NDK releases.
- [`run.sh`](run.sh) — builds, pushes and drives the depth sweep. It classifies every attempt
  by the result marker, and health-gates on a live system service so that a reboot is not
  counted as a data point. No root.
- [`leak.sh`](leak.sh) — the reliable leak: crash the system process once, then read the
  world-readable tombstone and print the leaked library bases, pointers and memory. No root,
  and the recommended entry point on this build.

## Changes from the reporter's proof of concept

*It runs at all on this release.* The NDK now routes service lookups through a unified
service manager, which returns a dead proxy unless a binder thread pool is running. The fix
is to resolve the thread-pool entry points dynamically, as the original already does for the
service lookup itself, and start the pool before the first lookup.

*It is repeatable without a reboot.* The temporary storage the mount step creates is not
reclaimed on process exit, so a second run failed indefinitely until reboot. It now clears
stale storage at start-up and deletes its own at exit.

*It has a real oracle instead of exit-code guessing.* A single result line reports the leak,
the count of foreign bytes, or the transport error, and a recursion transaction that comes
back reporting a dead object is reported as a system-process overflow rather than aborting
opaquely.

*Its knobs are tunable* through the environment: the recursion depth, which was hardcoded;
the number of hog threads, which was random and which hangs the run if it exhausts the
system process's binder pool; and the mount target package and subdirectory. The default
target is an app whose library directory is unused — do not point it at an app whose
libraries are extracted there, because the mount would shadow them.

## Toward domainprobe

The reachability question this poses per domain — can this context talk to the incremental
service, the clipboard and the activity manager's shell commands, and drive the callback
recursion — is a natural [`domainprobe`](../../domainprobe/README.md) row, the way the
Telecom pivot is measured there. Integration is deferred until the controlled leak is
reproduced on this build.

## Run

```sh
./run.sh                            # sweep a range of depths, several tries each
DEPTHS="..." ITERS=20 ./run.sh      # or drive the sweep explicitly
```

## References

- Project Zero [issue 465827985](https://project-zero.issues.chromium.org/issues/465827985) — the report, proof of concept and root-cause analysis.
- Qualys, [The Stack Clash](https://blog.qualys.com/vulnerabilities-threat-research/2017/06/19/the-stack-clash) — the guard-page-jump technique this reuses in userspace.
- Red Hat, [stack-clash mitigation in GCC](https://developers.redhat.com/blog/2017/09/25/stack-clash-mitigation-gcc-background) — what the flag emits, and why a guard page alone is insufficient.
- LLVM, [the request to enable it by default](http://www.mail-archive.com/llvm-bugs@lists.llvm.org/msg97146.html).
- [`../cve-2026-49881-telecom/README.md`](../cve-2026-49881-telecom/README.md) — the other route into the same domain.
