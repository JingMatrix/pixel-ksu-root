# P0-465827985 — shell→system_server LPE by jumping the stack guard page

A native-code hardening gap in Android, reported by Jann Horn of Google Project
Zero as [issue 465827985](https://project-zero.issues.chromium.org/issues/465827985)
(disclosed 2025-12-03, derestricted 2026-03-03 with no fix at the 90-day
deadline; no CVE assigned). It is not a memory-corruption bug in one function and
not a kernel bug. Android compiles native code *without* stack-clash protection
([`-fstack-clash-protection`](https://developers.redhat.com/blog/2017/09/25/stack-clash-mitigation-gcc-background),
the flag that emits a *stack probe* per page as a large frame is allocated), so a
function with a large stack frame, entered while the stack pointer already sits
near the bottom of the stack, can advance the stack pointer *past* the guard
page without touching it and then use unrelated virtual memory as stack. Driven
far enough, that yields control of a `system_server` binder thread's instruction
pointer from unprivileged `shell`.

This is a userspace instance of the classic *Stack Clash* — Qualys's 2017
demonstration that a few-KiB guard page does not stop an attacker who advances
the stack by more than a page without writing into it, then "jumps the guard"
([The Stack Clash](https://blog.qualys.com/vulnerabilities-threat-research/2017/06/19/the-stack-clash)).
The mitigation has been standard in GCC and Clang for years and is simply not
enabled for Android's native build; enabling it by default has been
[requested of upstream Clang](http://www.mail-archive.com/llvm-bugs@lists.llvm.org/msg97146.html).

Like [`cve-2026-49881-telecom`](../cve-2026-49881-telecom), this earns a place in
the tree not because it roots anything by itself but because it is a
privilege-domain pivot — `u:r:shell:s0` → `u:r:system_server:s0` — which widens
the userspace context every kernel-CVE hunt here is reached from. It runs
entirely as uid 2000 (shell); root is never used and would defeat the point.

Everything below is measured on `panther-CP2A.260705.006` (Pixel 7, Android 17,
security patch 2026-07-05). The reporter tested Android 16 (BP3A, kernel
6.1.134); the tuning differs between the two builds (see Status).

## Why the guard page is jumpable at all

The report identifies four preconditions, all of which hold on stock Android and
none of which the missing compiler flag would need to exist for it to matter:

1. *Unbounded, cheap recursion over binder.* Android's synchronous IPC allows a
   synchronous callback back into the caller, and that pair can be nested
   arbitrarily. `ActivityManager`'s
   [`SHELL_COMMAND_TRANSACTION`](https://cs.android.com/search?q=SHELL_COMMAND_TRANSACTION)
   commands (`am start --start-profiler`, `dumpheap`, `trace-ipc`, `profile`)
   each issue a synchronous
   [`ShellCallback.openFile`](https://cs.android.com/search?q=file:ShellCallback.java)
   callback — permitted out of `system_server` because `ShellCallback` marks the
   binder [`allowBlocking`](https://cs.android.com/search?q=allowBlocking%20file:Binder.java).
   We answer each callback by issuing the next command, driving the recursion to
   any depth on the *same* server thread.
2. *Thread stacks share the address space with the heap and shared memory.*
   Non-main-thread stacks are placed in the same VA region as heap allocations
   and shared mappings, so "below the stack" is memory an attacker can populate.
3. *A thin guard region.* A non-main thread that can run Java code has only an
   8-16 KiB guard region at the bottom of its stack — small enough for a single
   large frame to clear.
4. *A large frame that spills a return address before it is initialized.*
   `android::incfs::MountRegistry::Mounts::loadFrom()`
   ([incremental-fs](https://cs.android.com/search?q=MountRegistry%20loadFrom))
   has a 128 KiB stack buffer and calls a non-leaf function *before* initializing
   it, so a saved instruction pointer can be spilled into — and later reloaded
   from — memory that now lies below the jumped guard page.

## The mechanism, concretely

1. *Drive the stack down.* Each nested `start` level moves the target thread's
   stack pointer down ~6496 bytes. We recurse to an attacker-chosen depth
   (`DP_DEPTH`) via the `ShellCallback` loop above.
2. *Jump the guard with `loadFrom()`.* Its 128 KiB frame is reached by
   [`IIncrementalService.isFileFullyLoaded`](https://cs.android.com/search?q=IIncrementalService)
   when the mount cache is stale, which we force by `createStorage`-mounting an
   incrementalfs instance over an empty `/data/app/.../lib/<subdir>`. Entered
   with the SP already near the bottom, the frame clears the 16 KiB guard into
   the memory below.
3. *Land the jump in attacker memory and hijack it.* `Bitmap` ashmem blobs
   sprayed through
   [`IClipboard.setPrimaryClip`](https://cs.android.com/search?q=setPrimaryClip)
   place attacker-shared memory below the binder-thread stacks. When a spilled
   link register lands there, flipper threads overwrite it with `0xaaaaaaaaa`
   before it is reloaded, giving PC control (the reporter observed a crash at
   `pc 0xaaaaaaaaa`).

Why shell and not `untrusted_app`: `shell` sepolicy reaches almost every service,
including `incremental_service`, which by design mounts over empty `/data/app`
dirs; `untrusted_app` cannot reach `loadFrom()` this way, and the reporter did not
get it working from `untrusted_app`.

## Status on panther-CP2A.260705.006 — present / unpatched

- *The primitive reproduces.* At recursion depth ≈150 the nested recursion
  overflows a `system_server` binder thread and the transaction returns
  `Status(-129, EX_TRANSACTION_FAILED): 'DEAD_OBJECT'` — the thread crashed past
  its guard page. Stack-clash protection is not enabled on this build; the bug is
  live.
- *The stock depth (131) is too shallow here.* It was tuned for Android 16; on
  this Android 17 build 131 levels never reach the guard (`isFileFullyLoaded`
  returns normally). The controlled-jump window — recurse to just below where the
  recursion self-crashes, then let `loadFrom` tip it over — is a few levels wide
  around 131-150 and needs sweeping, which is what `run.sh` does.
- *The reporter's spray leak did NOT reproduce here (~30 attempts, all orderings).*
  Every overflow faults on an *unmapped* page just below the guard (`foreign=0`),
  i.e. the Bitmap spray never sits under the victim thread. That is inherent, not
  a tuning miss: we do not control *where* system_server mmaps the sprayed blobs,
  so "spray below the stack" is the ~5-10% gamble the report settles for.

## A reliable info leak instead: harvest the crash tombstone (`leak.sh`)

The bug's *dependable* effect is the crash, so the redesigned path leaks from
that, not from a spray landing. On this build `/data/tombstones` is `0775` and
tombstones are `0664` — world-readable, so unprivileged `shell` reads them.
One overflow (100% at depth ≈150) makes `tombstoned` write a full dump of the
faulting `system_server` binder thread, and `leak.sh` extracts from it, no root,
in one shot:

- Native-library load bases → a complete system_server ASLR defeat. The
  tombstone's memory map lists the `r-x` base of `libart.so`, `libandroid_runtime.so`,
  `libbinder.so`, `libhwui.so`, `libc.so`, … Verified to differ per boot (a live
  leak, e.g. `libart` at `0x72'64663000` one boot and `0x7b'f555d000` the next).
- Live pointers in the crash registers (stack `sp`/`x0`, heap `0xb4…`, code
  into libc/libart) and ~19 `memory near` blocks of system_server memory.

This trades the reporter's racy ~5-10% write/PC-hijack for a ~100% *read*
primitive — weaker in capability, far stronger in reliability, and it hands a
follow-on exploit the ASLR defeat it needs. The write/PC-hijack path stays open
(see run.sh / DP_SPRAY_FIRST) but is not reproduced on this build.

## Files

- `repro.cc` — the PoC, ported from the report's `native_repro.tar.gz` with the
  fixes below.
- `Android.mk` / `Application.mk` — ndk-build inputs. Build with NDK 27.x:
  `binder_parcel_utils.h`, used for `ndk::AParcel_writeVector`, was removed in
  NDK 28+ (see [[ndk-binder-client-gotchas]]).
- `run.sh` — build, push and drive the depth sweep; classifies every attempt by
  the `DP_RESULT` marker and health-gates on a live `activity` service so a
  reboot is not counted as a data point. No root.
- `leak.sh` — the reliable info leak: crash `system_server` once, then read the
  world-readable tombstone and print the leaked library bases, pointers and
  memory. No root. This is the recommended entry point on this build.

## Changes from the reporter's PoC (all in `repro.cc`)

1. *Runs at all on Android 17.* The NDK now routes service lookups through
   `BackendUnifiedServiceManager`, which returns a dead proxy (`BR_DEAD_REPLY` at
   `associateClass`) unless a binder threadpool is running. Resolve
   `ABinderProcess_setThreadPoolMaxThreadCount` / `_startThreadPool` via `dlsym`
   (as the PoC already does for `AServiceManager_checkService`) and start the pool
   before the first lookup.
2. *Repeatable without a reboot.* `createStorage`'s temporary storage is not
   reclaimed on process exit, so a second run returned `-1` forever until reboot.
   Now `openStorage`→`deleteStorage` clears stale storage at startup and the PoC
   deletes its own at exit (IIncrementalService ordinals: `openStorage` 1,
   `createStorage` 2, `isFileFullyLoaded` 14, `deleteStorage` 19).
3. *A real oracle instead of exit-code guessing.* A single `DP_RESULT` line
   reports leak / foreign-byte-count / transport-error; a recursion transaction
   that returns `DEAD_OBJECT` is reported as a `system_server` overflow rather
   than aborting opaquely.
4. *Tunable knobs:* `DP_DEPTH` (recursion depth; was hardcoded 131), `DP_NUM_HOG`
   (was random 0..24; >~16 hangs by exhausting `system_server`'s binder pool),
   `DP_MOUNT_PKG` / `DP_MOUNT_SUBDIR` (mount target; default Chrome, whose `lib/`
   is unused — do not use an app whose libraries are extracted under `lib/arm64`,
   which incfs would then shadow).

## Toward domainprobe

The reachability question this poses per domain — can this context talk to
`incremental_service`, `clipboard`, and `activity`'s `SHELL_COMMAND`, and drive
`ShellCallback` recursion — is a natural [`domainprobe`](../../domainprobe) row,
the way telecom's pivot is measured there. Integration is deferred until the
controlled leak is reproduced on this build.

## Run

```sh
./run.sh                            # sweep depths 131 140 150 160, 8 tries each
DEPTHS="131 135 140 145" ITERS=20 ./run.sh
```

## References

- Project Zero [issue 465827985](https://project-zero.issues.chromium.org/issues/465827985) — the report, PoC and root-cause analysis.
- Qualys, [The Stack Clash](https://blog.qualys.com/vulnerabilities-threat-research/2017/06/19/the-stack-clash) (2017) — the guard-page-jump technique this reuses in userspace.
- Red Hat, [Stack Clash mitigation in GCC](https://developers.redhat.com/blog/2017/09/25/stack-clash-mitigation-gcc-background) — what `-fstack-clash-protection` emits and why a guard page alone is insufficient.
- LLVM, [request to enable `-fstack-clash-protection` by default](http://www.mail-archive.com/llvm-bugs@lists.llvm.org/msg97146.html).
