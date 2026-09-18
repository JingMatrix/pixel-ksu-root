# domainprobe — what an Android SELinux domain can actually reach

A probe app that answers one question per line: *from this domain, does this
socket family create, this device node open, this SELinux rule allow, this
syscall return — or does the kernel refuse?* It runs the same probe in six
domains so the contrast that decides where a primitive is deliverable is visible
in one place.

It exists because that question kept deciding things and could not be answered
from `adb shell`. shell is not the domain a real delivery uses; something a shell
cannot reach may be open in the app sandbox, and something no app can reach may
be open to `system_server`. Guessing from `ls -lZ` is not enough. Open the app;
each domain's findings are a card you expand.

## The six domains

| domain | context | how it is entered |
|---|---|---|
| shell | `u:r:shell:s0` | the pushed cli binary, or *Shizuku* in-app |
| runas_app | `u:r:runas_app:s0` | the same binary under `run-as` |
| untrusted_app | `u:r:untrusted_app:s0` | the app process (JNI) |
| isolated_app | `u:r:isolated_app:s0` | an `isolatedProcess` service (JNI) |
| zygote_next | native zygote | an `isolatedProcess` + `nativeService` service |
| system_server | `u:r:system_server:s0` | CVE-2026-49881 (a Telecom bug) |

The probe runs *in* its domain — a pushed binary answers for `shell`, a JNI
library for whichever process loads it. Two domains are reached by userspace
bugs/quirks rather than a normal API: `system_server` through CVE-2026-49881
(see [`../cves/cve-2026-49881-telecom`](../cves/cve-2026-49881-telecom)), and
`zygote_next` through an `android:nativeService` isolated service, which on
Android 17 routes through the native/secondary zygote. shell is reachable in-app
when Shizuku or Sui is running; otherwise shell and runas_app come from
[`domainprobe.sh`](domainprobe.sh).

## What it probes

[`cpp/probe.c`](app/src/main/cpp/probe.c) is the probe — device nodes (IPC, DMA,
GPU, HID, kernel-info leaks), socket families (all netlink protocols, AF_PACKET,
PF_KEY, AF_ALG, AF_VSOCK), syscalls, and the SELinux policy — built two ways from
one source: a JNI library the app loads, and a standalone binary the host pushes.
[`JavaProbe.java`](app/src/main/java/dev/pixelksu/domainprobe/JavaProbe.java) is
the pure-Java mirror, run only in `system_server` (which cannot load our native
library), covering the socket, node and SELinux rows.

The SELinux rows read the loaded policy directly through `/sys/fs/selinux`, the
[DirtySepolicy](https://github.com/LSPosed/DirtySepolicy) technique: whether a
context validates (a type is in the policy), and `compute_av` — whether a given
`(scontext, tcontext, class, perm)` is allowed — without performing the
operation. The interface is reachable only from domains sepolicy grants
`security:compute_av`, so each row is both a reachability test and a policy read.
The probe reports the raw result (`allow` / `deny`, `valid` / errno); reading a
verdict into it — an injected rule, a patched policy — is left to whoever runs it.

Syscalls run in a forked child: the app domain's seccomp filter turns an
unlisted syscall into `SIGSYS` rather than `EACCES`, which kills the process, so
the parent recovers the signal from `waitpid` and reports it — a stronger denial
than `EACCES`, from a different mechanism.

## Conclusions that mattered

The live per-domain matrix is in the app; these are the findings that changed
decisions elsewhere:

- *ashmem is not an app-domain reclaim vehicle.* `/dev/ashmem` is refused in
  every unprivileged domain, which retired `ashmem_area_cache` as the widest
  content-controlled reclaim vehicle in
  [CVE-2026-46242](../cves/cve-2026-46242-badepoll/README.md).
- *The tracefs KASLR leak stays shell-only.* `trace_marker` is app-writable
  (`--w--w--w-`, for `android.os.Trace`), but planting the pointer is useless
  without reading it back, and `per_cpu/*/trace_pipe_raw` is `-r--r-----`
  group `readtracefs` (gid 3012) — a group `shell` holds and no app domain does
  (an `untrusted_app` gets `1079 3002 3003 9997 …`, not 3012). So an app can
  write the marker but not recover the base: not an app-sandbox KASLR leak.
- *`isolated_app` carries `AID_READPROC`* (`groups=…,3009`) — a real capability
  the plain isolated domain inherits, visible in the identity line.
- **netlink `xfrm`/`netfilter`, `packet`, `key` sockets and `CAP_NET_ADMIN` are
  closed to every app domain and open to `system_server`** — the reason that
  domain is worth reaching, and the search-space argument in
  [`../cves/cve-2026-49881-telecom`](../cves/cve-2026-49881-telecom).

## Build and run

```sh
gradle :app:assembleDebug        # AGP 9.3, Kotlin 2.3, SDK 37 (targetSdk 37)
./domainprobe.sh [serial]        # drives all domains and prints one table
```

Or open the app: it runs the in-app domains, fires the CVE-2026-49881 trigger for
`system_server`, and — when Shizuku/Sui is running — the shell domain too. Adding
a probe is one row in `run_all()` (native) or `JavaProbe.run()` (also reaches
`system_server`); both use the same `%-28s VERDICT detail` line format.
