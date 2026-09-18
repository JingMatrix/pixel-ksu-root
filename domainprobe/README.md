# domainprobe — what an Android SELinux domain can actually reach

A probe app that answers one question per line: from this domain, does this socket family
create, this device node open, this
[SELinux](https://source.android.com/docs/security/features/selinux) rule allow, this
syscall return — or does the kernel refuse? It runs the same probe in six domains, so the
contrast that decides where a primitive is deliverable is visible in one place.

It exists because that question kept deciding things and could not be answered from
`adb shell`. The shell is not the domain a real delivery uses: something a shell cannot
reach may be open in the app sandbox, and something no app can reach may be open to
`system_server`. Guessing from a directory listing is not enough. Open the app; each
domain's findings are a card you expand.

## The six domains

| domain | context | how it is entered |
|---|---|---|
| shell | `u:r:shell:s0` | the pushed command-line binary, or *Shizuku* in-app |
| runas_app | `u:r:runas_app:s0` | the same binary under `run-as` |
| untrusted_app | `u:r:untrusted_app:s0` | the app process, through JNI |
| isolated_app | `u:r:isolated_app:s0` | an isolated-process service, through JNI |
| zygote_next | native zygote | an isolated process declared as a native service |
| system_server | `u:r:system_server:s0` | CVE-2026-49881, a Telecom logic flaw |

The probe runs *in* its domain: a pushed binary answers for the shell, a JNI library for
whichever process loads it. Two of the six are reached by bugs or quirks rather than by a
normal API — `system_server` through
[CVE-2026-49881](../cves/cve-2026-49881-telecom/README.md), and the native zygote through
an isolated service declared native, which routes through the secondary zygote. The shell
domain is reachable in-app when Shizuku or Sui is running, and otherwise comes from
[`domainprobe.sh`](domainprobe.sh).

## What it probes

[`cpp/probe.c`](app/src/main/cpp/probe.c) is the probe itself: device nodes for IPC, DMA,
GPU and HID, along with the ones that leak kernel information; socket families, including
every netlink protocol as well as packet, key-management, crypto and vsock sockets;
syscalls; and the loaded policy. One source is built two ways, as a JNI library the app
loads and as a standalone binary the host pushes.
[`JavaProbe.java`](app/src/main/java/dev/pixelksu/domainprobe/JavaProbe.java) is the pure
Java mirror, used only in `system_server`, which cannot load the native library; it covers
the socket, node and policy rows.

The policy rows read the loaded policy directly through `/sys/fs/selinux`, following the
[DirtySepolicy](https://github.com/LSPosed/DirtySepolicy) technique: whether a context
validates, which says a type is in the policy, and whether a given subject, object, class
and permission tuple is allowed — without performing the operation. The interface is
reachable only from domains the policy grants access to it, so each row is simultaneously a
reachability test and a policy read. The probe reports the raw result and leaves the
interpretation — an injected rule, a patched policy — to whoever runs it.

Syscalls run in a forked child, because the app domain's
[seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html) filter turns an
unlisted syscall into a fatal signal rather than an error return, which would kill the
process. The parent recovers the signal from the child's exit status and reports it: a
stronger denial than a permission error, arriving through a different mechanism.

## Conclusions that mattered

The live per-domain matrix is in the app. These are the findings that changed decisions
elsewhere.

Ashmem is not an app-domain reclaim vehicle: the device node is refused in every
unprivileged domain, which retired the ashmem cache as the widest content-controlled
reclaim vehicle for
[CVE-2026-46242](../cves/cve-2026-46242-badepoll/README.md).

The tracefs KASLR leak stays shell-only. The marker file is app-writable, because the
platform's own tracing API writes to it, but planting a pointer is useless without reading
it back, and the raw per-processor buffers are readable only by a group the shell user
holds and no app domain does. An app can write the marker and not recover the base.

The isolated app domain carries the process-reading group, which is a real capability the
plain isolated domain inherits rather than something the app arranges for itself.

Finally, the netlink families that configure the network stack, along with packet and
key-management sockets and the network-administration capability, are closed to every app
domain and open to `system_server`. That is the reason the domain is worth reaching at all,
and it is the search-space argument in
[`../cves/cve-2026-49881-telecom`](../cves/cve-2026-49881-telecom/README.md).

## Build and run

```sh
gradle :app:assembleDebug
./domainprobe.sh [serial]        # drives all domains and prints one table
```

Or open the app: it runs the in-app domains, fires the Telecom trigger for `system_server`,
and, when Shizuku or Sui is running, the shell domain too. Adding a probe is one row in the
native `run_all()`, or in the Java mirror when the row must also answer for
`system_server`; both use the same fixed-width verdict line format.
