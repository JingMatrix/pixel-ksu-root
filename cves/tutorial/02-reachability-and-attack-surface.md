# Reachability and Attack Surface Mapping

A memory-safety defect is a property of code. An exploit is a property of a code path that some
concrete process, with some concrete set of credentials, can actually enter. The gap between
those two statements is where most candidate bugs die. A use-after-free in a driver whose device
node is opened only by a vendor daemon running in its own SELinux domain is, from an app or an
`adb shell`, exactly as useful as no bug at all — you can read the patch, write the trigger, and
never once execute it.

So the first question to settle about any candidate is not "is it exploitable" but "from where".
That question decomposes into four independent gates, all of which must open before a single
instruction of the vulnerable function runs on your behalf:

1. Discretionary access control — the uid, gid and supplementary groups of your process against
   the mode bits and ownership of the object.
2. Mandatory access control — on Android, SELinux: your process's domain against the object's
   type, for a specific class and permission, and for `ioctl` down to the specific command number.
3. Syscall filtering — the seccomp-bpf program installed on your process, which differs between
   the app sandbox, `system_server` and the shell.
4. In-code checks — `capable()`, `ns_capable()`, `CAP_SYS_ADMIN` tests inside the driver itself,
   and feature gates such as a device node that only exists if a vendor module is loaded.

Reachability analysis is the discipline of answering all four empirically, on the target, from
the domain you will really be in, rather than inferring them from a directory listing.

## Two historical examples of the reachability argument

CVE-2019-2215, the binder use-after-free Project Zero found in the wild, is the canonical case.
`binder_poll()` hands an epoll instance the `wait_queue_head` embedded in the calling thread's
`struct binder_thread`; the `BINDER_THREAD_EXIT` ioctl then frees that thread through
`binder_thread_release()` without unregistering the epoll entry, so epoll's later teardown and
wakeup paths walk a wait queue inside freed memory. The root-cause analysis puts it plainly: "if
epoll is called on this thread, `binder_poll` tells epoll to use `wait`, the wait queue that is
embedded in the `binder_thread` struct. Therefore, when the `binder_thread` struct is freed, epoll
is pointing to the now freed wait queue." The fix landed upstream in early 2018 and was left out of
many shipped downstream kernels. Its value came from `/dev/binder` being open to essentially every
process on the system, including the most tightly confined ones — the writeup notes the bug is
reachable from Chrome's renderer processes, which run in Android's `isolated_app` domain, making it
a viable second stage after a renderer compromise
([Bad Binder: Android In-The-Wild Exploit, Project Zero](https://projectzero.google/2019/11/bad-binder-android-in-wild-exploit.html);
[root-cause analysis](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-2215.html)).
The same argument makes GPU drivers perennially attractive. Man Yue Mo's Arm Mali work rests on a
single reachability fact, stated in the writeup as "on all Android devices, the GPU driver can be
accessed from the untrusted app domain, so any compromised or malicious app can launch an attack on
the kernel"
([Corrupting memory without memory corruption](https://github.blog/security/vulnerability-research/corrupting-memory-without-memory-corruption/)),
which turns a vendor driver with no upstream review into first-order surface for any installed
application. The bugs found in it are ordinary memory-safety defects —
[GHSL-2022-054 (CVE-2022-38181)](https://securitylab.github.com/advisories/GHSL-2022-054_Arm_Mali/)
is a use-after-free in the same driver — and it is the domain that makes them chains.

The inverse case is the same argument run backwards. A driver whose device node is opened only
from a domain you cannot enter has no entry point, so nothing about the bug has to change for the
exploit to be impossible — the patch reads the same and the trigger is the same code, and it never
runs. That is the vendor daemon of the opening paragraph. Section
[01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md)
covers how candidates arrive; this is the filter applied immediately afterwards.

## Discretionary access control: uids, AIDs and supplementary groups

Android does not use Linux users in the desktop sense. It assigns fixed numeric identities,
called AIDs, to system components, and allocates one uid per installed application. The numeric
constants are declared in a single header in the platform source,
[`system/core/libcutils/include/private/android_filesystem_config.h`](https://android.googlesource.com/platform/system/core/+/master/libcutils/include/private/android_filesystem_config.h),
as `#define AID_*` statements; that header is the authority for the numbers and for the one-line
comment describing what each AID is for. It is not where the numeric-to-name mapping lives. AOSP's
[Discretionary access control](https://source.android.com/docs/core/permissions/filesystem) page
documents "the removal of the `android_ids[]` array" from that same header: friendly names are now
generated inside bionic and reached through accessor functions, and OEM AIDs are defined in
`config.fs` rather than in the header at all. Useful structure in the number space: `AID_SYSTEM` is
1000 and the 1000–1999 band is core system services; `AID_SHELL` is 2000; the 3000–3999 band is
*shared GIDs*, which exist purely to be handed out as supplementary groups; applications start at
`AID_APP_START` (10000) and isolated processes at `AID_ISOLATED_START` (90000).

That 3000 band is where a process that is not root gets a raw kernel interface, and the header's
one-line comments describe intent rather than the enforcement point. Three AIDs in the band are
enforced by three different mechanisms, and confusing them produces right predictions from wrong
models:

- `AID_UHID` (3011), commented "Allow read/write to `/dev/uhid` node", is a plain DAC group on the
  node's mode bits. The enforcement is the ordinary VFS permission check, and the whole of it is
  visible in `ls -l /dev/uhid`.
- `AID_READPROC` (3009) is the `gid=` argument of the `hidepid=` mount of `/proc`, so its effect is
  a mount option, not a per-file mode. Init mounts it that way in first-stage —
  `mount("proc", "/proc", "proc", 0, "hidepid=2,gid=" MAKE_STR(AID_READPROC))`
  ([`init/first_stage_init.cpp`](https://android.googlesource.com/platform/system/core/+/refs/heads/main/init/first_stage_init.cpp))
  — and you read it back from `/proc/mounts`, where the `proc` line carries `hidepid=` and the
  exempted gid.
- `AID_INET` (3003) is, on current releases, a userspace policy key. The in-kernel
  `in_egroup_p(AID_INET)` test in the socket path lived behind `CONFIG_ANDROID_PARANOID_NETWORK`,
  which GKI does not carry: `zcat /proc/config.gz | grep -i PARANOID_NETWORK` returns nothing on a
  Pixel. What actually refuses the socket is an eBPF cgroup program attached by netd, whose
  `inet_socket_create` returns `BPF_ALLOW` only when the calling uid's app-id has
  `BPF_PERMISSION_INTERNET` in its map entry
  ([`bpf/progs/netd.c`, Connectivity module](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/heads/main/bpf/progs/netd.c)).
  The pins are visible with `ls /sys/fs/bpf/netd_shared/` —
  `prog_netd_cgroupsock_inet_create` and `map_netd_uid_permission_map`. The gid is still granted the
  way the header implies, through
  [`data/etc/platform.xml`](https://android.googlesource.com/platform/frameworks/base/+/main/data/etc/platform.xml),
  where `<permission name="android.permission.INTERNET">` declares `<group gid="inet" />`; the
  kernel simply does not consult it. A reader who reasons "3003 is absent from my `id` output,
  therefore the kernel refuses `socket(AF_INET, ...)`" gets the right answer on a normal app and the
  wrong one on any uid whose map entry and gid list disagree.

`AID_UHID` is the one of the three that carries a bug class. A shell user holding group 3011 opens
`/dev/uhid` and drives the HID core — `hid-generic` plus every specialized driver whose bus, vendor
and product ID it chooses to claim — despite the node being mode `0660 root:uhid`. That matters
because HID advisories are written for the transport the bug was found on, not for the transports
that can reach it. CVE-2019-19532 is described as "multiple out-of-bounds write bugs that can be
caused by a malicious USB device in the Linux kernel HID drivers" and scored `AV:P` — physical
attack vector — yet the code it reaches is the same driver code a `UHID_CREATE2` from an
unprivileged shell binds. The kernel has since acknowledged the gap directly: Greg Kroah-Hartman's
December 2021 series added `hid_is_usb()` and inserted it into every driver that had assumed USB
([`f83baa0cb6cf`](https://github.com/torvalds/linux/commit/f83baa0cb6cfc92ebaf7f9d3a99d7e34f2e77a8a),
[`93020953d0fa`](https://github.com/torvalds/linux/commit/93020953d0fa7035fd036ad87a47ae2b7aa4ae33)),
because, as the pull request summarizing it says, drivers "assume that a HID device is on USB
transport, but that might not necessarily be the case, as the device can be faked by uhid". Every
driver still missing that check is reachable from gid 3011. The client side is
[`cves/lib/trigger/uhid.c`](../lib/trigger/uhid.c), whose `lib_uhid_create2()` sets the bus, vendor
and product a driver will match on.

How to observe the subject half:

```
$ adb shell id
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),
1015(sdcard_rw),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),
3009(readproc),3011(uhid) context=u:r:shell:s0
```

Inside an app process, the same answer comes from `/proc/self/status`:

```
$ grep -E '^(Uid|Gid|Groups|CapEff|Seccomp)' /proc/self/status
```

`CapEff` there is normally `0000000000000000` for both shell and apps, which rules out every code
path guarded by `capable(CAP_SYS_ADMIN)` or `CAP_NET_ADMIN`, and also rules out `CAP_DAC_OVERRIDE`,
the capability that would make the entire DAC analysis moot. Pair that with the object half:

```
$ ls -lZ /dev/uhid
crw-rw---- 1 root uhid u:object_r:uhid_device:s0 10, 239 /dev/uhid
```

`ls -lZ` gives you owner, group, mode and SELinux type in one line. The two commands are the two
inputs to one check, and the check is a first-match rule, not a set membership test: access is
permitted if your uid is the owner and the owner bits allow it; otherwise if any gid in your `id`
list matches the file's group and the group bits allow it; otherwise if the other bits allow it.
Group membership is therefore necessary but not sufficient — a node at `0600 root:uhid` grants a
3011 holder nothing, because the matching clause is the group clause and its bits are empty — and
it is not necessary either, since an owning uid or permissive other bits reach the same object
without it. `CAP_DAC_OVERRIDE` bypasses all three clauses, which is what the `CapEff` reading above
excludes. For `/dev/uhid` at `0660 root:uhid` with 3011 in the group list the conclusion is narrow
but exact: DAC permits this open, and whether it succeeds now depends entirely on whether policy
allows `shell` to `read write` a `chr_file` of type `uhid_device`.

## Mandatory access control: SELinux domains as the real gate

On a modern Android device, SELinux is the binding constraint far more often than DAC. Every
process runs in a domain; system services get theirs from a `type_transition` on the labelled
executable, and applications get theirs from `seapp_contexts` matching on package, `seinfo` tag
and uid, which is also where the per-app MLS categories that isolate `untrusted_app` instances
from each other come from. The design and its rationale are set out in
[The Android Platform Security Model](https://arxiv.org/abs/1904.05572v1) (Mayrhofer, Vander Stoep,
Brubaker and Kralevich, ACM TOPS 24(3), 2021,
[DOI 10.1145/3448609](https://dl.acm.org/doi/10.1145/3448609)). The link is pinned to v1 of the
preprint deliberately; later arXiv versions are a different paper with a different author list.

Establish your own domain first, because it is not always what you assume:

```
$ getenforce
Enforcing
$ cat /proc/self/attr/current
u:r:shell:s0
$ ps -AZ | grep system_server
u:r:system_server:s0  system  1523 ...
```

`getenforce` returning `Enforcing` is the statement that none of the following analysis is
advisory ([Validate SELinux, AOSP](https://source.android.com/docs/security/features/selinux/validate)).

### Reading the policy off the device

The loaded binary policy is exported by selinuxfs at `/sys/fs/selinux/policy`, described as the
"interface to upload the current running policy in kernel binary format" in the
[SELinux Notebook's SELinux filesystem chapter](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/lsm_selinux.md).
Reading it is itself policy-gated, so on a production device expect it to fail from an app and
possibly from the shell.

The first fallback is the precompiled binary policy, which most vendors ship. Init looks for it at
`/vendor/etc/selinux/precompiled_sepolicy`, or `/odm/etc/selinux/precompiled_sepolicy` when an odm
partition is present, and loads it directly if the recorded hashes match the CIL on the other
partitions ([`system/core/init/selinux.cpp`](https://android.googlesource.com/platform/system/core/+/refs/heads/main/init/selinux.cpp)).
Prefer it when it exists: it is byte-for-byte the policy the device loaded, with no reconstruction
step to get wrong.

When the vendor ships no precompiled policy, init compiles one at boot out of CIL fragments spread
across five partitions, and you reproduce that compile off-device. The inputs are
`/system/etc/selinux/plat_sepolicy.cil` and `/system/etc/selinux/mapping/<ver>.cil`, where `<ver>`
is the string in `/vendor/etc/selinux/plat_sepolicy_vers.txt`;
`/system_ext/etc/selinux/system_ext_sepolicy.cil` with its own mapping file;
`/product/etc/selinux/product_sepolicy.cil` with its mapping file;
`/vendor/etc/selinux/plat_pub_versioned.cil` and `/vendor/etc/selinux/vendor_sepolicy.cil`; and
`/odm/etc/selinux/odm_sepolicy.cil` when present. Compile the same set with the same flags init
uses — `secilc <plat> -m -M true -G -N -c <policy_version> <mapping> ... -o policy -f /dev/null` —
to get the binary blob. This step is not optional: SETools reads a binary policy, and handing
`sesearch` a `.cil` file simply fails. Both routes also work against a factory image you have
unpacked, which lets you analyse a device you cannot boot.

Analysis then runs on a workstation with [SETools](https://github.com/SELinuxProject/setools),
which provides `seinfo` to list policy components, `sesearch` to search rules, `sediff` to compare
two policies, and `sedta` for domain-transition analysis. The queries that answer reachability:

```
$ seinfo --stats policy
$ sesearch --allow -s shell -t uhid_device -c chr_file policy
allow shell uhid_device:chr_file { append getattr ioctl lock map open read write };

$ sesearch --allow -s untrusted_app -c chr_file policy | sort
$ sesearch --allow -s untrusted_app -c file -p read policy | grep sysfs
```

The first form is the direct question — may this domain touch this type at all. The second,
enumerating every `chr_file` a domain may open, is worth running once per target domain and
keeping: it is a complete inventory of that domain's driver attack surface, usually short enough to
read end to end.

Lateral movement is a different query, and which one to run depends on how the domain is entered.
`sedta -s shell policy` lists the domains reachable from `shell` by executing a labelled binary,
and `sesearch -T -s shell policy` prints the `type_transition` rules underneath that result; both
are informative for init-spawned services and for the shell, because those domains are entered by
`exec`. They are close to empty for app domains, and not because apps are contained: an app process
is forked from zygote and labelled during specialization from `seapp_contexts`, so no
`type_transition` on an executable is involved and an app cannot exec a platform binary into a new
domain in the first place. The real lateral route out of an app domain is to induce a process
already running in the target domain to act on your behalf, which is the binder surface covered
below.

Two refinements matter. First, `ioctl` is filtered per command number: SELinux gained extended
permissions so policy could allow a driver's benign ioctls and deny the dangerous ones
([kernel commit `fa1aa14`](https://github.com/torvalds/linux/commit/fa1aa143ac4a682c7f5fd52a3cf05f5a6fe44a0a);
the motivating Android work is Jeff Vander Stoep's
[ioctl command whitelisting in SELinux, LSS 2015](https://kernsec.org/files/lss2015/vanderstoep.pdf);
syntax in the
[SELinux Notebook's xperm rules](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/xperm_rules.md)).
`allow` on the node is therefore necessary but not sufficient. The rule shape to look for (this is
an illustrative rule, not a capture from any device):

```
allowxperm untrusted_app gpu_device:chr_file ioctl { 0x8000-0x80ff };
```

Two facts decide whether you can read such a rule correctly, and both invert the naive reading.

The first is what an empty result means. If no `allowxperm` rule exists for a (source, target,
class) tuple, the base `allow … ioctl` permits every command; the Notebook states it directly —
"as no other *allowxperm* rules have been defined in the example, all other ioctl calls may
continue to use any valid request parameters (provided there are *allow* rules for the *ioctl*
permission)". An empty `sesearch --allowxperm` output is therefore the permissive case, not the
restrictive one. Extended permissions constrain only the tuples they name.

The second is which number the rule contains. The kernel truncates the command before the check:
`selinux_file_ioctl()` calls `ioctl_has_perm(cred, file, FILE__IOCTL, (u16) cmd)`, and
`ioctl_has_perm()` then splits that half-word into `u8 driver = cmd >> 8` and `u8 xperm = cmd &
0xff`. Policy never sees the direction and size bits. As the Notebook puts it, "from the 32-bit
ioctl request parameter value only the least significant 16 bits are used. Thus *0x8927*,
*0x00008927* and *0xabcd8927* are the same extended permission."

Work an example through. Mali's kbase header defines `KBASE_IOCTL_TYPE` as `0x80` and declares
`KBASE_IOCTL_MEM_ALLOC` as `_IOWR(KBASE_IOCTL_TYPE, 5, union kbase_ioctl_mem_alloc)`. `_IOWR`
composes `(dir << 30) | (size << 16) | (type << 8) | nr`, so with `dir` = 3 and a 32-byte union the
constant your code passes to `ioctl()` is `0xc0208005`. Truncated to 16 bits that is `0x8005`:
driver byte `0x80`, function byte `0x05`, which is what the rule above would permit and what a
denial would name. The number in the policy is `(_IOC_TYPE << 8) | _IOC_NR`; comparing the full
`_IOWR(...)` constant against the printed range is the standard way to conclude, wrongly, that your
ioctl is out of range. If the truncated command genuinely falls outside the permitted set, the bug
is not reachable from that domain even though the node opens.

Second, `dontaudit` rules suppress the audit record, not the denial. A silent `EACCES` is not
evidence that no rule was consulted. Check for the suppression explicitly with
`sesearch --dontaudit -s <domain> -t <type> policy` before concluding anything from an empty log.

### Reading denials, and asking policy without performing the operation

When an access does fail under MAC, the kernel emits an AVC record naming every element of the
tuple you lack: `pid=` and `comm=` for the subject, an object half, and the
`scontext`/`tcontext`/`tclass` triple. Which fields the object half contains is decided by the form
of audit data the calling hook supplied, not by what kind of object it is. In
`security/lsm_audit.c`, a record built from a `struct path` or a `struct file` prints `path=`, one
built from a dentry or an inode prints `name=`, and both then append `dev=` and `ino=` taken from
the backing inode; a socket record prints the address instead, which for an `AF_UNIX` socket bound
into the filesystem is again spelled `path=` and carries no inode fields. The same file emits the
`pid= comm=` prefix on every record, so a line without a pid has been abridged somewhere.

Two records from AOSP's own documentation
([Validate SELinux](https://source.android.com/docs/security/features/selinux/validate)), one of
each shape:

```
avc: denied  { connectto } for  pid=2671 comm="ping" path="/dev/socket/dnsproxyd"
  scontext=u:r:shell:s0 tcontext=u:r:netd:s0 tclass=unix_stream_socket
```

```
type=1400 audit: avc:  denied  { read write } for  pid=177 comm="rmt_storage" name="mem"
  dev="tmpfs" ino=6004 scontext=u:r:rmt:s0 tcontext=u:object_r:kmem_device:s0 tclass=chr_file
```

The first is a network-class record: its `tclass` is `unix_stream_socket` and its `path=` is the
address netd bound, which is why no `dev=` or `ino=` follows. Its `tcontext` is a *domain*,
`u:r:netd:s0`, and not an object type — the object is a socket netd is listening on, so the rule
that would permit the access names `netd` as its target. The second is the file shape the gloss
above describes, down to the `object_r` type in `tcontext` that a device node carries. The target
half of a query is therefore read out of the record rather than inferred from the path.

`scontext`, `tcontext`, `tclass` and the permission set are exactly the arguments `sesearch` takes,
so a denial translates mechanically into the query that confirms it —
`sesearch --allow -s shell -t netd -c unix_stream_socket -p connectto policy` for the first record
above — or into a candidate rule via `audit2allow` fed the denial lines on stdin. Use `audit2allow`
as a reader, not a fixer: on a locked device you cannot install the rule it prints, but the rule
states precisely what you lack. AOSP notes it is no longer shipped in the tree and should come from
your distribution's policycoreutils package
([Validate SELinux](https://source.android.com/docs/security/features/selinux/validate)).

Two routes to the records, with different privilege. `adb shell dmesg | grep 'avc: '` reads the
kernel ring buffer, and on a production build that read needs root, so the form that works is
`adb shell su -c 'dmesg' | grep 'avc: '` on a device you have already rooted. (The collection
script here, `runner/scripts/harvest-live.sh`, takes the ring buffer and the other root-only reads
of this section that way.) `adb logcat -b all | grep 'avc: '` gets the same records
unprivileged, because logd's auditd component opens the kernel audit socket and writes what it
reads into the main and events buffers
([`logd/LogAudit.cpp`](https://android.googlesource.com/platform/system/logging/+/refs/heads/main/logd/LogAudit.cpp)).
Which one you have is
knowable in advance from `cat /proc/sys/kernel/dmesg_restrict` and
`cat /proc/sys/kernel/kptr_restrict` — the first says whether an unprivileged `dmesg` is permitted
at all, the second whether the pointers in whatever you do read will be printed or zeroed. After a
reboot the previous boot's kernel log survives in pstore, and the path to read is the numbered one:
`cat /sys/fs/pstore/console-ramoops-0`. Read it by name rather than listing the directory first;
policy grants `shell` read on the pstore file and not directory read, so `ls /sys/fs/pstore` is
denied while `cat` of a known path is not.

What makes the log a discriminator between a DAC refusal and a MAC refusal is call ordering in the
VFS, not a convention. `inode_permission()` runs `do_inode_permission()` — the DAC check — and
returns on failure, reaching `security_inode_permission()` only if DAC passed
([fs/namei.c, v6.1](https://github.com/torvalds/linux/blob/v6.1/fs/namei.c)). A DAC refusal
therefore never reaches SELinux and never produces an AVC record at all. So: `EACCES` with a
matching AVC record is MAC; `EACCES` with no record — after `sesearch --dontaudit -s <domain> -t
<type> policy` has confirmed the record is not merely suppressed — is DAC.

Policy can also be asked without performing the operation, which matters when performing it would
be destructive or would kill the process. selinuxfs exposes the access-decision interface at
`/sys/fs/selinux/access` (the kernel side of `security_compute_av`) and a context validator at
`/sys/fs/selinux/context` (`security_check_context`). The raw interface takes numeric class and
permission vectors resolved from `/sys/fs/selinux/class/<name>/index` and
`/sys/fs/selinux/class/<name>/perms/<perm>`; the usable front ends are `selinux_check_access(3)` and,
on Android, `android.os.SELinux.checkSELinuxAccess`. Writing a candidate context to
`/sys/fs/selinux/context` separates "this type is not in the loaded policy" from "this type exists
and the access is denied" — the kernel answers `EINVAL` for the former. LSPosed's
[DirtySepolicy](https://github.com/LSPosed/DirtySepolicy) uses these same oracles in the opposite
direction, to detect rules that root solutions inject into the running policy.

`sediff old_policy new_policy` over two consecutive monthly builds shows which domains lost access
to which types — which attack surface a given patch level removed — and is frequently more
informative than the bulletin text.

## Seccomp: the per-process syscall gate

Since Android O a seccomp-bpf filter has been installed system-wide, with the policy expressed in
bionic rather than in each process
([Seccomp filter in Android O](https://android-developers.googleblog.com/2017/07/seccomp-filter-in-android-o.html)).
The policy files are `bionic/libc/SYSCALLS.TXT` plus the `SECCOMP_ALLOWLIST_*` and
`SECCOMP_BLOCKLIST_*` tables, compiled into the BPF programs installed by
[`libc/seccomp/seccomp_policy.cpp`](https://android.googlesource.com/platform/bionic/+/master/libc/seccomp/seccomp_policy.cpp).
Three distinct filters exist — `set_app_seccomp_filter()`, `set_app_zygote_seccomp_filter()` and
`set_system_seccomp_filter()` — so the set of syscalls you may issue genuinely differs between an
ordinary app, an app zygote child and a system process, and the shell (not a zygote descendant)
differs again. The action for a disallowed syscall is `SECCOMP_RET_TRAP`, which raises `SIGSYS`
rather than returning an error.

That changes how you probe. A filtered syscall does not hand you `ENOSYS`; it kills the process.
`SIGSYS` is delivered to the calling thread and its default action terminates that thread's whole
thread group, so a forked child absorbs the kill and the parent survives to report it:

```c
pid_t p = fork();
if (p == 0) { syscall(__NR_userfaultfd, 0); _exit(errno ? errno : 0); }
int st; waitpid(p, &st, 0);
if (WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS) /* gate 3: the filter killed it */;
else if (WIFEXITED(st) && WEXITSTATUS(st) == ENOSYS) /* gate 4: not compiled in */;
else if (WIFEXITED(st))                        /* reached the implementation */;
```

Propagating the errno rather than exiting zero is what separates gate 3 from gate 4. The three
outcomes are distinct findings with different remedies. `SIGSYS` says the call never reached the
kernel's syscall entry; it is a stronger negative than any `errno`, and the remedy is a different
domain. `ENOSYS` says the filter allowed it and the kernel it reached was not built with that
feature — on this project's target, `msgget` returns `ENOSYS` because `# CONFIG_SYSVIPC is not set`,
a result no seccomp or SELinux analysis would ever explain. Any other errno says the call reached
the implementation and was refused there, by a `capable()` test or by the driver's own logic.

The fork is a complete answer only where native code runs. A managed process that cannot fork —
`system_server` being the case that matters, where an unhandled `SIGSYS` takes the whole system
down — has no way to absorb the kill, which is why characterizing that domain needs the
one-syscall-per-boot procedure that `domainprobe/probe-syscalls.sh` drives: issue one candidate,
let the device reboot if it dies, read the verdict from what survived.

Confirm the filter is installed before trusting any of it. The answer differs per domain, so record
which domain the reading came from:

```
$ adb shell grep -i seccomp /proc/self/status   # u:r:shell:s0
Seccomp:        2
Seccomp_filters:        1
```

Mode 2 is filter mode. `Seccomp_filters` (present on recent kernels) counts attached programs.

Sweep the syscalls that are load-bearing for exploitation rather than for applications:
`userfaultfd`, `add_key`/`keyctl`, `msgget` and the other System V IPC calls, `io_uring_setup`,
`perf_event_open`, `bpf`, `process_vm_readv`, `ptrace`, `mq_open`, `landlock_*` and
`unshare(CLONE_NEWUSER)` — each is a spray vehicle, an information source or a privilege lever. The
last deserves separate mention: on desktop Linux, unprivileged user namespaces hand an attacker
`CAP_NET_ADMIN` and `CAP_SYS_ADMIN` inside the namespace and thereby open large amounts of kernel
code — nftables, overlayfs, packet sockets — to unprivileged users, which is why distributions have
repeatedly debated restricting them
([Controlling access to user namespaces, LWN](https://lwn.net/Articles/673597/)). On Android the
question is settled one gate earlier, and not by seccomp: the arm64 GKI defconfig sets
`CONFIG_NAMESPACES=y` and never sets `CONFIG_USER_NS`
([`arch/arm64/configs/gki_defconfig`, android14-6.1](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/configs/gki_defconfig);
same on android15-6.6 and android16-6.12), so the feature is not compiled in and
`unshare(CLONE_NEWUSER)` returns `EINVAL` rather than being filtered or refused. A Linux bug
reachable only through a user namespace is therefore out of scope for these targets — which is a
gate-4 verdict, readable from the config, and the reason the probe above has to distinguish an
errno from a signal.

## In-code checks and feature gates

The fourth gate is the one with no policy file behind it. It has two halves: credential tests the
driver performs itself, and the question of whether the code exists in this build at all.

The credential half is `capable()` and `ns_capable()`, which are the same function —
`capable(cap)` is literally `return ns_capable(&init_user_ns, cap)` in
[kernel/capability.c](https://github.com/torvalds/linux/blob/v6.1/kernel/capability.c) — evaluated
against different namespaces. On a kernel built without `CONFIG_USER_NS` there is only the initial
user namespace, so the two coincide and the distinction is inert; it matters only where
unprivileged user namespaces exist and a capability held in a nested namespace is not a capability
held in the initial one. What the `CapEff` reading above settles is only the credential side.
SELinux mediates capabilities too: `cred_has_capability()` maps the request onto the `capability`
or `capability2` class and consults the AVC, so a bit set in `cap_effective` is necessary and not
sufficient. `sesearch --allow -s <domain> -t <domain> -c capability <policy>` and its `capability2`
counterpart are the second half of that question. The credential half — which bits to set, in which
namespace, and why an all-ones `CapEff` still fails a `capable()` test taken in a nested user
namespace — is developed in
[09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md), where it becomes
load-bearing once you are writing to `struct cred`.

The feature half is answered by the kernel's own config, exported at `/proc/config.gz` when
`CONFIG_IKCONFIG_PROC=y`:

```
$ adb shell su -c 'cat /proc/config.gz' | zcat |
    grep -E 'SYSVIPC|USER_NS|UHID|KPROBE_EVENTS|DEBUG_INFO_BTF|DEBUG_MUTEXES'
# CONFIG_SYSVIPC is not set
# CONFIG_USER_NS is not set
CONFIG_UHID=y
CONFIG_KPROBE_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
# CONFIG_DEBUG_MUTEXES is not set
```

That is panther on build CP2A.260705.006. The `su` in that command is not decoration: reading
`/proc/config.gz` on a production Pixel needs root. Off-device, the same
file comes from the kernel image of the matching GKI or factory build, which is the route when the
target is not rooted.

Every line of that output settles a claim made elsewhere in this section. `# CONFIG_SYSVIPC is not
set` is why the `msgget` row of the syscall sweep returns `ENOSYS` on a Pixel. `# CONFIG_USER_NS is
not set` is why the user-namespace paragraph's conclusion holds here. `CONFIG_UHID=y` is why
`/dev/uhid` exists to be opened. `CONFIG_KPROBE_EVENTS=y` and `CONFIG_DEBUG_INFO_BTF=y` are the
preconditions of the two instruments below, `CONFIG_DEBUG_INFO_BTF_MODULES=y` decides whether a
driver's types are in the vmlinux blob or in a per-module one, and `# CONFIG_DEBUG_MUTEXES is not
set` fixes the size of every `struct mutex` whose successor fields you are about to compute.

For code that is not in the kernel image, the vendor-module half is `grep -w <driver>
/proc/modules`: a device node that appears only when a module is loaded is a reachability question
with a completely different answer from a node whose driver is built in.

## Enumerating nodes and interfaces from the domain itself

The controlling methodology point: a listing is not a reachability test. `ls -Z /dev` from the
shell tells you what exists and how it is labelled; it tells you nothing about what an app can
open, because the shell is not the domain in which any real delivery happens. Something a shell
cannot reach may be open to `untrusted_app`, and something no app can reach may be open to
`system_server`. The probe has to execute inside the domain being characterized — a pushed binary
for the shell, a JNI library loaded by the app process for the app domains, a Java-only mirror for
processes that cannot load a native library at all.

A practical sweep has three parts:

- Device nodes. For each entry under `/dev`, attempt `open(path, O_RDONLY | O_NONBLOCK)` and
  record the errno. Exclude `/dev/watchdog*` first: the watchdog "activates as soon as
  /dev/watchdog is opened and will reboot unless the watchdog is pinged within a certain time",
  and closing the fd without the magic character leaves the driver assuming userspace died, which
  "will then cause a reboot if the watchdog is not re-opened in sufficient time"
  ([watchdog API, kernel documentation](https://docs.kernel.org/watchdog/watchdog-api.html)).
  `O_NONBLOCK` does not make an open side-effect-free and does not prevent every blocking open
  either, so run a `/dev` sweep only on a device you are willing to reboot, and keep the exclusion
  list in the sweep source rather than in your head. Classifying the results: success means all
  four gates opened. `EACCES` means DAC or MAC refused, disambiguated by the AVC rule above.
  `EPERM` is usually gate 4 — an in-driver `capable()` test, which neither the mode bits nor the
  policy will ever explain. `ENOENT` means the driver is not built or the vendor module is not
  loaded. `ENXIO` or `ENODEV` means the node exists but nothing is bound behind it. A successful
  open is not proof of reachable functionality either, since the ioctl command is a separate
  question decided by the extended permissions above.
- Socket families. `socket(AF_X, SOCK_DGRAM, proto)` across `AF_PACKET`, `AF_KEY`, `AF_ALG`,
  `AF_VSOCK`, `AF_BLUETOOTH` and every `NETLINK_*` protocol individually. The netlink case is not
  an empirical curiosity: `socket_type_to_security_class()` in `security/selinux/hooks.c` maps each
  netlink protocol to its own SELinux class — `netlink_route_socket`, `netlink_xfrm_socket`,
  `netlink_audit_socket`, `netlink_generic_socket` and a dozen more, with `netlink_socket` as the
  fallback for protocols it does not name. So `NETLINK_ROUTE` being open says nothing about
  `NETLINK_XFRM`, and the empirical result has a policy query behind it:
  `sesearch --allow -s <domain> -c netlink_xfrm_socket <policy>`. Each family that opens is a
  self-contained parser and object graph reachable from that domain.
- Information sources. `/proc/kallsyms`, `/proc/slabinfo`, `/proc/vmallocinfo`, `/proc/zoneinfo`,
  `/proc/buddyinfo`, `/proc/self/pagemap`, `/sys/kernel/debug`, `/sys/kernel/tracing`,
  `/sys/kernel/btf/vmlinux`. Test each by reading, not by stat: several of these exist and are
  readable but return zeroed or censored content, which is a different finding from a refusal.
  `kptr_restrict` in particular causes `%pK` pointers — including all of `/proc/kallsyms` — to print
  as zeros rather than to fail
  ([kernel sysctl documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html)),
  and `/proc/self/pagemap` zeroes the PFN field rather than erroring for a caller without
  `CAP_SYS_ADMIN` ([pagemap documentation](https://docs.kernel.org/admin-guide/mm/pagemap.html)).
  The pagemap check is `file_ns_capable(file, &init_user_ns, CAP_SYS_ADMIN)`, which reads
  `file->f_cred` — the credentials recorded at `open()`, not the caller's at read time — so an fd
  opened before a credential change keeps returning zeroed PFNs afterwards, and any chain that
  acquires `CAP_SYS_ADMIN` mid-run must reopen pagemap before PFNs appear. A reader that checks
  only for errors will record all of these as successes.

Record the matrix once per domain and keep it. It is the input to every later decision about where
a primitive can be delivered, and it goes stale only when the device updates.

## Userspace surface: exported components, providers and binder services

Kernel reachability is often decided by userspace reachability: the way into a favourable domain
is by compromising, or merely talking to, a process already running there. Enumerating that
surface uses ordinary platform tooling:

```
$ adb shell service list          # every registered binder service and its interface token
$ adb shell dumpsys -l            # services that implement dump
$ adb shell cmd -l                # services with a shell command interface
$ adb shell pm list packages -f
$ adb shell dumpsys package com.example.app   # exported activities/services/receivers/providers
$ adb shell content query --uri content://com.example.provider/items
```

`service list` is the master index: each line is a kernel-mediated IPC endpoint, most living in
`system_server`, each accepting attacker-shaped `Parcel` data. Three papers map this surface
systematically — Feng et al.'s
[Understanding and defending the binder attack surface in Android](https://dl.acm.org/doi/10.1145/2991079.2991120)
(ACSAC 2016), which studied over a hundred vulnerabilities and built dependency-aware transaction
fuzzing; [FANS](https://www.usenix.org/system/files/sec20fall_liu_prepub.pdf) (USENIX Security
2020), which automated interface recovery for native system services; and
[Ghost in the Binder](https://dl.acm.org/doi/abs/10.1145/3460120.3484801) (CCS 2021), which showed
that inducing a system service to transact with an attacker-controlled binder server affects the
majority of binder interfaces. Project Zero's
[Mitigations are attack surface, too](https://projectzero.google/2020/02/mitigations-are-attack-surface-too.html)
makes the complementary point for vendor kernels: out-of-tree "security" subsystems added by OEMs
are themselves unreviewed surface reachable from the same unprivileged contexts.

## Hidden-API blocklists, and why they are not a reachability boundary

Since Android 9, ART restricts reflective access to non-SDK framework members. Blocked members
raise `NoSuchMethodException` from `Class.getDeclaredMethod`, return `NULL` from JNI
`GetMethodID`, and are filtered out of `getDeclaredMethods` results
([Restrictions on non-SDK interfaces, Android developer
documentation](https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces)).
This is a compatibility mechanism, and the same documentation supplies the switch that turns it
off for testing: `adb shell settings put global hidden_api_policy 1`.

Three consequences for attack-surface work. First, enforcement is per-process runtime state, not a
kernel boundary, so it is liftable from inside the process. The mechanism the bypasses turn on is
that ART decides by the caller's declaring class, and code on the boot classpath is exempt: a
reflective lookup performed on your behalf by a platform class is not filtered, which is exactly
what meta-reflection arranges. From there the documented-by-side-effect route is
`dalvik.system.VMRuntime.setHiddenApiExemptions(new String[]{"L"})`, reached itself by
meta-reflection or by a passthrough such as
[LSPosed's AndroidHiddenApiBypass](https://github.com/LSPosed/AndroidHiddenApiBypass). The
observable that makes it testable is a single call: the same `getDeclaredMethod` throws
`NoSuchMethodException` before the bypass and returns a `Method` after, run in-process in the
domain being characterized.

Second, if you achieve code execution inside a framework process, the blocklist does not constrain
which internal APIs you may call there — the surviving constraints are SELinux, seccomp and DAC,
which is the set you must actually enumerate. Third, the reverse is also true and often surprising:
lifting the blocklist gives you the framework's managed wrappers, not new syscalls. The two halves
of that are checked separately. Whether the domain may map executable memory is a policy question
with a query you run yourself —
`sesearch --allow -s untrusted_app -t untrusted_app -c process -p execmem <policy>`, substituting
the domain you are characterizing — and whether a wrapper exists is a lookup for the method on
`android.system.Os` and `libcore.io.Os` in that release's own jars. The conclusion is conditional
on both: no managed wrapper *and* no `execmem` means the syscall cannot be issued from managed code
at all, whatever the hidden-API policy says, while either half alone leaves a route. Both checks
can also be made in-process, from inside the domain, by writing a query to `/sys/fs/selinux/access`
and attempting the reflective lookup — which is what
[`domainprobe/app/src/main/cpp/probe.c`](../../domainprobe/app/src/main/cpp/probe.c) and
[`JavaProbe.java`](../../domainprobe/app/src/main/java/dev/pixelksu/domainprobe/JavaProbe.java) do
here. Distinguish "method is on the blocklist" from "method does not exist in this release" before
concluding anything: the former is liftable, the latter is not.

## Establishing reachability on a kernel you cannot rebuild

Two problems remain after policy analysis. You need to know whether the vulnerable function is
actually entered when you exercise a candidate trigger, and you need struct layouts for a kernel
binary you did not build.

For the first, a kprobe is the ground truth. Probes are created by writing to
`/sys/kernel/tracing/kprobe_events` and enabled per event, on a kernel built with
`CONFIG_KPROBE_EVENTS` ([kprobe-based event tracing,
kernel documentation](https://docs.kernel.org/trace/kprobetrace.html)):

```
# echo 0 > /proc/sys/kernel/kptr_restrict
# echo 'p:reach uhid_char_write' > /sys/kernel/tracing/kprobe_events
# echo "common_pid==$TRIGGER_PID" > /sys/kernel/tracing/events/kprobes/reach/filter
# echo 1 > /sys/kernel/tracing/events/kprobes/reach/enable
# echo 1 > /sys/kernel/tracing/tracing_on
  ... run the unprivileged trigger, in the target domain ...
# cat /sys/kernel/tracing/trace
# echo 0 > /sys/kernel/tracing/events/kprobes/reach/enable
# echo > /sys/kernel/tracing/kprobe_events
# echo 1 > /proc/sys/kernel/kptr_restrict
```

Three of those lines are not decoration, and
[`cves/lib/tools/kprobe.sh`](../lib/tools/kprobe.sh) writes all three. `tracing_on` is a global
switch independent of the per-event `enable`; if it is off, every probe records nothing and the
result is indistinguishable from a path that was never entered. `kptr_restrict` masks pointers in
trace output, so a probe that fetches an address prints zeros unless it is relaxed first. The
per-pid `filter` keeps an unfiltered probe on a busy symbol from filling the ring buffer with other
processes' traffic and evicting the one hit that mattered.

Any line in `trace` naming `reach` proves the path was entered. The negative is weaker and needs
work before it means anything, because an empty buffer is equally consistent with a probe on an
inlined or blacklisted symbol, a wrapped ring buffer, and a wrong model of the call graph. Separate
them: `cat /sys/kernel/tracing/kprobe_profile` prints per-probe hit and miss counts, which
distinguishes "never fired" from "fired and the record was lost"; and, where debugfs is mounted,
`grep -w <sym> /sys/kernel/debug/kprobes/blacklist` catches symbols kprobes refuses to instrument.
The usual symbol-existence check, `grep -w <sym> /sys/kernel/tracing/available_filter_functions`,
needs `CONFIG_DYNAMIC_FTRACE`, which these targets do not have — panther's config carries
`# CONFIG_FUNCTION_TRACER is not set`, so the file does not exist. Where it is missing, the
interface answers the question itself: whether the kernel accepts a name written to `kprobe_events`
is a symbol-existence oracle, since it rejects a name it does not know. That is the technique
[`cves/lib/tools/symbol-shape.sh`](../lib/tools/symbol-shape.sh) uses in `probe` mode to decide
whether a fix is present on a device whose `/proc/kallsyms` is unreadable.

Installing the probe needs root and policy permitting tracefs writes, but the measured process does
not — so the normal arrangement is a rooted development device and an unprivileged trigger under
it. Remove every probe afterwards: an enabled probe changes the timing of everything measured
later, and timing is most of what this work measures.

Fetch arguments with the documented syntax when you need what was passed rather than merely that it
was called — `$arg1` for a register argument, `+0x8($arg1)` for a field of the structure it points
at, and `@ADDR` for a literal kernel address, each optionally suffixed with a type. A complete
line, in the form `kprobe.sh` writes:

```
# echo 'p:peek __arm64_sys_getpid word=@0xffffffc008001000:x64' > /sys/kernel/tracing/kprobe_events
```

Arming that on a syscall the probing shell is about to make, filtered to its own pid, turns the
probe into an arbitrary kernel read at an address you choose — which is how a derived struct offset
gets verified against the running kernel rather than assumed.

For the second, use BTF. BTF is the compact type-description format the kernel build generates
from DWARF and exposes at `/sys/kernel/btf/vmlinux`
([BPF Type Format, kernel documentation](https://docs.kernel.org/bpf/btf.html)). It is present on
any kernel built with `CONFIG_DEBUG_INFO_BTF`, which the arm64 GKI defconfig sets, so the gate-4
check above already answered whether your target has it.

Neither `pahole` nor `bpftool` exists on an Android device, so the blob is pulled and read on a
workstation. On a production build reading it needs root, so the pull goes through `su`:

```
$ adb shell su -c 'cat /sys/kernel/btf/vmlinux' > vmlinux.btf
$ pahole -F btf -C uhid_device --hex vmlinux.btf
struct uhid_device {
        struct hid_device *        hid;                  /*     0     8 */
        ...
        wait_queue_head_t          waitq;                /*  0x1170  0x18 */
        ...
};
```

`pahole -F btf -C <struct>` prints every member with its byte offset and size; with `--hex` those
offsets are directly usable as constants.

Split BTF is the case that bites on exactly this example. `uhid_device` is in vmlinux BTF here only
because `CONFIG_UHID=y` on this target; GKI builds most drivers as modules, and with
`CONFIG_DEBUG_INFO_BTF_MODULES=y` a module's types live in its own `/sys/kernel/btf/<module>` blob
that carries only the types the module adds, resolved against the base. Tell which case you are in
with `grep -w <driver> /proc/modules`, `ls /sys/kernel/btf/` and
`zcat /proc/config.gz | grep CONFIG_UHID`; for a type that turns out to be in a module, read it as
`pahole --btf_base /sys/kernel/btf/vmlinux /sys/kernel/btf/<mod>`, pulling both blobs, since the
module blob alone does not resolve its own base types.

The reachability-relevant conclusion is the same either way: an offset is a property of one build's
configuration and compiler, so it is derived per build and never copied. A field sitting after a
`struct mutex` is the standard trap, since lock structure size varies with `CONFIG_DEBUG_MUTEXES`
and lockdep — `# CONFIG_DEBUG_MUTEXES is not set` on this target, which is a config read, not an
assumption. Derive, then verify independently with a kprobe read at the address you computed.

When BTF is unavailable or unreadable, the fallback ladder — the matching GKI vmlinux, symbol
recovery from the shipped image with `vmlinux-to-elf`, and live structure walking with `drgn` or
`crash` — is set out in
[09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md), which owns it because
that is where the derived offsets end up being written to.

`/proc/kallsyms` sits awkwardly between these: it is the fastest way to resolve a symbol address,
and it is also the first thing hardened away. Under `kptr_restrict` the addresses print as zeros
rather than failing, so always sanity-check that the first column is nonzero before believing it.
Section [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) covers what to do
when it is not.

## Instruments

- `id`, `grep -E '^(Uid|Gid|Groups|CapEff)' /proc/self/status` — the calling process's uid, gids,
  supplementary groups and effective capabilities; no privilege required, but must be run inside the
  domain you are characterizing. It is the subject half of the DAC check only, and an empty
  `CapEff` is what rules out `CAP_DAC_OVERRIDE` bypassing the rest.
- `ls -lZ <path>` — owner, group, mode and SELinux type of an object in one line; unprivileged. The
  object half: mode bits decide which of the owner, group and other clauses applies.
- `getenforce`, `cat /proc/self/attr/current`, `ps -AZ` — global enforcing mode, own domain, and the
  domain of every visible process; unprivileged, though `ps -AZ` needs `AID_READPROC` to see others.
- `sesearch --allow|--allowxperm|--dontaudit -s <domain> -t <type> -c <class> <policy>` — whether a
  policy rule exists, including per-ioctl extended permissions; runs on a workstation over a binary
  policy pulled from the device or image. An empty `--allowxperm` result means every command is
  permitted, not none, and the numbers in the rules are the command's low 16 bits.
- `seinfo --stats <policy>`, `sedta -s <domain> <policy>`, `sesearch -T -s <domain> <policy>`,
  `sediff <old> <new>` — policy inventory, exec-transition reachability and the `type_transition`
  rules behind it, and what changed between two builds; workstation, SETools. The transition
  queries are informative for exec-entered domains and near-empty for app domains, which are
  labelled from `seapp_contexts` instead.
- `logcat -b all | grep 'avc: '` (unprivileged, via auditd's forwarding into logd),
  `su -c dmesg | grep 'avc: '` (privileged), `cat /sys/fs/pstore/console-ramoops-0` (across a
  reboot; read the path by name, since listing `/sys/fs/pstore` is denied), and `audit2allow` — the
  exact (scontext, tcontext, tclass, permission) tuple a denial refused. `cat
  /proc/sys/kernel/dmesg_restrict` says in advance which of the first two routes you have, and
  `dontaudit` rules mean an empty log is not evidence.
- `zcat /proc/config.gz | grep -E '<options>'`, `grep -w <driver> /proc/modules` — whether the
  vulnerable code is compiled into this kernel at all, and whether the vendor module backing a node
  is loaded; needs `CONFIG_IKCONFIG_PROC` and, on a production Pixel, root, with the matching
  GKI or factory build's config as the off-device substitute.
- `/sys/fs/selinux/access` and `/sys/fs/selinux/context`, via `selinux_check_access(3)` or
  `SELinux.checkSELinuxAccess` — ask policy whether an access would be allowed, and whether a type
  exists, without performing the operation; reachable only from domains policy permits.
- `grep -i seccomp /proc/self/status` plus the fork-and-check-`WTERMSIG` probe with the child's
  errno propagated through its exit status — which seccomp mode is installed, which syscalls the
  filter kills, and which reach a kernel that was not built with them; unprivileged, but must fork
  because the action is `SIGSYS`, and unavailable in a managed process that cannot fork.
- `service list`, `dumpsys -l`, `cmd -l`, `dumpsys package <pkg>`, `content query --uri` — the binder
  and component surface reachable from userspace; shell privilege.
- `echo 'p:name symbol' > /sys/kernel/tracing/kprobe_events` plus `tracing_on`, the event's
  `filter`, `enable` and `trace` files, and `kprobe_profile` for hit and miss counts — whether a
  kernel function was actually entered, and its arguments or memory at `@ADDR`; needs root, tracefs
  mounted, policy permitting it, and `CONFIG_KPROBE_EVENTS`. Relax `kptr_restrict` first or fetched
  pointers print masked.
- The same `kprobe_events` write with no `enable` — a symbol-existence oracle, because the kernel
  rejects a name it does not know; the fallback where `available_filter_functions` is absent for
  want of `CONFIG_DYNAMIC_FTRACE`.
- `adb shell su -c 'cat /sys/kernel/btf/vmlinux' > vmlinux.btf` then
  `pahole -F btf -C <struct> --hex vmlinux.btf`, or
  `pahole --btf_base vmlinux.btf <module>.btf` for a type in a module — struct layouts and field
  offsets on a kernel you cannot rebuild; needs `CONFIG_DEBUG_INFO_BTF` and, on a production build,
  root to read the blob. Neither `pahole` nor `bpftool` runs on the device.
- `/proc/kallsyms`, `/proc/slabinfo`, `/proc/vmallocinfo`, `/proc/buddyinfo`, `/proc/self/pagemap` —
  symbol addresses, cache inventory, vmalloc layout, free-page distribution and virtual-to-physical
  mapping; each is separately restricted, and several censor their content to zeros rather than
  failing, so test by reading and checking the values. `pagemap` checks the credentials the fd was
  opened with, so reopen it after any credential change.

## Grounded in this project

The domain-contrast methodology described here is implemented as a probe app under
[`domainprobe/`](../../domainprobe/): `domainprobe/app/src/main/cpp/probe.c` is one probe source
built both as a JNI library and as a pushed binary so the identical sweep runs in six different
SELinux domains, `domainprobe/probe-syscalls.sh` drives the one-syscall-per-boot procedure that
`SIGSYS`-killing filters force, and `domainprobe/README.md` records the per-domain conclusions that
retired or kept individual techniques. The group-membership argument for `/dev/uhid` is exercised by
[`cves/lib/trigger/uhid.c`](../lib/trigger/uhid.c); the binder and ActivityManager reachability
arguments, including which `IActivityManager` calls survive from an unprivileged shell, are
documented in [`cves/lib/trigger/binder.h`](../lib/trigger/binder.h) and
[`cves/lib/trigger/amclient.h`](../lib/trigger/amclient.h). Symbol-table and BTF-derived facts are
produced by [`cves/lib/tools/symbol-shape.sh`](../lib/tools/symbol-shape.sh) and
[`cves/lib/tools/kprobe.sh`](../lib/tools/kprobe.sh); the SELinux enforcement global whose offset is
derived by exactly the BTF procedure above is documented in
[`cves/lib/root/selinux_state.h`](../lib/root/selinux_state.h).

## See also

- [01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md) —
  where candidates come from, and whether the fix is present before asking whether it is reachable.
- [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) — what to do when
  `/proc/kallsyms` is censored and the address has to be leaked instead of read.
- [05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md) — the allocation primitives
  whose availability the syscall and socket-family sweeps here decide.
- [07-read-write-primitives.md](07-read-write-primitives.md) — turning a reachable bug into a
  primitive, using the struct offsets the BTF workflow supplies.
- [09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md) — the SELinux state a
  write primitive targets once DAC has been defeated, the capability sets and the namespace they
  are relative to, and the offset-derivation ladder for kernels whose BTF you cannot read.
- [10-survivability-and-measurement.md](10-survivability-and-measurement.md) — treating a
  reachability matrix as a measurement with a date and a build.
- [11-case-studies.md](11-case-studies.md) — the full chains in which these decisions were made.
- [12-further-reading-and-glossary.md](12-further-reading-and-glossary.md) — AID, domain, xperm and
  BTF in the glossary.
