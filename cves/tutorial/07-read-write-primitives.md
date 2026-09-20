# From a Bug to a Read/Write Primitive

A crash report tells you that something went wrong. It does not tell you what you can do. The step that turns a memory-safety defect into an exploit is the construction of a *primitive*: a function you can call, with arguments you choose, whose effect on kernel memory you can predict. Everything downstream — credential patching, SELinux state edits, module loading — is written against primitives, not against bugs. Once a bug is stated as `read(kaddr, len) -> bytes` and `write(kaddr, bytes)`, the rest of the exploit stops being a research problem and becomes ordinary programming.

A useful primitive is described by six properties, and skipping any of them is how exploits become flaky:

1. Domain — which addresses it can touch. A slab primitive reaches whatever shares its cache; a kernel-virtual primitive reaches the linear map, which on arm64 spans all of System RAM; a page-table primitive reaches physical frames through a mapping of your own, and needs no kernel address at all.
2. Granularity — a byte, a word, a page, or a fixed-size structure.
3. Repeatability — one shot, N shots, or unlimited. Single-shot primitives force you to spend your one write on something that bootstraps a better one.
4. Side effects — does exercising it corrupt refcounts, leave a dangling pointer, or arm a delayed panic at process exit?
5. Preconditions — what must already be known (a KASLR slide, a `struct page` address, a slab cache identity) before it can be aimed.
6. Verifiability — can you read back and confirm the primitive points where you think it does, before you use it?

The last property is the one most writeups omit and the one this section argues hardest for.

## Aiming a primitive needs the target's own offsets

Every primitive is aimed with offsets. `pipe_buffer.page` at +0 and `.flags` at +24 are facts about one kernel build on one architecture, not universal constants, and copying them out of a blog post is the most common cause of an exploit that works on the author's device and nowhere else.

One invocation settles the question for the device in hand:

```
adb pull /sys/kernel/btf/vmlinux
pahole -F btf -C pipe_buffer ./vmlinux
```

pahole prints one structure with `/* offset | size */` comments on each member and explicit `/* XXX N bytes hole */` markers. What you may conclude: the byte offset of every field, the total size — which decides the kmalloc bucket the object lands in — and where the compiler left padding you can corrupt harmlessly. What you may not conclude: that any of it transfers to a different build. The working rule for the rest of this section is that every offset an exploit uses is derived from the BTF of the device it will run on, and lives as a named constant in one header rather than as a literal at the point of use.

Availability has two independent failure modes and they need to be told apart. `/sys/kernel/btf/vmlinux` is mode 0444 upstream, but it exists only if the build set `CONFIG_DEBUG_INFO_BTF` — Android's kleaf pipeline documents [no runtime dependency on BTF](https://android.googlesource.com/kernel/build/+/refs/heads/master/kleaf/docs/btf.md) and offers `--btf_debug_info=disable` — and on Android it is readable only if SELinux permits the calling domain:

```
ls -lZ /sys/kernel/btf/vmlinux
dd if=/sys/kernel/btf/vmlinux bs=4096 count=1 of=/dev/null
```

`No such file or directory` means the build carries no BTF and type recovery has to come out of the image. `Permission denied` on the read, with the listing showing a file and a label, means the blob is present and policy is in the way, which is a different problem with different answers — a more privileged context, or the same BTF sliced out of the public boot image on a workstation. The recovery toolchain for both cases — `vmlinux-to-elf`, the `__start_BTF..__stop_BTF` slice out of a boot image, reading offsets out of accessor disassembly — is in [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md#recovering-structure-layout-and-symbols-without-rebuilding-the-kernel), which also carries the runtime-address half, including why `/proc/kallsyms` prints a column of zeros under `kptr_restrict`. The differential use of the same blob — two dumps of one structure, the target's against a build known to be on the far side of a fix, to decide whether the patch landed — is in [01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md).

Two further instruments belong to checking a primitive rather than building one. [drgn](https://drgn.readthedocs.io/en/latest/user_guide.html) debugs the running kernel by default — `sudo drgn`, with `-c` reserved for a vmcore or a userspace core dump — and evaluates Python against real structures (`prog["selinux_state"].enforcing`); it needs root and debug info. [crash](https://crash-utility.github.io/crash_whitepaper.html) does the same given a namelist plus a memory source (a dump file, or `/dev/mem` on a live system), offering `struct` for a formatted structure at an address, `rd` for raw memory in several widths, and `list` for walking a linked list of structures. On Android the memory source you actually get is pstore/ramoops — see [Crash Triage and Root-Cause Analysis](03-crash-triage-and-root-cause-analysis.md).

## The taxonomy: bug class to primitive

### A leaked or out-of-bounds pointer becomes an arbitrary read

The cheapest read comes from persuading the kernel to dereference a pointer you chose, through code that already exists. The canonical vehicle is `struct msg_msg`, the System V message object, whose header carries a length (`m_ts`) and a `next` pointer to a chained `msg_msgseg`. Corrupting `m_ts` upward turns `msgrcv()` into an out-of-bounds read of whatever follows the message in the slab; corrupting `next` makes the copy-out walk to an address of your choosing, and `MSG_COPY` lets you read the message repeatedly without unlinking and destroying it. The technique is laid out step by step in [Will's corCTF 2021 "Fire of Salvation" writeup](https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html).

Three preconditions decide whether it is available at all, and on Android none of them can be assumed. System V IPC must be compiled in; `MSG_COPY` requires `CONFIG_CHECKPOINT_RESTORE`, without which `prepare_copy()` in [`ipc/msg.c`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/ipc/msg.c) returns `ERR_PTR(-ENOSYS)`, and it must be paired with `IPC_NOWAIT` or `do_msgrcv()` in the same file returns `-EINVAL` before ever reaching the queue; and the SELinux `msgq` and `msg` classes must be allowed to the calling domain. The config half is one command wherever `CONFIG_IKCONFIG_PROC=y`, as on GKI:

```
zcat /proc/config.gz | grep -E 'CONFIG_SYSVIPC|CONFIG_CHECKPOINT_RESTORE'
```

and a short probe separates the ways it can fail at runtime:

```c
int q = msgget(IPC_PRIVATE, IPC_CREAT | 0600);      /* ENOSYS: no CONFIG_SYSVIPC   */
                                                    /* EACCES: SELinux msgq denial */
struct { long mtype; char m[16]; } snd = { 1 }, rcv;
msgsnd(q, &snd, sizeof snd.m, 0);
msgrcv(q, &rcv, sizeof rcv.m, 0, MSG_COPY | IPC_NOWAIT);  /* ENOSYS: no CHECKPOINT_RESTORE */
```

For the policy question ahead of time, `sesearch --allow -s untrusted_app -c msgq <policy>` against a pulled policy answers it offline — the same instrument [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) uses for leak sources. On this project's reference Pixel the answer is that the canonical technique is simply absent: `CONFIG_SYSVIPC` is not set, so there is no `msg_msg` type in the kernel and no queue to create. The substitute used throughout this project is `add_key()` with a `user`-type payload, whose `user_preparse()` allocates `24 + datalen + 1` bytes — a 200-byte payload lands squarely in `kmalloc-256`, is held until the key is unlinked, and allocates no `struct file` alongside it.

The generalizable shape: find a structure whose length or pointer field is consulted by a copy-to-user path, corrupt the field, and let the kernel perform the read.

### A use-after-free becomes type confusion, which becomes read and write

A dangling pointer is not itself a primitive. It becomes one when you refill the freed allocation with a different type whose fields overlap those the stale pointer still reaches. The reader and the writer disagree about what the bytes mean, and that disagreement is the primitive.

In the data-only direction, [DirtyCred](https://zplin.me/papers/DirtyCred.pdf) (Lin, Wu and Xing, CCS 2022, whose worked example is the CVE-2021-4154 `fs_context` file type confusion) corrupts nothing in the usual sense: it frees an unprivileged `struct cred` or `struct file` while a reference remains and races a privileged allocation of the same type into the slot, so the stale reference now names a privileged object. There is no forged pointer to get right and nothing to verify byte by byte, which is what makes it portable across kernels.

In the pointer direction, the target of choice holds a pointer the kernel will follow on an ordinary syscall, and `struct pipe_buffer` is the workhorse. Alexander Popov's [notes on its security properties](https://a13xp0p0v.github.io/2026/04/20/pipe-buffer-experiments.html) catalogue the options: overwriting `page`, `offset` and `len` gives arbitrary read and write, since `read()` and `write()` copy to and from the page you named; overwriting `ops` gives control flow; partially overwriting `page` aims one pipe at another pipe's page. Interrupt Labs' [pipe_buffer article](https://www.interruptlabs.co.uk/articles/pipe-buffer) works the same corruption through in code, including that the write path goes through `copy_page_from_iter()` and so needs the buffer marked mergeable.

Two engineering details decide where the array lands and whether you can tell. The size is under your control: a default 65536-byte pipe holds 16 entries of 40 bytes, 640 in total, while `fcntl(fd, F_SETPIPE_SZ, 2*PAGE_SIZE)` produces a 2-entry, 80-byte array. Which cache those land in is decided by the GFP flags as much as by the size. [`fs/pipe.c`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/fs/pipe.c) allocates the array with `kcalloc(pipe_bufs, sizeof(struct pipe_buffer), GFP_KERNEL_ACCOUNT)`, so on 5.14 and later it comes from the accounted set rather than the plain caches: 640 bytes to `kmalloc-cg-1k`, and 80 bytes to `kmalloc-cg-96` on x86 — but to `kmalloc-cg-128` on the arm64 GKI 6.1 ladder, whose `KMALLOC_MIN_SIZE` of 64 means there is no 96-byte cache to land in. [05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md#mapping-an-object-to-a-cache) derives that ladder from `ARCH_DMA_MINALIGN` and shows where it moved again after 6.5. Derive both halves rather than copying them — `grep -n 'GFP_KERNEL_ACCOUNT' fs/pipe.c` for the matching release, confirmed on a rooted reference device with

```
bpftrace -e 'kprobe:kmem_cache_alloc { @[str(((struct kmem_cache *)arg0)->name)] = count(); }'
```

or a `/proc/slabinfo` delta taken across a thousand `pipe()` calls. The split collapses when kmem accounting is off (`cgroup.memory=nokmem` on the command line, or `CONFIG_MEMCG_KMEM=n`), where `kmalloc-cg-N` and `kmalloc-N` are literally the same `kmem_cache` and the distinction stops mattering. [Heap Grooming and Spraying](05-heap-grooming-and-spraying.md) has the instruments for the cache-merging question generally — `/sys/kernel/slab/<cache>/aliases`, the `:0000256`-style symlinks, and `slabinfo -a` — and they are better than inferring merging from a cache's absence in `/proc/slabinfo`.

The second detail is a trap rather than a knob. `/proc/sys/fs/pipe-user-pages-soft` (16384 pages) does not cap a pipe spray. `alloc_pipe_info()` tests `too_many_pipe_buffers_soft()` and, for an unprivileged user over the line, sets `pipe_bufs = PIPE_MIN_DEF_BUFFERS` — 2 — and carries on. The `pipe()` call still succeeds; the array it allocates is 80 bytes — `kmalloc-cg-128` on the arm64 ladder above — instead of 640 in `kmalloc-cg-1k`. A spray that crosses the limit therefore keeps reporting success while silently populating the wrong cache, which is a mis-targeting bug that looks like bad luck. Resize immediately after creation, or keep the count below the threshold.

### A direct out-of-bounds write corrupts the neighbour

When the bug writes past the end of an allocation you need no type confusion, only the right neighbour at the right distance. The reference case is [CVE-2021-22555](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html), a fifteen-year-old netfilter bug that wrote four zero bytes at a controllable offset up to 0x4C bytes out of bounds. Four zero bytes is not obviously a primitive; the writeup's contribution is the chain that makes it one, and the controllable offset is what lets the zeros be aimed at a chosen field of an adjacent `msg_msg` header rather than at whatever happens to sit immediately past the allocation. Zeroing that field produces the out-of-bounds read above, and from there full read/write and code execution. Evaluate an OOB write by what it can reach, not by how many bytes it moves.

### Forging objects through legitimate interfaces

Rather than corrupting a live object, construct a complete, plausible object in memory you control and persuade a kernel interface to interpret it — ideally an interface whose job is already to print kernel-derived state back to userspace.

`/proc/<pid>/maps` is the clean example. Its seq_file handler walks the calling process's VMA tree and formats what it finds into text. Since 6.1 that tree is a maple tree rooted at `mm_struct.mm_mt`, and the write target is a single field inside it: `mm->mm_mt.ma_root`. A maple tree holding exactly one entry does not allocate a node for it; the entry pointer is stored directly in `ma_root`, with the low bits reserved for the tree's internal encodings. An 8-byte-aligned pointer written there is read back as *the one entry in the tree*, which is what makes a single 8-byte write sufficient — no node has to be forged, and no node layout has to be recovered.

Offsets come from the target's own BTF, as everywhere else:

```
pahole -F btf -C mm_struct ./vmlinux | grep -n 'mm_mt\|ma_root'
pahole -F btf -C vm_area_struct ./vmlinux
```

On this project's reference build `mm_mt` sits at the start of `mm_struct` and `ma_root` is its first member, so the write target is `mm + 0x08`.

The forged object then has to be byte-valid for exactly the fields `show_map_vma()` in [`fs/proc/task_mmu.c`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/fs/proc/task_mmu.c) touches, and no others. It reads `vm_start` and `vm_end` for the address column, `vm_flags` for the permission column, and `vm_file`; when `vm_file` is non-NULL it also reads `vm_pgoff` for the offset column and dereferences `file->f_inode->i_sb->s_dev` and `->i_ino` for the device and inode columns, then calls `seq_file_path()` — that is, `d_path()` — on `file->f_path`. The last of those is the read primitive: `d_path()` copies `dentry->d_name.len` bytes from `dentry->d_name.name`, so setting `d_name.name` to an arbitrary kernel address and `d_name.len` to a length prints those bytes as the pathname column of a `/proc/self/maps` line, on demand, as many times as you ask.

Two properties of that path are what make it usable rather than merely reachable. It takes no references — no `path_get`, `mntget`, `dget` or `fput` — so nothing has to be unwound and no per-CPU mount counter is written. And it makes no indirect calls as long as the forgery sets `d_op = NULL` and leaves `vm_file` non-NULL, which skips the `vm_ops->name` branch; on a CFI kernel that is the difference between a read and an immediate `Oops - CFI`. The remaining objects — a `struct file`, `inode`, `super_block`, two `dentry`s, a `mount` with its embedded `vfsmount`, and a `mnt_namespace` with a non-zero `seq` — are constructed in free space on the same forged page, each populated only in the fields the walk consults.

The pattern to look for generally is a kernel path that follows a pointer you can set, walks a structure whose layout you know from BTF, and emits derived values to userspace; `/proc` and sysfs are full of them. Before 6.1 the same idea against `/proc/<pid>/maps` targets `mm->mmap`, the head of a VMA linked list, which is a different structure with a different walk — the maple tree replaced it in 6.1, so this forgery is version-bounded on both sides.

The constraint is teardown, and it is specific rather than general. `exit_mmap()` walks the VMA tree through `free_pgtables()` and `unlink_anon_vmas()`, and a forged root does not survive that walk. The hazard is wider than "do not call `exit()`": once `ma_root` is corrupt, any fault in any thread — a data access, stack growth, or an instruction fetch of a code page that was never resident or has since been reclaimed — resolves through `find_vma()` against the single-entry forgery, fails, and raises SIGSEGV, which reaches `do_group_exit()` and therefore `exit_mmap()`. The working answer is to install SIGSEGV and SIGBUS handlers on a pre-faulted alternate stack that park the faulting thread forever, and to park the process itself rather than return. See [Survivability, Stabilization, and Treating Exploitation as an Experiment](10-survivability-and-measurement.md).

## Dirty Pipe: one uninitialized flag

The clearest demonstration that a primitive can come from metadata rather than data is CVE-2022-0847, published by Max Kellermann as [The Dirty Pipe Vulnerability](https://dirtypipe.cm4all.com/).

The mechanism is a bookkeeping failure. Commit [241699cd72a8, "new iov_iter flavour: pipe-backed"](https://github.com/torvalds/linux/commit/241699cd72a8) (Linux 4.9) added pipe-backed iov_iter functions that allocate a `struct pipe_buffer` but never initialize its `flags` member. That was harmless until commit [f6dd975583bd, "pipe: merge anon_pipe_buf*_ops"](https://github.com/torvalds/linux/commit/f6dd975583bd) (Linux 5.8) converted the "may this buffer be appended to in place" decision from a comparison of `ops` pointers into a per-buffer flag, `PIPE_BUF_FLAG_CAN_MERGE`. From 5.8 onward a `pipe_buffer` created by splicing page-cache data inherited whatever `flags` value the ring slot last held, and if that stale value included the merge bit, a subsequent `write()` to the pipe went straight into the page cache page belonging to the spliced file.

The exploit is five steps: fill and drain a pipe so every ring entry carries the merge flag; open the target file `O_RDONLY`; `splice()` one byte from just before the target offset into the pipe; `write()` the replacement bytes; the kernel merges them into the page cache.

Two consequences follow from two different facts, and conflating them is a common mistake. The page is not marked dirty, so writeback never picks it up and the change lives only in memory until the page is evicted — that is why the effect is transient. No write permission is needed for an unrelated reason: the bytes arrive through `pipe_write()`'s merge path, which calls `copy_page_from_iter()` on the page directly. The file's write path is never entered, so its permission check is never reached. Read permission is required only because `splice()` needs it.

Kellermann states the constraints explicitly, and they are a model for documenting any primitive: the offset must not be on a page boundary; the write cannot cross a page boundary; the attacker must have read permission; the file cannot be resized. Fixes shipped in 5.16.11, 5.15.25 and 5.10.102.

Four checks establish whether a given build is affected and whether a given attempt worked:

```
pahole -F btf -C pipe_buffer ./vmlinux              # is there a flags member, and at what offset
git log --oneline -1 f6dd975583bd                   # the commit that introduced the flag
bpftrace -e 'kprobe:copy_page_from_iter /comm == "poc"/ {
    printf("page=%p off=%d len=%d\n", arg0, arg1, arg2); }'
sync; echo 3 > /proc/sys/vm/drop_caches             # root: does the file revert
```

`pahole` answers the structural half — a `flags` member exists from 5.8, and its offset on this build is what the exploit will use. Presence reasoning is a version window: affected from 5.8 up to the three fix releases, applied to whatever release the banner names, as [01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md) sets out. The bpftrace probe watches the transfer itself, and the second argument is what distinguishes the two paths: `pipe_write()`'s merge branch passes `buf->offset + buf->len`, which is non-zero for a spliced buffer, while the ordinary branch allocates a fresh page and passes offset 0. Seeing a non-zero offset on a page you never allocated is the merge path being taken. It needs root and BPF, so it is a reference-device instrument. The last line is the confirmation that the effect is page-cache-only rather than on disk: after the write, a second process reading the file sees the modified bytes, and `drop_caches` restores the original content from storage.

As a primitive, Dirty Pipe is an arbitrary write into the page cache of any readable file, hence an arbitrary write to any file a privileged process will later read. It reaches userspace state, not kernel memory. What makes it cheap to deploy is that it needs no leak, no heap grooming and no KASLR defeat: the setup is deterministic and the effect is verifiable by reading the file back.

## Page tables: turning a write into all of memory

A write primitive confined to slab objects is limited by what happens to be nearby. The way out is to aim it at a page table. Last-level page tables are ordinary order-0 pages from the buddy allocator, and each 8-byte PTE holds a physical frame number plus permission bits. If a freed slab page is reused as a page-table page — or a page-table page as a slab object — then a write to your object writes a PTE, and the next access to the corresponding userspace virtual address touches a physical frame of your choosing, with permissions of your choosing.

What that buys is worth stating precisely, because the usual formulation overstates it. On arm64 the linear map covers all System RAM, so another process's pages are *already* reachable from a kernel-virtual primitive — `__va(pa) = (pa - PHYS_OFFSET) | PAGE_OFFSET`, the formula established in [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) and implemented in `cves/lib/addr/physmap.h`. The real advantages are three others. A page-table primitive needs no KASLR slide and no kernel address at all, because the address you use afterwards is your own userspace VA. Its result is cheap to verify — you read your own mapping back and compare against something you know. And it can name physical ranges that have no linear-map alias: a PTE takes a raw output address, whereas the linear map covers only what the kernel mapped, excluding NOMAP regions and firmware carveouts. `cat /proc/iomem` as root lists the `System RAM` ranges; everything outside them has no `__va()` and is reachable, if at all, only through a page table.

The value you write is the part the technique's name hides, so here is one, field by field, for a read-write non-executable user mapping. Take a PFN from `/proc/self/pagemap` — say 0x123456 — and assemble, with the bit definitions from [`arch/arm64/include/asm/pgtable-hwdef.h`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/include/asm/pgtable-hwdef.h) for the matching release:

| bits | macro | value | meaning |
| --- | --- | --- | --- |
| 1:0 | `PTE_TYPE_PAGE` | `0b11` | valid, and a page descriptor at level 3. Clear bit 0 and the entry faults. |
| 4:2 | `PTE_ATTRINDX(t)` | `0` | MAIR index. `MT_NORMAL` is 0 in 6.1 ([`arch/arm64/include/asm/memory.h`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/include/asm/memory.h)), but the numbering has changed across releases — take it from the target's header, or copy it out of an existing user PTE. |
| 6 | `PTE_USER` | `1` | AP[1]: EL0 may access. |
| 7 | `PTE_RDONLY` | `0` | AP[2]: clear means writable. |
| 9:8 | `PTE_SHARED` | `0b11` | inner shareable. |
| 10 | `PTE_AF` | `1` | access flag. Omit it and the first access takes an access fault instead of the mapping you wanted. |
| 11 | `PTE_NG` | `1` | not global; user mappings are ASID-tagged. |
| 47:12 | output address | `0x123456` | the frame, `PFN << 12`. |
| 53 | `PTE_PXN` | `1` | not executable at EL1. |
| 54 | `PTE_UXN` | `1` | not executable at EL0. |

which gives `0x0060000123456f43`. Linux's own software bits — `PTE_WRITE` (bit 51, aliased onto hardware DBM) and `PTE_DIRTY` (bit 55) — are absent from that value deliberately: the MMU does not consult them on a load or store, and they matter only if the kernel later walks the entry, in `fork()`, `mprotect()` or `munmap()`. An entry the kernel wrote for a shared writable mapping looks different — `PAGE_SHARED` in [`arch/arm64/include/asm/pgtable-prot.h`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/include/asm/pgtable-prot.h) sets `PTE_RDONLY | PTE_WRITE`, the writable-clean DBM encoding — which is worth knowing if anything is going to inspect your forgery.

Observing page tables is the other half, and `/proc` covers most of it. Whether a given mapping pattern creates page-table pages at all, and how many, is visible directly:

```
grep VmPTE /proc/self/status        # this process's page-table bytes
grep PageTables /proc/meminfo       # system-wide
```

Faulting in an `mmap` of *n* MiB and watching `VmPTE` climb by 4 KiB per 2 MiB of populated address space is how you calibrate a spray that is supposed to produce PTE pages — it converts "spray page tables" from an instruction into a measured quantity. Whether a *particular* page is a page table, and whether a freed slab page can come back as one, are the other two questions:

```
mount -t debugfs none /sys/kernel/debug        # reference device, CONFIG_PAGE_OWNER=y page_owner=on
cat /sys/kernel/debug/page_owner > owner.txt    # PFN, order, GFP flags and stack per page
tools/mm/page_owner_sort owner.txt sorted.txt   # grouped by allocation site
cat /proc/pagetypeinfo                          # root: free pages per order per migratetype
```

`page_owner` records the allocation stack of every tracked page, which identifies a page-table page positively — by the `pte_alloc_one` frame in its stack and the `__GFP_ACCOUNT|__GFP_ZERO` in its flags — rather than by inference from what else is nearby. `/proc/pagetypeinfo` answers the migratetype question that decides whether a page freed from a slab can be handed to a page-table allocation at all: both come from the buddy allocator, but a free block only satisfies a request of a different migratetype through fallback, and the counts per type are what say how likely that is.

Two allocator facts constrain the timing. PTE pages are allocated with `GFP_PGTABLE_USER` (`GFP_KERNEL | __GFP_ZERO | __GFP_ACCOUNT`, defined in [`include/linux/gfp.h`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/gfp.h) and passed by `pte_alloc_one()` in [`include/asm-generic/pgalloc.h`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/asm-generic/pgalloc.h), which arm64 uses unchanged), so they are zeroed order-0 buddy pages, not slab objects. And they are freed through the RCU table-free path: arm64 selects `CONFIG_MMU_GATHER_RCU_TABLE_FREE`, so a page table released by `munmap()` is not returned to the allocator until a grace period elapses. A reclaim that does not account for that deferral measures the wrong window.

This is [Dirty Pagetable](https://yanglingxi1993.github.io/dirty_pagetable/dirty_pagetable.html), by Nicolas Wu and Ye Zhang, demonstrated on a Pixel 7 against CVE-2023-21400. The writeup develops two setups — a double-free and a UAF write — and shows that even an increment primitive suffices *once the number of increments can be multiplied*. A bare increment does not: incrementing a PTE's physical-address field does walk the mapping across physical memory one frame at a time, but a single process can hold at most 32768 file descriptors, so `dup()` alone caps the count far below what is needed. The writeup recovers the technique by repeating `fork()` and `dup()`, each fork contributing its own budget of increments. The variant in Notselwyn's [Flipping Pages](https://pwning.tech/nftables/) (CVE-2024-1086, nf_tables double-free) sprays PMDs rather than PTEs, which is the point: "If we spray PMDs, the PTEs will be allocated as well - from the same freelist. This means that 50% of the spray is PMD, and 50% is PTE." The double-freed page is therefore claimed as a page table reachable through one userspace mapping while writes arrive through another; the author reports 99.4% success across 1000 attempts on 6.4.16.

For the virtual-to-physical direction there is `/proc/<pid>/pagemap`, one 64-bit entry per virtual page, bits 0–54 holding the PFN, bit 55 soft-dirty and bit 63 present. The caveat is in the [kernel documentation](https://docs.kernel.org/admin-guide/mm/pagemap.html): "Since Linux 4.0 only users with the CAP_SYS_ADMIN capability can get PFNs... Starting from 4.2 the PFN field is zeroed if the user does not have CAP_SYS_ADMIN." An unprivileged reader gets present and swapped bits but a zero PFN. Two conclusions follow: pagemap is a verification instrument, not an unprivileged oracle; and a partial escalation granting `CAP_SYS_ADMIN` unlocks exact physical-page knowledge for the rest of the chain, which is often reason enough to stage an escalation in two steps.

The other `/proc` instruments for physical layout: `cat /proc/buddyinfo` prints, per zone, the count of free blocks at each order from 0 to 10, and watching a specific order's count change when you free a slab page is how you confirm the page actually returned to the buddy allocator rather than being cached on a per-CPU list — the distinction that decides whether cross-cache reuse is possible at all. `cat /proc/zoneinfo` gives zone boundaries, watermarks and per-CPU list sizes; `cat /proc/vmallocinfo` gives vmalloc mappings with sizes and allocating callers, and is root-only because it leaks kernel virtual addresses.

[USMA](https://i.blackhat.com/Asia-22/Thursday-Materials/AS-22-YongLiu-USMA-Share-Kernel-Code-wp.pdf) (Liu, Wang and Yao, Black Hat Asia 2022) inverts the direction: it maps a kernel code section into userspace to be overwritten directly, sidestepping control-flow integrity because the code executed afterwards is reached legitimately. The paper works from the double free in `packet_set_ring()` in [`net/packet/af_packet.c`](https://github.com/torvalds/linux/blob/v5.11/net/packet/af_packet.c) on 5.11.20 without naming an identifier; that bug is [CVE-2021-22600](https://www.cve.org/CVERecord?id=CVE-2021-22600), fixed by commit ec6af094ea28, per the CVE record rather than the paper.

## Read before you write

Every technique above shares a structural weakness: the setup that puts your object where you need it is probabilistic. Slab reuse, cross-cache reuse, page-table aliasing — each depends on an allocation landing in a slot you do not directly observe. The probability is often good and sometimes excellent, but it is never one.

The asymmetry that follows is the operational point. A read that lands on the wrong object returns garbage; you notice, retry, and lose nothing. A write that lands on the wrong object corrupts a structure belonging to another subsystem, and the outcomes are immediate panic, delayed panic in a context that destroys your evidence, or silent corruption that makes every subsequent measurement in that boot a lie. The cost of a failed read is a retry; the cost of a failed write is the boot, and often the trust you had in the last ten experiments.

Put numbers on it. Let *p* be the probability that one setup attempt lands the object where you intend, and take *p* = 0.2, which is a realistic figure for a cross-cache reclaim driven by a bounded spray. A blind write succeeds with probability 0.2, on every attempt, forever: there is no abort branch, so the first attempt commits unconditionally and the exploit's success rate is exactly the setup's landing rate. A verified write succeeds with probability 1 − (1 − *p*)^N over N attempts: 89% at N = 10, 99.9% at N = 31. Determinism is not a property of the write; it is a property of the loop around the write.

That formula holds only under two conditions, and an exploit that violates either does not converge no matter how many times it retries:

1. A failed verification must be non-destructive. The check reads; the abort path must leave nothing dangling, nothing double-freed and no reference count wrong, or attempt N+1 starts from a worse state than attempt N and the per-attempt probability decays instead of staying constant.
2. Each retry must re-roll the placement independently. If the failed attempt leaves the allocator in the state that caused the miss — the same partial slab at the head of the freelist, the same per-CPU cache contents — then the attempts are correlated, the product does not telescope, and a hundred retries buy little more than one.

Verification means reading a field whose correct value you already know, through the same aliasing you are about to write through. For the cross-cache case — "does the page I control alias the slab page I aimed at?" — the page descriptor answers it directly, and four independent properties together are conclusive. Read them with `pahole -F btf -C page ./vmlinux` in hand for the offsets:

1. `page->flags` has `PG_slab` set: the page belongs to the slab allocator at all.
2. `page->flags` has `PG_head` set: it is the first page of a compound allocation, which is what a reclaim of a higher-order page must land on.
3. The *following* descriptor's `compound_head` equals `descriptor | 1`. The low bit is what marks that word as a back-pointer to the head rather than an ordinary pointer, and this test is what rules out a page that merely looks plausible. The same tail descriptor carries the allocation order in the low byte of its flags word, so the expected order is checkable in the same read.
4. The cache pointer names the cache the reclaim expected, compared after clearing any tag in the top byte of the pointer.

The bit indices are not literals. `PG_slab` and `PG_head` are members of `enum pageflags` in [`include/linux/page-flags.h`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/page-flags.h), and that enum is conditional on configuration — `CONFIG_MMU`, `CONFIG_MEMORY_FAILURE`, `CONFIG_PAGE_IDLE_FLAG` and `CONFIG_KASAN_HW_TAGS` each add members — so the index of a flag depends on the build. Take it from the target's own BTF (`bpftool btf dump file /sys/kernel/btf/vmlinux format c` and read the enum) rather than from a header of a different release; on 6.1 with the GKI configuration they come out at 9 and 16. The implementation, including the tag-clearing comparison and a report structure that says *which* of the four checks failed rather than only that one did, is `cves/lib/rw/slabpage.h` and `slabpage.c`.

If instead you believe you have resolved another process's credential structure, the same discipline applies with a different field: read a value you set yourself, or a pointer that must point back at a structure you can locate independently, and require the match before writing.

The literature bears this out from the other direction. The Flipping Pages author states plainly that he "did not want to use cross-cache attacks for stability and compatiblity related reasons", and reports success measured over a thousand runs — an exploit engineered so its failure modes are countable rather than catastrophic. The systematic treatment of how page-level spraying behaves statistically is [Understanding Page Spray in Linux Kernel Exploitation](https://www.usenix.org/system/files/usenixsecurity24-guo-ziyi.pdf) (Guo et al., USENIX Security 2024). The mechanics of raising the landing rate are in [Cross-Cache Attacks](06-cross-cache-attacks.md); no improvement there substitutes for a check.

## Promoting a primitive

Primitives form a ladder, and the shape of a mature chain is one slow, awkward, single-shot primitive used exclusively to install a fast, clean, repeatable one. The classic promotion is into a pipe: spend a single 40-byte kernel write on a `pipe_buffer` entry, and `read()` and `write()` on that pipe become a physical read and write repeatable indefinitely with no further corruption.

The field values differ between the two directions, and getting them backwards is the difference between a primitive and a panic. Both cases assume the target address is within one page; `offset` is `target & (PAGE_SIZE - 1)` in both.

For a read of *N* bytes, set `page` to the page descriptor (see the conversion below), `offset` to the in-page offset, and `len` to *N* + 1 — then `read(fd, buf, N)`. The extra byte is what keeps the entry alive. `pipe_read()` in [`fs/pipe.c`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/fs/pipe.c) does `buf->len -= chars` and then

```c
		if (!buf->len) {
			pipe_buf_release(pipe, buf);
```

and `pipe_buf_release()` calls `ops->release`, which for anonymous pipes is `anon_pipe_buf_release()` and ends in `put_page()` on a page you forged and do not own. Leaving one byte in the entry means the branch is never taken. The `ops` pointer matters for the same reason: `pipe_buf_confirm()` calls `ops->confirm` if it is non-NULL, so point `ops` at operations that have none (`anon_pipe_buf_ops` in 6.1 defines only `release`, `try_steal` and `get`).

For a write, set `len` to *0* and `flags |= PIPE_BUF_FLAG_CAN_MERGE`. Zero, not the length: the merge path calls

```c
			ret = copy_page_from_iter(buf->page, offset, chars, from);
```

with `offset = buf->offset + buf->len`, so any non-zero `len` displaces the write past the target by that many bytes. Three further conditions decide whether `pipe_write()` in [`fs/pipe.c`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/fs/pipe.c) takes the merge path at all, and all three are on you to satisfy — read them off the guard in the release you are targeting, since the merge path has been rewritten more than once since 5.8:

1. The pipe must be non-empty. The guard is `if (chars && !was_empty)`, with `was_empty = pipe_empty(head, pipe->tail)`.
2. The forged entry must occupy the `(head - 1) & mask` slot — the merge path uses that one entry and no other.
3. The write length must not be a multiple of `PAGE_SIZE`, because `chars = total_len & (PAGE_SIZE-1)` and a zero `chars` fails the same guard. The path additionally requires `offset + chars <= PAGE_SIZE`.

In both directions the entry is borrowed, not taken: it belongs to a live pipe, so save it before and restore it after, or the next ordinary use of that pipe — including its close — faults. A stronger variant: if the page holding the `pipe_buffer` array is one you *also* map in userspace, re-aiming is a plain `memcpy` on your own mapping and the kernel write is needed exactly once.

The field the recipe glosses over is `page`, and it is the one derivation that cannot be skipped. `pipe_buffer.page` is a `struct page *` — an address in the vmemmap array — not a physical address and not a linear-map address. The conversion from a frame number is

```
page = VMEMMAP_START + (PFN - PHYS_PFN(PHYS_OFFSET)) * sizeof(struct page)
```

and all three constants are per-target. On this project's reference device `PHYS_OFFSET` is 0x80000000, so `PHYS_PFN(PHYS_OFFSET)` is 0x80000; `VMEMMAP_START` is 0xfffffffe00000000; and `sizeof(struct page)` is 0x40. A PFN of 0x1c2f3d read out of `/proc/self/pagemap` therefore converts as

```
0x1c2f3d - 0x80000 = 0x142f3d          index into the descriptor array
0x142f3d * 0x40    = 0x50bcf40         byte offset
0xfffffffe00000000 + 0x50bcf40 = 0xfffffffe050bcf40
```

Derive each constant for the target rather than copying these. `sizeof(struct page)` comes from `pahole -F btf -C page ./vmlinux` — do not assume 64, since the size depends on configuration. The start of RAM comes from `su -c 'grep "System RAM" /proc/iomem'` or from the device tree at `/proc/device-tree/memory@*/reg`, and [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) covers why it is constant on arm64 and how to confirm it. `VMEMMAP_START` comes from `readelf -s vmlinux.elf | grep -i vmemmap`, or from the arm64 definition in [`arch/arm64/include/asm/memory.h`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/include/asm/memory.h) for the matching release: it is `-(1 << (VA_BITS - VMEMMAP_SHIFT))`, which for `VA_BITS=39` and 64-byte descriptors gives 0xfffffffe00000000.

The subtraction is the part that gets forgotten. The descriptor array is indexed from the *first frame of RAM*, not from PFN 0 — the kernel's own `vmemmap` symbol is `(struct page *)VMEMMAP_START - (memstart_addr >> PAGE_SHIFT)`, with the base already folded in — so a raw pagemap PFN must have `PHYS_PFN(PHYS_OFFSET)` subtracted before it is scaled. Omitting it yields an address that is plausible, in range, and wrong; the conversion lives in one place, `cves/lib/addr/physmap.h`, so this subtraction is applied consistently rather than re-derived per caller.

## A ground-truth read for a privileged context

When you already hold privilege there is a primitive that needs no bug at all, and it is the right tool for checking the claims of one that does. Kprobe-based event tracing fetches a word from a literal kernel address into a trace record ([kprobetrace documentation](https://docs.kernel.org/trace/kprobetrace.html)). The full sequence, including the steps that are usually omitted and that account for most reports of "it returns nothing":

```
echo 0 > /proc/sys/kernel/kptr_restrict
echo 'p:peek __arm64_sys_getpid w0=@0xffffff8012345678:x64' > /sys/kernel/tracing/kprobe_events
echo 1 > /sys/kernel/tracing/events/kprobes/peek/enable
echo 1 > /sys/kernel/tracing/tracing_on
./trigger                                  # must issue syscall(__NR_getpid) directly
cat /sys/kernel/tracing/trace
echo 0 > /sys/kernel/tracing/tracing_on
echo > /sys/kernel/tracing/kprobe_events
```

The trace line contains `w0=0x...`: the eight bytes living at that address when the probe fired. The grammar supports `@ADDR` for absolute kernel memory, `+OFFS(FETCHARG)` for dereference, `$argN`/`$retval` and explicit types.

Three things go wrong, and their signatures are distinguishable:

1. The write to `kprobe_events` fails outright. Kernels disagree about whether the sized spelling is accepted, so retry with the bare form `w0=@0xffffff8012345678` and no type suffix. Arming both spellings in turn, taking whichever the kernel accepts, is what `cves/lib/rw/kprobe_read.c` does.
2. `trace` contains no `peek:` line at all. The probe never fired. bionic answers `getpid()` from a cached value after the first real call, so a trigger that calls the libc wrapper in a loop issues no syscall at all and the probe sits idle. Call `syscall(__NR_getpid)` directly, and pick a probe point whose wrapper cannot be short-circuited this way.
3. A `peek:` line exists but the value is not what an independent source says is at that address. Check `cat /proc/sys/kernel/kptr_restrict` before blaming the address: the fetched pointer comes back masked unless it is 0, which is why the sequence above writes it first and why the library restores it on every exit path, successful or not.

The conclusion you may draw from a clean read is ground truth about kernel memory, independent of any corruption primitive. The cost is write access to tracefs, so it is a root- or debug-context instrument, and every probe left enabled perturbs the timing of everything that runs afterwards — hence the two teardown lines, not just a warning. Where BPF and BTF are present, [bpftrace](https://bpftrace.org/) covers the same ground with struct-aware syntax, for example `bpftrace -e 'kprobe:vfs_read { printf("%d\n", ((struct file *)arg0)->f_inode->i_ino); }'`.

Sanitizer reports — KASAN naming the object you corrupted, KFENCE sampling in production — are the subject of [Crash Triage and Root-Cause Analysis](03-crash-triage-and-root-cause-analysis.md). One arm64-specific question belongs here, because it changes what a mis-aimed primitive does: whether hardware tag-based KASAN (MTE) is active, since with tags on, a primitive aimed one object off faults immediately instead of returning plausible bytes. Three checks, cheapest first:

```
grep -o '\bmte\b' /proc/cpuinfo                              # CPU feature present
zcat /proc/config.gz | grep -E 'KASAN_HW_TAGS|ARM64_MTE'     # built in
cat /proc/cmdline | tr ' ' '\n' | grep kasan                 # switched on at boot
```

On this project's reference Pixel the build sets `CONFIG_KASAN_HW_TAGS=y` and MTE is nonetheless inactive at runtime, which is the ordinary retail configuration: compiled in, not switched on. That has a second consequence worth carrying — tag checks will not catch your mistakes for you, so a stray write is silent and a UAF that touches freed memory looks identical from outside to one that touches nothing.

## Instruments

- `pahole -F btf -C <struct> ./vmlinux` — field offsets, sizes and padding holes, from the target's own BTF; workstation, no device.
- `bpftool btf dump file /sys/kernel/btf/vmlinux format c` — every kernel type as C, including the `enum pageflags` indices; needs BTF in the build and read access to the blob.
- `ls -lZ /sys/kernel/btf/vmlinux` plus an actual read — distinguishes "no BTF in this build" (ENOENT) from "SELinux denies it" (EACCES).
- `sudo drgn` — scripted walking of live kernel structures; `-c <vmcore>` for a dump. Needs root and debug info.
- `crash <namelist> <memory-source>` — `struct`, `rd` and `list` over `/dev/mem` or a dump file.
- `zcat /proc/config.gz | grep -E 'CONFIG_SYSVIPC|CONFIG_CHECKPOINT_RESTORE'` — whether `msg_msg` and `MSG_COPY` exist at all; needs `CONFIG_IKCONFIG_PROC`.
- `sesearch --allow -s <domain> -c msgq <policy>` — whether the calling domain may use System V queues; workstation, against a pulled policy.
- `cat /proc/buddyinfo`, `cat /proc/zoneinfo` — free-block counts per order per zone; confirms a page reached the buddy allocator; unprivileged.
- `cat /proc/pagetypeinfo` — free pages per order per migratetype, which decides whether a freed slab page can serve a page-table allocation; root.
- `cat /proc/vmallocinfo` — vmalloc mappings with sizes and callers; root.
- `grep VmPTE /proc/self/status`, `grep PageTables /proc/meminfo` — page-table pages created by a mapping pattern, measured rather than assumed; unprivileged.
- `/sys/kernel/debug/page_owner` with `CONFIG_PAGE_OWNER=y page_owner=on` — the allocation site of a specific page; reference device only.
- `su -c 'grep "System RAM" /proc/iomem'` — the physical ranges the linear map covers, and by exclusion the ones only a page table can reach; root.
- `/proc/<pid>/pagemap` — virtual-to-PFN mapping, bits 0–54 PFN, bit 63 present; PFN zeroed without `CAP_SYS_ADMIN` since 4.2.
- `echo 0 > /proc/sys/kernel/kptr_restrict; echo 'p:peek SYM w0=@ADDR:x64' > /sys/kernel/tracing/kprobe_events` — arbitrary kernel read at a probe point; needs tracefs write access, a direct `syscall()` trigger, and teardown afterwards.
- `bpftrace -e 'kprobe:fn { ... }'` — the same with struct-aware field access, and the way to watch `copy_page_from_iter()` take the merge path; needs BPF, BTF and root.
- `fcntl(fd, F_SETPIPE_SZ, n)` — choose the size, and therefore the accounted cache, a `pipe_buffer` array lands in; unprivileged. `/proc/sys/fs/pipe-user-pages-soft` is the threshold past which the kernel silently gives you 2-entry pipes instead.
- `grep -o '\bmte\b' /proc/cpuinfo`, `zcat /proc/config.gz | grep -E 'KASAN_HW_TAGS|ARM64_MTE'`, `cat /proc/cmdline | tr ' ' '\n' | grep kasan` — whether tag checks will catch a mis-aimed primitive.

## Grounded in this project

The read/write contract described here is expressed in `cves/lib/rw/krw.h`, which types the three address spaces separately so a link-time offset can never be handed to a primitive expecting a linear-map address. The pipe promotion is `cves/lib/rw/pipe_rw.h` and `cves/lib/rw/pipe_krw.h`, the latter being the userspace-alias variant where the `pipe_buffer` array sits on a page the caller also maps, so re-aiming needs no kernel write; `lib_pipe_buf_forge()` in `pipe_rw.c` is where the `len = N+1` read case and the `len = 0` write case are decided by one flag. `cves/lib/rw/nameblob.h` is the buffer-descriptor redirection variant, including the multi-pass trick for writing addresses containing zero bytes through a C-string interface. The verify-before-write discipline is `cves/lib/rw/slabpage.h`, which checks four independent page-descriptor properties before a write is allowed through a cross-cache alias. The privileged ground-truth read is `cves/lib/rw/kprobe_read.h` and `kprobe_read.c`, which carries the `kptr_restrict`, direct-`syscall()` and type-suffix handling described above. The physical-address instruments are `cves/lib/addr/pagemap.h` and `cves/lib/addr/physmap.h`, the latter holding the PFN-to-descriptor conversion and the `PHYS_OFFSET_PFN` subtraction. The forged-object-through-a-legitimate-interface technique — corrupting `mm->mm_mt.ma_root` so `/proc/self/maps` becomes a repeatable arbitrary read — is `cves/cve-2026-43049-ffwheel/ffread_mm.c`, with its resolution walk in `cves/cve-2026-43049-ffwheel/ffread_resolve.c`.

## See also

- [01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md) — establishing that the bug is present before building anything on it, the OTA route to the target's own kernel image, and the differential BTF check for whether a struct-changing fix landed.
- [02-reachability-and-attack-surface.md](02-reachability-and-attack-surface.md) — whether the interface that drives the primitive is reachable at your privilege level.
- [03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md) — reading the panic a mis-aimed write produces, and the sanitizer reports.
- [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) — the linear map, `PHYS_OFFSET`, recovering the runtime slide that turns a link-time offset into an address a primitive can accept, and the BTF-and-symbol recovery toolchain for a build whose `/sys/kernel/btf/vmlinux` you cannot read.
- [05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md) — placing the object the primitive will corrupt, and the cache-merging instruments.
- [06-cross-cache-attacks.md](06-cross-cache-attacks.md) — the probabilistic setup that makes verification mandatory.
- [08-triggering-races-reliably.md](08-triggering-races-reliably.md) — widening the window the type confusion depends on.
- [09-privilege-escalation-to-root.md](09-privilege-escalation-to-root.md) — what to do with the read/write once it exists.
- [10-survivability-and-measurement.md](10-survivability-and-measurement.md) — teardown hazards of forged objects, and measuring success rates honestly.
- [11-case-studies.md](11-case-studies.md) — these primitives assembled into complete chains.
- [12-further-reading-and-glossary.md](12-further-reading-and-glossary.md) — the wider literature.
