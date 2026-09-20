# Crash Triage and Root-Cause Analysis

Most of the time spent turning a kernel bug into a working exploit is spent reading crash logs. A memory-corruption primitive under development fails by killing the machine, and the only evidence of what went wrong is whatever the kernel managed to print in the microseconds between noticing something impossible and giving up. Learning to read that evidence precisely — and to tell the difference between a crash that proves the bug behaves as theorized and a crash that proves the exploit has a typo — is the difference between converging on a working chain and rerunning the same broken shot a hundred times.

This section is about arm64 specifically, because that is what Android runs on, and the exception model is different enough from x86 that habits transfer badly. The log excerpts and disassembly below are taken from this project's own runs on panther (Pixel 7, `6.1.157-android14-11-gbd23337e42e7-ab14791245`, build `CP2A.260705.006`), captured from `/sys/fs/pstore/console-ramoops-0` after each panic. Blocks that show a message *shape* rather than a capture are marked as such.

## Anatomy of an arm64 oops

When the kernel takes a fatal exception at EL1 it calls `die()`, which prints a fixed sequence. The header comes from `__die()` in [`arch/arm64/kernel/traps.c`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/kernel/traps.c):

```
Internal error: Oops: 0000000096000004 [#1] PREEMPT SMP
```

The format string is `"Internal error: %s: %016lx [#%d]"`. The string is the death reason (`Oops`, `Oops - BUG`, `Oops - CFI`, `Oops - KASAN`, `aarch64 BRK`), the hex field is the *ESR_EL1 value* at the time of the exception, and `[#1]` is the die counter — a second oops in the same boot prints `[#2]`, which matters because the first one is almost always the interesting one and later ones are collateral.

Everything you need to classify the fault is in that ESR word. Bits 31:26 are the exception class (EC); bits 24:0 are the instruction-specific syndrome. The constants live in [`arch/arm64/include/asm/esr.h`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/include/asm/esr.h):

| EC | Meaning |
|---|---|
| `0x25` | Data abort taken from EL1 (`DABT_CUR`) — a load or store to a bad address |
| `0x21` | Instruction abort from EL1 (`IABT_CUR`) — the PC itself went somewhere unmapped or non-executable |
| `0x3C` | `BRK` instruction executed at EL1 — a deliberate trap, not a memory fault |
| `0x0E` | Illegal execution state |
| `0x22` / `0x26` | PC / SP alignment fault |

For `0x96000004`: `0x96000004 >> 26 = 0x25`, a data abort; the low six bits are the fault status code, `0x04`.

### The fault status code, and what its level tells you

The FSC is not a single verdict but a pair — a fault class and the translation-table level at which the page-table walk gave up. The ranges you meet in practice:

| FSC | Meaning |
|---|---|
| `0x04`–`0x07` | Translation fault, levels 0 through 3 — nothing is mapped there |
| `0x09`–`0x0B` | Access flag fault, levels 1 through 3 |
| `0x0D`–`0x0F` | Permission fault, levels 1 through 3 — mapped, but you wrote to something read-only or executed something non-executable |

The level is a coarse magnitude estimate for the bad pointer, and it is free. A walk that fails at level 0 never got past the top table, which is what a wild value looks like; a walk that fails at level 2 or 3 got several tables deep, which is what a small offset from a base that *is* mapped looks like. Two real records from the same device:

```
Unable to handle kernel paging request at virtual address 005801543aa9001f
  FSC = 0x04: level 0 translation fault

Unable to handle kernel paging request at virtual address 0000000000001968
  FSC = 0x06: level 2 translation fault
  [0000000000001968] pgd=08000000c9f22003, p4d=..., pud=..., pmd=0000000000000000
```

The first is a corrupted 64-bit word being used as a pointer. The second is a NULL-ish base plus a structure offset — the walk resolved pgd, p4d and pud and only fell over at pmd, and the kernel printed the partial walk to prove it. That distinction alone tells you whether to go looking for a garbage pointer or for a field read out of a zeroed object, before you symbolize anything.

Three more fields from the `Mem abort info:` block that `mem_abort_decode()` in `arch/arm64/mm/fault.c` prints:

- `WnR` — the aborting access was a write. Read it together with the FSC rather than alone: for an abort taken on a cache-maintenance or address-translation instruction the architecture sets `WnR` to 1 regardless of the actual direction, so a `WnR = 1` next to `CM = 1` says nothing about whether you were writing.
- `CM` — the abort was taken on a cache-maintenance operation rather than an ordinary load or store.
- `S1PTW` — the abort was taken on a stage-1 page-table walk rather than on the access itself, which can only happen when a stage-2 (hypervisor) translation is in effect. An ordinary bad-pointer fault leaves it clear; a set `S1PTW` says the fault is about the page tables rather than about the pointer, and the address in the header is a page-table address, not the one your code dereferenced.

If the `Mem abort info:` block was truncated by the ring buffer, decode the raw ESR yourself:

```
# host, on the ESR value copied out of the log
cargo install aarch64-esr-decoder      # or: nix run nixpkgs#aarch64-esr-decoder
aarch64-esr-decoder 0x96000004
```

[google/aarch64-esr-decoder](https://github.com/google/aarch64-esr-decoder) prints each field with its architectural meaning, cross-referenced to the [Arm Architecture Reference Manual's ESR_EL1 description](https://developer.arm.com/documentation/ddi0601/2022-03/AArch64-Registers/ESR-EL1--Exception-Syndrome-Register--EL1-).

### The header line

Between `Modules linked in:` and the register dump the kernel prints one line that decides how you read everything below it:

```
CPU: 6 PID: 1 Comm: init Tainted: G           O       6.1.157-android14-11-gbd23337e42e7-ab14791245 #1
Hardware name: GS201 PANTHER MP based on GS201 (DT)
pstate: 004000c5 (nzcv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
```

- `Comm` and `PID` name the task that took the fault. This is the first question of any use-after-free triage: did the crash happen in the process that ran the exploit, or in some other task that touched the object after you freed it? `Comm: init` with `PID: 1` is the second case, and it changes the whole hypothesis — the free already completed, something else reached the corpse, and the evidence you want next is a `ps` from the moment of the shot plus the consumer's own timing. The consumer-side mechanics of that are [section 08](08-triggering-races-reliably.md)'s subject.
- `CPU` matters for anything that reasons about per-CPU allocator state. A reclaim groomed on one CPU and a fault reported on another is a fact about your steering, not a detail.
- `Tainted:` carries the flag letters. `O` is an out-of-tree module (on a Pixel, dozens of them), `G` is "no proprietary module has been loaded", `W` is "a warning already fired earlier this boot". A `W` here is a pointer to an earlier record you have not read yet. The notation is in the official [bug-hunting guide](https://docs.kernel.org/admin-guide/bug-hunting.html).
- `pstate` decodes the execution context. The `DAIF` group is printed with an uppercase letter per masked bit, so `daIF` means `I` and `F` are masked — IRQs and FIQs off at the moment of the fault. The `PREEMPT SMP` token back in the `Internal error:` header is a build property, not a per-fault one. The practical consequence of a masked `I`: that path cannot sleep, so no widening technique that depends on a sleep, a page fault or a scheduler yield was ever going to work there. Find that out from the crash rather than from twenty failed shots.

### The register dump, the trace, and the `Code:` line

Below the header, `show_regs()` prints `pc` and `lr` with symbolization, then `sp`, then `x29` down to `x0`. The conclusions you can legitimately draw:

- `pc` is where execution was. If `pc` symbolizes to a plausible kernel function and the fault is a data abort, the kernel was running real code and touched a bad pointer. If `pc` is garbage, or a value you recognize (a spray payload, a userspace address), you redirected control flow and the abort is *yours*.
- `lr` is the return address, so `lr` normally names the caller of the function containing `pc`. On a corrupted stack it is the single most useful surviving breadcrumb.
- The faulting address is printed separately, above the header. Match it against the register dump, but mask before you compare: arm64 ignores the top byte of an address when TBI is enabled, so the printed fault address can differ from the register that produced it in bits 63:56 alone.
- `Call trace:` comes from `dump_backtrace()`, which walks the frame-pointer chain in `x29`. Each frame is a *return* address, one instruction past the call, which is why a frame reads `+0xa0` when the `bl` is at `+0x9c`. It is reliable for normal C frames and unreliable the moment you have smashed a stack or jumped through a corrupted function pointer, because there is no chain left to walk.
- The `Code:` line is the raw instruction words around `pc`, with the faulting one in parentheses. Decode it with the in-tree script: `ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- ./scripts/decodecode < oops.txt`, which annotates the faulting instruction with `<*>`. This tells you which load or store aborted when the symbolized function contains several.

### One record, read end to end

The following is one record from a run of the FFWheel chain, with the `Modules linked in:` block, most of the register dump and the tail of the call trace elided:

```
[   24.324598][    T1] Unable to handle kernel paging request at virtual address 005801543aa9001f
[   24.324621][    T1] Mem abort info:
[   24.324627][    T1]   ESR = 0x0000000096000004
[   24.324632][    T1]   EC = 0x25: DABT (current EL), IL = 32 bits
[   24.324638][    T1]   SET = 0, FnV = 0
[   24.324644][    T1]   EA = 0, S1PTW = 0
[   24.324648][    T1]   FSC = 0x04: level 0 translation fault
[   24.324655][    T1] Data abort info:
[   24.324658][    T1]   ISV = 0, ISS = 0x00000004
[   24.324663][    T1]   CM = 0, WnR = 0
[   24.324668][    T1] [005801543aa9001f] address between user and kernel address ranges
[   24.324674][    T1] Internal error: Oops: 0000000096000004 [#1] PREEMPT SMP
[   24.325527][    T1] CPU: 6 PID: 1 Comm: init Tainted: G           O       6.1.157-android14-11-gbd23337e42e7-ab14791245 #1
[   24.325536][    T1] Hardware name: GS201 PANTHER MP based on GS201 (DT)
[   24.325541][    T1] pstate: 004000c5 (nzcv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
[   24.325549][    T1] pc : __wake_up_common+0xa4/0x160
[   24.325566][    T1] lr : __wake_up+0x7c/0xd0
[   24.325580][    T1] x29: ffffffc00805b900 x28: ffffff8815455868 x27: 00000000040c0004
[   24.325601][    T1] x23: 0000000000000000 x22: 7d5801543aa9001f x21: 0000000000000000
[   24.325664][    T1] x2 : 0000000000000001 x1 : 0000000000000001 x0 : 7d5801543aa9001f
[   24.325672][    T1] Call trace:
[   24.325677][    T1]  __wake_up_common+0xa4/0x160
[   24.325686][    T1]  __wake_up+0x7c/0xd0
[   24.325695][    T1]  uhid_queue_event+0xa0/0xf8
[   24.325703][    T1]  uhid_hid_open+0x18/0x28
[   24.325710][    T1]  hid_hw_open+0x70/0xa8
[   24.325720][    T1]  hidinput_open+0x14/0x24
[   24.325730][    T1]  input_open_device+0xb0/0xec
[   24.325739][    T1]  evdev_open+0x150/0x1d4
[   24.325748][    T1]  chrdev_open+0x1c0/0x230
[   24.325856][    T1] Code: eb1902df 54000500 aa1603e0 aa1603e8 (f94002d6)
[   24.325867][    T1] Kernel panic - not syncing: Oops: Fatal exception
```

Field by field:

1. `ESR = 0x96000004`, EC `0x25`, FSC `0x04`. A data abort on a read (`WnR = 0`, `CM = 0`, so the direction is meaningful), level 0 — the walk failed immediately. Not a small offset from a live base.
2. `x0` and `x22` both hold `7d5801543aa9001f`; the printed fault address is `005801543aa9001f`. Identical but for the top byte, which TBI strips. So the aborting access dereferenced `x22`, and `x22` is a 64-bit word of non-pointer data.
3. The `Code:` line places the fault exactly. Disassembling `__wake_up_common` out of this build's own `Image` gives, at `+0x94` through `+0xa4`:

```
ffffffc00811b308:  eb1902df   cmp  x22, x25
ffffffc00811b30c:  54000500   b.eq __wake_up_common+0x138
ffffffc00811b310:  aa1603e0   mov  x0, x22
ffffffc00811b314:  aa1603e8   mov  x8, x22
ffffffc00811b318:  f94002d6   ldr  x22, [x22]
```

   Word for word the same five values as the `Code:` line, with `f94002d6` — `ldr x22, [x22]` — in the parentheses. The faulting instruction is the list-walk step of the wait-queue iteration: it is loading `->next` out of a wait-queue entry.

4. `Call trace:` gives the provenance of the list: `uhid_queue_event+0xa0` called `__wake_up`, which is `__wake_up(&uhid->waitq, ...)`. So the corrupted list head lives inside a `struct uhid_device`.
5. `Comm: init`, `PID: 1`, and the rest of the trace is `evdev_open` from `chrdev_open`. The exploit's own thread is not in this picture at all. `init` opened the evdev node for the HID device, the input core called down into uhid, and uhid woke a queue whose head had already been overwritten. The free happened earlier and elsewhere; this is the consumer walking the corpse.

The conclusion the record supports is narrow and useful: the uhid object was freed and its `waitq` list head was overwritten with non-pointer data, and the resulting panic is fired by a consumer that this exploit does not control. It is not evidence about whether the *intended* write landed. A record of this shape is also a work item rather than a dead end: a chain that leaks an object a system service will later touch has to close that consumer's path, and the cheapest place to close it is upstream of the freed memory rather than inside it. In FFWheel the leaked object is an `input_dev` whose `open` handler reaches the freed uhid device, so the chain writes a non-zero `users` count into each leaked `input_dev` over the kernel write it already holds; `input_open_device()` then takes its already-open branch and never calls `->open`.

## `BRK` immediates: self-inflicted traps versus real faults

EC `0x3C` is the case people misread most often. A `BRK` at EL1 is not a memory fault — it is the kernel deliberately trapping itself, and the 16-bit immediate encoded in the low bits of the ESR says which subsystem did it. The allocation is build-specific, so pin the citation: this is [`arch/arm64/include/asm/brk-imm.h` on `android14-6.1`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/include/asm/brk-imm.h), the branch panther's kernel is built from.

```
0x004  kprobes                       KPROBES_BRK_IMM
0x005  uprobes                       UPROBES_BRK_IMM
0x006  kprobe software single-step   KPROBES_BRK_SS_IMM
0x100  a deliberate fault (reserved) FAULT_BRK_IMM
0x400  kgdb, dynamic                 KGDB_DYN_DBG_BRK_IMM
0x401  kgdb, compiled-in             KGDB_COMPILED_DBG_BRK_IMM
0x800  BUG() and WARN() traps        BUG_BRK_IMM
0x900-0x9ff  tag-based KASAN         KASAN_BRK_IMM | KASAN_BRK_MASK
0x8000-0x83ff  Control-Flow Integrity  CFI_BRK_IMM_BASE | CFI_BRK_IMM_MASK
```

That list is the whole of it on 6.1. Mainline adds `UBSAN_BRK_IMM 0x5500` with mask `0x00ff` and replaces `KPROBES_BRK_SS_IMM` with `KRETPROBES_BRK_IMM 0x007`; neither exists on `android14-6.1`, so a table copied from mainline will make you look for hooks this build does not have. The consequence is visible in the target's own text. Disassembling panther's `Image` and counting `brk` immediates:

```
$ aarch64-linux-gnu-objdump -d vmlinux.elf | grep -oP '\tbrk\t#0x[0-9a-f]+' | sort | uniq -c | sort -rn | head -5
  12511 	brk	#0x8228
  12426 	brk	#0x800
   3228 	brk	#0x5512
   1195 	brk	#0x1
    901 	brk	#0x8229
```

`brk #0x5512` is in the 0x55xx band, and it is there because `CONFIG_UBSAN_TRAP=y` and clang lowers a trapping sanitizer check to that encoding. But `android14-6.1` registers no break hook for that band, so if one of those ever fires the kernel does not print a UBSAN report — `brk_handler()` in `arch/arm64/kernel/debug-monitors.c` falls through to `pr_warn("Unexpected kernel BRK exception at EL1")`, returns `-EFAULT`, and the fault-info entry names the death reason `aarch64 BRK`. The only UBSAN checks this build enables are `UBSAN_BOUNDS`, `UBSAN_ARRAY_BOUNDS` and `UBSAN_LOCAL_BOUNDS` (`SHIFT`, `BOOL`, `ENUM` and `UNREACHABLE` are all off in its config), so an `Internal error: aarch64 BRK` with an immediate in the 0x55xx range is an array-bounds violation, not a mystery.

### `BUG()` and `WARN()` share an immediate and nothing else

Both compile to `brk #0x800`, and that is where the similarity ends. `bug_handler()` in `traps.c` dispatches on the bug table entry, not on the immediate:

```c
static int bug_handler(struct pt_regs *regs, unsigned long esr)
{
	switch (report_bug(regs->pc, regs)) {
	case BUG_TRAP_TYPE_BUG:
		die("Oops - BUG", regs, esr);
		break;
	case BUG_TRAP_TYPE_WARN:
		break;
	...
	}
	/* If thread survives, skip over the BUG instruction and continue: */
	arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);
	return DBG_HOOK_HANDLED;
}
```

`BUGFLAG_WARNING` in the entry decides which arm runs. A `WARN()` returns `BUG_TRAP_TYPE_WARN`, the handler steps over the trap, and the machine keeps going; a `BUG()` returns `BUG_TRAP_TYPE_BUG` and dies. The two produce completely different log shapes. A survivable warning, from a real panther boot:

```
[    1.608868][  T289] ------------[ cut here ]------------
[    1.608875][  T289] !uclamp_is_used()
[    1.609009][  T289] WARNING: CPU: 0 PID: 289 at .../sched/sched_priv.h:959 rvh_enqueue_task_fair_pixel_mod+0x804/0x93c [vh_sched]
[    1.610543][  T289] CPU: 0 PID: 289 Comm: irq/374-max777x Tainted: G           O       6.1.157-...
[    1.610570][  T289] pc : rvh_enqueue_task_fair_pixel_mod+0x804/0x93c [vh_sched]
```

No `Internal error:` header, no `Kernel panic`, and that boot carried on. It is drawn from the console capture of a shot that panicked seventeen seconds later, in an unrelated subsystem — which is the situation the `console-ramoops-0` argument below is about. A fatal assertion looks like this instead:

```
kernel BUG at fs/foo.c:123!                                      (shape, not a capture)
Internal error: Oops - BUG: 00000000f2000800 [#1] PREEMPT SMP
```

`0xf2000800 >> 26` is `0x3C`, and `0xf2000800 & 0xffff` is `0x800`, so the header alone identifies it before you read a line of the trace.

So the reading rule is the inverse of what the shared immediate suggests. `Internal error: Oops - BUG` is never a bare `WARN`; `WARNING: CPU:` is never a `BUG`. Two qualifications:

- The `file:line` text on either form requires `CONFIG_DEBUG_BUGVERBOSE`, which is not in the GKI defconfig but is `=y` in panther's shipped `/proc/config.gz`. Without it you get the trap and the backtrace and no source location, so check rather than assume.
- `panic_on_warn` turns a `WARN` fatal, at which point it *does* stop the machine and *does* produce a panic banner. Check before you conclude a warning is survivable: `cat /proc/sys/kernel/panic_on_warn`. The sysctl is documented in [kernel.rst](https://docs.kernel.org/admin-guide/sysctl/kernel.html).

Either way, a `WARN` that fired before your panic is evidence, and on a `panic_on_warn` build it *is* the panic. Which crash record actually contains it is the subject of *Persistent crash storage* below.

### CFI traps and what they actually prove

`CONFIG_CFI_CLANG` makes the compiler emit a type check before every indirect call and a `BRK` on mismatch, encoding which registers hold the operands in the immediate: `CFI_BRK_IMM_TARGET` is bits 4:0, naming the register holding the branch target, and `CFI_BRK_IMM_TYPE` is bits 9:5, naming the register holding the expected type. `cfi_handler()` reads them back out of the ESR with `FIELD_GET`, hands them to `report_cfi_failure()` in `kernel/cfi.c`, which prints

```c
pr_err("CFI failure at %pS (target: %pS; expected type: 0x%08x)\n", ...)
```

— the call site, the value that was about to be called, and the 32-bit hash the call site demanded — before `die("Oops - CFI", regs, esr)`. The mechanism is Sami Tolvanen's [arm64: Add CFI error handling](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b26e484b8bb3a992ef30e851d771973a3dd2336b), which introduced this handler and the immediate encoding, plus the `CFI_BRK_IMM_*` definitions in the `brk-imm.h` linked above; [KVM: arm64 hypervisor kCFI](https://lwn.net/Articles/977761/) covers the EL2 variant. CFI first shipped on Android in 2018 as LLVM jump-table CFI ([Control Flow Integrity in the Android kernel](https://android-developers.googleblog.com/2018/10/control-flow-integrity-in-android-kernel.html), Sami Tolvanen), which is a different implementation with a different report format — that generation printed only `CFI failure (target: ...)` with no type field and no BRK immediate, so a report in that shape is telling you about a much older kernel.

Confirm CFI is on before attributing anything to it. Two independent checks:

```
adb shell 'zcat /proc/config.gz' | grep -E 'CFI_CLANG|CFI_PERMISSIVE'
CONFIG_ARCH_SUPPORTS_CFI_CLANG=y
CONFIG_CFI_CLANG=y
# CONFIG_CFI_PERMISSIVE is not set

adb shell grep -wE 'cfi_handler|report_cfi_failure' /proc/kallsyms
```

`/proc/config.gz` needs `CONFIG_IKCONFIG_PROC`, which GKI sets. `CONFIG_CFI_PERMISSIVE` (or `cfi=permissive` on the command line) makes `report_cfi_failure()` return `BUG_TRAP_TYPE_WARN` instead of `BUG_TRAP_TYPE_BUG`, so the handler steps over the trap and the machine survives with a `WARNING:` banner and no `Oops - CFI`. On such a build a CFI violation does not look like a crash at all, which changes what you go looking for in the log. `__kcfi_typeid_*` symbols do not appear in this build's `/proc/kallsyms`, so grepping for them is not a presence test; `cfi_handler` is.

The triage conclusion, stated precisely, is narrower than "CFI stopped you". kCFI compares a hash derived from the *function prototype* at the call site against a hash stored in the four bytes immediately before the target. Here is one real call site from panther's own image, with the check intact:

```
ffffffc008014424:  f9400288   ldr   x8, [x20]              ; the function pointer
ffffffc008014428:  aa1303e1   mov   x1, x19
ffffffc00801442c:  f9400680   ldr   x0, [x20, #8]
ffffffc008014430:  b85fc110   ldur  w16, [x8, #-4]         ; the target's stored type id
ffffffc008014434:  7287e151   movk  w17, #0x3f0a           ; the expected type, low half
ffffffc008014438:  72a128d1   movk  w17, #0x946, lsl #16   ; ... and high half
ffffffc00801443c:  6b11021f   cmp   w16, w17
ffffffc008014440:  54000040   b.eq  ffffffc008014448
ffffffc008014444:  d4304500   brk   #0x8228
ffffffc008014448:  d63f0100   blr   x8
```

`0x8228 - CFI_BRK_IMM_BASE = 0x228`; bits 4:0 are `0x08` and bits 9:5 are `0x11`, so the ESR names `x8` as the target register and `x17` as the type register, which is exactly what the two instructions before the `brk` set up. The expected hash is `0x09463f0a`, visible in the two `movk` immediates. Searching the image for that word as a function prefix finds every legal target of this call site:

```
$ grep -A2 '09463f0a' vmlinux.dis | grep '>:'
ffffffc008014710 <trace_event_raw_event_initcall_start>:
ffffffc0080147bc <perf_trace_initcall_start>:
ffffffc008014a80 <__bpf_trace_initcall_start>:
ffffffc008014f34 <trace_initcall_start_cb>:
```

Four of them. So an `Oops - CFI` is a statement that *the value you wrote does not carry the type hash this call site expects* — not that indirect-call hijacking is closed. It shrinks the target set to same-prototype functions; here, from every function in the kernel to four. Two follow-ups are available and both are mechanical:

1. Look for a same-prototype target. The call site's disassembly hands you the expected hash in the `movk` pair, and the prefix word before each function is that function's hash, so the candidate set is a grep. Whether any of the four is *useful* is a separate question, and usually the answer is no — but it is a question, not a wall.
2. Look for an unchecked call site. The check is a property of the call site, not of the target: hand-written assembly makes indirect calls with no check at all, and C call sites in functions marked `__nocfi` are compiled without one. A function pointer that is only ever called from such a site is not protected by CFI no matter how the pointer got there.

A CFI trap in a function you never touched is a separate and cheaper signal: you corrupted a structure containing a function pointer that something else called, which names *what* you corrupted, for free.

## Persistent crash storage

None of the above helps if the log does not survive. Android sets `CONFIG_PANIC_ON_OOPS=y` — see [`arch/arm64/configs/gki_defconfig` on `android14-6.1`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/configs/gki_defconfig), which is the reference for every config claim in this section — so any oops reboots the device immediately and `dmesg` is gone by the time you can run `adb` again. The sysctl behind it is documented in [kernel.rst](https://docs.kernel.org/admin-guide/sysctl/kernel.html). On a kernel where it is *not* set, Seth Jenkins' [Exploiting null-dereferences in the Linux kernel](https://projectzero.google/2023/01/exploiting-null-dereferences-in-linux.html) describes what the recovery path leaves behind — locks still held, refcounts still raised, allocations still allocated, because "the kernel is not able to perform any associated cleanup that it would normally perform on a typical syscall error recovery path" — and argues for backporting the `oops_limit` counter that panics after repeated oopses.

The answer is pstore with the ramoops backend: a reserved physical RAM region that the kernel writes crash records into and re-reads after the reset, since DRAM contents survive a warm reboot. The [ramoops documentation](https://docs.kernel.org/admin-guide/ramoops.html) covers `mem_address`, `mem_size`, `mem_type`, `record_size` and `max_reason`; the per-record-type sizes are module parameters in [`fs/pstore/ram.c`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/fs/pstore/ram.c) rather than on that page — `console_size`, `ftrace_size` and `pmsg_size`, each `module_param_named(..., 0400)`. After the reboot the records appear under `/sys/fs/pstore` as `dmesg-ramoops-0`, `console-ramoops-0` and `pmsg-ramoops-0`. What your build has:

```
adb shell 'zcat /proc/config.gz' | grep PSTORE
```

The capture discipline — automatic per-run collection, not overwriting your own evidence, and the `O_SYNC` breadcrumb file that records what your *exploit* believed — belongs to [section 10](10-survivability-and-measurement.md), which owns it. What belongs here is which record to read.

`console-ramoops-0` is the record to prefer for exploit triage, and the reason is a triage argument rather than a capacity one. `dmesg-ramoops-0` holds only the tail that the panic handler flushed, which is the oops and little else. The console record holds the entire boot, so it contains the kernel's own earlier complaints — a `WARN`, a refcount underflow, an SELinux denial — and those are frequently the actual root cause with the panic as a downstream consequence. The capture the `WARN` above came from is the concrete case: `WARNING: ... !uclamp_is_used()` at timestamp 1.608, panic at 18.891. A `dmesg-ramoops-0` from that same shot would have shown the second event and hidden the first, and the only way to know whether the gap matters is to read what is in it.

```
adb shell cat /sys/fs/pstore/console-ramoops-0
adb shell getprop ro.boot.bootreason      # 'kernel_panic', 'reboot,...', 'cold'
```

Note the asymmetry that catches people: the shell domain is granted enough to open a pstore record by name and not enough to enumerate the directory it sits in. AOSP's [`private/shell.te`](https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/shell.te) carries `allow shell pstorefs:dir search;` and `allow shell pstorefs:file r_file_perms;`, granted so that `logcat -L` can read the previous boot's log. `search` on a directory permits traversing it to a path you already know; listing it needs `read` on the directory, which is not in that rule. So `cat /sys/fs/pstore/console-ramoops-0` succeeds and `ls /sys/fs/pstore` is denied, and anything that collects crash records automatically has to name the record it wants rather than discover it. Vendor policy diverges from AOSP's, so check on the device rather than assume: dump the policy and query it:

```
adb shell 'cat /sys/fs/selinux/policy' > policy.bin
sesearch --allow -s shell -t pstorefs -c file policy.bin
sesearch --allow -s shell -t pstorefs -c dir  policy.bin
```

An `allow shell pstorefs:file { ... read ... }` line out of the first query and an `allow shell pstorefs:dir search;` with no `read` in it out of the second is that asymmetry, printed — the rule that lets you open a known path exists and the rule that would let you list the directory does not. Reading `/sys/fs/selinux/policy` is itself policy-gated; [section 02](02-reachability-and-attack-surface.md) owns the method and the fallbacks (the precompiled policy on the device image, or the same files out of a factory image). The denial side is visible separately — `logcat -b events | grep avc:` from a shell, or `dmesg | grep 'avc:'` on a kernel whose log you can read — and that, not `getenforce`, is what tells you a specific access was refused. `getenforce` answers only whether policy is advisory at all, which is the check you run immediately before a `setenforce 0`.

Legacy devices expose the same data at `/proc/last_kmsg`. On a device you control, `CONFIG_PSTORE_BLK` or a serial console over USB are better still, and a `kdump`/`crash` workflow is best of all — none of which exists on a locked retail phone.

## Light-weight triage: ftrace and kprobes

A full crash dump answers "why did it die". Tracing answers a cheaper and often more useful question: "did this path run at all, and with what". These are different instruments, and reaching for the crash dump when a probe would do wastes a reboot.

The tracefs interface lives at `/sys/kernel/tracing` (or `/sys/kernel/debug/tracing` if only debugfs is mounted). A dynamic probe is three writes, per the [kprobe event documentation](https://docs.kernel.org/trace/kprobetrace.html):

```sh
T=/sys/kernel/tracing
echo 'p:mytrap some_function arg0=%x0 field=+0x20(%x0):x64' > $T/kprobe_events
echo 1 > $T/events/kprobes/mytrap/enable
echo 1 > $T/tracing_on
cat $T/trace
```

Each line of `trace` is one execution of `some_function`, with `x0` and the 64-bit word at `x0+0x20` printed. Conclusions you can draw: whether the path is reached at all; how many times; with which object; and, from the timestamps, how far apart two events fell — which is exactly the measurement a race needs. `r:` gives a kretprobe, and the entry/return distinction matters when a teardown function frees something partway through: the entry probe says the teardown *started*, the return probe says it *finished*.

Two masking knobs are commonly confused here, and relaxing the wrong one leads to the conclusion that a leak failed:

- `kptr_restrict` decides whether `/proc/kallsyms` hands you real addresses or a column of zeros, and it is not the only input — the masking ladder in `kallsyms_show_value()` also consults `perf_event_paranoid` and `CAP_SYSLOG`, and [section 04](04-kaslr-and-information-leaks.md) owns it. What it gates for a probe is the *prerequisite*, not the fetch: resolving the symbol whose address an `@ADDR` argument names is what needs an unmasked table, while the fetch itself prints the word verbatim into the trace record and `kptr_restrict` does not touch it.
- `%p` in a `printk` format is *hashed*, unconditionally and independently of `kptr_restrict`. The knob for that is `no_hash_pointers` on the kernel command line. A symbolized pointer that prints as a stable-looking but wrong value is this, not the other.

Three refinements worth knowing:

1. `symbol+offset` probe points let you instrument *a specific branch* rather than a function, which is how a probe becomes a race oracle rather than a call counter. The derivation runs against the stripped retail image and is mechanical.
2. `@ADDR` fetches a literal kernel address into the trace record, which makes a kprobe an arbitrary kernel read for anyone who already has root. That is not an exploitation primitive — it is the ground truth you check an unprivileged primitive's claims against.
3. `available_filter_functions` lists what `ftrace` can hook, and `$T/kprobe_events` rejects names the kernel does not know. That rejection is itself a patch-presence test: a fix that splits or renames a function changes which symbols exist, and asking the kernel to probe a name is a way to query the symbol table without being allowed to read it.

### Deriving a branch probe offset

Take `posix_cpu_timer_del()` as the worked case. The interesting event there is not that the function ran — it runs whenever a process timer is deleted — but that the inlined `lock_task_sighand()` inside it returned NULL. That branch is the one [the upstream source annotates](https://elixir.bootlin.com/linux/v6.1.157/source/kernel/time/posix-cpu-timers.c) with "this raced with the reaping of the task", so an entry probe on the function counts deletions while a probe on that branch counts the concurrent-reap case specifically. Recover the function from the device's own kernel and disassemble it:

```sh
vmlinux-to-elf Image vmlinux.elf
aarch64-linux-gnu-objdump -d --start-address=<sym> --stop-address=<sym+size> vmlinux.elf
```

The path of interest is reached only through one branch, and the branch is identifiable because its arm ends in a `WARN`:

```
posix_cpu_timer_del+0x058:  cbz x0, +0x128        ; sighand == NULL
posix_cpu_timer_del+0x128:  ldr x8, [x19, #152]   ; ctmr->head
                     +0x12c cbz x8, +0x138
                     +0x130 brk #0x800            ; WARN_ON_ONCE, posix-cpu-timers.c:495
```

`+0x128` is the first instruction that only the NULL-sighand path reaches, so that is the probe point, and `+152` is where the field it wants lives — cross-checked against the same kernel's BTF as `k_itimer.it` plus `cpu_timer.head`. The probe line is then:

```sh
echo "p:pcd_race posix_cpu_timer_del+0x128 head=+152(%x19):x64 itclock=+48(%x19):x32" \
  > /sys/kernel/tracing/kprobe_events
```

Four acceptance rules decide whether that write succeeds, and each failure is diagnosable rather than mysterious because the `echo` returns an error:

- The offset must be 4-byte aligned. arm64 instructions are fixed width and a misaligned probe point is rejected outright.
- The offset must fall inside the symbol. The kernel resolves `symbol+offset` against its own kallsyms and refuses an offset past the end.
- The instruction must not be in a kprobe-blacklisted region. The blacklist covers the kprobe machinery itself, fault and exception entry, and anything marked `NOKPROBE_SYMBOL`; see the [kprobes documentation](https://docs.kernel.org/trace/kprobes.html).
- The symbol must exist at all. Inlined functions have no entry point, which is why the probe here is on the *caller* at an offset rather than on `lock_task_sighand`.

The offset is KASLR-independent and stable across reboots, and it is build-specific: it must be re-derived for every kernel, so it belongs in a per-build derivation step that records it beside the other offsets rather than in a constant compiled into the exploit.

Be honest about the cost. A probe changes the timing of the path it sits on, so a measurement taken with probes armed describes a kernel with probes armed. That framing is correct for "did this happen" and wrong for "how often does this win". Always remove probes and restore `tracing_on`, `kptr_restrict` and `current_tracer` on the way out, because a probe left enabled silently biases everything that runs afterwards on that boot.

Availability: `CONFIG_KPROBES=y` is set in the same `gki_defconfig`, and `CONFIG_KPROBE_EVENTS` follows from it (`default y` in `kernel/trace/Kconfig` once `KPROBES` is set) rather than appearing in the defconfig itself — panther's `/proc/config.gz` shows `CONFIG_KPROBE_EVENTS=y`. But tracefs is root-only on production devices, `kptr_restrict` defaults to 2, and SELinux may block the writes even for root until `setenforce 0`. So kprobes are an instrument for the *investigation* phase — on an unlocked device, an emulator, or after a chain has already reached root and you want to verify what it did. They are not available to the unprivileged process the exploit actually starts from. Where BPF is permitted, `bpftrace -e 'kprobe:some_function { printf("%llx\n", arg0); }'` gives the same data with less ceremony; `perf probe` and `perf record` are the equivalent for sampling and hardware counters.

## Symbolizing under KASLR

KASLR randomizes the kernel image base at every boot, so raw addresses in an oops are meaningless across runs and useless for comparing two crashes. The only stable quantity is `symbol+offset`.

When the target kernel has `kallsyms` and the log was produced by the kernel itself, symbolization is already done — `pc : __wake_up_common+0xa4/0x160` is what you want. When you have raw addresses, two in-tree scripts convert them:

```sh
# pipe a whole oops through, with a vmlinux for the same build
./scripts/decode_stacktrace.sh vmlinux < oops.txt

# resolve one frame to file:line
./scripts/faddr2line vmlinux __wake_up_common+0xa4/0x160
```

[`faddr2line`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/scripts/faddr2line) exists for three reasons, none of which is KASLR. It accepts the `func+0x123/0x456` form the kernel actually prints and does the arithmetic against the symbol's own address rather than requiring you to compute a link-time address by hand; it *validates* the reported size against the symbol's real size in the ELF; and it expands inlined frames that `addr2line` alone collapses into one line. Slide-independence is a consequence of the first, not the motive.

The size validation is the cheapest decisive check in this section. If `faddr2line` tells you the offset exceeds the symbol's size — or that the size in the log disagrees with the size in your `vmlinux` — then your `vmlinux` is not the build that produced the log, and every line number you were about to read is wrong. Run it before trusting anything else. [`decode_stacktrace.sh`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/scripts/decode_stacktrace.sh) does the same for every line of a pasted trace. Both need a `vmlinux` with debug info for the exact build.

On a device you control, the simplest move is to remove the variable: boot with `nokaslr` on the command line so addresses are reproducible between runs and directly comparable with `objdump` output. On a locked retail device that is not an option, and you recover the slide arithmetically instead — obtain one symbol's runtime address by any means, subtract its link-time address, and apply that delta to everything else. Building such a leak, and recovering an analyzable ELF from a retail `boot.img` with `unpack_bootimg` and `vmlinux-to-elf`, are [section 04](04-kaslr-and-information-leaks.md)'s subject.

One property of that reconstructed ELF is a triage consequence rather than a leak consequence, so it belongs here: the symbols come from the kernel's own compressed `kallsyms` table, which carries names and addresses and nothing else. `readelf -sW vmlinux.elf` on the reconstruction used throughout this section reports every function with size `0` and there is no DWARF at all, so `faddr2line` can neither validate a size against it nor produce a source line from it. It is a disassembly target, not a debug target. For line numbers you need the matching build's real `vmlinux`, which for GKI kernels is published as a build artifact alongside the release.

## Offsets, for triage

The triage-specific version of the offset question is narrower than the general one: *the oops faulted at `object+0x20` — was `0x20` the field I meant on this build?* The general apparatus for answering it, including extracting BTF from a downloadable image when the device will not serve it, is [section 04](04-kaslr-and-information-leaks.md)'s. What triage needs is one invocation and one cross-check.

BTF is the ground truth, because it is generated from that build's own DWARF. `CONFIG_DEBUG_INFO_BTF=y` is in the same `gki_defconfig`, so the blob exists on every GKI kernel. Pull it once per build and query it on the host:

```sh
$ adb shell su -c 'cat /sys/kernel/btf/vmlinux' > btf-vmlinux
$ pahole --hex -C cred btf-vmlinux
struct cred {
	atomic_t                   usage;                /*     0   0x4 */
	kuid_t                     uid;                  /*   0x4   0x4 */
	...
	kernel_cap_t               cap_ambient;          /*  0x48   0x8 */
	unsigned char              jit_keyring;          /*  0x50   0x1 */

	/* XXX 7 bytes hole, try to pack */

	struct key *               session_keyring;      /*  0x58   0x8 */
```

The trailing comment is offset then size, both in hex because of `--hex`; without it `pahole` prints both in decimal, and a block that mixes the two came from two runs. The `/* XXX 7 bytes hole */` annotation is the part that matters for triage: a neighbouring offset computed by hand from the preceding member's size is wrong exactly when a hole sits between them, and this is how you see it. `pahole -E` expands nested structs so you can compute an offset through an embedded member.

Whether you can read that file at all is per-device and must be measured, not assumed. The sysfs attribute's DAC mode is `0444`, so the permission bits permit everyone and SELinux is the real gate:

```sh
adb shell ls -lZ /sys/kernel/btf/vmlinux
sesearch --allow -s shell -t <the label that printed> -c file policy.bin
```

A harvest that reads the blob through `su` answers the question for root and leaves the unprivileged case unmeasured, which is why the label check above is the one that settles it. When your domain is denied, the identical blob is inside the kernel image between `__start_BTF` and `__stop_BTF`, and [section 04](04-kaslr-and-information-leaks.md) gives the slice.

The cross-check that is specific to crash triage is the disassembled accessor. BTF tells you where the compiler put a field; the code tells you which field an instruction actually touched, and the two agreeing is what makes an offset believable. Continuing the worked record above, BTF says:

```
$ pahole --hex -C uhid_device btf-vmlinux | grep waitq
	wait_queue_head_t          waitq;                /* 0x1170  0x18 */
```

and the function in the backtrace computes its argument like this:

```
ffffffc008bd9704:  52822e0a   mov  w10, #0x1170
ffffffc008bd9708:  8b080ea8   add  x8, x21, x8, lsl #3
ffffffc008bd970c:  8b0a02a0   add  x0, x21, x10
        ...                                        (arguments 2-4 set up)
ffffffc008bd9724:  97d50521   bl   __wake_up
```

`x21` is the `struct uhid_device *`, the immediate is `0x1170`, and `x0` is the first argument to `__wake_up`. Two independent derivations, same number. When they disagree, the disassembly wins and your BTF is from a different build.

Allocator state is the other thing a triage frequently needs, because a large share of "mysterious" crashes reduce to *the object was not in the cache I assumed* — SLUB merges caches with compatible size and flags, so a cache you named by its own driver's name may have no pages of its own. [Section 05](05-heap-grooming-and-spraying.md) owns the instruments for that, including the correct reading of `/sys/kernel/slab/<name>/aliases` (it prints an alias count, and it is the symlink target that names the canonical cache), and [section 06](06-cross-cache-attacks.md) owns the page-level ones.

## Telling your bug from their bug

The discipline that saves the most time is refusing to attribute a crash to the target until the alternatives are eliminated. In rough order of frequency:

1. *A stale binary.* The device is running the previous build because a push was interrupted by the reboot the last panic caused. Verify by hashing the file on the device against the host copy before every run, not by trusting that the push returned success.
2. *A wrong offset or a wrong constant.* Re-derive it from the running kernel's BTF, as above. A field offset that is right for upstream 6.1 can be wrong for an Android common-kernel 6.1 with backports.
3. *A base address parsed wrong.* A leak that produces a correct string parsed with the wrong radix, or a symbol resolved against the wrong section start, yields an address a fixed distance from the right one. The signature is a fault address that is *close to* something plausible.
4. *A mitigation firing.* `Oops - CFI` means CFI; `Oops - BUG` means an assertion the kernel knows the name of; a `WARNING:` banner from `refcount.c` means a refcount saturated rather than a use-after-free, and the machine survived it.
5. *Only then, the bug.*

Two positive tests separate these cheaply.

First, run the chain with the corrupting write disabled — everything up to and including the free and the reclaim, but no write. If it still panics, the panic is not caused by your write. The worked record earlier in this section is exactly this outcome read after the fact: the fault is a consumer walking a freed wait queue, which happens whether or not the payload write ever ran.

Second, write a recognizable value instead of the real payload and look at where it turns up. The two shapes are easy to tell apart. A landed marker produces a fault address that *is* the marker, or a small function of it — the shape to look for is

```
Unable to handle kernel paging request at virtual address 4141414141414141   (shape, not a capture)
  FSC = 0x04: level 0 translation fault
...
x22: 4141414141414141
```

A write that never landed produces a fault address that is something else entirely — an ordinary heap pointer, a small offset from zero, or the level-2 shape shown at the top of this section. When the marker is absent, the primitive has not been delivered and every hypothesis about the payload is premature; there is nothing to learn from tuning the payload until the marker appears. Remember to mask the top byte before comparing: TBI means a tagged register value and the printed fault address differ in bits 63:56.

### Poison values, and which of them this kernel can actually produce

The kernel labels some of its own freed memory, and a recognized constant in a register or fault address saves a great deal of work. Two of them are unconditional, and the rest need a boot parameter or a rebuild. From [`include/linux/poison.h`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/include/linux/poison.h), with `CONFIG_ILLEGAL_POINTER_VALUE` on arm64 being `0xdead000000000000`:

Always present, no configuration required:

| Value | Meaning |
|---|---|
| `0xdead000000000100` / `0xdead000000000122` | `LIST_POISON1` / `LIST_POISON2` — a list entry was deleted and then used |
| `0xdead000000000300` | `TIMER_ENTRY_STATIC` — a static timer used as a list node |

Requires a boot parameter or a rebuild, and therefore an unlocked bootloader:

| Value | Meaning | Needs |
|---|---|---|
| `0x6b6b6b6b...`, last byte `0xa5` | `POISON_FREE` and `POISON_END` — a genuine use-after-free | `slub_debug=P` |
| `0x5a5a5a5a...` | `POISON_INUSE` — read of an allocated-but-uninitialized object | `slub_debug=P` |
| `0xbb` / `0xcc` red zones | `SLUB_RED_INACTIVE` / `SLUB_RED_ACTIVE` — you ran off the end of an object | `slub_debug=Z` |
| `0xaaaaaaaa...` | `PAGE_POISON` — a freed *page*, not a slab object | `page_poison=1`, and `CONFIG_PAGE_POISONING` |

Find out which you have rather than hunting for a pattern the build cannot emit. Three checks, in increasing authority:

```sh
adb shell cat /proc/cmdline | tr ' ' '\n' | grep -E 'slub_debug|page_poison|init_on_'
adb shell 'zcat /proc/config.gz' | grep -E 'SLUB_DEBUG|INIT_ON_|PAGE_POISONING'
adb shell su -c 'cat /sys/kernel/slab/kmalloc-192/{poison,red_zone,store_user,sanity_checks}'
```

The per-cache sysfs files print `0` or `1` and are the authoritative answer for the cache you care about, because `slub_debug` can be scoped to one cache. The boot parameters themselves are documented in [kernel-parameters](https://docs.kernel.org/admin-guide/kernel-parameters.html).

On panther the answers are `CONFIG_SLUB_DEBUG=y` but `CONFIG_SLUB_DEBUG_ON` unset and no `slub_debug=` on the command line, and `CONFIG_PAGE_POISONING` unset. So every row in the second table is unreachable on the retail device, and a triage that expects `0x6b6b6b6b` there will never see it. What that build does set is `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` (with `CONFIG_INIT_ON_FREE_DEFAULT_ON` unset), which changes the shape of a use-after-free rather than annotating it: the object's bytes survive the free, so a dangling read *before* anything reclaims the slot still returns the old contents, but the allocation that reclaims the slot zeroes it, so a dangling read *after* a reclaim you did not control returns zeros. On this target, "the field read back as 0" is a use-after-free signature in its own right, and it is the one you will actually see. `init_on_free=1` on the command line moves the zeroing to the free, which erases the pre-reclaim read as well.

### Detectors, and which are reachable on a retail phone

On a kernel you can configure, turn the detectors on and let them do the classification. `slub_debug=FZPU` on the command line (or `slub_debug=FZP,kmalloc-192` for one cache) adds red zones, poisoning and owner tracking, and turns a silent corruption into a report naming the allocation and free sites. `CONFIG_KASAN` gives the fullest report — bug type, access address, allocation stack, free stack, and a shadow-memory dump around the address — at a large performance cost; the [KASAN documentation](https://docs.kernel.org/dev-tools/kasan.html) describes the generic, software-tag and hardware-tag (MTE) modes and the `kasan.fault=report|panic` knob. `CONFIG_PROVE_LOCKING` (lockdep) does the equivalent for locking order and is the fastest way to confirm that a race you think you are winning is a race the kernel also considers illegal.

`CONFIG_KFENCE` is the one of these that GKI ships enabled, in the same `gki_defconfig`, so its output is reachable on a retail phone and the route matters. It is a sampling detector: a small number of guarded allocations, near-zero overhead, and a report only when a bug happens to land on a guarded object. The report is a kernel-log block beginning

```
BUG: KFENCE: use-after-free read in <func>+0x..
```

followed by the access stack, the allocation stack and the free stack. Being a kernel-log block is the operative fact on a retail phone: it goes to the console, and therefore into `console-ramoops-0`, and therefore into the record any post-panic pstore capture already saves. The debugfs files the [KFENCE documentation](https://docs.kernel.org/dev-tools/kfence.html) describes — `/sys/kernel/debug/kfence/stats` and `/sys/kernel/debug/kfence/objects` — are lab-only, because debugfs is not mounted on production Android.

What you can read on the device is the sampling rate, which tells you how long you would have to run to expect a hit:

```sh
adb shell su -c 'cat /sys/module/kfence/parameters/sample_interval'
```

The parameter is `module_param_cb(..., 0600)` in `mm/kfence/core.c`, so it is root-readable and root-writable; the GKI defconfig sets `CONFIG_KFENCE_SAMPLE_INTERVAL=500` and panther's build adds `CONFIG_KFENCE_NUM_OBJECTS=63`, meaning one guarded allocation attempted every 500 ms across a 63-slot pool. At that rate KFENCE is not an instrument you aim at a specific object; the expected number of hits is a function of run length, and what it produces is an occasional report you did not ask for.

### Oops semantics

An oops kills the offending task and lets the machine continue; a panic stops everything. The recovery path does not unwind — locks stay held, refcounts stay raised, allocations stay allocated — which is why `panic_on_oops` exists and why an oops-tolerant kernel can be attacked by oopsing deliberately in a loop. During triage this cuts the other way: if the device does *not* reboot after your crash, the kernel state you left behind is corrupt in ways that will make the next run's results meaningless. Reboot between shots, and treat any result from a run that followed an un-rebooted oops as void.

## Instruments

- `aarch64-esr-decoder <esr>` — field-by-field decode of an ESR value from an oops header. Host tool, no privilege.
- `ARCH=arm64 CROSS_COMPILE=... ./scripts/decodecode < oops.txt` — disassembles the `Code:` line and marks the faulting instruction. Host, needs a cross binutils.
- `./scripts/decode_stacktrace.sh vmlinux < oops.txt`, `./scripts/faddr2line vmlinux sym+0x2c/0x44` — symbol+offset to file:line, with size validation that detects a mismatched build. Host, needs a `vmlinux` with debug info for that exact build.
- `adb shell cat /sys/fs/pstore/console-ramoops-0` — previous boot's full console including the panic and everything that preceded it. Needs `CONFIG_PSTORE_RAM` + `CONFIG_PSTORE_CONSOLE` and a policy that grants file read and directory search; directory *read* is denied separately, so never `ls` it.
- `adb shell getprop ro.boot.bootreason` — whether the last reset was a kernel panic. Unprivileged.
- `cat /proc/sys/kernel/panic_on_warn` — whether a `WARN` on this build is survivable or fatal. Unprivileged.
- `zcat /proc/config.gz | grep -E 'CFI_CLANG|CFI_PERMISSIVE|SLUB_DEBUG|INIT_ON_|PAGE_POISONING|KFENCE|PSTORE'` — what the kernel was actually built with. Needs `CONFIG_IKCONFIG_PROC`, which GKI sets.
- `grep -wE 'cfi_handler|report_cfi_failure' /proc/kallsyms` — CFI presence on a build whose config you cannot read. `__kcfi_typeid_*` symbols are not in kallsyms and are not a substitute.
- `echo 'p:ev sym+0xOFF a=+0x20(%x0):x64' > /sys/kernel/tracing/kprobe_events` then `cat .../trace` — did a path run, on what object, when. Root, `CONFIG_KPROBE_EVENTS`, tracefs mounted, SELinux permissive or policy-allowed; the write's own error is the acceptance check.
- `bpftrace -e 'kprobe:f { printf("%llx\n", arg0); }'` — same observation with less setup, where BPF is permitted. Root.
- `pahole --hex -C <struct> btf-vmlinux` — exact field offsets, sizes and holes for the running build. Readability of `/sys/kernel/btf/vmlinux` is subject to policy — check with `ls -lZ`, since the DAC mode is `0444` and SELinux is the gate.
- `objdump -d --start-address=<sym> --stop-address=<sym+size> vmlinux.elf` — the accessor's own displacement, as a cross-check on any BTF offset, and the source of every `symbol+offset` probe point. Host.
- `cat /proc/cmdline`, `cat /sys/kernel/slab/<cache>/{poison,red_zone,store_user,sanity_checks}` — whether any poison or red-zone signature can appear at all on this boot, per cache. Second path needs root.
- `cat /sys/module/kfence/parameters/sample_interval` — KFENCE coverage rate, and therefore how long a run must be before a free report is plausible. Root.
- `adb shell 'cat /sys/fs/selinux/policy' > policy.bin` then `sesearch --allow -s <domain> -t <type> -c <class> policy.bin` — whether a denial, not a bug, is blocking an instrument. `logcat -b events | grep avc:` is the denial-side confirmation; `getenforce` only says whether policy is advisory.

## Grounded in this project

The kprobe triage instruments described above exist here as reusable modules rather than ad-hoc shell. [`cves/lib/tools/kprobe.sh`](../lib/tools/kprobe.sh) wraps the arm/enable/read/remove cycle with unconditional cleanup and per-process filtering; [`cves/lib/trace/fnprobe.h`](../lib/trace/fnprobe.h) is the C interface to the same interface, with a separate entry-versus-return arm so a measurement can say which side of a free an event fell on; [`cves/lib/rw/kprobe_read.h`](../lib/rw/kprobe_read.h) is the `@ADDR` fetch used as a post-root ground-truth read, with a batched form because each arm/fire/disarm cycle is expensive. [`cves/lib/base/steplog.h`](../lib/base/steplog.h) is the `O_SYNC` breadcrumb file that survives the panic reboot. [`cves/lib/tools/symbol-shape.sh`](../lib/tools/symbol-shape.sh) uses probe *rejection* as a symbol-table query, with a three-way verdict that reports inconclusive rather than guessing. A derived branch probe point needs no special case in any of them: the wrapper's `arm` takes the tracing interface's own spec grammar, so `symbol+offset` with a field fetch goes through the same arm/read/clear cycle as a plain function probe.

The capture side is `save_pstore_panic()` in `runner/lib/exploit.sh`: every shot that panics gets the previous boot's console saved beside its own log as `shot-NNNN-PANIC.pstore.log`, gated on the panic reason so a stale record is not re-attributed to a clean shot. The records quoted in this section are those files. The per-build artifacts they are read against — BTF, `kallsyms`, the config — are pulled by [`runner/scripts/harvest-live.sh`](../../runner/scripts/harvest-live.sh), which takes `/sys/kernel/btf/vmlinux` through `su` and so says nothing about the unprivileged read.

## See also

- [01-vulnerability-discovery-and-patch-triage.md](01-vulnerability-discovery-and-patch-triage.md) — matching a crash to a specific source revision, and why a version number is not a patch-presence test.
- [02-reachability-and-attack-surface.md](02-reachability-and-attack-surface.md) — reading the policy off the device, and the SELinux and capability questions that decide which of these instruments you can run at all.
- [04-kaslr-and-information-leaks.md](04-kaslr-and-information-leaks.md) — recovering the slide that makes raw crash addresses meaningful, reconstructing an ELF from a retail `boot.img`, extracting BTF from an image when the device will not serve it, and the `/proc/kallsyms` masking ladder.
- [05-heap-grooming-and-spraying.md](05-heap-grooming-and-spraying.md) — reading allocator state as evidence rather than guessing at it, and the cache-merging instruments a "wrong cache" crash needs.
- [06-cross-cache-attacks.md](06-cross-cache-attacks.md) — the page-level views of the same state, for crashes that reduce to a page going somewhere unintended.
- [08-triggering-races-reliably.md](08-triggering-races-reliably.md) — using probe timestamps as a race oracle, and what a fault in a consumer's context implies about timing.
- [10-survivability-and-measurement.md](10-survivability-and-measurement.md) — capturing crash evidence automatically across many runs, and the `O_SYNC` breadcrumb that records what the exploit believed.
- [12-further-reading-and-glossary.md](12-further-reading-and-glossary.md) — sources and terminology.
