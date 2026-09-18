# cves/lib — the shared exploitation library

The reusable half of this tree. Each exploit directory is a thin orchestrator over these
modules: it owns the defect, the topology that reaches it, and the tuning that wins its
race. Everything a second exploit would otherwise reimplement lives here.

Modules are grouped by the role they play in a chain, which is also roughly the order a
chain uses them:

| directory | role |
|---|---|
| `base/` | time, processors, files, bytes, child processes, handshakes, outcomes |
| `addr/` | the address-space model: linear map, page descriptors, physical layout |
| `kaslr/` | recovering the kernel image base without writing anything |
| `leak/` | disclosing kernel values through timing |
| `spray/` | placing chosen bytes in kernel memory |
| `trigger/` | driver front-ends that carry a defect to its window |
| `rw/` | kernel read and write, and the contract everything above it speaks |
| `root/` | turning read and write into durable, reachable privilege |
| `trace/` | watching a running kernel from a privileged process |
| `tools/` | shell instruments: probes and observation |

## Two rules

A module never includes a consumer's header. Dependencies run library to library and
exploit to library, never the other way. An exploit-specific constant in a shared module is
the same violation wearing a different hat.

A device or kernel-build constant is a parameter or an `#ifndef`-guarded default, never a
bare definition. The value comes from the target description through `lib/target.h`; the
default beside its use exists only so the module compiles standalone, and every real build
overrides it.

`runner/scripts/lib-audit.sh` checks both.

## The read/write contract

Everything in `root/`, and most of `rw/`, is written against `rw/krw.h` rather than against
a particular primitive: a read, a write, and whatever state they need. That is what lets a
chain install a slow primitive, use it to build a fast one, and keep every consumer working
across the swap.

Addresses are typed by the space they belong to — link-time, linear-map, runtime — so
handing a primitive the wrong kind is a compile error rather than a fault on the device.
The primitives accept linear-map addresses only, because those stay valid regardless of
where the kernel was loaded; the arm64 layout that makes this true is documented in the
[kernel's memory map](https://docs.kernel.org/arch/arm64/memory.html).

## Modules

### base/
| module | what it answers |
|---|---|
| `util.h` | diagnostics, assertions, process naming and limits |
| `clock.h` | monotonic time, and the three ways to wait: sleep, spin, delay |
| `cpu.h` | affinity, requested or confirmed — the distinction matters |
| `file.h` | whole-file reads and writes, where a short read is normal |
| `bytes.h` | composing a fabricated object in a plain buffer |
| `proc.h` | bounded waits, escalating termination, resource headroom |
| `ipc.h` | a one-line handshake between the halves of a split chain |
| `timing.h` | the cycle counter a side channel measures with |
| `procinfo.h` | free memory and allocator readings |
| `outcome.h` | the four things a run can report, and why they differ |
| `mmguard.h` | staying usable once this process's own mappings describe something the kernel must not walk: make every page resident, and close the mappings to other readers |

### addr/
| module | what it answers |
|---|---|
| `physmap.h` | frame ↔ kernel address ↔ page descriptor, by arithmetic |
| `physlayout.{c,h}` | the same across regions, using values read from the kernel |
| `pagemap.h` | where a page actually landed, for a [privileged observer](https://docs.kernel.org/admin-guide/mm/pagemap.html) |
| `zoneguess.h` | where it probably landed, for everyone else |

### kaslr/
`kaslr_tracefs.h` recovers the image base by making the kernel record one of its own code
addresses through [ftrace](https://docs.kernel.org/trace/ftrace.html) and reading it back —
no writes, no privilege, and available before any exploitation step. `slide_tracefs.c`
links it into a payload; `kaslr_marker.c` is a standalone probe. The reasoning is in
[`kaslr/README.md`](kaslr/README.md).

### leak/
`futex_bucket.h` models which hash bucket an address falls in, which is the basis for
recovering an address-space identifier by timing a
[`futex`](https://man7.org/linux/man-pages/man2/futex.2.html) operation. `kernelsnitch/` is
the search built on that model, after
[KernelSnitch](https://lukasmaar.github.io/papers/ndss25-kernelsnitch.pdf) (NDSS 2025).

### spray/
| module | vehicle |
|---|---|
| `sockpool.{c,h}` | phased, multi-processor socket spray with drain-and-read-back |
| `skbspray.{c,h}` | the single-shot form, where phases are not needed |
| `notifyspray.{c,h}` | content-controlled small allocations through change notification |
| `keyspray.{c,h}` | hold a freed object with chosen bytes, where there is no System-V IPC |
| `physspray.{c,h}` | one structure replicated across anonymous memory |
| `crosscache.{c,h}` | a page freed from one [slab cache](https://docs.kernel.org/mm/slub.html) and refilled from another — see [`spray/crosscache/README.md`](spray/crosscache/README.md) |

### trigger/
| module | front-end |
|---|---|
| `uhid.{c,h}` | a [virtual input device](https://docs.kernel.org/hid/uhid.html) |
| `binder.{c,h}` | the [binder](https://source.android.com/docs/core/architecture/hidl/binder-ipc) transport: opening, the command stream, object descriptors |
| `ashmem.h` | the shared-memory device's user interface |

### rw/
| module | primitive |
|---|---|
| `krw.h` | the contract, and the typed address model |
| `nameblob.{c,h}` | read and write through a redirected buffer descriptor |
| `pipe_rw.{c,h}` | read and write a physical page through a borrowed [pipe](https://man7.org/linux/man-pages/man7/pipe.7.html) entry |
| `slabpage.{c,h}` | is this page the one the reclaim aimed at |

### root/
| module | step |
|---|---|
| `cred.{c,h}` | make a [credential](https://docs.kernel.org/security/credentials.html) privileged |
| `cred_image.{c,h}` | edit one reversibly, verified, field by named field |
| `taskscan.{c,h}` | find a task record by the identifier it reports |
| `kernelsu.{c,h}` | is a controllable privilege daemon present |
| `kprobe_read.{c,h}` | read kernel state through a [probe](https://docs.kernel.org/trace/kprobes.html), for ground truth |
| `handoff.{c,h}` | make the privilege durable and reachable |

### trace/
| module | instrument |
|---|---|
| `fnprobe.{c,h}` | watch a kernel function: arm, read the records back, restore |

### tools/
Shell instruments, documented in [`tools/README.md`](tools/README.md): probe arming and
reading, and three presence tests that share one verdict contract.
