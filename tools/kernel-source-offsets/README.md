# tools/kernel-source-offsets — struct layout from source, no BTF

[`cves/targets/README.md`](../../cves/targets/README.md) describes two sources
for a target's structure layouts: BTF sliced from a kernel image, or the same
BTF harvested live from a rooted device. Both need `CONFIG_DEBUG_INFO_BTF`.
Plenty of shipping kernels — most vendor (non-GKI) kernels among them — don't
have it. This is the fallback: derive the same numbers from the kernel's own
source tree instead.

## Why this gives the same answer as BTF

Struct layout (field order, offset, size) is an ABI fact — declaration order
plus the target's alignment rules — not a compiler optimisation choice. Any
conformant compiler for the target architecture reproduces it byte-for-byte.
The kernel already relies on this every build: `arch/*/kernel/asm-offsets.c`
is a tiny translation unit that computes `offsetof()`/`sizeof()` for a
hand-picked set of fields and emits each as a `.ascii "->NAME VALUE"` string
in its `.s` output, later grepped into `include/generated/asm-offsets.h`. The
host compiler running this need not match the kernel's own build toolchain
version — what has to match is the *source* (the same struct definitions) and
the same `.config` (so every `#ifdef`-conditional field resolves the same
way).

`derive.sh` runs that identical mechanism against a caller-supplied probe:
capture the exact compiler invocation Kbuild used for its own
`asm-offsets.c` (via `make V=1`), then recompile a custom probe with those
same flags. The result is the same number BTF would have reported, and it's
reproducible from nothing but the kernel source tree — no device, no image
parsing. The flags must be captured from Kbuild, not reassembled by hand: a
single missing Kbuild flag shifts struct offsets silently, with no
diagnostic to catch it.

## Usage

```sh
tools/kernel-source-offsets/derive.sh \
  --kdir /path/to/kernel/source \
  --out  /path/to/scratch/build-dir \
  --config captured.config \
  --probe  my_probe.c \
  [--extra-include DIR]... [--pre-target TARGET]...
```

- `--config` seeds `--out`'s `.config` via `olddefconfig` — pass whatever
  `.config` matches the exact build being targeted (`adb shell cat
  /proc/config.gz | gunzip`, from a rooted device on that build, is the
  simplest source). Only needed the first time for a given `--out`; repeat
  runs against the same directory reuse it.
- `my_probe.c` includes the real kernel headers and calls `DEFINE(NAME,
  offsetof(struct foo, bar))` (from `#include <linux/kbuild.h>`) once per
  fact wanted — see [`../../cves/targets/kernel/a52sxq-A528BXXSBGYI3-struct-probe.c`](../../cves/targets/kernel/a52sxq-A528BXXSBGYI3-struct-probe.c)
  for a worked example (task_struct, cred, rt_mutex_waiter,
  file_operations, pipe_inode_info, a locally-declared `struct
  configfs_buffer` copied from its private definition in
  `fs/configfs/file.c`, and more).
- `--extra-include` for anything the probe's own `#include`s need beyond what
  Kbuild already passes for `asm-offsets.c` — a directory like
  `kernel/locking` (for `rtmutex_common.h`, not under `include/`), or a
  `security/*/include` directory for an LSM-internal struct.
- `--pre-target` for a generated header the probe needs that
  `asm-offsets.c` itself never pulls in, so nothing else would produce it —
  e.g. `security/selinux/flask.h` only exists as a side effect of building an
  object that includes it (`--pre-target security/selinux/hooks.o`).

Output format and scope: `derive.sh --help`.

## See also

- [`../../cves/targets/README.md`](../../cves/targets/README.md) — where the
  resulting offsets fit into a target description, and how the BTF path
  works when it's available.
- [`../pixel-image/README.md`](../pixel-image/README.md) — the symbol-address
  half, offline, from a boot image.
- [`../../cves/lib/kaslr/README.md`](../../cves/lib/kaslr/README.md) — the
  text-base leak this struct data is combined with at runtime.
