/* Struct-layout probe for a52sxq-A528BXXSBGYI3 (no CONFIG_DEBUG_INFO_BTF).
 * See ../../../tools/kernel-source-offsets/README.md for the mechanism this
 * relies on. Re-derive with:
 *
 *   tools/kernel-source-offsets/derive.sh --kdir <kernel source> \
 *     --out <scratch build dir> --config <captured .config> \
 *     --extra-include <kernel source>/security/selinux \
 *     --extra-include <build dir>/security/selinux \
 *     --pre-target security/selinux/hooks.o \
 *     --probe cves/targets/kernel/a52sxq-A528BXXSBGYI3-struct-probe.c
 *
 * The .config: adb shell cat /proc/config.gz | gunzip, from a rooted device
 * on build A528BXXSBGYI3. The two --extra-include and the --pre-target are
 * for security/selinux/include/objsec.h's own #include "flask.h", which
 * only exists once something that reaches it has been built. */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/seccomp.h>
#include <linux/fs.h>
#include <linux/pipe_fs_i.h>
#include <linux/miscdevice.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/fdtable.h>
#include <linux/mutex.h>
#include <linux/kbuild.h>
#include "kernel/locking/rtmutex_common.h"
#include "security/selinux/include/objsec.h"

/* fs/configfs/file.c, struct configfs_buffer -- private to that .c, copied
 * verbatim (field order/types) so offsetof() sees the real kernel layout. */
struct configfs_buffer {
  size_t count;
  loff_t pos;
  char *page;
  struct configfs_item_operations *ops;
  struct mutex mutex;
  int needs_read_fill;
  bool read_in_progress;
  bool write_in_progress;
  char *bin_buffer;
  int bin_buffer_size;
  int cb_max_size;
  struct config_item *item;
  struct module *owner;
  union {
    struct configfs_attribute *attr;
    struct configfs_bin_attribute *bin_attr;
  };
};

int main(void) {
  DEFINE(TASK_PID_OFF, offsetof(struct task_struct, pid));
  DEFINE(TASK_TGID_OFF, offsetof(struct task_struct, tgid));
  DEFINE(TASK_REAL_PARENT_OFF, offsetof(struct task_struct, real_parent));
  DEFINE(TASK_REAL_CRED_OFF, offsetof(struct task_struct, real_cred));
  DEFINE(TASK_CRED_OFF, offsetof(struct task_struct, cred));
  DEFINE(TASK_COMM_OFF, offsetof(struct task_struct, comm));
  DEFINE(TASK_TASKS_OFF, offsetof(struct task_struct, tasks));
  DEFINE(TASK_SECCOMP_OFF, offsetof(struct task_struct, seccomp));
  DEFINE(TASK_ATOMIC_FLAGS_OFF, offsetof(struct task_struct, atomic_flags));
  DEFINE(TASK_GROUP_LEADER_OFF, offsetof(struct task_struct, group_leader));
  DEFINE(TASK_FILES_OFF, offsetof(struct task_struct, files));
  DEFINE(TASK_THREAD_INFO_FLAGS_OFF,
         offsetof(struct task_struct, thread_info) +
             offsetof(struct thread_info, flags));

  DEFINE(FAKE_TASK_USAGE_OFF, offsetof(struct task_struct, usage));
  DEFINE(FAKE_TASK_PRIO_OFF, offsetof(struct task_struct, prio));
  DEFINE(FAKE_TASK_NORMAL_PRIO_OFF, offsetof(struct task_struct, normal_prio));
  DEFINE(FAKE_TASK_TASK_GROUP_OFF, offsetof(struct task_struct, sched_task_group));
  DEFINE(FAKE_TASK_PI_LOCK_OFF, offsetof(struct task_struct, pi_lock));
  DEFINE(FAKE_TASK_PI_WAITERS_OFF, offsetof(struct task_struct, pi_waiters));
  DEFINE(FAKE_TASK_PI_TOP_TASK_OFF, offsetof(struct task_struct, pi_top_task));
  DEFINE(FAKE_TASK_PI_BLOCKED_ON_OFF, offsetof(struct task_struct, pi_blocked_on));
  DEFINE(TASK_STRUCT_SIZE, sizeof(struct task_struct));

  DEFINE(CRED_UID_OFF, offsetof(struct cred, uid));
  DEFINE(CRED_SECUREBITS_OFF, offsetof(struct cred, securebits));
  DEFINE(CRED_CAPS_OFF, offsetof(struct cred, cap_inheritable));
  DEFINE(CRED_CAP_INHERITABLE_OFF, offsetof(struct cred, cap_inheritable));
  DEFINE(CRED_CAP_PERMITTED_OFF, offsetof(struct cred, cap_permitted));
  DEFINE(CRED_CAP_EFFECTIVE_OFF, offsetof(struct cred, cap_effective));
  DEFINE(CRED_CAP_BSET_OFF, offsetof(struct cred, cap_bset));
  DEFINE(CRED_CAP_AMBIENT_OFF, offsetof(struct cred, cap_ambient));
  DEFINE(CRED_SECURITY_OFF, offsetof(struct cred, security));
  DEFINE(CRED_USAGE_OFF, offsetof(struct cred, usage));
  DEFINE(CRED_USER_OFF, offsetof(struct cred, user));
  DEFINE(CRED_USER_NS_OFF, offsetof(struct cred, user_ns));
  DEFINE(CRED_GROUP_INFO_OFF, offsetof(struct cred, group_info));
  DEFINE(CRED_SIZE, sizeof(struct cred));
  DEFINE(KERNEL_CAP_T_SIZE, sizeof(kernel_cap_t));

  DEFINE(SELINUX_CRED_OSID_OFF, offsetof(struct task_security_struct, osid));
  DEFINE(SELINUX_CRED_SID_OFF, offsetof(struct task_security_struct, sid));
  DEFINE(SELINUX_CRED_SIZE, sizeof(struct task_security_struct));

  DEFINE(SECCOMP_MODE_OFF, offsetof(struct seccomp, mode));
  DEFINE(SECCOMP_FILTER_OFF, offsetof(struct seccomp, filter));
  DEFINE(SECCOMP_STRUCT_SIZE, sizeof(struct seccomp));

  DEFINE(WAITER_TREE_ENTRY_OFF, offsetof(struct rt_mutex_waiter, tree_entry));
  DEFINE(WAITER_PI_TREE_ENTRY_OFF, offsetof(struct rt_mutex_waiter, pi_tree_entry));
  DEFINE(WAITER_TASK_OFF, offsetof(struct rt_mutex_waiter, task));
  DEFINE(WAITER_LOCK_OFF, offsetof(struct rt_mutex_waiter, lock));
  DEFINE(WAITER_PRIO_OFF, offsetof(struct rt_mutex_waiter, prio));
  DEFINE(WAITER_DEADLINE_OFF, offsetof(struct rt_mutex_waiter, deadline));
  DEFINE(WAITER_STRUCT_SIZE, sizeof(struct rt_mutex_waiter));

  DEFINE(FOPS_OWNER_OFF, offsetof(struct file_operations, owner));
  DEFINE(FOPS_LLSEEK_OFF, offsetof(struct file_operations, llseek));
  DEFINE(FOPS_READ_OFF, offsetof(struct file_operations, read));
  DEFINE(FOPS_WRITE_OFF, offsetof(struct file_operations, write));
  DEFINE(FOPS_READ_ITER_OFF, offsetof(struct file_operations, read_iter));
  DEFINE(FOPS_WRITE_ITER_OFF, offsetof(struct file_operations, write_iter));
  DEFINE(FOPS_IOCTL_OFF, offsetof(struct file_operations, unlocked_ioctl));
  DEFINE(FOPS_COMPAT_IOCTL_OFF, offsetof(struct file_operations, compat_ioctl));
  DEFINE(FOPS_MMAP_OFF, offsetof(struct file_operations, mmap));
  DEFINE(FOPS_OPEN_OFF, offsetof(struct file_operations, open));
  DEFINE(FOPS_RELEASE_OFF, offsetof(struct file_operations, release));
  DEFINE(FOPS_SPLICE_READ_OFF, offsetof(struct file_operations, splice_read));
  DEFINE(FOPS_SHOW_FDINFO_OFF, offsetof(struct file_operations, show_fdinfo));
  DEFINE(FOPS_STRUCT_SIZE, sizeof(struct file_operations));

  DEFINE(MISCDEVICE_FOPS_OFF, offsetof(struct miscdevice, fops));

  DEFINE(FILE_OFF_F_INODE, offsetof(struct file, f_inode));
  DEFINE(FILE_OFF_F_OP, offsetof(struct file, f_op));
  DEFINE(FILE_OFF_F_COUNT, offsetof(struct file, f_count));
  DEFINE(FILE_OFF_F_POS, offsetof(struct file, f_pos));
  DEFINE(FILE_OFF_PRIVATE_DATA, offsetof(struct file, private_data));
  DEFINE(FILE_SIZE, sizeof(struct file));

  DEFINE(INODE_OFF_I_SB, offsetof(struct inode, i_sb));
  DEFINE(INODE_OFF_I_INO, offsetof(struct inode, i_ino));
  DEFINE(SUPER_BLOCK_OFF_S_DEV, offsetof(struct super_block, s_dev));

  DEFINE(MM_PGD_OFF, offsetof(struct mm_struct, pgd));
  DEFINE(FILES_FDT_OFF, offsetof(struct files_struct, fdt));
  DEFINE(FDT_FD_OFF, offsetof(struct fdtable, fd));

  /* Pre-8cefc107ca54 (< 5.5): nrbufs/curbuf/buffers, not ring_size/head/tail. */
  DEFINE(PIPE_INODE_OFF_NRBUFS, offsetof(struct pipe_inode_info, nrbufs));
  DEFINE(PIPE_INODE_OFF_CURBUF, offsetof(struct pipe_inode_info, curbuf));
  DEFINE(PIPE_INODE_OFF_BUFFERS, offsetof(struct pipe_inode_info, buffers));
  DEFINE(PIPE_INODE_OFF_BUFS, offsetof(struct pipe_inode_info, bufs));
  DEFINE(PIPE_INODE_INFO_SIZE, sizeof(struct pipe_inode_info));
  DEFINE(PIPE_BUFFER_OFF_PAGE, offsetof(struct pipe_buffer, page));
  DEFINE(PIPE_BUFFER_OFF_OFFSET, offsetof(struct pipe_buffer, offset));
  DEFINE(PIPE_BUFFER_OFF_LEN, offsetof(struct pipe_buffer, len));
  DEFINE(PIPE_BUFFER_OFF_OPS, offsetof(struct pipe_buffer, ops));
  DEFINE(PIPE_BUFFER_OFF_FLAGS, offsetof(struct pipe_buffer, flags));
  DEFINE(PIPE_BUFFER_OFF_PRIVATE, offsetof(struct pipe_buffer, private));
  DEFINE(PIPE_BUFFER_SIZE, sizeof(struct pipe_buffer));

  DEFINE(STRUCT_PAGE_SIZE, sizeof(struct page));
  DEFINE(STRUCT_PAGE_FLAGS_OFF, offsetof(struct page, flags));
  DEFINE(STRUCT_PAGE_COMPOUND_HEAD_OFF, offsetof(struct page, compound_head));
  DEFINE(STRUCT_SLAB_CACHE_OFF, offsetof(struct page, slab_cache));
  DEFINE(STRUCT_PAGE_TYPE_OFF, offsetof(struct page, page_type));
  DEFINE(PG_SLAB_BIT, PG_slab);
  DEFINE(PG_HEAD_BIT, PG_head);

  DEFINE(CFG_PAGE_OFF, offsetof(struct configfs_buffer, page));
  DEFINE(CFG_NEEDS_READ_FILL_OFF, offsetof(struct configfs_buffer, needs_read_fill));
  DEFINE(CFG_BIN_BUFFER_OFF, offsetof(struct configfs_buffer, bin_buffer));
  DEFINE(CFG_BIN_BUFFER_SIZE_OFF, offsetof(struct configfs_buffer, bin_buffer_size));
  DEFINE(CFG_CB_MAX_SIZE_OFF, offsetof(struct configfs_buffer, cb_max_size));
  DEFINE(CFG_BUFFER_SIZE, sizeof(struct configfs_buffer));

  return 0;
}
