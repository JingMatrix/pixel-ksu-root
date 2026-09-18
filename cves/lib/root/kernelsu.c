/* lib/root/kernelsu.c -- see kernelsu.h. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "kernelsu.h"

/* KernelSU reboot(2) backdoor: magic1=0xDEADBEEF, magic2=0xCAFEBABE, arg=&fd. */
struct lib_ksu_get_info_cmd {
  unsigned int version;
  unsigned int flags;
  unsigned int features;
  unsigned int uapi_version;
};

int lib_verify_kernelsu_control(struct lib_ksu_info *out) {
  int fd = -1;
  syscall(SYS_reboot, 0xDEADBEEF, 0xCAFEBABE, 0, &fd);
  if (fd < 0) {
    dprintf(STDERR_FILENO, "late-load: KernelSU driver fd unavailable\n");
    return 13;
  }

  struct lib_ksu_get_info_cmd info;
  memset(&info, 0, sizeof(info));
  int ret = ioctl(fd, _IOR('K', 2, struct lib_ksu_get_info_cmd), &info);
  int saved_errno = errno;
  close(fd);
  if (ret != 0 || info.version == 0 || (info.flags & 1U) == 0 ||
      (info.flags & 4U) == 0) {
    dprintf(STDERR_FILENO,
            "late-load: KernelSU control check failed ret=%d errno=%d "
            "version=%u flags=0x%x\n",
            ret, saved_errno, info.version, info.flags);
    return 14;
  }

  dprintf(STDOUT_FILENO,
          "KernelSU control verified version=%u flags=0x%x "
          "uapi=%u features=0x%x\n",
          info.version, info.flags, info.uapi_version, info.features);
  if (out) {
    out->version = info.version;
    out->flags = info.flags;
    out->features = info.features;
    out->uapi_version = info.uapi_version;
  }
  return 0;
}
