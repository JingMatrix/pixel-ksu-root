/* lib/trigger/ashmem.h -- the anonymous-shared-memory device's user interface.
 *
 * The driver names a region through a fixed-size character buffer copied
 * whole into the kernel. That buffer is the only user-controlled, kernel-side
 * blob of known size the device exposes, which is why more than one technique
 * builds on it: a chain that reaches the buffer's backing object turns a name
 * into a forged structure.
 *
 * This header states the interface only -- the request code, the buffer size,
 * and the constants a name-blob technique needs to place bytes at a chosen
 * offset. The technique itself lives with the primitive that uses it.
 *
 * No device or kernel-build constant belongs here: the values below are the
 * driver's user interface and are the same wherever the driver is present.
 */
#ifndef LIB_TRIGGER_ASHMEM_H
#define LIB_TRIGGER_ASHMEM_H

#include <sys/ioctl.h>

/* Capacity of the name buffer, including its terminator. */
#ifndef ASHMEM_NAME_LEN
#define ASHMEM_NAME_LEN 256
#endif

#ifndef ASHMEM_IOC_MAGIC
#define ASHMEM_IOC_MAGIC 0x77
#endif

/* Copy a name into the region's buffer. */
#ifndef ASHMEM_SET_NAME
#define ASHMEM_SET_NAME _IOW(ASHMEM_IOC_MAGIC, 1, char[ASHMEM_NAME_LEN])
#endif

/* The driver prefixes every stored name with a fixed string, so a blob a
 * caller wants at a chosen offset in the kernel buffer must be written that
 * many bytes earlier. ASHMEM_NAME_PREFIX_LEN is the prefix length;
 * ASHMEM_NAME_PREFIX_WORD is its first eight bytes, which a scan uses to
 * recognise a name buffer among unrelated memory. */
#ifndef ASHMEM_NAME_PREFIX_LEN
#define ASHMEM_NAME_PREFIX_LEN 11
#endif
#ifndef ASHMEM_NAME_PREFIX_WORD
#define ASHMEM_NAME_PREFIX_WORD 0x6d6873612f766564ULL
#endif

/* Default path of the device node. A caller that cannot rely on the path
 * resolves the node by device number instead. */
#ifndef ASHMEM_DEVICE_PATH
#define ASHMEM_DEVICE_PATH "/dev/ashmem"
#endif

#endif /* LIB_TRIGGER_ASHMEM_H */
