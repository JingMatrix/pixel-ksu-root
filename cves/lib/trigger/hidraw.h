/* lib/trigger/hidraw.h - holding a HID device's hidraw character device open.
 *
 * hidraw_disconnect() routes through drop_ref(hidraw, 1) (drivers/hid/hidraw.c),
 * which sets hidraw->exist = 0 and then frees the object only when
 * hidraw->open is zero. An open file descriptor on the device's own
 * /dev/hidrawN therefore keeps struct hidraw allocated across a disconnect.
 *
 * That matters because hid_disconnect() frees it before clearing
 * hdev->claimed, so any report delivered in between reaches
 * hidraw_report_event(), which walks dev->list on the freed object. For
 * kmalloc-128 the SLUB free pointer sits at offset 64 -- exactly where
 * struct hidraw keeps that list_head -- so the free alone is enough to make
 * the walk fault. Holding the node open removes the free, and with it the
 * fault, without needing the object's address or winning a reclaim.
 *
 * The device is identified by appearance, not by name: snapshot
 * /sys/class/hidraw before creating the HID device, then take the entry that
 * was not there before. Nothing here depends on the descriptor's identity
 * strings.
 */
#ifndef LIB_HIDRAW_H
#define LIB_HIDRAW_H

#define LIB_HIDRAW_MAX_SEEN 64
#define LIB_HIDRAW_NAME_LEN 32

struct lib_hidraw_watch {
	char seen[LIB_HIDRAW_MAX_SEEN][LIB_HIDRAW_NAME_LEN];
	int nseen;
};

/* Record the hidraw entries that already exist. Call before creating the
 * device. Returns 0, or -1 if /sys/class/hidraw cannot be read. */
int lib_hidraw_snapshot(struct lib_hidraw_watch *w);

/* Wait up to timeout_ms for an entry that the snapshot did not contain, then
 * open its character device and return the fd. /dev/<name> is used when it
 * exists; otherwise a private node is created at <node_dir>/<name> from the
 * major:minor the class exports, which needs CAP_MKNOD. `minor_out` may be
 * NULL. Returns the fd, or -1 (errno set) if none appeared or none opened. */
int lib_hidraw_open_new(struct lib_hidraw_watch *w, const char *node_dir,
			int timeout_ms, int *minor_out);

#endif /* LIB_HIDRAW_H */
