/* lib/trigger/uhid.h - reusable /dev/uhid device helper for the kernel-exploit lib.
 *
 * Wraps the mechanics of driving a virtual HID device: opening /dev/uhid,
 * writing one uhid_event, UHID_CREATE2 setup, and the poll loop that answers
 * UHID_GET_REPORT / UHID_OUTPUT and stops on UHID_CLOSE.
 *
 * EXPLOIT-SPECIFIC and therefore NOT in the lib:
 *   - the HID report descriptor blob (the force-feedback rumble descriptor):
 *     the caller passes it to lib_uhid_create2 as rdesc/rdesc_len.
 *   - the reply content for UHID_OUTPUT reports: the caller supplies an
 *     `answer` callback which builds and sends its own UHID_INPUT2 replies
 *     (via lib_uhid_send, using an fd it keeps itself). UHID_GET_REPORT is
 *     answered with a default EIO GET_REPORT_REPLY by the loop.
 *
 * No device/kernel-version constants live here.
 */
#ifndef LIB_UHID_H
#define LIB_UHID_H

#include <stddef.h>
#include <linux/uhid.h>

/* Open /dev/uhid O_RDWR | O_CLOEXEC. Returns the fd, or -1 on failure
 * (errno set). */
int lib_uhid_open(void);

/* Write one uhid_event to the uhid fd. Returns 0 on success, -1 on a short or
 * failed write (errno set). */
int lib_uhid_send(int fd, const struct uhid_event *ev);

/* Send UHID_CREATE2 for a device with the given identity and report
 * descriptor. name/phys/uniq may be NULL (treated as empty). rdesc/rdesc_len
 * is the caller-owned HID report descriptor. Returns 0 on success, -1 on error
 * (rdesc_len too large for the kernel's rd_data field, or the write failed). */
int lib_uhid_create2(int fd, const char *name, const char *phys,
                     const char *uniq, unsigned bus, unsigned vendor,
                     unsigned product, unsigned version,
                     const unsigned char *rdesc, size_t rdesc_len);

/* Poll loop over the uhid fd, total budget timeout_ms milliseconds:
 *   - UHID_OUTPUT     -> answer(ev.u.output.data) if answer != NULL. The
 *                        callback sends its own replies via lib_uhid_send. If
 *                        it returns < 0 the loop aborts and this returns -1.
 *   - UHID_GET_REPORT -> a default EIO UHID_GET_REPORT_REPLY is sent.
 *   - UHID_CLOSE      -> stop; returns 1.
 * Returns 1 when UHID_CLOSE was seen, 0 on timeout, -1 on read/poll error or
 * an aborting answer callback. */
int lib_uhid_run_until_close(int fd, int (*answer)(const unsigned char *out),
                             int timeout_ms);

#endif /* LIB_UHID_H */
