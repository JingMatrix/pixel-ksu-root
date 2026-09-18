/* Report descriptors shaped for a free window. */
#include "hid_rdesc.h"

#include <string.h>

size_t lib_hid_rdesc_build(unsigned char *out, size_t cap,
			   const struct lib_hid_rdesc_spec *spec,
			   int *pad_placed)
{
	static const unsigned char head[] = {
		0x06, 0x00, 0xff,       /* Usage Page (vendor defined) */
		0x09, 0x01,             /* Usage (1)                   */
		0xa1, 0x01,             /* Collection (application)    */
		0x85, 0x00,             /* Report ID, patched below    */
		0x15, 0x00,             /* Logical Minimum (0)         */
		0x26, 0xff, 0x00,       /* Logical Maximum (255)       */
		0x75, 0x08,             /* Report Size (8)             */
		0x95, 0x01,             /* Report Count (1)            */
	};
	size_t n = sizeof(head);
	int i, id, placed = 0;

	if (pad_placed)
		*pad_placed = 0;
	if (!out || !spec || cap < n + (size_t)spec->fields * 4 + 16)
		return 0;

	memcpy(out, head, n);
	out[8] = spec->report_id;
	for (i = 0; i < spec->fields; i++) {
		out[n++] = 0x09;
		out[n++] = (unsigned char)(0x10 + (i & 0x7f));
		out[n++] = 0x81;
		out[n++] = 0x02;                /* Input (Data,Variable) */
	}

	if (spec->reply_id) {
		if (n + 8 > cap)
			return 0;
		out[n++] = 0x85; out[n++] = spec->reply_id;
		out[n++] = 0x09; out[n++] = 0x02;
		out[n++] = 0x95; out[n++] = (unsigned char)spec->reply_count;
		out[n++] = 0x81; out[n++] = 0x02;
	}

	if (spec->pad_reports > 0 && spec->pad_fields > 0) {
		/* Two usages per padding field: the parser takes the report
		 * count as the usage total when it exceeds the usages actually
		 * declared, which puts these in a different cache than a
		 * single-usage target field. */
		if (n + 2 > cap)
			return 0;
		out[n++] = 0x95;
		out[n++] = 0x02;
		for (id = spec->report_id + 1;
		     id <= 0xff && placed < spec->pad_reports; id++) {
			if (spec->reply_id && id == spec->reply_id)
				continue;       /* already declared */
			if (n + 2 + (size_t)spec->pad_fields * 4 + 1 > cap)
				break;
			out[n++] = 0x85;
			out[n++] = (unsigned char)id;
			for (i = 0; i < spec->pad_fields; i++) {
				out[n++] = 0x09;
				out[n++] = (unsigned char)(0x10 + (i & 0x7f));
				out[n++] = 0x81;
				out[n++] = 0x02;
			}
			placed++;
		}
		if (pad_placed)
			*pad_placed = placed;
	}

	if (n + 1 > cap)
		return 0;
	out[n++] = 0xc0;                        /* End Collection */
	return n;
}
