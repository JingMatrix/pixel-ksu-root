/* lib/trace/interval.h -- how far apart two kernel events are, as a spread.
 *
 * A race is decided by an interval: how long a path spends between the point it
 * commits to an object and the point it reads it, or how long one side of a
 * teardown runs before the other. A single measurement of such an interval says
 * almost nothing, because the useful cases live in the tail -- a reclaim needs
 * the rare long one, not the typical short one -- so what a caller wants is the
 * distribution.
 *
 * Records are paired by name in the order they were written: each `close`
 * record is matched to the `open` record before it, and unmatched records are
 * ignored. That is the right pairing when one event cannot overlap itself,
 * which is the usual case for a path holding a lock, and the wrong one when
 * several can be in flight at once -- there, a sample may pair two different
 * flights and the spread reads low.
 */
#ifndef LIB_INTERVAL_H
#define LIB_INTERVAL_H

#include <stdlib.h>
#include <string.h>

#include "fnprobe.h"

#ifndef LIB_INTERVAL_MAX
#define LIB_INTERVAL_MAX 16384
#endif

struct lib_interval {
	const char *open;         /* the record that starts an interval */
	const char *close;        /* the record that ends one           */
	double us[LIB_INTERVAL_MAX];
	int n;
	double pending;           /* the last unmatched open            */
};

static inline int lib_interval_record(const char *name, double ts,
				      const char *line, void *ctx)
{
	struct lib_interval *iv = ctx;

	(void)line;
	if (!strcmp(name, iv->open)) {
		iv->pending = ts;
	} else if (!strcmp(name, iv->close) && iv->pending > 0.0 &&
		   iv->n < LIB_INTERVAL_MAX) {
		iv->us[iv->n++] = (ts - iv->pending) * 1e6;
		iv->pending = 0.0;
	}
	return 0;
}

/* Walk the records and collect the intervals. Returns how many were paired. */
static inline int lib_interval_collect(struct lib_interval *iv,
				       const char *open, const char *close)
{
	memset(iv, 0, sizeof(*iv));
	iv->open = open;
	iv->close = close;
	lib_fnprobe_each(lib_interval_record, iv);
	return iv->n;
}

static inline int lib_interval_cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return x < y ? -1 : x > y ? 1 : 0;
}

/* Sort in place and return the value at a percentile, 0 to 100. */
static inline double lib_interval_pct(struct lib_interval *iv, int pct)
{
	if (!iv->n)
		return -1.0;
	qsort(iv->us, (size_t)iv->n, sizeof(iv->us[0]), lib_interval_cmp);
	return iv->us[(iv->n - 1) * pct / 100];
}

/* How many samples are at least `us` long, which is the number a race cares
 * about when it needs an interval of a particular size. */
static inline int lib_interval_atleast(const struct lib_interval *iv, double us)
{
	int i, n = 0;

	for (i = 0; i < iv->n; i++)
		if (iv->us[i] >= us)
			n++;
	return n;
}

#endif /* LIB_INTERVAL_H */
