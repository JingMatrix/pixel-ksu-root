/* lib/base/knobs.h - per-shot tuning knobs taken from the environment.
 *
 * A runner that drives a parameter search needs two things from a payload:
 * that it reads the knob, and that it says what value it ended up with and
 * where that came from. The second is what makes a search trustworthy -- a
 * knob that is silently ignored produces a whole sweep of identical runs
 * wearing different labels.
 *
 * The value is reported as NAME=value:env or NAME=value:default on a line
 * beginning "resolved-config", which is the shape the runner parses.
 */
#ifndef LIB_KNOBS_H
#define LIB_KNOBS_H

#include <stdlib.h>

/* Returns the environment value of `name` if it is set and non-empty, else
 * `dflt`. `*src` is set to "env" or "default" for the report. */
static inline int lib_knob_int(const char *name, int dflt, const char **src)
{
	const char *v = getenv(name);

	if (v && *v) {
		*src = "env";
		return atoi(v);
	}
	*src = "default";
	return dflt;
}

static inline long lib_knob_long(const char *name, long dflt, const char **src)
{
	const char *v = getenv(name);

	if (v && *v) {
		*src = "env";
		return atol(v);
	}
	*src = "default";
	return dflt;
}

#endif /* LIB_KNOBS_H */
