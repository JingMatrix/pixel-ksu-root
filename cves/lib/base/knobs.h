/* lib/base/knobs.h - per-shot tuning knobs taken from the environment.
 *
 * A runner that drives a parameter search needs two things from a payload:
 * that it reads the knob, and that it says what value it ended up with and
 * where that came from. The second is what makes a search trustworthy -- a
 * knob that is silently ignored produces a whole sweep of identical runs
 * wearing different labels.
 *
 * So reading a knob IS reporting it: the first time any knob is resolved it
 * prints one self-describing line
 *
 *     cfg NAME=value default=D src=env|default
 *
 * which the runner lifts into run-config.txt. The record is complete and
 * drift-free because it is produced by the same call that reads the value --
 * there is no separate list to maintain, and it works for every consumer that
 * takes a knob through this header, not one exploit. A consumer with its own
 * env parser reports through lib_knob_report() directly.
 */
#ifndef LIB_KNOBS_H
#define LIB_KNOBS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Print one `cfg` line per knob, the first time it is seen. Deduped so a knob
 * read in a loop prints once; the per-translation-unit table means a knob read
 * from two files may print twice, which the runner collapses (sort -u). */
static inline void lib_knob_report(const char *name, long value, long dflt,
				   int from_env)
{
	static char seen[192][48];
	static int nseen;

	for (int i = 0; i < nseen; i++)
		if (!strcmp(seen[i], name))
			return;
	if (nseen < (int)(sizeof(seen) / sizeof(seen[0]))) {
		snprintf(seen[nseen], sizeof(seen[0]), "%s", name);
		nseen++;
	}
	printf("cfg %s=%ld default=%ld src=%s\n", name, value, dflt,
	       from_env ? "env" : "default");
}

/* Returns the environment value of `name` if it is set and non-empty, else
 * `dflt`. `src`, when non-NULL, receives "env" or "default" for the report. */
static inline int lib_knob_int(const char *name, int dflt, const char **src)
{
	const char *v = getenv(name);
	int value = (v && *v) ? atoi(v) : dflt;

	if (src)
		*src = (v && *v) ? "env" : "default";
	lib_knob_report(name, value, dflt, v && *v);
	return value;
}

static inline long lib_knob_long(const char *name, long dflt, const char **src)
{
	const char *v = getenv(name);
	long value = (v && *v) ? atol(v) : dflt;

	if (src)
		*src = (v && *v) ? "env" : "default";
	lib_knob_report(name, value, dflt, v && *v);
	return value;
}

/* A boolean knob. The runner accepts 0/1/true/false/yes/no for a `bool`
 * tunable and passes the operator's spelling through verbatim
 * (runner/lib/exploit.sh:_knob_value_ok), so a consumer that compares against
 * "0" alone silently reads `false` as true -- a knob that cannot be turned off
 * is worse than no knob. Every spelling is handled here, once. */
static inline int lib_knob_bool(const char *name, int dflt, const char **src)
{
	const char *v = getenv(name);
	int from_env = v && *v, value = dflt;

	if (from_env) {
		switch (*v) {
		case '0': case 'f': case 'F': case 'n': case 'N':
			value = 0;
			break;
		default:
			value = 1;
			break;
		}
	}
	if (src)
		*src = from_env ? "env" : "default";
	lib_knob_report(name, value, dflt, from_env);
	return value;
}

#endif
