/* lib/base/kallsyms.h -- asking the kernel what it exports.
 *
 * The kernel publishes its symbol table, and two questions get asked of it
 * often enough to be worth one implementation:
 *
 *   Does this name exist? The presence or absence of a symbol distinguishes one
 *   kernel from another, which is how a fix that restructured a code path is
 *   detected without triggering anything.
 *
 *   Where is it? Only for a caller that is already privileged -- addresses are
 *   masked to zero otherwise, and a run that does not check for that will
 *   happily compute offsets from nothing.
 *
 * Both are unreliable by nature and this header makes that explicit rather than
 * papering over it. The table may be unreadable, a symbol may be absent because
 * it was inlined rather than because the code is not there, and an address may
 * be masked. Each is reported as a distinct answer, because collapsing them
 * turns "cannot tell" into a confident wrong verdict.
 *
 * Header-only, libc only, no device constant.
 */
#ifndef LIB_BASE_KALLSYMS_H
#define LIB_BASE_KALLSYMS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef LIB_KALLSYMS_PATH
#define LIB_KALLSYMS_PATH "/proc/kallsyms"
#endif

/* What a lookup found. */
enum lib_symbol_state {
	LIB_SYMBOL_ABSENT = 0,   /* the table was read and the name is not in it   */
	LIB_SYMBOL_PRESENT,      /* the name is there                              */
	LIB_SYMBOL_UNREADABLE,   /* the table could not be read -- no answer       */
};

/* Look `want` up. On LIB_SYMBOL_PRESENT, `addr` receives the published address,
 * which is 0 for an unprivileged caller -- present and zero is a normal result
 * and means the name exists but the address is withheld. `type` receives the
 * one-letter kind. Either pointer may be NULL. */
static inline enum lib_symbol_state lib_symbol_lookup(const char *want,
						      unsigned long long *addr,
						      char *type)
{
	char line[512];
	size_t wl = strlen(want);
	FILE *f = fopen(LIB_KALLSYMS_PATH, "re");
	enum lib_symbol_state state = LIB_SYMBOL_ABSENT;

	if (!f)
		return LIB_SYMBOL_UNREADABLE;
	while (fgets(line, sizeof(line), f)) {
		/* Each row is `<address> <type> <name>[\t[module]]`. The name is
		 * matched as a whole field, so a symbol is not found by being a
		 * prefix of another. */
		char *sp = strrchr(line, ' ');

		if (!sp)
			continue;
		sp++;
		if (strncmp(sp, want, wl) ||
		    (sp[wl] != '\n' && sp[wl] != '\0' && sp[wl] != '\t'))
			continue;
		if (addr)
			*addr = strtoull(line, NULL, 16);
		if (type) {
			char *t = strchr(line, ' ');
			*type = t ? t[1] : '?';
		}
		state = LIB_SYMBOL_PRESENT;
		break;
	}
	fclose(f);
	return state;
}

/* Does the name exist? Returns 1 yes, 0 no, -1 no answer. The three-way result
 * is the point: a caller that treats "cannot read the table" as "absent" will
 * report a patched kernel as vulnerable, or the reverse. */
static inline int lib_symbol_present(const char *want)
{
	switch (lib_symbol_lookup(want, NULL, NULL)) {
	case LIB_SYMBOL_PRESENT:    return 1;
	case LIB_SYMBOL_ABSENT:     return 0;
	default:                    return -1;
	}
}

/* The published address, or 0 if the symbol is absent, the table is unreadable,
 * or the caller is not privileged enough to be shown addresses. A caller that
 * needs to tell those apart uses lib_symbol_lookup(). */
static inline unsigned long long lib_symbol_addr(const char *want)
{
	unsigned long long addr = 0;

	if (lib_symbol_lookup(want, &addr, NULL) != LIB_SYMBOL_PRESENT)
		return 0;
	return addr;
}

#endif /* LIB_BASE_KALLSYMS_H */
