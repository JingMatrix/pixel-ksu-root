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

/* ── reverse lookup: an address to the symbol that contains it ───────────────
 *
 * lib_symbol_addr answers name -> address; a backtrace needs the other
 * direction, address -> name. That is not a per-symbol query but a table: load
 * the whole exported table once, sorted by address, and each lookup is the
 * nearest symbol at or below the address. Addresses are masked to zero for an
 * unprivileged caller, so a table that loads all zeros is reported as unusable
 * rather than resolving everything to the first symbol.
 */
struct lib_ksym_ent {
	unsigned long long addr;
	const char *name;   /* points into `blob` */
};

struct lib_ksymtab {
	char *blob;                 /* the whole file, names NUL-terminated in place */
	struct lib_ksym_ent *v;
	int n;
};

static inline int lib_ksym_cmp(const void *a, const void *b)
{
	unsigned long long x = ((const struct lib_ksym_ent *)a)->addr;
	unsigned long long y = ((const struct lib_ksym_ent *)b)->addr;
	return (x > y) - (x < y);
}

/* Load /proc/kallsyms into `t`, sorted by address. Returns the symbol count, 0
 * if addresses are masked (nothing usable), -1 if the table could not be read.
 * lib_ksymtab_free() releases it. */
static inline int lib_ksymtab_load(struct lib_ksymtab *t)
{
	memset(t, 0, sizeof(*t));
	FILE *f = fopen(LIB_KALLSYMS_PATH, "re");
	if (!f)
		return -1;
	/* Slurp the file: names are kept as pointers into this buffer. */
	size_t cap = 1 << 20, len = 0;
	char *blob = (char *)malloc(cap);
	if (!blob) {
		fclose(f);
		return -1;
	}
	for (;;) {
		if (len + 65536 > cap) {
			size_t ncap = cap * 2;
			char *nb = (char *)realloc(blob, ncap);
			if (!nb) {
				free(blob);
				fclose(f);
				return -1;
			}
			blob = nb;
			cap = ncap;
		}
		size_t got = fread(blob + len, 1, 65536, f);
		len += got;
		if (got < 65536)
			break;
	}
	fclose(f);
	if (len == 0) {
		free(blob);
		return -1;
	}
	blob[len - 1] = '\0';

	int cap_n = 4096, n = 0;
	struct lib_ksym_ent *v = (struct lib_ksym_ent *)malloc(
		(size_t)cap_n * sizeof(*v));
	if (!v) {
		free(blob);
		return -1;
	}
	unsigned long long maxaddr = 0;
	char *save = NULL;
	for (char *line = strtok_r(blob, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		/* `<address> <type> <name>[\t[module]]` */
		char *sp1 = strchr(line, ' ');
		if (!sp1)
			continue;
		char *sp2 = strchr(sp1 + 1, ' ');
		if (!sp2)
			continue;
		unsigned long long a = strtoull(line, NULL, 16);
		char *name = sp2 + 1;
		char *tab = strchr(name, '\t');
		if (tab)
			*tab = '\0';   /* drop the module suffix */
		if (n == cap_n) {
			int ncap = cap_n * 2;
			struct lib_ksym_ent *nv = (struct lib_ksym_ent *)realloc(
				v, (size_t)ncap * sizeof(*v));
			if (!nv)
				break;
			v = nv;
			cap_n = ncap;
		}
		v[n].addr = a;
		v[n].name = name;
		if (a > maxaddr)
			maxaddr = a;
		n++;
	}
	if (n == 0 || maxaddr == 0) {   /* empty or every address masked */
		free(v);
		free(blob);
		return 0;
	}
	qsort(v, (size_t)n, sizeof(*v), lib_ksym_cmp);
	t->blob = blob;
	t->v = v;
	t->n = n;
	return n;
}

static inline void lib_ksymtab_free(struct lib_ksymtab *t)
{
	free(t->v);
	free(t->blob);
	memset(t, 0, sizeof(*t));
}

/* Write "name+0xoff" for the symbol containing `addr` into `buf`. Returns buf on
 * success, NULL when the table is empty or the address is below the first
 * symbol; the caller prints the raw address then. */
static inline const char *lib_ksym_name(const struct lib_ksymtab *t,
					unsigned long long addr, char *buf,
					size_t buflen)
{
	if (!t->n || addr < t->v[0].addr)
		return NULL;
	int lo = 0, hi = t->n - 1, best = 0;
	while (lo <= hi) {
		int mid = lo + (hi - lo) / 2;
		if (t->v[mid].addr <= addr) {
			best = mid;
			lo = mid + 1;
		} else {
			hi = mid - 1;
		}
	}
	unsigned long long off = addr - t->v[best].addr;
	if (off)
		snprintf(buf, buflen, "%s+0x%llx", t->v[best].name, off);
	else
		snprintf(buf, buflen, "%s", t->v[best].name);
	return buf;
}

#endif /* LIB_BASE_KALLSYMS_H */
