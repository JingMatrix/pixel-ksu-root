/* Reclaim through keyring payloads. */
#include "keyspray.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define KEY_SPEC_PROCESS_KEYRING (-2)
#define KEYCTL_CLEAR 7

static long key_add(const char *desc, const void *payload, size_t len)
{
	return syscall(__NR_add_key, "user", desc, payload, len,
		       (long)KEY_SPEC_PROCESS_KEYRING);
}

int lib_keyspray_init(struct lib_keyspray *s, size_t object_size)
{
	if (!s || object_size < LIB_KEYSPRAY_MIN_OBJECT) {
		errno = EINVAL;
		return -1;
	}
	memset(s, 0, sizeof(*s));
	s->object_size = object_size;
	s->len = object_size - LIB_KEYSPRAY_HEADER;
	s->payload = calloc(1, s->len);
	return s->payload ? 0 : -1;
}

int lib_keyspray_at(struct lib_keyspray *s, size_t obj_off, const void *src, size_t n)
{
	if (!s || !s->payload || obj_off < LIB_KEYSPRAY_HEADER ||
	    obj_off - LIB_KEYSPRAY_HEADER + n > s->len) {
		errno = EINVAL;
		return -1;
	}
	memcpy(s->payload + (obj_off - LIB_KEYSPRAY_HEADER), src, n);
	return 0;
}

int lib_keyspray_once(struct lib_keyspray *s)
{
	char desc[32];

	/* A repeated description updates the key in place instead of
	 * allocating, so every one is new. */
	snprintf(desc, sizeof(desc), "ks-%u-%u", (unsigned)getpid(), s->seq++);
	if (key_add(desc, s->payload, s->len) < 0) {
		s->refused++;
		return -1;
	}
	s->placed++;
	return 0;
}

unsigned long lib_keyspray_burst(struct lib_keyspray *s, unsigned long n)
{
	unsigned long landed = 0, refused_in_a_row = 0;

	while (n--) {
		if (lib_keyspray_once(s) == 0) {
			landed++;
			refused_in_a_row = 0;
		} else if (++refused_in_a_row > 8) {
			break;      /* the quota is reached; more will not help */
		}
	}
	return landed;
}

void lib_keyspray_release(struct lib_keyspray *s)
{
	syscall(__NR_keyctl, (long)KEYCTL_CLEAR, (long)KEY_SPEC_PROCESS_KEYRING,
		0L, 0L, 0L);
	if (s) {
		free(s->payload);
		s->payload = NULL;
	}
}
