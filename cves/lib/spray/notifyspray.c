/* lib/spray/notifyspray.c -- see notifyspray.h. */
#define _GNU_SOURCE
#include "notifyspray.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

int lib_notifyspray_open(struct lib_notifyspray *s, const char *dir, int count)
{
	int made = 0;

	s->watchers = calloc((size_t)count, sizeof(int));
	if (!s->watchers)
		return -1;
	s->dir = dir;
	for (int i = 0; i < count; i++) {
		s->watchers[i] = inotify_init1(IN_NONBLOCK);
		if (s->watchers[i] < 0)
			break;
		if (inotify_add_watch(s->watchers[i], dir, IN_CREATE | IN_DELETE) < 0) {
			close(s->watchers[i]);
			s->watchers[i] = -1;
			break;
		}
		made++;
	}
	s->count = made;
	if (!made) {
		free(s->watchers);
		s->watchers = NULL;
		return -1;
	}
	return made;
}

void lib_notifyspray_close(struct lib_notifyspray *s)
{
	if (!s->watchers)
		return;
	for (int i = 0; i < s->count; i++)
		if (s->watchers[i] >= 0)
			close(s->watchers[i]);
	free(s->watchers);
	s->watchers = NULL;
	s->count = 0;
}

void lib_notifyspray_drain(struct lib_notifyspray *s)
{
	/* One buffer for every instance: the contents are discarded, and the
	 * only thing that matters is emptying the queues. */
	static char sink[65536];

	for (int i = 0; i < s->count; i++)
		while (read(s->watchers[i], sink, sizeof(sink)) > 0)
			;
}

long lib_notifyspray_fire(struct lib_notifyspray *s, const char *name,
			  size_t namelen, int rounds)
{
	char path[512];
	size_t dirlen = strlen(s->dir);
	long events = 0;

	if (dirlen + 1 + namelen + 1 > sizeof(path))
		return 0;
	memcpy(path, s->dir, dirlen);
	path[dirlen] = '/';
	memcpy(path + dirlen + 1, name, namelen);
	path[dirlen + 1 + namelen] = '\0';

	/* Start from empty, so the first operations are not discarded by a
	 * queue already full from a previous wave. */
	lib_notifyspray_drain(s);

	for (int r = 0; r < rounds; r++) {
		/* A directory rather than a file: creating and removing one
		 * produces the same two events per instance, leaves nothing
		 * behind, and never touches file contents -- so the spray can
		 * run indefinitely. */
		if (mkdir(path, 0700) < 0)
			break;
		rmdir(path);
		events += 2L * s->count;
		/* Drain as we go, not at the end. A queue that fills stops
		 * allocating, which is the failure this technique is most prone
		 * to, and it happens within moments. */
		if ((r & 0x3f) == 0x3f)
			lib_notifyspray_drain(s);
	}
	return events;
}
