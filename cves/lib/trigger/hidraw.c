/* Holding a HID device's hidraw character device open. */
#include "hidraw.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include "../base/clock.h"

#define HIDRAW_CLASS "/sys/class/hidraw"

static int hr_known(const struct lib_hidraw_watch *w, const char *name)
{
	int i;

	for (i = 0; i < w->nseen; i++) {
		if (!strcmp(w->seen[i], name))
			return 1;
	}
	return 0;
}

int lib_hidraw_snapshot(struct lib_hidraw_watch *w)
{
	struct dirent *de;
	DIR *d;

	if (!w)
		return -1;
	w->nseen = 0;
	d = opendir(HIDRAW_CLASS);
	if (!d)
		return -1;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		if (w->nseen >= LIB_HIDRAW_MAX_SEEN)
			break;
		snprintf(w->seen[w->nseen], LIB_HIDRAW_NAME_LEN, "%s", de->d_name);
		w->nseen++;
	}
	closedir(d);
	return 0;
}

/* "<major>:<minor>\n" from the class entry's dev attribute. */
static int hr_devno(const char *name, unsigned *major, unsigned *minor)
{
	char path[256], buf[64];
	int fd, n;

	snprintf(path, sizeof(path), HIDRAW_CLASS "/%s/dev", name);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	return sscanf(buf, "%u:%u", major, minor) == 2 ? 0 : -1;
}

/* /dev/<name> if the device manager made one, else a private node. */
static int hr_open(const char *name, const char *node_dir, int *minor_out)
{
	unsigned major = 0, minor = 0;
	char path[256];
	int fd;

	snprintf(path, sizeof(path), "/dev/%s", name);
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd >= 0) {
		if (minor_out && hr_devno(name, &major, &minor) == 0)
			*minor_out = (int)minor;
		return fd;
	}
	if (hr_devno(name, &major, &minor) != 0)
		return -1;
	if (minor_out)
		*minor_out = (int)minor;
	snprintf(path, sizeof(path), "%s/%s", node_dir ? node_dir : "/data/local/tmp", name);
	unlink(path);
	if (mknod(path, S_IFCHR | 0600, makedev(major, minor)) != 0)
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	unlink(path);   /* the open fd is what holds the reference */
	return fd;
}

int lib_hidraw_open_new(struct lib_hidraw_watch *w, const char *node_dir,
			int timeout_ms, int *minor_out)
{
	int64_t deadline;

	if (!w)
		return -1;
	deadline = lib_now_ns() + (int64_t)timeout_ms * 1000000;
	do {
		struct dirent *de;
		DIR *d = opendir(HIDRAW_CLASS);

		if (d) {
			while ((de = readdir(d)) != NULL) {
				int fd;

				if (de->d_name[0] == '.' || hr_known(w, de->d_name))
					continue;
				fd = hr_open(de->d_name, node_dir, minor_out);
				if (fd >= 0) {
					closedir(d);
					return fd;
				}
			}
			closedir(d);
		}
		lib_sleep_until(lib_now_ns() + 2000000);
	} while (lib_now_ns() < deadline);

	errno = ENOENT;
	return -1;
}
