/* lib/root/handoff.c -- see handoff.h. */
#define _GNU_SOURCE
#include "handoff.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../base/file.h"

/* Size of the private filesystem. It holds one small helper, so this is
 * generous; the point is that it is bounded. */
#ifndef LIB_HANDOFF_MOUNT_OPTS
#define LIB_HANDOFF_MOUNT_OPTS "mode=0755,size=4m"
#endif

int lib_handoff_is_mounted(const char *path)
{
	char mounts[16384];
	char needle[512];
	int fd = open("/proc/mounts", O_RDONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return 0;
	n = lib_read_full(fd, mounts, sizeof(mounts) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	mounts[n] = '\0';
	/* Bounded by spaces: a mount point is a whole field, and matching a
	 * substring would accept a different path that contains this one. */
	snprintf(needle, sizeof(needle), " %s ", path);
	return strstr(mounts, needle) != NULL;
}

int lib_handoff_mount(const char *dir)
{
	if (lib_handoff_is_mounted(dir))
		return 1;
	if (mount("tmpfs", dir, "tmpfs", 0, LIB_HANDOFF_MOUNT_OPTS) == 0)
		return 1;
	/* Busy means someone mounted it between the check and the attempt,
	 * which is the outcome asked for. */
	return errno == EBUSY;
}

/* Apply a label by running the system's own tool: the interface for setting one
 * directly is not available to every caller, and the tool is present wherever
 * the policy it serves is. */
static int set_label(const char *path, const char *label)
{
	pid_t pid = fork();
	int status = 0;

	if (pid == 0) {
		execl("/system/bin/chcon", "chcon", label, path, (char *)NULL);
		_exit(127);
	}
	if (pid < 0)
		return 0;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int copy_file(const char *src, const char *dst)
{
	char buf[16384];
	int in = open(src, O_RDONLY | O_CLOEXEC);
	int out;

	if (in < 0)
		return 0;
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
	if (out < 0) {
		close(in);
		return 0;
	}
	for (;;) {
		ssize_t n = read(in, buf, sizeof(buf));

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		if (lib_write_full(out, buf, (size_t)n) != 0) {
			close(in);
			close(out);
			return 0;
		}
	}
	close(in);
	/* Permissions are set explicitly rather than left to the creation mode,
	 * which the process umask would otherwise reduce. */
	fchmod(out, 0755);
	close(out);
	return 1;
}

int lib_handoff_install(const char *dir, const char *name, const char *src,
			const char *label)
{
	char tmp[512], dst[512];

	if (snprintf(tmp, sizeof(tmp), "%s/.%s.new.%d", dir, name, (int)getpid()) >= (int)sizeof(tmp))
		return 0;
	if (snprintf(dst, sizeof(dst), "%s/%s", dir, name) >= (int)sizeof(dst))
		return 0;

	if (!copy_file(src, tmp))
		return 0;
	/* Labelled before it is visible under its final name, so nothing can
	 * find it in an unlabelled state and be refused. */
	set_label(tmp, label ? label : LIB_HANDOFF_LABEL);
	if (rename(tmp, dst) != 0) {
		unlink(tmp);
		return 0;
	}
	set_label(dst, label ? label : LIB_HANDOFF_LABEL);
	return 1;
}

pid_t lib_handoff_find_process(const char *comm)
{
	DIR *d = opendir("/proc");
	struct dirent *e;
	pid_t found = 0;

	if (!d)
		return 0;
	while ((e = readdir(d)) != NULL) {
		char path[64], name[128];
		pid_t pid = (pid_t)atoi(e->d_name);

		if (pid <= 0)
			continue;
		snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
		if (lib_read_first_line(path, name, sizeof(name)) == 0 &&
		    strcmp(name, comm) == 0) {
			found = pid;
			break;
		}
	}
	closedir(d);
	return found;
}

int lib_handoff_publish_to(pid_t pid, const char *dir, const char *name,
			   const char *src, const char *label)
{
	char nspath[64];
	pid_t child;
	int status = 0;

	snprintf(nspath, sizeof(nspath), "/proc/%d/ns/mnt", (int)pid);

	/* The namespace change is irreversible for the process that makes it,
	 * so it is made in a child: the caller stays where it was and keeps
	 * whatever else it still has to do. */
	child = fork();
	if (child == 0) {
		int fd = open(nspath, O_RDONLY | O_CLOEXEC);

		if (fd < 0)
			_exit(1);
		if (setns(fd, CLONE_NEWNS) != 0)
			_exit(1);
		close(fd);
		if (!lib_handoff_mount(dir))
			_exit(1);
		_exit(lib_handoff_install(dir, name, src, label) ? 0 : 1);
	}
	if (child < 0)
		return 0;
	while (waitpid(child, &status, 0) < 0 && errno == EINTR)
		;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int lib_handoff_prepare(const char *dir, const char *name, const char *src,
			const char *label, struct lib_handoff_report *report)
{
	struct lib_handoff_report r;

	memset(&r, 0, sizeof(r));
	r.mounted = lib_handoff_mount(dir);
	if (r.mounted)
		r.installed = lib_handoff_install(dir, name, src, label);
	r.labelled = r.installed;
	if (report)
		*report = r;
	return r.installed;
}
