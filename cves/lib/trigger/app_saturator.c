/* Occupying a target app's binder thread pool from a separate process. */
#include "app_saturator.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

pid_t lib_app_saturator_launch(const char *dex_path, const unsigned char *dex,
			       size_t dex_len, const char *class_name,
			       int threads, int hold_ms)
{
	int fd = open(dex_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (fd < 0) {
		perror("lib_app_saturator_launch: open dex");
		return -1;
	}
	if (write(fd, dex, dex_len) != (ssize_t)dex_len) {
		perror("lib_app_saturator_launch: write dex");
		close(fd);
		return -1;
	}
	close(fd);

	pid_t pid = fork();

	if (pid < 0) {
		perror("lib_app_saturator_launch: fork");
		return -1;
	}
	if (pid == 0) {
		char n[16], hold[16];
		char classpath[256];
		char *envp[2];

		snprintf(n, sizeof(n), "%d", threads);
		snprintf(hold, sizeof(hold), "%d", hold_ms);
		snprintf(classpath, sizeof(classpath), "CLASSPATH=%s", dex_path);
		envp[0] = classpath;
		envp[1] = NULL;
		execle("/system/bin/app_process", "app_process", "/system/bin",
		      class_name, n, hold, NULL, envp);
		perror("lib_app_saturator_launch: execve app_process");
		_exit(127);
	}
	return pid;
}
