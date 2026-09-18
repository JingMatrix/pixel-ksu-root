/* Acting inside a kernel function's own window. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* cpu_set_t, sched_setaffinity -- see ../base/cpu.h */
#endif
#include "window_gate.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "fnprobe.h"
#include "../base/clock.h"
#include "../base/cpu.h"

int lib_window_gate_arm(struct lib_window_gate *g, const char *name,
			const char *sym)
{
	if (!g || !name || !sym)
		return -1;
	memset(g, 0, sizeof(*g));
	pthread_mutex_init(&g->lock, NULL);
	pthread_cond_init(&g->cond, NULL);
	snprintf(g->name, sizeof(g->name), "%s", name);
	if (lib_fnprobe_arm(name, sym) != 0)
		return -1;
	/* Best effort: without it the record's timestamp is not comparable with
	 * the caller's clock, which costs a diagnostic, not the gate. */
	lib_fnprobe_set_clock("mono");
	return lib_fnprobe_start();
}

static void gate_open(struct lib_window_gate *g)
{
	pthread_mutex_lock(&g->lock);
	g->open = 1;
	pthread_cond_broadcast(&g->cond);
	pthread_mutex_unlock(&g->lock);
}

static void *gate_thread(void *arg)
{
	struct lib_window_gate *g = arg;
	char match[32];
	int64_t give_up = lib_now_ns() + (int64_t)g->budget_ms * 1000000;
	int fd, fl;

	lib_pin_cpu(g->watch_cpu);
	snprintf(match, sizeof(match), " %s: ", g->name);

	fd = lib_fnprobe_stream();
	if (fd >= 0) {
		fl = fcntl(fd, F_GETFL, 0);
		if (fl >= 0)
			fcntl(fd, F_SETFL, fl | O_NONBLOCK);
		while (!g->stop && lib_now_ns() < give_up) {
			char buf[512];
			const char *hit;
			ssize_t n = read(fd, buf, sizeof(buf) - 1);

			if (n <= 0)
				continue;
			buf[n] = '\0';
			hit = strstr(buf, match);
			if (!hit)
				continue;
			if (lib_fnprobe_record_ns(hit, &g->record_ns) != 0)
				g->record_ns = 0;
			break;
		}
		close(fd);
	}
	g->open_ns = lib_now_ns();
	gate_open(g);
	return NULL;
}

int lib_window_gate_watch(struct lib_window_gate *g, int cpu, int budget_ms)
{
	if (!g)
		return -1;
	g->watch_cpu = cpu;
	g->budget_ms = budget_ms > 0 ? budget_ms : 15000;
	if (pthread_create(&g->watcher, NULL, gate_thread, g) != 0)
		return -1;
	g->watcher_live = 1;
	return 0;
}

int lib_window_gate_wait(struct lib_window_gate *g)
{
	int opened;

	if (!g)
		return -1;
	pthread_mutex_lock(&g->lock);
	while (!g->open && !g->stop)
		pthread_cond_wait(&g->cond, &g->lock);
	opened = g->open;
	pthread_mutex_unlock(&g->lock);
	return opened ? 0 : -1;
}

void lib_window_gate_stop(struct lib_window_gate *g)
{
	if (!g)
		return;
	pthread_mutex_lock(&g->lock);
	g->stop = 1;
	pthread_cond_broadcast(&g->cond);
	pthread_mutex_unlock(&g->lock);
}

void lib_window_gate_close(struct lib_window_gate *g)
{
	if (!g)
		return;
	g->stop = 1;
	if (g->watcher_live) {
		pthread_join(g->watcher, NULL);
		g->watcher_live = 0;
	}
	lib_fnprobe_disable(g->name);
}

int64_t lib_window_gate_delivery_us(const struct lib_window_gate *g)
{
	if (!g || !g->record_ns || !g->open_ns)
		return -1;
	return (g->open_ns - g->record_ns) / 1000;
}
