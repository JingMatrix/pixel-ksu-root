/* lib/spray/sockpool.c -- see sockpool.h. */
#define _GNU_SOURCE
#include "sockpool.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../base/cpu.h"

/* The byte a warming message carries. Its value is irrelevant; it is checked on
 * drain only to notice a pool that did not hold what was put in it. */
#define WARM_BYTE LIB_SOCKPOOL_WARM_BYTE

struct worker {
	struct lib_sockpool *pool;
	enum lib_sockpool_phase phase;
	const void *payload;
	size_t len;
	int repeats;
	int cpu;
	atomic_int *cursor;
	atomic_int *failures;
};

int lib_sockpool_open(struct lib_sockpool *p, int count)
{
	int type = p->sock_type ? p->sock_type : SOCK_STREAM;

	p->pairs = calloc((size_t)count, sizeof(*p->pairs));
	if (!p->pairs)
		return -1;
	for (int i = 0; i < count; i++) {
		int sv[2];

		if (socketpair(AF_UNIX, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv)) {
			while (i--) {
				close(p->pairs[i].tx);
				close(p->pairs[i].rx);
			}
			free(p->pairs);
			p->pairs = NULL;
			return -1;
		}
		p->pairs[i].tx = sv[0];
		p->pairs[i].rx = sv[1];
	}
	p->count = count;
	return 0;
}

int lib_sockpool_close(struct lib_sockpool *p)
{
	if (!p->pairs)
		return 0;
	for (int i = 0; i < p->count; i++) {
		close(p->pairs[i].tx);
		close(p->pairs[i].rx);
	}
	free(p->pairs);
	p->pairs = NULL;
	p->count = 0;
	return 0;
}

/* Receive exactly `len` bytes, or report failure. A short receive means the
 * pool did not hold what was queued, which is the one thing a drain can learn. */
static int recv_exact(int fd, void *buf, size_t len)
{
	unsigned char *at = buf;
	size_t done = 0;

	while (done < len) {
		ssize_t got = recv(fd, at + done, len - done, MSG_DONTWAIT);

		if (got <= 0)
			return -1;
		done += (size_t)got;
	}
	return 0;
}

static void *worker_main(void *arg)
{
	struct worker *w = arg;

	if (w->cpu >= 0 && lib_pin_cpu(w->cpu) != 0) {
		atomic_fetch_add_explicit(w->failures, 1, memory_order_relaxed);
		return NULL;
	}
	for (;;) {
		int i = atomic_fetch_add_explicit(w->cursor, 1, memory_order_relaxed);

		if (i >= w->pool->count)
			break;
		switch (w->phase) {
		case LIB_SOCKPOOL_WARM: {
			unsigned char b = WARM_BYTE;

			for (int r = 0; r < w->repeats; r++)
				if (send(w->pool->pairs[i].tx, &b, 1,
					 MSG_DONTWAIT | MSG_NOSIGNAL) != 1)
					atomic_fetch_add_explicit(w->failures, 1,
								  memory_order_relaxed);
			break;
		}
		case LIB_SOCKPOOL_PUNCH: {
			unsigned char got[64];
			int n = w->repeats > (int)sizeof(got) ? (int)sizeof(got) : w->repeats;

			if (recv_exact(w->pool->pairs[i].rx, got, (size_t)n)) {
				atomic_fetch_add_explicit(w->failures, 1, memory_order_relaxed);
				break;
			}
			for (int r = 0; r < n; r++)
				if (got[r] != WARM_BYTE)
					atomic_fetch_add_explicit(w->failures, 1,
								  memory_order_relaxed);
			break;
		}
		case LIB_SOCKPOOL_FILL:
			for (int r = 0; r < w->repeats; r++)
				if (send(w->pool->pairs[i].tx, w->payload, w->len,
					 MSG_DONTWAIT | MSG_NOSIGNAL) != (ssize_t)w->len)
					atomic_fetch_add_explicit(w->failures, 1,
								  memory_order_relaxed);
			break;
		}
	}
	return NULL;
}

int lib_sockpool_run(struct lib_sockpool *p, enum lib_sockpool_phase phase,
		     const void *payload, size_t len, int repeats)
{
	struct worker workers[LIB_SOCKPOOL_MAX_WORKERS];
	pthread_t threads[LIB_SOCKPOOL_MAX_WORKERS];
	atomic_int cursor = 0, failures = 0;
	int cpus = lib_cpu_count();
	int want = p->max_workers ? p->max_workers : (cpus > 1 ? cpus - 1 : 1);
	int started = 0;

	if (!p->pairs)
		return -1;
	if (want > LIB_SOCKPOOL_MAX_WORKERS)
		want = LIB_SOCKPOOL_MAX_WORKERS;

	for (int i = 0; i < want; i++) {
		workers[i].pool = p;
		workers[i].phase = phase;
		workers[i].payload = payload;
		workers[i].len = len;
		workers[i].repeats = repeats;
		workers[i].cursor = &cursor;
		workers[i].failures = &failures;
		/* Spread across processors from the caller's first, so the
		 * spray does not share a processor with whatever it races. */
		workers[i].cpu = p->first_cpu < 0 ? -1 :
				 (cpus > 1 ? p->first_cpu + i : p->first_cpu);
		if (pthread_create(&threads[i], NULL, worker_main, &workers[i])) {
			atomic_fetch_add_explicit(&failures, 1, memory_order_relaxed);
			break;
		}
		started++;
	}
	for (int i = 0; i < started; i++)
		pthread_join(threads[i], NULL);
	return atomic_load_explicit(&failures, memory_order_relaxed);
}

int lib_sockpool_drain(struct lib_sockpool *p, int index, void *buf, size_t len)
{
	if (!p->pairs || index < 0 || index >= p->count)
		return -1;
	return recv_exact(p->pairs[index].rx, buf, len);
}
