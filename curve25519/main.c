/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef unsigned long long cycles_t;

#define ARRAY_SIZE(a)                               \
  ((sizeof(a) / sizeof(*(a))) /                     \
   (size_t)(!(sizeof(a) % sizeof(*(a)))))

int dummy;

#include "test_vectors.h"

static __inline__ cycles_t get_cycles(void)
{
  uint64_t rax,rdx,aux;
  asm volatile ( "rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (aux) : : );
  return (rdx << 32) + rax;
}

#define declare_it(name) \
void curve25519_ecdh_ ## name(u8 *ss, const u8 *priv, const u8 *pub); \
static inline int name(void) \
{ \
  curve25519_ecdh_ ## name(dummy_out, vectors[0].scalar, vectors[0].public);	\
}


#define do_it(name) do {	     \
	for (i = 0; i < WARMUP; ++i) \
	        ret |= name(); \
	for (j = 0; j <= DOUBLING_STEPS; ++j) { \
	        trial_times[0] = get_cycles(); \
		for (i = 1; i <= TRIALS; ++i) { \
			ret |= name(); \
		        trial_times[i] = get_cycles(); } \
		for (i = 0; i < TRIALS; ++i) \
		        trial_times[i] = trial_times[i+1] - trial_times[i]; \
		qsort(trial_times, TRIALS, sizeof(cycles_t), compare_cycles); \
		median_ ## name[j] = trial_times[TRIALS/2]; \
	} \
} while (0)


#define test_it(name, before, after) do { \
	memset(out, __LINE__, 32); \
	before; \
	curve25519_ecdh_ ## name(out, vectors[i].scalar, vectors[i].public); \
	after; \
	if (memcmp(out, vectors[i].secret, 32)) { \
		fprintf(stderr,#name " self-test %zu: FAIL\n", i + 1); \
		return false; \
	} \
} while (0)


#define report_it(name) do { \
	char dec[20]; \
	size_t l; \
	fprintf(stderr,"%11s",#name); \
	for (j = 0; j <= DOUBLING_STEPS; ++j) { \
	        fprintf(stderr, "\t%6.2f", (double)(median_ ## name[j])); \
	} \
	fprintf(stderr, "\n"); \
} while (0)



enum { WARMUP = 50000, TRIALS = 10000, IDLE = 1 * 1000, DOUBLING_STEPS = 0 };
u8 dummy_out[32];

declare_it(hacl51)
declare_it(hacl64)
declare_it(vale64)
declare_it(libsodium)

static int compare_cycles(const void *a, const void *b)
{
	return *((cycles_t *)a) - *((cycles_t *)b);
}

static bool verify(void)
{
	int ret;
	size_t i = 0;
	u8 out[32];

	test_it(hacl51, {}, {});
	test_it(hacl64, {}, {});
	test_it(vale64, {}, {});
	test_it(libsodium, {}, {});
	return true;
}

int main()
{
	int ret = 0, i, j;
	cycles_t median_hacl51[DOUBLING_STEPS+1];
	cycles_t median_hacl64[DOUBLING_STEPS+1];
	cycles_t median_vale64[DOUBLING_STEPS+1];
	cycles_t median_libsodium[DOUBLING_STEPS+1];

	unsigned long flags;
	cycles_t* trial_times = calloc(TRIALS + 1, sizeof(cycles_t));

	if (!verify())
		return -1;

	do_it(hacl51);
	do_it(hacl64);
	do_it(vale64);
	do_it(libsodium);

	report_it(hacl51);
	report_it(hacl64);
	report_it(vale64);
	report_it(libsodium);

	/* Don't let compiler be too clever. */
	dummy = ret;

	/* We should never actually agree to insert the module. Choosing
	 * -0x1000 here is an amazing hack. It causes the kernel to not
	 * actually load the module, while the standard userspace tools
	 * don't return an error, because it's too big. */
	free(trial_times);
	return -0x1000;
}
