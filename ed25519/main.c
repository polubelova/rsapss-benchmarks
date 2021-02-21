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

//pub, s, prefix
extern void Hacl_Ed25519_expand_keys(uint8_t *ks, uint8_t *priv);
//extern void Hacl_Ed25519_secret_to_public(uint8_t *pub, uint8_t *priv);

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

enum {KEY_LEN = 32, SGNT_LEN = 64};

#define declare_it(name) \
void ed25519_sign_ ## name(u32 len,  u8 *out, const u8 *text, const u8 *keys_expanded, const u8 *skey); \
static inline int name(size_t len) \
{ \
  ed25519_sign_ ## name(len, dummy_out, input_data, input_keys, input_skey);	\
}


#define do_it(name) do {	     \
	for (i = 0; i < WARMUP; ++i) \
	        ret |= name(sizeof(input_data)); \
	for (j = 0, s = STARTING_SIZE; j <= DOUBLING_STEPS; ++j, s *= 2) { \
	        trial_times[0] = get_cycles(); \
		for (i = 1; i <= TRIALS; ++i) { \
			ret |= name(s); \
		        trial_times[i] = get_cycles(); } \
		for (i = 0; i < TRIALS; ++i) \
		        trial_times[i] = trial_times[i+1] - trial_times[i]; \
		qsort(trial_times, TRIALS, sizeof(cycles_t), compare_cycles); \
		median_ ## name[j] = trial_times[TRIALS/2]; \
	} \
} while (0)


#define test_it(name, before, after) do { \
	memset(out, __LINE__, vectors[i].input_len); \
	before; \
	Hacl_Ed25519_expand_keys(input_keys, vectors[i].skey); \
	ed25519_sign_ ## name(vectors[i].input_len, out, vectors[i].input, input_keys, vectors[i].skey); \
	after; \
	if (memcmp(out, vectors[i].signature, SGNT_LEN)) { \
		fprintf(stderr,#name " self-test %zu: FAIL\n", i + 1); \
		return false; \
	} \
} while (0)


#define report_it(name) do { \
	char dec[20]; \
	size_t l; \
	fprintf(stderr,"%11s",#name); \
	for (j = 0, s = STARTING_SIZE; j <= DOUBLING_STEPS; ++j, s *= 2) { \
	        fprintf(stderr, "\t%6.2f", (double)(median_ ## name[j])); \
	} \
	fprintf(stderr, "\n"); \
} while (0)



enum { WARMUP = 50000, TRIALS = 10000, IDLE = 1 * 1000, STARTING_SIZE = 64, DOUBLING_STEPS = 5 };
u8 dummy_out[SGNT_LEN];
u8 input_skey[KEY_LEN];
u8 input_data[STARTING_SIZE * (1ULL << DOUBLING_STEPS)];
u8 input_keys[3 * KEY_LEN];

declare_it(hacl)
declare_it(libsodium)

static int compare_cycles(const void *a, const void *b)
{
	return *((cycles_t *)a) - *((cycles_t *)b);
}

static bool verify(void)
{
	int ret;
	size_t i = 0;
	u8 out[64];

	test_it(hacl, {}, {});
	test_it(libsodium, {}, {});
	return true;
}

int main()
{
	size_t s;
	int ret = 0, i, j;
	cycles_t median_hacl[DOUBLING_STEPS+1];
	cycles_t median_libsodium[DOUBLING_STEPS+1];

	unsigned long flags;
	cycles_t* trial_times = calloc(TRIALS + 1, sizeof(cycles_t));

	if (!verify())
		return -1;

	for (i = 0; i < sizeof(input_data); ++i)
		input_data[i] = i;
	for (i = 0; i < KEY_LEN; ++i)
		input_skey[i] = i;

	Hacl_Ed25519_expand_keys(input_keys, input_skey);
	do_it(hacl);
	do_it(libsodium);

	fprintf(stderr,"%11s","");
	for (j = 0, s = STARTING_SIZE; j <= DOUBLING_STEPS; ++j, s *= 2) \
		fprintf(stderr, " \x1b[4m%6zu\x1b[24m", s);
	fprintf(stderr,"\n");

	report_it(hacl);
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
