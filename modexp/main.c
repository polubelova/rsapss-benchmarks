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

#include "openssl/bn.h"

extern void Hacl_Bignum64_bn_from_bytes_be(uint32_t len, uint8_t *b, uint64_t *res);
extern void Hacl_Bignum64_bn_to_bytes_be(uint32_t len, uint64_t *b, uint8_t *res);
extern void Hacl_Bignum64_bn_precomp_r2_mod_n(uint32_t len, uint32_t nBits, uint64_t *n, uint64_t *res);

extern BIGNUM *pre_asm_BN_new(void);
extern int pre_asm_BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
extern int pre_asm_BN_rand(BIGNUM *rnd, int bits, int top, int bottom);
extern int pre_asm_BN_rand_range(BIGNUM *rnd, const BIGNUM *range);

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
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
void modexp_ ## name(u32 len,  u8 *cb, const u8 *ab, const u8 *bb, const u8 *nb, const u8 *r2b); \
static inline int name(size_t len) \
{ \
  modexp_ ## name(len, dummy_out, input_ab, input_bb, input_nb, input_r2b);	\
}


#define do_it(name) do {	     \
        for (i = 0; i < WARMUP; ++i)					\
	  ret |= name(s);						\
	trial_times[0] = get_cycles();					\
	for (i = 1; i <= TRIALS; ++i) {					\
	  ret |= name(s);						\
	  trial_times[i] = get_cycles(); }				\
	for (i = 0; i < TRIALS; ++i)					\
	  trial_times[i] = trial_times[i+1] - trial_times[i];		\
	qsort(trial_times, TRIALS, sizeof(cycles_t), compare_cycles);	\
	median_ ## name[j] = trial_times[TRIALS/2];			\
} while (0)


#define test_it(name, before, after) do { \
	memset(out, __LINE__, vectors[i].len); \
	before; \
	modexp_ ## name(vectors[i].len, out, vectors[i].ab, vectors[i].bb, vectors[i].nb, NULL); \
	after; \
	if (memcmp(out, vectors[i].resb, vectors[i].len)) { \
		fprintf(stderr,#name " self-test %zu: FAIL\n", i + 1); \
		return false; \
	} \
} while (0)


#define report_it(name) do { \
	fprintf(stderr,"%11s",#name); \
	for (j = 0; j <= DOUBLING_STEPS; ++j) { \
	        fprintf(stderr, "\t%6.2f", (double)(median_ ## name[j])); \
	} \
	fprintf(stderr, "\n"); \
} while (0)


#define update_values() do { \
	pre_asm_BN_rand(input_n, 8 * s, 1, 1); \
	pre_asm_BN_rand_range(input_a, input_n); \
	pre_asm_BN_rand(input_b, 8 * s, 1, 0); \
	pre_asm_BN_bn2binpad(input_a, input_ab, s); \
	pre_asm_BN_bn2binpad(input_b, input_bb, s); \
	pre_asm_BN_bn2binpad(input_n, input_nb, s); \
	Hacl_Bignum64_bn_from_bytes_be(s, input_nb, input_nh); \
	Hacl_Bignum64_bn_precomp_r2_mod_n(s / 8, 8 * s - 1, input_nh, input_r2h); \
	Hacl_Bignum64_bn_to_bytes_be(s, input_r2h, input_r2b); \
} while (0)


enum { WARMUP = 500, TRIALS = 1000, IDLE = 1 * 1000, DOUBLING_STEPS = 5 };
u8 dummy_out[2048];
u8 input_ab[2048];
u8 input_bb[2048];
u8 input_nb[2048];
u8 input_r2b[2048];

BIGNUM *input_a = NULL, *input_b = NULL, *input_n = NULL;
u64 input_nh[256];
u64 input_r2h[256];

declare_it(openssl)
declare_it(openssl_no_mulx)
declare_it(openssl_c)
declare_it(gmp)
declare_it(gmp_c)
declare_it(hacl_fw)
declare_it(hacl_bm)

static int compare_cycles(const void *a, const void *b)
{
	return *((cycles_t *)a) - *((cycles_t *)b);
}

static bool verify(void)
{
	size_t i = 0;
	u8 out[512];

	test_it(openssl, {}, {});
	test_it(openssl_no_mulx, {}, {});
	test_it(openssl_c, {}, {});
	test_it(gmp, {}, {});
	test_it(gmp_c, {}, {});
	test_it(hacl_fw, {}, {});
	test_it(hacl_bm, {}, {});

	return true;
}

int main()
{
	size_t s;
	int ret = 0, i, j;
	int s_value[DOUBLING_STEPS+1];
	cycles_t median_openssl[DOUBLING_STEPS+1];
	cycles_t median_openssl_no_mulx[DOUBLING_STEPS+1];
	cycles_t median_openssl_c[DOUBLING_STEPS+1];
	cycles_t median_gmp[DOUBLING_STEPS+1];
	cycles_t median_gmp_c[DOUBLING_STEPS+1];
	cycles_t median_hacl_fw[DOUBLING_STEPS+1];
	cycles_t median_hacl_bm[DOUBLING_STEPS+1];

	unsigned long flags;
	cycles_t* trial_times = calloc(TRIALS + 1, sizeof(cycles_t));

	if (!verify())
	  return -1;

	input_a = pre_asm_BN_new();
	input_b = pre_asm_BN_new();
	input_n = pre_asm_BN_new();
	//////////////////////////////////
	j = 0;
	s = 32; // modular size in bytes
	s_value[j] = s;
	update_values();

	do_it(openssl);
	do_it(openssl_no_mulx);
	do_it(openssl_c);
	do_it(gmp);
	do_it(gmp_c);
	do_it(hacl_fw);
	do_it(hacl_bm);

	fprintf(stderr,"\n j = 0\n");
	//////////////////////////////////

	j = 1;
	s = 64; // modular size in bytes
	s_value[j] = s;
	update_values();

	do_it(openssl);
	do_it(openssl_no_mulx);
	do_it(openssl_c);
	do_it(gmp);
	do_it(gmp_c);
	do_it(hacl_fw);
	do_it(hacl_bm);

	fprintf(stderr,"\n j = 1\n");
	//////////////////////////////////

	j = 2;
	s = 128; // modular size in bytes
	s_value[j] = s;
	update_values();

	do_it(openssl);
	do_it(openssl_no_mulx);
	do_it(openssl_c);
	do_it(gmp);
	do_it(gmp_c);
	do_it(hacl_fw);
	do_it(hacl_bm);

	fprintf(stderr,"\n j = 2\n");
	//////////////////////////////////

	j = 3;
	s = 256; // modular size in bytes
	s_value[j] = s;
	update_values();

	do_it(openssl);
	do_it(openssl_no_mulx);
	do_it(openssl_c);
	do_it(gmp);
	do_it(gmp_c);
	do_it(hacl_fw);
	do_it(hacl_bm);

	fprintf(stderr,"\n j = 3\n");
	//////////////////////////////////

	j = 4;
	s = 384; // modular size in bytes
	s_value[j] = s;
	update_values();

	do_it(openssl);
	do_it(openssl_no_mulx);
	do_it(openssl_c);
	do_it(gmp);
	do_it(gmp_c);
	do_it(hacl_fw);
	do_it(hacl_bm);

	fprintf(stderr,"\n j = 4\n");
	//////////////////////////////////

	j = 5;
	s = 512; // modular size in bytes
	s_value[j] = s;
	update_values();

	do_it(openssl);
	do_it(openssl_no_mulx);
	do_it(openssl_c);
	do_it(gmp);
	do_it(gmp_c);
	do_it(hacl_fw);
	do_it(hacl_bm);

	fprintf(stderr,"\n j = 5\n");
	//////////////////////////////////

	/* j = 6; */
	/* s = 768; // modular size in bytes */
	/* s_value[j] = s; */
	/* update_values(); */
	/* do_all(); */
	/* fprintf(stderr,"\n j = 6\n"); */
	/* ////////////////////////////////// */

	/* j = 7; */
	/* s = 1024; // modular size in bytes */
	/* s_value[j] = s; */
	/* update_values(); */
	/* do_all(); */
	/* fprintf(stderr,"\n j = 7\n"); */
	/* ////////////////////////////////// */

	/* j = 8; */
	/* s = 2048; // modular size in bytes */
	/* s_value[j] = s; */
	/* update_values(); */
	/* do_all(); */
	/* fprintf(stderr,"\n j = 8\n"); */
	/* ////////////////////////////////// */

	fprintf(stderr,"%11s","");
	for (j = 0; j <= DOUBLING_STEPS; ++j) \
		fprintf(stderr, " \x1b[4m%6u\x1b[24m", s_value[j] * 8);
	fprintf(stderr,"\n");

	report_it(openssl);
	report_it(openssl_no_mulx);
	report_it(openssl_c);
	report_it(gmp);
	report_it(gmp_c);
	report_it(hacl_fw);
	report_it(hacl_bm);

	/* Don't let compiler be too clever. */
	dummy = ret;

	/* We should never actually agree to insert the module. Choosing
	 * -0x1000 here is an amazing hack. It causes the kernel to not
	 * actually load the module, while the standard userspace tools
	 * don't return an error, because it's too big. */
	free(trial_times);
	return -0x1000;
}
