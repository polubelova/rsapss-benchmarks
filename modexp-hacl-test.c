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

#include "Hacl_Bignum64.h"
#include "Hacl_BenchBignum.h"
#include "test_helpers.h"

#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/rsa.h"
#include "openssl/bn.h"

#define ROUNDS 1000
#define SIZE   1


void print_bytes(uint32_t len, uint8_t *in){
  for (int i = 0; i < len; i++)
    printf("%02x, ", in[i]);
  printf("\n");
}

void ossl_print(const BIGNUM* n)
{
  int num = (BN_num_bits(n)+7)/8;
  uint8_t to[num];
  BN_bn2binpad(n, to, num);
  print_bytes(num, to);
}

void hacl_print(uint32_t len, uint64_t *b)
{
  uint8_t to[len];
  Hacl_Bignum64_bn_to_bytes_be(len, b, to);
  print_bytes(len, to);
}


uint64_t *bn_ossl_to_hacl(uint32_t nBytes, BIGNUM *a){
  uint8_t ab[nBytes];
  BN_bn2binpad(a, ab, nBytes);
  return Hacl_Bignum64_new_bn_from_bytes_be(nBytes, ab);
}

void bn_compare_and_print(uint32_t nBytes, BIGNUM *a, uint64_t *b){
  uint8_t ab[nBytes];
  BN_bn2binpad(a, ab, nBytes);

  uint8_t bb[nBytes];
  Hacl_Bignum64_bn_to_bytes_be(nBytes, b, bb);
  compare_and_print(nBytes, ab, bb);
}


void test_ct(int nBits){
  cycles c1,c2;
  clock_t t1,t2;

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *a = NULL, *b = NULL, *n = NULL;
  a = BN_new();
  b = BN_new();
  n = BN_new();

  int nBytes = (nBits - 1) / 8 + 1;
  int nLen = (nBits - 1) / 64 + 1;

  BN_rand(n, nBits, 1, 1);
  BN_rand_range(a, n);
  BN_rand(b, nBits, 1, 0);

  uint64_t *ah = bn_ossl_to_hacl(nBytes, a);
  uint64_t *bh = bn_ossl_to_hacl(nBytes, b);
  uint64_t *nh = bn_ossl_to_hacl(nBytes, n);
  uint64_t ch[nLen];
  Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64* k = Hacl_Bignum64_mont_ctx_init(nLen, nh);

  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_bm_consttime_mm_precomp(k, ah, nBits, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_bm_consttime_mm_precomp(k, ah, nBits, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = c2 - c1;


  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_bm_consttime_amm_precomp(k, ah, nBits, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_bm_consttime_amm_precomp(k, ah, nBits, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff2 = t2 - t1;
  uint64_t cyc2 = c2 - c1;



  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_consttime_mm_precomp(4, k, ah, nBits, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_consttime_mm_precomp(4, k, ah, nBits, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff3 = t2 - t1;
  uint64_t cyc3 = c2 - c1;


  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_consttime_amm_precomp(4, k, ah, nBits, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_consttime_amm_precomp(4, k, ah, nBits, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff4 = t2 - t1;
  uint64_t cyc4 = c2 - c1;


  uint64_t count = ROUNDS * SIZE;
  printf ("%d\t || %.2f\t || %.2f\t || %.2f\t || %.2f\t || %.2f || %.2f || %.2f || %.2f \n",
	  nBits, (double)cyc1/count, (double)cyc2/count, (double)cyc3/count, (double)cyc4/count,
	  (double)cyc1/cyc3, (double)cyc2/cyc4, (double)cyc1/cyc2, (double)cyc3/cyc4);
}


void test_vt(int nBits){
  cycles c1,c2;
  clock_t t1,t2;

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *a = NULL, *b = NULL, *n = NULL;
  a = BN_new();
  b = BN_new();
  n = BN_new();

  int nBytes = (nBits - 1) / 8 + 1;
  int nLen = (nBits - 1) / 64 + 1;

  BN_rand(n, nBits, 1, 1);
  BN_rand_range(a, n);
  BN_rand(b, nBits, 1, 0);

  uint64_t *ah = bn_ossl_to_hacl(nBytes, a);
  uint64_t *bh = bn_ossl_to_hacl(nBytes, b);
  uint64_t *nh = bn_ossl_to_hacl(nBytes, n);
  uint64_t ch[nLen];
  Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64* k = Hacl_Bignum64_mont_ctx_init(nLen, nh);

  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_bm_vartime_mm_precomp(k, ah, nBits, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_bm_vartime_mm_precomp(k, ah, nBits, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = c2 - c1;


  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_bm_vartime_amm_precomp(k, ah, nBits, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_bm_vartime_amm_precomp(k, ah, nBits, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff2 = t2 - t1;
  uint64_t cyc2 = c2 - c1;



  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_vartime_mm_precomp(4, k, ah, nBits, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_vartime_mm_precomp(4, k, ah, nBits, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff3 = t2 - t1;
  uint64_t cyc3 = c2 - c1;


  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_vartime_amm_precomp(4, k, ah, nBits, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_vartime_amm_precomp(4, k, ah, nBits, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff4 = t2 - t1;
  uint64_t cyc4 = c2 - c1;


  uint64_t count = ROUNDS * SIZE;
  printf ("%d\t || %.2f\t || %.2f\t || %.2f\t || %.2f\t || %.2f || %.2f || %.2f || %.2f \n",
	  nBits, (double)cyc1/count, (double)cyc2/count, (double)cyc3/count, (double)cyc4/count,
	  (double)cyc1/cyc3, (double)cyc2/cyc4, (double)cyc1/cyc2, (double)cyc3/cyc4);
}


void test_ct_l(int nBits, int l){
  cycles c1,c2;
  clock_t t1,t2;

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *a = NULL, *b = NULL, *n = NULL;
  a = BN_new();
  b = BN_new();
  n = BN_new();

  int nBytes = (nBits - 1) / 8 + 1;
  int nLen = (nBits - 1) / 64 + 1;

  BN_rand(n, nBits, 1, 1);
  BN_rand_range(a, n);
  BN_rand(b, nBits, 1, 0);

  uint64_t *ah = bn_ossl_to_hacl(nBytes, a);
  uint64_t *bh = bn_ossl_to_hacl(nBytes, b);
  uint64_t *nh = bn_ossl_to_hacl(nBytes, n);
  uint64_t ch[nLen];
  Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64* k = Hacl_Bignum64_mont_ctx_init(nLen, nh);


  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_consttime_mm_precomp(l, k, ah, nBits, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_consttime_mm_precomp(l, k, ah, nBits, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = c2 - c1;


  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_consttime_amm_precomp(l, k, ah, nBits, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_consttime_amm_precomp(l, k, ah, nBits, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff2 = t2 - t1;
  uint64_t cyc2 = c2 - c1;


  uint64_t count = ROUNDS * SIZE;
  printf ("%d\t || %d\t || %.2f\t || %.2f\t || %.2f\t \n",
	  nBits, l, (double)cyc1/count, (double)cyc2/count, (double)cyc1/cyc2);
}


void test_vt_l(int nBits, int l){
  cycles c1,c2;
  clock_t t1,t2;

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *a = NULL, *b = NULL, *n = NULL;
  a = BN_new();
  b = BN_new();
  n = BN_new();

  int nBytes = (nBits - 1) / 8 + 1;
  int nLen = (nBits - 1) / 64 + 1;

  BN_rand(n, nBits, 1, 1);
  BN_rand_range(a, n);
  BN_rand(b, nBits, 1, 0);

  uint64_t *ah = bn_ossl_to_hacl(nBytes, a);
  uint64_t *bh = bn_ossl_to_hacl(nBytes, b);
  uint64_t *nh = bn_ossl_to_hacl(nBytes, n);
  uint64_t ch[nLen];
  Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64* k = Hacl_Bignum64_mont_ctx_init(nLen, nh);


  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_vartime_mm_precomp(l, k, ah, nBits, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_vartime_mm_precomp(l, k, ah, nBits, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = c2 - c1;


  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_vartime_amm_precomp(l, k, ah, nBits, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchBignum_mod_exp_fw_vartime_amm_precomp(l, k, ah, nBits, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff2 = t2 - t1;
  uint64_t cyc2 = c2 - c1;


  uint64_t count = ROUNDS * SIZE;
  printf ("%d\t || %d\t || %.2f\t || %.2f\t || %.2f\t \n",
	  nBits, l, (double)cyc1/count, (double)cyc2/count, (double)cyc1/cyc2);
}


int main() {
  printf ("\nnBits\t || ct-bm-mm\t || ct-bm-amm\t || ct-fw-mm\t || ct-fw-amm\t || bm-mm/fw-mm || bm-amm/fw-amm || bm-mm/bm-amm || fw-mm/fw-amm\n");
  for (int i = 16; i <= 4096; i = i * 2)
    test_ct(i);


  printf ("\nnBits\t || vt-bm-mm\t || vt-bm-amm\t || vt-fw-mm\t || vt-fw-amm\t || bm-mm/fw-mm || bm-amm/fw-amm || bm-mm/bm-amm || fw-mm/fw-amm\n");
  for (int i = 16; i <= 4096; i = i * 2)
    test_vt(i);


  printf ("\nnBits\t || l\t || ct-fw-mm\t || ct-fw-amm\t || fw-mm/fw-amm\n");
  for (int i = 64; i <= 4096; i = i * 2) {
    for (int l = 3; l < 8; l++) {
      test_ct_l(i, l);
    }
  }


  printf ("\nnBits\t || l\t || vt-fw-mm\t || vt-fw-amm\t || fw-mm/fw-amm\n");
  for (int i = 64; i <= 4096; i = i * 2) {
    for (int l = 3; l < 8; l++) {
      test_vt_l(i, l);
    }
  }

  return EXIT_SUCCESS;
}
