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

#include "Hacl_BenchKaratsuba.h"
#include "Hacl_Bignum64.h"
#include "test_helpers.h"

#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/rsa.h"
#include "openssl/bn.h"

#define ROUNDS 100000
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


void test_mul(int nBits, int threshold){
  cycles c1,c2;
  clock_t t1,t2;

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *a = NULL, *b = NULL, *c = NULL;
  a = BN_new();
  b = BN_new();
  c = BN_new();

  int nBytes = (nBits - 1) / 8 + 1;
  int nLen = (nBits - 1) / 64 + 1;

  BN_rand(a, nBits, 1, 0);
  BN_rand(b, nBits, 1, 0);

  uint64_t *ah = bn_ossl_to_hacl(nBytes, a);
  uint64_t *bh = bn_ossl_to_hacl(nBytes, b);
  uint64_t ch[nLen + nLen];

  uint64_t tmp[(uint32_t)4U * nLen];
  memset(tmp, 0U, (uint32_t)4U * nLen * sizeof (uint64_t));


  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchKaratsuba_bn_karatsuba_mul_uint64(threshold, nLen, ah, bh, tmp, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchKaratsuba_bn_karatsuba_mul_uint64(threshold, nLen, ah, bh, tmp, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = c2 - c1;

  uint64_t count = ROUNDS * SIZE;
  printf ("%d\t ||%d\t || %.2f\t \n", nBits, threshold, (double)cyc1/count);
}


void test_sqr(int nBits, int threshold){
  cycles c1,c2;
  clock_t t1,t2;

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *a = NULL, *c = NULL;
  a = BN_new();
  c = BN_new();

  int nBytes = (nBits - 1) / 8 + 1;
  int nLen = (nBits - 1) / 64 + 1;

  BN_rand(a, nBits, 1, 0);

  uint64_t *ah = bn_ossl_to_hacl(nBytes, a);
  uint64_t ch[nLen + nLen];

  uint64_t tmp[(uint32_t)4U * nLen];
  memset(tmp, 0U, (uint32_t)4U * nLen * sizeof (uint64_t));


  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchKaratsuba_bn_karatsuba_sqr_uint64(threshold, nLen, ah, tmp, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_BenchKaratsuba_bn_karatsuba_sqr_uint64(threshold, nLen, ah, tmp, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = c2 - c1;

  uint64_t count = ROUNDS * SIZE;
  printf ("%d\t ||%d\t || %.2f\t \n", nBits, threshold, (double)cyc1/count);
}


int main() {

  printf ("\n nBits\t || l\t || hacl-mul \n");
  for (int i = 32; i <= 8192; i = i * 2) {
    for (int th = 2; th <= 36; th = th + 2) {
      test_mul(i, th);
    }
  printf("\n-----------------------------------------------------\n");
  }

  printf("\n-----------------------------------------------------\n");
  printf ("\n nBits\t || l\t || hacl-sqr \n");

  for (int i = 32; i <= 8192; i = i * 2) {
    for (int th = 2; th <= 36; th = th + 2) {
      test_sqr(i, th);
    }
  printf("\n-----------------------------------------------------\n");
  }

  return EXIT_SUCCESS;
}
