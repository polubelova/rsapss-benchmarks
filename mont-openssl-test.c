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

void ossl_bn_mont_mul(BIGNUM *a, BIGNUM *b, BIGNUM *c, BN_MONT_CTX *mont, BN_CTX *ctx){
  BN_mod_mul_montgomery(c, a, b, mont, ctx);
}

void ossl_bn_mont_sqr(BIGNUM *a, BIGNUM *c, BN_MONT_CTX *mont, BN_CTX *ctx){
  BN_mod_mul_montgomery(c, a, a, mont, ctx);
}

void hacl_bn_mont_mul(uint32_t len, uint64_t *n, uint64_t mu, uint64_t *a, uint64_t *b, uint64_t *res){
  Hacl_Bignum64_bn_mont_mul(len, n, mu, a, b, res);
}

void hacl_bn_mont_sqr(uint32_t len, uint64_t *n, uint64_t mu, uint64_t *a, uint64_t *res){
  Hacl_Bignum64_bn_mont_sqr(len, n, mu, a, res);
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


void test_mont_mul(int nBits){
  cycles c1,c2;
  clock_t t1,t2;

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *a = NULL, *b = NULL, *n = NULL, *c = NULL;
  a = BN_new();
  b = BN_new();
  n = BN_new();
  c = BN_new();

  int nBytes = (nBits - 1) / 8 + 1;
  int nLen = (nBits - 1) / 64 + 1;

  BN_rand(n, nBits, 1, 1);
  BN_rand_range(a, n);
  BN_rand_range(b, n);

  uint64_t *ah = bn_ossl_to_hacl(nBytes, a);
  uint64_t *bh = bn_ossl_to_hacl(nBytes, b);
  uint64_t *nh = bn_ossl_to_hacl(nBytes, n);
  uint64_t ch[nLen];
  uint64_t mu = Hacl_Bignum64_mod_inv_limb(nh[0]);

  BN_MONT_CTX *mont = NULL;
  mont = BN_MONT_CTX_new();
  BN_MONT_CTX_set(mont, n, ctx);

  /* ossl_bn_mont_mul(a, b, c, mont, ctx); */
  /* hacl_bn_mont_mul(nLen, nh, mu, ah, bh, ch); */
  /* bn_compare_and_print(nBytes, c, ch); */

  /* ossl_bn_mont_sqr(a, c, mont, ctx); */
  /* hacl_bn_mont_sqr(nLen, nh, mu, ah, ch); */
  /* bn_compare_and_print(nBytes, c, ch); */


  for (int j = 0; j < ROUNDS; j++) {
    hacl_bn_mont_mul(nLen, nh, mu, ah, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    hacl_bn_mont_mul(nLen, nh, mu, ah, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = c2 - c1;


  for (int j = 0; j < ROUNDS; j++) {
    ossl_bn_mont_mul(a, b, c, mont, ctx);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    ossl_bn_mont_mul(a, b, c, mont, ctx);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff2 = t2 - t1;
  uint64_t cyc2 = c2 - c1;


  uint64_t count = ROUNDS * SIZE;
  printf ("%d\t || %.2f\t || %.2f\t || %.2f \n", nBits, (double)cyc1/count, (double)cyc2/count, (double)cyc1/cyc2);

}


void test_mont_sqr(int nBits){
  cycles c1,c2;
  clock_t t1,t2;

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *a = NULL, *n = NULL, *c = NULL;
  a = BN_new();
  n = BN_new();
  c = BN_new();

  int nBytes = (nBits - 1) / 8 + 1;
  int nLen = (nBits - 1) / 64 + 1;

  BN_rand(n, nBits, 1, 1);
  BN_rand_range(a, n);

  uint64_t *ah = bn_ossl_to_hacl(nBytes, a);
  uint64_t *nh = bn_ossl_to_hacl(nBytes, n);
  uint64_t ch[nLen];
  uint64_t mu = Hacl_Bignum64_mod_inv_limb(nh[0]);

  BN_MONT_CTX *mont = NULL;
  mont = BN_MONT_CTX_new();
  BN_MONT_CTX_set(mont, n, ctx);

  for (int j = 0; j < ROUNDS; j++) {
    hacl_bn_mont_sqr(nLen, nh, mu, ah, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    hacl_bn_mont_sqr(nLen, nh, mu, ah, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = c2 - c1;


  for (int j = 0; j < ROUNDS; j++) {
    ossl_bn_mont_sqr(a, c, mont, ctx);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    ossl_bn_mont_sqr(a, c, mont, ctx);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff2 = t2 - t1;
  uint64_t cyc2 = c2 - c1;


  uint64_t count = ROUNDS * SIZE;
  printf ("%d\t || %.2f\t || %.2f\t || %.2f \n", nBits, (double)cyc1/count, (double)cyc2/count, (double)cyc1/cyc2);

}


int main() {
  printf ("nBits\t || hacl\t || openssl\t || hacl / openssl \n");

  //for (int i = 256; i <= 8192; i = i * 2)
  //test(i);
  test_mont_mul(256);
  test_mont_mul(512);
  test_mont_mul(1024);
  test_mont_mul(1536);
  test_mont_mul(2048);
  test_mont_mul(3072);
  test_mont_mul(4096);
  test_mont_mul(6144);
  test_mont_mul(8192);

  printf("\n-----------------------------------------------------\n");
  printf ("nBits\t || hacl\t || openssl\t || hacl / openssl \n");

  test_mont_sqr(256);
  test_mont_sqr(512);
  test_mont_sqr(1024);
  test_mont_sqr(1536);
  test_mont_sqr(2048);
  test_mont_sqr(3072);
  test_mont_sqr(4096);
  test_mont_sqr(6144);
  test_mont_sqr(8192);

  return EXIT_SUCCESS;
}
