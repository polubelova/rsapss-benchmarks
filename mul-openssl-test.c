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

void ossl_bn_mul(BIGNUM *a, BIGNUM *b, BIGNUM *c, BN_CTX *ctx){
  BN_mul(c, a, b, ctx);
}

void ossl_bn_sqr(BIGNUM *a, BIGNUM *c, BN_CTX *ctx){
  BN_sqr(c, a, ctx);
}


void hacl_bn_mul(uint32_t len, uint64_t *a, uint64_t *b, uint64_t *res){
  Hacl_Bignum64_mul(len, a, b, res);
}

void hacl_bn_sqr(uint32_t len, uint64_t *a, uint64_t *res){
  Hacl_Bignum64_sqr(len, a, res);
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


void test_mul(int nBits){
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

  /* ossl_bn_mul(a, b, c, ctx); */
  /* hacl_bn_mul(nLen, ah, bh, ch); */
  /* bn_compare_and_print(nBytes + nBytes, c, ch); */

  /* ossl_bn_sqr(a, c, ctx); */
  /* hacl_bn_sqr(nLen, ah, ch); */
  /* bn_compare_and_print(nBytes + nBytes, c, ch); */

  /* ossl_bn_mul(a, a, c, ctx); */
  /* hacl_bn_mul(nLen, ah, ah, ch); */
  /* bn_compare_and_print(nBytes + nBytes, c, ch); */


  for (int j = 0; j < ROUNDS; j++) {
    hacl_bn_mul(nLen, ah, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    hacl_bn_mul(nLen, ah, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = c2 - c1;


  for (int j = 0; j < ROUNDS; j++) {
    ossl_bn_mul(a, b, c, ctx);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    ossl_bn_mul(a, b, c, ctx);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff2 = t2 - t1;
  uint64_t cyc2 = c2 - c1;


  uint64_t count = ROUNDS * SIZE;
  printf ("%d\t || %.2f\t || %.2f\t || %.2f \n", nBits, (double)cyc1/count, (double)cyc2/count, (double)cyc1/cyc2);

}


void test_sqr(int nBits){
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

  /* ossl_bn_sqr(a, c, ctx); */
  /* hacl_bn_sqr(nLen, ah, ch); */
  /* bn_compare_and_print(nBytes + nBytes, c, ch); */


  for (int j = 0; j < ROUNDS; j++) {
    hacl_bn_sqr(nLen, ah, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    hacl_bn_sqr(nLen, ah, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = c2 - c1;


  for (int j = 0; j < ROUNDS; j++) {
    ossl_bn_sqr(a, c, ctx);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    ossl_bn_sqr(a, c, ctx);
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
  test_mul(256);
  test_mul(512);
  test_mul(1024);
  test_mul(1536);
  test_mul(2048);
  test_mul(3072);
  test_mul(4096);
  test_mul(6144);
  test_mul(8192);

  printf("\n-----------------------------------------------------\n");
  printf ("nBits\t || hacl\t || openssl\t || hacl / openssl \n");

  test_sqr(256);
  test_sqr(512);
  test_sqr(1024);
  test_sqr(1536);
  test_sqr(2048);
  test_sqr(3072);
  test_sqr(4096);
  test_sqr(6144);
  test_sqr(8192);

  return EXIT_SUCCESS;
}
