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

void ossl_bn_mod_exp_ct(BIGNUM *a, BIGNUM *b, BIGNUM *n, BIGNUM *c, BN_CTX *ctx, BN_MONT_CTX *in_mont){
  // c == a ^^ b % n
  BN_mod_exp_mont_consttime(c, a, b, n, ctx, in_mont);
  /* ossl_print(a); */
  /* ossl_print(b); */
  /* ossl_print(c); */
  /* ossl_print(n); */
}

void hacl_bn_mod_exp_ct(Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64 *k, uint64_t *a, uint32_t bBits, uint64_t *b, uint64_t *res){
  Hacl_Bignum64_mod_exp_consttime_precomp(k, a, bBits, b, res);
  /* hacl_print(8*len, a); */
  /* hacl_print(8*len, b); */
  /* hacl_print(8*len, res); */
  /* hacl_print(8*len, n); */
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


void test(int nBits){
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
  BN_rand(b, nBits, 1, 0);

  uint64_t *ah = bn_ossl_to_hacl(nBytes, a);
  uint64_t *bh = bn_ossl_to_hacl(nBytes, b);
  uint64_t *nh = bn_ossl_to_hacl(nBytes, n);
  uint64_t ch[nLen];
  Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64* k = Hacl_Bignum64_mont_ctx_init(nLen, nh);

  BN_MONT_CTX *mont = NULL;
  mont = BN_MONT_CTX_new();
  BN_MONT_CTX_set(mont, n, ctx);

  /* ossl_bn_mod_exp_ct(a, b, n, c, ctx, mont); */
  /* hacl_bn_mod_exp_ct(k, ah, nBits, bh, ch); */
  /* bn_compare_and_print(nBytes, c, ch); */


  for (int j = 0; j < ROUNDS; j++) {
    hacl_bn_mod_exp_ct(k, ah, nBits, bh, ch);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    hacl_bn_mod_exp_ct(k, ah, nBits, bh, ch);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = c2 - c1;


  for (int j = 0; j < ROUNDS; j++) {
    ossl_bn_mod_exp_ct(a, b, n, c, ctx, mont);
  }

  t1 = clock();
  c1 = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    ossl_bn_mod_exp_ct(a, b, n, c, ctx, mont);
  }
  c2 = cpucycles_end();
  t2 = clock();
  double diff2 = t2 - t1;
  uint64_t cyc2 = c2 - c1;


  uint64_t count = ROUNDS * SIZE;
  //printf("\nBits = %d", nBits);
  //printf("\nHACL* BN_mod_exp_mont_consttime\n"); print_time(count,diff1,cyc1);
  //printf("\nOpenSSL BN_mod_exp_mont_consttime\n"); print_time(count,diff2,cyc2);
  //printf("\nratio signature hacl/openssl %8.2f\n", (double)cyc1/cyc2);
  // (double)cdiff/count
  printf ("%d\t || %.2f\t || %.2f\t || %.2f \n", nBits, (double)cyc1/count, (double)cyc2/count, (double)cyc1/cyc2);

}


int main() {
  printf ("nBits\t || hacl\t || openssl\t || hacl / openssl \n");

  //for (int i = 256; i <= 8192; i = i * 2)
  //test(i);
  test(256);
  test(512);
  test(1024);
  test(1536);
  test(2048);
  test(3072);
  test(4096);
  test(6144);
  test(8192);

  return EXIT_SUCCESS;
}
