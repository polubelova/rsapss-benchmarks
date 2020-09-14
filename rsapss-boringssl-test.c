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

#include "Hacl_RSAPSS.h"

#include "test_helpers.h"
#include "rsapss_vectors.h"

#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"
#include "openssl/digest.h"
#include "openssl/bn.h"

#define ROUNDS 1000
#define SIZE   1


RSA*
createPrivateKey(
  uint8_t* kN,
  uint32_t kN_len,
  uint8_t* kE,
  uint32_t kE_len,
  uint8_t* kD,
  uint32_t kD_len
)
{
  RSA* pRsaKey = RSA_new();
  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *d = BN_new();

  BN_bin2bn(kN, kN_len, n);
  BN_bin2bn(kE, kE_len, e);
  BN_bin2bn(kD, kD_len, d);

  RSA_set0_key(pRsaKey, n, e, d);

  return pRsaKey;
}

RSA*
createPublicKey(
  uint8_t* kN,
  uint32_t kN_len,
  uint8_t* kE,
  uint32_t kE_len
)
{
  RSA* pRsaKey = RSA_new();
  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();

  BN_bin2bn(kN, kN_len, n);
  BN_bin2bn(kE, kE_len, e);

  RSA_set0_key(pRsaKey, n, e, NULL);

  return pRsaKey;
}


int
boringssl_sign(
  RSA* pRsaKey,
  size_t salt_len,
  uint8_t* msg,
  uint32_t msg_len,
  uint8_t* sig,
  size_t sig_len
)
{
  EVP_PKEY *pkey = NULL;
  pkey = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(pkey, pRsaKey);

  EVP_PKEY_CTX *pkey_ctx;
  pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);

  EVP_MD_CTX md_ctx;
  EVP_MD_CTX_init(&md_ctx);

  EVP_DigestSignInit(&md_ctx, &pkey_ctx, EVP_sha256(), NULL, pkey);
  EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
  EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256());
  EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, salt_len);
  int ret = EVP_DigestSign(&md_ctx, sig, &sig_len, msg, msg_len);
  return ret;
}


int
boringssl_verify(
  RSA* pRsaKey,
  uint8_t* msg,
  uint32_t msg_len,
  uint8_t* sig,
  size_t sig_len
)
{
  EVP_PKEY *pkey = NULL;
  pkey = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(pkey, pRsaKey);

  EVP_PKEY_CTX *pkey_ctx;
  pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);

  EVP_MD_CTX md_ctx;
  EVP_MD_CTX_init(&md_ctx);

  EVP_DigestVerifyInit(&md_ctx, &pkey_ctx, EVP_sha256(), NULL, pkey);
  EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
  EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256());
  EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, 20);
  int ret = EVP_DigestVerify(&md_ctx, sig, sig_len, msg, msg_len);
  return ret;
}

bool print_result(uint32_t len, uint8_t* comp, uint8_t* exp) {
  return compare_and_print(len, comp, exp);
}

bool print_test(
  uint32_t modBits,
  uint8_t *nb,
  uint32_t eBits,
  uint8_t *eb,
  uint32_t dBits,
  uint8_t *db,
  uint32_t msgLen,
  uint8_t *msg,
  uint32_t saltLen,
  uint8_t *salt,
  uint8_t *sgnt_expected
){
  uint32_t nbLen = (modBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;
  uint8_t sgnt[nbLen];
  memset(sgnt, 0U, nbLen * sizeof (sgnt[0U]));

  uint64_t *skey = Hacl_RSAPSS_new_rsapss_load_skey(modBits, eBits, dBits, nb, eb, db);
  Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256, modBits, eBits, dBits, skey, saltLen, salt, msgLen, msg, sgnt);
  printf("RSAPSS sign Result:\n");
  bool ok = print_result(nbLen, sgnt, sgnt_expected);

  printf("RSAPSS verify Result:\n");
  uint64_t *pkey = Hacl_RSAPSS_new_rsapss_load_pkey(modBits, eBits, nb, eb);
  bool ver = Hacl_RSAPSS_rsapss_verify(Spec_Hash_Definitions_SHA2_256, modBits, eBits, pkey, saltLen, nbLen, sgnt, msgLen, msg);
  if (ver) printf("Success!\n");
  ok = ok && ver;

  printf("Boringssl verify Result\n");
  RSA* privkey = createPrivateKey(nb, nbLen, eb, (eBits - 1) / 8 + 1, db, (dBits - 1) / 8 + 1);
  RSA* pubkey = createPublicKey(nb, nbLen, eb, (eBits - 1) / 8 + 1);
  bool ver_boringssl = boringssl_verify(pubkey, msg, msgLen, sgnt_expected, nbLen);
  if (ver_boringssl) printf("Success!\n"); else printf("Failure :(\n");

  return ok;
}


int main() {

  bool ok = true;
  for (int i = 0; i < sizeof(vectors)/sizeof(rsapss_test_vector); ++i) {
    ok &= print_test(vectors[i].modBits,vectors[i].n,vectors[i].eBits,vectors[i].e,vectors[i].dBits,vectors[i].d,
		     vectors[i].msgLen,vectors[i].msg,vectors[i].saltLen,vectors[i].salt,vectors[i].sgnt_expected);
  }


  uint8_t res = 1;
  uint8_t comp[256U];
  cycles a,b;
  clock_t t1,t2;

  uint64_t *skey = Hacl_RSAPSS_new_rsapss_load_skey(2048U, 24U, 2048U, vectors[3].n, vectors[3].e, vectors[3].d);
  uint64_t *pkey = Hacl_RSAPSS_new_rsapss_load_pkey(2048U, 24U, vectors[3].n, vectors[3].e);

  ok = true;
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256, 2048U, 24U, 2048U, skey, 0U, NULL, 128U, vectors[3].msg, comp);
    res = res ^ comp[0];
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256, 2048U, 24U, 2048U, skey, 0U, NULL, 128U, vectors[3].msg, comp);
    res = res ^ comp[0];
  }
  b = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = b - a;



  for (int j = 0; j < ROUNDS; j++) {
    int r = Hacl_RSAPSS_rsapss_verify(Spec_Hash_Definitions_SHA2_256, 2048U, 24U, pkey, 0U, 256U, comp, 128U, vectors[3].msg);
    res = res ^ r;
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    int r = Hacl_RSAPSS_rsapss_verify(Spec_Hash_Definitions_SHA2_256, 2048U, 24U, pkey, 0U, 256U, comp, 128U, vectors[3].msg);
    res = res ^ r;
  }
  b = cpucycles_end();
  t2 = clock();
  double diff2 = t2 - t1;
  uint64_t cyc2 = b - a;



  RSA* privkey = createPrivateKey(test4_n, 256U, test4_e, 3U, test4_d, 256U);
  RSA* pubkey = createPublicKey(test4_n, 256U, test4_e, 3U);

  for (int j = 0; j < ROUNDS; j++) {
    boringssl_sign(privkey, 0U, vectors[3].msg, 128U, comp, 256U);
    res = res ^ comp[0];
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    boringssl_sign(privkey, 0U, vectors[3].msg, 128U, comp, 256U);
    res = res ^ comp[0];
  }
  b = cpucycles_end();
  t2 = clock();
  double diff3 = t2 - t1;
  uint64_t cyc3 = b - a;



  for (int j = 0; j < ROUNDS; j++) {
    int r = boringssl_verify(pubkey, vectors[3].msg, 128U, comp, 256U);
    res = res ^ r;
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    int r = boringssl_verify(pubkey, vectors[3].msg, 128U, comp, 256U);
    res = res ^ r;
  }
  b = cpucycles_end();
  t2 = clock();
  double diff4 = t2 - t1;
  uint64_t cyc4 = b - a;

  uint64_t count = ROUNDS * SIZE;
  printf("\nHACL* RSAPSS signature\n"); print_time(count,diff1,cyc1);
  printf("\nHACL* RSAPSS verification\n"); print_time(count,diff2,cyc2);
  printf("\nBoringssl RSAPSS signature\n"); print_time(count,diff3,cyc3);
  printf("\nBoringssl RSAPSS verification\n"); print_time(count,diff4,cyc4);
  printf("\nratio signature hacl/boringssl %8.2f\n", (double)cyc1/cyc3);
  printf("\nratio verification hacl/boringssl %8.2f\n", (double)cyc2/cyc4);

  if (ok) return EXIT_SUCCESS;
  else return EXIT_FAILURE;
}
