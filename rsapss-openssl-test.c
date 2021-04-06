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


void print_bytes(uint32_t len, uint8_t *in){
  for (int i = 0; i < len; i++)
    printf("%02x, ", in[i]);
  printf("\n");
}


EVP_PKEY*
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

  EVP_PKEY *pkey = NULL;
  pkey = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(pkey, pRsaKey);

  return pkey;
}


EVP_PKEY*
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

  EVP_PKEY *pkey = NULL;
  pkey = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(pkey, pRsaKey);

  return pkey;
}


void generate_rsakey(
  uint32_t modBits,
  uint8_t *nb,
  uint32_t eBits,
  uint8_t *eb,
  uint32_t dBits,
  uint8_t *db
){
  uint32_t nbLen = (modBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;
  uint32_t ebLen = (eBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;
  uint32_t dbLen = (dBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;

  unsigned long ei = 65537;
  BIGNUM *bne = BN_new();
  BN_set_word(bne, ei);

  RSA* pRsaKey = RSA_new();
  const BIGNUM *n = NULL;
  const BIGNUM *e = NULL;
  const BIGNUM *d = NULL;

  RSA_generate_key_ex(pRsaKey, modBits, bne, NULL);
  RSA_get0_key(pRsaKey, &n, &e, &d);
  BN_bn2binpad(n, nb, nbLen);
  BN_bn2binpad(e, eb, ebLen);
  BN_bn2binpad(d, db, dbLen);
}


int
openssl_sign(
  EVP_PKEY *pkey,
  size_t salt_len,
  uint8_t* msg,
  uint32_t msg_len,
  uint8_t* sig,
  size_t sig_len
)
{
  const EVP_MD *digest_algo;
  unsigned char md[128];
  unsigned digest_len;
  EVP_MD_CTX *md_ctx;

  digest_algo = EVP_sha256();
  md_ctx = EVP_MD_CTX_new();
  EVP_DigestInit(md_ctx, digest_algo);
  EVP_DigestUpdate(md_ctx, msg, msg_len);
  EVP_DigestFinal(md_ctx, md, &digest_len);

  EVP_PKEY_CTX *pkey_ctx;
  pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);

  EVP_PKEY_sign_init(pkey_ctx);
  EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
  EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, salt_len);
  EVP_PKEY_CTX_set_signature_md(pkey_ctx, digest_algo);
  EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, digest_algo);

  int ret = EVP_PKEY_sign(pkey_ctx, sig, &sig_len, md, digest_len);

  return ret;
}


int
openssl_verify(
  EVP_PKEY *pkey,
  size_t salt_len,
  uint8_t* msg,
  uint32_t msg_len,
  uint8_t* sig,
  size_t sig_len
)
{
  const EVP_MD *digest_algo;
  unsigned char md[128];
  unsigned digest_len;
  EVP_MD_CTX *md_ctx;

  digest_algo = EVP_sha256();
  md_ctx = EVP_MD_CTX_new();
  EVP_DigestInit(md_ctx, digest_algo);
  EVP_DigestUpdate(md_ctx, msg, msg_len);
  EVP_DigestFinal(md_ctx, md, &digest_len);

  EVP_PKEY_CTX *pkey_ctx;
  pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);

  EVP_PKEY_verify_init(pkey_ctx);
  EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
  EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, salt_len);
  EVP_PKEY_CTX_set_signature_md(pkey_ctx, digest_algo);
  EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, digest_algo);

  int ret = EVP_PKEY_verify(pkey_ctx, sig, sig_len, md, digest_len);
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
  uint32_t ebLen = (eBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;
  uint32_t dbLen = (dBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;

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

  printf("Openssl verify Result\n");
  EVP_PKEY* privkey = createPrivateKey(nb, nbLen, eb, ebLen, db, dbLen);
  EVP_PKEY* pubkey = createPublicKey(nb, nbLen, eb, ebLen);
  bool ver_openssl = openssl_verify(pubkey, saltLen, msg, msgLen, sgnt_expected, nbLen);
  if (ver_openssl) printf("Success!\n"); else printf("Failure :(\n");

  return ok;
}


void test_sign(uint32_t modBits){
  size_t eBits   = 17;
  size_t dBits   = modBits;

  size_t msg_len = 24;
  uint8_t msg[msg_len];
  memset(msg, 0U, msg_len * sizeof (msg[0U]));

  uint32_t nbLen = (modBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;
  uint32_t ebLen = (eBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;
  uint32_t dbLen = (dBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;

  uint8_t test_n[nbLen];
  uint8_t test_e[ebLen];
  uint8_t test_d[dbLen];

  generate_rsakey(modBits, test_n, eBits, test_e, dBits, test_d);
  uint64_t *skey = Hacl_RSAPSS_new_rsapss_load_skey(modBits, eBits, dBits, test_n, test_e, test_d);
  EVP_PKEY* privkey = createPrivateKey(test_n, nbLen, test_e, ebLen, test_d, dbLen);

  uint8_t comp[nbLen];
  uint8_t comp1[nbLen];

  /* printf("\n Signature: OPENSSL =?= HACL \n"); */
  /* Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256, modBits, eBits, dBits, skey, 0U, NULL, msg_len, msg, comp); */
  /* openssl_sign(privkey, 0U, msg, msg_len, comp1, nbLen); */
  /* compare_and_print(nbLen, comp, comp1); */

  cycles a,b;
  clock_t t1,t2;
  uint8_t res = 1;

  for (int j = 0; j < ROUNDS; j++) {
    Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256, modBits, eBits, dBits, skey, 0U, NULL, msg_len, msg, comp);
    res = res ^ comp[0];
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256, modBits, eBits, dBits, skey, 0U, NULL, msg_len, msg, comp);
    res = res ^ comp[0];
  }
  b = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = b - a;



  for (int j = 0; j < ROUNDS; j++) {
    openssl_sign(privkey, 0U, msg, msg_len, comp, nbLen);
    res = res ^ comp[0];
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    openssl_sign(privkey, 0U, msg, msg_len, comp, nbLen);
    res = res ^ comp[0];
  }
  b = cpucycles_end();
  t2 = clock();
  double diff3 = t2 - t1;
  uint64_t cyc3 = b - a;

  uint64_t count = ROUNDS * SIZE;
  //printf("\nHACL* RSAPSS signature\n"); print_time(count,diff1,cyc1);
  //printf("\nOpenSSL RSAPSS signature\n"); print_time(count,diff3,cyc3);
  //printf("\nratio signature hacl/openssl %8.2f\n", (double)cyc1/cyc3);

  printf ("%d\t || %.2f\t || %.2f\t || %.2f \n", modBits, (double)cyc1/count, (double)cyc3/count, (double)cyc1/cyc3);
}


void test_verify(uint32_t modBits){
  size_t eBits   = 17;
  size_t dBits   = modBits;

  size_t msg_len = 24;
  uint8_t msg[msg_len];
  memset(msg, 0U, msg_len * sizeof (msg[0U]));

  uint32_t nbLen = (modBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;
  uint32_t ebLen = (eBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;
  uint32_t dbLen = (dBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;

  uint8_t test_n[nbLen];
  uint8_t test_e[ebLen];
  uint8_t test_d[dbLen];

  generate_rsakey(modBits, test_n, eBits, test_e, dBits, test_d);
  uint64_t *skey = Hacl_RSAPSS_new_rsapss_load_skey(modBits, eBits, dBits, test_n, test_e, test_d);
  EVP_PKEY* privkey = createPrivateKey(test_n, nbLen, test_e, ebLen, test_d, dbLen);
  uint64_t *pkey = Hacl_RSAPSS_new_rsapss_load_pkey(modBits, eBits, test_n, test_e);
  EVP_PKEY* pubkey = createPublicKey(test_n, nbLen, test_e, ebLen);

  uint8_t comp[nbLen];
  uint8_t comp1[nbLen];

  //printf("\n Signature: OPENSSL =?= HACL \n");
  Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256, modBits, eBits, dBits, skey, 0U, NULL, msg_len, msg, comp);
  //openssl_sign(privkey, 0U, msg, msg_len, comp1, nbLen);
  //compare_and_print(nbLen, comp, comp1);

  /* printf("\n Verification: \n"); */
  /* int r1 = Hacl_RSAPSS_rsapss_verify(Spec_Hash_Definitions_SHA2_256, modBits, eBits, pkey, 0U, nbLen, comp, msg_len, msg); */
  /* if (r1) printf("HACL: Success!\n"); else printf("HACL: Failure :(\n"); */
  /* int r2 = openssl_verify(pubkey, 0U, msg, msg_len, comp, nbLen); */
  /* if (r2) printf("OPENSSL: Success!\n"); else printf("OPENSSL: Failure :(\n"); */

  cycles a,b;
  clock_t t1,t2;
  uint8_t res = 1;

  for (int j = 0; j < ROUNDS; j++) {
    int r = Hacl_RSAPSS_rsapss_verify(Spec_Hash_Definitions_SHA2_256, modBits, eBits, pkey, 0U, nbLen, comp, msg_len, msg);
    res = res ^ r;
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    int r = Hacl_RSAPSS_rsapss_verify(Spec_Hash_Definitions_SHA2_256, modBits, eBits, pkey, 0U, nbLen, comp, msg_len, msg);
    res = res ^ r;
  }
  b = cpucycles_end();
  t2 = clock();
  double diff2 = t2 - t1;
  uint64_t cyc2 = b - a;


  for (int j = 0; j < ROUNDS; j++) {
    int r = openssl_verify(pubkey, 0U, msg, msg_len, comp, nbLen);
    res = res ^ r;
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    int r = openssl_verify(pubkey, 0U, msg, msg_len, comp, nbLen);
    res = res ^ r;
  }
  b = cpucycles_end();
  t2 = clock();
  double diff4 = t2 - t1;
  uint64_t cyc4 = b - a;


  uint64_t count = ROUNDS * SIZE;
  //printf("\nHACL* RSAPSS verification\n"); print_time(count,diff2,cyc2);
  //printf("\nOpenSSL RSAPSS verification\n"); print_time(count,diff4,cyc4);
  //printf("\nratio verification hacl/openssl %8.2f\n", (double)cyc2/cyc4);
  printf ("%d\t || %.2f\t || %.2f\t || %.2f \n", modBits, (double)cyc2/count, (double)cyc4/count, (double)cyc2/cyc4);
}



int main() {

  bool ok = true;
  for (int i = 0; i < sizeof(vectors)/sizeof(rsapss_test_vector); ++i) {
    ok &= print_test(vectors[i].modBits,vectors[i].n,vectors[i].eBits,vectors[i].e,vectors[i].dBits,vectors[i].d,
		     vectors[i].msgLen,vectors[i].msg,vectors[i].saltLen,vectors[i].salt,vectors[i].sgnt_expected);
  }

  printf("\n ---------------------------------------------------- \n");
  printf("\n RSAPSS sign \n");
  printf("\n nBits\t || hacl\t || openssl\t || hacl / openssl \n");
  test_sign(2048U);
  test_sign(3072U);
  test_sign(4096U);
  test_sign(6144U);
  test_sign(8192U);

  printf("\n ---------------------------------------------------- \n");
  printf("\n RSAPSS verify \n");
  printf("\n nBits\t || hacl\t || openssl\t || hacl / openssl \n");
  test_verify(2048U);
  test_verify(3072U);
  test_verify(4096U);
  test_verify(6144U);
  test_verify(8192U);

  printf("\n ---------------------------------------------------- \n");

  if (ok) return EXIT_SUCCESS;
  else return EXIT_FAILURE;
}
