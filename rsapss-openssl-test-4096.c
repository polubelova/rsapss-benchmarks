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
openssl_sign(
  RSA* pRsaKey,
  size_t salt_len,
  uint8_t* msg,
  uint32_t msg_len,
  uint8_t* sig,
  size_t sig_len
)
{
  int status = 0;
  unsigned char pDigest[32];
  unsigned char EM[sig_len];

  /* hash the message */
  SHA256(msg, msg_len, pDigest);

  /* compute the PSS padded data */
  status = RSA_padding_add_PKCS1_PSS(pRsaKey, EM, pDigest, EVP_sha256(), salt_len /* maximum salt length*/);

  /* perform digital signature */
  status = RSA_private_encrypt(sig_len, EM, sig, pRsaKey, RSA_NO_PADDING);
  return status;
}

int
openssl_verify(
  RSA* pRsaKey,
  uint8_t* msg,
  uint32_t msg_len,
  uint8_t* sig,
  size_t sig_len
)
{
  int status = 0;
  unsigned char pDigest[32];
  unsigned char EM[sig_len];
  unsigned char pDecrypted[sig_len];

  /* hash the message */
  SHA256(msg, msg_len, pDigest);

  status = RSA_public_decrypt(sig_len, sig, pDecrypted, pRsaKey, RSA_NO_PADDING);
  /* verify the data */
  status = RSA_verify_PKCS1_PSS(pRsaKey, pDigest, EVP_sha256(), pDecrypted, -2 /* salt length recovered from signature*/);
  return status;
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

  return ok;
}

int main() {

  bool ok = true;
  for (int i = 0; i < sizeof(vectors)/sizeof(rsapss_test_vector); ++i) {
    ok &= print_test(vectors[i].modBits,vectors[i].n,vectors[i].eBits,vectors[i].e,vectors[i].dBits,vectors[i].d,
		     vectors[i].msgLen,vectors[i].msg,vectors[i].saltLen,vectors[i].salt,vectors[i].sgnt_expected);
  }

  uint8_t res = 1;
  uint8_t comp[512U];
  cycles a,b;
  clock_t t1,t2;

  uint64_t *skey = Hacl_RSAPSS_new_rsapss_load_skey(4096U, 24U, 4096U, vectors[4].n, vectors[4].e, vectors[4].d);
  uint64_t *pkey = Hacl_RSAPSS_new_rsapss_load_pkey(4096U, 24U, vectors[4].n, vectors[4].e);

  ok = true;
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256, 4096U, 24U, 4096U, skey, 0U, NULL, 128U, vectors[4].msg, comp);
    res = res ^ comp[0];
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256, 4096U, 24U, 4096U, skey, 0U, NULL, 128U, vectors[4].msg, comp);
    res = res ^ comp[0];
  }
  b = cpucycles_end();
  t2 = clock();
  double diff1 = t2 - t1;
  uint64_t cyc1 = b - a;



  for (int j = 0; j < ROUNDS; j++) {
    int r = Hacl_RSAPSS_rsapss_verify(Spec_Hash_Definitions_SHA2_256, 4096U, 24U, pkey, 0U, 512U, comp, 128U, vectors[4].msg);
    res = res ^ r;
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    int r = Hacl_RSAPSS_rsapss_verify(Spec_Hash_Definitions_SHA2_256, 4096U, 24U, pkey, 0U, 512U, comp, 128U, vectors[4].msg);
    res = res ^ r;
  }
  b = cpucycles_end();
  t2 = clock();
  double diff2 = t2 - t1;
  uint64_t cyc2 = b - a;



  RSA* privkey = createPrivateKey(test5_n, 512U, test5_e, 3U, test5_d, 512U);
  RSA* pubkey = createPublicKey(test5_n, 512U, test5_e, 3U);

  for (int j = 0; j < ROUNDS; j++) {
    openssl_sign(privkey, 0U, vectors[4].msg, 128U, comp, 512U);
    res = res ^ comp[0];
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    openssl_sign(privkey, 0U, vectors[4].msg, 128U, comp, 512U);
    res = res ^ comp[0];
  }
  b = cpucycles_end();
  t2 = clock();
  double diff3 = t2 - t1;
  uint64_t cyc3 = b - a;



  for (int j = 0; j < ROUNDS; j++) {
    int r = openssl_verify(pubkey, vectors[4].msg, 128U, comp, 512U);
    res = res ^ r;
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    int r = openssl_verify(pubkey, vectors[4].msg, 128U, comp, 512U);
    res = res ^ r;
  }
  b = cpucycles_end();
  t2 = clock();
  double diff4 = t2 - t1;
  uint64_t cyc4 = b - a;

  uint64_t count = ROUNDS * SIZE;
  printf("\nHACL* RSAPSS signature\n"); print_time(count,diff1,cyc1);
  printf("\nHACL* RSAPSS verification\n"); print_time(count,diff2,cyc2);
  printf("\nOpenSSL RSAPSS signature\n"); print_time(count,diff3,cyc3);
  printf("\nOpenSSL RSAPSS verification\n"); print_time(count,diff4,cyc4);
  printf("\nratio signature hacl/openssl %8.2f\n", (double)cyc1/cyc3);
  printf("\nratio verification hacl/openssl %8.2f\n", (double)cyc2/cyc4);


  if (ok) return EXIT_SUCCESS;
  else return EXIT_FAILURE;
}
