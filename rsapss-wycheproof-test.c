#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "Hacl_RSAPSS.h"

#include "test_helpers.h"
#include "rsapss_wycheproof_vectors.h"


bool hacl_verify(
  Spec_Hash_Definitions_hash_alg alg,
  uint32_t modBits,
  uint8_t *n1,
  uint32_t pkeyBits,
  uint8_t *e,
  uint32_t msgLen,
  uint8_t *msg,
  uint32_t saltLen,
  uint32_t sgntLen,
  uint8_t *sgnt
)
{
  uint32_t nLenBytes = (modBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;
  uint32_t nLen = (modBits - (uint32_t)1U) / (uint32_t)64U + (uint32_t)1U;
  uint32_t eLen = (pkeyBits - (uint32_t)1U) / (uint32_t)64U + (uint32_t)1U;
  uint32_t pkeyLen = nLen + eLen;

  uint64_t pkey[pkeyLen];
  memset(pkey, 0U, pkeyLen * sizeof pkey[0U]);
  uint64_t *nNat = pkey;
  uint64_t *eNat = pkey + nLen;
  Hacl_Bignum_Convert_bn_from_bytes_be((modBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U, n1, nNat);
  Hacl_Bignum_Convert_bn_from_bytes_be((pkeyBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U, e, eNat);

  bool verify_sgnt;
  if (sgntLen == nLenBytes)
    verify_sgnt = Hacl_RSAPSS_rsapss_verify(alg, modBits, pkeyBits, pkey, saltLen, sgnt, msgLen, msg);
  else
    verify_sgnt = false;

  return verify_sgnt;
}

bool print_result(uint32_t len, uint8_t* comp, uint8_t* exp) {
  return compare_and_print(len, comp, exp);
}

bool print_test(
  Spec_Hash_Definitions_hash_alg alg,
  uint32_t modBits,
  uint8_t *n1,
  uint32_t pkeyBits,
  uint8_t *e,
  uint32_t msgLen,
  uint8_t *msg,
  uint32_t saltLen,
  uint32_t sgntLen,
  uint8_t *sgnt,
  bool valid
){
  bool ver = hacl_verify(alg, modBits, n1, pkeyBits, e, msgLen, msg, saltLen, sgntLen, sgnt);
  //printf ("ver = %d  valid = %d\n", ver, valid);
  //if (ver == valid) printf("Success!\n"); else printf("Failure!\n");
  return (ver == valid);
}

int main() {

  bool ok = true;

  printf("RSAPSS_SHA256_2048_0: ");
  for (int i = 0; i < sizeof(sha256_2048_0_vectors)/sizeof(rsapss_verify_test_vector); ++i) {
    //printf("test i = %d\n", i);
    ok &= print_test(Spec_Hash_Definitions_SHA2_256,sha256_2048_0_vectors[i].modBits,sha256_2048_0_vectors[i].n,sha256_2048_0_vectors[i].eBits,sha256_2048_0_vectors[i].e,
		     sha256_2048_0_vectors[i].msgLen,sha256_2048_0_vectors[i].msg,sha256_2048_0_vectors[i].sLen,sha256_2048_0_vectors[i].sgntLen,
		     sha256_2048_0_vectors[i].sgnt,sha256_2048_0_vectors[i].valid);
  }
  if (ok) printf("Success!\n"); else printf("Failure!\n");

  printf("RSAPSS_SHA256_2048_32: ");
  for (int i = 0; i < sizeof(sha256_2048_32_vectors)/sizeof(rsapss_verify_test_vector); ++i) {
    //printf("test i = %d\n", i);
    ok &= print_test(Spec_Hash_Definitions_SHA2_256,sha256_2048_32_vectors[i].modBits,sha256_2048_32_vectors[i].n,sha256_2048_32_vectors[i].eBits,sha256_2048_32_vectors[i].e,
		     sha256_2048_32_vectors[i].msgLen,sha256_2048_32_vectors[i].msg,sha256_2048_32_vectors[i].sLen,sha256_2048_32_vectors[i].sgntLen,
		     sha256_2048_32_vectors[i].sgnt,sha256_2048_32_vectors[i].valid);
  }
  if (ok) printf("Success!\n"); else printf("Failure!\n");

  printf("RSAPSS_SHA256_3072_32: ");
  for (int i = 0; i < sizeof(sha256_3072_32_vectors)/sizeof(rsapss_verify_test_vector); ++i) {
    //printf("test i = %d\n", i);
    ok &= print_test(Spec_Hash_Definitions_SHA2_256,sha256_3072_32_vectors[i].modBits,sha256_3072_32_vectors[i].n,sha256_3072_32_vectors[i].eBits,sha256_3072_32_vectors[i].e,
		     sha256_3072_32_vectors[i].msgLen,sha256_3072_32_vectors[i].msg,sha256_3072_32_vectors[i].sLen,sha256_3072_32_vectors[i].sgntLen,
		     sha256_3072_32_vectors[i].sgnt,sha256_3072_32_vectors[i].valid);
  }
  if (ok) printf("Success!\n"); else printf("Failure!\n");

  printf("RSAPSS_SHA256_4096_32: ");
  for (int i = 0; i < sizeof(sha256_4096_32_vectors)/sizeof(rsapss_verify_test_vector); ++i) {
    //printf("test i = %d\n", i);
    ok &= print_test(Spec_Hash_Definitions_SHA2_256,sha256_4096_32_vectors[i].modBits,sha256_4096_32_vectors[i].n,sha256_4096_32_vectors[i].eBits,sha256_4096_32_vectors[i].e,
		     sha256_4096_32_vectors[i].msgLen,sha256_4096_32_vectors[i].msg,sha256_4096_32_vectors[i].sLen,sha256_4096_32_vectors[i].sgntLen,
		     sha256_4096_32_vectors[i].sgnt,sha256_4096_32_vectors[i].valid);
  }
  if (ok) printf("Success!\n"); else printf("Failure!\n");

  printf("RSAPSS_SHA512_4096_32: ");
  for (int i = 0; i < sizeof(sha512_4096_32_vectors)/sizeof(rsapss_verify_test_vector); ++i) {
    //printf("test i = %d\n", i);
    ok &= print_test(Spec_Hash_Definitions_SHA2_512,sha512_4096_32_vectors[i].modBits,sha512_4096_32_vectors[i].n,sha512_4096_32_vectors[i].eBits,sha512_4096_32_vectors[i].e,
		     sha512_4096_32_vectors[i].msgLen,sha512_4096_32_vectors[i].msg,sha512_4096_32_vectors[i].sLen,sha512_4096_32_vectors[i].sgntLen,
		     sha512_4096_32_vectors[i].sgnt,sha512_4096_32_vectors[i].valid);
  }
  if (ok) printf("Success!\n"); else printf("Failure!\n");

  if (ok)
    return EXIT_SUCCESS;
  else
    return EXIT_FAILURE;
}
