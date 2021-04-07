#include "kbench-common.h"
#include "Hacl_RSAPSS.h"
#include "openssl/evp.h"


int rsapss_verify_hacl(uint32_t modBits, uint8_t *sgnt, uint64_t* pkey, EVP_PKEY *pubkey){
  uint32_t nbLen = (modBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;
  size_t msg_len = 24;
  uint8_t msg[msg_len];
  memset(msg, 0U, msg_len * sizeof (msg[0U]));

  return Hacl_RSAPSS_rsapss_verify(Spec_Hash_Definitions_SHA2_256, modBits, 17, pkey, 0U, nbLen, sgnt, msg_len, msg);
}
