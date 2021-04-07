#include "kbench-common.h"
#include "Hacl_RSAPSS.h"
#include "openssl/evp.h"


void rsapss_sign_hacl(uint32_t modBits, uint8_t *sgnt, uint64_t* skey, EVP_PKEY *privkey){
  size_t msg_len = 24;
  uint8_t msg[msg_len];
  memset(msg, 0U, msg_len * sizeof (msg[0U]));

  Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256, modBits, 17, modBits, skey, 0, NULL, msg_len, msg, sgnt);
}
