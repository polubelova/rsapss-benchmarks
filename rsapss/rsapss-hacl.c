#include "kbench-common.h"
#include "openssl/rsa.h"

extern bool
Hacl_RSAPSS_rsapss_sign(
  Spec_Hash_Definitions_hash_alg a,
  uint32_t modBits,
  uint32_t eBits,
  uint32_t dBits,
  uint64_t *skey,
  uint32_t sLen,
  uint8_t *salt,
  uint32_t msgLen,
  uint8_t *msg,
  uint8_t *sgnt
);

extern bool
Hacl_RSAPSS_rsapss_verify(
  Spec_Hash_Definitions_hash_alg a,
  uint32_t modBits,
  uint32_t eBits,
  uint64_t *pkey,
  uint32_t sLen,
  uint32_t k,
  uint8_t *sgnt,
  uint32_t msgLen,
  uint8_t *msg
);

void rsapss_sign_hacl(uint32_t modBits, uint8_t *sgnt, uint64_t* skey, RSA* privkey){
  size_t msg_len = 24;
  uint8_t msg[msg_len];
  memset(msg, 0U, msg_len * sizeof (msg[0U]));

  Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256, modBits, 17, modBits, skey, 0, NULL, msg_len, msg, sgnt);
}
