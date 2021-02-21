#include "kbench-common.h"

extern bool Hacl_Ed25519_verify(uint8_t *pub, uint32_t len, uint8_t *msg, uint8_t *signature);

bool ed25519_verify_hacl(
  uint32_t len,
  uint8_t *pub,
  uint8_t *msg,
  uint8_t *signature
)
{
  return Hacl_Ed25519_verify(pub, len, msg, signature);
}
