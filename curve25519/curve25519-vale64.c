#include "kbench-common.h"

extern bool Hacl_Curve25519_64_ecdh(uint8_t *out, uint8_t *priv, uint8_t *pub);

void curve25519_ecdh_vale64(uint8_t *out, uint8_t *priv, uint8_t *pub)
{
  Hacl_Curve25519_64_ecdh(out, priv, pub);
}
