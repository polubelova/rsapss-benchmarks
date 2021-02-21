#include "kbench-common.h"

//extern void Hacl_Ed25519_sign(uint8_t *signature, uint8_t *priv, uint32_t len, uint8_t *msg);
//extern bool Hacl_Ed25519_verify(uint8_t *pub, uint32_t len, uint8_t *msg, uint8_t *signature);
extern void Hacl_Ed25519_sign_expanded(uint8_t *signature, uint8_t *ks, uint32_t len, uint8_t *msg);

void ed25519_sign_hacl(
  uint32_t len,
  uint8_t *signature,
  uint8_t *msg,
  uint8_t *keys_expanded,
  uint8_t *priv
)
{
  Hacl_Ed25519_sign_expanded(signature, keys_expanded, len, msg);
}


/* bool ed25519_verify_verify( */
/*   uint8_t *pub, */
/*   uint32_t len, */
/*   uint8_t *msg, */
/*   uint8_t *signature */
/* ) */
/* { */
/*   Hacl_Ed25519_verify(pub, len, msg, signature); */
/* } */
