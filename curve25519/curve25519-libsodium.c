#include "kbench-common.h"

extern int sodium_init(void);
extern int crypto_scalarmult(unsigned char *q, const unsigned char *n,
                      const unsigned char *p);

void curve25519_ecdh_libsodium(uint8_t *out, uint8_t *priv, uint8_t *pub)
{
  if (sodium_init() == -1) {
    return;
  }

  crypto_scalarmult(out, priv, pub);
}
