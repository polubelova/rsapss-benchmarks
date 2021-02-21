#include "kbench-common.h"

extern int sodium_init(void);
extern int crypto_sign_verify_detached(const unsigned char *sig,
                                const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *pk);

bool ed25519_verify_libsodium(
  uint32_t len,
  uint8_t *pub,
  uint8_t *msg,
  uint8_t *signature
)
{
  if (sodium_init() == -1) {
  return false;
  }

  if (crypto_sign_verify_detached(signature, msg, len, pub) != 0)
    return false;
  else
    return true;
}
