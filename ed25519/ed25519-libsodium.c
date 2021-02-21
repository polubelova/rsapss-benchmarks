#include "kbench-common.h"

extern int sodium_init(void);
extern int crypto_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
                         const unsigned char *m, unsigned long long mlen,
                         const unsigned char *sk);

void ed25519_sign_libsodium(
  uint32_t len,
  uint8_t *signature,
  uint8_t *msg,
  uint8_t *keys_expanded, //pub, s, prefix
  uint8_t *priv
)
{
  if (sodium_init() == -1) {
  return;
  }

  uint8_t skey[64] = { 0 }; //s, pub
  memcpy (skey, priv, 32);
  memcpy (skey + 32, keys_expanded, 32);

  crypto_sign_detached(signature, NULL, msg, len, skey);
}
