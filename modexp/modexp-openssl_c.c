#include "kbench-common.h"
#include "openssl/bn.h"

extern int no_asm_BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx,
                              BN_MONT_CTX *in_mont);
extern BIGNUM *no_asm_BN_new(void);
extern BIGNUM *no_asm_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
extern BN_CTX *no_asm_BN_CTX_new(void);
extern int no_asm_BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);


void modexp_openssl_c(uint32_t len, uint8_t* cb, uint8_t* ab, uint8_t* bb, uint8_t* nb, uint8_t* r2b){
  // c == a ^^ b % n
  BIGNUM *n = no_asm_BN_new();
  BIGNUM *a = no_asm_BN_new();
  BIGNUM *b = no_asm_BN_new();
  BIGNUM *c = no_asm_BN_new();
  BN_CTX *ctx = no_asm_BN_CTX_new();

  no_asm_BN_bin2bn(ab, len, a);
  no_asm_BN_bin2bn(bb, len, b);
  no_asm_BN_bin2bn(nb, len, n);

  no_asm_BN_mod_exp_mont_consttime(c, a, b, n, ctx, NULL);

  no_asm_BN_bn2binpad(c, cb, len);
}
