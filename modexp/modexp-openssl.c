#include "kbench-common.h"
#include "openssl/bn.h"

extern int pre_asm_BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx,
                              BN_MONT_CTX *in_mont);
extern BIGNUM *pre_asm_BN_new(void);
extern BIGNUM *pre_asm_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
extern BN_CTX *pre_asm_BN_CTX_new(void);
extern int pre_asm_BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);

void modexp_openssl(uint32_t len, uint8_t* cb, uint8_t* ab, uint8_t* bb, uint8_t* nb, uint8_t* r2b){
  // c == a ^^ b % n
  BIGNUM *n = pre_asm_BN_new();
  BIGNUM *a = pre_asm_BN_new();
  BIGNUM *b = pre_asm_BN_new();
  BIGNUM *c = pre_asm_BN_new();
  BN_CTX *ctx = pre_asm_BN_CTX_new();

  pre_asm_BN_bin2bn(ab, len, a);
  pre_asm_BN_bin2bn(bb, len, b);
  pre_asm_BN_bin2bn(nb, len, n);

  pre_asm_BN_mod_exp_mont_consttime(c, a, b, n, ctx, NULL);

  pre_asm_BN_bn2binpad(c, cb, len);
}
