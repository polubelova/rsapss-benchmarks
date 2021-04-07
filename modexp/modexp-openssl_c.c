#include "kbench-common.h"
#include "openssl/bn.h"
#include "Hacl_Bignum64.h"

extern int no_asm_BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx,
                              BN_MONT_CTX *in_mont);

void modexp_openssl_c(uint32_t len, uint8_t* cb, uint8_t* ab, uint8_t* bb, uint8_t* nb,
		      Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64 *k){
  // c == a ^^ b % n
  BIGNUM *n = BN_new();
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();
  BIGNUM *c = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  BN_bin2bn(ab, len, a);
  BN_bin2bn(bb, len, b);
  BN_bin2bn(nb, len, n);

  no_asm_BN_mod_exp_mont_consttime(c, a, b, n, ctx, NULL);

  BN_bn2binpad(c, cb, len);
}
