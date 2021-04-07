#include "kbench-common.h"
#include "Hacl_Bignum64.h"

void modexp_hacl(uint32_t len, uint8_t* cb, uint8_t* ab, uint8_t* bb, uint8_t* nb,
		 Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64 *k){
  uint64_t *a = Hacl_Bignum64_new_bn_from_bytes_be(len, ab);
  uint64_t *b = Hacl_Bignum64_new_bn_from_bytes_be(len, bb);
  uint64_t *n;
  uint64_t c[len / 8];
  Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64 *kl;

  if (k) {
    kl = k;
  } else {
    //fprintf(stderr,"\n CREATE BN_MONT_CTX\n");
    n = Hacl_Bignum64_new_bn_from_bytes_be(len, nb);
    kl = Hacl_Bignum64_mont_ctx_init(len / 8, n);
  }

  Hacl_Bignum64_mod_exp_consttime_precomp(kl, a, len * 8, b, c);
  Hacl_Bignum64_bn_to_bytes_be(len, c, cb);
}
