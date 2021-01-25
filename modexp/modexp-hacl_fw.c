#include "kbench-common.h"

extern uint64_t *Hacl_Bignum64_new_bn_from_bytes_be(uint32_t len, uint8_t *b);
extern void Hacl_Bignum64_bn_to_bytes_be(uint32_t len, uint64_t *b, uint8_t *res);
extern uint64_t *Hacl_Bignum64_new_precompr2(uint32_t len, uint64_t *n);
extern void Hacl_Bignum64_bn_mod_exp_fw_ct_precompr2(
  uint32_t len,
  uint64_t *n,
  uint64_t *a,
  uint32_t bBits,
  uint64_t *b,
  uint32_t l,
  uint64_t *r2,
  uint64_t *res
);

void modexp_hacl_fw(uint32_t len, uint8_t* cb, uint8_t* ab, uint8_t* bb, uint8_t* nb, uint8_t* r2b){

  uint64_t *a = Hacl_Bignum64_new_bn_from_bytes_be(len, ab);
  uint64_t *b = Hacl_Bignum64_new_bn_from_bytes_be(len, bb);
  uint64_t *n = Hacl_Bignum64_new_bn_from_bytes_be(len, nb);
  uint64_t *r2;
  if (r2b) {
    r2 = Hacl_Bignum64_new_bn_from_bytes_be(len, r2b);
  } else {
    r2 = Hacl_Bignum64_new_precompr2(len / 8, n);
  }

  uint64_t c[len / 8];
  Hacl_Bignum64_bn_mod_exp_fw_ct_precompr2(len / 8, n, a, len * 8, b, 4, r2, c);
  Hacl_Bignum64_bn_to_bytes_be(len, c, cb);
}
