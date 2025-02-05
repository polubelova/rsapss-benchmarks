#include "kbench-common.h"
#include "gmp.h"
#include "Hacl_Bignum64.h"

void modexp_gmp(uint32_t len, uint8_t* cb, uint8_t* ab, uint8_t* bb, uint8_t* nb,
		Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64 *k){
  // c == a ^^ b % n
  mpz_t n, a, b, c;
  mpz_init(n);
  mpz_init(a);
  mpz_init(b);
  mpz_init(c);

  mpz_import(a, len, 1, 1, 1, 0, ab);
  mpz_import(b, len, 1, 1, 1, 0, bb);
  mpz_import(n, len, 1, 1, 1, 0, nb);

  mpz_powm_sec(c, a, b, n);

  mpz_export(cb, NULL, 1, 1, 1, 0, c);
}
