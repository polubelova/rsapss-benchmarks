module Hacl.BenchBignum

open FStar.Mul
open Lib.IntTypes

open Hacl.Bignum.Definitions

module BN = Hacl.Bignum
module BS = Hacl.Bignum.SafeAPI
module MA = Hacl.Bignum.MontArithmetic
module BM = Hacl.Bignum.Montgomery
module AM = Hacl.Bignum.AlmostMontgomery
module BE = Hacl.Bignum.Exponentiation

#set-options "--z3rlimit 50 --fuel 0 --ifuel 0"

inline_for_extraction noextract
let t_limbs: limb_t = U64

inline_for_extraction noextract
let kam (len:BN.meta_len t_limbs) =
  AM.mk_runtime_almost_mont #t_limbs len

inline_for_extraction noextract
let km (len:BN.meta_len t_limbs) =
  BM.mk_runtime_mont #t_limbs len

//a right-to-left bignary method
val mod_exp_bm_vartime_mm_precomp: len:Ghost.erased _ -> BS.bn_mod_exp_ctx_st t_limbs len
let mod_exp_bm_vartime_mm_precomp len k a bBits b res =
  let len1 = MA.bn_field_get_len k in
  BS.mk_bn_mod_exp_ctx len (BE.bn_mod_exp_bm_vartime_precomp (km len1)) k a bBits b res

//montgomery ladder
val mod_exp_bm_consttime_mm_precomp: len:Ghost.erased _ -> BS.bn_mod_exp_ctx_st t_limbs len
let mod_exp_bm_consttime_mm_precomp len k a bBits b res =
  let len1 = MA.bn_field_get_len k in
  BS.mk_bn_mod_exp_ctx len (BE.bn_mod_exp_bm_consttime_precomp (km len1)) k a bBits b res


val mod_exp_fw_vartime_mm_precomp:
    len:Ghost.erased (BN.meta_len t_limbs)
  -> l:size_t{0 < v l /\ v l < bits U32 /\ pow2 (v l) * v len <= max_size_t} ->
  BS.bn_mod_exp_ctx_st t_limbs len

let mod_exp_fw_vartime_mm_precomp len l k a bBits b res =
  let len1 = MA.bn_field_get_len k in
  BS.mk_bn_mod_exp_ctx len (BE.bn_mod_exp_fw_vartime_precomp (km len1) l) k a bBits b res


val mod_exp_fw_consttime_mm_precomp:
    len:Ghost.erased (BN.meta_len t_limbs)
  -> l:size_t{0 < v l /\ v l < bits U32 /\ pow2 (v l) * v len <= max_size_t} ->
  BS.bn_mod_exp_ctx_st t_limbs len

let mod_exp_fw_consttime_mm_precomp len l k a bBits b res =
  let len1 = MA.bn_field_get_len k in
  BS.mk_bn_mod_exp_ctx len (BE.bn_mod_exp_fw_consttime_precomp (km len1) l) k a bBits b res

// Almost Montgommery Multiplication

//a right-to-left bignary method
val mod_exp_bm_vartime_amm_precomp: len:Ghost.erased _ -> BS.bn_mod_exp_ctx_st t_limbs len
let mod_exp_bm_vartime_amm_precomp len k a bBits b res =
  let len1 = MA.bn_field_get_len k in
  BS.mk_bn_mod_exp_ctx len (BE.bn_mod_exp_amm_bm_vartime_precomp (kam len1)) k a bBits b res

//montgomery ladder
val mod_exp_bm_consttime_amm_precomp: len:Ghost.erased _ -> BS.bn_mod_exp_ctx_st t_limbs len
let mod_exp_bm_consttime_amm_precomp len k a bBits b res =
  let len1 = MA.bn_field_get_len k in
  BS.mk_bn_mod_exp_ctx len (BE.bn_mod_exp_amm_bm_consttime_precomp (kam len1)) k a bBits b res


val mod_exp_fw_vartime_amm_precomp:
    len:Ghost.erased (BN.meta_len t_limbs)
  -> l:size_t{0 < v l /\ v l < bits U32 /\ pow2 (v l) * v len <= max_size_t} ->
  BS.bn_mod_exp_ctx_st t_limbs len

let mod_exp_fw_vartime_amm_precomp len l k a bBits b res =
  let len1 = MA.bn_field_get_len k in
  BS.mk_bn_mod_exp_ctx len (BE.bn_mod_exp_amm_fw_vartime_precomp (kam len1) l) k a bBits b res


val mod_exp_fw_consttime_amm_precomp:
    len:Ghost.erased (BN.meta_len t_limbs)
  -> l:size_t{0 < v l /\ v l < bits U32 /\ pow2 (v l) * v len <= max_size_t} ->
  BS.bn_mod_exp_ctx_st t_limbs len

let mod_exp_fw_consttime_amm_precomp len l k a bBits b res =
  let len1 = MA.bn_field_get_len k in
  BS.mk_bn_mod_exp_ctx len (BE.bn_mod_exp_amm_fw_consttime_precomp (kam len1) l) k a bBits b res
