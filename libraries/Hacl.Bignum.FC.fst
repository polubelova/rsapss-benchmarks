module Hacl.Bignum.FC

open FStar.HyperStack
open FStar.HyperStack.ST
open FStar.Mul

open Lib.IntTypes
open Lib.Buffer

open Hacl.Bignum.Base
open Hacl.Bignum.Definitions

module ST = FStar.HyperStack.ST
module HS = FStar.HyperStack
module B = LowStar.Buffer
module Loops = Lib.LoopCombinators
module BSeq = Lib.ByteSequence

module SN = Hacl.Spec.Bignum
module BN = Hacl.Bignum
module BM = Hacl.Bignum.Montgomery
module SM = Hacl.Spec.Bignum.Montgomery
module AM = Hacl.Bignum.AlmostMontgomery
module SAM = Hacl.Spec.Bignum.AlmostMontgomery
module BR = Hacl.Bignum.ModReduction
module BI = Hacl.Bignum.ModInv
module BE = Hacl.Bignum.Exponentiation
module BS = Hacl.Bignum.SafeAPI

// inline_for_extraction noextract
// val bn_add1:
//     #t:limb_t
//   -> aLen:size_t{0 < v aLen}
//   -> a:lbignum t aLen
//   -> b1:limb t
//   -> res:lbignum t aLen ->
//   Stack (carry t)
//   (requires fun h ->
//     live h a /\ live h res /\ eq_or_disjoint a res)
//   (ensures  fun h0 c_out h1 -> modifies (loc res) h0 h1 /\
//     v c_out * pow2 (bits t * v aLen) + bn_v h1 res == bn_v h0 a + v b1)

// let bn_add1 #t aLen a b1 res =
//   let h0 = ST.get () in
//   SN.bn_add1_lemma (as_seq h0 a) b1;
//   BN.bn_add1 aLen a b1 res


// inline_for_extraction noextract
// val bn_sub1:
//     #t:limb_t
//   -> aLen:size_t{0 < v aLen}
//   -> a:lbignum t aLen
//   -> b1:limb t
//   -> res:lbignum t aLen ->
//   Stack (carry t)
//   (requires fun h ->
//     live h a /\ live h res /\ eq_or_disjoint a res)
//   (ensures  fun h0 c_out h1 -> modifies (loc res) h0 h1 /\
//     bn_v h1 res - v c_out * pow2 (bits t * v aLen) == bn_v h0 a - v b1)

// let bn_sub1 #t aLen a b1 res =
//   let h0 = ST.get () in
//   SN.bn_sub1_lemma (as_seq h0 a) b1;
//   BN.bn_sub1 aLen a b1 res


inline_for_extraction noextract
val bn_add_eq_len:
    #t:limb_t
  -> len:size_t
  -> a:lbignum t len
  -> b:lbignum t len
  -> res:lbignum t len ->
  Stack (carry t)
  (requires fun h ->
    live h a /\ live h b /\ live h res /\
    eq_or_disjoint a b /\ eq_or_disjoint a res /\ eq_or_disjoint b res)
  (ensures  fun h0 c_out h1 -> modifies (loc res) h0 h1 /\
    v c_out * pow2 (bits t * v len) + bn_v h1 res == bn_v h0 a + bn_v h0 b)

let bn_add_eq_len #t len a b res =
  let h0 = ST.get () in
  SN.bn_add_lemma (as_seq h0 a) (as_seq h0 b);
  BN.bn_add_eq_len len a b res


inline_for_extraction noextract
val bn_sub_eq_len:
    #t:limb_t
  -> len:size_t
  -> a:lbignum t len
  -> b:lbignum t len
  -> res:lbignum t len ->
  Stack (carry t)
  (requires fun h ->
    live h a /\ live h b /\ live h res /\
    eq_or_disjoint a b /\ eq_or_disjoint a res /\ eq_or_disjoint b res)
  (ensures  fun h0 c_out h1 -> modifies (loc res) h0 h1 /\
    bn_v h1 res - v c_out * pow2 (bits t * v len) == bn_v h0 a - bn_v h0 b)

let bn_sub_eq_len #t len a b res =
  let h0 = ST.get () in
  SN.bn_sub_lemma (as_seq h0 a) (as_seq h0 b);
  BN.bn_sub_eq_len len a b res


// inline_for_extraction noextract
// val bn_add:
//     #t:limb_t
//   -> aLen:size_t
//   -> a:lbignum t aLen
//   -> bLen:size_t{v bLen <= v aLen}
//   -> b:lbignum t bLen
//   -> res:lbignum t aLen ->
//   Stack (carry t)
//   (requires fun h ->
//     live h a /\ live h b /\ live h res /\
//     disjoint a b /\ eq_or_disjoint a res /\ disjoint b res)
//   (ensures  fun h0 c_out h1 -> modifies (loc res) h0 h1 /\
//     v c_out * pow2 (bits t * v aLen) + bn_v h1 res == bn_v h0 a + bn_v h0 b)

// let bn_add #t aLen a bLen b res =
//   let h0 = ST.get () in
//   SN.bn_add_lemma (as_seq h0 a) (as_seq h0 b);
//   BN.bn_add aLen a bLen b res


// inline_for_extraction noextract
// val bn_sub:
//     #t:limb_t
//   -> aLen:size_t
//   -> a:lbignum t aLen
//   -> bLen:size_t{v bLen <= v aLen}
//   -> b:lbignum t bLen
//   -> res:lbignum t aLen ->
//   Stack (carry t)
//   (requires fun h ->
//     live h a /\ live h b /\ live h res /\
//     disjoint a b /\ eq_or_disjoint a res /\ disjoint b res)
//   (ensures  fun h0 c_out h1 -> modifies (loc res) h0 h1 /\
//     bn_v h1 res - v c_out * pow2 (bits t * v aLen) == bn_v h0 a - bn_v h0 b)

// let bn_sub #t aLen a bLen b res =
//   let h0 = ST.get () in
//   SN.bn_sub_lemma (as_seq h0 a) (as_seq h0 b);
//   BN.bn_sub aLen a bLen b res


// inline_for_extraction noextract
// val bn_reduce_once:
//     #t:limb_t
//   -> aLen:size_t{v aLen > 0}
//   -> n:lbignum t aLen
//   -> c:carry t
//   -> a:lbignum t aLen ->
//   Stack unit
//   (requires fun h ->
//     live h a /\ live h n /\ disjoint a n /\
//     v c * pow2 (bits t * v aLen) + bn_v h a < 2 * bn_v h n)
//   (ensures  fun h0 _ h1 -> modifies (loc a) h0 h1 /\
//     bn_v h1 a == (v c * pow2 (bits t * v aLen) + bn_v h0 a) % bn_v h0 n)

// let bn_reduce_once #t aLen n c a =
//   let h0 = ST.get () in
//   SN.bn_reduce_once_lemma (as_seq h0 n) c (as_seq h0 a);
//   BN.bn_reduce_once aLen n c a


inline_for_extraction noextract
val bn_add_mod_n:
    #t:limb_t
  -> len:size_t{v len > 0}
  -> n:lbignum t len
  -> a:lbignum t len
  -> b:lbignum t len
  -> res:lbignum t len ->
  Stack unit
  (requires fun h ->
    live h n /\ live h a /\ live h b /\ live h res /\
    disjoint n a /\ disjoint n b /\ disjoint n res /\
    eq_or_disjoint a b /\ eq_or_disjoint a res /\ eq_or_disjoint b res /\

    bn_v h a < bn_v h n /\ bn_v h b < bn_v h n)
  (ensures  fun h0 _ h1 -> modifies (loc res) h0 h1 /\
    bn_v h1 res == (bn_v h0 a + bn_v h0 b) % bn_v h0 n)

let bn_add_mod_n #t len n a b res =
  let h0 = ST.get () in
  SN.bn_add_mod_n_lemma (as_seq h0 n) (as_seq h0 a) (as_seq h0 b);
  BN.bn_add_mod_n len n a b res


inline_for_extraction noextract
val bn_sub_mod_n:
    #t:limb_t
  -> len:size_t{v len > 0}
  -> n:lbignum t len
  -> a:lbignum t len
  -> b:lbignum t len
  -> res:lbignum t len ->
  Stack unit
  (requires fun h ->
    live h n /\ live h a /\ live h b /\ live h res /\
    disjoint n a /\ disjoint n b /\ disjoint n res /\
    eq_or_disjoint a b /\ eq_or_disjoint a res /\ eq_or_disjoint b res /\

    bn_v h a < bn_v h n /\ bn_v h b < bn_v h n)
  (ensures  fun h0 _ h1 -> modifies (loc res) h0 h1 /\
    bn_v h1 res == (bn_v h0 a - bn_v h0 b) % bn_v h0 n)

let bn_sub_mod_n #t len n a b res =
  let h0 = ST.get () in
  SN.bn_sub_mod_n_lemma (as_seq h0 n) (as_seq h0 a) (as_seq h0 b);
  BN.bn_sub_mod_n len n a b res


// inline_for_extraction noextract
// val bn_mul1:
//     #t:limb_t
//   -> aLen:size_t
//   -> a:lbignum t aLen
//   -> l:limb t
//   -> res:lbignum t aLen ->
//   Stack (limb t)
//   (requires fun h ->
//     live h a /\ live h res /\ eq_or_disjoint res a)
//   (ensures  fun h0 c_out h1 -> modifies (loc res) h0 h1 /\
//     v c_out * pow2 (bits t * v aLen) + bn_v h1 res == bn_v h0 a * v l)

// let bn_mul1 #t aLen a l res =
//   let h0 = ST.get () in
//   SN.bn_mul1_lemma (as_seq h0 a) l;
//   BN.bn_mul1 aLen a l res


inline_for_extraction noextract
val bn_karatsuba_mul:
    #t:limb_t
  -> len:size_t{0 < v len /\ 4 * v len <= max_size_t}
  -> a:lbignum t len
  -> b:lbignum t len
  -> res:lbignum t (len +! len) ->
  Stack unit
  (requires fun h ->
    live h a /\ live h b /\ live h res /\
    disjoint res a /\ disjoint res b /\ eq_or_disjoint a b)
  (ensures  fun h0 _ h1 -> modifies (loc res) h0 h1 /\
    bn_v h1 res == bn_v h0 a * bn_v h0 b)

let bn_karatsuba_mul #t len a b res =
  let h0 = ST.get () in
  SN.bn_karatsuba_mul_lemma (as_seq h0 a) (as_seq h0 b);
  BN.bn_karatsuba_mul len a b res


inline_for_extraction noextract
val bn_mul:
    #t:limb_t
  -> aLen:size_t
  -> bLen:size_t{v aLen + v bLen <= max_size_t}
  -> a:lbignum t aLen
  -> b:lbignum t bLen
  -> res:lbignum t (aLen +! bLen) ->
  Stack unit
  (requires fun h ->
    live h a /\ live h b /\ live h res /\
    disjoint res a /\ disjoint res b /\ eq_or_disjoint a b)
  (ensures  fun h0 _ h1 -> modifies (loc res) h0 h1 /\
    bn_v h1 res == bn_v h0 a * bn_v h0 b)

let bn_mul #t aLen bLen a b res =
  let h0 = ST.get () in
  SN.bn_mul_lemma (as_seq h0 a) (as_seq h0 b);
  BN.bn_mul aLen bLen a b res


inline_for_extraction noextract
val bn_karatsuba_sqr:
    #t:limb_t
  -> len:size_t{0 < v len /\ 4 * v len <= max_size_t}
  -> a:lbignum t len
  -> res:lbignum t (len +! len) ->
  Stack unit
  (requires fun h -> live h a /\ live h res /\ disjoint res a)
  (ensures  fun h0 _ h1 -> modifies (loc res) h0 h1 /\
    bn_v h1 res == bn_v h0 a * bn_v h0 a)

let bn_karatsuba_sqr #t len a res =
  let h0 = ST.get () in
  SN.bn_karatsuba_sqr_lemma (as_seq h0 a);
  BN.bn_karatsuba_sqr len a res


inline_for_extraction noextract
val bn_sqr:
    #t:limb_t
  -> len:size_t{0 < v len /\ v len + v len <= max_size_t}
  -> a:lbignum t len
  -> res:lbignum t (len +! len) ->
  Stack unit
  (requires fun h -> live h a /\ live h res /\ disjoint res a)
  (ensures  fun h0 _ h1 -> modifies (loc res) h0 h1 /\
    bn_v h1 res == bn_v h0 a * bn_v h0 a)

let bn_sqr #t len a res =
  let h0 = ST.get () in
  SN.bn_sqr_lemma (as_seq h0 a);
  BN.bn_sqr len a res


inline_for_extraction noextract
val bn_lt_mask:
    #t:limb_t
  -> len:size_t
  -> a:lbignum t len
  -> b:lbignum t len ->
  Stack (limb t)
  (requires fun h -> live h a /\ live h b)
  (ensures  fun h0 r h1 -> modifies0 h0 h1 /\
    (if v r = 0 then bn_v h0 a >= bn_v h0 b else bn_v h0 a < bn_v h0 b))

let bn_lt_mask #t len a b =
  let h0 = ST.get () in
  SN.bn_lt_mask_lemma (as_seq h0 a) (as_seq h0 b);
  BN.bn_lt_mask len a b


inline_for_extraction noextract
val bn_from_bytes_be:
    #t:limb_t
  -> len:size_t{0 < v len /\ numbytes t * v (blocks len (size (numbytes t))) <= max_size_t}
  -> b:lbuffer uint8 len
  -> res:lbignum t (blocks len (size (numbytes t))) ->
  Stack unit
  (requires fun h -> live h b /\ live h res /\ disjoint res b)
  (ensures  fun h0 _ h1 -> modifies (loc res) h0 h1 /\
    bn_v h1 res == BSeq.nat_from_bytes_be (as_seq h0 b))

let bn_from_bytes_be #t len b res =
  let h0 = ST.get () in
  SN.bn_from_bytes_be_lemma #t (v len) (as_seq h0 b);
  BN.bn_from_bytes_be len b res


inline_for_extraction noextract
val bn_to_bytes_be:
    #t:limb_t
  -> len:size_t{0 < v len /\ numbytes t * v (blocks len (size (numbytes t))) <= max_size_t}
  -> b:lbignum t (blocks len (size (numbytes t)))
  -> res:lbuffer uint8 len ->
  Stack unit
  (requires fun h ->
    live h b /\ live h res /\ disjoint res b /\
    bn_v h b < pow2 (8 * v len))
  (ensures  fun h0 _ h1 -> modifies (loc res) h0 h1 /\
    as_seq h1 res == BSeq.nat_to_intseq_be #U8 (v len) (bn_v h0 b))

let bn_to_bytes_be #t len b res =
  let h0 = ST.get () in
  SN.bn_to_bytes_be_lemma #t (v len) (as_seq h0 b);
  BN.bn_to_bytes_be len b res


inline_for_extraction noextract
val bn_from_bytes_le:
    #t:limb_t
  -> len:size_t{0 < v len /\ numbytes t * v (blocks len (size (numbytes t))) <= max_size_t}
  -> b:lbuffer uint8 len
  -> res:lbignum t (blocks len (size (numbytes t))) ->
  Stack unit
  (requires fun h -> live h b /\ live h res /\ disjoint res b)
  (ensures  fun h0 _ h1 -> modifies (loc res) h0 h1 /\
    bn_v h1 res == BSeq.nat_from_bytes_le (as_seq h0 b))

let bn_from_bytes_le #t len b res =
  let h0 = ST.get () in
  SN.bn_from_bytes_le_lemma #t (v len) (as_seq h0 b);
  BN.bn_from_bytes_le len b res


inline_for_extraction noextract
val bn_to_bytes_le:
    #t:limb_t
  -> len:size_t{0 < v len /\ numbytes t * v (blocks len (size (numbytes t))) <= max_size_t}
  -> b:lbignum t (blocks len (size (numbytes t)))
  -> res:lbuffer uint8 len ->
  Stack unit
  (requires fun h ->
    live h b /\ live h res /\ disjoint res b /\
    bn_v h b < pow2 (8 * v len))
  (ensures  fun h0 _ h1 -> modifies (loc res) h0 h1 /\
    as_seq h1 res == BSeq.nat_to_intseq_le #U8 (v len) (bn_v h0 b))

let bn_to_bytes_le #t len b res =
  let h0 = ST.get () in
  SN.bn_to_bytes_le_lemma #t (v len) (as_seq h0 b);
  BN.bn_to_bytes_le len b res


inline_for_extraction noextract
val bn_mod_slow:
    #t:limb_t
  -> len:BN.meta_len t
  -> nBits:size_t
  -> n:lbignum t len
  -> a:lbignum t (len +! len)
  -> res:lbignum t len ->
  Stack unit
  (requires fun h ->
    live h n /\ live h a /\ live h res /\
    disjoint res n /\ disjoint res a /\

    1 < bn_v h n /\ bn_v h n % 2 = 1 /\
    v nBits / bits t < v len /\ pow2 (v nBits) < bn_v h n)
  (ensures  fun h0 r h1 -> modifies (loc res) h0 h1 /\
    bn_v h1 res == bn_v h0 a % bn_v h0 n)

let bn_mod_slow #t len nBits n a res =
  BR.mk_bn_mod_slow #t len
    (BM.bn_precomp_r2_mod_n (BN.mk_runtime_bn t len))
    (BR.bn_mod_slow_precomp (AM.mk_runtime_almost_mont len)) nBits n a res


inline_for_extraction noextract
val bn_mod_inv_prime:
    #t:limb_t
  -> len:BN.meta_len t
  -> nBits:size_t
  -> n:lbignum t len
  -> a:lbignum t len
  -> res:lbignum t len ->
  Stack unit
  (requires fun h ->
    live h n /\ live h a /\ live h res /\
    disjoint res n /\ disjoint res a /\ disjoint n a /\

    v nBits / bits t < v len /\ pow2 (v nBits) < bn_v h n /\
    bn_v h n % 2 = 1 /\ 1 < bn_v h n /\
    0 < bn_v h a /\ bn_v h a < bn_v h n /\
    FStar.Math.Euclid.is_prime (bn_v h n))
  (ensures  fun h0 r h1 -> modifies (loc res) h0 h1 /\
    bn_v h1 res * bn_v h0 a % bn_v h0 n = 1)

let bn_mod_inv_prime #t len nBits n a res =
  BI.mk_bn_mod_inv_prime len
    (BE.mk_bn_mod_exp len
      (BM.bn_precomp_r2_mod_n (BN.mk_runtime_bn t len))
      (BE.bn_mod_exp_fw_vartime_precomp (BM.mk_runtime_mont len) 4ul))
    nBits n a res


inline_for_extraction noextract
val bn_mod_exp:
    #t:limb_t
  -> len:BN.meta_len t
  -> nBits:size_t
  -> n:lbignum t len
  -> a:lbignum t len
  -> bBits:size_t{bits t * v (blocks0 bBits (size (bits t))) <= max_size_t}
  -> b:lbignum t (blocks0 bBits (size (bits t)))
  -> res:lbignum t len ->
  Stack unit
  (requires fun h ->
    live h n /\ live h a /\ live h b /\ live h res /\
    disjoint res a /\ disjoint res b /\ disjoint res n /\ disjoint n a /\

    v nBits / bits t < v len /\ pow2 (v nBits) < bn_v h n /\
    bn_v h n % 2 = 1 /\ 1 < bn_v h n /\
    bn_v h b < pow2 (v bBits) /\ bn_v h a < bn_v h n)
  (ensures  fun h0 _ h1 -> modifies (loc res) h0 h1 /\
    bn_v h1 res == Lib.NatMod.pow_mod #(bn_v h0 n) (bn_v h0 a) (bn_v h0 b))

let bn_mod_exp #t len nBits n a bBits b res =
  BE.mk_bn_mod_exp len
    (BM.bn_precomp_r2_mod_n (BN.mk_runtime_bn t len))
    (BE.bn_mod_exp_fw_vartime_precomp (BM.mk_runtime_mont len) 4ul)
    nBits n a bBits b res


inline_for_extraction noextract
val new_bn_from_bytes_be:
    #t:limb_t
  -> r:HS.rid
  -> len:size_t
  -> b:lbuffer uint8 len ->
  ST (B.buffer (limb t))
  (requires fun h ->
    live h b /\
    ST.is_eternal_region r)
  (ensures  fun h0 res h1 ->
    B.(modifies loc_none h0 h1) /\
    not (B.g_is_null res) ==> (
      0 < v len /\ numbytes t * v (blocks len (size (numbytes t))) <= max_size_t /\
      B.len res == blocks len (size (numbytes t)) /\
      B.(fresh_loc (loc_buffer res) h0 h1) /\
      B.(loc_includes (loc_region_only false r) (loc_buffer res)) /\
      as_seq h1 (res <: lbignum t (blocks len (size (numbytes t)))) ==
      Hacl.Spec.Bignum.Convert.bn_from_bytes_be (v len) (as_seq h0 b)))

let new_bn_from_bytes_be #t r len b =
  BS.new_bn_from_bytes_be r len b


inline_for_extraction noextract
val new_bn_from_bytes_le:
    #t:limb_t
  -> r:HS.rid
  -> len:size_t
  -> b:lbuffer uint8 len ->
  ST (B.buffer (limb t))
  (requires fun h ->
    live h b /\
    ST.is_eternal_region r)
  (ensures  fun h0 res h1 ->
    B.(modifies loc_none h0 h1) /\
    not (B.g_is_null res) ==> (
      0 < v len /\ numbytes t * v (blocks len (size (numbytes t))) <= max_size_t /\
      B.len res == blocks len (size (numbytes t)) /\
      B.(fresh_loc (loc_buffer res) h0 h1) /\
      B.(loc_includes (loc_region_only false r) (loc_buffer res)) /\
      as_seq h1 (res <: lbignum t (blocks len (size (numbytes t)))) ==
      Hacl.Spec.Bignum.Convert.bn_from_bytes_le (v len) (as_seq h0 b)))

let new_bn_from_bytes_le #t r len b =
  BS.new_bn_from_bytes_le r len b

//////////////////////////////////////////////////////////////////////////////
