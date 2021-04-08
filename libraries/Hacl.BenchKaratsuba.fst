module Hacl.BenchKaratsuba

open FStar.HyperStack
open FStar.HyperStack.ST
open FStar.Mul

open Lib.IntTypes
open Lib.Buffer

open Hacl.Bignum.Definitions
open Hacl.Bignum.Base
open Hacl.Impl.Lib

open Hacl.Bignum.Addition
open Hacl.Bignum.Multiplication

module ST = FStar.HyperStack.ST
module LSeq = Lib.Sequence
module B = LowStar.Buffer
module Loops = Lib.LoopCombinators
module K = Hacl.Bignum.Karatsuba

#set-options "--z3rlimit 150 --fuel 0 --ifuel 0"


inline_for_extraction noextract
let bn_karatsuba_mul_st (t:limb_t) =
    len:size_t{4 * v len <= max_size_t}
  -> a:lbignum t len
  -> b:lbignum t len
  -> tmp:lbignum t (4ul *! len)
  -> res:lbignum t (len +! len) ->
  Stack unit
  (requires fun h ->
    live h a /\ live h b /\ live h res /\ live h tmp /\
    disjoint res tmp /\ disjoint tmp a /\ disjoint tmp b /\
    disjoint res a /\ disjoint res b /\ eq_or_disjoint a b)
  (ensures  fun h0 _ h1 -> modifies (loc res |+| loc tmp) h0 h1)


inline_for_extraction noextract
val bn_karatsuba_mul_open:
    #t:limb_t
  -> (self: unit -> bn_karatsuba_mul_st t)
  -> threshold:size_t{v threshold > 0} ->
  bn_karatsuba_mul_st t

let bn_karatsuba_mul_open #t (self: unit -> bn_karatsuba_mul_st t) threshold len a b tmp res =
  let h0 = ST.get () in
  if len <. threshold || len %. 2ul =. 1ul then
    bn_mul_u len a len b res
  else begin
    let len2 = len /. 2ul in

    let a0 = sub a 0ul len2 in
    let a1 = sub a len2 len2 in

    let b0 = sub b 0ul len2 in
    let b1 = sub b len2 len2 in

    // tmp = [ t0_len2; t1_len2; ..]
    let t0 = sub tmp 0ul len2 in
    let t1 = sub tmp len2 len2 in
    let tmp' = sub tmp len len2 in

    let c0 = K.bn_sign_abs a0 a1 tmp' t0 in
    let c1 = K.bn_sign_abs b0 b1 tmp' t1 in

    // tmp = [ t0_len2; t1_len2; t23_len; ..]
    (**) let h0 = ST.get () in
    let t23 = sub tmp len len in
    let tmp1 = sub tmp (len +! len) (len +! len) in
    self () len2 t0 t1 tmp1 t23;

    let r01 = sub res 0ul len in
    let r23 = sub res len len in
    self () len2 a0 b0 tmp1 r01;
    self () len2 a1 b1 tmp1 r23;
    let c = K.bn_karatsuba_last len c0 c1 tmp res in
    () end


val bn_karatsuba_mul_uint32 : threshold:size_t{v threshold > 0} -> unit -> bn_karatsuba_mul_st U32
let rec bn_karatsuba_mul_uint32 threshold () aLen a b tmp res =
  bn_karatsuba_mul_open (bn_karatsuba_mul_uint32 threshold) threshold aLen a b tmp res


val bn_karatsuba_mul_uint64 : threshold:size_t{v threshold > 0} -> unit -> bn_karatsuba_mul_st U64
let rec bn_karatsuba_mul_uint64 threshold () aLen a b tmp res =
  bn_karatsuba_mul_open (bn_karatsuba_mul_uint64 threshold) threshold aLen a b tmp res


inline_for_extraction noextract
val bn_karatsuba_mul_: #t:limb_t -> threshold:size_t{v threshold > 0} -> bn_karatsuba_mul_st t
let bn_karatsuba_mul_ #t threshold =
  match t with
  | U32 -> bn_karatsuba_mul_uint32 threshold ()
  | U64 -> bn_karatsuba_mul_uint64 threshold ()


//TODO: pass tmp as a parameter?
inline_for_extraction noextract
val bn_karatsuba_mul:
    #t:limb_t
  -> threshold:size_t{v threshold > 0}
  -> aLen:size_t{0 < v aLen /\ 4 * v aLen <= max_size_t}
  -> a:lbignum t aLen
  -> b:lbignum t aLen
  -> res:lbignum t (aLen +! aLen) ->
  Stack unit
  (requires fun h ->
    live h a /\ live h b /\ live h res /\
    disjoint res a /\ disjoint res b /\ eq_or_disjoint a b)
  (ensures  fun h0 _ h1 -> modifies (loc res) h0 h1)

let bn_karatsuba_mul #t threshold aLen a b res =
  push_frame ();
  let tmp = create (4ul *! aLen) (uint #t 0) in
  bn_karatsuba_mul_ threshold aLen a b tmp res;
  pop_frame ()


inline_for_extraction noextract
let bn_karatsuba_sqr_st (t:limb_t) =
    len:size_t{4 * v len <= max_size_t /\ 0 < v len}
  -> a:lbignum t len
  -> tmp:lbignum t (4ul *! len)
  -> res:lbignum t (len +! len) ->
  Stack unit
  (requires fun h ->
    live h a /\ live h res /\ live h tmp /\
    disjoint res tmp /\ disjoint tmp a /\ disjoint res a)
  (ensures  fun h0 _ h1 -> modifies (loc res |+| loc tmp) h0 h1)


inline_for_extraction noextract
val bn_karatsuba_sqr_open:
    #t:limb_t
  -> (self: unit -> bn_karatsuba_sqr_st t)
  -> threshold:size_t{v threshold > 0} ->
  bn_karatsuba_sqr_st t

let bn_karatsuba_sqr_open #t (self: unit -> bn_karatsuba_sqr_st t) threshold len a tmp res =
  let h0 = ST.get () in
  if len <. threshold || len %. 2ul =. 1ul then
    bn_sqr_u len a res
  else begin
    let len2 = len /. 2ul in

    let a0 = sub a 0ul len2 in
    let a1 = sub a len2 len2 in

    let t0 = sub tmp 0ul len2 in
    let tmp' = sub tmp len len2 in
    let c0 = K.bn_sign_abs a0 a1 tmp' t0 in

    let t23 = sub tmp len len in
    let tmp1 = sub tmp (len +! len) (len +! len) in
    self () len2 t0 tmp1 t23;

    let r01 = sub res 0ul len in
    let r23 = sub res len len in
    self () len2 a0 tmp1 r01;
    self () len2 a1 tmp1 r23;
    let c = K.bn_karatsuba_last_sqr len tmp res in
    () end


val bn_karatsuba_sqr_uint32 : threshold:size_t{v threshold > 0} -> unit -> bn_karatsuba_sqr_st U32
let rec bn_karatsuba_sqr_uint32 threshold () aLen a tmp res =
  bn_karatsuba_sqr_open (bn_karatsuba_sqr_uint32 threshold) threshold aLen a tmp res


val bn_karatsuba_sqr_uint64 : threshold:size_t{v threshold > 0} -> unit -> bn_karatsuba_sqr_st U64
let rec bn_karatsuba_sqr_uint64 threshold () aLen a tmp res =
  bn_karatsuba_sqr_open (bn_karatsuba_sqr_uint64 threshold) threshold aLen a tmp res


inline_for_extraction noextract
val bn_karatsuba_sqr_: #t:limb_t -> threshold:size_t{v threshold > 0} -> bn_karatsuba_sqr_st t
let bn_karatsuba_sqr_ #t threshold =
  match t with
  | U32 -> bn_karatsuba_sqr_uint32 threshold ()
  | U64 -> bn_karatsuba_sqr_uint64 threshold ()


//TODO: pass tmp as a parameter?
inline_for_extraction noextract
val bn_karatsuba_sqr:
    #t:limb_t
  -> threshold:size_t{v threshold > 0}
  -> aLen:size_t{0 < v aLen /\ 4 * v aLen <= max_size_t}
  -> a:lbignum t aLen
  -> res:lbignum t (aLen +! aLen) ->
  Stack unit
  (requires fun h -> live h a /\ live h res /\ disjoint res a)
  (ensures  fun h0 _ h1 -> modifies (loc res) h0 h1)

let bn_karatsuba_sqr #t threshold aLen a res =
  push_frame ();
  let tmp = create (4ul *! aLen) (uint #t 0) in
  bn_karatsuba_sqr_ threshold aLen a tmp res;
  pop_frame ()
