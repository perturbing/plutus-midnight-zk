{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# OPTIONS_GHC -fno-full-laziness #-}
{-# OPTIONS_GHC -fno-ignore-interface-pragmas #-}
{-# OPTIONS_GHC -fno-omit-interface-pragmas #-}
{-# OPTIONS_GHC -fno-spec-constr #-}
{-# OPTIONS_GHC -fno-specialise #-}
{-# OPTIONS_GHC -fno-strictness #-}
{-# OPTIONS_GHC -fno-unbox-small-strict-fields #-}
{-# OPTIONS_GHC -fno-unbox-strict-fields #-}

module Plutus.Crypto.BlsUtils (
    bls12_381_base_prime,
    bls12_381_scalar_prime,
    bls12_381_scalar_delta,
    MultiplicativeGroup (..),
    -- Scalar type and functions
    Scalar (..),
    mkScalar,
    negateScalar,
) where

import PlutusTx (makeIsDataIndexed, makeLift)
import PlutusTx.Builtins (
    BuiltinBLS12_381_G1_Element,
    BuiltinBLS12_381_G2_Element,
    bls12_381_G1_add,
    bls12_381_G1_compressed_zero,
    bls12_381_G1_neg,
    bls12_381_G1_scalarMul,
    bls12_381_G1_uncompress,
    bls12_381_G2_add,
    bls12_381_G2_compressed_zero,
    bls12_381_G2_neg,
    bls12_381_G2_scalarMul,
    bls12_381_G2_uncompress,
    expModInteger,
 )
import PlutusTx.Numeric (
    AdditiveGroup (..),
    AdditiveMonoid (..),
    AdditiveSemigroup (..),
    Module (..),
    MultiplicativeMonoid (..),
    MultiplicativeSemigroup (..),
 )
import PlutusTx.Prelude (
    Bool (..),
    Eq (..),
    Integer,
    Ord ((<), (<=)),
    error,
    modulo,
    ($),
    (&&),
 )
import qualified Prelude as Haskell

-- In this module, we setup the two prime order fields for BLS12-381.
-- as the type Fp/Fp2 (base points) and Scalar.
-- Note that for safety, both the Scalar and Fp constructors
-- are not exposed. Instead, the mkScalar and mkFp suffice,
-- which fail in a script if an integer provided that is negative.

-- The prime order of the generator in the field. So, g^order = id,
bls12_381_scalar_prime :: Integer
bls12_381_scalar_prime = 52435875175126190479447740508185965837690552500527637822603658699938581184513

-- The prime of the base field. So for a g on the curve, its
-- x and y coordinates are elements of the base field.
bls12_381_base_prime :: Integer
bls12_381_base_prime = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787

{- | Coset generator for the BLS12-381 scalar field permutation argument.
δ = 7^{2^S} mod q, where:
  - 7 is the multiplicative generator of F_q* (and a quadratic nonresidue),
  - S = 32 is the 2-adicity (q − 1 = T · 2^32 with T odd),
  - q = 'bls12_381_scalar_prime'.
  - T = 12208678567578594777604504606729831043093128246378069236549469339647

F_q* is cyclic of order q − 1 = T · 2^32. Since gcd(T, 2^32) = 1, the Chinese
Remainder Theorem gives an internal direct product decomposition:
  F_q* ≅ ⟨ω⟩ × ⟨δ⟩
where ω = 7^T has order 2^32 (the roots of unity) and δ = 7^{2^32} has order T
(the odd-part subgroup).  The two subgroups share only the identity {1}.

Let H = ⟨ω^{2^S/n}⟩ be the evaluation domain of size n = 2^k.  The cosets
δ^0·H, δ^1·H, δ^2·H, … are pairwise disjoint: if δ^i·ω^a = δ^j·ω^b then
δ^{i−j} = ω^{b−a}, forcing both sides to be 1 (left side has odd order, right
side has 2-power order), so i ≡ j and a ≡ b.  The Halo2 permutation argument
exploits this: column i's coset shift δ^i gives each cell (column i, row j) the
unique field identity δ^i · ω^j, so no prover can conflate values across columns.

This is a constant of the field definition — it does not depend on the circuit
design or the trusted setup.
-}
bls12_381_scalar_delta :: Integer
bls12_381_scalar_delta = 3793952369011177517951424454785176000433849974408744014172535497121832470999

newtype Scalar = Scalar {unScalar :: Integer} deriving (Haskell.Show)
makeLift ''Scalar
makeIsDataIndexed ''Scalar [('Scalar, 0)]

-- Exclude for safety negative integers and integers large/equal
-- to the field prime. This is the primary interface to work with
-- the Scalar type onchain. This is for security reasons,
-- to make sure provided objects are field elements.
{-# INLINEABLE mkScalar #-}
mkScalar :: Integer -> Scalar
mkScalar n = if 0 <= n && n < bls12_381_scalar_prime then Scalar n else error ()

instance Eq Scalar where
    {-# INLINEABLE (==) #-}
    Scalar a == Scalar b = a == b

instance AdditiveSemigroup Scalar where
    {-# INLINEABLE (+) #-}
    (+) (Scalar a) (Scalar b) = Scalar $ (a + b) `modulo` bls12_381_scalar_prime

instance AdditiveMonoid Scalar where
    {-# INLINEABLE zero #-}
    zero = Scalar 0

-- Note that PlutusTx.Numeric implements negate for an additive group. This is
-- canonically defined as zero - x. But not that a more efficient way to do it
-- in plutus is by calculating it as: inv (Scalar x) = Scalar $ bls12_381_scalar_prime - x
-- saving a modulo operation (not considering 0 here).
instance AdditiveGroup Scalar where
    {-# INLINEABLE (-) #-}
    (-) (Scalar a) (Scalar b) = Scalar $ (a - b) `modulo` bls12_381_scalar_prime

-- This is a more efficient way to calculate the additive inverse
-- Be sure that you are using this one instead of the one from PlutusTx.Numeric.
{-# INLINEABLE negateScalar #-}
negateScalar :: Scalar -> Scalar
negateScalar (Scalar x) = if x == 0 then Scalar 0 else Scalar $ bls12_381_scalar_prime - x

instance MultiplicativeSemigroup Scalar where
    {-# INLINEABLE (*) #-}
    (*) (Scalar a) (Scalar b) = Scalar $ (a * b) `modulo` bls12_381_scalar_prime

instance MultiplicativeMonoid Scalar where
    {-# INLINEABLE one #-}
    one = Scalar 1

-- Since plutus 1.9, PlutusTx.Numeric does not implement a Multiplicative group anymore.
-- But since we use a field, multiplicative inversion is well-defined if we exclude 0.
-- We also implement the reciprocal (the multiplicative inverse of an element in the group).
-- For the additive group, there is negate function in PlutusTx.Numeric for the additive inverse.
class (MultiplicativeMonoid a) => MultiplicativeGroup a where
    div :: a -> a -> a
    recip :: a -> a

-- In math this is b^a mod p, where b is of type scalar and a any integer
instance Module Integer Scalar where
    {-# INLINEABLE scale #-}
    scale :: Integer -> Scalar -> Scalar
    scale e b = Scalar $ expModInteger (unScalar b) e bls12_381_scalar_prime

instance MultiplicativeGroup Scalar where
    {-# INLINEABLE recip #-}
    recip (Scalar a) = Scalar $ expModInteger a (-1) bls12_381_scalar_prime
    {-# INLINEABLE div #-}
    div a b = a * recip b

-- Implementing an additive group for both the G1 and G2 elements.

instance AdditiveSemigroup BuiltinBLS12_381_G1_Element where
    {-# INLINEABLE (+) #-}
    (+) = bls12_381_G1_add

instance AdditiveMonoid BuiltinBLS12_381_G1_Element where
    {-# INLINEABLE zero #-}
    zero = bls12_381_G1_uncompress bls12_381_G1_compressed_zero

instance AdditiveGroup BuiltinBLS12_381_G1_Element where
    {-# INLINEABLE (-) #-}
    (-) a b = a + bls12_381_G1_neg b

instance Module Scalar BuiltinBLS12_381_G1_Element where
    {-# INLINEABLE scale #-}
    scale (Scalar a) = bls12_381_G1_scalarMul a

instance AdditiveSemigroup BuiltinBLS12_381_G2_Element where
    {-# INLINEABLE (+) #-}
    (+) = bls12_381_G2_add

instance AdditiveMonoid BuiltinBLS12_381_G2_Element where
    {-# INLINEABLE zero #-}
    zero = bls12_381_G2_uncompress bls12_381_G2_compressed_zero

instance AdditiveGroup BuiltinBLS12_381_G2_Element where
    {-# INLINEABLE (-) #-}
    (-) a b = a + bls12_381_G2_neg b

instance Module Scalar BuiltinBLS12_381_G2_Element where
    {-# INLINEABLE scale #-}
    scale (Scalar a) = bls12_381_G2_scalarMul a
