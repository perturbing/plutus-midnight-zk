{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-full-laziness #-}
{-# OPTIONS_GHC -fno-ignore-interface-pragmas #-}
{-# OPTIONS_GHC -fno-omit-interface-pragmas #-}
{-# OPTIONS_GHC -fno-spec-constr #-}
{-# OPTIONS_GHC -fno-specialise #-}
{-# OPTIONS_GHC -fno-strictness #-}
{-# OPTIONS_GHC -fno-unbox-small-strict-fields #-}
{-# OPTIONS_GHC -fno-unbox-strict-fields #-}

{- | PlutusBlake2b transcript for the midnight-zk Halo2 GWC verifier.

The transcript implements Fiat-Shamir challenge derivation. It is an
accumulated byte buffer; hashing occurs only at squeeze time.

= Protocol

  * 'absorb': append bytes to the current state (no hashing).
  * 'squeeze': hash the current state with blake2b_256; the challenge is
    that hash interpreted as a little-endian integer reduced mod q; the
    state is replaced by the 32-byte hash output.

State replacement (rather than appending) after a squeeze ensures
consecutive squeezes produce distinct, independent challenges:
blake2b_256(h) ≠ h with overwhelming probability.

This matches the transcript used in the midnight-zk Rust prover:

> ProofTranscript { transcript_data: vec![], .. }   -- start empty
> fn absorb(&mut self, data: &[u8]) { self.transcript_data.extend(data); }
> fn squeeze_fq(&mut self) -> Fq {
>     let h = blake2b_256(&self.transcript_data);
>     self.transcript_data = h.to_vec();   -- replace, not append
>     LE_int(h) mod q
> }
-}
module Plutus.Crypto.MidnightZk.Transcript (
    -- * Transcript type
    Transcript,

    -- * Transcript operations
    initTranscript,
    absorb,
    absorbScalar,
    squeeze,
) where

import GHC.ByteOrder (ByteOrder (..))
import Plutus.Crypto.BlsUtils (Scalar (..), bls12_381_scalar_prime)
import PlutusTx.Builtins (
    BuiltinByteString,
    blake2b_256,
    byteStringToInteger,
    integerToByteString,
 )
import PlutusTx.Prelude (
    modulo,
    ($),
    (<>),
 )

-- ---------------------------------------------------------------------------
-- Transcript type
-- ---------------------------------------------------------------------------

{- | Transcript state: an accumulated byte buffer. Starts as the VK identity
bytes and grows as commitments and evaluations are appended. Only hashed
(and thereby reset to 32 bytes) at each 'squeeze'.
-}
type Transcript = BuiltinByteString

-- ---------------------------------------------------------------------------
-- Transcript operations
-- ---------------------------------------------------------------------------

{- | Initialise the transcript with the 32-byte verifying-key identity bytes.
This binds all subsequent challenges to the specific circuit.

The VK repr is used directly as the initial accumulated state (no hashing).
-}
{-# INLINEABLE initTranscript #-}
initTranscript :: BuiltinByteString -> Transcript
initTranscript vkRepr = vkRepr

{- | Absorb arbitrary bytes into the transcript by appending them.
No hashing occurs; hashing is deferred to 'squeeze'.
-}
{-# INLINEABLE absorb #-}
absorb :: Transcript -> BuiltinByteString -> Transcript
absorb state bytes = state <> bytes

-- | Absorb a scalar field element as a 32-byte little-endian integer.
{-# INLINEABLE absorbScalar #-}
absorbScalar :: Transcript -> Scalar -> Transcript
absorbScalar state (Scalar n) =
    absorb state (integerToByteString LittleEndian 32 n)

{- | Squeeze one challenge scalar from the transcript.

Returns the challenge and the new transcript state.

The challenge is blake2b_256 of the current state, interpreted as a
little-endian integer reduced modulo the BLS12-381 scalar prime q.

The state is replaced with the 32-byte hash output (not appended), so
consecutive squeezes produce independent challenges.
-}
{-# INLINEABLE squeeze #-}
squeeze :: Transcript -> (Scalar, Transcript)
squeeze state =
    let hash = blake2b_256 state
        challenge = Scalar $ byteStringToInteger LittleEndian hash `modulo` bls12_381_scalar_prime
     in (challenge, hash)
