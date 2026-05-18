{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module EquivScripts.ShaPreimage (
    shaPreimageHGate,
    shaPreimageHEval,
) where

import Plutus.Crypto.MidnightZk.Types (Proof)
import PlutusTx (CompiledCode, compile)
import SpecializedVerifier (mkHEvalFromFiles, mkHGateFromFiles)

shaPreimageHGate :: CompiledCode (Proof -> [Integer] -> Integer)
shaPreimageHGate = $$(compile (mkHGateFromFiles "../test-vectors/sha-preimage/sha_preimage"))

shaPreimageHEval :: CompiledCode (Proof -> [Integer] -> Integer)
shaPreimageHEval = $$(compile (mkHEvalFromFiles "../test-vectors/sha-preimage/sha_preimage"))
