{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module SpecificScripts.EcdsaThreshold (ecdsaThreshold) where

import Plutus.Crypto.MidnightZk.Types (Proof)
import PlutusTx (CompiledCode, compile)
import SpecializedVerifier (mkVerifierFromFiles)

ecdsaThreshold :: CompiledCode (Proof -> [Integer] -> Bool)
ecdsaThreshold = $$(compile (mkVerifierFromFiles "../test-vectors/ecdsa-threshold/ecdsa_threshold"))
