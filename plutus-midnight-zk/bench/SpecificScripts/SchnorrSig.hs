{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module SpecificScripts.SchnorrSig (schnorrSig) where

import Plutus.Crypto.MidnightZk.Types (Proof)
import PlutusTx (CompiledCode, compile)
import SpecializedVerifier (mkVerifierFromFiles)

schnorrSig :: CompiledCode (Proof -> [Integer] -> Bool)
schnorrSig = $$(compile (mkVerifierFromFiles "../test-vectors/schnorr-sig/schnorr_sig"))
