{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module SpecificScripts.RsaSig (rsaSig) where

import Plutus.Crypto.MidnightZk.Types (Proof)
import PlutusTx (CompiledCode, compile)
import SpecializedVerifier (mkVerifierFromFiles)

rsaSig :: CompiledCode (Proof -> [Integer] -> Bool)
rsaSig = $$(compile (mkVerifierFromFiles "../test-vectors/rsa-sig/rsa_sig"))
