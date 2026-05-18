{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module SpecificScripts.ShaPreimage (shaPreimage) where

import Plutus.Crypto.MidnightZk.Types (Proof)
import PlutusTx (CompiledCode, compile)
import SpecializedVerifier (mkVerifierFromFiles)

shaPreimage :: CompiledCode (Proof -> [Integer] -> Bool)
shaPreimage = $$(compile (mkVerifierFromFiles "../test-vectors/sha-preimage/sha_preimage"))
