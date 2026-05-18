{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module SpecificScripts.Ecc (ecc) where

import Plutus.Crypto.MidnightZk.Types (Proof)
import PlutusTx (CompiledCode, compile)
import SpecializedVerifier (mkVerifierFromFiles)

ecc :: CompiledCode (Proof -> [Integer] -> Bool)
ecc = $$(compile (mkVerifierFromFiles "../test-vectors/ecc/ecc"))
