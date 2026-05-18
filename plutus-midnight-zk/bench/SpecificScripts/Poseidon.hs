{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module SpecificScripts.Poseidon (poseidon) where

import Plutus.Crypto.MidnightZk.Types (Proof)
import PlutusTx (CompiledCode, compile)
import SpecializedVerifier (mkVerifierFromFiles)

poseidon :: CompiledCode (Proof -> [Integer] -> Bool)
poseidon = $$(compile (mkVerifierFromFiles "../test-vectors/poseidon/poseidon"))
