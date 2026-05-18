{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module SpecificScripts.EthereumSig (ethereumSig) where

import Plutus.Crypto.MidnightZk.Types (Proof)
import PlutusTx (CompiledCode, compile)
import SpecializedVerifier (mkVerifierFromFiles)

ethereumSig :: CompiledCode (Proof -> [Integer] -> Bool)
ethereumSig = $$(compile (mkVerifierFromFiles "../test-vectors/ethereum-sig/ethereum_sig"))
