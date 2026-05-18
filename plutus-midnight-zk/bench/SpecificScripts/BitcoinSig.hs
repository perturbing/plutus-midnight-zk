{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module SpecificScripts.BitcoinSig (bitcoinSig) where

import Plutus.Crypto.MidnightZk.Types (Proof)
import PlutusTx (CompiledCode, compile)
import SpecializedVerifier (mkVerifierFromFiles)

bitcoinSig :: CompiledCode (Proof -> [Integer] -> Bool)
bitcoinSig = $$(compile (mkVerifierFromFiles "../test-vectors/bitcoin-sig/bitcoin_sig"))
