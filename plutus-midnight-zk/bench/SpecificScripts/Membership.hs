{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module SpecificScripts.Membership (membership) where

import Plutus.Crypto.MidnightZk.Types (Proof)
import PlutusTx (CompiledCode, compile)
import SpecializedVerifier (mkVerifierFromFiles)

membership :: CompiledCode (Proof -> [Integer] -> Bool)
membership = $$(compile (mkVerifierFromFiles "../test-vectors/membership/membership"))
