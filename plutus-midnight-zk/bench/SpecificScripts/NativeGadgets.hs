{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module SpecificScripts.NativeGadgets (nativeGadgets) where

import Plutus.Crypto.MidnightZk.Types (Proof)
import PlutusTx (CompiledCode, compile)
import SpecializedVerifier (mkVerifierFromFiles)

nativeGadgets :: CompiledCode (Proof -> [Integer] -> Bool)
nativeGadgets = $$(compile (mkVerifierFromFiles "../test-vectors/native-gadgets/native_gadgets"))
