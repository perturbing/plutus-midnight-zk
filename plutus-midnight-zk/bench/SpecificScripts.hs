module SpecificScripts (verifyScriptSpecialized) where

import Plutus.Crypto.MidnightZk.Types (Proof)
import PlutusCore (DefaultFun, DefaultUni)
import PlutusTx (CompiledCode, getPlcNoAnn, liftCodeDef, unsafeApplyCode)
import qualified UntypedPlutusCore as UPLC

verifyScriptSpecialized ::
    CompiledCode (Proof -> [Integer] -> Bool) ->
    Proof ->
    [Integer] ->
    UPLC.Program UPLC.NamedDeBruijn DefaultUni DefaultFun ()
verifyScriptSpecialized code proof pubInputs =
    getPlcNoAnn $
        code
            `unsafeApplyCode` liftCodeDef proof
            `unsafeApplyCode` liftCodeDef pubInputs
