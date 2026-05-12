{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}
{-# OPTIONS_GHC -fno-full-laziness #-}
{-# OPTIONS_GHC -fno-ignore-interface-pragmas #-}
{-# OPTIONS_GHC -fno-omit-interface-pragmas #-}
{-# OPTIONS_GHC -fno-spec-constr #-}
{-# OPTIONS_GHC -fno-specialise #-}
{-# OPTIONS_GHC -fno-strictness #-}
{-# OPTIONS_GHC -fno-unbox-small-strict-fields #-}
{-# OPTIONS_GHC -fno-unbox-strict-fields #-}

module Scripts (verifyScript) where

import Plutus.Crypto.MidnightZk.Types (Proof, RotationSetSpec, VerifyingKey)
import Plutus.Crypto.MidnightZk.Verifier (verify)
import PlutusCore (DefaultFun, DefaultUni)
import PlutusTx (compile, getPlcNoAnn, liftCodeDef, unsafeApplyCode)
import qualified UntypedPlutusCore as UPLC

verifyScript ::
    VerifyingKey ->
    [RotationSetSpec] ->
    Proof ->
    [Integer] ->
    UPLC.Program UPLC.NamedDeBruijn DefaultUni DefaultFun ()
verifyScript vk specs proof pubInputs =
    getPlcNoAnn $
        $$(compile [||verify||])
            `unsafeApplyCode` liftCodeDef vk
            `unsafeApplyCode` liftCodeDef specs
            `unsafeApplyCode` liftCodeDef proof
            `unsafeApplyCode` liftCodeDef pubInputs
