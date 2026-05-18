module EquivCheck (runEquivCheck) where

import BenchCommon (evalUplcInteger)
import Data.Aeson (Value, eitherDecodeFileStrict)
import Plutus.Crypto.BlsUtils (unScalar)
import Plutus.Crypto.MidnightZk.JsonParser (
    parseInstance,
    parsePlutusProof,
    parsePlutusVK,
 )
import Plutus.Crypto.MidnightZk.Types (Proof)
import Plutus.Crypto.MidnightZk.Verifier (
    computeHEval,
    computeHGate,
    computeXnMinusOne,
    deriveTranscript,
 )
import PlutusTx (CompiledCode, getPlcNoAnn, liftCodeDef, unsafeApplyCode)
import qualified UntypedPlutusCore as UPLC

decodeOrDie :: FilePath -> IO Value
decodeOrDie fp = do
    r <- eitherDecodeFileStrict fp
    case r of
        Left err -> error $ "JSON decode error in " ++ fp ++ ": " ++ err
        Right v -> return v

applySubVerifier ::
    CompiledCode (Proof -> [Integer] -> Integer) ->
    Proof ->
    [Integer] ->
    UPLC.Program UPLC.NamedDeBruijn UPLC.DefaultUni UPLC.DefaultFun ()
applySubVerifier code proof pubInputs =
    getPlcNoAnn $
        code
            `unsafeApplyCode` liftCodeDef proof
            `unsafeApplyCode` liftCodeDef pubInputs

checkEq :: String -> Integer -> Integer -> IO ()
checkEq label pure_ uplc_
    | pure_ == uplc_ = putStrLn $ "  PASS " ++ label
    | otherwise      = error $
        "  FAIL " ++ label ++
        "\n    pure = " ++ show pure_ ++
        "\n    uplc = " ++ show uplc_

-- | Compare hGate and hEval from TH-generated UPLC against pure Haskell for one circuit.
runEquivCheck ::
    String ->
    String ->
    String ->
    CompiledCode (Proof -> [Integer] -> Integer) ->
    CompiledCode (Proof -> [Integer] -> Integer) ->
    IO ()
runEquivCheck tvDir dir name hGateCode hEvalCode = do
    let base = tvDir ++ "/" ++ dir ++ "/" ++ name
    vkV    <- decodeOrDie (base ++ "_plutus_vk.json")
    ccV    <- decodeOrDie (base ++ "_circuit_constraint.json")
    proofV <- decodeOrDie (base ++ "_plutus_proof.json")
    instV  <- decodeOrDie (base ++ "_plutus_instance.json")

    let vk        = parsePlutusVK vkV ccV
        proof     = parsePlutusProof proofV
        pubInputs = parseInstance instV

    let (x, y, theta, beta, gamma, trashChal, _, _, _, _) =
            deriveTranscript vk proof pubInputs
        xnMinusOne = computeXnMinusOne vk x

    let pureHGate = unScalar (computeHGate vk proof pubInputs x y)
        pureHEval = unScalar (computeHEval vk proof pubInputs x xnMinusOne y theta beta gamma trashChal)

    let uplcHGate = evalUplcInteger (applySubVerifier hGateCode proof pubInputs)
        uplcHEval = evalUplcInteger (applySubVerifier hEvalCode proof pubInputs)

    checkEq "hGate (genHornerFold + genEvalGate)" pureHGate uplcHGate
    checkEq "hEval (full constraint sum)"          pureHEval uplcHEval
