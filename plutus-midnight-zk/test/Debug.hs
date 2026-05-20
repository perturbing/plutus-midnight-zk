module Main (main) where

import Data.Aeson (Value, eitherDecodeFileStrict)
import Data.List (intercalate)
import Numeric (showHex)
import Plutus.Crypto.BlsUtils (Scalar (..), bls12_381_scalar_prime, mkScalar)
import Plutus.Crypto.MidnightZk.JsonParser (
    parseInstance,
    parsePlutusProof,
    parsePlutusVK,
    parseRotationSets,
 )
import Plutus.Crypto.MidnightZk.Transcript
import Plutus.Crypto.BlsUtils (Scalar (..))
import Plutus.Crypto.MidnightZk.Types
import Plutus.Crypto.MidnightZk.Verifier
import PlutusTx.Builtins (
    BuiltinByteString,
    bls12_381_G1_compressed_zero,
    integerToByteString,
 )
import GHC.ByteOrder (ByteOrder (..))
import qualified Data.ByteString as BS

decodeOrDie :: FilePath -> IO Value
decodeOrDie fp = do
    r <- eitherDecodeFileStrict fp
    case r of
        Left err -> error $ "JSON decode error in " ++ fp ++ ": " ++ err
        Right v  -> return v

hexScalar :: Scalar -> String
hexScalar (Scalar n) = showHex n ""

main :: IO ()
main = do
    let base = "../test-vectors/poseidon/poseidon"
    vkV    <- decodeOrDie (base ++ "_plutus_vk.json")
    ccV    <- decodeOrDie (base ++ "_circuit_constraint.json")
    proofV <- decodeOrDie (base ++ "_plutus_proof.json")
    rsV    <- decodeOrDie (base ++ "_rotation_sets.json")
    instV  <- decodeOrDie (base ++ "_plutus_instance.json")

    let vk       = parsePlutusVK vkV ccV
        proof    = parsePlutusProof proofV
        specs    = parseRotationSets rsV proof
        pubInputs = parseInstance instV

    putStrLn $ "num specs: " ++ show (length specs)
    putStrLn $ "num slots in spec 0: " ++ show (length (rssSlots (head specs)))
    putStrLn $ "rotations spec 0: " ++ show (rssRotations (head specs))

    putStrLn $ "prfAdviceEvals len: " ++ show (length (prfAdviceEvals proof))
    putStrLn $ "prfFixedEvals len: " ++ show (length (prfFixedEvals proof))
    putStrLn $ "prfPermSigmaEvals len: " ++ show (length (prfPermSigmaEvals proof))
    putStrLn $ "prfPermProdEvals len: " ++ show (length (prfPermProdEvals proof))
    putStrLn $ "prfLogupEvals len: " ++ show (length (prfLogupEvals proof))
    putStrLn $ "prfDummyEvals len: " ++ show (length (prfDummyEvals proof))
    putStrLn $ "prfQEvalsOnX3 len: " ++ show (length (prfQEvalsOnX3 proof))

    putStrLn $ "vkSimpleSelectorMask len: " ++ show (length (vkSimpleSelectorMask vk))
    putStrLn $ "vkFixedComs len: " ++ show (length (vkFixedComs vk))
    putStrLn $ "vkPermSigmaComs len: " ++ show (length (vkPermSigmaComs vk))

    -- Simulate transcript to check challenges
    let cfg  = vkConfig vk
        omg  = ccOmega cfg
        omgInv = ccOmegaInv cfg

    let td0 = initTranscript (vkTranscriptRepr vk)
    let td1 = td0 <> bls12_381_G1_compressed_zero
    let td2 = absorb td1 (integerToByteString LittleEndian 32 (toInteger (length pubInputs)))
    let td3 = foldl (\td n -> absorb td (integerToByteString LittleEndian 32 n)) td2 pubInputs
    let td4 = foldl (<>) td3 (prfAdviceComs proof)
    let (theta, td4s) = squeeze td4
    putStrLn $ "theta = " ++ hexScalar theta

    let td5 = foldl (<>) td4s (prfLookupMultComs proof)
    let (beta, td5b) = squeeze td5
    let (gamma, td5g) = squeeze td5b
    putStrLn $ "beta  = " ++ hexScalar beta
    putStrLn $ "gamma = " ++ hexScalar gamma

    let td6 = foldl (<>) td5g (prfPermProdComs proof)
    let td7 = foldl (\td (helpers, accum) -> foldl (<>) td helpers <> accum)
                td6
                (zip (prfLookupHelperComs proof) (prfLookupAccumComs proof))
    let (trashChal, td7s) = squeeze td7
    putStrLn $ "trashChal = " ++ hexScalar trashChal

    let td7t = foldl (<>) td7s (prfTrashComs proof)
    let (y, td8s) = squeeze td7t
    putStrLn $ "y = " ++ hexScalar y

    let td9 = foldl (<>) td8s (prfHComs proof)
    let (x, td9s) = squeeze td9
    putStrLn $ "x = " ++ hexScalar x

    let td9inst = absorb td9s (integerToByteString LittleEndian 32 0)

    let chkS n = unScalar (mkScalar n)
          where mkScalar v = Scalar $ v `mod` bls12_381_scalar_prime
    let fixForTranscript =
            concatMap
                (\(isSel, v) -> if isSel then [] else [v])
                (zip (vkSimpleSelectorMask vk) (map chkS (prfFixedEvals proof)))

    let allEvals =
            map chkS (prfAdviceEvals proof)
                ++ fixForTranscript
                ++ map chkS (prfPermSigmaEvals proof)
                ++ map chkS (prfPermProdEvals proof)
                ++ map chkS (prfLogupEvals proof)
                ++ map chkS (prfTrashEvals proof)
                ++ map chkS (prfDummyEvals proof)

    putStrLn $ "allEvals len: " ++ show (length allEvals)

    let td10 = foldl (\td n -> absorb td (integerToByteString LittleEndian 32 n)) td9inst allEvals
    let (x1, td10s) = squeeze td10
    let (x2, td10ss) = squeeze td10s
    putStrLn $ "x1 = " ++ hexScalar x1
    putStrLn $ "x2 = " ++ hexScalar x2

    let td11 = td10ss <> prfFCom proof
    let (x3, td11s) = squeeze td11
    putStrLn $ "x3 = " ++ hexScalar x3

    let td12 = foldl (\td n -> absorb td (integerToByteString LittleEndian 32 n)) td11s (prfQEvalsOnX3 proof)
    let (x4, _) = squeeze td12
    putStrLn $ "x4 = " ++ hexScalar x4

    -- ── Debug: intermediate GWC values ──────────────────────────────────────
    -- Scalar arithmetic using raw Integer ops to avoid PlutusTx typeclass
    -- conflicts in this non-NoImplicitPrelude module.
    let q = bls12_381_scalar_prime
    let mpow b e
          | e == 0    = 1
          | even e    = let h = mpow b (e `div` 2) in (h * h) `mod` q
          | otherwise = (b * mpow b (e - 1)) `mod` q
        smulS (Scalar a) (Scalar b) = Scalar ((a * b) `mod` q)
        ssubS (Scalar a) (Scalar b) = Scalar ((a - b) `mod` q)
    let n      = ccDomainSize (vkConfig vk)
        omgS   = ccOmega (vkConfig vk)
        omgLs  = ccOmegaLast (vkConfig vk)
        hSplit     = Scalar (mpow (unScalar x) (n - 1))
        xnMinusOne = ssubS (smulS hSplit x) (Scalar 1)
        xNextS     = smulS x omgS
        xLastS     = smulS x omgLs

    putStrLn $ "hSplit = " ++ hexScalar hSplit
    putStrLn $ "xnMinusOne = " ++ hexScalar xnMinusOne

    let (hEval, linComEval, selColData) = computeHEval vk proof pubInputs x xnMinusOne y theta beta gamma trashChal
    putStrLn $ "hEval = " ++ hexScalar hEval
    putStrLn $ "linComEval = " ++ hexScalar linComEval
    putStrLn $ "selColData: " ++ show (length selColData) ++ " entries"
    mapM_ (\(ci, ck) -> putStrLn $ "  col " ++ show ci ++ " c_k = " ++ hexScalar ck) selColData

    let rotSets = assembleRotationSets vk proof specs x x1 xNextS xLastS linComEval hSplit xnMinusOne selColData
    putStrLn $ "numRotSets = " ++ show (length rotSets)
    mapM_ (\(ri, rs) -> do
        putStrLn $ "  RotSet " ++ show (ri :: Int) ++ " qEvalsAtPts:"
        mapM_ (\(i, v) -> putStrLn $ "    [" ++ show (i :: Int) ++ "] " ++ hexScalar v)
              (zip [0..] (rsQEvalsAtPts rs))
        ) (zip [0..] rotSets)

    let proverQEs = map mkScalar (prfQEvalsOnX3 proof)
    putStrLn "proverQEs:"
    mapM_ (\(i, v) -> putStrLn $ "  [" ++ show (i :: Int) ++ "] " ++ hexScalar v)
          (zip [0..] proverQEs)

    putStrLn "r(x3) and diff per rotation set:"
    mapM_ (\(ri, rs, qEi) -> do
        let rAtX3 = lagrange (rsPoints rs) (rsQEvalsAtPts rs) x3
            diff  = ssubS qEi rAtX3
        putStrLn $ "  RotSet " ++ show (ri :: Int)
        putStrLn $ "    r(x3)          = " ++ hexScalar rAtX3
        putStrLn $ "    qE - r(x3)     = " ++ hexScalar diff
        ) (zip3 [0..] rotSets proverQEs)

    -- Check if verify passes
    let result = verify vk specs proof pubInputs
    putStrLn $ "verify result: " ++ show result
