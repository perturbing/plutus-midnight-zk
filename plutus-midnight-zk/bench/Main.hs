module Main (main) where

import Scripts (verifyScript)
import SpecificScripts (verifyScriptSpecialized)
import SpecificScripts.BitcoinSig (bitcoinSig)
import SpecificScripts.Ecc (ecc)
import SpecificScripts.EcdsaThreshold (ecdsaThreshold)
import SpecificScripts.EthereumSig (ethereumSig)
import SpecificScripts.Membership (membership)
import SpecificScripts.NativeGadgets (nativeGadgets)
import SpecificScripts.Poseidon (poseidon)
import SpecificScripts.RsaSig (rsaSig)
import SpecificScripts.SchnorrSig (schnorrSig)
import SpecificScripts.ShaPreimage (shaPreimage)

import EquivCheck (runEquivCheck)
import EquivScripts.ShaPreimage (shaPreimageHEval, shaPreimageHGate)

import Data.Aeson (Value, eitherDecodeFileStrict)
import Plutus.Crypto.MidnightZk.Types (Proof, RotationSetSpec, VerifyingKey)
import PlutusTx (CompiledCode)
import System.Directory (doesDirectoryExist)
import System.IO (stdout)
import Text.Printf (printf)

import BenchCommon (TestSize (..), printHeader, printSizeStatistics)

import Plutus.Crypto.MidnightZk.JsonParser (
    parseInstance,
    parsePlutusProof,
    parsePlutusVK,
    parseRotationSets,
 )

findTestVectors :: IO FilePath
findTestVectors = do
    here <- doesDirectoryExist "test-vectors"
    return $ if here then "test-vectors" else "../test-vectors"

decodeOrDie :: FilePath -> IO Value
decodeOrDie fp = do
    r <- eitherDecodeFileStrict fp
    case r of
        Left err -> error $ "JSON decode error in " ++ fp ++ ": " ++ err
        Right v -> return v

loadVkSpecs :: FilePath -> String -> String -> IO (VerifyingKey, [RotationSetSpec])
loadVkSpecs tvDir dir name = do
    let base = tvDir ++ "/" ++ dir ++ "/" ++ name
    vkV <- decodeOrDie (base ++ "_plutus_vk.json")
    ccV <- decodeOrDie (base ++ "_circuit_constraint.json")
    rsV <- decodeOrDie (base ++ "_rotation_sets.json")
    return (parsePlutusVK vkV ccV, parseRotationSets rsV)

loadProof :: FilePath -> String -> String -> IO (Proof, [Integer])
loadProof tvDir dir name = do
    let base = tvDir ++ "/" ++ dir ++ "/" ++ name
    proofV <- decodeOrDie (base ++ "_plutus_proof.json")
    instV <- decodeOrDie (base ++ "_plutus_instance.json")
    return (parsePlutusProof proofV, parseInstance instV)

-- Generic: VK+specs passed as runtime arguments.
runBenchGeneric :: String -> String -> String -> IO ()
runBenchGeneric label dir name = do
    tvDir <- findTestVectors
    (vk, specs) <- loadVkSpecs tvDir dir name
    (proof, pubInputs) <- loadProof tvDir dir name
    let prog = verifyScript vk specs proof pubInputs
    printf "%s\n" label
    printSizeStatistics stdout NoSize prog

-- Fully specialized: structure unrolled and VK bytes inlined at compile time.
runBenchSpecialized :: String -> CompiledCode (Proof -> [Integer] -> Bool) -> String -> String -> IO ()
runBenchSpecialized label code dir name = do
    tvDir <- findTestVectors
    (proof, pubInputs) <- loadProof tvDir dir name
    let prog = verifyScriptSpecialized code proof pubInputs
    printf "%s\n" label
    printSizeStatistics stdout NoSize prog

main :: IO ()
main = do
    -- ── Generic baseline ─────────────────────────────────────────────────────
    printf "=== Generic verifier (VK+specs at runtime) ===\n"
    printHeader stdout
    runBenchGeneric "SHA-256 preimage" "sha-preimage" "sha_preimage"

    -- ── Fully specialized circuits ───────────────────────────────────────────
    printf "\n=== Fully specialized verifiers (all loops unrolled + VK bytes inlined) ===\n"
    printHeader stdout
    runBenchSpecialized "SHA-256 preimage" shaPreimage "sha-preimage" "sha_preimage"
    runBenchSpecialized "Bitcoin Schnorr sig" bitcoinSig "bitcoin-sig" "bitcoin_sig"
    runBenchSpecialized "Poseidon hash preimage" poseidon "poseidon" "poseidon"
    runBenchSpecialized "JubJub ECC scalar mult" ecc "ecc" "ecc"
    runBenchSpecialized "Bitcoin threshold ECDSA 4-5" ecdsaThreshold "ecdsa-threshold" "ecdsa_threshold"
    runBenchSpecialized "Ethereum ECDSA sig" ethereumSig "ethereum-sig" "ethereum_sig"
    runBenchSpecialized "Multi-set membership" membership "membership" "membership"
    runBenchSpecialized "Native gadget ops" nativeGadgets "native-gadgets" "native_gadgets"
    runBenchSpecialized "RSA signature" rsaSig "rsa-sig" "rsa_sig"
    runBenchSpecialized "Schnorr via Poseidon+JubJub" schnorrSig "schnorr-sig" "schnorr_sig"

    -- ── Per-sub-generator equivalence checks ─────────────────────────────────
    printf "\n=== Sub-generator equivalence checks (TH UPLC vs pure Haskell) ===\n"
    tvDir <- findTestVectors
    printf "SHA-256 preimage:\n"
    runEquivCheck tvDir "sha-preimage" "sha_preimage" shaPreimageHGate shaPreimageHEval
    printf "All equivalence checks passed.\n"
