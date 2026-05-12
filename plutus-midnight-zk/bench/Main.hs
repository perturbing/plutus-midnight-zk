module Main (main) where

import Scripts (verifyScript)

import Data.Aeson (Value, eitherDecodeFileStrict)
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

runBench :: String -> String -> String -> IO ()
runBench label dir name = do
    tvDir <- findTestVectors
    let base = tvDir ++ "/" ++ dir ++ "/" ++ name

    vkV <- decodeOrDie (base ++ "_plutus_vk.json")
    ccV <- decodeOrDie (base ++ "_circuit_constraint.json")
    proofV <- decodeOrDie (base ++ "_plutus_proof.json")
    rsV <- decodeOrDie (base ++ "_rotation_sets.json")
    instV <- decodeOrDie (base ++ "_plutus_instance.json")

    let vk = parsePlutusVK vkV ccV
        specs = parseRotationSets rsV
        proof = parsePlutusProof proofV
        pubInputs = parseInstance instV

    let prog = verifyScript vk specs proof pubInputs
    printf "%s\n" label
    printSizeStatistics stdout NoSize prog
  where
    decodeOrDie :: FilePath -> IO Value
    decodeOrDie fp = do
        r <- eitherDecodeFileStrict fp
        case r of
            Left err -> error $ "JSON decode error in " ++ fp ++ ": " ++ err
            Right v -> return v

main :: IO ()
main = do
    printHeader stdout
    runBench "SHA-256 preimage" "sha-preimage" "sha_preimage"
    runBench "Bitcoin Schnorr signature" "bitcoin-sig" "bitcoin_sig"
    runBench "Poseidon hash preimage" "poseidon" "poseidon"
    runBench "JubJub ECC scalar mult" "ecc" "ecc"
    runBench "Bitcoin threshold ECDSA 4-of-5" "ecdsa-threshold" "ecdsa_threshold"
    runBench "Ethereum ECDSA signature" "ethereum-sig" "ethereum_sig"
    runBench "Multi-set membership" "membership" "membership"
    runBench "Native gadget operations" "native-gadgets" "native_gadgets"
    runBench "RSA signature verification" "rsa-sig" "rsa_sig"
    runBench "Schnorr via Poseidon+JubJub" "schnorr-sig" "schnorr_sig"
