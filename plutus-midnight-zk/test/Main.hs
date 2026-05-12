module Main (main) where

import Control.Exception (SomeException, evaluate, try)
import Data.Aeson (Value, eitherDecodeFileStrict)
import Data.Bits (xor)
import Plutus.Crypto.MidnightZk.JsonParser (
    parseInstance,
    parsePlutusProof,
    parsePlutusVK,
    parseRotationSets,
 )
import Plutus.Crypto.MidnightZk.Types (Proof (..))
import Plutus.Crypto.MidnightZk.Verifier (verify)

-- ---------------------------------------------------------------------------
-- Test runner
-- ---------------------------------------------------------------------------

runTest :: String -> String -> String -> IO ()
runTest label dir name = do
    putStrLn $ "\n=== " ++ label ++ " ==="
    let base = "../test-vectors/" ++ dir ++ "/" ++ name

    vkV <- decodeOrDie (base ++ "_plutus_vk.json")
    ccV <- decodeOrDie (base ++ "_circuit_constraint.json")
    proofV <- decodeOrDie (base ++ "_plutus_proof.json")
    rsV <- decodeOrDie (base ++ "_rotation_sets.json")
    instV <- decodeOrDie (base ++ "_plutus_instance.json")

    let vk = parsePlutusVK vkV ccV
        proof = parsePlutusProof proofV
        specs = parseRotationSets rsV
        pubInputs = parseInstance instV

    resultE <- try (evaluate (verify vk specs proof pubInputs)) :: IO (Either SomeException Bool)
    case resultE of
        Left ex -> error $ "EXCEPTION in verify: " ++ show ex
        Right True -> putStrLn "PASS: valid proof accepted"
        Right False -> error "FAIL: valid proof was rejected"

    -- Corruption test: XOR the first advice eval with 1.
    let corruptedProof =
            proof
                { prfAdviceEvals = case prfAdviceEvals proof of
                    [] -> error "no advice evals to corrupt"
                    (e : es) -> (e `xor` 1) : es
                }
    badResultE <- try (evaluate (verify vk specs corruptedProof pubInputs)) :: IO (Either SomeException Bool)
    case badResultE of
        Left _ -> putStrLn "PASS: corrupted proof raised exception (rejected)"
        Right False -> putStrLn "PASS: corrupted proof rejected"
        Right True -> error "FAIL: corrupted proof was accepted"
  where
    decodeOrDie :: FilePath -> IO Value
    decodeOrDie fp = do
        r <- eitherDecodeFileStrict fp
        case r of
            Left err -> error $ "JSON decode error in " ++ fp ++ ": " ++ err
            Right v -> return v

-- ---------------------------------------------------------------------------
-- Main
-- ---------------------------------------------------------------------------

main :: IO ()
main = do
    runTest "SHA-256 preimage" "sha-preimage" "sha_preimage"
    runTest "Bitcoin Schnorr signature" "bitcoin-sig" "bitcoin_sig"
    runTest "Poseidon hash preimage" "poseidon" "poseidon"
    runTest "JubJub ECC scalar mult" "ecc" "ecc"
    runTest "Bitcoin threshold ECDSA 4-of-5" "ecdsa-threshold" "ecdsa_threshold"
    runTest "Ethereum ECDSA signature" "ethereum-sig" "ethereum_sig"
    runTest "Multi-set membership" "membership" "membership"
    runTest "Native gadget operations" "native-gadgets" "native_gadgets"
    runTest "RSA signature verification" "rsa-sig" "rsa_sig"
    runTest "Schnorr via Poseidon + JubJub" "schnorr-sig" "schnorr_sig"
    putStrLn "\nAll tests passed."
