{-# LANGUAGE OverloadedStrings #-}

{- | JSON parser for midnight-zk Plutus verifier artifacts.

Reads the six JSON files produced by the Rust @write-test-vectors@ binary
and returns the Haskell types consumed by the Plutus verifier.

Gate polynomial expressions are stored in the JSON as flat RPN arrays of
human-readable instruction objects (e.g. @{"op":"Advice","query_index":0}@).
'instrsToGateExpr' converts each array into a 'GateExpr' tree by running
the RPN stack machine at parse time on 'GateExpr' nodes rather than 'Scalar'
values.  On-chain evaluation is then a simple structural recursion with no
stack threading or byte-scanning.

The VK and circuit-constraint data are stored in separate JSON files:
@*_plutus_vk.json@ holds the trusted-setup-dependent fields (commitments,
SRS point, Ω); @*_circuit_constraint.json@ holds the circuit-design-dependent
fields (gate polynomials, permutation column types, lookup/trash expressions).
Pass both to 'parsePlutusVK'.
-}
module Plutus.Crypto.MidnightZk.JsonParser (
    -- * High-level parsers (each takes an already-decoded 'Value')
    parsePlutusVK,
    parsePlutusProof,
    parseRotationSets,
    parseInstance,

    -- * Low-level helpers (exported for testing)
    leHexToInteger,
    hexToBytes,
    instrsToGateExpr,
) where

import Data.Aeson (Value (..), (.:), (.:?))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as AesonKey
import qualified Data.Aeson.Types as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Vector as V
import Plutus.Crypto.BlsUtils (Scalar (..), bls12_381_scalar_prime, mkScalar)
import Plutus.Crypto.MidnightZk.Types (
    CircuitConfig (..),
    GateExpr (..),
    Proof (..),
    RotationSetSpec (..),
    SlotKind (..),
    SlotSpec (..),
    VerifyingKey (..),
 )
import PlutusTx.Builtins (BuiltinByteString, expModInteger, toBuiltin)

-- ---------------------------------------------------------------------------
-- ByteString helpers
-- ---------------------------------------------------------------------------

-- | Hex-decode a text string to a strict 'BS.ByteString'.
hexToBytes :: Text -> BS.ByteString
hexToBytes t =
    case B16.decode (TE.encodeUtf8 t) of
        Right bs -> bs
        Left err -> error $ "hexToBytes: invalid hex: " ++ err

-- | Interpret a hex-encoded byte string as a little-endian 'Integer'.
leHexToInteger :: Text -> Integer
leHexToInteger = leToInteger . hexToBytes

leToInteger :: BS.ByteString -> Integer
leToInteger bs = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 (BS.reverse bs)

toBuiltinBS :: BS.ByteString -> BuiltinByteString
toBuiltinBS = toBuiltin

-- ---------------------------------------------------------------------------
-- Gate expression tree building (RPN array → GateExpr at parse time)
-- ---------------------------------------------------------------------------

{- | Build a 'GateExpr' tree from a JSON array of RPN instruction objects.

The JSON array is in postfix order (produced by the Rust serialiser).
This function runs the RPN stack machine at *parse time*, pushing 'GateExpr'
nodes instead of 'Scalar' values, so the result is an expression tree.
On-chain evaluation is then a simple structural recursion with no stack
threading — invalid programs are structurally impossible by construction.

Scalars in @Constant@ and @Scaled@ are decoded from 32-byte LE hex here
and stored in 'GEConst' / 'GEScale' — no byte-scanning at on-chain evaluation.

midnight-zk has no multi-phase challenges; @Challenge@ instructions will not
appear in the test vectors and are not handled.
-}
instrsToGateExpr :: Value -> GateExpr
instrsToGateExpr (Array vs) =
    case foldl applyInstr [] (V.toList vs) of
        [e] -> e
        _ -> error "instrsToGateExpr: malformed RPN (stack not singleton at end)"
  where
    applyInstr stk v =
        case Aeson.parseMaybe parseInstr v of
            Just f -> f stk
            Nothing -> error $ "instrsToGateExpr: cannot parse instruction: " ++ show v
    parseInstr = Aeson.withObject "Instruction" $ \o -> do
        op <- o .: "op"
        case (op :: Text) of
            "Constant" -> do
                s <- leHexToScalar <$> o .: "value"
                return $ (GEConst s :)
            "Advice" -> do
                qi <- o .: "query_index"
                return $ (GEAdv qi :)
            "Fixed" -> do
                qi <- o .: "query_index"
                return $ (GEFix qi :)
            "Instance" -> do
                qi <- o .: "query_index"
                return $ (GEInst qi :)
            "Negated" ->
                return $ \stk -> case stk of
                    (a : rest) -> GENeg a : rest
                    _ -> error "instrsToGateExpr: stack underflow on Negated"
            "Sum" ->
                return $ \stk -> case stk of
                    (b : a : rest) -> GEAdd a b : rest
                    _ -> error "instrsToGateExpr: stack underflow on Sum"
            "Product" ->
                return $ \stk -> case stk of
                    (b : a : rest) -> GEMul a b : rest
                    _ -> error "instrsToGateExpr: stack underflow on Product"
            "Scaled" -> do
                s <- leHexToScalar <$> o .: "factor"
                return $ \stk -> case stk of
                    (a : rest) -> GEScale a s : rest
                    _ -> error "instrsToGateExpr: stack underflow on Scaled"
            "Challenge" -> fail "instrsToGateExpr: Challenge nodes are not supported (midnight-zk uses no multi-phase challenges)"
            _ -> fail $ "instrsToGateExpr: unknown op: " ++ T.unpack op
instrsToGateExpr v = error $ "instrsToGateExpr: expected Array, got: " ++ show v

-- ---------------------------------------------------------------------------
-- Scalar field element helpers
-- ---------------------------------------------------------------------------

leHexToScalar :: Text -> Scalar
leHexToScalar = mkScalar . leHexToInteger

-- ---------------------------------------------------------------------------
-- VerifyingKey parser
-- ---------------------------------------------------------------------------

{- | Parse @*_plutus_vk.json@ and @*_circuit_constraint.json@ together into a 'VerifyingKey'.

The two files are deliberately kept separate:

* @*_plutus_vk.json@ contains the trusted-setup-dependent fields (fixed and
  permutation commitments, SRS G2 point, Ω, transcript hash).  These change
  when you redo the trusted setup with a new SRS.

* @*_circuit_constraint.json@ contains the circuit-design-dependent fields
  (gate polynomials, permutation column types, lookup and trash expressions).
  These change only when the circuit logic changes, not with the SRS.
  All expressions are decoded into 'GateExpr' trees here; no byte-scanning occurs
  at on-chain evaluation time.
-}

{- | Parse @*_plutus_vk.json@ and @*_circuit_constraint.json@ together into a 'VerifyingKey'.

__No structural invariants are validated here__ (e.g. 'ccDomainSize' is a
power of 2, 'ccOmega' is a primitive root of the domain, 'ccBlinding' ≥ 1).
In production the VK is baked into the compiled Plutus script, so its hash is
committed by the script address — a malformed VK would require a different
script hash and would not match any deployed validator.  Validation is
therefore the responsibility of the off-chain tooling that compiles the script.
-}
parsePlutusVK :: Value -> Value -> VerifyingKey
parsePlutusVK vkV ccV =
    case Aeson.parseMaybe parseVK vkV of
        Just vk -> vk
        Nothing -> error "parsePlutusVK: failed to parse VK JSON"
  where
    -- Parse the circuit_constraint JSON once and bind the results.
    (gatePolys, permCTs, liExprs, ltExprs, trashSels, trashCons) =
        parseCircuitConstraint ccV

    parseVK = Aeson.withObject "VK" $ \o -> do
        k <- o .: "k"
        omegaHex <- o .: "omega"
        blinding <- o .: "blinding_factors"
        na <- o .: "num_advice_columns"
        npc <- o .: "num_perm_columns"
        degree <- o .: "cs_degree"
        nl <- o .: "num_lookups"

        fixedComs <- o .: "fixed_commitments"
        permComs <- o .: "permutation_commitments"
        sG2Hex <- o .: "s_g2"
        trHex <- o .: "transcript_repr"

        let q = bls12_381_scalar_prime
            n = 2 ^ (k :: Integer)
            omega = leHexToScalar omegaHex
            Scalar omegaInt = omega
            omegaInv = Scalar $ expModInteger omegaInt (q - 2) q
            Scalar omegaInvInt = omegaInv
            omegaLast = Scalar $ expModInteger omegaInvInt (blinding + 1) q
            nInv = Scalar $ expModInteger n (q - 2) q
            chunkSize = (degree :: Integer) - 2
            cfg =
                CircuitConfig
                    { ccDomainSize = n
                    , ccOmega = omega
                    , ccOmegaInv = omegaInv
                    , ccOmegaLast = omegaLast
                    , ccNInv = nInv
                    , ccBlinding = blinding
                    , ccNumAdviceCols = na
                    , ccNumPermCols = npc
                    , ccPermChunkSize = chunkSize
                    , ccNumLookups = nl
                    , ccNumHPieces = (degree :: Integer) - 1
                    }
            mkG1 h = toBuiltinBS (hexToBytes h)

        return
            VerifyingKey
                { vkConfig = cfg
                , vkFixedComs = map mkG1 fixedComs
                , vkPermSigmaComs = map mkG1 permComs
                , vkSrsG2 = toBuiltinBS (hexToBytes sG2Hex)
                , vkTranscriptRepr = toBuiltinBS (hexToBytes trHex)
                , vkGatePolys = gatePolys
                , vkPermColTypes = permCTs
                , vkLookupInputExprs = liExprs
                , vkLookupTableExprs = ltExprs
                , vkTrashSelectors = trashSels
                , vkTrashConstraintExprs = trashCons
                }

{- | Parse @*_circuit_constraint.json@.

Returns @(gatePolys, permColTypes, lookupInputExprs, lookupTableExprs,
trashSelectors, trashConstraintExprs)@.  All expression arrays are converted
to 'GateExpr' trees at this point — constants and scale scalars are
pre-decoded so on-chain evaluation needs no byte scanning.
Note: @delta@ is NOT read from this file — it is a constant of the
BLS12-381 scalar field ('bls12_381_scalar_delta' in "Plutus.Crypto.BlsUtils").
-}
parseCircuitConstraint ::
    Value ->
    ( [GateExpr]
    , [(Integer, Integer)]
    , [[GateExpr]]
    , [[GateExpr]]
    , [GateExpr]
    , [[GateExpr]]
    )
parseCircuitConstraint v =
    case Aeson.parseMaybe parseCC v of
        Just r -> r
        Nothing -> error "parseCircuitConstraint: failed to parse circuit_constraint JSON"
  where
    parseCC = Aeson.withObject "CircuitConstraint" $ \o -> do
        gatePolyVs <- (o .: "gate_polys" :: Aeson.Parser [Value])
        permColVs <- (o .: "perm_col_types" :: Aeson.Parser [Value])
        liExprVs <- (o .: "lookup_input_exprs" :: Aeson.Parser [[Value]])
        ltExprVs <- (o .: "lookup_table_exprs" :: Aeson.Parser [[Value]])
        tSelVs <- (o .: "trash_selectors" :: Aeson.Parser [Value])
        tConVs <- (o .: "trash_constraint_exprs" :: Aeson.Parser [[Value]])
        return
            ( map instrsToGateExpr gatePolyVs
            , map parsePermColType permColVs
            , map (map instrsToGateExpr) liExprVs
            , map (map instrsToGateExpr) ltExprVs
            , map instrsToGateExpr tSelVs
            , map (map instrsToGateExpr) tConVs
            )

    parsePermColType :: Value -> (Integer, Integer)
    parsePermColType v' =
        case Aeson.parseMaybe p v' of
            Just r -> r
            Nothing -> error "parsePermColType: failed"
      where
        p = Aeson.withObject "PermColType" $ \o -> do
            ct <- o .: "col_type"
            ei <- o .: "eval_idx"
            return (ct, ei)

-- ---------------------------------------------------------------------------
-- Proof parser
-- ---------------------------------------------------------------------------

-- | Parse @*_plutus_proof.json@.
parsePlutusProof :: Value -> Proof
parsePlutusProof v =
    case Aeson.parseMaybe parseProof v of
        Just proof -> proof
        Nothing -> error "parsePlutusProof: failed"
  where
    parseProof = Aeson.withObject "Proof" $ \o -> do
        advComs <- map mkG1 <$> (o .: "advice_commitments" :: Aeson.Parser [Text])
        luPerms <- (o .: "lookup_permuted_commitments" :: Aeson.Parser [Value])
        ppComs <- map mkG1 <$> (o .: "permutation_product_commitments" :: Aeson.Parser [Text])
        lpComs <- map mkG1 <$> (o .: "lookup_product_commitments" :: Aeson.Parser [Text])
        trComs <- map mkG1 <$> (o .: "trash_commitments" :: Aeson.Parser [Text])
        randCom <- mkG1 <$> (o .: "random_poly_commitment" :: Aeson.Parser Text)
        hComs <- map mkG1 <$> (o .: "h_commitments" :: Aeson.Parser [Text])

        advEvals <- map leHexToInteger <$> (o .: "advice_evals" :: Aeson.Parser [Text])
        fixEvals <- map leHexToInteger <$> (o .: "fixed_evals" :: Aeson.Parser [Text])
        randEval <- leHexToInteger <$> (o .: "random_eval" :: Aeson.Parser Text)
        sigEvals <- map leHexToInteger <$> (o .: "sigma_evals" :: Aeson.Parser [Text])
        ppEvalVs <- (o .: "permutation_product_evals" :: Aeson.Parser [Value])
        luEvalVs <- (o .: "lookup_evals" :: Aeson.Parser [Value])
        trEvals <- map leHexToInteger <$> (o .: "trash_evals" :: Aeson.Parser [Text])

        gwcV <- (o .: "gwc" :: Aeson.Parser Value)
        (fCom, qEvalsOnX3, wCom) <- parseGwc gwcV

        let luInputComs = map (mkG1 . getField "permuted_input") luPerms
            luTableComs = map (mkG1 . getField "permuted_table") luPerms
            ppFlat = concatMap flattenPPEval ppEvalVs
            luFlat = concatMap flattenLuEval luEvalVs

        return
            Proof
                { prfAdviceComs = advComs
                , prfLookupInputComs = luInputComs
                , prfLookupTableComs = luTableComs
                , prfPermProdComs = ppComs
                , prfLookupProdComs = lpComs
                , prfTrashComs = trComs
                , prfRandomCom = randCom
                , prfHComs = hComs
                , prfFCom = fCom
                , prfPiPt = wCom
                , prfAdviceEvals = advEvals
                , prfFixedEvals = fixEvals
                , prfRandomEval = randEval
                , prfPermSigmaEvals = sigEvals
                , prfPermProdEvals = ppFlat
                , prfLookupEvals = luFlat
                , prfTrashEvals = trEvals
                , prfQEvalsOnX3 = qEvalsOnX3
                }

    mkG1 :: Text -> BuiltinByteString
    mkG1 = toBuiltinBS . hexToBytes

    -- Extract a Text field from a JSON object (used for lookup permuted coms).
    getField :: Text -> Value -> Text
    getField key val =
        case Aeson.parseMaybe (Aeson.withObject "obj" (.: AesonKey.fromText key)) val of
            Just t -> t
            Nothing -> error $ "getField: key not found: " ++ T.unpack key

    parseGwc :: Value -> Aeson.Parser (BuiltinByteString, [Integer], BuiltinByteString)
    parseGwc = Aeson.withObject "GWC" $ \o -> do
        fC <- mkG1 <$> (o .: "f_commitment" :: Aeson.Parser Text)
        qEs <- map leHexToInteger <$> (o .: "q_evals" :: Aeson.Parser [Text])
        wC <- mkG1 <$> (o .: "w_commitment" :: Aeson.Parser Text)
        return (fC, qEs, wC)

    -- Flatten one permutation product eval object.
    -- The JSON has {"eval":"...", "next_eval":"...", "last_eval": null | "..."}.
    -- Non-last chunks: [eval, next_eval, last_eval]  (3 values)
    -- Last chunk:      [eval, next_eval]             (2 values, last_eval is null)
    flattenPPEval :: Value -> [Integer]
    flattenPPEval val =
        case Aeson.parseMaybe (Aeson.withObject "PPEval" flat) val of
            Just xs -> xs
            Nothing -> error "flattenPPEval: failed"
      where
        flat o = do
            e <- leHexToInteger <$> (o .: "eval" :: Aeson.Parser Text)
            ne <- leHexToInteger <$> (o .: "next_eval" :: Aeson.Parser Text)
            mle <- (o .:? "last_eval" :: Aeson.Parser (Maybe Text))
            return $ case mle of
                Just le -> [e, ne, leHexToInteger le]
                Nothing -> [e, ne]

    -- Flatten one lookup eval object into 5 values in the proof order:
    -- [product_eval, product_next_eval, permuted_input_eval,
    --  permuted_input_inv_eval, permuted_table_eval]
    flattenLuEval :: Value -> [Integer]
    flattenLuEval val =
        case Aeson.parseMaybe (Aeson.withObject "LuEval" flat) val of
            Just xs -> xs
            Nothing -> error "flattenLuEval: failed"
      where
        flat o = do
            pe <- leHexToInteger <$> (o .: "product_eval" :: Aeson.Parser Text)
            pne <- leHexToInteger <$> (o .: "product_next_eval" :: Aeson.Parser Text)
            pie <- leHexToInteger <$> (o .: "permuted_input_eval" :: Aeson.Parser Text)
            pii <- leHexToInteger <$> (o .: "permuted_input_inv_eval" :: Aeson.Parser Text)
            pte <- leHexToInteger <$> (o .: "permuted_table_eval" :: Aeson.Parser Text)
            return [pe, pne, pie, pii, pte]

-- ---------------------------------------------------------------------------
-- RotationSets parser
-- ---------------------------------------------------------------------------

-- | Poly-kind name → 'SlotKind'.
polyKind :: Text -> SlotKind
polyKind "Advice" = SKAdvice
polyKind "Instance" = SKInstance
polyKind "LookupTable" = SKLookupTable
polyKind "Trash" = SKTrash
polyKind "Fixed" = SKFixed
polyKind "PermSigma" = SKPermSigma
polyKind "H" = SKH
polyKind "Random" = SKRandom
polyKind "PermProd" = SKPermProd
polyKind "LookupProd" = SKLookupProd
polyKind "LookupInput" = SKLookupInput
polyKind k = error $ "polyKind: unknown kind: " ++ T.unpack k

-- | Parse @*_rotation_sets.json@.
parseRotationSets :: Value -> [RotationSetSpec]
parseRotationSets v =
    case Aeson.parseMaybe parseRS v of
        Just specs -> specs
        Nothing -> error "parseRotationSets: failed"
  where
    parseRS = Aeson.withObject "RotationSets" $ \o -> do
        sets <- (o .: "sets" :: Aeson.Parser [Value])
        mapM parseSet sets

    parseSet = Aeson.withObject "Set" $ \o -> do
        rots <- (o .: "rotations" :: Aeson.Parser [Integer])
        slots <- (o .: "slots" :: Aeson.Parser [Value])
        slotSpecs <- mapM (parseSlot (length rots)) slots
        return
            RotationSetSpec
                { rssRotations = rots
                , rssSlots = slotSpecs
                }

    parseSlot _numRots = Aeson.withObject "Slot" $ \o -> do
        kindText <- (o .: "poly_kind" :: Aeson.Parser Text)
        idx <- o .: "index"
        evalIdxs <- (o .: "eval_idxs" :: Aeson.Parser [Integer])
        return
            SlotSpec
                { ssKind = polyKind kindText
                , ssIndex = idx
                , ssEvalIdxs = evalIdxs
                }

-- ---------------------------------------------------------------------------
-- Public inputs parser
-- ---------------------------------------------------------------------------

-- | Parse @*_plutus_instance.json@: an array of 32-byte LE hex strings.
parseInstance :: Value -> [Integer]
parseInstance (Array vs) = map parseField (V.toList vs)
  where
    parseField (String t) = leHexToInteger t
    parseField _ = error "parseInstance: expected string element"
parseInstance _ = error "parseInstance: expected Array"
