{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TemplateHaskell #-}

{- | Template Haskell code generator for circuit-specific Halo2 verifiers.

Reads JSON circuit data at GHC compile-time and emits a
@Proof -> [Integer] -> Bool@ (or @Integer@ for sub-verifiers) expression
with all loops over the verifying key \/ rotation-set structure unrolled
into straight-line arithmetic.
-}
module SpecializedVerifier (
    mkVerifierFromFiles,
    mkHGateFromFiles,
    mkHEvalFromFiles,
) where

import Control.Monad (foldM)
import Data.Aeson (eitherDecodeFileStrict)
import qualified Data.ByteString as BS
import GHC.ByteOrder (ByteOrder (..))
import Language.Haskell.TH
import Language.Haskell.TH.Syntax (Code (..), TExp (..), runIO, unsafeCodeCoerce)
import Plutus.Crypto.BlsUtils (
    Scalar (..),
    bls12_381_scalar_delta,
    bls12_381_scalar_prime,
    mkScalar,
 )
import Plutus.Crypto.MidnightZk.JsonParser (parsePlutusVK, parseRotationSets)
import Plutus.Crypto.MidnightZk.Transcript (absorb, initTranscript, squeeze)
import Plutus.Crypto.MidnightZk.Types
import Plutus.Crypto.MidnightZk.Verifier (batchInverse, evalGate, powers, verifyGwc)
import PlutusTx.Builtins (
    BuiltinByteString,
    bls12_381_G1_compressed_zero,
    bls12_381_G1_uncompress,
    bls12_381_G2_uncompress,
    fromBuiltin,
    integerToByteString,
 )
import PlutusTx.Foldable (foldl, sum)
import PlutusTx.List (drop, head, length, map, zipWith, (!!))
import PlutusTx.Numeric (
    AdditiveGroup (..),
    AdditiveMonoid (..),
    AdditiveSemigroup (..),
    Module (..),
    MultiplicativeMonoid (..),
    MultiplicativeSemigroup (..),
 )
import PlutusTx.Prelude ((.), (<>))
import Prelude (Bool, Integer, fromIntegral, return)
import qualified Prelude as P

-- ── Helpers ───────────────────────────────────────────────────────────────────

intE :: Integer -> Q Exp
intE = litE . integerL

bind :: Name -> Q Exp -> Q Dec
bind n e = valD (varP n) (normalB e) []

liftScalar :: Scalar -> Q Exp
liftScalar (Scalar n) = [|Scalar $(intE n)|]

liftBS :: BuiltinByteString -> Q Exp
liftBS bs = do
    let raw = fromBuiltin bs :: BS.ByteString
        len = P.toInteger (BS.length raw)
        ival = BS.foldl' (\acc b -> acc * 256 + P.toInteger b) 0 raw
    [|integerToByteString BigEndian $(intE len) $(intE ival)|]

liftBSList :: [BuiltinByteString] -> Q Exp
liftBSList = listE . P.map liftBS

powMod :: Integer -> Integer -> Integer -> Integer
powMod _ 0 _ = 1
powMod b n m
    | P.even n = let r = powMod b (n `P.div` 2) m in (r P.* r) `P.mod` m
    | P.otherwise = (b P.* powMod b (n P.- 1) m) `P.mod` m

-- ── GateExpr unrolling ────────────────────────────────────────────────────────

genEvalGate :: Name -> Name -> Name -> GateExpr -> Q Exp
genEvalGate advN fixN instN = go
  where
    go (GEConst s) = liftScalar s
    go (GEAdv i) = [|$(varE advN) !! $(intE i)|]
    go (GEFix i) = [|$(varE fixN) !! $(intE i)|]
    go (GEInst i) = [|$(varE instN) !! $(intE i)|]
    go (GENeg e) = [|Scalar 0 - $(go e)|]
    go (GEAdd a b) = [|$(go a) + $(go b)|]
    go (GEMul a b) = [|$(go a) * $(go b)|]
    go (GEScale e s) = [|$(go e) * $(liftScalar s)|]

-- | @foldl (\acc e -> acc * y + evalE e) (Scalar 0) gps@ — unrolled at meta level.
genHornerFold :: Name -> Name -> Name -> Name -> [GateExpr] -> Q Exp
genHornerFold advN fixN instN yN =
    P.foldl
        (\acc gp -> [|$(acc) * $(varE yN) + $(genEvalGate advN fixN instN gp)|])
        [|Scalar 0|]

-- | @foldl (\a e -> a * c + evalE e) (Scalar 0) exprs@ — theta compression, unrolled.
genCompressFold :: Name -> Name -> Name -> Name -> [GateExpr] -> Q Exp
genCompressFold advN fixN instN cN =
    P.foldl
        (\acc e -> [|$(acc) * $(varE cN) + $(genEvalGate advN fixN instN e)|])
        [|Scalar 0|]

-- ── x1-power expressions (unrolled) ──────────────────────────────────────────

-- | @[Scalar 1, x1, x1*x1, …, x1^{n-1}]@ as a list of Q Exp.
genX1Powers :: Name -> Integer -> [Q Exp]
genX1Powers x1N n
    | n P.<= 0 = []
    | P.otherwise =
        P.scanl (\acc _ -> [|$(acc) * $(varE x1N)|]) [|Scalar 1|] [1 .. n P.- 1]

-- ── Fixed names matching those in the generated let block ────────────────────

advEvalsN, fixEvalsN, instEvalsN :: Name
permProdEvalsN, sigmaEvalsN, lookupEvalsN, trashEvalsN, randomEvalN, hEvalN :: Name
advEvalsN = mkName "advEvals"
fixEvalsN = mkName "fixEvals"
instEvalsN = mkName "instEvals"
permProdEvalsN = mkName "permProdEvals"
sigmaEvalsN = mkName "sigmaEvals"
lookupEvalsN = mkName "lookupEvals"
trashEvalsN = mkName "trashEvals"
randomEvalN = mkName "randomEval"
hEvalN = mkName "hEval"

advicePtsN, luTablePtsN, trashPtsN, fixedPtsN, permSigmaPtsN :: Name
hPtsN, randomPtN, permProdPtsN, luProdPtsN, luInputPtsN :: Name
advicePtsN = mkName "advicePts"
luTablePtsN = mkName "lookupTablePts"
trashPtsN = mkName "trashPts"
fixedPtsN = mkName "fixedPts"
permSigmaPtsN = mkName "permSigmaPts"
hPtsN = mkName "hPts"
randomPtN = mkName "randomPt"
permProdPtsN = mkName "permProdPts"
luProdPtsN = mkName "lookupProdPts"
luInputPtsN = mkName "lookupInputPts"

xN, x1N, x2N, x3N, x4N, yN, thetaN, betaN, gammaN, trashChalN :: Name
xNextN, xPrevN, xLastN, hSplitN :: Name
l0N, lLastN, lBlindN, activeRowsN :: Name
omgLitN, omgInvLitN, omgLastLitN, nInvLitN :: Name
xN = mkName "x"
x1N = mkName "x1"
x2N = mkName "x2"
x3N = mkName "x3"
x4N = mkName "x4"
yN = mkName "y"
thetaN = mkName "theta"
betaN = mkName "beta"
gammaN = mkName "gamma"
trashChalN = mkName "trashChal"
xNextN = mkName "xNext"
xPrevN = mkName "xPrev"
xLastN = mkName "xLast"
hSplitN = mkName "hSplit"
l0N = mkName "l0"
lLastN = mkName "lLast"
lBlindN = mkName "lBlind"
activeRowsN = mkName "activeRows"
omgLitN = mkName "omgLit"
omgInvLitN = mkName "omgInvLit"
omgLastLitN = mkName "omgLastLit"
nInvLitN = mkName "nInvLit"

prfN, pubInputsN :: Name
prfN = mkName "prf"
pubInputsN = mkName "pubInputs"

-- ── Slot evaluation expression ────────────────────────────────────────────────

genSlotEval :: Integer -> SlotSpec -> Integer -> Integer -> Q Exp
genSlotEval blinding ss rotPos rotOff =
    let i = ssIndex ss
        ei = ssEvalIdxs ss P.!! fromIntegral rotPos
        luE f = [|$(varE lookupEvalsN) !! $(intE (5 P.* i P.+ f))|]
        ppE f = [|$(varE permProdEvalsN) !! $(intE (3 P.* i P.+ f))|]
     in case ssKind ss of
            SKAdvice -> [|$(varE advEvalsN) !! $(intE ei)|]
            SKFixed -> [|$(varE fixEvalsN) !! $(intE ei)|]
            SKLookupTable -> luE 4
            SKTrash -> [|$(varE trashEvalsN) !! $(intE i)|]
            SKPermSigma -> [|$(varE sigmaEvalsN) !! $(intE i)|]
            SKH -> varE hEvalN
            SKRandom -> varE randomEvalN
            SKInstance -> [|Scalar 0|]
            SKPermProd
                | rotOff P.== 0 -> ppE 0
                | rotOff P.== 1 -> ppE 1
                | P.otherwise -> ppE 2
            SKLookupProd
                | rotOff P.== 0 -> luE 0
                | P.otherwise -> luE 1
            SKLookupInput
                | rotOff P.== 0 -> luE 2
                | P.otherwise -> luE 3

-- ── Slot com-pair expressions ─────────────────────────────────────────────────

genSlotComPairs :: Integer -> Q Exp -> SlotSpec -> Q ([Q Exp], [Q Exp])
genSlotComPairs numHPieces x1jE ss = do
    let i = ssIndex ss
        single ptsN =
            return
                ( [[|unScalar $(x1jE)|]]
                , [[|$(varE ptsN) !! $(intE i)|]]
                )
    case ssKind ss of
        SKInstance -> return ([], [])
        SKH -> do
            let hPows = genX1Powers hSplitN numHPieces
                scs = P.map (\p -> [|unScalar ($(x1jE) * $(p))|]) hPows
                pts = P.map (\k -> [|$(varE hPtsN) !! $(intE k)|]) [0 .. numHPieces P.- 1]
            return (scs, pts)
        SKAdvice -> single advicePtsN
        SKLookupTable -> single luTablePtsN
        SKTrash -> single trashPtsN
        SKFixed -> single fixedPtsN
        SKPermSigma -> single permSigmaPtsN
        SKRandom -> return ([[|unScalar $(x1jE)|]], [varE randomPtN])
        SKPermProd -> single permProdPtsN
        SKLookupProd -> single luProdPtsN
        SKLookupInput -> single luInputPtsN

-- ── Eval-point expression from rotation offset ───────────────────────────────

genEvalPt :: Integer -> Integer -> Q Exp
genEvalPt blinding rotOff
    | rotOff P.== 0 = varE xN
    | rotOff P.== 1 = varE xNextN
    | rotOff P.== (-1) = varE xPrevN
    | rotOff P.== P.negate (blinding P.+ 1) = varE xLastN
    | rotOff P.>= 1 =
        let r = rotOff
         in [|$(varE xN) * scale $(intE r) $(varE omgLitN)|]
    | P.otherwise =
        let r = P.negate rotOff
         in [|$(varE xN) * scale $(intE r) $(varE omgInvLitN)|]

-- ── One rotation set expression (fully unrolled) ──────────────────────────────

genRotationSet :: Integer -> Integer -> RotationSetSpec -> Q Exp
genRotationSet blinding numHPieces spec = do
    let rotOffs = rssRotations spec
        slots = rssSlots spec
        nSlots = P.toInteger (P.length slots)

    let x1pows = genX1Powers x1N nSlots

    slotPairs <-
        P.mapM
            (\(x1j, ss) -> genSlotComPairs numHPieces x1j ss)
            (P.zip x1pows slots)

    let allScalarsE = listE (P.concatMap P.fst slotPairs)
        allPointsE = listE (P.concatMap P.snd slotPairs)

    let genQEval rotPos rotOff =
            P.foldl
                ( \acc (x1j, ss) ->
                    [|$(acc) + $(x1j) * $(genSlotEval blinding ss rotPos rotOff)|]
                )
                [|Scalar 0|]
                (P.zip x1pows slots)

    qEvalEs <- P.mapM (\(pos, off) -> genQEval pos off) (P.zip [0 ..] rotOffs)
    ptsEs <- P.mapM (genEvalPt blinding) rotOffs

    [|
        RotationSet
            { rsPoints = $(listE (P.map return ptsEs))
            , rsComScalars = $(allScalarsE)
            , rsComs = $(allPointsE)
            , rsQEvalsAtPts = $(listE (P.map return qEvalEs))
            }
        |]

-- ── Unrolled perm chunk constraint (startDelta precomputed as a constant) ─────

-- Returns (constraintExpr, nextDelta) where nextDelta is a Scalar constant.
genPermChunk ::
    [(Integer, Integer)] ->
    Integer ->
    Integer ->
    Integer ->
    Integer ->
    Scalar -> -- startDelta (precomputed): delta^{j*chunkSize}
    Q (Q Exp, Scalar)
genPermChunk pct j numChunks chunkSize numPermCols (Scalar startD) = do
    let nc =
            if j P.<= numChunks P.- 2
                then chunkSize
                else numPermCols P.- (numChunks P.- 1) P.* chunkSize
        q = bls12_381_scalar_prime
        dval = bls12_381_scalar_delta
        colDs = P.map (\k -> Scalar ((startD P.* powMod dval k q) `P.mod` q)) [0 .. nc P.- 1]
        nextDelta = Scalar ((startD P.* powMod dval nc q) `P.mod` q)

    let initLA = [|$(varE permProdEvalsN) !! $(intE (3 P.* j P.+ 1))|]
        initRA = [|$(varE permProdEvalsN) !! $(intE (3 P.* j P.+ 0))|]

    (finalLA, finalRA) <-
        foldM
            ( \(laQ, raQ) k -> do
                let gi = j P.* chunkSize P.+ k
                    (ct, ei) = pct P.!! fromIntegral gi
                    ceE = case ct of
                        0 -> [|$(varE advEvalsN) !! $(intE ei)|]
                        1 -> [|$(varE fixEvalsN) !! $(intE ei)|]
                        _ -> [|$(varE instEvalsN) !! $(intE ei)|]
                    cdE = liftScalar (colDs P.!! fromIntegral k)
                    seE = [|$(varE sigmaEvalsN) !! $(intE gi)|]
                    shiftE = [|$(cdE) * $(varE betaN) * $(varE xN)|]
                return
                    ( [|$(laQ) * ($(ceE) + $(varE betaN) * $(seE) + $(varE gammaN))|]
                    , [|$(raQ) * ($(ceE) + $(shiftE) + $(varE gammaN))|]
                    )
            )
            (initLA, initRA)
            [0 .. nc P.- 1]

    let cExpr = [|$(varE activeRowsN) * ($(finalLA) - $(finalRA))|]
    return (cExpr, nextDelta)

-- ── Unrolled lookup Horner for lookup k ──────────────────────────────────────

genLookupHorner :: [[GateExpr]] -> [[GateExpr]] -> Integer -> Name -> Q Exp
genLookupHorner inputExprs tableExprs k accN = do
    let luE f = [|$(varE lookupEvalsN) !! $(intE (5 P.* k P.+ f))|]
    inputArgE <- genCompressFold advEvalsN fixEvalsN instEvalsN thetaN (inputExprs P.!! fromIntegral k)
    tableArgE <- genCompressFold advEvalsN fixEvalsN instEvalsN thetaN (tableExprs P.!! fromIntegral k)
    let prodEval = luE 0
        prodNext = luE 1
        inputEval = luE 2
        inputInv = luE 3
        tableEval = luE 4
        e0 = [|$(varE l0N) * (Scalar 1 - $(prodEval))|]
        e1 = [|$(varE lLastN) * ($(prodEval) * $(prodEval) - $(prodEval))|]
        e2 =
            [|
                $(varE activeRowsN)
                    * ( $(prodNext)
                            * ($(inputEval) + $(varE betaN))
                            * ($(tableEval) + $(varE gammaN))
                            - $(prodEval)
                            * ($(return inputArgE) + $(varE betaN))
                            * ($(return tableArgE) + $(varE gammaN))
                      )
                |]
        e3 = [|$(varE l0N) * ($(inputEval) - $(tableEval))|]
        e4 = [|$(varE activeRowsN) * ($(inputEval) - $(tableEval)) * ($(inputEval) - $(inputInv))|]
    [|
        ( ( ( ($(varE accN) * $(varE yN) + $(e0))
                * $(varE yN)
                + $(e1)
            )
                * $(varE yN)
                + $(e2)
          )
            * $(varE yN)
            + $(e3)
        )
            * $(varE yN)
            + $(e4)
        |]

-- ── What the generated lambda returns ────────────────────────────────────────

data VOutput
    = VOFull -- Proof -> [Integer] -> Bool
    | VOHGate -- Proof -> [Integer] -> Integer  (unScalar hGate)
    | VOHEval -- Proof -> [Integer] -> Integer  (unScalar hEval)

-- ── Main verifier body generator ─────────────────────────────────────────────

mkVerifier :: VOutput -> VerifyingKey -> [RotationSetSpec] -> Q Exp
mkVerifier vOutput vk specs = do
    let cfg = vkConfig vk
        omg = ccOmega cfg
        omgInv = ccOmegaInv cfg
        omgLast = ccOmegaLast cfg
        nInv = ccNInv cfg
        nDomain = ccDomainSize cfg
        blinding = ccBlinding cfg
        chunkSize = ccPermChunkSize cfg
        numPermCols = ccNumPermCols cfg
        numChunks = (numPermCols P.+ chunkSize P.- 1) `P.div` chunkSize
        numLookups = ccNumLookups cfg
        numHPieces = ccNumHPieces cfg
        numTrash = P.toInteger (P.length (vkTrashSelectors vk))
        pct = vkPermColTypes vk
        q = bls12_381_scalar_prime

    -- Gate Horner (always unrolled)
    hGateE <- genHornerFold advEvalsN fixEvalsN instEvalsN yN (vkGatePolys vk)

    -- Perm section (built at meta level for VOHEval and VOFull)
    let dval = bls12_381_scalar_delta
        startDeltas =
            P.scanl
                ( \(Scalar d) j ->
                    let nc =
                            if j P.<= numChunks P.- 2
                                then chunkSize
                                else numPermCols P.- (numChunks P.- 1) P.* chunkSize
                     in Scalar ((d P.* powMod dval nc q) `P.mod` q)
                )
                (Scalar 1)
                [0 .. numChunks P.- 2]

    chunkResults <-
        P.mapM
            (\(j, sd) -> genPermChunk pct j numChunks chunkSize numPermCols sd)
            (P.zip [0 ..] startDeltas)
    let chunkExprs = P.map P.fst chunkResults

    let hP0E =
            [|
                $(return hGateE)
                    * $(varE yN)
                    + $(varE l0N)
                    * (Scalar 1 - $(varE permProdEvalsN) !! 0)
                |]
        hP1E =
            [|
                $(hP0E)
                    * $(varE yN)
                    + $(varE lLastN)
                    * ( let zl = $(varE permProdEvalsN) !! $(intE (3 P.* (numChunks P.- 1)))
                         in zl * zl - zl
                      )
                |]
    let hP2E =
            P.foldl
                ( \acc j ->
                    [|
                        $(acc)
                            * $(varE yN)
                            + $(varE l0N)
                            * ( $(varE permProdEvalsN)
                                    !! $(intE (3 P.* (j P.+ 1)))
                                    - $(varE permProdEvalsN)
                                    !! $(intE (3 P.* j P.+ 2))
                              )
                        |]
                )
                hP1E
                [0 .. numChunks P.- 2]
    chunkEs <- P.sequence chunkExprs
    let hPermE =
            P.foldl
                (\acc c -> [|$(acc) * $(varE yN) + $(return c)|])
                hP2E
                chunkEs

    -- Lookup/trash accumulator names
    let luAccN k = mkName ("hLookupAcc" P.<> P.show k)
        firstLuAcc = mkName "hPermFinal"
        trAccN t = mkName ("hTrashAcc" P.<> P.show t)
        firstTrAcc =
            if numLookups P.== 0
                then firstLuAcc
                else luAccN (numLookups P.- 1)
        lastHN =
            if numTrash P.== 0
                then (if numLookups P.== 0 then firstLuAcc else luAccN (numLookups P.- 1))
                else trAccN (numTrash P.- 1)

    -- Rotation set names (for VOFull)
    let nSets = P.toInteger (P.length specs)
        rotSetN i = mkName ("rotSet" P.<> P.show i)

    rotSetEs <- P.mapM (genRotationSet blinding numHPieces) specs

    -- ── Build declarations ────────────────────────────────────────────────────

    omgLitD <- bind omgLitN (liftScalar omg)
    omgInvLitD <- bind omgInvLitN (liftScalar omgInv)
    omgLastLitD <- bind omgLastLitN (liftScalar omgLast)
    nInvLitD <- bind nInvLitN (liftScalar nInv)

    let transcriptReprN = mkName "transcriptRepr"
        srsG2BsN = mkName "srsG2Bs"
        fixedComsN = mkName "fixedComs"
        permSigComsN = mkName "permSigComs"

    trReprE <- liftBS (vkTranscriptRepr vk)
    srsG2E <- liftBS (vkSrsG2 vk)
    fixedE <- liftBSList (vkFixedComs vk)
    permSigE <- liftBSList (vkPermSigmaComs vk)
    trReprD <- bind transcriptReprN (return trReprE)
    srsG2D <- bind srsG2BsN (return srsG2E)
    fixedD <- bind fixedComsN (return fixedE)
    permSigD <- bind permSigComsN (return permSigE)
    let byteDecls = [trReprD, srsG2D, fixedD, permSigD]

    let td0N = mkName "td0"
        td1N = mkName "td1"
        td2N = mkName "td2"
        td3N = mkName "td3"
        td4N = mkName "td4"
        td4sN = mkName "td4s"
        td5N = mkName "td5"
        td5sN = mkName "td5s"
        td5ssN = mkName "td5ss"
        td6N = mkName "td6"
        td7N = mkName "td7"
        td7sN = mkName "td7s"
        td7tN = mkName "td7t"
        td8rN = mkName "td8r"
        td8sN = mkName "td8s"
        td9N = mkName "td9"
        td9sN = mkName "td9s"
        td10N = mkName "td10"
        td10sN = mkName "td10s"
        td10ssN = mkName "td10ss"
        td11N = mkName "td11"
        td11sN = mkName "td11s"
        td12N = mkName "td12"
        chkSN = mkName "chkS"
        allEvalsN = mkName "allEvals"

    transcriptDecls <-
        P.sequence
            [ bind td0N [|initTranscript $(varE transcriptReprN)|]
            , bind td1N [|$(varE td0N) <> bls12_381_G1_compressed_zero|]
            , bind td2N [|absorb $(varE td1N) (integerToByteString LittleEndian 32 (length $(varE pubInputsN)))|]
            , bind td3N [|foldl (\td n -> absorb td (integerToByteString LittleEndian 32 n)) $(varE td2N) $(varE pubInputsN)|]
            , bind td4N [|foldl (<>) $(varE td3N) (prfAdviceComs $(varE prfN))|]
            , valD (tupP [varP thetaN, varP td4sN]) (normalB [|squeeze $(varE td4N)|]) []
            , bind td5N [|foldl (<>) $(varE td4sN) (zipWith (<>) (prfLookupInputComs $(varE prfN)) (prfLookupTableComs $(varE prfN)))|]
            , valD (tupP [varP betaN, varP td5sN]) (normalB [|squeeze $(varE td5N)|]) []
            , valD (tupP [varP gammaN, varP td5ssN]) (normalB [|squeeze $(varE td5sN)|]) []
            , bind td6N [|foldl (<>) $(varE td5ssN) (prfPermProdComs $(varE prfN))|]
            , bind td7N [|foldl (<>) $(varE td6N) (prfLookupProdComs $(varE prfN))|]
            , valD (tupP [varP trashChalN, varP td7sN]) (normalB [|squeeze $(varE td7N)|]) []
            , bind td7tN [|foldl (<>) $(varE td7sN) (prfTrashComs $(varE prfN))|]
            , bind td8rN [|$(varE td7tN) <> prfRandomCom $(varE prfN)|]
            , valD (tupP [varP yN, varP td8sN]) (normalB [|squeeze $(varE td8rN)|]) []
            , bind td9N [|foldl (<>) $(varE td8sN) (prfHComs $(varE prfN))|]
            , valD (tupP [varP xN, varP td9sN]) (normalB [|squeeze $(varE td9N)|]) []
            , bind chkSN [|unScalar . mkScalar|]
            , bind
                allEvalsN
                [|
                    [0]
                        <> map $(varE chkSN) (prfAdviceEvals $(varE prfN))
                        <> map $(varE chkSN) (prfFixedEvals $(varE prfN))
                        <> [$(varE chkSN) (prfRandomEval $(varE prfN))]
                        <> map $(varE chkSN) (prfPermSigmaEvals $(varE prfN))
                        <> map $(varE chkSN) (prfPermProdEvals $(varE prfN))
                        <> map $(varE chkSN) (prfLookupEvals $(varE prfN))
                        <> map $(varE chkSN) (prfTrashEvals $(varE prfN))
                    |]
            , bind td10N [|foldl (\td n -> absorb td (integerToByteString LittleEndian 32 n)) $(varE td9sN) $(varE allEvalsN)|]
            , valD (tupP [varP x1N, varP td10sN]) (normalB [|squeeze $(varE td10N)|]) []
            , valD (tupP [varP x2N, varP td10ssN]) (normalB [|squeeze $(varE td10sN)|]) []
            , bind td11N [|$(varE td10ssN) <> prfFCom $(varE prfN)|]
            , valD (tupP [varP x3N, varP td11sN]) (normalB [|squeeze $(varE td11N)|]) []
            , bind td12N [|foldl (\td n -> absorb td (integerToByteString LittleEndian 32 n)) $(varE td11sN) (prfQEvalsOnX3 $(varE prfN))|]
            , valD (tupP [varP x4N, wildP]) (normalB [|squeeze $(varE td12N)|]) []
            ]

    let npN = mkName "np"
        pubOmgsN = mkName "pubOmgs"
        omgBlSN = mkName "omgBlindStart"
        lBlindOmgsN = mkName "lBlindOmgs"
        allDenomsN = mkName "allDenoms"
        allInvsN = mkName "allInvs"
        prefixN = mkName "prefix"
        lagFromInvN = mkName "lagFromInv"
        instEvalCommN = mkName "instEvalComm"
        pubLagsN = mkName "pubLags"
        instEvalPubN = mkName "instEvalPub"
        restInvsN = mkName "restInvs"
        lLastInvN = mkName "lLastInv"
        lBlindInvsN = mkName "lBlindInvs"
        xnMinusOneN = mkName "xnMinusOne"
        hGateN = mkName "hGate"
        hPermFinalN = firstLuAcc

    evalPrepDecls <-
        P.sequence
            [ bind hSplitN [|scale $(intE (nDomain P.- 1)) $(varE xN)|]
            , bind xnMinusOneN [|$(varE hSplitN) * $(varE xN) - Scalar 1|]
            , bind advEvalsN [|map mkScalar (prfAdviceEvals $(varE prfN))|]
            , bind fixEvalsN [|map mkScalar (prfFixedEvals $(varE prfN))|]
            , bind permProdEvalsN [|map mkScalar (prfPermProdEvals $(varE prfN))|]
            , bind sigmaEvalsN [|map mkScalar (prfPermSigmaEvals $(varE prfN))|]
            , bind lookupEvalsN [|map mkScalar (prfLookupEvals $(varE prfN))|]
            , bind trashEvalsN [|map mkScalar (prfTrashEvals $(varE prfN))|]
            , bind randomEvalN [|mkScalar (prfRandomEval $(varE prfN))|]
            , bind npN [|length $(varE pubInputsN)|]
            , bind pubOmgsN [|powers $(varE omgLitN) $(varE npN)|]
            , bind omgBlSN [|$(varE omgLastLitN) * $(varE omgLitN)|]
            , bind lBlindOmgsN [|map ($(varE omgBlSN) *) (powers $(varE omgLitN) $(intE blinding))|]
            , bind allDenomsN [|map ($(varE xN) -) ($(varE pubOmgsN) <> [$(varE omgLastLitN)] <> $(varE lBlindOmgsN)) <> [$(varE xnMinusOneN)]|]
            , bind allInvsN [|batchInverse $(varE allDenomsN)|]
            , bind prefixN [|$(varE xnMinusOneN) * $(varE nInvLitN)|]
            , bind lagFromInvN [|\omgI inv -> omgI * $(varE prefixN) * inv|]
            , bind instEvalCommN [|Scalar 0|]
            , bind pubLagsN [|zipWith $(varE lagFromInvN) $(varE pubOmgsN) $(varE allInvsN)|]
            , bind instEvalPubN [|sum (zipWith (\inp lv -> mkScalar inp * lv) $(varE pubInputsN) $(varE pubLagsN))|]
            , bind instEvalsN [|[$(varE instEvalCommN), $(varE instEvalPubN)]|]
            , bind l0N [|head $(varE pubLagsN)|]
            , bind restInvsN [|drop $(varE npN) $(varE allInvsN)|]
            , bind lLastInvN [|head $(varE restInvsN)|]
            , bind lBlindInvsN [|drop 1 $(varE restInvsN)|]
            , bind lBlindN [|sum (zipWith $(varE lagFromInvN) $(varE lBlindOmgsN) $(varE lBlindInvsN))|]
            , bind lLastN [|$(varE lagFromInvN) $(varE omgLastLitN) $(varE lLastInvN)|]
            , bind (mkName "hInv") [|$(varE lBlindInvsN) !! $(intE blinding)|]
            , bind activeRowsN [|Scalar 1 - $(varE lLastN) - $(varE lBlindN)|]
            ]

    hGateDecl <- bind hGateN (return hGateE)
    hPermDecl <- bind hPermFinalN hPermE

    lookupDecls <-
        P.mapM
            ( \(k, prevN) ->
                bind
                    (luAccN k)
                    (genLookupHorner (vkLookupInputExprs vk) (vkLookupTableExprs vk) k prevN)
            )
            (P.zip [0 .. numLookups P.- 1] (firstLuAcc : P.map luAccN [0 .. numLookups P.- 2]))

    trashDecls <-
        P.mapM
            ( \(t, prevN) -> do
                let selE =
                        genEvalGate
                            advEvalsN
                            fixEvalsN
                            instEvalsN
                            (vkTrashSelectors vk P.!! fromIntegral t)
                    consE =
                        genCompressFold
                            advEvalsN
                            fixEvalsN
                            instEvalsN
                            trashChalN
                            (vkTrashConstraintExprs vk P.!! fromIntegral t)
                    trEv = [|$(varE trashEvalsN) !! $(intE t)|]
                selBody <- selE
                consBody <- consE
                bind
                    (trAccN t)
                    [|
                        $(varE prevN)
                            * $(varE yN)
                            + ($(return consBody) - (Scalar 1 - $(return selBody)) * $(trEv))
                        |]
            )
            (P.zip [0 .. numTrash P.- 1] (firstTrAcc : P.map trAccN [0 .. numTrash P.- 2]))

    let hInvN = mkName "hInv"
    hEvalDecl <- bind hEvalN [|$(varE lastHN) * $(varE hInvN)|]

    -- VOFull-only declarations
    evalPtDecls <-
        P.sequence
            [ bind xNextN [|$(varE xN) * $(varE omgLitN)|]
            , bind xPrevN [|$(varE xN) * $(varE omgInvLitN)|]
            , bind xLastN [|$(varE xN) * $(varE omgLastLitN)|]
            ]

    rotPtDecls <-
        P.sequence
            [ bind advicePtsN [|map bls12_381_G1_uncompress (prfAdviceComs $(varE prfN))|]
            , bind luTablePtsN [|map bls12_381_G1_uncompress (prfLookupTableComs $(varE prfN))|]
            , bind trashPtsN [|map bls12_381_G1_uncompress (prfTrashComs $(varE prfN))|]
            , bind fixedPtsN [|map bls12_381_G1_uncompress $(varE fixedComsN)|]
            , bind permSigmaPtsN [|map bls12_381_G1_uncompress $(varE permSigComsN)|]
            , bind hPtsN [|map bls12_381_G1_uncompress (prfHComs $(varE prfN))|]
            , bind randomPtN [|bls12_381_G1_uncompress (prfRandomCom $(varE prfN))|]
            , bind permProdPtsN [|map bls12_381_G1_uncompress (prfPermProdComs $(varE prfN))|]
            , bind luProdPtsN [|map bls12_381_G1_uncompress (prfLookupProdComs $(varE prfN))|]
            , bind luInputPtsN [|map bls12_381_G1_uncompress (prfLookupInputComs $(varE prfN))|]
            ]

    rotSetDecls <-
        P.mapM
            (\(i, e) -> bind (rotSetN i) (return e))
            (P.zip [0 ..] rotSetEs)

    let fComN = mkName "fCom_"; qEN = mkName "qE"; piPtN = mkName "piPt_"; sG2N = mkName "sG2_"
    finalDecls <-
        P.sequence
            [ bind fComN [|bls12_381_G1_uncompress (prfFCom $(varE prfN))|]
            , bind qEN [|map mkScalar (prfQEvalsOnX3 $(varE prfN))|]
            , bind piPtN [|bls12_381_G1_uncompress (prfPiPt $(varE prfN))|]
            , bind sG2N [|bls12_381_G2_uncompress $(varE srsG2BsN)|]
            ]

    -- ── Assemble based on VOutput ─────────────────────────────────────────────

    let baseDecls =
            [omgLitD, omgInvLitD, omgLastLitD, nInvLitD]
                P.<> byteDecls
                P.<> transcriptDecls
                P.<> evalPrepDecls
                P.<> [hGateDecl]

    let (extraDecls, bodyExpr) = case vOutput of
            VOHGate ->
                ( []
                , [|unScalar $(varE hGateN)|]
                )
            VOHEval ->
                ( [hPermDecl] P.<> lookupDecls P.<> trashDecls P.<> [hEvalDecl]
                , [|unScalar $(varE hEvalN)|]
                )
            VOFull ->
                ( [hPermDecl]
                    P.<> lookupDecls
                    P.<> trashDecls
                    P.<> [hEvalDecl]
                    P.<> evalPtDecls
                    P.<> rotPtDecls
                    P.<> rotSetDecls
                    P.<> finalDecls
                , [|
                    verifyGwc
                        $(varE sG2N)
                        $(varE fComN)
                        $(varE x2N)
                        $(varE x3N)
                        $(varE x4N)
                        $(listE (P.map (varE . rotSetN) [0 .. nSets P.- 1]))
                        $(varE qEN)
                        $(varE piPtN)
                    |]
                )

    let allDecls = baseDecls P.<> extraDecls
    let body = letE (P.map return allDecls) bodyExpr
    lamE [varP prfN, varP pubInputsN] body

-- ── File-reading entry points ─────────────────────────────────────────────────

mkVerifierBase :: VOutput -> P.String -> Q Exp
mkVerifierBase vOutput base = do
    let dec fp = do
            r <- eitherDecodeFileStrict fp
            case r of
                P.Left err -> P.error ("TH JSON error in " P.<> fp P.<> ": " P.<> err)
                P.Right v -> P.return v
    vkJson <- runIO (dec (base P.<> "_plutus_vk.json"))
    ccJson <- runIO (dec (base P.<> "_circuit_constraint.json"))
    rsJson <- runIO (dec (base P.<> "_rotation_sets.json"))
    let vk = parsePlutusVK vkJson ccJson
        specs = parseRotationSets rsJson
    mkVerifier vOutput vk specs

-- | Fully specialised: all loops unrolled and VK bytes inlined as constants.
mkVerifierFromFiles :: P.String -> Code Q (Proof -> [Integer] -> Bool)
mkVerifierFromFiles base = unsafeCodeCoerce (mkVerifierBase VOFull base)

{- | Sub-verifier returning @unScalar hGate@ as an Integer.
Tests 'genHornerFold' + 'genEvalGate' against pure 'computeHGate'.
-}
mkHGateFromFiles :: P.String -> Code Q (Proof -> [Integer] -> Integer)
mkHGateFromFiles base = unsafeCodeCoerce (mkVerifierBase VOHGate base)

{- | Sub-verifier returning @unScalar hEval@ as an Integer.
Tests the full constraint sum (gate + perm + lookup + trash) against 'computeHEval'.
-}
mkHEvalFromFiles :: P.String -> Code Q (Proof -> [Integer] -> Integer)
mkHEvalFromFiles base = unsafeCodeCoerce (mkVerifierBase VOHEval base)
