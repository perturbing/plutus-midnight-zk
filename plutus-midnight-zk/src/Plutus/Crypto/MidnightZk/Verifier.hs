{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# OPTIONS_GHC -fno-full-laziness #-}
{-# OPTIONS_GHC -fno-ignore-interface-pragmas #-}
{-# OPTIONS_GHC -fno-omit-interface-pragmas #-}
{-# OPTIONS_GHC -fno-spec-constr #-}
{-# OPTIONS_GHC -fno-specialise #-}
{-# OPTIONS_GHC -fno-strictness #-}
{-# OPTIONS_GHC -fno-unbox-small-strict-fields #-}
{-# OPTIONS_GHC -fno-unbox-strict-fields #-}

{- | Generic Halo2 GWC verifier for midnight-zk circuits.

= Algorithm Overview (GWC multi-point KZG opening)

Polynomials are grouped into rotation sets S₀, …, Sₘ₋₁. Each Sᵢ contains
polynomials all queried at the same set of evaluation points.

__Level 1 — Within-set batching (challenge x₁):__

> q_i(X)  = Σ_j  x₁^j · poly_{i,j}(X)   (combined polynomial)
> qCom_i  = Σ_j  x₁^j · [poly_{i,j}]₁   (combined commitment via MSM)
> q_i(p)  = Σ_j  x₁^j · poly_{i,j}(p)   (combined evaluation at each p ∈ Sᵢ)

__Level 2 — Across-set reduction via auxiliary polynomial f (challenge x₂):__

> r_i(X)  = Lagrange interpolant of q_i through the points in Sᵢ
> V_i(X)  = ∏_{p ∈ Sᵢ} (X − p)          (vanishing polynomial of Sᵢ)
> c_i     = (q_i(x₃) − r_i(x₃)) / V_i(x₃)   (GWC contribution)
>
> f(x₃)  = c₀ + x₂·(c₁ + x₂·(… + x₂·cₘ₋₁))    (Horner in x₂)

If all claimed evaluations are consistent, (q_i − r_i) vanishes on Sᵢ,
so V_i divides exactly and cᵢ is a well-defined field element.
The prover commits to f and sends fCom.

__Level 3 — Single KZG opening (challenges x₃, x₄):__

> finalCom = Σᵢ x₄^i · qCom_i  +  x₄^m · fCom
> vEval    = Σᵢ x₄^i · q_i(x₃) +  x₄^m · f(x₃)

Single KZG check with witness π = [w(s)]₁ (where f(X)−f(x₃)=(X−x₃)·w(X)):

> e(π, [s]G₂) = e(finalCom − vEval·G₁ + x₃·π, G₂)

Exactly 2 Miller loops regardless of the number of rotation sets.

= Rotation Set Assembly

'assembleRotationSets' is a generic interpreter of a '[RotationSetSpec]' parsed
from @*_rotation_sets.json@. The spec encodes which polynomials belong to which
rotation set and in what x₁-power order — it is produced by the Rust circuit
binary and is deterministic per circuit (does not depend on the witness or proof).

For each 'RotationSetSpec', the assembler:

  * Resolves rotation offsets (0, 1, -1, -(blinding+1)) to evaluation points.
  * Pre-scales each polynomial's commitment by x₁^j.
  * Pre-combines evaluations at each rotation point via dotX1.

The result is a '[RotationSet]' with @rsScaledComs@ and @rsQEvalsAtPts@ ready
for the generic 'verifyGwc' core.

= Linearization Commitment Special Case

The H slot in the rotation sets represents the __linearization commitment__
@lin_com@ (not the raw h polynomial). The prover commits to:

  L(X) = (1−x^n)·h(X) + Σₖ cₖ·Sₖ(X)

where h(X) = Σⱼ (X^{N-1})^ʲ·hⱼ(X) is the vanishing quotient, Sₖ are the
simple (multiplicative) selector fixed columns, and

  cₖ = y^{P+L+T} · Σ_{j: gate j uses Sₖ} gateⱼ(x) · y^{G−1−j}

(y-weighted sum of gate evaluations for gates gated by selector column k,
scaled by the number of perm/logup/trash constraints P+L+T that follow).

At evaluation point x (with Sₖ(x) substituted by 1):

  L(x) = −(x^n−1)·h(x) + Σₖ cₖ  =  (zero − xnMinusOne)·hEval + selGatedSum

This is the value returned as @linComEval@ by 'computeHEval' and used for
the H slot at RotCur in 'assembleRotationSets'.

For the commitment MSM, each h-piece l gets the scalar

  x₁^{hPos} · (1−x^n) · hSplit^l

and each simple selector column k additionally contributes

  x₁^{hPos} · cₖ · [Sₖ]₁

so @lin_com@ occupies one logical slot (with |hPieces|+|selCols| G1 points)
in the x₁-ordering of set 0.
-}
module Plutus.Crypto.MidnightZk.Verifier (
    -- * Main entry point
    verify,

    -- * Generic GWC core (circuit-agnostic)
    verifyGwc,

    -- * Rotation-set assembly (midnight-zk protocol)
    assembleRotationSets,

    -- * Field / group helpers
    powers,
    lagrange,
    horner,
    computeHEval,
    batchInverse,
) where

import GHC.ByteOrder (ByteOrder (..))
import Plutus.Crypto.BlsUtils (
    MultiplicativeGroup (..),
    Scalar (..),
    bls12_381_scalar_delta,
    bls12_381_scalar_prime,
    mkScalar,
 )
import Plutus.Crypto.MidnightZk.Transcript (
    absorb,
    initTranscript,
    squeeze,
 )
import Plutus.Crypto.MidnightZk.Types (
    CircuitConfig (..),
    G1,
    G2,
    GateExpr (..),
    Proof (..),
    Rotation (..),
    RotationSet (..),
    RotationSetSpec (..),
    SlotKind (..),
    SlotSpec (..),
    VerifyingKey (..),
 )
import PlutusTx.Builtins (
    BuiltinByteString,
    bls12_381_G1_compressed_generator,
    bls12_381_G1_compressed_zero,
    bls12_381_G1_multiScalarMul,
    bls12_381_G1_uncompress,
    bls12_381_G2_compressed_generator,
    bls12_381_G2_uncompress,
    bls12_381_finalVerify,
    bls12_381_millerLoop,
    integerToByteString,
 )
import PlutusTx.Foldable (foldl, sum)
import PlutusTx.List (concatMap, drop, head, length, map, reverse, tail, unzip, zip, zipWith, (!!))
import PlutusTx.Numeric (
    AdditiveGroup (..),
    AdditiveMonoid (..),
    AdditiveSemigroup (..),
    Module (..),
    MultiplicativeMonoid (..),
    MultiplicativeSemigroup (..),
 )
import PlutusTx.Prelude (
    Bool (..),
    Eq (..),
    Integer,
    enumFromTo,
    error,
    fst,
    modulo,
    otherwise,
    snd,
    ($),
    (&&),
    (.),
    (<=),
    (<>),
 )

-- ===========================================================================
-- Main entry point
-- ===========================================================================

{- | Verify a midnight-zk Halo2 proof.

@specs@ is the rotation-set layout parsed from @*_rotation_sets.json@.
@pubInputs@ is a list of field elements representing the public circuit inputs.
Returns @True@ iff the proof is valid.

The verifier performs ten steps:

  1. Derive all Fiat-Shamir challenges from the PlutusBlake2b transcript.
  2. Compute evaluation points from x and ω.
  3. Assemble rotation sets using 'specs' (pre-computing combined commitments and evals).
  4–5. (done in assembly) Combined commitments and evaluations per set.
  6. Lagrange interpolants — computed inside 'verifyGwc'.
  7–10. GWC contributions, f(x₃), finalCom/vEval, pairing — in 'verifyGwc'.
-}
{-# INLINEABLE verify #-}
verify :: VerifyingKey -> [RotationSetSpec] -> Proof -> [Integer] -> Bool
verify vk specs prf pubInputs =
    let
        cfg = vkConfig vk
        omg = ccOmega cfg

        -- ── Step 1: Build transcript and derive all challenges ────────────────
        --
        -- Absorb order (must exactly match the v7 LogUp prover's transcript):
        --
        --   VK transcript repr       → absorb
        --   G1 identity (instance)   → absorb (placeholder for instance com)
        --   public inputs            → absorb length, then each element
        --   advice commitments       → absorb; squeeze θ  (lookup compression)
        --   multiplicity coms        → absorb; squeeze β, γ  (logup/perm challenges)
        --   perm z-product coms      → absorb
        --   per-lookup helpers+accum → absorb; squeeze trashChal
        --   trash commitments        → absorb; squeeze y  (gate Horner-folding)
        --   h-piece commitments      → absorb; squeeze x  (evaluation point)
        --   all evaluations          → absorb; squeeze x₁ (within-set combiner)
        --                                      squeeze x₂ (across-set combiner)
        --   fCom                     → absorb; squeeze x₃ (opening point for f)
        --   qEvalsOnX3               → absorb; squeeze x₄ (fold combiner)

        -- Absorb VK transcript repr (circuit identity)
        td0 = initTranscript (vkTranscriptRepr vk)

        -- Absorb G1 identity: placeholder for the instance polynomial commitment.
        td1 = td0 <> bls12_381_G1_compressed_zero

        -- Absorb public inputs: length (LE 32-byte), then each element (LE 32-byte).
        td2 = absorb td1 (integerToByteString LittleEndian 32 (length pubInputs))
        td3 = foldl (\td n -> absorb td (integerToByteString LittleEndian 32 n)) td2 pubInputs

        -- Absorb advice commitments; squeeze θ (lookup compression challenge).
        td4 = foldl (<>) td3 (prfAdviceComs prf)
        (theta, td4s) = squeeze td4

        -- Absorb multiplicity commitments (one per lookup); squeeze β, γ.
        td5 = foldl (<>) td4s (prfLookupMultComs prf)
        (beta, td5b) = squeeze td5
        (gamma, td5g) = squeeze td5b

        -- Absorb perm z-product commitments (no squeeze here).
        td6 = foldl (<>) td5g (prfPermProdComs prf)

        -- Absorb per-lookup LogUp commitments: for each lookup k, absorb helpers then accum.
        -- Then squeeze trash_challenge (once, after ALL lookups).
        td7 = foldl2
                (\td helpers accum -> foldl (<>) td helpers <> accum)
                td6
                (prfLookupHelperComs prf)
                (prfLookupAccumComs prf)
        (trashChal, td7s) = squeeze td7

        -- Absorb trash commitments; squeeze y (gate constraint Horner-folding challenge).
        td7t = foldl (<>) td7s (prfTrashComs prf)
        (y, td8s) = squeeze td7t

        -- Absorb h-piece commitments; squeeze x (the shared evaluation point).
        td9 = foldl (<>) td8s (prfHComs prf)
        (x, td9s) = squeeze td9

        -- Absorb committed instance eval (always 0: committed_pi = G1Affine::identity()).
        -- midnight-proofs writes this value to the transcript immediately after squeezing x
        -- and before the advice evals.  We absorb the constant 0 here to stay in sync.
        -- (The Instance slot in the rotation sets uses eval_idxs pointing into allEvals
        -- which starts at adviceEvals[0], so this eval is NOT in allEvals.)
        td9inst = absorb td9s (integerToByteString LittleEndian 32 0)

        -- Absorb all polynomial evaluations in canonical order:
        --   adviceEvals, fixedEvals (non-simple-selectors only), permSigmaEvals,
        --   permProdEvals, logupEvals, trashEvals, dummyEvals
        --
        -- Simple-selector fixed evals are NOT absorbed (prover omits them; verifier
        -- substitutes 1).  dummyEvals are fewer-point-sets padding evals.
        -- Each list is folded directly — no allEvals concatenation — to avoid
        -- building an O(total_evals) intermediate list in memory.
        absorb32 td n = absorb td (integerToByteString LittleEndian 32 n)
        chkS = unScalar . mkScalar
        td10a = foldl (\td n -> absorb32 td (chkS n)) td9inst (prfAdviceEvals prf)
        td10b = foldl2 (\td isSel n -> if isSel then td else absorb32 td (chkS n))
                    td10a (vkSimpleSelectorMask vk) (prfFixedEvals prf)
        td10c = foldl (\td n -> absorb32 td (chkS n)) td10b (prfPermSigmaEvals prf)
        td10d = foldl (\td n -> absorb32 td (chkS n)) td10c (prfPermProdEvals prf)
        td10e = foldl (\td n -> absorb32 td (chkS n)) td10d (prfLogupEvals prf)
        td10f = foldl (\td n -> absorb32 td (chkS n)) td10e (prfTrashEvals prf)
        td10  = foldl (\td n -> absorb32 td (chkS n)) td10f (prfDummyEvals prf)

        -- Squeeze x₁ (within-set combiner) then x₂ (across-set combiner).
        -- x₁ ≠ x₂ is guaranteed by state replacement.
        (x1, td10s) = squeeze td10
        (x2, td10ss) = squeeze td10s

        -- Absorb fCom; squeeze x₃ (opening point for f).
        td11 = td10ss <> prfFCom prf
        (x3, td11s) = squeeze td11

        -- Absorb q_evals_on_x₃ (one per rotation set); squeeze x₄ (fold combiner).
        td12 =
            foldl
                (\td n -> absorb td (integerToByteString LittleEndian 32 n))
                td11s
                (prfQEvalsOnX3 prf)
        (x4, _) = squeeze td12

        -- ── Step 2: Compute evaluation points ────────────────────────────────
        --
        -- xNext = x · ω              (rotation +1)
        -- xPrev = x · ω⁻¹           (rotation −1)
        -- xLast = x · ω^{−(blinding+1)}  (last usable row rotation)
        --
        -- ω^{−(blinding+1)} is computed by multiplying ω⁻¹ by itself (blinding+1) times.
        -- Since blinding is small (typically 5), this is efficient.
        -- Note: pow2k computes x^{2^k}, NOT x^k, so cannot be used here.

        omgInv = ccOmegaInv cfg
        xNext = x * omg
        omgLast = ccOmegaLast cfg
        xLast = x * omgLast

        -- ── Step 3: Assemble rotation sets ───────────────────────────────────
        --
        -- This is the only circuit-aware step. It uses x, x₁, and the proof/VK
        -- to build [RotationSet] with pre-scaled commitments and pre-combined evals.

        -- ── Step 3 (continued): Derive h(x) from gate expressions ────────────
        --
        -- h(x) = hEvalSum / (x^n − 1), where hEvalSum is the Horner-folded
        -- sum of all gate/perm/lookup/trash constraint evaluations at x.
        -- This replaces the prover-supplied hint: the KZG opening for the
        -- combined h commitment then enforces consistency automatically.
        n = ccDomainSize cfg
        -- hSplit = x^{N-1} is needed both here (for xn) and in assembleRotationSets (for h-pieces).
        -- Computing it once and deriving xn = hSplit * x saves one expModInteger vs scale n x.
        hSplit = scale (n - 1) x
        xnMinusOne = hSplit * x - one
        (hEval, linComEval, selColData) = computeHEval vk prf pubInputs x xnMinusOne y theta beta gamma trashChal

        rotSets = assembleRotationSets vk prf specs x x1 xNext xLast linComEval hSplit xnMinusOne selColData

        fCom' = bls12_381_G1_uncompress (prfFCom prf)
        qE = map mkScalar (prfQEvalsOnX3 prf)
        piPt' = bls12_381_G1_uncompress (prfPiPt prf)
        sG2' = bls12_381_G2_uncompress (vkSrsG2 vk)
     in
        verifyGwc sG2' fCom' x2 x3 x4 rotSets qE piPt'

-- ===========================================================================
-- Gate constraint check
-- ===========================================================================

{- | Evaluate one gate/lookup/trash constraint expression tree.

Structural recursion over 'GateExpr': leaf nodes return constants or proof
evaluations; composite nodes apply field operations to their children.
No stack threading — invalid programs are structurally impossible.

Scalars in 'GEConst' and 'GEScale' are pre-decoded at parse time and lifted
into the Plutus script — zero byte-scanning overhead at on-chain evaluation.
-}
-- | List index without a negative-index bounds check.
-- PlutusTx's built-in '!!' checks n < 0 at every recursion step, costing
-- ~200 ExMem per hop. All indices here are non-negative by construction.
{-# INLINEABLE fastIndex #-}
fastIndex :: [a] -> Integer -> a
fastIndex []     _ = error ()
fastIndex (x:xs) n = if n == 0 then x else fastIndex xs (n - 1)

-- | Strict left fold over two lists in parallel, without building a zip list.
{-# INLINEABLE foldl2 #-}
foldl2 :: (b -> a -> c -> b) -> b -> [a] -> [c] -> b
foldl2 _ acc []     _      = acc
foldl2 _ acc _      []     = acc
foldl2 f acc (x:xs) (y:ys) = foldl2 f (f acc x y) xs ys

{-# INLINEABLE evalGate #-}
evalGate :: GateExpr -> [Scalar] -> [Scalar] -> [Scalar] -> Scalar
evalGate expr adv fix inst = go expr
  where
    go (GEConst s)   = s
    go (GEAdv qi)    = fastIndex adv qi
    go (GEFix qi)    = fastIndex fix qi
    go (GEInst qi)   = fastIndex inst qi
    go (GENeg e)     = zero - go e
    go (GEAdd a b)   = go a + go b
    go (GEMul a b)   = go a * go b
    go (GEScale e s) = go e * s

{- | Derive h(x) from the gate constraint sum.

Computes h(x) = hEvalSum / (x^n − 1), where hEvalSum is the Horner-folded
sum of all circuit constraint expressions evaluated at x.

The KZG opening check in 'verifyGwc' then enforces that the committed h
polynomial actually opens to this value — so h must genuinely encode the
circuit constraints for the proof to pass.
-}
{-# INLINEABLE computeHEval #-}
computeHEval ::
    VerifyingKey ->
    Proof ->
    [Integer] -> -- pubInputs: public instance field elements
    Scalar -> -- x: evaluation point
    Scalar -> -- xnMinusOne = x^n - 1
    Scalar -> -- y: Fiat-Shamir challenge for Horner folding
    Scalar -> -- theta: lookup compression challenge
    Scalar -> -- beta: permutation/lookup challenge
    Scalar -> -- gamma: permutation/lookup challenge
    Scalar -> -- trashChal: trash argument challenge
    (Scalar, Scalar, [(Integer, Scalar)])
    -- ^ (hEval, linComEval, selColData)
computeHEval vk prf pubInputs x xnMinusOne y theta beta gamma trashChal =
    let
        cfg          = vkConfig vk
        blinding     = ccBlinding cfg
        omega        = ccOmega cfg
        chunkSize    = ccPermChunkSize cfg
        numPermCols  = ccNumPermCols cfg
        numChunks    = length (prfPermProdComs prf)
        numLookups   = ccNumLookups cfg
        delta        = mkScalar bls12_381_scalar_delta

        -- Bind VK/proof fields used in inner loops to avoid repeated field extraction
        permColTypes  = vkPermColTypes vk
        liExprs       = vkLookupInputExprs vk
        ltExprs       = vkLookupTableExprs vk
        lsExprs       = vkLookupSelectorExprs vk
        trashSels     = vkTrashSelectors vk
        trashCons     = vkTrashConstraintExprs vk
        trashEvs      = prfTrashEvals prf
        logupEvs      = prfLogupEvals prf
        permProdRaw   = prfPermProdEvals prf
        sigmaRaw      = prfPermSigmaEvals prf

        -- Polynomial evaluations from the proof, lifted to Scalar
        advEvals = map mkScalar (prfAdviceEvals prf)
        fixEvals = map mkScalar (prfFixedEvals prf)

        -- Lagrange basis: L_i(x) = ω^i · (x^n−1) · n⁻¹ / (x − ω^i)
        -- Each evaluation needs one field inversion (x − ω^i).
        -- We need inversions for:
        --   indices 0..np-1       : pub input rows  (x − ω^0, x − ω^1, …)
        --   index  np             : lLast row        (x − ω^{n-blinding-1})
        --   indices np+1..np+b   : blinding rows    (x − ω^{n-blinding}, …)
        --   index  np+1+b        : final h division  (1 / xnMinusOne)
        --
        -- Collecting all np+1+blinding+1 denominators into one batchInverse call
        -- replaces that many recip calls with 1 recip + O(n) multiplications.
        nInv = ccNInv cfg
        np = length pubInputs
        pubOmgs = powers omega np -- [ω^0, ..., ω^{np-1}]
        lLastOmg = ccOmegaLast cfg
        omgBlindStart = lLastOmg * omega -- ω^{n-blinding}
        lBlindOmgs = map (omgBlindStart *) (powers omega blinding)
        allDenoms = map (x -) (pubOmgs <> [lLastOmg] <> lBlindOmgs) <> [xnMinusOne]
        allInvs = batchInverse allDenoms
        prefix = xnMinusOne * nInv
        lagrangeFromInv omgI inv = omgI * prefix * inv

        -- Instance evaluations: midnight-zk circuits have exactly 2 instance
        -- columns.  Col 0 is committed to G1_zero (the zero polynomial); its eval
        -- is hardcoded to 0 here and absorbed as 0 in the transcript above.
        -- Soundness relies on the KZG opening check: if a proof claimed a non-zero
        -- eval for G1_zero, the final pairing check would fail.  This matches the
        -- Rust verifier (proofs/src/plonk/verifier.rs) which also makes no explicit
        -- zero assertion and relies on the same implicit KZG enforcement.
        -- Col 1 is the public input column; its eval is computed via Lagrange.
        instEvalComm = zero
        pubLagranges = zipWith lagrangeFromInv pubOmgs allInvs
        instEvalPub = sum (zipWith (\inp lv -> mkScalar inp * lv) pubInputs pubLagranges)
        instEvals = [instEvalComm, instEvalPub]

        -- Evaluate one gate constraint expression
        evalE e = evalGate e advEvals fixEvals instEvals

        l0 = head pubLagranges
        restInvs0 = drop np allInvs
        lLastInv = head restInvs0
        lBlindInvs = drop 1 restInvs0
        lBlind = sum (zipWith lagrangeFromInv lBlindOmgs lBlindInvs)
        lLast = lagrangeFromInv lLastOmg lLastInv
        hInv = fastIndex lBlindInvs blinding

        activeRows = one - lLast - lBlind

        -- ── Permutation expressions ───────────────────────────────────────────

        -- Get proof evaluation for a permutation column (advice/fixed/instance)
        getPermColEval globalIdx =
            let (ct, ei) = fastIndex permColTypes globalIdx
             in if ct == 0
                    then fastIndex advEvals ei
                    else
                        if ct == 1
                            then fastIndex fixEvals ei
                            else fastIndex instEvals ei -- ct == 2
        permProdEvals = map mkScalar permProdRaw
        sigmaEvals = map mkScalar sigmaRaw
        ppEval j fld = fastIndex permProdEvals (3 * j + fld)
        sigmaEval i = fastIndex sigmaEvals i

        -- Number of columns in chunk j
        chunkColCount j =
            if j <= numChunks - 2
                then chunkSize
                else numPermCols - (numChunks - 1) * chunkSize

        -- Product constraint for chunk j, given curDelta = δ^{j·chunkSize}.
        -- Returns (constraint, δ^{(j+1)·chunkSize}) so the caller can thread
        -- curDelta across chunks without any expModInteger.
        --   activeRows * (z_j(ωx) · Π(col + β·σ + γ) − z_j(x) · Π(col + δ^gi·β·x + γ))
        -- where δ = bls12_381_scalar_delta (7^{2^32} mod q), the BLS12-381 coset generator.
        permChunkConstraint j curDelta =
            let nc = chunkColCount j
                -- Single pass: compute leftProd, rightProd, nextDelta together,
                -- sharing getPermColEval per column and using one enumFromTo.
                (leftProd, rightProd, nextDelta) =
                    foldl
                        ( \(lAcc, rAcc, cd) k ->
                            let gi = j * chunkSize + k
                                ce = getPermColEval gi
                                se = sigmaEval gi
                                shift = cd * beta * x
                             in ( lAcc * (ce + beta * se + gamma)
                                , rAcc * (ce + shift + gamma)
                                , cd * delta
                                )
                        )
                        (ppEval j 1, ppEval j 0, curDelta)
                        (enumFromTo 0 (nc - 1))
             in (activeRows * (leftProd - rightProd), nextDelta)

        -- ── Horner-fold all expressions with y ────────────────────────────────
        selColList = vkSimpleSelColList vk

        -- Evaluate all gate expressions on-chain; Horner-fold for hGate.
        -- Also build gvWithCols (one pass) for the per-column selFold Horner folds.
        -- selFold_k = foldl (\acc (gv,col) -> acc*y + if col==sc then gv else 0) 0 gvWithCols
        --           = Σ_{j: col_j=k} gv_j · y^{G−1−j}   (same y-weighting as hGate)
        -- This avoids building intermediate yPowsDesc, gateYPows, and S separate zipWith lists.
        gateColIdxs = vkGateSelCols vk
        gateVals = map evalE (vkGatePolys vk)
        gvWithCols = zip gateVals gateColIdxs
        hGate = foldl (\acc gv -> acc * y + gv) zero gateVals
        finalSelFolds = map (\sc -> foldl (\acc (gv, col) -> acc * y + if col == sc then gv else zero) zero gvWithCols) selColList

        -- Perm: two fixed exprs, then numChunks-1 continuation exprs, then numChunks chunk exprs
        hPerm =
            let hP0 = hGate * y + l0 * (one - ppEval 0 0)
                hP1 = hP0 * y + lLast * (let zl = ppEval (numChunks - 1) 0 in zl * zl - zl)
                hP2 = foldl (\acc j -> acc * y + l0 * (ppEval (j + 1) 0 - ppEval j 2)) hP1 (enumFromTo 0 (numChunks - 2))
                (result, _) = foldl (\(acc, cd) j -> let (c, cd') = permChunkConstraint j cd in (acc * y + c, cd')) (hP2, one) (enumFromTo 0 (numChunks - 1))
            in result

        -- LogUp: each lookup's (nc+2) constraints folded, threading the eval offset
        (hLookup, _) = foldl (logupHornerForK liExprs ltExprs lsExprs logupEvs l0 lLast activeRows theta beta y evalE) (hPerm, 0) (enumFromTo 0 (numLookups - 1))

        -- Trash: inline each trash expr, no intermediate map list
        numTrash = length trashSels
        hEvalSum =
            foldl
                ( \acc t ->
                    let trashE = mkScalar (fastIndex trashEvs t)
                        selE = evalE (fastIndex trashSels t)
                        consExprs = fastIndex trashCons t
                        compressed = foldl (\a e -> a * trashChal + evalE e) zero consExprs
                     in acc * y + (compressed - (one - selE) * trashE)
                )
                hLookup
                (enumFromTo 0 (numTrash - 1))
        hEval = hEvalSum * hInv

        -- ── Linearization commitment evaluation ───────────────────────────────
        -- The lin_com polynomial is L(X) = (1-x^n)*h(X) + Σ_k c_k * S_k(X).
        -- At x, with S_k(x) = 1 (simple selector substitution):
        --   L(x) = -(x^n-1)*h(x) + Σ_k c_k
        --
        -- c_k = y^{nRemaining} * selFold_k, where selFold_k is the partial Horner
        -- sum of gate evaluations for gates gated by simple selector column k,
        -- and nRemaining = P + L + T is the count of perm+logup+trash expressions
        -- that are folded after the gate fold (each multiplying gate contributions
        -- by y^{nRemaining} more).
        --
        -- nP = 2*numChunks+1: perm constraint count
        -- nL = Σ_k (nc_k + 2): logup constraint count (boundary + nc helpers + accum per lookup)
        -- nT = numTrash: trash constraint count
        nP = 2 * numChunks + 1
        nL = foldl (\acc k -> acc + length (fastIndex liExprs k) + 2) 0 (enumFromTo 0 (numLookups - 1))
        nT = numTrash
        nRemaining = nP + nL + nT
        yNRem = scale nRemaining y -- y^{nRemaining}
        -- c_k = selFold_k * y^{nRemaining}
        selColData = zipWith (\sc sf -> (sc, sf * yNRem)) selColList finalSelFolds
        selGatedSum = sum (map snd selColData)
        linComEval = (zero - xnMinusOne) * hEval + selGatedSum
     in
        (hEval, linComEval, selColData)

{- | Horner-fold the LogUp constraints for lookup k.

For a lookup with nc_k chunks, yields nc_k + 2 constraints (in this order):

  * Boundary:    @(l₀ + l_last) · Z(x)@
  * Helper×nc_k: @h_c · Π_j(f_j+β) − Σ_j Π_{k≠j}(f_k+β)@ for each chunk c
  * Accumulator: @active · ((Z_next − Z − selector·Σh) · (t+β) + m)@

The function also advances the flat eval @offset@ by nc_k + 3.
-}
{-# INLINEABLE logupHornerForK #-}
logupHornerForK ::
    [[[[GateExpr]]]] -> -- liExprs: per-lookup chunk expressions
    [[GateExpr]] ->     -- ltExprs: per-lookup table expressions
    [GateExpr] ->       -- lsExprs: per-lookup selector expressions
    [Integer] ->        -- logupEvs: flat LogUp evaluations
    Scalar -> -- l₀
    Scalar -> -- l_last
    Scalar -> -- activeRows = 1 − l_last − l_blind
    Scalar -> -- θ: compression challenge
    Scalar -> -- β: LogUp challenge
    Scalar -> -- y: Horner challenge
    (GateExpr -> Scalar) -> -- evalE: on-chain gate expression evaluator
    (Scalar, Integer) -> -- (accumulator, offset)
    Integer -> -- k: lookup index
    (Scalar, Integer)
logupHornerForK liExprs ltExprs lsExprs logupEvs l0 lLast activeRows theta beta y evalE (acc, offset) k =
    let
        chunkExprs = fastIndex liExprs k
        nc = length chunkExprs

        -- Extract LogUp evals from the flat array at this lookup's offset:
        --   offset+0: mult_eval; +1..+nc: helper_evals; +nc+1: accum_eval; +nc+2: accum_next_eval
        multEval      = mkScalar (fastIndex logupEvs offset)
        helperEvals   = map (\j -> mkScalar (fastIndex logupEvs (offset + 1 + j))) (enumFromTo 0 (nc - 1))
        accumEval     = mkScalar (fastIndex logupEvs (offset + nc + 1))
        accumNextEval = mkScalar (fastIndex logupEvs (offset + nc + 2))

        compressExprs exprs = foldl (\a e -> a * theta + evalE e) zero exprs

        -- 1. Boundary: (l₀ + l_last) · Z(x)
        boundary = (l0 + lLast) * accumEval
        acc1 = acc * y + boundary

        -- 2. Helper constraints
        acc2 =
            foldl
                (\a (parallelInputExprs, h_c) ->
                    let fsBeta = map (\ws -> compressExprs ws + beta) parallelInputExprs
                        product_c = foldl (*) one fsBeta
                        sumParts  = sum (partialProds fsBeta)
                    in a * y + (h_c * product_c - sumParts))
                acc1
                (zip chunkExprs helperEvals)

        -- 3. Accumulator constraint on active rows:
        --    active · ((Z_next − Z − selector · Σ_c h_c) · (t + β) + m) = 0
        tableCompressed = compressExprs (fastIndex ltExprs k)
        selectorVal = evalE (fastIndex lsExprs k)
        sumH = foldl (+) zero helperEvals
        accumConstraint =
            activeRows *
            ((accumNextEval - accumEval - selectorVal * sumH) * (tableCompressed + beta) + multEval)

        acc3 = acc2 * y + accumConstraint
    in
        (acc3, offset + nc + 3)

{- | For a list @[a₀, …, aₙ₋₁]@, return @[Π_{k≠0}aₖ, …, Π_{k≠n−1}aₖ]@.

Uses a prefix/suffix product sweep — no field inversions required.
-}
{-# INLINEABLE partialProds #-}
partialProds :: [Scalar] -> [Scalar]
partialProds []  = []
partialProds [_] = [one]
partialProds xs  =
    let revList  = foldl (\acc x -> x : acc) [] xs
        (revPfxs, _) = foldl (\(ps, acc) x -> (acc : ps, acc * x)) ([], one) xs
        (result, _)  =
            foldl
                (\(res, sfx) (pfx, rx) -> (pfx * sfx : res, sfx * rx))
                ([], one)
                (zip revPfxs revList)
    in result

-- ===========================================================================
-- Generic GWC core (circuit-agnostic)
-- ===========================================================================

{- | Generic GWC verifier (Steps 6–10). Circuit-agnostic: it operates only on
the pre-assembled '[RotationSet]' values and the prover's claimed q_i(x₃).

Steps performed:

  6. Lagrange interpolation r_i(x₃) for each set (using 'rsQEvalsAtPts').
  7. GWC contribution c_i = (q_i(x₃) − r_i(x₃)) / V_i(x₃) per set.
  8. f(x₃) = c₀ + x₂·(c₁ + x₂·(…)) via Horner in x₂.
  9. finalCom = Σ x₄^i · qCom_i + x₄^m · fCom  and  vEval = Σ x₄^i · qE_i + x₄^m · f(x₃).
  10. KZG pairing check: e(π, [s]G₂) = e(finalCom − vEval·G₁ + x₃·π, G₂).
-}
{-# INLINEABLE verifyGwc #-}
verifyGwc ::
    -- | [s]G₂: SRS point
    G2 ->
    -- | fCom: GWC auxiliary polynomial commitment
    G1 ->
    -- | x₂: across-set Horner combiner
    Scalar ->
    -- | x₃: opening point
    Scalar ->
    -- | x₄: fold combiner
    Scalar ->
    [RotationSet] ->
    -- | qE_i = q_i(x₃) from prfQEvalsOnX3 (one per set)
    [Scalar] ->
    -- | π: KZG opening witness
    G1 ->
    Bool
verifyGwc sG2 fCom x2 x3 x4 rotSets qE piPt =
    let
        -- ── Steps 6–7: Lagrange interpolants and GWC contributions ──────────
        --
        -- c_i = (q_i(x₃) − r_i(x₃)) / V_i(x₃),  V_i(x₃) = Π_{p ∈ Sᵢ} (x₃ − p)
        --
        -- Each rotation set needs one field inversion. Collect all m denominators
        -- and batch-invert in one recip call (Montgomery's trick), then multiply
        -- each numerator by its inverse.
        --
        -- Numerator/denominator per set (shared (x₃−p) subexpressions):
        --   n=1: num = qE − v₀,                      den = x₃ − p₀
        --   n=2: num = qE·(p₀−p₁) − v₀·(x₃−p₁) + v₁·(x₃−p₀),
        --              den = (p₀−p₁)·(x₃−p₀)·(x₃−p₁)
        --   n≥3: num = qE − r(x₃),                   den = Π(x₃ − pⱼ)

        (nums, dens) = unzip (zipWith (\rs qEi -> gwcNumDen (rsPoints rs) (rsQEvalsAtPts rs) qEi x3) rotSets qE)
        invDenoms = batchInverse dens
        contribs = zipWith (*) nums invDenoms

        -- ── Step 8: f(x₃) via Horner in x₂ ──────────────────────────────
        --
        -- f(x₃) = c₀ + x₂·(c₁ + x₂·(c₂ + x₂·(…)))
        --
        -- x₂ is drawn after the evaluations are absorbed, preventing an
        -- attacker from cancelling errors across different sorted sets.

        fEval = horner x2 contribs

        -- ── Steps 9–10: Mega-MSM for right and vEval ─────────────────────
        --
        -- vEval  = Σᵢ x₄^i · q_i(x₃) + x₄^m · f(x₃)
        --
        -- KZG check: e(π, [s]G₂) = e(right, G₂)
        -- right  = Σᵢ Σ_j (x₄^i · x₁^j) · [poly_{i,j}]₁
        --            +  x₄^m · fCom  +  x₃ · π  −  vEval · G₁
        --
        -- Single foldl threads the x₄ power, accumulates vEval, and builds
        -- scalar/point lists by prepending (O(newItems) per step, no copies).
        -- MSM commutativity (Σ sᵢ·Pᵢ) means reversed set order is correct.

        (revScalars, revPoints, x4m, vEvalQE) =
            foldl
                ( \(ss, ps, x4i, v) (rs, qEi) ->
                    let x4i_int = unScalar x4i
                     in ( map (\s -> (x4i_int * s) `modulo` bls12_381_scalar_prime) (rsComScalars rs) <> ss
                        , rsComs rs <> ps
                        , x4i * x4
                        , v + x4i * qEi
                        )
                )
                ([], [], one, zero)
                (zip rotSets qE)
        vEval = vEvalQE + x4m * fEval
        g1Gen = bls12_381_G1_uncompress bls12_381_G1_compressed_generator
        g2Gen = bls12_381_G2_uncompress bls12_381_G2_compressed_generator
        allScalars = unScalar x4m : unScalar x3 : unScalar (zero - vEval) : revScalars
        allPoints = fCom : piPt : g1Gen : revPoints
        right = bls12_381_G1_multiScalarMul allScalars allPoints
     in
        bls12_381_finalVerify
            (bls12_381_millerLoop piPt sG2)
            (bls12_381_millerLoop right g2Gen)

-- ===========================================================================
-- Rotation set assembly (midnight-zk circuit structure)
-- ===========================================================================

{- | Generic rotation-set assembler: interprets a '[RotationSetSpec]' parsed
from @*_rotation_sets.json@ to build the '[RotationSet]' values used by 'verifyGwc'.

Each returned 'RotationSet' carries:

  * @rsPoints@: the actual evaluation points (resolved from rotation offsets).
  * @rsScaledComs@: [x₁^j · [poly_j(s)]₁, …], so qCom_i = Σ rsScaledComs.
  * @rsQEvalsAtPts@: [q_i(p₀), q_i(p₁), …], pre-combined with x₁ powers,
    used directly for Lagrange interpolation in 'verifyGwc'.
-}
{-# INLINEABLE assembleRotationSets #-}
assembleRotationSets ::
    VerifyingKey ->
    Proof ->
    -- | Rotation-set layout from *_rotation_sets.json
    [RotationSetSpec] ->
    -- | x:     evaluation point
    Scalar ->
    -- | x₁:    within-set combiner
    Scalar ->
    -- | x·ω:   rotation +1
    Scalar ->
    -- | x·ω^{−(blinding+1)}: last usable row rotation
    Scalar ->
    -- | L(x): linearization commitment evaluation (from 'computeHEval')
    Scalar ->
    -- | x^{N-1}: precomputed in 'verify' to share with xn = hSplit·x
    Scalar ->
    -- | x^n − 1: used to scale h-piece commitment scalars by (1 − x^n)
    Scalar ->
    -- | [(col_idx, c_k)]: simple-selector commitment scalars from 'computeHEval'
    [(Integer, Scalar)] ->
    [RotationSet]
assembleRotationSets vk prf specs x x1 xNext xLast linComEval hSplit xnMinusOne selColData =
    let
        -- G1 elements decoded once; bls12_381_G1_uncompress paid once per commitment.
        advicePts     = map bls12_381_G1_uncompress (prfAdviceComs prf)
        lookupMultPts = map bls12_381_G1_uncompress (prfLookupMultComs prf)
        -- Flat list of all LogUp helper commitments across all lookups
        lookupHelperPts = map bls12_381_G1_uncompress (concatMap (\x -> x) (prfLookupHelperComs prf))
        lookupAccumPts  = map bls12_381_G1_uncompress (prfLookupAccumComs prf)
        trashPts      = map bls12_381_G1_uncompress (prfTrashComs prf)
        fixedPts      = map bls12_381_G1_uncompress (vkFixedComs vk)
        permSigmaPts  = map bls12_381_G1_uncompress (vkPermSigmaComs vk)
        hPts          = map bls12_381_G1_uncompress (prfHComs prf)
        permProdPts   = map bls12_381_G1_uncompress (prfPermProdComs prf)

        -- ── Resolve a rotation offset to an evaluation point ─────────────
        omg     = ccOmega (vkConfig vk)
        omgInv  = ccOmegaInv (vkConfig vk)
        blinding = ccBlinding (vkConfig vk)

        toRotation :: Integer -> Rotation
        toRotation r
            | r == 0 = RotCur
            | r == 1 = RotNext
            | r == (-1) = RotPrev
            | r == -(blinding + 1) = RotLast
            | otherwise = RotArb r

        evalPt :: Rotation -> Scalar
        evalPt RotCur  = x
        evalPt RotNext = xNext
        evalPt RotPrev = x * omgInv  -- rotation −1 (not used in v7 circuits but kept for completeness)
        evalPt RotLast = xLast
        evalPt (RotArb r)
            | 1 <= r    = x * fastIndex (powers omg (r + 1)) r
            | otherwise = x * fastIndex (powers omgInv ((-r) + 1)) (-r)

        -- ── (scalar, G1) pair(s) for one slot ────────────────────────────
        getComPairs :: Scalar -> SlotSpec -> ([Scalar], [G1])
        getComPairs x1j ss =
            let i = ssIndex ss
             in case ssKind ss of
                    SKInstance    -> ([], [])  -- zero polynomial; contributes nothing
                    SKH           ->
                        -- lin_com(X) = (1-x^n)*h(X) + Σ_k c_k * S_k(X)
                        -- The verifier-side MSM for the H slot:
                        --   h-pieces: x1j * (1-x^n) * hSplit^l * [h_l]  for each piece l
                        --   sel cols: x1j * c_k * [S_k]                 for each simple sel col k
                        let nh = ccNumHPieces (vkConfig vk)
                            negXnM1 = zero - xnMinusOne  -- (1 - x^n) = -(x^n - 1)
                            scale01 = x1j * negXnM1
                            hPieceScalars = map (scale01 *) (powers hSplit nh)
                            selScalars = map (\(_, ck) -> x1j * ck) selColData
                            selPts = map (\(colIdx, _) -> fastIndex fixedPts colIdx) selColData
                        in (hPieceScalars <> selScalars, hPts <> selPts)
                    SKAdvice      -> ([x1j], [fastIndex advicePts i])
                    SKLogupMult   -> ([x1j], [fastIndex lookupMultPts i])
                    SKTrash       -> ([x1j], [fastIndex trashPts i])
                    SKFixed       -> ([x1j], [fastIndex fixedPts i])
                    SKPermSigma   -> ([x1j], [fastIndex permSigmaPts i])
                    SKPermProd    -> ([x1j], [fastIndex permProdPts i])
                    SKLogupAccum  -> ([x1j], [fastIndex lookupAccumPts i])
                    SKLogupHelper -> ([x1j], [fastIndex lookupHelperPts i])

        -- ── Evaluation of one slot at a given rotation position ─────────
        -- ssEvalVals is precomputed at parse time (off-chain), so indexing by rotPos
        -- costs O(rotPos) ≤ O(4) rather than O(absIdx) ≤ O(195).
        -- SKH at RotCur uses the verifier-derived linComEval = L(x).
        -- SKInstance is always zero (committed to G1_zero).
        getEval :: SlotSpec -> Integer -> Rotation -> Scalar
        getEval ss rotPos rot =
            case ssKind ss of
                SKH        -> case rot of
                                  RotCur -> linComEval
                                  _      -> fastIndex (ssEvalVals ss) rotPos
                SKInstance -> zero
                _          -> fastIndex (ssEvalVals ss) rotPos

        -- ── Build one RotationSet from its spec ───────────────────────────
        buildSet :: RotationSetSpec -> RotationSet
        buildSet spec =
            let rotInts = rssRotations spec
                rots = map toRotation rotInts
                slots = rssSlots spec
                nSlots = length slots
                nRots = length rots
                x1Powers = powers x1 nSlots
                pairs = zipWith getComPairs x1Powers slots
                comScalars = map unScalar (concatMap fst pairs)
                coms = concatMap snd pairs
                qEvalsAtPts =
                    zipWith
                        (\rotPos rot -> sum (zipWith (\x1j ss -> x1j * getEval ss rotPos rot) x1Powers slots))
                        (enumFromTo 0 (nRots - 1))
                        rots
             in RotationSet
                    { rsPoints = map evalPt rots
                    , rsComScalars = comScalars
                    , rsComs = coms
                    , rsQEvalsAtPts = qEvalsAtPts
                    }
     in
        map buildSet specs

-- ===========================================================================
-- Field and group helpers
-- ===========================================================================

-- | Compute [1, x, x², …, x^{n−1}].
{-# INLINEABLE powers #-}
powers :: Scalar -> Integer -> [Scalar]
powers x = go one
  where
    go acc k =
        if k <= 0
            then []
            else acc : go (acc * x) (k - 1)

{- | Fold a list with Horner's method in x.

> horner x [c₀, c₁, …, cₙ₋₁] = c₀ + x·(c₁ + x·(… + x·cₙ₋₁))

Used for the across-set f(x₃) = c₀ + x₂·(c₁ + x₂·(… + x₂·cₘ₋₁)).
-}
{-# INLINEABLE horner #-}
horner :: Scalar -> [Scalar] -> Scalar
horner _ [] = zero
horner _ [c] = c
horner x2 (c : cs) = c + x2 * horner x2 cs

{- | Generic Lagrange interpolation at a target point x₃.

Given n distinct points @ps = [p₀, …, p_{n−1}]@ and values @vs = [v₀, …, v_{n−1}]@,
returns the unique polynomial r of degree < n evaluated at x₃:

> r(x₃) = Σ_j  v_j · L_j(x₃)
>
> where L_j(x₃) = ∏_{k≠j} (x₃ − p_k) / (p_j − p_k)

Using the identity L_j(x₃) = V(x₃) / ((x₃ − p_j) · w_j)  where
V(x₃) = ∏_k (x₃ − p_k) and w_j = ∏_{k≠j} (p_j − p_k):

> r(x₃) = V(x₃) · Σ_j  v_j / ((x₃ − p_j) · w_j)

The n denominators @(x₃ − p_j) · w_j@ are batch-inverted with one 'recip'
call (Montgomery's trick), replacing the n individual 'recip' calls that a
naive per-basis implementation would require.
-}
{-# INLINEABLE lagrange #-}
lagrange :: [Scalar] -> [Scalar] -> Scalar -> Scalar
lagrange [_] [v] _ = v
lagrange ps vs x3 =
    -- diffs[j] = x3 - p_j;  bigV = Π diffs (vanishing poly)
    let diffs = map (x3 -) ps
        bigV = foldl (*) one diffs
        -- bdens[j] = Π_{k≠j} (p_j - p_k)  (Lagrange basis denominator)
        bdens = map (\pj -> foldl (\a pk -> if pk == pj then a else a * (pj - pk)) one ps) ps
        -- combined[j] = (x3 - p_j) · Π_{k≠j}(p_j - p_k); invert all at once
        invs = batchInverse (zipWith (*) diffs bdens)
     in -- L_j(x3) = bigV · invs[j];  r(x3) = bigV · Σ_j v_j · invs[j]
        bigV * sum (zipWith (*) vs invs)

{- | GWC contribution for one rotation set.

> c_i = (qEvalAtX3 − rAtX3) / V_i(x₃)
>
> where V_i(x₃) = ∏_{p ∈ pts} (x₃ − p)

If the prover's claimed evaluations are consistent with the commitments,
(q_i − r_i) vanishes on Sᵢ and V_i divides exactly.
-}

{- | Split a GWC contribution into @(numerator, denominator)@ for batch inversion.

The caller collects all denominators, batch-inverts in one 'recip', then multiplies:
@c_i = numerator_i * batchInverse(denominator_i)@.

Shared @(x₃ − p)@ sub-expressions are computed once per case:

  * |Sᵢ|=1: @num = qE − v₀@,  @den = x₃ − p₀@
  * |Sᵢ|=2: @num = qE·(p₀−p₁) − v₀·(x₃−p₁) + v₁·(x₃−p₀)@,
             @den = (p₀−p₁)·(x₃−p₀)·(x₃−p₁)@
  * |Sᵢ|≥3: @num = qE − r(x₃)@,  @den = Π_{p ∈ pts} (x₃ − p)@
-}
{-# INLINEABLE gwcNumDen #-}
gwcNumDen :: [Scalar] -> [Scalar] -> Scalar -> Scalar -> (Scalar, Scalar)
gwcNumDen [p0] [v0] qE x3 =
    (qE - v0, x3 - p0)
gwcNumDen [p0, p1] [v0, v1] qE x3 =
    let d0 = x3 - p0
        d1 = x3 - p1
        dp = p0 - p1
     in (qE * dp - v0 * d1 + v1 * d0, dp * d0 * d1)
gwcNumDen pts vs qE x3 =
    (qE - lagrange pts vs x3, foldl (\acc p -> acc * (x3 - p)) one pts)

{- | Montgomery batch modular inversion.

Given @[d₀, d₁, …, d_{n−1}]@, returns @[1/d₀, 1/d₁, …, 1/d_{n−1}]@ using one
@recip@ call and O(n) multiplications instead of n separate @recip@ calls.

Forward pass accumulates prefix products and the input list in reverse; the
backward pass recovers individual inverses from the total inverse.
-}
{-# INLINEABLE batchInverse #-}
batchInverse :: [Scalar] -> [Scalar]
batchInverse [] = []
batchInverse [d] = [recip d]
batchInverse ds =
    let
        -- Forward pass: one left-fold over ds.
        --   acc  = running product d₀·d₁·…·dₖ  (becomes `total` at the end)
        --   pps  = [d₀·…·d_{k-1}, …, d₀, 1]   prefix products, newest first
        --   rds  = [dₖ, …, d₁, d₀]             inputs in reverse
        --
        -- After the fold:
        --   total        = d₀·d₁·…·d_{n-1}
        --   revPrevProds = [d₀·…·d_{n-2}, …, d₀, 1]   (prev-product for each d, reversed)
        --   revDs        = [d_{n-1}, …, d₀]
        (total, revPrevProds, revDs) =
            foldl
                (\(acc, pps, rds) d -> (acc * d, acc : pps, d : rds))
                (one, [], [])
                ds

        -- Backward pass: one left-fold over zip revDs revPrevProds.
        --   r   = running suffix inverse, starts at 1/total
        --   is  = result list, built left-to-right (prepend → final order correct)
        --
        -- At each step for (dₖ, pp) where pp = d₀·…·d_{k-1}:
        --   1/dₖ = r · pp   because r = 1/(d₀·…·dₖ) and pp = d₀·…·d_{k-1}
        --   advance r → r · dₖ  =  1/(d₀·…·d_{k-1})  for the next step
        (invs, _) =
            foldl
                (\(is, r) (d, pp) -> (r * pp : is, r * d))
                ([], recip total)
                (zip revDs revPrevProds)
     in
        invs
