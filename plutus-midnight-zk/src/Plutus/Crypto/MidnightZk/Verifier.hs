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

= h-piece Special Case

h(X) = Σⱼ (X^{N-1})^j · hⱼ(X), so at evaluation point x:

  h(x) = Σⱼ (x^{N-1})^j · hⱼ(x)

The evaluation h(x) is derived by the verifier from the gate constraint sum:

  h(x) = (Σᵢ yⁱ · constraintᵢ(x)) / (x^n − 1)

This is the PLONK step-8 reconstruction: since the verifier already evaluates
all advice/fixed/permutation/lookup polynomials at x, it can compute the
numerator for free, and one field inversion gives h(x).  No prover hint is
needed; the KZG opening for the combined h commitment enforces consistency.

For the commitment MSM, each h-piece j gets the scalar

  x₁^{hPos} · hSplit^j,  where hSplit = x^{N-1}, hPos = 1 + nl + nf + np

so h(X) occupies one logical slot in the x₁-ordering of set 0.
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
import PlutusTx.List (concatMap, drop, head, length, map, unzip, zip, zipWith, (!!))
import PlutusTx.Numeric (
    AdditiveGroup (..),
    AdditiveMonoid (..),
    AdditiveSemigroup (..),
    Module (..),
    MultiplicativeMonoid (..),
    MultiplicativeSemigroup (..),
 )
import PlutusTx.Prelude (
    Bool,
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
        -- Absorb order (must exactly match the prover's transcript):
        --
        --   VK transcript repr       → absorb
        --   G1 identity (instance)   → absorb (placeholder for instance com)
        --   public inputs            → absorb length, then each element
        --   advice commitments       → absorb; squeeze θ  (lookup compression challenge)
        --   lookup input+table coms  → absorb interleaved; squeeze β, γ  (perm/lookup challenges)
        --   perm+lookup prod coms    → absorb; squeeze trash; absorb trash coms
        --   random poly commitment   → absorb; squeeze y  (gate Horner-folding challenge)
        --   h-piece commitments      → absorb; squeeze x  (evaluation point)
        --   all evaluations          → absorb; squeeze x₁ (within-set combiner)
        --                                      squeeze x₂ (across-set combiner)
        --   fCom                     → absorb; squeeze x₃ (opening point for f)
        --   qEvalsOnX3               → absorb; squeeze x₄ (fold combiner)
        --
        -- All challenges are used: θ/β/γ/trash/y in computeHEval (gate constraint check);
        -- x/x₁/x₂/x₃/x₄ in assembleRotationSets and verifyGwc.

        -- Absorb VK transcript repr (circuit identity)
        td0 = initTranscript (vkTranscriptRepr vk)

        -- Absorb G1 identity: placeholder for the instance polynomial commitment.
        -- The instance commitment is the G1 zero point (public inputs are not
        -- blinded). It must still be absorbed to match the prover.
        td1 = td0 <> bls12_381_G1_compressed_zero

        -- Absorb public inputs: length (LE 32-byte), then each element (LE 32-byte).
        td2 = absorb td1 (integerToByteString LittleEndian 32 (length pubInputs))
        td3 = foldl (\td n -> absorb td (integerToByteString LittleEndian 32 n)) td2 pubInputs

        -- Absorb advice commitments; squeeze θ (used for lookup compression).
        td4 = foldl (<>) td3 (prfAdviceComs prf)
        (theta, td4s) = squeeze td4

        -- Absorb lookup permuted-input and permuted-table commitments interleaved
        -- as [A'₀, S'₀, A'₁, S'₁, …]; squeeze β then γ.
        -- zipWith (<>) pairs bytes as A'ᵢ<>S'ᵢ; foldl (<>) appends — same total
        -- byte sequence as interleaving because ByteString (<>) is associative.
        td5 = foldl (<>) td4s (zipWith (<>) (prfLookupInputComs prf) (prfLookupTableComs prf))
        (beta, td5s) = squeeze td5
        (gamma, td5ss) = squeeze td5s

        -- Absorb perm product commitments then lookup product commitments; squeeze
        -- the trash_challenge. Then absorb any extra blinding (trash)
        -- commitments (when blinding_factors > 5).
        -- NOTE: squeeze happens BEFORE trash coms, matching the Rust prover order.
        td6 = foldl (<>) td5ss (prfPermProdComs prf)
        td7 = foldl (<>) td6 (prfLookupProdComs prf)
        (trashChal, td7s) = squeeze td7 -- trash_challenge (before trash coms)
        td7t = foldl (<>) td7s (prfTrashComs prf) -- absorb trash coms after squeeze

        -- Absorb random polynomial commitment; squeeze y (used for gate constraint check).
        td8r = td7t <> prfRandomCom prf
        (y, td8s) = squeeze td8r

        -- Absorb h-piece commitments; squeeze x (the shared evaluation point).
        td9 = foldl (<>) td8s (prfHComs prf)
        (x, td9s) = squeeze td9

        -- Absorb all polynomial evaluations in canonical order:
        --   instEval, adviceEvals, fixedEvals, randomEval,
        --   permSigmaEvals, permProdEvals, lookupEvals, trashEvals
        --
        -- mkScalar validates each integer is in [0, q): a proof containing an
        -- out-of-range scalar is rejected here rather than silently mis-hashed.
        chkS = unScalar . mkScalar
        allEvals =
            [0] -- instance_poly_eval hardcoded 0 (col 0 is the zero polynomial)
                <> map chkS (prfAdviceEvals prf)
                <> map chkS (prfFixedEvals prf)
                <> [chkS (prfRandomEval prf)]
                <> map chkS (prfPermSigmaEvals prf)
                <> map chkS (prfPermProdEvals prf)
                <> map chkS (prfLookupEvals prf)
                <> map chkS (prfTrashEvals prf)
        td10 =
            foldl
                (\td n -> absorb td (integerToByteString LittleEndian 32 n))
                td9s
                allEvals

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
        xPrev = x * omgInv
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
        hEval = computeHEval vk prf pubInputs x xnMinusOne y theta beta gamma trashChal

        rotSets = assembleRotationSets vk prf specs x x1 xNext xPrev xLast hEval hSplit

        -- ── Steps 6–10: Generic GWC verifier ─────────────────────────────────

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
{-# INLINEABLE evalGate #-}
evalGate :: GateExpr -> [Scalar] -> [Scalar] -> [Scalar] -> Scalar
evalGate expr adv fix inst = go expr
  where
    go (GEConst s) = s
    go (GEAdv qi) = adv !! qi
    go (GEFix qi) = fix !! qi
    go (GEInst qi) = inst !! qi
    go (GENeg e) = zero - go e
    go (GEAdd a b) = go a + go b
    go (GEMul a b) = go a * go b
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
    Scalar
computeHEval vk prf pubInputs x xnMinusOne y theta beta gamma trashChal =
    let
        cfg = vkConfig vk
        blinding = ccBlinding cfg
        omega = ccOmega cfg
        chunkSize = ccPermChunkSize cfg
        numPermCols = ccNumPermCols cfg
        numChunks = length (prfPermProdComs prf)
        numLookups = ccNumLookups cfg
        delta = mkScalar bls12_381_scalar_delta

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
        hInv = lBlindInvs !! blinding

        activeRows = one - lLast - lBlind

        -- ── Permutation expressions ───────────────────────────────────────────

        -- Get proof evaluation for a permutation column (advice/fixed/instance)
        getPermColEval globalIdx =
            let (ct, ei) = vkPermColTypes vk !! globalIdx
             in if ct == 0
                    then advEvals !! ei
                    else
                        if ct == 1
                            then fixEvals !! ei
                            else instEvals !! ei -- ct == 2
        permProdEvals = map mkScalar (prfPermProdEvals prf)
        sigmaEvals = map mkScalar (prfPermSigmaEvals prf)
        ppEval j fld = permProdEvals !! (3 * j + fld)
        sigmaEval i = sigmaEvals !! i

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
        -- Each section folds directly into the accumulator without building
        -- an intermediate list — eliminates O(n) cons-cell allocations per section
        -- and the O(numChunks²) list-append cost in the perm chunk loop.

        -- Gate: fold evalE directly over vkGatePolys, no intermediate list
        hGate = foldl (\acc e -> acc * y + evalE e) zero (vkGatePolys vk)

        -- Perm: two fixed exprs, then numChunks-1 continuation exprs, then numChunks chunk exprs
        hPerm =
            let hP0 = hGate * y + l0 * (one - ppEval 0 0)
                hP1 = hP0 * y + lLast * (let zl = ppEval (numChunks - 1) 0 in zl * zl - zl)
                hP2 = foldl (\acc j -> acc * y + l0 * (ppEval (j + 1) 0 - ppEval j 2)) hP1 (enumFromTo 0 (numChunks - 2))
                (result, _) = foldl (\(acc, cd) j -> let (c, cd') = permChunkConstraint j cd in (acc * y + c, cd')) (hP2, one) (enumFromTo 0 (numChunks - 1))
             in result

        -- Lookup: each lookup's 5 exprs folded directly, no concatMap intermediate
        hLookup = foldl (lookupHornerForK vk prf l0 lLast activeRows theta beta gamma evalE y) hPerm (enumFromTo 0 (numLookups - 1))

        -- Trash: inline each trash expr, no intermediate map list
        numTrash = length (vkTrashSelectors vk)
        hEvalSum =
            foldl
                ( \acc t ->
                    let trashE = mkScalar (prfTrashEvals prf !! t)
                        selE = evalE (vkTrashSelectors vk !! t)
                        consExprs = vkTrashConstraintExprs vk !! t
                        compressed = foldl (\a e -> a * trashChal + evalE e) zero consExprs
                     in acc * y + (compressed - (one - selE) * trashE)
                )
                hLookup
                (enumFromTo 0 (numTrash - 1))
     in
        -- h(x) = hEvalSum / (x^n − 1)
        -- x is a random challenge outside the domain, so x^n ≠ 1 and the inversion is safe.

        hEvalSum * hInv

{- | Horner-fold the 5 lookup expressions for lookup k into accumulator acc.
Avoids building an intermediate list: returns acc*y^5 + e0*y^4 + ... + e4.
-}
{-# INLINEABLE lookupHornerForK #-}
lookupHornerForK ::
    VerifyingKey ->
    Proof ->
    Scalar -> -- l0
    Scalar -> -- lLast
    Scalar -> -- activeRows
    Scalar -> -- theta
    Scalar -> -- beta
    Scalar -> -- gamma
    (GateExpr -> Scalar) -> -- evalE
    Scalar -> -- y (Horner challenge)
    Scalar -> -- acc
    Integer -> -- k: lookup index
    Scalar
lookupHornerForK vk prf l0 lLast activeRows theta beta gamma evalE y acc k =
    let
        luE fld = mkScalar (prfLookupEvals prf !! (5 * k + fld))
        prodEval = luE 0 -- z_k(x)
        prodNext = luE 1 -- z_k(ωx)
        inputEval = luE 2 -- A'_k(x)
        inputInv = luE 3 -- A'_k(ω⁻¹·x)
        tableEval = luE 4 -- S'_k(x)
        compressExprs = foldl (\a e -> a * theta + evalE e) zero

        inputArgs = compressExprs (vkLookupInputExprs vk !! k)
        tableArgs = compressExprs (vkLookupTableExprs vk !! k)

        leftProd = prodNext * (inputEval + beta) * (tableEval + gamma)
        rightProd = prodEval * (inputArgs + beta) * (tableArgs + gamma)
        e0 = l0 * (one - prodEval)
        e1 = lLast * (prodEval * prodEval - prodEval)
        e2 = activeRows * (leftProd - rightProd)
        e3 = l0 * (inputEval - tableEval)
        e4 = activeRows * (inputEval - tableEval) * (inputEval - inputInv)
     in
        ((((acc * y + e0) * y + e1) * y + e2) * y + e3) * y + e4

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
    -- | x·ω⁻¹: rotation −1
    Scalar ->
    -- | x·ω^{−(blinding+1)}: last usable row rotation
    Scalar ->
    -- | h(x): verifier-derived gate evaluation (from 'computeHEval')
    Scalar ->
    -- | x^{N-1}: precomputed in 'verify' to share with xn = hSplit·x
    Scalar ->
    [RotationSet]
assembleRotationSets vk prf specs x x1 xNext xPrev xLast hEval hSplit =
    let
        -- G1 elements decoded once; bls12_381_G1_uncompress paid once per commitment.
        -- Proof commitments (advice cols queried at multiple rotations appear in
        -- several rotation sets; decoding once avoids re-paying the builtin cost).
        advicePts = map bls12_381_G1_uncompress (prfAdviceComs prf)
        lookupTablePts = map bls12_381_G1_uncompress (prfLookupTableComs prf)
        trashPts = map bls12_381_G1_uncompress (prfTrashComs prf)
        fixedPts = map bls12_381_G1_uncompress (vkFixedComs vk)
        permSigmaPts = map bls12_381_G1_uncompress (vkPermSigmaComs vk)
        hPts = map bls12_381_G1_uncompress (prfHComs prf)
        randomPt = bls12_381_G1_uncompress (prfRandomCom prf)
        permProdPts = map bls12_381_G1_uncompress (prfPermProdComs prf)
        lookupProdPts = map bls12_381_G1_uncompress (prfLookupProdComs prf)
        lookupInputPts = map bls12_381_G1_uncompress (prfLookupInputComs prf)

        -- Scalar evals decoded once; mkScalar validates [0, q) on entry.
        advEvalsRS = map mkScalar (prfAdviceEvals prf)
        fixEvalsRS = map mkScalar (prfFixedEvals prf)
        permSigEvalsRS = map mkScalar (prfPermSigmaEvals prf)
        permProdEvalsRS = map mkScalar (prfPermProdEvals prf)
        lookupEvalsRS = map mkScalar (prfLookupEvals prf)
        trashEvalsRS = map mkScalar (prfTrashEvals prf)
        randomEvalRS = mkScalar (prfRandomEval prf)

        -- ── Resolve a rotation offset to an evaluation point ─────────────
        omg = ccOmega (vkConfig vk)
        omgInv = ccOmegaInv (vkConfig vk)
        blinding = ccBlinding (vkConfig vk)

        toRotation :: Integer -> Rotation
        toRotation r
            | r == 0 = RotCur
            | r == 1 = RotNext
            | r == (-1) = RotPrev
            | r == -(blinding + 1) = RotLast
            | otherwise = RotArb r

        evalPt :: Rotation -> Scalar
        evalPt RotCur = x
        evalPt RotNext = xNext
        evalPt RotPrev = xPrev
        evalPt RotLast = xLast
        evalPt (RotArb r)
            | 1 <= r = x * (powers omg (r + 1) !! r)
            | otherwise = x * (powers omgInv ((-r) + 1) !! (-r))

        -- ── (scalar, G1) pair(s) for one slot ────────────────────────────
        --
        -- Returns parallel (scalars, points) lists. No EC scalar muls here;
        -- the x₁^j factors are combined with x₄^i in verifyGwc's mega-MSM.
        -- H (kind 6) expands to nh pairs; all other kinds contribute one (or zero).
        getComPairs :: Scalar -> SlotSpec -> ([Scalar], [G1])
        getComPairs x1j ss =
            let i = ssIndex ss
             in case ssKind ss of
                    SKInstance -> ([], []) -- zero polynomial; contributes nothing
                    SKH ->
                        -- nh entries, scalar = x₁^j · hSplit^m for m = 0..nh-1
                        let nh = ccNumHPieces (vkConfig vk)
                         in (map (x1j *) (powers hSplit nh), hPts)
                    SKAdvice -> ([x1j], [advicePts !! i])
                    SKLookupTable -> ([x1j], [lookupTablePts !! i])
                    SKTrash -> ([x1j], [trashPts !! i])
                    SKFixed -> ([x1j], [fixedPts !! i])
                    SKPermSigma -> ([x1j], [permSigmaPts !! i])
                    SKRandom -> ([x1j], [randomPt])
                    SKPermProd -> ([x1j], [permProdPts !! i])
                    SKLookupProd -> ([x1j], [lookupProdPts !! i])
                    SKLookupInput -> ([x1j], [lookupInputPts !! i])

        -- ── Evaluation of one slot at a given rotation position ─────────
        getEval :: SlotSpec -> Integer -> Rotation -> Scalar
        getEval ss rotPos rot =
            let i = ssIndex ss
                luE field = lookupEvalsRS !! (5 * i + field)
                ppE fld = permProdEvalsRS !! (3 * i + fld)
             in case ssKind ss of
                    SKAdvice -> advEvalsRS !! (ssEvalIdxs ss !! rotPos)
                    SKFixed -> fixEvalsRS !! (ssEvalIdxs ss !! rotPos)
                    SKLookupTable -> luE 4
                    SKTrash -> trashEvalsRS !! i
                    SKPermSigma -> permSigEvalsRS !! i
                    SKH -> hEval
                    SKRandom -> randomEvalRS
                    SKInstance -> zero
                    SKPermProd -> case rot of RotCur -> ppE 0; RotNext -> ppE 1; _ -> ppE 2
                    SKLookupProd -> case rot of RotCur -> luE 0; _ -> luE 1
                    SKLookupInput -> case rot of RotCur -> luE 2; _ -> luE 3

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
