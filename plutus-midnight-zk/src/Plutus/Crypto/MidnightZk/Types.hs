{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-full-laziness #-}
{-# OPTIONS_GHC -fno-ignore-interface-pragmas #-}
{-# OPTIONS_GHC -fno-omit-interface-pragmas #-}
{-# OPTIONS_GHC -fno-spec-constr #-}
{-# OPTIONS_GHC -fno-specialise #-}
{-# OPTIONS_GHC -fno-strictness #-}
{-# OPTIONS_GHC -fno-unbox-small-strict-fields #-}
{-# OPTIONS_GHC -fno-unbox-strict-fields #-}

{- | Core types for the plutus-midnight-zk generic Halo2 GWC verifier.

Design philosophy: separate circuit-generic types from circuit-specific
configuration. The verifier algorithm operates on 'RotationSet' lists;
a thin circuit-specific assembly layer maps a 'Proof' + 'VerifyingKey'
into that generic representation.

On-chain representation: commitments are stored as compressed byte strings
(48 bytes for G1, 96 bytes for G2). Decompression happens at verification
time inside the verifier. This matches the Halo2 proof format on the wire.

Runtime types ('PolyQuery', 'RotationSet') are computed inside the verifier
and are not stored on-chain; they do not need IsData or Lift instances.
-}
module Plutus.Crypto.MidnightZk.Types (
    -- * Group element type aliases
    G1,
    G2,

    -- * Gate constraint expression tree (decoded at parse time, not on-chain)
    GateExpr (..),

    -- * Circuit configuration (variable per circuit)
    CircuitConfig (..),

    -- * Rotation sets (internal computation type, not on-chain)
    Rotation (..),
    RotationSet (..),
    SlotKind (..),
    SlotSpec (..),
    RotationSetSpec (..),

    -- * On-chain types (need IsData / Lift instances)
    VerifyingKey (..),
    Proof (..),
) where

import Plutus.Crypto.BlsUtils (Scalar)
import PlutusTx (makeIsDataIndexed, makeLift)
import PlutusTx.Builtins (
    BuiltinBLS12_381_G1_Element,
    BuiltinBLS12_381_G2_Element,
    BuiltinByteString,
 )
import PlutusTx.Prelude (Bool, Integer)
import qualified Prelude as Haskell

-- ---------------------------------------------------------------------------
-- Group element type aliases
-- ---------------------------------------------------------------------------

-- | BLS12-381 G1 element. Used in runtime computations inside the verifier.
type G1 = BuiltinBLS12_381_G1_Element

-- | BLS12-381 G2 element. Used in the final KZG pairing check.
type G2 = BuiltinBLS12_381_G2_Element

-- ---------------------------------------------------------------------------
-- Gate constraint expression tree
-- ---------------------------------------------------------------------------

{- | One node in a gate/lookup/trash constraint expression tree.

The JSON instruction arrays (flat RPN / postfix) are converted to 'GateExpr'
trees once at parse time by 'instrsToGateExpr' in "JsonParser".  On-chain
evaluation is then a simple structural recursion ('evalGate' in "Verifier")
with no stack threading — invalid programs are structurally impossible.

Scalars in 'GEConst' and 'GEScale' are decoded from 32-byte LE hex at
JSON-parse time and lifted into the compiled Plutus script via 'makeLift',
so their cost is zero at on-chain execution time.

midnight-zk has no multi-phase challenges, so there is no @GEChal@ constructor.
-}
data GateExpr
    = -- | Constant field element.
      GEConst Scalar
    | -- | @advEvals[query_index]@
      GEAdv Integer
    | -- | @fixEvals[query_index]@
      GEFix Integer
    | -- | @instEvals[query_index]@
      GEInst Integer
    | -- | Negation: −e
      GENeg GateExpr
    | -- | Addition: a + b
      GEAdd GateExpr GateExpr
    | -- | Multiplication: a × b
      GEMul GateExpr GateExpr
    | -- | Scalar multiplication: e × s
      GEScale GateExpr Scalar
    deriving (Haskell.Show)

makeLift ''GateExpr
makeIsDataIndexed
    ''GateExpr
    [ ('GEConst, 0)
    , ('GEAdv, 1)
    , ('GEFix, 2)
    , ('GEInst, 3)
    , ('GENeg, 4)
    , ('GEAdd, 5)
    , ('GEMul, 6)
    , ('GEScale, 7)
    ]

-- ---------------------------------------------------------------------------
-- Circuit configuration
-- ---------------------------------------------------------------------------

{- | All circuit-variable parameters. Two different midnight-zk circuits will
have the same type of 'VerifyingKey' but different 'CircuitConfig' values.

These are determined at circuit-compilation time and form part of the
verifying key; they are not secret.
-}
data CircuitConfig = CircuitConfig
    { ccDomainSize :: Integer
    -- ^ N = 2^K. The size of the evaluation domain.
    , ccOmega :: Scalar
    -- ^ Primitive N-th root of unity in the BLS12-381 scalar field.
    , ccOmegaInv :: Scalar
    -- ^ ω⁻¹ mod q. Precomputed at parse time; saves one 'recip' per verification.
    , ccOmegaLast :: Scalar
    -- ^ ω^{−(blinding+1)} mod q. Precomputed at parse time; saves blinding multiplications.
    , ccNInv :: Scalar
    -- ^ N⁻¹ mod q. Precomputed at parse time; saves one 'recip' per verification.
    , ccBlinding :: Integer
    {- ^ Number of blinding rows at the end of each column witness.
    The "last usable row" rotation offset is -(ccBlinding + 1).
    -}
    , ccNumAdviceCols :: Integer
    -- ^ Number of witness (advice) columns in the circuit.
    , ccNumPermCols :: Integer
    -- ^ Total number of columns covered by the permutation argument.
    , ccPermChunkSize :: Integer
    {- ^ Columns per permutation grand-product polynomial.
    Number of grand products = ceiling(ccNumPermCols / ccPermChunkSize).
    The last chunk opens at (x, x*omega) only; all others also at x*omega^(-(blinding+1)).
    -}
    , ccNumLookups :: Integer
    -- ^ Number of Plookup lookup arguments.
    , ccNumHPieces :: Integer
    {- ^ Number of vanishing-quotient pieces h0, h1, ... for h(X).
    h(X) = h0(X) + X^(N-1) * h1(X) + X^(2*(N-1)) * h2(X) + ...
    Equals (max_constraint_degree - 1) for the circuit.
    -}
    }
    deriving (Haskell.Show)

makeLift ''CircuitConfig
makeIsDataIndexed ''CircuitConfig [('CircuitConfig, 0)]

-- ---------------------------------------------------------------------------
-- Rotation sets — internal computation types
-- ---------------------------------------------------------------------------

{- | A sorted set S_i in the GWC protocol: a group of polynomials that are
all queried at exactly the same set of evaluation points.

The GWC protocol reduces checking all polynomials in this set to a single
KZG opening at x₃. This type carries pre-computed data so that the generic
verifier ('verifyGwc') needs no circuit-specific knowledge:

  * 'rsPoints': the evaluation points {p₀, …, pₘ₋₁}.
  * 'rsComScalars' / 'rsComs': parallel lists of x₁^j factors and raw G1 points.
    The x₄^i weight is applied in 'verifyGwc', so qCom_i = Σ_j x₄^i·rsComScalars[j]·rsComs[j],
    computed as part of the mega-MSM rather than via individual EC scalar muls.
  * 'rsQEvalsAtPts': the x₁-combined evaluations [q_i(p₀), …, q_i(pₘ₋₁)],
    where q_i(p) = Σ_j x₁^j · poly_j(p). Used for Lagrange interpolation.

Protocol equations:

  qCom_i     = Σ_j  x₄^i · rsComScalars[j] · rsComs[j]   (folded into mega-MSM)
  r_i(x₃)   = Lagrange interpolant through {(rsPoints[k], rsQEvalsAtPts[k])}
  c_i        = (q_i(x₃) − r_i(x₃)) / V_i(x₃)
  V_i(x₃)   = Π_{p ∈ rsPoints} (x₃ − p)

This type is an internal computation type and is not stored on-chain.
-}
data RotationSet = RotationSet
    { rsPoints :: [Scalar]
    {- ^ Actual field elements at which all polynomials in this set are
    evaluated: e.g. [x], [x, x·ω], [x, x·ω, x·ω⁻¹].
    -}
    , rsComScalars :: [Integer]
    {- ^ Unscaled x₁^j factors as raw integers (already reduced mod q), parallel to rsComs.
    Stored unwrapped to avoid Scalar constructor/destructor overhead in the MSM hot path.
    H pieces carry x₁^j · hSplit^m; all other kinds carry x₁^j.
    The x₄^i weight is applied in 'verifyGwc' so that one mega-MSM covers
    all commitments without individual EC scalar multiplications.
    -}
    , rsComs :: [G1]
    -- ^ Raw (unscaled) commitment G1 points, parallel to rsComScalars.
    , rsQEvalsAtPts :: [Scalar]
    {- ^ Pre-combined evaluations: rsQEvalsAtPts[k] = q_i(rsPoints[k])
                                                    = Σ_j x₁^j · poly_j(rsPoints[k]).
    One value per evaluation point in rsPoints.
    -}
    }
    deriving (Haskell.Show)

-- ---------------------------------------------------------------------------
-- Rotation set specs — parsed from rotation_sets.json (internal types)
-- ---------------------------------------------------------------------------

-- | Polynomial kind for a slot within a rotation set.
data SlotKind
    = -- | column index into 'prfAdviceComs'; eval from 'ssEvalVals'
      SKAdvice
    | -- | zero polynomial (commitment and eval are both zero)
      SKInstance
    | -- | k into 'prfLookupMultComs'; eval from 'ssEvalVals'
      SKLogupMult
    | -- | k into 'prfTrashComs'
      SKTrash
    | -- | column index into 'vkFixedComs'; eval from 'ssEvalVals'
      SKFixed
    | -- | k into 'vkPermSigmaComs'
      SKPermSigma
    | -- | uses all 'prfHComs' with hSplit scaling (index ignored)
      SKH
    | -- | chunk index into 'prfPermProdComs'
      SKPermProd
    | -- | k into 'prfLookupAccumComs'; eval from 'ssEvalVals'
      SKLogupAccum
    | -- | flat helper index into concat 'prfLookupHelperComs'; eval from 'ssEvalVals'
      SKLogupHelper
    deriving (Haskell.Show)

makeLift ''SlotKind

{- | Specification for one polynomial slot within a rotation set.
Parsed from @*_rotation_sets.json@. The 'ssIndex' interpretation depends on 'ssKind'.
-}
data SlotSpec = SlotSpec
    { ssKind :: SlotKind
    -- ^ Polynomial kind.
    , ssIndex :: Integer
    -- ^ Primary index into the appropriate proof/VK array.
    , ssEvalVals :: [Scalar]
    {- ^ Per-rotation precomputed evaluation values (one per rotation in the containing set).
    Precomputed off-chain at parse time from the proof eval arrays so that on-chain
    verification uses O(rotPos) ≤ O(4) indexing instead of O(absIdx) ≤ O(195).
    For 'SKH' at 'RotCur', the value at index 0 is a placeholder (linComEval is
    substituted at verification time).  For 'SKInstance', all values are zero.
    -}
    }
    deriving (Haskell.Show)

makeLift ''SlotSpec

{- | Specification for one rotation set.
Parsed from @*_rotation_sets.json@. Contains the rotation offsets (0, 1, -1,
or -(blinding+1)) and the ordered list of polynomial slots (x₁-power order).
-}
data RotationSetSpec = RotationSetSpec
    { rssRotations :: [Integer]
    -- ^ Rotation offsets relative to x (e.g. [0], [0,1], [0,-1], [0,1,-1]).
    , rssSlots :: [SlotSpec]
    -- ^ Polynomial slots in x₁-power order.
    }
    deriving (Haskell.Show)

makeLift ''RotationSetSpec

{- | Symbolic rotation offset, resolved from the raw integer stored in the JSON.

The four values used by midnight-zk circuits are named; any other offset (not
expected in practice) is carried in 'RotArb'. Conversion from 'Integer' happens
inside 'assembleRotationSets' where 'ccBlinding' is available to identify 'RotLast'.

Internal computation type; not stored on-chain.
-}
data Rotation
    = -- | Rotation 0: evaluation point x (current row).
      RotCur
    | -- | Rotation +1: evaluation point x·ω (next row).
      RotNext
    | -- | Rotation −1: evaluation point x·ω⁻¹ (previous row).
      RotPrev
    | -- | Rotation −(blinding+1): evaluation point x·ω^{−(blinding+1)} (last usable row).
      RotLast
    | -- | Any other rotation offset (not used in midnight-zk, kept for completeness).
      RotArb Integer
    deriving (Haskell.Eq, Haskell.Show)

-- ---------------------------------------------------------------------------
-- Verifying key (on-chain type)
-- ---------------------------------------------------------------------------

{- | The verifying key contains all circuit constants committed to polynomial
encodings plus the SRS point and the circuit's transcript identity hash.

Commitments are stored as compressed byte strings (48 bytes per G1 point,
96 bytes for the G2 point). Decompression via 'bls12_381_G1_uncompress' /
'bls12_381_G2_uncompress' happens inside the verifier exactly once per
commitment — this is required to validate subgroup membership on-chain.

Query maps have been eliminated: advice and fixed evaluation indices are now
embedded directly in each 'SlotSpec' in '*_rotation_sets.json', so the verifier
can look up evaluations in O(1) without scanning a circuit-level query map.

Note: the permutation coset generator δ is NOT a field here — it is a pure
constant of the BLS12-381 scalar field ('bls12_381_scalar_delta' in
"Plutus.Crypto.BlsUtils") and does not depend on the circuit or trusted setup.
-}
data VerifyingKey = VerifyingKey
    { vkConfig :: CircuitConfig
    -- ^ Variable circuit parameters.
    , vkFixedComs :: [BuiltinByteString]
    -- ^ Compressed G1 commitments to each fixed column, one per column.
    , vkPermSigmaComs :: [BuiltinByteString]
    {- ^ Compressed G1 commitments to permutation sigma polynomials,
    one per column covered by the permutation (length = ccNumPermCols).
    -}
    , vkSrsG2 :: BuiltinByteString
    -- ^ Compressed G2 point [s]G₂ from the SRS (96 bytes).
    , vkTranscriptRepr :: BuiltinByteString
    {- ^ 32-byte circuit identity hash, absorbed first into the transcript.
    Binds all Fiat-Shamir challenges to this specific circuit.
    -}
    , vkSimpleSelectorMask :: [Bool]
    {- ^ Per fixed-query position: True if this position is a simple (multiplicative)
    selector.  Simple selector evals are substituted with 1 by the verifier and are
    NOT absorbed into the Fiat-Shamir transcript.  Length = total number of fixed
    queries (including simple selectors).
    -}
    , vkGatePolys :: [GateExpr]
    {- ^ Decoded gate constraint expression trees, in evaluate_identities order.
    Each 'GateExpr' is one polynomial expression.  Constant and scale scalars
    are pre-decoded at parse time and lifted into the script — no byte-scanning
    at on-chain evaluation.
    -}
    , vkPermColTypes :: [(Integer, Integer)]
    {- ^ Per permutation column: (colType, evalIdx) where
    colType 0=Advice, 1=Fixed, 2=Instance; evalIdx is the
    unified eval array index at Rotation::cur().
    Ordered as in the permutation Argument columns list.
    -}
    , vkLookupInputExprs :: [[[[GateExpr]]]]
    -- ^ Per lookup: [chunk][parallel_input][width_exprs]. Decoded at parse time.
    , vkLookupTableExprs :: [[GateExpr]]
    -- ^ Per lookup argument: list of decoded table expression trees.
    , vkLookupSelectorExprs :: [GateExpr]
    -- ^ Per lookup: one decoded selector expression tree.
    , vkTrashSelectors :: [GateExpr]
    -- ^ Per trashcan argument: decoded selector expression tree.
    , vkTrashConstraintExprs :: [[GateExpr]]
    -- ^ Per trashcan argument: list of decoded constraint expression trees.
    , vkGateSelCols :: [Integer]
    {- ^ Per gate polynomial: fixed column index of the simple selector used by that gate,
    or -1 if the gate uses no simple selector. Parallel to vkGatePolys.
    Used in computeHEval to track per-selector-column Horner accumulators.
    -}
    , vkSimpleSelColList :: [Integer]
    {- ^ Unique simple selector column indices (in first-appearance order from vkGateSelCols,
    all ≥ 0). One entry per distinct simple-selector column in the circuit.
    Used as the key list for per-column Horner accumulators in computeHEval.
    -}
    }
    deriving (Haskell.Show)

makeLift ''VerifyingKey
makeIsDataIndexed ''VerifyingKey [('VerifyingKey, 0)]

-- ---------------------------------------------------------------------------
-- Proof (on-chain type)
-- ---------------------------------------------------------------------------

{- | A midnight-zk Halo2 proof. Contains all commitments (in
transcript-absorption order) and evaluations produced by the prover.

Commitments are compressed G1 byte strings (48 bytes each). List lengths
are determined by 'CircuitConfig'.
-}
data Proof = Proof
    -- Commitments (absorbed into the transcript in this order)
    { prfAdviceComs :: [BuiltinByteString]
    -- ^ Compressed G1: one per advice column. [a₀], [a₁], …
    , prfLookupMultComs :: [BuiltinByteString]
    -- ^ Compressed G1: LogUp multiplicity [m_k], one per lookup. Absorbed after advice_coms.
    , prfPermProdComs :: [BuiltinByteString]
    -- ^ Compressed G1: permutation z-product [Z_j], one per chunk.
    , prfLookupHelperComs :: [[BuiltinByteString]]
    {- ^ Compressed G1: LogUp helper polynomials, per lookup.
    For lookup k with nc_k chunks: [h_{k,0}, …, h_{k,nc_k-1}].
    Absorbed after perm_prod_coms, interleaved with 'prfLookupAccumComs' per lookup.
    -}
    , prfLookupAccumComs :: [BuiltinByteString]
    -- ^ Compressed G1: LogUp accumulator [Z_k], one per lookup. Absorbed after each lookup's helpers.
    , prfTrashComs :: [BuiltinByteString]
    {- ^ Compressed G1: extra blinding commitments (circuit-dependent; often empty).
    Absorbed after the trash challenge squeeze.
    -}
    , prfHComs :: [BuiltinByteString]
    {- ^ Compressed G1: vanishing-quotient pieces [h₀], [h₁], …
    where h(X) = h₀(X) + X^{N-1}·h₁(X) + X^{2(N-1)}·h₂(X) + …
    -}
    , prfFCom :: BuiltinByteString
    {- ^ Compressed G1: GWC auxiliary polynomial commitment.
    Absorbed after evaluations to derive the opening point x₃.
    -}
    , prfPiPt :: BuiltinByteString
    {- ^ Compressed G1: KZG opening witness π = [w(s)]₁ where
    f(X) − f(x₃) = (X − x₃) · w(X).
    -}
    , -- Evaluations (sent after all commitments; x is derived before these)
      prfAdviceEvals :: [Integer]
    {- ^ Advice polynomial evaluations, in @advice_queries@ order.
    One entry per query (not per column).
    -}
    , prfFixedEvals :: [Integer]
    -- ^ Fixed column evaluations, in @fixed_queries@ order (simple selectors omitted from transcript).
    , prfPermSigmaEvals :: [Integer]
    -- ^ Permutation sigma polynomial evaluations at x, one per sigma column.
    , prfPermProdEvals :: [Integer]
    {- ^ Permutation z-product evaluations, flattened across all chunks.
    Non-last chunks each have 3 evals: (x, x·ω, x·ω^(-(blinding+1))).
    The last chunk has 2 evals: (x, x·ω).
    Total count = (numChunks - 1) × 3 + 2.
    Indexed as 3·j + field for chunk j (field ∈ 0..2 for non-last, 0..1 for last).
    -}
    , prfLogupEvals :: [Integer]
    {- ^ LogUp evaluations, flat across all lookups. For lookup k with nc_k chunks:
    offset(k) = Σ_{i<k}(nc_i + 3);
    at offset(k)+0: mult_eval; +1..+nc_k: helper_evals; +nc_k+1: accum_eval; +nc_k+2: accum_next_eval.
    These values are pre-indexed into 'ssEvalVals' at parse time by 'parseRotationSets'.
    -}
    , prfTrashEvals :: [Integer]
    {- ^ Extra blinding polynomial evaluations at x (one per trash commitment).
    Empty for circuits with standard blinding (blinding_factors ≤ 5).
    -}
    , prfDummyEvals :: [Integer]
    {- ^ Dummy polynomial evaluations injected by the @fewer-point-sets@ feature.
    These are appended after all regular evaluations in the proof stream.
    Absorbed into the Fiat-Shamir transcript before x₁\/x₂ are squeezed, and
    referenced by 'ssEvalIdxs' entries for Fixed\@1-only columns in the merged
    rotation set.  Empty for circuits compiled without @fewer-point-sets@.
    -}
    , prfQEvalsOnX3 :: [Integer]
    {- ^ Prover's claimed evaluation qᵢ(x₃) for each rotation set i.
    Length equals the number of rotation sets.
    -}
    }
    deriving (Haskell.Show)

makeLift ''Proof
makeIsDataIndexed ''Proof [('Proof, 0)]
