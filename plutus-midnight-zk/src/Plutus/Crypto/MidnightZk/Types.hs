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
import PlutusTx.Prelude (Integer)
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
    , rsComScalars :: [Scalar]
    {- ^ Unscaled x₁^j factors, parallel to rsComs.
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

{- | Specification for one polynomial slot within a rotation set.
Parsed from @*_rotation_sets.json@. The 'ssIndex' interpretation depends on 'ssKind':

  * 0 Advice:      column index into 'prfAdviceComs'; 'ssEvalIdxs[rotPos]' indexes 'prfAdviceEvals'
  * 1 Instance:    (index ignored; uses G1 zero and eval = 0 hardcoded)
  * 2 LookupTable: k into 'prfLookupTableComs'
  * 3 Trash:       k into 'prfTrashComs'
  * 4 Fixed:       column index into 'vkFixedComs'; 'ssEvalIdxs[rotPos]' indexes 'prfFixedEvals'
  * 5 PermSigma:   k into 'vkPermSigmaComs'
  * 6 H:           (index ignored; uses all 'prfHComs' with hSplit scaling)
  * 7 Random:      (index ignored)
  * 8 PermProd:    chunk index into 'prfPermProdComs'
  * 9 LookupProd:  k into 'prfLookupProdComs'
  * 10 LookupInput: k into 'prfLookupInputComs'
-}
data SlotSpec = SlotSpec
    { ssKind :: Integer
    -- ^ Poly kind discriminant (0–10). See above.
    , ssIndex :: Integer
    -- ^ Primary index into the appropriate proof/VK array.
    , ssEvalIdxs :: [Integer]
    {- ^ Per-rotation evaluation indices (one per rotation in the containing set).
    Used for kinds 0 and 4 to directly index 'prfAdviceEvals' / 'prfFixedEvals'
    without a linear scan through a query map. Ignored for all other kinds.
    -}
    }
    deriving (Haskell.Show)

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
    , vkGatePolys :: [GateExpr]
    {- ^ Decoded gate constraint expression trees, in evaluate_identities order.
    Each 'GateExpr' is one polynomial expression.  Constant and scale scalars
    are pre-decoded at parse time and lifted into the script — no byte-scanning
    at on-chain evaluation.
    -}
    , vkPermColTypes :: [(Integer, Integer)]
    {- ^ Per permutation column: (colType, evalIdx) where
    colType 0=Advice, 1=Fixed, 2=Instance; evalIdx is the
    proof evaluation index at Rotation::cur().
    Ordered as in the permutation Argument columns list.
    -}
    , vkLookupInputExprs :: [[GateExpr]]
    -- ^ Per lookup argument: list of decoded input expression trees.
    , vkLookupTableExprs :: [[GateExpr]]
    -- ^ Per lookup argument: list of decoded table expression trees.
    , vkTrashSelectors :: [GateExpr]
    -- ^ Per trashcan argument: decoded selector expression tree.
    , vkTrashConstraintExprs :: [[GateExpr]]
    -- ^ Per trashcan argument: list of decoded constraint expression trees.
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
    , prfLookupInputComs :: [BuiltinByteString]
    -- ^ Compressed G1: permuted input [A'_k], one per lookup.
    , prfLookupTableComs :: [BuiltinByteString]
    -- ^ Compressed G1: permuted table [S'_k], one per lookup.
    , prfPermProdComs :: [BuiltinByteString]
    -- ^ Compressed G1: permutation grand product [Z_j], one per chunk.
    , prfLookupProdComs :: [BuiltinByteString]
    -- ^ Compressed G1: lookup grand product [Z^lp_k], one per lookup.
    , prfTrashComs :: [BuiltinByteString]
    {- ^ Compressed G1: extra blinding commitments (circuit-dependent; often empty).
    Absorbed into the transcript after lookup prod coms, before the challenge squeeze.
    -}
    , prfRandomCom :: BuiltinByteString
    -- ^ Compressed G1: blinding (random) polynomial commitment.
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
      -- Note: instance_poly_eval is always 0 in midnight-zk (col 0 is the zero polynomial).
      -- The 32 bytes are consumed from the proof stream for transcript consistency but
      -- not stored here; the verifier hardcodes 0 at all use sites.
      prfAdviceEvals :: [Integer]
    {- ^ Advice polynomial evaluations, in @advice_queries@ order.
    One entry per query (not per column).
    -}
    , prfFixedEvals :: [Integer]
    -- ^ Fixed column evaluations, in @fixed_queries@ order.
    , prfRandomEval :: Integer
    -- ^ Blinding polynomial evaluation at x.
    , prfPermSigmaEvals :: [Integer]
    -- ^ Permutation sigma polynomial evaluations at x, one per sigma column.
    , prfPermProdEvals :: [Integer]
    {- ^ Permutation grand-product evaluations, flattened across all chunks.
    Non-last chunks each have 3 evals: (x, x·ω, x·ω^(-(blinding+1))).
    The last chunk has 2 evals: (x, x·ω).
    Total count = (numPermProds - 1) × 3 + 2.
    Indexed as 3·j + field for chunk j (field ∈ 0..2 for non-last, 0..1 for last).
    -}
    , prfLookupEvals :: [Integer]
    {- ^ Lookup evaluations, 5 values per lookup in order:
    [prod@x, prod@x·ω, input@x, input@x·ω⁻¹, table@x].
    -}
    , prfTrashEvals :: [Integer]
    {- ^ Extra blinding polynomial evaluations at x (one per trash commitment).
    Written to the transcript after lookup evals, before the GWC f-commitment.
    Empty for circuits with standard blinding (blinding_factors ≤ 5).
    -}
    , prfQEvalsOnX3 :: [Integer]
    {- ^ Prover's claimed evaluation qᵢ(x₃) for each rotation set i.
    Length equals the number of rotation sets.
    -}
    }
    deriving (Haskell.Show)

makeLift ''Proof
makeIsDataIndexed ''Proof [('Proof, 0)]
