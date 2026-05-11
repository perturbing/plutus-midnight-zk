# Halo2 Constraint System: Gates, Permutations, Lookups, and h(x)

This document explains how midnight-zk / Halo2 constraint expressions are
constructed, how `computeHEval` derives h(x) from them, and which parts of
that computation can be precomputed before a proof is seen.

---

## 1. PLONK vs Halo2 gates

PLONK uses a fixed gate template: for each row i, it checks

```
qL·a + qR·b + qO·c + qM·a·b + qC = 0
```

where the selectors `q*` are fixed columns and `a, b, c` are witness
(advice) columns.  There is one gate shape for the whole circuit.

Halo2 is custom-gate: the constraint system is a list of arbitrary
multivariate polynomials over advice, fixed, instance, and challenge
columns, where each polynomial can reference cells at arbitrary row
*rotations* (offsets relative to the current row).  The compiler
produces one RPN bytecode string per gate polynomial.  A single gate can
have multiple polynomials (e.g. a selector times a sub-expression), each
of which must equal zero at every active row.

Every gate polynomial is constrained to be zero across all active rows,
meaning its evaluation on the evaluation domain vanishes on the same set
as `x^n - 1` (the vanishing polynomial).  The quotient

```
h(X) = (Σ yⁱ · constraintᵢ(X)) / (X^n - 1)
```

is a well-defined polynomial (no remainder) iff all constraints hold.
The prover commits to h; the verifier reconstructs h(x) from proof
evaluations and checks consistency via the KZG opening.

---

## 2. Gate polynomial evaluation (expression trees)

Each gate poly is stored in the JSON as a flat RPN (postfix) instruction array.
`instrsToGateExpr` in `JsonParser.hs` converts each array to a `GateExpr`
recursive tree at parse time by simulating the RPN stack with `GateExpr` nodes
instead of `Scalar` values.  On-chain evaluation (`evalGate` in `Verifier.hs`)
is then simple structural recursion — no stack threading, no mutable state.

| Constructor | Payload | Semantics |
|-------------|---------|-----------|
| `GEConst`   | `Scalar` | constant field element |
| `GEAdv qi`  | `Integer` | `advEvals[qi]` |
| `GEFix qi`  | `Integer` | `fixEvals[qi]` |
| `GEInst qi` | `Integer` | `instEvals[qi]` |
| `GENeg e`   | `GateExpr` | `0 − eval e` |
| `GEAdd a b` | `GateExpr GateExpr` | `eval a + eval b` |
| `GEMul a b` | `GateExpr GateExpr` | `eval a × eval b` |
| `GEScale e s` | `GateExpr Scalar` | `eval e × s` |

midnight-zk has no multi-phase challenges, so there is no `GEChal` constructor.

`query_index` is not a column index; it is the index into the
**flattened query list** produced by `cs.advice_queries()` /
`cs.fixed_queries()` during circuit compilation.  Different rotations of
the same column produce separate query entries.  The rotation-set JSON
embeds the concrete eval-array index for each slot, so the verifier needs
no query-map scan at runtime.

`instEvals[0]` = committed instance eval (always 0 in midnight-zk);
`instEvals[1]` = Lagrange interpolation of public inputs at x.

---

## 3. Permutation argument

### 3.1 What sigma polynomials encode

For each permutation column c and row i, there is a copy constraint
linking cell (c, i) to some other cell (c', i').  The sigma polynomial
encodes the destination:

```
σ_c(ωⁱ) = δ^{c'} · ω^{i'}
```

where `δ = bls12_381_scalar_delta = 7^{2^32} mod q` is the coset
generator.  The cosets `{δ^k · H}` for k = 0, 1, 2, … are pairwise
disjoint, so each cell `(c, i)` has a unique
identifier `δ^c · ω^i` in F_q*, enabling the standard
permutation-check via grand products.

### 3.2 Grand product Z_j(X)

The permutation argument is split into chunks of `chunkSize` columns.
For chunk j (columns `j·chunkSize` through `j·chunkSize + nc - 1`),
the grand product is:

```
Z_j(ω · X) · Π_k (col_k(X) + β · σ_{gi_k}(X) + γ)
= Z_j(X)   · Π_k (col_k(X) + δ^{gi_k} · β · X + γ)
```

where `gi_k = j·chunkSize + k` is the global column index, `β` and `γ`
are Fiat-Shamir challenges, and `col_k(X)` is the advice/fixed/instance
polynomial for column k.

The left side uses the actual permutation destination (σ); the right
side uses the "identity" permutation (each cell maps to itself, identified
by `δ^{gi} · ω^row`).  If all copy constraints hold, the two products
are equal, so `Z_j(X)` telescopes to a constant — and the boundary
conditions below pin it to 1.

### 3.3 Chunk openings and constraints

Each chunk j contributes the following expressions to `computeHEval`:

| Expression | What it checks |
|---|---|
| `l₀ · (1 − Z_j(x))` | Z_j starts at 1 on row 0 |
| `l_last · (Z_j(x)² − Z_j(x))` | Z_j ends at 0 or 1 (blinding) |
| `l₀ · (Z_j(x) − Z_{j-1}(ω^last · x))` (j > 0) | chunks chain: Z_j(1) = Z_{j-1}(ω^last) |
| `activeRows · (Z_j(ωx) · Π(col + β·σ + γ) − Z_j(x) · Π(col + δ^gi·β·x + γ))` | grand-product recurrence |

For the recurrence, the proof provides:
- `ppEval j 0` = Z_j(x)
- `ppEval j 1` = Z_j(ω·x)
- `ppEval j 2` = Z_j(ω^last · x)  (omitted for the last chunk)

The sigma evaluations `sigmaEval gi` = σ_{gi}(x) come from
`prfPermSigmaEvals`.

### 3.4 Why δ is a field constant, not a VK field

δ = 7^{2^32} mod q is a fixed constant of the BLS12-381 scalar field —
it depends only on the field definition (characteristic q and 2-adicity
S = 32).  It does not depend on the trusted setup or circuit design.  It
is therefore hardcoded in `BlsUtils.hs` as `bls12_381_scalar_delta` and
is not read from any JSON file.

---

## 4. Lookup argument

Each lookup argument k contributes 5 expressions.  The key values from
the proof are:

| Symbol       | Proof field index | Meaning                         |
|---|---|---|
| `prodEval`   | `5k + 0`          | Z_k(x) — lookup grand product   |
| `prodNext`   | `5k + 1`          | Z_k(ω·x)                        |
| `inputEval`  | `5k + 2`          | A'_k(x) — permuted input        |
| `inputInv`   | `5k + 3`          | A'_k(ω⁻¹·x)                     |
| `tableEval`  | `5k + 4`          | S'_k(x) — permuted table        |

The "compressed" input and table expressions are evaluated via the VK
`GateExpr` trees and then Horner-folded with the challenge θ:

```
inputArgs = θ^{m-1}·e_0(x) + θ^{m-2}·e_1(x) + … + e_{m-1}(x)
```

The 5 constraint expressions are:

```
e0 = l₀ · (1 − Z_k(x))                                        -- starts at 1
e1 = l_last · (Z_k(x)² − Z_k(x))                              -- ends at 0 or 1
e2 = activeRows · (Z_k(ωx)·(A'_k + β)·(S'_k + γ) − Z_k(x)·(inputArgs + β)·(tableArgs + γ))
e3 = l₀ · (A'_k(x) − S'_k(x))                                 -- A' and S' start equal
e4 = activeRows · (A'_k(x) − S'_k(x)) · (A'_k(x) − A'_k(ω⁻¹·x))
```

---

## 5. Trash (extra blinding) argument

For circuits with `blinding_factors > 5`, there are extra "trash"
polynomial commitments and evaluations.  Each trash argument t contributes
one expression:

```
trashE_t = compressed_constraints_t − (1 − selector_t(x)) · trashEval_t
```

where `compressed_constraints_t` is a Horner fold of the constraint
expressions with the trash challenge.

---

## 6. Assembling h(x): the Horner fold

All gate, permutation, lookup, and trash expressions are Horner-folded
with the challenge y in the order: gate → perm → lookup → trash.

```
hEvalSum = foldl (\acc e -> acc * y + e) 0 (gateExprs ++ permExprs ++ lookupExprs ++ trashExprs)
```

This is equivalent to

```
hEvalSum = Σᵢ yⁱ · constraintᵢ(x)    (highest power = index 0)
```

Then:

```
h(x) = hEvalSum / (x^n − 1)
```

The field inversion of `x^n - 1` is safe because x is a Fiat-Shamir
challenge outside the evaluation domain, so `x^n ≠ 1` with overwhelming
probability.

The verifier's h(x) is fed into `assembleRotationSets` as the claimed
evaluation for the H rotation set slot (slot kind 6).  The KZG pairing
check then enforces that the committed h polynomial (split across hComs)
is consistent with this value.

---

## 7. What can be precomputed before seeing a proof?

All Fiat-Shamir challenges (x, y, θ, β, γ, trashChal) are derived from
the transcript, which includes all proof commitments and evaluations.
Nothing challenge-dependent can be computed without a proof.

### Fully precomputable (VK-only, no proof, no challenges)

| Value | How |
|---|---|
| `delta = bls12_381_scalar_delta` | Pure constant of BLS12-381 |
| `nInv = recip (mkScalar n)` | n = ccDomainSize, in CircuitConfig |
| `numChunks`, `chunkColCount j` | Derived from ccNumPermCols / ccPermChunkSize |
| `[δ^0, δ^1, …, δ^{numPermCols−1}]` | Coset shift array; one scalar per perm column |
| Gate / lookup / trash `GateExpr` trees | Already stored in VK |

The coset shift array is the most valuable precomputation: for a circuit
with 30 permutation columns it is 30 scalar multiplications that are
identical for every proof.  With Plutus Template Haskell lifting, these
can be burned in as literals at compile time.

### Needs x (from transcript, after proof commitments absorbed)

- `lagrangeAtRow i` = ωⁱ · (x^n − 1) / (n · (x − ωⁱ))
- `l₀`, `l_last`, `l_blind`, `activeRows`
- The coset shift terms `δ^{gi} · β · x` in `permChunkConstraint`
  (also need β from transcript)

### Needs proof evaluations (after x, β, γ, θ, y are known)

- `advEvals`, `fixEvals`, `instEvalComm` — directly from proof fields
- `ppEval`, `sigmaEval` — from `prfPermProdEvals` / `prfPermSigmaEvals`
- `luE` — from `prfLookupEvals`
- `trashE` — from `prfTrashEvals`
- All `evalGate` calls (gate / lookup / trash expression evaluation)

### Needs proof + public inputs

- `instEvalPub = Σ pubInputs[i] · L_i(x)` — Lagrange sum over public
  input values; requires both the Fiat-Shamir x challenge and the
  concrete public input scalars.

### Summary

The computation barrier is the transcript: until all proof commitments are
absorbed, no challenge is available.  The deepest on-chain optimisation is
to precompute the VK-static scalars (coset shifts, nInv, etc.) at
script-compilation time via Template Haskell `makeLift`, so that the
on-chain script only evaluates the proof-dependent arithmetic.
