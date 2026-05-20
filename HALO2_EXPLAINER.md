# How Halo2 Works: From Computation to Proof

This document gives an intuitive end-to-end walkthrough of how Halo2 encodes
a computation, proves it correct, and verifies that proof — from the execution
trace all the way through the GWC KZG multi-point opening check.

It is written to complement the precise specification in `VERIFIER_SPEC.md`
and the constraint-system reference in `CONSTRAINT_SYSTEM.md`.

---

## 1. The problem we are solving

We want to convince a verifier that we know a secret input (`witness`) that
satisfies some computation, without revealing the input itself.

In midnight-zk the verifier is a Plutus smart contract. The prover runs a
circuit off-chain, generates a proof, and submits it on-chain. The contract
checks the proof and accepts or rejects it — in milliseconds, without
re-running the computation.

---

## 2. The execution trace as a table

Halo2 represents the computation as a rectangular table of field elements:

```
         col 0      col 1      col 2      ...
row 0  | witness₀ | witness₁ |  fixed₀  | ...
row 1  | witness₂ | witness₃ |  fixed₁  | ...
row 2  | ...
```

There are three kinds of columns:

- **Advice columns** — the *witness*: private inputs and intermediate values
  computed by the prover. These are what must stay hidden.
- **Fixed columns** — constants baked in at circuit-compilation time (lookup
  tables, selector activations, etc.). The same for every proof.
- **Instance columns** — public inputs, known to both prover and verifier.

Each row encodes one step of the computation. A circuit with N rows can
represent N steps. N is always a power of two (N = 2^k) to enable efficient
polynomial arithmetic over a multiplicative subgroup.

---

## 3. Encoding constraints as polynomials

The *correctness rules* of the computation are expressed as **gate
constraints**: multivariate polynomial equations that must hold at every row.

For example, a multiplication gate might assert:

```
advice[0] × advice[1] − advice[2] = 0     (for every row)
```

Because the table has N rows, this is really N equations. The trick is to
encode all N at once using polynomials.

### The evaluation domain

Let ω be a primitive N-th root of unity in the BLS12-381 scalar field (so
ω^N = 1). The N domain points are `{1, ω, ω², …, ω^{N-1}}`.

Each column is treated as a polynomial evaluated at these N points: the value
at row i is the polynomial's value at ω^i. Any column of N values has a
unique polynomial of degree < N passing through them (by Lagrange
interpolation).

Call the advice polynomials `a₀(X), a₁(X), …` and the fixed polynomials
`f₀(X), f₁(X), …`.  The multiplication gate becomes:

```
a₀(X) × a₁(X) − a₂(X) = 0     for all X ∈ {1, ω, …, ω^{N-1}}
```

### The vanishing polynomial trick

A polynomial that equals zero on every element of the domain `H = {ωⁱ}` is
divisible by the **vanishing polynomial** `Z_H(X) = X^N − 1`.

So instead of checking N equations, the prover computes:

```
h(X) = (Σᵢ yⁱ · constraintᵢ(X)) / (X^N − 1)
```

where `y` is a random challenge (Fiat-Shamir). If all constraints hold, the
numerator vanishes on H, the division is exact, and `h(X)` is a well-defined
polynomial. If any constraint fails at any row, `h(X)` is not a polynomial
(there is a remainder), and the verification check will fail.

The factor `yⁱ` prevents a dishonest prover from cancelling errors across
different constraints — the random linear combination makes each constraint
independently enforced with high probability.

---

## 4. KZG polynomial commitments

The prover cannot just hand over the polynomials — that would reveal the
witness. Instead, they use **KZG commitments**: a commitment to polynomial
`p(X)` is the group element `[p(s)]₁ = p(s) · G₁_gen`, where `s` is a secret
from a trusted setup (the SRS). The SRS provides `[s⁰]₁, [s¹]₁, …, [s^d]₁`
but `s` itself is unknown.

A KZG commitment is:
- **Binding**: it uniquely determines the polynomial (given the SRS).
- **Hiding** (with randomisation): the commitment reveals nothing about the
  polynomial's values.

The prover commits to all advice polynomials early — before seeing any
challenges. This prevents them from changing the witness after seeing what the
verifier would check.

---

## 5. The Fiat-Shamir transcript

Halo2 uses the **Fiat-Shamir heuristic** to make the proof non-interactive.
A transcript accumulates all commitments sent so far; squeezing the transcript
(via BLAKE2b-256) produces a random-looking challenge field element.

The order matters and must match exactly between prover and verifier:

```
absorb(transcript_repr)                   → seeds the transcript with the circuit identity
absorb(G1_zero)                           → instance column placeholder
absorb(pubInputs)                         → public inputs
absorb(advice_commitments)                → squeeze θ   (lookup θ-compression challenge)
absorb(lookup_multiplicity_commitments)   → squeeze β, γ (permutation + LogUp challenges)
absorb(perm_product_commitments)          → (no squeeze)
absorb(per-lookup helpers + accumulator)  → squeeze trashChal (once, after all lookups)
absorb(trash_commitments)                 → squeeze y   (gate Horner-folding challenge)
absorb(h_commitments)                     → squeeze x   (shared evaluation point)
absorb(all_evaluations)                   → squeeze x₁, x₂
absorb(fCom)                              → squeeze x₃  (GWC opening point)
absorb(q_evals_on_x₃)                    → squeeze x₄
```

Note that `β` is the challenge for **both** the permutation argument and the LogUp
lookup argument; `γ` is used only for the permutation argument.

Because every commitment is absorbed before its associated challenge is
squeezed, a cheating prover cannot adaptively choose their commitments to
cancel out a challenge they already know.

---

## 6. Opening polynomials at a random point

Once the evaluation point `x` is determined from the transcript, the prover
evaluates every polynomial at `x` and sends these values. The verifier can
then check:

> "Does the polynomial committed in `[p(s)]₁` actually evaluate to the claimed
> value at `x`?"

This is a **KZG opening proof**: the prover sends a *witness polynomial*
`w(X) = (p(X) − p(x)) / (X − x)` committed as `[w(s)]₁ = π`. The verifier
checks using a pairing:

```
e(π, [s]G₂) = e([p(s)]₁ − p(x)·G₁, G₂)
```

This works because the pairing is bilinear: both sides compute `e(G₁, G₂)^{w(s)·(s−x)}`
if the claim is correct.

---

## 7. The permutation argument (copy constraints)

Many computations require that the same value appears in multiple cells — for
instance, the output of one gate is the input of another. These **copy
constraints** cannot be expressed by local gate polynomials alone (which only
see one row at a time).

Halo2 uses a **grand product argument**. Each cell `(column c, row i)` gets a
unique identifier `δ^c · ω^i` where `δ` is a coset generator. The sigma
polynomials `σ_c(X)` encode where each cell's value is supposed to be copied
to.

The prover builds a grand product polynomial `Z(X)` that telescopes to 1 if
and only if all copy constraints hold. At every row, it checks:

```
Z(ωX) · Π(col_k + β·σ_k(X) + γ) = Z(X) · Π(col_k + δ^k·β·X + γ)
```

The left side uses the actual copy destinations (σ); the right side uses the
"identity" permutation. If they match, `Z(X)` is constant — pinned to 1 at
row 0. The β and γ challenges prevent the prover from finding clever
cancellations across columns.

For circuits with many permutation columns, the argument is split into chunks
to keep polynomial degrees manageable.

---

## 8. The lookup argument (LogUp)

Some constraints are most naturally expressed as "this value is in this table"
— for example, range checks or S-box lookups. midnight-zk uses the **LogUp**
argument (v7), based on the logarithmic-derivative identity:

```
Σ_i 1/(f_i + β) = Σ_j m_j/(t_j + β)
```

where `f_i` are the (θ-compressed) input expressions, `t_j` are the table entries,
`m_j` are their multiplicities, and `β` is a Fiat-Shamir challenge.

The prover commits to a **multiplicity polynomial** `m(X)` (one per lookup), `nc`
**helper polynomials** `h_0(X), …, h_{nc−1}(X)` (one per chunk of parallel inputs),
and an **accumulator** `Z(X)` that certifies the telescoping sum.

The three types of constraint per lookup are:

- **Boundary**: `(l₀ + l_last) · Z(x) = 0` — forces Z to be zero at the boundary rows.
- **Helper** (one per chunk c): `h_c · Π_j(f_j+β) − Σ_j Π_{k≠j}(f_k+β) = 0` — certifies
  that `h_c = Σ_j 1/(f_j+β)` as a polynomial identity.
- **Accumulator**: `activeRows · ((Z_next − Z − sel·Σ_c h_c) · (t+β) + m) = 0` — certifies
  the running sum `Z(ωX) − Z(X) = sel(X) · Σ_c h_c(X) − m(X)/(t(X)+β)`.

Only the challenge `β` is needed (not `γ`). Evaluations sent per lookup at `x`: one
`mult_eval`, `nc` `helper_evals`, one `accum_eval`, and one `accum_next_eval` (at `xω`).

---

## 9. The quotient polynomial h(X) — the core soundness check

All gate, permutation, and lookup constraints are combined into one polynomial:

```
numerator(X) = Σᵢ yⁱ · constraintᵢ(X)
```

The prover divides by `Z_H(X) = X^N − 1` to get `h(X)`. Because `h(X)` can
have degree up to `(d−1)·N` (where `d` is the constraint degree), it is split
into `nh = d − 1` pieces:

```
h(X) = h₀(X) + X^{N-1}·h₁(X) + X^{2(N-1)}·h₂(X) + …
```

Each piece has degree < N−1 and is committed to separately as `prfHComs[j]`.

**The soundness trick**: the verifier never trusts the prover's h directly.
Instead, the verifier independently computes what `h(x)` *must* equal, using
the claimed polynomial evaluations sent by the prover:

```
hEval = (Σᵢ yⁱ · constraintᵢ(x)) / (x^N − 1)
```

Then the GWC opening (see §10) enforces that the committed `h` polynomial
actually opens to this `hEval`. If the prover cheated — committed to an `h`
that doesn't encode the real constraints — their commitment opens to a
different value and the final pairing check fails.

Note: `h(X)` is **not** the witness. The witness is the advice columns. `h(X)`
is a derived proof artifact that certifies the constraints hold; its
commitments need no independent blinding because `h` carries no secret
information beyond what the advice already reveals.

---

## 10. The multi-point opening problem

Different polynomials are evaluated at different points:

- Most polynomials are queried at the current row `x`.
- Grand product polynomials also need `xω` (next row) and `xω^{last}` (last row).
- Lookup polynomials need `x` and `xω`; some also need `xω⁻¹`.

With n polynomials each needing a KZG opening proof, the naive approach
requires n pairings — too expensive.

### GWC: batching across multiple evaluation points

The **GWC protocol** (Gemini-With-Challenges) reduces all openings to a single
pairing, regardless of how many polynomials and evaluation points there are.

**Step 1 — Group by rotation set.**
Polynomials that share the exact same set of evaluation points are placed in
the same *rotation set* Sᵢ. For example, all polynomials queried only at `{x}`
form one set; those queried at `{x, xω}` form another.

**Step 2 — Within-set batching (challenge x₁).**
Inside rotation set Sᵢ, combine all `nᵢ` polynomials into one:

```
q_i(X) = Σⱼ x₁^j · poly_{i,j}(X)
```

The combined commitment `qCom_i = Σⱼ x₁^j · [poly_{i,j}]₁` is a multi-scalar
multiplication. The combined evaluation at each point `p ∈ Sᵢ` is
`q_i(p) = Σⱼ x₁^j · poly_{i,j}(p)`.

**Step 3 — Across-set reduction (challenge x₂).**
For each set Sᵢ, compute the Lagrange interpolant `r_i(X)` — the unique
low-degree polynomial agreeing with `q_i` on Sᵢ. Then define:

```
c_i = (q_i(x₃) − r_i(x₃)) / V_i(x₃)
```

where `V_i(X) = Π_{p ∈ Sᵢ} (X − p)` is the vanishing polynomial of Sᵢ and
`x₃` is a fresh random challenge. If all claimed evaluations are correct,
`(q_i − r_i)` vanishes on Sᵢ, so `V_i` divides exactly and `c_i` is a
well-defined scalar.

The prover commits to the auxiliary polynomial `f(X)` whose evaluation at `x₃`
is `f(x₃) = Σᵢ x₂^i · c_i` (Horner in x₂). The commitment `fCom = [f(s)]₁`
is absorbed into the transcript before `x₃` is squeezed, binding `f`.

**Step 4 — Single KZG opening (challenges x₃, x₄).**
All `qCom_i` and `fCom` are folded into one combined commitment with powers of
x₄:

```
finalCom = Σᵢ x₄^i · qCom_i  +  x₄^m · fCom
vEval    = Σᵢ x₄^i · q_i(x₃) +  x₄^m · f(x₃)
```

Now there is one commitment (`finalCom`) and one claimed evaluation (`vEval`)
at a single point (`x₃`). A single KZG witness `π` proves the opening:

```
e(π, [s]G₂) = e(finalCom − vEval·G₁ + x₃·π, G₂)
```

**This is exactly two Miller loops** — one on each side — regardless of how
many polynomials, rotation sets, or evaluation points the circuit has.

---

## 11. Putting it all together

The complete verification flow:

```
1. Parse the VK, proof, rotation sets, and public inputs from JSON.

2. Rebuild the Fiat-Shamir transcript to derive all challenges
   (θ, β, γ, trashChal, y, x, x₁, x₂, x₃, x₄).

3. Compute evaluation points: x, xω, xω⁻¹, xω^{last}.

4. Compute hEval — what h(x) must be — from the prover's claimed
   evaluations and the circuit's GateExpr constraint trees.

5. Assemble rotation sets: for each RotationSetSpec, convert raw integer
   rotation offsets to the Rotation ADT, look up commitments and
   evaluations per slot, and pre-combine with x₁ powers.

6. Run the generic GWC verifier (verifyGwc):
   a. Lagrange interpolate r_i(x₃) for each rotation set.
   b. Compute GWC contributions c_i.
   c. Compute f(x₃) via Horner in x₂.
   d. Fold into finalCom and vEval with x₄ powers.
   e. Single KZG pairing check.

7. Accept iff the pairing holds.
```

The key separation: `computeHEval` answers "what should the linearization
commitment `lin_com` evaluate to at x, given the constraint system?" and
`verifyGwc` answers "does the prover's committed `lin_com` actually open to
that?". Both are necessary — neither alone is sufficient.

---

## 12. What makes midnight-zk special

Standard Halo2 commits to instance columns. midnight-zk does not:

- **Instance column 0** is the zero polynomial. Its commitment is the G1
  identity; its evaluation is always 0. Public inputs are not committed to in
  the usual sense.
- **Public inputs** are placed in instance column 1, rows 0..np−1. The
  verifier reconstructs their contribution via Lagrange interpolation:
  `pubInstEval = Σᵢ pubInputs[i] · L_i(x)`.

This simplifies the transcript (no instance commitment to absorb beyond the
G1-zero placeholder) while keeping the constraint system correct.

The **trash argument** handles circuits that require extra blinding commitments
beyond the standard `blinding_factors` rows. It adds one extra polynomial per
trashcan, with its own grand-product-style constraint and challenge.

**Linearization commitment**: midnight-zk does not commit to the vanishing quotient
`h(X)` directly. Instead the prover commits to the **linearization polynomial**:

```
L(X) = (1 − x^n) · h(X) + Σ_k c_k · S_k(X)
```

where `S_k` are the *simple-selector* fixed columns (boolean activators that are
optimised away from the proof stream) and `c_k` are Fiat-Shamir-derived scalars
computed during the gate constraint evaluation. The verifier reconstructs
`L(x) = linComEval` from the gate fold without ever seeing `S_k(x)` (substituting 1),
then the KZG opening check enforces consistency. This folds the selector
commitments `[S_k(s)]₁` into the H slot MSM, which covers both the h-piece
commitments and the selector column commitments (see VERIFIER_SPEC.md §7.2).

**Fewer-point-sets**: when the `fewer-point-sets` feature is active, all polynomials
are merged into a single rotation set by adding synthetic *dummy evaluations* for
non-native rotation points. This reduces the number of Lagrange interpolations and
MSMs in the GWC check, lowering on-chain verification cost at the price of a slightly
larger proof.
