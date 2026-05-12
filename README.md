# plutus-midnight-zk

A Plutus on-chain verifier for [midnight-zk](https://github.com/midnightntwrk/midnight-zk)
circuits (GWC / Halo2 over BLS12-381), together with a Rust test-vector generator that
proves and serialises all 10 example circuits.

```bash
plutus-midnight-zk/   Haskell — Plutus verifier library + test suite
rust-midnight-zk/     Rust    — test-vector generator (10 circuits)
test-vectors/         JSON    — pre-generated artifacts (tracked in git)
```

---

## Quick start

### Prerequisites — Filecoin SRS

The circuits use the Filecoin trusted-setup parameters (SRS), which are not
included in the repository. They must be present under `examples/assets/`
before re-generating test vectors:

```bash
mkdir -p examples/assets
curl -L -o examples/assets/bls_filecoin_2p19 \
  https://midnight-s3-fileshare-dev-eu-west-1.s3.eu-west-1.amazonaws.com/bls_filecoin_2p19
```

The pre-generated `test-vectors/` in the repository are sufficient to run the
Haskell verifier without downloading the SRS.

### Run the Plutus verifier test suite (no SRS needed)

```bash
nix run .#plutus-midnight-zk-run-vector-test
```

Or inside a dev shell:

```bash
nix develop
cabal test run-vector-test
```

Expected output (20 lines — 2 per circuit × 10 circuits):

```bash
=== SHA-256 preimage ===
PASS: valid proof accepted
PASS: corrupted proof rejected
=== Bitcoin Schnorr signature ===
PASS: valid proof accepted
PASS: corrupted proof rejected
...
All tests passed.
```

### Run the script-size and ExUnit benchmarks (no SRS needed)

```bash
nix run .#plutus-midnight-zk-bench
```

Or inside a dev shell:

```bash
nix develop
cabal bench bench
```

Expected output — script size and CEK execution units for each of the 10 circuits:

```
    n     Script size             CPU usage               Memory usage
  ----------------------------------------------------------------------
  SHA-256 preimage
    -   <size> (<x.x%>)       <cpu> (<x.x%>)       <mem> (<x.x%>)
  ...
```

Percentages are relative to the current Cardano mainnet transaction limits
(`maxTxSize` = 16 384 bytes, `maxTxExSteps` = 10 000 000 000, `maxTxExMem` = 16 500 000).

---

### Regenerate test vectors (requires SRS)

```bash
nix run .#rust-midnight-zk-write-test-vectors
```

Or inside a dev shell:

```bash
cargo run --bin write-test-vectors
```

---

## Circuits

| Circuit | Directory | Description |
| ------- | --------- | ----------- |
| Poseidon hash preimage | `poseidon/` | Poseidon-128 hash preimage knowledge |
| SHA-256 preimage | `sha-preimage/` | SHA-256 preimage knowledge |
| JubJub ECC | `ecc/` | JubJub elliptic-curve scalar multiplication |
| Schnorr signature | `schnorr-sig/` | Schnorr signature via Poseidon + JubJub |
| Native gadgets | `native-gadgets/` | Range checks and bit decomposition |
| Multi-set membership | `membership/` | Multi-set membership via MapChip |
| RSA signature | `rsa-sig/` | RSA-PKCS1 signature verification |
| Bitcoin Schnorr | `bitcoin-sig/` | BIP-340 Schnorr signature |
| Ethereum ECDSA | `ethereum-sig/` | Ethereum ECDSA signature (EIP-191) |
| ECDSA threshold | `ecdsa-threshold/` | 4-of-5 threshold ECDSA |

---

## Test vector format

Six JSON files are written per circuit under `test-vectors/<name>/`:

| File | Contents |
| ---- | -------- |
| `*_plutus_vk.json` | **Trusted-setup-dependent**: fixed/perm commitments, SRS G2 point, transcript repr, domain params (k, ω, degree, queries) |
| `*_circuit_constraint.json` | **Circuit-design-dependent**: gate polynomials, permutation column types, lookup and trash expressions (δ is a field constant — hardcoded in `BlsUtils.hs`) |
| `*_circuit_params.json` | 10 integers describing the circuit layout (columns, lookups, chunks, etc.) |
| `*_rotation_sets.json` | Rotation-set metadata for the GWC multi-point opening |
| `*_plutus_proof.json` | GWC proof parsed into named fields (commitments and evaluations) |
| `*_plutus_instance.json` | Public input scalars as 32-byte little-endian hex strings |

The VK and circuit-constraint data are deliberately split: redoing the trusted setup (new
SRS) produces a new `*_plutus_vk.json` but leaves `*_circuit_constraint.json` and
`*_rotation_sets.json` unchanged.

Gate polynomial expressions in `*_circuit_constraint.json` are stored as human-readable flat
RPN instruction arrays so that the constraint system is auditable without tooling:

```json
"gate_polys": [
  [
    {"op": "Fixed", "query_index": 9},
    {"op": "Advice", "query_index": 0},
    {"op": "Advice", "query_index": 1},
    {"op": "Product"},
    {"op": "Sum"},
    {"op": "Negated"}
  ],
  ...
]
```

See `VERIFIER_SPEC.md` for the full instruction set and all JSON field definitions.

---

## Project structure

```bash
plutus-midnight-zk/
  src/Plutus/Crypto/
    BlsUtils.hs                  BLS12-381 field/group arithmetic helpers
    MidnightZk/
      Types.hs                   Proof, VerifyingKey, CircuitConfig, RotationSet*
      Transcript.hs              PlutusBlake2b Fiat-Shamir transcript
      Verifier.hs                assembleRotationSets + verifyGwc + computeHEval
      JsonParser.hs              JSON → Haskell types (RPN arrays → GateExpr trees)
  test/
    Main.hs                      10-circuit test runner

rust-midnight-zk/
  src/
    circuit_params.rs            JSON serialisation helpers (shared across circuits)
    rotation_sets.rs             Rotation-set binary encoding
    lib.rs
  src/bin/
    write_test_vectors.rs        Runs all 10 circuits and writes JSON artifacts

test-vectors/
  <circuit-name>/
    *_plutus_vk.json             trusted-setup-dependent VK fields
    *_circuit_constraint.json    circuit-design-dependent fields (gate polys, etc.)
    *_circuit_params.json        10 scalar circuit dimensions
    *_rotation_sets.json         GWC rotation-set metadata
    *_plutus_proof.json          proof (commitments + evaluations)
    *_plutus_instance.json       public inputs
```

---

## Documentation

Three markdown files cover the project at different levels of detail:

| File | Audience | Purpose |
| ---- | -------- | ------- |
| `HALO2_EXPLAINER.md` | New readers | Intuitive end-to-end walkthrough: from encoding computation in gates, through KZG commitments and Fiat-Shamir, to the GWC multi-point opening. Start here if you are unfamiliar with Halo2. |
| `CONSTRAINT_SYSTEM.md` | Protocol readers | Reference for the constraint system: gate/permutation/lookup/trash expressions, the Horner fold that assembles h(x), and a breakdown of what can be precomputed before seeing a proof. |
| `VERIFIER_SPEC.md` | Auditors / implementers | Authoritative line-by-line specification: all JSON field definitions, transcript absorption order, rotation-set assembly, GWC algorithm, and KZG pairing check. Sufficient to independently re-implement or audit the verifier. |

---

## Development shell

```bash
nix develop
```

Provides GHC 9.6, Cabal, and the Rust toolchain. Inside the shell:

```bash
# Haskell
cabal build
cabal test run-vector-test
cabal bench bench

# Rust
cargo build
cargo run --bin write-test-vectors
```
