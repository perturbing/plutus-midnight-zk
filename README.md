# plutus-midnight-zk

A Plutus on-chain verifier for [midnight-zk](https://github.com/midnightntwrk/midnight-zk) circuits (GWC / PLONK over BLS12-381).

The repository has two components:

```
plutus-midnight-zk/   Haskell — Plutus verifier (TODO)
rust-midnight-zk/     Rust    — test-vector generator
```

## Components

### `rust-midnight-zk` — test-vector generator

Builds the binary `write-test-vectors`, which runs 10 example circuits through
the full prove/verify cycle and writes the inputs the Plutus verifier needs for
each one.  Five JSON files are produced per circuit under `test-vectors/<name>/`:

| File | Contents |
|---|---|
| `*_plutus_vk.json` | Verifying key and SRS g2 commitment |
| `*_circuit_params.json` | 10 integers describing the circuit layout (number of columns, lookups, etc.) |
| `*_rotation_sets.json` | Rotation-set metadata for the GWC multiopen check |
| `*_plutus_proof.json` | GWC proof parsed into named fields |
| `*_plutus_instance.json` | Public input scalars as 32-byte little-endian hex strings |

Circuits covered: Poseidon hash, SHA-256 preimage, ECC operations, Schnorr
signature, native gadgets, set membership, RSA signature, Bitcoin BIP-340
signature, Ethereum ECDSA signature, 4-of-5 ECDSA threshold signature.

### `plutus-midnight-zk` — Plutus verifier

**TODO** — will consume the JSON test vectors produced above to verify
midnight-zk proofs on-chain.

## Generating test vectors

### Prerequisites — Filecoin SRS

The circuits use the Filecoin trusted-setup parameters (SRS), which are not
included in the repository.  They must be present under `examples/assets/`
before running the generator, otherwise it will panic with a message about a
missing SRS.

The simplest way is to download the pre-parsed file directly:

```bash
mkdir -p examples/assets
curl -L -o examples/assets/bls_filecoin_2p19 \
  https://midnight-s3-fileshare-dev-eu-west-1.s3.eu-west-1.amazonaws.com/bls_filecoin_2p19
```

### Running

```bash
nix run .#rust-midnight-zk-write-test-vectors
```

Output is written to `test-vectors/` in the current directory by default.  Pass
an alternative path as the first argument:

```bash
nix run .#rust-midnight-zk-write-test-vectors -- /tmp/my-vectors
```

## Development shell

```bash
nix develop
```

Provides Rust (nightly) and Haskell toolchains.  Within the shell you can also
run the generator directly:

```bash
cargo run --bin write-test-vectors
```

## Nix cache

Binary caches are configured in `flake.nix`.  The first build fetches the
midnight-zk crates from GitHub (`midnightntwrk/midnight-zk`, branch `next`) and
may take a while; subsequent builds are cached.
