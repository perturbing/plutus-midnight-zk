//! Shared helpers for computing GWC circuit parameters and serialising Plutus outputs.

use ff::{Field, PrimeField};
use group::GroupEncoding;
use std::fs;
use midnight_curves::{Bls12, Fq};
use midnight_proofs::{plonk::VerifyingKey, poly::kzg::KZGCommitmentScheme};
use crate::rotation_sets::rotation_sets_bytes;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Proof parser ─────────────────────────────────────────────────────────────

struct ProofReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ProofReader<'a> {
    fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }

    /// Read a compressed G1 point (48 bytes) as hex.
    fn g1(&mut self) -> String {
        let s = to_hex(&self.data[self.pos..self.pos + 48]);
        self.pos += 48;
        s
    }

    /// Read a 32-byte field element as hex.
    fn scalar(&mut self) -> String {
        let s = to_hex(&self.data[self.pos..self.pos + 32]);
        self.pos += 32;
        s
    }

    fn remaining(&self) -> usize { self.data.len() - self.pos }
}

/// Parse a GWC proof into its constituent parts as a structured JSON object.
///
/// The returned object has keys:
/// `advice_commitments`, `lookup_permuted_commitments`,
/// `permutation_product_commitments`, `lookup_product_commitments`,
/// `trash_commitments`, `random_poly_commitment`, `h_commitments`,
/// `advice_evals`, `fixed_evals`, `random_eval`, `sigma_evals`,
/// `permutation_product_evals`, `lookup_evals`, `trash_evals`, `gwc`.
pub fn proof_to_json(proof: &[u8], p: &CircuitParams) -> serde_json::Value {
    let mut r = ProofReader::new(proof);
    let np = (p.npc + p.chunk_size - 1) / p.chunk_size;
    let perm_all_3evals = p.num_ppe == np * 3;

    // ── Commitments ───────────────────────────────────────────────────────
    let advice_commitments: Vec<_> =
        (0..p.na).map(|_| r.g1()).collect();

    let lookup_permuted_commitments: Vec<_> = (0..p.nl)
        .map(|_| serde_json::json!({
            "permuted_input": r.g1(),
            "permuted_table": r.g1(),
        }))
        .collect();

    let permutation_product_commitments: Vec<_> =
        (0..np).map(|_| r.g1()).collect();
    let lookup_product_commitments: Vec<_> =
        (0..p.nl).map(|_| r.g1()).collect();
    let trash_commitments: Vec<_> =
        (0..p.num_trash).map(|_| r.g1()).collect();
    let random_poly_commitment = r.g1();
    let h_commitments: Vec<_> =
        (0..p.nh).map(|_| r.g1()).collect();

    // ── Evaluations ───────────────────────────────────────────────────────
    // TODO: instance_poly_eval is always zero in current test vectors.  This may be
    // because format_committed_instances returns [] (no committed instance columns),
    // with public inputs travelling via verifier-side Lagrange interpolation instead —
    // but this interpretation of the code may be wrong.  Revisit if/when the Plutus
    // verifier moves into this codebase.
    let instance_poly_eval     = r.scalar();
    let advice_evals: Vec<_>  = (0..p.naq).map(|_| r.scalar()).collect();
    let fixed_evals: Vec<_>   = (0..p.nfq).map(|_| r.scalar()).collect();
    let random_eval            = r.scalar();
    let sigma_evals: Vec<_>   = (0..p.npc).map(|_| r.scalar()).collect();

    let permutation_product_evals: Vec<_> = (0..np)
        .map(|i| {
            let eval      = r.scalar();
            let next_eval = r.scalar();
            let last_eval = if perm_all_3evals || i < np - 1 {
                serde_json::Value::String(r.scalar())
            } else {
                serde_json::Value::Null
            };
            serde_json::json!({
                "eval":      eval,
                "next_eval": next_eval,
                "last_eval": last_eval,
            })
        })
        .collect();

    let lookup_evals: Vec<_> = (0..p.nl)
        .map(|_| serde_json::json!({
            "product_eval":            r.scalar(),
            "product_next_eval":       r.scalar(),
            "permuted_input_eval":     r.scalar(),
            "permuted_input_inv_eval": r.scalar(),
            "permuted_table_eval":     r.scalar(),
        }))
        .collect();

    let trash_evals: Vec<_> = (0..p.num_trash).map(|_| r.scalar()).collect();

    // ── GWC multiopen proof ───────────────────────────────────────────────
    let f_commitment = r.g1();
    let q_evals: Vec<_> = (0..p.num_q).map(|_| r.scalar()).collect();
    let w_commitment = r.g1();

    assert_eq!(
        r.remaining(), 0,
        "proof_to_json: {} bytes unconsumed", r.remaining()
    );

    serde_json::json!({
        "advice_commitments":            advice_commitments,
        "lookup_permuted_commitments":   lookup_permuted_commitments,
        "permutation_product_commitments": permutation_product_commitments,
        "lookup_product_commitments":    lookup_product_commitments,
        "trash_commitments":             trash_commitments,
        "random_poly_commitment":        random_poly_commitment,
        "h_commitments":                 h_commitments,
        "instance_poly_eval":            instance_poly_eval,
        "advice_evals":                  advice_evals,
        "fixed_evals":                   fixed_evals,
        "random_eval":                   random_eval,
        "sigma_evals":                   sigma_evals,
        "permutation_product_evals":     permutation_product_evals,
        "lookup_evals":                  lookup_evals,
        "trash_evals":                   trash_evals,
        "gwc": {
            "f_commitment": f_commitment,
            "q_evals":      q_evals,
            "w_commitment": w_commitment,
        },
    })
}

// ── Rotation-set parser ───────────────────────────────────────────────────────

fn poly_kind_name(k: u8) -> &'static str {
    match k {
        0  => "Advice",
        1  => "Instance",
        2  => "LookupTable",
        3  => "Trash",
        4  => "Fixed",
        5  => "PermSigma",
        6  => "H",
        7  => "Random",
        8  => "PermProd",
        9  => "LookupProd",
        10 => "LookupInput",
        _  => "Unknown",
    }
}

/// Parse a rotation-sets binary buffer into a structured JSON object.
///
/// Format per the `rotation_sets.rs` spec:
/// `num_sets`, then for each set: rotations, then slots (poly_kind, index, eval_idxs).
pub fn rotation_sets_to_json(buf: &[u8]) -> serde_json::Value {
    let mut pos = 0usize;

    macro_rules! read_u32 {
        () => {{
            let v = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
            pos += 4;
            v
        }};
    }
    macro_rules! read_i32 {
        () => {{
            let v = i32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
            pos += 4;
            v
        }};
    }
    macro_rules! read_u8 {
        () => {{
            let v = buf[pos];
            pos += 1;
            v
        }};
    }

    let num_sets = read_u32!();

    let sets: Vec<serde_json::Value> = (0..num_sets)
        .map(|_| {
            let num_rotations = read_u32!();
            let rotations: Vec<i32> = (0..num_rotations).map(|_| read_i32!()).collect();
            let num_slots = read_u32!();
            let slots: Vec<serde_json::Value> = (0..num_slots)
                .map(|_| {
                    let kind      = read_u8!();
                    let index     = read_u32!();
                    let eval_idxs: Vec<u32> =
                        (0..num_rotations).map(|_| read_u32!()).collect();
                    serde_json::json!({
                        "poly_kind": poly_kind_name(kind),
                        "index":     index,
                        "eval_idxs": eval_idxs,
                    })
                })
                .collect();
            serde_json::json!({
                "rotations": rotations,
                "slots":     slots,
            })
        })
        .collect();

    assert_eq!(pos, buf.len(), "rotation_sets_to_json: {} bytes unconsumed", buf.len() - pos);

    serde_json::json!({ "num_sets": num_sets, "sets": sets })
}

/// All circuit-structure scalars needed by the Plutus verifier.
#[derive(Debug, Clone, Copy)]
pub struct CircuitParams {
    pub na: u32,         // number of advice columns
    pub nl: u32,         // number of lookups
    pub npc: u32,        // number of permutation commitments
    pub chunk_size: u32, // degree − 2
    pub nh: u32,         // degree − 1
    pub naq: u32,        // number of advice queries
    pub nfq: u32,        // number of fixed queries
    pub num_trash: u32,  // extra G1 blinding commitments
    pub num_ppe: u32,    // perm-product eval count
    pub num_q: u32,      // rotation-set (Q) count
}

/// Serialize `params` as 10 × u32 LE (40 bytes).
pub fn params_to_bytes(p: &CircuitParams) -> [u8; 40] {
    let words = [
        p.na, p.nl, p.npc, p.chunk_size, p.nh,
        p.naq, p.nfq, p.num_trash, p.num_ppe, p.num_q,
    ];
    let mut out = [0u8; 40];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn compute_circuit_params(
    na: u32,
    nl: u32,
    npc: u32,
    degree: usize,
    naq: u32,
    nfq: u32,
    proof: &[u8],
    num_q: u32,
) -> CircuitParams {
    let chunk_size = (degree - 2) as u32;
    let np = (npc + chunk_size - 1) / chunk_size;
    let nh = (degree - 1) as u32;

    let sc_init = 1 + naq + nfq + 1 + npc + (np - 1) * 3 + 2 + 5 * nl;
    let trailing = 96 + num_q * 32;
    let commit_bytes = proof.len() as u32 - trailing - sc_init * 32;
    let actual_g1 = commit_bytes / 48;
    let expected_g1_base = na + 2 * nl + np + nl + 1 + nh;
    let num_trash = actual_g1 - expected_g1_base;

    let non_perm_sc = 1 + naq + nfq + 1 + npc + 5 * nl + num_trash;
    let total_scalars_and_q = (proof.len() as u32 - actual_g1 * 48 - 96) / 32;
    let num_ppe = total_scalars_and_q - non_perm_sc - num_q;

    CircuitParams { na, nl, npc, chunk_size, nh, naq, nfq, num_trash, num_ppe, num_q }
}

/// Encode a slice of field elements as concatenated 32-byte LE representations.
pub fn instance_field_bytes<F: PrimeField>(pi: &[F]) -> Vec<u8> {
    pi.iter().flat_map(|f| f.to_repr().as_ref().to_vec()).collect()
}

/// Write `{name}_circuit_params.json` and `{name}_rotation_sets.json` into `dir`.
///
/// `circuit_params.json` contains the 10 circuit-structure scalars as named fields.
/// `rotation_sets.json` contains the rotation-set binary as a hex string.
///
/// Returns the computed `CircuitParams` so callers can reuse it (e.g. for proof parsing)
/// without recomputing rotation sets a second time.
pub fn write_json_circuit_artifacts(
    dir: &str,
    name: &str,
    na: u32,
    nl: u32,
    npc: u32,
    degree: usize,
    naq: u32,
    nfq: u32,
    proof: &[u8],
    aq: &[(usize, i32)],
    fq: &[(usize, i32)],
) -> CircuitParams {
    let buf0 = rotation_sets_bytes(aq, fq, na as usize, nl as usize, npc as usize, degree, 0, false);
    let num_q = u32::from_le_bytes(buf0[0..4].try_into().unwrap());

    let p = compute_circuit_params(na, nl, npc, degree, naq, nfq, proof, num_q);

    let chunk_size = (degree - 2) as u32;
    let np = (npc + chunk_size - 1) / chunk_size;
    let perm_all_3evals = p.num_ppe == np * 3;

    let rot_buf = rotation_sets_bytes(
        aq, fq,
        na as usize, nl as usize, npc as usize,
        degree,
        p.num_trash as usize,
        perm_all_3evals,
    );

    let params_json = serde_json::json!({
        "num_advice_columns":           p.na,
        "num_lookups":                  p.nl,
        "num_permutation_commitments":  p.npc,
        "permutation_chunk_size":       p.chunk_size,
        "num_quotient_commitments":     p.nh,
        "num_advice_queries":           p.naq,
        "num_fixed_queries":            p.nfq,
        "num_blinding_commitments":     p.num_trash,
        "num_permutation_product_evals": p.num_ppe,
        "num_rotation_sets":            p.num_q,
    });
    let params_out = serde_json::to_string_pretty(&params_json).unwrap();
    fs::write(format!("{dir}/{name}_circuit_params.json"), &params_out)
        .expect("failed to write circuit_params.json");

    let rot_out = serde_json::to_string_pretty(&rotation_sets_to_json(&rot_buf)).unwrap();
    fs::write(format!("{dir}/{name}_rotation_sets.json"), &rot_out)
        .expect("failed to write rotation_sets.json");

    p
}

/// Write all five Plutus artifact files for a circuit into `dir` as JSON.
///
/// Files written:
///   `{name}_plutus_vk.json`       – Plutus verifying key (structured)
///   `{name}_circuit_params.json`  – 10 circuit-structure scalars
///   `{name}_rotation_sets.json`   – rotation-set metadata (hex)
///   `{name}_plutus_proof.json`    – proof bytes (hex)
///   `{name}_plutus_instance.json` – public inputs as array of 32-byte LE hex strings
///
/// Does not use `write_plutus_vk`; all VK fields are accessed via the public API.
pub fn write_json_all_artifacts(
    dir: &str,
    name: &str,
    vk: &VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
    s_g2_bytes: &[u8],
    proof: &[u8],
    pi: &[Fq],
) {
    fs::create_dir_all(dir).expect("failed to create output dir");

    // VK
    {
        let k = vk.n().trailing_zeros();

        // Primitive 2^k-th root of unity: square ROOT_OF_UNITY down from 2^S.
        let mut omega = Fq::ROOT_OF_UNITY;
        for _ in 0..(Fq::S - k) {
            omega = omega.square();
        }

        let fixed_commitments: Vec<String> = vk.fixed_commitments().iter()
            .map(|c| to_hex(c.to_bytes().as_ref()))
            .collect();
        let perm_commitments: Vec<String> = vk.permutation().commitments().iter()
            .map(|c| to_hex(c.to_bytes().as_ref()))
            .collect();
        let advice_queries: Vec<serde_json::Value> = vk.cs().advice_queries().iter()
            .map(|(col, rot)| serde_json::json!({ "col": col.index(), "rot": rot.0 }))
            .collect();
        let fixed_queries: Vec<serde_json::Value> = vk.cs().fixed_queries().iter()
            .map(|(col, rot)| serde_json::json!({ "col": col.index(), "rot": rot.0 }))
            .collect();

        let vk_json = serde_json::json!({
            "k":                    k,
            "fixed_commitments":    fixed_commitments,
            "permutation_commitments": perm_commitments,
            "transcript_repr":      to_hex(vk.transcript_repr().to_repr().as_ref()),
            "blinding_factors":     vk.cs().blinding_factors() as u32,
            "num_advice_columns":   vk.cs().num_advice_columns() as u32,
            "num_perm_columns":     vk.cs().permutation().columns.len() as u32,
            "cs_degree":            vk.cs().degree() as u32,
            "num_lookups":          vk.cs().lookups().len() as u32,
            "advice_queries":       advice_queries,
            "fixed_queries":        fixed_queries,
            "s_g2":                 to_hex(s_g2_bytes),
            "omega":                to_hex(omega.to_repr().as_ref()),
        });
        let vk_out = serde_json::to_string_pretty(&vk_json).unwrap();
        fs::write(format!("{dir}/{name}_plutus_vk.json"), &vk_out)
            .expect("failed to write plutus_vk.json");
    }

    // circuit_params.json + rotation_sets.json + proof.json
    {
        let cs = vk.cs();
        let na  = cs.num_advice_columns() as u32;
        let nl  = cs.lookups().len() as u32;
        let npc = vk.permutation().commitments().len() as u32;
        let naq = cs.advice_queries().len() as u32;
        let nfq = cs.fixed_queries().len() as u32;
        let aq: Vec<(usize, i32)> = cs.advice_queries().iter()
            .map(|(col, r)| (col.index(), r.0)).collect();
        let fq_vec: Vec<(usize, i32)> = cs.fixed_queries().iter()
            .map(|(col, r)| (col.index(), r.0)).collect();

        let p = write_json_circuit_artifacts(
            dir, name, na, nl, npc, cs.degree(), naq, nfq, proof, &aq, &fq_vec,
        );

        let proof_out = serde_json::to_string_pretty(&proof_to_json(proof, &p)).unwrap();
        fs::write(format!("{dir}/{name}_plutus_proof.json"), &proof_out)
            .expect("failed to write plutus_proof.json");
    }

    // instance
    let instance_json: Vec<String> = pi.iter()
        .map(|f| to_hex(f.to_repr().as_ref()))
        .collect();
    let inst_out = serde_json::to_string_pretty(&serde_json::json!(instance_json)).unwrap();
    fs::write(format!("{dir}/{name}_plutus_instance.json"), &inst_out)
        .expect("failed to write plutus_instance.json");

    println!("{name}: ok");
}
