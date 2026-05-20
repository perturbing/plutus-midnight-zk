//! Shared helpers for computing GWC circuit parameters and serialising Plutus outputs.

use ff::{Field, PrimeField};
use group::GroupEncoding;
use std::fs;
use midnight_curves::{Bls12, Fq};
use midnight_proofs::{
    plonk::{Any, ConstraintSystem, Expression, VerifyingKey},
    poly::kzg::KZGCommitmentScheme,
};
use crate::rotation_sets::rotation_sets_bytes;

// ── Gate-expression serialisation ─────────────────────────────────────────────

/// Emit an `Expression<Fq>` as a flat RPN sequence of human-readable instruction
/// objects into `out`.
fn emit_json_instrs(expr: &Expression<Fq>, out: &mut Vec<serde_json::Value>) {
    match expr {
        Expression::Constant(f) => {
            out.push(serde_json::json!({
                "op": "Constant",
                "value": to_hex(f.to_repr().as_ref()),
            }));
        }
        Expression::Selector(_) => {
            unreachable!("Selector in finalized VK gate poly — should have been compiled away");
        }
        Expression::Fixed(q) => {
            out.push(serde_json::json!({
                "op": "Fixed",
                "query_index": q.index().expect("unresolved Fixed query index in VK"),
            }));
        }
        Expression::Advice(q) => {
            out.push(serde_json::json!({
                "op": "Advice",
                "query_index": q.index.expect("unresolved Advice query index in VK"),
            }));
        }
        Expression::Instance(q) => {
            out.push(serde_json::json!({
                "op": "Instance",
                "query_index": q.index.expect("unresolved Instance query index in VK"),
            }));
        }
        Expression::Negated(a) => {
            emit_json_instrs(a, out);
            out.push(serde_json::json!({"op": "Negated"}));
        }
        Expression::Sum(a, b) => {
            emit_json_instrs(a, out);
            emit_json_instrs(b, out);
            out.push(serde_json::json!({"op": "Sum"}));
        }
        Expression::Product(a, b) => {
            emit_json_instrs(a, out);
            emit_json_instrs(b, out);
            out.push(serde_json::json!({"op": "Product"}));
        }
        Expression::Scaled(a, f) => {
            emit_json_instrs(a, out);
            out.push(serde_json::json!({
                "op": "Scaled",
                "factor": to_hex(f.to_repr().as_ref()),
            }));
        }
    }
}

fn expr_to_json_instrs(expr: &Expression<Fq>) -> serde_json::Value {
    let mut instructions = Vec::new();
    emit_json_instrs(expr, &mut instructions);
    serde_json::Value::Array(instructions)
}

/// Compute the `(col_type, eval_idx)` for one permutation column.
fn perm_col_entry(col: midnight_proofs::plonk::Column<Any>, cs: &ConstraintSystem<Fq>) -> (u8, u32) {
    let col_idx = col.index();
    match col.column_type() {
        Any::Advice => {
            let ei = cs.advice_queries()
                .iter()
                .position(|(c, r)| c.index() == col_idx && r.0 == 0)
                .unwrap_or_else(|| panic!("advice perm col {col_idx} not queried at rot 0"))
                as u32;
            (0, ei)
        }
        Any::Fixed => {
            let ei = cs.fixed_queries()
                .iter()
                .position(|(c, r)| c.index() == col_idx && r.0 == 0)
                .unwrap_or_else(|| panic!("fixed perm col {col_idx} not queried at rot 0"))
                as u32;
            (1, ei)
        }
        Any::Instance => {
            let ei = cs.instance_queries()
                .iter()
                .position(|(c, r)| c.index() == col_idx && r.0 == 0)
                .unwrap_or_else(|| panic!("instance perm col {col_idx} not queried at rot 0"))
                as u32;
            (2, ei)
        }
    }
}

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

/// 32-byte LE hex for the field element 1.
const ONE_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000";

/// Parse a GWC proof (v7 LogUp format) into its constituent parts as a structured JSON object.
///
/// Commitment layout (48 bytes each):
///   advice[na] | mult[nl] | perm_z[np] | per_lookup(helpers[nc_k] + accum) | trash[num_trash] | h[nh]
///
/// Evaluation layout (32 bytes each):
///   advice[naq] | fixed[nfq] | sigma[npc] | perm_z_evals[num_ppe] |
///   per_lookup(mult_eval + helpers[nc_k] + accum_eval + accum_next_eval) | trash[num_trash]
///
/// GWC (trailing):
///   f_commit[48] | q_evals[num_q × 32] | w_commit[48]
pub fn proof_to_json(proof: &[u8], p: &CircuitParams) -> serde_json::Value {
    let mut r = ProofReader::new(proof);
    let np = (p.npc + p.chunk_size - 1) / p.chunk_size;
    let perm_all_3evals = p.num_ppe == np * 3;

    // ── Commitments ───────────────────────────────────────────────────────
    let advice_commitments: Vec<_> = (0..p.na).map(|_| r.g1()).collect();

    // LogUp: multiplicities (one per lookup, written before perm z)
    let lookup_multiplicity_commitments: Vec<_> = (0..p.nl).map(|_| r.g1()).collect();

    // Permutation z-poly commitments
    let permutation_product_commitments: Vec<_> = (0..np).map(|_| r.g1()).collect();

    // LogUp: per lookup — helpers + accumulator (written after perm z)
    let lookup_logup_commitments: Vec<_> = p.lookup_num_chunks.iter()
        .map(|&nc| {
            let helpers: Vec<String> = (0..nc).map(|_| r.g1()).collect();
            let accumulator = r.g1();
            serde_json::json!({ "helpers": helpers, "accumulator": accumulator })
        })
        .collect();

    let trash_commitments: Vec<_> = (0..p.num_trash).map(|_| r.g1()).collect();
    let h_commitments: Vec<_> = (0..p.nh).map(|_| r.g1()).collect();

    // ── Evaluations ───────────────────────────────────────────────────────
    // Committed instance eval (always 0: committed_pi = G1Affine::identity()).
    // midnight-proofs writes this before advice evals; we skip it here since
    // the Haskell verifier hard-codes 0 at this transcript position.
    let _ = r.scalar();

    // Advice evals
    let advice_evals: Vec<_> = (0..p.naq).map(|_| r.scalar()).collect();

    // Fixed evals: read nfq (actual in proof), reconstruct full array with 1s at simple-selector positions.
    let proof_fixed: Vec<String> = (0..p.nfq).map(|_| r.scalar()).collect();
    let fixed_evals = reconstruct_fixed_evals(&proof_fixed, &p.simple_sel_mask);

    // Permutation sigma evals (common)
    let sigma_evals: Vec<_> = (0..p.npc).map(|_| r.scalar()).collect();

    // Permutation z-poly evals
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

    // LogUp evals: per lookup — mult_eval, helper_evals[nc], accum_eval, accum_next_eval
    let lookup_evals: Vec<_> = p.lookup_num_chunks.iter()
        .map(|&nc| {
            let mult_eval = r.scalar();
            let helper_evals: Vec<String> = (0..nc).map(|_| r.scalar()).collect();
            let accum_eval = r.scalar();
            let accum_next_eval = r.scalar();
            serde_json::json!({
                "mult_eval":       mult_eval,
                "helper_evals":    helper_evals,
                "accum_eval":      accum_eval,
                "accum_next_eval": accum_next_eval,
            })
        })
        .collect();

    let trash_evals: Vec<_> = (0..p.num_trash).map(|_| r.scalar()).collect();

    // fewer-point-sets: dummy evals (absorbed into transcript between regular evals and GWC)
    let dummy_evals: Vec<_> = (0..p.num_dummy).map(|_| r.scalar()).collect();

    // ── GWC multiopen proof ───────────────────────────────────────────────
    let f_commitment = r.g1();
    let q_evals: Vec<_> = (0..p.num_q).map(|_| r.scalar()).collect();
    let w_commitment = r.g1();

    assert_eq!(
        r.remaining(), 0,
        "proof_to_json: {} bytes unconsumed", r.remaining()
    );

    serde_json::json!({
        "advice_commitments":              advice_commitments,
        "lookup_multiplicity_commitments": lookup_multiplicity_commitments,
        "permutation_product_commitments": permutation_product_commitments,
        "lookup_logup_commitments":        lookup_logup_commitments,
        "trash_commitments":               trash_commitments,
        "h_commitments":                   h_commitments,
        "advice_evals":                    advice_evals,
        "fixed_evals":                     fixed_evals,
        "sigma_evals":                     sigma_evals,
        "permutation_product_evals":       permutation_product_evals,
        "lookup_evals":                    lookup_evals,
        "trash_evals":                     trash_evals,
        "dummy_evals":                     dummy_evals,
        "gwc": {
            "f_commitment": f_commitment,
            "q_evals":      q_evals,
            "w_commitment": w_commitment,
        },
    })
}

/// Reconstruct the full fixed-evals vector (length = mask.len()) by inserting
/// the string `ONE_HEX` at positions where the mask is `true` (simple selector).
fn reconstruct_fixed_evals(proof_evals: &[String], mask: &[bool]) -> Vec<serde_json::Value> {
    let mut result = Vec::with_capacity(mask.len());
    let mut it = proof_evals.iter();
    for &is_simple in mask {
        if is_simple {
            result.push(serde_json::Value::String(ONE_HEX.to_string()));
        } else {
            result.push(serde_json::Value::String(it.next().expect("fixed eval missing").clone()));
        }
    }
    result
}

// ── Rotation-set parser ───────────────────────────────────────────────────────

fn poly_kind_name(k: u8) -> &'static str {
    match k {
        0  => "Advice",
        1  => "Instance",
        2  => "LogupMult",
        3  => "Trash",
        4  => "Fixed",
        5  => "PermSigma",
        6  => "H",
        8  => "PermProd",
        9  => "LogupAccum",
        10 => "LogupHelper",
        _  => "Unknown",
    }
}

/// Parse a rotation-sets binary buffer into a structured JSON object.
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
#[derive(Debug, Clone)]
pub struct CircuitParams {
    pub na: u32,                      // number of advice columns
    pub nl: u32,                      // number of lookups (BatchedArguments)
    pub npc: u32,                     // number of permutation columns
    pub chunk_size: u32,              // degree − 2
    pub nh: u32,                      // degree − 1 (quotient limbs)
    pub naq: u32,                     // number of advice queries
    pub nfq: u32,                     // fixed evals IN PROOF (= total − simple_selectors)
    pub num_trash: u32,               // extra blinding commitments
    pub num_ppe: u32,                 // perm product eval count
    pub num_q: u32,                   // rotation-set (Q) count
    pub lookup_num_chunks: Vec<u32>,  // per-lookup helper poly count
    // Not serialised in params_to_bytes but used by proof_to_json:
    pub nfq_total: u32,               // total fixed_queries (for index mapping)
    pub simple_sel_mask: Vec<bool>,   // per fixed_query: is it a simple selector?
    pub num_dummy: u32,               // fewer-point-sets dummy evals (between regular evals and GWC)
}

/// Serialize `params` as 11 × u32 LE (44 bytes).
///
/// Fields: na, nl, npc, chunk_size, nh, naq, nfq, num_trash, num_ppe, num_q,
///         total_lookup_helpers (= sum of lookup_num_chunks).
pub fn params_to_bytes(p: &CircuitParams) -> [u8; 44] {
    let total_lh: u32 = p.lookup_num_chunks.iter().sum();
    let words = [
        p.na, p.nl, p.npc, p.chunk_size, p.nh,
        p.naq, p.nfq, p.num_trash, p.num_ppe, p.num_q,
        total_lh,
    ];
    let mut out = [0u8; 44];
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
    nfq_total: u32,
    nfq_actual: u32,
    num_trash: u32,
    proof: &[u8],
    num_q: u32,
    lookup_num_chunks: &[u32],
    simple_sel_mask: Vec<bool>,
) -> CircuitParams {
    let chunk_size = (degree - 2) as u32;
    let np = (npc + chunk_size - 1) / chunk_size;
    let nh = (degree - 1) as u32;
    let total_lh: u32 = lookup_num_chunks.iter().sum();

    // G1 count (including GWC F and W):
    //   advice + mult + perm_z + helpers + accum + trash + h + F + W
    //   = na + nl + np + total_lh + nl + num_trash + nh + 2
    //   = na + 2*nl + np + total_lh + num_trash + nh + 2
    let g1_count = na + 2 * nl + np + total_lh + num_trash + nh + 2;

    // num_ppe: 2 evals for the last perm chunk, 3 for every other (eval + next_eval + last_eval).
    // The `fewer-point-sets` feature inserts num_dummy extra scalars AFTER the regular evals and
    // BEFORE the GWC F commitment; compute num_dummy as the leftover after accounting for
    // everything else.
    let num_ppe = if np > 0 { 3 * np - 1 } else { 0 };
    let total_sc = (proof.len() as u32 - g1_count * 48) / 32;
    // base_sc: committed-instance eval (1) + advice + fixed + sigma + logup + trash
    // (everything except perm_z evals, dummy, Q)
    let base_sc = 1 + naq + nfq_actual + npc + total_lh + 3 * nl + num_trash;
    let num_dummy = total_sc - base_sc - num_ppe - num_q;

    CircuitParams {
        na,
        nl,
        npc,
        chunk_size,
        nh,
        naq,
        nfq: nfq_actual,
        num_trash,
        num_ppe,
        num_q,
        lookup_num_chunks: lookup_num_chunks.to_vec(),
        nfq_total,
        simple_sel_mask,
        num_dummy,
    }
}

/// Encode a slice of field elements as concatenated 32-byte LE representations.
pub fn instance_field_bytes<F: PrimeField>(pi: &[F]) -> Vec<u8> {
    pi.iter().flat_map(|f| f.to_repr().as_ref().to_vec()).collect()
}

/// Write `{name}_circuit_params.json` and `{name}_rotation_sets.json` into `dir`.
///
/// Returns the computed `CircuitParams` for reuse in proof parsing.
pub fn write_json_circuit_artifacts(
    dir: &str,
    name: &str,
    na: u32,
    nl: u32,
    npc: u32,
    degree: usize,
    naq: u32,
    nfq_total: u32,
    nfq_actual: u32,
    num_trash: u32,
    proof: &[u8],
    aq: &[(usize, i32)],
    fq: &[(usize, i32)],
    lookup_num_chunks: &[u32],
    simple_sel_mask: Vec<bool>,
) -> CircuitParams {
    let lnc_usize: Vec<usize> = lookup_num_chunks.iter().map(|&c| c as usize).collect();

    let buf0 = rotation_sets_bytes(
        aq, fq, &simple_sel_mask,
        na as usize, nl as usize, npc as usize,
        degree, 0, false,
        &lnc_usize,
    );
    let num_q = u32::from_le_bytes(buf0[0..4].try_into().unwrap());

    let p = compute_circuit_params(
        na, nl, npc, degree, naq, nfq_total, nfq_actual, num_trash, proof, num_q,
        lookup_num_chunks, simple_sel_mask.clone(),
    );

    let chunk_size = (degree - 2) as u32;
    let np = (npc + chunk_size - 1) / chunk_size;
    let perm_all_3evals = p.num_ppe == np * 3;

    let rot_buf = rotation_sets_bytes(
        aq, fq, &simple_sel_mask,
        na as usize, nl as usize, npc as usize,
        degree,
        p.num_trash as usize,
        perm_all_3evals,
        &lnc_usize,
    );

    let total_lh: u32 = lookup_num_chunks.iter().sum();
    let params_json = serde_json::json!({
        "num_advice_columns":              p.na,
        "num_lookups":                     p.nl,
        "num_permutation_commitments":     p.npc,
        "permutation_chunk_size":          p.chunk_size,
        "num_quotient_commitments":        p.nh,
        "num_advice_queries":              p.naq,
        "num_fixed_queries":               p.nfq,
        "num_blinding_commitments":        p.num_trash,
        "num_permutation_product_evals":   p.num_ppe,
        "num_rotation_sets":               p.num_q,
        "total_lookup_helpers":            total_lh,
        "lookup_num_chunks_per_lookup":    p.lookup_num_chunks,
    });
    let params_out = serde_json::to_string_pretty(&params_json).unwrap();
    fs::write(format!("{dir}/{name}_circuit_params.json"), &params_out)
        .expect("failed to write circuit_params.json");

    let rot_out = serde_json::to_string_pretty(&rotation_sets_to_json(&rot_buf)).unwrap();
    fs::write(format!("{dir}/{name}_rotation_sets.json"), &rot_out)
        .expect("failed to write rotation_sets.json");

    p
}

/// Write all six Plutus artifact files for a circuit into `dir` as JSON.
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

        let simple_sel_mask_json: Vec<bool> = vk.cs().fixed_queries().iter()
            .map(|(col, _)| vk.cs().has_simple_selector_col(col.index()))
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
            "s_g2":                 to_hex(s_g2_bytes),
            "omega":                to_hex(omega.to_repr().as_ref()),
            "simple_selector_mask": simple_sel_mask_json,
        });
        let vk_out = serde_json::to_string_pretty(&vk_json).unwrap();
        fs::write(format!("{dir}/{name}_plutus_vk.json"), &vk_out)
            .expect("failed to write plutus_vk.json");

        // Circuit-structure-dependent fields
        let gate_polys: Vec<serde_json::Value> = vk.cs().gates()
            .iter()
            .flat_map(|g| g.polynomials().iter().map(expr_to_json_instrs))
            .collect();

        // For each gate polynomial: the fixed column index of the first simple selector
        // used by that gate, or null if the gate uses no simple selector.
        // Used by the Haskell verifier to compute the linearization commitment correctly.
        let gate_sel_cols: Vec<serde_json::Value> = vk.cs().gates()
            .iter()
            .flat_map(|g| {
                let maybe_sel: Option<serde_json::Value> = g.queried_selectors()
                    .iter()
                    .find(|s| s.is_simple())
                    .map(|s| serde_json::Value::Number(serde_json::Number::from(s.index() as u64)));
                let val = maybe_sel.unwrap_or(serde_json::Value::Null);
                g.polynomials().iter().map(move |_| val.clone()).collect::<Vec<_>>()
            })
            .collect();

        let perm_col_types: Vec<serde_json::Value> = vk.cs().permutation()
            .get_columns()
            .iter()
            .map(|col| {
                let (ct, ei) = perm_col_entry(*col, vk.cs());
                serde_json::json!({ "col_type": ct, "eval_idx": ei })
            })
            .collect();

        // LogUp lookup input exprs: [lookup][chunk][parallel_input][width_exprs]
        // This is the 4-level nested structure needed for LogUp constraint evaluation.
        let lookup_input_exprs: Vec<serde_json::Value> = vk.cs().lookups()
            .iter()
            .map(|lk| {
                let cs_degree = vk.cs().degree();
                let chunked = lk.chunk_by_degree(cs_degree);
                // input_expression_chunks: [chunk][parallel_input][width]
                let chunks: Vec<serde_json::Value> = chunked.input_expression_chunks()
                    .iter()
                    .map(|chunk| {
                        let parallel: Vec<serde_json::Value> = chunk.iter()
                            .map(|width_exprs| {
                                let exprs: Vec<serde_json::Value> = width_exprs.iter()
                                    .map(expr_to_json_instrs)
                                    .collect();
                                serde_json::Value::Array(exprs)
                            })
                            .collect();
                        serde_json::Value::Array(parallel)
                    })
                    .collect();
                serde_json::Value::Array(chunks)
            })
            .collect();

        // LogUp table exprs: [lookup][width_exprs] (for θ-compression)
        let lookup_table_exprs: Vec<Vec<serde_json::Value>> = vk.cs().lookups()
            .iter()
            .map(|lk| lk.table_expressions().iter().map(expr_to_json_instrs).collect())
            .collect();

        // LogUp selector exprs: [lookup] — single expression per lookup
        let lookup_selector_exprs: Vec<serde_json::Value> = vk.cs().lookups()
            .iter()
            .map(|lk| expr_to_json_instrs(lk.selector_expression()))
            .collect();

        let trash_selectors: Vec<serde_json::Value> = vk.cs().trashcans()
            .iter()
            .map(|t| expr_to_json_instrs(t.selector()))
            .collect();
        let trash_constraint_exprs: Vec<Vec<serde_json::Value>> = vk.cs().trashcans()
            .iter()
            .map(|t| t.constraint_expressions().iter().map(expr_to_json_instrs).collect())
            .collect();

        let cc_json = serde_json::json!({
            "gate_polys":              gate_polys,
            "gate_sel_cols":           gate_sel_cols,
            "perm_col_types":          perm_col_types,
            "lookup_input_exprs":      lookup_input_exprs,
            "lookup_table_exprs":      lookup_table_exprs,
            "lookup_selector_exprs":   lookup_selector_exprs,
            "trash_selectors":         trash_selectors,
            "trash_constraint_exprs":  trash_constraint_exprs,
        });
        let cc_out = serde_json::to_string_pretty(&cc_json).unwrap();
        fs::write(format!("{dir}/{name}_circuit_constraint.json"), &cc_out)
            .expect("failed to write circuit_constraint.json");
    }

    // circuit_params.json + rotation_sets.json + proof.json
    {
        let cs = vk.cs();
        let na  = cs.num_advice_columns() as u32;
        let nl  = cs.lookups().len() as u32;
        let npc = vk.permutation().commitments().len() as u32;
        let naq = cs.advice_queries().len() as u32;
        let nfq_total = cs.fixed_queries().len() as u32;
        let num_simple = cs.num_simple_selectors() as u32;
        let nfq_actual = nfq_total - num_simple;
        let num_trash = cs.trashcans().len() as u32;

        let simple_sel_mask: Vec<bool> = cs.fixed_queries().iter()
            .map(|(col, _)| cs.has_simple_selector_col(col.index()))
            .collect();

        let lookup_num_chunks: Vec<u32> = cs.lookups().iter()
            .map(|lk| lk.num_chunks(cs.degree()) as u32)
            .collect();

        let aq: Vec<(usize, i32)> = cs.advice_queries().iter()
            .map(|(col, r)| (col.index(), r.0)).collect();
        let fq_vec: Vec<(usize, i32)> = cs.fixed_queries().iter()
            .map(|(col, r)| (col.index(), r.0)).collect();
        let p = write_json_circuit_artifacts(
            dir, name,
            na, nl, npc, cs.degree(),
            naq, nfq_total, nfq_actual, num_trash,
            proof,
            &aq, &fq_vec,
            &lookup_num_chunks,
            simple_sel_mask,
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
