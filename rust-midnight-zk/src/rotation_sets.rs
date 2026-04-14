//! Shared utility for computing rotation-set bytes for all midnight-zk circuit binaries.
//!
//! ## Slot binary format (new, with per-rotation eval indices)
//!
//! ```text
//! num_sets (u32 LE)
//! for each rotation set (in sorted GWC order):
//!   num_rotations (u32 LE)
//!   rotation_offsets[num_rotations] (i32 LE each)
//!   num_slots (u32 LE)
//!   for each slot:
//!     poly_kind (u8)
//!     index     (u32 LE)
//!     eval_idxs[num_rotations] (u32 LE each)
//! ```
//!
//! ## Poly kind enum
//!
//! | kind | name        | index           | eval_idxs[rotPos]                        |
//! |------|-------------|-----------------|------------------------------------------|
//! | 0    | Advice      | col index       | index into prfAdviceEvals                |
//! | 1    | Instance    | —               | (ignored)                                |
//! | 2    | LookupTable | k               | (ignored; always field 4 in prfLkEvals)  |
//! | 3    | Trash       | k               | (ignored)                                |
//! | 4    | Fixed       | col index       | index into prfFixedEvals                 |
//! | 5    | PermSigma   | k               | (ignored)                                |
//! | 6    | H           | —               | (ignored)                                |
//! | 7    | Random      | —               | (ignored)                                |
//! | 8    | PermProd    | chunk index     | (ignored; dispatched by rotation offset) |
//! | 9    | LookupProd  | k               | (ignored; dispatched by rotation offset) |
//! | 10   | LookupInput | k               | (ignored; dispatched by rotation offset) |
//!
//! ## Ordering invariant
//!
//! Sets are sorted by `(cardinality, original_first_encounter_idx)`, matching the
//! `sort_by_key(|&i| (point_sets[i].len(), i))` step in both `multi_open` (prover)
//! and `multi_prepare` (verifier) in `midnight-proofs/src/poly/kzg/mod.rs`.

/// Slot: (poly_kind, index, eval_idxs_per_rotation)
type Slot = (u8, u32, Vec<u32>);

/// Indexed rotation set: (original_first_encounter_idx, rotation_offsets, slots)
type IndexedSet = (usize, Vec<i32>, Vec<Slot>);

/// Build and serialize rotation-set bytes for a midnight-zk circuit.
///
/// # Arguments
/// * `advice_queries` – `(col_index, rotation_offset)` pairs in the order returned by
///   `cs.advice_queries()`. This order determines the x₁-power assignment within sets.
/// * `fixed_queries`  – same for `cs.fixed_queries()`.
/// * `na`             – `cs.num_advice_columns()`
/// * `nl`             – `cs.lookups().len()`
/// * `npc`            – `vk.permutation().commitments().len()`
/// * `degree`         – `cs.degree()`
/// * `num_trash`      – number of extra blinding commitments (derived from proof size)
pub fn rotation_sets_bytes(
    advice_queries: &[(usize, i32)],
    fixed_queries: &[(usize, i32)],
    na: usize,
    nl: usize,
    npc: usize,
    degree: usize,
    num_trash: usize,
    // When true, ALL perm grand-product chunks open at {x, x·ω, x·ω^last}
    // (i.e. nppe = np×3). When false, only non-last chunks do (nppe = (np−1)×3+2).
    perm_all_3evals: bool,
) -> Vec<u8> {
    let chunk_size = degree - 2;
    let np = (npc + chunk_size - 1) / chunk_size; // numPermProds
    let last_chunk = np.saturating_sub(1);
    let num_non_last = np.saturating_sub(1);

    // Mirror midnight-proofs' ConstraintSystem::blinding_factors():
    //   blinding_factors = max(3, max_distinct_rotations_per_advice_col) + num_trash + 2
    // The "+2" accounts for one multiopen evaluation and one extra safety factor.
    // For circuits where every advice column has ≤3 query rotations, this reduces to
    // the familiar 5 + num_trash (= 3 + num_trash + 2).
    let max_queries_per_col = {
        let mut per_col: std::collections::HashMap<usize, std::collections::HashSet<i32>> =
            Default::default();
        for &(c, rot) in advice_queries {
            per_col.entry(c).or_default().insert(rot);
        }
        per_col.values().map(|s| s.len()).max().unwrap_or(3)
    };
    let blinding = (std::cmp::max(3, max_queries_per_col) + num_trash + 2) as i32;
    let last_rot = -(blinding + 1);

    // ── Compute exact rotation set per advice column ──────────────────────────
    //
    // Two advice columns belong to the same rotation set iff they are queried at
    // exactly the same set of rotation offsets.  We track:
    //   adv_col_rot_set[c]    – sorted, deduped rotation set for column c
    //   adv_rs_encounter      – unique rotation sets in first-encounter order
    //                           (order the first column of each set appears in advice_queries)
    //   adv_rs_cols[rs]       – columns in each rotation set, in encounter order
    //   adv_rs_rot_order[rs]  – rotation offsets for the set, in the order they were
    //                           first seen in advice_queries (determines rotPos)

    let adv_col_rot_set: Vec<Vec<i32>> = (0..na)
        .map(|c| {
            let mut rots: Vec<i32> = advice_queries
                .iter()
                .filter(|&&(col, _)| col == c)
                .map(|&(_, r)| r)
                .collect();
            rots.sort();
            rots.dedup();
            rots
        })
        .collect();

    let mut adv_rs_encounter: Vec<Vec<i32>> = vec![];
    let mut adv_rs_cols: std::collections::HashMap<Vec<i32>, Vec<usize>> = Default::default();
    let mut adv_rs_rot_order: std::collections::HashMap<Vec<i32>, Vec<i32>> = Default::default();
    for &(c, rot) in advice_queries {
        let rs = adv_col_rot_set[c].clone();
        if !adv_rs_cols.contains_key(&rs) {
            adv_rs_encounter.push(rs.clone());
        }
        let cols = adv_rs_cols.entry(rs.clone()).or_default();
        if !cols.contains(&c) {
            cols.push(c);
        }
        let rot_order = adv_rs_rot_order.entry(rs).or_default();
        if !rot_order.contains(&rot) {
            rot_order.push(rot);
        }
    }

    // ── Group fixed queries by column for rotation-aware set placement ───────
    //
    // A fixed column queried only at rot=0        → Set {0}.
    // A fixed column queried only at rot=1        → singleton {1} set.
    // A fixed column queried at rot=0 AND rot=1   → Set {0,1}.
    // (Other combinations are not used by current circuits and will panic.)
    let mut fq_col_order: Vec<usize> = vec![];
    let mut fq_col_rots: std::collections::HashMap<usize, Vec<(i32, u32)>> = Default::default();
    for (q, &(col, rot)) in fixed_queries.iter().enumerate() {
        if !fq_col_rots.contains_key(&col) {
            fq_col_order.push(col);
        }
        fq_col_rots.entry(col).or_default().push((rot, q as u32));
    }
    let fix_rot_eval_idx = |col: usize, rot: i32| -> u32 {
        fq_col_rots[&col]
            .iter()
            .find(|&&(r, _)| r == rot)
            .unwrap_or_else(|| panic!("fixed query (col={col}, rot={rot}) not found in col map"))
            .1
    };
    let fixed_col_rot_set = |col: usize| -> Vec<i32> {
        let mut r: Vec<i32> = fq_col_rots[&col].iter().map(|&(r, _)| r).collect();
        r.sort();
        r.dedup();
        r
    };

    // Validate that every fixed column uses a supported rotation pattern.
    // Unsupported patterns would be silently omitted from all rotation sets, producing
    // incorrect output.  Add explicit handling before removing this assertion.
    for &col in &fq_col_order {
        let rs = fixed_col_rot_set(col);
        assert!(
            rs == [0i32] || rs == [0i32, 1] || rs == [1i32],
            "fixed column {col} has unsupported rotation set {rs:?}; \
             add handling for this pattern in rotation_sets_bytes"
        );
    }

    // Fixed columns queried ONLY at rot=1 (no rot=0) form their own singleton {1} set.
    let fix_only_rot1: Vec<usize> = fq_col_order
        .iter()
        .copied()
        .filter(|&col| fixed_col_rot_set(col) == [1i32])
        .collect();
    let set_fix1: Option<(Vec<i32>, Vec<Slot>)> = if fix_only_rot1.is_empty() {
        None
    } else {
        let s: Vec<Slot> = fix_only_rot1
            .iter()
            .map(|&col| (4u8, col as u32, vec![fix_rot_eval_idx(col, 1)]))
            .collect();
        Some((vec![1i32], s))
    };

    // Zeros placeholder for slots whose eval_idxs are ignored by the verifier
    let zeros = |n: usize| vec![0u32; n];

    let adv_eval_idx = |c: usize, rot: i32| -> u32 {
        advice_queries
            .iter()
            .position(|&(col, r)| col == c && r == rot)
            .unwrap_or_else(|| panic!("advice query ({c}, {rot}) not found")) as u32
    };

    // Sorted forms — used for rotation-set identity comparisons.
    let rs0_sorted: Vec<i32> = vec![0];
    let rs01_sorted: Vec<i32> = vec![0, 1];
    let rs0m1_sorted: Vec<i32> = vec![-1, 0]; // sorted: -1 < 0
    // Encounter-order forms — used for actual storage in rotation sets bytes.
    let rs0: Vec<i32> = vec![0];
    let rs01: Vec<i32> = vec![0, 1];
    let rs0m1_enc: Vec<i32> = vec![0, -1]; // rot=0 encountered before rot=-1
    let rs01last_enc: Vec<i32> = vec![0, 1, last_rot];

    // ── Build indexed_sets ────────────────────────────────────────────────────
    //
    // construct_intermediate_sets processes queries in order:
    //   advice → instance → perm prods → lookups → trash → fixed → sigma → H → random
    //
    // For each unique advice rotation set (in encounter order), we:
    //   1. Add the advice column slots.
    //   2. If the rotation set matches a "known" set (one that also contains
    //      non-advice polynomials), add those extra slots too.
    //
    // Non-advice-only sets ({0,1}, {0,-1}, {0,1,last_rot}) are added after advice
    // if they were not already introduced by an advice column.

    let mut indexed_sets: Vec<IndexedSet> = vec![];
    let mut next_idx: usize = 0;

    // Which "known" sets have been introduced already (from advice)?
    let mut seen_rs0 = false;
    let mut seen_rs01 = false;
    let mut seen_rs0m1 = false;

    // Step 1: advice columns, in encounter order
    for rs in &adv_rs_encounter {
        let cols = &adv_rs_cols[rs];
        let rot_order = &adv_rs_rot_order[rs];
        let num_rots = rot_order.len();

        let mut slots: Vec<Slot> = vec![];

        // Advice slots for this rotation set.
        for &c in cols {
            let eval_idxs: Vec<u32> = rot_order.iter().map(|&rot| adv_eval_idx(c, rot)).collect();
            slots.push((0, c as u32, eval_idxs));
        }

        // Non-advice slots for "known" rotation sets.
        // (These are added in the same relative order the prover uses.)
        let rs_sorted = {
            let mut s = rs.clone();
            s.sort();
            s
        };

        if rs_sorted == rs0_sorted {
            seen_rs0 = true;
            // Instance, LkTable, Trash, Fixed(rot=0), PermSigma, H, Random
            slots.push((1, 0, zeros(num_rots)));
            for k in 0..nl {
                slots.push((2, k as u32, zeros(num_rots)));
            }
            for k in 0..num_trash {
                slots.push((3, k as u32, zeros(num_rots)));
            }
            for &col in &fq_col_order {
                if fixed_col_rot_set(col) == [0] {
                    slots.push((4, col as u32, vec![fix_rot_eval_idx(col, 0)]));
                }
            }
            for k in 0..npc {
                slots.push((5, k as u32, zeros(num_rots)));
            }
            slots.push((6, 0, zeros(num_rots)));
            slots.push((7, 0, zeros(num_rots)));
        } else if rs_sorted == rs01_sorted {
            seen_rs01 = true;
            // PermProd last chunk (standard), LkProd, Fixed(rot=0,1)
            if np > 0 && !perm_all_3evals {
                slots.push((8, last_chunk as u32, zeros(num_rots)));
            }
            for k in 0..nl {
                slots.push((9, k as u32, zeros(num_rots)));
            }
            for &col in &fq_col_order {
                if fixed_col_rot_set(col) == [0, 1] {
                    slots.push((4, col as u32, vec![fix_rot_eval_idx(col, 0), fix_rot_eval_idx(col, 1)]));
                }
            }
        } else if rs_sorted == rs0m1_sorted {
            seen_rs0m1 = true;
            // LkInput
            for k in 0..nl {
                slots.push((10, k as u32, zeros(num_rots)));
            }
        }
        // For any other rotation set: only advice slots (no extra non-advice polys).

        indexed_sets.push((next_idx, rot_order.clone(), slots));
        next_idx += 1;
    }

    // Step 2: instance introduces {0} if not already from advice.
    if !seen_rs0 {
        let mut s0: Vec<Slot> = vec![];
        s0.push((1, 0, zeros(1)));
        for k in 0..nl {
            s0.push((2, k as u32, zeros(1)));
        }
        for k in 0..num_trash {
            s0.push((3, k as u32, zeros(1)));
        }
        for &col in &fq_col_order {
            if fixed_col_rot_set(col) == [0] {
                s0.push((4, col as u32, vec![fix_rot_eval_idx(col, 0)]));
            }
        }
        for k in 0..npc {
            s0.push((5, k as u32, zeros(1)));
        }
        s0.push((6, 0, zeros(1)));
        s0.push((7, 0, zeros(1)));
        indexed_sets.push((next_idx, rs0.clone(), s0));
        next_idx += 1;
    }

    // Step 3: perm grand products.
    // perm_prod[0]@x_next → first encounter of {0,1} if not from advice.
    // perm non-last@x_last → always a new set (no advice cols use last_rot).
    if !seen_rs01 {
        let mut s01: Vec<Slot> = vec![];
        if np > 0 && !perm_all_3evals {
            s01.push((8, last_chunk as u32, zeros(2)));
        }
        for k in 0..nl {
            s01.push((9, k as u32, zeros(2)));
        }
        for &col in &fq_col_order {
            if fixed_col_rot_set(col) == [0, 1] {
                s01.push((4, col as u32, vec![fix_rot_eval_idx(col, 0), fix_rot_eval_idx(col, 1)]));
            }
        }
        if !s01.is_empty() {
            indexed_sets.push((next_idx, rs01.clone(), s01));
            next_idx += 1;
        }
    }

    // Perm non-last chunks → {0,1,last_rot} set.
    // Rotation order: [0, 1, last_rot] (encounter order: x first, x·ω second, x·ω^last third).
    {
        let n4 = if perm_all_3evals { np } else { num_non_last };
        if n4 > 0 {
            let s4: Vec<Slot> = (0..n4).map(|j| (8u8, j as u32, zeros(3))).collect();
            indexed_sets.push((next_idx, rs01last_enc.clone(), s4));
            next_idx += 1;
        }
    }

    // Step 4: lookup inputs → {0,-1} if not from advice.
    // Rotation order: [0, -1] (x first, x·ω⁻¹ second — encounter order).
    if !seen_rs0m1 {
        if nl > 0 {
            let s0m1: Vec<Slot> = (0..nl).map(|k| (10u8, k as u32, zeros(2))).collect();
            indexed_sets.push((next_idx, rs0m1_enc.clone(), s0m1));
            next_idx += 1;
        }
    }

    // Step 5: fixed columns queried ONLY at rot=1 → singleton {1} set.
    if let Some((rots, slots)) = set_fix1 {
        indexed_sets.push((next_idx, rots, slots));
    }

    // ── Sort by (cardinality, original_idx) — matches prover/verifier ────────
    indexed_sets.sort_by_key(|&(idx, ref rots, _)| (rots.len(), idx));

    // ── Serialize ─────────────────────────────────────────────────────────────
    let mut buf: Vec<u8> = vec![];
    let num_sets = indexed_sets.len() as u32;
    buf.extend_from_slice(&num_sets.to_le_bytes());
    for (_, rots, slots) in &indexed_sets {
        let num_rots = rots.len() as u32;
        buf.extend_from_slice(&num_rots.to_le_bytes());
        for &r in rots {
            buf.extend_from_slice(&r.to_le_bytes());
        }
        buf.extend_from_slice(&(slots.len() as u32).to_le_bytes());
        for (kind, index, eval_idxs) in slots {
            buf.push(*kind);
            buf.extend_from_slice(&index.to_le_bytes());
            for &e in eval_idxs {
                buf.extend_from_slice(&e.to_le_bytes());
            }
        }
    }

    buf
}
