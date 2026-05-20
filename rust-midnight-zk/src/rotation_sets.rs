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
//! ## Poly kind enum (v7 LogUp format)
//!
//! | kind | name        | index                    | eval_idxs[rotPos]                              |
//! |------|-------------|--------------------------|------------------------------------------------|
//! | 0    | Advice      | col index                | absolute index into unified eval array         |
//! | 1    | Instance    | —                        | (ignored, always returns 0)                    |
//! | 2    | LogupMult   | lookup index k           | absolute index into unified eval array         |
//! | 3    | Trash       | k                        | absolute index into unified eval array         |
//! | 4    | Fixed       | col index                | absolute index into unified eval array         |
//! | 5    | PermSigma   | k                        | absolute index into unified eval array         |
//! | 6    | H           | —                        | rotPos=0 ignored (uses hEval); others: unified |
//! | 8    | PermProd    | chunk index              | absolute index into unified eval array         |
//! | 9    | LogupAccum  | lookup index k           | absolute indices into unified eval array       |
//! | 10   | LogupHelper | flat helper index        | absolute index into unified eval array         |
//!
//! ## Unified eval array layout
//!
//! The unified array (used by the Haskell verifier for all eval_idxs) is:
//!   adviceEvals[naq] | fixedEvals[nfq_total] | sigmaEvals[npc] |
//!   permProdEvals[num_ppe] | logupEvals[logup_total] | trashEvals[num_trash] | dummyEvals[num_dummy]
//!
//! All eval_idxs in this file are absolute offsets into this array.
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

/// Build and serialize rotation-set bytes for a midnight-zk circuit (v7 LogUp format).
///
/// # Arguments
/// * `advice_queries`     – `(col_index, rotation_offset)` pairs in the order returned by
///   `cs.advice_queries()`.
/// * `fixed_queries`      – same for `cs.fixed_queries()` (includes simple-selector columns).
/// * `simple_sel_mask`    – per-query boolean; `true` means the query is for a simple-selector
///   column whose evaluation is omitted from the proof (verifier substitutes 1).  Length must
///   equal `fixed_queries.len()`.
/// * `na`                 – `cs.num_advice_columns()`
/// * `nl`                 – `cs.lookups().len()`
/// * `npc`                – `vk.permutation().commitments().len()`
/// * `degree`             – `cs.degree()`
/// * `num_trash`          – number of extra blinding commitments
/// * `perm_all_3evals`    – when true ALL perm chunks open at {x, x·ω, x·ω^last}
/// * `lookup_num_chunks`  – per-lookup helper poly count (len must equal `nl`)
pub fn rotation_sets_bytes(
    advice_queries: &[(usize, i32)],
    fixed_queries: &[(usize, i32)],
    simple_sel_mask: &[bool],
    na: usize,
    nl: usize,
    npc: usize,
    degree: usize,
    num_trash: usize,
    perm_all_3evals: bool,
    lookup_num_chunks: &[usize],
) -> Vec<u8> {
    assert_eq!(
        simple_sel_mask.len(), fixed_queries.len(),
        "simple_sel_mask length {} != fixed_queries length {}",
        simple_sel_mask.len(), fixed_queries.len(),
    );
    assert_eq!(
        lookup_num_chunks.len(), nl,
        "lookup_num_chunks length {} != nl {}",
        lookup_num_chunks.len(), nl,
    );

    let chunk_size = degree - 2;
    let np = (npc + chunk_size - 1) / chunk_size;
    let last_chunk = np.saturating_sub(1);
    let num_non_last = np.saturating_sub(1);

    // ── Unified eval array offsets ─────────────────────────────────────────────
    let naq = advice_queries.len();
    // The Haskell fixEvalsRS holds ALL fixed_queries entries (real evals plus 1s substituted
    // for simple selectors), so use the full count for offset arithmetic.
    let nfq_total = fixed_queries.len();
    // A fixed column is a simple selector if any of its query entries is marked in the mask.
    // Simple-selector columns are omitted from rotation-set slots (verifier substitutes 1).
    let is_simple_col = |col: usize| -> bool {
        fixed_queries.iter().enumerate().any(|(q, &(c, _))| c == col && simple_sel_mask[q])
    };
    let num_ppe = if np > 0 {
        if perm_all_3evals { 3 * np } else { 3 * np - 1 }
    } else {
        0
    };
    let logup_total: usize = lookup_num_chunks.iter().map(|&nc| nc + 3).sum::<usize>();
    let logup_total = if nl == 0 { 0 } else { logup_total };

    let adv_off: usize = 0;
    let fix_off: usize = adv_off + naq;
    let sigma_off: usize = fix_off + nfq_total;
    let pp_off: usize = sigma_off + npc;
    let logup_off: usize = pp_off + num_ppe;
    let trash_off: usize = logup_off + logup_total;
    let dummy_off: usize = trash_off + num_trash;

    // Mirror midnight-proofs' ConstraintSystem::blinding_factors():
    //   max(3, max_distinct_rotations_per_advice_col) + num_trash + total_nc + 3
    // where total_nc = sum of per-lookup helper poly counts.
    // The +3 accounts for: multi-open commitment, off-by-one defense, linearization margin.
    let max_queries_per_col = {
        let mut per_col: std::collections::HashMap<usize, std::collections::HashSet<i32>> =
            Default::default();
        for &(c, rot) in advice_queries {
            per_col.entry(c).or_default().insert(rot);
        }
        per_col.values().map(|s| s.len()).max().unwrap_or(3)
    };
    let total_nc: usize = lookup_num_chunks.iter().sum();
    let blinding = (std::cmp::max(3, max_queries_per_col) + num_trash + total_nc + 3) as i32;
    let last_rot = -(blinding + 1);

    // ── Compute exact rotation set per advice column ──────────────────────────
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

    // ── Group fixed queries by column ─────────────────────────────────────────
    // fq_col_rots includes ALL fixed queries (for rotation-set validation).
    // fq_col_order lists only non-simple-selector columns in encounter order
    // (only these get rotation-set slots).
    let mut fq_col_order: Vec<usize> = vec![];
    let mut fq_col_rots: std::collections::HashMap<usize, Vec<(i32, u32)>> = Default::default();
    for (q, &(col, rot)) in fixed_queries.iter().enumerate() {
        if !fq_col_rots.contains_key(&col) && !is_simple_col(col) {
            fq_col_order.push(col);
        }
        fq_col_rots.entry(col).or_default().push((rot, q as u32));
    }
    // Returns absolute index into the Haskell unified eval array (fixEvalsRS section).
    // Uses the raw query index because fixEvalsRS contains ALL fixed queries (real + substituted).
    let fix_rot_eval_idx = |col: usize, rot: i32| -> u32 {
        (fix_off as u32)
            + fq_col_rots[&col]
                .iter()
                .find(|&&(r, _)| r == rot)
                .unwrap_or_else(|| panic!("fixed query (col={col}, rot={rot}) not found"))
                .1
    };
    let fixed_col_rot_set = |col: usize| -> Vec<i32> {
        let mut r: Vec<i32> = fq_col_rots[&col].iter().map(|&(r, _)| r).collect();
        r.sort();
        r.dedup();
        r
    };

    for &col in &fq_col_order {
        let rs = fixed_col_rot_set(col);
        assert!(
            rs == [0i32] || rs == [0i32, 1] || rs == [1i32],
            "fixed column {col} has unsupported rotation set {rs:?}"
        );
    }

    // Precompute flat eval offsets for LogUp:
    //   flat_eval_offset(k) = sum_{i<k}(nc_i + 3)
    let logup_flat_eval_offsets: Vec<u32> = {
        let mut offsets = vec![0u32; nl + 1];
        for k in 0..nl {
            offsets[k + 1] = offsets[k] + lookup_num_chunks[k] as u32 + 3;
        }
        offsets
    };
    let logup_flat_helper_offsets: Vec<u32> = {
        let mut offsets = vec![0u32; nl + 1];
        for k in 0..nl {
            offsets[k + 1] = offsets[k] + lookup_num_chunks[k] as u32;
        }
        offsets
    };

    let adv_eval_idx = |c: usize, rot: i32| -> u32 {
        (adv_off as u32)
            + advice_queries
                .iter()
                .position(|&(col, r)| col == c && r == rot)
                .unwrap_or_else(|| panic!("advice query ({c}, {rot}) not found")) as u32
    };

    // ── Per-kind unified eval_idx helpers ──────────────────────────────────────

    // PermProd: flat index into ppEvalsRS for chunk j at rotation fld (0=cur,1=next,2=last).
    // For non-all-3evals: chunk j<np-1 has fld 0..2; chunk np-1 has fld 0..1 only.
    let pp_eval_idx = |j: usize, fld: usize| -> u32 { (pp_off + 3 * j + fld) as u32 };

    // PermSigma: sigma_off + col_index
    let sigma_eval_idx = |k: usize| -> u32 { (sigma_off + k) as u32 };

    // Trash: trash_off + trash_index
    let trash_eval_idx = |k: usize| -> u32 { (trash_off + k) as u32 };

    // LogupMult: logup_off + flat_eval_offset(k) + 0
    let mult_eval_idx = |k: usize| -> u32 { logup_off as u32 + logup_flat_eval_offsets[k] };

    // LogupHelper: logup_off + flat_eval_offset(k) + 1 + j
    let helper_eval_idx = |k: usize, j: u32| -> u32 {
        logup_off as u32 + logup_flat_eval_offsets[k] + 1 + j
    };

    // LogupAccum: logup_off + flat_eval_offset(k) + nc+1 (cur) and +nc+2 (next)
    let accum_eval_cur_idx = |k: usize| -> u32 {
        logup_off as u32 + logup_flat_eval_offsets[k] + lookup_num_chunks[k] as u32 + 1
    };
    let accum_eval_next_idx = |k: usize| -> u32 {
        logup_off as u32 + logup_flat_eval_offsets[k] + lookup_num_chunks[k] as u32 + 2
    };

    // Dummy: dummy_off + running index
    let dummy_eval_idx = |d: usize| -> u32 { (dummy_off + d) as u32 };

    let zeros = |n: usize| vec![0u32; n];

    // ── Fewer-point-sets: build merged rotation set ────────────────────────────
    #[cfg(feature = "fewer-point-sets")]
    {
        // Simulate compute_dummy_queries to determine the union and dummy ordering.
        //
        // Groups in verifier query insertion order:
        //   1. Advice columns (in order of first appearance in advice_queries)
        //   2. Perm product chunks (0..np)
        //   3. Per-lookup: mult, helpers, accum
        //   4. Trash
        //   5. Fixed non-simple cols (in order of first appearance in fixed_queries)
        //   6. Sigma cols (0..npc)
        //   7. H (linearization)

        // For each group we track its real point set (sorted rotations).
        // "point set" uses the same integer rotation offsets as in the rotation_sets.

        // Advice unique cols in insertion order
        let mut adv_unique_cols: Vec<usize> = vec![];
        for &(c, _) in advice_queries {
            if !adv_unique_cols.contains(&c) {
                adv_unique_cols.push(c);
            }
        }

        // Fixed unique cols: non-simple-selector only, in first-encounter order.
        // Simple-selector cols are excluded because midnight-proofs skips them in the
        // multi-open query list (compute_dummy_queries never receives them).
        let mut fix_unique_cols: Vec<usize> = vec![];
        for &(col, _) in fixed_queries {
            if !fix_unique_cols.contains(&col) && !is_simple_col(col) {
                fix_unique_cols.push(col);
            }
        }

        // Build group list: (point_set, slot_info)
        // slot_info encodes how to build the slot once we know dummy assignments.
        //
        // Group ordering matches midnight-proofs verifier.rs lines 284-330:
        //   1. Advice, 2. Instance (committed col 0 at rot 0), 3. PermProd,
        //   4. Lookup (mult, helpers, accum per lookup), 5. Trash,
        //   6. Fixed (non-simple-selector), 7. Sigma, 8. H
        enum GroupKind {
            Adv { col: usize },
            Instance,
            PermProd { chunk: usize },
            LogupMult { k: usize },
            LogupHelper { k: usize, j: usize },
            LogupAccum { k: usize },
            Trash { t: usize },
            Fixed { col: usize },
            Sigma { k: usize },
            H,
        }
        struct Group {
            // Points in the ORDER they first appear in the query list for this commitment.
            // This must match compute_dummy_queries' insertion-order semantics exactly.
            points: Vec<i32>,
            kind: GroupKind,
        }

        let mut groups: Vec<Group> = vec![];

        // 1. Advice — points in advice_queries insertion order (not sorted).
        // compute_dummy_queries groups queries by commitment pointer and tracks points in
        // the order they first appear in the query list.  We must replicate that here so
        // that the union (and therefore dummy indices) match the proof stream exactly.
        for &col in &adv_unique_cols {
            let pts: Vec<i32> = {
                let mut seen = std::collections::HashSet::new();
                let mut ordered = vec![];
                for &(c, r) in advice_queries {
                    if c == col && seen.insert(r) {
                        ordered.push(r);
                    }
                }
                ordered
            };
            groups.push(Group { points: pts, kind: GroupKind::Adv { col } });
        }

        // 1.5. Instance: the committed instance column (col 0) queried at rotation 0.
        // midnight-proofs emits dummy evals for this group even though all its
        // polynomial evaluations are zero — the dummies must occupy the correct
        // positions in the proof stream so subsequent groups index correctly.
        groups.push(Group { points: vec![0i32], kind: GroupKind::Instance });

        // 2. Perm products
        for j in 0..np {
            let pts = if j < np - 1 || perm_all_3evals {
                vec![0i32, 1, last_rot]
            } else {
                vec![0i32, 1]
            };
            groups.push(Group { points: pts, kind: GroupKind::PermProd { chunk: j } });
        }

        // 3. Lookups: per lookup k: mult, helpers[0..nc], accum
        for k in 0..nl {
            let nc = lookup_num_chunks[k];
            groups.push(Group { points: vec![0i32], kind: GroupKind::LogupMult { k } });
            for j in 0..nc {
                groups.push(Group { points: vec![0i32], kind: GroupKind::LogupHelper { k, j } });
            }
            groups.push(Group { points: vec![0i32, 1], kind: GroupKind::LogupAccum { k } });
        }

        // 4. Trash
        for t in 0..num_trash {
            groups.push(Group { points: vec![0i32], kind: GroupKind::Trash { t } });
        }

        // 5. Fixed (all in fixed_queries, each unique col)
        for &col in &fix_unique_cols {
            let pts = fixed_col_rot_set(col);
            groups.push(Group { points: pts, kind: GroupKind::Fixed { col } });
        }

        // 6. Sigma
        for k in 0..npc {
            groups.push(Group { points: vec![0i32], kind: GroupKind::Sigma { k } });
        }

        // 7. H (linearization commitment)
        groups.push(Group { points: vec![0i32], kind: GroupKind::H });

        // Compute union (insertion order, from non-singleton groups)
        let mut union: Vec<i32> = vec![];
        for g in &groups {
            if g.points.len() <= 1 { continue; }
            for &p in &g.points {
                if !union.contains(&p) {
                    union.push(p);
                }
            }
        }

        if union.is_empty() {
            // No merging needed — fall through to the standard path.
            // (This can happen if all advice columns have a single rotation and
            //  there are no permutation products, which is unlikely in practice.)
        } else {
            // Assign dummy indices: for each group in insertion order,
            // for each union point missing from the group's points, assign next dummy idx.
            let mut dummy_idx = 0usize;
            // Map: (group_position, union_point) → dummy_idx
            let mut dummy_map: std::collections::HashMap<(usize, i32), usize> =
                std::collections::HashMap::new();
            for (gi, g) in groups.iter().enumerate() {
                for &up in &union {
                    if !g.points.contains(&up) {
                        dummy_map.insert((gi, up), dummy_idx);
                        dummy_idx += 1;
                    }
                }
            }

            // Build eval_idxs for one slot in the merged set.
            // union_rots = union (in encounter order).
            let eval_idx_for = |gi: usize, g: &Group, union_rot: i32, _union_rot_pos: usize| -> u32 {
                if g.points.contains(&union_rot) {
                    // Real eval at this rotation — use the kind-specific real eval_idx.
                    let rot_pos_in_group = g.points.iter().position(|&r| r == union_rot).unwrap();
                    match &g.kind {
                        GroupKind::Adv { col } => adv_eval_idx(*col, union_rot),
                        GroupKind::Instance => 0u32, // always zero; ignored by Haskell SKInstance
                        GroupKind::PermProd { chunk: j } => pp_eval_idx(*j, rot_pos_in_group),
                        GroupKind::LogupMult { k } => mult_eval_idx(*k),
                        GroupKind::LogupHelper { k, j } => {
                            helper_eval_idx(*k, *j as u32)
                        }
                        GroupKind::LogupAccum { k } => {
                            if union_rot == 0 { accum_eval_cur_idx(*k) }
                            else { accum_eval_next_idx(*k) }
                        }
                        GroupKind::Trash { t } => trash_eval_idx(*t),
                        GroupKind::Fixed { col } => fix_rot_eval_idx(*col, union_rot),
                        GroupKind::Sigma { k } => sigma_eval_idx(*k),
                        GroupKind::H => 0, // ignored for RotCur (uses hEval); dummy for others
                    }
                } else {
                    // Dummy eval
                    let d = dummy_map[&(gi, union_rot)];
                    dummy_eval_idx(d)
                }
            };

            // Build the merged set slots (in group insertion order = x₁-power order).
            let num_union = union.len();
            let mut merged_slots: Vec<Slot> = vec![];

            for (gi, g) in groups.iter().enumerate() {
                let eval_idxs: Vec<u32> = union.iter().enumerate()
                    .map(|(ui, &up)| eval_idx_for(gi, g, up, ui))
                    .collect();

                match &g.kind {
                    GroupKind::Adv { col } =>
                        merged_slots.push((0, *col as u32, eval_idxs)),
                    // Instance: zero polynomial. Slot is emitted here so x₁ powers are
                    // correct; eval_idxs are ignored by the Haskell (SKInstance → zero).
                    // Dummy indices ARE consumed here so subsequent groups index correctly.
                    GroupKind::Instance =>
                        merged_slots.push((1, 0, eval_idxs)),
                    GroupKind::PermProd { chunk: j } =>
                        merged_slots.push((8, *j as u32, eval_idxs)),
                    GroupKind::LogupMult { k } =>
                        merged_slots.push((2, *k as u32, eval_idxs)),
                    GroupKind::LogupHelper { k, j } => {
                        let flat_idx = logup_flat_helper_offsets[*k] + *j as u32;
                        merged_slots.push((10, flat_idx, eval_idxs));
                    }
                    GroupKind::LogupAccum { k } =>
                        merged_slots.push((9, *k as u32, eval_idxs)),
                    GroupKind::Trash { t } =>
                        merged_slots.push((3, *t as u32, eval_idxs)),
                    GroupKind::Fixed { col } =>
                        merged_slots.push((4, *col as u32, eval_idxs)),
                    GroupKind::Sigma { k } =>
                        merged_slots.push((5, *k as u32, eval_idxs)),
                    GroupKind::H =>
                        merged_slots.push((6, 0, eval_idxs)),
                }
            }

            // Serialize the single merged set.
            let mut buf: Vec<u8> = vec![];
            buf.extend_from_slice(&1u32.to_le_bytes()); // num_sets = 1
            buf.extend_from_slice(&(num_union as u32).to_le_bytes());
            for &r in &union {
                buf.extend_from_slice(&r.to_le_bytes());
            }
            buf.extend_from_slice(&(merged_slots.len() as u32).to_le_bytes());
            for (kind, index, eval_idxs) in &merged_slots {
                buf.push(*kind);
                buf.extend_from_slice(&index.to_le_bytes());
                for &e in eval_idxs {
                    buf.extend_from_slice(&e.to_le_bytes());
                }
            }
            return buf;
        }
    }

    // ── Standard (non-fewer-point-sets or empty union) path ───────────────────

    // Compute advice rotation sets and encounter/column ordering.
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

    let rs0_sorted: Vec<i32> = vec![0];
    let rs01_sorted: Vec<i32> = vec![0, 1];
    let rs01last_enc: Vec<i32> = vec![0, 1, last_rot];

    // Helper: non-advice slots for the {0} set.
    let build_set0_extra = |num_rots: usize| -> Vec<Slot> {
        let mut s: Vec<Slot> = vec![];
        s.push((1, 0, zeros(num_rots))); // Instance
        for k in 0..nl {
            let nc = lookup_num_chunks[k] as u32;
            let helper_off = logup_flat_helper_offsets[k];
            s.push((2, k as u32, vec![mult_eval_idx(k)]));
            for j in 0..nc {
                // slot index = flat helper index; eval_idx uses local j (0..nc)
                s.push((10, helper_off + j, vec![helper_eval_idx(k, j)]));
            }
        }
        for t in 0..num_trash {
            s.push((3, t as u32, vec![trash_eval_idx(t)]));
        }
        for &col in &fq_col_order {
            if fixed_col_rot_set(col) == [0] {
                s.push((4, col as u32, vec![fix_rot_eval_idx(col, 0)]));
            }
        }
        for k in 0..npc {
            s.push((5, k as u32, vec![sigma_eval_idx(k)]));
        }
        s.push((6, 0, zeros(num_rots))); // H
        s
    };

    // Helper: non-advice slots for the {0,1} set.
    let build_set01_extra = |_num_rots: usize| -> Vec<Slot> {
        let mut s: Vec<Slot> = vec![];
        if np > 0 && !perm_all_3evals {
            s.push((8, last_chunk as u32, vec![
                pp_eval_idx(last_chunk, 0),
                pp_eval_idx(last_chunk, 1),
            ]));
        }
        for k in 0..nl {
            s.push((9, k as u32, vec![accum_eval_cur_idx(k), accum_eval_next_idx(k)]));
        }
        for &col in &fq_col_order {
            if fixed_col_rot_set(col) == [0, 1] {
                s.push((4, col as u32, vec![
                    fix_rot_eval_idx(col, 0),
                    fix_rot_eval_idx(col, 1),
                ]));
            }
        }
        s
    };

    let mut indexed_sets: Vec<IndexedSet> = vec![];
    let mut next_idx: usize = 0;
    let mut seen_rs0 = false;
    let mut seen_rs01 = false;

    for rs in &adv_rs_encounter {
        let cols = &adv_rs_cols[rs];
        let rot_order = &adv_rs_rot_order[rs];
        let num_rots = rot_order.len();

        let mut slots: Vec<Slot> = vec![];
        for &c in cols {
            let eval_idxs: Vec<u32> = rot_order.iter().map(|&rot| adv_eval_idx(c, rot)).collect();
            slots.push((0, c as u32, eval_idxs));
        }

        let rs_sorted = {
            let mut s = rs.clone();
            s.sort();
            s
        };

        if rs_sorted == rs0_sorted {
            seen_rs0 = true;
            slots.extend(build_set0_extra(num_rots));
        } else if rs_sorted == rs01_sorted {
            seen_rs01 = true;
            slots.extend(build_set01_extra(num_rots));
        }

        indexed_sets.push((next_idx, rot_order.clone(), slots));
        next_idx += 1;
    }

    if !seen_rs0 {
        let mut s0: Vec<Slot> = vec![];
        s0.extend(build_set0_extra(1));
        indexed_sets.push((next_idx, vec![0], s0));
        next_idx += 1;
    }

    if !seen_rs01 {
        let s01 = build_set01_extra(2);
        if !s01.is_empty() {
            indexed_sets.push((next_idx, vec![0, 1], s01));
            next_idx += 1;
        }
    }

    {
        let n4 = if perm_all_3evals { np } else { num_non_last };
        if n4 > 0 {
            let s4: Vec<Slot> = (0..n4)
                .map(|j| (8u8, j as u32, vec![pp_eval_idx(j, 0), pp_eval_idx(j, 1), pp_eval_idx(j, 2)]))
                .collect();
            indexed_sets.push((next_idx, rs01last_enc.clone(), s4));
            next_idx += 1;
        }
    }

    if let Some((rots, slots)) = set_fix1 {
        indexed_sets.push((next_idx, rots, slots));
    }

    indexed_sets.sort_by_key(|&(idx, ref rots, _)| (rots.len(), idx));

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
