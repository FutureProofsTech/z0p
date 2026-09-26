//! Red-team suite, round two: cross-proof transplants, false statements,
//! IVC tampering, codec limits, transcript abuse, and hostile garbage.
//!
//! Every test prints its vector with attempt/rejection counts
//! (`cargo test -- --nocapture`); assertions pin 100% rejection of
//! forgeries and zero panics on hostile input.

use z0p::{
    air, babybear::Field, fold, fri, lookup, merkle::MerkleTree, range, rng::ChaCha20, table,
    transcript::Transcript,
};

/// Deterministic scrambler for hostile input (no external RNG needed).
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn report(vector: &str, attempts: usize, rejected: usize) {
    println!(
        "redteam {vector:<28} attempts={attempts:<5} rejected={rejected:<5} ACCEPTED={}",
        attempts - rejected
    );
}

fn air_proof_pair() -> (air::Params, air::Proof, air::Params, air::Proof) {
    let (_, trace_b) = air::build_trace(Field::ONE, Field::ONE, 32);
    let b_last = trace_b[31];
    // LDE 256 -> final 16 quarters exactly (ratio 16 = 4^2).
    let mk = |last: Field| {
        air::Params::new(32, 8, 8, 16, Field::ONE, Field::ONE, last).expect("air params")
    };
    let p1 = mk(b_last);
    let p2 = mk(b_last + Field::ONE);
    let mut t = Transcript::new(b"redteam/air");
    let proof1 = air::prove(p1, &mut t).expect("prove p1");
    let mut t = Transcript::new(b"redteam/air");
    // False statement still proves structurally; it must never verify.
    let proof2 = air::prove(p2, &mut t).expect("prove p2");
    (p1, proof1, p2, proof2)
}

fn air_verifies(params: air::Params, proof: &air::Proof) -> bool {
    let mut t = Transcript::new(b"redteam/air");
    air::verify(params, proof, &mut t).is_ok()
}

#[test]
fn false_statements_never_verify() {
    let mut attempts = 0;
    let mut rejected = 0;
    // Range: 300 does not fit 8 bits. Proves structurally, must not verify.
    let rparams = range::Params::new(8, 8, 8, 8, 4, Field::new(300)).expect("range params");
    let mut t = Transcript::new(b"redteam/range-false");
    let rproof = range::prove(rparams, &mut t).expect("structural range prove");
    let mut t = Transcript::new(b"redteam/range-false");
    rejected += usize::from(range::verify(rparams, &rproof, &mut t).is_err());
    attempts += 1;
    // Table: 999 is not a member of [10, 20, 30, 40].
    let table_vals: Vec<Field> = [10, 20, 30, 40].iter().map(|v| Field::new(*v)).collect();
    let tparams = table::Params::new(8, 8, 8, 4, Field::new(999)).expect("table params");
    let mut t = Transcript::new(b"redteam/table-false");
    let tproof = table::prove(tparams, &table_vals, &mut t).expect("structural table prove");
    let mut t = Transcript::new(b"redteam/table-false");
    rejected += usize::from(table::verify(tparams, &table_vals, &tproof, &mut t).is_err());
    attempts += 1;
    // Lookup: out-of-table witness fails closed at prove time.
    let mut t = Transcript::new(b"redteam/lookup-false");
    let witness = [Field::new(1), Field::new(2), Field::new(77)];
    let table: Vec<Field> = (0..8).map(Field::new).collect();
    rejected += usize::from(lookup::prove(&witness, &table, &mut t).is_err());
    attempts += 1;
    report("false-statements", attempts, rejected);
    assert_eq!(rejected, attempts, "false statements must never verify");
}

#[test]
fn transplant_attacks_rejected() {
    let (p1, proof1, p2, proof2) = air_proof_pair();
    // Sanity: true proves, false does not.
    assert!(air_verifies(p1, &proof1));
    assert!(!air_verifies(p2, &proof2));
    // P1/P2 share the identical trace (only `b_last` differs), so their
    // column caps are byte-identical: transplanting proves nothing. Pin
    // that understanding explicitly instead of counting it as an attack.
    assert_eq!(proof1.column_cap, proof2.column_cap);
    // A cap from a genuinely different trace for the transplant vector.
    let (_, other_b) = air::build_trace(Field::new(2), Field::new(3), 32);
    let p3 = air::Params::new(32, 8, 8, 16, Field::new(2), Field::new(3), other_b[31])
        .expect("air params");
    let mut t = Transcript::new(b"redteam/air");
    let proof3 = air::prove(p3, &mut t).expect("prove p3");
    assert_ne!(proof1.column_cap, proof3.column_cap);
    let mut attempts = 0;
    let mut rejected = 0;
    // Opening transplant across statements.
    let mut bad = proof1.clone();
    bad.openings[0] = proof2.openings[0].clone();
    rejected += usize::from(!air_verifies(p1, &bad));
    attempts += 1;
    // Foreign-trace column-cap transplant.
    let mut bad = proof1.clone();
    bad.column_cap.clone_from(&proof3.column_cap);
    rejected += usize::from(!air_verifies(p1, &bad));
    attempts += 1;
    // Whole-FRI-proof transplant.
    let mut bad = proof1.clone();
    bad.fri_proof = proof2.fri_proof.clone();
    rejected += usize::from(!air_verifies(p1, &bad));
    attempts += 1;
    // Whole-commitment transplant.
    let mut bad = proof1.clone();
    bad.fri_commitment = proof2.fri_commitment.clone();
    rejected += usize::from(!air_verifies(p1, &bad));
    attempts += 1;
    report("transplant-attacks", attempts, rejected);
    assert_eq!(rejected, attempts, "transplants must fail");
}

#[test]
fn fri_surgery_rejected() {
    let params = fri::Params::new(4, 8, 4).expect("fri params");
    let poly_a: Vec<Field> = (0..16u32)
        .map(|i| Field::new(i.wrapping_mul(0x9e37_79b9).wrapping_add(17)))
        .collect();
    let poly_b: Vec<Field> = (0..16u32)
        .map(|i| Field::new(i.wrapping_mul(0x1234_5678).wrapping_add(99)))
        .collect();
    let mut t = Transcript::new(b"redteam/fri-a");
    let sa = fri::commit(&poly_a, params, &mut t).expect("commit a");
    let ca = fri::public_commitment(&sa);
    let (pa, _) = fri::open(&sa, &mut t).expect("open a");
    let mut t = Transcript::new(b"redteam/fri-b");
    let sb = fri::commit(&poly_b, params, &mut t).expect("commit b");
    let cb = fri::public_commitment(&sb);
    let (pb, _) = fri::open(&sb, &mut t).expect("open b");
    let mut attempts = 0;
    let mut rejected = 0;
    // Proof A against commitment B.
    let mut t = Transcript::new(b"redteam/fri-a");
    rejected += usize::from(fri::verify(&cb, &pa, params, &mut t).is_err());
    attempts += 1;
    // Final-poly swap.
    let mut swapped = pa.clone();
    swapped.final_poly.clone_from(&pb.final_poly);
    let mut t = Transcript::new(b"redteam/fri-a");
    rejected += usize::from(fri::verify(&ca, &swapped, params, &mut t).is_err());
    attempts += 1;
    // Query amputation (count mismatch).
    let mut cut = pa.clone();
    cut.queries.pop();
    let mut t = Transcript::new(b"redteam/fri-a");
    rejected += usize::from(fri::verify(&ca, &cut, params, &mut t).is_err());
    attempts += 1;
    // Query duplication (count mismatch the other way).
    let mut dup = pa.clone();
    let first = dup.queries[0].clone();
    dup.queries.push(first);
    let mut t = Transcript::new(b"redteam/fri-a");
    rejected += usize::from(fri::verify(&ca, &dup, params, &mut t).is_err());
    attempts += 1;
    report("fri-surgery", attempts, rejected);
    assert_eq!(rejected, attempts, "FRI surgery must fail");
}

#[test]
fn fold_tamper_rejected() {
    // Two chained 8-step segments, LDE 64 -> final 4 (ratio 16 = 4^2).
    let build = || {
        let mut segments = Vec::new();
        let (mut a, mut b) = (Field::ONE, Field::ONE);
        for _ in 0..2 {
            let (col_a, col_b) = air::build_trace(a, b, 8);
            a = col_a[7];
            b = col_b[7];
            segments.push((col_a, col_b));
        }
        (segments, b)
    };
    let (segments, out_b) = build();
    let params = fold::Params::new(8, 8, 8, 4, Field::ONE, Field::ONE, out_b).expect("fold params");
    let mut t = Transcript::new(b"redteam/fold");
    let mut acc = fold::Accumulator::new(params);
    for (col_a, col_b) in &segments {
        acc.add_segment(col_a, col_b, &mut t).expect("segment");
    }
    let proof = acc.finalize(&mut t).expect("finalize");
    let verifies = |proof: &fold::IvcProof| {
        let mut t = Transcript::new(b"redteam/fold");
        fold::verify(params, proof, &mut t).is_ok()
    };
    assert!(verifies(&proof), "honest IVC must verify");
    let mut attempts = 0;
    let mut rejected = 0;
    // Claim forgery in step 0.
    let mut bad = proof.clone();
    bad.steps[0].claims.out_a += Field::ONE;
    rejected += usize::from(!verifies(&bad));
    attempts += 1;
    // Column-value forgery in step 1.
    let mut bad = proof.clone();
    bad.steps[1].openings[0].cols[0] += Field::ONE;
    rejected += usize::from(!verifies(&bad));
    attempts += 1;
    // Step-cap forgery.
    let mut bad = proof.clone();
    bad.steps[0].column_cap[0][0] ^= 1;
    rejected += usize::from(!verifies(&bad));
    attempts += 1;
    // Step amputation breaks the chain.
    let mut bad = proof.clone();
    bad.steps.pop();
    rejected += usize::from(!verifies(&bad));
    attempts += 1;
    report("fold-tamper", attempts, rejected);
    assert_eq!(rejected, attempts, "IVC tampering must fail");
}

#[test]
fn leaf_node_confusion_rejected() {
    // Second-preimage resistance from domain separation: a node preimage
    // must never verify as a leaf, in either hash role.
    let leaves: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 32]).collect();
    let tree = MerkleTree::new(&leaves).expect("tree");
    let root = tree.root();
    let mut attempts = 0;
    let mut rejected = 0;
    // Craft `0x01 || L0 || L1` (a node preimage) and offer it as leaf data
    // against the node digest used as a root: the `0x00` leaf prefix kills it.
    let path0 = tree.prove(0).expect("prove");
    let mut node_prelude = vec![0x01u8];
    node_prelude.extend_from_slice(&leaves[0]);
    node_prelude.extend_from_slice(&leaves[1]);
    let node_digest = {
        let l0 = z0p::merkle::hash_leaf(&leaves[0]);
        let l1 = z0p::merkle::hash_leaf(&leaves[1]);
        z0p::merkle::hash_node(&l0, &l1)
    };
    rejected += usize::from(!MerkleTree::verify(&node_digest, &node_prelude, 0, &[]));
    attempts += 1;
    // The crafted preimage also fails against the real root at any index.
    for i in 0..4 {
        rejected += usize::from(!MerkleTree::verify(&root, &node_prelude, i, &path0));
        attempts += 1;
    }
    report("leaf-node-confusion", attempts, rejected);
    assert_eq!(rejected, attempts, "domain confusion must fail");
}

#[test]
fn garbage_never_panics_or_verifies() {
    // Hostile bytes: every decode-then-verify chain must fail closed with
    // `Err`, never panic (panic = denial of service on untrusted input).
    let mut state = 0xbad5_eed5_1234_5678u64;
    let trials = 500;
    let mut panics = 0;
    let mut accepted = 0;
    for _ in 0..trials {
        let len = usize::try_from(splitmix(&mut state) % 320).expect("mod 320 fits usize");
        let mut bytes = vec![0u8; len];
        for b in &mut bytes {
            *b = u8::try_from(splitmix(&mut state) % 256).expect("mod 256 fits u8");
        }
        let trial = std::panic::catch_unwind(|| {
            let mut ok = false;
            if air::Proof::from_bytes(&bytes).is_ok() {
                ok = true;
            }
            if fri::Proof::from_bytes(&bytes).is_ok() {
                ok = true;
            }
            if fri::Commitment::from_bytes(&bytes).is_ok() {
                ok = true;
            }
            if fold::IvcProof::from_bytes(&bytes).is_ok() {
                ok = true;
            }
            if range::Proof::from_bytes(&bytes).is_ok() {
                ok = true;
            }
            if table::Proof::from_bytes(&bytes).is_ok() {
                ok = true;
            }
            ok
        });
        match trial {
            Err(_) => panics += 1,
            Ok(true) => accepted += 1,
            Ok(false) => {}
        }
    }
    println!("redteam garbage-hostile            trials={trials:<5} panics={panics:<5} decoded={accepted:<5}");
    assert_eq!(panics, 0, "decoding hostile input must never panic");
    assert_eq!(accepted, 0, "random garbage must never decode");
}

#[test]
fn count_limits_fail_closed() {
    let mut attempts = 0;
    let mut rejected = 0;
    // FRI proof: final-poly count above MAX_ELEMS fails before allocation.
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    rejected += usize::from(fri::Proof::from_bytes(&bytes).is_err());
    attempts += 1;
    // AIR proof: cap count above MAX_CAP_DIGESTS.
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&257u32.to_le_bytes());
    rejected += usize::from(air::Proof::from_bytes(&bytes).is_err());
    attempts += 1;
    // Fold proof: step count above MAX_STEPS.
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&((1u32 << 20) + 1).to_le_bytes());
    rejected += usize::from(fold::IvcProof::from_bytes(&bytes).is_err());
    attempts += 1;
    // Version byte outside the supported set.
    rejected += usize::from(fri::Commitment::from_bytes(&[0x7Fu8; 64]).is_err());
    attempts += 1;
    report("count-limits", attempts, rejected);
    assert_eq!(rejected, attempts, "oversized counts must fail closed");
}

#[test]
fn transcript_abuse_diverges() {
    let mut attempts = 0;
    let mut rejected = 0;
    // Absorb-order swap changes every later challenge.
    let mut t1 = Transcript::new(b"redteam/order");
    t1.absorb(b"a", b"first");
    t1.absorb(b"b", b"second");
    let mut t2 = Transcript::new(b"redteam/order");
    t2.absorb(b"b", b"second");
    t2.absorb(b"a", b"first");
    rejected += usize::from(t1.challenge_bb(b"x") != t2.challenge_bb(b"x"));
    attempts += 1;
    // Challenge replay under one label still separates via the counter.
    let mut t = Transcript::new(b"redteam/replay");
    let first = t.challenge_bb(b"same");
    rejected += usize::from(t.challenge_bb(b"same") != first);
    attempts += 1;
    // Query indices stay in range over many squeezes.
    let mut t = Transcript::new(b"redteam/range");
    let mut in_range = true;
    for _ in 0..200 {
        if t.challenge_index(b"q", 64) >= 64 {
            in_range = false;
        }
    }
    rejected += usize::from(in_range);
    attempts += 1;
    // PoW downgrade: proof ground at 8 bits verified under 0-bit params
    // diverges (the nonce absorb is missing) and must fail.
    let (_, trace_b) = air::build_trace(Field::ONE, Field::ONE, 32);
    let mk = |grind: u32| {
        air::Params::new(32, 8, 8, 16, Field::ONE, Field::ONE, trace_b[31])
            .expect("params")
            .with_grinding_bits(grind)
            .with_cap_height(2)
    };
    let ground = mk(8);
    let mut t = Transcript::new(b"redteam/downgrade");
    let proof = air::prove(ground, &mut t).expect("prove");
    let mut t = Transcript::new(b"redteam/downgrade");
    rejected += usize::from(air::verify(mk(0), &proof, &mut t).is_err());
    attempts += 1;
    report("transcript-abuse", attempts, rejected);
    assert_eq!(rejected, attempts, "transcript abuse must diverge");
}

#[test]
fn rate_boundary_exact() {
    // Exact ceiling over LDE 64: bound = 31 passes the gate and verifies;
    // bound = 32 fails closed at prove time, and a raised commitment
    // fails at verify time.
    let params = fri::Params::new(4, 8, 4).expect("fri params");
    let coeffs: Vec<Field> = (0..16u32)
        .map(|i| Field::new(i.wrapping_mul(0x9e37_79b9).wrapping_add(5)))
        .collect();
    let lde = z0p::ntt::evaluate_on_coset(&coeffs, 4, fri::LDE_SHIFT).expect("lde");
    assert_eq!(lde.len(), 64);
    let mut attempts = 0;
    let mut rejected = 0;
    // Boundary honest case verifies.
    let mut t = Transcript::new(b"redteam/edge");
    let state = fri::commit_evals(&lde, 31, params, &mut t).expect("edge commit");
    let commitment = fri::public_commitment(&state);
    let (proof, _) = fri::open(&state, &mut t).expect("edge open");
    let mut t = Transcript::new(b"redteam/edge");
    let edge_ok = fri::verify(&commitment, &proof, params, &mut t).is_ok();
    rejected += usize::from(edge_ok);
    attempts += 1;
    // One past the ceiling fails at prove time (never reaches verify).
    let mut t = Transcript::new(b"redteam/edge");
    rejected += usize::from(fri::commit_evals(&lde, 32, params, &mut t).is_err());
    attempts += 1;
    // Raised commitment fails at verify time.
    let mut high = commitment.clone();
    high.degree_bound = 32;
    let mut t = Transcript::new(b"redteam/edge");
    rejected += usize::from(fri::verify(&high, &proof, params, &mut t).is_err());
    attempts += 1;
    report("rate-boundary-exact", attempts, rejected);
    assert_eq!(rejected, attempts, "boundary behavior must be exact");
}

#[test]
fn zk_roundtrips_and_tamper() {
    let mut rng = ChaCha20::new([77u8; 32], [88u8; 12]);
    let mut attempts = 0;
    let mut rejected = 0;
    // AIR blinded roundtrip + tamper. Masking enlarges the composition,
    // so the ZK shape needs the smaller final (mirrors `test_params_zk`).
    let (_, trace_b) = air::build_trace(Field::ONE, Field::ONE, 16);
    let aparams =
        air::Params::new(16, 8, 8, 4, Field::ONE, Field::ONE, trace_b[15]).expect("air params");
    let mut t = Transcript::new(b"redteam/zk-air");
    let aproof = air::prove_zk(aparams, 8, &mut rng, &mut t).expect("zk prove");
    let mut t = Transcript::new(b"redteam/zk-air");
    rejected += usize::from(air::verify(aparams, &aproof, &mut t).is_ok());
    attempts += 1;
    let mut bad = aproof.clone();
    bad.openings[0].a += Field::ONE;
    let mut t = Transcript::new(b"redteam/zk-air");
    rejected += usize::from(air::verify(aparams, &bad, &mut t).is_err());
    attempts += 1;
    // Range blinded roundtrip + tamper (ZK shape: final 8).
    let rparams = range::Params::new(8, 16, 8, 8, 8, Field::new(42)).expect("range params");
    let mut t = Transcript::new(b"redteam/zk-range");
    let rproof = range::prove_zk(rparams, 8, &mut rng, &mut t).expect("zk range");
    let mut t = Transcript::new(b"redteam/zk-range");
    rejected += usize::from(range::verify(rparams, &rproof, &mut t).is_ok());
    attempts += 1;
    // Masking must not smuggle falsehoods: blinded out-of-range and
    // non-member proofs still fail.
    let table_vals: Vec<Field> = [10, 20, 30, 40].iter().map(|v| Field::new(*v)).collect();
    let rparams_oor = range::Params::new(8, 16, 8, 8, 8, Field::new(70_000)).expect("range params");
    let mut t = Transcript::new(b"redteam/zk-range-oor");
    let roor = range::prove_zk(rparams_oor, 8, &mut rng, &mut t).expect("zk range oor");
    let mut t = Transcript::new(b"redteam/zk-range-oor");
    rejected += usize::from(range::verify(rparams_oor, &roor, &mut t).is_err());
    attempts += 1;
    let tparams_nm = table::Params::new(8, 8, 8, 8, Field::new(99)).expect("table params");
    let mut t = Transcript::new(b"redteam/zk-table-nm");
    let tnm =
        table::prove_zk(tparams_nm, &table_vals, 8, &mut rng, &mut t).expect("zk table non-member");
    let mut t = Transcript::new(b"redteam/zk-table-nm");
    rejected += usize::from(table::verify(tparams_nm, &table_vals, &tnm, &mut t).is_err());
    attempts += 1;
    // Table blinded roundtrip.
    let tparams = table::Params::new(8, 8, 8, 8, Field::new(30)).expect("table params");
    let mut t = Transcript::new(b"redteam/zk-table");
    let tproof = table::prove_zk(tparams, &table_vals, 8, &mut rng, &mut t).expect("zk table");
    let mut t = Transcript::new(b"redteam/zk-table");
    rejected += usize::from(table::verify(tparams, &table_vals, &tproof, &mut t).is_ok());
    attempts += 1;
    report("zk-roundtrips-tamper", attempts, rejected);
    assert_eq!(
        rejected, attempts,
        "ZK proofs must verify; tampering must fail"
    );
}
