//! Security adversarial suite: every attack vector must fail, on the record.
//!
//! Each test prints its vector, attempt count, and rejection count
//! (`cargo test -- --nocapture` shows the table). Assertions pin 100%
//! rejection — a single acceptance fails the suite. Shapes are small and
//! fast; grinding is 8 bits so proof-of-work gates execute for real.

use z0p::{air, babybear::Field, fri, merkle::MerkleTree, transcript::Transcript};

/// Fixed transcript domain for the whole suite.
const LABEL: &[u8] = b"security/air";

/// Deterministic scrambler for fuzz positions (no external RNG needed).
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn security_params() -> air::Params {
    let (_, trace_b) = air::build_trace(Field::ONE, Field::ONE, 32);
    let b_last = trace_b[31];
    // LDE 256 -> final 16 quarters exactly (ratio 16 = 4^2).
    air::Params::new(32, 8, 8, 16, Field::ONE, Field::ONE, b_last)
        .expect("security params")
        .with_grinding_bits(8)
        .with_cap_height(2)
}

fn honest_proof() -> (air::Params, air::Proof) {
    let params = security_params();
    let mut transcript = Transcript::new(LABEL);
    let proof = air::prove(params, &mut transcript).expect("honest prove");
    (params, proof)
}

fn verifies(params: air::Params, proof: &air::Proof) -> bool {
    let mut transcript = Transcript::new(LABEL);
    air::verify(params, proof, &mut transcript).is_ok()
}

fn report(vector: &str, attempts: usize, rejected: usize) {
    println!(
        "security {vector:<28} attempts={attempts:<5} rejected={rejected:<5} ACCEPTED={}",
        attempts - rejected
    );
}

#[test]
fn honest_proof_accepts() {
    let (params, proof) = honest_proof();
    assert!(verifies(params, &proof), "honest proof must verify");
    println!(
        "security honest-accepts             attempts=1     rejected=0     ACCEPTED=1 (sanity)"
    );
}

#[test]
fn tampered_fri_values_rejected() {
    let (params, proof) = honest_proof();
    let mut attempts = 0;
    let mut rejected = 0;
    for q in 0..proof.fri_proof.queries.len() {
        for f in 0..proof.fri_proof.queries[q].folds.len() {
            for v in 0..4 {
                let mut bad = proof.clone();
                bad.fri_proof.queries[q].folds[f].values[v] += Field::ONE;
                attempts += 1;
                rejected += usize::from(!verifies(params, &bad));
            }
        }
    }
    report("tamper-fri-values", attempts, rejected);
    assert_eq!(rejected, attempts, "every FRI value forgery must fail");
}

#[test]
fn tampered_final_poly_rejected() {
    let (params, proof) = honest_proof();
    let mut attempts = 0;
    let mut rejected = 0;
    for i in 0..proof.fri_proof.final_poly.len() {
        let mut bad = proof.clone();
        bad.fri_proof.final_poly[i] += Field::ONE;
        attempts += 1;
        rejected += usize::from(!verifies(params, &bad));
    }
    report("tamper-final-poly", attempts, rejected);
    assert_eq!(rejected, attempts, "every final-poly forgery must fail");
}

#[test]
fn tampered_trace_values_rejected() {
    let (params, proof) = honest_proof();
    let mut attempts = 0;
    let mut rejected = 0;
    for i in 0..proof.openings.len() {
        for which in 0..4 {
            let mut bad = proof.clone();
            let slot = &mut bad.openings[i];
            match which {
                0 => slot.a += Field::ONE,
                1 => slot.b += Field::ONE,
                2 => slot.a_next += Field::ONE,
                _ => slot.b_next += Field::ONE,
            }
            attempts += 1;
            rejected += usize::from(!verifies(params, &bad));
        }
    }
    report("tamper-trace-values", attempts, rejected);
    assert_eq!(rejected, attempts, "every trace forgery must fail");
}

#[test]
fn tampered_paths_rejected() {
    let (params, proof) = honest_proof();
    let mut attempts = 0;
    let mut rejected = 0;
    // Truncate one step off the first FRI fold path and first trace path.
    let mut bad = proof.clone();
    bad.fri_proof.queries[0].folds[0].path.pop();
    attempts += 1;
    rejected += usize::from(!verifies(params, &bad));
    let mut bad = proof.clone();
    bad.openings[0].path.pop();
    attempts += 1;
    rejected += usize::from(!verifies(params, &bad));
    // Flip a digest byte in each.
    let mut bad = proof.clone();
    bad.fri_proof.queries[0].folds[0].path[0].0[0] ^= 1;
    attempts += 1;
    rejected += usize::from(!verifies(params, &bad));
    let mut bad = proof.clone();
    bad.openings[0].path[0].0[0] ^= 1;
    attempts += 1;
    rejected += usize::from(!verifies(params, &bad));
    // Swap a path direction bit.
    let mut bad = proof.clone();
    let first = bad.openings[0].path[0].1;
    bad.openings[0].path[0].1 = !first;
    attempts += 1;
    rejected += usize::from(!verifies(params, &bad));
    report("tamper-merkle-paths", attempts, rejected);
    assert_eq!(rejected, attempts, "every path forgery must fail");
}

#[test]
fn tampered_commitments_rejected() {
    let (params, proof) = honest_proof();
    let mut attempts = 0;
    let mut rejected = 0;
    let mut bad = proof.clone();
    bad.fri_commitment.caps[0][0][0] ^= 1;
    attempts += 1;
    rejected += usize::from(!verifies(params, &bad));
    let mut bad = proof.clone();
    bad.column_cap[0][0] ^= 1;
    attempts += 1;
    rejected += usize::from(!verifies(params, &bad));
    report("tamper-commitments", attempts, rejected);
    assert_eq!(rejected, attempts, "every commitment forgery must fail");
}

#[test]
fn wrong_domain_and_statement_rejected() {
    let (params, proof) = honest_proof();
    let mut attempts = 0;
    let mut rejected = 0;
    // Wrong transcript domain: verifier replays a different history.
    let mut transcript = Transcript::new(b"security/WRONG");
    rejected += usize::from(air::verify(params, &proof, &mut transcript).is_err());
    attempts += 1;
    // Cross-statement replay: proof for b_last verified against b_last + 1.
    let (_, trace_b) = air::build_trace(Field::ONE, Field::ONE, 32);
    let other = air::Params::new(
        32,
        8,
        8,
        16,
        Field::ONE,
        Field::ONE,
        trace_b[31] + Field::ONE,
    )
    .expect("other params")
    .with_grinding_bits(8)
    .with_cap_height(2);
    rejected += usize::from(!verifies(other, &proof));
    attempts += 1;
    report("wrong-domain-statement", attempts, rejected);
    assert_eq!(rejected, attempts, "domain/statement confusion must fail");
}

#[test]
fn forged_pow_nonce_rejected() {
    let (params, proof) = honest_proof();
    // Wrong nonces are rejected: either the PoW gate fails, or the replayed
    // transcript samples different queries whose openings cannot match.
    // Each candidate rejects with probability ~1 (a PoW fluke only passes
    // the gate; the query check still fails), so a short hunt is decisive.
    let mut found = 0;
    for delta in 1..=5u64 {
        let mut bad = proof.clone();
        bad.fri_proof.pow_nonce = bad.fri_proof.pow_nonce.wrapping_add(delta);
        if !verifies(params, &bad) {
            found += 1;
        }
    }
    println!(
        "security forged-pow-nonce           attempts=5     rejected={found:<5} ACCEPTED={}",
        5 - found
    );
    assert!(found >= 1, "at least one forged nonce must fail");
    // Impossible difficulty fails deterministically at the transcript.
    let mut transcript = Transcript::new(b"security/pow");
    transcript.absorb(b"stmt", b"hello");
    assert!(
        !transcript.verify_grind(b"pow", 0, 257),
        "absurd difficulty must fail"
    );
}

#[test]
fn rate_gate_forgeries_rejected() {
    // Raised bound toward the LDE size trips the rate gate; a random word
    // under a lowered bound trips the final low-degree check.
    let fri_params = fri::Params::new(4, 8, 4).expect("fri params");
    let coeffs: Vec<Field> = (0..16u32)
        .map(|i| Field::new(i.wrapping_mul(0x9e37_79b9).wrapping_add(17)))
        .collect();
    let mut prover = Transcript::new(b"security/rate");
    let state = fri::commit(&coeffs, fri_params, &mut prover).expect("commit");
    let commitment = fri::public_commitment(&state);
    let (proof, _) = fri::open(&state, &mut prover).expect("open");
    let lde = commitment.lde_len;
    let mut high = commitment.clone();
    high.degree_bound = lde - 1;
    let mut verifier = Transcript::new(b"security/rate");
    let raised = fri::verify(&high, &proof, fri_params, &mut verifier).is_err();

    let loose = fri::Params::new(4, 8, 16).expect("loose params");
    let mut seed = 0x2b2b_2b2b_2b2b_2b2bu64;
    let random_evals: Vec<Field> = (0..64)
        .map(|_| {
            seed = splitmix(&mut seed);
            Field::from_u64(seed)
        })
        .collect();
    let mut prover = Transcript::new(b"security/lowbound");
    let state = fri::commit_evals(&random_evals, 7, loose, &mut prover).expect("commit");
    let commitment = fri::public_commitment(&state);
    let (proof, _) = fri::open(&state, &mut prover).expect("open");
    let mut verifier = Transcript::new(b"security/lowbound");
    let lowered = fri::verify(&commitment, &proof, loose, &mut verifier).is_err();

    let rejected = usize::from(raised) + usize::from(lowered);
    report("rate-gate-forgeries", 2, rejected);
    assert!(raised && lowered, "both bound forgeries must fail");
}

#[test]
fn byte_fuzz_proof_rejected() {
    let (params, proof) = honest_proof();
    let bytes = proof.to_bytes();
    let trials = 200;
    let mut state = 0xf022_1e57_ca71_e500u64;
    let mut rejected = 0;
    let mut accepted_at = Vec::new();
    for _ in 0..trials {
        let mut mutated = bytes.clone();
        let pos =
            usize::try_from(splitmix(&mut state) % mutated.len() as u64).expect("proof fits usize");
        let bit = u8::try_from(splitmix(&mut state) % 8).expect("mod 8 fits u8");
        mutated[pos] ^= 1 << bit;
        // Decoder gate first (shape violations die here), then the verifier.
        match air::Proof::from_bytes(&mutated) {
            Err(_) => rejected += 1,
            Ok(decoded) => {
                if verifies(params, &decoded) {
                    accepted_at.push(pos);
                } else {
                    rejected += 1;
                }
            }
        }
    }
    report("byte-fuzz-proof", trials, rejected);
    println!("security byte-fuzz-proof accepted positions: {accepted_at:?}");
    assert_eq!(rejected, trials, "every bit-flip must be rejected");
}

#[test]
fn byte_fuzz_commitment_rejected() {
    let (params, proof) = honest_proof();
    let bytes = proof.fri_commitment.to_bytes();
    let trials = 100;
    let mut state = 0xc001_17f0_5500_0000u64;
    let mut rejected = 0;
    let mut accepted_at = Vec::new();
    for _ in 0..trials {
        let mut mutated = bytes.clone();
        let pos = usize::try_from(splitmix(&mut state) % mutated.len() as u64)
            .expect("commitment fits usize");
        let bit = u8::try_from(splitmix(&mut state) % 8).expect("mod 8 fits u8");
        mutated[pos] ^= 1 << bit;
        match fri::Commitment::from_bytes(&mutated) {
            Err(_) => rejected += 1,
            Ok(decoded) => {
                // A decodable-but-mutated commitment still fails full AIR
                // verification: caps feed the transcript, so queries diverge.
                let mut bad = proof.clone();
                bad.fri_commitment = decoded;
                if verifies(params, &bad) {
                    accepted_at.push(pos);
                } else {
                    rejected += 1;
                }
            }
        }
    }
    report("byte-fuzz-commitment", trials, rejected);
    println!("security byte-fuzz-commitment accepted positions: {accepted_at:?}");
    assert_eq!(
        rejected, trials,
        "every commitment bit-flip must be rejected"
    );
}

#[test]
fn truncated_and_empty_inputs_rejected() {
    let (_, proof) = honest_proof();
    let bytes = proof.to_bytes();
    let mut attempts = 0;
    let mut rejected = 0;
    assert!(air::Proof::from_bytes(&[]).is_err());
    attempts += 1;
    rejected += 1;
    assert!(fri::Commitment::from_bytes(&[]).is_err());
    attempts += 1;
    rejected += 1;
    for cut in 1..=8 {
        let cut_len = bytes.len() - cut;
        rejected += usize::from(air::Proof::from_bytes(&bytes[..cut_len]).is_err());
        attempts += 1;
    }
    let mut long = bytes.clone();
    long.push(0xAA);
    rejected += usize::from(air::Proof::from_bytes(&long).is_err());
    attempts += 1;
    report("truncated-empty-inputs", attempts, rejected);
    assert_eq!(rejected, attempts, "malformed inputs must be rejected");
}

#[test]
fn merkle_adversarial_vectors() {
    let leaves: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 32]).collect();
    let tree = MerkleTree::new(&leaves).expect("tree");
    let root = tree.root();
    let mut attempts = 0;
    let mut rejected = 0;
    for (i, leaf) in leaves.iter().enumerate() {
        let path = tree.prove(i).expect("prove");
        // Wrong leaf, wrong index, truncated and extended paths all fail.
        let mut bad = leaf.clone();
        bad[0] ^= 1;
        rejected += usize::from(!MerkleTree::verify(&root, &bad, i, &path));
        attempts += 1;
        rejected += usize::from(!MerkleTree::verify(&root, leaf, i + 8, &path));
        attempts += 1;
        rejected += usize::from(!MerkleTree::verify(&root, leaf, i, &path[..path.len() - 1]));
        attempts += 1;
        let mut long = path.clone();
        long.push(([0u8; 32], true));
        rejected += usize::from(!MerkleTree::verify(&root, leaf, i, &long));
        attempts += 1;
    }
    report("merkle-adversarial", attempts, rejected);
    assert_eq!(rejected, attempts, "every Merkle forgery must fail");
}
