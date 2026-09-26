//! Speed + size benchmarks for `z0p` (zero dependencies).
//!
//! Run with `cargo bench`. Reports median wall time for prove/verify and
//! exact wire sizes in bytes (`to_bytes` length, asserted equal every run:
//! 1-byte version, `u32` counts, 4 B per field, 8 B per index/nonce,
//! 32 B per digest, 33 B per Merkle path step).
//!
//! Every benchmark verifies its proof once outside the timed region, so a
//! passing run also gates correctness.

use std::hint::black_box;
use std::time::Instant;

use z0p::{
    air, babybear::Field, fold, fri, gf2::F64, hash::blake3_256, lookup, merkle, ntt, range, table,
    transcript::Transcript,
};

/// Median of per-iteration milliseconds over `reps` runs (plus one warmup).
fn median_ms<F>(reps: usize, mut work: F) -> f64
where
    F: FnMut(),
{
    work();
    let mut samples = Vec::with_capacity(reps);
    for _ in 0..reps {
        let start = Instant::now();
        work();
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    samples[reps / 2]
}

// Small exact values stay far below 2^53; float conversion is lossless.
#[allow(clippy::cast_precision_loss)]
fn kb(bytes: usize) -> f64 {
    bytes as f64 / 1024.0
}

fn path_bytes(path: &[([u8; 32], bool)]) -> usize {
    path.len() * 33
}

fn fri_proof_body_bytes(proof: &fri::Proof) -> usize {
    // Mirrors `Proof::write_body` exactly: counts, fields, nonce, and
    // 33 bytes per path step.
    let mut total = 4 + 4 * proof.final_poly.len() + 8 + 4;
    for query in &proof.queries {
        total += 4;
        for fold in &query.folds {
            total += 4 * 4 + 4 + path_bytes(&fold.path);
        }
    }
    total
}

fn fri_proof_bytes(proof: &fri::Proof) -> usize {
    1 + fri_proof_body_bytes(proof)
}

fn fri_commitment_body_bytes(commitment: &fri::Commitment) -> usize {
    // Three dimensions, cap counts, then the digests.
    let mut total = 8 + 8 + 8 + 4;
    for cap in &commitment.caps {
        total += 4 + 32 * cap.len();
    }
    total
}

fn fri_commitment_bytes(commitment: &fri::Commitment) -> usize {
    1 + fri_commitment_body_bytes(commitment)
}

fn air_proof_bytes(proof: &air::Proof) -> usize {
    let mut total = 1
        + 4
        + 32 * proof.column_cap.len()
        + 4
        + fri_commitment_body_bytes(&proof.fri_commitment)
        + fri_proof_body_bytes(&proof.fri_proof);
    for opening in &proof.openings {
        total += 8 + 16 + 4 + path_bytes(&opening.path);
    }
    total
}

fn range_proof_bytes(proof: &range::Proof) -> usize {
    let mut total = 1
        + 4
        + 32 * proof.column_cap.len()
        + 4
        + fri_commitment_body_bytes(&proof.fri_commitment)
        + fri_proof_body_bytes(&proof.fri_proof);
    for opening in &proof.openings {
        // Index, value, bits count, bits, path count, then steps.
        total += 8 + 4 + 4 + 4 * opening.bits.len() + 4 + path_bytes(&opening.path);
    }
    total
}

fn table_proof_bytes(proof: &table::Proof) -> usize {
    let mut total = 1
        + 4
        + 32 * proof.column_cap.len()
        + 4
        + fri_commitment_body_bytes(&proof.fri_commitment)
        + fri_proof_body_bytes(&proof.fri_proof);
    for opening in &proof.openings {
        total += 8 + 4 + 4 + path_bytes(&opening.path);
    }
    total
}

fn sumcheck_proof_bytes(proof: &z0p::sumcheck::Proof) -> usize {
    let mut total = 4;
    for round in &proof.round_evals {
        total += 4 * round.len();
    }
    total += 4 * proof.final_values.len();
    total
}

fn lookup_proof_bytes(proof: &lookup::Proof) -> usize {
    4 + 4 * proof.multiplicities.len()
        + 4 * proof.quot_w.len()
        + 4 * proof.quot_t.len()
        + 8
        + sumcheck_proof_bytes(&proof.sc_sum_w)
        + sumcheck_proof_bytes(&proof.sc_read_w)
        + sumcheck_proof_bytes(&proof.sc_sum_t)
        + sumcheck_proof_bytes(&proof.sc_read_t)
}

fn fold_proof_bytes(proof: &fold::IvcProof) -> usize {
    let mut total = 1
        + 4
        + fri_commitment_body_bytes(&proof.fri_commitment)
        + fri_proof_body_bytes(&proof.fri_proof);
    for step in &proof.steps {
        total += 16 + 4 + 32 * step.column_cap.len() + 4;
        for opening in &step.openings {
            total += 8 + 16 + 4 + path_bytes(&opening.path);
        }
    }
    total
}

fn bench_sha3() {
    let data = vec![0x5au8; 1 << 20];
    let throughput = median_ms(3, || {
        black_box(blake3_256(black_box(&data)));
    });
    #[allow(clippy::cast_precision_loss)]
    let mb_s = 1.0 / (throughput / 1000.0);
    println!("blake3 1MiB       : {throughput:8.2} ms  ({mb_s:.1} MB/s)");
}

fn bench_f64_mul() {
    let ops = 1_000_000usize;
    let ms = median_ms(5, || {
        let mut acc = F64::new(0x1234_5678_9abc_def1);
        let b = F64::new(0xdead_beef_cafe_f00d);
        for _ in 0..ops {
            acc = black_box(acc * b) + F64::ONE;
        }
        black_box(acc);
    });
    #[allow(clippy::cast_precision_loss)]
    let mops = ops as f64 / (ms / 1000.0) / 1e6;
    println!("gf2 F64 mul        : {ms:8.2} ms for 1M ops  ({mops:.1} Mops/s)");
}

fn bench_field_mul() {
    let ops = 1_000_000usize;
    let ms = median_ms(5, || {
        let mut acc = Field::new(0x1234_5678);
        let b = Field::new(0x9e37_79b9);
        for _ in 0..ops {
            acc = black_box(acc * b) + Field::ONE;
        }
        black_box(acc);
    });
    #[allow(clippy::cast_precision_loss)]
    let mops = ops as f64 / (ms / 1000.0) / 1e6;
    println!("bb field mul       : {ms:8.2} ms for 1M ops  ({mops:.1} Mops/s)");
}

fn bench_ntt() {
    let n = 1usize << 14;
    let ms = median_ms(5, || {
        let mut values = vec![Field::ONE; n];
        for (i, value) in values.iter_mut().enumerate() {
            *value = Field::new(
                u32::try_from(i)
                    .expect("bench size fits u32")
                    .wrapping_mul(0x9e37_79b9),
            );
        }
        ntt::forward(black_box(&mut values)).expect("ntt domain");
        black_box(values);
    });
    println!("ntt forward 2^14   : {ms:8.2} ms");
}

fn bench_fri() {
    let params = fri::Params::new(4, 12, 4).expect("params");
    let coeffs: Vec<Field> = (0..256).map(|i| Field::new(i * 0x9e37_79b9 + 17)).collect();
    let mut prover_t = Transcript::new(b"bench/fri");
    let state = fri::commit(black_box(&coeffs), params, &mut prover_t).expect("commit");
    let commitment = fri::public_commitment(&state);
    let (proof, _) = fri::open(&state, &mut prover_t).expect("open");
    let mut verifier_t = Transcript::new(b"bench/fri");
    fri::verify(&commitment, &proof, params, &mut verifier_t).expect("verify");

    let prove_ms = median_ms(7, || {
        let mut prover_t = Transcript::new(b"bench/fri");
        let state = fri::commit(black_box(&coeffs), params, &mut prover_t).expect("commit");
        black_box(fri::open(&state, &mut prover_t).expect("open").0);
    });
    let verify_ms = median_ms(11, || {
        let mut transcript = Transcript::new(b"bench/fri");
        let ok = fri::verify(&commitment, &proof, params, &mut transcript).is_ok();
        assert!(ok);
        black_box(ok);
    });
    let bytes = fri_commitment_bytes(&commitment) + fri_proof_bytes(&proof);
    assert_eq!(
        bytes,
        commitment.to_bytes().len() + proof.to_bytes().len(),
        "byte counter must match the wire format"
    );
    println!(
        "fri poly256 B4 Q12: prove {prove_ms:8.2} ms  verify {verify_ms:8.2} ms  proof {bytes} B ({:.1} KiB)",
        kb(bytes)
    );
}

fn bench_air() {
    let (_, trace_b) = air::build_trace(Field::ONE, Field::ONE, 64);
    let b_last = trace_b[63];
    let params = air::Params::new(64, 8, 12, 8, Field::ONE, Field::ONE, b_last).expect("params");
    let mut transcript = Transcript::new(b"bench/air");
    let proof = air::prove(params, &mut transcript).expect("prove");
    let mut transcript = Transcript::new(b"bench/air");
    air::verify(params, &proof, &mut transcript).expect("verify");

    let prove_ms = median_ms(7, || {
        let mut transcript = Transcript::new(b"bench/air");
        black_box(air::prove(params, &mut transcript).expect("prove"));
    });
    let verify_ms = median_ms(11, || {
        let mut transcript = Transcript::new(b"bench/air");
        let ok = air::verify(params, &proof, &mut transcript).is_ok();
        assert!(ok);
        black_box(ok);
    });
    let bytes = air_proof_bytes(&proof);
    assert_eq!(
        bytes,
        proof.to_bytes().len(),
        "byte counter must match the wire format"
    );
    println!(
        "air fib64          : prove {prove_ms:8.2} ms  verify {verify_ms:8.2} ms  proof {bytes} B ({:.1} KiB)",
        kb(bytes)
    );
}

fn bench_range() {
    let params = range::Params::new(8, 16, 8, 8, 4, Field::new(12_345)).expect("params");
    let mut transcript = Transcript::new(b"bench/range");
    let proof = range::prove(params, &mut transcript).expect("prove");
    let mut transcript = Transcript::new(b"bench/range");
    range::verify(params, &proof, &mut transcript).expect("verify");

    let prove_ms = median_ms(11, || {
        let mut transcript = Transcript::new(b"bench/range");
        black_box(range::prove(params, &mut transcript).expect("prove"));
    });
    let verify_ms = median_ms(21, || {
        let mut transcript = Transcript::new(b"bench/range");
        let ok = range::verify(params, &proof, &mut transcript).is_ok();
        assert!(ok);
        black_box(ok);
    });
    let bytes = range_proof_bytes(&proof);
    assert_eq!(
        bytes,
        proof.to_bytes().len(),
        "byte counter must match the wire format"
    );
    assert_eq!(
        bytes,
        proof.to_bytes().len(),
        "byte counter must match the wire format"
    );
    println!(
        "range 16-bit       : prove {prove_ms:8.2} ms  verify {verify_ms:8.2} ms  proof {bytes} B ({:.1} KiB)",
        kb(bytes)
    );
}

fn bench_table() {
    let table: Vec<Field> = [10, 20, 30, 40].iter().map(|v| Field::new(*v)).collect();
    let params = table::Params::new(8, 8, 8, 4, Field::new(30)).expect("params");
    let mut transcript = Transcript::new(b"bench/table");
    let proof = table::prove(params, &table, &mut transcript).expect("prove");
    let mut transcript = Transcript::new(b"bench/table");
    table::verify(params, &table, &proof, &mut transcript).expect("verify");

    let prove_ms = median_ms(11, || {
        let mut transcript = Transcript::new(b"bench/table");
        black_box(table::prove(params, black_box(&table), &mut transcript).expect("prove"));
    });
    let verify_ms = median_ms(21, || {
        let mut transcript = Transcript::new(b"bench/table");
        let ok = table::verify(params, &table, &proof, &mut transcript).is_ok();
        assert!(ok);
        black_box(ok);
    });
    let bytes = table_proof_bytes(&proof);
    assert_eq!(
        bytes,
        proof.to_bytes().len(),
        "byte counter must match the wire format"
    );
    println!(
        "table 4-entry      : prove {prove_ms:8.2} ms  verify {verify_ms:8.2} ms  proof {bytes} B ({:.1} KiB)",
        kb(bytes)
    );
}

fn bench_lookup() {
    let table: Vec<Field> = (0..16).map(Field::new).collect();
    let witness: Vec<Field> = (0..64).map(|i| table[i % 16]).collect();
    let mut transcript = Transcript::new(b"bench/lookup");
    let proof =
        lookup::prove(black_box(&witness), black_box(&table), &mut transcript).expect("prove");
    let mut transcript = Transcript::new(b"bench/lookup");
    lookup::verify(&witness, &table, &proof, &mut transcript).expect("verify");

    let prove_ms = median_ms(7, || {
        let mut transcript = Transcript::new(b"bench/lookup");
        black_box(lookup::prove(&witness, &table, &mut transcript).expect("prove"));
    });
    let verify_ms = median_ms(11, || {
        let mut transcript = Transcript::new(b"bench/lookup");
        let ok = lookup::verify(&witness, &table, &proof, &mut transcript).is_ok();
        assert!(ok);
        black_box(ok);
    });
    let bytes = lookup_proof_bytes(&proof);
    println!(
        "lookup 64-in-16    : prove {prove_ms:8.2} ms  verify {verify_ms:8.2} ms  proof {bytes} B ({:.1} KiB)",
        kb(bytes)
    );
}

fn bench_fold() {
    let build = || {
        let mut segments = Vec::new();
        let (mut a, mut b) = (Field::ONE, Field::ONE);
        for _ in 0..4 {
            let (col_a, col_b) = air::build_trace(a, b, 8);
            a = col_a[7];
            b = col_b[7];
            segments.push((col_a, col_b));
        }
        segments
    };
    let segments = build();
    let out_b = segments[3].1[7];
    let params = fold::Params::new(8, 8, 8, 4, Field::ONE, Field::ONE, out_b).expect("params");
    let mut transcript = Transcript::new(b"bench/fold");
    let mut acc = fold::Accumulator::new(params);
    for (col_a, col_b) in &segments {
        acc.add_segment(col_a, col_b, &mut transcript)
            .expect("segment");
    }
    let proof = acc.finalize(&mut transcript).expect("finalize");
    let mut transcript = Transcript::new(b"bench/fold");
    fold::verify(params, &proof, &mut transcript).expect("verify");

    let prove_ms = median_ms(7, || {
        let segments = build();
        let mut transcript = Transcript::new(b"bench/fold");
        let mut acc = fold::Accumulator::new(params);
        for (col_a, col_b) in &segments {
            acc.add_segment(col_a, col_b, &mut transcript)
                .expect("segment");
        }
        black_box(acc.finalize(&mut transcript).expect("finalize"));
    });
    let verify_ms = median_ms(11, || {
        let mut transcript = Transcript::new(b"bench/fold");
        let ok = fold::verify(params, &proof, &mut transcript).is_ok();
        assert!(ok);
        black_box(ok);
    });
    let bytes = fold_proof_bytes(&proof);
    assert_eq!(
        bytes,
        proof.to_bytes().len(),
        "byte counter must match the wire format"
    );
    println!(
        "fold 4x8 fib       : prove {prove_ms:8.2} ms  verify {verify_ms:8.2} ms  proof {bytes} B ({:.1} KiB)",
        kb(bytes)
    );
}

fn bench_merkle() {
    let leaves: Vec<Vec<u8>> = (0..65536)
        .map(|i| {
            u32::try_from(i)
                .expect("bench range")
                .to_le_bytes()
                .to_vec()
        })
        .collect();
    let ms = median_ms(3, || {
        black_box(merkle::MerkleTree::new(black_box(&leaves)).expect("tree"));
    });
    println!("merkle 64k leaves : {ms:8.2} ms");
}

/// Production shape via `for_security(100)`: blowup 16, queries plus
/// 20-bit grinding, size-optimal final size and cap.
fn bench_fri_production() {
    let params = fri::Params::for_security(256, 100).expect("params");
    let coeffs: Vec<Field> = (0..256).map(|i| Field::new(i * 0x9e37_79b9 + 17)).collect();
    let mut prover_t = Transcript::new(b"bench/fri-prod");
    let state = fri::commit(black_box(&coeffs), params, &mut prover_t).expect("commit");
    let commitment = fri::public_commitment(&state);
    let (proof, _) = fri::open(&state, &mut prover_t).expect("open");
    let mut verifier_t = Transcript::new(b"bench/fri-prod");
    fri::verify(&commitment, &proof, params, &mut verifier_t).expect("verify");

    let prove_ms = median_ms(2, || {
        let mut prover_t = Transcript::new(b"bench/fri-prod");
        let state = fri::commit(black_box(&coeffs), params, &mut prover_t).expect("commit");
        black_box(fri::open(&state, &mut prover_t).expect("open").0);
    });
    let verify_ms = median_ms(3, || {
        let mut transcript = Transcript::new(b"bench/fri-prod");
        let ok = fri::verify(&commitment, &proof, params, &mut transcript).is_ok();
        assert!(ok);
        black_box(ok);
    });
    let bytes = fri_commitment_bytes(&commitment) + fri_proof_bytes(&proof);
    assert_eq!(
        bytes,
        commitment.to_bytes().len() + proof.to_bytes().len(),
        "byte counter must match the wire format"
    );
    println!(
        "fri prod B{}Q{}G{}C{}F{}: prove {prove_ms:8.2} ms  verify {verify_ms:8.2} ms  proof {bytes} B ({:.1} KiB)",
        params.blowup,
        params.num_queries,
        params.grinding_bits,
        params.cap_height,
        params.final_size,
        kb(bytes)
    );
}

/// Production shape AIR via `for_security(100)` over fib64.
fn bench_air_production() {
    let (_, trace_b) = air::build_trace(Field::ONE, Field::ONE, 64);
    let b_last = trace_b[63];
    let params =
        air::Params::for_security(64, Field::ONE, Field::ONE, b_last, 100).expect("params");
    let mut transcript = Transcript::new(b"bench/air-prod");
    let proof = air::prove(params, &mut transcript).expect("prove");
    let mut transcript = Transcript::new(b"bench/air-prod");
    air::verify(params, &proof, &mut transcript).expect("verify");

    let prove_ms = median_ms(2, || {
        let mut transcript = Transcript::new(b"bench/air-prod");
        black_box(air::prove(params, &mut transcript).expect("prove"));
    });
    let verify_ms = median_ms(3, || {
        let mut transcript = Transcript::new(b"bench/air-prod");
        let ok = air::verify(params, &proof, &mut transcript).is_ok();
        assert!(ok);
        black_box(ok);
    });
    let bytes = air_proof_bytes(&proof);
    assert_eq!(
        bytes,
        proof.to_bytes().len(),
        "byte counter must match the wire format"
    );
    println!(
        "air prod B{}Q{}G{}C{}F{}: prove {prove_ms:8.2} ms  verify {verify_ms:8.2} ms  proof {bytes} B ({:.1} KiB)",
        params.blowup,
        params.num_queries,
        params.grinding_bits,
        params.cap_height,
        params.final_size,
        kb(bytes)
    );
}

fn bench_air_big() {
    let (_, trace_b) = air::build_trace(Field::ONE, Field::ONE, 1024);
    let b_last = trace_b[1023];
    let params = air::Params::new(1024, 8, 12, 8, Field::ONE, Field::ONE, b_last).expect("params");
    let mut transcript = Transcript::new(b"bench/air1024");
    let proof = air::prove(params, &mut transcript).expect("prove");
    let mut transcript = Transcript::new(b"bench/air1024");
    air::verify(params, &proof, &mut transcript).expect("verify");

    let prove_ms = median_ms(2, || {
        let mut transcript = Transcript::new(b"bench/air1024");
        black_box(air::prove(params, &mut transcript).expect("prove"));
    });
    let verify_ms = median_ms(3, || {
        let mut transcript = Transcript::new(b"bench/air1024");
        let ok = air::verify(params, &proof, &mut transcript).is_ok();
        assert!(ok);
        black_box(ok);
    });
    let bytes = air_proof_bytes(&proof);
    assert_eq!(
        bytes,
        proof.to_bytes().len(),
        "byte counter must match the wire format"
    );
    println!(
        "air fib1024        : prove {prove_ms:8.2} ms  verify {verify_ms:8.2} ms  proof {bytes} B ({:.1} KiB)",
        kb(bytes)
    );
}

/// Production-shape AIR at scale via `for_security(100)`: the real
/// per-step numbers with grinding amortized over a large trace.
fn bench_air_scaled(n_steps: usize) {
    let (_, trace_b) = air::build_trace(Field::ONE, Field::ONE, n_steps);
    let b_last = trace_b[n_steps - 1];
    let params =
        air::Params::for_security(n_steps, Field::ONE, Field::ONE, b_last, 100).expect("params");
    let mut transcript = Transcript::new(b"bench/air-scale");
    let proof = air::prove(params, &mut transcript).expect("prove");
    let mut transcript = Transcript::new(b"bench/air-scale");
    air::verify(params, &proof, &mut transcript).expect("verify");

    let prove_ms = median_ms(2, || {
        let mut transcript = Transcript::new(b"bench/air-scale");
        black_box(air::prove(params, &mut transcript).expect("prove"));
    });
    let verify_ms = median_ms(3, || {
        let mut transcript = Transcript::new(b"bench/air-scale");
        let ok = air::verify(params, &proof, &mut transcript).is_ok();
        assert!(ok);
        black_box(ok);
    });
    let bytes = air_proof_bytes(&proof);
    assert_eq!(
        bytes,
        proof.to_bytes().len(),
        "byte counter must match the wire format"
    );
    println!(
        "air prod N{n_steps} B{}Q{}G{}C{}F{}: prove {prove_ms:8.2} ms  verify {verify_ms:8.2} ms  proof {bytes} B ({:.1} KiB)",
        params.blowup,
        params.num_queries,
        params.grinding_bits,
        params.cap_height,
        params.final_size,
        kb(bytes)
    );
}

/// Production-shape FRI over 1024 coefficients via `for_security(100)`.
fn bench_fri_production_big() {
    let params = fri::Params::for_security(1024, 100).expect("params");
    let coeffs: Vec<Field> = (0..1024)
        .map(|i| Field::new(i * 0x9e37_79b9 + 17))
        .collect();
    let mut prover_t = Transcript::new(b"bench/fri-prod-big");
    let state = fri::commit(black_box(&coeffs), params, &mut prover_t).expect("commit");
    let commitment = fri::public_commitment(&state);
    let (proof, _) = fri::open(&state, &mut prover_t).expect("open");
    let mut verifier_t = Transcript::new(b"bench/fri-prod-big");
    fri::verify(&commitment, &proof, params, &mut verifier_t).expect("verify");

    let prove_ms = median_ms(2, || {
        let mut prover_t = Transcript::new(b"bench/fri-prod-big");
        let state = fri::commit(black_box(&coeffs), params, &mut prover_t).expect("commit");
        black_box(fri::open(&state, &mut prover_t).expect("open").0);
    });
    let verify_ms = median_ms(3, || {
        let mut transcript = Transcript::new(b"bench/fri-prod-big");
        let ok = fri::verify(&commitment, &proof, params, &mut transcript).is_ok();
        assert!(ok);
        black_box(ok);
    });
    let bytes = fri_commitment_bytes(&commitment) + fri_proof_bytes(&proof);
    assert_eq!(
        bytes,
        commitment.to_bytes().len() + proof.to_bytes().len(),
        "byte counter must match the wire format"
    );
    println!(
        "fri prod P1024 B{}Q{}G{}C{}F{}: prove {prove_ms:8.2} ms  verify {verify_ms:8.2} ms  proof {bytes} B ({:.1} KiB)",
        params.blowup,
        params.num_queries,
        params.grinding_bits,
        params.cap_height,
        params.final_size,
        kb(bytes)
    );
}

/// Run `bench` when no filter is set or `name` contains it.
fn run_filtered(filter: &str, name: &str, bench: impl FnOnce()) {
    if filter.is_empty() || name.contains(filter) {
        bench();
    }
}

fn main() {
    println!("z0p speed/size (release profile, median of N runs)");
    println!("------------------------------------------------------------");
    // `BENCH_ROW=substr` runs only matching rows (profiling, iteration).
    let filter = std::env::var("BENCH_ROW").unwrap_or_default();
    run_filtered(&filter, "blake3", bench_sha3);
    run_filtered(&filter, "f64", bench_f64_mul);
    run_filtered(&filter, "field", bench_field_mul);
    run_filtered(&filter, "ntt", bench_ntt);
    run_filtered(&filter, "fri poly", bench_fri);
    run_filtered(&filter, "air fib64", bench_air);
    run_filtered(&filter, "range", bench_range);
    run_filtered(&filter, "table", bench_table);
    run_filtered(&filter, "lookup", bench_lookup);
    run_filtered(&filter, "fold", bench_fold);
    run_filtered(&filter, "merkle", bench_merkle);
    run_filtered(&filter, "air fib1024", bench_air_big);
    run_filtered(&filter, "fri prod B", bench_fri_production);
    run_filtered(&filter, "air prod B", bench_air_production);
    run_filtered(&filter, "fri prod P1024", bench_fri_production_big);
    run_filtered(&filter, "air prod N1024", || bench_air_scaled(1024));
    run_filtered(&filter, "air prod N8192", || bench_air_scaled(8192));
    run_filtered(&filter, "air prod N65536", || bench_air_scaled(65536));
    run_filtered(&filter, "air prod N1048576", || bench_air_scaled(1_048_576));
}
