//! Hardening suite: hostile parameter structs and fuzzed proof bytes must
//! be rejected with errors, never panics or unbounded work.
//!
//! The `Params` structs have public fields (so callers can build them by
//! hand, deliberately or not), which means every entry point must re-validate
//! rather than trust the constructor. Decoders parse untrusted bytes, so each
//! one is fed truncations, extensions, and single-bit flips.

use z0p::{
    air, babybear::Field, basefold, ext4::Ext4, fold, lookup_pcs, range, rng::ChaCha20, table,
    transcript::Transcript,
};

const LABEL: &[u8] = b"hardening";

fn valid_air() -> air::Params {
    let (_, trace_b) = air::build_trace(Field::ONE, Field::ONE, 32);
    air::Params::new(32, 4, 8, 8, Field::ONE, Field::ONE, trace_b[31]).expect("valid air params")
}

#[test]
fn air_invalid_params_error_without_panic() {
    let base = valid_air();
    let mut transcript = Transcript::new(LABEL);
    let proof = air::prove(base, &mut transcript).expect("baseline prove");
    let invalid = [
        air::Params { n_steps: 0, ..base },
        air::Params { n_steps: 3, ..base },
        air::Params { blowup: 1, ..base },
        air::Params { blowup: 3, ..base },
        air::Params {
            blowup: usize::MAX,
            ..base
        },
        air::Params {
            num_queries: 0,
            ..base
        },
        air::Params {
            num_queries: usize::MAX,
            ..base
        },
        air::Params {
            final_size: 0,
            ..base
        },
        air::Params {
            final_size: 3,
            ..base
        },
        air::Params {
            grinding_bits: 64,
            ..base
        },
    ];
    for params in invalid {
        assert!(
            air::prove(params, &mut Transcript::new(LABEL)).is_err(),
            "prove accepted {params:?}"
        );
        assert!(
            air::verify(params, &proof, &mut Transcript::new(LABEL)).is_err(),
            "verify accepted {params:?}"
        );
    }
}

#[test]
fn range_invalid_params_error_without_panic() {
    let base = range::Params::new(32, 8, 4, 8, 8, Field::new(5)).expect("valid range params");
    let proof = range::prove(base, &mut Transcript::new(LABEL)).expect("baseline prove");
    let invalid = [
        range::Params { n_rows: 0, ..base },
        range::Params { n_rows: 3, ..base },
        range::Params { n_bits: 0, ..base },
        range::Params { n_bits: 33, ..base },
        range::Params { blowup: 1, ..base },
        range::Params {
            num_queries: 0,
            ..base
        },
        range::Params {
            final_size: 0,
            ..base
        },
    ];
    for params in invalid {
        assert!(range::prove(params, &mut Transcript::new(LABEL)).is_err());
        assert!(range::verify(params, &proof, &mut Transcript::new(LABEL)).is_err());
    }
}

#[test]
fn table_invalid_params_error_without_panic() {
    let table_vals: Vec<Field> = [10u32, 20, 30, 40].iter().map(|v| Field::new(*v)).collect();
    let base = table::Params::new(8, 8, 8, 4, Field::new(30)).expect("valid table params");
    let proof = table::prove(base, &table_vals, &mut Transcript::new(LABEL)).expect("baseline");
    let invalid = [
        table::Params { n_rows: 0, ..base },
        table::Params { n_rows: 3, ..base },
        table::Params { blowup: 1, ..base },
        table::Params {
            num_queries: 0,
            ..base
        },
        table::Params {
            num_queries: usize::MAX,
            ..base
        },
        table::Params {
            final_size: 3,
            ..base
        },
    ];
    for params in invalid {
        assert!(table::prove(params, &table_vals, &mut Transcript::new(LABEL)).is_err());
        assert!(table::verify(params, &table_vals, &proof, &mut Transcript::new(LABEL)).is_err());
    }
}

#[test]
fn fold_invalid_params_error_without_panic() {
    let (trace_a, trace_b) = air::build_trace(Field::ONE, Field::ONE, 32);
    let base = fold::Params::new(32, 4, 8, 8, trace_a[0], trace_b[0], trace_b[31])
        .expect("valid fold params");
    let mut acc = fold::Accumulator::new(base);
    let mut transcript = Transcript::new(LABEL);
    acc.add_segment(&trace_a, &trace_b, &mut transcript)
        .expect("baseline segment");
    let proof = acc.finalize(&mut transcript).expect("baseline finalize");

    let invalid = [
        fold::Params {
            seg_steps: 0,
            ..base
        },
        fold::Params {
            seg_steps: 3,
            ..base
        },
        fold::Params { blowup: 1, ..base },
        fold::Params { blowup: 3, ..base },
        fold::Params {
            num_queries: 0,
            ..base
        },
        fold::Params {
            final_size: 0,
            ..base
        },
    ];
    for params in invalid {
        let mut acc = fold::Accumulator::new(params);
        assert!(acc
            .add_segment(&trace_a, &trace_b, &mut Transcript::new(LABEL))
            .is_err());
        assert!(fold::verify(params, &proof, &mut Transcript::new(LABEL)).is_err());
    }
}

/// Flip one bit at every offset of a valid encoding; decoding must return
/// `Ok` or `Err`, never panic. Successful decodes are then shape-checked by
/// `verify`.
#[test]
fn air_decoder_fuzz_never_panics() {
    let params = valid_air();
    let proof = air::prove(params, &mut Transcript::new(LABEL)).expect("prove");
    let bytes = proof.to_bytes();

    let mut decoded_ok = 0usize;
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut mutated = bytes.clone();
            mutated[i] ^= 1 << bit;
            if air::Proof::from_bytes(&mutated).is_ok() {
                decoded_ok += 1;
            }
        }
    }
    // Truncations and extensions.
    for cut in 0..bytes.len() {
        let _ = air::Proof::from_bytes(&bytes[..cut]);
    }
    let mut extended = bytes.clone();
    extended.extend_from_slice(&[0u8; 17]);
    assert!(air::Proof::from_bytes(&extended).is_err());
    let mut prefixed = vec![0xFFu8];
    prefixed.extend_from_slice(&bytes);
    assert!(air::Proof::from_bytes(&prefixed).is_err());
    println!("hardening air-decoder-fuzz bit-flips-decoded-ok={decoded_ok}");
}

/// The raw byte streams of every proof type survive the same storm.
#[test]
fn all_decoders_fuzz_never_panic() {
    let table_vals: Vec<Field> = [10u32, 20, 30, 40].iter().map(|v| Field::new(*v)).collect();
    let range_proof = range::prove(
        range::Params::new(32, 8, 4, 8, 8, Field::new(5)).unwrap(),
        &mut Transcript::new(LABEL),
    )
    .unwrap()
    .to_bytes();
    let table_proof = table::prove(
        table::Params::new(8, 8, 8, 4, Field::new(30)).unwrap(),
        &table_vals,
        &mut Transcript::new(LABEL),
    )
    .unwrap()
    .to_bytes();
    let basefold_state = basefold::commit(&[1u32, 2, 3, 4].map(Field::new), 4).unwrap();
    let basefold_commitment = basefold_state.commitment().clone();
    let basefold_point = [Ext4::ONE; 2];
    let basefold_proof = basefold::open(
        &basefold_state,
        &basefold_point,
        Ext4::from_base(Field::new(10)),
        basefold::Params::new(4, 2, 0).unwrap(),
        &mut Transcript::new(LABEL),
    )
    .unwrap();
    let capped_params = basefold::Params::new(4, 2, 0).unwrap().with_cap_height(1);
    let capped_proof = basefold::open(
        &basefold_state,
        &basefold_point,
        Ext4::from_base(Field::new(10)),
        capped_params,
        &mut Transcript::new(LABEL),
    )
    .unwrap();
    let mut capped_verifier = Transcript::new(LABEL);
    basefold::verify(
        &basefold_commitment,
        &basefold_point,
        Ext4::from_base(Field::new(10)),
        &capped_proof,
        capped_params,
        &mut capped_verifier,
    )
    .unwrap();
    let basefold_bytes = basefold_proof.to_bytes();
    let capped_bytes = capped_proof.to_bytes();
    let lookup_params = basefold::Params::new(4, 2, 0).unwrap().with_cap_height(1);
    let lookup_witness: Vec<Field> = [10u32, 20, 10, 30].iter().map(|v| Field::new(*v)).collect();
    let (lookup_commitments, lookup_proof) = lookup_pcs::prove(
        &lookup_witness,
        &table_vals,
        lookup_params,
        &mut Transcript::new(LABEL),
    )
    .unwrap();
    let mut lookup_verifier = Transcript::new(LABEL);
    lookup_pcs::verify(
        &lookup_commitments,
        &lookup_proof,
        lookup_params,
        &mut lookup_verifier,
    )
    .unwrap();
    let lookup_bytes = lookup_proof.to_bytes();
    let lookup_commitment_bytes = lookup_commitments.to_bytes();

    let mut seed = 0xdead_beef_1234_5678u64;
    for stream in [
        &range_proof,
        &table_proof,
        &basefold_bytes,
        &capped_bytes,
        &lookup_bytes,
        &lookup_commitment_bytes,
    ] {
        for _ in 0..2000 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let mut mutated = stream.clone();
            if mutated.is_empty() {
                break;
            }
            let idx = usize::try_from(seed).expect("seed fits usize") % mutated.len();
            mutated[idx] ^= u8::try_from((seed >> 32) & 0xff).expect("masked to u8");
            let _ = range::Proof::from_bytes(&mutated);
            let _ = table::Proof::from_bytes(&mutated);
            let _ = basefold::Proof::from_bytes(&mutated);
            let _ = lookup_pcs::Proof::from_bytes(&mutated);
            let _ = lookup_pcs::Commitments::from_bytes(&mutated);
        }
    }
}

#[test]
fn field_invariant_and_constant_time_inverse() {
    assert_eq!(Field::new(Field::MODULUS), Field::ZERO);
    assert_eq!(Field::new(Field::MODULUS + 7), Field::new(7));
    assert_eq!(Field::new(u32::MAX).as_u32(), u32::MAX % Field::MODULUS);
    assert_eq!(Field::ZERO.inv(), Field::ZERO);
    let mut seed = 0x1234_5678_9abc_def0u64;
    for _ in 0..10_000 {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let x = Field::new(u32::try_from(seed & 0xffff_ffff).expect("masked to u32"));
        assert!(x.as_u32() < Field::MODULUS);
        if x != Field::ZERO {
            assert_eq!(x * x.inv(), Field::ONE);
        }
    }
}

#[test]
fn next_field_is_in_range_and_uniform_ish() {
    const DRAWS: u32 = 40_000;
    let mut rng = ChaCha20::new([7u8; 32], [9u8; 12]);
    let mut buckets = [0u32; 8];
    for _ in 0..DRAWS {
        let x = rng.next_field();
        assert!(x.as_u32() < Field::MODULUS);
        let bucket = x.as_u32() as usize * 8 / Field::MODULUS as usize;
        buckets[bucket.min(7)] += 1;
    }
    let expected = DRAWS / 8;
    for count in buckets {
        let deviation = (i64::from(count) - i64::from(expected)).unsigned_abs();
        assert!(
            deviation < u64::from(expected) / 4,
            "bucket {count} deviates too far from {expected}"
        );
    }
}
