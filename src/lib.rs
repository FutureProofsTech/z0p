//! `z0p`: from-scratch zero-knowledge core with zero dependencies.
//!
//! Layers owned 100% by this crate:
//! - [`gf2`]: binary fields `GF(2^8)`, `GF(2^64)`, `GF(2^128)` for word ops.
//! - [`babybear`]: NTT-friendly prime field for the FRI domain.
//! - [`hash`]: SHA3-256 from the FIPS 202 spec.
//! - [`transcript`]: Fiat-Shamir transcript over SHA3-256.
//! - [`merkle`]: domain-separated binary Merkle tree.
//! - [`ntt`]: Cooley-Tukey NTT over [`babybear`].
//! - [`par`]: data parallelism over `std::thread::scope` (no dependencies).
//! - [`fri`]: FRI polynomial-commitment (commit / open / verify).
//! - [`mle`]: multilinear polynomials in hypercube-evaluation form.
//! - [`sumcheck`]: interactive sumcheck over [`mle`] products.
//! - [`lookup`]: `LogUp`-style table-membership argument via [`sumcheck`].
//! - [`air`]: minimal Fibonacci AIR/STARK end-to-end over [`fri`].
//! - [`range`]: range-check AIR (bit decomposition over committed columns).
//! - [`fold`]: hash-based folding/IVC accumulation with one batched FRI.
//! - [`rng`]: `ChaCha20` (RFC 8439) CSPRNG plus OS seeding.
//! - [`blind`]: hiding layer — vanishing-multiple masking for ZK proofs.
//! - [`table`]: table-membership AIR (vanishing product over committed data).
//!
//! # Platinum rules enforced in this crate
//! - `#![forbid(unsafe_code)]`: no `unsafe` anywhere.
//! - `cargo fmt --check` clean.
//! - `cargo clippy --all-targets -- -D warnings` clean (pedantic).
//! - No `unwrap`/`expect`/`panic` on public paths: fallible APIs return [`error::Error`].
//! - Every public item documented, `#[must_use]` on pure constructors.
//!
//! # Soundness posture
//! Hash-based and transparent (no trusted setup, no elliptic curves): the
//! plausibly post-quantum STARK family. Concrete bits come from the FRI
//! rate, the query count, and the proof-of-work difficulty — see the
//! [`fri`] soundness notes for the sizing table. Bench defaults are fast
//! but weak (`~18` conjectured bits); production callers want blowup `16`,
//! `40` queries, and `20`-bit grinding (`~100` conjectured bits), set via
//! `Params::with_grinding_bits` on [`fri`], [`air`], [`range`], [`table`],
//! and [`fold`].
//!
//! # Example
//! ```
//! use z0p::gf2::F64;
//! let a = F64::new(7);
//! // Addition is XOR; multiplication is carryless.
//! assert_eq!(a + a, F64::ZERO);
//! assert_eq!(a * F64::ONE, a);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(clippy::all, clippy::pedantic)]

pub mod air;
pub mod babybear;
pub mod blind;
mod codec;
pub mod error;
pub mod fold;
pub mod fri;
pub mod gf2;
pub mod hash;
pub mod lookup;
pub mod merkle;
pub mod mle;
pub mod ntt;
pub mod par;
pub mod range;
pub mod rng;
pub mod sumcheck;
pub mod table;
pub mod transcript;

pub use error::{Error, Result};
