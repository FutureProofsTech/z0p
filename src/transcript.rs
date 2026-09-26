//! Fiat-Shamir transcript over SHA3-256.
//!
//! Append-only and domain-separated: every [`Transcript::absorb`] frames the
//! label and the payload with 64-bit length prefixes, so distinct call
//! sequences can never collide. [`Transcript::squeeze`] feeds its own output
//! back into the log, binding later challenges to earlier ones.
//!
//! Challenge mapping into binary fields is uniform (every byte string is a
//! valid [`F64`]/[`F128`] element). Mapping into [`babybear`](crate::babybear)
//! uses reduction modulo `p`, which carries a `< 2^-31` uniformity bias;
//! see [`Transcript::challenge_bb`].
//!
//! # Domain-separation audit (all labels used by this crate)
//!
//! Cross-protocol collisions are impossible by prefix: `fri-*`, `fib/*`,
//! `range/*`, `table/*`, `fold/*`, `lookup/*`, `sumcheck/*`.
//!
//! Within a protocol, every label carries one payload type in a fixed
//! order on both sides, and repeats are counter-separated by
//! [`Transcript::squeeze`]:
//! - FRI: `fri-dims` (dimensions, first), `fri-layer-root` (cap digests), `fri-fold` (3 fold challenges
//!   per layer), `fri-final` (final poly), `fri-pow` (grinding nonce),
//!   `fri-query` (one index per query).
//! - AIR/range/table: `<proto>/params` (all parameters, first),
//!   `<proto>/column` (column cap), `<proto>/alpha` (one challenge per
//!   constraint class, fixed count).
//! - fold: `fold/params` (first), then per step `fold/step` (claims),
//!   `fold/trace` (column cap), five `fold/alpha`, and finally one
//!   `fold/gamma` per step — identical order prover and verifier.
//! - lookup: `lookup/ctx` (separator with distinct payloads
//!   `sum-w`/`read-w`/`sum-t`/`read-t`), then per-phase labels
//!   (`witness`, `table`, `sums`, `qw`, `qt`, `m`, `beta`,
//!   `beta-challenge`, `r1`, `r2`).
//! - sumcheck: `sumcheck/claim`, then per round `sumcheck/round` and
//!   `sumcheck/challenge`.
//!
//! Every protocol absorbs its parameters (or claims) before its first
//! challenge, so one transcript can serve sequential proofs safely —
//! each proof binds its own identity first, and verifiers must replay
//! the exact call sequence.

use crate::babybear::Field as Bb;
use crate::gf2::{F128, F64};
use crate::hash::{blake3_256, blake3_256_small, CHUNK_LEN};

/// Fiat-Shamir transcript: absorb statements, squeeze challenges.
#[derive(Clone, Debug)]
pub struct Transcript {
    log: Vec<u8>,
    counter: u64,
}

impl Transcript {
    /// Create a transcript bound to an application label.
    #[must_use]
    pub fn new(label: &[u8]) -> Self {
        let mut transcript = Self {
            log: Vec::new(),
            counter: 0,
        };
        transcript.absorb(b"domain", label);
        transcript
    }

    /// Absorb `(label, data)` with length-prefix framing.
    pub fn absorb(&mut self, label: &[u8], data: &[u8]) {
        self.log
            .extend_from_slice(&(label.len() as u64).to_le_bytes());
        self.log.extend_from_slice(label);
        self.log
            .extend_from_slice(&(data.len() as u64).to_le_bytes());
        self.log.extend_from_slice(data);
    }

    /// Absorb an [`F64`] word.
    pub fn absorb_f64(&mut self, label: &[u8], x: F64) {
        self.absorb(label, &x.to_le_bytes());
    }

    /// Absorb an [`F128`] element.
    pub fn absorb_f128(&mut self, label: &[u8], x: F128) {
        self.absorb(label, &x.to_le_bytes());
    }

    /// Absorb a [`Bb`] (`BabyBear`) element.
    pub fn absorb_bb(&mut self, label: &[u8], x: Bb) {
        self.absorb(label, &x.to_le_bytes());
    }

    /// Squeeze 32 raw challenge bytes.
    pub fn challenge_bytes(&mut self, label: &[u8]) -> [u8; 32] {
        self.squeeze_raw(label)
    }

    /// Squeeze a uniform [`F64`] challenge.
    pub fn challenge_f64(&mut self, label: &[u8]) -> F64 {
        let bytes = self.squeeze_raw(label);
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[..8]);
        F64::from_le_bytes(word)
    }

    /// Squeeze a uniform [`F128`] challenge.
    pub fn challenge_f128(&mut self, label: &[u8]) -> F128 {
        let bytes = self.squeeze_raw(label);
        let mut word = [0u8; 16];
        word.copy_from_slice(&bytes[..16]);
        F128::from_le_bytes(word)
    }

    /// Squeeze a [`Bb`] challenge via `u64 LE mod p`.
    ///
    /// The `2^64 mod p` bias is below `2^-31`; fine for FRI folding and query
    /// sampling, documented here so auditors see the assumption.
    pub fn challenge_bb(&mut self, label: &[u8]) -> Bb {
        let bytes = self.squeeze_raw(label);
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[..8]);
        Bb::from_u64(u64::from_le_bytes(word))
    }

    /// Squeeze a query index below `domain_size` (must be a power of two).
    ///
    /// Uses the low bits of the hash output, which is unbiased for
    /// power-of-two domains.
    pub fn challenge_index(&mut self, label: &[u8], domain_size: usize) -> usize {
        debug_assert!(domain_size.is_power_of_two());
        let bytes = self.squeeze_raw(label);
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[..8]);
        // Mask first in `u64`, then narrow: the masked value is `< domain_size`
        // (`<= 2^27` in this crate), so the narrowing cast is exact.
        #[allow(clippy::cast_possible_truncation)]
        let masked = (u64::from_le_bytes(word) & (domain_size as u64 - 1)) as usize;
        masked
    }

    fn squeeze_raw(&mut self, label: &[u8]) -> [u8; 32] {
        let mut input = Vec::with_capacity(self.log.len() + 16 + label.len());
        input.extend_from_slice(&self.log);
        input.extend_from_slice(&(label.len() as u64).to_le_bytes());
        input.extend_from_slice(label);
        input.extend_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        // The input buffer is needed as hash input either way; the
        // single-chunk path only skips the hasher's second copy.
        let out = if input.len() <= CHUNK_LEN {
            blake3_256_small(&input)
        } else {
            blake3_256(&input)
        };
        self.absorb(label, &out);
        out
    }

    /// Proof-of-work preimage head: digest of the full history plus label
    /// framing. Hashing the history once (instead of per nonce attempt)
    /// shrinks every attempt to tens of bytes; binding is unchanged, since
    /// both sides recompute the digest from matching histories and BLAKE3
    /// is collision-resistant.
    ///
    /// Both [`Transcript::grind`] and [`Transcript::verify_grind`] hash
    /// exactly `head || nonce_le`, so a nonce found by one checks on the
    /// other whenever the absorbed histories match.
    fn pow_head(&self, label: &[u8]) -> Vec<u8> {
        let history = blake3_256(&self.log);
        let mut head = Vec::with_capacity(32 + 8 + label.len());
        head.extend_from_slice(&history);
        head.extend_from_slice(&(label.len() as u64).to_le_bytes());
        head.extend_from_slice(label);
        head
    }

    /// Grind a proof-of-work nonce: smallest `u64` (little-endian) whose
    /// digest under the history commitment carries at least
    /// `difficulty_bits` leading zero bits (MSB-first).
    ///
    /// Prover work scales as `2^difficulty_bits` hashes; keep `<= 24` in
    /// production (`16` is seconds-friendly, `20` is the standard target).
    /// Attempts are allocation-free (short head, single-chunk path) and
    /// sharded across threads when the difficulty pays for spawning; the
    /// banded search returns exactly the nonce a sequential scan would, so
    /// results are identical at any thread count. The nonce is absorbed
    /// under `label`, binding every later challenge to the work.
    /// Deterministic over the transcript state: the same history always
    /// yields the same nonce.
    pub fn grind(&mut self, label: &[u8], difficulty_bits: u32) -> u64 {
        debug_assert!(difficulty_bits <= 32);
        let head = self.pow_head(label);
        let units = if difficulty_bits >= usize::BITS {
            usize::MAX
        } else {
            1usize << difficulty_bits
        };
        // Each attempt is sub-microsecond; demand milliseconds per thread.
        let workers = crate::par::worker_count(units, 4096);
        let nonce = if workers > 1 {
            grind_parallel(&head, difficulty_bits, workers)
        } else {
            grind_sequential(&head, difficulty_bits)
        };
        self.absorb(label, &nonce.to_le_bytes());
        nonce
    }

    /// Check a proof-of-work nonce from [`Transcript::grind`].
    ///
    /// Returns `false` (absorbing nothing) when the nonce misses the target
    /// under the current history. On success absorbs exactly as [`Transcript::grind`]
    /// does, so later challenges match the prover's transcript bit for bit.
    #[must_use]
    pub fn verify_grind(&mut self, label: &[u8], nonce: u64, difficulty_bits: u32) -> bool {
        if difficulty_bits > 256 {
            return false;
        }
        let head = self.pow_head(label);
        if leading_zero_bits(&pow_digest(&head, nonce)) < difficulty_bits {
            return false;
        }
        self.absorb(label, &nonce.to_le_bytes());
        true
    }
}

/// Digest of `head || nonce_le` without per-attempt allocation: short heads
/// stay on the single-chunk path.
fn pow_digest(head: &[u8], nonce: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(head.len() + 8);
    input.extend_from_slice(head);
    input.extend_from_slice(&nonce.to_le_bytes());
    if input.len() <= CHUNK_LEN {
        blake3_256_small(&input)
    } else {
        blake3_256(&input)
    }
}

/// Sequential nonce scan: smallest passing nonce from zero upward.
fn grind_sequential(head: &[u8], difficulty_bits: u32) -> u64 {
    let mut input = Vec::with_capacity(head.len() + 8);
    input.extend_from_slice(head);
    input.extend_from_slice(&[0u8; 8]);
    let base = head.len();
    let mut nonce = 0u64;
    loop {
        input[base..].copy_from_slice(&nonce.to_le_bytes());
        let digest = if input.len() <= CHUNK_LEN {
            blake3_256_small(&input)
        } else {
            blake3_256(&input)
        };
        if leading_zero_bits(&digest) >= difficulty_bits {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// First passing nonce in `[start, start + count)` (`None` when empty).
fn scan_range(head: &[u8], start: u64, count: u64, difficulty_bits: u32) -> Option<u64> {
    let mut input = Vec::with_capacity(head.len() + 8);
    input.extend_from_slice(head);
    input.extend_from_slice(&[0u8; 8]);
    let base = head.len();
    let mut nonce = start;
    for _ in 0..count {
        input[base..].copy_from_slice(&nonce.to_le_bytes());
        let digest = if input.len() <= CHUNK_LEN {
            blake3_256_small(&input)
        } else {
            blake3_256(&input)
        };
        if leading_zero_bits(&digest) >= difficulty_bits {
            return Some(nonce);
        }
        nonce = nonce.wrapping_add(1);
    }
    None
}

/// Parallel nonce scan returning exactly the sequential answer.
///
/// Bands of `workers * BAND` nonces are covered fully, lowest first, and
/// the band minimum wins — so the result equals [`grind_sequential`]
/// regardless of thread count or scheduling.
fn grind_parallel(head: &[u8], difficulty_bits: u32, workers: usize) -> u64 {
    const BAND_PER_WORKER: u64 = 4096;
    let band = (workers as u64).wrapping_mul(BAND_PER_WORKER);
    let mut base = 0u64;
    loop {
        let mut best: Option<u64> = None;
        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for worker in 0..workers {
                let start = base.wrapping_add((worker as u64).wrapping_mul(BAND_PER_WORKER));
                handles.push(
                    scope.spawn(move || scan_range(head, start, BAND_PER_WORKER, difficulty_bits)),
                );
            }
            for handle in handles {
                if let Ok(Some(nonce)) = handle.join() {
                    best = Some(best.map_or(nonce, |current| current.min(nonce)));
                }
            }
        });
        if let Some(nonce) = best {
            return nonce;
        }
        base = base.wrapping_add(band);
    }
}

/// Leading zero bits of a digest, most-significant-bit first.
fn leading_zero_bits(digest: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for &byte in digest {
        let zeros = byte.leading_zeros();
        count += zeros;
        if zeros < 8 {
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_bound() {
        let mut a = Transcript::new(b"test");
        a.absorb(b"stmt", b"hello");
        let c1 = a.challenge_f64(b"r1");
        let c2 = a.challenge_f64(b"r2");
        let mut b = Transcript::new(b"test");
        b.absorb(b"stmt", b"hello");
        assert_eq!(c1, b.challenge_f64(b"r1"));
        assert_eq!(c2, b.challenge_f64(b"r2"));
        let mut c = Transcript::new(b"test");
        c.absorb(b"stmt", b"other");
        assert_ne!(c1, c.challenge_f64(b"r1"));
    }

    #[test]
    fn index_in_range() {
        let mut t = Transcript::new(b"idx");
        for _ in 0..32 {
            assert!(t.challenge_index(b"q", 64) < 64);
        }
    }

    #[test]
    fn grind_roundtrip() {
        let mut prover = Transcript::new(b"pow");
        prover.absorb(b"stmt", b"hello");
        let nonce = prover.grind(b"pow", 8);
        let mut verifier = Transcript::new(b"pow");
        verifier.absorb(b"stmt", b"hello");
        assert!(verifier.verify_grind(b"pow", nonce, 8));
        // Histories match afterwards: later challenges agree.
        assert_eq!(
            prover.challenge_f64(b"next"),
            verifier.challenge_f64(b"next")
        );
    }

    #[test]
    fn grind_rejects_wrong_nonce_and_history() {
        let mut prover = Transcript::new(b"pow");
        prover.absorb(b"stmt", b"hello");
        let nonce = prover.grind(b"pow", 8);
        // Wrong nonce fails and absorbs nothing: a later correct check
        // still succeeds on the untouched history.
        let mut verifier = Transcript::new(b"pow");
        verifier.absorb(b"stmt", b"hello");
        assert!(!verifier.verify_grind(b"pow", nonce.wrapping_add(1), 8));
        assert!(verifier.verify_grind(b"pow", nonce, 8));
        // Different history fails outright.
        let mut other = Transcript::new(b"pow");
        other.absorb(b"stmt", b"other");
        assert!(!other.verify_grind(b"pow", nonce, 8));
        // Impossible difficulty fails without absorbing.
        let mut strict = Transcript::new(b"pow");
        strict.absorb(b"stmt", b"hello");
        assert!(!strict.verify_grind(b"pow", nonce, 257));
    }

    #[test]
    fn domain_separation() {
        // Different initial domains diverge every challenge.
        let mut a = Transcript::new(b"proto-a");
        let mut b = Transcript::new(b"proto-b");
        assert_ne!(a.challenge_f64(b"x"), b.challenge_f64(b"x"));
        // Same label twice still separates via the squeeze counter.
        let mut t = Transcript::new(b"counter");
        let first = t.challenge_bb(b"same");
        let second = t.challenge_bb(b"same");
        assert_ne!(first, second);
        // Absorbing between squeezes changes everything after.
        let mut u = Transcript::new(b"counter");
        u.challenge_bb(b"same");
        u.absorb(b"mid", b"data");
        assert_ne!(u.challenge_bb(b"same"), second);
    }

    #[test]
    fn grind_is_deterministic() {
        let mut a = Transcript::new(b"pow");
        a.absorb(b"stmt", b"hello");
        let mut b = Transcript::new(b"pow");
        b.absorb(b"stmt", b"hello");
        assert_eq!(a.grind(b"pow", 8), b.grind(b"pow", 8));
    }

    #[test]
    fn parallel_scan_matches_sequential() {
        // Forced two-worker search must return exactly the sequential
        // nonce, on any machine (threading threshold may keep `grind`
        // itself sequential on single-core runners).
        let mut head = blake3_256(b"fixed test head").to_vec();
        head.extend_from_slice(b"pow");
        assert_eq!(grind_parallel(&head, 8, 2), grind_sequential(&head, 8));
        assert_eq!(grind_parallel(&head, 10, 3), grind_sequential(&head, 10));
    }

    #[test]
    fn higher_difficulty_roundtrip() {
        // 13 bits clears the threading threshold on multi-core machines
        // (sequential fallback elsewhere); either path verifies.
        let mut prover = Transcript::new(b"pow13");
        prover.absorb(b"stmt", b"hello");
        let nonce = prover.grind(b"pow", 13);
        let mut verifier = Transcript::new(b"pow13");
        verifier.absorb(b"stmt", b"hello");
        assert!(verifier.verify_grind(b"pow", nonce, 13));
    }
}
