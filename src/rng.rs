//! `ChaCha20` (RFC 8439) stream cipher as the crate CSPRNG, plus OS seeding.
//!
//! Zero dependencies. Used to sample blinding randomness in
//! [`crate::blind`]. All arithmetic is wrapping/`rotate_left` over `u32`:
//! naturally constant-time on every platform (no table lookups, no branches
//! on secrets).
//!
//! Secret hygiene: [`ChaCha20`] wipes its key material on [`Drop`], and
//! [`fresh_stream`] wipes the OS seed after use. Both are best-effort
//! overwrites — this crate forbids `unsafe`, which rules out volatile
//! writes, so no certified protection against an optimizer eliding dead
//! stores is claimed. Blinding streams are short-lived by construction;
//! long-term keys belong in OS keystores, not here.
//!
//! Validated against RFC 8439 §2.1.1 (quarter round) and §2.3.2 (block
//! function) test vectors.

use crate::babybear::Field;
use crate::error::Error;

/// `ChaCha20` quarter round on four state words by index (RFC 8439 §2.1).
pub(crate) fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Raw `ChaCha20` block (RFC 8439 §2.3): 64 keystream bytes for
/// `(key, counter, nonce)`.
#[must_use]
pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        let mut word = [0u8; 4];
        word.copy_from_slice(chunk);
        state[4 + i] = u32::from_le_bytes(word);
    }
    state[12] = counter;
    for (i, chunk) in nonce.chunks_exact(4).enumerate() {
        let mut word = [0u8; 4];
        word.copy_from_slice(chunk);
        state[13 + i] = u32::from_le_bytes(word);
    }
    let initial = state;
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.wrapping_add(initial[i]).to_le_bytes());
    }
    out
}

/// Seekable `ChaCha20` stream: `counter` selects the 64-byte block.
///
/// `Debug` redacts the key and buffered keystream (never log streams).
#[derive(Clone)]
pub struct ChaCha20 {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
    block: [u8; 64],
    used: usize,
}

impl core::fmt::Debug for ChaCha20 {
    /// Redacted: shows position only, never key material or keystream.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChaCha20")
            .field("nonce", &self.nonce)
            .field("counter", &self.counter)
            .field("used", &self.used)
            .finish_non_exhaustive()
    }
}

impl ChaCha20 {
    /// Create a stream from a 32-byte key and 12-byte nonce (counter 0).
    ///
    /// Keys must be uniform; use [`os_seed`] or a fixed test key.
    /// Nonces must never repeat under one key in production.
    #[must_use]
    pub const fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
        Self {
            key,
            nonce,
            counter: 0,
            block: [0; 64],
            used: 64,
        }
    }

    /// Fill `out` with keystream bytes.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            if self.used == 64 {
                self.block = block(&self.key, self.counter, &self.nonce);
                self.counter = self.counter.wrapping_add(1);
                self.used = 0;
            }
            let take = (64 - self.used).min(out.len() - done);
            out[done..done + take].copy_from_slice(&self.block[self.used..self.used + take]);
            self.used += take;
            done += take;
        }
    }

    /// Next unbiased `u32` (little-endian keystream word).
    #[must_use]
    pub fn next_u32(&mut self) -> u32 {
        let mut word = [0u8; 4];
        self.fill_bytes(&mut word);
        u32::from_le_bytes(word)
    }

    /// Next unbiased `u64` (little-endian keystream double-word).
    #[must_use]
    pub fn next_u64(&mut self) -> u64 {
        let mut word = [0u8; 8];
        self.fill_bytes(&mut word);
        u64::from_le_bytes(word)
    }

    /// Next field element via `u64 mod p` (bias `< 2^-31`, documented in
    /// [`crate::transcript`] style; fine for blinding randomness).
    #[must_use]
    pub fn next_field(&mut self) -> Field {
        Field::from_u64(self.next_u64())
    }
}

impl Drop for ChaCha20 {
    /// Best-effort key wipe (see the module docs on its limits).
    fn drop(&mut self) {
        self.key = [0u8; 32];
        self.nonce = [0u8; 12];
        self.block = [0u8; 64];
        self.counter = 0;
        self.used = 0;
    }
}

/// Seed 32 bytes from the operating system (`/dev/urandom`).
///
/// # Errors
/// Returns [`Error::RngUnavailable`] when the OS RNG cannot be read.
pub fn os_seed() -> Result<[u8; 32], Error> {
    use std::io::Read as _;
    let mut file = std::fs::File::open("/dev/urandom").map_err(|_| Error::RngUnavailable)?;
    let mut seed = [0u8; 32];
    file.read_exact(&mut seed)
        .map_err(|_| Error::RngUnavailable)?;
    Ok(seed)
}

/// Convenience: fresh [`ChaCha20`] from [`os_seed`] with a zero nonce.
///
/// Callers needing nonce separation must set their own nonce discipline;
/// the zero nonce is safe for single-use blinding streams. The seed
/// buffer is wiped (opaque read anchors the wipe) before returning.
///
/// # Errors
/// Propagates [`Error::RngUnavailable`] from [`os_seed`].
pub fn fresh_stream() -> Result<ChaCha20, Error> {
    let mut seed = os_seed()?;
    let stream = ChaCha20::new(seed, [0u8; 12]);
    seed = [0u8; 32];
    let _ = std::hint::black_box(seed);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarter_round_vector() {
        // RFC 8439 §2.1.1.
        let mut state = [0u32; 16];
        state[0] = 0x1111_1111;
        state[1] = 0x0102_0304;
        state[2] = 0x9b8d_6f43;
        state[3] = 0x0123_4567;
        quarter_round(&mut state, 0, 1, 2, 3);
        assert_eq!(
            (state[0], state[1], state[2], state[3]),
            (0xea2a_92f4, 0xcb1c_f8ce, 0x4581_472e, 0x5881_c4bb)
        );
    }

    #[test]
    fn block_vector() {
        // RFC 8439 §2.3.2: key 00..1f, counter 1, nonce 00:00:00:09:...
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::try_from(i).unwrap();
        }
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(block(&key, 1, &nonce), expected);
    }

    #[test]
    fn stream_matches_blocks() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let mut stream = ChaCha20::new(key, nonce);
        let mut first = [0u8; 64];
        stream.fill_bytes(&mut first);
        assert_eq!(first, block(&key, 0, &nonce));
        let mut second = [0u8; 64];
        stream.fill_bytes(&mut second);
        assert_eq!(second, block(&key, 1, &nonce));
    }

    #[test]
    fn unaligned_and_deterministic() {
        let key = [3u8; 32];
        let nonce = [5u8; 12];
        let mut rng_a = ChaCha20::new(key, nonce);
        let mut rng_b = ChaCha20::new(key, nonce);
        let mut out_x = [0u8; 100];
        let mut out_y = [0u8; 100];
        rng_a.fill_bytes(&mut out_x);
        rng_b.fill_bytes(&mut out_y);
        assert_eq!(out_x, out_y);
        // u32/u64 views agree with the byte stream.
        let mut rng_c = ChaCha20::new(key, nonce);
        let mut words = [0u8; 12];
        rng_c.fill_bytes(&mut words);
        let mut rng_d = ChaCha20::new(key, nonce);
        assert_eq!(
            rng_d.next_u32(),
            u32::from_le_bytes(words[0..4].try_into().unwrap())
        );
        assert_eq!(
            rng_d.next_u64(),
            u64::from_le_bytes(words[4..12].try_into().unwrap())
        );
    }

    #[test]
    fn key_sensitivity() {
        let mut a = ChaCha20::new([0u8; 32], [0u8; 12]);
        let mut b = ChaCha20::new([1u8; 32], [0u8; 12]);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn debug_redacts_key_material() {
        // `Debug` renders bytes decimally: the key would show as 171s.
        let stream = ChaCha20::new([0xab; 32], [0xcd; 12]);
        let shown = format!("{stream:?}");
        assert!(!shown.contains("171"), "key must not appear: {shown}");
        assert!(shown.contains("ChaCha20"));
    }

    #[test]
    fn os_seed_smoke() {
        // Environment-dependent; failure here means no OS RNG, not bad math.
        let seed = os_seed().unwrap();
        assert_ne!(seed, [0u8; 32]);
    }
}
