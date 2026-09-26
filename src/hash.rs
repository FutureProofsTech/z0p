//! BLAKE3 hash function from the official specification (unkeyed mode,
//! 256-bit output). Zero dependencies.
//!
//! Replaces SHA3-256 as the crate hash backend: same 256-bit digests and
//! 128-bit security level, roughly an order of magnitude faster in software
//! (7-round ARX compression instead of Keccak's 24-round sponge). All crate
//! digests (Merkle trees, transcripts) use this module.
//!
//! The [`Hasher`] buffers input and resolves chunk-boundary flags exactly:
//! a full 16th block of a chunk is held back until more input arrives (which
//! proves it was not the chunk's last block) or finalization. Validated
//! against reference vectors from the official Python bindings, including
//! multi-chunk inputs crossing the 1024-byte chunk boundary.

/// BLAKE3 initialization vector.
const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// BLAKE3 message permutation.
const PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// Flag: first block of a chunk.
const CHUNK_START: u32 = 1;
/// Flag: last block of a chunk.
const CHUNK_END: u32 = 2;
/// Flag: parent (chaining-value) node.
const PARENT: u32 = 4;
/// Flag: root node.
const ROOT: u32 = 8;

const BLOCK_LEN: usize = 64;
const BLOCK_LEN_U32: u32 = 64;
/// Chunk length: inputs this size or smaller hash as a single chunk.
pub(crate) const CHUNK_LEN: usize = 1024;
/// Maximum chaining-value stack depth (covers any input length).
const MAX_STACK: usize = 54;

fn quarter_round(
    state: &mut [u32; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    first: u32,
    second: u32,
) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(first);
    state[d] ^= state[a];
    state[d] = state[d].rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(second);
    state[d] ^= state[a];
    state[d] = state[d].rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_right(7);
}

fn round(state: &mut [u32; 16], message: &[u32; 16]) {
    quarter_round(state, 0, 4, 8, 12, message[0], message[1]);
    quarter_round(state, 1, 5, 9, 13, message[2], message[3]);
    quarter_round(state, 2, 6, 10, 14, message[4], message[5]);
    quarter_round(state, 3, 7, 11, 15, message[6], message[7]);
    quarter_round(state, 0, 5, 10, 15, message[8], message[9]);
    quarter_round(state, 1, 6, 11, 12, message[10], message[11]);
    quarter_round(state, 2, 7, 8, 13, message[12], message[13]);
    quarter_round(state, 3, 4, 9, 14, message[14], message[15]);
}

fn permute(message: &mut [u32; 16]) {
    let mut permuted = [0u32; 16];
    for (i, &slot) in PERMUTATION.iter().enumerate() {
        permuted[i] = message[slot];
    }
    *message = permuted;
}

/// Raw compression: 16 output words from chaining value, block, and params.
fn compress(
    chaining: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let counter_bytes = counter.to_le_bytes();
    let mut low = [0u8; 4];
    let mut high = [0u8; 4];
    low.copy_from_slice(&counter_bytes[..4]);
    high.copy_from_slice(&counter_bytes[4..]);
    let mut state = [0u32; 16];
    state[..8].copy_from_slice(chaining);
    state[8..12].copy_from_slice(&IV[..4]);
    state[12] = u32::from_le_bytes(low);
    state[13] = u32::from_le_bytes(high);
    state[14] = block_len;
    state[15] = flags;
    let mut message = *block_words;
    for _ in 0..7 {
        round(&mut state, &message);
        permute(&mut message);
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
    }
    for (i, &chain) in chaining.iter().enumerate() {
        state[i + 8] ^= chain;
    }
    state
}

/// First 8 output words as bytes: chaining value of a node.
fn chaining_bytes(output: &[u32; 16]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, chunk) in bytes.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&output[i].to_le_bytes());
    }
    bytes
}

fn words_from_block(block: &[u8; 64]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

/// Parent chaining value of two child chaining values.
///
/// Allocation-free: the 64-byte preimage parses straight into words.
/// Byte-identical to the historical two-`Vec` construction.
fn parent_cv(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(left);
    block[32..].copy_from_slice(right);
    chaining_bytes(&compress(
        &IV,
        &words_from_block(&block),
        0,
        BLOCK_LEN_U32,
        PARENT,
    ))
}

/// Root bytes of two child chaining values.
///
/// Allocation-free, byte-identical (see [`parent_cv`]).
fn parent_root(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(left);
    block[32..].copy_from_slice(right);
    chaining_bytes(&compress(
        &IV,
        &words_from_block(&block),
        0,
        BLOCK_LEN_U32,
        PARENT | ROOT,
    ))
}

/// Output bytes (chaining value, or root when `root` is set) of `blocks`
/// (1..=16 blocks, last possibly partial) under `counter`.
fn chunk_output(blocks: &[u8], counter: u64, root: bool) -> [u8; 32] {
    debug_assert!(!blocks.is_empty() && blocks.len() <= CHUNK_LEN);
    let mut chaining = IV;
    let block_count = (blocks.len() + BLOCK_LEN - 1) / BLOCK_LEN;
    for (i, block) in blocks.chunks(BLOCK_LEN).enumerate() {
        let mut words = [0u32; 16];
        let mut full_words = 0;
        for (j, chunk) in block.chunks_exact(4).enumerate() {
            words[j] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            full_words = j + 1;
        }
        // A short final block still contributes its bytes (zero-padded).
        let remainder = &block[full_words * 4..];
        if !remainder.is_empty() {
            let mut last = [0u8; 4];
            last[..remainder.len()].copy_from_slice(remainder);
            words[full_words] = u32::from_le_bytes(last);
        }
        let mut flags = 0u32;
        if i == 0 {
            flags |= CHUNK_START;
        }
        if i + 1 == block_count {
            flags |= CHUNK_END;
            if root {
                flags |= ROOT;
            }
        }
        let len = u32::try_from(block.len()).unwrap_or(u32::MAX);
        let output = compress(&chaining, &words, counter, len, flags);
        chaining.copy_from_slice(&output[..8]);
    }
    let mut bytes = [0u8; 32];
    for (i, word) in bytes.chunks_exact_mut(4).enumerate() {
        word.copy_from_slice(&chaining[i].to_le_bytes());
    }
    bytes
}

/// Incremental BLAKE3 hasher.
///
/// Retains at most 2047 unprocessed tail bytes plus a 54-entry chaining
/// stack: complete non-final 1024-byte chunks are compressed eagerly with
/// exact flags, and only the ambiguous tail (at most one complete chunk
/// plus a partial one) waits for finalization, where every flag is known.
#[derive(Clone, Debug)]
pub struct Hasher {
    buf: Vec<u8>,
    start: usize,
    stack: [[u8; 32]; MAX_STACK],
    stack_len: usize,
    next_index: u64,
    total_len: usize,
}

impl Hasher {
    /// Create a fresh hasher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            stack: [[0; 32]; MAX_STACK],
            stack_len: 0,
            next_index: 0,
            total_len: 0,
        }
    }

    /// Absorb input bytes; callable repeatedly with arbitrary splits.
    pub fn update(&mut self, input: &[u8]) {
        self.total_len += input.len();
        self.buf.extend_from_slice(input);
        // Compress complete chunks while at least two chunks remain: the
        // retained chunk might still be the last one.
        while self.buf.len() - self.start >= 2 * CHUNK_LEN {
            let end = self.start + CHUNK_LEN;
            let cv = chunk_output(&self.buf[self.start..end], self.next_index, false);
            self.push_merged(cv);
            self.start = end;
        }
        // Amortized compaction keeps memory bounded on large streams.
        if self.start >= 65536 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
    }

    /// Squeeze the 32-byte digest, consuming the hasher.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        if self.total_len == 0 {
            // Empty input: single empty block with all flags.
            let output = compress(&IV, &[0u32; 16], 0, 0, CHUNK_START | CHUNK_END | ROOT);
            return chaining_bytes(&output);
        }
        let tail_len = self.buf.len() - self.start;
        debug_assert!(!self.buf[self.start..].is_empty() && tail_len < 2 * CHUNK_LEN);
        if tail_len > CHUNK_LEN {
            // Leading complete chunk is not last: merge it eagerly.
            let end = self.start + CHUNK_LEN;
            let cv = chunk_output(&self.buf[self.start..end], self.next_index, false);
            self.push_merged(cv);
            self.start = end;
        }
        // The remaining tail (at most one chunk) is last: no merging.
        let partial = &self.buf[self.start..];
        debug_assert!(!partial.is_empty() && partial.len() <= CHUNK_LEN);
        if self.stack_len == 0 {
            // Single chunk total: root it directly.
            return chunk_output(partial, self.next_index, true);
        }
        let final_cv = chunk_output(partial, self.next_index, false);
        // Fold right-to-left with `ROOT` on the outermost combine.
        let mut current = final_cv;
        for i in (1..self.stack_len).rev() {
            current = parent_cv(&self.stack[i], &current);
        }
        parent_root(&self.stack[0], &current)
    }

    /// Push a completed non-final chunk with Bao merge-while-even stacking.
    fn push_merged(&mut self, cv: [u8; 32]) {
        debug_assert!(self.stack_len < MAX_STACK);
        self.stack[self.stack_len] = cv;
        self.stack_len += 1;
        self.next_index += 1;
        let mut total = self.next_index;
        while total % 2 == 0 {
            let right = self.stack[self.stack_len - 1];
            let left = self.stack[self.stack_len - 2];
            self.stack_len -= 2;
            self.stack[self.stack_len] = parent_cv(&left, &right);
            self.stack_len += 1;
            total /= 2;
        }
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot BLAKE3-256.
///
/// # Example
/// ```
/// use z0p::hash::blake3_256;
/// let digest = blake3_256(b"abc");
/// assert_eq!(digest[0], 0x64);
/// ```
#[must_use]
pub fn blake3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// One-shot digest for short inputs (`<= 1024` bytes).
///
/// Allocation-free: inputs of at most one chunk root directly through one
/// compression chain instead of the buffering [`Hasher`]. Byte-identical to
/// [`blake3_256`] on the same input; oversized inputs take the slow path
/// (correct in release, flagged in debug).
pub(crate) fn blake3_256_small(data: &[u8]) -> [u8; 32] {
    if data.is_empty() {
        return chaining_bytes(&compress(
            &IV,
            &[0u32; 16],
            0,
            0,
            CHUNK_START | CHUNK_END | ROOT,
        ));
    }
    debug_assert!(data.len() <= CHUNK_LEN);
    if data.len() > CHUNK_LEN {
        return blake3_256(data);
    }
    chunk_output(data, 0, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    #[test]
    fn kat_empty() {
        assert_eq!(
            hex(&blake3_256(b"")),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn kat_abc() {
        assert_eq!(
            hex(&blake3_256(b"abc")),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn kat_multiblock() {
        // Chunk-boundary coverage: exactly one chunk, one byte over, two.
        let cases = [
            (
                1024,
                "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
            ),
            (
                1025,
                "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
            ),
            (
                2048,
                "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
            ),
            (
                3000,
                "5fade288bf27444bee55ba2babb98c3c922c1e84c2e445e7d1f6da24756f5060",
            ),
        ];
        for (len, expected) in cases {
            let input = pattern(len);
            assert_eq!(hex(&blake3_256(&input)), expected, "len {len}");
            assert_eq!(hex_bytes(expected).len(), 32);
        }
    }

    #[test]
    fn small_matches_oneshot() {
        // Single-chunk fast path must agree byte-for-byte, including the
        // empty input and both sides of every internal boundary.
        for len in [0usize, 1, 7, 63, 64, 65, 1000, 1023, 1024] {
            let input = pattern(len);
            assert_eq!(
                hex(&blake3_256_small(&input)),
                hex(&blake3_256(&input)),
                "len {len}"
            );
        }
    }

    #[test]
    fn incremental_matches_oneshot() {
        let input = pattern(3000);
        let mut hasher = Hasher::new();
        // Odd splits, including 1-byte updates and chunk-boundary splits.
        let mut offset = 0;
        for chunk in [1usize, 7, 63, 64, 65, 959, 1024, 1025, 90] {
            let end = (offset + chunk).min(input.len());
            hasher.update(&input[offset..end]);
            offset = end;
            if offset >= input.len() {
                break;
            }
        }
        hasher.update(&input[offset..]);
        assert_eq!(hex(&hasher.finalize()), hex(&blake3_256(&input)));
    }

    #[test]
    fn exact_boundary_input() {
        // Input ending exactly on chunk boundaries exercises the hold-back.
        for len in [64usize, 1024, 2048] {
            let input = pattern(len);
            let mut hasher = Hasher::new();
            hasher.update(&input[..len / 2]);
            hasher.update(&input[len / 2..]);
            assert_eq!(
                hex(&hasher.finalize()),
                hex(&blake3_256(&input)),
                "len {len}"
            );
        }
    }
}
