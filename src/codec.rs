//! Canonical proof serialization: versioned, length-prefixed, paranoid.
//!
//! Every proof type encodes as `VERSION || body` with little-endian
//! integers, `u32` counts, 4-byte canonical fields, 32-byte digests, and
//! one byte per Merkle direction bit (`0`/`1` only). Decoding rejects
//! anything else: wrong versions, trailing bytes, truncated reads,
//! non-canonical field elements (`>= p`, a malleability vector), and
//! out-of-range direction bytes.
//!
//! Denial-of-service discipline: counts are capped before looping, vectors
//! grow incrementally (never `with_capacity` from an untrusted count),
//! and every read is cursor-checked — memory use stays proportional to
//! the input length.

use crate::babybear::Field;
use crate::error::{Error, Result};

/// Encoding version. Bump on any format change; old proofs then fail
/// loudly instead of misparsing.
pub(crate) const VERSION: u8 = 1;

/// Maximum query/opening count (matches the tuner ceiling).
pub(crate) const MAX_QUERIES: u32 = 1 << 20;
/// Maximum folds per query (domains stop at `2^27`, quartering).
pub(crate) const MAX_FOLDS: u32 = 64;
/// Maximum stored Merkle path steps (domains stop at `2^27`).
pub(crate) const MAX_PATH_STEPS: u32 = 128;
/// Maximum digests in one cap (auto-tune stops at 16).
pub(crate) const MAX_CAP_DIGESTS: u32 = 256;
/// Maximum flat elements (final polynomials, bit columns).
pub(crate) const MAX_ELEMS: u32 = 1 << 27;
/// Maximum fold steps in one IVC proof.
pub(crate) const MAX_STEPS: u32 = 1 << 20;

/// Little-endian byte writer over a fresh buffer.
#[derive(Debug, Default)]
pub(crate) struct Writer {
    out: Vec<u8>,
}

impl Writer {
    /// Fresh writer.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Append one byte.
    pub(crate) fn byte(&mut self, value: u8) {
        self.out.push(value);
    }

    /// Append a `u32` (4 bytes).
    pub(crate) fn u32_le(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a `u64` (8 bytes).
    pub(crate) fn u64_le(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a `usize` length as a `u32` count (honest proofs never
    /// approach the limit; debug-checked).
    pub(crate) fn count(&mut self, len: usize) {
        debug_assert!(u32::try_from(len).is_ok());
        #[allow(clippy::cast_possible_truncation)]
        self.u32_le(len as u32);
    }

    /// Append raw bytes.
    pub(crate) fn bytes(&mut self, data: &[u8]) {
        self.out.extend_from_slice(data);
    }

    /// Append a field element (4 canonical bytes).
    pub(crate) fn field(&mut self, value: Field) {
        self.bytes(&value.to_le_bytes());
    }

    /// Append a Merkle direction bit (`1` = left).
    pub(crate) fn direction(&mut self, is_left: bool) {
        self.byte(u8::from(is_left));
    }

    /// Append a Merkle path (digests plus direction bits).
    pub(crate) fn path(&mut self, path: &[([u8; 32], bool)]) {
        self.count(path.len());
        for (digest, is_left) in path {
            self.bytes(digest);
            self.direction(*is_left);
        }
    }

    /// Append cap digests with a count prefix.
    pub(crate) fn cap(&mut self, cap: &[[u8; 32]]) {
        self.count(cap.len());
        for digest in cap {
            self.bytes(digest);
        }
    }

    /// Finish into the byte vector.
    #[must_use]
    pub(crate) fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// Cursor-checked little-endian reader over untrusted input.
#[derive(Debug)]
pub(crate) struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap `input` at position zero.
    #[must_use]
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// Bytes left unread.
    #[must_use]
    pub(crate) fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    /// Take exactly `n` bytes or fail closed.
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::MalformedInput {
            reason: "truncated proof encoding",
        })?;
        if end > self.input.len() {
            return Err(Error::MalformedInput {
                reason: "truncated proof encoding",
            });
        }
        let out = &self.input[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Read one byte.
    pub(crate) fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a `u32` (4 bytes).
    pub(crate) fn u32_le(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a `u64` (8 bytes).
    pub(crate) fn u64_le(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a `usize` dimension (rejects values wider than the platform;
    /// range checks belong to `verify`, not decoding).
    pub(crate) fn dimension(&mut self) -> Result<usize> {
        usize::try_from(self.u64_le()?).map_err(|_| Error::MalformedInput {
            reason: "dimension exceeds platform width",
        })
    }

    /// Read a 32-byte digest.
    pub(crate) fn digest(&mut self) -> Result<[u8; 32]> {
        let bytes = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Read a canonical field element (rejects `>= p`).
    pub(crate) fn field(&mut self) -> Result<Field> {
        let bytes = self.take(4)?;
        let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if value >= Field::MODULUS {
            return Err(Error::MalformedInput {
                reason: "non-canonical field encoding",
            });
        }
        Ok(Field::new_unchecked(value))
    }

    /// Read a Merkle direction bit (rejects anything but `0`/`1`).
    pub(crate) fn direction(&mut self) -> Result<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::MalformedInput {
                reason: "invalid Merkle direction byte",
            }),
        }
    }

    /// Read a capped count (`<= max`), failing closed past it.
    pub(crate) fn count(&mut self, max: u32) -> Result<usize> {
        let n = self.u32_le()?;
        if n > max {
            return Err(Error::MalformedInput {
                reason: "proof count exceeds hard limit",
            });
        }
        usize::try_from(n).map_err(|_| Error::MalformedInput {
            reason: "count exceeds platform width",
        })
    }

    /// Read a Merkle path.
    pub(crate) fn path(&mut self) -> Result<Vec<([u8; 32], bool)>> {
        let mut path = Vec::new();
        for _ in 0..self.count(MAX_PATH_STEPS)? {
            path.push((self.digest()?, self.direction()?));
        }
        Ok(path)
    }

    /// Read cap digests.
    pub(crate) fn cap(&mut self) -> Result<Vec<[u8; 32]>> {
        let mut cap = Vec::new();
        for _ in 0..self.count(MAX_CAP_DIGESTS)? {
            cap.push(self.digest()?);
        }
        Ok(cap)
    }

    /// Expect the encoding version byte.
    pub(crate) fn version(&mut self) -> Result<()> {
        if self.byte()? != VERSION {
            return Err(Error::MalformedInput {
                reason: "unsupported proof encoding version",
            });
        }
        Ok(())
    }

    /// Expect no trailing bytes.
    pub(crate) fn end(&self) -> Result<()> {
        if self.remaining() != 0 {
            return Err(Error::MalformedInput {
                reason: "trailing bytes after proof encoding",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_rejects_non_bits() {
        let mut reader = Reader::new(&[2]);
        assert!(reader.direction().is_err());
        let mut reader = Reader::new(&[0]);
        assert!(!reader.direction().unwrap());
        let mut reader = Reader::new(&[1]);
        assert!(reader.direction().unwrap());
    }

    #[test]
    fn counts_fail_closed() {
        // Over-limit count fails before any allocation.
        let mut writer = Writer::new();
        writer.u32_le(MAX_QUERIES + 1);
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        assert!(reader.count(MAX_QUERIES).is_err());
        // Truncated reads fail.
        let mut reader = Reader::new(&[1, 2, 3]);
        assert!(reader.u32_le().is_err());
        assert!(reader.digest().is_err());
        // Non-canonical field fails.
        let mut writer = Writer::new();
        writer.bytes(&Field::MODULUS.to_le_bytes());
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        assert!(reader.field().is_err());
        // Version and trailer checks.
        let mut reader = Reader::new(&[VERSION + 1]);
        assert!(reader.version().is_err());
        let mut reader = Reader::new(&[VERSION, 0]);
        reader.version().unwrap();
        assert!(reader.end().is_err());
    }
}
