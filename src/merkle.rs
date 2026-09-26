//! Binary Merkle tree over SHA3-256.
//!
//! Second-preimage hardened by domain separation:
//! leaf = `H(0x00 || data)`, node = `H(0x01 || left || right)`.
//! Fallible construction and opening return [`Error`](crate::Error); success
//! paths never panic.

use crate::error::{Error, Result};
use crate::hash::{blake3_256, blake3_256_small, CHUNK_LEN};

/// Hash a leaf preimage with the leaf domain separator.
///
/// Allocation-free for preimages below one chunk (every leaf in this
/// crate): the prefix goes on a stack buffer down the single-chunk path.
#[must_use]
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    if data.len() < CHUNK_LEN {
        let mut buf = [0u8; CHUNK_LEN];
        buf[0] = 0x00;
        let end = 1 + data.len();
        buf[1..end].copy_from_slice(data);
        blake3_256_small(&buf[..end])
    } else {
        let mut prefixed = Vec::with_capacity(1 + data.len());
        prefixed.push(0x00);
        prefixed.extend_from_slice(data);
        blake3_256(&prefixed)
    }
}

/// Hash two child digests with the node domain separator.
///
/// The 65-byte preimage is a single chunk, so this roots directly through
/// the allocation-free path — byte-identical to the buffered [`blake3_256`]
/// (pinned by `small_matches_oneshot` at length 65 in [`crate::hash`]).
#[must_use]
pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut prefixed = [0u8; 65];
    prefixed[0] = 0x01;
    prefixed[1..33].copy_from_slice(left);
    prefixed[33..65].copy_from_slice(right);
    blake3_256_small(&prefixed)
}

/// Binary Merkle tree. Leaves are padded by duplicating the last leaf up to a
/// power of two, so every internal node has exactly two children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleTree {
    layers: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build from raw leaf preimages.
    ///
    /// # Errors
    /// Returns [`Error::EmptyInput`] when `leaf_data` is empty.
    pub fn new(leaf_data: &[Vec<u8>]) -> Result<Self> {
        if leaf_data.is_empty() {
            return Err(Error::EmptyInput);
        }
        let mut current = vec![[0u8; 32]; leaf_data.len()];
        crate::par::for_each_indexed(&mut current, 1024, |base, piece| {
            for (j, slot) in piece.iter_mut().enumerate() {
                *slot = hash_leaf(&leaf_data[base + j]);
            }
        });
        Ok(finish(current))
    }

    /// Build from concatenated fixed-size leaf preimages.
    ///
    /// `flat` holds `flat.len() / leaf_len` leaves back to back. One
    /// allocation instead of one per leaf; the root is identical to
    /// [`MerkleTree::new`] over the same chunks.
    ///
    /// # Errors
    /// Returns [`Error::EmptyInput`] for empty input or zero `leaf_len`, or
    /// [`Error::MalformedInput`] when `flat.len()` is not a multiple of
    /// `leaf_len`.
    pub fn from_flat(flat: &[u8], leaf_len: usize) -> Result<Self> {
        if flat.is_empty() || leaf_len == 0 {
            return Err(Error::EmptyInput);
        }
        if flat.len() % leaf_len != 0 {
            return Err(Error::MalformedInput {
                reason: "flat leaves must tile the buffer exactly",
            });
        }
        let count = flat.len() / leaf_len;
        let mut current = vec![[0u8; 32]; count];
        crate::par::for_each_indexed(&mut current, 1024, |base, piece| {
            for (j, slot) in piece.iter_mut().enumerate() {
                let i = base + j;
                *slot = hash_leaf(&flat[i * leaf_len..(i + 1) * leaf_len]);
            }
        });
        Ok(finish(current))
    }

    /// Build directly from pre-hashed leaf digests (already `hash_leaf`ed).
    ///
    /// # Errors
    /// Returns [`Error::EmptyInput`] when `leaf_digests` is empty.
    pub fn from_digests(leaf_digests: &[[u8; 32]]) -> Result<Self> {
        if leaf_digests.is_empty() {
            return Err(Error::EmptyInput);
        }
        Ok(finish(leaf_digests.to_vec()))
    }

    /// The root digest.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.layers[self.layers.len() - 1][0]
    }

    /// Number of leaves after padding (always a power of two).
    #[must_use]
    pub fn num_leaves(&self) -> usize {
        self.layers[0].len()
    }
    /// Open leaf `index`.
    ///
    /// Returns `(sibling, current_is_left)` pairs from the leaf layer up.    ///
    /// # Errors
    /// Returns [`Error::IndexOutOfBounds`] when `index >= num_leaves()`.
    pub fn prove(&self, mut index: usize) -> Result<Vec<([u8; 32], bool)>> {
        if index >= self.num_leaves() {
            return Err(Error::IndexOutOfBounds {
                index,
                len: self.num_leaves(),
            });
        }
        let mut path = Vec::with_capacity(self.layers.len() - 1);
        for layer in &self.layers[..self.layers.len() - 1] {
            let is_left = index % 2 == 0;
            let sibling = if is_left {
                layer[index + 1]
            } else {
                layer[index - 1]
            };
            path.push((sibling, is_left));
            index /= 2;
        }
        Ok(path)
    }

    /// Verify a path against `root` for the given leaf preimage and index.
    ///
    /// Returns `false` when `index` does not fit the path depth or any hash
    /// comparison fails.
    #[must_use]
    pub fn verify(
        root: &[u8; 32],
        leaf_data: &[u8],
        index: usize,
        path: &[([u8; 32], bool)],
    ) -> bool {
        if index >> path.len() != 0 {
            return false;
        }
        let mut current = hash_leaf(leaf_data);
        for (sibling, is_left) in path {
            current = if *is_left {
                hash_node(&current, sibling)
            } else {
                hash_node(sibling, &current)
            };
        }
        &current == root
    }

    /// Verify a path for an already-hashed leaf digest.
    ///
    /// Returns `false` when `index` does not fit the path depth or any hash
    /// comparison fails.
    #[must_use]
    pub fn verify_digest(
        root: &[u8; 32],
        leaf_digest: &[u8; 32],
        index: usize,
        path: &[([u8; 32], bool)],
    ) -> bool {
        if index >> path.len() != 0 {
            return false;
        }
        let mut current = *leaf_digest;
        for (sibling, is_left) in path {
            current = if *is_left {
                hash_node(&current, sibling)
            } else {
                hash_node(sibling, &current)
            };
        }
        &current == root
    }

    /// Cap digests: the top `dropped` tree levels stay in the commitment
    /// (`dropped = 0` is `[root]`), so openings shrink by that many steps.
    ///
    /// Always `2^dropped` digests when the tree is deeper than `dropped`;
    /// dropping at or past the depth returns every leaf digest. Prover and
    /// verifier must drop identically from the same depth: columns drop
    /// `min(height, depth)`, FRI quads drop `min(height, depth - 2)`
    /// (the verifier rebuilds the bottom two levels from the values).
    /// See [`MerkleTree::prove_capped`].
    #[must_use]
    pub fn cap(&self, dropped: usize) -> Vec<[u8; 32]> {
        let depth = self.layers.len() - 1;
        self.layers[depth - dropped.min(depth)].clone()
    }

    /// Open leaf `index`, dropping the top `drop_top` path steps (the cap
    /// covers them). Clamped to the full path: dropping at or past the
    /// depth yields an empty path against the leaf-level cap.
    ///
    /// # Errors
    /// Returns [`Error::IndexOutOfBounds`] when `index >= num_leaves()`.
    pub fn prove_capped(&self, index: usize, drop_top: usize) -> Result<Vec<([u8; 32], bool)>> {
        let mut full = self.prove(index)?;
        let drop = drop_top.min(full.len());
        full.truncate(full.len() - drop);
        Ok(full)
    }

    /// Verify a capped opening against one cap entry.
    ///
    /// `total_depth` is the full tree depth (stored steps plus dropped
    /// top steps); the caller selects the entry as
    /// `cap[index >> path.len()]` and rejects missing entries. Returns
    /// `false` on any out-of-range input or mismatch.
    #[must_use]
    pub fn verify_capped(
        cap_entry: &[u8; 32],
        leaf_data: &[u8],
        index: usize,
        total_depth: usize,
        path: &[([u8; 32], bool)],
    ) -> bool {
        if path.len() > total_depth || index >> total_depth != 0 {
            return false;
        }
        let mut current = hash_leaf(leaf_data);
        for (sibling, is_left) in path {
            current = if *is_left {
                hash_node(&current, sibling)
            } else {
                hash_node(sibling, &current)
            };
        }
        &current == cap_entry
    }
}

/// Capped-tree shape for `num_leaves` (must be a power of two, as all
/// trees in this crate are): `(drop, depth)` with
/// `drop = min(cap_height, depth)`.
///
/// Prover and verifier derive identical shapes from the same leaf count,
/// so caps, paths, and entry indices agree bit for bit.
#[must_use]
pub fn capped_shape(num_leaves: usize, cap_height: usize) -> (usize, usize) {
    #[allow(clippy::cast_possible_truncation)]
    let depth = num_leaves.trailing_zeros() as usize;
    (cap_height.min(depth), depth)
}

/// Concatenated cap digests for transcript absorption.
pub(crate) fn cap_bytes(cap: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * cap.len());
    for digest in cap {
        out.extend_from_slice(digest);
    }
    out
}

/// Pad leaf digests by duplicating the last leaf up to a power of two,
/// then hash up to a root. Shared tail of every constructor.
fn finish(mut current: Vec<[u8; 32]>) -> MerkleTree {
    let target = current.len().next_power_of_two();
    while current.len() < target {
        let last = current[current.len() - 1];
        current.push(last);
    }
    let mut layers = vec![current];
    while layers[layers.len() - 1].len() > 1 {
        layers.push(hash_level(&layers[layers.len() - 1]));
    }
    MerkleTree { layers }
}
/// Hash one Merkle level: `next[i] = H(prev[2i] || prev[2i + 1])`.
///
/// Parallel across parent nodes when worthwhile; bit-identical either way
/// (each parent is a pure function of its pair).
fn hash_level(prev: &[[u8; 32]]) -> Vec<[u8; 32]> {
    debug_assert_eq!(prev.len() % 2, 0);
    let mut next = vec![[0u8; 32]; prev.len() / 2];
    crate::par::for_each_indexed(&mut next, 1024, |base, piece| {
        for (j, slot) in piece.iter_mut().enumerate() {
            let i = base + j;
            *slot = hash_node(&prev[2 * i], &prev[2 * i + 1]);
        }
    });
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert_eq!(MerkleTree::new(&[]), Err(Error::EmptyInput));
    }

    #[test]
    fn prove_verify_pow2() {
        let leaves: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 32]).collect();
        let tree = MerkleTree::new(&leaves).unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            let path = tree.prove(i).unwrap();
            assert!(MerkleTree::verify(&tree.root(), leaf, i, &path));
            let mut bad = leaf.clone();
            bad[0] ^= 1;
            assert!(!MerkleTree::verify(&tree.root(), &bad, i, &path));
        }
        assert_eq!(
            tree.prove(8),
            Err(Error::IndexOutOfBounds { index: 8, len: 8 })
        );
    }

    #[test]
    fn odd_padded() {
        let leaves: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i]).collect();
        let tree = MerkleTree::new(&leaves).unwrap();
        assert_eq!(tree.num_leaves(), 8);
        let path = tree.prove(4).unwrap();
        assert!(MerkleTree::verify(&tree.root(), &leaves[4], 4, &path));
    }

    #[test]
    fn flat_matches_nested() {
        // Non-power-of-two count exercises padding; 3000 leaves exercise
        // the parallel leaf path on multi-core runners.
        for count in [5usize, 3000] {
            let leaves: Vec<Vec<u8>> = (0..count)
                .map(|i| vec![u8::try_from(i % 251).unwrap(); 5])
                .collect();
            let flat: Vec<u8> = leaves.concat();
            let nested = MerkleTree::new(&leaves).unwrap();
            let flat_tree = MerkleTree::from_flat(&flat, 5).unwrap();
            assert_eq!(nested.root(), flat_tree.root());
            assert_eq!(nested.num_leaves(), flat_tree.num_leaves());
        }
        assert_eq!(MerkleTree::from_flat(&[], 4), Err(Error::EmptyInput));
        assert_eq!(MerkleTree::from_flat(&[1, 2, 3], 0), Err(Error::EmptyInput));
        assert!(MerkleTree::from_flat(&[1, 2, 3], 2).is_err());
    }

    #[test]
    fn capped_roundtrip() {
        // Distinct leaves (no padding aliases), so every negative check
        // is strict; heights run past the depth into degeneracy.
        let leaves: Vec<Vec<u8>> = (0..16u8).map(|i| vec![i; 7]).collect();
        let tree = MerkleTree::new(&leaves).unwrap();
        let depth = 4;
        for height in 0..=6 {
            let cap = tree.cap(height);
            let effective = height.min(depth);
            assert_eq!(cap.len(), 1usize << effective);
            for (i, leaf) in leaves.iter().enumerate() {
                let path = tree.prove_capped(i, height).unwrap();
                assert_eq!(path.len(), depth - effective);
                let entry = cap[i >> path.len()];
                assert!(MerkleTree::verify_capped(&entry, leaf, i, depth, &path));
                if cap.len() > 1 {
                    let entry_idx = i >> path.len();
                    let wrong = cap[(entry_idx + 1) % cap.len()];
                    assert!(!MerkleTree::verify_capped(&wrong, leaf, i, depth, &path));
                }
                let mut bad = leaf.clone();
                bad[0] ^= 1;
                assert!(!MerkleTree::verify_capped(&entry, &bad, i, depth, &path));
                // Over-long paths fail even with the right entry.
                let mut long = path.clone();
                long.push(([0u8; 32], true));
                assert!(!MerkleTree::verify_capped(&entry, leaf, i, depth, &long));
            }
        }
        // Odd count exercises padding on the positive path.
        let odd: Vec<Vec<u8>> = (0..12u8).map(|i| vec![i; 7]).collect();
        let odd_tree = MerkleTree::new(&odd).unwrap();
        assert_eq!(odd_tree.num_leaves(), 16);
        for height in 0..=6 {
            let cap = odd_tree.cap(height);
            for (i, leaf) in odd.iter().enumerate() {
                let path = odd_tree.prove_capped(i, height).unwrap();
                let entry = cap[i >> path.len()];
                assert!(MerkleTree::verify_capped(&entry, leaf, i, depth, &path));
            }
        }
        assert!(tree.prove_capped(16, 0).is_err());
    }
}
