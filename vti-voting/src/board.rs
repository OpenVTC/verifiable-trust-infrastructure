//! The board: an election's append-only Merkle tree log (RFC 9162 §2.1), its tree heads, and
//! the inclusion and consistency proofs that make it checkable (VTI-VOT-050).
//!
//! The log holds leaf hashes only. What a leaf is — the JCS canonicalization of a board entry
//! (conventions §3.8) — is the caller's business: [`leaf_hash`] takes the entry's bytes.
//!
//! Proof generation follows RFC 9162 §2.1.3.1 (`PATH`) and §2.1.4.1 (`PROOF`/`SUBPROOF`);
//! verification follows §2.1.3.2 and §2.1.4.2, which work on the path alone, so an auditor
//! checks a proof without the log.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// `HASH(0x00 ‖ entry)`.
pub fn leaf_hash(entry: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(entry);
    h.finalize().into()
}

/// `HASH(0x01 ‖ left ‖ right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The hash of an empty tree: `HASH()`.
pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// The largest power of two strictly less than `n` (`n > 1`).
fn split(n: usize) -> usize {
    debug_assert!(n > 1);
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// An append-only log of leaf hashes.
#[derive(Debug, Default, Clone)]
pub struct Board {
    leaves: Vec<Hash>,
}

/// Why a proof cannot be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BoardError {
    #[error("tree size {size} exceeds the log's {len}")]
    SizeOutOfRange { size: usize, len: usize },
    #[error("leaf {index} is not within a tree of size {size}")]
    LeafOutOfRange { index: usize, size: usize },
    #[error("consistency needs 0 < first ({first}) <= second ({second})")]
    BadSizes { first: usize, second: usize },
}

impl Board {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild a board from leaf hashes already recorded, in order.
    pub fn from_leaves(leaves: Vec<Hash>) -> Self {
        Self { leaves }
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Append an entry; returns its index.
    pub fn append(&mut self, entry: &[u8]) -> usize {
        self.leaves.push(leaf_hash(entry));
        self.leaves.len() - 1
    }

    pub fn leaf(&self, index: usize) -> Option<&Hash> {
        self.leaves.get(index)
    }

    /// `MTH` of the first `size` leaves: the root a head of that size signs.
    ///
    /// # Errors
    /// [`BoardError::SizeOutOfRange`] beyond the log.
    pub fn root(&self, size: usize) -> Result<Hash, BoardError> {
        self.check_size(size)?;
        Ok(mth(&self.leaves[..size]))
    }

    /// The audit path of leaf `index` in the tree of the first `size` leaves.
    ///
    /// # Errors
    /// [`BoardError::SizeOutOfRange`], [`BoardError::LeafOutOfRange`].
    pub fn inclusion_proof(&self, index: usize, size: usize) -> Result<Vec<Hash>, BoardError> {
        self.check_size(size)?;
        if index >= size {
            return Err(BoardError::LeafOutOfRange { index, size });
        }
        let mut path = Vec::new();
        audit_path(index, &self.leaves[..size], &mut path);
        Ok(path)
    }

    /// The consistency proof between the trees of the first `first` and `second` leaves.
    ///
    /// # Errors
    /// [`BoardError::SizeOutOfRange`], [`BoardError::BadSizes`].
    pub fn consistency_proof(&self, first: usize, second: usize) -> Result<Vec<Hash>, BoardError> {
        self.check_size(second)?;
        if first == 0 || first > second {
            return Err(BoardError::BadSizes { first, second });
        }
        let mut path = Vec::new();
        subproof(first, &self.leaves[..second], true, &mut path);
        Ok(path)
    }

    fn check_size(&self, size: usize) -> Result<(), BoardError> {
        if size > self.leaves.len() {
            Err(BoardError::SizeOutOfRange {
                size,
                len: self.leaves.len(),
            })
        } else {
            Ok(())
        }
    }
}

/// `MTH(D[n])`.
fn mth(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

/// `PATH(m, D[n])`, leaf-first.
fn audit_path(m: usize, leaves: &[Hash], out: &mut Vec<Hash>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split(n);
    if m < k {
        audit_path(m, &leaves[..k], out);
        out.push(mth(&leaves[k..]));
    } else {
        audit_path(m - k, &leaves[k..], out);
        out.push(mth(&leaves[..k]));
    }
}

/// `SUBPROOF(m, D[n], b)`.
fn subproof(m: usize, leaves: &[Hash], b: bool, out: &mut Vec<Hash>) {
    let n = leaves.len();
    if m == n {
        if !b {
            out.push(mth(leaves));
        }
        return;
    }
    let k = split(n);
    if m <= k {
        subproof(m, &leaves[..k], b, out);
        out.push(mth(&leaves[k..]));
    } else {
        subproof(m - k, &leaves[k..], false, out);
        out.push(mth(&leaves[..k]));
    }
}

/// RFC 9162 §2.1.3.2: does `path` prove `leaf` at `index` in a tree of `size` with `root`?
pub fn verify_inclusion(
    index: usize,
    size: usize,
    leaf: &Hash,
    path: &[Hash],
    root: &Hash,
) -> bool {
    if index >= size {
        return false;
    }
    let (mut fnn, mut sn) = (index, size - 1);
    let mut r = *leaf;
    for p in path {
        if sn == 0 {
            return false;
        }
        if fnn & 1 == 1 || fnn == sn {
            r = node_hash(p, &r);
            if fnn & 1 == 0 {
                while fnn & 1 == 0 && fnn != 0 {
                    fnn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

/// RFC 9162 §2.1.4.2: does `path` prove the tree of `second` with `second_root` extends the
/// tree of `first` with `first_root`? Equal sizes need an empty path and equal roots.
pub fn verify_consistency(
    first: usize,
    second: usize,
    first_root: &Hash,
    second_root: &Hash,
    path: &[Hash],
) -> bool {
    if first == 0 || first > second {
        return false;
    }
    if first == second {
        return path.is_empty() && first_root == second_root;
    }
    // When `first` is an exact power of two, the first tree's root is the proof's implicit
    // first node.
    let mut path: Vec<Hash> = path.to_vec();
    if first.is_power_of_two() {
        path.insert(0, *first_root);
    }
    let Some((head, rest)) = path.split_first() else {
        return false;
    };
    let (mut fnn, mut sn) = (first - 1, second - 1);
    while fnn & 1 == 1 {
        fnn >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (*head, *head);
    for c in rest {
        if sn == 0 {
            return false;
        }
        if fnn & 1 == 1 || fnn == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fnn & 1 == 0 {
                while fnn & 1 == 0 && fnn != 0 {
                    fnn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    sn == 0 && fr == *first_root && sr == *second_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(h: &Hash) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The eight leaves of the Certificate Transparency reference test vectors
    /// (RFC 6962's `merkle_tree_test.cc`, unchanged under RFC 9162's hashing).
    fn reference_board() -> Board {
        let inputs: [&[u8]; 8] = [
            b"",
            &[0x00],
            &[0x10],
            &[0x20, 0x21],
            &[0x30, 0x31],
            &[0x40, 0x41, 0x42, 0x43],
            &[0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            &[
                0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
                0x6e, 0x6f,
            ],
        ];
        let mut b = Board::new();
        for i in inputs {
            b.append(i);
        }
        b
    }

    #[test]
    fn roots_match_the_reference_vectors() {
        let b = reference_board();
        let expected = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        for (i, e) in expected.iter().enumerate() {
            assert_eq!(hex(&b.root(i + 1).unwrap()), *e, "size {}", i + 1);
        }
        assert_eq!(
            hex(&Board::new().root(0).unwrap()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn every_inclusion_proof_verifies_and_a_wrong_one_does_not() {
        let b = reference_board();
        for size in 1..=b.len() {
            let root = b.root(size).unwrap();
            for index in 0..size {
                let path = b.inclusion_proof(index, size).unwrap();
                let leaf = *b.leaf(index).unwrap();
                assert!(verify_inclusion(index, size, &leaf, &path, &root));
                if size > 1 {
                    let other = *b.leaf((index + 1) % size).unwrap();
                    assert!(!verify_inclusion(index, size, &other, &path, &root));
                }
                // Claimed against a later head, a path for this size proves nothing.
                if size < b.len() {
                    let later = b.root(size + 1).unwrap();
                    assert!(!verify_inclusion(index, size + 1, &leaf, &path, &later));
                }
            }
        }
    }

    #[test]
    fn every_consistency_proof_verifies_and_a_rewrite_does_not() {
        let b = reference_board();
        for second in 1..=b.len() {
            for first in 1..=second {
                let path = b.consistency_proof(first, second).unwrap();
                let (r1, r2) = (b.root(first).unwrap(), b.root(second).unwrap());
                assert!(
                    verify_consistency(first, second, &r1, &r2, &path),
                    "{first} -> {second}"
                );
            }
        }
        // A board that rewrote an early entry is not consistent with a head taken before.
        let mut rewritten = Board::new();
        rewritten.append(b"tampered");
        for i in 1..b.len() {
            rewritten.leaves.push(*b.leaf(i).unwrap());
        }
        let path = rewritten.consistency_proof(3, 8).unwrap();
        assert!(!verify_consistency(
            3,
            8,
            &b.root(3).unwrap(),
            &rewritten.root(8).unwrap(),
            &path
        ));
    }

    #[test]
    fn proof_sizes_stay_logarithmic() {
        let mut b = Board::new();
        for i in 0u32..300_000 {
            b.append(&i.to_be_bytes());
        }
        assert!(b.inclusion_proof(123_456, 300_000).unwrap().len() <= 19);
        assert!(b.consistency_proof(100_000, 300_000).unwrap().len() <= 38);
    }
}
