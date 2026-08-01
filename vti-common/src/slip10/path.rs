//! BIP-32 style derivation paths (`m/44'/0'/0'`).
//!
//! This is the parsing half of [`crate::slip10`]. It replaces the
//! `derivation-path` crate, which reached us transitively through
//! `ed25519-dalek-bip32`. Only the subset SLIP-0010 needs is kept: the
//! BIP-44/BIP-49 constructors and the `DerivationPathType` classifier that
//! crate also carried have no consumer in this workspace.
//!
//! Parsing semantics are deliberately byte-for-byte identical to
//! `derivation-path` 0.2.0 — a path string that parsed before must parse to
//! the same `ChildIndex` sequence now, and one that failed before must still
//! fail. Operators have these strings baked into stored key records, so a
//! parser that is merely "equivalent for sensible inputs" is not good enough.

use std::fmt;
use std::str::FromStr;

/// A single element of a derivation path.
///
/// The distinction is load-bearing for SLIP-0010: Ed25519 supports *only*
/// hardened derivation, so [`ChildIndex::Normal`] is representable (it has to
/// be — operators can type it) but is rejected at derivation time by
/// [`crate::slip10::ExtendedSigningKey::derive_child`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ChildIndex {
    /// A non-hardened index. Parsed and displayed, never derivable on Ed25519.
    Normal(u32),
    /// A hardened index — written with a trailing `'`.
    Hardened(u32),
}

/// Failure building a [`ChildIndex`] from a raw number.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ChildIndexError {
    /// The index set bit 31, which is reserved to encode hardening.
    #[error("number too large: {0}")]
    NumberTooLarge(u32),
}

/// Failure parsing a [`ChildIndex`] from a string.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ChildIndexParseError {
    /// The digits were not a valid `u32`.
    #[error("could not parse child index: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
    /// The number parsed but was out of range.
    #[error("invalid child index: {0}")]
    ChildIndex(#[from] ChildIndexError),
}

impl ChildIndex {
    /// Build a hardened index. Fails if `num` has bit 31 set.
    pub fn hardened(num: u32) -> Result<Self, ChildIndexError> {
        Ok(Self::Hardened(Self::check_size(num)?))
    }

    /// Build a normal (non-hardened) index. Fails if `num` has bit 31 set.
    pub fn normal(num: u32) -> Result<Self, ChildIndexError> {
        Ok(Self::Normal(Self::check_size(num)?))
    }

    fn check_size(num: u32) -> Result<u32, ChildIndexError> {
        if num & (1 << 31) == 0 {
            Ok(num)
        } else {
            Err(ChildIndexError::NumberTooLarge(num))
        }
    }

    /// The index without its hardening flag.
    #[inline]
    pub fn to_u32(self) -> u32 {
        match self {
            Self::Hardened(index) | Self::Normal(index) => index,
        }
    }

    /// The wire encoding: bit 31 set for hardened, clear for normal.
    ///
    /// This is what gets fed to the HMAC in SLIP-0010 child derivation, so it
    /// must stay big-endian-serialised exactly as BIP-32 specifies.
    #[inline]
    pub fn to_bits(self) -> u32 {
        match self {
            Self::Hardened(index) => (1 << 31) | index,
            Self::Normal(index) => index,
        }
    }

    /// Inverse of [`ChildIndex::to_bits`].
    #[inline]
    pub fn from_bits(bits: u32) -> Self {
        if bits & (1 << 31) == 0 {
            Self::Normal(bits)
        } else {
            Self::Hardened(bits & !(1 << 31))
        }
    }

    /// Whether this index is hardened.
    #[inline]
    pub fn is_hardened(self) -> bool {
        matches!(self, Self::Hardened(_))
    }

    /// Whether this index is non-hardened.
    #[inline]
    pub fn is_normal(self) -> bool {
        matches!(self, Self::Normal(_))
    }
}

impl fmt::Display for ChildIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.to_u32(), f)?;
        if self.is_hardened() {
            f.write_str("'")?;
        }
        Ok(())
    }
}

impl FromStr for ChildIndex {
    type Err = ChildIndexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut chars = s.chars();
        Ok(match chars.next_back() {
            Some('\'') => Self::hardened(u32::from_str(chars.as_str())?)?,
            // Includes the empty-string case, which falls through to a
            // `ParseIntError` — same as `derivation-path` 0.2.0.
            _ => Self::normal(u32::from_str(s)?)?,
        })
    }
}

/// Failure parsing a [`DerivationPath`] from a string.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DerivationPathParseError {
    /// The input was empty.
    #[error("empty")]
    Empty,
    /// The path did not start with `m`.
    #[error("invalid prefix: {0}")]
    InvalidPrefix(String),
    /// One of the `/`-separated segments was not a valid index.
    #[error("invalid child index: {0}")]
    InvalidChildIndex(#[from] ChildIndexParseError),
}

/// An ordered list of [`ChildIndex`] items, e.g. `m/26'/2'/0'/1'`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivationPath(Box<[ChildIndex]>);

impl DerivationPath {
    /// Build a path from a list of indexes.
    #[inline]
    pub fn new<P: Into<Box<[ChildIndex]>>>(path: P) -> Self {
        Self(path.into())
    }

    /// The indexes, in order from the master key outward.
    #[inline]
    pub fn path(&self) -> &[ChildIndex] {
        &self.0
    }

    /// Number of derivation steps. `m` alone has length 0.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the bare master path `m`.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for index in self.path() {
            f.write_str("/")?;
            fmt::Display::fmt(index, f)?;
        }
        Ok(())
    }
}

impl FromStr for DerivationPath {
    type Err = DerivationPathParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(DerivationPathParseError::Empty);
        }
        let mut parts = s.split('/');
        // `split` on a non-empty string always yields at least one item.
        match parts.next().expect("split yields at least one segment") {
            "m" => (),
            prefix => return Err(DerivationPathParseError::InvalidPrefix(prefix.to_owned())),
        }
        let path = parts
            .map(|part| ChildIndex::from_str(part).map_err(DerivationPathParseError::from))
            .collect::<Result<Box<[ChildIndex]>, _>>()?;
        Ok(Self::new(path))
    }
}

impl AsRef<[ChildIndex]> for DerivationPath {
    fn as_ref(&self) -> &[ChildIndex] {
        self.path()
    }
}

impl<'a> IntoIterator for &'a DerivationPath {
    type IntoIter = std::slice::Iter<'a, ChildIndex>;
    type Item = &'a ChildIndex;

    fn into_iter(self) -> Self::IntoIter {
        self.path().iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_workspace_key_hierarchy_shape() {
        // The real shape from `vta-keys::paths`: m/26'/2'/<ctx>'/<key>'.
        let path: DerivationPath = "m/26'/2'/0'/17'".parse().unwrap();
        assert_eq!(
            path.path(),
            &[
                ChildIndex::Hardened(26),
                ChildIndex::Hardened(2),
                ChildIndex::Hardened(0),
                ChildIndex::Hardened(17),
            ]
        );
        assert_eq!(path.to_string(), "m/26'/2'/0'/17'");
    }

    #[test]
    fn round_trips_mixed_hardened_and_normal() {
        let path: DerivationPath = "m/44'/0'/0'/1/0".parse().unwrap();
        assert_eq!(path.path()[3], ChildIndex::Normal(1));
        assert_eq!(path.path()[4], ChildIndex::Normal(0));
        assert_eq!(path.to_string(), "m/44'/0'/0'/1/0");
    }

    #[test]
    fn bare_master_path_is_empty() {
        let path: DerivationPath = "m".parse().unwrap();
        assert!(path.is_empty());
        assert_eq!(path.to_string(), "m");
    }

    #[test]
    fn rejects_empty_input() {
        assert!(matches!(
            "".parse::<DerivationPath>(),
            Err(DerivationPathParseError::Empty)
        ));
    }

    #[test]
    fn rejects_a_missing_or_wrong_prefix() {
        // `derivation-path` 0.2.0 rejected both of these; so must we.
        assert!(matches!(
            "44'/0'/0'".parse::<DerivationPath>(),
            Err(DerivationPathParseError::InvalidPrefix(_))
        ));
        assert!(matches!(
            "not/a/valid/path".parse::<DerivationPath>(),
            Err(DerivationPathParseError::InvalidPrefix(_))
        ));
        assert!(matches!(
            "M/44'".parse::<DerivationPath>(),
            Err(DerivationPathParseError::InvalidPrefix(_))
        ));
    }

    #[test]
    fn rejects_a_trailing_separator() {
        // "m/" splits to ["m", ""] and the empty segment must fail to parse.
        assert!("m/".parse::<DerivationPath>().is_err());
    }

    #[test]
    fn rejects_an_index_with_bit_31_set() {
        // 2^31 is not representable: that bit encodes hardening.
        assert!("m/2147483648'".parse::<DerivationPath>().is_err());
        assert!("m/2147483648".parse::<DerivationPath>().is_err());
        // 2^31 - 1 is the largest legal index.
        let path: DerivationPath = "m/2147483647'".parse().unwrap();
        assert_eq!(path.path()[0], ChildIndex::Hardened(2147483647));
    }

    #[test]
    fn rejects_non_numeric_segments() {
        assert!("m/abc'".parse::<DerivationPath>().is_err());
        assert!("m/-1".parse::<DerivationPath>().is_err());
        assert!("m/1''".parse::<DerivationPath>().is_err());
    }

    #[test]
    fn bit_encoding_round_trips() {
        for index in [
            ChildIndex::Normal(0),
            ChildIndex::Normal(2147483647),
            ChildIndex::Hardened(0),
            ChildIndex::Hardened(26),
            ChildIndex::Hardened(2147483647),
        ] {
            assert_eq!(ChildIndex::from_bits(index.to_bits()), index);
        }
        assert_eq!(ChildIndex::Hardened(0).to_bits(), 0x8000_0000);
        assert_eq!(ChildIndex::Normal(0).to_bits(), 0);
    }

    #[test]
    fn rejects_out_of_range_constructors() {
        assert!(ChildIndex::hardened(1 << 31).is_err());
        assert!(ChildIndex::normal(1 << 31).is_err());
        assert!(ChildIndex::hardened((1 << 31) - 1).is_ok());
    }
}
