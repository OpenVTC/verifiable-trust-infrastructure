//! The `chunkedTrustTask` backup transfer algorithm — the shape both ends share.
//!
//! A backup bundle moves as a sequence of Trust Task documents over whatever
//! transport already carries the control plane, instead of over the VTA's HTTPS
//! blob endpoint. That is what makes a backup possible for a VTA reachable only
//! over DIDComm or TSP. The algorithm is specified once, in
//! `vta/backup/initiate-export/1.1` § Chunked transfer
//! (trustoverip/dtgwg-trust-tasks-tf#474); the wire types are the generated
//! modules re-exported below, and this module holds only the arithmetic and the
//! digest encoding both ends must agree on.
//!
//! Hashing is left to the caller: this module is compiled without `sha2`, and a
//! caller passes the 32 raw SHA-256 bytes in. The encoding — a sha2-256
//! multihash, base58btc multibase — lives here so there is one of it.

pub use trust_tasks_rs::specs::vta::backup::{
    finalize_import::v1_1 as finalize_import_1_1, get_chunk::v1_0 as get_chunk,
    initiate_export::v1_1 as initiate_export_1_1, initiate_import::v1_1 as initiate_import_1_1,
    put_chunk::v1_0 as put_chunk,
};

/// The algorithm name on the wire.
///
/// lowerCamelCase because trusttasks SPEC §4.10 requires it of a value a
/// specification defines; earlier VTI design notes wrote `chunked-trust-task`.
pub const ALGORITHM_CHUNKED: &str = "chunkedTrustTask";

/// The `stream` algorithm: one HTTPS transfer against the VTA's blob endpoint.
pub const ALGORITHM_STREAM: &str = "stream";

/// Largest chunk, in raw bytes. Normative: the largest power of two whose
/// chunk document survives base64url, DIDComm authcrypt and two nested forward
/// wrappers inside a 1 MiB mediator message (the derivation is in the spec).
pub const MAX_CHUNK_SIZE: u64 = 262_144;

/// Smallest chunk size a manifest may declare.
pub const MIN_CHUNK_SIZE: u64 = 16_384;

/// Largest chunk count, so the manifest — one digest per chunk — fits in one
/// message too. Together with [`MAX_CHUNK_SIZE`] this caps a bundle at 1 GiB.
pub const MAX_CHUNK_COUNT: u64 = 4_096;

/// Number of chunks a bundle of `size` bytes divides into at `chunk_size`.
///
/// `None` when `chunk_size` is outside the normative bounds or the count would
/// exceed [`MAX_CHUNK_COUNT`] — the caller refuses rather than truncating.
pub fn chunk_count(size: u64, chunk_size: u64) -> Option<u64> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) || size == 0 {
        return None;
    }
    let count = size.div_ceil(chunk_size);
    (count <= MAX_CHUNK_COUNT).then_some(count)
}

/// Byte range `[start, end)` of chunk `index` in a bundle of `size` bytes, or
/// `None` for an index past the last chunk.
pub fn chunk_range(size: u64, chunk_size: u64, index: u64) -> Option<(u64, u64)> {
    let count = chunk_count(size, chunk_size)?;
    if index >= count {
        return None;
    }
    let start = index * chunk_size;
    Some((start, (start + chunk_size).min(size)))
}

/// Encode 32 raw SHA-256 bytes as the spec's `DigestMultibase`: a sha2-256
/// multihash (`0x12 0x20` ‖ digest), base58btc.
pub fn sha256_digest_multibase(digest: &[u8; 32]) -> String {
    let mut mh = Vec::with_capacity(34);
    mh.extend_from_slice(&[0x12, 0x20]);
    mh.extend_from_slice(digest);
    multibase::encode(multibase::Base::Base58Btc, mh)
}

/// Decode a `DigestMultibase` to its 32 SHA-256 bytes.
///
/// `None` for anything that is not a sha2-256 multihash, in either permitted
/// base. The spec requires comparing decoded multihash bytes rather than
/// strings, and requires a party that does not implement the named hash to
/// treat the value as unverifiable — never to skip the check — so an unknown
/// algorithm is a refusal here, not a pass.
pub fn sha256_from_digest_multibase(value: &str) -> Option<[u8; 32]> {
    let (_base, bytes) = multibase::decode(value).ok()?;
    match bytes.split_at_checked(2) {
        Some(([0x12, 0x20], digest)) => digest.try_into().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_follow_the_ceiling_formula() {
        // The spec's worked example: 524300 bytes in 256 KiB chunks is two full
        // chunks and a 12-byte remainder.
        assert_eq!(chunk_count(524_300, MAX_CHUNK_SIZE), Some(3));
        assert_eq!(
            chunk_range(524_300, MAX_CHUNK_SIZE, 2),
            Some((524_288, 524_300))
        );
        assert_eq!(chunk_range(524_300, MAX_CHUNK_SIZE, 3), None);
        assert_eq!(chunk_count(MAX_CHUNK_SIZE, MAX_CHUNK_SIZE), Some(1));
    }

    #[test]
    fn out_of_bound_sizes_are_refused_not_clamped() {
        assert_eq!(chunk_count(10, MAX_CHUNK_SIZE + 1), None);
        assert_eq!(chunk_count(10, MIN_CHUNK_SIZE - 1), None);
        assert_eq!(chunk_count(0, MAX_CHUNK_SIZE), None);
        // One byte past what 4096 chunks can hold.
        assert_eq!(
            chunk_count(MAX_CHUNK_COUNT * MAX_CHUNK_SIZE + 1, MAX_CHUNK_SIZE),
            None
        );
    }

    #[cfg(feature = "client")]
    #[test]
    fn digest_round_trips_and_matches_the_spec_example() {
        // chunk 2 of the specification's example bundle is b"backup-tail!".
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(b"backup-tail!").into();
        let encoded = sha256_digest_multibase(&digest);
        assert_eq!(encoded, "zQmTcWLvAPe4Txz32vVqZe5jgX4nBPiaBsTTCp4bLXDMzTT");
        assert_eq!(sha256_from_digest_multibase(&encoded), Some(digest));
    }

    #[test]
    fn a_non_sha256_multihash_is_unverifiable() {
        // sha2-512 multihash prefix (0x13 0x40): well-formed, but not one this
        // build can compare, so it must not read as a match of anything.
        let mut mh = vec![0x13, 0x40];
        mh.extend_from_slice(&[0u8; 64]);
        let encoded = multibase::encode(multibase::Base::Base58Btc, mh);
        assert_eq!(sha256_from_digest_multibase(&encoded), None);
        assert_eq!(sha256_from_digest_multibase("not-multibase"), None);
    }
}
