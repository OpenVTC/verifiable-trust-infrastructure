//! `keys/sign-sshsig/0.1` — an SSHSIG signature (OpenSSH `PROTOCOL.sshsig`, the
//! format git verifies for `gpg.format = ssh`) over a message digest, made by a
//! VTA-held key that never leaves the VTA.
//!
//! The wire types are the generated ones. What lives here is the one piece of
//! behaviour both ends need to agree on byte for byte: the signed data. The VTA
//! builds it from the request and signs that — never bytes the caller chose —
//! and a client verifying the answer rebuilds it the same way.

pub use vti_specs::keys::sign_sshsig::v0_1::{
    Payload as SignSshsigPayload, PayloadAlgorithm as SignSshsigAlgorithm,
    PayloadHashAlgorithm as SshsigHashAlgorithm, Response as SignSshsigResponse,
    ResponseAlgorithm as SignSshsigResponseAlgorithm, error_codes,
};

// The statement an SSHSIG signature covers is the signing core's: one definition
// for the VTA that signs it and a client that verifies it.
pub use vta_signing::sshsig::{SSHSIG_MAGIC, signed_data};

use vta_signing::sshsig::SshsigHash;

/// The signing core's name for `alg`, when it is one the core signs.
fn core_hash(alg: &SshsigHashAlgorithm) -> Option<SshsigHash> {
    match alg {
        SshsigHashAlgorithm::Sha256 => Some(SshsigHash::Sha256),
        SshsigHashAlgorithm::Sha512 => Some(SshsigHash::Sha512),
        _ => None,
    }
}

/// The SSHSIG spelling of `alg` — what goes into the signed data.
#[must_use]
pub fn hash_algorithm_name(alg: &SshsigHashAlgorithm) -> Option<&'static str> {
    core_hash(alg).map(SshsigHash::name)
}

/// The digest length `alg` produces, in bytes.
#[must_use]
pub fn digest_len(alg: &SshsigHashAlgorithm) -> Option<usize> {
    core_hash(alg).map(SshsigHash::digest_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire enum maps onto the core's algorithms: the spelling that goes into
    /// the signed data and the digest length the VTA checks the request against.
    #[test]
    fn the_wire_hash_algorithms_map_to_the_cores_spelling_and_length() {
        assert_eq!(
            hash_algorithm_name(&SshsigHashAlgorithm::Sha256),
            Some("sha256")
        );
        assert_eq!(
            hash_algorithm_name(&SshsigHashAlgorithm::Sha512),
            Some("sha512")
        );
        assert_eq!(digest_len(&SshsigHashAlgorithm::Sha256), Some(32));
        assert_eq!(digest_len(&SshsigHashAlgorithm::Sha512), Some(64));
    }

    #[test]
    fn the_signed_data_is_the_cores() {
        assert_eq!(
            &signed_data("git", "sha512", &[0xAB; 64])[..6],
            SSHSIG_MAGIC
        );
    }
}
