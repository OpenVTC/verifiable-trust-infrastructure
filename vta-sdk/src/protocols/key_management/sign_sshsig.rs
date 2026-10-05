//! `keys/sign-sshsig/0.1` — an SSHSIG signature (OpenSSH `PROTOCOL.sshsig`, the
//! format git verifies for `gpg.format = ssh`) over a message digest, made by a
//! VTA-held key that never leaves the VTA.
//!
//! The wire types are the generated ones. What lives here is the one piece of
//! behaviour both ends need to agree on byte for byte: the signed data. The VTA
//! builds it from the request and signs that — never bytes the caller chose —
//! and a client verifying the answer rebuilds it the same way.

pub use trust_tasks_rs::specs::keys::sign_sshsig::v0_1::{
    Payload as SignSshsigPayload, PayloadAlgorithm as SignSshsigAlgorithm,
    PayloadHashAlgorithm as SshsigHashAlgorithm, Response as SignSshsigResponse,
    ResponseAlgorithm as SignSshsigResponseAlgorithm, error_codes,
};

/// `MAGIC_PREAMBLE` of `PROTOCOL.sshsig`. Every byte string the VTA signs for
/// this task begins with it, which is what keeps the signature from verifying
/// as anything but an SSHSIG statement.
pub const SSHSIG_MAGIC: &[u8; 6] = b"SSHSIG";

/// The SSHSIG spelling of `alg` — what goes into the signed data.
#[must_use]
pub fn hash_algorithm_name(alg: &SshsigHashAlgorithm) -> Option<&'static str> {
    match alg {
        SshsigHashAlgorithm::Sha256 => Some("sha256"),
        SshsigHashAlgorithm::Sha512 => Some("sha512"),
        _ => None,
    }
}

/// The digest length `alg` produces, in bytes.
#[must_use]
pub fn digest_len(alg: &SshsigHashAlgorithm) -> Option<usize> {
    match alg {
        SshsigHashAlgorithm::Sha256 => Some(32),
        SshsigHashAlgorithm::Sha512 => Some(64),
        _ => None,
    }
}

/// The bytes an SSHSIG signature is made over:
///
/// ```text
/// byte[6]  "SSHSIG"
/// string   namespace
/// string   reserved (empty)
/// string   hash_algorithm
/// string   H(message)
/// ```
///
/// with `string` the RFC 4251 §5 encoding (big-endian `u32` length, then the
/// bytes).
#[must_use]
pub fn signed_data(namespace: &str, hash_algorithm: &str, message_hash: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        SSHSIG_MAGIC.len() + 16 + namespace.len() + hash_algorithm.len() + message_hash.len(),
    );
    out.extend_from_slice(SSHSIG_MAGIC);
    for field in [
        namespace.as_bytes(),
        b"",
        hash_algorithm.as_bytes(),
        message_hash,
    ] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Ed25519 public key of the specification's example, base64url.
    const EXAMPLE_PUBLIC_KEY: &str = "HIZTeh5BcFIwYJ8AQ9_NgxmdwQpC7THQ8r4CnPDRs0I";

    /// The layout `ssh-keygen -Y sign` signs, checked field by field.
    #[test]
    fn signed_data_is_the_sshsig_layout() {
        let hash = [0xAB; 64];
        let d = signed_data("git", "sha512", &hash);
        assert_eq!(&d[..6], b"SSHSIG");
        assert_eq!(&d[6..10], &3u32.to_be_bytes());
        assert_eq!(&d[10..13], b"git");
        assert_eq!(&d[13..17], &0u32.to_be_bytes());
        assert_eq!(&d[17..21], &6u32.to_be_bytes());
        assert_eq!(&d[21..27], b"sha512");
        assert_eq!(&d[27..31], &64u32.to_be_bytes());
        assert_eq!(&d[31..], &hash);
    }

    /// A signature `ssh-keygen -Y sign -n git` produced (the example in the
    /// specification) verifies over the bytes built here — the property the
    /// whole task rests on.
    #[test]
    fn an_openssh_signature_verifies_over_signed_data() {
        use base64::Engine;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let hash = b64
            .decode("ZNK6UR4HwIpHXYznMreGQrxQYoYkXyEqA9lXghSB8x0qCebX7kzmrrWkvpd-TTFuFZ7HD5DBVT80O19QxSt8FA")
            .unwrap();
        let sig = b64
            .decode("qQkWdYdoux5DnKSW0G1nIGQMrGC2L1RJkfuq9nrNuuAlU8hFazUPwKWlS3A68WWHs0DQxVbPl2GXjPUJdSIPBQ")
            .unwrap();
        let pk: [u8; 32] = b64.decode(EXAMPLE_PUBLIC_KEY).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        let sig = Signature::from_slice(&sig).unwrap();
        vk.verify(&signed_data("git", "sha512", &hash), &sig)
            .expect("OpenSSH signature verifies over the SSHSIG signed data");
        assert!(
            vk.verify(&signed_data("file", "sha512", &hash), &sig)
                .is_err(),
            "and not under another namespace"
        );
    }
}
