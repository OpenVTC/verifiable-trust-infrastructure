//! `keys/sign-sshsig/0.1`: the statement an SSHSIG signature is made over.
//!
//! The signer builds the statement from the namespace, the hash algorithm and
//! the message digest, never from bytes a caller chose, so a signature made here
//! verifies as an SSH signature and as nothing else.

use crate::{FormatRefusal, SignError, Signer};

#[cfg(test)]
use crate::PublicKey;

/// `SSHSIG` followed by its version, the magic every signed statement begins
/// with.
pub const SSHSIG_MAGIC: &[u8; 6] = b"SSHSIG";

/// The hash algorithms an SSHSIG statement names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SshsigHash {
    Sha256,
    Sha512,
}

impl SshsigHash {
    /// The SSHSIG spelling: what goes into the signed data.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// The digest length this algorithm produces, in bytes.
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
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

/// The statement to sign for `message_hash`, after checking it is the length
/// `hash` produces.
pub fn prepare_sshsig(
    namespace: &str,
    hash: SshsigHash,
    message_hash: &[u8],
) -> Result<Vec<u8>, FormatRefusal> {
    if message_hash.len() != hash.digest_len() {
        return Err(FormatRefusal::InvalidArgument(format!(
            "messageHash is {} bytes; {} produces {}",
            message_hash.len(),
            hash.name(),
            hash.digest_len()
        )));
    }
    Ok(signed_data(namespace, hash.name(), message_hash))
}

/// The raw signature over the SSHSIG statement for `message_hash`.
pub fn sign_sshsig(
    signer: &dyn Signer,
    namespace: &str,
    hash: SshsigHash,
    message_hash: &[u8],
) -> Result<Vec<u8>, SignError> {
    let statement = prepare_sshsig(namespace, hash, message_hash)?;
    signer.sign(&statement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningSecret;

    /// The layout `ssh-keygen -Y sign` signs, checked field by field.
    #[test]
    fn signed_data_is_the_sshsig_layout() {
        let data = signed_data("file", "sha512", &[0xAA; 64]);

        assert_eq!(&data[..6], b"SSHSIG");
        let mut rest = &data[6..];
        let mut fields = Vec::new();
        while !rest.is_empty() {
            let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            fields.push(rest[4..4 + len].to_vec());
            rest = &rest[4 + len..];
        }
        assert_eq!(
            fields,
            vec![
                b"file".to_vec(),
                Vec::new(),
                b"sha512".to_vec(),
                vec![0xAA; 64]
            ]
        );
    }

    /// A signature `ssh-keygen -Y sign -n git` produced (the example in the
    /// specification) verifies over the bytes built here — the property the
    /// whole task rests on.
    #[test]
    fn an_openssh_signature_verifies_over_signed_data() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        let hash = B64
            .decode("ZNK6UR4HwIpHXYznMreGQrxQYoYkXyEqA9lXghSB8x0qCebX7kzmrrWkvpd-TTFuFZ7HD5DBVT80O19QxSt8FA")
            .unwrap();
        let signature = B64
            .decode("qQkWdYdoux5DnKSW0G1nIGQMrGC2L1RJkfuq9nrNuuAlU8hFazUPwKWlS3A68WWHs0DQxVbPl2GXjPUJdSIPBQ")
            .unwrap();
        let key = PublicKey::Ed25519(
            B64.decode("HIZTeh5BcFIwYJ8AQ9_NgxmdwQpC7THQ8r4CnPDRs0I")
                .unwrap()
                .try_into()
                .unwrap(),
        );

        assert_eq!(
            key.verify(&signed_data("git", "sha512", &hash), &signature),
            Ok(())
        );
        assert!(
            key.verify(&signed_data("file", "sha512", &hash), &signature)
                .is_err()
        );
    }

    #[test]
    fn a_digest_of_the_wrong_length_is_refused_and_nothing_is_signed() {
        let signer = SigningSecret::ed25519([1; 32]);

        assert_eq!(
            sign_sshsig(&signer, "file", SshsigHash::Sha256, &[0; 31]),
            Err(SignError::Format(FormatRefusal::InvalidArgument(
                "messageHash is 31 bytes; sha256 produces 32".to_string()
            )))
        );
    }

    #[test]
    fn the_signature_verifies_over_the_statement_and_over_nothing_else() {
        let signer = SigningSecret::ed25519([1; 32]);
        let hash = [7u8; 32];

        let signature = sign_sshsig(&signer, "file", SshsigHash::Sha256, &hash).unwrap();

        let key = signer.public_key();
        assert_eq!(
            key.verify(&signed_data("file", "sha256", &hash), &signature),
            Ok(())
        );
        assert!(key.verify(&hash, &signature).is_err());
        assert!(
            key.verify(&signed_data("other", "sha256", &hash), &signature)
                .is_err()
        );
    }

    #[test]
    fn the_hash_algorithms_spell_and_size_themselves() {
        assert_eq!(
            (SshsigHash::Sha256.name(), SshsigHash::Sha256.digest_len()),
            ("sha256", 32)
        );
        assert_eq!(
            (SshsigHash::Sha512.name(), SshsigHash::Sha512.digest_len()),
            ("sha512", 64)
        );
    }
}
