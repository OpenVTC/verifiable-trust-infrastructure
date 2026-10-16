//! A credential's proof must be its issuer's.
//!
//! Resolving whatever `verificationMethod` a proof names and verifying the signature
//! against it proves only that *somebody* signed the credential — which is equally true of
//! a forgery that names a victim as `issuer` and points the proof at the forger's own key.
//! What makes the signature the issuer's is that the method sits under the issuer's DID
//! (trust-tasks framework SPEC §4.7; W3C VC Data Integrity: the verification method must be
//! one the issuer controls).
//!
//! Shared by every issuer-bound verifier in the workspace — the VTC's credential-exchange,
//! recognition and relationship paths, and the room credential opener in `vti-rooms-dtg` —
//! so the rule exists once.

use crate::error::AppError;

/// Refuse unless `vm` is a DID URL under `issuer_did`.
///
/// Exact string equality of the DID, and the method must be a DID URL with a non-empty
/// fragment: a bare DID names no verification method. A relative `#fragment` method is
/// refused — every producer in this workspace emits absolute methods, and a proof whose
/// signer cannot be read off it without context is one nobody should have to guess at.
///
/// The message names the rule, not the identifiers, so a refusal is no oracle for which
/// DIDs a verifier compared.
pub fn check_issuer_binding(vm: &str, issuer_did: &str) -> Result<(), AppError> {
    match vm.split_once('#') {
        Some((base, fragment)) if !fragment.is_empty() && base == issuer_did => Ok(()),
        Some((_, fragment)) if !fragment.is_empty() => Err(AppError::Validation(
            "proof verificationMethod is not under the credential's issuer".to_string(),
        )),
        _ => Err(AppError::Validation(
            "proof verificationMethod is not a DID URL naming a verification method".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_binding_is_exact_and_needs_a_fragment() {
        check_issuer_binding("did:web:a.example#key-0", "did:web:a.example").expect("bound");
        assert!(check_issuer_binding("did:web:b.example#key-0", "did:web:a.example").is_err());
        assert!(check_issuer_binding("did:web:a.example", "did:web:a.example").is_err());
        assert!(check_issuer_binding("did:web:a.example#", "did:web:a.example").is_err());
        // Relative: resolves against nothing the proof itself states.
        assert!(check_issuer_binding("#key-0", "did:web:a.example").is_err());
        // A prefix is not the DID.
        assert!(check_issuer_binding("did:web:a.example:x#key-0", "did:web:a.example").is_err());
        let err = check_issuer_binding("did:web:b.example#key-0", "did:web:a.example")
            .unwrap_err()
            .to_string();
        assert!(
            !err.contains("a.example"),
            "no identifiers in the refusal: {err}"
        );
    }
}
