//! What a signature over bytes the signer did not build means.
//!
//! A signature is only meaningful against the question it answers, and a
//! signature over bytes whose meaning the signer never established answers
//! every question at once. So a caller states which case it is in, and the two
//! cases are not interchangeable (see [`SigningDomain`]).

/// Domain-separation tag for payloads the signer cannot inspect.
///
/// Contains no NUL, so `TAG || 0x00 || payload` parses unambiguously however
/// the payload begins.
pub const OPAQUE_SIGNING_DOMAIN_V1: &[u8] = b"vti.vta.opaque-signing.v1";

/// The bytes actually signed for an opaque payload.
///
/// A verifier of a signature produced by the generic signing operation checks
/// it over **this**, not over the payload it supplied. Published here so a
/// verifier can reconstruct it without reimplementing the framing.
#[must_use]
pub fn opaque_signing_input(payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(OPAQUE_SIGNING_DOMAIN_V1.len() + 1 + payload.len());
    input.extend_from_slice(OPAQUE_SIGNING_DOMAIN_V1);
    input.push(0x00);
    input.extend_from_slice(payload);
    input
}

/// Which kind of bytes a signing request carries, and therefore whether the
/// signer signs them as presented.
///
/// # Why this is an argument rather than a default
///
/// Given an oracle that signs whatever it is handed under a principal's key, a
/// caller authorized for one purpose can obtain a signature that verifies as
/// something else entirely — an assertion in another protocol, a token, a proof
/// over a document the principal never saw. Authorizing *which key* signs
/// bounds the blast radius to that key; it says nothing about what the bytes
/// will be taken to mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigningDomain {
    /// The bytes are defined by a specification this signer implements — a
    /// data-integrity proof input, a task envelope — and that specification
    /// has already established what they mean and how a verifier reconstructs
    /// them. They are signed exactly as presented, because framing them again
    /// would produce a signature that specification's verifier rejects.
    ///
    /// Reachable only from inside the signer's own code, where the caller is
    /// the code that built the bytes.
    ProtocolDefined,

    /// The bytes came from a caller and the signer cannot parse them. They are
    /// signed under [`OPAQUE_SIGNING_DOMAIN_V1`], so the resulting signature
    /// verifies as *an opaque-signing payload* and as nothing else.
    ///
    /// This does not make signing arbitrary bytes safe; it makes the result
    /// unusable outside the domain it was requested in.
    Opaque,
}

impl SigningDomain {
    /// The bytes to sign for `payload` in this domain.
    #[must_use]
    pub fn signing_input(self, payload: &[u8]) -> std::borrow::Cow<'_, [u8]> {
        match self {
            Self::ProtocolDefined => std::borrow::Cow::Borrowed(payload),
            Self::Opaque => std::borrow::Cow::Owned(opaque_signing_input(payload)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_opaque_payload_is_framed_under_the_tag_and_a_nul() {
        assert_eq!(
            opaque_signing_input(b"payload"),
            b"vti.vta.opaque-signing.v1\0payload".to_vec()
        );
    }

    #[test]
    fn the_tag_carries_no_nul_so_framing_is_unambiguous() {
        assert!(!OPAQUE_SIGNING_DOMAIN_V1.contains(&0));
        assert_ne!(opaque_signing_input(b"\0x"), opaque_signing_input(b"x"));
    }

    #[test]
    fn a_protocol_defined_payload_is_signed_as_presented_and_an_opaque_one_framed() {
        assert_eq!(
            SigningDomain::ProtocolDefined
                .signing_input(b"as is")
                .as_ref(),
            b"as is"
        );
        assert_eq!(
            SigningDomain::Opaque.signing_input(b"x").as_ref(),
            opaque_signing_input(b"x").as_slice()
        );
    }
}
