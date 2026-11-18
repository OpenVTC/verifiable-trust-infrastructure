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
///
/// Deliberately exhaustive: a domain a signer does not know must not be signed
/// in, so every `match` has to weigh a new one rather than default it. The
/// workspace's `non_exhaustive_census` holds it to that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    fn an_opaque_payload_is_not_signed_as_presented() {
        let payload = b"{\"alg\":\"none\"}";
        assert_ne!(
            SigningDomain::Opaque.signing_input(payload).as_ref(),
            payload,
            "an opaque payload is framed before signing, or the signature over it \
             verifies as whatever the payload happens to be"
        );
    }

    #[test]
    fn protocol_defined_bytes_are_signed_as_presented() {
        let payload = b"canonicalised proof input";
        assert_eq!(
            SigningDomain::ProtocolDefined
                .signing_input(payload)
                .as_ref(),
            payload,
            "framing these would produce a proof a conforming verifier rejects"
        );
    }

    /// The point of the exercise: a signature obtained from the opaque
    /// operation must not verify as a document in another domain, and vice
    /// versa.
    #[test]
    fn the_two_domains_never_agree_on_the_bytes() {
        for payload in [
            b"".as_slice(),
            b"x".as_slice(),
            OPAQUE_SIGNING_DOMAIN_V1, // a payload that starts like the tag
        ] {
            assert_ne!(
                SigningDomain::Opaque.signing_input(payload),
                SigningDomain::ProtocolDefined.signing_input(payload),
            );
        }
    }

    /// The framing is unambiguous however the payload begins: the tag carries
    /// no NUL, so the first NUL is always the separator.
    #[test]
    fn the_framing_cannot_be_forged_by_a_chosen_payload() {
        assert!(
            !OPAQUE_SIGNING_DOMAIN_V1.contains(&0x00),
            "a NUL in the tag would make the separator ambiguous"
        );

        // A caller who prefixes the tag themselves does not thereby produce
        // the same signing input as the framing does.
        let mut impersonating = OPAQUE_SIGNING_DOMAIN_V1.to_vec();
        impersonating.push(0x00);
        impersonating.extend_from_slice(b"payload");

        assert_ne!(
            SigningDomain::Opaque.signing_input(&impersonating),
            SigningDomain::Opaque.signing_input(b"payload"),
            "framing is applied once by the VTA, not something a caller can pre-apply"
        );
    }

    #[test]
    fn a_verifier_can_reconstruct_what_was_signed() {
        let payload = b"an assertion";
        assert_eq!(
            opaque_signing_input(payload),
            SigningDomain::Opaque.signing_input(payload).into_owned(),
        );
    }

    #[test]
    fn an_opaque_payload_is_framed_under_the_tag_and_a_nul() {
        assert_eq!(
            opaque_signing_input(b"payload"),
            b"vti.vta.opaque-signing.v1\0payload".to_vec()
        );
    }
}
