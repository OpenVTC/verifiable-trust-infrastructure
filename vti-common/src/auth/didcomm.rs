//! Shared authentication guard for just-unpacked DIDComm envelopes.
//!
//! `ATM::unpack` (affinidi-messaging-sdk) authenticates the JWE `skid` sender
//! key and surfaces it as `encrypted_from_kid`, but it does **not** compare that
//! key's DID to the inner plaintext `from` header — nor does it reject
//! plaintext / anoncrypt envelopes. Any handler that consumes `atm.unpack`
//! directly and then trusts `msg.from` as a proven signer is therefore open to
//! the authentication-bypass class: an attacker authcrypts with their
//! *own* key (so `encrypted` and `authenticated` are both true) while claiming a
//! victim's `from`, and the handler mistakes them for the victim.
//!
//! The DIDComm *transport* path already binds the two — its `to_inbound` only
//! surfaces a sender when `from == encrypted_from_kid`'s DID. These helpers give
//! the direct-`unpack` callers (the REST `/auth/*` handlers, vault unseal) the
//! same guarantee. They take primitive fields rather than the SDK metadata
//! struct so `vti-common` needn't depend on the messaging SDK.

/// Reject a DIDComm envelope that wasn't sender-authenticated **and** encrypted
/// (i.e. authcrypt). `subject` names the message for the error text (e.g.
/// `"authenticate message"`, `"sealed secret"`).
pub fn require_authcrypt(
    encrypted: bool,
    authenticated: bool,
    subject: &str,
) -> Result<(), String> {
    if encrypted && authenticated {
        Ok(())
    } else {
        Err(format!(
            "{subject} must be an authenticated (authcrypt) DIDComm envelope"
        ))
    }
}

/// Verify an unpacked envelope is authcrypt **and** that its plaintext `from`
/// matches the DID of the key that actually authenticated it, returning that
/// cryptographically-bound sender DID (with any `#fragment` stripped).
///
/// `from` is the inner message's `from` header; `encrypted_from_kid` is the
/// authenticated sender key id from unpack metadata. Callers pass the returned
/// (proven) sender on to authorization; they must **not** trust `from` on their
/// own. See the module docs for the rationale.
pub fn bind_authcrypt_sender(
    from: Option<&str>,
    encrypted: bool,
    authenticated: bool,
    encrypted_from_kid: Option<&str>,
    subject: &str,
) -> Result<String, String> {
    require_authcrypt(encrypted, authenticated, subject)?;

    let kid = encrypted_from_kid
        .ok_or_else(|| format!("{subject} is authcrypt but carries no authenticated sender key"))?;
    let key_did = base_did(kid);

    match from.map(base_did) {
        Some(from_did) if from_did == key_did => Ok(key_did.to_string()),
        Some(from_did) => Err(format!(
            "{subject} sender mismatch: plaintext from `{from_did}` does not match the authenticated sender `{key_did}`"
        )),
        None => Err(format!("{subject} has no sender (from)")),
    }
}

/// Strip a `#fragment` from a DID / kid, returning the base DID.
fn base_did(did: &str) -> &str {
    did.split_once('#').map(|(base, _)| base).unwrap_or(did)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:key:z6MkSender";
    const KID: &str = "did:key:z6MkSender#z6MkSender";

    #[test]
    fn require_authcrypt_accepts_both_flags() {
        assert!(require_authcrypt(true, true, "msg").is_ok());
    }

    #[test]
    fn require_authcrypt_rejects_missing_flag() {
        assert!(require_authcrypt(false, true, "msg").is_err());
        assert!(require_authcrypt(true, false, "msg").is_err());
        assert!(require_authcrypt(false, false, "msg").is_err());
    }

    /// Happy path: authcrypt with a `from` matching the authenticated key's DID
    /// returns the bound base DID (fragment stripped on both sides).
    #[test]
    fn binds_matching_sender() {
        assert_eq!(
            bind_authcrypt_sender(Some(DID), true, true, Some(KID), "auth"),
            Ok(DID.to_string()),
        );
        // `from` may itself carry a fragment; still binds to the base DID.
        assert_eq!(
            bind_authcrypt_sender(Some(KID), true, true, Some(KID), "auth"),
            Ok(DID.to_string()),
        );
    }

    /// The core bypass: authenticated (attacker's own key) but the plaintext
    /// `from` claims a different DID → rejected, never bound to the claimed DID.
    #[test]
    fn rejects_sender_mismatch() {
        let attacker_kid = "did:key:z6MkAttacker#z6MkAttacker";
        let err = bind_authcrypt_sender(
            Some("did:key:z6MkAdminVictim"),
            true,
            true,
            Some(attacker_kid),
            "authenticate message",
        )
        .expect_err("forged from must be rejected");
        assert!(err.contains("sender mismatch"), "got: {err}");
        assert!(err.contains("z6MkAdminVictim"));
        assert!(err.contains("z6MkAttacker"));
    }

    /// A plaintext envelope (both flags false) is rejected at the authcrypt gate
    /// before the sender is even considered.
    #[test]
    fn rejects_plaintext() {
        let err = bind_authcrypt_sender(Some(DID), false, false, Some(KID), "auth")
            .expect_err("plaintext rejected");
        assert!(err.contains("authcrypt"), "got: {err}");
    }

    /// Anoncrypt (encrypted but not authenticated) is rejected: no proven sender.
    #[test]
    fn rejects_anoncrypt() {
        let err =
            bind_authcrypt_sender(None, true, false, None, "auth").expect_err("anoncrypt rejected");
        assert!(err.contains("authcrypt"), "got: {err}");
    }

    /// Authcrypt but the metadata carries no sender key id — refuse rather than
    /// fall back to trusting `from`.
    #[test]
    fn rejects_missing_sender_key() {
        let err = bind_authcrypt_sender(Some(DID), true, true, None, "auth")
            .expect_err("missing kid rejected");
        assert!(err.contains("no authenticated sender key"), "got: {err}");
    }

    /// Authcrypt with a proven key but no `from` header — refuse.
    #[test]
    fn rejects_missing_from() {
        let err = bind_authcrypt_sender(None, true, true, Some(KID), "auth")
            .expect_err("missing from rejected");
        assert!(err.contains("no sender"), "got: {err}");
    }
}
