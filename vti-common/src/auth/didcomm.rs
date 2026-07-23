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
//! surfaces a sender when `from == encrypted_from_kid`'s DID. [`bind_authcrypt_sender`]
//! gives the direct-`unpack` callers (the REST `/auth/*` handlers, vault unseal)
//! the same guarantee in one call: it does the authcrypt gate **and** the
//! `from == skid` binding, returning the proven sender or a typed
//! [`AuthcryptError`]. It takes primitive fields rather than the SDK metadata
//! struct so `vti-common` needn't depend on the messaging SDK.

/// Why binding an authcrypt sender failed. Auth handlers render it with
/// [`AuthcryptError::message`]; the vault path matches specific variants to map
/// onto its own error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthcryptError {
    /// Not a sender-authenticated encrypted (authcrypt) envelope — the message
    /// was plaintext or anoncrypt, so its `from` is unauthenticated.
    NotAuthcrypt,
    /// Authcrypt, but the unpack metadata carried no authenticated sender key.
    NoSenderKey,
    /// The inner message carried no `from` header.
    NoFrom,
    /// The inner `from` did not match the DID of the authenticated sender key —
    /// the core forged-sender case (attacker authcrypts with their own key while
    /// claiming a victim's `from`).
    Mismatch {
        claimed: String,
        authenticated: String,
    },
}

impl AuthcryptError {
    /// A one-line human message for `subject` (e.g. `"authenticate message"`,
    /// `"sealed secret"`).
    pub fn message(&self, subject: &str) -> String {
        match self {
            AuthcryptError::NotAuthcrypt => {
                format!("{subject} must be an authenticated (authcrypt) DIDComm envelope")
            }
            AuthcryptError::NoSenderKey => {
                format!("{subject} is authcrypt but carries no authenticated sender key")
            }
            AuthcryptError::NoFrom => format!("{subject} has no sender (from)"),
            AuthcryptError::Mismatch {
                claimed,
                authenticated,
            } => format!(
                "{subject} sender mismatch: plaintext from `{claimed}` does not match the authenticated sender `{authenticated}`"
            ),
        }
    }
}

/// Gate an unpacked envelope as authcrypt **and** verify its plaintext `from`
/// matches the DID of the key that actually authenticated it, returning that
/// cryptographically-bound sender DID (with any `#fragment` stripped).
///
/// This is the single entry point for direct-`unpack` callers: it folds the
/// authcrypt requirement and the addressing-consistency check into one call.
/// `from` is the inner message's `from` header; `encrypted_from_kid` is the
/// authenticated sender key id from unpack metadata. Callers pass the returned
/// (proven) sender on to authorization; they must **not** trust `from` on their
/// own. See the module docs for the rationale.
pub fn bind_authcrypt_sender(
    from: Option<&str>,
    encrypted: bool,
    authenticated: bool,
    encrypted_from_kid: Option<&str>,
) -> Result<String, AuthcryptError> {
    if !(encrypted && authenticated) {
        return Err(AuthcryptError::NotAuthcrypt);
    }
    let kid = encrypted_from_kid.ok_or(AuthcryptError::NoSenderKey)?;
    let key_did = base_did(kid);

    match from.map(base_did) {
        Some(from_did) if from_did == key_did => Ok(key_did.to_string()),
        Some(from_did) => Err(AuthcryptError::Mismatch {
            claimed: from_did.to_string(),
            authenticated: key_did.to_string(),
        }),
        None => Err(AuthcryptError::NoFrom),
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

    /// Happy path: authcrypt with a `from` matching the authenticated key's DID
    /// returns the bound base DID (fragment stripped on both sides).
    #[test]
    fn binds_matching_sender() {
        assert_eq!(
            bind_authcrypt_sender(Some(DID), true, true, Some(KID)),
            Ok(DID.to_string()),
        );
        // `from` may itself carry a fragment; still binds to the base DID.
        assert_eq!(
            bind_authcrypt_sender(Some(KID), true, true, Some(KID)),
            Ok(DID.to_string()),
        );
    }

    /// The core forged-sender case: authenticated (attacker's own key) but the
    /// plaintext `from` claims a different DID → `Mismatch`, never bound to the
    /// claimed DID.
    #[test]
    fn rejects_sender_mismatch() {
        let err = bind_authcrypt_sender(
            Some("did:key:z6MkAdminVictim"),
            true,
            true,
            Some("did:key:z6MkAttacker#z6MkAttacker"),
        )
        .expect_err("forged from must be rejected");
        assert_eq!(
            err,
            AuthcryptError::Mismatch {
                claimed: "did:key:z6MkAdminVictim".to_string(),
                authenticated: "did:key:z6MkAttacker".to_string(),
            }
        );
        // And the rendered message names both DIDs.
        let msg = err.message("authenticate message");
        assert!(
            msg.contains("z6MkAdminVictim") && msg.contains("z6MkAttacker"),
            "got: {msg}"
        );
    }

    /// A plaintext envelope (both flags false) is `NotAuthcrypt`, before the
    /// sender is even considered.
    #[test]
    fn rejects_plaintext() {
        assert_eq!(
            bind_authcrypt_sender(Some(DID), false, false, Some(KID)),
            Err(AuthcryptError::NotAuthcrypt),
        );
    }

    /// Anoncrypt (encrypted but not authenticated) is `NotAuthcrypt`: no proven
    /// sender.
    #[test]
    fn rejects_anoncrypt() {
        assert_eq!(
            bind_authcrypt_sender(None, true, false, None),
            Err(AuthcryptError::NotAuthcrypt),
        );
    }

    /// Authcrypt but the metadata carries no sender key id — `NoSenderKey`,
    /// rather than falling back to trusting `from`.
    #[test]
    fn rejects_missing_sender_key() {
        assert_eq!(
            bind_authcrypt_sender(Some(DID), true, true, None),
            Err(AuthcryptError::NoSenderKey),
        );
    }

    /// Authcrypt with a proven key but no `from` header — `NoFrom`.
    #[test]
    fn rejects_missing_from() {
        assert_eq!(
            bind_authcrypt_sender(None, true, true, Some(KID)),
            Err(AuthcryptError::NoFrom),
        );
    }

    /// Each variant renders a distinct, subject-tagged message.
    #[test]
    fn messages_are_subject_tagged() {
        assert!(
            AuthcryptError::NotAuthcrypt
                .message("sealed secret")
                .starts_with("sealed secret must be an authenticated")
        );
        assert!(
            AuthcryptError::NoFrom
                .message("refresh message")
                .contains("no sender")
        );
    }
}
