//! A holder's DIDComm / TSP secrets, for an identity that is **not** a `did:key`.
//!
//! [`MediatorSession::connect`](crate::mediator::MediatorSession::connect) and
//! [`TspMediatorSession::connect`](crate::tsp::TspMediatorSession::connect) take one Ed25519
//! seed and derive both secrets from it. That is right for a `did:key`, whose key-agreement
//! key *is* the converted signing key, and cannot express anything else. A pairwise
//! relationship DID is a `did:peer:2` with an independent signing key `V` and key-agreement
//! key `E` under their own `#key-N` ids, and a wallet carrying witness documents
//! ([`crate::witness`]) has to hold that DID's one mediator socket. The `connect_with_secrets`
//! constructors take its secrets as [`HolderSecret`]s instead.
//!
//! **Checked against the published document before any socket opens.** Each secret must
//! sit under the holder DID, name a verification method that document publishes, and carry
//! that method's public key; there must be an Ed25519 secret for an `authentication` method
//! and an X25519 secret for a `keyAgreement` method. A wrong key otherwise surfaces as an
//! opaque mediator authentication failure, or as a socket that never decrypts what it is
//! sent.

use std::collections::HashSet;

use affinidi_secrets_resolver::secrets::{KeyType, Secret};
use serde_json::Value;

use crate::error::FfiError;
use crate::proof::lists_method_under;

/// One private key of the holder, under the verification-method id it is published as.
///
/// The shape of `vta_sdk::did_secrets::SecretEntry`, without the key type: the multicodec
/// prefix of `private_key_multibase` is authoritative for it.
#[derive(Clone, uniffi::Record)]
pub struct HolderSecret {
    /// The verification method this key is published as — an absolute DID URL under the
    /// holder, e.g. `did:peer:2.Vz…#key-1`.
    pub key_id: String,
    /// The private key, multibase (base58btc) with its multicodec prefix: `0x1300` Ed25519,
    /// `0x1302` X25519.
    pub private_key_multibase: String,
}

// Hand-written so the key never reaches a log, a panic or a test failure.
impl std::fmt::Debug for HolderSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HolderSecret")
            .field("key_id", &self.key_id)
            .field("private_key_multibase", &"<redacted>")
            .finish()
    }
}

/// Resolve `holder_did` and turn `secrets` into the session's secrets, refusing any that the
/// published document does not bear out ([`check_holder_secrets`]).
pub(crate) async fn holder_secrets(
    holder_did: &str,
    secrets: Vec<HolderSecret>,
) -> Result<Vec<Secret>, FfiError> {
    let doc_json = crate::resolver::resolve_did(holder_did.to_string()).await?;
    let doc: Value = serde_json::from_str(&doc_json).map_err(|e| FfiError::Decode {
        reason: format!("DID document of {holder_did} is not valid JSON: {e}"),
    })?;
    check_holder_secrets(holder_did, &doc, secrets)
}

/// The check behind [`holder_secrets`], over an already-resolved document. Pure, so it is
/// tested without a resolver.
pub(crate) fn check_holder_secrets(
    holder_did: &str,
    doc: &Value,
    secrets: Vec<HolderSecret>,
) -> Result<Vec<Secret>, FfiError> {
    let refuse = |reason: String| FfiError::InvalidInput { reason };
    if secrets.is_empty() {
        return Err(refuse(format!("no secrets given for {holder_did}")));
    }
    if doc.get("id").and_then(Value::as_str) != Some(holder_did) {
        return Err(refuse(format!(
            "the resolved document is not {holder_did}'s"
        )));
    }

    let prefix = format!("{holder_did}#");
    let mut seen = HashSet::new();
    let mut has_authentication = false;
    let mut has_key_agreement = false;
    let mut out = Vec::with_capacity(secrets.len());

    for entry in secrets {
        let key_id = entry.key_id.as_str();
        if !key_id.strip_prefix(&prefix).is_some_and(|f| !f.is_empty()) {
            return Err(refuse(format!(
                "secret id `{key_id}` is not a verification method of {holder_did}"
            )));
        }
        if !seen.insert(key_id.to_string()) {
            return Err(refuse(format!("secret id `{key_id}` is given twice")));
        }
        // The decode error is not carried: it could quote the key.
        let secret =
            Secret::from_multibase(&entry.private_key_multibase, Some(key_id)).map_err(|_| {
                refuse(format!(
                    "the secret for `{key_id}` is not a multicodec-prefixed multibase private key"
                ))
            })?;
        let published = published_key(doc, key_id).ok_or_else(|| {
            refuse(format!(
                "{holder_did}'s document publishes no verification method `{key_id}`"
            ))
        })?;
        if published != secret.get_public_bytes() {
            return Err(refuse(format!(
                "the secret for `{key_id}` is not the key {holder_did}'s document publishes there"
            )));
        }
        match secret.get_key_type() {
            KeyType::Ed25519 if lists_method_under(doc, key_id, "authentication") => {
                has_authentication = true;
            }
            KeyType::X25519 if lists_method_under(doc, key_id, "keyAgreement") => {
                has_key_agreement = true;
            }
            _ => {}
        }
        out.push(secret);
    }

    if !has_authentication {
        return Err(refuse(format!(
            "no Ed25519 secret for an `authentication` method of {holder_did}: the mediator \
             could not authenticate the session"
        )));
    }
    if !has_key_agreement {
        return Err(refuse(format!(
            "no X25519 secret for a `keyAgreement` method of {holder_did}: nothing sent to it \
             could be decrypted"
        )));
    }
    Ok(out)
}

/// The raw public key `doc` publishes for the verification method `key_id`, wherever the
/// method is declared — `verificationMethod`, or embedded in a relationship — and by absolute
/// or relative id.
fn published_key(doc: &Value, key_id: &str) -> Option<Vec<u8>> {
    let fragment = &key_id[key_id.find('#')?..];
    let names = |m: &Value| {
        m.get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| id == key_id || id == fragment)
    };
    let method = ["verificationMethod", "authentication", "keyAgreement"]
        .iter()
        .filter_map(|member| doc.get(*member).and_then(Value::as_array))
        .flatten()
        .find(|m| m.is_object() && names(m))?;
    if let Some(mb) = method.get("publicKeyMultibase").and_then(Value::as_str) {
        return Secret::decode_multikey(mb).ok();
    }
    let x = method.get("publicKeyJwk")?.get("x")?.as_str()?;
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_tdk::dids::{DID, KeyType as PeerKeyType, PeerKeyRole};

    /// A `did:peer:2` relationship DID — signing key `V`, key-agreement key `E` — with its
    /// document, and its secrets as a wallet would hold them.
    async fn relationship_did() -> (String, Value, Vec<HolderSecret>) {
        let (did, secrets) = DID::generate_did_peer(
            vec![
                (PeerKeyRole::Verification, PeerKeyType::Ed25519),
                (PeerKeyRole::Encryption, PeerKeyType::X25519),
            ],
            None,
        )
        .expect("mint a did:peer");
        let doc: Value =
            serde_json::from_str(&crate::resolver::resolve_did(did.clone()).await.unwrap())
                .unwrap();
        let held = secrets
            .iter()
            .map(|s| HolderSecret {
                key_id: s.id.clone(),
                private_key_multibase: s.get_private_keymultibase().unwrap(),
            })
            .collect();
        (did, doc, held)
    }

    fn reason(err: FfiError) -> String {
        match err {
            FfiError::InvalidInput { reason } => reason,
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    // One test (one runtime): the process-wide resolver is initialised and used within the
    // same runtime, as in `resolver::tests`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relationship_did_is_checked_against_its_document() {
        let (did, doc, held) = relationship_did().await;

        // Its own secrets pass, in the order given.
        let secrets = check_holder_secrets(&did, &doc, held.clone()).expect("its own secrets");
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].id, held[0].key_id);
        assert_eq!(secrets[1].id, held[1].key_id);

        // The same check through resolution.
        holder_secrets(&did, held.clone()).await.expect("resolved");

        // Nothing given.
        assert!(
            reason(check_holder_secrets(&did, &doc, vec![]).unwrap_err()).contains("no secrets")
        );

        // Another key under the published id.
        let (_, _, other) = relationship_did().await;
        let mut wrong = held.clone();
        wrong[0].private_key_multibase = other[0].private_key_multibase.clone();
        assert!(
            reason(check_holder_secrets(&did, &doc, wrong).unwrap_err()).contains("is not the key")
        );

        // A key id under another DID.
        let mut foreign = held.clone();
        foreign[0].key_id = other[0].key_id.clone();
        assert!(
            reason(check_holder_secrets(&did, &doc, foreign).unwrap_err())
                .contains("is not a verification method of")
        );

        // An id the document does not publish.
        let mut unpublished = held.clone();
        unpublished[0].key_id = format!("{did}#key-9");
        assert!(
            reason(check_holder_secrets(&did, &doc, unpublished).unwrap_err())
                .contains("publishes no verification method")
        );

        // The same id twice.
        let twice = vec![held[0].clone(), held[0].clone()];
        assert!(
            reason(check_holder_secrets(&did, &doc, twice).unwrap_err()).contains("given twice")
        );

        // No key-agreement secret.
        assert!(
            reason(check_holder_secrets(&did, &doc, vec![held[0].clone()]).unwrap_err())
                .contains("keyAgreement")
        );

        // No authentication secret.
        assert!(
            reason(check_holder_secrets(&did, &doc, vec![held[1].clone()]).unwrap_err())
                .contains("authentication")
        );

        // Another DID's document.
        let (_, other_doc, _) = relationship_did().await;
        assert!(
            reason(check_holder_secrets(&did, &other_doc, held.clone()).unwrap_err())
                .contains("is not")
        );

        // A malformed key is refused without quoting it.
        let mut garbage = held;
        garbage[0].private_key_multibase = "zNotAKey".to_string();
        let why = reason(check_holder_secrets(&did, &doc, garbage).unwrap_err());
        assert!(why.contains("not a multicodec-prefixed") && !why.contains("zNotAKey"));
    }

    #[test]
    fn debug_never_prints_the_key() {
        let s = HolderSecret {
            key_id: "did:peer:2.x#key-1".into(),
            private_key_multibase: "zSecretMaterial".into(),
        };
        let printed = format!("{s:?}");
        assert!(printed.contains("<redacted>") && !printed.contains("zSecretMaterial"));
    }
}
