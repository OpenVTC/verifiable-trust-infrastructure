//! Build and holder-sign a Trust Task document — the one client-side
//! implementation of "an `eddsa-jcs-2022` proof by a `did:key` holder, over the
//! proof-less document".
//!
//! Both VTI services authenticate holder-submitted Trust Tasks the same way:
//! verify the document's Data-Integrity proof with a **`did:key`-only** resolver
//! (`vti_common::auth::di_proof`) and take the proof's `verificationMethod` DID
//! as the proven signer, cross-checked against the document `issuer` where one
//! is present. That is the whole authentication for the VTC's `POST
//! /trust-tasks` holder surface (join submit / manifest / status) and for both
//! services' canonical REST login.
//!
//! Signing had already been written three times — [`crate::auth_di`], the
//! provision-client's VP signer, and `vta-mobile-core` — with the JCS
//! presence-sensitivity handled slightly differently each time. This is the
//! shared primitive; [`crate::auth_di`] builds on it, and so does anything that
//! needs to speak a holder-signed Trust Task.
//!
//! Two invariants that are easy to get wrong and expensive to debug, because a
//! mistake in either yields a signature that verifies nowhere:
//!
//! - **Sign the proof-less document.** `eddsa-jcs-2022` canonicalises via JCS,
//!   which is presence-sensitive, and the verifier strips `proof` before
//!   checking. Signing a document that already carries a `proof` key — even an
//!   empty one — produces a signature over different bytes.
//! - **Set `recipient`.** SPEC §4.8.2 audience binding rejects a *signed*
//!   document with no in-band recipient unless its specification is a bearer
//!   spec. [`build_signed`] always sets it, so the caller cannot forget.

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::Utc;
use serde_json::Value;
use trust_tasks_rs::{Proof, TrustTask};

use crate::did_key::decode_private_key_multibase;

/// Why building or signing a Trust Task document failed.
#[derive(Debug)]
pub enum TrustTaskSignError {
    /// The holder DID is not a `did:key`. Both services verify the proof with a
    /// `did:key`-only resolver, so no other method can sign a document they
    /// will accept — refused here rather than after a round trip.
    NotDidKey(String),
    /// The holder's private key could not be decoded from its multibase form.
    BadPrivateKey(String),
    /// The Trust Task type URI failed to parse.
    TypeUri(String),
    /// Serialising the document, or signing it, failed.
    Sign(String),
}

impl std::fmt::Display for TrustTaskSignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDidKey(did) => write!(
                f,
                "signing a Trust Task requires a did:key holder; got {did}"
            ),
            Self::BadPrivateKey(e) => write!(f, "decode holder private key: {e}"),
            Self::TypeUri(e) => write!(f, "Trust Task type URI parse: {e}"),
            Self::Sign(e) => write!(f, "sign Trust Task: {e}"),
        }
    }
}

impl std::error::Error for TrustTaskSignError {}

/// The `did:key:zXxx#zXxx` verification-method id the Data-Integrity resolver
/// recognises for a `did:key` holder.
pub fn did_key_to_vm(did: &str) -> Option<String> {
    let mb = did.strip_prefix("did:key:")?;
    Some(format!("{did}#{mb}"))
}

/// An unsigned Trust Task addressed from `issuer` to `recipient`, with a fresh
/// `urn:uuid:` id and `issuedAt` stamped now.
///
/// Split out from [`build_signed`] because the unsigned form is a legitimate
/// wire shape for bearer specifications — `auth/refresh/0.1` carries no proof,
/// its opaque token being the credential.
pub fn build_unsigned(
    type_uri: &str,
    payload: Value,
    issuer: &str,
    recipient: &str,
) -> Result<TrustTask<Value>, TrustTaskSignError> {
    let mut doc: TrustTask<Value> = TrustTask::new(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        type_uri
            .parse()
            .map_err(|e| TrustTaskSignError::TypeUri(format!("{e}")))?,
        payload,
    );
    doc.issuer = Some(issuer.to_string());
    doc.recipient = Some(recipient.to_string());
    doc.issued_at = Some(Utc::now());
    Ok(doc)
}

/// Attach the holder's `eddsa-jcs-2022` Data-Integrity proof to `doc` in place.
///
/// `holder_did` must be a `did:key` whose seed is `private_key_multibase`. The
/// proof is computed over the document with `proof` removed — see the module
/// docs for why that matters.
pub async fn sign_in_place(
    doc: &mut TrustTask<Value>,
    holder_did: &str,
    private_key_multibase: &str,
) -> Result<(), TrustTaskSignError> {
    let vm_id = did_key_to_vm(holder_did)
        .ok_or_else(|| TrustTaskSignError::NotDidKey(holder_did.to_string()))?;
    let seed = decode_private_key_multibase(private_key_multibase)
        .map_err(|e| TrustTaskSignError::BadPrivateKey(e.to_string()))?;
    let mut signer = Secret::generate_ed25519(Some(&vm_id), Some(&seed));
    signer.id = vm_id;

    let mut signing_doc =
        serde_json::to_value(&*doc).map_err(|e| TrustTaskSignError::Sign(e.to_string()))?;
    if let Some(obj) = signing_doc.as_object_mut() {
        obj.remove("proof");
    }
    let di_proof = DataIntegrityProof::sign(
        &signing_doc,
        &signer,
        SignOptions::new()
            .with_proof_purpose("assertionMethod")
            .with_created(Utc::now()),
    )
    .await
    .map_err(|e| TrustTaskSignError::Sign(e.to_string()))?;
    let proof_json =
        serde_json::to_value(&di_proof).map_err(|e| TrustTaskSignError::Sign(e.to_string()))?;
    doc.proof = Some(
        serde_json::from_value::<Proof>(proof_json)
            .map_err(|e| TrustTaskSignError::Sign(e.to_string()))?,
    );
    Ok(())
}

/// Build a holder-signed Trust Task and return it as the JSON body to POST.
///
/// The one call a client needs: `issuer` is the holder (and the proven signer),
/// `recipient` is the service the document is addressed to (audience binding).
pub async fn build_signed(
    type_uri: &str,
    payload: Value,
    holder_did: &str,
    private_key_multibase: &str,
    recipient: &str,
) -> Result<String, TrustTaskSignError> {
    let mut doc = build_unsigned(type_uri, payload, holder_did, recipient)?;
    sign_in_place(&mut doc, holder_did, private_key_multibase).await?;
    serde_json::to_string(&doc).map_err(|e| TrustTaskSignError::Sign(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn did_key_from_seed(seed_byte: u8) -> (String, String) {
        let seed = [seed_byte; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let did = format!(
            "did:key:{}",
            crate::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
        );
        let mut buf = vec![0x80, 0x26];
        buf.extend_from_slice(&seed);
        (did, multibase::encode(multibase::Base::Base58Btc, &buf))
    }

    const TYPE: &str = "https://trusttasks.org/spec/vtc/join-requests/submit/0.2";

    /// The signed document verifies under the same `did:key` resolver both
    /// services use, and carries issuer + recipient.
    #[tokio::test]
    async fn signed_document_verifies_server_side() {
        use affinidi_data_integrity::{DidKeyResolver, VerifyOptions};

        let (did, pk) = did_key_from_seed(0xa1);
        let body = build_signed(TYPE, json!({"vp": {}}), &did, &pk, "did:key:z6MkVtc")
            .await
            .expect("sign");
        let doc: TrustTask<Value> = serde_json::from_str(&body).unwrap();

        assert_eq!(doc.issuer.as_deref(), Some(did.as_str()));
        assert_eq!(doc.recipient.as_deref(), Some("did:key:z6MkVtc"));

        let proof: DataIntegrityProof =
            serde_json::from_value(serde_json::to_value(doc.proof.as_ref().unwrap()).unwrap())
                .unwrap();
        let mut unsigned = doc.clone();
        unsigned.proof = None;
        proof
            .verify(&unsigned, &DidKeyResolver, VerifyOptions::new())
            .await
            .expect("must verify under the server's resolver");
    }

    /// The proof covers the payload — a post-signature edit does not verify.
    #[tokio::test]
    async fn tampered_payload_fails() {
        use affinidi_data_integrity::{DidKeyResolver, VerifyOptions};

        let (did, pk) = did_key_from_seed(0xa2);
        let body = build_signed(TYPE, json!({"vp": {}}), &did, &pk, "did:key:z6MkVtc")
            .await
            .unwrap();
        let mut doc: TrustTask<Value> = serde_json::from_str(&body).unwrap();
        doc.payload = json!({"vp": {"forged": true}});

        let proof: DataIntegrityProof =
            serde_json::from_value(serde_json::to_value(doc.proof.as_ref().unwrap()).unwrap())
                .unwrap();
        let mut unsigned = doc.clone();
        unsigned.proof = None;
        assert!(
            proof
                .verify(&unsigned, &DidKeyResolver, VerifyOptions::new())
                .await
                .is_err()
        );
    }

    /// A non-`did:key` holder is refused locally.
    #[tokio::test]
    async fn non_did_key_holder_refused() {
        let (_, pk) = did_key_from_seed(0xa3);
        let err = build_signed(
            TYPE,
            json!({}),
            "did:web:example.com",
            &pk,
            "did:key:z6MkVtc",
        )
        .await
        .expect_err("did:web must be refused");
        assert!(matches!(err, TrustTaskSignError::NotDidKey(_)), "{err:?}");
    }

    /// The unsigned builder always sets `recipient` — a signed document without
    /// one is rejected by SPEC §4.8.2 audience binding.
    #[test]
    fn unsigned_sets_issuer_and_recipient() {
        let doc = build_unsigned(TYPE, json!({}), "did:key:z6MkA", "did:key:z6MkB").unwrap();
        assert_eq!(doc.issuer.as_deref(), Some("did:key:z6MkA"));
        assert_eq!(doc.recipient.as_deref(), Some("did:key:z6MkB"));
        assert!(doc.proof.is_none());
    }
}
