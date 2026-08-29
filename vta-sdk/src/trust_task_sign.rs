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
    /// [`HolderKey::from_did_key`] was handed something that is not a
    /// `did:key`. Only that constructor is method-specific, because only
    /// `did:key` puts the verification method in the identifier; any other DID
    /// names its key explicitly through [`HolderKey::new`].
    NotDidKey(String),
    /// A verification method that does not identify a key: not a `did:`, or
    /// carrying no `#fragment`. A proof names *a key*, not a subject, so
    /// `did:webvh:<scid>:example.com:glenn` is not one and
    /// `did:webvh:<scid>:example.com:glenn#key-0` is.
    NotAVerificationMethod(String),
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
                "HolderKey::from_did_key needs a did:key, which carries its own verification \
                 method; got {did} — use HolderKey::new and name the key"
            ),
            Self::NotAVerificationMethod(vm) => write!(
                f,
                "`{vm}` does not identify a key: a verification method is a DID with a \
                 `#fragment`, e.g. did:webvh:<scid>:example.com:glenn#key-0"
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

/// The key a Trust Task proof is made with: the verification method the proof
/// will name, and the private key behind it.
///
/// **Any DID that can name a key may sign.** The verifier resolves the
/// verification method and checks the signature; the DID method is not the
/// authorization. `did:key:z6Mk…#z6Mk…`,
/// `did:webvh:<scid>:example.com:glenn#key-0` and `did:web:example.com#key-1`
/// are all ordinary holders.
///
/// This type exists because the two cases differ in one way that a bare
/// `(did, key)` pair cannot express: a `did:key` *contains* its verification
/// method, and nothing else does. Deriving `#key-0` from a `did:webvh` is not
/// possible — the document says what the keys are called — so the caller has
/// to name it, and a signer that takes only a DID silently cannot serve any
/// method but one. That is the shape the restriction had before this type:
/// not a policy anyone chose, but a helper that only knew how to build one
/// kind of identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderKey {
    verification_method: String,
    private_key_multibase: String,
}

impl HolderKey {
    /// A holder that names its own verification method — the general case.
    ///
    /// `verification_method` must be a DID with a `#fragment`, e.g.
    /// `did:webvh:<scid>:example.com:glenn#key-0`. Whether the key is *in* that
    /// DID document, and whether the DID document is reachable, is the
    /// verifier's business; this only refuses what cannot identify a key at all.
    pub fn new(
        verification_method: impl Into<String>,
        private_key_multibase: impl Into<String>,
    ) -> Result<Self, TrustTaskSignError> {
        let verification_method = verification_method.into();
        let (did, fragment) = verification_method.split_once('#').ok_or_else(|| {
            TrustTaskSignError::NotAVerificationMethod(verification_method.clone())
        })?;
        if !did.starts_with("did:") || fragment.is_empty() {
            return Err(TrustTaskSignError::NotAVerificationMethod(
                verification_method.clone(),
            ));
        }
        Ok(Self {
            verification_method,
            private_key_multibase: private_key_multibase.into(),
        })
    }

    /// A `did:key` holder, whose verification method is `<did>#<multibase>` and
    /// so needs no naming.
    pub fn from_did_key(
        did: &str,
        private_key_multibase: impl Into<String>,
    ) -> Result<Self, TrustTaskSignError> {
        let vm =
            did_key_to_vm(did).ok_or_else(|| TrustTaskSignError::NotDidKey(did.to_string()))?;
        Ok(Self {
            verification_method: vm,
            private_key_multibase: private_key_multibase.into(),
        })
    }

    /// The verification method the proof will name.
    #[must_use]
    pub fn verification_method(&self) -> &str {
        &self.verification_method
    }

    /// The holder DID — the verification method without its fragment. This is
    /// the DID a verifier recovers as the proven signer.
    #[must_use]
    pub fn holder_did(&self) -> &str {
        self.verification_method
            .split('#')
            .next()
            .unwrap_or(&self.verification_method)
    }
}

/// Attach the holder's `eddsa-jcs-2022` Data-Integrity proof to `doc` in place,
/// naming `holder_did`'s `did:key` verification method.
///
/// The `did:key` convenience form of [`sign_in_place_with`]; see [`HolderKey`]
/// for why any other method has to name its key.
pub async fn sign_in_place(
    doc: &mut TrustTask<Value>,
    holder_did: &str,
    private_key_multibase: &str,
) -> Result<(), TrustTaskSignError> {
    let key = HolderKey::from_did_key(holder_did, private_key_multibase)?;
    sign_in_place_with(doc, &key).await
}

/// Attach the holder's `eddsa-jcs-2022` Data-Integrity proof to `doc` in place.
///
/// The proof is computed over the document with `proof` removed — see the
/// module docs for why that matters.
pub async fn sign_in_place_with(
    doc: &mut TrustTask<Value>,
    key: &HolderKey,
) -> Result<(), TrustTaskSignError> {
    let vm_id = key.verification_method.clone();
    let seed = decode_private_key_multibase(&key.private_key_multibase)
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
    let key = HolderKey::from_did_key(holder_did, private_key_multibase)?;
    build_signed_with(type_uri, payload, &key, recipient).await
}

/// Build a holder-signed Trust Task for a holder of any DID method.
///
/// The `issuer` is [`HolderKey::holder_did`] — the verification method's own
/// DID — so the document's claimed issuer and its proven signer cannot come
/// apart at the point of construction.
pub async fn build_signed_with(
    type_uri: &str,
    payload: Value,
    key: &HolderKey,
    recipient: &str,
) -> Result<String, TrustTaskSignError> {
    let mut doc = build_unsigned(type_uri, payload, key.holder_did(), recipient)?;
    sign_in_place_with(&mut doc, key).await?;
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

    /// The whole point of [`HolderKey`]: a holder that is not a `did:key`
    /// signs, and the document it produces is well-formed — `issuer` is the
    /// holder DID, and the proof names the key the holder was told to use.
    ///
    /// A `did:webvh` verification method is not derivable from its DID: the DID
    /// document decides that `#key-0` is what the key is called. So the only
    /// thing that ever prevented this was a helper that could build one shape
    /// of identifier.
    #[tokio::test]
    async fn a_did_webvh_holder_signs_and_names_its_key() {
        const VM: &str = "did:webvh:QmScidExample:example.com:glenn#key-0";
        let (_did, pk) = did_key_from_seed(0xb2);

        let key = HolderKey::new(VM, &pk).expect("a DID with a fragment is a verification method");
        assert_eq!(
            key.holder_did(),
            "did:webvh:QmScidExample:example.com:glenn"
        );

        let body = build_signed_with(TYPE, json!({"vp": {}}), &key, "did:key:z6MkVtc")
            .await
            .expect("a did:webvh holder can sign");
        let doc: TrustTask<Value> = serde_json::from_str(&body).unwrap();

        assert_eq!(doc.issuer.as_deref(), Some(key.holder_did()));
        let proof = doc.proof.as_ref().expect("signed");
        let di: DataIntegrityProof =
            serde_json::from_value(serde_json::to_value(proof).unwrap()).unwrap();
        assert_eq!(
            di.verification_method, VM,
            "the proof must name the key the DID document publishes, not a derived one"
        );
    }

    /// A verification method identifies a *key*. A bare DID does not, and
    /// neither does a non-DID string — refused at construction rather than
    /// producing a proof nothing can resolve.
    #[test]
    fn a_verification_method_must_name_a_key() {
        for bad in [
            "did:webvh:QmScid:example.com:glenn",
            "did:webvh:QmScid:example.com:glenn#",
            "https://example.com/keys#key-0",
            "no-scheme#key-0",
        ] {
            assert!(
                matches!(
                    HolderKey::new(bad, "z1234"),
                    Err(TrustTaskSignError::NotAVerificationMethod(_))
                ),
                "`{bad}` must be refused"
            );
        }
    }

    /// `did:key` keeps its convenience: it is the one method whose verification
    /// method is derivable, because the key is in the identifier.
    #[test]
    fn a_did_key_holder_still_derives_its_own_verification_method() {
        let (did, pk) = did_key_from_seed(0xb3);
        let key = HolderKey::from_did_key(&did, &pk).expect("did:key derives");
        assert_eq!(key.verification_method(), format!("{did}#{}", &did[8..]));
        assert_eq!(key.holder_did(), did);

        assert!(matches!(
            HolderKey::from_did_key("did:webvh:QmScid:example.com:glenn", &pk),
            Err(TrustTaskSignError::NotDidKey(_))
        ));
    }

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

    /// The `did:key` convenience form refuses a DID it cannot derive a
    /// verification method from — which is every other method.
    ///
    /// This is a limit of *this entry point*, not a rule about who may sign: a
    /// `did:web` holder signs perfectly well through [`build_signed_with`] by
    /// naming its key. The refusal is here so the caller finds out at the
    /// helper rather than by sending a proof whose `verificationMethod` was
    /// invented.
    #[tokio::test]
    async fn the_did_key_helper_refuses_a_did_it_cannot_derive_a_key_from() {
        let (_, pk) = did_key_from_seed(0xa3);
        let err = build_signed(
            TYPE,
            json!({}),
            "did:web:example.com",
            &pk,
            "did:key:z6MkVtc",
        )
        .await
        .expect_err("the derive-it form cannot serve did:web");
        assert!(matches!(err, TrustTaskSignError::NotDidKey(_)), "{err:?}");

        // The same holder, naming its key, signs.
        let key = HolderKey::new("did:web:example.com#key-1", &pk).expect("names a key");
        build_signed_with(TYPE, json!({}), &key, "did:key:z6MkVtc")
            .await
            .expect("naming the key is all it took");
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
