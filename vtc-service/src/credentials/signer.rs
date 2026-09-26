//! `LocalSigner` — plan §D1's cached-locally signing surface.
//!
//! Wraps the VTC's `#key-0` Ed25519 secret in the shape
//! [`affinidi_data_integrity::DataIntegrityProof::sign`] wants.
//! The secret already lives in the secret store (loaded at boot
//! from `VtcKeyBundle` per `tasks/vtc-mvp/vta-driven-keys.md`); the
//! signer is a thin handle that pairs it with the VTC's issuer
//! DID so callers don't have to plumb both through every builder.
//!
//! ## Why not just pass `&Secret` directly
//!
//! Three reasons we wrap:
//! 1. **Issuer-DID coupling.** Every VC the VTC signs has
//!    `issuer = vtc_did`. Pairing the DID with the secret in one
//!    handle means the VMC + VEC builders don't have to take both
//!    and the caller can't pass mismatched values.
//! 2. **Assertion-method id.** `secret.id` is the
//!    `verificationMethod` URI the proof carries. Building it
//!    once at construction (`{vtc_did}#key-0`) keeps the wire
//!    shape consistent.
//! 3. **Test fixtures.** Tests want a "from seed bytes" shortcut
//!    that doesn't go through the keyring / secrets-resolver
//!    plumbing. [`LocalSigner::from_ed25519_seed`] gives them
//!    that without exposing the wrapper internals.

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, VerifyOptions};
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_vc::VerifiableCredential;
use vti_common::error::AppError;
use vti_common::trust_task::envelope::{EnvelopeRole, seal_envelope};

/// Verification-method fragment the VTC consistently uses for
/// its assertion-method key. Lines up with what
/// `server::init_auth` stamps onto the secret at boot
/// (`{vtc_did}#key-0`).
pub const ASSERTION_KEY_FRAGMENT: &str = "key-0";

/// A local signer wrapping the VTC's `#key-0` Ed25519 secret.
/// Constructed once at boot from the secret store and shared via
/// `AppState`; cloning is cheap (the inner secret is a small
/// owned struct).
#[derive(Debug, Clone)]
pub struct LocalSigner {
    issuer_did: String,
    /// The signing keys, primary first.
    ///
    /// A `Vec` rather than one `Secret` because the post-quantum transition
    /// wants a credential signed by **every** key the issuer holds — one proof
    /// per cryptosuite, so a classical verifier and a post-quantum one can each
    /// check the suite it understands without either needing to know about the
    /// other.
    ///
    /// The first is the primary: it supplies `public_bytes()` and the
    /// conventional `#key-0` assertion method, so every existing caller sees
    /// exactly what it saw before.
    ///
    /// **This is why the change needs no migration.** A VTC provisioned before
    /// post-quantum keys existed holds one secret here and emits one proof, in
    /// the same wire shape as always; one provisioned after holds two and emits
    /// two. There is no flag to set and no stored bundle to rewrite — the
    /// number of proofs simply follows the number of keys.
    secrets: Vec<Secret>,
}

impl LocalSigner {
    /// Construct from a fully-formed [`Secret`]. Caller is
    /// responsible for ensuring `secret.id` is
    /// `{issuer_did}#key-0` — the helpers below all enforce
    /// this; this constructor exists for callers that already
    /// did the work (e.g. the boot path that read the secret
    /// out of [`affinidi_secrets_resolver::ThreadedSecretsResolver`]).
    pub fn new(issuer_did: String, secret: Secret) -> Self {
        Self {
            issuer_did,
            secrets: vec![secret],
        }
    }

    /// Add a second signing key, so every credential this signer issues carries
    /// a proof from it as well.
    ///
    /// Intended for a post-quantum key alongside the classical one. The added
    /// key's cryptosuite is chosen from its own type, so an ML-DSA-44 secret
    /// produces an `mldsa44-jcs-2024` proof beside the `eddsa-jcs-2022` one
    /// without either being named here.
    ///
    /// A key whose type has no Data Integrity cryptosuite — ML-DSA-65 and -87,
    /// which W3C Quantum-Resistant Cryptosuites v1.0 does not define suites for
    /// — will fail at signing time with a message saying exactly that
    /// (affinidi-tdk-rs#818), rather than being silently dropped here. Failing
    /// loudly is right: a key added for post-quantum protection that quietly
    /// did nothing is the worst outcome available.
    #[must_use]
    pub fn with_additional_key(mut self, secret: Secret) -> Self {
        self.secrets.push(secret);
        self
    }

    /// How many keys sign each credential.
    pub fn key_count(&self) -> usize {
        self.secrets.len()
    }

    /// The primary signing key.
    fn primary(&self) -> &Secret {
        // Non-empty by construction: every constructor pushes at least one.
        &self.secrets[0]
    }

    /// Construct from 32 raw Ed25519 seed bytes. The resulting
    /// signer's `secret.id` is [`assertion_method_id`] of the issuer. Used by
    /// tests + the boot path that decodes a `VtcKeyBundle`.
    pub fn from_ed25519_seed(issuer_did: String, seed: &[u8; 32]) -> Self {
        let assertion_id = assertion_method_id(&issuer_did);
        let secret = Secret::generate_ed25519(Some(&assertion_id), Some(seed));
        Self {
            issuer_did,
            secrets: vec![secret],
        }
    }

    /// A signer whose issuer is the `did:key` of its own Ed25519 key, signing
    /// as that did:key's one verification method (`did:key:<id>#<id>`) — for
    /// tests, which have no DID document to put `#key-0` in.
    #[cfg(test)]
    pub(crate) fn did_key_for_seed(seed: &[u8; 32]) -> Self {
        let probe = Secret::generate_ed25519(None, Some(seed));
        let mb = probe.get_public_keymultibase().expect("ed25519 multikey");
        let did = format!("did:key:{mb}");
        let secret = Secret::generate_ed25519(Some(&format!("{did}#{mb}")), Some(seed));
        Self::new(did, secret)
    }

    /// Sign `doc` with every key this signer holds and return the value to put
    /// in its `proof` member.
    ///
    /// **One key produces a proof object; several produce an array.** Emitting a
    /// bare object for the single-key case is deliberate: it is byte-identical
    /// to what this service has always issued, so a VTC that has not been given
    /// a post-quantum key changes nothing about its output, and no verifier
    /// anywhere needs to have been updated first.
    async fn proof_value_for(
        &self,
        doc: &(impl serde::Serialize + Sync),
    ) -> Result<serde_json::Value, AppError> {
        self.proof_value_with(doc, SignOptions::new()).await
    }

    async fn proof_value_with(
        &self,
        doc: &(impl serde::Serialize + Sync),
        options: SignOptions,
    ) -> Result<serde_json::Value, AppError> {
        let signers: Vec<&dyn affinidi_data_integrity::signer::Signer> = self
            .secrets
            .iter()
            .map(|s| s as &dyn affinidi_data_integrity::signer::Signer)
            .collect();

        // `sign_multi` is fail-fast and pins one `created` across the batch, so
        // the proofs on a credential cannot disagree about when it was signed.
        let proofs = DataIntegrityProof::sign_multi(doc, &signers, options)
            .await
            .map_err(|e| AppError::Internal(format!("sign: {e}")))?;

        let value = if proofs.len() == 1 {
            serde_json::to_value(&proofs[0])
        } else {
            serde_json::to_value(&proofs)
        };
        value.map_err(|e| AppError::Internal(format!("serialize proof: {e}")))
    }

    /// VTC issuer DID — stamped on every credential's `issuer`
    /// field.
    pub fn issuer_did(&self) -> &str {
        &self.issuer_did
    }

    /// `verificationMethod` URI the proof carries.
    pub fn assertion_method_id(&self) -> &str {
        &self.primary().id
    }

    /// Bytes-on-the-wire public key, useful to tests that want
    /// to verify a freshly-signed VC without going through the
    /// did resolver.
    pub fn public_bytes(&self) -> &[u8] {
        self.primary().get_public_bytes()
    }

    /// The raw Ed25519 signing key behind this signer.
    ///
    /// For signing **non-credential** byte strings — currently the audit
    /// checkpoints (#708), whose signature covers a domain-tagged binary
    /// encoding rather than a JSON-LD document. A Data Integrity proof would
    /// be the wrong shape there: it would make a security-critical signature
    /// depend on JSON canonicalisation agreeing between signer and verifier,
    /// where the whole point is a byte-exact commitment.
    ///
    /// Not for authorization assertions — those are VCs (see the workspace
    /// CLAUDE.md). A checkpoint asserts "the log had this head and this many
    /// entries", which is tamper-evidence, not a grant.
    ///
    /// `None` if the underlying secret is not a 32-byte Ed25519 key.
    pub fn ed25519_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        let bytes = self.primary().get_private_bytes();
        <[u8; 32]>::try_from(bytes)
            .ok()
            .map(|b| ed25519_dalek::SigningKey::from_bytes(&b))
    }

    /// Sign the supplied VC in place. Appends the
    /// `DataIntegrityProof` to `vc.proof`. Returns
    /// [`AppError::Internal`] on signing failure — every error
    /// the data-integrity layer surfaces is a workspace bug
    /// (wrong key type, canonicalisation crash, etc.) rather
    /// than operator input.
    pub async fn sign(&self, vc: &mut VerifiableCredential) -> Result<(), AppError> {
        vc.proof = Some(self.proof_value_for(vc).await?);
        Ok(())
    }

    /// Sign an arbitrary JSON credential document **in place**, splicing the
    /// resulting `DataIntegrityProof` into its `proof` field.
    ///
    /// Unlike [`sign`](Self::sign) (a typed [`VerifiableCredential`]), this signs
    /// a raw `serde_json::Value`. It's the signing surface for the DTG issuance
    /// layer ([`super::dtg`]): a credential's canonical shape is sourced from the
    /// `dtg-credentials` catalog, then fields the catalog struct doesn't model
    /// (a top-level `id`, a `credentialStatus` block) are spliced **before**
    /// signing so the proof covers them. Any pre-existing `proof` is removed
    /// first — a proof never covers itself.
    /// Sign a Trust Task request this VTC originates to a peer — `proofPurpose:
    /// authentication`, the purpose under which the key-roles spec lists the
    /// operational key — in place. The document must already carry `id`,
    /// this VTC as `issuer`, and `recipient`; `issuedAt` is set or truncated
    /// to whole seconds (VTI-KEY-107).
    pub async fn sign_operational_doc(&self, doc: &mut serde_json::Value) -> Result<(), AppError> {
        self.sign_operational(doc, EnvelopeRole::Request).await
    }

    /// Sign a Trust Task response (success or `trust-task-error`) this VTC
    /// returns, as [`sign_operational_doc`](Self::sign_operational_doc) does a
    /// request. The response is issued by this VTC whatever the request named,
    /// and gets an `id` and a whole-second `issuedAt` when it lacks them.
    pub async fn sign_operational_response(
        &self,
        doc: &mut serde_json::Value,
    ) -> Result<(), AppError> {
        self.sign_operational(doc, EnvelopeRole::Response).await
    }

    async fn sign_operational(
        &self,
        doc: &mut serde_json::Value,
        role: EnvelopeRole,
    ) -> Result<(), AppError> {
        seal_envelope(doc, &self.issuer_did, role)
            .map_err(|e| AppError::Internal(format!("cannot sign as this VTC: {e}")))?;
        let obj = doc
            .as_object_mut()
            .ok_or_else(|| AppError::Internal("request document is not a JSON object".into()))?;
        obj.remove("proof");
        let proof_value = self
            .proof_value_with(
                &*doc,
                SignOptions::new().with_proof_purpose("authentication"),
            )
            .await?;
        doc.as_object_mut()
            .expect("checked above")
            .insert("proof".into(), proof_value);
        Ok(())
    }

    pub async fn sign_doc(&self, doc: &mut serde_json::Value) -> Result<(), AppError> {
        let obj = doc
            .as_object_mut()
            .ok_or_else(|| AppError::Internal("credential document is not a JSON object".into()))?;
        obj.remove("proof");
        let proof_value = self.proof_value_for(&*doc).await?;
        doc.as_object_mut()
            .expect("checked above")
            .insert("proof".into(), proof_value);
        Ok(())
    }

    /// Verify a previously-signed VC against this signer's public
    /// key. Used by tests + the M2.13 renewal path that hands
    /// freshly-issued VCs to verifiers. Returns `Ok(())` on
    /// success, [`AppError::Validation`] when the proof is
    /// missing or malformed, [`AppError::Forbidden`] when the
    /// signature does not verify.
    pub fn verify(&self, vc: &VerifiableCredential) -> Result<(), AppError> {
        let proof_value = vc
            .proof
            .as_ref()
            .ok_or_else(|| AppError::Validation("VC has no proof to verify".into()))?;
        // A proof *set*, because a hybrid credential carries several — one per
        // suite — and reading only the first would make the check depend on
        // which order the issuer happened to emit them in.
        let proofs = super::proof_set::proof_set(proof_value)
            .map_err(|e| AppError::Validation(format!("parse VC proof: {e}")))?;

        let mut vc_without_proof = vc.clone();
        vc_without_proof.proof = None;

        // Each proof is checked against the key it names: a hybrid credential's
        // ML-DSA proof against the ML-DSA key, not the primary Ed25519 one. A
        // proof naming no key this signer holds is not one it made.
        let outcomes: Vec<(String, Result<(), String>)> = proofs
            .iter()
            .map(|proof| {
                let did = super::proof_set::proof_signer_did(proof).to_string();
                let r = match self
                    .secrets
                    .iter()
                    .find(|s| s.id == proof.verification_method)
                {
                    None => Err("proof names a key this signer does not hold".to_string()),
                    Some(secret) => proof
                        .verify_with_public_key(
                            &vc_without_proof,
                            secret.get_public_bytes(),
                            VerifyOptions::new(),
                        )
                        .map_err(|e| e.to_string()),
                };
                (did, r)
            })
            .collect();

        super::proof_set::accept_all(&outcomes)
            .map_err(|e| AppError::Forbidden(format!("verify VC: {e}")))?;
        Ok(())
    }
}

/// `{did}#key-0` — the conventional assertion-method id for the
/// VTC. Re-exposed here so the VMC + VEC builders compose the
/// same URI without re-deriving it from `LocalSigner` every
/// time.
///
/// A `did:key` has no `#key-0`: its one verification method is
/// `did:key:<id>#<id>`, and a verifier refuses a proof naming any other
/// (VTI-KEY-022), so that is the id a did:key issuer signs as.
pub fn assertion_method_id(issuer_did: &str) -> String {
    match issuer_did.strip_prefix("did:key:") {
        Some(id) => format!("{issuer_did}#{id}"),
        None => format!("{issuer_did}#{ASSERTION_KEY_FRAGMENT}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DID: &str = "did:webvh:vtc.example.com:abc";

    #[test]
    fn from_seed_constructs_with_canonical_kid() {
        let seed = [0xAB; 32];
        let signer = LocalSigner::from_ed25519_seed(TEST_DID.into(), &seed);
        assert_eq!(signer.issuer_did(), TEST_DID);
        assert_eq!(
            signer.assertion_method_id(),
            format!("{TEST_DID}#{ASSERTION_KEY_FRAGMENT}")
        );
        // Public key bytes deterministic for the seed.
        let other = LocalSigner::from_ed25519_seed(TEST_DID.into(), &seed);
        assert_eq!(signer.public_bytes(), other.public_bytes());
    }

    #[test]
    fn different_seeds_produce_different_public_keys() {
        let a = LocalSigner::from_ed25519_seed(TEST_DID.into(), &[0xAB; 32]);
        let b = LocalSigner::from_ed25519_seed(TEST_DID.into(), &[0xCD; 32]);
        assert_ne!(a.public_bytes(), b.public_bytes());
    }

    #[test]
    fn assertion_method_id_is_did_hash_fragment() {
        assert_eq!(
            assertion_method_id("did:webvh:scid:vtc.example"),
            "did:webvh:scid:vtc.example#key-0".to_string()
        );
        assert_eq!(
            assertion_method_id("did:key:zX"),
            "did:key:zX#zX".to_string()
        );
    }
}

#[cfg(test)]
mod multi_key_tests {
    use super::*;
    use affinidi_secrets_resolver::secrets::Secret;

    const DID: &str = "did:webvh:vtc.example.com:multi";

    fn vc() -> serde_json::Value {
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:uuid:multi-key-probe",
            "type": ["VerifiableCredential"],
            "issuer": DID,
            "credentialSubject": { "id": "did:example:subject" },
        })
    }

    /// **The backward-compatibility guarantee.** One key still emits a bare
    /// proof object.
    ///
    /// This is what makes the change need no migration and no coordinated
    /// deploy: a VTC that has never been given a post-quantum key issues
    /// byte-identically to before, so no verifier anywhere had to be updated
    /// first. If this ever starts emitting a single-element array, every
    /// existing consumer of a VTC credential is affected at once.
    #[tokio::test]
    async fn one_key_emits_a_proof_object_not_an_array() {
        let signer = LocalSigner::from_ed25519_seed(DID.into(), &[0x11; 32]);
        assert_eq!(signer.key_count(), 1);

        let mut doc = vc();
        signer.sign_doc(&mut doc).await.expect("signs");

        let proof = doc.get("proof").expect("proof present");
        assert!(
            proof.is_object(),
            "a single-key signer must emit the historical shape, not a one-element array: {proof}"
        );
    }

    /// A request this VTC originates (a registry write) is signed for
    /// `authentication`, not the credential default `assertionMethod`, and the
    /// envelope members it was built with survive signing.
    #[tokio::test]
    async fn a_request_is_signed_for_authentication() {
        let signer = LocalSigner::from_ed25519_seed(DID.into(), &[0x11; 32]);
        let doc = vti_common::capability_client::build_document(
            DID,
            "did:web:registry.example",
            "https://trusttasks.org/spec/registry/record/put/0.1",
            serde_json::json!({}),
        );
        let mut doc = serde_json::to_value(&doc).unwrap();
        signer.sign_operational_doc(&mut doc).await.expect("signs");
        assert_eq!(doc["proof"]["proofPurpose"], "authentication", "{doc}");
        assert_eq!(doc["issuer"], DID);
        assert_eq!(doc["recipient"], "did:web:registry.example");
        assert!(
            doc.get("issuedAt").is_some() && doc.get("id").is_some(),
            "{doc}"
        );

        // Credentials keep their own purpose.
        let mut vc = vc();
        signer.sign_doc(&mut vc).await.expect("signs");
        assert_ne!(vc["proof"]["proofPurpose"], "authentication");
    }

    /// Two keys emit a proof set — one per key, so a verifier can check the
    /// suite it understands.
    #[tokio::test]
    async fn two_keys_emit_one_proof_each() {
        let pq = Secret::generate_ml_dsa_44(Some(&format!("{DID}#key-pq")), None);
        let signer =
            LocalSigner::from_ed25519_seed(DID.into(), &[0x11; 32]).with_additional_key(pq);
        assert_eq!(signer.key_count(), 2);

        let mut doc = vc();
        signer.sign_doc(&mut doc).await.expect("signs with both");

        let proofs = doc
            .get("proof")
            .and_then(|p| p.as_array())
            .expect("two keys produce an array");
        assert_eq!(proofs.len(), 2);

        // Each key picks its own suite from its own type — neither is named at
        // the call site, which is what lets a fleet add a post-quantum key
        // without touching issuance code.
        let suites: Vec<&str> = proofs
            .iter()
            .filter_map(|p| p.get("cryptosuite").and_then(|s| s.as_str()))
            .collect();
        assert!(suites.contains(&"eddsa-jcs-2022"), "suites: {suites:?}");
        assert!(suites.contains(&"mldsa44-jcs-2024"), "suites: {suites:?}");
    }

    /// The proofs on one credential agree about when it was signed.
    ///
    /// `sign_multi` pins `created` once for the batch. Without that the first
    /// proof could carry t0 and the second t0+ms, which is a gift to anyone
    /// diffing two proofs that are supposed to describe one signing event.
    #[tokio::test]
    async fn every_proof_carries_the_same_created() {
        let pq = Secret::generate_ml_dsa_44(Some(&format!("{DID}#key-pq")), None);
        let signer =
            LocalSigner::from_ed25519_seed(DID.into(), &[0x11; 32]).with_additional_key(pq);

        let mut doc = vc();
        signer.sign_doc(&mut doc).await.expect("signs");

        let proofs = doc.get("proof").and_then(|p| p.as_array()).expect("array");
        let created: Vec<&str> = proofs
            .iter()
            .filter_map(|p| p.get("created").and_then(|c| c.as_str()))
            .collect();
        assert_eq!(created.len(), 2);
        assert_eq!(created[0], created[1], "one signing event, one timestamp");
    }

    /// A hybrid credential verifies — the round trip this whole phase is for.
    #[tokio::test]
    async fn a_two_key_credential_verifies() {
        let pq = Secret::generate_ml_dsa_44(Some(&format!("{DID}#key-pq")), None);
        let signer =
            LocalSigner::from_ed25519_seed(DID.into(), &[0x11; 32]).with_additional_key(pq);

        let mut vc: VerifiableCredential =
            serde_json::from_value(vc()).expect("fixture is a credential");
        signer.sign(&mut vc).await.expect("signs");

        // `verify` checks against the PRIMARY key's public bytes, so this also
        // pins that a proof set does not have to be verifiable in its entirety
        // by one verifier — RequireAny is the rule, and the classical half is
        // what this caller can check.
        signer.verify(&vc).expect("the Ed25519 proof verifies");
    }
}
