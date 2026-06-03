//! Mint an SD-JWT-VC — the VTA issues its **own** Verifiable Credential
//! (task 1.5, `docs/05-design-notes/vti-credential-architecture.md` §5 "Mint").
//!
//! This is the credential vault's **issue path**: the VTA, acting as an
//! issuer, produces a fresh SD-JWT-VC carrying a chosen set of claims, with a
//! subset of those claims made **selectively disclosable**, bound to a holder
//! key (`cnf`) so the credential can later be held + presented with holder
//! binding (task 1.4). The output is the compact SD-JWT-VC serialization.
//!
//! ## Scope (SD-JWT-VC only)
//!
//! This task mints **SD-JWT-VC** exclusively. It pulls in **no BBS**
//! (`affinidi-bbs` is audit-gated — `vti-credential-architecture.md` §4, open
//! question #1; BBS minting is a later, audit-gated task) and adds **no route
//! / DIDComm handler** — minting is a library operation only.
//!
//! ## Security invariants (spec §14, and the task brief)
//!
//! - **The issuer key never leaves the VTA.** The issuer's private key is
//!   used *only* through the [`JwtSigner`] abstraction
//!   (`affinidi_sd_jwt::signer::JwtSigner`) the caller passes in. This module
//!   never takes, holds, copies, serializes, or logs raw key bytes — it sees
//!   the signer as an opaque object whose sole capability is "sign this
//!   header+payload". This mirrors the signing-oracle pattern (sign without
//!   key export). A KMS- or enclave-backed signer therefore drops in
//!   unchanged.
//! - **Selectively-disclosable claims are hidden-but-recoverable.** Every
//!   claim named in `disclosable` is emitted into the SD-JWT's `_sd` disclosure
//!   frame, so the signed JWT body carries only its **salted digest**, never
//!   the cleartext value. The value travels in a tilde-appended *disclosure*
//!   (salt + name + value), so a holder can recover and prove it, but a party
//!   reading only the signed body cannot. This is the claim-minimisation
//!   precondition for §7 selective disclosure.
//! - **Holder binding from issuance.** The holder DID is encoded as the `cnf`
//!   confirmation key (an OKP/Ed25519 JWK derived from the `did:key`), so the
//!   credential is bound to the holder from the moment it is minted and a
//!   later presentation can prove possession of the matching key (§14.4).
//! - **Protected claims stay protected.** `vct`, `iss`, `iat`, `exp`, `nbf`,
//!   and `cnf` must never be selectively disclosed; the underlying
//!   `affinidi_sd_jwt_vc::issue` rejects any frame that tries to, and this
//!   module never adds them to the disclosure frame.
//!
//! ## What this module does NOT do
//!
//! It does not resolve schemas (§8), allocate a status-list entry (§9 — task
//! 1.6 territory), or build a presentation (task 1.4). It mints and returns
//! the compact credential; an optional convenience also files the freshly
//! minted credential into the holder's own vault via [`storage::put`].

use affinidi_sd_jwt::hasher::Sha256Hasher;
use affinidi_sd_jwt::signer::JwtSigner;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::model::{CredentialPurpose, StoredCredential};
use super::receive;

/// Inputs to [`mint_sd_jwt_vc`].
///
/// The issuer **signer** is passed separately (not in this struct) so the
/// key-bearing object is never co-located with, or accidentally captured into,
/// the plain-data request — and so it is obvious at the call site that the
/// signer is the *only* path to the issuer key.
#[derive(Debug, Clone)]
pub struct MintRequest<'a> {
    /// Verifiable Credential Type — a URN or HTTPS URL identifying the
    /// credential type (the SD-JWT-VC `vct` claim). Must be non-empty.
    pub vct: &'a str,
    /// Issuer identifier — the VTA's own DID (the `iss` claim). Must be
    /// non-empty. This is the public identity of the key the `signer` wraps;
    /// a verifier resolves it to check the signature.
    pub issuer_did: &'a str,
    /// The holder / subject DID this credential is about (the `sub` claim) and
    /// whose key is bound as `cnf`. Must be a resolvable Ed25519 `did:key` so
    /// the confirmation JWK can be derived for holder binding.
    pub subject_did: &'a str,
    /// The credential claims. A JSON object; its members become credential
    /// claims (those named in `disclosable` are made selectively disclosable,
    /// the rest are emitted in the clear).
    pub claims: &'a Value,
    /// The set of claim names (top-level keys of `claims`) that must be
    /// **selectively disclosable** — hidden (as salted digests) in the signed
    /// body and recoverable only via their disclosures. Names not present in
    /// `claims`, and the protected claims (`vct`/`iss`/`iat`/`exp`/`nbf`/`cnf`),
    /// are rejected.
    pub disclosable: &'a [&'a str],
    /// Issued-at, Unix seconds (the `iat` claim). The validity-window start.
    pub iat: u64,
    /// Optional expiry, Unix seconds (the `exp` claim). The validity-window
    /// end; `None` mints a non-expiring credential.
    pub exp: Option<u64>,
}

/// Mint (issue) an SD-JWT-VC signed by the VTA's issuer key, with the named
/// claims made selectively disclosable and the holder DID bound as `cnf`.
///
/// `signer` is the issuer's signing capability — an
/// [`affinidi_sd_jwt::signer::JwtSigner`]. Its key is used **only** to sign;
/// this function never sees or exports the raw key material. It must produce
/// `EdDSA` (Ed25519) signatures so the resulting `iss` `did:key` resolves to a
/// verifying key that matches.
///
/// Returns the compact SD-JWT-VC serialization (`<jws>~<disclosure>~…`),
/// ready to deliver to the holder.
///
/// ## Failure modes (mint nothing on any)
/// - `vct`, `issuer_did`, or `subject_did` empty → [`AppError::Validation`].
/// - `subject_did` is not a resolvable Ed25519 `did:key` (cannot derive the
///   `cnf` binding JWK) → [`AppError::Validation`].
/// - `claims` is not a JSON object → [`AppError::Validation`].
/// - a name in `disclosable` is not a top-level key of `claims`, or names a
///   protected claim → [`AppError::Validation`].
/// - the issuer signer fails / the issue step rejects the frame
///   → [`AppError::Validation`].
pub fn mint_sd_jwt_vc(req: &MintRequest<'_>, signer: &dyn JwtSigner) -> Result<String, AppError> {
    if req.vct.trim().is_empty() {
        return Err(AppError::Validation("vct must be non-empty".to_string()));
    }
    if req.issuer_did.trim().is_empty() {
        return Err(AppError::Validation(
            "issuer_did must be non-empty".to_string(),
        ));
    }
    if req.subject_did.trim().is_empty() {
        return Err(AppError::Validation(
            "subject_did must be non-empty".to_string(),
        ));
    }

    // The claims must be an object; we index into it by name for the
    // disclosure-frame validation below.
    let claims_obj = req
        .claims
        .as_object()
        .ok_or_else(|| AppError::Validation("claims must be a JSON object".to_string()))?;

    // Every selectively-disclosable name must be an actual top-level claim,
    // and must not be a protected SD-JWT-VC claim. The underlying `issue`
    // re-checks the protected set, but we reject early with a precise message
    // and refuse to silently no-op a name that discloses nothing.
    const PROTECTED: &[&str] = &["vct", "iss", "iat", "exp", "nbf", "cnf", "sub", "status"];
    for name in req.disclosable {
        if PROTECTED.contains(name) {
            return Err(AppError::Validation(format!(
                "`{name}` is a protected claim and cannot be selectively disclosable"
            )));
        }
        if !claims_obj.contains_key(*name) {
            return Err(AppError::Validation(format!(
                "disclosable claim `{name}` is not present in `claims`"
            )));
        }
    }

    // Derive the holder confirmation key (`cnf`) JWK from the subject DID, so
    // the credential is holder-bound from issuance (spec §14.4). A subject DID
    // that isn't a resolvable Ed25519 did:key fails closed here.
    let holder_jwk = ed25519_did_key_to_cnf_jwk(req.subject_did)?;

    // Build the disclosure frame: exactly the named claims go under `_sd`, so
    // only their salted digests appear in the signed body; everything else is
    // emitted in the clear. An empty list means nothing is selectively
    // disclosed (a fully-cleartext credential), which is valid.
    let disclosure_frame = json!({
        "_sd": req.disclosable.iter().map(|s| Value::String((*s).to_string())).collect::<Vec<_>>(),
    });

    let hasher = Sha256Hasher;
    let vc = affinidi_sd_jwt_vc::issue(
        req.vct,
        req.issuer_did,
        Some(req.subject_did),
        req.claims,
        &disclosure_frame,
        signer,
        &hasher,
        Some(&holder_jwk),
        req.iat,
        req.exp,
    )
    .map_err(|e| AppError::Validation(format!("SD-JWT-VC issue failed: {e}")))?;

    Ok(vc.serialize())
}

/// Mint an SD-JWT-VC and, as a convenience, file it into the holder's own
/// vault under `id`.
///
/// This is sugar over [`mint_sd_jwt_vc`] plus the vault's own
/// [`receive`](super::receive) write path: it mints, then runs the freshly
/// minted credential through the *same* receive verification (issuer signature
/// and temporal validity) and indexing the holder uses for any incoming
/// credential. Routing it through receive (rather than a bespoke store) keeps a
/// single, audited write path and guarantees a self-minted credential is
/// indexed identically to a received one. Returns the stored envelope.
///
/// `now_unix` is the current time in Unix seconds (the receive temporal check
/// uses it); production callers pass `chrono::Utc::now().timestamp() as u64`.
pub async fn mint_and_store_sd_jwt_vc(
    vault: &KeyspaceHandle,
    id: &str,
    req: &MintRequest<'_>,
    signer: &dyn JwtSigner,
    now_unix: u64,
) -> Result<StoredCredential, AppError> {
    let compact = mint_sd_jwt_vc(req, signer)?;
    // Self-mint provenance; the receive path indexes it like any credential.
    receive::receive_sd_jwt_vc(
        vault,
        id,
        &compact,
        Some("self-minted".to_string()),
        now_unix,
    )
    .await
}

/// Build the holder-binding confirmation JWK (`cnf.jwk`) for an Ed25519
/// `did:key` subject.
///
/// SD-JWT-VC holder binding (`cnf`) carries the holder's *public* key as a
/// JWK. For an Ed25519 `did:key` we resolve the raw public key and express it
/// as an OKP / `Ed25519` JWK (RFC 8037). Only the public key is ever
/// touched — there is no private material here.
fn ed25519_did_key_to_cnf_jwk(subject_did: &str) -> Result<Value, AppError> {
    let pub_bytes = affinidi_crypto::did_key::did_key_to_ed25519_pub(subject_did).map_err(|e| {
        AppError::Validation(format!(
            "subject_did ({subject_did}) is not a resolvable Ed25519 did:key: {e}"
        ))
    })?;
    let x = URL_SAFE_NO_PAD.encode(pub_bytes);
    let mut jwk = Map::new();
    jwk.insert("kty".to_string(), Value::String("OKP".to_string()));
    jwk.insert("crv".to_string(), Value::String("Ed25519".to_string()));
    jwk.insert("x".to_string(), Value::String(x));
    Ok(Value::Object(jwk))
}

/// Best-effort mapping of a credential type tag onto the indexed
/// [`CredentialPurpose`] taxonomy, used only by callers that want to classify
/// a freshly minted credential. Mirrors the receive-side inference but is
/// exposed here so a mint caller can label what it just issued.
///
/// (Kept private; the canonical store path is [`mint_and_store_sd_jwt_vc`],
/// which reuses receive's own inference. This helper exists for the unit tests
/// and any future mint-with-explicit-purpose path.)
#[allow(dead_code)]
fn purpose_for_vct(vct: &str) -> Option<CredentialPurpose> {
    let lower = vct.to_ascii_lowercase();
    if lower.contains("invitation") || lower.contains("invite") {
        Some(CredentialPurpose::Invite)
    } else if lower.contains("membership") {
        Some(CredentialPurpose::Membership)
    } else if lower.contains("role") {
        Some(CredentialPurpose::Role)
    } else if lower.contains("endorsement") {
        Some(CredentialPurpose::Endorsement)
    } else if lower.contains("personhood") {
        Some(CredentialPurpose::Personhood)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{CredentialFormat, CredentialStatus};
    use super::super::storage;
    use super::*;
    use affinidi_sd_jwt::SdJwt;
    use affinidi_sd_jwt::error::SdJwtError;
    use affinidi_sd_jwt::signer::JwtSigner;
    use affinidi_sd_jwt::verifier::{VerificationOptions, verify};
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, Ordering};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    /// A production-shape EdDSA (Ed25519) JWT signer. The raw key lives only
    /// inside this object; it is exposed to the mint code *only* through the
    /// `JwtSigner` trait (sign-only), never as bytes.
    struct EddsaSigner {
        key: SigningKey,
        kid: String,
        /// Flipped true the moment `sign_jwt` runs, so a test can assert the
        /// key was used *only* via the signer (and that minting actually
        /// signed, rather than e.g. emitting an unsigned token).
        used: AtomicBool,
    }

    impl JwtSigner for EddsaSigner {
        fn algorithm(&self) -> &str {
            "EdDSA"
        }
        fn key_id(&self) -> Option<&str> {
            Some(&self.kid)
        }
        fn sign_jwt(&self, header: &Value, payload: &Value) -> Result<String, SdJwtError> {
            self.used.store(true, Ordering::SeqCst);
            let header_b64 = URL_SAFE_NO_PAD.encode(
                serde_json::to_string(header)
                    .map_err(SdJwtError::from)?
                    .as_bytes(),
            );
            let payload_b64 = URL_SAFE_NO_PAD.encode(
                serde_json::to_string(payload)
                    .map_err(SdJwtError::from)?
                    .as_bytes(),
            );
            let signing_input = format!("{header_b64}.{payload_b64}");
            let sig: Signature = self.key.sign(signing_input.as_bytes());
            let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
            Ok(format!("{signing_input}.{sig_b64}"))
        }
    }

    /// An issuer whose DID is the real `did:key` for its Ed25519 key, so the
    /// minted `iss` resolves back to the verifying key.
    fn issuer(seed: u8) -> (EddsaSigner, String) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let did =
            affinidi_crypto::did_key::ed25519_pub_to_did_key(signing.verifying_key().as_bytes());
        let kid = format!("{did}#key-0");
        (
            EddsaSigner {
                key: signing,
                kid,
                used: AtomicBool::new(false),
            },
            did,
        )
    }

    /// A holder did:key (a different key than the issuer).
    fn holder_did(seed: u8) -> String {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        affinidi_crypto::did_key::ed25519_pub_to_did_key(signing.verifying_key().as_bytes())
    }

    /// The receive-path verifier reused here to verify a minted credential end
    /// to end: resolves `iss` and checks the issuer Ed25519 signature.
    struct IssuerVerifier {
        key: ed25519_dalek::VerifyingKey,
    }
    impl affinidi_sd_jwt::signer::JwtVerifier for IssuerVerifier {
        fn verify_jwt(&self, jws: &str) -> Result<Value, SdJwtError> {
            use ed25519_dalek::Verifier;
            let parts: Vec<&str> = jws.split('.').collect();
            if parts.len() != 3 {
                return Err(SdJwtError::Verification("malformed JWS".into()));
            }
            let signing_input = format!("{}.{}", parts[0], parts[1]);
            let sig_bytes = URL_SAFE_NO_PAD
                .decode(parts[2])
                .map_err(|e| SdJwtError::Verification(e.to_string()))?;
            let sig = Signature::from_slice(&sig_bytes)
                .map_err(|e| SdJwtError::Verification(e.to_string()))?;
            self.key
                .verify(signing_input.as_bytes(), &sig)
                .map_err(|_| SdJwtError::Verification("bad sig".into()))?;
            let payload = URL_SAFE_NO_PAD
                .decode(parts[1])
                .map_err(|e| SdJwtError::Verification(e.to_string()))?;
            serde_json::from_slice(&payload).map_err(|e| SdJwtError::Verification(e.to_string()))
        }
    }

    fn fresh_vault() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace("vault").expect("vault keyspace");
        (dir, store, ks)
    }

    #[test]
    fn minted_vc_verifies_carries_vct_cnf_and_hides_disclosable_claims() {
        let (signer, issuer_did) = issuer(9);
        let subject = holder_did(7);
        let claims = json!({
            "community": "did:web:community.example",
            "tier": "founding",
            "public_label": "VTC East",
        });
        let req = MintRequest {
            vct: "https://openvtc.org/credentials/MembershipCredential",
            issuer_did: &issuer_did,
            subject_did: &subject,
            claims: &claims,
            // `community` + `tier` selectively disclosable; `public_label` clear.
            disclosable: &["community", "tier"],
            iat: 1_700_000_000,
            exp: Some(1_900_000_000),
        };

        let compact = mint_sd_jwt_vc(&req, &signer).expect("mint");

        // The issuer key was used — and only via the signer.
        assert!(signer.used.load(Ordering::SeqCst));

        let hasher = Sha256Hasher;
        let sd_jwt = SdJwt::parse(&compact, &hasher).expect("parse");

        // --- the SIGNED BODY (unverified payload view) ---
        let body = sd_jwt.payload().expect("payload");
        // Protected claims present in the clear.
        assert_eq!(
            body["vct"],
            "https://openvtc.org/credentials/MembershipCredential"
        );
        assert_eq!(body["iss"], issuer_did);
        assert_eq!(body["sub"], subject);
        // cnf holder binding present and matches the holder key.
        let expected_x = URL_SAFE_NO_PAD
            .encode(affinidi_crypto::did_key::did_key_to_ed25519_pub(&subject).unwrap());
        assert_eq!(body["cnf"]["jwk"]["kty"], "OKP");
        assert_eq!(body["cnf"]["jwk"]["crv"], "Ed25519");
        assert_eq!(body["cnf"]["jwk"]["x"], expected_x);
        // Non-disclosable claim is in the clear.
        assert_eq!(body["public_label"], "VTC East");
        // SELECTIVELY-DISCLOSABLE claims are ABSENT from the cleartext body.
        assert!(body.get("community").is_none());
        assert!(body.get("tier").is_none());
        // Their salted digests ARE present under `_sd`.
        let sd = body.get("_sd").and_then(Value::as_array).expect("_sd");
        assert_eq!(sd.len(), 2, "two disclosure digests in the signed body");
        // But not their cleartext values anywhere in the signed JSON.
        let body_str = serde_json::to_string(&body).unwrap();
        assert!(!body_str.contains("founding"));
        assert!(!body_str.contains("did:web:community.example"));

        // --- recoverable via disclosures ---
        assert_eq!(sd_jwt.disclosures.len(), 2);
        let mut recovered: Vec<(String, Value)> = sd_jwt
            .disclosures
            .iter()
            .map(|d| {
                (
                    d.claim_name.clone().unwrap_or_default(),
                    d.claim_value.clone(),
                )
            })
            .collect();
        recovered.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(recovered[0].0, "community");
        assert_eq!(recovered[0].1, "did:web:community.example");
        assert_eq!(recovered[1].0, "tier");
        assert_eq!(recovered[1].1, "founding");

        // --- issuer signature verifies against the iss did:key ---
        let pub_bytes = affinidi_crypto::did_key::did_key_to_ed25519_pub(&issuer_did).unwrap();
        let verifier = IssuerVerifier {
            key: ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes).unwrap(),
        };
        let opts = VerificationOptions::default();
        let result = verify(&sd_jwt, &verifier, &hasher, &opts, None).expect("verify");
        assert!(result.is_verified());
        // After verification + disclosure reconstruction, the disclosed claims
        // are recoverable in the verified claim set.
        assert_eq!(result.claims["community"], "did:web:community.example");
        assert_eq!(result.claims["tier"], "founding");
        // Temporal validity holds at a time inside the window.
        affinidi_sd_jwt_vc::verify_temporal(&result.claims, 1_800_000_000).expect("temporal");
    }

    #[test]
    fn minted_vc_signature_is_bound_to_the_issuer_key() {
        // A credential minted by issuer A must NOT verify under issuer B's key.
        let (signer, issuer_did) = issuer(9);
        let subject = holder_did(7);
        let claims = json!({ "x": "y" });
        let req = MintRequest {
            vct: "RoleCredential",
            issuer_did: &issuer_did,
            subject_did: &subject,
            claims: &claims,
            disclosable: &["x"],
            iat: 1_700_000_000,
            exp: None,
        };
        let compact = mint_sd_jwt_vc(&req, &signer).expect("mint");
        let hasher = Sha256Hasher;
        let sd_jwt = SdJwt::parse(&compact, &hasher).unwrap();

        // Verify under a DIFFERENT key — must fail.
        let (_other, other_did) = issuer(3);
        let wrong_pub = affinidi_crypto::did_key::did_key_to_ed25519_pub(&other_did).unwrap();
        let verifier = IssuerVerifier {
            key: ed25519_dalek::VerifyingKey::from_bytes(&wrong_pub).unwrap(),
        };
        let opts = VerificationOptions::default();
        assert!(verify(&sd_jwt, &verifier, &hasher, &opts, None).is_err());
    }

    #[test]
    fn empty_disclosable_mints_a_fully_cleartext_vc() {
        let (signer, issuer_did) = issuer(9);
        let subject = holder_did(7);
        let claims = json!({ "a": 1, "b": 2 });
        let req = MintRequest {
            vct: "EndorsementCredential",
            issuer_did: &issuer_did,
            subject_did: &subject,
            claims: &claims,
            disclosable: &[],
            iat: 1_700_000_000,
            exp: None,
        };
        let compact = mint_sd_jwt_vc(&req, &signer).expect("mint");
        let hasher = Sha256Hasher;
        let sd_jwt = SdJwt::parse(&compact, &hasher).unwrap();
        assert_eq!(sd_jwt.disclosures.len(), 0);
        let body = sd_jwt.payload().unwrap();
        assert_eq!(body["a"], 1);
        assert_eq!(body["b"], 2);
    }

    #[test]
    fn rejects_disclosable_claim_not_in_claims() {
        let (signer, issuer_did) = issuer(9);
        let subject = holder_did(7);
        let claims = json!({ "a": 1 });
        let req = MintRequest {
            vct: "X",
            issuer_did: &issuer_did,
            subject_did: &subject,
            claims: &claims,
            disclosable: &["nope"],
            iat: 1_700_000_000,
            exp: None,
        };
        let err = mint_sd_jwt_vc(&req, &signer).expect_err("must reject");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn rejects_disclosing_protected_claim() {
        let (signer, issuer_did) = issuer(9);
        let subject = holder_did(7);
        let claims = json!({ "a": 1 });
        let req = MintRequest {
            vct: "X",
            issuer_did: &issuer_did,
            subject_did: &subject,
            claims: &claims,
            disclosable: &["iss"],
            iat: 1_700_000_000,
            exp: None,
        };
        let err = mint_sd_jwt_vc(&req, &signer).expect_err("must reject");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn rejects_bad_subject_did() {
        let (signer, issuer_did) = issuer(9);
        let claims = json!({ "a": 1 });
        let req = MintRequest {
            vct: "X",
            issuer_did: &issuer_did,
            subject_did: "did:web:not-a-key",
            claims: &claims,
            disclosable: &["a"],
            iat: 1_700_000_000,
            exp: None,
        };
        let err = mint_sd_jwt_vc(&req, &signer).expect_err("must reject");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn rejects_empty_vct() {
        let (signer, issuer_did) = issuer(9);
        let subject = holder_did(7);
        let claims = json!({ "a": 1 });
        let req = MintRequest {
            vct: "  ",
            issuer_did: &issuer_did,
            subject_did: &subject,
            claims: &claims,
            disclosable: &["a"],
            iat: 1_700_000_000,
            exp: None,
        };
        let err = mint_sd_jwt_vc(&req, &signer).expect_err("must reject");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn mint_and_store_files_it_into_the_vault_indexed() {
        let (_dir, _store, vault) = fresh_vault();
        let (signer, issuer_did) = issuer(9);
        let subject = holder_did(7);
        let claims = json!({ "community": "did:web:c.example", "tier": "gold" });
        let req = MintRequest {
            vct: "https://openvtc.org/credentials/MembershipCredential",
            issuer_did: &issuer_did,
            subject_did: &subject,
            claims: &claims,
            disclosable: &["tier"],
            iat: 1_700_000_000,
            exp: Some(1_900_000_000),
        };

        let stored = mint_and_store_sd_jwt_vc(&vault, "minted-1", &req, &signer, 1_800_000_000)
            .await
            .expect("mint+store");

        assert_eq!(stored.id, "minted-1");
        assert_eq!(stored.format, CredentialFormat::SdJwtVc);
        assert_eq!(stored.issuer_did.as_deref(), Some(issuer_did.as_str()));
        assert_eq!(stored.subject_did.as_deref(), Some(subject.as_str()));
        assert_eq!(stored.status, CredentialStatus::Valid);
        assert_eq!(stored.purpose, Some(CredentialPurpose::Membership));
        assert_eq!(stored.source.as_deref(), Some("self-minted"));

        // Round-trips out of the store and is findable by the type index.
        let got = storage::get(&vault, "minted-1").await.unwrap().unwrap();
        assert_eq!(got.body, stored.body);
        let by_type = storage::find_by_index(
            &vault,
            crate::vault::IndexField::Type,
            "https://openvtc.org/credentials/MembershipCredential",
        )
        .await
        .unwrap();
        assert_eq!(by_type.len(), 1);
        assert_eq!(by_type[0].id, "minted-1");
    }

    #[test]
    fn purpose_for_vct_maps_catalog() {
        assert_eq!(
            purpose_for_vct("InvitationCredential"),
            Some(CredentialPurpose::Invite)
        );
        assert_eq!(
            purpose_for_vct("x/RoleCredential"),
            Some(CredentialPurpose::Role)
        );
        assert_eq!(purpose_for_vct("Mystery"), None);
    }
}
