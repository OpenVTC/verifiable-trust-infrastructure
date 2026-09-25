//! Shared Data Integrity proof construction **and verification** for
//! DID-signed Trust Tasks.
//!
//! Construction: the holder key never enters Rust — `affinidi-data-integrity`'s
//! `prepare_sign_input` does the `eddsa-jcs-2022` canonicalization, the native
//! [`Signer`] signs the result, and we assemble the proof. Used by the step-up
//! DID-signed gate ([`crate::stepup`]) and VTA `authenticate` ([`crate::session`]).
//!
//! Every document the device sends is signed under
//! [`REQUEST_PROOF_PURPOSE`] (`authentication`): the VTA and the VTC accept a
//! Trust Task over DIDComm or TSP only when its proof verifies as its `issuer`
//! and that issuer is the transport sender, so the proof is what authenticates
//! the request. [`attach_did_signed_proof`] refuses to sign a document that does
//! not name the signer as its `issuer`, or that lacks a `recipient` or an
//! `issuedAt`, because the peer would refuse it anyway.
//!
//! Verification, of two kinds:
//!
//! - [`verify_signed_request`] is the gate every inbound approval request passes
//!   before its content may be shown to the operator (the task-consent request
//!   in [`crate::consent`], the step-up approve-request in [`crate::task`]). Any
//!   failure is [`FfiError::UntrustedIssuer`] — the typed "do not prompt"
//!   refusal.
//! - [`verify_reply`] is the gate every reply to a document the device sent
//!   passes before anything reads it. Any failure is
//!   [`FfiError::UnverifiedReply`].

use std::sync::Arc;

use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions, prepare_sign_input};
use multibase::Base;
use serde::Serialize;
use trust_tasks_proof::affinidi::CachedDidResolver;
use trust_tasks_rs::{Proof, TrustTask};

use crate::error::FfiError;
use crate::keys::Signer;

/// The proof purpose of every document this device signs. A Trust Task request
/// is the device authenticating itself to its peer (VTI-KEY-106), and the peer
/// requires the proof to verify as the transport sender.
pub(crate) const REQUEST_PROOF_PURPOSE: &str = "authentication";

/// The proof purpose a peer's reply must be signed under (VTI-KEY-106: the VTA
/// and the VTC sign every response, errors included, with their operational
/// key under `authentication`).
pub(crate) const REPLY_PROOF_PURPOSE: &str = "authentication";

/// The proof purpose the VTA signs the approval requests it pushes to a device
/// under (step-up approve-request, task-consent request).
pub(crate) const PUSHED_REQUEST_PROOF_PURPOSE: &str = "assertionMethod";

/// Build an `eddsa-jcs-2022` Data Integrity proof over `doc` (which MUST NOT yet
/// carry a proof), signed via the native `signer` under
/// [`REQUEST_PROOF_PURPOSE`], and attach it. `created` is an RFC 3339
/// timestamp.
///
/// Refuses, before anything is signed, a document that
///
/// - already carries a proof,
/// - has an empty `id`,
/// - does not name the signer as its `issuer` (the peer binds the proof's
///   signer, the `issuer` and the transport sender to one DID, so a document
///   issued in someone else's name is refused there — and signing it here
///   would be the device vouching for a claim it cannot make),
/// - has no `recipient` (the proof must bind the document to one peer, or it
///   could be replayed to another), or
/// - has no `issuedAt`.
pub(crate) fn attach_did_signed_proof<P: Serialize>(
    doc: &mut TrustTask<P>,
    signer: &dyn Signer,
    created: &str,
) -> Result<(), FfiError> {
    let refuse = |reason: String| Err(FfiError::InvalidInput { reason });
    let signer_did = signer.did();
    if doc.proof.is_some() {
        return refuse("the document already carries a proof".into());
    }
    if doc.id.is_empty() {
        return refuse("a signed document needs a unique `id`".into());
    }
    match doc.issuer.as_deref() {
        Some(issuer) if issuer == signer_did => {}
        Some(issuer) => {
            return refuse(format!(
                "the document names `{issuer}` as its issuer but would be signed by `{signer_did}`"
            ));
        }
        None => return refuse("a signed document must name its issuer".into()),
    }
    if doc.recipient.as_deref().is_none_or(str::is_empty) {
        return refuse("a signed document must name its recipient".into());
    }
    if doc.issued_at.is_none() {
        return refuse("a signed document must carry `issuedAt`".into());
    }

    // `DataIntegrityProof` is `#[non_exhaustive]` as of affinidi-data-integrity
    // 0.7.6 — build via `new` (the in-process `sign` would require the holder
    // key in Rust, which this flow deliberately avoids). `proof_value` is filled
    // in below after the native signer produces the signature.
    let mut proof_config = DataIntegrityProof::new(
        CryptoSuite::EddsaJcs2022,
        did_key_vm(&signer_did)?,
        REQUEST_PROOF_PURPOSE.to_string(),
        None,
        Some(created.to_string()),
        None,
    );

    // Library does eddsa-jcs-2022 canonicalization + hashing of (document, proof
    // config); the native enclave signs the result.
    let signing_input = prepare_sign_input(&*doc, &proof_config, CryptoSuite::EddsaJcs2022)
        .map_err(|e| FfiError::InvalidInput {
            reason: format!("failed to canonicalize for signing: {e}"),
        })?;
    let signature = signer.sign(signing_input)?;
    proof_config.proof_value = Some(multibase::encode(Base::Base58Btc, signature));

    let proof_json = serde_json::to_value(&proof_config).map_err(|e| FfiError::InvalidInput {
        reason: format!("proof serialize: {e}"),
    })?;
    doc.proof =
        Some(
            serde_json::from_value::<Proof>(proof_json).map_err(|e| FfiError::InvalidInput {
                reason: format!("proof shape: {e}"),
            })?,
        );
    Ok(())
}

/// Verify the `eddsa-jcs-2022` Data Integrity proof on an inbound approval
/// request and return the **proven** issuer DID.
///
/// This is the consumer side of the spec's `untrusted_issuer` rule (task-consent
/// request 0.1, consumer rule 1): *"Verify the `proof` and that the `issuer` is
/// an executor it is enrolled with. An unverifiable request → `untrusted_issuer`;
/// the device MUST NOT prompt."* Every failure maps to
/// [`FfiError::UntrustedIssuer`] so the native layer has exactly one variant
/// meaning "drop this, never prompt".
///
/// Enforced, in order:
/// 1. the document carries an `issuer` and a `proof`;
/// 2. the proof is a Data Integrity proof with `proofPurpose:assertionMethod`;
/// 3. the DID of `proof.verificationMethod` **is** the document `issuer` (a
///    valid signature only proves *some* key signed; authenticity additionally
///    requires that key to be the declared issuer's);
/// 4. the issuer is in `trusted_issuers` — the enrolled-executor allowlist the
///    native layer holds (the enrolled VTA DID plus any granted executor DIDs).
///    Checked **before** any DID resolution so the device never performs
///    network I/O on behalf of a DID it is not enrolled with;
/// 5. the signature verifies (`eddsa-jcs-2022` only) against key material
///    resolved from the issuer's DID document, via the crate's shared resolver
///    cache (`did:key` offline; `did:web` / `did:webvh` over the network).
///
/// Verification runs over the **raw** JSON document (`proof` removed), not a
/// typed round-trip — so it is byte-faithful to what the executor signed, extra
/// wire fields included.
pub(crate) async fn verify_signed_request(
    raw: &serde_json::Value,
    trusted_issuers: &[String],
) -> Result<String, FfiError> {
    let refuse = |reason: String| FfiError::UntrustedIssuer { reason };

    let issuer = raw
        .get("issuer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| refuse("request carries no issuer to bind the proof to".into()))?;

    let proof_value = raw
        .get("proof")
        .ok_or_else(|| refuse("request carries no proof".into()))?;
    let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone())
        .map_err(|e| refuse(format!("proof is not a Data Integrity proof: {e}")))?;

    if proof.proof_purpose != PUSHED_REQUEST_PROOF_PURPOSE {
        return Err(refuse(format!(
            "proof purpose is `{}`, not `{PUSHED_REQUEST_PROOF_PURPOSE}`",
            proof.proof_purpose
        )));
    }

    let vm_did = proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or_default();
    if vm_did.is_empty() || vm_did != issuer {
        return Err(refuse(format!(
            "proof verificationMethod is controlled by `{vm_did}`, not the document issuer `{issuer}`"
        )));
    }

    if !trusted_issuers.iter().any(|t| t == issuer) {
        return Err(refuse(format!(
            "issuer {issuer} is not an executor this device is enrolled with"
        )));
    }

    verify_signature(raw, &proof, issuer, PUSHED_REQUEST_PROOF_PURPOSE)
        .await
        .map_err(refuse)?;

    Ok(issuer.to_string())
}

/// Verify the reply to a Trust Task this device sent, before anything reads it.
///
/// `request` is the document as sent; `expected_signer` is the peer it was sent
/// to (the VTA DID). The reply is accepted only when all of these hold:
///
/// 1. its `type` is the request's `type` plus `#response`, or a
///    `trust-task-error` — an answer to a different question is not an answer;
/// 2. its `threadId` is the request's thread (`request.threadId ?? request.id`,
///    SPEC §4.9). The request's `id` is fresh per request, so this binds the
///    reply to this request and a replayed reply to an earlier one is refused;
/// 3. its `issuer` is `expected_signer`, and its `recipient` is the request's
///    `issuer` (this device);
/// 4. it carries an `eddsa-jcs-2022` Data Integrity proof under
///    `authentication` (VTI-KEY-106), whose `verificationMethod` belongs to
///    `expected_signer` and is listed under `authentication` in that DID's
///    document;
/// 5. the signature verifies over the reply with its `proof` removed.
///
/// **Error replies are held to the same rule.** The VTA and the VTC sign
/// refusals too (VTI-KEY-106), and an unattributable `trust-task-error` is no
/// more the peer's word than an unattributable success — acting on one lets
/// anyone on the path make the device believe its approval was refused.
///
/// Every failure is [`FfiError::UnverifiedReply`].
pub(crate) async fn verify_reply(
    request: &serde_json::Value,
    reply: &serde_json::Value,
    expected_signer: &str,
) -> Result<(), FfiError> {
    let refuse = |reason: String| FfiError::UnverifiedReply { reason };
    let str_field = |doc: &serde_json::Value, name: &str| {
        doc.get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };

    if expected_signer.is_empty() {
        return Err(refuse("no peer to verify the reply against".into()));
    }
    let request_id = str_field(request, "id")
        .filter(|id| !id.is_empty())
        .ok_or_else(|| refuse("the request has no `id` to thread a reply to".into()))?;
    let request_type =
        str_field(request, "type").ok_or_else(|| refuse("the request has no `type`".into()))?;
    let our_did =
        str_field(request, "issuer").ok_or_else(|| refuse("the request names no issuer".into()))?;
    let expected_thread = str_field(request, "threadId").unwrap_or(request_id);

    // 1. It answers this question.
    let reply_type = str_field(reply, "type").unwrap_or_default();
    let is_error = reply_type.starts_with(TRUST_TASK_ERROR_TYPE_PREFIX);
    if !is_error && reply_type != format!("{request_type}#response") {
        return Err(refuse(format!(
            "the reply's type `{reply_type}` does not answer a `{request_type}` request"
        )));
    }

    // 2. It answers this request.
    match str_field(reply, "threadId") {
        Some(thread) if thread == expected_thread => {}
        Some(thread) => {
            return Err(refuse(format!(
                "the reply is threaded to `{thread}`, not to the request `{expected_thread}`"
            )));
        }
        None => return Err(refuse("the reply carries no `threadId`".into())),
    }

    // 3. It is from the peer, to us.
    match str_field(reply, "issuer") {
        Some(issuer) if issuer == expected_signer => {}
        Some(issuer) => {
            return Err(refuse(format!(
                "the reply is issued by `{issuer}`, not by `{expected_signer}`"
            )));
        }
        None => return Err(refuse("the reply names no issuer".into())),
    }
    match str_field(reply, "recipient") {
        Some(recipient) if recipient == our_did => {}
        Some(recipient) => {
            return Err(refuse(format!(
                "the reply is addressed to `{recipient}`, not to `{our_did}`"
            )));
        }
        None => return Err(refuse("the reply names no recipient".into())),
    }

    // 4 + 5. Its proof is the peer's, under `authentication`, and verifies.
    let proof_value = reply
        .get("proof")
        .ok_or_else(|| refuse("the reply carries no proof".into()))?;
    let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone()).map_err(|e| {
        refuse(format!(
            "the reply's proof is not a Data Integrity proof: {e}"
        ))
    })?;
    if proof.proof_purpose != REPLY_PROOF_PURPOSE {
        return Err(refuse(format!(
            "the reply's proof purpose is `{}`, not `{REPLY_PROOF_PURPOSE}`",
            proof.proof_purpose
        )));
    }
    let vm_did = proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or_default();
    if vm_did != expected_signer {
        return Err(refuse(format!(
            "the reply is signed by `{vm_did}`, not by `{expected_signer}`"
        )));
    }

    verify_signature(reply, &proof, expected_signer, REPLY_PROOF_PURPOSE)
        .await
        .map_err(refuse)
}

/// The `type` prefix of a framework error document.
const TRUST_TASK_ERROR_TYPE_PREFIX: &str = "https://trusttasks.org/spec/trust-task-error/";

/// Check that `proof.verificationMethod` is listed under `relationship` in
/// `signer`'s DID document, then verify the `eddsa-jcs-2022` signature over
/// `raw` with its `proof` member removed.
///
/// The relationship check is ours to make: the proof library verifies a
/// signature against whatever key the method names, and the resolver accepts a
/// key listed under *either* `authentication` or `assertionMethod`. A proof
/// that says `authentication` is only an authentication by that DID when the
/// DID's controller has put the key there.
async fn verify_signature(
    raw: &serde_json::Value,
    proof: &DataIntegrityProof,
    signer: &str,
    relationship: &str,
) -> Result<(), String> {
    let client = crate::resolver::client().await.map_err(|e| e.to_string())?;
    let resolved = client
        .resolve(signer)
        .await
        .map_err(|e| format!("could not resolve {signer}: {e}"))?;
    let did_doc = serde_json::to_value(&resolved.doc)
        .map_err(|e| format!("could not read the DID document of {signer}: {e}"))?;
    if !lists_method_under(&did_doc, &proof.verification_method, relationship) {
        return Err(format!(
            "{} is not listed under `{relationship}` in the DID document of {signer}",
            proof.verification_method
        ));
    }

    let mut unsigned = raw.clone();
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("proof");
    }
    let resolver = CachedDidResolver::new(Arc::new(client.clone()));
    proof
        .verify(
            &unsigned,
            &resolver,
            VerifyOptions::new().with_allowed_suites(vec![CryptoSuite::EddsaJcs2022]),
        )
        .await
        .map_err(|e| format!("proof verification failed: {e}"))
}

/// Whether `did_doc` lists the verification method `vm` under `relationship`,
/// by absolute DID URL, by relative `#fragment`, or as an embedded method.
fn lists_method_under(did_doc: &serde_json::Value, vm: &str, relationship: &str) -> bool {
    let fragment = vm.find('#').map(|i| &vm[i..]);
    let names_vm = |id: &str| id == vm || fragment.is_some_and(|f| id == f);
    did_doc
        .get(relationship)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|entries| {
            entries.iter().any(|entry| match entry {
                serde_json::Value::String(id) => names_vm(id),
                serde_json::Value::Object(m) => m
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(names_vm),
                _ => false,
            })
        })
}

/// Derive the verification-method URI for a `did:key` holder. The mobile holder
/// key is a `did:key`, whose verification method is `<did>#<method-specific-id>`.
pub(crate) fn did_key_vm(did: &str) -> Result<String, FfiError> {
    let suffix = did
        .strip_prefix("did:key:")
        .ok_or_else(|| FfiError::InvalidInput {
            reason: format!("the DID-signed gate requires a did:key holder; got {did}"),
        })?;
    Ok(format!("{did}#{suffix}"))
}

/// Deterministic executor keys + the production sign path, for the request
/// verification tests in [`crate::consent`] and [`crate::task`]. Mirrors the
/// VTA's `mint_signed_requests` (`vta-service` `consent_request.rs`): sign the
/// proofless document with `eddsa-jcs-2022` / `assertionMethod`, attach the
/// proof. `did:key` issuers resolve offline, so the tests exercise the full
/// verify path without touching the network.
#[cfg(test)]
pub(crate) mod test_support {
    use affinidi_data_integrity::crypto_suites::CryptoSuite;
    use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
    use ed25519_dalek::SigningKey;

    /// The `did:key` of the deterministic Ed25519 key seeded from `seed`.
    pub(crate) fn did_for(seed: u8) -> String {
        affinidi_crypto::did_key::ed25519_pub_to_did_key(
            &SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    fn secret_for(seed: u8) -> affinidi_secrets_resolver::secrets::Secret {
        let did = did_for(seed);
        let vm = format!("{did}#{}", did.strip_prefix("did:key:").unwrap());
        affinidi_secrets_resolver::secrets::Secret::generate_ed25519(Some(&vm), Some(&[seed; 32]))
    }

    /// Sign `doc` (which must not yet carry a proof) as the `seed` executor and
    /// attach the proof, exactly as the VTA signs an outbound request.
    pub(crate) async fn sign_as(doc: &mut serde_json::Value, seed: u8) {
        sign_as_with_purpose(doc, seed, super::PUSHED_REQUEST_PROOF_PURPOSE).await;
    }

    /// [`sign_as`] under an explicit proof purpose — the VTA signs its replies
    /// under `authentication`.
    pub(crate) async fn sign_as_with_purpose(doc: &mut serde_json::Value, seed: u8, purpose: &str) {
        let proof = DataIntegrityProof::sign(
            &*doc,
            &secret_for(seed),
            SignOptions::new()
                .with_proof_purpose(purpose)
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .expect("test signing cannot fail");
        doc["proof"] = serde_json::to_value(&proof).expect("proof serializes");
    }
}
