//! Single `eddsa-jcs-2022` Data-Integrity proof verifier for Trust Task
//! documents (P1.4).
//!
//! Every place that verifies a holder's DI proof on a Trust Task and recovers
//! the cryptographically-proven signer DID delegates here. In the **VTA**: the
//! canonical REST authenticate path (`routes/auth.rs::
//! verify_authenticate_proof`, signer unknown a priori) and the did-signed
//! step-up gate (`trust_tasks/step_up.rs::verify_did_signed_gate`, signer
//! checked against the document issuer). In the **VTC**: the same REST
//! authenticate path, and the join-request dispatcher's holder-binding check
//! (`trust_tasks/helpers.rs::verify_trust_task_proof`).
//!
//! It started as one implementation in the VTA that had already drifted into
//! two copies there, then a third when the VTC ported it. It lives in
//! `vti-common` because *both services verify the same holder proof over the
//! same wire shape* — a divergence between them is a divergence in what a
//! signature means, which is not a thing to let happen twice.
//!
//! # Which DIDs may sign
//!
//! Any DID that can name a key. A proof's `verificationMethod` is resolved by
//! [`TrustTaskVmResolver`](super::vm_resolver::TrustTaskVmResolver), which
//! handles `did:key` locally and every other method through the configured DID
//! cache — so `did:webvh:<scid>:example.com:glenn#key-0` signs a Trust Task
//! exactly as a `did:key` does.
//!
//! This used to be `did:key` only, on the reasoning that the mobile holder key
//! is always a `did:key` and it kept proof verification off the network on an
//! unauthenticated route. The first half was never true of the whole surface:
//! every DID this workspace provisions for an integration is a `did:webvh`, so
//! the restriction meant a provisioned integration could not sign a Trust Task
//! at all. The second half is a real cost and is bounded rather than dismissed
//! — see the resolver's own module docs, and
//! [`verify_trust_task_proof`], whose `did:key`-only behaviour is unchanged for
//! callers that want it.

use affinidi_data_integrity::{DataIntegrityError, DataIntegrityProof, VerifyOptions};

use super::purpose::{ProofPurpose, PurposeBound};
use super::vm_resolver::TrustTaskVmResolver;
use serde::Serialize;
use serde_json::Value;
use trust_tasks_rs::TrustTask;

/// Why a Trust Task DI-proof verification failed. Callers map these onto their
/// own transport error types (`AppError::Authentication`, `GateError`, …).
#[derive(Debug)]
pub enum DiProofError {
    /// The document carries no `proof`.
    NoProof,
    /// The `proof` block is not a Data-Integrity proof.
    NotDataIntegrity,
    /// The proof's `verificationMethod` carries no DID.
    NoDid,
    /// The signer's key could not be retrieved — no resolver is configured
    /// for its DID method, or the DID did not resolve (network, rate limit,
    /// lookup failure) — so the proof was never checked. Distinct from the
    /// proof being wrong, which includes a key the signer's DID document does
    /// not authorise for the proof's purpose: that stays [`Self::VerifyFailed`].
    /// Either way the document is refused. Renders identically to [`Self::VerifyFailed`] on
    /// the wire (see that variant's `Display` arm for why); a caller that
    /// verifies its own outbound reply may branch on this variant directly to
    /// tell "could not retrieve the key" apart from "proof is invalid".
    ResolverFailed(String),
    /// The signature failed to verify (carries the underlying reason).
    VerifyFailed(String),
    /// The proof declares a purpose other than the one this document needs.
    WrongPurpose {
        /// The purpose the document needs.
        expected: &'static str,
    },
}

impl DiProofError {
    /// The underlying verifier detail, for the operator's log only.
    ///
    /// Deliberately not reachable through [`Display`]: that rendering goes on
    /// the wire, and this is exactly what Framework 0.5.0 forbids putting
    /// there. Log it beside the rejection; never return it.
    #[must_use]
    pub fn cause(&self) -> Option<&str> {
        match self {
            Self::ResolverFailed(e) | Self::VerifyFailed(e) => Some(e),
            _ => None,
        }
    }
}

impl std::fmt::Display for DiProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoProof => write!(f, "document has no proof"),
            Self::NotDataIntegrity => write!(f, "proof is not a Data Integrity proof"),
            Self::NoDid => write!(f, "proof verificationMethod carries no DID"),
            // Framework 0.5.0, *What a `message` May Not Say*: a `message`
            // MUST NOT reveal "resolver, verifier, or key-status internals",
            // normative for every code rather than for `identityMismatch`
            // alone. This `Display` reaches the wire through
            // `PermissionDenied { reason }`, so interpolating the underlying
            // verifier error published which cryptosuite ran, whether the key
            // resolved, and how it failed — to a party that is, on the
            // unauthenticated routes, not yet anybody.
            //
            // The producer needs to know its proof did not verify and that
            // retrying unchanged will not help. It does not need to know why,
            // and every additional word is an oracle. The cause is available
            // to the operator through [`Self::cause`].
            //
            // `ResolverFailed` renders identically and deliberately: it is
            // the same `DataIntegrityError::Resolver` distinction one layer
            // down, exposed to callers who branch on the variant itself
            // rather than on this text — this text still must not tell an
            // unauthenticated caller whether the difference was "could not
            // reach the resolver" versus "the signature was wrong".
            Self::ResolverFailed(_) | Self::VerifyFailed(_) => {
                write!(f, "proof verification failed")
            }
            Self::WrongPurpose { expected } => {
                write!(f, "proof must be made for `{expected}`")
            }
        }
    }
}

/// Classify a verification failure as a retrieval problem or an actual bad
/// proof — the one place `DataIntegrityError` becomes a `DiProofError`, so
/// every caller of [`verify_trust_task_proof_with`] gets the same answer.
///
/// Only a failure to *retrieve* the key is a resolver failure. The resolver
/// also refuses keys the DID document does not authorise for the proof's
/// purpose, controller mismatches and malformed methods through the same
/// upstream `Resolver` variant; those are verdicts on the proof, and reporting
/// one as "could not retrieve" would tell a caller a forged reply "may be
/// genuine".
fn classify(e: DataIntegrityError) -> DiProofError {
    if super::vm_resolver::is_unretrievable(&e) {
        return DiProofError::ResolverFailed(e.to_string());
    }
    DiProofError::VerifyFailed(e.to_string())
}

/// Verify the proof on `doc` **against `did:key` only**, with no network I/O.
///
/// The narrow form, kept for callers whose signer is a `did:key` by
/// construction and who do not want an unauthenticated request to be able to
/// trigger DID resolution. Anything that must accept a provisioned
/// integration's `did:webvh` holder wants
/// [`verify_trust_task_proof_with`] and a configured resolver.
///
/// Typed, so it re-serialises: for a document this process built. A document
/// that arrived over the network goes through [`verify_trust_task_proof_value`]
/// (see [`verify_trust_task_proof_with`] for why).
pub async fn verify_trust_task_proof(doc: &TrustTask<Value>) -> Result<String, DiProofError> {
    verify_trust_task_proof_with(doc, &TrustTaskVmResolver::did_key_only()).await
}

/// Verify the `eddsa-jcs-2022` Data-Integrity proof on `doc` and return the
/// proven signer DID — the base DID (before `#`) of the proof's
/// `verificationMethod`.
///
/// The signature is verified over the document with its `proof` block removed
/// (`eddsa-jcs-2022` canonicalises the proofless document via JCS). The
/// returned DID is *proven*, not merely claimed; binding it to an expected
/// identity (session DID, document issuer) is the caller's job — and remains so
/// however the verification method resolved. A proof by
/// `did:webvh:…:someone-else#key-0` verifies perfectly well; that it is not the
/// party you expected is a separate check, and not one this function makes.
///
/// # Only for a document this process built (VTI-45)
///
/// This form verifies a **re-serialisation** of `doc`, not the JSON that was
/// signed. That is exact for a document serialised by this workspace, and
/// wrong for one that arrived over the wire: `trust-tasks-rs` parses
/// `issuedAt`, `expiresAt` and the proof's `created` as `DateTime<Utc>` and
/// writes them back in its own spelling, so a producer that signed
/// `2026-09-25T12:37:33.000Z` (JavaScript's `toISOString()` on every whole
/// second), `+00:00`, a one-digit fraction or a lowercase `z` is refused as
/// "signature invalid". A `null` on a known optional member, an unknown member
/// of the proof and a payload member the type `P` does not keep are lost the
/// same way. Each of those breaks a correctly signed document.
///
/// Every network ingress verifies the received JSON instead, with
/// [`verify_trust_task_proof_value`]. This form remains for documents this
/// process produced and checks against itself (its own signing, tests).
///
/// # Generic over the payload
///
/// A proof is taken over the document, and the payload's Rust *shape* is not
/// part of it — `eddsa-jcs-2022` canonicalises whatever serialises. Existing
/// `&TrustTask<Value>` call sites are unaffected — `P` infers to `Value`.
pub async fn verify_trust_task_proof_with<P: Serialize + Clone + Sync>(
    doc: &TrustTask<P>,
    resolver: &TrustTaskVmResolver,
) -> Result<String, DiProofError> {
    let (unsigned, di) = split_typed(doc)?;
    verify_core(&unsigned, &di, resolver).await
}

/// Verify the `eddsa-jcs-2022` Data-Integrity proof on a Trust Task document
/// **as it was received** — `received` parsed straight from the wire bytes —
/// and return the proven signer DID.
///
/// This is the form for every network ingress (VTI-45). `serde_json::Value`
/// keeps every string verbatim, so what is canonicalised here is exactly the
/// members the producer signed: only the top-level `proof` member is removed,
/// and the proof itself is read from the received JSON rather than from a typed
/// `trust_tasks_rs::Proof` (which would rewrite `created`).
///
/// Everything else is as [`verify_trust_task_proof_with`]: the same purpose
/// binding (VTI-KEY-022), the same cached-DID refresh-and-retry (VTI-KEY-134),
/// the same error classification and wire text. Binding the signer to the
/// party you expected remains the caller's job.
///
/// The typed document a handler then acts on must be parsed from this same
/// `received`, so that what was verified is what is executed.
///
/// # The proof configuration
///
/// `affinidi-data-integrity` hashes a proof configuration rebuilt from its
/// typed `DataIntegrityProof` (`type`, `cryptosuite`, `created`,
/// `verificationMethod`, `proofPurpose`, `nonce`, `@context`), not the proof
/// object as received. A proof member outside that set (`challenge`, `domain`,
/// `expires`, `id`, `previousProof`), or a `null` on one of its optional
/// members, would be dropped from what is hashed. Such a proof is refused here
/// as [`DiProofError::VerifyFailed`], with the members named in
/// [`DiProofError::cause`]: either the producer signed them, and the signature
/// cannot verify without them, or it did not, and a proof member the signature
/// does not cover is not one this verifier should appear to have checked.
/// Lifting the limitation belongs in `affinidi-data-integrity` (hash the proof
/// configuration as received), not here.
pub async fn verify_trust_task_proof_value(
    received: &Value,
    resolver: &TrustTaskVmResolver,
) -> Result<String, DiProofError> {
    let (unsigned, di) = split_received(received)?;
    verify_core(&unsigned, &di, resolver).await
}

/// The proofless document and its parsed proof, from a typed document — by
/// re-serialising it (see [`verify_trust_task_proof_with`]).
fn split_typed<P: Serialize>(
    doc: &TrustTask<P>,
) -> Result<(Value, DataIntegrityProof), DiProofError> {
    let proof = doc.proof.as_ref().ok_or(DiProofError::NoProof)?;
    // The framework `Proof` round-trips into a `DataIntegrityProof` (same shape;
    // the mobile engine builds it the same way).
    let proof = serde_json::to_value(proof).map_err(|_| DiProofError::NotDataIntegrity)?;
    let di = parse_proof(&proof)?;
    let mut unsigned = serde_json::to_value(doc).map_err(|_| DiProofError::NotDataIntegrity)?;
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("proof");
    }
    Ok((unsigned, di))
}

/// The proofless document and its parsed proof, from the received JSON — only
/// the top-level `proof` member removed, nothing re-serialised.
fn split_received(received: &Value) -> Result<(Value, DataIntegrityProof), DiProofError> {
    let obj = received.as_object().ok_or(DiProofError::NoProof)?;
    let proof = match obj.get("proof") {
        None | Some(Value::Null) => return Err(DiProofError::NoProof),
        Some(proof) => proof,
    };
    let di = parse_proof(proof)?;
    let mut unsigned = obj.clone();
    unsigned.remove("proof");
    Ok((Value::Object(unsigned), di))
}

/// Parse a proof object, refusing one whose members the verifier would not
/// carry into the proof configuration it hashes (see
/// [`verify_trust_task_proof_value`], *The proof configuration*).
fn parse_proof(proof: &Value) -> Result<DataIntegrityProof, DiProofError> {
    let di: DataIntegrityProof =
        serde_json::from_value(proof.clone()).map_err(|_| DiProofError::NotDataIntegrity)?;
    let carried = serde_json::to_value(&di).map_err(|_| DiProofError::NotDataIntegrity)?;
    if &carried != proof {
        let carried = carried.as_object();
        let mut lost: Vec<&str> = proof
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(k, v)| carried.and_then(|c| c.get(k.as_str())) != Some(*v))
            .map(|(k, _)| k.as_str())
            .collect();
        lost.sort_unstable();
        return Err(DiProofError::VerifyFailed(format!(
            "the proof carries members the verifier cannot include in the proof \
             configuration it hashes: {}",
            lost.join(", ")
        )));
    }
    Ok(di)
}

/// The one verification both the typed and the received-JSON forms run.
async fn verify_core(
    unsigned: &Value,
    di: &DataIntegrityProof,
    resolver: &TrustTaskVmResolver,
) -> Result<String, DiProofError> {
    let signer_did = di
        .verification_method
        .split('#')
        .next()
        .unwrap_or_default()
        .to_string();
    if signer_did.is_empty() {
        return Err(DiProofError::NoDid);
    }

    // VTI-KEY-022: the key must be one the signer authorised for the purpose
    // the proof declares, not merely a key its DID document lists.
    let bound = PurposeBound::for_proof(resolver, di).map_err(classify)?;
    if let Err(first) = di.verify(unsigned, &bound, VerifyOptions::new()).await {
        // Checked against a cached document, a failure may only mean the
        // signer rotated since it was cached — the key id kept, its material
        // replaced. Re-resolve once, fresh, and verify again; fail closed on
        // whatever that says (VTI-KEY-134). A document fetched for this call is
        // not fetched again, and the refresh is rate-limited per DID
        // (`FRESH_RESOLVE_MIN_INTERVAL`), so a stream of bad proofs cannot turn
        // this verifier into a fetch amplifier. The retry stays bound to the
        // proof's purpose.
        if !resolver.refresh_if_cached(&signer_did).await {
            return Err(classify(first));
        }
        di.verify(unsigned, &bound, VerifyOptions::new())
            .await
            .map_err(classify)?;
    }

    Ok(signer_did)
}

/// The `proofPurpose` of a human approver's own decision: a
/// `task-consent/decision` or a step-up `approve-response`.
pub const APPROVAL_PROOF_PURPOSE: &str = "assertionMethod";

/// Refuse a proof not made for [`APPROVAL_PROOF_PURPOSE`].
fn require_approval_purpose(di: &DataIntegrityProof) -> Result<(), DiProofError> {
    if ProofPurpose::parse(&di.proof_purpose).ok() != Some(ProofPurpose::AssertionMethod) {
        return Err(DiProofError::WrongPurpose {
            expected: APPROVAL_PROOF_PURPOSE,
        });
    }
    Ok(())
}

/// Verify a human approver's decision (`task-consent/decision`, step-up
/// `approve-response`) and return the proven signer DID.
///
/// Everything [`verify_trust_task_proof_with`] checks, plus: the proof is made
/// for [`APPROVAL_PROOF_PURPOSE`]. A decision is the approver's attestation,
/// not an operational message, and a proof made for `authentication` is
/// refused. This matches the did-hosting RP's `verify_approval`
/// (affinidi-webvh-service #213), which is where a wallet's decisions are also
/// sent.
///
/// That the key is listed under the signer's `assertionMethod` relationship is
/// not a second check here: it is VTI-KEY-022's purpose binding, which every
/// proof gets — the verification runs through a [`PurposeBound`] resolver
/// fixed to `assertionMethod`, including the retry after a DID-cache refresh.
///
/// Binding the signer to the approver the caller expects remains the caller's
/// job, as with [`verify_trust_task_proof_with`].
///
/// Typed, so for a document this process built; a received decision goes
/// through [`verify_approval_proof_value`] (VTI-45).
pub async fn verify_approval_proof_with<P: Serialize + Clone + Sync>(
    doc: &TrustTask<P>,
    resolver: &TrustTaskVmResolver,
) -> Result<String, DiProofError> {
    let (unsigned, di) = split_typed(doc)?;
    require_approval_purpose(&di)?;
    // The declared purpose is now `assertionMethod`, so the general verifier
    // binds the resolver to exactly that relationship.
    verify_core(&unsigned, &di, resolver).await
}

/// [`verify_approval_proof_with`] over the document **as received** — the form
/// for every network ingress, for the reasons
/// [`verify_trust_task_proof_value`] gives.
pub async fn verify_approval_proof_value(
    received: &Value,
    resolver: &TrustTaskVmResolver,
) -> Result<String, DiProofError> {
    let (unsigned, di) = split_received(received)?;
    require_approval_purpose(&di)?;
    verify_core(&unsigned, &di, resolver).await
}

/// [`verify_approval_proof_with`] against `did:key` only, with no network I/O.
///
/// Typed: for a document this process built.
pub async fn verify_approval_proof(doc: &TrustTask<Value>) -> Result<String, DiProofError> {
    verify_approval_proof_with(doc, &TrustTaskVmResolver::did_key_only()).await
}

#[cfg(test)]
mod approval_tests {
    use super::*;
    use affinidi_data_integrity::SignOptions;
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;

    /// A `did:peer:2` whose one Ed25519 key is published under `purpose_code`
    /// (`A` = assertionMethod only, `D` = capabilityDelegation only; `V` would
    /// be both authentication and assertionMethod), and its signing secret.
    fn peer(purpose_code: char, seed: u8) -> (String, Secret) {
        let probe = Secret::generate_ed25519(None, Some(&[seed; 32]));
        let mb = probe.get_public_keymultibase().expect("public key");
        let did = format!("did:peer:2.{purpose_code}{mb}");
        let secret = Secret::generate_ed25519(Some(&format!("{did}#key-1")), Some(&[seed; 32]));
        (did, secret)
    }

    async fn decision(issuer: &str, secret: &Secret, purpose: &str) -> TrustTask<Value> {
        let mut doc = json!({
            "id": "urn:uuid:decision-1",
            "type": "https://trusttasks.org/spec/task-consent/decision/0.1",
            "issuer": issuer,
            "recipient": "did:web:vta.example",
            "issuedAt": "2026-09-25T10:00:00Z",
            "payload": { "decision": "approve" },
        });
        let proof =
            DataIntegrityProof::sign(&doc, secret, SignOptions::new().with_proof_purpose(purpose))
                .await
                .expect("sign");
        doc["proof"] = serde_json::to_value(proof).unwrap();
        serde_json::from_value(doc).unwrap()
    }

    /// An approver's decision verifies only as an `assertionMethod` proof by a
    /// key the approver lists under `assertionMethod`.
    #[tokio::test]
    async fn an_approval_is_an_assertion_by_an_assertion_key() {
        let (asserting, secret) = peer('A', 3);
        let ok = decision(&asserting, &secret, "assertionMethod").await;
        assert_eq!(verify_approval_proof(&ok).await.unwrap(), asserting);

        // The right key, made for `authentication`.
        let operational = decision(&asserting, &secret, "authentication").await;
        assert!(matches!(
            verify_approval_proof(&operational).await,
            Err(DiProofError::WrongPurpose {
                expected: "assertionMethod"
            })
        ));

        // Declared `assertionMethod`, by a key the DID does not list under
        // `assertionMethod`: refused by the approval verifier and, since
        // VTI-KEY-022 binds every proof to its purpose, by the general one too.
        let (delegating, secret) = peer('D', 4);
        let misfiled = decision(&delegating, &secret, "assertionMethod").await;
        for err in [
            verify_trust_task_proof(&misfiled).await.unwrap_err(),
            verify_approval_proof(&misfiled).await.unwrap_err(),
        ] {
            assert!(
                err.cause().is_some_and(|c| c.contains("assertionMethod")),
                "{err:?}"
            );
        }

        // And the relationship is the one the proof declares: an
        // assertion-only key does not make an `authentication` proof.
        let err = verify_trust_task_proof(&operational).await.unwrap_err();
        assert!(
            err.cause().is_some_and(|c| c.contains("authentication")),
            "{err:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The chokepoint this whole split exists to protect: every inbound call
    /// site that stringifies a `DiProofError` (the ~12 unauthenticated routes
    /// this variant must stay invisible to) does so through `Display`/`.to_string()`
    /// alone. If this ever diverges, every one of those routes starts leaking
    /// which failure mode occurred, one call site at a time — this is the one
    /// place that regression is caught for all of them at once.
    #[test]
    fn resolver_failed_and_verify_failed_render_identically() {
        let resolver_failed = DiProofError::ResolverFailed("some resolver detail".to_string());
        let verify_failed = DiProofError::VerifyFailed("some other detail".to_string());
        assert_eq!(resolver_failed.to_string(), verify_failed.to_string());
        assert_eq!(resolver_failed.to_string(), "proof verification failed");
    }

    /// The operator-facing detail must still be recoverable for both variants
    /// — opacity is a wire-facing property, not an operator one.
    #[test]
    fn cause_surfaces_the_detail_for_both_variants() {
        assert_eq!(
            DiProofError::ResolverFailed("did not resolve".to_string()).cause(),
            Some("did not resolve")
        );
        assert_eq!(
            DiProofError::VerifyFailed("bad signature".to_string()).cause(),
            Some("bad signature")
        );
        assert_eq!(DiProofError::NoProof.cause(), None);
    }

    /// A `did:webvh` verification method against a resolver configured for
    /// `did:key` only fails at resolution — no network, no signature check
    /// ever runs — and that failure must classify as `ResolverFailed`, not
    /// `VerifyFailed`. Mirrors the "no resolver configured" case that a
    /// `did:webvh`-only TEE VTA's own reply hits in production (FTL-29595).
    #[tokio::test]
    async fn a_resolver_failure_classifies_as_resolver_failed() {
        let doc: TrustTask<Value> = serde_json::from_value(serde_json::json!({
            "id": "urn:uuid:11111111-1111-4111-8111-111111111111",
            "type": "https://trusttasks.org/spec/vta/contexts/create/1.0",
            "issuer": "did:webvh:QmScid:example.com:glenn",
            "recipient": "did:key:z6MkVta",
            "payload": {},
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:webvh:QmScid:example.com:glenn#key-0",
                "created": "2026-08-29T00:00:00Z",
                "proofValue": "z2aBcD"
            }
        }))
        .expect("a well-formed Trust Task");

        let err = verify_trust_task_proof_with(&doc, &TrustTaskVmResolver::did_key_only())
            .await
            .expect_err("did:key-only cannot resolve a did:webvh key");
        assert!(
            matches!(err, DiProofError::ResolverFailed(_)),
            "expected ResolverFailed, got {err:?}"
        );
    }

    /// The resolver refuses keys the signer's DID document does not authorise
    /// for the proof's purpose through the same upstream `Resolver` variant
    /// it uses for a failed lookup. That refusal is a verdict on the proof:
    /// classifying it as a retrieval failure would tell the caller a forged
    /// reply "may be genuine".
    #[test]
    fn an_authorisation_refusal_is_an_invalid_proof_not_a_retrieval_failure() {
        for refusal in [
            "verificationMethod is not listed under assertionMethod in its DID document",
            "verificationMethod's controller is not the DID that names it",
            "a did:key X25519 key is authorised for keyAgreement only",
        ] {
            let err = classify(DataIntegrityError::Resolver(refusal.to_string()));
            assert!(
                matches!(err, DiProofError::VerifyFailed(_)),
                "`{refusal}` must stay an invalid proof, got {err:?}"
            );
        }
    }

    /// End to end: a `did:key` proof whose method is not the key's own
    /// (the fragment does not repeat the key id) is refused by the resolver,
    /// and that refusal is an invalid proof.
    #[tokio::test]
    async fn a_did_key_method_mismatch_classifies_as_verify_failed() {
        let doc: TrustTask<Value> = serde_json::from_value(serde_json::json!({
            "id": "urn:uuid:22222222-2222-4222-8222-222222222222",
            "type": "https://trusttasks.org/spec/vta/contexts/create/1.0",
            "issuer": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "recipient": "did:key:z6MkVta",
            "payload": {},
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofPurpose": "assertionMethod",
                "verificationMethod":
                    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#not-the-key",
                "created": "2026-08-29T00:00:00Z",
                "proofValue": "z2aBcD"
            }
        }))
        .expect("a well-formed Trust Task");

        let err = verify_trust_task_proof_with(&doc, &TrustTaskVmResolver::did_key_only())
            .await
            .expect_err("the method is not the did:key's own key");
        assert!(
            matches!(err, DiProofError::VerifyFailed(_)),
            "expected VerifyFailed, got {err:?}"
        );
    }

    /// The same resolver failure, reached through the identical production
    /// path as the case above, but this time the proof carries a real
    /// `did:key` signature that simply does not verify — classified as
    /// `VerifyFailed`, and — the actual regression this pair guards — renders
    /// the same wire text as the resolver failure above.
    #[tokio::test]
    async fn an_actual_bad_signature_classifies_as_verify_failed_with_identical_wire_text() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let did = format!(
            "did:key:{}",
            crate::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
        );
        let mut seed_secret = vec![0x80, 0x26];
        seed_secret.extend_from_slice(&[7u8; 32]);
        let secret_mb = multibase::encode(multibase::Base::Base58Btc, &seed_secret);

        let signed = crate::trust_task_sign::build_signed(
            "https://trusttasks.org/spec/vta/contexts/create/1.0",
            serde_json::json!({}),
            &did,
            &secret_mb,
            "did:key:z6MkVta",
        )
        .await
        .expect("build a validly-signed document");
        let mut doc: TrustTask<Value> = serde_json::from_str(&signed).expect("signed doc parses");

        // Corrupt the signature so it no longer verifies. A single-character
        // flip keeps the multibase string decodable (same length, same
        // alphabet), so this exercises "signature does not verify" rather
        // than "proof is malformed" — the failure this split must not
        // reclassify as a resolver problem.
        let proof = doc.proof.as_mut().expect("document is signed");
        let last = proof.proof_value.pop().expect("non-empty proofValue");
        proof.proof_value.push(if last == '1' { '2' } else { '1' });

        let err = verify_trust_task_proof_with(&doc, &TrustTaskVmResolver::did_key_only())
            .await
            .expect_err("a corrupted signature must not verify");
        assert!(
            matches!(err, DiProofError::VerifyFailed(_)),
            "expected VerifyFailed, got {err:?}"
        );

        // The invariant that matters: whichever of the two failed, the wire
        // text is the same one an unauthenticated caller would have seen for
        // the resolver failure above.
        assert_eq!(err.to_string(), "proof verification failed");
    }
}
