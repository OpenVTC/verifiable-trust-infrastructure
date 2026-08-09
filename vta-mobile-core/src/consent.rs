//! Task-execution consent — the mobile device as a **second approver**.
//!
//! Mirrors the step-up approver ([`crate::stepup`] / [`crate::task`]): the VTA
//! pushes a signed `task-consent/request/0.1` over the mediator, the native app
//! shows the operator what executing the task would do (the VTA's dry-run
//! `effects`) plus a human-checkable match code, and — behind a biometric — the
//! operator returns a DID-signed `task-consent/decision/0.1`.
//!
//! Two exports:
//! - [`parse_task_consent_request`] **verifies** the request's own
//!   `eddsa-jcs-2022` Data Integrity proof against the caller-supplied
//!   enrolled-executor allowlist, then surfaces the display fields. Field
//!   extraction reads off a lenient `Value` rather than the strict generated
//!   `request` type, because the VTA's wire payload carries fields beyond that
//!   schema (`excludeRequester`, `statePin`), and the display path must not be
//!   brittle to them — the proof is verified over the raw document, so the
//!   extra fields are covered by the signature too.
//! - [`build_task_consent_decision_did_signed`] / [`build_task_consent_decision_denied`]
//!   assemble the decision from the **typed** `decision` payload (which this
//!   crate constructs, so no unknown-field concern) and attach the same
//!   `eddsa-jcs-2022` Data Integrity proof the step-up gate uses. The proof — not
//!   the transport — is the approver's authority: the VTA takes the signer from
//!   it (see the executor's `task_consent::handle_decision`).
//!
//! Sender attribution is layered. The transport authenticates first: the
//! mediator verifies the VTA's authcrypt envelope before `receive_next` yields,
//! and the native layer checks the message `from` is the enrolled VTA. On top of
//! that, the request document's own DI proof is now **verified on-device before
//! anything is surfaced for display** (belt-and-braces against a compromised
//! mediator, as the browser approver does): the proof must be present and valid,
//! the proof key must be the document `issuer`'s, and the issuer must be an
//! enrolled executor — otherwise [`crate::FfiError::UntrustedIssuer`] and the
//! device MUST NOT prompt (the spec's `untrusted_issuer` rule). See
//! [`crate::proof::verify_signed_request`].

use chrono::DateTime;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::task_consent::decision::v0_1 as decision;

use crate::error::FfiError;
use crate::keys::Signer;
use crate::proof::attach_did_signed_proof;

/// Type URI of the request document this approver renders.
const TASK_CONSENT_REQUEST_TYPE: &str = "https://trusttasks.org/spec/task-consent/request/0.1";

/// Length of the human-checkable match code compared across the two screens.
/// UI-only (there is no wire field); mirrors the browser approver's code.
const MATCH_CODE_LEN: usize = 6;

/// Multihash prefix for SHA-256 with a 32-byte digest, as carried inside a
/// `digestMultibase`. Stripped before deriving the match code because it is
/// constant — see [`match_code_from_digest`].
const MULTIHASH_SHA2_256_32: [u8; 2] = [0x12, 0x20];

/// The operator's comparison code: the first [`MATCH_CODE_LEN`] hex characters
/// of the **digest bytes**, not of their multibase encoding.
///
/// This distinction is the whole point. `payloadDigest` is a multibase-encoded
/// multihash, so its first three characters are always `zQm` — that is the
/// base58btc marker plus the sha2-256 multihash prefix, and it is identical for
/// every digest ever produced:
///
/// ```text
/// zQmcdLJ…   zQmRTnb…   zQmb7oR…   zQmbu6r…      ← four different payloads
/// ```
///
/// Slicing the encoded string would therefore spend half a six-character code on
/// a constant, leaving ~17.6 bits where the operator believes they are comparing
/// ~35 — and it would still *look* like six random characters, which is what
/// makes it dangerous rather than merely wasteful. An attacker searching offline
/// for a payload that renders the same code to the operator would face ~195k
/// candidates instead of ~60 billion.
///
/// Decoding first restores the full entropy and, because the digest is still
/// SHA-256, reproduces **exactly** the code this surface showed when the wire
/// carried bare hex: `hex(digest)[..6]` either way. The encoding migration is
/// therefore invisible on this screen.
fn match_code_from_digest(payload_digest: &str) -> Result<String, FfiError> {
    let (_base, bytes) = multibase::decode(payload_digest).map_err(|e| FfiError::Decode {
        reason: format!("payloadDigest is not multibase: {e}"),
    })?;
    let digest = bytes
        .strip_prefix(&MULTIHASH_SHA2_256_32)
        .ok_or_else(|| FfiError::Decode {
            reason: "payloadDigest is not a sha2-256 multihash".to_string(),
        })?;
    // Two hex characters per byte.
    let need = MATCH_CODE_LEN.div_ceil(2);
    if digest.len() < need {
        return Err(FfiError::Decode {
            reason: format!("payloadDigest carries {} bytes, need {need}", digest.len()),
        });
    }
    Ok(hex::encode(&digest[..need])[..MATCH_CODE_LEN].to_string())
}

/// One consequence of executing the task, authored by the VTA by dry-running the
/// handler it is about to invoke. The `kind` set is OPEN — a surface MUST render
/// a kind it does not recognise (always show `summary`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct TaskConsentEffect {
    pub kind: String,
    /// Human-facing sentence — the one member always safe to render.
    pub summary: String,
    pub path: Option<String>,
    /// Prior/resulting values as raw JSON strings, when present (for a diff).
    pub before: Option<String>,
    pub after: Option<String>,
}

/// The `task-consent/request` fields the native approval UI needs to display and
/// to answer.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TaskConsentRequest {
    /// The executor that issued the request — the **proven** signer of the
    /// document's Data Integrity proof, guaranteed to be in the caller's
    /// enrolled-executor allowlist.
    pub issuer: String,
    /// Nonce echoed + bound into the decision (never recomputed here).
    pub challenge: String,
    /// The salted digest the decision echoes; the executor re-derives it from the
    /// payload it is about to run and refuses on mismatch.
    pub payload_digest: String,
    /// First chars of `payload_digest` — the code the operator matches against
    /// the requesting screen.
    pub match_code: String,
    /// Type URI of the task awaiting approval.
    pub task_type: String,
    /// The DID that submitted the task.
    pub requester: String,
    /// Named approver set the policy required.
    pub approver_set: Option<String>,
    /// Distinct approvals the policy requires.
    pub min_approvals: u64,
    /// Integrity effect of executing: `none` | `mutating` | `destructive`.
    pub side_effects: Option<String>,
    /// What executing discloses to the caller: `none` | `metadata` | `secret`.
    pub discloses: Option<String>,
    /// Whether the task acts with the subject's own authority.
    pub acts_as_subject: bool,
    /// What executing will do — the basis of the operator's decision. MAY be
    /// empty; fall back to `consequences`, and if both are empty the UI must say
    /// the consequences could not be determined (never render "no effects").
    pub effects: Vec<TaskConsentEffect>,
    /// The identifier the task acts on, when known.
    pub subject: Option<String>,
    /// Browser-attested origin of the page that proposed the task, when present.
    pub origin: Option<String>,
    /// RFC 3339 expiry of the pending request, when present.
    pub expires_at: Option<String>,
    /// The task specification's static fallback text, used when `effects` is
    /// empty because the VTA had no dry-run for this handler.
    pub consequences: Vec<String>,
}

/// Verify and parse an inbound `task-consent/request/0.1` for display.
///
/// `trusted_issuers` is the enrolled-executor allowlist the native layer holds:
/// the enrolled VTA's DID plus any granted executor DIDs. The request's Data
/// Integrity proof is verified first ([`crate::proof::verify_signed_request`]);
/// an unverifiable request returns [`FfiError::UntrustedIssuer`] and MUST NOT
/// be prompted on. Async because verification resolves the issuer's DID for its
/// key material (through the crate's shared resolver cache).
///
/// Field extraction stays lenient by design (see the module note): validates
/// the document type and the binding fields the decision must echo, and
/// surfaces the rest best-effort.
#[uniffi::export(async_runtime = "tokio")]
pub async fn parse_task_consent_request(
    json: String,
    trusted_issuers: Vec<String>,
) -> Result<TaskConsentRequest, FfiError> {
    let v: serde_json::Value = serde_json::from_str(&json).map_err(|e| FfiError::Decode {
        reason: format!("not valid JSON: {e}"),
    })?;

    if v.get("type").and_then(|t| t.as_str()) != Some(TASK_CONSENT_REQUEST_TYPE) {
        return Err(FfiError::Decode {
            reason: "not a task-consent/request/0.1 document".to_string(),
        });
    }

    // The gate: no valid proof from an enrolled executor, no prompt.
    let issuer = crate::proof::verify_signed_request(&v, &trusted_issuers).await?;

    let p = v.get("payload").ok_or_else(|| FfiError::Decode {
        reason: "task-consent request has no payload".to_string(),
    })?;

    let opt_str = |k: &str| p.get(k).and_then(|x| x.as_str()).map(String::from);
    let req_str = |k: &str| {
        opt_str(k).ok_or_else(|| FfiError::Decode {
            reason: format!("task-consent request payload is missing `{k}`"),
        })
    };

    // The three fields the decision is bound to must be present.
    let challenge = req_str("challenge")?;
    let payload_digest = req_str("payloadDigest")?;
    let task_type = req_str("taskType")?;

    let match_code = match_code_from_digest(&payload_digest)?;

    let exposure = p.get("exposure");
    let discloses = exposure
        .and_then(|e| e.get("discloses"))
        .and_then(|x| x.as_str())
        .map(String::from);
    let acts_as_subject = exposure
        .and_then(|e| e.get("actsAsSubject"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    let effects = p
        .get("effects")
        .and_then(|e| e.as_array())
        .map(|arr| arr.iter().map(parse_effect).collect())
        .unwrap_or_default();

    let consequences = p
        .get("consequences")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(TaskConsentRequest {
        issuer,
        challenge,
        payload_digest,
        match_code,
        task_type,
        requester: opt_str("requester").unwrap_or_default(),
        approver_set: opt_str("approverSet"),
        min_approvals: p.get("minApprovals").and_then(|x| x.as_u64()).unwrap_or(1),
        side_effects: opt_str("sideEffects"),
        discloses,
        acts_as_subject,
        effects,
        subject: opt_str("subject"),
        origin: opt_str("origin"),
        expires_at: opt_str("expiresAt"),
        consequences,
    })
}

fn parse_effect(v: &serde_json::Value) -> TaskConsentEffect {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
    let j = |k: &str| v.get(k).filter(|x| !x.is_null()).map(|x| x.to_string());
    TaskConsentEffect {
        kind: s("kind").unwrap_or_default(),
        summary: s("summary").unwrap_or_default(),
        path: s("path"),
        before: j("before"),
        after: j("after"),
    }
}

/// The envelope + echo fields for a task-consent decision. `id` and `issued_at`
/// are supplied by the native layer, keeping the builder pure.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TaskConsentDecisionDraft {
    /// Document id (e.g. a fresh UUID).
    pub id: String,
    /// The approver's DID (document `issuer`).
    pub issuer_did: String,
    /// The VTA's DID (document `recipient`).
    pub recipient_did: String,
    /// RFC 3339 timestamp for `issuedAt` and the proof's `created`.
    pub issued_at: String,
    /// Echoed verbatim from the request — binds this decision to that pending one.
    pub challenge: String,
    /// Echoed verbatim from the request — the executor re-derives and matches it.
    pub payload_digest: String,
}

/// Build a DID-signed **approval** `task-consent/decision/0.1`, gated by an
/// `eddsa-jcs-2022` Data Integrity proof over the document. `signer` is the
/// native enclave key; its private material never enters this crate.
#[uniffi::export]
pub fn build_task_consent_decision_did_signed(
    draft: TaskConsentDecisionDraft,
    signer: Box<dyn Signer>,
) -> Result<String, FfiError> {
    let mut doc = assemble_decision(&draft, decision::Decision::Approve, None)?;
    attach_did_signed_proof(&mut doc, &*signer, &draft.issued_at)?;
    serialize(&doc)
}

/// Build a DID-signed **denial** `task-consent/decision/0.1`, carrying the human
/// `reason`, gated by the same proof. A denial is a signed refusal the executor
/// records; nothing executes.
#[uniffi::export]
pub fn build_task_consent_decision_denied(
    draft: TaskConsentDecisionDraft,
    reason: String,
    signer: Box<dyn Signer>,
) -> Result<String, FfiError> {
    let mut doc = assemble_decision(&draft, decision::Decision::Deny, Some(reason))?;
    attach_did_signed_proof(&mut doc, &*signer, &draft.issued_at)?;
    serialize(&doc)
}

fn assemble_decision(
    draft: &TaskConsentDecisionDraft,
    d: decision::Decision,
    reason: Option<String>,
) -> Result<TrustTask<decision::Payload>, FfiError> {
    let issued_at = DateTime::parse_from_rfc3339(&draft.issued_at)
        .map_err(|e| FfiError::InvalidInput {
            reason: format!("issued_at is not an RFC 3339 timestamp: {e}"),
        })?
        .with_timezone(&chrono::Utc);

    let payload = decision::Payload {
        challenge: decision::PayloadChallenge::try_from(draft.challenge.clone()).map_err(conv)?,
        decision: d,
        // `payloadDigest` moved to the shared `DigestMultibase` type — a
        // multibase-encoded multihash, not the bare hex it used to be. Parse
        // rather than assume: a draft carrying a stale hex digest must fail
        // here, at the device that would otherwise sign a decision the VTA
        // could never match.
        payload_digest: decision::DigestMultibase::try_from(draft.payload_digest.clone())
            .map_err(conv)?,
        reason,
        ext: None,
    };

    let mut doc = TrustTask::for_payload(draft.id.clone(), payload);
    doc.issuer = Some(draft.issuer_did.clone());
    doc.recipient = Some(draft.recipient_did.clone());
    doc.issued_at = Some(issued_at);
    Ok(doc)
}

fn serialize(doc: &TrustTask<decision::Payload>) -> Result<String, FfiError> {
    serde_json::to_string(doc).map_err(|e| FfiError::InvalidInput {
        reason: format!("failed to serialize task-consent decision: {e}"),
    })
}

/// Map a `trust-tasks-rs` newtype `ConversionError` (e.g. a challenge below the
/// 16-char minimum) to an FFI error.
fn conv<E: ::std::fmt::Display>(e: E) -> FfiError {
    FfiError::InvalidInput {
        reason: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::test_support::{did_for, sign_as};

    /// Seed of the enrolled executor the happy-path tests sign as.
    const EXECUTOR: u8 = 7;
    /// Seed of a key holder the device is *not* enrolled with.
    const STRANGER: u8 = 8;

    const REQUEST: &str = r##"{
      "id": "urn:uuid:11111111-1111-1111-1111-111111111111",
      "type": "https://trusttasks.org/spec/task-consent/request/0.1",
      "issuer": "did:webvh:scid:vta.example:vta",
      "recipient": "did:key:zApprover",
      "issuedAt": "2026-07-18T10:00:00Z",
      "payload": {
        "challenge": "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ",
        "taskType": "https://trusttasks.org/spec/vta/webvh/dids/update/1.0",
        "payloadDigest": "zQmSK9pGKFnmc77pqyNAPJyPKt8rMqctngfg3vwuMArwGYZ",
        "sideEffects": "destructive",
        "exposure": { "discloses": "none", "actsAsSubject": false },
        "effects": [
          { "kind": "documentChange", "summary": "Adds a FileStore service at #files.", "path": "/service", "after": {"id":"#files"} },
          { "kind": "keyRotation", "summary": "Rotates this DID's update key." }
        ],
        "requester": "did:key:zWorker",
        "approverSet": "webvh-approvers",
        "minApprovals": 1,
        "excludeRequester": true,
        "expiresAt": "2026-07-18T10:10:00Z",
        "subject": "did:webvh:scid:webvh.storm.ws:acme",
        "statePin": { "resource": "did:webvh:...", "version": "1-abc" }
      }
    }"##;

    /// The wire REQUEST re-issued (and, unless `signer` is `None`, signed) by a
    /// deterministic `did:key` executor, as a JSON string ready for the parse.
    async fn request_issued_by(issuer_seed: u8, signer: Option<u8>) -> String {
        let mut v: serde_json::Value = serde_json::from_str(REQUEST).unwrap();
        v["issuer"] = serde_json::Value::String(did_for(issuer_seed));
        if let Some(s) = signer {
            sign_as(&mut v, s).await;
        }
        v.to_string()
    }

    fn enrolled() -> Vec<String> {
        vec![did_for(EXECUTOR)]
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parses_a_signed_request_from_an_enrolled_executor() {
        // `excludeRequester` and `statePin` are beyond the strict schema — the
        // lenient parse must not choke on them, and because verification runs
        // over the raw document, the signature covers them too.
        let json = request_issued_by(EXECUTOR, Some(EXECUTOR)).await;
        let r = parse_task_consent_request(json, enrolled()).await.unwrap();
        assert_eq!(r.issuer, did_for(EXECUTOR), "issuer is the proven signer");
        assert_eq!(r.challenge, "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ");
        assert_eq!(r.match_code, "3b0c7f");
        assert_eq!(
            r.task_type,
            "https://trusttasks.org/spec/vta/webvh/dids/update/1.0"
        );
        assert_eq!(r.requester, "did:key:zWorker");
        assert_eq!(r.approver_set.as_deref(), Some("webvh-approvers"));
        assert_eq!(r.min_approvals, 1);
        assert_eq!(r.side_effects.as_deref(), Some("destructive"));
        assert_eq!(r.discloses.as_deref(), Some("none"));
        assert!(!r.acts_as_subject);
        assert_eq!(r.effects.len(), 2);
        assert_eq!(r.effects[0].kind, "documentChange");
        assert_eq!(r.effects[0].path.as_deref(), Some("/service"));
        assert!(r.effects[0].after.is_some());
        assert_eq!(r.effects[1].summary, "Rotates this DID's update key.");
        assert_eq!(
            r.subject.as_deref(),
            Some("did:webvh:scid:webvh.storm.ws:acme")
        );
        assert_eq!(r.expires_at.as_deref(), Some("2026-07-18T10:10:00Z"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_a_non_request_document() {
        let err =
            parse_task_consent_request(r#"{"type":"other","payload":{}}"#.to_string(), vec![])
                .await
                .unwrap_err();
        assert!(matches!(err, FfiError::Decode { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_a_signed_request_missing_the_binding_fields() {
        let mut v: serde_json::Value = serde_json::from_str(
            r#"{"id":"x","type":"https://trusttasks.org/spec/task-consent/request/0.1","payload":{"challenge":"VHJhbnNmZXJDb25maXJtTm9uY2VYWQ"}}"#,
        )
        .unwrap();
        v["issuer"] = serde_json::Value::String(did_for(EXECUTOR));
        sign_as(&mut v, EXECUTOR).await;
        let err = parse_task_consent_request(v.to_string(), enrolled())
            .await
            .unwrap_err();
        // The proof is fine; the display contract is not — a Decode, not an
        // untrusted issuer.
        assert!(matches!(err, FfiError::Decode { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_a_request_without_a_proof() {
        let json = request_issued_by(EXECUTOR, None).await;
        let err = parse_task_consent_request(json, enrolled())
            .await
            .unwrap_err();
        assert!(matches!(err, FfiError::UntrustedIssuer { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_a_valid_proof_from_a_non_enrolled_did() {
        // A perfectly good signature — but not from anyone this device is
        // enrolled with. MUST NOT prompt.
        let json = request_issued_by(STRANGER, Some(STRANGER)).await;
        let err = parse_task_consent_request(json, enrolled())
            .await
            .unwrap_err();
        assert!(matches!(err, FfiError::UntrustedIssuer { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_an_issuer_verification_method_mismatch() {
        // Signed by the stranger's key while claiming the enrolled executor as
        // issuer: the classic spoof the issuer≡verificationMethod binding stops.
        // Enroll both DIDs so the test isolates the binding check itself.
        let json = request_issued_by(EXECUTOR, Some(STRANGER)).await;
        let err = parse_task_consent_request(json, vec![did_for(EXECUTOR), did_for(STRANGER)])
            .await
            .unwrap_err();
        assert!(matches!(err, FfiError::UntrustedIssuer { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_a_request_tampered_after_signing() {
        let mut v: serde_json::Value =
            serde_json::from_str(&request_issued_by(EXECUTOR, Some(EXECUTOR)).await).unwrap();
        // The attack the proof exists to stop: effects rewritten in flight.
        v["payload"]["effects"] = serde_json::json!([]);
        let err = parse_task_consent_request(v.to_string(), enrolled())
            .await
            .unwrap_err();
        assert!(matches!(err, FfiError::UntrustedIssuer { .. }));
    }

    /// A fake signer that returns a fixed 64-byte signature, so the builders can
    /// be exercised without an enclave. Mirrors the step-up builder tests.
    struct FakeSigner {
        did: String,
    }
    impl Signer for FakeSigner {
        fn did(&self) -> String {
            self.did.clone()
        }
        fn sign(&self, _input: Vec<u8>) -> Result<Vec<u8>, FfiError> {
            Ok(vec![7u8; 64])
        }
    }

    /// The code must come from the digest *bytes*. Deriving it from the encoded
    /// string would spend three of six characters on the constant `zQm`.
    #[test]
    fn match_code_is_derived_from_the_digest_bytes_not_the_encoding() {
        // Decodes to 3b0c7f1d9e2a…, so the code is the same six characters this
        // surface showed when the wire carried bare hex. The migration is
        // invisible here — that is the property worth pinning.
        let code =
            match_code_from_digest("zQmSK9pGKFnmc77pqyNAPJyPKt8rMqctngfg3vwuMArwGYZ").unwrap();
        assert_eq!(code, "3b0c7f");
        assert_eq!(code.len(), MATCH_CODE_LEN);
        assert!(
            !code.starts_with("zQm"),
            "derived from the encoding, not the bytes: {code}"
        );
    }

    /// The regression the decode guards against: distinct payloads must yield
    /// distinct codes. Slicing the multibase string gave every digest the same
    /// three leading characters.
    #[test]
    fn match_codes_differ_across_payloads() {
        use sha2::{Digest, Sha256};
        let codes: std::collections::BTreeSet<String> = (0..16)
            .map(|i| {
                let d = Sha256::digest(format!("payload-{i}").as_bytes());
                let mut buf = MULTIHASH_SHA2_256_32.to_vec();
                buf.extend_from_slice(&d);
                let mb = multibase::encode(multibase::Base::Base58Btc, &buf);
                // Every encoded form shares the constant prefix …
                assert!(mb.starts_with("zQm"), "{mb}");
                // … but the derived codes must not.
                match_code_from_digest(&mb).unwrap()
            })
            .collect();
        assert_eq!(codes.len(), 16, "codes collided: {codes:?}");
    }

    #[test]
    fn a_non_multibase_digest_is_refused() {
        // Bare hex — what the wire carried before the migration.
        let err = match_code_from_digest(
            "3b0c7f1d9e2a5648c1f30b7ae4d2986153ca0f7b8d41e6295af03c8bd71e4a62",
        );
        assert!(err.is_err(), "stale hex must not silently produce a code");
    }

    fn draft() -> TaskConsentDecisionDraft {
        TaskConsentDecisionDraft {
            id: "urn:uuid:22222222-2222-2222-2222-222222222222".to_string(),
            issuer_did: "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv".to_string(),
            recipient_did: "did:webvh:scid:vta.example:vta".to_string(),
            issued_at: "2026-07-18T10:05:00Z".to_string(),
            challenge: "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ".to_string(),
            // `digestMultibase`: base58btc over the sha2-256 multihash
            // (`0x12 0x20` || digest). The bare hex this used to be is
            // non-conforming under the shared `DigestMultibase` type, and the
            // draft-parsing guard rejects it — which is how this fixture was
            // caught.
            payload_digest: "zQmSK9pGKFnmc77pqyNAPJyPKt8rMqctngfg3vwuMArwGYZ".to_string(),
        }
    }

    #[test]
    fn builds_a_signed_approval_that_echoes_the_binding_and_carries_a_proof() {
        let signer = Box::new(FakeSigner {
            did: draft().issuer_did.clone(),
        });
        let json = build_task_consent_decision_did_signed(draft(), signer).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["type"],
            "https://trusttasks.org/spec/task-consent/decision/0.1"
        );
        assert_eq!(v["payload"]["decision"], "approve");
        assert_eq!(v["payload"]["challenge"], "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ");
        // Echoed verbatim: the decision is bound to the digest the executor
        // will re-derive, so any re-encoding here would break the match.
        assert_eq!(
            v["payload"]["payloadDigest"],
            "zQmSK9pGKFnmc77pqyNAPJyPKt8rMqctngfg3vwuMArwGYZ"
        );
        assert_eq!(v["issuer"], draft().issuer_did);
        assert_eq!(v["recipient"], "did:webvh:scid:vta.example:vta");
        // The proof is the authority.
        assert_eq!(v["proof"]["type"], "DataIntegrityProof");
        assert_eq!(v["proof"]["cryptosuite"], "eddsa-jcs-2022");
        assert!(v["proof"]["proofValue"].as_str().unwrap().starts_with('z'));
    }

    #[test]
    fn builds_a_signed_denial_with_a_reason() {
        let signer = Box::new(FakeSigner {
            did: draft().issuer_did.clone(),
        });
        let json =
            build_task_consent_decision_denied(draft(), "codes did not match".to_string(), signer)
                .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["payload"]["decision"], "deny");
        assert_eq!(v["payload"]["reason"], "codes did not match");
        assert!(v["proof"]["proofValue"].is_string());
    }
}
