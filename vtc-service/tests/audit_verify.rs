//! Integration coverage for `GET /v1/audit/verify` — the audit
//! hash-chain verification surface (#537 tier 3).
//!
//! The chain itself is unit-tested in `vti_common::audit::envelope`;
//! what matters here is that the endpoint walks the *store* in the
//! right order, reports honest counters, and actually catches a
//! tampered row rather than rubber-stamping whatever it reads.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

const VERIFY_TASK: &str = "https://trusttasks.org/spec/audit/verify/0.1";
const PROFILE_TASK: &str = "https://trusttasks.org/spec/vtc/community/profile/update/0.1";

struct Fixture {
    router: axum::Router,
    state: AppState,
    vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder().with_audit(true).build().await;
    Fixture {
        router: vtc.router.clone(),
        state: vtc.state.clone(),
        vtc,
    }
}

/// Super-admin = Admin role with empty `allowed_contexts`.
async fn super_admin_token(fix: &Fixture) -> String {
    fix.vtc.token("did:key:z6MkAdmin", "admin", vec![]).await
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

async fn verify(fix: &Fixture, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri("/v1/audit/verify")
        .header("Trust-Task", VERIFY_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    body_value(fix.router.clone().oneshot(req).await.unwrap()).await
}

/// Write some real audit envelopes by exercising a route that emits
/// them, so the chain under test is one the daemon actually produced.
async fn seed_audit_rows(fix: &Fixture, token: &str, count: usize) {
    let profile = vtc_service::community::CommunityProfile::new(
        "did:webvh:vtc.example.com:abc",
        "Example Community",
    );
    vtc_service::community::store_profile(&fix.state.community_ks, &profile)
        .await
        .unwrap();

    for i in 0..count {
        let req = Request::builder()
            .method("PUT")
            .uri("/v1/community/profile")
            .header("Trust-Task", PROFILE_TASK)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{"name":"Rename {i}"}}"#)))
            .unwrap();
        let resp = fix.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "seed write {i} succeeded");
    }
}

#[tokio::test]
async fn empty_log_verifies_vacuously() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    let (status, body) = verify(&fix, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["verified"], true);
    assert_eq!(body["entriesExamined"], 0);
    assert_eq!(body["entriesVerified"], 0);
    // Nothing chainable seen, so there is no head to report.
    assert!(body.get("head").is_none() || body["head"].is_null());
}

#[tokio::test]
async fn a_real_chain_verifies_and_reports_its_head() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed_audit_rows(&fix, &token, 3).await;

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["verified"], true, "body: {body}");

    let verified = body["entriesVerified"].as_u64().unwrap();
    assert!(
        verified >= 3,
        "at least the three seeded writes: {verified}"
    );
    assert_eq!(
        body["entriesExamined"], body["entriesVerified"],
        "a v2-only store must have nothing skipped"
    );
    assert_eq!(body["legacySkipped"], 0);
    assert_eq!(body["unparseableSkipped"], 0);
    assert!(
        body["head"].as_str().is_some_and(|h| h.len() == 64),
        "head is a hex-encoded SHA-256"
    );
}

#[tokio::test]
async fn a_tampered_envelope_is_caught() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed_audit_rows(&fix, &token, 3).await;

    // Rewrite one stored envelope's payload in place, leaving its
    // `entry_hash` as written — exactly what an adversary editing the
    // store would produce.
    let mut rows = fix
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap();
    rows.sort_by(|(a, _), (b, _)| a.cmp(b));
    let (key, value) = rows.into_iter().next().expect("at least one envelope");
    let mut env: Value = serde_json::from_slice(&value).unwrap();
    env["actorDidPlain"] = json!("did:key:z6MkNotWhoActedAtAll");
    // `actor_did_plain` is excluded from chain_digest (RTBF), so to
    // actually break the digest we must alter a covered field.
    env["timestamp"] = json!("2020-01-01T00:00:00Z");
    fix.state
        .audit_ks
        .insert_raw(key, serde_json::to_vec(&env).unwrap())
        .await
        .unwrap();

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK, "tamper is a finding, not an error");
    assert_eq!(body["verified"], false, "body: {body}");
    let brk = &body["chainBreak"];
    assert!(!brk.is_null(), "a break must be reported: {body}");
    assert!(
        brk["kind"] == "tamperedEntry" || brk["kind"] == "brokenLink",
        "unexpected break kind: {brk}"
    );
}

#[tokio::test]
async fn a_dropped_envelope_breaks_the_link() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed_audit_rows(&fix, &token, 4).await;

    // Delete a middle row — the classic "cover my tracks" edit.
    let mut rows = fix
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap();
    rows.sort_by(|(a, _), (b, _)| a.cmp(b));
    assert!(rows.len() >= 3, "need a middle row to drop");
    let (key, _) = rows.remove(rows.len() / 2);
    fix.state.audit_ks.remove(key).await.unwrap();

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["verified"], false, "body: {body}");
    assert_eq!(body["chainBreak"]["kind"], "brokenLink");
}

#[tokio::test]
async fn non_super_admin_is_refused() {
    let fix = build().await;
    // Context-scoped admin: Admin role, but not community-wide.
    let scoped = fix
        .vtc
        .token("did:key:z6MkScoped", "admin", vec!["some-ctx".into()])
        .await;
    let (status, _) = verify(&fix, &scoped).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the audit chain is the community-wide god view"
    );
}

// ---------------------------------------------------------------------------
// Signed checkpoints (#708)
// ---------------------------------------------------------------------------
//
// The chain tests above cover what an unkeyed SHA-256 can prove. These cover
// what it *cannot*: an adversary who holds the store can restamp a forged
// suffix or truncate to a valid prefix and the chain still verifies. Only a
// signature made with a key that is not in the store contradicts that.

use vti_common::audit::{AuditCheckpoint, CheckpointClaim};

/// A fixture whose `credential_signer` is present, so checkpoints can be
/// signed and verified. (`build()` above has no signer — checkpoint status
/// there is `chainBroken`, which is itself asserted below.)
async fn build_signed() -> Fixture {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_signers(true)
        .build()
        .await;
    Fixture {
        router: vtc.router.clone(),
        state: vtc.state.clone(),
        vtc,
    }
}

/// Sign a checkpoint over the audit log's current state and persist it —
/// what the periodic emitter does on a tick.
async fn checkpoint_now(fix: &Fixture) -> AuditCheckpoint {
    let signer = fix
        .state
        .credential_signer
        .as_ref()
        .expect("fixture built with signers");
    let key = signer
        .ed25519_signing_key()
        .expect("community key is Ed25519");
    vtc_service::audit_checkpoint::emit_checkpoint(
        &fix.state.audit_ks,
        &fix.state.audit_checkpoint_ks,
        &key,
        signer.assertion_method_id(),
        chrono::Utc::now(),
    )
    .await
    .expect("emit")
    .expect("there were new entries to attest")
}

#[tokio::test]
async fn a_log_with_no_checkpoints_says_so_rather_than_looking_clean() {
    let fix = build_signed().await;
    let token = super_admin_token(&fix).await;
    seed_audit_rows(&fix, &token, 3).await;

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    // The chain is fine...
    assert_eq!(body["verified"], true, "body: {body}");
    // ...but nothing has attested to it, and that must be visible.
    assert_eq!(
        body["checkpoints"]["status"], "noCheckpoints",
        "body: {body}"
    );
}

#[tokio::test]
async fn a_checkpointed_log_verifies_as_consistent() {
    let fix = build_signed().await;
    let token = super_admin_token(&fix).await;
    seed_audit_rows(&fix, &token, 4).await;
    let cp = checkpoint_now(&fix).await;
    assert!(
        cp.entry_count >= 4,
        "checkpoint should cover the seeded rows"
    );

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["verified"], true, "body: {body}");
    assert_eq!(body["checkpoints"]["status"], "consistent", "body: {body}");
    assert_eq!(body["checkpoints"]["verifiedCheckpoints"], 1);
    assert_eq!(body["checkpoints"]["unattestedEntries"], 0);
}

/// **The whole point of #708.**
///
/// Delete a *suffix* of the log. The remaining prefix is a perfectly valid
/// chain — `verified` stays `true`, exactly as it did before checkpoints
/// existed — but it is now shorter than a signature made with the community
/// key attests to, and that contradiction cannot be manufactured from the
/// store alone.
#[tokio::test]
async fn truncating_the_log_is_caught_even_though_the_chain_still_verifies() {
    let fix = build_signed().await;
    let token = super_admin_token(&fix).await;
    seed_audit_rows(&fix, &token, 6).await;
    let cp = checkpoint_now(&fix).await;
    let attested = cp.entry_count;

    // Delete the newest two rows — the cheapest way to erase an incident,
    // and one that needs no forgery at all.
    let mut rows = fix
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap();
    rows.sort_by(|(a, _), (b, _)| a.cmp(b));
    assert!(rows.len() >= 3);
    for (key, _) in rows.iter().rev().take(2) {
        fix.state.audit_ks.remove(key.clone()).await.unwrap();
    }

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["verified"], true,
        "a truncated prefix is still a valid chain — that is the whole problem: {body}"
    );
    assert_eq!(body["checkpoints"]["status"], "truncated", "body: {body}");
    assert_eq!(body["checkpoints"]["attestedEntries"], attested);
    assert!(
        body["checkpoints"]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("TRUNCATION"),
        "the detail must name the finding: {body}"
    );
}

/// Deleting the checkpoints that contradict a truncated log must not restore
/// a clean bill of health — otherwise the mechanism protects nothing.
#[tokio::test]
async fn deleting_a_checkpoint_is_itself_detected() {
    let fix = build_signed().await;
    let token = super_admin_token(&fix).await;

    seed_audit_rows(&fix, &token, 2).await;
    checkpoint_now(&fix).await;
    seed_audit_rows(&fix, &token, 2).await;
    checkpoint_now(&fix).await;

    // Remove the *first* checkpoint, leaving the second orphaned.
    let mut rows = fix
        .state
        .audit_checkpoint_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap();
    rows.sort_by(|(a, _), (b, _)| a.cmp(b));
    assert_eq!(rows.len(), 2, "expected two checkpoints");
    fix.state
        .audit_checkpoint_ks
        .remove(rows[0].0.clone())
        .await
        .unwrap();

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["checkpoints"]["status"], "chainBroken", "body: {body}");
    assert!(
        body["checkpoints"]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("deleted"),
        "detail should explain the broken checkpoint link: {body}"
    );
}

/// A checkpoint minted by someone who holds the store but not the community
/// key must not verify — that is the entire security argument for signing
/// with the community key rather than the audit HMAC key.
#[tokio::test]
async fn a_checkpoint_forged_with_a_foreign_key_is_rejected() {
    let fix = build_signed().await;
    let token = super_admin_token(&fix).await;
    seed_audit_rows(&fix, &token, 3).await;

    let attacker = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let signer = fix.state.credential_signer.as_ref().unwrap();
    let forged = AuditCheckpoint::sign(
        CheckpointClaim {
            checkpoint_id: uuid::Uuid::new_v4(),
            head: [0u8; 32],
            entry_count: 0,
            head_event_id: uuid::Uuid::nil(),
            checkpoint_at: chrono::Utc::now(),
            prev_checkpoint: None,
            // Names the community's real key — but is not signed by it.
            verification_method: signer.assertion_method_id().to_string(),
        },
        &attacker,
    );
    fix.state
        .audit_checkpoint_ks
        .insert(forged.storage_key(), &forged)
        .await
        .unwrap();

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["checkpoints"]["status"], "chainBroken", "body: {body}");
    assert!(
        body["checkpoints"]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("invalid signature"),
        "detail should name the bad signature: {body}"
    );
}

/// Entries written since the last checkpoint are the live truncation window.
/// They are real exposure, so the endpoint reports them rather than letting
/// "consistent" imply everything is signed.
#[tokio::test]
async fn entries_written_after_a_checkpoint_are_reported_as_unattested() {
    let fix = build_signed().await;
    let token = super_admin_token(&fix).await;
    seed_audit_rows(&fix, &token, 2).await;
    let cp = checkpoint_now(&fix).await;
    seed_audit_rows(&fix, &token, 3).await;

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["checkpoints"]["status"], "consistent", "body: {body}");
    assert_eq!(body["checkpoints"]["attestedEntries"], cp.entry_count);
    assert!(
        body["checkpoints"]["unattestedEntries"].as_u64().unwrap() >= 3,
        "the post-checkpoint tail must be surfaced: {body}"
    );
}

/// Without a community signing key there is nothing to verify against, and
/// the endpoint must say so rather than report a green checkpoint status.
#[tokio::test]
async fn a_vtc_with_no_signing_key_cannot_claim_checkpoint_health() {
    let fix = build().await; // no signers
    let token = super_admin_token(&fix).await;
    seed_audit_rows(&fix, &token, 2).await;

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["checkpoints"]["status"], "chainBroken", "body: {body}");
    assert!(
        body["checkpoints"]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("no community signing key"),
        "body: {body}"
    );
}

/// A checkpoint naming a `verificationMethod` the current signer does **not**
/// own must not be waved through against the live key.
///
/// This is the bug the per-checkpoint `verificationMethod` existed to prevent
/// and which the verifier previously had: it passed `|_vm| Some(current_key)`,
/// so the field was decorative and *any* checkpoint was checked against
/// whatever key happened to be live. A checkpoint claiming to be signed under
/// some other key — a retired one, or one this community never held — was
/// indistinguishable from one signed under the current key.
///
/// With no resolver configured the unknown method cannot be resolved, so the
/// verifier reports that as its own condition rather than as a forgery. The
/// distinction matters operationally: "the signing key is no longer published"
/// is expected after a rotation, "this checkpoint was forged" is an incident.
#[tokio::test]
async fn a_checkpoint_naming_an_unknown_key_is_not_verified_against_the_live_one() {
    let fix = build_signed().await;
    let token = super_admin_token(&fix).await;
    seed_audit_rows(&fix, &token, 2).await;

    let signer = fix.state.credential_signer.as_ref().unwrap();
    let key = signer.ed25519_signing_key().unwrap();

    // Signed by the community's REAL key, so the signature is genuine — but it
    // names a different verificationMethod. Under the old code this verified,
    // because the named method was ignored entirely.
    let cp = AuditCheckpoint::sign(
        CheckpointClaim {
            checkpoint_id: uuid::Uuid::new_v4(),
            head: [0u8; 32],
            entry_count: 0,
            head_event_id: uuid::Uuid::nil(),
            checkpoint_at: chrono::Utc::now(),
            prev_checkpoint: None,
            verification_method: "did:webvh:scid:vtc.example#key-retired".to_string(),
        },
        &key,
    );
    fix.state
        .audit_checkpoint_ks
        .insert(cp.storage_key(), &cp)
        .await
        .unwrap();

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["checkpoints"]["status"], "chainBroken",
        "a checkpoint naming a key the signer does not own must not verify \
         against the live key: {body}"
    );
    let detail = body["checkpoints"]["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("key-retired") && detail.contains("could not be resolved"),
        "the finding must name the unresolvable key and say so, rather than \
         reporting a forgery: {detail}"
    );
}
