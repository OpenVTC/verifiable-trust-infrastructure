//! The administrator's operational verbs as signed Trust Tasks
//! (`trust_tasks::admin_tasks`): the trust-registry reconciler, the audit log,
//! the runtime configuration, admin invites and the auth service's sessions.
//!
//! Each verb is driven through `POST /v1/trust-tasks` exactly as the console
//! sends it, and held to four things:
//!
//! - a document signed by an administrator is answered;
//! - an unsigned document, and one signed by a DID the community holds no
//!   entry for, are refused;
//! - a signer whose role the bearer route's extractor refused is refused —
//!   a member for every admin verb, and a context-scoped admin where the
//!   route asked for an unrestricted one;
//! - the bearer route is gone.


use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use crate::common::signed::{
    admin, bearer_route_served, call, error_code, party_with_role, payload, post, unsigned,
};
use vtc_service::acl::VtcRole;
use vtc_service::registry::{
    MockRegistryClient, SyncJob, SyncJobKind, SyncJobState, store_sync_job,
};
use vtc_service::test_support::TestVtc;

const DIAGNOSTICS: &str = "https://trusttasks.org/spec/vtc/registry/diagnostics/0.1";
const SYNC_LIST: &str = "https://trusttasks.org/spec/vtc/registry/sync-jobs/list/0.1";
const SYNC_RETRY: &str = "https://trusttasks.org/spec/vtc/registry/sync-jobs/retry/0.1";
const SYNC_DISCARD: &str = "https://trusttasks.org/spec/vtc/registry/sync-jobs/discard/0.1";
const RECORDS: &str = "https://trusttasks.org/spec/vtc/registry/records/list/0.1";
const AUDIT_LIST: &str = "https://trusttasks.org/spec/audit/list/0.1";
const AUDIT_VERIFY: &str = "https://trusttasks.org/spec/audit/verify/0.1";
const CONFIG_SHOW: &str = "https://trusttasks.org/spec/config/show/0.1";
const CONFIG_PATCH: &str = "https://trusttasks.org/spec/config/patch/0.1";
const CONFIG_RELOAD: &str = "https://trusttasks.org/spec/config/reload/0.1";
const CONFIG_RESTART: &str = "https://trusttasks.org/spec/config/restart/0.1";
const INVITES_LIST: &str = "https://trusttasks.org/spec/vtc/admin/invites/list/0.1";
const INVITES_CREATE: &str = "https://trusttasks.org/spec/vtc/admin/invites/create/0.1";
const INVITES_REVOKE: &str = "https://trusttasks.org/spec/vtc/admin/invites/revoke/0.1";
const SESSIONS_LIST: &str = "https://trusttasks.org/spec/auth/sessions/list/0.1";
const REVOKE_SESSION: &str = "https://trusttasks.org/spec/auth/revoke-session/0.2";

/// An invitee who is already an admin, so an invite for them writes no entry
/// and costs no gesture.
const INVITEE: &str = "did:key:z6MkAlreadyAnAdmin";

/// A VTC every verb here can succeed on: audit (patch, reload and restart
/// refuse without it), signers and a public URL (invites), a supervisor
/// (restart), and a registry (records).
async fn vtc() -> TestVtc {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_signers(true)
        .with_public_url("https://vtc.example.com")
        .supervisor(Some(vtc_service::supervisor::SupervisorKind::Manual))
        .with_registry_client(std::sync::Arc::new(MockRegistryClient::new()))
        .build()
        .await;
    crate::common::signed::seed_role(&vtc, INVITEE, VtcRole::Admin, &[]).await;
    vtc
}

fn failed_job() -> SyncJob {
    let mut job = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:z6MkStranded");
    job.state = SyncJobState::Failed;
    job.attempts = 3;
    job.last_attempted_at = Some(chrono::Utc::now());
    job
}

/// Every moved verb, with a payload it succeeds on against [`vtc`] (after
/// [`prepare`]), and whether it takes an unrestricted admin: the bearer
/// route's `SuperAdminAuth`, and the community-wide configuration writes and
/// admin-invite management, which the bearer routes left to any admin.
fn verbs(job_id: &str, jti: &str) -> Vec<(&'static str, Value, bool)> {
    vec![
        (DIAGNOSTICS, json!({}), false),
        (SYNC_LIST, json!({ "state": "failed" }), false),
        (SYNC_RETRY, json!({ "allFailed": true }), false),
        (SYNC_DISCARD, json!({ "jobId": job_id }), false),
        (RECORDS, json!({ "source": "local" }), false),
        (AUDIT_LIST, json!({ "pageSize": 5 }), true),
        (AUDIT_VERIFY, json!({}), true),
        (CONFIG_SHOW, json!({}), false),
        (
            CONFIG_PATCH,
            json!({ "overrides": { "log.level": "debug" } }),
            true,
        ),
        (CONFIG_RELOAD, json!({}), true),
        (CONFIG_RESTART, json!({}), true),
        (INVITES_LIST, json!({}), true),
        (INVITES_CREATE, json!({ "did": INVITEE }), true),
        (INVITES_REVOKE, json!({ "jti": jti }), true),
    ]
}

/// Seed what the success cases act on: a failed sync job to discard, and an
/// invite to revoke. Returns their ids.
async fn prepare(vtc: &TestVtc, by: &Party, invite: bool) -> (String, String) {
    let job = failed_job();
    store_sync_job(&vtc.state.sync_queue_ks, &job)
        .await
        .unwrap();
    if !invite {
        return (job.id.to_string(), String::new());
    }
    let (_, created) = call(vtc, by, INVITES_CREATE, json!({ "did": INVITEE })).await;
    let jti = payload(&created)["jti"]
        .as_str()
        .unwrap_or_else(|| panic!("an invite to revoke: {created}"))
        .to_string();
    (job.id.to_string(), jti)
}

/// A VTC of its own per verb: `retry` requeues the job `discard` needs failed.
#[tokio::test]
async fn every_moved_verb_answers_a_signed_administrator() {
    for i in 0..verbs("", "").len() {
        let vtc = vtc().await;
        let admin = admin(&vtc).await;
        // Only the revocation needs an invite to exist, and minting one hashes
        // its claim code with Argon2id.
        let needs_invite = verbs("", "")[i].0 == INVITES_REVOKE;
        let (job_id, jti) = prepare(&vtc, &admin, needs_invite).await;
        let (uri, body, _) = verbs(&job_id, &jti).swap_remove(i);
        let (status, doc) = call(&vtc, &admin, uri, body).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {doc}");
        assert_eq!(error_code(&doc), None, "{uri}: {doc}");
        assert_eq!(
            doc["type"].as_str(),
            Some(format!("{uri}#response").as_str()),
            "{uri}: {doc}"
        );
        assert!(
            doc.get("proof").is_some(),
            "{uri}: the answer is signed: {doc}"
        );
    }
}

#[tokio::test]
async fn every_moved_verb_refuses_an_unsigned_document() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    for (uri, body, _) in verbs("00000000-0000-0000-0000-000000000000", "x") {
        let (_, doc) = post(&vtc, &unsigned(&admin, uri, body)).await;
        assert_eq!(error_code(&doc), Some("proofRequired"), "{uri}: {doc}");
    }
}

#[tokio::test]
async fn every_moved_verb_refuses_a_signer_the_community_does_not_know() {
    let vtc = vtc().await;
    let stranger = Party::new();
    for (uri, body, _) in verbs("00000000-0000-0000-0000-000000000000", "x") {
        let (_, doc) = call(&vtc, &stranger, uri, body).await;
        assert_eq!(error_code(&doc), Some("permissionDenied"), "{uri}: {doc}");
    }
}

#[tokio::test]
async fn every_moved_verb_refuses_a_member() {
    let vtc = vtc().await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    for (uri, body, _) in verbs("00000000-0000-0000-0000-000000000000", "x") {
        let (_, doc) = call(&vtc, &member, uri, body).await;
        assert_eq!(error_code(&doc), Some("permissionDenied"), "{uri}: {doc}");
    }
}

/// A context-scoped admin is refused the audit log, the configuration writes
/// and admin invites, and admitted to the rest.
#[tokio::test]
async fn the_unrestricted_verbs_refuse_a_context_admin() {
    let vtc = vtc().await;
    let scoped = party_with_role(&vtc, VtcRole::Admin, &["ctx-a"]).await;
    for (uri, body, unrestricted) in verbs("00000000-0000-0000-0000-000000000000", "x") {
        if !unrestricted {
            continue;
        }
        let (_, doc) = call(&vtc, &scoped, uri, body).await;
        assert_eq!(error_code(&doc), Some("permissionDenied"), "{uri}: {doc}");
    }
}

#[tokio::test]
async fn the_bearer_routes_are_gone() {
    let vtc = vtc().await;
    for (method, path) in [
        ("GET", "/v1/health/diagnostics"),
        ("GET", "/v1/registry/sync-jobs"),
        ("POST", "/v1/registry/sync-jobs/retry"),
        ("POST", "/v1/registry/sync-jobs/discard"),
        ("GET", "/v1/registry/records"),
        ("GET", "/v1/audit"),
        ("GET", "/v1/audit/verify"),
        ("GET", "/v1/admin/config"),
        ("PATCH", "/v1/admin/config"),
        ("POST", "/v1/admin/config/reload"),
        ("POST", "/v1/admin/config/restart"),
        ("GET", "/v1/admin/invites"),
        ("POST", "/v1/admin/invites"),
        (
            "DELETE",
            "/v1/admin/invites/00000000-0000-0000-0000-000000000000",
        ),
        ("GET", "/v1/auth/sessions"),
        ("DELETE", "/v1/auth/sessions"),
        ("DELETE", "/v1/auth/sessions/sess-1"),
        ("GET", "/v1/git-ns/drift"),
    ] {
        assert!(
            !bearer_route_served(&vtc, method, path).await,
            "{method} {path} is still served"
        );
    }
}

/// An invite for a DID with no entry writes an unrestricted admin one, so on
/// this door it asks for the inviter's passkey gesture bound to the document.
#[tokio::test]
async fn an_invite_that_grants_admin_asks_for_a_bound_gesture() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    let (_, doc) = call(
        &vtc,
        &admin,
        INVITES_CREATE,
        json!({ "did": "did:key:z6MkNotYetAnything" }),
    )
    .await;
    // The inviter enrolled no passkey here, so the refusal says so rather
    // than carrying a ceremony it could not complete.
    assert_eq!(error_code(&doc), Some("permissionDenied"), "{doc}");
    assert!(
        doc["payload"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("step-up required")),
        "{doc}"
    );
    assert!(
        vtc_service::acl::get_acl_entry(&vtc.state.acl_ks, "did:key:z6MkNotYetAnything")
            .await
            .unwrap()
            .is_none(),
        "no entry is written before the gesture"
    );
}

/// `config/show`'s `keys` narrows the answer.
#[tokio::test]
async fn config_show_answers_only_the_named_keys() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    let (_, doc) = call(&vtc, &admin, CONFIG_SHOW, json!({ "keys": ["log.level"] })).await;
    let fields = payload(&doc)["fields"].as_array().expect("fields");
    assert_eq!(fields.len(), 1, "{doc}");
    assert_eq!(fields[0]["key"], "log.level");
}

// ─── sessions ────────────────────────────────────────────────────────────

mod sessions {
    use super::*;
    use vti_common::auth::session::{Session, SessionState, get_session, now_epoch, store_session};

    /// A live REST session for `did`, returning its id.
    async fn seed_session(vtc: &TestVtc, did: &str) -> String {
        let session_id = format!("sess-{}", uuid::Uuid::new_v4());
        store_session(
            &vtc.state.sessions_ks,
            &Session {
                session_id: session_id.clone(),
                did: did.into(),
                challenge: String::new(),
                state: SessionState::Authenticated,
                created_at: now_epoch(),
                last_seen: now_epoch(),
                refresh_token: Some(format!("rt-{session_id}")),
                refresh_expires_at: Some(now_epoch() + 3600),
                tee_attested: false,
                amr: vec!["did".into()],
                acr: "aal1".into(),
                acr_expires_at: None,
                token_id: None,
                session_pubkey_b58btc: None,
            },
        )
        .await
        .expect("store session");
        session_id
    }

    async fn alive(vtc: &TestVtc, id: &str) -> bool {
        get_session(&vtc.state.sessions_ks, id)
            .await
            .unwrap()
            .is_some()
    }

    struct Fixture {
        vtc: TestVtc,
        root: Party,
        scoped: Party,
        in_a: Party,
        in_ab: Party,
        member: Party,
    }

    async fn fixture() -> Fixture {
        let vtc = TestVtc::builder().with_audit(true).build().await;
        let root = party_with_role(&vtc, VtcRole::Admin, &[]).await;
        let scoped = party_with_role(&vtc, VtcRole::Admin, &["ctx-a"]).await;
        let in_a = party_with_role(&vtc, VtcRole::Admin, &["ctx-a"]).await;
        let in_ab = party_with_role(&vtc, VtcRole::Admin, &["ctx-a", "ctx-b"]).await;
        let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
        Fixture {
            vtc,
            root,
            scoped,
            in_a,
            in_ab,
            member,
        }
    }

    fn ids(doc: &Value) -> Vec<String> {
        payload(doc)["sessions"]
            .as_array()
            .unwrap_or_else(|| panic!("a session list: {doc}"))
            .iter()
            .map(|s| s["id"].as_str().unwrap().to_string())
            .collect()
    }

    /// The published response shape: `{ sessions: [Session] }`, not a bare array.
    #[tokio::test]
    async fn the_listing_has_the_published_shape() {
        let f = fixture().await;
        let id = seed_session(&f.vtc, &f.in_a.did).await;
        let (_, doc) = call(&f.vtc, &f.root, SESSIONS_LIST, json!({})).await;
        let session = payload(&doc)["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == id.as_str())
            .unwrap_or_else(|| panic!("{doc}"))
            .clone();
        assert_eq!(session["subject"], f.in_a.did.as_str());
        assert!(session["issuedAt"].is_string() && session["expiresAt"].is_string());
        assert_eq!(session["acr"], "aal1");
        assert_eq!(session["amr"], json!(["did"]));
    }

    /// A context admin sees the sessions of subjects whose access it could
    /// withdraw, and no others: not an unrestricted admin's, not a wider
    /// admin's.
    #[tokio::test]
    async fn a_context_admin_sees_only_the_sessions_it_could_end() {
        let f = fixture().await;
        let covered = seed_session(&f.vtc, &f.in_a.did).await;
        let root = seed_session(&f.vtc, &f.root.did).await;
        let wide = seed_session(&f.vtc, &f.in_ab.did).await;
        let own = seed_session(&f.vtc, &f.scoped.did).await;

        let (_, doc) = call(&f.vtc, &f.scoped, SESSIONS_LIST, json!({})).await;
        let seen = ids(&doc);
        assert!(seen.contains(&covered) && seen.contains(&own), "{doc}");
        assert!(!seen.contains(&root) && !seen.contains(&wide), "{doc}");

        let (_, doc) = call(&f.vtc, &f.root, SESSIONS_LIST, json!({})).await;
        let seen = ids(&doc);
        for id in [&covered, &root, &wide, &own] {
            assert!(seen.contains(id), "an unrestricted admin sees {id}: {doc}");
        }
    }

    /// A member lists and ends only its own sessions.
    #[tokio::test]
    async fn a_member_manages_only_its_own_sessions() {
        let f = fixture().await;
        let mine = seed_session(&f.vtc, &f.member.did).await;
        let other = seed_session(&f.vtc, &f.in_a.did).await;

        let (_, doc) = call(&f.vtc, &f.member, SESSIONS_LIST, json!({})).await;
        assert_eq!(ids(&doc), vec![mine.clone()], "{doc}");

        let (_, doc) = call(
            &f.vtc,
            &f.member,
            REVOKE_SESSION,
            json!({ "sessionId": other }),
        )
        .await;
        assert_eq!(payload(&doc)["revokedCount"], 0, "{doc}");
        assert!(alive(&f.vtc, &other).await);

        let (_, doc) = call(&f.vtc, &f.member, REVOKE_SESSION, json!({ "all": true })).await;
        assert_eq!(payload(&doc)["revokedCount"], 1, "{doc}");
        assert!(!alive(&f.vtc, &mine).await);
    }

    /// A named session outside the caller's authority, an absent one and a
    /// gone one are answered identically: `revokedCount: 0`.
    #[tokio::test]
    async fn a_named_session_outside_the_callers_authority_is_answered_as_absent() {
        let f = fixture().await;
        let root = seed_session(&f.vtc, &f.root.did).await;
        let wide = seed_session(&f.vtc, &f.in_ab.did).await;
        for id in [root.as_str(), wide.as_str(), "sess-no-such"] {
            let (_, doc) = call(
                &f.vtc,
                &f.scoped,
                REVOKE_SESSION,
                json!({ "sessionId": id }),
            )
            .await;
            assert_eq!(payload(&doc), &json!({ "revokedCount": 0 }), "{id}: {doc}");
        }
        assert!(alive(&f.vtc, &root).await && alive(&f.vtc, &wide).await);

        let covered = seed_session(&f.vtc, &f.in_a.did).await;
        let (_, doc) = call(
            &f.vtc,
            &f.scoped,
            REVOKE_SESSION,
            json!({ "sessionId": covered }),
        )
        .await;
        assert_eq!(payload(&doc)["revokedCount"], 1, "{doc}");
        assert!(!alive(&f.vtc, &covered).await);
    }

    /// The `subject` form outside the caller's authority is `permissionDenied`
    /// — the same whether or not the subject has sessions — and the refusal is
    /// in the audit trail with the producer and the subject (revoke-session
    /// 0.2, consumer item 7).
    #[tokio::test]
    async fn a_refused_revocation_by_subject_is_audited() {
        let f = fixture().await;
        let root = seed_session(&f.vtc, &f.root.did).await;
        for subject in [f.root.did.as_str(), "did:key:z6MkNobody"] {
            let (_, doc) = call(
                &f.vtc,
                &f.scoped,
                REVOKE_SESSION,
                json!({ "subject": subject, "reason": "test" }),
            )
            .await;
            assert_eq!(
                error_code(&doc),
                Some("permissionDenied"),
                "{subject}: {doc}"
            );
        }
        assert!(alive(&f.vtc, &root).await);

        let (_, doc) = call(
            &f.vtc,
            &f.root,
            AUDIT_LIST,
            json!({ "action": "SessionRevocationRefused" }),
        )
        .await;
        let entries = payload(&doc)["entries"]
            .as_array()
            .unwrap_or_else(|| panic!("{doc}"));
        assert_eq!(entries.len(), 2, "{doc}");
        for e in entries {
            assert_eq!(e["actor"], f.scoped.did.as_str(), "{doc}");
            assert_eq!(e["detail"]["reason"], "test", "{doc}");
        }
        let targets: Vec<&str> = entries
            .iter()
            .filter_map(|e| e["target"].as_str())
            .collect();
        assert!(targets.contains(&f.root.did.as_str()) && targets.contains(&"did:key:z6MkNobody"));
    }

    /// Within the caller's authority, the `subject` form ends every session.
    #[tokio::test]
    async fn a_revocation_by_subject_ends_every_session() {
        let f = fixture().await;
        let a = seed_session(&f.vtc, &f.in_a.did).await;
        let b = seed_session(&f.vtc, &f.in_a.did).await;
        let (_, doc) = call(
            &f.vtc,
            &f.scoped,
            REVOKE_SESSION,
            json!({ "subject": f.in_a.did }),
        )
        .await;
        assert_eq!(payload(&doc)["revokedCount"], 2, "{doc}");
        assert!(!alive(&f.vtc, &a).await && !alive(&f.vtc, &b).await);
    }

    /// `all: false` targets nothing, and more than one target is ambiguous:
    /// both are `malformedRequest`.
    #[tokio::test]
    async fn a_revocation_naming_no_single_target_is_malformed() {
        let f = fixture().await;
        for body in [
            json!({ "all": false }),
            json!({ "sessionId": "s", "subject": f.in_a.did }),
            json!({}),
        ] {
            let (_, doc) = call(&f.vtc, &f.root, REVOKE_SESSION, body.clone()).await;
            assert_eq!(error_code(&doc), Some("malformedRequest"), "{body}: {doc}");
        }
    }

    #[tokio::test]
    async fn the_session_verbs_refuse_unsigned_and_unknown_signers() {
        let f = fixture().await;
        for (uri, body) in [
            (SESSIONS_LIST, json!({})),
            (REVOKE_SESSION, json!({ "all": true })),
        ] {
            let (_, doc) = post(&f.vtc, &unsigned(&f.root, uri, body.clone())).await;
            assert_eq!(error_code(&doc), Some("proofRequired"), "{uri}: {doc}");
            let (_, doc) = call(&f.vtc, &Party::new(), uri, body).await;
            assert_eq!(error_code(&doc), Some("permissionDenied"), "{uri}: {doc}");
        }
    }
}
