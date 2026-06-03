//! Integration coverage for `GET /v1/health/diagnostics`.
//!
//! Exercises the full router stack — Trust-Task header → auth
//! extractor → handler → registry storage — through
//! `Router::oneshot`.
//!
//! Phase 3 M3.8.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower::ServiceExt;
use vti_common::auth::jwt::JwtKeys;
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vtc_service::config::AppConfig;
use vtc_service::registry::{RegistryHealth, SyncJob, SyncJobKind, SyncJobState, store_sync_job};
use vtc_service::routes;
use vtc_service::server::AppState;

const DIAGNOSTICS_TASK: &str = "https://trusttasks.org/openvtc/vtc/health/diagnostics/1.0";

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

struct Fixture {
    router: axum::Router,
    jwt_keys: Arc<JwtKeys>,
    state: AppState,
    _dir: tempfile::TempDir,
}

async fn build() -> Fixture {
    init_jwt_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("open store");

    let sessions_ks = store.keyspace("sessions").unwrap();
    let acl_ks = store.keyspace("acl").unwrap();
    let community_ks = store.keyspace("community").unwrap();
    let config_ks = store.keyspace("config").unwrap();
    let passkey_ks = store.keyspace("passkey").unwrap();
    let install_ks = store.keyspace("install").unwrap();
    let members_ks = store.keyspace("members").unwrap();
    let join_requests_ks = store.keyspace("join_requests").unwrap();
    let policies_ks = store.keyspace("policies").unwrap();
    let active_policies_ks = store.keyspace("active_policies").unwrap();
    let status_lists_ks = store.keyspace("status_lists").unwrap();
    let registry_records_ks = store.keyspace("registry_records").unwrap();
    let sync_queue_ks = store.keyspace("sync_queue").unwrap();
    let sync_cursor_ks = store.keyspace("sync_cursor").unwrap();
    let relationships_ks = store.keyspace("relationships").unwrap();
    let relationships_by_did_ks = store.keyspace("relationships_by_did").unwrap();
    let endorsement_types_ks = store.keyspace("endorsement_types").unwrap();
    let endorsements_ks = store.keyspace("endorsements").unwrap();
    let audit_ks = store.keyspace("audit").unwrap();
    let audit_key_ks = store.keyspace("audit_key").unwrap();

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").expect("jwt keys"));

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "did:webvh:vtc.example.com:abc"
        [store]
        data_dir = "{}"
        [auth]
        jwt_signing_key = "{}"
        "#,
        dir.path().display(),
        BASE64.encode(jwt_seed),
    ))
    .expect("parse config");

    let state = AppState {
        sessions_ks: sessions_ks.clone(),
        acl_ks,
        community_ks,
        config_ks,
        passkey_ks,
        install_ks: install_ks.clone(),
        members_ks,
        join_requests_ks,
        policies_ks,
        active_policies_ks,
        status_lists_ks,
        registry_records_ks,
        sync_queue_ks: sync_queue_ks.clone(),
        sync_cursor_ks,
        relationships_ks,
        relationships_by_did_ks,
        endorsement_types_ks,
        schemas_ks: store.keyspace("schemas").unwrap(),
        endorsements_ks,
        registry_client: None,
        registry_health: RegistryHealth::new(),
        credential_signer: None,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys.clone()),
        atm: None,
        webauthn: None,
        public_url: None,
        install_signer: None,
        install_store: vtc_service::install::InstallTokenStore::new(install_ks),
        audit_ks,
        audit_key_ks,
        audit_writer: None,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    let router = routes::router().with_state(state.clone());
    Fixture {
        router,
        jwt_keys,
        state,
        _dir: dir,
    }
}

async fn token_for(fix: &Fixture, role: &str) -> String {
    use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};
    let session_id = format!("sess-{}", uuid::Uuid::new_v4());
    let session = Session {
        session_id: session_id.clone(),
        did: "did:key:z6MkAdmin".into(),
        challenge: "test".into(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: None,
        tee_attested: false,
        amr: Vec::new(),
        acr: String::new(),
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&fix.state.sessions_ks, &session)
        .await
        .unwrap();
    let claims = fix.jwt_keys.new_claims(
        "did:key:z6MkAdmin".to_string(),
        session_id,
        role.to_string(),
        vec![],
        900,
        false,
    );
    fix.jwt_keys.encode(&claims).expect("encode")
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

fn get(uri: &str, task: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("Trust-Task", task)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn diagnostics_empty_queue_reports_zero_counts() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;

    let resp = fix
        .router
        .clone()
        .oneshot(get("/v1/health/diagnostics", DIAGNOSTICS_TASK, &token))
        .await
        .unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["queue_depth"], 0);
    assert_eq!(v["rtbf_batched_count"], 0);
    assert_eq!(v["failed_count"], 0);
    // Default RegistryHealth state is "degraded" (no successful
    // probe yet).
    assert_eq!(v["registry_status"], "degraded");
    assert!(
        v.get("oldest_pending_age_seconds")
            .is_none_or(|x| x.is_null()),
        "empty queue → no oldest_pending_age"
    );
}

#[tokio::test]
async fn diagnostics_reports_pending_rtbf_and_failed_counts() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;

    // Pending dispatchable.
    let pending = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:zP");
    store_sync_job(&fix.state.sync_queue_ks, &pending)
        .await
        .unwrap();

    // RTBF-batched (future-dated next_attempt_at).
    let mut rtbf = SyncJob::fresh(SyncJobKind::DeleteMember, "did:key:zR");
    rtbf.next_attempt_at = chrono::Utc::now() + chrono::Duration::hours(20);
    rtbf.rtbf_batched = true;
    store_sync_job(&fix.state.sync_queue_ks, &rtbf)
        .await
        .unwrap();

    // Failed (terminal).
    let mut failed = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:zF");
    failed.state = SyncJobState::Failed;
    failed.last_error = Some("permanent error from upstream".into());
    store_sync_job(&fix.state.sync_queue_ks, &failed)
        .await
        .unwrap();

    let resp = fix
        .router
        .clone()
        .oneshot(get("/v1/health/diagnostics", DIAGNOSTICS_TASK, &token))
        .await
        .unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // Pending (1) + RTBF-pending (1) = queue_depth 2; Failed
    // sits outside the active queue.
    assert_eq!(v["queue_depth"], 2);
    assert_eq!(v["rtbf_batched_count"], 1);
    assert_eq!(v["failed_count"], 1);
    // Pending (dispatchable) job's age is surfaced; RTBF row
    // doesn't count toward "stuck" SLI.
    assert!(v["oldest_pending_age_seconds"].is_number());
}

#[tokio::test]
async fn diagnostics_requires_admin_role() {
    let fix = build().await;
    // `reader` is a valid VTC ACL role but not admin —
    // AdminAuth must reject.
    let reader_token = token_for(&fix, "reader").await;

    let resp = fix
        .router
        .clone()
        .oneshot(get(
            "/v1/health/diagnostics",
            DIAGNOSTICS_TASK,
            &reader_token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "non-admin must be rejected"
    );
}

#[tokio::test]
async fn diagnostics_requires_trust_task_header() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/health/diagnostics")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "missing Trust-Task header must 400"
    );
}
