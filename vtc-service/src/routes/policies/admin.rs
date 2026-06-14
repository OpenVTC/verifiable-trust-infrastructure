//! Policy admin endpoints — upload, activate, test (M2.3.1).
//!
//! Spec §7 + plan §§D2, D3, D8.
//!
//! ## Hot-swap atomicity (plan §D8)
//!
//! [`ACTIVATE_LOCK`] is a process-wide async mutex that serialises
//! the activate flow. The flip itself is a single `set_active_policy_id`
//! call (one fjall put), but we hold the lock across:
//! 1. Look up the candidate policy.
//! 2. Stamp `activated_at` and `store_policy(candidate)`.
//! 3. Read the prior pointer (to record the predecessor in audit).
//! 4. Flip the active pointer.
//! 5. Emit `PolicyActivated`.
//!
//! Steps 2 + 4 are independent fjall puts — without the lock, two
//! concurrent activations of the same purpose could observe each
//! other's prior state and emit contradictory audit envelopes. One
//! global lock is fine in Phase 2: activations are infrequent
//! (operator-initiated, not request-path).
//!
//! The compiled-policy in-memory registry (the `Arc<RwLock<…>>`
//! D8 talks about) lands in M2.5 when default policies need to be
//! evaluated by the join + removal handlers. For M2.3 alone, the
//! fjall pointer flip is the source of truth; consumers don't
//! exist yet.

use std::sync::LazyLock;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tokio::sync::Mutex;
use tracing::info;
use uuid::Uuid;

use vti_common::audit::{AuditEvent, PolicyActivatedData, PolicyUploadedData};
use vti_common::error::AppError;

use crate::auth::AdminAuth;
use crate::policy::POLICY_SOURCE_MAX_BYTES;
use crate::policy::{
    PolicyPurpose, compile, evaluate, get_active_policy_id, get_policy, max_version_for,
    new_policy, set_active_policy_id, store_policy, validate_purpose_package,
};
use crate::server::AppState;

/// Process-wide async mutex covering every activate-policy call so
/// the predecessor pointer + audit envelope can't be skewed by a
/// concurrent flip on the same purpose. See module docs.
static ACTIVATE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

// ---------------------------------------------------------------------------
// Request / response shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct UploadBody {
    /// Wire-form camelCase purpose (`"join"`, `"removal"`,
    /// `"crossCommunityRoles"`, …). Validated by serde against
    /// [`PolicyPurpose`].
    pub purpose: PolicyPurpose,
    /// Full Rego source. Bounded by [`POLICY_SOURCE_MAX_BYTES`];
    /// uploads above the cap are rejected with 413.
    pub rego_source: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct UploadResponse {
    pub id: Uuid,
    /// SHA-256 of the source bytes, lowercase hex. Matches what
    /// `sha256sum policy.rego` prints — operators can verify the
    /// upload made it across the wire intact.
    pub sha256: String,
    pub purpose: PolicyPurpose,
    pub version: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct ActivateResponse {
    pub id: Uuid,
    pub purpose: PolicyPurpose,
    pub sha256: String,
    /// Predecessor active policy id for this purpose. `null` for
    /// the first activation under a given purpose.
    pub previous_policy_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct TestBody {
    /// Rego query to evaluate against the candidate policy
    /// (e.g. `"data.vtc.join.allow"`). Caller chooses the query so
    /// `test` can be used to probe any rule in the module, not
    /// just `allow`.
    pub query: String,
    /// JSON document fed to the policy as `input`. Mirrors the
    /// shape M2.6 / M2.7 will pass in production.
    pub input: JsonValue,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct TestResponse {
    pub id: Uuid,
    pub purpose: PolicyPurpose,
    pub sha256: String,
    /// Raw regorus `QueryResults` JSON. Same shape M2.6 / M2.7
    /// will pluck `result[0].expressions[0].value` from when they
    /// wire policy evaluation into the membership flows.
    pub result: JsonValue,
}

// ---------------------------------------------------------------------------
// POST /v1/policies — upload
// ---------------------------------------------------------------------------

/// Compile + persist a new policy revision. Does NOT activate it —
/// `POST /v1/policies/{id}/activate` is a separate call.
#[utoipa::path(
    post, path = "/policies", tag = "policies",
    security(("bearer_jwt" = [])),
    request_body = UploadBody,
    responses(
        (status = 201, description = "Policy revision compiled + stored", body = UploadResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn upload(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<UploadBody>,
) -> Result<(StatusCode, Json<UploadResponse>), AppError> {
    if body.rego_source.len() > POLICY_SOURCE_MAX_BYTES {
        return Err(AppError::Validation(format!(
            "rego_source exceeds {POLICY_SOURCE_MAX_BYTES} bytes (got {})",
            body.rego_source.len(),
        )));
    }

    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    // Allocate id first so the compile error can name it. The
    // `new_policy` helper also allocates one — we override via
    // `Policy { id, .. }` after compile rather than mint twice.
    let id = Uuid::new_v4();
    let compiled = compile(&body.rego_source, id)?;
    // Reject a module compiled into the wrong package for its declared
    // purpose — it would compile + activate cleanly, then evaluate to
    // `undefined` (silent host default-deny) for that whole ceremony.
    validate_purpose_package(&compiled, body.purpose)?;
    let sha256 = *compiled.source_sha256();
    let version = max_version_for(&state.policies_ks, body.purpose).await? + 1;

    let mut policy = new_policy(
        body.purpose,
        body.rego_source,
        sha256,
        admin.0.did.clone(),
        version,
    );
    policy.id = id;
    store_policy(&state.policies_ks, &policy).await?;

    let sha256_hex = hex::encode(sha256);
    audit_writer
        .write(
            &admin.0.did,
            None,
            AuditEvent::PolicyUploaded(PolicyUploadedData {
                policy_id: id.to_string(),
                purpose: body.purpose.as_str().to_string(),
                sha256: sha256_hex.clone(),
                version,
            }),
        )
        .await?;

    info!(
        actor = admin.0.did.as_str(),
        policy_id = %id,
        purpose = body.purpose.as_str(),
        version,
        sha256 = sha256_hex.as_str(),
        "policy uploaded"
    );

    Ok((
        StatusCode::CREATED,
        Json(UploadResponse {
            id,
            sha256: sha256_hex,
            purpose: body.purpose,
            version,
        }),
    ))
}

// ---------------------------------------------------------------------------
// POST /v1/policies/{id}/activate
// ---------------------------------------------------------------------------

#[utoipa::path(
    post, path = "/policies/{id}/activate", tag = "policies",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Policy revision id")),
    responses(
        (status = 200, description = "Policy revision activated", body = ActivateResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Policy not found"),
    ),
)]
pub async fn activate(
    admin: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ActivateResponse>, AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let _guard = ACTIVATE_LOCK.lock().await;

    let mut policy = get_policy(&state.policies_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("policy not found: {id}")))?;

    // Re-probe before flipping it live: a policy uploaded before the
    // package gate (or via a path that bypassed `upload`) must not be
    // activated into a silent default-deny for its ceremony.
    validate_purpose_package(&compile(&policy.rego_source, policy.id)?, policy.purpose)?;

    let previous = get_active_policy_id(&state.active_policies_ks, policy.purpose).await?;

    if previous == Some(id) {
        return Err(AppError::Conflict(format!(
            "policy {id} is already active for purpose {}",
            policy.purpose.as_str()
        )));
    }

    let now = Utc::now();
    policy.activated_at = Some(now);
    store_policy(&state.policies_ks, &policy).await?;

    set_active_policy_id(&state.active_policies_ks, policy.purpose, id).await?;

    let sha256_hex = hex::encode(policy.sha256);
    audit_writer
        .write(
            &admin.0.did,
            None,
            AuditEvent::PolicyActivated(PolicyActivatedData {
                policy_id: id.to_string(),
                purpose: policy.purpose.as_str().to_string(),
                sha256: sha256_hex.clone(),
                previous_policy_id: previous.map(|p| p.to_string()),
            }),
        )
        .await?;

    info!(
        actor = admin.0.did.as_str(),
        policy_id = %id,
        purpose = policy.purpose.as_str(),
        previous = ?previous,
        "policy activated"
    );

    Ok(Json(ActivateResponse {
        id,
        purpose: policy.purpose,
        sha256: sha256_hex,
        previous_policy_id: previous,
    }))
}

// ---------------------------------------------------------------------------
// POST /v1/policies/{id}/test
// ---------------------------------------------------------------------------

/// Evaluate a stored policy against a caller-supplied input.
/// **Does not activate** the policy and does not mutate any state
/// beyond log lines. Used by operators to dry-run a candidate
/// upload before flipping the active pointer.
#[utoipa::path(
    post, path = "/policies/{id}/test", tag = "policies",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Policy revision id")),
    request_body = TestBody,
    responses(
        (status = 200, description = "Policy evaluation result", body = TestResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Policy not found"),
    ),
)]
pub async fn test(
    admin: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<TestBody>,
) -> Result<Json<TestResponse>, AppError> {
    let policy = get_policy(&state.policies_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("policy not found: {id}")))?;

    // Recompile every call. The harness is cheap and a per-call
    // recompile means the test endpoint never depends on a
    // long-running compiled-cache (M2.5 introduces that for the
    // active policies; archived rows aren't cached).
    let compiled = compile(&policy.rego_source, policy.id)?;
    let result = evaluate(&compiled, &body.query, body.input)?;

    info!(
        actor = admin.0.did.as_str(),
        policy_id = %id,
        purpose = policy.purpose.as_str(),
        "policy tested"
    );

    Ok(Json(TestResponse {
        id,
        purpose: policy.purpose,
        sha256: hex::encode(policy.sha256),
        result,
    }))
}
