//! `/v1/credentials/endorsements/*` — custom endorsement
//! issuance + retrieval + revocation (Phase 4 M4.8.2-4).
//!
//! ## Four endpoints
//!
//! - `POST /v1/credentials/endorsements` — issue. Auth:
//!   Admin OR Issuer role. Consults the type registry
//!   (M4.8.1). Allocates a slot on the shared `Revocation`
//!   status list (D8 review), builds + signs the VEC,
//!   persists the row, emits `CustomEndorsementIssued` +
//!   `VecIssued`.
//! - `GET /v1/credentials/endorsements` — paginated list.
//!   Auth: Admin OR Issuer.
//! - `GET /v1/credentials/endorsements/{id}` — show.
//! - `DELETE /v1/credentials/endorsements/{id}` — revoke.
//!   Auth: Admin OR the original issuer. Flips the
//!   status-list bit + emits both `CustomEndorsementRevoked`
//!   and `StatusListFlipped`.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::info;
use uuid::Uuid;
use vti_common::audit::{
    AuditEvent, CredentialIssuedData, CustomEndorsementIssuedData, CustomEndorsementRevokedData,
    StatusListFlippedData,
};
use vti_common::auth::AuthClaims;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated};

use crate::acl::{VtcRole, get_acl_entry};
use crate::credentials::{CredentialStatusRef, CustomEndorsementParams, build_custom_endorsement};
use crate::endorsement_types::type_exists;
use crate::endorsements::{
    Endorsement, get_endorsement, list_endorsements, mark_revoked, store_endorsement,
};
use crate::server::AppState;
use crate::status_list;

const LIST_MAX_LIMIT: usize = 200;

/// `CLAIM_MAX_BYTES` upper bound on the on-the-wire body
/// (matches the builder cap). Larger inputs surface as 400.
const CLAIM_MAX_BYTES: usize = 8 * 1024;

// ─── Issue ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct IssueBody {
    pub subject_did: String,
    #[serde(rename = "type")]
    pub endorsement_type: String,
    pub claim: JsonValue,
    /// Optional override; defaults to 30d.
    #[serde(default)]
    pub validity_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct IssueResponse {
    pub id: Uuid,
    pub vec_id: String,
    pub vec: JsonValue,
}

#[utoipa::path(
    post, path = "/credentials/endorsements", tag = "endorsements",
    security(("bearer_jwt" = [])),
    request_body = IssueBody,
    responses(
        (status = 201, description = "Endorsement issued", body = IssueResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin or issuer"),
    ),
)]
pub async fn issue(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(body): Json<IssueBody>,
) -> Result<(StatusCode, Json<IssueResponse>), AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let signer = state
        .credential_signer
        .as_ref()
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;

    // 1. Auth: Admin OR Issuer (read the VTC ACL row — JWT
    //    role degrades non-Admin VTC roles to Reader, so the
    //    JWT alone can't distinguish Issuer from Member).
    let acl = get_acl_entry(&state.acl_ks, &auth.did)
        .await?
        .ok_or_else(|| AppError::Forbidden("caller has no ACL row".into()))?;
    if !matches!(acl.role, VtcRole::Admin | VtcRole::Issuer) {
        return Err(AppError::Forbidden(
            "only Admin or Issuer-role members can mint custom endorsements".into(),
        ));
    }

    // 2. Type registry consultation (D4 review).
    if !type_exists(&state.endorsement_types_ks, &body.endorsement_type).await? {
        return Err(AppError::Validation(format!(
            "endorsement-type-not-registered: '{}' is not in the endorsement type registry",
            body.endorsement_type
        )));
    }

    // 3. Body-side validation. The builder enforces the same
    //    cap; we check here too so 400 surfaces cleanly
    //    before any state mutation.
    if !body.claim.is_object() {
        return Err(AppError::Validation("claim must be a JSON object".into()));
    }
    let claim_bytes = serde_json::to_vec(&body.claim)
        .map_err(|e| AppError::Internal(format!("serialise claim: {e}")))?;
    if claim_bytes.len() > CLAIM_MAX_BYTES {
        return Err(AppError::Validation(format!(
            "claim exceeds {CLAIM_MAX_BYTES} bytes"
        )));
    }

    // 4. Subject must be a current ACL member — operators
    //    that want cross-community endorsements layer their
    //    own policy (out of scope for Phase 4).
    if get_acl_entry(&state.acl_ks, &body.subject_did)
        .await?
        .is_none()
    {
        return Err(AppError::Validation(format!(
            "subject DID {} is not a current community member",
            body.subject_did
        )));
    }

    // 5. Allocate status-list slot — locked RMW so a concurrent
    //    allocate/flip can't clobber this allocation (P0.1).
    let (slot, list_credential_id) = status_list::with_locked(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        |row| {
            let slot = status_list::allocate(row).ok_or_else(|| {
                AppError::Internal(
                    "revocation status list is full — cannot allocate slot for endorsement".into(),
                )
            })?;
            Ok((slot, row.list_credential_id.clone()))
        },
    )
    .await?;
    let status_ref = CredentialStatusRef::revocation(list_credential_id, slot);

    // 6. Build + sign the VEC.
    let id = Uuid::new_v4();
    let vec_id = format!("urn:uuid:{id}");
    let validity = body
        .validity_seconds
        .map(|s| Duration::seconds(s as i64))
        .unwrap_or_else(|| {
            crate::credentials::custom_endorsement::DEFAULT_CUSTOM_ENDORSEMENT_VALIDITY
        });
    let params = CustomEndorsementParams::new(
        &body.subject_did,
        &body.endorsement_type,
        body.claim.clone(),
        status_ref,
    )
    .with_id(&vec_id)
    .with_validity(validity);
    let vec = build_custom_endorsement(signer, params).await?;

    // Issue-time schema validation: enforce a registered credentialSchema for
    // this endorsement type, if any (no-op when none is registered).
    crate::schemas::validate_issued(
        &state.schemas_ks,
        &serde_json::to_value(&vec)
            .map_err(|e| AppError::Internal(format!("endorsement -> value: {e}")))?,
    )
    .await?;

    // 7. Persist the Endorsement row.
    let now = Utc::now();
    let valid_until = now + validity;
    let end = Endorsement {
        id,
        endorsement_type: body.endorsement_type.clone(),
        issuer_did: signer.issuer_did().to_string(),
        subject_did: body.subject_did.clone(),
        claim: body.claim.clone(),
        status_list_index: slot,
        vec_id: vec_id.clone(),
        created_at: now,
        revoked_at: None,
    };
    store_endorsement(&state.endorsements_ks, &end).await?;

    // 8. Audit — two envelopes (custom endorsement + generic
    //    VEC issuance accounting).
    audit_writer
        .write(
            &auth.did,
            Some(&body.subject_did),
            AuditEvent::CustomEndorsementIssued(CustomEndorsementIssuedData {
                endorsement_id: id.to_string(),
                endorsement_type: body.endorsement_type.clone(),
                status_list_index: slot,
            }),
        )
        .await?;
    audit_writer
        .write(
            &auth.did,
            Some(&body.subject_did),
            AuditEvent::VecIssued(CredentialIssuedData {
                credential_id: vec_id.clone(),
                credential_type: "VerifiableEndorsementCredential".into(),
                valid_from: rfc3339(now),
                valid_until: rfc3339(valid_until),
                status_list_index: Some(slot),
            }),
        )
        .await?;

    info!(
        endorsement_id = %id,
        endorsement_type = %body.endorsement_type,
        subject = %body.subject_did,
        slot,
        "custom endorsement issued"
    );

    let vec_value = serde_json::to_value(&vec)
        .map_err(|e| AppError::Internal(format!("serialise VEC: {e}")))?;
    Ok((
        StatusCode::CREATED,
        Json(IssueResponse {
            id,
            vec_id,
            vec: vec_value,
        }),
    ))
}

// ─── List ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema, utoipa::IntoParams)]
pub struct ListQuery {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

#[utoipa::path(
    get, path = "/credentials/endorsements", tag = "endorsements",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Paginated list of endorsements", body = Paginated<Endorsement>),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin or issuer"),
    ),
)]
pub async fn list(
    auth: AuthClaims,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Paginated<Endorsement>>, AppError> {
    let acl = get_acl_entry(&state.acl_ks, &auth.did)
        .await?
        .ok_or_else(|| AppError::Forbidden("caller has no ACL row".into()))?;
    if !matches!(acl.role, VtcRole::Admin | VtcRole::Issuer) {
        return Err(AppError::Forbidden(
            "only Admin or Issuer-role members can list custom endorsements".into(),
        ));
    }

    let limit = query.limit.unwrap_or(50).clamp(1, LIST_MAX_LIMIT);
    let audit_key = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?
        .active_key()
        .await?;
    let cursor = query
        .cursor
        .as_deref()
        .map(|c| Cursor::decode(c, &audit_key.key))
        .transpose()
        .map_err(|e| AppError::Validation(format!("invalid cursor: {e}")))?;
    let page =
        list_endorsements(&state.endorsements_ks, &audit_key, cursor.as_ref(), limit).await?;
    Ok(Json(page))
}

// ─── Show ────────────────────────────────────────────────

#[utoipa::path(
    get, path = "/credentials/endorsements/{id}", tag = "endorsements",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Endorsement id")),
    responses(
        (status = 200, description = "Endorsement", body = Endorsement),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin or issuer"),
        (status = 404, description = "Endorsement not found"),
    ),
)]
pub async fn show(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Endorsement>, AppError> {
    let acl = get_acl_entry(&state.acl_ks, &auth.did)
        .await?
        .ok_or_else(|| AppError::Forbidden("caller has no ACL row".into()))?;
    if !matches!(acl.role, VtcRole::Admin | VtcRole::Issuer) {
        return Err(AppError::Forbidden(
            "only Admin or Issuer-role members can read custom endorsements".into(),
        ));
    }
    let row = get_endorsement(&state.endorsements_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("endorsement {id} not found")))?;
    Ok(Json(row))
}

// ─── Revoke ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RevokeResponse {
    pub id: String,
}

#[utoipa::path(
    delete, path = "/credentials/endorsements/{id}", tag = "endorsements",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Endorsement id")),
    responses(
        (status = 200, description = "Endorsement revoked", body = RevokeResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin or issuer"),
        (status = 404, description = "Endorsement not found"),
    ),
)]
pub async fn revoke(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<RevokeResponse>), AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let row = get_endorsement(&state.endorsements_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("endorsement {id} not found")))?;

    // Auth: Admin OR original issuer (always == signer DID;
    // any Admin/Issuer of the community).
    let acl = get_acl_entry(&state.acl_ks, &auth.did)
        .await?
        .ok_or_else(|| AppError::Forbidden("caller has no ACL row".into()))?;
    let is_admin = matches!(acl.role, VtcRole::Admin);
    // Issuer-side check: did the caller mint this row? The
    // `issuer_did` on every endorsement is the community
    // DID; the *originating actor* is recorded on the audit
    // envelope. For revoke, we treat any current Issuer role
    // member as an authorised retractor — the audit trail
    // captures who actually called.
    let is_issuer_role = matches!(acl.role, VtcRole::Issuer);
    if !is_admin && !is_issuer_role {
        return Err(AppError::Forbidden(
            "only Admin or Issuer-role members can revoke endorsements".into(),
        ));
    }

    // Idempotent no-op.
    if row.is_revoked() {
        return Ok((StatusCode::OK, Json(RevokeResponse { id: id.to_string() })));
    }

    // Flip the status-list bit — locked RMW so a concurrent allocate/flip
    // can't clobber this revocation (P0.1). (Wrapping the subsequent
    // `mark_revoked` in the same critical section for crash-atomicity is
    // the separate P3.9 hygiene item.)
    let slot_idx = row.status_list_index;
    status_list::with_locked(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        move |sl| {
            status_list::flip(sl, slot_idx, true)
                .map_err(|e| AppError::Internal(format!("flip status-list bit {slot_idx}: {e}")))
        },
    )
    .await?;

    // Mark the row revoked.
    let updated = mark_revoked(&state.endorsements_ks, id)
        .await?
        .ok_or_else(|| AppError::Internal("row disappeared mid-revoke".into()))?;

    // Two paired envelopes — CustomEndorsementRevoked
    // (semantic) + StatusListFlipped (bit-flip accounting).
    audit_writer
        .write(
            &auth.did,
            Some(&row.subject_did),
            AuditEvent::CustomEndorsementRevoked(CustomEndorsementRevokedData {
                endorsement_id: id.to_string(),
                endorsement_type: row.endorsement_type.clone(),
            }),
        )
        .await?;
    audit_writer
        .write(
            &auth.did,
            Some(&row.subject_did),
            AuditEvent::StatusListFlipped(StatusListFlippedData {
                purpose: "revocation".into(),
                index: row.status_list_index,
                revoked: true,
            }),
        )
        .await?;

    info!(
        endorsement_id = %id,
        endorsement_type = %row.endorsement_type,
        slot = row.status_list_index,
        by = %auth.did,
        "custom endorsement revoked"
    );
    let _ = updated;

    Ok((StatusCode::OK, Json(RevokeResponse { id: id.to_string() })))
}

fn rfc3339(t: chrono::DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
