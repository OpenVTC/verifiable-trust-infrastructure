//! VRC (Verifiable Recognition Credential) graph endpoints
//! — Phase 4 M4.6. Spec §5.4 + §6.1; planning-review D1
//! (issuer is the *member*, not the community).
//!
//! ## Three endpoints
//!
//! 1. `POST /v1/relationships` — publish a self-issued VRC.
//!    Caller's session DID must equal the VC's `issuer`
//!    field. The VTC verifies the data-integrity proof
//!    against the member's resolved `#key-0`, runs
//!    `relationships.rego` against an enriched input
//!    (`{ vrc, issuer_member: { did, is_current },
//!        subject_member: { did, is_current }, action }`),
//!    persists the row + secondary-index entries on allow,
//!    emits `VrcPublished`.
//!
//! 2. `GET /v1/members/{did}/relationships` — see
//!    `src/routes/members/relationships.rs`. Owns its own
//!    file because the URL is rooted under `/v1/members/`.
//!
//! 3. `DELETE /v1/relationships/{id}` — issuer-only retraction
//!    (admin can also revoke for moderation). Deletes the row
//!    plus secondary-index entries; emits `VrcRevoked`. Per
//!    D7, VRCs carry no `credentialStatus`; revocation is row
//!    deletion, not a status-list bit flip.

use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use tracing::info;
use uuid::Uuid;
use vti_common::audit::{AuditEvent, VrcPublishedData, VrcRevokedData};
use vti_common::error::AppError;

use crate::acl::get_acl_entry;
use crate::auth::AuthClaims;
use crate::members::get_member;
use crate::policy::{
    PolicyPurpose, compile as compile_policy, evaluate as evaluate_policy, get_active_policy_id,
    get_policy,
};
use crate::relationships::{
    Relationship, delete_relationship, find_by_hash, get_relationship, store_relationship,
};
use crate::server::AppState;

// ─── Publish ─────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PublishBody {
    /// The self-issued VRC. Must be a JSON-LD VC body with
    /// `type` array including `VerifiableRecognitionCredential`,
    /// an `issuer` field matching the caller's session DID,
    /// `credentialSubject.id` naming the subject, and a
    /// data-integrity proof.
    pub vrc: JsonValue,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct PublishResponse {
    pub id: Uuid,
    pub issuer_did: String,
    pub subject_did: String,
    pub vrc_sha256: String,
}

#[utoipa::path(
    post, path = "/relationships", tag = "relationships",
    security(("bearer_jwt" = [])),
    request_body = PublishBody,
    responses(
        (status = 201, description = "Relationship (VRC) published", body = PublishResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not the VRC issuer or policy denied"),
    ),
)]
pub async fn publish(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(body): Json<PublishBody>,
) -> Result<(StatusCode, Json<PublishResponse>), AppError> {
    // 1. Parse the VC's core fields without going through the
    //    typed `VerifiableCredential` — VRCs carry a few
    //    extensions the typed parser doesn't know about, and
    //    we want to store the JSON-LD verbatim either way.
    let vrc = &body.vrc;
    let issuer_did = extract_did_field(vrc, "issuer")?;
    let subject_did = extract_subject_id(vrc)?;

    // 2. Caller == issuer check (D1: self-issued only).
    if auth.did != issuer_did {
        return Err(AppError::Forbidden(format!(
            "session DID ({}) does not match VRC issuer ({issuer_did}) — \
             VRCs are self-issued; the VTC never mints them on a member's behalf",
            auth.did
        )));
    }

    // 3. Verify the VC's data-integrity proof against the
    //    issuer's resolved #key-0. Daemon-config prerequisites
    //    surface after caller validation.
    let resolver = state.did_resolver.as_ref().cloned().ok_or_else(|| {
        AppError::Internal("DID resolver not configured — VRC publish requires it".into())
    })?;
    verify_vc_proof(vrc, &issuer_did, &resolver)
        .await
        .map_err(|e| AppError::Validation(format!("VrcProofInvalid: {e}")))?;

    // 4. Enrich both parties with `is_current` for the policy
    //    input. A member is `current` iff they have a live ACL
    //    row + a non-tombstoned Member row.
    let issuer_current = is_current_member(&state, &issuer_did).await?;
    let subject_current = is_current_member(&state, &subject_did).await?;
    if !subject_current {
        // Subject must at least exist (resolvable); the default
        // policy refuses if either party isn't current, but
        // we surface the more specific "subject unknown" 422
        // before falling through to the generic policy 403.
        if get_acl_entry(&state.acl_ks, &subject_did).await?.is_none() {
            return Err(AppError::Validation(format!(
                "subject DID {subject_did} is not a current community member"
            )));
        }
    }

    let policy_input = json!({
        "vrc": vrc,
        "issuer_member": { "did": issuer_did, "is_current": issuer_current },
        "subject_member": { "did": subject_did, "is_current": subject_current },
        "action": "publish",
    });
    let allow = evaluate_relationships_policy(&state, &policy_input).await?;
    if !allow {
        return Err(AppError::Forbidden(
            "RelationshipPolicyDenied: active relationships.rego rejected the publish".into(),
        ));
    }

    // 5. Compute hash for idempotent re-publish.
    let canon = canonicalise(vrc);
    let digest = Sha256::digest(canon.as_bytes());
    let vrc_sha256 = hex::encode(digest);

    // 6. Idempotency: same hash → same id.
    if let Some(existing) = find_by_hash(&state.relationships_ks, &vrc_sha256).await? {
        return Ok((
            StatusCode::OK,
            Json(PublishResponse {
                id: existing.id,
                issuer_did: existing.issuer_did,
                subject_did: existing.subject_did,
                vrc_sha256: existing.vrc_sha256,
            }),
        ));
    }

    // 7. Store the row + secondary-index entries.
    let id = Uuid::new_v4();
    let rel = Relationship {
        id,
        issuer_did: issuer_did.clone(),
        subject_did: subject_did.clone(),
        vrc_jsonld: vrc.clone(),
        vrc_sha256: vrc_sha256.clone(),
        created_at: Utc::now(),
    };
    store_relationship(
        &state.relationships_ks,
        &state.relationships_by_did_ks,
        &rel,
    )
    .await?;

    // 8. Audit.
    let edge_type = vrc
        .pointer("/credentialSubject/endorsement/type")
        .and_then(|v| v.as_str())
        .unwrap_or("recognition")
        .to_string();
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &issuer_did,
                Some(&subject_did),
                AuditEvent::VrcPublished(VrcPublishedData {
                    vrc_id: id.to_string(),
                    subject_did: Some(subject_did.clone()),
                    edge_type,
                }),
            )
            .await?;
    }

    info!(
        vrc_id = %id,
        issuer = %issuer_did,
        subject = %subject_did,
        "VRC published"
    );

    Ok((
        StatusCode::CREATED,
        Json(PublishResponse {
            id,
            issuer_did,
            subject_did,
            vrc_sha256,
        }),
    ))
}

// ─── Revoke ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RevokeResponse {
    pub id: String,
}

#[utoipa::path(
    delete, path = "/relationships/{id}", tag = "relationships",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Relationship (VRC) id")),
    responses(
        (status = 200, description = "Relationship (VRC) revoked", body = RevokeResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not the issuer or an admin"),
        (status = 404, description = "Relationship not found"),
    ),
)]
pub async fn revoke(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<RevokeResponse>), AppError> {
    let rel = get_relationship(&state.relationships_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("VRC {id} not found")))?;

    // Auth: issuer of the row OR admin.
    let is_issuer = auth.did == rel.issuer_did;
    let is_admin = auth.role == vti_common::acl::Role::Admin;
    if !is_issuer && !is_admin {
        return Err(AppError::Forbidden(
            "only the issuer or an admin can revoke a VRC".into(),
        ));
    }

    delete_relationship(&state.relationships_ks, &state.relationships_by_did_ks, id).await?;

    let revoked_by = if is_issuer { "issuer" } else { "admin" };
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &auth.did,
                Some(&rel.subject_did),
                AuditEvent::VrcRevoked(VrcRevokedData {
                    vrc_id: id.to_string(),
                    revoked_by: revoked_by.into(),
                }),
            )
            .await?;
    }

    info!(vrc_id = %id, revoked_by, "VRC revoked");

    Ok((StatusCode::OK, Json(RevokeResponse { id: id.to_string() })))
}

// ─── Helpers ─────────────────────────────────────────────

/// Extract a DID from a JSON-LD VC field that may be either a
/// string or an object with an `id` member (W3C spec allows
/// both shapes for `issuer`).
fn extract_did_field(vrc: &JsonValue, field: &str) -> Result<String, AppError> {
    let v = vrc
        .get(field)
        .ok_or_else(|| AppError::Validation(format!("VRC missing {field}")))?;
    match v {
        JsonValue::String(s) => Ok(s.clone()),
        JsonValue::Object(o) => o
            .get("id")
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .ok_or_else(|| AppError::Validation(format!("VRC.{field}.id missing or not a string"))),
        _ => Err(AppError::Validation(format!(
            "VRC.{field} is neither a string nor an object"
        ))),
    }
}

fn extract_subject_id(vrc: &JsonValue) -> Result<String, AppError> {
    vrc.pointer("/credentialSubject/id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| {
            AppError::Validation("VRC.credentialSubject.id missing or not a string".into())
        })
}

/// Verify a VC's data-integrity proof against the issuer's
/// resolved `#key-0`. Mirrors the personhood + recognition
/// verifiers; same upstream `get_public_key_bytes()` helper.
async fn verify_vc_proof(
    vrc: &JsonValue,
    issuer_did: &str,
    resolver: &DIDCacheClient,
) -> Result<(), String> {
    let proof_value = vrc
        .get("proof")
        .ok_or_else(|| "VRC missing proof".to_string())?;
    let proof: DataIntegrityProof =
        serde_json::from_value(proof_value.clone()).map_err(|e| format!("parse proof: {e}"))?;

    let mut vrc_without_proof = vrc.clone();
    if let Some(obj) = vrc_without_proof.as_object_mut() {
        obj.remove("proof");
    }

    let verification_method = proof_value
        .get("verificationMethod")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "proof missing verificationMethod".to_string())?;

    let resolved = resolver
        .resolve(issuer_did)
        .await
        .map_err(|e| format!("resolve {issuer_did}: {e}"))?;
    let vm = resolved
        .doc
        .verification_method
        .iter()
        .find(|m| m.id.as_str() == verification_method)
        .ok_or_else(|| format!("verificationMethod {verification_method} not on {issuer_did}"))?;
    let pubkey = vm
        .get_public_key_bytes()
        .map_err(|e| format!("extract pubkey: {e}"))?;

    proof
        .verify_with_public_key(&vrc_without_proof, &pubkey, VerifyOptions::new())
        .map_err(|e| format!("verify: {e}"))?;
    Ok(())
}

/// A member is `is_current` iff they have a live ACL row +
/// the Member row exists and isn't tombstoned. Either
/// missing → false.
async fn is_current_member(state: &AppState, did: &str) -> Result<bool, AppError> {
    let acl = get_acl_entry(&state.acl_ks, did).await?;
    if acl.is_none() {
        return Ok(false);
    }
    let member = get_member(&state.members_ks, did).await?;
    Ok(member.is_some_and(|m| !m.is_removed()))
}

/// Evaluate `relationships.rego.allow`. Fail-closed.
async fn evaluate_relationships_policy(
    state: &AppState,
    input: &JsonValue,
) -> Result<bool, AppError> {
    let Some(id) =
        get_active_policy_id(&state.active_policies_ks, PolicyPurpose::Relationships).await?
    else {
        return Ok(false);
    };
    let policy = get_policy(&state.policies_ks, id)
        .await?
        .ok_or_else(|| AppError::Internal(format!("active relationships policy {id} not found")))?;
    let compiled = compile_policy(&policy.rego_source, policy.id)?;
    let result = evaluate_policy(&compiled, "data.vtc.relationships.allow", input.clone())?;
    Ok(result
        .pointer("/result/0/expressions/0/value")
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

/// Canonicalise the VRC JSON for the SHA-256 hash. JCS
/// (RFC 8785) is the W3C-standard canonical form for VC
/// signing, but the data-integrity layer already canonicalises
/// during proof verification; for our local idempotency check
/// we only need a *deterministic* form, not a *standard* one.
/// `serde_json` sorts keys lexicographically when serialising
/// from a `BTreeMap` — we convert + serialise to get that.
fn canonicalise(v: &JsonValue) -> String {
    fn into_sorted(v: JsonValue) -> JsonValue {
        match v {
            JsonValue::Object(m) => {
                let mut sorted: std::collections::BTreeMap<String, JsonValue> =
                    std::collections::BTreeMap::new();
                for (k, val) in m {
                    sorted.insert(k, into_sorted(val));
                }
                serde_json::to_value(sorted).expect("sorted object is JSON-able")
            }
            JsonValue::Array(arr) => JsonValue::Array(arr.into_iter().map(into_sorted).collect()),
            other => other,
        }
    }
    serde_json::to_string(&into_sorted(v.clone())).unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_did_field_handles_string_form() {
        let vrc = json!({ "issuer": "did:key:zA" });
        assert_eq!(extract_did_field(&vrc, "issuer").unwrap(), "did:key:zA");
    }

    #[test]
    fn extract_did_field_handles_object_form() {
        let vrc = json!({ "issuer": { "id": "did:key:zA", "name": "x" } });
        assert_eq!(extract_did_field(&vrc, "issuer").unwrap(), "did:key:zA");
    }

    #[test]
    fn extract_did_field_rejects_missing() {
        let vrc = json!({});
        assert!(extract_did_field(&vrc, "issuer").is_err());
    }

    #[test]
    fn extract_subject_id_extracts_nested() {
        let vrc = json!({
            "credentialSubject": { "id": "did:key:zSubject", "role": "member" }
        });
        assert_eq!(extract_subject_id(&vrc).unwrap(), "did:key:zSubject");
    }

    #[test]
    fn canonicalise_is_key_order_stable() {
        let a = json!({ "b": 1, "a": 2, "c": { "y": 5, "x": 4 } });
        let b = json!({ "a": 2, "c": { "x": 4, "y": 5 }, "b": 1 });
        assert_eq!(canonicalise(&a), canonicalise(&b));
    }
}
