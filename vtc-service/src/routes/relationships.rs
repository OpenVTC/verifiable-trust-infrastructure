//! VRC (Verifiable Relationship Credential) graph endpoints
//! — Phase 4 M4.6. Spec §5.4 + §6.1; planning-review D1
//! (issuer is the *member*, not the community).
//!
//! ## Three endpoints
//!
//! 1. `POST /v1/relationships` — publish a self-issued VRC.
//!    The VTC verifies the credential's data-integrity proof
//!    against the key its `issuer` field names, then authorizes
//!    the *publication* separately: either a publish
//!    authorization proving the caller controls the issuing key
//!    (see [`verify_publish_authorization`]), or — deprecated —
//!    an `issuer` equal to the session DID. It then runs
//!    `relationships.rego` against an enriched input
//!    (`{ vrc, authenticated_member: { did, is_current },
//!        identifier_form, issuer: { did, is_current },
//!        subject: { did, is_current },
//!        action }`), persists the row + secondary-index
//!    entries on allow, and emits `VrcPublished`.
//!
//!    Splitting issuance from publication is what lets a member
//!    publish an edge under a pairwise relationship DID rather
//!    than their membership DID — the privacy property DTG
//!    Credentials asks for, and the subject of #1054. See
//!    `docs/05-design-notes/vrc-publish-proof-of-possession.md`.
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

use crate::credentials::vm_resolver::{DidVmResolver, check_issuer_binding};
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
    Relationship, delete_relationship, find_by_hash, get_relationship,
    issuer_counterparties_besides, store_relationship,
};
use crate::server::AppState;

// ─── Publish ─────────────────────────────────────────────

/// Which kind of identifier a VRC is issued under. A member picks per
/// relationship; the community declares which it expects (see the community
/// profile's `relationshipIdentifierDefault`). Both are permanent, supported
/// forms — neither is a migration state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentifierForm {
    /// Issued under the member's membership DID. The edge names them and the
    /// graph is correlatable by design — what a public community wants.
    Attributed,
    /// Issued under a relationship DID scoped to one counterparty, with a
    /// publish authorization proving control of it.
    Pairwise,
}

impl IdentifierForm {
    /// Wire value, and the string operator policies match on.
    fn as_str(self) -> &'static str {
        match self {
            IdentifierForm::Attributed => "attributed",
            IdentifierForm::Pairwise => "pairwise",
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PublishBody {
    /// The self-issued VRC, in the DTG Credentials wire form:
    /// `@context` carrying the W3C v2 and DTG contexts, `type`
    /// `["VerifiableCredential", "DTGCredential",
    /// "RelationshipCredential"]`, an `issuer`,
    /// `credentialSubject.id` naming the subject, and a
    /// data-integrity proof. Built by
    /// `dtg_credentials::DTGCredential::new_vrc`.
    pub vrc: JsonValue,
    /// Proof that the caller controls the key behind the VRC's
    /// `issuer`, when that is not the caller's session DID —
    /// i.e. whenever the credential is issued under a pairwise
    /// relationship DID rather than the member's membership DID.
    ///
    /// See [`verify_publish_authorization`]. Required unless
    /// `issuer` equals the session DID (the deprecated form).
    #[serde(default)]
    pub pop: Option<JsonValue>,
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

    // 2. Shape: is this even a relationship credential? Checked
    //    before anything expensive, and before authorization,
    //    because a malformed body is a 400 whoever sent it.
    check_vrc_shape(vrc)?;

    // 3. Cheapest authorization gate first: a VRC issued under a
    //    DID that is not the session's must carry a publish
    //    authorization. Rejecting here keeps a caller error a
    //    caller error — the daemon-config prerequisites below
    //    would otherwise mask it with a 500.
    if body.pop.is_none() && issuer_did != auth.did {
        return Err(AppError::Forbidden(format!(
            "VRC issuer ({issuer_did}) is not the session DID and no publish \
             authorization (`pop`) was supplied — a VRC issued under a \
             relationship DID must carry proof the caller controls it"
        )));
    }

    // 4. Verify the VC's data-integrity proof against the key
    //    the `issuer` field names. This establishes that the
    //    credential was made by the party it names as issuer —
    //    true whatever kind of identifier that is, and untouched
    //    by the authorization change below.
    let resolver = state.did_resolver.as_ref().cloned().ok_or_else(|| {
        AppError::Internal("DID resolver not configured — VRC publish requires it".into())
    })?;
    verify_di_proof(vrc, &issuer_did, &resolver)
        .await
        .map_err(|e| AppError::Validation(format!("VrcProofInvalid: {e}")))?;

    // 5. Hash the VRC. This moves ahead of policy evaluation
    //    because the publish authorization binds to it.
    let canon = canonicalise(vrc);
    let digest = Sha256::digest(canon.as_bytes());
    let vrc_sha256 = hex::encode(digest);

    // 6. Authorize the *publication*, which is a separate act
    //    from the issuance verified at step 2. Issuing a VRC and
    //    publishing it to the community graph are different
    //    disclosures, and the second one is the issuer's to make:
    //    without this, any member who was ever handed a VRC could
    //    publish someone else's edge.
    //
    //    Previously this was `auth.did == issuer_did`, which
    //    forced the member's membership DID into the durable,
    //    publishable credential. The session proves membership;
    //    the authorization object proves control of the issuing
    //    key; neither requires them to be the same string (#1054).
    //    A member chooses this per relationship. Both forms are
    //    first-class and permanent — neither is a migration
    //    state:
    //
    //    **attributed** — the VRC is issued under the member's
    //    own membership DID. The edge names them, and the graph
    //    is correlatable by design. This is what a public
    //    community wants; DTG Credentials permits it directly
    //    ("the member may also assert the M-DID in any VRC where
    //    the member wishes to assert a VTC relationship").
    //
    //    **pairwise** — the VRC is issued under a relationship
    //    DID scoped to this counterparty, and the authorization
    //    object proves the caller controls it.
    //
    //    The community declares which it expects; the member
    //    decides each time. Only the *claim* is enforced here —
    //    see the uniqueness check below.
    let identifier_form = match (&body.pop, issuer_did == auth.did) {
        (Some(pop), _) => {
            let aud = crate::routes::recognise::vtc_did(&state).await?;
            verify_publish_authorization(
                pop,
                &issuer_did,
                &vrc_sha256,
                &aud,
                &auth.session_id,
                &resolver,
            )
            .await
            .map_err(|e| AppError::Forbidden(format!("VrcPublishAuthorizationInvalid: {e}")))?;
            IdentifierForm::Pairwise
        }
        (None, true) => IdentifierForm::Attributed,
        // Rejected at step 2; restated rather than `unreachable!` so a
        // future edit that moves the gate cannot turn a caller error into
        // a panicking request handler.
        (None, false) => {
            return Err(AppError::Forbidden(
                "VRC issuer is not the session DID and no publish authorization \
                 (`pop`) was supplied"
                    .into(),
            ));
        }
    };

    //    An identifier presented as pairwise must actually be
    //    pairwise. DTG Credentials: "each entity MUST generate a
    //    new, unique R-DID for every single entity they connect
    //    with, even within the same community."
    //
    //    This is type integrity, not a privacy policy, which is
    //    why it is unconditional rather than something a
    //    community can switch off. A verifier reading a pairwise
    //    edge is entitled to conclude the identifier says nothing
    //    beyond that one relationship; a reused R-DID breaks that
    //    inference for every reader of the graph, not just for
    //    the member who reused it. A member who wants to be
    //    recognised across their relationships has a supported
    //    way to do it — the attributed form above.
    //
    //    The community is the only party that can see the
    //    violation: each counterparty sees only its own edge.
    if identifier_form == IdentifierForm::Pairwise {
        let others = issuer_counterparties_besides(
            &state.relationships_ks,
            &state.relationships_by_did_ks,
            &issuer_did,
            &subject_did,
        )
        .await?;
        if !others.is_empty() {
            return Err(AppError::Validation(format!(
                "relationship DID {issuer_did} already has an edge to {} other \
                 counterpart(y|ies) — a relationship DID must be unique to one \
                 counterparty. Mint a new one for this relationship, or issue \
                 under your membership DID to publish an attributed edge",
                others.len()
            )));
        }
    }

    // 7. Enrich for the policy input.
    //
    //    `authenticated_member` is the caller — the party whose
    //    membership actually gates this publish. `issuer` and
    //    `subject` are the credential's own parties, which under
    //    pairwise identifiers are not resolvable to members and
    //    are not meant to be.
    //
    let member_current = is_current_member(&state, &auth.did).await?;
    let issuer_current = is_current_member(&state, &issuer_did).await?;
    let subject_current = is_current_member(&state, &subject_did).await?;

    // The subject membership check only asks an answerable
    // question on the deprecated form, where the subject is named
    // by a membership DID. Under pairwise identifiers it is not
    // just unanswerable but the wrong question: DTG Credentials
    // §Community-Anchored ZKP is explicit that "community
    // membership is not a precondition for issuing, holding, or
    // presenting a VRC". The subject's consent to the edge is
    // their publication of the reciprocal VRC, not our assertion
    // that they exist.
    if identifier_form == IdentifierForm::Attributed
        && !subject_current
        && get_acl_entry(&state.acl_ks, &subject_did).await?.is_none()
    {
        return Err(AppError::Validation(format!(
            "subject DID {subject_did} is not a current community member"
        )));
    }

    let policy_input = json!({
        "vrc": vrc,
        "authenticated_member": { "did": auth.did, "is_current": member_current },
        "identifier_form": identifier_form.as_str(),
        // `is_current` on the credential'"'"'s own parties is meaningful only for
        // the attributed form; under pairwise identifiers neither party is
        // resolvable to a member, and is not meant to be.
        "issuer": { "did": issuer_did, "is_current": issuer_current },
        "subject": { "did": subject_did, "is_current": subject_current },
        "action": "publish",
    });
    let allow = evaluate_relationships_policy(&state, &policy_input).await?;
    if !allow {
        return Err(AppError::Forbidden(
            "RelationshipPolicyDenied: active relationships.rego rejected the publish".into(),
        ));
    }

    // 8. Idempotency: same hash → same id.
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

    // 9. Store the row + secondary-index entries.
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

    // 10. Audit.
    //
    //    The actor is the **authenticated member**, not the VRC's
    //    issuer. Under the pairwise form those differ, and the
    //    issuing relationship DID names nobody — recording it as
    //    the actor would leave the trail unable to answer "which
    //    member published this edge" for anyone, at any access
    //    level, ever.
    //
    //    This is a deliberate, narrow exception to the rule that
    //    the membership-to-relationship linkage must not be
    //    persisted, and it is confined to the one store built to
    //    hold privileged records: the audit envelope HMACs the
    //    actor under a rotating key, keeps the plaintext in a
    //    field that RTBF can null without breaking the
    //    tamper-evidence chain, and is admin-gated. What #1054
    //    set out to remove was *public, permanent, unavoidable*
    //    correlation — a membership DID welded into a credential
    //    anyone can retain and republish. Accountability inside
    //    an access-controlled, redactable, tamper-evident log is
    //    a different thing, and giving it up would buy nothing:
    //    `vrc_id` resolves to the row, and the row holds the
    //    relationship DIDs, so any trail that references the edge
    //    and names the member creates the mapping regardless.
    //
    //    The residual is real and worth stating: an operator with
    //    audit access can map every pairwise edge to its member.
    //    The `info!` below deliberately does *not* carry the
    //    member — logs have neither the redaction machinery nor
    //    the access controls that make this trade defensible.
    let edge_type = vrc
        .pointer("/credentialSubject/endorsement/type")
        .and_then(|v| v.as_str())
        .unwrap_or("recognition")
        .to_string();
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &auth.did,
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

/// Reject anything that is not a conformant VRC before it becomes an edge in
/// the community's trust graph.
///
/// The VTC does not mint VRCs — they are self-issued — but it decides what
/// enters the graph, and an edge is only interpretable if it says what it is.
/// Delegates to [`crate::credentials::ingress`], the one place the DTG common
/// structure is checked, so this endpoint and every other ingress point agree
/// about what a DTG credential is.
fn check_vrc_shape(vrc: &JsonValue) -> Result<(), AppError> {
    crate::credentials::ingress::require_dtg_type(
        vrc,
        dtg_credentials::DTGCredentialType::Relationship,
        "this endpoint publishes relationship edges",
    )
}

/// `type` of the publish authorization object. Guarding on it stops a
/// signature the member made over some *other* object being replayed here as
/// authorization to publish.
const PUBLISH_AUTHORIZATION_TYPE: &str = "VrcPublishAuthorization";

/// How stale a publish authorization may be. Bounds replay inside a live
/// session; the same tolerance is allowed for clock skew in either direction.
const PUBLISH_AUTHORIZATION_MAX_AGE_SECS: i64 = 300;

/// Verify a publish authorization: proof that the caller controls the key
/// behind the VRC's `issuer`, bound to this request.
///
/// The session proves the caller is a community member. This proves the caller
/// is the issuer of the credential being published. Keeping the two separate is
/// what lets a member publish an edge under a pairwise relationship DID without
/// putting their membership DID into the credential (#1054) — the VTC learns
/// that *a* member published this edge, not which member is behind the
/// relationship DID.
///
/// Every field is load-bearing:
///
/// | field       | prevents                                              |
/// |-------------|-------------------------------------------------------|
/// | `type`      | replaying a signature made over some other object     |
/// | `vrc`       | authorizing a different credential                    |
/// | `aud`       | replaying an authorization at another community       |
/// | `sessionId` | replaying another member's authorization              |
/// | `issuedAt`  | unbounded replay within one live session              |
///
/// **The object is verified and dropped.** It carries `sessionId`, which is
/// attributable to a membership DID; persisting or logging it would rebuild
/// exactly the durable membership-to-relationship linkage that publishing under
/// a pairwise identifier exists to remove. See
/// `docs/05-design-notes/vrc-publish-proof-of-possession.md`.
async fn verify_publish_authorization(
    pop: &JsonValue,
    issuer_did: &str,
    expected_vrc_sha256: &str,
    expected_aud: &str,
    expected_session_id: &str,
    resolver: &DIDCacheClient,
) -> Result<(), String> {
    let field = |name: &str| -> Result<String, String> {
        pop.get(name)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("authorization missing `{name}`"))
    };

    let ty = field("type")?;
    if ty != PUBLISH_AUTHORIZATION_TYPE {
        return Err(format!(
            "authorization `type` must be `{PUBLISH_AUTHORIZATION_TYPE}`, got `{ty}`"
        ));
    }

    let bound_vrc = field("vrc")?;
    if bound_vrc != expected_vrc_sha256 {
        return Err("authorization is bound to a different VRC".into());
    }

    let aud = field("aud")?;
    if aud != expected_aud {
        return Err("authorization `aud` is not this community".into());
    }

    let session_id = field("sessionId")?;
    if session_id != expected_session_id {
        return Err("authorization is bound to a different session".into());
    }

    let issued_at = chrono::DateTime::parse_from_rfc3339(&field("issuedAt")?)
        .map_err(|e| format!("authorization `issuedAt` is not an RFC 3339 timestamp: {e}"))?
        .with_timezone(&Utc);
    let age = Utc::now().signed_duration_since(issued_at).num_seconds();
    if age.abs() > PUBLISH_AUTHORIZATION_MAX_AGE_SECS {
        return Err(format!(
            "authorization `issuedAt` is outside the \
             {PUBLISH_AUTHORIZATION_MAX_AGE_SECS}s freshness window (age {age}s)"
        ));
    }

    // Signed by the key the VRC's `issuer` names. `check_issuer_binding`
    // inside `verify_di_proof` is what makes this proof-of-possession rather
    // than proof-of-anything-signed.
    verify_di_proof(pop, issuer_did, resolver).await
}

/// Verify a data-integrity proof on a JSON document: bind the proof's
/// `verificationMethod` to the named controller, then let the DI library
/// resolve the key (via the shared [`DidVmResolver`]) and check the signature —
/// the same path the credential-exchange + recognition verifiers take.
///
/// Used for both the VRC itself (controller = the credential's `issuer`) and
/// the publish authorization object (controller = the same issuer, proving the
/// caller holds the key rather than merely holding the credential).
async fn verify_di_proof(
    doc: &JsonValue,
    controller_did: &str,
    resolver: &DIDCacheClient,
) -> Result<(), String> {
    let vrc = doc;
    let proof_value = vrc
        .get("proof")
        .ok_or_else(|| "document missing proof".to_string())?;
    let proof: DataIntegrityProof =
        serde_json::from_value(proof_value.clone()).map_err(|e| format!("parse proof: {e}"))?;

    let verification_method = proof_value
        .get("verificationMethod")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "proof missing verificationMethod".to_string())?;
    check_issuer_binding(verification_method, controller_did).map_err(|e| e.to_string())?;

    let mut vrc_without_proof = vrc.clone();
    if let Some(obj) = vrc_without_proof.as_object_mut() {
        obj.remove("proof");
    }

    let vm_resolver = DidVmResolver::new(Some(resolver.clone()));
    proof
        .verify(&vrc_without_proof, &vm_resolver, VerifyOptions::new())
        .await
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

// ── Connections graph (admin) ──────────────────────────────────────────────

/// One node in the connections graph — a member that is an endpoint of at least
/// one relationship (VRC). Isolated members (no VRCs) are not surfaced.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GraphNode {
    pub did: String,
}

/// One directed edge — a published VRC from `issuerDid` (the asserting member)
/// to `subjectDid`. Body-free (no VRC JSON-LD): the graph shows the shape, not
/// the credential contents.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdge {
    pub id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RelationshipsGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

/// `GET /v1/relationships/graph` — the community's member-relationship (VRC)
/// graph: every published trust edge between members, for the admin-UI
/// connections view. Admin-gated; a full scan of the relationships keyspace
/// (communities are small and this is operator-only). Edge-derived nodes —
/// members with no VRCs don't appear.
#[utoipa::path(
    get, path = "/relationships/graph", tag = "relationships",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Member-relationship graph", body = RelationshipsGraph),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn graph(
    _auth: crate::auth::AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<RelationshipsGraph>, AppError> {
    let rels = crate::relationships::list_all(&state.relationships_ks).await?;
    let mut nodes = std::collections::BTreeSet::new();
    let mut edges = Vec::with_capacity(rels.len());
    for r in rels {
        nodes.insert(r.issuer_did.clone());
        nodes.insert(r.subject_did.clone());
        edges.push(GraphEdge {
            id: r.id.to_string(),
            issuer_did: r.issuer_did,
            subject_did: r.subject_did,
            created_at: r.created_at.to_rfc3339(),
        });
    }
    Ok(Json(RelationshipsGraph {
        nodes: nodes.into_iter().map(|did| GraphNode { did }).collect(),
        edges,
    }))
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

    /// `check_vrc_shape` must accept exactly what the catalog mints as a VRC,
    /// and reject what it mints as anything else.
    ///
    /// Asserted against **catalog output** rather than a literal. A literal
    /// here could agree with the literal in `check_vrc_shape` while both
    /// disagreed with what clients actually send — the failure mode that let
    /// `VerifiableRecognitionCredential` live in this file's fixtures while no
    /// client ever emitted it, and that broke recognition in #1062 next door.
    #[test]
    fn accepts_what_the_catalog_mints_as_a_vrc_and_nothing_else() {
        use dtg_credentials::DTGCredential;

        use crate::test_support::dtg_json as body;

        let now = Utc::now();
        let vrc =
            DTGCredential::new_vrc("did:peer:2.zR1".into(), "did:peer:2.zR2".into(), now, None);
        check_vrc_shape(&body(&vrc)).expect("a catalog-minted VRC must be publishable");

        // Same catalog, different subtype — this endpoint publishes
        // relationship edges, and a membership edge has different issuance
        // rules.
        let vmc = DTGCredential::new_vmc(
            "did:web:community.example".into(),
            "did:key:zMember".into(),
            now,
            None,
            false,
        );
        let err = check_vrc_shape(&body(&vmc)).expect_err("a VMC must not publish as a VRC");
        assert!(
            format!("{err:?}").contains("relationship edges"),
            "unexpected rejection: {err:?}"
        );
    }

    #[test]
    fn canonicalise_is_key_order_stable() {
        let a = json!({ "b": 1, "a": 2, "c": { "y": 5, "x": 4 } });
        let b = json!({ "a": 2, "c": { "x": 4, "y": 5 }, "b": 1 });
        assert_eq!(canonicalise(&a), canonicalise(&b));
    }
}
