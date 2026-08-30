//! VRC (Verifiable Relationship Credential) graph endpoints
//! — Phase 4 M4.6. Spec §5.4 + §6.1; planning-review D1
//! (issuer is the *member*, not the community).
//!
//! ## Four endpoints
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
//!    (admin can also revoke for moderation). Authorized the
//!    same three ways publication is: session DID equals the
//!    row's issuer, admin, or a `VrcRevokeAuthorization`
//!    proving control of a pairwise issuer. Deletes the row
//!    plus secondary-index entries; emits `VrcRevoked`. Per
//!    D7, VRCs carry no `credentialStatus`; revocation is row
//!    deletion, not a status-list bit flip.
//!
//! 4. `POST` / `DELETE /v1/relationships/{id}/persona` —
//!    attach or withdraw a VPC (persona credential) on an
//!    edge that already exists. See [`attach_persona`] for the
//!    binding argument and for what upstream has not settled.

use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;

use crate::credentials::vm_resolver::{DidVmResolver, check_issuer_binding};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use tracing::info;
use trust_tasks_rs::TrustTask as TrustTaskDoc;
use uuid::Uuid;
use vti_common::audit::{
    AuditEvent, VpcAnnotationData, VrcLifecycleData, VrcPublishedData, VrcRevokedData,
    VrcSupersededData,
};
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
    pub vrc_digest_multibase: String,
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
    State(state): State<AppState>,
    Json(doc): Json<TrustTaskDoc<JsonValue>>,
) -> Result<(StatusCode, Json<TrustTaskDoc<PublishResponse>>), AppError> {
    let now = Utc::now();
    let vtc_did = crate::routes::recognise::vtc_did(&state).await?;

    // 0. Framework validation, before anything task-specific:
    //    expiry, audience binding, and the spec's own policy
    //    (SPEC §7.2). A document that fails here is malformed as
    //    a Trust Task, whatever its payload says.
    doc.validate_basic(now, &vtc_did)
        .map_err(|e| AppError::Validation(format!("malformed Trust Task document: {e}")))?;

    // 0b. The document's proof authenticates this request. There is
    //     no bearer token on this route.
    //
    //     A proof is the better answer to "who is calling": it is
    //     transport-independent, and unlike a token it cannot be
    //     used by whoever captured it. What a session gave that a
    //     proof does not is *immediate revocation* — a signed-out
    //     session stops working on the next request, where a proof
    //     has no such handle. Publishing is therefore governed by
    //     ACL membership rather than session state, which is the
    //     deliberate consequence: a member who has signed out but
    //     not been removed is still a member, and it is not obvious
    //     they should be barred from publishing an edge they hold
    //     the key for. Removing them from the community does stop
    //     them immediately, because `is_current_member` reads the
    //     ACL live.
    let signer_did = vti_common::auth::di_proof::verify_trust_task_proof_with(
        &doc,
        &state.trust_task_vm_resolver(),
    )
    .await
    .map_err(|e| AppError::Forbidden(format!("document proof: {e}")))?;

    // 0c. Per-DID rate limiting, keyed on the HMAC of the signer
    //     rather than the DID itself — the discipline the audit
    //     writer already applies, so the counter does not double as
    //     a live register of who is active in this community.
    //
    //     It runs *after* proof verification, because the DID does
    //     not exist until the proof is checked; it therefore cannot
    //     bound the cost of verification. That is the per-IP
    //     governor's job, and this route now sits behind it. Two
    //     different controls: one protects the server from anonymous
    //     load, this protects the graph from an admitted member.
    enforce_publish_rate_limit(&state, &signer_did).await?;

    let body: PublishBody = serde_json::from_value(doc.payload.clone())
        .map_err(|e| AppError::Validation(format!("invalid publish payload: {e}")))?;

    // 1. Parse the VC's core fields without going through the
    //    typed `VerifiableCredential` — VRCs carry a few
    //    extensions the typed parser doesn't know about, and
    //    we want to store the JSON-LD verbatim either way.
    let vrc = &body.vrc;
    let issuer_did = extract_did_field(vrc, "issuer")?;
    let subject_did = extract_subject_id(vrc)?;

    // 2. Shape + validity window: is this even a relationship
    //    credential, and is it in date? Checked before anything
    //    expensive, and before authorization, because a
    //    malformed or expired body is a 400 whoever sent it.
    //
    //    `now` was read once at the top of the handler, so every
    //    check in this request evaluates at one instant.
    check_vrc_shape(vrc, now)?;

    // 3. Cheapest authorization gate first: a VRC issued under a
    //    DID that is not the session's must carry a publish
    //    authorization. Rejecting here keeps a caller error a
    //    caller error — the daemon-config prerequisites below
    //    would otherwise mask it with a 500.
    if body.pop.is_none() && issuer_did != signer_did {
        return Err(AppError::Forbidden(format!(
            "VRC issuer ({issuer_did}) is not the document signer and no publish \
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
    let vrc_digest_multibase = crate::credentials::ingress::digest_multibase(vrc)?;

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
    let identifier_form = match (&body.pop, issuer_did == signer_did) {
        (Some(pop), _) => {
            let vrc_digest = crate::credentials::ingress::digest_multibase(vrc)?;
            verify_publish_authorization(pop, &issuer_did, &doc.id, &vrc_digest, &resolver)
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
                "VRC issuer is not the document signer and no publish \
                 authorization (`pop`) was supplied"
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
    let member_current = is_current_member(&state, &signer_did).await?;
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
        "authenticated_member": { "did": signer_did, "is_current": member_current },
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
    if let Some(existing) = find_by_hash(&state.relationships_ks, &vrc_digest_multibase).await? {
        // A response is itself a Trust Task document: `respond_with` swaps
        // issuer and recipient, stamps the `#response` type, and carries the
        // request's `threadId` (or its `id` when it had none) so the two
        // halves of the exchange correlate — SPEC §4.4.1, §4.9.
        return Ok((
            StatusCode::OK,
            Json(doc.respond_with(
                Uuid::new_v4().to_string(),
                PublishResponse {
                    id: existing.id,
                    issuer_did: existing.issuer_did,
                    subject_did: existing.subject_did,
                    vrc_digest_multibase: existing.vrc_digest_multibase,
                },
            )),
        ));
    }

    // 9. Store the row + secondary-index entries.
    let id = Uuid::new_v4();
    let rel = Relationship {
        id,
        issuer_did: issuer_did.clone(),
        subject_did: subject_did.clone(),
        vrc_jsonld: vrc.clone(),
        vrc_digest_multibase: vrc_digest_multibase.clone(),
        created_at: Utc::now(),
        // A persona is asserted separately, against an edge that already
        // exists — see [`attach_persona`].
        persona: None,
        // A freshly published edge has had nothing recorded against it. Every
        // later state — suspended, restored, superseded, withdrawn — is an
        // append to this log, never a mutation of the row's other fields.
        lifecycle: crate::relationships::LifecycleLog::default(),
    };
    store_relationship(
        &state.relationships_ks,
        &state.relationships_by_did_ks,
        &rel,
    )
    .await?;

    // 9b. A VRC to a counterparty this issuer already has an edge to is a new
    //     version of one assertion, not a second relationship — DTG
    //     Credentials makes an R-DID unique per counterparty, so the pair
    //     *is* the relationship. Record the displacement on the earlier rows
    //     so the graph can say which one the issuer currently stands behind.
    //
    //     After the store, not before: superseding first and then failing to
    //     write the replacement would leave the issuer with no edge at all,
    //     where this ordering's worst case is a brief window in which both
    //     stand. The redundant-but-live reading is the safe one.
    //
    //     The idempotent-publish branch above returns before reaching here, so
    //     re-sending the identical credential cannot supersede its own row.
    let superseded = crate::relationships::supersede_prior_edges(
        &state.relationships_ks,
        &state.relationships_by_did_ks,
        &issuer_did,
        &subject_did,
        id,
        &vrc_digest_multibase,
        now,
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
                // The proven signer, which is now what "the member" means on
                // this route.
                &signer_did,
                Some(&subject_did),
                AuditEvent::VrcPublished(VrcPublishedData {
                    vrc_id: id.to_string(),
                    subject_did: Some(subject_did.clone()),
                    edge_type,
                }),
            )
            .await?;
    }

    // Supersession is a lifecycle change to an edge the community already
    // held, so it is audited in its own right rather than folded into the
    // publish entry — an operator asking "what happened to edge X" must find
    // the answer under X, not under the credential that replaced it.
    if let Some(writer) = state.audit_writer.as_ref() {
        for displaced in &superseded {
            writer
                .write(
                    &signer_did,
                    Some(&subject_did),
                    AuditEvent::VrcSuperseded(VrcSupersededData {
                        vrc_id: displaced.to_string(),
                        superseded_by_digest_multibase: vrc_digest_multibase.clone(),
                    }),
                )
                .await?;
        }
    }

    info!(
        vrc_id = %id,
        issuer = %issuer_did,
        subject = %subject_did,
        superseded = superseded.len(),
        "VRC published"
    );

    Ok((
        StatusCode::CREATED,
        Json(doc.respond_with(
            Uuid::new_v4().to_string(),
            PublishResponse {
                id,
                issuer_did,
                subject_did,
                vrc_digest_multibase,
            },
        )),
    ))
}

// ─── Revoke ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RevokeResponse {
    pub id: String,
}

/// `type` of the revoke authorization. Distinct from the publish type so the
/// authorization a member signs every time they lodge an edge cannot be
/// replayed to delete it.
const REVOKE_AUTHORIZATION_TYPE: &str = "VrcRevokeAuthorization";

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub struct RevokeBody {
    /// Proof that the caller controls the key behind the row's `issuerDid`,
    /// when that is not the caller's session DID — i.e. for every edge
    /// published under a pairwise relationship DID.
    ///
    /// Bound to the row `id` rather than to a credential, because `DELETE
    /// /v1/relationships/{id}` names the row and carries no credential to
    /// bind to.
    #[serde(default)]
    pub pop: Option<JsonValue>,
}

/// `DELETE /v1/relationships/{id}` — retract an edge.
///
/// ## Why there is a body here at all
///
/// `revoke` kept the identity equality that `publish` replaced in #1054/#1061:
/// `auth.did == rel.issuer_did`. For an edge published under a pairwise
/// relationship DID that compares a membership DID against an R-DID and is
/// false by construction, so a member could lodge an edge and then never take
/// it back — only an admin could. The property the equality was standing in
/// for is *control of the issuing key*, and once the identifier stopped being
/// the member's own, only a proof can establish it.
///
/// Three routes to authorization, and the first two are exactly as before:
///
/// - **attributed** — `auth.did == rel.issuer_did`. Still correct, still
///   sufficient, no proof needed. The session already demonstrates control of
///   that key.
/// - **admin** — moderation, keyed on the row id and not on issuer identity.
///   Unchanged.
/// - **pairwise** — a `VrcRevokeAuthorization` signed by the row's
///   `issuerDid`, bound to this row, this community, this session and this
///   moment. New.
///
/// Like the publish authorization, **it is verified and discarded** — never
/// stored, logged or audited. It carries `sessionId`, which is attributable to
/// a membership DID, and this handler writes to the audit store, so it is the
/// one place on the pairwise path where that linkage could plausibly become
/// durable. See `docs/05-design-notes/vrc-publish-proof-of-possession.md`.
#[utoipa::path(
    delete, path = "/relationships/{id}",
    operation_id = "relationshipRevoke", tag = "relationships",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Relationship (VRC) id")),
    request_body(content = RevokeBody, description = "Optional. Required only \
        for an edge issued under a pairwise relationship DID."),
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
    // Optional: every client sending this request today sends no body at all,
    // and must keep working. `Option<Json<_>>` yields `None` when there is no
    // JSON content-type, and still rejects a malformed body when there is.
    body: Option<Json<RevokeBody>>,
) -> Result<(StatusCode, Json<RevokeResponse>), AppError> {
    let rel = get_relationship(&state.relationships_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("VRC {id} not found")))?;

    let pop = body.and_then(|Json(b)| b.pop);
    let revoked_by = authorize_edge_control(
        &state,
        &auth,
        &rel,
        id,
        pop.as_ref(),
        REVOKE_AUTHORIZATION_TYPE,
        "revoke",
    )
    .await?;

    delete_relationship(&state.relationships_ks, &state.relationships_by_did_ks, id).await?;

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

/// Establish that the caller may change the state of an existing edge, and
/// report which of the two capacities they acted in.
///
/// Extracted from [`revoke`] when suspension and restoration arrived, because
/// all three verbs answer the identical question — *does this caller control
/// this edge* — and three copies of a three-branch authorization check is
/// exactly how the ingress-window check ended up implemented three different
/// ways and enforced on one path (#1069). The verb differs only in the
/// authorization `type` it will accept, which is a parameter.
///
/// Three routes, in the order the publish path documents (caller errors before
/// daemon-config prerequisites):
///
/// - **attributed** — the session DID is the row's issuer. The session already
///   demonstrates control of that key; no proof is needed.
/// - **admin** — moderation, keyed on the row id and not on issuer identity.
/// - **pairwise** — an authorization signed by the row's `issuerDid`, bound to
///   this edge, this community, this session. For an edge published under a
///   relationship DID this is the *only* route, because the session DID is an
///   M-DID and the comparison is false by construction.
///
/// The authorization is verified and discarded — never stored, logged or
/// audited. It carries `sessionId`, which is attributable to a membership DID,
/// and these handlers write to the audit store, so this is the one place on
/// the pairwise path where that linkage could plausibly become durable. See
/// `docs/05-design-notes/vrc-publish-proof-of-possession.md`.
///
/// `authorization_type` must be distinct per verb: a signature the member made
/// to suspend an edge must not be replayable to delete it.
///
/// Returns `"issuer"` or `"admin"` for the audit trail. Proving control of the
/// issuing key *is* being the issuer — recording it as an admin action would
/// misattribute a member's own decision in the one trail an operator uses to
/// answer who did what.
async fn authorize_edge_control(
    state: &AppState,
    auth: &AuthClaims,
    rel: &Relationship,
    id: Uuid,
    pop: Option<&JsonValue>,
    authorization_type: &str,
    verb: &str,
) -> Result<&'static str, AppError> {
    let is_issuer = auth.did == rel.issuer_did;
    let is_admin = auth.role == vti_common::acl::Role::Admin;

    // Cheapest gate first, before the resolver is touched: with none of the
    // three routes available this is a caller error, and reaching the
    // daemon-config prerequisite below would report it as a 500.
    if !is_issuer && !is_admin && pop.is_none() {
        return Err(AppError::Forbidden(format!(
            "only the issuer or an admin can {verb} a VRC — an edge issued \
             under a relationship DID needs an authorization (`pop`) proving \
             control of it"
        )));
    }

    // A supplied authorization must verify, whoever supplied it. Accepting a
    // request that carried an authorization we then ignored would make the
    // failure of a *bad* one indistinguishable from success.
    let mut proved_control = false;
    if let Some(pop) = pop {
        let resolver = state.did_resolver.as_ref().cloned().ok_or_else(|| {
            AppError::Internal(format!(
                "DID resolver not configured — a VRC {verb} authorization requires it"
            ))
        })?;
        let aud = crate::routes::recognise::vtc_did(state).await?;
        check_authorization_envelope(pop, authorization_type, &aud, &auth.session_id)
            .and_then(|()| {
                let edge = authorization_field(pop, "relationship")?;
                if edge != id.to_string() {
                    return Err("authorization is bound to a different edge".into());
                }
                Ok(())
            })
            .map_err(|e| AppError::Forbidden(format!("{authorization_type}Invalid: {e}")))?;
        verify_di_proof(pop, &rel.issuer_did, &resolver)
            .await
            .map_err(|e| AppError::Forbidden(format!("{authorization_type}Invalid: {e}")))?;
        proved_control = true;
    }

    Ok(if is_issuer || proved_control {
        "issuer"
    } else {
        "admin"
    })
}

// ─── Suspend / restore ───────────────────────────────────
//
// The two verbs #1079 says the graph has no vocabulary for. Until they
// existed, an edge had exactly two states — published and deleted — so a
// community with a reason to stop relying on an edge *temporarily* had to
// destroy it, and the member had to re-issue and re-publish to get it back.
// That is not a smaller version of revocation; it is a different act, and
// collapsing the two is what makes "suspended" unrepresentable.
//
// Neither verb touches the credential. The VRC's signature, its window and
// its digest are all unchanged — what changes is what this community records
// against it, and `credentials::lifecycle` states once how the two combine.
// That separation is what lets suspension exist at all for a credential type
// that deliberately carries no `credentialStatus` (planning-review D7).

/// The two verbs [`record_edge_lifecycle`] serves.
///
/// An enum rather than a bundle of `&str` parameters because the three things
/// that vary — the authorization `type` accepted, the event appended, and the
/// audit variant emitted — must vary *together*. Passing them separately is
/// how a handler ends up accepting a restore authorization and recording a
/// suspension, and nothing about the types would object.
#[derive(Debug, Clone, Copy)]
enum EdgeLifecycleVerb {
    Suspend,
    Restore,
}

impl EdgeLifecycleVerb {
    /// `type` of the authorization object this verb will accept. Distinct per
    /// verb — and distinct from revocation's — so a signature made to suspend
    /// an edge cannot be replayed to restore or delete it.
    fn authorization_type(self) -> &'static str {
        match self {
            Self::Suspend => "VrcSuspendAuthorization",
            Self::Restore => "VrcRestoreAuthorization",
        }
    }

    /// The verb as it appears in a rejection message.
    fn as_str(self) -> &'static str {
        match self {
            Self::Suspend => "suspend",
            Self::Restore => "restore",
        }
    }

    fn event(self, reason: Option<String>) -> crate::relationships::LifecycleEventKind {
        match self {
            Self::Suspend => crate::relationships::LifecycleEventKind::Suspended { reason },
            Self::Restore => crate::relationships::LifecycleEventKind::Restored { reason },
        }
    }

    fn audit(self, data: VrcLifecycleData) -> AuditEvent {
        match self {
            Self::Suspend => AuditEvent::VrcSuspended(data),
            Self::Restore => AuditEvent::VrcRestored(data),
        }
    }
}

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub struct LifecycleBody {
    /// Proof that the caller controls the key behind the row's `issuerDid`,
    /// when that is not the caller's session DID — i.e. for every edge
    /// published under a pairwise relationship DID. Verified by the same
    /// `authorize_edge_control` gate revocation uses, with a `type` distinct
    /// to this verb.
    #[serde(default)]
    pub pop: Option<JsonValue>,
    /// Optional operator- or member-supplied note, stored verbatim on the
    /// event.
    ///
    /// Recorded because a suspension a reader cannot interpret is close to
    /// useless: "temporarily ineffective, cause unstated" gives the
    /// counterparty nothing to act on. It is deliberately free text and
    /// deliberately optional — the state machine never reads it.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct LifecycleResponse {
    pub id: Uuid,
    /// The edge's resolved state after the event, as
    /// [`crate::credentials::lifecycle::resolve`] computes it.
    ///
    /// The *resolved* state, not the event that was just recorded, because
    /// those are not the same thing and the difference is the point of the
    /// precedence rule: restoring an edge whose `validUntil` has passed
    /// records a restoration and still answers `expired`.
    pub state: crate::relationships::InForce,
}

/// `POST /v1/relationships/{id}/suspend` — make an edge temporarily
/// ineffective without withdrawing it.
///
/// Authorized exactly as revocation is (issuer session DID, admin, or a
/// `VrcSuspendAuthorization` proving control of a pairwise issuer), because it
/// is the same question about the same edge. It is not, however, the same
/// *act*: revocation deletes the row and is unrecoverable, while this appends
/// an event and leaves a supported way back.
///
/// Refused with a 409 if the edge is already suspended, or if it has been
/// superseded or withdrawn. Those are conflicts rather than validation errors
/// — the request is well-formed and the caller is entitled to make it; it is
/// the edge's state that refuses, and for a suspension a retry after a
/// restoration would succeed.
#[utoipa::path(
    post, path = "/relationships/{id}/suspend", tag = "relationships",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Relationship (VRC) id")),
    request_body(content = LifecycleBody, description = "Optional. `pop` is \
        required only for an edge issued under a pairwise relationship DID."),
    responses(
        (status = 200, description = "Relationship suspended", body = LifecycleResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not the issuer or an admin"),
        (status = 404, description = "Relationship not found"),
        (status = 409, description = "Edge is already suspended, superseded or withdrawn"),
    ),
)]
pub async fn suspend(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    body: Option<Json<LifecycleBody>>,
) -> Result<(StatusCode, Json<LifecycleResponse>), AppError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    record_edge_lifecycle(auth, state, id, body, EdgeLifecycleVerb::Suspend).await
}

/// `POST /v1/relationships/{id}/restore` — reverse a suspension.
///
/// Reverses a suspension and nothing else. An edge that has expired, been
/// superseded or been withdrawn is refused with a 409, and the boundary is
/// deliberate — see the module doc of [`crate::credentials::lifecycle`] on
/// restoration versus replacement. Restoring an edge whose `validUntil` passed
/// while it was suspended *succeeds* (the suspension is genuinely reversed)
/// and the response reports `expired`, because a recorded event cannot extend
/// a window the issuer signed.
#[utoipa::path(
    post, path = "/relationships/{id}/restore", tag = "relationships",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Relationship (VRC) id")),
    request_body(content = LifecycleBody, description = "Optional. `pop` is \
        required only for an edge issued under a pairwise relationship DID."),
    responses(
        (status = 200, description = "Suspension reversed", body = LifecycleResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not the issuer or an admin"),
        (status = 404, description = "Relationship not found"),
        (status = 409, description = "Edge is not suspended"),
    ),
)]
pub async fn restore(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    body: Option<Json<LifecycleBody>>,
) -> Result<(StatusCode, Json<LifecycleResponse>), AppError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    record_edge_lifecycle(auth, state, id, body, EdgeLifecycleVerb::Restore).await
}

/// The shared spine of [`suspend`] and [`restore`]: load, authorize, append,
/// audit, report the resolved state.
///
/// One function rather than two near-identical handlers because everything
/// except the verb is common, and the ordering *is* the security property —
/// authorize before touching the log, and read `now` once so the appended
/// event and the state reported back cannot straddle two instants.
async fn record_edge_lifecycle(
    auth: AuthClaims,
    state: AppState,
    id: Uuid,
    body: LifecycleBody,
    verb: EdgeLifecycleVerb,
) -> Result<(StatusCode, Json<LifecycleResponse>), AppError> {
    let now = Utc::now();
    let rel = get_relationship(&state.relationships_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("VRC {id} not found")))?;

    let actor = authorize_edge_control(
        &state,
        &auth,
        &rel,
        id,
        body.pop.as_ref(),
        verb.authorization_type(),
        verb.as_str(),
    )
    .await?;

    let updated = crate::relationships::record_lifecycle_event(
        &state.relationships_ks,
        &state.relationships_by_did_ks,
        id,
        verb.event(body.reason.clone()),
        now,
    )
    .await?;

    // The actor is the authenticated member, not the edge's issuer, for the
    // reason the publish and persona trails record it that way: under a
    // pairwise identifier the issuer names nobody, so a trail keyed on it
    // could never answer who changed this edge's state.
    if let Some(writer) = state.audit_writer.as_ref() {
        let event = verb.audit(VrcLifecycleData {
            vrc_id: id.to_string(),
            recorded_by: actor.into(),
            reason: body.reason,
        });
        writer
            .write(&auth.did, Some(&updated.subject_did), event)
            .await?;
    }

    info!(vrc_id = %id, actor, verb = verb.as_str(), "VRC lifecycle event recorded");

    Ok((
        StatusCode::OK,
        Json(LifecycleResponse {
            id,
            state: updated.in_force_at(now),
        }),
    ))
}

// ─── Persona annotation (VPC) ────────────────────────────
//
// DTG Credentials §Annotation Credentials: a VPC creates no
// graph structure, it annotates structure that already exists.
// So there is no "publish a VPC" — there is only "attach this
// persona to that edge", which is why both verbs sit under
// `/v1/relationships/{id}/persona` rather than on a collection
// of their own.
//
// What the VPC is *for* (§Privacy Considerations 3): correlation
// across relationships should happen only through the holder's
// deliberate assertion of a persona or an M-DID, "never as a
// side effect of credential structure". Before this existed the
// VTC offered a member exactly two settings — publish under a
// pairwise R-DID and be correlatable with nothing, or publish
// under the M-DID and be correlatable with everything. The VPC
// is the third: correlate these edges, under this name, because
// I chose to.

/// `type` of the attach authorization. Distinct from the detach type so an
/// attach authorization cannot be replayed to remove a persona, or vice versa.
const VPC_ATTACH_AUTHORIZATION_TYPE: &str = "VpcAttachAuthorization";

/// `type` of the detach authorization.
const VPC_DETACH_AUTHORIZATION_TYPE: &str = "VpcDetachAuthorization";

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AttachPersonaBody {
    /// The self-issued VPC, in the DTG Credentials wire form:
    /// `type` including `PersonaCredential`, `issuer` the P-DID
    /// of the persona, `credentialSubject.id` the counterparty's
    /// DID, and a data-integrity proof. Built by
    /// `dtg_credentials::DTGCredential::new_vpc`.
    pub vpc: JsonValue,
    /// Proof that the caller controls the key behind the edge's
    /// `issuerDid`, when that is not the caller's session DID.
    /// Required for every pairwise edge, since a relationship
    /// DID is never the session DID by construction.
    #[serde(default)]
    pub pop: Option<JsonValue>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct DetachPersonaBody {
    /// As for [`AttachPersonaBody::pop`], with
    /// `type: "VpcDetachAuthorization"` and no `vpc` field.
    #[serde(default)]
    pub pop: Option<JsonValue>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct PersonaResponse {
    pub id: Uuid,
    /// The P-DID now on the edge, or `null` after a detach.
    pub persona_did: Option<String>,
}

/// `POST /v1/relationships/{id}/persona` — attach a VPC to a published edge,
/// asserting that the party behind the edge's `issuerDid` is this persona.
///
/// ## How the VPC is bound to the edge — and what is assumed
///
/// **This is the part trustoverip/dtgwg-cred-spec#9 has not settled.** A VPC
/// names its persona (`issuer`) and the counterparty (`credentialSubject.id`).
/// It does *not* name the relationship DID the persona used, so a VPC on its
/// own does not identify an edge, and nothing in the current specification
/// says how it should.
///
/// Rather than invent a credential-level binding and present it as settled,
/// the binding here is made at the *request* level, out of three parts:
///
/// 1. the caller names the edge, by id, in the URL;
/// 2. the caller proves control of that edge's `issuerDid` — the same
///    proof-of-possession construction publishing the edge required
///    (`docs/05-design-notes/vrc-publish-proof-of-possession.md`);
/// 3. the VPC's `credentialSubject.id` must equal the edge's `subjectDid`.
///
/// (2) is what makes it safe: the only party who could have published this
/// edge is the only party who can annotate it, so attaching a persona is
/// exactly as authorized as publishing the edge was. (3) is a consistency
/// check, not a binding — it rules out attaching a persona asserted to some
/// *other* counterparty. Nothing is added to the VPC and no claim is made
/// about how the specification should resolve #9; if it lands an in-credential
/// binding (a `digest` over the VRC, as the VWC has), this endpoint can
/// require that as well without changing the stored shape.
///
/// **Known limitation of (3).** DTG Credentials says the VPC's subject is
/// "typically the R-DID or M-DID used in the relationship". A VPC whose
/// subject is the counterparty's *M-DID*, on an edge whose `subjectDid` is
/// their *R-DID*, is rejected here. That case is real and this endpoint
/// cannot presently accept it — resolving it needs the same #9 answer.
///
/// ## The persona is the edge issuer's
///
/// One VRC is one direction of an edge, and the persona it carries belongs to
/// the party who issued it. The counterparty asserts their own persona on
/// their own reciprocal VRC. This keeps each half-edge self-contained and
/// means neither party can put words in the other's mouth.
#[utoipa::path(
    post, path = "/relationships/{id}/persona", tag = "relationships",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Relationship (VRC) id")),
    request_body = AttachPersonaBody,
    responses(
        (status = 200, description = "Persona (VPC) attached", body = PersonaResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller does not control the edge's issuer"),
        (status = 404, description = "Relationship not found"),
    ),
)]
pub async fn attach_persona(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<AttachPersonaBody>,
) -> Result<(StatusCode, Json<PersonaResponse>), AppError> {
    let mut rel = get_relationship(&state.relationships_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("VRC {id} not found")))?;

    // Shape and validity window first: a malformed or expired VPC is a 400
    // whoever sent it, and rejecting it here costs nothing and reveals nothing
    // about the edge.
    //
    // The window is checked for the same reason it is on the publish path — an
    // annotation that outlives its own credential would keep asserting a
    // persona the issuer had stopped standing behind. `now` is read once and
    // passed in so every check in this request evaluates at one instant.
    let now = Utc::now();
    check_vpc_shape(&body.vpc, now)?;
    let persona_did = extract_did_field(&body.vpc, "issuer")?;
    let vpc_subject = extract_subject_id(&body.vpc)?;

    // Then authorization, before anything that could read the edge back to
    // the caller. Edge ids are unguessable UUIDs, but a member who has seen
    // one should still learn nothing from this endpoint about an edge they do
    // not control — which is why neither this error nor the consistency check
    // below quotes the row's DIDs. Same ordering rule as publish: caller
    // errors before daemon-config prerequisites, and disclosure last.
    if body.pop.is_none() && rel.issuer_did != auth.did {
        return Err(AppError::Forbidden(format!(
            "edge {id} was not issued by the session DID and no authorization \
             (`pop`) was supplied — annotating an edge published under a \
             relationship DID requires proof the caller controls it"
        )));
    }

    let resolver = state.did_resolver.as_ref().cloned().ok_or_else(|| {
        AppError::Internal("DID resolver not configured — VPC attach requires it".into())
    })?;

    // The VPC was made by the persona it names. This is the analogue of the
    // VRC's own proof check, and it holds whatever kind of identifier the
    // P-DID is.
    verify_di_proof(&body.vpc, &persona_did, &resolver)
        .await
        .map_err(|e| AppError::Validation(format!("VpcProofInvalid: {e}")))?;

    if let Some(pop) = &body.pop {
        let aud = crate::routes::recognise::vtc_did(&state).await?;
        // Same digest form as the publish authorization and the stored row:
        // RFC 8785, multihash, base58btc. This was a bare hex SHA-256 over a
        // recursive key sort, which no second implementation could reproduce
        // from a specification.
        let vpc_digest = crate::credentials::ingress::digest_multibase(&body.vpc)?;
        check_authorization_envelope(pop, VPC_ATTACH_AUTHORIZATION_TYPE, &aud, &auth.session_id)
            .and_then(|()| {
                let bound = authorization_field(pop, "vpcDigestMultibase")?;
                if bound != vpc_digest {
                    return Err("authorization is bound to a different VPC".into());
                }
                let edge = authorization_field(pop, "relationship")?;
                if edge != id.to_string() {
                    return Err("authorization is bound to a different edge".into());
                }
                Ok(())
            })
            .map_err(|e| AppError::Forbidden(format!("VpcAttachAuthorizationInvalid: {e}")))?;
        verify_di_proof(pop, &rel.issuer_did, &resolver)
            .await
            .map_err(|e| AppError::Forbidden(format!("VpcAttachAuthorizationInvalid: {e}")))?;
    }

    if vpc_subject != rel.subject_did {
        return Err(AppError::Validation(format!(
            "VPC names {vpc_subject} as the counterparty but edge {id} points at \
             a different DID — a persona is asserted to the party the edge names"
        )));
    }

    // No uniqueness check on the P-DID, deliberately, and in direct contrast
    // to the R-DID rule the publish path enforces. A relationship DID that
    // recurs across counterparties is a defect; a persona DID that recurs is
    // the entire point of the credential.
    rel.persona = Some(crate::relationships::PersonaAnnotation {
        persona_did: persona_did.clone(),
        vpc_jsonld: body.vpc.clone(),
        attached_at: Utc::now(),
    });
    store_relationship(
        &state.relationships_ks,
        &state.relationships_by_did_ks,
        &rel,
    )
    .await?;

    audit_persona_change(&state, &auth.did, &rel, id, &persona_did, true).await?;
    info!(vrc_id = %id, persona = %persona_did, "VPC attached");

    Ok((
        StatusCode::OK,
        Json(PersonaResponse {
            id,
            persona_did: Some(persona_did),
        }),
    ))
}

/// `DELETE /v1/relationships/{id}/persona` — withdraw the persona from an
/// edge, leaving the edge itself in place.
///
/// This exists because the assertion it reverses is a disclosure. A member who
/// can correlate their edges under a persona but can never stop is worse off
/// than one who never could, so the withdrawal has to be as available as the
/// assertion — and gated the same way, or anyone could strip another member's
/// persona.
///
/// Idempotent: detaching from an edge that carries no persona is a 200 with a
/// null `personaDid`, matching `delete_relationship`'s convention. No audit
/// entry is written in that case — nothing changed.
///
/// The authorization object is carried in the request body. `DELETE` with a
/// body is unusual, but the alternative is putting a signed object in a query
/// string, and the proof of control has to travel with the request somehow.
#[utoipa::path(
    delete, path = "/relationships/{id}/persona", tag = "relationships",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Relationship (VRC) id")),
    request_body = DetachPersonaBody,
    responses(
        (status = 200, description = "Persona (VPC) detached", body = PersonaResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller does not control the edge's issuer"),
        (status = 404, description = "Relationship not found"),
    ),
)]
pub async fn detach_persona(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<DetachPersonaBody>,
) -> Result<(StatusCode, Json<PersonaResponse>), AppError> {
    let mut rel = get_relationship(&state.relationships_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("VRC {id} not found")))?;

    if body.pop.is_none() && rel.issuer_did != auth.did {
        return Err(AppError::Forbidden(format!(
            "edge {id} was not issued by the session DID and no authorization \
             (`pop`) was supplied"
        )));
    }

    if let Some(pop) = &body.pop {
        let resolver = state.did_resolver.as_ref().cloned().ok_or_else(|| {
            AppError::Internal("DID resolver not configured — VPC detach requires it".into())
        })?;
        let aud = crate::routes::recognise::vtc_did(&state).await?;
        check_authorization_envelope(pop, VPC_DETACH_AUTHORIZATION_TYPE, &aud, &auth.session_id)
            .and_then(|()| {
                let edge = authorization_field(pop, "relationship")?;
                if edge != id.to_string() {
                    return Err("authorization is bound to a different edge".into());
                }
                Ok(())
            })
            .map_err(|e| AppError::Forbidden(format!("VpcDetachAuthorizationInvalid: {e}")))?;
        verify_di_proof(pop, &rel.issuer_did, &resolver)
            .await
            .map_err(|e| AppError::Forbidden(format!("VpcDetachAuthorizationInvalid: {e}")))?;
    }

    let Some(previous) = rel.persona.take() else {
        return Ok((
            StatusCode::OK,
            Json(PersonaResponse {
                id,
                persona_did: None,
            }),
        ));
    };
    store_relationship(
        &state.relationships_ks,
        &state.relationships_by_did_ks,
        &rel,
    )
    .await?;

    audit_persona_change(&state, &auth.did, &rel, id, &previous.persona_did, false).await?;
    info!(vrc_id = %id, persona = %previous.persona_did, "VPC detached");

    Ok((
        StatusCode::OK,
        Json(PersonaResponse {
            id,
            persona_did: None,
        }),
    ))
}

/// Write the `VpcAttached` / `VpcDetached` audit entry.
///
/// The actor is the **authenticated member**, not the edge's issuer, for the
/// same reason the VRC publish trail records it that way: under a pairwise
/// identifier the issuer names nobody, so a trail keyed on it could never
/// answer "who asserted this persona". Recording the P-DID beside the member
/// does create an M-DID-to-P-DID mapping inside the audit store — accepted, on
/// the same reasoning set out in
/// `docs/05-design-notes/vrc-publish-proof-of-possession.md` §Audit
/// attribution, and confined to the same store. The `info!` above deliberately
/// carries the persona and not the member.
async fn audit_persona_change(
    state: &AppState,
    actor_did: &str,
    rel: &Relationship,
    id: Uuid,
    persona_did: &str,
    attached: bool,
) -> Result<(), AppError> {
    let Some(writer) = state.audit_writer.as_ref() else {
        return Ok(());
    };
    let data = VpcAnnotationData {
        vrc_id: id.to_string(),
        persona_did: persona_did.to_string(),
    };
    let event = if attached {
        AuditEvent::VpcAttached(data)
    } else {
        AuditEvent::VpcDetached(data)
    };
    writer
        .write(actor_did, Some(&rel.subject_did), event)
        .await?;
    Ok(())
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

/// Reject anything that is not a conformant, currently-valid VRC before it
/// becomes an edge in the community's trust graph.
///
/// The VTC does not mint VRCs — they are self-issued — but it decides what
/// enters the graph, and an edge is only interpretable if it says what it is.
/// Delegates to [`crate::credentials::ingress`], the one place the DTG common
/// structure and the validity window are checked, so this endpoint and every
/// other ingress point agree about what a DTG credential is and about when it
/// is in date.
///
/// Until #1069 this path read neither `validFrom` nor `validUntil`, so a VRC
/// that had already expired became a permanent edge — permanent because the
/// graph is read without re-checking dates, and because per D7 a VRC has no
/// `credentialStatus` to retract it with. The only removal is the issuer (or an
/// admin) calling `DELETE /v1/relationships/{id}`.
fn check_vrc_shape(vrc: &JsonValue, now: chrono::DateTime<Utc>) -> Result<(), AppError> {
    crate::credentials::ingress::require_dtg_type(
        vrc,
        dtg_credentials::DTGCredentialType::Relationship,
        now,
        "this endpoint publishes relationship edges",
    )
}

/// Reject anything that is not a conformant VPC before it annotates an edge.
///
/// Same contract as [`check_vrc_shape`], one subtype over: DTG Credentials
/// §VPC says `type` MUST include `PersonaCredential`, and classification goes
/// through the catalog rather than a string comparison here.
///
/// This delegates to `credentials::ingress` rather than carrying its own copy
/// of the common-structure check. The VPC arrived on a branch cut before that
/// module existed and brought a local `check_dtg_shape` with it; keeping both
/// would have put two definitions of "is this a DTG credential" in the tree,
/// which is the condition #1064 was filed about.
fn check_vpc_shape(vpc: &JsonValue, now: chrono::DateTime<Utc>) -> Result<(), AppError> {
    crate::credentials::ingress::require_dtg_type(
        vpc,
        dtg_credentials::DTGCredentialType::Persona,
        now,
        "this endpoint attaches a persona annotation",
    )
}

/// Bound how fast one member can publish.
///
/// The limiter and the reasoning behind it live in
/// [`crate::relationships::rate_limit`]; this is the route's use of it.
async fn enforce_publish_rate_limit(state: &AppState, did: &str) -> Result<(), AppError> {
    if state
        .publish_rate_limiter
        .check_and_record(did, Utc::now())
        .await
    {
        return Ok(());
    }
    Err(AppError::Validation(format!(
        "rate limit: a member may publish at most {} relationship credentials \
         per {}s",
        crate::relationships::rate_limit::MAX_PER_WINDOW,
        crate::relationships::rate_limit::WINDOW_SECS,
    )))
}

/// `type` of the publish authorization object. Guarding on it stops a
/// signature the member made over some *other* object being replayed here as
/// authorization to publish.
const PUBLISH_AUTHORIZATION_TYPE: &str = "VrcPublishAuthorization";

/// How stale an authorization envelope may be. Still used by the VPC and
/// revoke authorizations, which carry their own `issuedAt`; the publish
/// authorization no longer does, because the document it rides in has one
/// and `validate_basic` already enforces the document's expiry.
const PUBLISH_AUTHORIZATION_MAX_AGE_SECS: i64 = 300;

/// Verify a publish authorization: proof that the caller controls the key
/// behind the VRC's `issuer`, bound to this document and this credential.
///
/// The document's own proof says a member sent this request. This says
/// somebody controls the key that issued the credential inside it. Both are
/// needed, because an edge may be published under a relationship DID that
/// names nobody: without this, any member ever handed a VRC could publish
/// another party's edge, and issuing a credential is a different disclosure
/// from publishing it to a community's graph.
///
/// Shape per `vtc/relationships/publish` (trustoverip/dtgwg-trust-tasks-tf#259):
///
/// | field                 | prevents                                        |
/// |-----------------------|-------------------------------------------------|
/// | `type`                | a signature over some other object being replayed |
/// | `documentId`          | replay into a different document                 |
/// | `vrcDigestMultibase`  | being moved to a different credential            |
///
/// **This is a different argument from the one it replaces.** The earlier form
/// bound to a REST session id, so a captured authorization was unusable by
/// another member because it named their session. Binding to the document is
/// available on every transport and is narrower — a session spans many
/// documents — but the document `id` is minted by the client, so a captured
/// authorization replayed inside a forged document carrying the same `id`
/// still verifies. That buys an attacker nothing: `vrcDigestMultibase` pins
/// the credential, and the stored edge carries the VRC's own issuer and
/// subject rather than the publisher's, so the forgery republishes a
/// credential that was already theirs to republish. The property holds; it
/// holds for a different reason, and that reason is worth writing down rather
/// than assuming the two are equivalent.
///
/// **Verified and discarded.** Retaining it would accumulate a durable link
/// between a member and a relationship DID that names nobody — the correlation
/// publishing under a relationship DID exists to avoid.
async fn verify_publish_authorization(
    pop: &JsonValue,
    issuer_did: &str,
    expected_document_id: &str,
    expected_vrc_digest: &str,
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
    if field("documentId")? != expected_document_id {
        return Err("authorization is bound to a different document".into());
    }
    if field("vrcDigestMultibase")? != expected_vrc_digest {
        return Err("authorization is bound to a different credential".into());
    }

    // Signed by the key the VRC's `issuer` names. `check_issuer_binding`
    // inside `verify_di_proof` is what makes this proof-of-possession rather
    // than proof-of-anything-signed.
    verify_di_proof(pop, issuer_did, resolver).await
}

/// Read a required string field off an authorization object.
fn authorization_field(pop: &JsonValue, name: &str) -> Result<String, String> {
    pop.get(name)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("authorization missing `{name}`"))
}

/// The checks every request-bound authorization object in this module shares:
/// what it authorizes (`type`), where (`aud`), by whom (`sessionId`), and how
/// recently (`issuedAt`).
///
/// Factored out because the persona endpoints need exactly these and would
/// otherwise copy them — and a copy is how one of the four quietly goes
/// missing. The per-object bindings (which VRC, which edge) stay at the call
/// sites, since those are what distinguish the objects.
fn check_authorization_envelope(
    pop: &JsonValue,
    expected_type: &str,
    expected_aud: &str,
    expected_session_id: &str,
) -> Result<(), String> {
    let ty = authorization_field(pop, "type")?;
    if ty != expected_type {
        return Err(format!(
            "authorization `type` must be `{expected_type}`, got `{ty}`"
        ));
    }

    let aud = authorization_field(pop, "aud")?;
    if aud != expected_aud {
        return Err("authorization `aud` is not this community".into());
    }

    let session_id = authorization_field(pop, "sessionId")?;
    if session_id != expected_session_id {
        return Err("authorization is bound to a different session".into());
    }

    let issued_at = chrono::DateTime::parse_from_rfc3339(&authorization_field(pop, "issuedAt")?)
        .map_err(|e| format!("authorization `issuedAt` is not an RFC 3339 timestamp: {e}"))?
        .with_timezone(&Utc);
    let age = Utc::now().signed_duration_since(issued_at).num_seconds();
    if age.abs() > PUBLISH_AUTHORIZATION_MAX_AGE_SECS {
        return Err(format!(
            "authorization `issuedAt` is outside the \
             {PUBLISH_AUTHORIZATION_MAX_AGE_SECS}s freshness window (age {age}s)"
        ));
    }
    Ok(())
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

// ── Connections graph (admin) ──────────────────────────────────────────────
//
// DTG Credentials defines a DTG edge as **two** VRCs, one in each direction.
// This endpoint used to return one entry per stored VRC, so a mutual
// relationship and a unilateral claim were indistinguishable: two members who
// had each vouched for the other looked the same as one member asserting an
// edge the other has never acknowledged (#1054).
//
// That distinction is the whole reason the subject-membership precondition
// could be dropped in #1061. The design there
// (`docs/05-design-notes/vrc-publish-proof-of-possession.md`) is that the
// subject's consent to an edge **is** their publication of the reciprocal VRC,
// rather than the community asserting on their behalf that they exist. If the
// graph cannot show whether that reciprocal VRC arrived, the consent signal the
// check was replaced with is invisible to the operator reading the graph.
//
// So the graph groups by unordered pair and reports the halves it holds.

/// One node in the connections graph — an identifier that is an endpoint of at
/// least one relationship (VRC). Isolated members (no VRCs) are not surfaced.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GraphNode {
    pub did: String,
}

/// One published VRC: a directed *half* of a DTG edge, from `issuerDid` (the
/// asserting party) to `subjectDid`. Body-free (no VRC JSON-LD) — the graph
/// shows the shape, not the credential contents. `id` is the row id, which is
/// what `DELETE /v1/relationships/{id}` takes.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GraphHalf {
    pub id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub created_at: String,
    /// The persona (P-DID) the issuer has asserted on this edge, if any.
    ///
    /// This is the one place the deliberate correlation a VPC exists to
    /// enable becomes visible: two pairwise edges carrying the same
    /// `personaDid` are the same party, said so by that party. Without it the
    /// annotation would be stored and never read, which is the state #1067
    /// describes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persona_did: Option<String>,
}

/// One edge between a pair of identifiers, carrying every VRC published between
/// them.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdge {
    /// The two endpoints, DID-sorted. Always exactly two entries, and sorting
    /// them gives the pair one identity whichever half was published first.
    /// Both entries are equal only for a self-issued VRC.
    pub endpoints: Vec<String>,
    /// Every VRC published between the endpoints, oldest first. One for a
    /// half-edge, two for the ordinary complete edge; more only if a party
    /// published several VRCs in the same direction, which nothing prevents
    /// (idempotency is per credential hash, not per direction).
    pub halves: Vec<GraphHalf>,
    /// An **in-force** VRC exists in both directions — a complete DTG edge,
    /// and the only form in which both parties currently consent.
    ///
    /// "In force" and not merely "present" since #1079. A half whose VRC has
    /// expired, or which has been suspended, superseded or withdrawn, no
    /// longer completes an edge — resolved through
    /// [`Relationship::in_force_at`], which is the one place the precedence
    /// rule lives. Before this the graph was read back without re-checking
    /// anything, so a half-edge whose reciprocal had expired years ago was
    /// indistinguishable from a live mutual relationship.
    ///
    /// The halves themselves are still listed whatever their state: an
    /// operator looking at a graph needs to see that a VRC was published, and
    /// removing it would make a withdrawn edge look like one that never
    /// existed. Which halves are in force is not yet surfaced per half — that
    /// needs a field on `GraphHalf`, and `relationships/graph/0.2` pins the
    /// response shape with `additionalProperties: false`, so it waits on a
    /// spec revision upstream rather than shipping a body the task rejects.
    pub complete: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RelationshipsGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

/// One directed half of a **membership** edge, lifted out of a member row into
/// the shape a published VRC contributes to the graph.
///
/// DTG Core Credentials makes VRCs and VMCs the two subtypes of *edge
/// credential*: "a bi-directional pair of credentials forms a complete DTG
/// edge" in both cases, and the community is a node like any other ("DTG node
/// types include persons, devices, AI agents, and VTCs"). A graph that renders
/// only VRC pairs is showing half the trust graph.
///
/// Membership halves are lifted rather than stored in the relationships
/// keyspace: they already exist, verified, on the member row. Copying them into
/// a second store would create two records of one fact, free to disagree — and
/// the VMC pair has its own lifecycle (status list, renewal, departure
/// handling) that the relationships keyspace does not model.
#[derive(Debug, Clone)]
pub struct MembershipHalf {
    /// The credential's own `id`. Not a relationships-keyspace row id, so it is
    /// not something `DELETE /v1/relationships/{id}` can take — a membership
    /// half is retracted by leaving the community, not by revoking an edge.
    pub id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub created_at: chrono::DateTime<Utc>,
    /// Whether this half currently stands. For the community's grant that is
    /// its validity window; for the member's acknowledgement it is the window
    /// **and** that its digest was verified against the grant — an unbound
    /// acknowledgement is still shown, but it does not complete an edge.
    pub in_force: bool,
}

/// Lift both halves of one member's membership edge.
///
/// Returns at most two halves: the community's grant (community → member) and
/// the member's acknowledgement (member → community). A member who has not
/// acknowledged yields one, which renders as the half-edge it is: the
/// community's claim, unanswered.
///
/// # A missing grant body does not fabricate a window
///
/// Rows written before the service kept credential bodies have the grant's `id`
/// but not its claims, so its window cannot be read. Such a half is treated as
/// standing — the ACL row is the community's live assertion of membership, and
/// it is the better evidence here than an absent document. This cannot
/// overstate an edge: the acknowledgement on those same rows is unbound, so the
/// edge is incomplete either way.
pub fn membership_halves(
    community_did: &str,
    member: &crate::members::Member,
    now: chrono::DateTime<Utc>,
) -> Vec<MembershipHalf> {
    /// Is a stored credential body inside its validity window? Absent body →
    /// `true`, per the doc comment above. Unreadable body → `false`: a document
    /// we cannot parse is not evidence of anything.
    fn window_stands(body: Option<&JsonValue>, now: chrono::DateTime<Utc>) -> bool {
        let Some(body) = body else {
            return true;
        };
        match crate::credentials::ingress::validity_window(body, "MembershipCredential") {
            Ok(window) => matches!(
                window.state_at(now),
                crate::credentials::lifecycle::InForce::Yes
            ),
            Err(_) => false,
        }
    }

    let mut halves = Vec::with_capacity(2);

    // The community's grant. A member with no `current_vmc_id` was admitted but
    // never issued to — no half to draw.
    if let Some(id) = &member.current_vmc_id {
        halves.push(MembershipHalf {
            id: id.clone(),
            issuer_did: community_did.to_string(),
            subject_did: member.did.clone(),
            created_at: member.joined_at,
            in_force: window_stands(member.current_vmc.as_ref(), now),
        });
    }

    // The member's acknowledgement.
    if let Some(id) = &member.member_vmc_id {
        halves.push(MembershipHalf {
            id: id.clone(),
            issuer_did: member.did.clone(),
            subject_did: community_did.to_string(),
            created_at: member.member_vmc_received_at.unwrap_or(member.joined_at),
            // `member_vmc_bound` is the digest check made at receipt. Without
            // it the acknowledgement names some grant, but not demonstrably
            // this one, and the spec is explicit that such a credential MUST
            // NOT be treated as completing a membership edge.
            in_force: member.member_vmc_bound && window_stands(member.member_vmc.as_ref(), now),
        });
    }

    halves
}

/// Group stored VRCs and lifted membership halves into pair-edges. Pure, so the
/// half/complete rule is testable without standing up a keyspace.
///
/// `now` is a parameter rather than read here because whether an edge is
/// complete is a question about an instant, and a test that cannot choose the
/// instant cannot pin an expiry boundary. Same reason the publish handler
/// reads `now` once at the top and passes it down.
fn build_graph(
    mut rels: Vec<Relationship>,
    memberships: Vec<MembershipHalf>,
    now: chrono::DateTime<Utc>,
) -> RelationshipsGraph {
    // Oldest first, id-tiebroken, so `halves` ordering is stable across calls
    // rather than inheriting whatever order the keyspace scan produced.
    rels.sort_by_key(|r| (r.created_at, r.id));

    let mut nodes = std::collections::BTreeSet::new();
    // BTreeMap, not HashMap: the response order is then a function of the data
    // and not of hash seeding, which keeps the admin view from reshuffling on
    // every poll.
    //
    // The resolved state rides alongside each half rather than on `GraphHalf`
    // itself: it decides `complete`, but it cannot be serialised until the
    // graph task's response schema admits it (see [`GraphEdge::complete`]).
    let mut pairs: std::collections::BTreeMap<(String, String), Vec<(GraphHalf, bool)>> =
        std::collections::BTreeMap::new();

    for r in rels {
        nodes.insert(r.issuer_did.clone());
        nodes.insert(r.subject_did.clone());
        let key = if r.issuer_did <= r.subject_did {
            (r.issuer_did.clone(), r.subject_did.clone())
        } else {
            (r.subject_did.clone(), r.issuer_did.clone())
        };
        let in_force = r.in_force_at(now).is_in_force();
        // Taken before the DIDs are moved into the half below.
        let persona_did = r.persona.map(|p| p.persona_did);
        pairs.entry(key).or_default().push((
            GraphHalf {
                id: r.id.to_string(),
                issuer_did: r.issuer_did,
                subject_did: r.subject_did,
                created_at: r.created_at.to_rfc3339(),
                persona_did,
            },
            in_force,
        ));
    }

    // Membership halves join the same pair map, so one `complete` rule covers
    // both kinds of edge. They are appended after the VRC halves and the pair's
    // halves are re-sorted below, rather than being merged in `created_at`
    // order here, because the two come from different stores and only the
    // combined list has a meaningful order.
    for half in memberships {
        nodes.insert(half.issuer_did.clone());
        nodes.insert(half.subject_did.clone());
        let key = if half.issuer_did <= half.subject_did {
            (half.issuer_did.clone(), half.subject_did.clone())
        } else {
            (half.subject_did.clone(), half.issuer_did.clone())
        };
        let in_force = half.in_force;
        pairs.entry(key).or_default().push((
            GraphHalf {
                id: half.id,
                issuer_did: half.issuer_did,
                subject_did: half.subject_did,
                created_at: half.created_at.to_rfc3339(),
                // A VPC annotates a relationship edge; membership is not
                // pseudonymous, so there is nothing to correlate here.
                persona_did: None,
            },
            in_force,
        ));
    }

    let edges = pairs
        .into_iter()
        .map(|((lo, hi), mut halves)| {
            // Oldest first across both sources, matching the `halves` contract.
            halves.sort_by(|a, b| {
                a.0.created_at
                    .cmp(&b.0.created_at)
                    .then(a.0.id.cmp(&b.0.id))
            });
            // A self-issued VRC (`lo == hi`) has no counterparty who could ever
            // reciprocate, so it can never be complete — without the `lo != hi`
            // guard the two `any` checks below would both match the same row
            // and report a self-vouch as a mutual relationship.
            //
            // Each direction must be satisfied by a half that is *in force*.
            // An expired or suspended VRC is still a published fact and still
            // appears below; what it no longer does is stand in for a party's
            // current consent.
            let live = |from: &String, to: &String| {
                halves
                    .iter()
                    .any(|(h, ok)| *ok && &h.issuer_did == from && &h.subject_did == to)
            };
            let complete = lo != hi && live(&lo, &hi) && live(&hi, &lo);
            GraphEdge {
                endpoints: vec![lo, hi],
                halves: halves.into_iter().map(|(h, _)| h).collect(),
                complete,
            }
        })
        .collect();

    RelationshipsGraph {
        nodes: nodes.into_iter().map(|did| GraphNode { did }).collect(),
        edges,
    }
}

/// `GET /v1/relationships/graph` — the community's relationship (VRC) graph for
/// the admin-UI connections view. Admin-gated; a full scan of the relationships
/// keyspace (communities are small and this is operator-only). Edge-derived
/// nodes — members with no VRCs don't appear.
///
/// Edges are pairs, not individual credentials: each carries the VRCs published
/// between its two endpoints and a `complete` flag saying whether both
/// directions are present. See the module comment above for why.
#[utoipa::path(
    get, path = "/relationships/graph", tag = "relationships",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Relationship graph", body = RelationshipsGraph),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn graph(
    _auth: crate::auth::AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<RelationshipsGraph>, AppError> {
    let now = Utc::now();
    let rels = crate::relationships::list_all(&state.relationships_ks).await?;

    // Membership halves come from the member rows, where they already sit
    // verified — see [`membership_halves`] for why they are lifted rather than
    // copied into the relationships keyspace. A community with no DID
    // configured has no node to draw them against; the VRC graph still renders.
    let community_did = state.config.read().await.vtc_did.clone();
    let memberships = match community_did {
        Some(community_did) if !community_did.is_empty() => {
            crate::members::list_members(&state.members_ks)
                .await?
                .iter()
                .filter(|m| !m.is_removed())
                .flat_map(|m| membership_halves(&community_did, m, now))
                .collect()
        }
        _ => Vec::new(),
    };

    Ok(Json(build_graph(rels, memberships, now)))
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
        check_vrc_shape(&body(&vrc), now).expect("a catalog-minted VRC must be publishable");

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
        let err = check_vrc_shape(&body(&vmc), now).expect_err("a VMC must not publish as a VRC");
        assert!(
            format!("{err:?}").contains("relationship edges"),
            "unexpected rejection: {err:?}"
        );
    }

    /// #1069: this endpoint read neither `validFrom` nor `validUntil`, so an
    /// expired VRC became a permanent edge — and per D7 a VRC has no
    /// `credentialStatus`, so nothing downstream would ever retract it.
    ///
    /// Asserted at the route's own gate rather than only in
    /// `credentials::ingress`, because the gap was this call site not doing
    /// the check, not the check being wrong.
    #[test]
    fn refuses_a_vrc_whose_validity_window_has_passed() {
        use chrono::Duration;
        use dtg_credentials::DTGCredential;

        use crate::test_support::dtg_json as body;

        let now = Utc::now();
        let expired = DTGCredential::new_vrc(
            "did:peer:2.zR1".into(),
            "did:peer:2.zR2".into(),
            now - Duration::days(30),
            Some(now - Duration::days(1)),
        );
        let err = check_vrc_shape(&body(&expired), now)
            .expect_err("an expired VRC must not enter the graph");
        assert!(
            format!("{err:?}").contains("expired at"),
            "unexpected rejection: {err:?}"
        );

        // Same credential, evaluated while it was still in date: publishable.
        // Without this, a check that rejected everything would pass the test
        // above.
        check_vrc_shape(&body(&expired), now - Duration::days(2))
            .expect("the same VRC inside its window is publishable");
    }

    // ─── Half-edges vs complete edges ───────────────────────
    //
    // A DTG edge is two VRCs, one each way. These pin the rule that says which
    // is which, because getting it wrong is silent: the graph still renders, it
    // just tells the operator a unilateral claim is a mutual relationship.

    const A: &str = "did:key:zAlice";
    const B: &str = "did:key:zBob";
    const C: &str = "did:key:zCarol";

    /// A stored row whose body is minted by the same catalog constructor the
    /// publish path documents (`DTGCredential::new_vrc`) rather than
    /// hand-rolled JSON — a hand-rolled fixture agrees with the test that wrote
    /// it and with nothing that ships.
    fn row(issuer: &str, subject: &str, minute: u32) -> Relationship {
        use chrono::TimeZone;
        let valid_from = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let vrc = dtg_credentials::DTGCredential::new_vrc(
            issuer.to_string(),
            subject.to_string(),
            valid_from,
            None,
        );
        let vrc_jsonld = serde_json::to_value(vrc.credential()).expect("VRC serialises");
        let vrc_digest_multibase =
            crate::credentials::ingress::digest_multibase(&vrc_jsonld).unwrap();
        Relationship {
            id: Uuid::new_v4(),
            issuer_did: issuer.into(),
            subject_did: subject.into(),
            vrc_jsonld,
            vrc_digest_multibase,
            created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, minute, 0).unwrap(),
            // These fixtures exercise the half/complete grouping, which is
            // independent of whether a persona was asserted. The persona
            // rendering has its own tests.
            persona: None,
            lifecycle: crate::relationships::LifecycleLog::default(),
        }
    }

    /// The instant the grouping tests resolve at: inside every `row`'s window
    /// and after every event they record. Fixed rather than `Utc::now()` so a
    /// test about grouping cannot start failing on a clock, and so the
    /// lifecycle tests below can name an instant on either side of an event.
    fn at(day: u32) -> chrono::DateTime<Utc> {
        use chrono::TimeZone;
        Utc.with_ymd_and_hms(2026, 2, day, 0, 0, 0).unwrap()
    }

    /// A member row with both halves of its membership pair, digest verified.
    fn member_row(did: &str, ack: Option<bool>) -> crate::members::Member {
        use chrono::TimeZone;
        let mut m = crate::members::Member::fresh(did);
        m.joined_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();

        let grant = dtg_credentials::DTGCredential::new_vmc(
            COMMUNITY.to_string(),
            did.to_string(),
            m.joined_at,
            None,
            false,
        )
        .with_id("urn:uuid:grant-1");
        let grant_json = serde_json::to_value(grant.credential()).expect("grant serialises");

        let role_vec = serde_json::json!({ "id": "urn:uuid:vec-1" });
        m.record_issued_credentials(grant_json, role_vec);

        if let Some(bound) = ack {
            let ack = dtg_credentials::DTGCredential::new_member_vmc(&grant, m.joined_at, None)
                .expect("acknowledgement builds")
                .with_id("urn:uuid:ack-1");
            let ack_json = serde_json::to_value(ack.credential()).expect("ack serialises");
            m.record_member_vmc("urn:uuid:ack-1", ack_json, bound);
            m.member_vmc_received_at = Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 5, 0).unwrap());
        }

        m
    }

    const COMMUNITY: &str = "did:web:community.example";

    /// The membership pair is a DTG edge in exactly the way a VRC pair is —
    /// "in both cases, a bi-directional pair of credentials forms a complete
    /// DTG edge" — and the community is a node like any other. A graph that
    /// rendered only VRC pairs was showing half the trust graph.
    #[test]
    fn an_acknowledged_membership_is_one_complete_edge() {
        let member = member_row(A, Some(true));
        let g = build_graph(vec![], membership_halves(COMMUNITY, &member, at(1)), at(1));

        assert_eq!(g.edges.len(), 1, "grant + acknowledgement are ONE edge");
        assert_eq!(
            g.edges[0].endpoints,
            {
                let mut e = vec![COMMUNITY.to_string(), A.to_string()];
                e.sort();
                e
            },
            "endpoints are DID-sorted, as for any edge"
        );
        assert_eq!(g.edges[0].halves.len(), 2);
        assert!(g.edges[0].complete);
        assert_eq!(g.nodes.len(), 2, "the community is a node in its own graph");
    }

    /// A membership the member has not answered is the community's claim, not
    /// a relationship — the same reading a one-sided VRC gets.
    #[test]
    fn an_unacknowledged_membership_is_a_half_edge() {
        let member = member_row(A, None);
        let g = build_graph(vec![], membership_halves(COMMUNITY, &member, at(1)), at(1));

        assert_eq!(g.edges.len(), 1);
        assert_eq!(g.edges[0].halves.len(), 1);
        assert!(!g.edges[0].complete);
        assert_eq!(g.edges[0].halves[0].issuer_did, COMMUNITY);
    }

    /// The spec is explicit: an acknowledgement whose digest does not match a
    /// valid grant MUST NOT be treated as completing a membership edge. It is
    /// still *shown* — a published fact is not hidden because it is unbound —
    /// but it does not stand in for the member's consent.
    #[test]
    fn an_unbound_acknowledgement_does_not_complete_the_edge() {
        let member = member_row(A, Some(false));
        let g = build_graph(vec![], membership_halves(COMMUNITY, &member, at(1)), at(1));

        assert_eq!(g.edges.len(), 1);
        assert_eq!(
            g.edges[0].halves.len(),
            2,
            "both halves are listed; a stored credential is not hidden"
        );
        assert!(
            !g.edges[0].complete,
            "an unverified digest is not the member's consent to THIS membership"
        );
    }

    /// Membership and relationship edges share one graph and one `complete`
    /// rule. They must not merge into each other: a member's VRC to a peer and
    /// their VMC pair with the community are different edges.
    #[test]
    fn membership_and_relationship_edges_coexist() {
        let member = member_row(A, Some(true));
        let g = build_graph(
            vec![row(A, B, 0), row(B, A, 1)],
            membership_halves(COMMUNITY, &member, at(1)),
            at(1),
        );

        assert_eq!(g.edges.len(), 2, "A—B and A—community are separate edges");
        assert!(g.edges.iter().all(|e| e.complete));
        assert_eq!(g.nodes.len(), 3, "A, B, and the community");

        // An edge touching the community DID is the membership one. This is how
        // a consumer tells them apart without a schema change: the community
        // knows its own DID, and `relationships/graph/0.2` pins the response
        // shape with `additionalProperties: false`.
        let membership = g
            .edges
            .iter()
            .find(|e| e.endpoints.contains(&COMMUNITY.to_string()))
            .expect("the membership edge");
        assert_eq!(membership.halves.len(), 2);
    }

    /// An expired grant stops standing for a current membership, exactly as an
    /// expired VRC stops completing a relationship edge (#1079).
    #[test]
    fn an_expired_grant_does_not_complete_the_edge() {
        use chrono::TimeZone;
        let mut member = member_row(A, Some(true));

        // Re-issue the stored grant with a window that has already closed.
        if let Some(grant) = member.current_vmc.as_mut() {
            grant["validUntil"] = serde_json::Value::String(
                Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0)
                    .unwrap()
                    .to_rfc3339(),
            );
        }

        let g = build_graph(vec![], membership_halves(COMMUNITY, &member, at(9)), at(9));
        assert_eq!(g.edges[0].halves.len(), 2, "both are still listed");
        assert!(!g.edges[0].complete);
    }

    /// Rows written before the service kept credential bodies still render a
    /// half — the id is enough to say the grant exists — and are honestly
    /// incomplete, because nothing verified the acknowledgement against it.
    #[test]
    fn a_pre_digest_row_renders_as_an_incomplete_edge() {
        let mut member = crate::members::Member::fresh(A);
        member.current_vmc_id = Some("urn:uuid:legacy-grant".into());
        member.member_vmc_id = Some("urn:uuid:legacy-ack".into());
        // `member_vmc_bound` defaults false: nothing checked a digest.

        let g = build_graph(vec![], membership_halves(COMMUNITY, &member, at(1)), at(1));
        assert_eq!(g.edges[0].halves.len(), 2);
        assert!(!g.edges[0].complete);
    }

    #[test]
    fn a_reciprocated_pair_is_one_complete_edge() {
        let g = build_graph(vec![row(A, B, 0), row(B, A, 1)], vec![], at(1));
        assert_eq!(g.edges.len(), 1, "two VRCs one each way are ONE edge");
        assert_eq!(g.edges[0].endpoints, vec![A.to_string(), B.to_string()]);
        assert_eq!(g.edges[0].halves.len(), 2);
        assert!(g.edges[0].complete);
        assert_eq!(g.nodes.len(), 2);
    }

    #[test]
    fn an_unreciprocated_vrc_is_a_half_edge() {
        let g = build_graph(vec![row(A, B, 0)], vec![], at(1));
        assert_eq!(g.edges.len(), 1);
        assert_eq!(g.edges[0].halves.len(), 1);
        assert!(
            !g.edges[0].complete,
            "B has never acknowledged this edge, so it is not complete"
        );
        // The subject still appears — the graph shows who was named, it just no
        // longer implies they agreed.
        assert_eq!(g.nodes.len(), 2);
    }

    /// The trap this whole change exists to close: several VRCs between two
    /// parties are not evidence of reciprocity if they all point one way.
    #[test]
    fn repeated_vrcs_in_one_direction_do_not_complete_an_edge() {
        let g = build_graph(
            vec![row(A, B, 0), row(A, B, 1), row(A, B, 2)],
            vec![],
            at(1),
        );
        assert_eq!(g.edges.len(), 1);
        assert_eq!(g.edges[0].halves.len(), 3);
        assert!(!g.edges[0].complete);
    }

    /// `endpoints` is DID-sorted, so the pair has one identity whichever half
    /// arrived first — otherwise the same relationship would appear as two
    /// edges depending on publish order.
    #[test]
    fn pair_identity_does_not_depend_on_publish_order() {
        let forward = build_graph(vec![row(A, B, 0), row(B, A, 1)], vec![], at(1));
        let reverse = build_graph(vec![row(B, A, 0), row(A, B, 1)], vec![], at(1));
        assert_eq!(forward.edges[0].endpoints, reverse.edges[0].endpoints);
        assert!(forward.edges[0].complete && reverse.edges[0].complete);
    }

    /// A VRC a party issued to themselves has no counterparty who could
    /// reciprocate. Both directions are the same direction, so the naive
    /// "a VRC each way" test would report it complete.
    #[test]
    fn a_self_issued_vrc_is_never_complete() {
        let g = build_graph(vec![row(A, A, 0)], vec![], at(1));
        assert_eq!(g.edges.len(), 1);
        assert_eq!(g.edges[0].endpoints, vec![A.to_string(), A.to_string()]);
        assert!(!g.edges[0].complete);
    }

    #[test]
    fn distinct_pairs_stay_distinct_and_ordering_is_stable() {
        let rows = vec![row(B, C, 2), row(A, B, 0), row(B, A, 1)];
        let g = build_graph(rows, vec![], at(1));
        assert_eq!(g.edges.len(), 2);
        // BTreeMap keyed on the sorted pair: (A,B) before (B,C).
        assert_eq!(g.edges[0].endpoints, vec![A.to_string(), B.to_string()]);
        assert_eq!(g.edges[1].endpoints, vec![B.to_string(), C.to_string()]);
        assert!(g.edges[0].complete);
        assert!(!g.edges[1].complete);
        // Halves are oldest-first regardless of the order rows came back in.
        assert_eq!(g.edges[0].halves[0].issuer_did, A);
        assert_eq!(g.edges[0].halves[1].issuer_did, B);
    }

    // ─── Precedence in the graph read (#1079) ───────────────
    //
    // Until this, the graph was read back without re-checking anything on the
    // reasoning that each edge had been validated at ingress. True, and
    // insufficient: it says nothing about the months since, and for a VRC
    // with no `validUntil` it says nothing at all. These pin the two ways an
    // edge can stop counting — its own window closing, and this community
    // recording something against it — as producing the same answer.

    /// A row whose VRC states an upper bound, so the window can be crossed
    /// inside a test.
    fn row_expiring(issuer: &str, subject: &str, minute: u32, until_day: u32) -> Relationship {
        use chrono::TimeZone;
        let mut rel = row(issuer, subject, minute);
        let until = Utc.with_ymd_and_hms(2026, 2, until_day, 0, 0, 0).unwrap();
        rel.vrc_jsonld["validUntil"] = json!(until.to_rfc3339());
        rel
    }

    /// The symptom #1079 names: "a half-edge whose reciprocal has expired is
    /// indistinguishable from one that never arrived". It is distinguishable
    /// now — the pair stops being complete the instant the reciprocal lapses,
    /// with no event recorded and nothing deleted.
    #[test]
    fn an_expired_reciprocal_no_longer_completes_an_edge() {
        let rows = || vec![row(A, B, 0), row_expiring(B, A, 1, 10)];

        let live = build_graph(rows(), vec![], at(9));
        assert!(
            live.edges[0].complete,
            "both halves in date: this is a mutual relationship"
        );

        let lapsed = build_graph(rows(), vec![], at(11));
        assert!(
            !lapsed.edges[0].complete,
            "B's half has expired, so B no longer consents to anything"
        );
        assert_eq!(
            lapsed.edges[0].halves.len(),
            2,
            "the expired half is still shown — it was published, and hiding it \
             would make a lapsed edge look like one that never existed"
        );
    }

    /// The other half of the precedence rule: a later recorded event beats a
    /// still-valid credential. Nothing about B's VRC has changed — its
    /// signature verifies and its window is open — and the edge is no longer
    /// complete.
    #[test]
    fn a_suspended_half_does_not_complete_an_edge() {
        let mut suspended = row(B, A, 1);
        suspended
            .lifecycle
            .record(
                crate::relationships::LifecycleEventKind::Suspended { reason: None },
                at(5),
            )
            .expect("first event on a fresh log");

        assert!(
            !build_graph(vec![row(A, B, 0), suspended.clone()], vec![], at(6)).edges[0].complete,
            "a suspended half is not consent"
        );
        // And it was genuinely the event doing the work: an instant before it
        // was recorded, the same rows read as complete.
        assert!(
            build_graph(vec![row(A, B, 0), suspended], vec![], at(4)).edges[0].complete,
            "the suspension must not apply before it was recorded"
        );
    }

    /// Restoration puts the edge back, which is the difference between
    /// suspension and revocation actually meaning something.
    #[test]
    fn a_restored_half_completes_the_edge_again() {
        let mut half = row(B, A, 1);
        let kinds = crate::relationships::LifecycleEventKind::Suspended { reason: None };
        half.lifecycle.record(kinds, at(5)).unwrap();
        half.lifecycle
            .record(
                crate::relationships::LifecycleEventKind::Restored { reason: None },
                at(7),
            )
            .unwrap();

        assert!(!build_graph(vec![row(A, B, 0), half.clone()], vec![], at(6)).edges[0].complete);
        assert!(build_graph(vec![row(A, B, 0), half], vec![], at(8)).edges[0].complete);
    }

    /// A superseded half is displaced, not deleted — and the replacement is
    /// what carries the pair. Without this, a re-issued edge would read as two
    /// live claims in the same direction.
    #[test]
    fn a_superseded_half_is_displaced_by_its_replacement() {
        let mut old_half = row(A, B, 0);
        old_half
            .lifecycle
            .record(
                crate::relationships::LifecycleEventKind::Superseded {
                    by: "zReplacement".into(),
                },
                at(5),
            )
            .unwrap();
        let replacement = row(A, B, 2);

        let g = build_graph(
            vec![old_half.clone(), replacement, row(B, A, 1)],
            vec![],
            at(6),
        );
        assert_eq!(g.edges[0].halves.len(), 3);
        assert!(g.edges[0].complete, "the replacement carries A's direction");

        // Remove the replacement and the pair is no longer complete: the
        // displaced half cannot stand in for it.
        let without = build_graph(vec![old_half, row(B, A, 1)], vec![], at(6));
        assert!(!without.edges[0].complete);
    }

    /// A stored VRC whose window will not parse resolves to
    /// `Indeterminate`, which is not in force. Rows written before #1075
    /// entered the graph without their window ever being read, so this is
    /// reachable — and treating an unreadable bound as "no bound stated" is
    /// the failure mode that makes the whole check ornamental.
    #[test]
    fn an_unreadable_window_is_not_in_force() {
        let mut broken = row(B, A, 1);
        broken.vrc_jsonld["validUntil"] = json!("whenever");
        assert!(matches!(
            broken.in_force_at(at(1)),
            crate::relationships::InForce::Indeterminate { .. }
        ));
        assert!(!build_graph(vec![row(A, B, 0), broken], vec![], at(1)).edges[0].complete);
    }
}
