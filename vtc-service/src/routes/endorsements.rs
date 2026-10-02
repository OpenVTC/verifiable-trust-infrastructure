//! `vtc/endorsements/{issue,list,show,revoke}/0.1` — community statement
//! issuance, retrieval and revocation (Phase 4 M4.8.2-4). All four are signed
//! documents only, dispatched by `trust_tasks::member_tasks`: each bearer REST
//! route had no caller once the spine dispatched it (issuance, #1809;
//! retrieval and revocation, tt-tf#689) and was removed.
//!
//! - `vtc/endorsements/issue/0.1` — issue. Auth: Admin OR Issuer role.
//!   `typeUri` is a predicate IRI the community registered
//!   (`vtc/endorsement-types/register/0.1`); anything else is
//!   `typeNotRegistered`. Allocates a slot on the shared `Revocation` status
//!   list (D8 review), builds + signs a DTG **Verifiable Statement
//!   Credential** — issuer the community, `issuerScope` `public`,
//!   `credentialSubject.predicate` = `typeUri`, `object.value` = `claim` —
//!   persists the row, emits `CustomEndorsementIssued` + `VecIssued`.
//!
//!   Under `vetted/1` the community records **its own identity check** (the
//!   registry admits the community as issuer). The claim is the statement's
//!   `VettedObjectValue`, must name this community and carries none of the
//!   vetter-only members (`identityCommitment`, `cardDigestMultibase`,
//!   `declaredRelationship`); the profile's REQUIRED
//!   task citation names this issue request document — `taskContext` its
//!   `id`, `taskDigestMultibase` its task digest — the exchange in which the
//!   community recorded the check. Any other registered predicate whose
//!   profile requires `taskContext` (`witnessed/1`, `presented/1`) is
//!   `predicateNotIssuable`: those statements are made by the party that ran
//!   the exchange, and the community ran none here.
//!
//!   The community's own `vetted/1` is also **delivered to its subject** — one
//!   `credential-exchange/issue`, as the role VAC is — because the member is the
//!   one who presents it as identity evidence. Delivery is best effort: the
//!   statement is already issued and recorded (its signed document kept on the
//!   row), so a failure is logged and does not fail the issue.
//! - `vtc/endorsements/list/0.1` — paginated list. Auth: Admin OR Issuer.
//! - `vtc/endorsements/show/0.1` — one endorsement by id.
//! - `vtc/endorsements/revoke/0.1` — revoke. Auth: Admin OR the original
//!   issuer. Flips the status-list bit + emits both `CustomEndorsementRevoked`
//!   and `StatusListFlipped`.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::{error, info, warn};
use uuid::Uuid;
use vta_sdk::protocols::members::STATEMENT_CREDENTIAL_TYPE;
use vti_common::audit::{
    AuditEvent, CredentialIssuedData, CustomEndorsementIssuedData, CustomEndorsementRevokedData,
    StatusListFlippedData,
};
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated};

use crate::acl::get_acl_entry;
use crate::credentials::statement::DEFAULT_STATEMENT_VALIDITY;
use crate::credentials::{CredentialStatusRef, StatementParams, build_statement};
use crate::endorsement_types::get_type;
use crate::endorsements::{
    Endorsement, get_endorsement, list_endorsements_matching, mark_revoked, store_endorsement,
};
use crate::error::TaskError;
use crate::server::AppState;
use crate::status_list;

const LIST_MAX_LIMIT: usize = 200;

/// `CLAIM_MAX_BYTES` upper bound on the on-the-wire body
/// (matches the builder cap). Larger inputs surface as 400.
const CLAIM_MAX_BYTES: usize = 8 * 1024;

use trust_tasks_rs::specs::vtc::endorsements as end_spec;

/// `vtc/endorsements/issue:typeNotRegistered`.
pub const ISSUE_ERR_TYPE_NOT_REGISTERED: &str =
    end_spec::issue::v0_1::error_codes::TYPE_NOT_REGISTERED.code;
/// `vtc/endorsements/issue:predicateNotIssuable` — registered, but the
/// predicate's profile requires a task citation this task cannot carry.
pub const ISSUE_ERR_PREDICATE_NOT_ISSUABLE: &str =
    end_spec::issue::v0_1::error_codes::PREDICATE_NOT_ISSUABLE.code;
/// `vtc/endorsements/issue:claimTooLarge` — over the 8 KiB cap.
pub const ISSUE_ERR_CLAIM_TOO_LARGE: &str =
    end_spec::issue::v0_1::error_codes::CLAIM_TOO_LARGE.code;
/// `vtc/endorsements/issue:claimSchemaViolation` — `claim` fails the type's
/// declared `claimSchema`.
pub const ISSUE_ERR_CLAIM_SCHEMA_VIOLATION: &str =
    end_spec::issue::v0_1::error_codes::CLAIM_SCHEMA_VIOLATION.code;
/// `vtc/endorsements/issue:statusListExhausted` — no free revocation slot.
pub const ISSUE_ERR_STATUS_LIST_EXHAUSTED: &str =
    end_spec::issue::v0_1::error_codes::STATUS_LIST_EXHAUSTED.code;
/// `vtc/endorsements/list:invalidCursor`.
pub const LIST_ERR_INVALID_CURSOR: &str = end_spec::list::v0_1::error_codes::INVALID_CURSOR.code;
/// `vtc/endorsements/show:notFound`.
pub const SHOW_ERR_NOT_FOUND: &str = end_spec::show::v0_1::error_codes::NOT_FOUND.code;
/// `vtc/endorsements/revoke:notFound`.
pub const REVOKE_ERR_NOT_FOUND: &str = end_spec::revoke::v0_1::error_codes::NOT_FOUND.code;
/// `vtc/endorsements/revoke:alreadyRevoked`.
pub const REVOKE_ERR_ALREADY_REVOKED: &str =
    end_spec::revoke::v0_1::error_codes::ALREADY_REVOKED.code;

// ─── Issue ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct IssueBody {
    pub subject_did: String,
    /// `typeUri`, the name the payload schema gives it. This carried an
    /// explicit `#[serde(rename = "type")]` until #1096 — a deliberate
    /// rename that simply disagreed with the spec.
    #[serde(rename = "typeUri")]
    pub endorsement_type: String,
    pub claim: JsonValue,
    /// Optional override; defaults to 30d.
    #[serde(default)]
    pub validity_seconds: Option<u64>,
    /// The payload's vendor-namespaced extensions. Under `vetted/1` the
    /// community reads [`UNIQUENESS_EXT`] from it; nothing in it is written
    /// into the credential.
    #[serde(default)]
    pub ext: Option<serde_json::Map<String, JsonValue>>,
}

/// `ext` namespace on a `vtc/endorsements/issue/0.1` payload under `vetted/1`
/// carrying the person's **uniqueness pseudonym** —
/// `{ "org.openvtc.uniqueness": { "pseudonym": "<value>" } }`.
///
/// The community binds it to the subject in the pseudonym store
/// (`members::pseudonym::claim_for_statement`) when it records its own
/// identity check, so `personhood.singleMembership` can be satisfied by that
/// check. It is never written into the statement: the registry fixes the
/// `vetted/1` value and has no member for it, and a stable per-person
/// identifier in a signed credential is the correlation handle the pseudonym
/// construction exists to avoid. Only a digest is stored.
pub const UNIQUENESS_EXT: &str = "org.openvtc.uniqueness";

/// The uniqueness pseudonym an issue request carries under [`UNIQUENESS_EXT`],
/// if any. Refused (`malformedRequest`) when the namespace is present but is
/// not `{ "pseudonym": "<non-empty string>" }`, or when it rides a predicate
/// other than `vetted/1`, which binds nothing.
fn uniqueness_pseudonym(
    body: &IssueBody,
    community_check: bool,
) -> Result<Option<String>, AppError> {
    let Some(ns) = body.ext.as_ref().and_then(|ext| ext.get(UNIQUENESS_EXT)) else {
        return Ok(None);
    };
    if !community_check {
        return Err(AppError::Validation(format!(
            "ext.{UNIQUENESS_EXT} is read only under {}: it binds a pseudonym to the \
             community's own identity check",
            dtg_credentials::VETTED_V1
        )));
    }
    let malformed = || {
        AppError::Validation(format!(
            "ext.{UNIQUENESS_EXT} must be {{ \"pseudonym\": \"<non-empty string>\" }}"
        ))
    };
    let obj = ns.as_object().ok_or_else(malformed)?;
    if obj.keys().any(|k| k != "pseudonym") {
        return Err(malformed());
    }
    let pseudonym = obj
        .get("pseudonym")
        .and_then(JsonValue::as_str)
        .filter(|p| !p.trim().is_empty())
        .ok_or_else(malformed)?;
    Ok(Some(pseudonym.to_string()))
}

/// One endorsement as the canonical `Endorsement` component names it.
///
/// A wire type distinct from the stored [`Endorsement`] because renaming the
/// stored fields would rewrite the persisted fjall rows — `Endorsement`
/// derives `Deserialize` and serialises `camelCase`, so `id` /
/// `endorsementType` / `createdAt` are the on-disk keys of every row already
/// written. Mapping at the boundary keeps the wire correct without a data
/// migration, the same split `GenerationRow` uses (#1095).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct EndorsementRow {
    /// `endorsementId`, stored as `id`.
    pub endorsement_id: Uuid,
    /// `typeUri`, stored as `endorsementType`.
    pub type_uri: String,
    pub subject_did: String,
    /// A reference to the issued credential — **not** a timestamp.
    ///
    /// #1096 read `issued` as "when it was issued" and mapped `createdAt`
    /// onto it, so this went out as an RFC 3339 string where the component
    /// requires an object.
    pub issued: CredentialReference,
    pub status_list_index: u32,
    pub claim: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// A pointer to the issued credential: its identifier and lifetime, not its
/// bytes.
///
/// #1098 mapped this to the registry-wide `IssuedCredential`, whose
/// `credential` and `expiresAt` are required and neither of which is on the
/// stored row — so `list` and `show` could not fill it and stayed
/// non-conformant. That turned out to be the component being used in the
/// wrong place rather than a gap in this service: `IssuedCredential` is
/// scoped to the moment of minting, and a listing is not an issuance event.
/// trustoverip/dtgwg-trust-tasks-tf#262 splits the two, and this is the read
/// side of that split. The credential itself now rides on the `issue`
/// response alone, which is the one call whose caller cannot get it any
/// other way.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialReference {
    pub credential_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl From<Endorsement> for EndorsementRow {
    fn from(e: Endorsement) -> Self {
        Self {
            endorsement_id: e.id,
            type_uri: e.endorsement_type,
            subject_did: e.subject_did,
            issued: CredentialReference {
                credential_id: e.credential_id,
                issued_at: Some(e.created_at),
                // Recorded since rows gained `validUntil`; absent on older rows.
                expires_at: e.valid_until,
            },
            status_list_index: e.status_list_index,
            claim: e.claim,
            revoked_at: e.revoked_at,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct IssueResponse {
    pub endorsement: EndorsementRow,
    /// The signed credential just minted, which only this call can hand
    /// back. A read carries `endorsement.issued` — the reference — instead,
    /// so a page of fifty endorsements does not embed fifty credentials.
    pub credential: JsonValue,
}

/// Refuse a `vetted/1` claim the community cannot issue as its own identity
/// check: one that is not a `VettedObjectValue` (the registry's object schema),
/// that carries any vetter-only member, or that names a community other than
/// `community_did`.
fn check_community_vetted_claim(community_did: &str, claim: &JsonValue) -> Result<(), TaskError> {
    use vta_sdk::protocols::vetting::{CheckShape, VettedObjectValue};
    let violation = |msg: String| {
        TaskError::declared(ISSUE_ERR_CLAIM_SCHEMA_VIOLATION, AppError::Validation(msg))
    };
    let value: VettedObjectValue = serde_json::from_value(claim.clone())
        .map_err(|e| violation(format!("claim is not a vetted/1 object value: {e}")))?;
    value
        .check_shape()
        .map_err(|e| violation(format!("claim is not a vetted/1 object value: {e}")))?;
    // A statement the community issues for itself carries none of the
    // vetter-only members (registry `vetted/1`): the salt behind
    // `identityCommitment` must never reach the community, and the community
    // is the party weighing statements, not a related or unrelated vetter.
    if !value.has_no_vetter_members() {
        return Err(violation(
            "a statement the community issues for itself carries none of \
             identityCommitment, cardDigestMultibase and declaredRelationship"
                .into(),
        ));
    }
    if value.community != community_did {
        return Err(violation(format!(
            "claim.community is `{}`, but this community is `{community_did}`: the community \
             records only its own identity checks",
            value.community
        )));
    }
    Ok(())
}

/// Issue a custom endorsement on behalf of `actor_did` — the operation behind
/// the `vtc/endorsements/issue/0.1` Trust Task. Issuance has no bearer REST
/// route: it is a signed document only, reached over TSP, DIDComm or HTTPS
/// `/trust-tasks`. The door has already established that `actor_did` is an
/// admin or issuer.
///
/// `request` is the issue request document as received: a `vetted/1`
/// statement cites it as the exchange the community recorded its check in.
pub(crate) async fn issue_inner(
    state: &AppState,
    actor_did: &str,
    body: IssueBody,
    request: &JsonValue,
) -> Result<IssueResponse, TaskError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let signer = state
        .credential_signer
        .as_ref()
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;

    // 2. Predicate registry consultation (D4 review).
    let Some(registered) = get_type(&state.endorsement_types_ks, &body.endorsement_type).await?
    else {
        return Err(TaskError::declared(
            ISSUE_ERR_TYPE_NOT_REGISTERED,
            AppError::Validation(format!(
                "endorsement-type-not-registered: '{}' is not a predicate registered with \
                 this community",
                body.endorsement_type
            )),
        ));
    };
    // `vetted/1` is the community's own identity check: the registry admits
    // the community as its issuer, and the task citation it requires is this
    // request. Every other registered predicate whose profile requires
    // `taskContext` (and `taskDigestMultibase`) cannot be minted here: this
    // task carries no citation for them, and those statements are made by the
    // party that ran the exchange — `witnessed/1` by a witness,
    // `presented/1` by the observer (vtc/endorsements/issue/0.1,
    // Conformance 2).
    let community_check = body.endorsement_type == dtg_credentials::VETTED_V1;
    if !community_check
        && crate::credentials::task_context::requirement_for_predicate(Some(&body.endorsement_type))
            == crate::credentials::task_context::Requirement::Required
    {
        return Err(TaskError::declared(
            ISSUE_ERR_PREDICATE_NOT_ISSUABLE,
            AppError::Validation(format!(
                "'{}' is registered, but its profile requires a taskContext citing the \
                 exchange the statement was made in; the community cannot issue it \
                 through vtc/endorsements/issue",
                body.endorsement_type
            )),
        ));
    }
    // 3. Body-side validation. The builder enforces the same
    //    cap; we check here too so 400 surfaces cleanly
    //    before any state mutation.
    if !body.claim.is_object() {
        return Err(AppError::Validation("claim must be a JSON object".into()).into());
    }
    let claim_bytes = serde_json::to_vec(&body.claim)
        .map_err(|e| AppError::Internal(format!("serialise claim: {e}")))?;
    if claim_bytes.len() > CLAIM_MAX_BYTES {
        return Err(TaskError::declared(
            ISSUE_ERR_CLAIM_TOO_LARGE,
            AppError::Validation(format!("claim exceeds {CLAIM_MAX_BYTES} bytes")),
        ));
    }
    // A predicate that declares a `claimSchema` binds every claim of it
    // (`vtc/endorsements/issue/0.1`, Conformance 3): the schema of the
    // statement's `object.value`. Registration stored the schema, but until
    // #1600 nothing read it back, so any claim was accepted.
    //
    // A stored schema that will not compile is the type's fault, not this
    // claim's, and it is a 500 — no declared code fits, and `claimSchemaViolation`
    // would be a lie, since that code means a claim failed a *valid* schema and
    // tells the caller to fix the claim. Registration has refused a malformed
    // schema since this change, so reaching here means a row written before it;
    // the answer names the type and says the type must be re-registered, so the
    // operator is not left reading "internal error" against a well-formed claim.
    if let Some(schema) = registered.claim_schema.as_ref() {
        if let Err(detail) = crate::schemas::check_schema(schema) {
            error!(
                type_uri = %body.endorsement_type,
                %detail,
                "stored claimSchema is not valid JSON Schema — issuance refused",
            );
            return Err(AppError::Internal(format!(
                "endorsement type '{}' has an invalid stored claimSchema ({detail}) — \
                 the claim was not at fault. An admin must delete and re-register the \
                 type with a valid JSON Schema before it can be issued against.",
                body.endorsement_type
            ))
            .into());
        }
        crate::schemas::validate_instance(schema, &body.claim).map_err(|e| match e {
            AppError::Validation(msg) => TaskError::declared(
                ISSUE_ERR_CLAIM_SCHEMA_VIOLATION,
                AppError::Validation(msg.replacen(
                    "credential does not conform to its registered schema",
                    "claim does not conform to the endorsement type's claimSchema",
                    1,
                )),
            ),
            e => TaskError::App(e),
        })?;
    }

    // The community's own identity check: the claim is the `vetted/1`
    // statement's `object.value`, so it must be one — the registry's schema,
    // which `VettedObjectValue` and its shape check carry — and it must be made
    // for this community. A statement naming another community would be one
    // this community has no standing to make (`vetted/1`: a statement counts
    // for the one community it names).
    if community_check {
        check_community_vetted_claim(signer.issuer_did(), &body.claim)?;
    }
    let pseudonym = uniqueness_pseudonym(&body, community_check)?;

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
        ))
        .into());
    }

    // 4b. The uniqueness pseudonym, bound before anything is minted so a
    //     person already here is refused without spending a status slot. The
    //     row id is fixed now so the binding names the statement that will
    //     carry it; if a later step fails, a binding made here is released.
    let id = Uuid::new_v4();
    let bound_here = match &pseudonym {
        Some(p) => {
            let outcome = crate::members::pseudonym::claim_for_statement(
                &state.members_ks,
                signer.issuer_did(),
                p,
                &body.subject_did,
                id,
            )
            .await?;
            outcome == crate::members::pseudonym::StatementClaim::Bound
        }
        None => false,
    };
    let minted = mint_and_record(state, actor_did, body, request, signer, audit_writer, id).await;
    if minted.is_err()
        && bound_here
        && let Err(e) =
            crate::members::pseudonym::release_for_statement(&state.members_ks, id).await
    {
        error!(
            endorsement_id = %id,
            error = %e,
            "could not release the uniqueness binding of a failed issue"
        );
    }
    minted
}

/// Steps 5–8 of [`issue_inner`]: allocate the revocation slot, mint, persist
/// the row and audit. Split out so a failure here can release a uniqueness
/// binding made before it.
#[allow(clippy::too_many_arguments)]
async fn mint_and_record(
    state: &AppState,
    actor_did: &str,
    body: IssueBody,
    request: &JsonValue,
    signer: &crate::credentials::LocalSigner,
    audit_writer: &vti_common::audit::AuditWriter,
    id: Uuid,
) -> Result<IssueResponse, TaskError> {
    let community_check = body.endorsement_type == dtg_credentials::VETTED_V1;
    // 5. Allocate status-list slot — locked RMW so a concurrent
    //    allocate/flip can't clobber this allocation (P0.1).
    let allocated = status_list::with_locked(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        |row| Ok(status_list::allocate(row).map(|slot| (slot, row.list_credential_id.clone()))),
    )
    .await?;
    // `statusListExhausted` (retryable: an operator provisions a new list).
    // The status stays the 500 it always was.
    let Some((slot, list_credential_id)) = allocated else {
        return Err(TaskError::declared(
            ISSUE_ERR_STATUS_LIST_EXHAUSTED,
            AppError::Internal(
                "revocation status list is full — cannot allocate slot for endorsement".into(),
            ),
        ));
    };
    let status_ref = CredentialStatusRef::revocation(list_credential_id, slot);

    // 6. Build + sign the credential: a VSC under the registered predicate —
    //    for `vetted/1`, citing this request as the exchange the community
    //    recorded its check in.
    let credential_id = format!("urn:uuid:{id}");
    let validity = body
        .validity_seconds
        .map(|s| Duration::seconds(s as i64))
        .unwrap_or(DEFAULT_STATEMENT_VALIDITY);
    let credential_value = if community_check {
        crate::credentials::dtg::issue_vetted_statement(
            signer,
            &body.subject_did,
            body.claim.clone(),
            request,
            &credential_id,
            &status_ref,
            validity,
        )
        .await?
    } else {
        let params = StatementParams::new(
            &body.subject_did,
            &body.endorsement_type,
            body.claim.clone(),
            status_ref,
        )
        .with_id(&credential_id)
        .with_validity(validity);
        let vsc = build_statement(signer, params).await?;
        serde_json::to_value(&vsc)
            .map_err(|e| AppError::Internal(format!("serialise statement: {e}")))?
    };
    let credential_type = STATEMENT_CREDENTIAL_TYPE;

    // Issue-time schema validation: enforce a registered credentialSchema for
    // this credential type, if any (no-op when none is registered).
    crate::schemas::validate_issued(&state.schemas_ks, &credential_value).await?;

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
        credential_id: credential_id.clone(),
        created_at: now,
        revoked_at: None,
        valid_until: Some(valid_until),
        auto_granted: false,
        // The community's own check is kept so it can be delivered again.
        credential: community_check.then(|| credential_value.clone()),
    };
    store_endorsement(&state.endorsements_ks, &end).await?;

    // 8. Audit — two envelopes (the endorsement row + generic
    //    credential issuance accounting).
    audit_writer
        .write(
            actor_did,
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
            actor_did,
            Some(&body.subject_did),
            AuditEvent::VecIssued(CredentialIssuedData {
                credential_id: credential_id.clone(),
                credential_type: credential_type.into(),
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
        "community statement issued"
    );

    if community_check {
        deliver_to_subject(state, &body.subject_did, &credential_value).await;
    }

    Ok(IssueResponse {
        endorsement: EndorsementRow {
            // `issue` knows the expiry it just computed; a read does not.
            issued: CredentialReference {
                credential_id,
                issued_at: Some(now),
                expires_at: Some(valid_until),
            },
            ..end.into()
        },
        credential: credential_value,
    })
}

/// Hand the community's own `vetted/1` to its subject's wallet. Best effort:
/// the statement is issued and recorded whether or not it goes, so a failure
/// is logged, never returned.
async fn deliver_to_subject(state: &AppState, subject_did: &str, credential: &JsonValue) {
    let typed = match crate::credentials::dtg::into_typed(credential.clone(), "vetted/1 statement")
    {
        Ok(typed) => typed,
        Err(e) => {
            warn!(subject = %subject_did, error = %e, "community vetted/1 statement not delivered");
            return;
        }
    };
    match crate::credentials::delivery::deliver_credentials(state, subject_did, &[&typed]).await {
        Ok(()) => info!(subject = %subject_did, "community vetted/1 statement queued for delivery"),
        Err(e) => {
            warn!(subject = %subject_did, error = %e, "community vetted/1 statement not delivered");
        }
    }
}

// ─── List ────────────────────────────────────────────────

/// The filters `vtc/endorsements/list/0.1` defines. The default matches every
/// row, live and revoked — the task's own default, and all the bearer route
/// has ever returned.
#[derive(Debug, Clone, Default)]
pub(crate) struct ListFilter {
    pub subject_did: Option<String>,
    pub type_uri: Option<String>,
    /// `includeRevoked`; absent means `true`.
    pub include_revoked: Option<bool>,
}

impl ListFilter {
    fn keeps(&self, row: &Endorsement) -> bool {
        self.subject_did
            .as_deref()
            .is_none_or(|d| row.subject_did == d)
            && self
                .type_uri
                .as_deref()
                .is_none_or(|t| row.endorsement_type == t)
            && (self.include_revoked.unwrap_or(true) || !row.is_revoked())
    }
}

/// One page of endorsements matching `filter` — the operation behind the
/// `vtc/endorsements/list/0.1` Trust Task. Signed document only: its bearer
/// REST route had no caller once the spine dispatched it (tt-tf#689) and was
/// removed. The door has already established that the caller is an admin or
/// issuer.
pub(crate) async fn list_inner(
    state: &AppState,
    filter: &ListFilter,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> Result<Paginated<EndorsementRow>, TaskError> {
    let limit = limit.unwrap_or(50).clamp(1, LIST_MAX_LIMIT);
    let audit_key = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?
        .active_key()
        .await?;
    let cursor = cursor
        .map(|c| Cursor::decode(c, &audit_key.key))
        .transpose()
        .map_err(|e| {
            TaskError::declared(
                LIST_ERR_INVALID_CURSOR,
                AppError::Validation(format!("invalid cursor: {e}")),
            )
        })?;
    let page = list_endorsements_matching(
        &state.endorsements_ks,
        &audit_key,
        cursor.as_ref(),
        limit,
        |row| filter.keeps(row),
    )
    .await?;
    Ok(page.map_items(EndorsementRow::from))
}

// ─── Show ────────────────────────────────────────────────

/// Read one endorsement — the operation behind the `vtc/endorsements/show/0.1`
/// Trust Task. Signed document only: its bearer REST route had no caller once
/// the spine dispatched it (tt-tf#689) and was removed. The door has already
/// established that the caller is an admin or issuer.
pub(crate) async fn show_inner(
    state: &AppState,
    id: Uuid,
) -> Result<EndorsementEnvelope, TaskError> {
    let row = get_endorsement(&state.endorsements_ks, id)
        .await?
        .ok_or_else(|| {
            TaskError::declared(
                SHOW_ERR_NOT_FOUND,
                AppError::NotFound(format!("endorsement {id} not found")),
            )
        })?;
    Ok(EndorsementEnvelope {
        endorsement: row.into(),
    })
}

// ─── Revoke ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
#[schema(as = EndorsementRevokeResponse)]
pub struct RevokeResponse {
    pub endorsement_id: String,
    pub revocation: RevocationDetail,
    pub status_list_index: u32,
}

/// The credential the revocation applies to, and when it took effect.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RevocationDetail {
    pub credential_id: String,
    pub revoked_at: String,
}

/// Revoke an endorsement on behalf of `actor_did` — the operation behind the
/// `vtc/endorsements/revoke/0.1` Trust Task. Signed document only: its bearer
/// REST route had no caller once the spine dispatched it (tt-tf#689) and was
/// removed. The door has already established that `actor_did` is an admin or
/// issuer, which must precede the lookup below (Conformance 1 before 2).
pub(crate) async fn revoke_inner(
    state: &AppState,
    actor_did: &str,
    id: Uuid,
) -> Result<RevokeResponse, TaskError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    // Looked up only after the capability check (Conformance 1 before 2), so
    // a caller who may not revoke cannot use this route to learn which
    // endorsement ids exist.
    let row = get_endorsement(&state.endorsements_ks, id)
        .await?
        .ok_or_else(|| {
            TaskError::declared(
                REVOKE_ERR_NOT_FOUND,
                AppError::NotFound(format!("endorsement {id} not found")),
            )
        })?;

    // `alreadyRevoked` (Conformance 3): the bit is not re-flipped and nothing
    // is re-audited. This used to answer 200 with the first revocation's
    // receipt; the specification requires that the caller can tell "I revoked
    // it now" from "it was already gone".
    if row.is_revoked() {
        let at = row
            .revoked_at
            .map(rfc3339)
            .unwrap_or_else(|| "an earlier call".into());
        return Err(TaskError::declared(
            REVOKE_ERR_ALREADY_REVOKED,
            AppError::Conflict(format!("endorsement {id} was already revoked at {at}")),
        ));
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

    // The community's own identity check is withdrawn, so the uniqueness
    // binding it made at issue goes with it. A binding an accepted provider's
    // credential made is not tagged with a statement and stays.
    if row.endorsement_type == dtg_credentials::VETTED_V1 {
        crate::members::pseudonym::release_for_statement(&state.members_ks, id).await?;
    }

    // Two paired envelopes — CustomEndorsementRevoked
    // (semantic) + StatusListFlipped (bit-flip accounting).
    audit_writer
        .write(
            actor_did,
            Some(&row.subject_did),
            AuditEvent::CustomEndorsementRevoked(CustomEndorsementRevokedData {
                endorsement_id: id.to_string(),
                endorsement_type: row.endorsement_type.clone(),
            }),
        )
        .await?;
    audit_writer
        .write(
            actor_did,
            Some(&row.subject_did),
            AuditEvent::StatusListFlipped(StatusListFlippedData {
                purpose: "revocation".into(),
                index: row.status_list_index,
                revoked: true,
            }),
        )
        .await?;

    // A vetter whose grant this was, holding no other, no longer has a profile
    // to publish (`vtc/vetting/vetters/profile/0.1`, Conformance 5).
    if row.endorsement_type == crate::endorsements::VETTER_GRANT_ROW_TYPE {
        crate::vetting::profiles::after_grant_revoked(state, actor_did, &row.subject_did).await?;
    }

    info!(
        endorsement_id = %id,
        endorsement_type = %row.endorsement_type,
        slot = row.status_list_index,
        by = %actor_did,
        "custom endorsement revoked"
    );
    // Every member the spec asks for was already in hand here: the handler
    // replied with `{id}` alone and dropped the rest, including `updated`,
    // which it had bound and then discarded with `let _ = updated;`.
    Ok(RevokeResponse {
        endorsement_id: id.to_string(),
        revocation: RevocationDetail {
            credential_id: row.credential_id.clone(),
            revoked_at: rfc3339(updated.revoked_at.unwrap_or_else(Utc::now)),
        },
        status_list_index: row.status_list_index,
    })
}

fn rfc3339(t: chrono::DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// `{ endorsement: … }` — the shape `vtc/endorsements/show/0.1` publishes.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EndorsementEnvelope {
    pub endorsement: EndorsementRow,
}
