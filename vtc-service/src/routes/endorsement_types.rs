//! `/v1/endorsement-types/*` — operator-uploaded endorsement
//! type registry (Phase 4 M4.8.1; D4 planning review).
//!
//! Three admin-gated endpoints:
//!
//! - `POST /v1/endorsement-types` — register a type.
//! - `GET /v1/endorsement-types` — paginated list.
//! - `DELETE /v1/endorsement-types/{uri}` — refuses while
//!   anything still references the type: a live endorsement of
//!   it, or an Accepts criterion naming it as its
//!   `vetting.statementType`. Both are reported in one refusal,
//!   so an operator who has to clear both learns that in one
//!   call rather than two.
//!
//! The criterion half is the symmetric partner of the check in
//! `routes::schemas::register_accepts`, which refuses a criterion
//! whose `statementType` is not registered. Without it, deleting
//! a type strands a criterion in exactly the state registration
//! forbids: applicants keep reading a manifest that requires a
//! type the community no longer recognises, and the criterion can
//! no longer be saved again.
//!
//! ## Reserved type URIs
//!
//! `"CommunityRole"` is reserved by the workspace (VEC-
//! managed role grants). The registrar refuses to register
//! it; the issuance path can't see it on disk either way.
//!
//! ## URI encoding on the wire
//!
//! The `DELETE /v1/endorsement-types/{uri}` path parameter
//! is URL-decoded by axum before reaching the handler. The
//! storage layer percent-encodes again before forming the
//! fjall key — keeps colons and slashes in operator-supplied
//! URIs from colliding with the keyspace prefix discipline.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::info;
use vti_common::audit::{AuditEvent, EndorsementTypeDeletedData, EndorsementTypeRegisteredData};
use vti_common::auth::AdminAuth;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated};

use trust_tasks_rs::specs::vtc::endorsement_types::delete::v0_1::Response as DeleteTaskResponse;
use vta_sdk::openapi::EndorsementTypeDelete01Response;

use crate::endorsement_types::{
    EndorsementType, RESERVED_TYPE_URIS, TYPE_URI_MAX_BYTES, delete_type, get_type, list_types,
    store_type,
};
use crate::endorsements::count_live_by_type;
use crate::error::TaskError;
use crate::schemas::list_accepts;
use crate::server::AppState;

const LIST_MAX_LIMIT: usize = 200;

use trust_tasks_rs::specs::vtc::endorsement_types as et_spec;

/// `vtc/endorsement-types/register:invalidUri` — empty, or over 512 bytes.
pub const REGISTER_ERR_INVALID_URI: &str = et_spec::register::v0_1::error_codes::INVALID_URI.code;
/// `vtc/endorsement-types/register:reserved` — a workspace-reserved URI.
pub const REGISTER_ERR_RESERVED: &str = et_spec::register::v0_1::error_codes::RESERVED.code;
/// `vtc/endorsement-types/register:exists` — already registered.
pub const REGISTER_ERR_EXISTS: &str = et_spec::register::v0_1::error_codes::EXISTS.code;
/// `vtc/endorsement-types/delete:notFound` — no such type registered.
pub const DELETE_ERR_NOT_FOUND: &str = et_spec::delete::v0_1::error_codes::NOT_FOUND.code;
/// `vtc/endorsement-types/delete:inUse` — a live endorsement or a criterion
/// still references the type.
pub const DELETE_ERR_IN_USE: &str = et_spec::delete::v0_1::error_codes::IN_USE.code;

/// `malformedRequest` — the **framework** standard code (SPEC §8.3), for a
/// `claimSchema` that is not itself valid JSON Schema.
///
/// `vtc/endorsement-types/register/0.1` declares exactly three codes —
/// `invalidUri`, `reserved`, `exists` — and none of them is about the schema:
/// `invalidUri` is "empty or over 512 bytes" and is about `typeUri`. Nothing
/// declared covers the body being well-formed JSON that is not a schema, so
/// this refusal carries the standard code rather than one minted under the
/// task's namespace. It is therefore not a census entry: the census tracks the
/// codes a `spec/vtc/*` task *declares*, and `CONSUMER_MINTED` is for codes
/// namespaced under the task slug, which a framework code is not.
///
/// Not a `const`, because `StandardCode::as_str` is not a `const fn`. It is
/// still `trust_tasks_rs`' spelling of the code, not a literal.
fn malformed_request_code() -> &'static str {
    trust_tasks_rs::StandardCode::MalformedRequest.as_str()
}

// ─── Register ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RegisterBody {
    pub type_uri: String,
    #[serde(default)]
    pub claim_schema: Option<JsonValue>,
    #[serde(default)]
    pub description: Option<String>,
}

/// POST /endorsement-types — register an endorsement type. Auth: Admin.
///
/// **Transitional bearer-token path (#1641).**
/// `vtc/endorsement-types/register/0.1` declares `proof` REQUIRED, and the
/// authoritative binding is the signed Trust Task document at
/// `POST /v1/trust-tasks`, where the proof authenticates the administrator and
/// their authority is read from their ACL entry. This route authenticates by
/// bearer JWT and verifies no document proof; the admin console uses it only
/// from a browser with no console signing key enrolled, and it is removed once
/// every client signs.
#[utoipa::path(
    post, path = "/endorsement-types",
    operation_id = "endorsementTypeRegister", tag = "endorsement-types",
    security(("bearer_jwt" = [])),
    request_body = RegisterBody,
    responses(
        (status = 201, description = "Endorsement type registered", body = RegisterResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn register(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<RegisterBody>,
) -> Result<(StatusCode, Json<RegisterResponse>), TaskError> {
    let response = register_inner(&state, &auth.0.did, body).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

/// The largest `claimSchema` a registration accepts, measured serialised.
///
/// The task publishes no bound, but the signed door caps a whole document at
/// 64 KiB, and a schema that registers over the bearer route but not over the
/// signed one is two doors disagreeing. 32 KiB leaves the document envelope,
/// the proof and the other members plenty of room, and is an order of
/// magnitude past any claim schema written for an endorsement.
pub const CLAIM_SCHEMA_MAX_BYTES: usize = 32 * 1024;

/// `description`'s bound, as `vtc/endorsement-types/register/0.1` publishes it
/// (`maxLength: 1024`, in characters).
pub const DESCRIPTION_MAX_CHARS: usize = 1024;

/// The registration, independent of the door it arrived through — the bearer
/// route above and the signed `vtc/endorsement-types/register/0.1` document
/// (`trust_tasks::handle_endorsement_type_register`) both call this, so the
/// two cannot answer differently. `actor_did` is whoever the door
/// authenticated: the session's subject on one, the verified signer on the
/// other; it is what the audit row and `createdByDid` name.
pub(crate) async fn register_inner(
    state: &AppState,
    actor_did: &str,
    body: RegisterBody,
) -> Result<RegisterResponse, TaskError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    // Validation.
    //
    // The two size bounds come first and carry the framework's
    // `malformedRequest`, as the schema check below does: the task declares no
    // code for an oversized member. The signed door's schema check already
    // refuses a long `description`; enforcing it here is what makes the bearer
    // route agree.
    if body
        .description
        .as_ref()
        .is_some_and(|d| d.chars().count() > DESCRIPTION_MAX_CHARS)
    {
        return Err(TaskError::declared(
            malformed_request_code(),
            AppError::Validation(format!(
                "description exceeds {DESCRIPTION_MAX_CHARS} characters"
            )),
        ));
    }
    if let Some(schema) = body.claim_schema.as_ref() {
        let size = serde_json::to_vec(schema)
            .map(|b| b.len())
            .unwrap_or(usize::MAX);
        if size > CLAIM_SCHEMA_MAX_BYTES {
            return Err(TaskError::declared(
                malformed_request_code(),
                AppError::Validation(format!(
                    "claimSchema is {size} bytes serialised; the limit is \
                     {CLAIM_SCHEMA_MAX_BYTES}. Shorten the schema and register \
                     again."
                )),
            ));
        }
    }
    let uri = body.type_uri.trim();
    if uri.is_empty() {
        return Err(TaskError::declared(
            REGISTER_ERR_INVALID_URI,
            AppError::Validation("type_uri cannot be empty".into()),
        ));
    }
    if uri.len() > TYPE_URI_MAX_BYTES {
        return Err(TaskError::declared(
            REGISTER_ERR_INVALID_URI,
            AppError::Validation(format!("type_uri exceeds {TYPE_URI_MAX_BYTES} bytes")),
        ));
    }
    if RESERVED_TYPE_URIS.contains(&uri) {
        return Err(TaskError::declared(
            REGISTER_ERR_RESERVED,
            AppError::Conflict(format!(
                "endorsement-type-reserved: '{uri}' is reserved by the workspace"
            )),
        ));
    }
    if get_type(&state.endorsement_types_ks, uri).await?.is_some() {
        return Err(TaskError::declared(
            REGISTER_ERR_EXISTS,
            AppError::Conflict(format!(
                "endorsement-type-exists: '{uri}' already registered"
            )),
        ));
    }
    // A `claimSchema` that is not itself valid JSON Schema is refused here,
    // where the operator can still fix it. Registration stored the document
    // unread until #1649 made `vtc/endorsements/issue/0.1` enforce it, at which
    // point a malformed one stopped being inert and became an opaque 500 on
    // every issuance of the type — a fault the issuing caller could neither
    // cause nor diagnose. Refusing at the one call that supplies the document
    // is the fix; naming the bad keyword is what makes the refusal actionable.
    if let Some(schema) = body.claim_schema.as_ref()
        && let Err(detail) = crate::schemas::check_schema(schema)
    {
        return Err(TaskError::declared(
            malformed_request_code(),
            AppError::Validation(format!(
                "claimSchema is not a valid JSON Schema — {detail}. Correct the schema \
                 and register again; a type whose stored schema will not compile cannot \
                 have endorsements issued against it."
            )),
        ));
    }

    let row = EndorsementType {
        type_uri: uri.to_string(),
        claim_schema: body.claim_schema,
        description: body.description.clone(),
        created_at: Utc::now(),
        created_by_did: actor_did.to_string(),
    };
    store_type(&state.endorsement_types_ks, &row).await?;

    audit_writer
        .write(
            actor_did,
            None,
            AuditEvent::EndorsementTypeRegistered(EndorsementTypeRegisteredData {
                type_uri: uri.to_string(),
                description: body.description,
            }),
        )
        .await?;

    info!(type_uri = %uri, by = %actor_did, "endorsement type registered");

    Ok(RegisterResponse {
        endorsement_type: row,
    })
}

/// `{ endorsementType: … }` — the shape `vtc/endorsement-types/register/0.1`
/// publishes. The handler returned the bare row until #1059's witness
/// compared it with its own schema; the row itself conformed.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    pub endorsement_type: EndorsementType,
}

// ─── List ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema, utoipa::IntoParams)]
#[schema(as = EndorsementTypeListQuery)]
pub struct ListQuery {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

#[utoipa::path(
    get, path = "/endorsement-types",
    operation_id = "endorsementTypeList", tag = "endorsement-types",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Paginated list of endorsement types", body = Paginated<EndorsementType>),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn list(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Paginated<EndorsementType>>, AppError> {
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
    let page = list_types(
        &state.endorsement_types_ks,
        &audit_key,
        cursor.as_ref(),
        limit,
    )
    .await?;
    Ok(Json(page))
}

// ─── Delete ──────────────────────────────────────────────

/// The response is the **generated** `vtc/endorsement-types/delete/0.1`
/// type, not a local restatement of it.
///
/// A hand-written `{ typeUri }` lived here until the census in
/// `vta-sdk/tests/generated_wire_types_census.rs` named it. It had been
/// invisible to that census only because it carried no doc comment
/// saying which task it restated — giving it one, while renaming it out
/// of a three-way `DeleteResponse` collision, is what surfaced a
/// violation that predated the rename.
///
/// `utoipa::ToSchema` cannot be derived on a foreign type, so the handler
/// returns [`EndorsementTypeDelete01Response`] — the `spec_types!` newtype
/// whose schema is rendered from the specification's own — wrapping the
/// generated value rather than describing the shape a second time.
///
/// Returning the wrapper, not the bare generated type, is what
/// `openapi_response_census` requires: the `body =` annotation and the
/// handler's return type must name the same thing, because that annotation
/// is what generates the console's `wire.ts` and a mismatch ships a console
/// reading a shape the daemon never sends.
///
/// **Transitional bearer-token path (#1641).**
/// `vtc/endorsement-types/delete/0.1` declares `proof` REQUIRED, and the
/// authoritative binding is the signed Trust Task document at
/// `POST /v1/trust-tasks`, where the proof authenticates the administrator and
/// their authority is read from their ACL entry. This route authenticates by
/// bearer JWT and verifies no document proof; the admin console uses it only
/// from a browser with no console signing key enrolled, and it is removed once
/// every client signs.
#[utoipa::path(
    delete, path = "/endorsement-types/{type_uri}",
    operation_id = "endorsementTypeDelete", tag = "endorsement-types",
    security(("bearer_jwt" = [])),
    params(("type_uri" = String, Path, description = "Endorsement type URI")),
    responses(
        (status = 200, description = "Endorsement type deleted", body = EndorsementTypeDelete01Response),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Endorsement type not found"),
    ),
)]
pub async fn delete(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(type_uri): Path<String>,
) -> Result<(StatusCode, Json<EndorsementTypeDelete01Response>), TaskError> {
    let body = delete_inner(&state, &auth.0.did, type_uri).await?;
    Ok((StatusCode::OK, Json(body.into())))
}

/// The deletion, independent of the door it arrived through — the bearer
/// route above and the signed `vtc/endorsement-types/delete/0.1` document
/// (`trust_tasks::handle_endorsement_type_delete`) both call this. It answers
/// with the generated response type; the bearer route wraps it in the OpenAPI
/// newtype, and the signed door returns it as the document's payload.
pub(crate) async fn delete_inner(
    state: &AppState,
    actor_did: &str,
    type_uri: String,
) -> Result<DeleteTaskResponse, TaskError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    if get_type(&state.endorsement_types_ks, &type_uri)
        .await?
        .is_none()
    {
        return Err(TaskError::declared(
            DELETE_ERR_NOT_FOUND,
            AppError::NotFound(format!("endorsement type '{type_uri}' not found")),
        ));
    }

    // Refuse while anything still references the type. Both halves are
    // gathered before refusing: an operator clearing one only to meet the
    // other is two round trips for one answer we already had.
    let in_use = count_live_by_type(&state.endorsements_ks, &type_uri).await?;
    let criteria: Vec<String> = list_accepts(&state.schemas_ks)
        .await?
        .into_iter()
        .filter(|c| {
            c.vetting
                .as_ref()
                .is_some_and(|v| v.statement_type == type_uri)
        })
        .map(|c| c.id)
        .collect();
    if in_use > 0 || !criteria.is_empty() {
        // The spec's `details` (`liveEndorsements`, `criteria`) has no slot
        // on the REST error body; the message names both halves instead.
        return Err(TaskError::declared(
            DELETE_ERR_IN_USE,
            AppError::Conflict(in_use_message(&type_uri, in_use, &criteria)),
        ));
    }

    delete_type(&state.endorsement_types_ks, &type_uri).await?;

    audit_writer
        .write(
            actor_did,
            None,
            AuditEvent::EndorsementTypeDeleted(EndorsementTypeDeletedData {
                type_uri: type_uri.clone(),
                live_endorsements_at_delete: in_use as u32,
            }),
        )
        .await?;

    info!(type_uri = %type_uri, by = %actor_did, "endorsement type deleted");

    Ok(DeleteTaskResponse::builder()
        .type_uri(type_uri)
        .try_into()
        .map_err(|e| {
            AppError::Internal(format!("delete response does not match its schema: {e}"))
        })?)
}

/// The 409 body for a type something still references.
///
/// Keeps the `endorsement-type-in-use:` prefix the live-endorsement
/// refusal has always carried, and names each clause that applies
/// plus what to do about it — an operator error should suggest the
/// fix, and the admin console renders this text verbatim.
fn in_use_message(type_uri: &str, in_use: usize, criteria: &[String]) -> String {
    let mut why = Vec::new();
    let mut fix = Vec::new();
    if in_use > 0 {
        why.push(format!("{in_use} live endorsement(s) of it exist"));
        fix.push("revoke the endorsements");
    }
    if !criteria.is_empty() {
        let named = criteria
            .iter()
            .map(|id| format!("'{id}'"))
            .collect::<Vec<_>>()
            .join(", ");
        why.push(if criteria.len() == 1 {
            format!("criterion {named} requires statements of it")
        } else {
            format!("criteria {named} require statements of it")
        });
        fix.push("remove or re-point the criteria");
    }
    format!(
        "endorsement-type-in-use: '{type_uri}' is still referenced — {}. {} before \
         deleting the type.",
        why.join("; "),
        capitalise(&fix.join(" and ")),
    )
}

fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::in_use_message;

    const URI: &str = "https://example.org/endorsements/identity-vetting/0.1";

    #[test]
    fn names_the_single_criterion_and_what_to_do() {
        let msg = in_use_message(URI, 0, &["kernel-developer".to_string()]);
        assert_eq!(
            msg,
            "endorsement-type-in-use: 'https://example.org/endorsements/identity-vetting/0.1' \
             is still referenced — criterion 'kernel-developer' requires statements of it. \
             Remove or re-point the criteria before deleting the type."
        );
    }

    #[test]
    fn reports_both_reasons_in_one_refusal() {
        let msg = in_use_message(
            URI,
            2,
            &["kernel-developer".to_string(), "contributor".to_string()],
        );
        assert!(msg.contains("2 live endorsement(s) of it exist"), "{msg}");
        assert!(
            msg.contains("criteria 'kernel-developer', 'contributor' require statements of it"),
            "{msg}"
        );
        assert!(
            msg.contains("Revoke the endorsements and remove or re-point the criteria"),
            "{msg}"
        );
    }

    #[test]
    fn keeps_the_live_endorsement_wording_the_prefix_promises() {
        let msg = in_use_message(URI, 1, &[]);
        assert!(msg.starts_with("endorsement-type-in-use: "), "{msg}");
        assert!(msg.contains("1 live endorsement(s) of it exist"), "{msg}");
        assert!(
            msg.contains("Revoke the endorsements before deleting the type."),
            "{msg}"
        );
    }
}
