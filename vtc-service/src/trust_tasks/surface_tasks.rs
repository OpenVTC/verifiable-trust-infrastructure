//! The community's administration surfaces that had only bearer REST, on the
//! signed-document spine: how the community presents itself to applicants,
//! its credential-schema registry, the vetting reads, the relationship graph's
//! suspend and restore, a join request's vetting facts and the credential
//! query an administrator sends a holder, and the rooms this host stores.
//!
//! | task | authority (the signer's ACL row, read now) |
//! |---|---|
//! | `vtc/community/{branding,requested-attributes,join-discovery}/show/0.1` | any entry |
//! | `vtc/community/{branding,requested-attributes,join-discovery}/update/0.1` | `Admin` |
//! | `vtc/schemas/{register,list,show,delete}/0.1` | `Admin` |
//! | `vtc/schemas/accepts/{register,list,show}/0.2`, `…/delete/0.1` | `Admin` |
//! | `vtc/vetting/vetters/grants/list/0.1` | `Admin` |
//! | `vtc/vetting/auto-grant/{show,update}/0.1` | `Admin` |
//! | `vtc/vetting/revocations/list/0.1` | `Admin` |
//! | `vtc/relationships/{suspend,restore}/0.1` | the edge's issuer, or `Admin` |
//! | `vtc/join-requests/vetting/show/0.1` | `Admin` |
//! | `vtc/join-requests/query/0.1` | `Admin` |
//! | `vtc/rooms/list/0.1` | `Admin` |
//!
//! Each is the question its bearer route asked: `AuthClaims` (any session —
//! which the VTC minted for an administrator only) for the presentation reads,
//! `AdminAuth` for everything else, and for suspend and restore the edge's
//! issuer or an administrator. On a document the edge's issuer is the signer
//! itself, so its proof stands in for the route's `pop` authorization: an edge
//! issued under a pairwise relationship DID is suspended by a document that DID
//! signs.
//!
//! The bearer routes of the branding, the requested attributes, the vetter
//! grants, the automatic grant and the withdrawal notices stay while
//! `vtc-client` calls them; the others have none.
//!
//! The listings page in memory: every one of these collections is an
//! administrator's view of one community, bounded by what the community holds,
//! so the cursor is the offset of the next item.

use serde::Serialize;
use serde_json::{Value, json};
use trust_tasks_rs::specs::vtc::community::{
    branding::{show::v0_1 as branding_show, update::v0_1 as branding_update},
    join_discovery::{show::v0_1 as join_discovery_show, update::v0_1 as join_discovery_update},
    requested_attributes::{show::v0_1 as requested_show, update::v0_1 as requested_update},
};
use trust_tasks_rs::specs::vtc::join_requests::{
    query::v0_1 as join_query, vetting::show::v0_1 as join_vetting_show,
};
use trust_tasks_rs::specs::vtc::relationships::{
    restore::v0_1 as rel_restore, suspend::v0_1 as rel_suspend,
};
use trust_tasks_rs::specs::vtc::rooms::list::v0_1 as rooms_list;
use trust_tasks_rs::specs::vtc::schemas::{
    accepts::{
        delete::v0_1 as accepts_delete, list::v0_2 as accepts_list,
        register::v0_2 as accepts_register, show::v0_2 as accepts_show,
    },
    delete::v0_1 as schemas_delete,
    list::v0_1 as schemas_list,
    register::v0_1 as schemas_register,
    show::v0_1 as schemas_show,
};
use trust_tasks_rs::specs::vtc::vetting::{
    auto_grant::{show::v0_1 as auto_grant_show, update::v0_1 as auto_grant_update},
    revocations::list::v0_1 as revocations_list,
    vetters::grants::list::v0_1 as grants_list,
};
use trust_tasks_rs::{Payload, RejectReason, TrustTask};
use uuid::Uuid;

use super::admin_tasks::member_signer;
use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, parse_payload, reject_with,
    reject_with_code, success_response, task_error_to_reject,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::error::AppError;
use crate::server::AppState;

pub(crate) const BRANDING_SHOW_TYPE: &str = <branding_show::Payload as Payload>::TYPE_URI;
pub(crate) const BRANDING_UPDATE_TYPE: &str = <branding_update::Payload as Payload>::TYPE_URI;
pub(crate) const REQUESTED_SHOW_TYPE: &str = <requested_show::Payload as Payload>::TYPE_URI;
pub(crate) const REQUESTED_UPDATE_TYPE: &str = <requested_update::Payload as Payload>::TYPE_URI;
pub(crate) const JOIN_DISCOVERY_SHOW_TYPE: &str =
    <join_discovery_show::Payload as Payload>::TYPE_URI;
pub(crate) const JOIN_DISCOVERY_UPDATE_TYPE: &str =
    <join_discovery_update::Payload as Payload>::TYPE_URI;
pub(crate) const SCHEMAS_REGISTER_TYPE: &str = <schemas_register::Payload as Payload>::TYPE_URI;
pub(crate) const SCHEMAS_LIST_TYPE: &str = <schemas_list::Payload as Payload>::TYPE_URI;
pub(crate) const SCHEMAS_SHOW_TYPE: &str = <schemas_show::Payload as Payload>::TYPE_URI;
pub(crate) const SCHEMAS_DELETE_TYPE: &str = <schemas_delete::Payload as Payload>::TYPE_URI;
pub(crate) const ACCEPTS_REGISTER_TYPE: &str = <accepts_register::Payload as Payload>::TYPE_URI;
pub(crate) const ACCEPTS_LIST_TYPE: &str = <accepts_list::Payload as Payload>::TYPE_URI;
pub(crate) const ACCEPTS_SHOW_TYPE: &str = <accepts_show::Payload as Payload>::TYPE_URI;
pub(crate) const ACCEPTS_DELETE_TYPE: &str = <accepts_delete::Payload as Payload>::TYPE_URI;
pub(crate) const VETTER_GRANTS_LIST_TYPE: &str = <grants_list::Payload as Payload>::TYPE_URI;
pub(crate) const AUTO_GRANT_SHOW_TYPE: &str = <auto_grant_show::Payload as Payload>::TYPE_URI;
pub(crate) const AUTO_GRANT_UPDATE_TYPE: &str = <auto_grant_update::Payload as Payload>::TYPE_URI;
pub(crate) const REVOCATIONS_LIST_TYPE: &str = <revocations_list::Payload as Payload>::TYPE_URI;
pub(crate) const RELATIONSHIPS_SUSPEND_TYPE: &str = <rel_suspend::Payload as Payload>::TYPE_URI;
pub(crate) const RELATIONSHIPS_RESTORE_TYPE: &str = <rel_restore::Payload as Payload>::TYPE_URI;
pub(crate) const JOIN_VETTING_SHOW_TYPE: &str = <join_vetting_show::Payload as Payload>::TYPE_URI;
pub(crate) const JOIN_QUERY_TYPE: &str = <join_query::Payload as Payload>::TYPE_URI;
pub(crate) const ROOMS_LIST_TYPE: &str = <rooms_list::Payload as Payload>::TYPE_URI;

// ─── the codes these tasks declare, as the error-code census witnesses them ─

pub(crate) const REQUESTED_ERR_DUPLICATE_TYPE: &str =
    requested_update::error_codes::DUPLICATE_TYPE.code;
pub(crate) const SCHEMAS_REGISTER_ERR_INVALID_CREDENTIAL_SCHEMA: &str =
    schemas_register::error_codes::INVALID_CREDENTIAL_SCHEMA.code;
pub(crate) const SCHEMAS_SHOW_ERR_NOT_FOUND: &str = schemas_show::error_codes::NOT_FOUND.code;
pub(crate) const SCHEMAS_DELETE_ERR_NOT_FOUND: &str = schemas_delete::error_codes::NOT_FOUND.code;
pub(crate) const SCHEMAS_DELETE_ERR_IN_USE: &str = schemas_delete::error_codes::IN_USE.code;
pub(crate) const ACCEPTS_REGISTER_ERR_INVALID_QUERY: &str =
    accepts_register::error_codes::INVALID_QUERY.code;
pub(crate) const ACCEPTS_REGISTER_ERR_UNREGISTERED_TYPE: &str =
    accepts_register::error_codes::UNREGISTERED_TYPE.code;
pub(crate) const ACCEPTS_REGISTER_ERR_UNREGISTERED_STATEMENT_TYPE: &str =
    accepts_register::error_codes::UNREGISTERED_STATEMENT_TYPE.code;
pub(crate) const ACCEPTS_REGISTER_ERR_INVALID_VETTING: &str =
    accepts_register::error_codes::INVALID_VETTING.code;
pub(crate) const ACCEPTS_REGISTER_ERR_NOT_PUBLISHABLE: &str =
    accepts_register::error_codes::NOT_PUBLISHABLE.code;
pub(crate) const ACCEPTS_REGISTER_ERR_UNSUPPORTED_REQUIREMENT: &str =
    accepts_register::error_codes::UNSUPPORTED_REQUIREMENT.code;
pub(crate) const ACCEPTS_SHOW_ERR_NOT_FOUND: &str = accepts_show::error_codes::NOT_FOUND.code;
pub(crate) const ACCEPTS_DELETE_ERR_NOT_FOUND: &str = accepts_delete::error_codes::NOT_FOUND.code;
pub(crate) const SUSPEND_ERR_NOT_FOUND: &str = rel_suspend::error_codes::NOT_FOUND.code;
pub(crate) const SUSPEND_ERR_ALREADY_SUSPENDED: &str =
    rel_suspend::error_codes::ALREADY_SUSPENDED.code;
pub(crate) const SUSPEND_ERR_TERMINAL: &str = rel_suspend::error_codes::TERMINAL.code;
pub(crate) const RESTORE_ERR_NOT_FOUND: &str = rel_restore::error_codes::NOT_FOUND.code;
pub(crate) const RESTORE_ERR_NOT_SUSPENDED: &str = rel_restore::error_codes::NOT_SUSPENDED.code;
pub(crate) const RESTORE_ERR_TERMINAL: &str = rel_restore::error_codes::TERMINAL.code;
pub(crate) const JOIN_VETTING_ERR_NOT_FOUND: &str = join_vetting_show::error_codes::NOT_FOUND.code;
pub(crate) const JOIN_QUERY_ERR_CRITERION_NOT_FOUND: &str =
    join_query::error_codes::CRITERION_NOT_FOUND.code;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    BRANDING_SHOW_TYPE,
    BRANDING_UPDATE_TYPE,
    REQUESTED_SHOW_TYPE,
    REQUESTED_UPDATE_TYPE,
    JOIN_DISCOVERY_SHOW_TYPE,
    JOIN_DISCOVERY_UPDATE_TYPE,
    SCHEMAS_REGISTER_TYPE,
    SCHEMAS_LIST_TYPE,
    SCHEMAS_SHOW_TYPE,
    SCHEMAS_DELETE_TYPE,
    ACCEPTS_REGISTER_TYPE,
    ACCEPTS_LIST_TYPE,
    ACCEPTS_SHOW_TYPE,
    ACCEPTS_DELETE_TYPE,
    VETTER_GRANTS_LIST_TYPE,
    AUTO_GRANT_SHOW_TYPE,
    AUTO_GRANT_UPDATE_TYPE,
    REVOCATIONS_LIST_TYPE,
    RELATIONSHIPS_SUSPEND_TYPE,
    RELATIONSHIPS_RESTORE_TYPE,
    JOIN_VETTING_SHOW_TYPE,
    JOIN_QUERY_TYPE,
    ROOMS_LIST_TYPE,
];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        BRANDING_SHOW_TYPE => handle_branding_show(state, ctx, doc).await,
        BRANDING_UPDATE_TYPE => handle_branding_update(state, ctx, doc).await,
        REQUESTED_SHOW_TYPE => handle_requested_show(state, ctx, doc).await,
        REQUESTED_UPDATE_TYPE => handle_requested_update(state, ctx, doc).await,
        JOIN_DISCOVERY_SHOW_TYPE => handle_join_discovery_show(state, ctx, doc).await,
        JOIN_DISCOVERY_UPDATE_TYPE => handle_join_discovery_update(state, ctx, doc).await,
        SCHEMAS_REGISTER_TYPE => handle_schemas_register(state, ctx, doc).await,
        SCHEMAS_LIST_TYPE => handle_schemas_list(state, ctx, doc).await,
        SCHEMAS_SHOW_TYPE => handle_schemas_show(state, ctx, doc).await,
        SCHEMAS_DELETE_TYPE => handle_schemas_delete(state, ctx, doc).await,
        ACCEPTS_REGISTER_TYPE => handle_accepts_register(state, ctx, doc).await,
        ACCEPTS_LIST_TYPE => handle_accepts_list(state, ctx, doc).await,
        ACCEPTS_SHOW_TYPE => handle_accepts_show(state, ctx, doc).await,
        ACCEPTS_DELETE_TYPE => handle_accepts_delete(state, ctx, doc).await,
        VETTER_GRANTS_LIST_TYPE => handle_vetter_grants_list(state, ctx, doc).await,
        AUTO_GRANT_SHOW_TYPE => handle_auto_grant_show(state, ctx, doc).await,
        AUTO_GRANT_UPDATE_TYPE => handle_auto_grant_update(state, ctx, doc).await,
        REVOCATIONS_LIST_TYPE => handle_revocations_list(state, ctx, doc).await,
        RELATIONSHIPS_SUSPEND_TYPE => {
            handle_edge_lifecycle(state, ctx, doc, EdgeVerb::Suspend).await
        }
        RELATIONSHIPS_RESTORE_TYPE => {
            handle_edge_lifecycle(state, ctx, doc, EdgeVerb::Restore).await
        }
        JOIN_VETTING_SHOW_TYPE => handle_join_vetting_show(state, ctx, doc).await,
        JOIN_QUERY_TYPE => handle_join_query(state, ctx, doc).await,
        ROOMS_LIST_TYPE => handle_rooms_list(state, ctx, doc).await,
        _ => return None,
    })
}

// ─── authority, payloads and pages ───────────────────────────────────────

/// The signer as an administrator of any role, with its payload held to the
/// published schema — the gate on this family's reads. A write asks the
/// capability it needs instead ([`as_capable`]).
async fn as_admin<P>(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<String, TrustTaskOutcome>
where
    P: trust_tasks_rs::validate::ValidatedPayload + serde::de::DeserializeOwned,
{
    let actor = admin_signer(state, ctx, doc).await?;
    parse_spec_payload::<P>(doc)?;
    Ok(actor.did)
}

/// The signer holding `cap` (`vtc-admin-roles.md` §4 "Gates"), with its
/// payload held to the published schema.
async fn as_capable<P>(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
    cap: crate::acl::Capability,
) -> Result<String, TrustTaskOutcome>
where
    P: trust_tasks_rs::validate::ValidatedPayload + serde::de::DeserializeOwned,
{
    let actor = super::capable_signer(state, ctx, doc, cap, None).await?;
    parse_spec_payload::<P>(doc)?;
    Ok(actor.did)
}

/// Any signer the community holds an entry for, with its payload held to the
/// published schema.
async fn as_member<P>(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<String, TrustTaskOutcome>
where
    P: trust_tasks_rs::validate::ValidatedPayload + serde::de::DeserializeOwned,
{
    let actor = member_signer(state, ctx, doc).await?;
    parse_spec_payload::<P>(doc)?;
    Ok(actor.did)
}

/// The default and largest page, as the listing specifications state them.
const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 100;

/// One page of `items` from the payload's `cursor` and `limit`, as
/// `{ items, nextCursor? }`. The cursor is the decimal offset of the next item,
/// prefixed so that a cursor from another listing's scheme is refused rather
/// than read as an offset.
fn page<T: Serialize>(doc: &TrustTask<Value>, items: Vec<T>) -> TrustTaskOutcome {
    let start = match doc.payload.get("cursor").and_then(Value::as_str) {
        None => 0,
        Some(c) => match c.strip_prefix("o").and_then(|n| n.parse::<usize>().ok()) {
            Some(n) if n <= items.len() => n,
            _ => {
                return reject_with(
                    doc,
                    RejectReason::MalformedRequest {
                        reason: "cursor is not one this listing issued".into(),
                    },
                );
            }
        },
    };
    let limit = doc
        .payload
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(DEFAULT_PAGE, |l| (l as usize).clamp(1, MAX_PAGE));
    let end = start.saturating_add(limit).min(items.len());
    let next = (end < items.len()).then(|| format!("o{end}"));
    let slice: Vec<&T> = items[start..end].iter().collect();
    let mut body = json!({ "items": slice });
    if let Some(next) = next {
        body["nextCursor"] = Value::String(next);
    }
    success_response(doc, body)
}

/// The payload member `field`, parsed as the route parsed its body.
fn member_of<T: serde::de::DeserializeOwned>(
    doc: &TrustTask<Value>,
    field: &str,
) -> Result<T, TrustTaskOutcome> {
    serde_json::from_value(doc.payload.get(field).cloned().unwrap_or(Value::Null)).map_err(|e| {
        reject_with(
            doc,
            RejectReason::MalformedRequest {
                reason: format!("payload.{field}: {e}"),
            },
        )
    })
}

/// The payload's own members without `ext`, for a route type that refuses
/// unknown members.
fn without_ext(doc: &TrustTask<Value>) -> Value {
    let mut v = doc.payload.clone();
    if let Some(map) = v.as_object_mut() {
        map.remove("ext");
    }
    v
}

fn declared(doc: &TrustTask<Value>, code: &str, message: impl Into<String>) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, None)
}

/// A declared code carrying `err`'s kind as `details.reason` (`not_found`,
/// `conflict`), the marker `vtc-client` reads a typed error back from.
fn declared_as(doc: &TrustTask<Value>, code: &'static str, err: AppError) -> TrustTaskOutcome {
    task_error_to_reject(doc, &crate::error::TaskError::declared(code, err))
}

// ─── how the community presents itself ───────────────────────────────────

async fn handle_branding_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = as_member::<branding_show::Payload>(state, ctx, &doc).await {
        return reject;
    }
    match crate::community::branding::load_branding(&state.community_ks).await {
        Ok(b) => success_response(&doc, json!({ "branding": b })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_branding_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match as_capable::<branding_update::Payload>(
        state,
        ctx,
        &doc,
        crate::acl::Capability::SurfaceAdmin,
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let body = doc.payload.get("branding").cloned().unwrap_or(Value::Null);
    match crate::routes::community::branding::update_branding(state, &actor, &body).await {
        Ok(b) => success_response(&doc, json!({ "branding": b })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_requested_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = as_member::<requested_show::Payload>(state, ctx, &doc).await {
        return reject;
    }
    match crate::community::requested_attributes::load_requested(&state.community_ks).await {
        Ok(r) => success_response(&doc, json!({ "requestedAttributes": r })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_requested_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match as_capable::<requested_update::Payload>(
        state,
        ctx,
        &doc,
        crate::acl::Capability::SurfaceAdmin,
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let body = doc
        .payload
        .get("requestedAttributes")
        .cloned()
        .unwrap_or(Value::Null);
    // A type asked for twice is the one refusal the specification names.
    if let Some(list) = body.as_array() {
        let mut seen = std::collections::BTreeSet::new();
        for t in list.iter().filter_map(|a| a["type"].as_str()) {
            if !seen.insert(t) {
                return declared(
                    &doc,
                    REQUESTED_ERR_DUPLICATE_TYPE,
                    format!("`{t}` is requested twice"),
                );
            }
        }
    }
    match crate::routes::community::requested_attributes::update_requested_attributes(
        state, &actor, body,
    )
    .await
    {
        Ok(r) => success_response(&doc, json!({ "requestedAttributes": r })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_join_discovery_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = as_member::<join_discovery_show::Payload>(state, ctx, &doc).await {
        return reject;
    }
    match crate::routes::community::join_discovery::show_join_discovery(state).await {
        Ok(d) => success_response(&doc, json!({ "joinDiscovery": d })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_join_discovery_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match as_capable::<join_discovery_update::Payload>(
        state,
        ctx,
        &doc,
        crate::acl::Capability::SurfaceAdmin,
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let mut setting = doc
        .payload
        .get("joinDiscovery")
        .cloned()
        .unwrap_or(Value::Null);
    if let Some(map) = setting.as_object_mut() {
        map.remove("ext");
    }
    let setting: crate::community::join_discovery::JoinDiscovery =
        match serde_json::from_value(setting) {
            Ok(s) => s,
            Err(e) => {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: format!("payload.joinDiscovery: {e}"),
                    },
                );
            }
        };
    match crate::routes::community::join_discovery::update_join_discovery(state, &actor, &setting)
        .await
    {
        Ok(d) => success_response(&doc, json!({ "joinDiscovery": d })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── the credential-schema registry ──────────────────────────────────────

async fn handle_schemas_register(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match as_capable::<schemas_register::Payload>(
        state,
        ctx,
        &doc,
        crate::acl::Capability::SurfaceAdmin,
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let body: crate::routes::schemas::RegisterSchemaBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    if let Some(schema) = &body.credential_schema
        && let Err(e) = jsonschema::validator_for(schema)
    {
        return declared(
            &doc,
            SCHEMAS_REGISTER_ERR_INVALID_CREDENTIAL_SCHEMA,
            format!("credentialSchema does not compile: {e}"),
        );
    }
    match crate::routes::schemas::register_inner(state, &actor, body).await {
        Ok(entry) => success_response(&doc, json!({ "schema": entry })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// A registry entry as a listing shows it: whether it carries a credential
/// schema, not the schema itself.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SchemaSummary {
    pub(crate) type_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dtg_type: Option<String>,
    pub(crate) kind: crate::schemas::SchemaKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    pub(crate) has_credential_schema: bool,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
    pub(crate) created_by_did: String,
}

async fn handle_schemas_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = as_admin::<schemas_list::Payload>(state, ctx, &doc).await {
        return reject;
    }
    let kind: Option<crate::schemas::SchemaKind> = match member_of(&doc, "kind") {
        Ok(k) => k,
        Err(reject) => return reject,
    };
    let mut entries = match crate::schemas::list_schemas(&state.schemas_ks).await {
        Ok(e) => e,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    entries.sort_by(|a, b| a.type_uri.cmp(&b.type_uri));
    let items: Vec<SchemaSummary> = entries
        .into_iter()
        .filter(|e| kind.is_none_or(|k| e.kind == k))
        .map(|e| SchemaSummary {
            has_credential_schema: e.credential_schema.is_some(),
            type_uri: e.type_uri,
            dtg_type: e.dtg_type,
            kind: e.kind,
            description: e.description,
            created_at: e.created_at,
            created_by_did: e.created_by_did,
        })
        .collect();
    page(&doc, items)
}

async fn handle_schemas_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = as_admin::<schemas_show::Payload>(state, ctx, &doc).await {
        return reject;
    }
    let type_uri: String = match member_of(&doc, "typeUri") {
        Ok(t) => t,
        Err(reject) => return reject,
    };
    match crate::schemas::get_schema(&state.schemas_ks, type_uri.trim()).await {
        Ok(Some(entry)) => success_response(&doc, json!({ "schema": entry })),
        Ok(None) => declared_as(
            &doc,
            SCHEMAS_SHOW_ERR_NOT_FOUND,
            AppError::NotFound(format!("schema `{type_uri}` not found")),
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_schemas_delete(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match as_capable::<schemas_delete::Payload>(
        state,
        ctx,
        &doc,
        crate::acl::Capability::SurfaceAdmin,
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let type_uri: String = match member_of(&doc, "typeUri") {
        Ok(t) => t,
        Err(reject) => return reject,
    };
    // A criterion whose query names the type would be left unevaluable.
    let type_uri = type_uri.trim().to_string();
    let criteria = match crate::schemas::list_accepts(&state.schemas_ks).await {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let users: Vec<String> = criteria
        .into_iter()
        .filter(|c| {
            c.dcql()
                .ok()
                .flatten()
                .is_some_and(|q| crate::schemas::accepts::referenced_types(&q).contains(&type_uri))
        })
        .map(|c| c.id)
        .collect();
    if !users.is_empty() {
        return reject_with_code(
            &doc,
            extended_code(SCHEMAS_DELETE_ERR_IN_USE),
            format!(
                "`{type_uri}` is referenced by the Accepts criteria {}; delete or re-register \
                 them first",
                users.join(", ")
            ),
            Some(json!({ "criterionIds": users.iter().take(16).collect::<Vec<_>>() })),
        );
    }
    match crate::routes::schemas::delete_inner(state, &actor, &type_uri).await {
        Ok(id) => success_response(&doc, json!({ "typeUri": id })),
        Err(e @ AppError::NotFound(_)) => declared_as(&doc, SCHEMAS_DELETE_ERR_NOT_FOUND, e),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_accepts_register(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match as_capable::<accepts_register::Payload>(
        state,
        ctx,
        &doc,
        crate::acl::Capability::SurfaceAdmin,
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let body: accepts_register::Payload = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let criterion = match accepts_criterion_from(body) {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    // The refusals the specification orders: the query parses, the types it
    // names are registered, the statement type is registered, the vetting
    // requirements are satisfiable, every requirement is one this community
    // can evaluate, and the manifest can publish the result.
    if let Some(query) = &criterion.query
        && let Err(AppError::Validation(m)) =
            crate::schemas::accepts::validate_accepts_query(&state.schemas_ks, query).await
    {
        let code = if m.starts_with("invalid DCQL query") {
            ACCEPTS_REGISTER_ERR_INVALID_QUERY
        } else {
            ACCEPTS_REGISTER_ERR_UNREGISTERED_TYPE
        };
        return declared(&doc, code, m);
    }
    if let Some(vetting) = &criterion.vetting {
        match crate::endorsement_types::storage::type_exists(
            &state.endorsement_types_ks,
            &vetting.statement_type,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                return declared(
                    &doc,
                    ACCEPTS_REGISTER_ERR_UNREGISTERED_STATEMENT_TYPE,
                    format!(
                        "vetting.statementType `{}` is not a registered endorsement type — \
                         register it with vtc/endorsement-types/register first",
                        vetting.statement_type
                    ),
                );
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        }
        use vta_sdk::protocols::vetting::CheckShape as _;
        if let Err(e) = vetting.check_shape() {
            return declared(
                &doc,
                ACCEPTS_REGISTER_ERR_INVALID_VETTING,
                format!("vetting: {e}"),
            );
        }
    }
    if let Some(reason) = unsupported_requirement(state, &criterion) {
        return declared(&doc, ACCEPTS_REGISTER_ERR_UNSUPPORTED_REQUIREMENT, reason);
    }
    match crate::routes::schemas::register_accepts_inner(state, &actor, criterion).await {
        Ok(criterion) => success_response(&doc, json!({ "criterion": criterion.to_wire() })),
        // Every check above passed, so what is left is the manifest refusing it.
        Err(AppError::Validation(m)) => declared(&doc, ACCEPTS_REGISTER_ERR_NOT_PUBLISHABLE, m),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// The criterion a `vtc/schemas/accepts/register/0.2` payload states, as the
/// store holds it: every requirement it states, and none it does not. The
/// registrant and time are the handler's to set.
fn accepts_criterion_from(
    body: accepts_register::Payload,
) -> Result<crate::schemas::AcceptsCriterion, AppError> {
    use crate::schemas::{Admission, CredentialIssuers};
    let admission = match body.admission {
        accepts_register::Admission::Automatic => Admission::Automatic,
        accepts_register::Admission::Review => Admission::Review,
        // A mode this build does not know is one it cannot honour; refusing is
        // the only reading that does not change what the criterion says.
        #[allow(unreachable_patterns)]
        other => {
            return Err(AppError::Validation(format!(
                "admission `{other}` is not one this community can decide by"
            )));
        }
    };
    let credential_issuers = match body.credential_issuers {
        None => None,
        Some(accepts_register::CredentialIssuers::Any) => Some(CredentialIssuers::Any),
        Some(accepts_register::CredentialIssuers::Community) => Some(CredentialIssuers::Community),
        Some(accepts_register::CredentialIssuers::Recognised) => {
            Some(CredentialIssuers::Recognised)
        }
        #[allow(unreachable_patterns)]
        Some(other) => {
            return Err(AppError::Validation(format!(
                "credentialIssuers `{other}` is not one this community can evaluate"
            )));
        }
    };
    let vetting = body
        .vetting
        .map(|v| serde_json::to_value(v).and_then(serde_json::from_value))
        .transpose()
        .map_err(|e| AppError::Validation(format!("vetting: {e}")))?;
    let mut criterion = crate::schemas::AcceptsCriterion::new(
        String::from(body.id).trim(),
        admission,
        String::new(),
    );
    criterion.query = body.query.map(|q| Value::Object(q.0));
    criterion.credential_issuers = credential_issuers;
    criterion.invitation_required = body.invitation_required.unwrap_or(false);
    criterion.description = body.description.map(String::from);
    criterion.vetting = vetting;
    Ok(criterion)
}

/// A requirement the criterion states that this community cannot decide a
/// submission against, if it states one. Only `recognised` issuers can be: a
/// community with no trust registry recognises no other community, and a
/// criterion it publishes must be one it can evaluate.
fn unsupported_requirement(
    state: &AppState,
    criterion: &crate::schemas::AcceptsCriterion,
) -> Option<String> {
    (criterion.credential_issuers == Some(crate::schemas::CredentialIssuers::Recognised)
        && state.registry_client.is_none())
    .then(|| {
        "credentialIssuers `recognised` needs a trust registry to recognise other communities \
         by, and this community has none configured — use `community`, or configure the \
         registry first"
            .to_string()
    })
}

async fn handle_accepts_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = as_admin::<accepts_list::Payload>(state, ctx, &doc).await {
        return reject;
    }
    match crate::schemas::list_accepts(&state.schemas_ks).await {
        Ok(mut criteria) => {
            criteria.sort_by(|a, b| a.id.cmp(&b.id));
            page(&doc, criteria.iter().map(|c| c.to_wire()).collect())
        }
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_accepts_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = as_admin::<accepts_show::Payload>(state, ctx, &doc).await {
        return reject;
    }
    let id: String = match member_of(&doc, "id") {
        Ok(i) => i,
        Err(reject) => return reject,
    };
    match crate::schemas::get_accepts(&state.schemas_ks, id.trim()).await {
        Ok(Some(c)) => success_response(&doc, json!({ "criterion": c.to_wire() })),
        Ok(None) => declared_as(
            &doc,
            ACCEPTS_SHOW_ERR_NOT_FOUND,
            AppError::NotFound(format!("accepts criterion `{id}` not found")),
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_accepts_delete(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match as_capable::<accepts_delete::Payload>(
        state,
        ctx,
        &doc,
        crate::acl::Capability::SurfaceAdmin,
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let id: String = match member_of(&doc, "id") {
        Ok(i) => i,
        Err(reject) => return reject,
    };
    match crate::routes::schemas::delete_accepts_inner(state, &actor, id.trim()).await {
        Ok(id) => success_response(&doc, json!({ "id": id })),
        Err(e @ AppError::NotFound(_)) => declared_as(&doc, ACCEPTS_DELETE_ERR_NOT_FOUND, e),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── the vetting reads ───────────────────────────────────────────────────

async fn handle_vetter_grants_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = as_admin::<grants_list::Payload>(state, ctx, &doc).await {
        return reject;
    }
    match crate::vetting::vetters::grant_rows(state).await {
        Ok(rows) => page(&doc, rows),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_auto_grant_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = as_admin::<auto_grant_show::Payload>(state, ctx, &doc).await {
        return reject;
    }
    match crate::vetting::auto_grant::status(state).await {
        Ok(s) => success_response(&doc, json!({ "autoGrant": s })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_auto_grant_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match as_capable::<auto_grant_update::Payload>(
        state,
        ctx,
        &doc,
        crate::acl::Capability::VettingManage,
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let config: vta_sdk::protocols::vetting::AutoGrantConfig =
        match serde_json::from_value(without_ext(&doc)) {
            Ok(c) => c,
            Err(e) => {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: format!("payload: {e}"),
                    },
                );
            }
        };
    match crate::vetting::auto_grant::configure(state, &actor, &config).await {
        Ok(s) => success_response(&doc, json!({ "autoGrant": s })),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_revocations_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = as_admin::<revocations_list::Payload>(state, ctx, &doc).await {
        return reject;
    }
    let wanted: Option<crate::routes::vetting::RevocationReviewState> =
        match member_of(&doc, "reviewState") {
            Ok(w) => w,
            Err(reject) => return reject,
        };
    match crate::routes::vetting::revocation_rows(state).await {
        Ok(rows) => page(
            &doc,
            rows.into_iter()
                .filter(|r| wanted.is_none_or(|w| r.review_state == w))
                .collect(),
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── the relationship graph's suspend and restore ────────────────────────

#[derive(Clone, Copy)]
enum EdgeVerb {
    Suspend,
    Restore,
}

/// `vtc/relationships/{suspend,restore}/0.1`.
///
/// The edge is loaded first. Its issuer — the signer itself, whatever DID the
/// edge was issued under — acts as issuer; an administrator acts as
/// moderator; anyone else is told `notFound`, as for an edge that does not
/// exist.
async fn handle_edge_lifecycle(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    verb: EdgeVerb,
) -> TrustTaskOutcome {
    use crate::routes::relationships::EdgeLifecycleVerb;
    let (not_found, already, terminal, route_verb) = match verb {
        EdgeVerb::Suspend => (
            SUSPEND_ERR_NOT_FOUND,
            SUSPEND_ERR_ALREADY_SUSPENDED,
            SUSPEND_ERR_TERMINAL,
            EdgeLifecycleVerb::Suspend,
        ),
        EdgeVerb::Restore => (
            RESTORE_ERR_NOT_FOUND,
            RESTORE_ERR_NOT_SUSPENDED,
            RESTORE_ERR_TERMINAL,
            EdgeLifecycleVerb::Restore,
        ),
    };
    let Some(signer) = ctx.verified_signer.clone() else {
        return reject_with(&doc, RejectReason::ProofRequired);
    };
    let valid = match verb {
        EdgeVerb::Suspend => parse_spec_payload::<rel_suspend::Payload>(&doc).map(|_| ()),
        EdgeVerb::Restore => parse_spec_payload::<rel_restore::Payload>(&doc).map(|_| ()),
    };
    if let Err(reject) = valid {
        return reject;
    }
    let id: String = match member_of(&doc, "id") {
        Ok(i) => i,
        Err(reject) => return reject,
    };
    let reason: Option<String> = match member_of(&doc, "reason") {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let missing = |doc: &TrustTask<Value>| {
        declared_as(
            doc,
            not_found,
            AppError::NotFound(format!("VRC {id} not found")),
        )
    };
    let Ok(uuid) = id.parse::<Uuid>() else {
        return missing(&doc);
    };
    let rel = match crate::relationships::get_relationship(&state.relationships_ks, uuid).await {
        Ok(Some(rel)) => rel,
        Ok(None) => return missing(&doc),
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let (actor, capacity) = if signer == rel.issuer_did {
        (signer, "issuer")
    } else {
        // Suspending or restoring another member's relationship is managing
        // members (vtc-admin-roles.md §4).
        match super::capable_signer(
            state,
            ctx,
            &doc,
            crate::acl::Capability::MembersManage,
            None,
        )
        .await
        {
            Ok(admin) => (admin.did, "admin"),
            Err(_) => return missing(&doc),
        }
    };
    match crate::routes::relationships::record_lifecycle_as(
        state, &actor, capacity, &rel, route_verb, reason,
    )
    .await
    {
        Ok(response) => success_response(&doc, response),
        Err(AppError::Conflict(m)) if m.contains("terminal") => {
            declared_as(&doc, terminal, AppError::Conflict(m))
        }
        Err(e @ AppError::Conflict(_)) => declared_as(&doc, already, e),
        Err(AppError::NotFound(_)) => missing(&doc),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── the join queue's vetting facts and credential query ─────────────────

async fn handle_join_vetting_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = as_admin::<join_vetting_show::Payload>(state, ctx, &doc).await {
        return reject;
    }
    let id: String = match member_of(&doc, "id") {
        Ok(i) => i,
        Err(reject) => return reject,
    };
    let not_found = |doc: &TrustTask<Value>| {
        declared_as(
            doc,
            JOIN_VETTING_ERR_NOT_FOUND,
            AppError::NotFound(format!("join request not found: {id}")),
        )
    };
    let Ok(uuid) = id.parse::<Uuid>() else {
        return not_found(&doc);
    };
    match crate::routes::join_requests::read::vetting_of(state, uuid).await {
        Ok(response) => success_response(&doc, response),
        Err(AppError::NotFound(_)) => not_found(&doc),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_join_query(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = as_admin::<join_query::Payload>(state, ctx, &doc).await {
        return reject;
    }
    let body: crate::routes::join_requests::present::SendQueryRequest =
        match serde_json::from_value(without_ext(&doc)) {
            Ok(b) => b,
            Err(e) => {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: format!("payload: {e}"),
                    },
                );
            }
        };
    match crate::routes::join_requests::present::send_query_inner(state, body).await {
        Ok(response) => success_response(&doc, response),
        Err(e @ AppError::NotFound(_)) => declared_as(&doc, JOIN_QUERY_ERR_CRITERION_NOT_FOUND, e),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── the rooms this host stores ──────────────────────────────────────────

async fn handle_rooms_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = as_admin::<rooms_list::Payload>(state, ctx, &doc).await {
        return reject;
    }
    let lifecycle: Option<String> = match member_of(&doc, "lifecycle") {
        Ok(l) => l,
        Err(reject) => return reject,
    };
    match crate::routes::rooms::hosted_rooms(state).await {
        Ok(mut rooms) => {
            rooms.sort_by(|a, b| a.room_id.cmp(&b.room_id));
            page(
                &doc,
                rooms
                    .into_iter()
                    .filter(|r| lifecycle.as_deref().is_none_or(|l| r.lifecycle == l))
                    .collect(),
            )
        }
        Err(e) => app_error_to_reject(&doc, &e),
    }
}
