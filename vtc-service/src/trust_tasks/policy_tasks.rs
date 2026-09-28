//! The community's policy log and its self-hosted DID log on the
//! signed-document spine.
//!
//! | task | authority (the signer's ACL row, read now) |
//! |---|---|
//! | `policy/list/0.2` | `Admin` |
//! | `policy/get/0.1` | `Admin` |
//! | `policy/active/0.1` | `Admin` |
//! | `policy/upsert/0.2` | `Admin` |
//! | `policy/activate/0.1` | `Admin` |
//! | `vtc/policies/test/0.1` | `Admin` |
//! | `did-management/did/register/0.1` | `Admin`, no context scope |
//!
//! Each is the question its bearer route asked: `AdminAuth` for the policy
//! verbs, `SuperAdminAuth` for installing the community's DID log. Every one
//! arrives here the same way over TSP, DIDComm or HTTPS.
//!
//! `policy/upsert` and `did/register` carry documents larger than the 64 KiB
//! default (a Rego module, a DID's whole log), so the spine admits them at the
//! limits [`super::size`] sets, for a signer with standing only.
//!
//! The bearer routes of `policy/{list,get,upsert,activate}` and `did/register`
//! stay while `vtc-client` calls them; `policy/active` and `vtc/policies/test`
//! have none.
//!
//! `policy/list/0.2` has no purpose filter. The console asks for one purpose's
//! revisions, so an `ext` member `org.openvtc.purpose` narrows the listing to
//! it — the same key a revision's own `ext` names its purpose by.

use serde_json::Value;
use trust_tasks_rs::specs::did_management::did::register::v0_1 as did_register;
use trust_tasks_rs::specs::policy::{
    activate::v0_1 as policy_activate, active::v0_1 as policy_active, get::v0_1 as policy_get,
    list::v0_2 as policy_list, upsert::v0_2 as policy_upsert,
};
use trust_tasks_rs::specs::vtc::policies::test::v0_1 as policy_test;
use trust_tasks_rs::{Payload, TrustTask};
use uuid::Uuid;
use vti_common::auth::extractor::AuthClaims;

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, parse_payload, reject_with_code,
    success_response, task_error_to_reject,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::error::AppError;
use crate::policy::PolicyPurpose;
use crate::routes::policies::{admin as policy_admin, read as policy_read};
use crate::server::AppState;

pub(crate) const POLICY_LIST_TYPE: &str = <policy_list::Payload as Payload>::TYPE_URI;
pub(crate) const POLICY_GET_TYPE: &str = <policy_get::Payload as Payload>::TYPE_URI;
pub(crate) const POLICY_ACTIVE_TYPE: &str = <policy_active::Payload as Payload>::TYPE_URI;
pub(crate) const POLICY_UPSERT_TYPE: &str = <policy_upsert::Payload as Payload>::TYPE_URI;
pub(crate) const POLICY_ACTIVATE_TYPE: &str = <policy_activate::Payload as Payload>::TYPE_URI;
pub(crate) const POLICY_TEST_TYPE: &str = <policy_test::Payload as Payload>::TYPE_URI;
pub(crate) const DID_REGISTER_TYPE: &str = <did_register::Payload as Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    POLICY_LIST_TYPE,
    POLICY_GET_TYPE,
    POLICY_ACTIVE_TYPE,
    POLICY_UPSERT_TYPE,
    POLICY_ACTIVATE_TYPE,
    POLICY_TEST_TYPE,
    DID_REGISTER_TYPE,
];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        POLICY_LIST_TYPE => handle_list(state, ctx, doc).await,
        POLICY_GET_TYPE => handle_get(state, ctx, doc).await,
        POLICY_ACTIVE_TYPE => handle_active(state, ctx, doc).await,
        POLICY_UPSERT_TYPE => handle_upsert(state, ctx, doc).await,
        POLICY_ACTIVATE_TYPE => handle_activate(state, ctx, doc).await,
        POLICY_TEST_TYPE => handle_test(state, ctx, doc).await,
        DID_REGISTER_TYPE => handle_did_register(state, ctx, doc).await,
        _ => return None,
    })
}

/// The signer as an administrator (the routes' `AdminAuth`), and its payload
/// validated against the published schema.
async fn admin_with<P>(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<(AuthClaims, P), TrustTaskOutcome>
where
    P: trust_tasks_rs::validate::ValidatedPayload + serde::de::DeserializeOwned,
{
    let actor = admin_signer(state, ctx, doc).await?;
    let payload = parse_spec_payload::<P>(doc)?;
    Ok((actor, payload))
}

/// A revision id, as the route's path parsed it.
fn revision_id(doc: &TrustTask<Value>, raw: &str) -> Result<Uuid, TrustTaskOutcome> {
    raw.parse().map_err(|_| {
        app_error_to_reject(
            doc,
            &AppError::Validation(format!("policy id {raw:?} is not a UUID")),
        )
    })
}

async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = admin_with::<policy_list::Payload>(state, ctx, &doc).await {
        return reject;
    }
    // The route's own query: its refusal of the filters this maintainer does
    // not implement, and its cursor binding.
    let mut query: policy_read::ListPoliciesQuery = match parse_payload(&doc) {
        Ok(q) => q,
        Err(reject) => return reject,
    };
    if let Some(raw) = doc.payload["ext"][policy_read::PURPOSE_EXT_KEY].as_str() {
        match serde_json::from_value::<PolicyPurpose>(Value::String(raw.to_owned())) {
            Ok(purpose) => query.purpose = Some(purpose),
            Err(e) => {
                return app_error_to_reject(
                    &doc,
                    &AppError::Validation(format!(
                        "ext.{} {raw:?} is not a known purpose: {e}",
                        policy_read::PURPOSE_EXT_KEY
                    )),
                );
            }
        }
    }
    match policy_read::list_policies_inner(state, query).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_get(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (_, payload) = match admin_with::<policy_get::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let id = match revision_id(&doc, payload.id.as_str()) {
        Ok(id) => id,
        Err(reject) => return reject,
    };
    match policy_read::show_policy_inner(state, id).await {
        Ok(response) => success_response(&doc, response),
        Err(AppError::NotFound(message)) => reject_with_code(
            &doc,
            extended_code(policy_get::error_codes::NOT_FOUND.code),
            message,
            None,
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_active(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = admin_with::<policy_active::Payload>(state, ctx, &doc).await {
        return reject;
    }
    let query: policy_read::ActiveQuery = match parse_payload(&doc) {
        Ok(q) => q,
        Err(reject) => return reject,
    };
    match policy_read::active_policies(state, query).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_upsert(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, _) = match admin_with::<policy_upsert::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    // The route's own body: its purpose binding through `ext`, and its refusal
    // of the selection hints this maintainer does not honour.
    let body: policy_admin::UploadBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match policy_admin::upload_inner(state, &actor.did, body).await {
        Ok(response) => success_response(&doc, response),
        Err(AppError::Conflict(message)) => reject_with_code(
            &doc,
            extended_code(policy_upsert::error_codes::VERSION_CONFLICT.code),
            message,
            None,
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_activate(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, payload) = match admin_with::<policy_activate::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    if payload.context_id.is_some() {
        return app_error_to_reject(
            &doc,
            &AppError::Validation(
                "this maintainer does not implement contextId: a VTC is a single community and \
                 its policy bindings are community-wide"
                    .into(),
            ),
        );
    }
    let id = match revision_id(&doc, payload.id.as_str()) {
        Ok(id) => id,
        Err(reject) => return reject,
    };
    let purpose =
        match serde_json::from_value::<PolicyPurpose>(Value::String(payload.purpose.to_string())) {
            Ok(p) => p,
            Err(e) => {
                return app_error_to_reject(
                    &doc,
                    &AppError::Validation(format!(
                        "purpose {:?} is not one this community decides: {e}",
                        payload.purpose.to_string()
                    )),
                );
            }
        };
    match policy_admin::activate_inner(state, &actor.did, id, Some(purpose)).await {
        Ok(response) => success_response(&doc, response),
        Err(AppError::NotFound(message)) => reject_with_code(
            &doc,
            extended_code(policy_activate::error_codes::NOT_FOUND.code),
            message,
            None,
        ),
        Err(AppError::Conflict(message)) => reject_with_code(
            &doc,
            extended_code(policy_activate::error_codes::ALREADY_ACTIVE.code),
            message,
            None,
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_test(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let (actor, payload) = match admin_with::<policy_test::Payload>(state, ctx, &doc).await {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let id = match revision_id(&doc, payload.id.as_str()) {
        Ok(id) => id,
        Err(reject) => return reject,
    };
    let body: policy_admin::TestBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match policy_admin::test(state, &actor.did, id, body).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `did-management/did/register/0.1` — the route's `SuperAdminAuth`: an
/// administrator with no context scope.
async fn handle_did_register(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Authority before the payload, as the route's extractor ran first.
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if let Err(e) = actor.require_super_admin() {
        return app_error_to_reject(&doc, &e);
    }
    let payload = match parse_spec_payload::<did_register::Payload>(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::routes::admin::did_register::register_inner(state, &actor.did, payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}
