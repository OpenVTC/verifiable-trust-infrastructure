//! External accounts (`external/*/0.1`, trust-tasks-tf #740) — the VTA as the
//! key authority for cloud and third-party accounts.
//!
//! The account store, drivers and scope checks live in `vta-external`; this
//! slice is the dispatch surface over them. Design:
//! `docs/05-design-notes/vta-external-accounts.md`.
//!
//! - **Management** (`external/accounts/*`) needs `external-accounts-manage` in
//!   the account's context, through the caller's act scope. Whether a change
//!   also needs other administrators is the approvals policy's decision, made
//!   on the spine before this slice runs (`pnm approvals require …`); suspend
//!   and binding revocation are meant to stay outside it.
//! - **Reads** (`list`, `get`) also answer a bound consumer — its own binding
//!   only, every other one omitted.
//! - **Issuance** (`external/credentials/issue`) checks, in the specification's
//!   order, before anything is signed: the account, the binding, the
//!   capability, the ceiling, the TTL, the rate. The credential leaves only
//!   sealed to the caller.
//!
//! Wire values are parsed into the generated `trust_tasks_rs::specs::external`
//! types (which validates them) and answered by rendering JSON through the
//! generated response type of each task, so a response that drifted from its
//! schema fails here rather than at a consumer.

use chrono::Utc;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::external as ext;

use vti_common::acl::Capability;
use vti_common::error::AppError;

use vta_external::driver::{self, DriverError, IssueRequest};
use vta_external::model::{AccountRecord, AccountState, Binding, SecretInfo, rfc3339};
use vta_external::scope::{self, RequestedScope, ScopeRefusal};
use vta_external::{fingerprint, store};

use crate::auth::AuthClaims;
use crate::server::AppState;

use trust_tasks_rs::RejectReason;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, reject_declared,
    reject_with, reject_with_code, success_response,
};

// ─── Shared plumbing ─────────────────────────────────────────────────────────

/// Whether the caller holds `cap`: its ACL entry's effective set, or — with no
/// entry, as for the offline CLI's synthesized claims — its role's. Mirrors
/// [`super::helpers::require_capability`], answering a bool so a read can fall
/// through from one standing to the next.
async fn holds(state: &AppState, auth: &AuthClaims, cap: Capability) -> bool {
    match vti_common::acl::get_acl_entry(&state.acl_ks, &auth.did).await {
        Ok(Some(entry)) => vti_common::acl::entry_has_capability(&entry, cap),
        Ok(None) => vti_common::acl::role_has_capability(&auth.role, cap),
        Err(e) => {
            tracing::error!(error = %e, did = %auth.did, "ACL read failed during an external-accounts check; refusing");
            false
        }
    }
}

/// `external-accounts-manage` in `context`, through the act scope.
async fn require_manage(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    context: &str,
) -> Result<(), TrustTaskOutcome> {
    if holds(state, auth, Capability::ExternalAccountsManage).await
        && auth.has_context_access(context)
    {
        return Ok(());
    }
    Err(reject_with(
        doc,
        RejectReason::PermissionDenied {
            reason: format!(
                "{} does not hold external-accounts-manage in context {context}",
                auth.did
            ),
        },
    ))
}

/// Answer with `value` rendered through the task's generated response type `R`.
fn respond<R: DeserializeOwned + Serialize>(
    doc: &TrustTask<Value>,
    value: Value,
) -> TrustTaskOutcome {
    match serde_json::from_value::<R>(value) {
        Ok(r) => success_response(doc, r),
        Err(e) => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("{} response does not match its schema: {e}", doc.type_uri),
            },
        ),
    }
}

/// The account's wire form, with its egress hosts derived from its settings.
fn wire(rec: &AccountRecord) -> Value {
    let egress = driver::driver_for(rec.model())
        .map(|d| d.egress_hosts(&rec.settings))
        .unwrap_or_default();
    rec.to_wire(&egress)
}

/// The account as a bound consumer may see it: its own binding, no other.
fn wire_for_consumer(rec: &AccountRecord, consumer: &str) -> Value {
    let mut view = rec.clone();
    view.bindings.retain(|b| b.consumer == consumer);
    wire(&view)
}

/// A value of a generated payload as JSON, for the domain types to read.
fn json_of<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

async fn audit(
    state: &AppState,
    action: &str,
    auth: &AuthClaims,
    resource: &str,
    outcome: &str,
    context: &str,
) {
    if let Err(e) = crate::audit::record(
        &state.audit_sink,
        action,
        &auth.did,
        Some(resource),
        outcome,
        Some(TRANSPORT_TRUST_TASK),
        Some(context),
    )
    .await
    {
        tracing::warn!(error = %e, action, "audit record failed for an external-accounts task");
    }
}

async fn audit_detail(
    state: &AppState,
    action: &str,
    auth: &AuthClaims,
    resource: &str,
    outcome: &str,
    context: &str,
    detail: &str,
) {
    if let Err(e) = crate::audit::record_with_detail(
        &state.audit_sink,
        action,
        &auth.did,
        Some(resource),
        outcome,
        Some(TRANSPORT_TRUST_TASK),
        Some(context),
        Some(detail),
    )
    .await
    {
        tracing::warn!(error = %e, action, "audit record failed for an external-accounts task");
    }
}

/// Load an account for management, answering `external:notFound` when absent.
async fn load_for_manage(
    state: &AppState,
    doc: &TrustTask<Value>,
    context: &str,
    id: &str,
    not_found: trust_tasks_rs::DeclaredErrorCode,
) -> Result<AccountRecord, TrustTaskOutcome> {
    match store::get(&state.external_accounts_ks, context, id).await {
        Ok(Some(rec)) => Ok(rec),
        Ok(None) => Err(reject_declared(
            doc,
            not_found,
            format!("no external account {id} in context {context}"),
        )),
        Err(e) => Err(app_error_to_reject(doc, e)),
    }
}

/// `context` and `id`, common to every account task.
fn context_and_id(doc: &TrustTask<Value>) -> (String, String) {
    let s = |k: &str| {
        doc.payload
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    (s("context"), s("id"))
}

// ─── Reads ───────────────────────────────────────────────────────────────────

const LIST_DEFAULT_LIMIT: usize = 50;

/// `external/accounts/list/0.1`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::list::v0_1 as t;
    let req: t::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let context = req.context.to_string();
    let in_context = auth.has_context_access(&context);
    let manager = in_context && holds(state, auth, Capability::ExternalAccountsManage).await;
    let consumer = !manager && in_context && holds(state, auth, Capability::ExternalAuthUse).await;
    if !manager && !consumer {
        return reject_with(
            &doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "{} may neither manage nor use external accounts in {context}",
                    auth.did
                ),
            },
        );
    }

    let want_state = req
        .state
        .as_ref()
        .map(|s| json_of(s).as_str().unwrap_or("").to_string());
    let want_model = req
        .model
        .as_ref()
        .map(|m| json_of(m).as_str().unwrap_or("").to_string());
    let limit = req
        .limit
        .map(|l| usize::try_from(l.get()).unwrap_or(usize::MAX).clamp(1, 500))
        .unwrap_or(LIST_DEFAULT_LIMIT);
    let after = req.cursor.as_ref().map(|c| c.to_string());

    let all = match store::list(&state.external_accounts_ks, &context).await {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let matching: Vec<AccountRecord> = all
        .into_iter()
        .filter(|a| {
            let state_ok = match &want_state {
                Some(s) => a.state.as_str() == s,
                None => a.state != AccountState::Archived,
            };
            let model_ok = want_model.as_deref().is_none_or(|m| a.model() == m);
            let bound_ok = manager || a.binding_for(&auth.did).is_some();
            state_ok && model_ok && bound_ok
        })
        // Ordered by id; the cursor is the last id of the previous page.
        .filter(|a| after.as_deref().is_none_or(|c| a.id.as_str() > c))
        .take(limit + 1)
        .collect();
    let more = matching.len() > limit;
    let page = &matching[..matching.len().min(limit)];
    let accounts: Vec<Value> = page
        .iter()
        .map(|a| {
            if manager {
                wire(a)
            } else {
                wire_for_consumer(a, &auth.did)
            }
        })
        .collect();
    let mut out = json!({ "accounts": accounts });
    if more && let Some(last) = page.last() {
        out["nextCursor"] = Value::String(last.id.clone());
    }
    respond::<t::Response>(&doc, out)
}

/// `external/accounts/get/0.1`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::get::v0_1 as t;
    let req: t::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (context, id) = (req.context.to_string(), req.id.to_string());
    let not_found = || {
        reject_declared(
            &doc,
            t::error_codes::NOT_FOUND,
            format!("no external account {id} in context {context}"),
        )
    };
    let in_context = auth.has_context_access(&context);
    let rec = match store::get(&state.external_accounts_ks, &context, &id).await {
        Ok(Some(rec)) => rec,
        Ok(None) => return not_found(),
        Err(e) => return app_error_to_reject(&doc, e),
    };
    if in_context && holds(state, auth, Capability::ExternalAccountsManage).await {
        return respond::<t::Response>(&doc, json!({ "account": wire(&rec) }));
    }
    // Anyone else learns nothing — not even that the account exists.
    if in_context
        && rec.binding_for(&auth.did).is_some()
        && holds(state, auth, Capability::ExternalAuthUse).await
    {
        return respond::<t::Response>(
            &doc,
            json!({ "account": wire_for_consumer(&rec, &auth.did) }),
        );
    }
    not_found()
}

/// `external/accounts/setup/0.1`.
pub(super) async fn handle_setup(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::setup::v0_1 as t;
    let req: t::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (context, id) = (req.context.to_string(), req.id.to_string());
    if let Err(r) = require_manage(state, auth, &doc, &context).await {
        return r;
    }
    let rec = match load_for_manage(state, &doc, &context, &id, t::error_codes::NOT_FOUND).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Some(d) = driver::driver_for(rec.model()) else {
        return app_error_to_reject(
            &doc,
            AppError::Internal(format!("no driver for {}", rec.model())),
        );
    };
    respond::<t::Response>(&doc, json!({ "setup": d.setup(&rec) }))
}

// ─── Create / update ─────────────────────────────────────────────────────────

/// `external/accounts/create/0.1`.
pub(super) async fn handle_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::create::v0_1 as t;
    let req: t::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (context, id) = (req.context.to_string(), req.id.to_string());
    if let Err(r) = require_manage(state, auth, &doc, &context).await {
        return r;
    }
    match vta_support::contexts::get_context(&state.contexts_ks, &context).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return app_error_to_reject(
                &doc,
                AppError::NotFound(format!("context {context} does not exist")),
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    }
    let settings = json_of(&req.settings);
    let model = vta_external::model::model_of(&settings).to_string();
    let invalid = |member: &str, why: String| {
        reject_with_code(
            &doc,
            declared(t::error_codes::INVALID_SETTINGS),
            why,
            Some(json!({ "member": member })),
        )
    };
    let Some(d) = driver::driver_for(&model) else {
        return reject_declared(
            &doc,
            t::error_codes::MODEL_UNSUPPORTED,
            format!(
                "model {model} is not implemented by this custodian (it serves: {})",
                driver::SUPPORTED_MODELS.join(", ")
            ),
        );
    };
    if let Err(e) = d.validate_settings(&settings) {
        return invalid(e.member, e.why);
    }

    let now = Utc::now();
    let rec = AccountRecord {
        id: id.clone(),
        label: req.label.to_string(),
        context: context.clone(),
        settings,
        state: AccountState::Active,
        public_material: None,
        secret: None,
        bindings: Vec::new(),
        // Nothing is usable until the provider-side setup (and, for a static
        // model, its secret) is done and a probe has shown it works.
        provider_setup_required: true,
        last_probe: None,
        created_at: now,
        updated_at: now,
    };
    match store::insert_new(&state.external_accounts_ks, &rec).await {
        Ok(true) => {}
        Ok(false) => {
            return reject_declared(
                &doc,
                t::error_codes::ALREADY_EXISTS,
                format!(
                    "account id {id} is taken in context {context} (ids of deleted accounts are never reused)"
                ),
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    }
    audit(
        state,
        "external.account.create",
        auth,
        &id,
        "success",
        &context,
    )
    .await;
    respond::<t::Response>(&doc, json!({ "account": wire(&rec) }))
}

/// The generated `DeclaredErrorCode` as a wire code, for a refusal that also
/// carries `details`.
fn declared(code: trust_tasks_rs::DeclaredErrorCode) -> trust_tasks_rs::TrustTaskCode {
    trust_tasks_rs::TrustTaskCode::Extended {
        slug: code.namespace().to_string(),
        local: code.local().to_string(),
    }
}

/// `external/accounts/update/0.1`.
pub(super) async fn handle_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::update::v0_1 as t;
    let req: t::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (context, id) = (req.context.to_string(), req.id.to_string());
    if let Err(r) = require_manage(state, auth, &doc, &context).await {
        return r;
    }
    let _guard = store::write_lock().await;
    let mut rec = match load_for_manage(state, &doc, &context, &id, t::error_codes::NOT_FOUND).await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if rec.state == AccountState::Archived {
        return reject_declared(
            &doc,
            t::error_codes::ARCHIVED,
            format!("account {id} is archived; restore it before changing it"),
        );
    }
    if let Some(label) = &req.label {
        rec.label = label.to_string();
    }
    if let Some(settings) = &req.settings {
        let settings = json_of(settings);
        let invalid = |member: &str, why: String| {
            reject_with_code(
                &doc,
                declared(t::error_codes::INVALID_SETTINGS),
                why,
                Some(json!({ "member": member })),
            )
        };
        if vta_external::model::model_of(&settings) != rec.model() {
            return invalid(
                "model",
                format!("an account's model cannot change (it is {})", rec.model()),
            );
        }
        let Some(d) = driver::driver_for(rec.model()) else {
            return app_error_to_reject(
                &doc,
                AppError::Internal(format!("no driver for {}", rec.model())),
            );
        };
        if let Err(e) = d.validate_settings(&settings) {
            return invalid(e.member, e.why);
        }
        if settings != rec.settings {
            // Replaced whole, never merged: what is stored is what was approved.
            rec.settings = settings;
            rec.provider_setup_required = true;
        }
    }
    rec.updated_at = Utc::now();
    if let Err(e) = store::put(&state.external_accounts_ks, &rec).await {
        return app_error_to_reject(&doc, e);
    }
    audit(
        state,
        "external.account.update",
        auth,
        &id,
        "success",
        &context,
    )
    .await;
    respond::<t::Response>(&doc, json!({ "account": wire(&rec) }))
}

// ─── Secret ──────────────────────────────────────────────────────────────────

/// `external/accounts/secret/set/0.1`. The bundle is sealed in the
/// administrator's client to a wrapping key from `keys/import-wrapping-key`,
/// and carries an `ExternalSecret` naming this account.
pub(super) async fn handle_secret_set(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::secret::set::v0_1 as t;
    use vta_sdk::sealed_transfer::SealedPayloadV1;
    let req: t::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (context, id) = (req.context.to_string(), req.id.to_string());
    if let Err(r) = require_manage(state, auth, &doc, &context).await {
        return r;
    }
    let rec = match load_for_manage(state, &doc, &context, &id, t::error_codes::NOT_FOUND).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if rec.state == AccountState::Archived {
        return reject_declared(
            &doc,
            t::error_codes::ARCHIVED,
            format!("account {id} is archived; restore it before setting its secret"),
        );
    }
    if !driver::driver_for(rec.model()).is_some_and(|d| d.holds_secret()) {
        return reject_declared(
            &doc,
            t::error_codes::NOT_STATIC_MODEL,
            format!("a {} account holds no secret", rec.model()),
        );
    }

    let unseal_failed = |why: String| reject_declared(&doc, t::error_codes::UNSEAL_FAILED, why);
    let (opened, wrapping_pub) = match state
        .wrapping_cache
        .open_sealed(req.sealed_secret.as_str())
        .await
    {
        Ok(o) => o,
        Err(e) => return unseal_failed(format!("the bundle did not open: {e}")),
    };
    if let Err(why) = verify_producer(&opened, &wrapping_pub) {
        return unseal_failed(why);
    }
    let SealedPayloadV1::ExternalSecret(bundle) = opened.payload else {
        return unseal_failed("the bundle does not carry an external secret".into());
    };
    if bundle.context != context || bundle.account != id {
        return unseal_failed(format!(
            "the bundle was sealed for {}/{}, not {context}/{id}",
            bundle.context, bundle.account
        ));
    }
    if bundle.secret.is_empty() {
        return unseal_failed("the sealed secret is empty".into());
    }
    // A secret cannot be paired with the wrong key id.
    if let Some(claimed) = &bundle.access_key_id
        && vta_external::s3_presign::access_key_id(&rec.settings) != Some(claimed.as_str())
    {
        return unseal_failed(format!(
            "the bundle's secret belongs to access key {claimed}, not this account's"
        ));
    }

    let seed_id = match store::store_secret(
        &state.external_secrets_ks,
        &state.keys_ks,
        &*state.seed_store,
        &context,
        &id,
        bundle.secret.as_bytes(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let key = match fingerprint::key(&state.external_secrets_ks).await {
        Ok(k) => k,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let print = fingerprint::of(&key, bundle.secret.as_bytes());
    drop(bundle);

    let now = Utc::now();
    let _guard = store::write_lock().await;
    let mut rec = match load_for_manage(state, &doc, &context, &id, t::error_codes::NOT_FOUND).await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    rec.secret = Some(SecretInfo {
        fingerprint: print.clone(),
        set_at: now,
        seed_id,
    });
    // Cleared by a probe that succeeds with the new secret, not by setting it.
    rec.provider_setup_required = true;
    rec.updated_at = now;
    if let Err(e) = store::put(&state.external_accounts_ks, &rec).await {
        return app_error_to_reject(&doc, e);
    }
    audit_detail(
        state,
        "external.account.secret_set",
        auth,
        &id,
        "success",
        &context,
        &format!("fingerprint:{print}"),
    )
    .await;
    respond::<t::Response>(&doc, json!({ "fingerprint": print, "setAt": rfc3339(now) }))
}

/// Check a sealed bundle's producer assertion. `DidSigned` is verified against
/// the producer's `did:key`; `PinnedOnly` is accepted because the bundle was
/// sealed to a single-use wrapping key the authenticated caller was handed
/// seconds before, and arrived inside its signed request. `Attested` is not a
/// thing an administrator's client produces.
fn verify_producer(
    opened: &vta_sdk::sealed_transfer::OpenedBundle,
    wrapping_pub: &[u8; 32],
) -> Result<(), String> {
    use vta_sdk::sealed_transfer::AssertionProof;
    use vta_sdk::sealed_transfer::verify::verify_did_signed_assertion_with_pubkey;
    let producer = &opened.producer.producer_did;
    match &opened.producer.proof {
        AssertionProof::PinnedOnly => Ok(()),
        AssertionProof::DidSigned(a) => {
            let pubkey = affinidi_crypto::did_key::did_key_to_ed25519_pub(producer)
                .map_err(|e| format!("a DID-signed producer must be an Ed25519 did:key: {e}"))?;
            verify_did_signed_assertion_with_pubkey(
                a,
                producer,
                &pubkey,
                wrapping_pub,
                &opened.bundle_id,
            )
            .map_err(|e| format!("producer assertion did not verify: {e}"))
        }
        _ => Err("unexpected producer assertion for an administrator's secret".into()),
    }
}

// ─── Bindings ────────────────────────────────────────────────────────────────

/// `external/accounts/bindings/grant/0.1`.
pub(super) async fn handle_bindings_grant(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::bindings::grant::v0_1 as t;
    let req: t::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (context, id) = (req.context.to_string(), req.id.to_string());
    if let Err(r) = require_manage(state, auth, &doc, &context).await {
        return r;
    }
    let mut binding: Binding = match serde_json::from_value(json_of(&req.binding)) {
        Ok(b) => b,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("binding: {e}"),
                },
            );
        }
    };
    let _guard = store::write_lock().await;
    let mut rec = match load_for_manage(state, &doc, &context, &id, t::error_codes::NOT_FOUND).await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if rec.state == AccountState::Archived {
        return reject_declared(
            &doc,
            t::error_codes::ARCHIVED,
            format!("account {id} is archived; restore it before binding to it"),
        );
    }
    if let Err(why) = scope::validate_ceiling(rec.model(), binding.scope_ceiling.as_ref()) {
        return reject_declared(&doc, t::error_codes::CEILING_NOT_APPLICABLE, why);
    }
    let now = Utc::now();
    binding.granted_at = Some(now);
    // One binding per consumer: a grant replaces, never adds a second.
    rec.bindings.retain(|b| b.consumer != binding.consumer);
    let consumer = binding.consumer.clone();
    rec.bindings.push(binding);
    rec.updated_at = now;
    if let Err(e) = store::put(&state.external_accounts_ks, &rec).await {
        return app_error_to_reject(&doc, e);
    }
    audit_detail(
        state,
        "external.account.binding_grant",
        auth,
        &id,
        "success",
        &context,
        &format!("consumer:{consumer}"),
    )
    .await;
    respond::<t::Response>(&doc, json!({ "account": wire(&rec) }))
}

/// `external/accounts/bindings/revoke/0.1`. Never consent-gated by design:
/// taking authority away must be fast and possible alone.
pub(super) async fn handle_bindings_revoke(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::bindings::revoke::v0_1 as t;
    let req: t::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (context, id) = (req.context.to_string(), req.id.to_string());
    let consumer = req.consumer.to_string();
    if let Err(r) = require_manage(state, auth, &doc, &context).await {
        return r;
    }
    let _guard = store::write_lock().await;
    let mut rec = match load_for_manage(state, &doc, &context, &id, t::error_codes::NOT_FOUND).await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let before = rec.bindings.len();
    rec.bindings.retain(|b| b.consumer != consumer);
    if rec.bindings.len() == before {
        return reject_declared(
            &doc,
            t::error_codes::NO_SUCH_BINDING,
            format!("account {id} has no binding for {consumer}"),
        );
    }
    rec.updated_at = Utc::now();
    if let Err(e) = store::put(&state.external_accounts_ks, &rec).await {
        return app_error_to_reject(&doc, e);
    }
    audit_detail(
        state,
        "external.account.binding_revoke",
        auth,
        &id,
        "success",
        &context,
        &format!("consumer:{consumer}"),
    )
    .await;
    respond::<t::Response>(&doc, json!({ "account": wire(&rec) }))
}

// ─── Probe and keys ──────────────────────────────────────────────────────────

/// `external/accounts/probe/0.1`. A provider refusal is a successful response
/// with `ok: false`.
pub(super) async fn handle_probe(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::probe::v0_1 as t;
    let req: t::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (context, id) = (req.context.to_string(), req.id.to_string());
    if let Err(r) = require_manage(state, auth, &doc, &context).await {
        return r;
    }
    let rec = match load_for_manage(state, &doc, &context, &id, t::error_codes::NOT_FOUND).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if rec.state == AccountState::Archived {
        return reject_declared(
            &doc,
            t::error_codes::ARCHIVED,
            format!("account {id} is archived; restore it first"),
        );
    }
    let Some(d) = driver::driver_for(rec.model()) else {
        return app_error_to_reject(
            &doc,
            AppError::Internal(format!("no driver for {}", rec.model())),
        );
    };
    let secret = match load_secret(state, &rec).await {
        Ok(s) => s,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    // No lock across the provider round trip.
    let report = d
        .probe(
            &rec,
            secret.as_deref().map(String::as_str),
            vta_external::driver::probe_client(),
            Utc::now(),
        )
        .await;
    drop(secret);
    let ok = report["ok"] == true;
    // An exchange alone proves the provider trusts the key, not that the
    // account can do what its bindings will ask: only a complete probe clears.
    let complete = report["complete"] == true;

    {
        let _guard = store::write_lock().await;
        let mut rec =
            match load_for_manage(state, &doc, &context, &id, t::error_codes::NOT_FOUND).await {
                Ok(r) => r,
                Err(resp) => return resp,
            };
        rec.last_probe = Some(report.clone());
        if ok && complete {
            rec.provider_setup_required = false;
        }
        rec.updated_at = Utc::now();
        if let Err(e) = store::put(&state.external_accounts_ks, &rec).await {
            return app_error_to_reject(&doc, e);
        }
    }
    audit(
        state,
        "external.account.probe",
        auth,
        &id,
        if ok { "success" } else { "failure" },
        &context,
    )
    .await;
    respond::<t::Response>(&doc, json!({ "report": report }))
}

/// `external/accounts/keys/rotate/0.1`. No model this build serves holds a key
/// (`s3-static-presign` holds a secret, rotated with `secret/set`), so every
/// account is refused with `notKeyModel`.
pub(super) async fn handle_keys_rotate(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::keys::rotate::v0_1 as t;
    let req: t::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (context, id) = (req.context.to_string(), req.id.to_string());
    if let Err(r) = require_manage(state, auth, &doc, &context).await {
        return r;
    }
    let rec = match load_for_manage(state, &doc, &context, &id, t::error_codes::NOT_FOUND).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if rec.state == AccountState::Archived {
        return reject_declared(
            &doc,
            t::error_codes::ARCHIVED,
            format!("account {id} is archived; restore it first"),
        );
    }
    reject_declared(
        &doc,
        t::error_codes::NOT_KEY_MODEL,
        format!(
            "a {} account holds a secret, not a key; replace it with external/accounts/secret/set",
            rec.model()
        ),
    )
}

async fn load_secret(
    state: &AppState,
    rec: &AccountRecord,
) -> Result<Option<zeroize::Zeroizing<String>>, AppError> {
    let Some(info) = &rec.secret else {
        return Ok(None);
    };
    store::load_secret(
        &state.external_secrets_ks,
        &state.keys_ks,
        &*state.seed_store,
        &rec.context,
        &rec.id,
        info.seed_id,
    )
    .await
}

// ─── Lifecycle ───────────────────────────────────────────────────────────────

/// One state transition. `allowed` lists the states it may start from.
#[allow(clippy::too_many_arguments)]
async fn transition<R: DeserializeOwned + Serialize>(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    not_found: trust_tasks_rs::DeclaredErrorCode,
    invalid: trust_tasks_rs::DeclaredErrorCode,
    archived: Option<trust_tasks_rs::DeclaredErrorCode>,
    allowed: &[AccountState],
    to: AccountState,
    action: &str,
    before_commit: impl Fn(&AccountRecord) -> Result<(), TrustTaskOutcome>,
) -> TrustTaskOutcome {
    let (context, id) = context_and_id(doc);
    if let Err(r) = require_manage(state, auth, doc, &context).await {
        return r;
    }
    let _guard = store::write_lock().await;
    let mut rec = match load_for_manage(state, doc, &context, &id, not_found).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // An archived account answers `external:archived` from the tasks for
    // which it is not a starting state; restore it first.
    if rec.state == AccountState::Archived
        && let Some(code) = archived
    {
        return reject_declared(
            doc,
            code,
            format!("account {id} is archived; restore it first"),
        );
    }
    if !allowed.contains(&rec.state) {
        return reject_declared(
            doc,
            invalid,
            format!(
                "account {id} is {}; this task needs it {}",
                rec.state.as_str(),
                allowed
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" or ")
            ),
        );
    }
    if let Err(resp) = before_commit(&rec) {
        return resp;
    }
    rec.state = to;
    rec.updated_at = Utc::now();
    if let Err(e) = store::put(&state.external_accounts_ks, &rec).await {
        return app_error_to_reject(doc, e);
    }
    audit(state, action, auth, &id, "success", &context).await;
    respond::<R>(doc, json!({ "account": wire(&rec) }))
}

/// `external/accounts/suspend/0.1` — the kill switch. Never consent-gated.
pub(super) async fn handle_suspend(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::suspend::v0_1 as t;
    if let Err(resp) = parse_payload::<t::Payload>(&doc) {
        return resp;
    }
    transition::<t::Response>(
        state,
        auth,
        &doc,
        t::error_codes::NOT_FOUND,
        t::error_codes::INVALID_TRANSITION,
        Some(t::error_codes::ARCHIVED),
        &[AccountState::Active],
        AccountState::Suspended,
        "external.account.suspend",
        |_| Ok(()),
    )
    .await
}

/// `external/accounts/resume/0.1`.
pub(super) async fn handle_resume(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::resume::v0_1 as t;
    if let Err(resp) = parse_payload::<t::Payload>(&doc) {
        return resp;
    }
    let refuse_setup = |rec: &AccountRecord| {
        if rec.provider_setup_required {
            Err(reject_declared(
                &doc,
                t::error_codes::PROVIDER_SETUP_REQUIRED,
                format!(
                    "account {} needs its provider setup completed and a successful probe first",
                    rec.id
                ),
            ))
        } else {
            Ok(())
        }
    };
    transition::<t::Response>(
        state,
        auth,
        &doc,
        t::error_codes::NOT_FOUND,
        t::error_codes::INVALID_TRANSITION,
        Some(t::error_codes::ARCHIVED),
        &[AccountState::Suspended],
        AccountState::Active,
        "external.account.resume",
        refuse_setup,
    )
    .await
}

/// `external/accounts/archive/0.1`.
pub(super) async fn handle_archive(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::archive::v0_1 as t;
    if let Err(resp) = parse_payload::<t::Payload>(&doc) {
        return resp;
    }
    transition::<t::Response>(
        state,
        auth,
        &doc,
        t::error_codes::NOT_FOUND,
        t::error_codes::INVALID_TRANSITION,
        Some(t::error_codes::ARCHIVED),
        &[AccountState::Active, AccountState::Suspended],
        AccountState::Archived,
        "external.account.archive",
        |_| Ok(()),
    )
    .await
}

/// `external/accounts/restore/0.1` — back from the archive, **suspended**:
/// turning an account on again always goes through `resume`.
pub(super) async fn handle_restore(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::restore::v0_1 as t;
    if let Err(resp) = parse_payload::<t::Payload>(&doc) {
        return resp;
    }
    transition::<t::Response>(
        state,
        auth,
        &doc,
        t::error_codes::NOT_FOUND,
        t::error_codes::INVALID_TRANSITION,
        None,
        &[AccountState::Archived],
        AccountState::Suspended,
        "external.account.restore",
        |_| Ok(()),
    )
    .await
}

/// `external/accounts/delete/0.1` — archived accounts only; the id is retired.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::accounts::delete::v0_1 as t;
    let req: t::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (context, id) = (req.context.to_string(), req.id.to_string());
    if let Err(r) = require_manage(state, auth, &doc, &context).await {
        return r;
    }
    let _guard = store::write_lock().await;
    let rec = match load_for_manage(state, &doc, &context, &id, t::error_codes::NOT_FOUND).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if rec.state != AccountState::Archived {
        return reject_declared(
            &doc,
            t::error_codes::INVALID_TRANSITION,
            format!(
                "account {id} is {}; archive it before deleting it",
                rec.state.as_str()
            ),
        );
    }
    if let Err(e) = store::delete(
        &state.external_accounts_ks,
        &state.external_secrets_ks,
        &context,
        &id,
    )
    .await
    {
        return app_error_to_reject(&doc, e);
    }
    let now = Utc::now();
    audit(
        state,
        "external.account.delete",
        auth,
        &id,
        "success",
        &context,
    )
    .await;
    respond::<t::Response>(&doc, json!({ "id": id, "deletedAt": rfc3339(now) }))
}

// ─── Issuance ────────────────────────────────────────────────────────────────

/// `external/credentials/issue/0.1`.
pub(super) async fn handle_issue(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use ext::credentials::issue::v0_1 as t;
    let req: t::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let context = req.context.to_string();
    let id = req.account.to_string();
    let requested: RequestedScope = match serde_json::from_value(json_of(&req.scope)) {
        Ok(s) => s,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("scope: {e}"),
                },
            );
        }
    };
    let ttl = u32::try_from(req.ttl_seconds).unwrap_or(u32::MAX);
    let resource = format!("{context}/{id}");

    // 1. The caller is a binding's consumer on the named account — the DID the
    //    proof or the transport established (`auth.did`), never one named in
    //    the payload. Every other caller, and every caller naming an account
    //    that does not exist, gets the same `notFound`: issuance is no oracle
    //    for which accounts exist or what state they are in.
    let rec = match store::get(&state.external_accounts_ks, &context, &id).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let bound = rec
        .as_ref()
        .and_then(|r| r.binding_for(&auth.did).cloned().map(|b| (r, b)));
    let Some((rec, binding)) = bound else {
        // A caller that holds the capability and is still unbound is what a
        // compromised or misconfigured consumer looks like.
        if holds(state, auth, Capability::ExternalAuthUse).await {
            tracing::warn!(security_alert = true, consumer = %auth.did, account = %resource,
                "external credential requested by a DID with no binding on the account");
            audit_detail(
                state,
                "external.credential.issue",
                auth,
                &resource,
                "denied",
                &context,
                "notBound",
            )
            .await;
        }
        return reject_declared(
            &doc,
            t::error_codes::NOT_FOUND,
            format!("no external account {id} in context {context} is bound to the caller"),
        );
    };

    // 2. The capability, in the account's context, through the act scope.
    if !(holds(state, auth, Capability::ExternalAuthUse).await && auth.has_context_access(&context))
    {
        audit_detail(
            state,
            "external.credential.issue",
            auth,
            &resource,
            "denied",
            &context,
            "permissionDenied",
        )
        .await;
        return reject_with(
            &doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "{} does not hold external-auth-use in context {context}",
                    auth.did
                ),
            },
        );
    }

    // 3. Only now, to a bound consumer: the account's state.
    if rec.state != AccountState::Active {
        return reject_declared(
            &doc,
            t::error_codes::NOT_ACTIVE,
            format!("account {id} is {}", rec.state.as_str()),
        );
    }
    let Some(d) = driver::driver_for(rec.model()).filter(|d| d.brokered()) else {
        return reject_declared(
            &doc,
            t::error_codes::NOT_BROKERED,
            format!(
                "a {} account is not used through credential issuance",
                rec.model()
            ),
        );
    };
    if rec.provider_setup_required {
        return reject_declared(
            &doc,
            t::error_codes::PROVIDER_SETUP_REQUIRED,
            format!("account {id} needs its provider setup completed and a complete probe"),
        );
    }

    // 4. and 5. Scope inside the ceiling; TTL under the binding's maximum.
    match scope::check_against_binding(rec.model(), &binding, &requested, ttl) {
        Ok(()) => {}
        Err(ScopeRefusal::TtlTooLong { requested, max }) => {
            return reject_declared(
                &doc,
                t::error_codes::TTL_TOO_LONG,
                format!("ttlSeconds {requested} exceeds the binding's maxTtlSeconds {max}"),
            );
        }
        Err(refusal) => {
            tracing::warn!(security_alert = true, consumer = %auth.did, account = %resource, refusal = %refusal,
                "external credential requested outside the binding's ceiling");
            audit_detail(
                state,
                "external.credential.issue",
                auth,
                &resource,
                "denied",
                &context,
                "scopeOutsideCeiling",
            )
            .await;
            return reject_declared(
                &doc,
                t::error_codes::SCOPE_OUTSIDE_CEILING,
                refusal.to_string(),
            );
        }
    }

    // 6. The binding's rate.
    if !state
        .external_rate
        .try_acquire(&context, &id, &auth.did, binding.rate_per_minute)
    {
        return reject_declared(
            &doc,
            t::error_codes::RATE_LIMITED,
            format!(
                "the binding's rate of {} per minute is exhausted",
                binding.rate_per_minute
            ),
        );
    }

    // The key to seal to, found before the provider is contacted: a credential
    // that cannot be delivered is never minted.
    let recipient = match sealing_key(&auth.did).await {
        Ok(k) => k,
        Err(why) => return reject_declared(&doc, t::error_codes::NO_KEY_AGREEMENT, why),
    };

    // Build the credential.
    let secret = match load_secret(state, rec).await {
        Ok(s) => s,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let issued = d
        .issue(IssueRequest {
            account: rec,
            secret: secret.as_deref().map(String::as_str),
            scope: &requested,
            ttl_seconds: ttl,
            source_cidrs: &binding.source_cidrs,
            now: Utc::now(),
        })
        .await;
    drop(secret);
    let issued = match issued {
        Ok(i) => i,
        Err(DriverError::SetupRequired(m)) => {
            return reject_declared(&doc, t::error_codes::PROVIDER_SETUP_REQUIRED, m);
        }
        Err(DriverError::Refused(m)) => {
            return reject_declared(&doc, t::error_codes::PROVIDER_REFUSED, m);
        }
        Err(DriverError::Unavailable(m)) => {
            return reject_declared(&doc, t::error_codes::PROVIDER_UNAVAILABLE, m);
        }
        Err(DriverError::Internal(m)) => return app_error_to_reject(&doc, AppError::Internal(m)),
    };

    let scope_json = serde_json::to_value(&requested).unwrap_or(Value::Null);
    let expires_at = rfc3339(issued.expires_at);
    let sealed = match seal_credential(state, &recipient, issued).await {
        Ok(s) => s,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // The audit row names the issuance, never the credential.
    audit_detail(
        state,
        "external.credential.issue",
        auth,
        &resource,
        "success",
        &context,
        &format!("scope:{scope_json} expiresAt:{expires_at}"),
    )
    .await;
    respond::<t::Response>(
        &doc,
        json!({ "sealedCredential": sealed, "expiresAt": expires_at, "scope": scope_json }),
    )
}

/// The consumer's key-agreement key: for a `did:key`, the X25519 derivation of
/// its Ed25519 key; otherwise the first X25519 `keyAgreement` method of its
/// resolved DID document.
async fn sealing_key(consumer: &str) -> Result<[u8; 32], String> {
    vta_sdk::didcomm_light::resolve_vta_keyagreement(consumer)
        .await
        .map(|(_, key)| key)
        .map_err(|e| format!("no X25519 key-agreement key for {consumer}: {e}"))
}

/// Seal an issued credential to the consumer's key-agreement key.
///
/// The producer assertion is `PinnedOnly`, as the specification requires: the
/// bundle travels inside this task's `#response`, whose proof is REQUIRED and
/// covers `sealedCredential`, and that proof is the anchor a consumer checks
/// before it opens the bundle.
async fn seal_credential(
    state: &AppState,
    recipient: &[u8; 32],
    issued: driver::Issued,
) -> Result<String, AppError> {
    use vta_sdk::sealed_transfer::{
        AssertionProof, ProducerAssertion, SealedPayloadV1, armor, seal_payload,
    };
    let vta_did = state
        .config
        .read()
        .await
        .vta_did
        .clone()
        .unwrap_or_default();
    let mut bundle_id = [0u8; 16];
    rand::fill(&mut bundle_id);
    let payload = SealedPayloadV1::ExternalCredential(Box::new(issued.credential));
    let nonce_store =
        crate::sealed_nonce_store::PersistentNonceStore::new(state.sealed_nonces_ks.clone());
    let bundle = seal_payload(
        recipient,
        bundle_id,
        ProducerAssertion {
            producer_did: vta_did,
            proof: AssertionProof::PinnedOnly,
        },
        &payload,
        &nonce_store,
    )
    .await
    .map_err(|e| AppError::Internal(format!("sealing the issued credential failed: {e}")))?;
    Ok(armor::encode(&bundle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Role;
    use crate::test_support::{build_signing_test_app_state, did_for_seed};
    use trust_tasks_rs::TypeUri;
    use vta_sdk::sealed_transfer::{ExternalCredentialPayload, ed25519_seed_to_x25519_secret};
    use vta_sdk::trust_tasks as uris;

    const CTX: &str = "community";
    const CONSUMER_SEED: u8 = 0x51;

    fn claims(did: &str, role: Role) -> AuthClaims {
        AuthClaims {
            did: did.to_string(),
            role,
            allowed_contexts: vec![CTX.to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    fn manager() -> AuthClaims {
        claims("did:key:zManager", Role::Admin)
    }

    fn consumer() -> AuthClaims {
        claims(&did_for_seed(CONSUMER_SEED).0, Role::Application)
    }

    fn doc(uri: &str, payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = uri.parse().expect("uri");
        TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
    }

    fn body(out: &TrustTaskOutcome) -> Value {
        serde_json::from_slice::<Value>(&out.body).expect("JSON")["payload"].clone()
    }

    fn code(out: &TrustTaskOutcome) -> String {
        body(out)["code"]
            .as_str()
            .unwrap_or("<success>")
            .to_string()
    }

    fn settings() -> Value {
        json!({
            "model": "s3-static-presign",
            "endpoint": "https://s3.example.invalid",
            "region": "auto",
            "bucket": "rooms",
            "pathStyle": true,
            "accessKeyId": "AKIDEXAMPLE",
        })
    }

    async fn state_with_account(id: &str) -> (AppState, tempfile::TempDir) {
        let (state, dir) = build_signing_test_app_state().await;
        crate::contexts::create_context(&state.contexts_ks, CTX, "Community")
            .await
            .unwrap();
        let out = handle_create(
            &state,
            &manager(),
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_CREATE_0_1,
                json!({ "context": CTX, "id": id, "label": "R2 main", "settings": settings() }),
            ),
        )
        .await;
        assert_eq!(code(&out), "<success>", "{}", body(&out));
        (state, dir)
    }

    /// Seal a secret the way an administrator's client does: to a wrapping key
    /// the VTA just handed out, through the SDK helper a client uses.
    async fn sealed_secret(state: &AppState, context: &str, account: &str, secret: &str) -> String {
        sealed_secret_for_key(state, context, account, secret, Some("AKIDEXAMPLE")).await
    }

    async fn sealed_secret_for_key(
        state: &AppState,
        context: &str,
        account: &str,
        secret: &str,
        access_key_id: Option<&str>,
    ) -> String {
        let key = state.wrapping_cache.generate().await;
        vta_sdk::client::seal_external_secret(
            &key.public_did,
            context,
            account,
            secret,
            access_key_id,
        )
        .await
        .unwrap()
    }

    async fn grant(state: &AppState, id: &str, consumer: &str, rate: u32) {
        let out = handle_bindings_grant(
            state,
            &manager(),
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_BINDINGS_GRANT_0_1,
                json!({ "context": CTX, "id": id, "binding": {
                    "consumer": consumer,
                    "scopeCeiling": { "prefixes": ["rooms/"], "actions": ["put", "get"] },
                    "maxTtlSeconds": 900, "ratePerMinute": rate,
                }}),
            ),
        )
        .await;
        assert_eq!(code(&out), "<success>", "{}", body(&out));
    }

    /// What a successful probe would leave: provider setup done.
    async fn mark_set_up(state: &AppState, id: &str) {
        let mut rec = store::get(&state.external_accounts_ks, CTX, id)
            .await
            .unwrap()
            .unwrap();
        rec.provider_setup_required = false;
        store::put(&state.external_accounts_ks, &rec).await.unwrap();
    }

    fn issue_doc(id: &str, prefix: &str, action: &str, key: &str, ttl: u32) -> TrustTask<Value> {
        doc(
            uris::TASK_EXTERNAL_CREDENTIALS_ISSUE_0_1,
            json!({ "context": CTX, "account": id,
                    "scope": { "prefix": prefix, "actions": [action], "objectKey": key },
                    "ttlSeconds": ttl }),
        )
    }

    /// An account ready to issue: secret set, consumer bound, set up.
    async fn ready(id: &str, rate: u32) -> (AppState, tempfile::TempDir) {
        let (state, dir) = state_with_account(id).await;
        let armored = sealed_secret(&state, CTX, id, "wJalrXUtnFEMI/K7MDENG").await;
        let out = handle_secret_set(
            &state,
            &manager(),
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_SECRET_SET_0_1,
                json!({ "context": CTX, "id": id, "sealedSecret": armored }),
            ),
        )
        .await;
        assert_eq!(code(&out), "<success>", "{}", body(&out));
        grant(&state, id, &consumer().did, rate).await;
        mark_set_up(&state, id).await;
        (state, dir)
    }

    #[tokio::test]
    async fn a_bound_consumer_gets_a_presigned_url_sealed_to_it_and_nothing_else() {
        let (state, _dir) = ready("r2-main", 60).await;
        let out = handle_issue(
            &state,
            &consumer(),
            issue_doc("r2-main", "rooms/3f9a/", "put", "blob", 600),
        )
        .await;
        let payload = body(&out);
        assert_eq!(code(&out), "<success>", "{payload}");
        assert_eq!(payload["scope"]["objectKey"], "blob");
        assert!(payload["expiresAt"].is_string());

        let armored = payload["sealedCredential"].as_str().unwrap();
        assert!(
            !armored.contains("X-Amz-Signature"),
            "the credential is sealed"
        );
        let x_secret = ed25519_seed_to_x25519_secret(&[CONSUMER_SEED; 32]);
        let c = vta_sdk::client::open_external_credential(armored, &x_secret)
            .expect("the consumer opens what was sealed to it");
        match &c {
            ExternalCredentialPayload::PresignedRequest {
                method,
                url,
                expires_at,
                ..
            } => {
                assert_eq!(method, "PUT");
                assert!(
                    url.starts_with("https://s3.example.invalid/rooms/rooms/3f9a/blob?"),
                    "{url}"
                );
                assert!(url.contains("X-Amz-Expires=600"), "{url}");
                assert!(url.contains("X-Amz-Signature="), "{url}");
                assert_eq!(expires_at, payload["expiresAt"].as_str().unwrap());
            }
            _ => panic!("expected a presigned request"),
        }
    }

    #[tokio::test]
    async fn issuance_refuses_in_the_specified_order() {
        let (state, _dir) = ready("r2-order", 2).await;
        let stranger = claims(&did_for_seed(0x52).0, Role::Application);
        assert_eq!(
            code(
                &handle_issue(
                    &state,
                    &stranger,
                    issue_doc("r2-order", "rooms/a/", "get", "k", 60)
                )
                .await
            ),
            "external:notFound",
            "an unbound caller learns nothing"
        );
        assert_eq!(
            code(
                &handle_issue(
                    &state,
                    &consumer(),
                    issue_doc("r2-order", "other/", "get", "k", 60)
                )
                .await
            ),
            "external/credentials/issue:scopeOutsideCeiling"
        );
        assert_eq!(
            code(
                &handle_issue(
                    &state,
                    &consumer(),
                    issue_doc("r2-order", "rooms/a/", "delete", "k", 60)
                )
                .await
            ),
            "external/credentials/issue:scopeOutsideCeiling"
        );
        assert_eq!(
            code(
                &handle_issue(
                    &state,
                    &consumer(),
                    issue_doc("r2-order", "rooms/a/", "get", "k", 901)
                )
                .await
            ),
            "external/credentials/issue:ttlTooLong"
        );
        assert_eq!(
            code(
                &handle_issue(
                    &state,
                    &stranger,
                    issue_doc("no-such-account", "rooms/a/", "get", "k", 60)
                )
                .await
            ),
            "external:notFound",
            "nor does a caller naming an account that does not exist"
        );
        // A reader holds no external-auth-use: bound or not, refused.
        let reader = claims(&consumer().did, Role::Reader);
        assert_eq!(
            code(
                &handle_issue(
                    &state,
                    &reader,
                    issue_doc("r2-order", "rooms/a/", "get", "k", 60)
                )
                .await
            ),
            "permissionDenied"
        );
        // The rate: two per minute, then refused.
        for _ in 0..2 {
            let out = handle_issue(
                &state,
                &consumer(),
                issue_doc("r2-order", "rooms/a/", "get", "k", 60),
            )
            .await;
            assert_eq!(code(&out), "<success>", "{}", body(&out));
        }
        assert_eq!(
            code(
                &handle_issue(
                    &state,
                    &consumer(),
                    issue_doc("r2-order", "rooms/a/", "get", "k", 60)
                )
                .await
            ),
            "external:rateLimited"
        );
    }

    #[tokio::test]
    async fn suspend_is_a_kill_switch_and_resume_turns_it_back_on() {
        let (state, _dir) = ready("r2-kill", 60).await;
        let lifecycle = |uri: &str| doc(uri, json!({ "context": CTX, "id": "r2-kill" }));
        let out = handle_suspend(
            &state,
            &manager(),
            lifecycle(uris::TASK_EXTERNAL_ACCOUNTS_SUSPEND_0_1),
        )
        .await;
        assert_eq!(body(&out)["account"]["state"], "suspended");
        assert_eq!(
            code(
                &handle_issue(
                    &state,
                    &consumer(),
                    issue_doc("r2-kill", "rooms/a/", "get", "k", 60)
                )
                .await
            ),
            "external:notActive"
        );
        assert_eq!(
            code(
                &handle_suspend(
                    &state,
                    &manager(),
                    lifecycle(uris::TASK_EXTERNAL_ACCOUNTS_SUSPEND_0_1)
                )
                .await
            ),
            "external/accounts/suspend:invalidTransition"
        );
        let out = handle_resume(
            &state,
            &manager(),
            lifecycle(uris::TASK_EXTERNAL_ACCOUNTS_RESUME_0_1),
        )
        .await;
        assert_eq!(body(&out)["account"]["state"], "active", "{}", body(&out));
        let out = handle_issue(
            &state,
            &consumer(),
            issue_doc("r2-kill", "rooms/a/", "get", "k", 60),
        )
        .await;
        assert_eq!(code(&out), "<success>");
    }

    #[tokio::test]
    async fn archive_restore_delete_and_an_id_is_never_reused() {
        let (state, _dir) = state_with_account("r2-life").await;
        let lifecycle = |uri: &str| doc(uri, json!({ "context": CTX, "id": "r2-life" }));
        assert_eq!(
            code(
                &handle_delete(
                    &state,
                    &manager(),
                    lifecycle(uris::TASK_EXTERNAL_ACCOUNTS_DELETE_0_1)
                )
                .await
            ),
            "external/accounts/delete:invalidTransition",
            "only an archived account is deleted"
        );
        let out = handle_archive(
            &state,
            &manager(),
            lifecycle(uris::TASK_EXTERNAL_ACCOUNTS_ARCHIVE_0_1),
        )
        .await;
        assert_eq!(body(&out)["account"]["state"], "archived");
        let out = handle_restore(
            &state,
            &manager(),
            lifecycle(uris::TASK_EXTERNAL_ACCOUNTS_RESTORE_0_1),
        )
        .await;
        assert_eq!(
            body(&out)["account"]["state"],
            "suspended",
            "a restore never lands active"
        );
        handle_archive(
            &state,
            &manager(),
            lifecycle(uris::TASK_EXTERNAL_ACCOUNTS_ARCHIVE_0_1),
        )
        .await;
        let out = handle_delete(
            &state,
            &manager(),
            lifecycle(uris::TASK_EXTERNAL_ACCOUNTS_DELETE_0_1),
        )
        .await;
        assert_eq!(body(&out)["id"], "r2-life", "{}", body(&out));
        let again = handle_create(
            &state,
            &manager(),
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_CREATE_0_1,
                json!({ "context": CTX, "id": "r2-life", "label": "again", "settings": settings() }),
            ),
        )
        .await;
        assert_eq!(code(&again), "external:alreadyExists");
    }

    #[tokio::test]
    async fn reads_show_a_consumer_its_own_binding_and_a_stranger_nothing() {
        let (state, _dir) = state_with_account("r2-read").await;
        grant(&state, "r2-read", &consumer().did, 60).await;
        grant(&state, "r2-read", "did:key:z6MkOtherConsumer", 60).await;
        let get = || {
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_GET_0_1,
                json!({ "context": CTX, "id": "r2-read" }),
            )
        };

        let as_manager = body(&handle_get(&state, &manager(), get()).await);
        assert_eq!(
            as_manager["account"]["bindings"].as_array().unwrap().len(),
            2
        );
        let as_consumer = body(&handle_get(&state, &consumer(), get()).await);
        let bindings = as_consumer["account"]["bindings"].as_array().unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0]["consumer"], consumer().did);

        let stranger = claims(&did_for_seed(0x53).0, Role::Application);
        assert_eq!(
            code(&handle_get(&state, &stranger, get()).await),
            "external:notFound"
        );
        let list = handle_list(
            &state,
            &stranger,
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_LIST_0_1,
                json!({ "context": CTX }),
            ),
        )
        .await;
        assert_eq!(body(&list)["accounts"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn a_secret_is_write_only_and_bound_to_its_account() {
        let (state, _dir) = state_with_account("r2-secret").await;
        let armored = sealed_secret(&state, CTX, "some-other-account", "s3cr3t").await;
        let out = handle_secret_set(
            &state,
            &manager(),
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_SECRET_SET_0_1,
                json!({ "context": CTX, "id": "r2-secret", "sealedSecret": armored }),
            ),
        )
        .await;
        assert_eq!(code(&out), "external/accounts/secret/set:unsealFailed");

        let armored = sealed_secret(&state, CTX, "r2-secret", "s3cr3t").await;
        let out = handle_secret_set(
            &state,
            &manager(),
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_SECRET_SET_0_1,
                json!({ "context": CTX, "id": "r2-secret", "sealedSecret": armored }),
            ),
        )
        .await;
        let fingerprint = body(&out)["fingerprint"].as_str().unwrap().to_string();
        let account = body(
            &handle_get(
                &state,
                &manager(),
                doc(
                    uris::TASK_EXTERNAL_ACCOUNTS_GET_0_1,
                    json!({ "context": CTX, "id": "r2-secret" }),
                ),
            )
            .await,
        );
        assert_eq!(account["account"]["secret"]["fingerprint"], fingerprint);
        assert!(!account.to_string().contains("s3cr3t"), "{account}");
        assert!(account["account"]["secret"].get("seedId").is_none());
    }

    #[tokio::test]
    async fn a_model_this_build_cannot_drive_is_not_created() {
        let (state, _dir) = build_signing_test_app_state().await;
        crate::contexts::create_context(&state.contexts_ks, CTX, "Community")
            .await
            .unwrap();
        let out = handle_create(
            &state,
            &manager(),
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_CREATE_0_1,
                json!({ "context": CTX, "id": "gcs", "label": "GCS", "settings": {
                    "model": "gcp-wif-pinned", "projectNumber": "123456789012",
                    "poolId": "vta-pool", "providerId": "vta-provider" }}),
            ),
        )
        .await;
        assert_eq!(
            code(&out),
            "external/accounts/create:modelUnsupported",
            "{}",
            body(&out)
        );
    }

    #[tokio::test]
    async fn management_needs_the_capability_in_the_context() {
        let (state, _dir) = state_with_account("r2-cap").await;
        let initiator = claims("did:key:zInitiator", Role::Initiator);
        let out = handle_suspend(
            &state,
            &initiator,
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_SUSPEND_0_1,
                json!({ "context": CTX, "id": "r2-cap" }),
            ),
        )
        .await;
        assert_eq!(code(&out), "permissionDenied");
        let mut elsewhere = manager();
        elsewhere.allowed_contexts = vec!["other".into()];
        let out = handle_setup(
            &state,
            &elsewhere,
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_SETUP_0_1,
                json!({ "context": CTX, "id": "r2-cap" }),
            ),
        )
        .await;
        assert_eq!(code(&out), "permissionDenied");
    }

    /// Through the dispatch spine, as a consumer's signed document arrives:
    /// payload validation, the policy class, and a signed `#response` — whose
    /// proof is what anchors the sealed bundle inside it.
    #[tokio::test]
    async fn issuance_through_the_spine_answers_with_a_signed_response() {
        let (state, _dir) = ready("r2-spine", 60).await;
        let vta_did = state.config.read().await.vta_did.clone().expect("vta_did");
        let (did, _) = did_for_seed(CONSUMER_SEED);
        let mut doc: TrustTask<Value> = serde_json::from_value(json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": uris::TASK_EXTERNAL_CREDENTIALS_ISSUE_0_1,
            "issuer": did,
            "recipient": vta_did,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "context": CTX, "account": "r2-spine",
                         "scope": { "prefix": "rooms/ab/", "actions": ["get"], "objectKey": "blob" },
                         "ttlSeconds": 300 },
        }))
        .unwrap();
        crate::test_support::sign_as(CONSUMER_SEED, &mut doc);
        let out = super::super::dispatch_trust_task_core(
            &state,
            &consumer(),
            &serde_json::to_vec(&doc).unwrap(),
            super::super::transport::TransportConfidentiality::HopByHop,
        )
        .await;
        let resp: Value = serde_json::from_slice(&out.body).unwrap();
        assert!(resp["payload"]["sealedCredential"].is_string(), "{resp}");
        assert!(resp["proof"].is_object(), "the response is signed: {resp}");
    }

    /// A setting the schema accepts and this custodian cannot use is answered
    /// `invalidSettings`, naming the member.
    #[tokio::test]
    async fn an_unusable_setting_names_its_member() {
        let (state, _dir) = build_signing_test_app_state().await;
        crate::contexts::create_context(&state.contexts_ks, CTX, "Community")
            .await
            .unwrap();
        let mut bad = settings();
        bad["endpoint"] = json!("https://s3.example.invalid/some/path");
        let out = handle_create(
            &state,
            &manager(),
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_CREATE_0_1,
                json!({ "context": CTX, "id": "r2-bad", "label": "bad", "settings": bad }),
            ),
        )
        .await;
        assert_eq!(code(&out), "external:invalidSettings", "{}", body(&out));
        assert_eq!(body(&out)["details"]["member"], "endpoint");
    }

    /// An archived account answers `external:archived` from every task that
    /// would change or use it; restore it first.
    #[tokio::test]
    async fn an_archived_account_is_refused_as_archived() {
        let (state, _dir) = state_with_account("r2-arch").await;
        let base = json!({ "context": CTX, "id": "r2-arch" });
        handle_archive(
            &state,
            &manager(),
            doc(uris::TASK_EXTERNAL_ACCOUNTS_ARCHIVE_0_1, base.clone()),
        )
        .await;
        let update = handle_update(
            &state,
            &manager(),
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_UPDATE_0_1,
                json!({ "context": CTX, "id": "r2-arch", "label": "renamed" }),
            ),
        )
        .await;
        assert_eq!(code(&update), "external:archived");
        let suspend = handle_suspend(
            &state,
            &manager(),
            doc(uris::TASK_EXTERNAL_ACCOUNTS_SUSPEND_0_1, base.clone()),
        )
        .await;
        assert_eq!(code(&suspend), "external:archived");
        let probe = handle_probe(
            &state,
            &manager(),
            doc(uris::TASK_EXTERNAL_ACCOUNTS_PROBE_0_1, base.clone()),
        )
        .await;
        assert_eq!(code(&probe), "external:archived");
        let armored = sealed_secret(&state, CTX, "r2-arch", "s").await;
        let secret = handle_secret_set(
            &state,
            &manager(),
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_SECRET_SET_0_1,
                json!({ "context": CTX, "id": "r2-arch", "sealedSecret": armored }),
            ),
        )
        .await;
        assert_eq!(code(&secret), "external:archived");
        // Reads still answer.
        let get = handle_get(
            &state,
            &manager(),
            doc(uris::TASK_EXTERNAL_ACCOUNTS_GET_0_1, base),
        )
        .await;
        assert_eq!(body(&get)["account"]["state"], "archived");
    }

    /// A secret sealed for another access key is refused, so a secret cannot
    /// be paired with the wrong key id.
    #[tokio::test]
    async fn a_secret_for_another_access_key_is_refused() {
        let (state, _dir) = state_with_account("r2-akid").await;
        let armored = sealed_secret_for_key(&state, CTX, "r2-akid", "s", Some("OTHERKEY")).await;
        let out = handle_secret_set(
            &state,
            &manager(),
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_SECRET_SET_0_1,
                json!({ "context": CTX, "id": "r2-akid", "sealedSecret": armored }),
            ),
        )
        .await;
        assert_eq!(code(&out), "external/accounts/secret/set:unsealFailed");
    }

    /// A probe with no binding and no `probePrefix` writes nothing: ok, not
    /// complete, and the account stays unusable.
    #[tokio::test]
    async fn an_incomplete_probe_does_not_make_an_account_usable() {
        let (state, _dir) = state_with_account("r2-probe").await;
        let armored = sealed_secret(&state, CTX, "r2-probe", "s").await;
        handle_secret_set(
            &state,
            &manager(),
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_SECRET_SET_0_1,
                json!({ "context": CTX, "id": "r2-probe", "sealedSecret": armored }),
            ),
        )
        .await;
        let out = handle_probe(
            &state,
            &manager(),
            doc(
                uris::TASK_EXTERNAL_ACCOUNTS_PROBE_0_1,
                json!({ "context": CTX, "id": "r2-probe" }),
            ),
        )
        .await;
        let report = &body(&out)["report"];
        assert_eq!(report["ok"], true, "{report}");
        assert_eq!(report["complete"], false, "{report}");
        let rec = store::get(&state.external_accounts_ks, CTX, "r2-probe")
            .await
            .unwrap()
            .unwrap();
        assert!(rec.provider_setup_required);
    }
}
