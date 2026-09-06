//! Persona trust-task slice (`spec/persona/*`) — authorization.
//!
//! The holder's own identity: the attribute pool, the profiles that project
//! over it, the bindings that assign a profile to a persona DID, and the
//! contacts peers disclose.
//!
//! # The boundary is one-way, and this module is where it is enforced
//!
//! The pool and profiles are **agent-scoped**, above every trust context.
//! Bindings, contacts and disclosure records are **context-scoped**. Nothing
//! inside a context may read the pool: the holder pushes a materialised
//! projection down, and a context never pulls.
//!
//! That is a rule about *direction* rather than a permission, because the
//! permission form invites the wrong implementation. An access-control failure
//! over a readable pool discloses everything; a pool no context can address has
//! nothing to disclose. `vta-persona`'s key layout provides the second half —
//! separately addressable prefixes — and [`Reach`] below provides the first.
//!
//! # The trap this module exists to avoid
//!
//! A guard written as *"is this caller an administrator"* **passes for an
//! administrator scoped to a single context**, who would then read and write
//! identity data belonging to every other context. An admin in one context must
//! be as powerless over the pool as an application in that context.
//!
//! The correct gate is [`AuthClaims::require_super_admin`] — `Admin` **and**
//! unrestricted scope. `vti-common`'s own `act_scope` documentation warns about
//! the same edge from the other side: an empty context list means *unrestricted*
//! for `Admin` and *nothing at all* for every other role, so a call site testing
//! `is_empty()` without the role gets one of the two backwards.

use serde_json::{Value, json};
use trust_tasks_rs::{ErrorPayload, StandardCode, TrustTask, TrustTaskCode};
use vta_sdk::trust_tasks as uris;
use vti_common::error::AppError;

use crate::audit;
use crate::auth::AuthClaims;
use crate::server::AppState;

use super::helpers::{TrustTaskOutcome, error_response, parse_payload, success_response};

/// The family namespace for codes shared across the slice. A proper path prefix
/// of each task slug, which SPEC §8.5 permits so a family-wide meaning is
/// defined once.
const FAMILY_SLUG: &str = "persona";

fn slug_from_doc(doc: &TrustTask<Value>) -> String {
    doc.type_uri
        .to_string()
        .strip_prefix("https://trusttasks.org/spec/")
        .and_then(|rest| rest.rsplit_once('/'))
        .map(|(slug, _ver)| slug.to_string())
        .unwrap_or_else(|| FAMILY_SLUG.to_string())
}

fn ext(slug: &str, local: &str) -> TrustTaskCode {
    TrustTaskCode::new_extended(slug, local).expect("persona extended code is grammar-valid")
}

/// Which side of the boundary a task sits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// Reachable only by an **unscoped holder** — `Admin` with unrestricted
    /// scope. A context-scoped caller is refused whatever its role.
    Holder,
    /// Reachable from inside a context, and confined to the caller's own.
    Context,
    /// Reachable by any authenticated caller, scoped or not.
    ///
    /// One task sits here, and it is not a hole. `renderers/list` returns a
    /// compile-time constant — the renderer ids this build ships and what each
    /// one discards — and carries nothing about the holder, any context, or
    /// any stored state at all.
    ///
    /// It needs its own variant because both of the others are wrong for it in
    /// opposite directions. `Context` refuses the unscoped holder: the payload
    /// schema has no `contextId`, so there is no context to name, and a
    /// handler that supplies one from the caller's own claims refuses the
    /// *most* privileged caller — an `Admin` with an unrestricted (empty)
    /// context list — while admitting every scoped one. `Holder` would refuse
    /// the callers who most need it: `disclosure/preview` is context-scoped
    /// and takes a renderer name, so an application that cannot list renderers
    /// cannot choose one, and choosing blind is how a holder ends up disclosing
    /// through a format that silently drops provenance.
    Any,
}

/// Every task in the family, paired with the side of the boundary it sits on.
///
/// Exhaustive by test. A task cannot join the family without someone deciding
/// which side it is on, because the census below fails until it appears here —
/// and defaulting a new task to `Context` is precisely how a pool read would
/// become reachable from inside one.
pub const REACH: &[(&str, Reach)] = &[
    // ── Agent-scoped: the holder's own, above every context ───────────────
    (uris::TASK_PERSONA_ATTRIBUTE_PUT_1_0, Reach::Holder),
    (uris::TASK_PERSONA_ATTRIBUTE_LIST_1_0, Reach::Holder),
    (uris::TASK_PERSONA_ATTRIBUTE_DELETE_1_0, Reach::Holder),
    (uris::TASK_PERSONA_PROFILE_PUT_1_0, Reach::Holder),
    (uris::TASK_PERSONA_PROFILE_GET_1_0, Reach::Holder),
    (uris::TASK_PERSONA_PROFILE_LIST_1_0, Reach::Holder),
    (uris::TASK_PERSONA_PROFILE_DELETE_1_0, Reach::Holder),
    // The critical gate. An application able to call this could bind any
    // profile to a persona it controls and read the result back through a
    // disclosure it requests of itself. Every other read leaks; this one is
    // directly exploitable.
    (uris::TASK_PERSONA_BINDING_SET_1_0, Reach::Holder),
    // Reads across every context, so it cannot be context-callable.
    (uris::TASK_PERSONA_DISCLOSURE_HISTORY_1_0, Reach::Holder),
    // Returns the linkage map between the holder's identities — the artifact
    // the whole family exists to keep from being assembled by anyone else.
    (uris::TASK_PERSONA_CORRELATION_ANALYZE_1_0, Reach::Holder),
    // ── Context-scoped: confined to the caller's own context ──────────────
    // Thin by construction: whether a profile is bound, its label, a claim
    // count. Never contents.
    (uris::TASK_PERSONA_BINDING_GET_1_0, Reach::Context),
    (uris::TASK_PERSONA_BINDING_LIST_1_0, Reach::Context),
    (uris::TASK_PERSONA_CONTACT_PUT_1_0, Reach::Context),
    (uris::TASK_PERSONA_CONTACT_GET_1_0, Reach::Context),
    (uris::TASK_PERSONA_CONTACT_LIST_1_0, Reach::Context),
    (uris::TASK_PERSONA_CONTACT_DELETE_1_0, Reach::Context),
    // The only path by which claim values reach an application — after a
    // human-visible summary. Being inside a context confers no privilege over
    // identity data: an application is a verifier, taking the same path as a
    // stranger's web page.
    (uris::TASK_PERSONA_DISCLOSURE_PREVIEW_1_0, Reach::Context),
    (uris::TASK_PERSONA_DISCLOSURE_PRESENT_1_0, Reach::Context),
    // ── Neither side: the agent's own advertised capabilities ─────────────
    (uris::TASK_PERSONA_RENDERERS_LIST_1_0, Reach::Any),
    // Authoring below the boundary is safe; the rule stops reading across it.
    (uris::TASK_PERSONA_LOCAL_PROFILE_PUT_1_0, Reach::Context),
    (uris::TASK_PERSONA_LOCAL_PROFILE_GET_1_0, Reach::Context),
    (uris::TASK_PERSONA_LOCAL_PROFILE_LIST_1_0, Reach::Context),
    (uris::TASK_PERSONA_LOCAL_PROFILE_DELETE_1_0, Reach::Context),
    // Safely context-callable — unlike `binding/set` — because both objects it
    // names live below the boundary. Its one load-bearing obligation is at the
    // handler: a `profileId` naming a POOL profile must be refused.
    (uris::TASK_PERSONA_LOCAL_BINDING_SET_1_0, Reach::Context),
];

/// The reach of a task, or `None` if this build does not know the URI.
///
/// Returning `None` rather than defaulting is deliberate. A task nobody
/// recognises must not be assumed safe to serve a context-scoped caller, and a
/// default of `Context` is exactly the shape of the leak this module prevents.
#[must_use]
pub fn reach_of(uri: &str) -> Option<Reach> {
    REACH.iter().find(|(u, _)| *u == uri).map(|(_, r)| *r)
}

/// Gate a persona task on the reach its URI declares.
///
/// `Holder` requires **unscoped holder** — `Admin` with unrestricted scope.
/// A context-scoped admin is refused, which is the whole point.
pub fn authorize(claims: &AuthClaims, uri: &str, context_id: Option<&str>) -> Result<(), AppError> {
    match reach_of(uri) {
        None => Err(AppError::Forbidden(format!(
            "unknown persona task {uri}: refusing rather than defaulting a reach"
        ))),
        Some(Reach::Holder) => claims.require_super_admin().map_err(|_| {
            AppError::Forbidden(
                "this task reads or writes the holder's attribute pool, which sits above every \
                 trust context. It requires an unscoped holder credential; an administrator \
                 scoped to a context is refused here exactly as an application would be."
                    .into(),
            )
        }),
        Some(Reach::Context) => match context_id {
            Some(ctx) => claims.require_context(ctx),
            None => Err(AppError::Validation(
                "a context-scoped persona task must name the context it acts in".into(),
            )),
        },
        // Authentication is the whole gate. See `Reach::Any` for why this task
        // does not belong on either side of the boundary, and why supplying a
        // context on its behalf was a bug rather than a convenience.
        Some(Reach::Any) => Ok(()),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────
//
// Request and response types come straight from `trust-tasks-rs` rather than
// hand-written SDK mirrors. `parse_payload` is generic over serde, so the
// generated types work as-is — and a mirror would be a second definition of the
// same contract, free to drift from the published schema without anything
// noticing. The generated types cannot.

use trust_tasks_rs::specs::persona as spec;
use vta_persona::{PersonaStore, ValueType, new_attribute};

/// Open the store for this request.
///
/// The correlation key is derived per agent and lives beside the at-rest key;
/// it never leaves the agent, which is what makes the blinded index blinded.
fn store(state: &AppState) -> PersonaStore {
    PersonaStore::new(state.persona_ks.clone(), state.persona_correlation_key)
}

/// Insert `key` into a response body only when `value` is `Some`.
///
/// `json!` renders a `None` as `null`, and every optional member in this
/// family's response schemas is typed `string`, `integer` or `date-time` —
/// none of which accepts null. An unset optional must be **absent**.
///
/// This is the response-side twin of the rule `payload_null_census` pins on
/// the request side in `vta-sdk`, and unlike that side it has no census: the
/// response-conformance layer catches it at run time in debug builds, which is
/// the only reason `disclosure/present`'s `credentialId` was ever noticed. Use
/// this rather than naming an `Option` inside `json!`.
fn put_opt<T: serde::Serialize>(body: &mut Value, key: &str, value: Option<T>) {
    if let Some(v) = value {
        body[key] = json!(v);
    }
}

/// Audit a persona task.
///
/// The attribute VALUE is deliberately never recorded. Copying identity data
/// into the audit store would give it a second home under a different retention
/// policy — the same reasoning app-state applies to its values, and it matters
/// more here because this store exists to hold personal data.
async fn audit_persona(
    state: &AppState,
    action: &str,
    auth: &AuthClaims,
    resource: Option<&str>,
    context_id: Option<&str>,
) {
    if let Err(e) = audit::record(
        &state.audit_sink,
        action,
        &auth.did,
        resource,
        "success",
        Some(super::helpers::TRANSPORT_TRUST_TASK),
        context_id,
    )
    .await
    {
        tracing::warn!(error = %e, action = %action, "audit record failed for persona task");
    }
}

/// Map a storage error onto the published error taxonomy.
///
/// Authorization failures use the framework's **standard** `permissionDenied`
/// rather than a task-namespaced synonym: the framework already names this
/// failure, and a duplicate would tell a client switching on the standard code
/// that something else went wrong.
fn reject(doc: &TrustTask<Value>, e: AppError) -> TrustTaskOutcome {
    let slug = slug_from_doc(doc);
    let message = e.to_string();
    let (code, details): (TrustTaskCode, Option<Value>) = match &e {
        AppError::Forbidden(_) | AppError::Unauthorized(_) => {
            (StandardCode::PermissionDenied.into(), None)
        }
        AppError::NotFound(_) => (ext(&slug, "notFound"), None),
        // The conflict carries the maintainer's view WITH the rejection. A bare
        // rejection obliges the caller to re-read, and between the rejection and
        // the re-read the record can change again — the pattern has no fixed
        // point under contention.
        AppError::Conflict(reason) => (
            ext(&slug, "versionConflict"),
            Some(json!({ "reason": reason })),
        ),
        AppError::Validation(reason) => (
            StandardCode::MalformedRequest.into(),
            Some(json!({ "reason": reason })),
        ),
        AppError::Gone(_) => (ext(&slug, "revisionReaped"), None),
        _ => (StandardCode::InternalError.into(), None),
    };

    let mut payload = ErrorPayload::new(code).with_message(message);
    if let Some(d) = details {
        payload = payload.with_details(d);
    }
    error_response(doc.reject_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload))
}

pub(super) async fn handle_attribute_put(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::attribute::put::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_ATTRIBUTE_PUT_1_0, None) {
        return reject(&doc, e);
    }

    let value_type = match serde_json::to_string(&req.value_type)
        .ok()
        .and_then(|s| serde_json::from_str::<ValueType>(&s).ok())
    {
        Some(v) => v,
        None => {
            return reject(&doc, AppError::Validation("unrecognised valueType".into()));
        }
    };

    let provenance = match serde_json::to_value(&req.provenance)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
    {
        Some(p) => p,
        None => return reject(&doc, AppError::Validation("unrecognised provenance".into())),
    };

    let mut attribute = new_attribute(
        req.type_.to_string(),
        value_type,
        req.value.clone(),
        provenance,
    );
    if let Some(id) = &req.attribute_id {
        attribute.attribute_id = id.to_string();
    }
    attribute.label = req.label.as_ref().map(|l| (**l).clone());

    let attribute_id = attribute.attribute_id.clone();
    let value = attribute.value.clone();
    let s = store(state);

    let written = match s.put(attribute, req.expected_version.map(|v| *v)).await {
        Ok(w) => w,
        Err(e) => return reject(&doc, e),
    };

    // Advisory, and computed after the write because the write has already
    // applied — a maintainer must not refuse on correlation grounds. The
    // holder decides.
    let shared = match &value {
        Some(v) => s.correlation_count(v, &attribute_id).await.unwrap_or(0),
        None => 0,
    };

    audit_persona(
        state,
        "persona.attribute.put",
        auth,
        Some(&attribute_id),
        None,
    )
    .await;

    success_response(
        &doc,
        serde_json::json!({
            "attributeId": attribute_id,
            "version": written.version,
            "created": written.created,
            "updatedAt": chrono::Utc::now().to_rfc3339(),
            "correlation": {
                "severity": if shared > 0 { "high" } else { "none" },
                "sharedWithProfileCount": shared,
            }
        }),
    )
}

pub(super) async fn handle_attribute_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::attribute::list::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_ATTRIBUTE_LIST_1_0, None) {
        return reject(&doc, e);
    }

    // Values are withheld unless asked for: the common case — rendering a
    // picker — needs type and label, not plaintext.
    let include_values = req.include_values;
    let s = store(state);
    let prefix = req.type_prefix.as_ref().map(|p| p.as_str());
    let attributes = match s.list_attributes(prefix, include_values).await {
        Ok(a) => a,
        Err(e) => return reject(&doc, e),
    };

    audit_persona(state, "persona.attribute.list", auth, None, None).await;
    success_response(&doc, serde_json::json!({ "attributes": attributes }))
}

pub(super) async fn handle_attribute_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::attribute::delete::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_ATTRIBUTE_DELETE_1_0, None) {
        return reject(&doc, e);
    }

    let id = req.attribute_id.to_string();
    let out = match store(state).delete(&id, req.cascade).await {
        Ok(o) => o,
        Err(e) => return reject(&doc, e),
    };

    audit_persona(state, "persona.attribute.delete", auth, Some(&id), None).await;
    success_response(
        &doc,
        serde_json::json!({
            "attributeId": id,
            "existed": out.existed,
            "removedFromProfiles": out.referring_profiles,
        }),
    )
}

// ─── Profiles ────────────────────────────────────────────────────────────

pub(super) async fn handle_profile_put(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::profile::put::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_PROFILE_PUT_1_0, None) {
        return reject(&doc, e);
    }

    // Entries round-trip through JSON into our own model. The generated
    // ProfileEntry and ours describe the same four shapes; going through the
    // wire form means the untagged discrimination is exercised exactly as a
    // peer's document would exercise it, rather than by a hand-written match
    // that could disagree with the schema.
    let entries = match serde_json::to_value(&req.entries)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
    {
        Some(e) => e,
        None => {
            return reject(
                &doc,
                AppError::Validation("unrecognised profile entry".into()),
            );
        }
    };

    let mut profile = vta_persona::new_profile(req.name.to_string(), entries);
    if let Some(id) = &req.profile_id {
        profile.profile_id = id.to_string();
    }
    profile.credential_refs = req.credential_refs.iter().map(|c| (**c).clone()).collect();
    let profile_id = profile.profile_id.clone();

    let written = match store(state)
        .put_profile(profile, req.expected_version.map(|v| *v))
        .await
    {
        Ok(w) => w,
        Err(e) => return reject(&doc, e),
    };

    audit_persona(state, "persona.profile.put", auth, Some(&profile_id), None).await;
    success_response(
        &doc,
        json!({
            "profileId": profile_id,
            "version": written.version,
            "created": written.created,
            "updatedAt": chrono::Utc::now().to_rfc3339(),
        }),
    )
}

pub(super) async fn handle_profile_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::profile::get::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_PROFILE_GET_1_0, None) {
        return reject(&doc, e);
    }

    let id = req.profile_id.to_string();
    let s = store(state);
    let Some(profile) = (match s.get_profile(&id).await {
        Ok(p) => p,
        Err(e) => return reject(&doc, e),
    }) else {
        // Not an empty success: a caller that cannot tell "absent" from "empty"
        // treats a typo as a profile that discloses nothing.
        return reject(&doc, AppError::NotFound(format!("profile {id}")));
    };

    // Resolution is opt-in because it is the expensive AND the disclosing
    // answer — it decrypts values and re-derives credential-backed ones.
    let resolved = if req.resolve {
        match s.resolve_profile(&id).await {
            Ok(r) => Some(r),
            Err(e) => return reject(&doc, e),
        }
    } else {
        None
    };

    audit_persona(state, "persona.profile.get", auth, Some(&id), None).await;
    let mut body = json!({ "profile": profile });
    if let Some(r) = resolved {
        // A resolved entry is a `ResolvedClaim`, not the pool `Attribute`, so an
        // INLINE entry is describable: `attributeId`, `version` and `updatedAt`
        // are optional there, and their absence is what says "this value lives
        // only in this profile".
        //
        // Until trust-tasks-rs 0.18 the array was typed as `Attribute`, which
        // required all three, and this handler refused rather than answer
        // non-conformantly — a synthesised `attributeId` would have been a lie
        // about where a value lives, and omitting the entry would have returned
        // a profile that appears to present less than it does. The schema is
        // fixed upstream (dtgwg-trust-tasks-tf#370) and the refusal is gone.
        body["resolved"] = json!(
            r.iter()
                .map(|c| {
                    let mut row = json!({
                        "type": c.r#type,
                        "value": c.value,
                        "valueType": c.value_type,
                        "provenance": c.provenance,
                        "stale": c.stale,
                    });
                    // Absent, not null — see `put_opt`.
                    put_opt(&mut row, "attributeId", c.attribute_id.clone());
                    put_opt(&mut row, "version", c.version);
                    put_opt(&mut row, "updatedAt", c.updated_at.clone());
                    row
                })
                .collect::<Vec<_>>()
        );
    }
    success_response(&doc, body)
}

pub(super) async fn handle_profile_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let _req: spec::profile::list::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_PROFILE_LIST_1_0, None) {
        return reject(&doc, e);
    }
    // No resolve option, deliberately: resolving every profile at once would
    // decrypt the holder's entire pool to answer a question about names.
    let profiles = match store(state).list_profiles().await {
        Ok(p) => p,
        Err(e) => return reject(&doc, e),
    };
    audit_persona(state, "persona.profile.list", auth, None, None).await;
    success_response(&doc, json!({ "profiles": profiles }))
}

pub(super) async fn handle_profile_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::profile::delete::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_PROFILE_DELETE_1_0, None) {
        return reject(&doc, e);
    }

    let id = req.profile_id.to_string();
    let s = store(state);

    // Refuse while a persona is bound unless the holder said unbind. A persona
    // that silently stopped presenting anything is a failure they discover from
    // the other side of a disclosure that did not happen.
    let bound = match s.personas_bound_to_anywhere(&id).await {
        Ok(b) => b,
        Err(e) => return reject(&doc, e),
    };
    if !bound.is_empty() && !req.unbind {
        let mut payload = ErrorPayload::new(ext(&slug_from_doc(&doc), "bound")).with_message(
            format!("{} persona(s) are bound to this profile", bound.len()),
        );
        payload = payload.with_details(json!({ "personaDids": bound }));
        return error_response(
            doc.reject_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload),
        );
    }
    if req.unbind
        && let Err(e) = s.unbind_everywhere(&id).await
    {
        return reject(&doc, e);
    }

    let existed = match s.delete_profile(&id).await {
        Ok(e) => e,
        Err(e) => return reject(&doc, e),
    };
    audit_persona(state, "persona.profile.delete", auth, Some(&id), None).await;
    success_response(
        &doc,
        json!({ "profileId": id, "existed": existed, "unboundPersonas": bound }),
    )
}

// ─── Bindings ────────────────────────────────────────────────────────────

pub(super) async fn handle_binding_set(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::binding::set::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // Holder-only, and the critical gate: an application able to call this
    // could bind any profile to a persona it controls and read the result back
    // through a disclosure it requests of itself.
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_BINDING_SET_1_0, None) {
        return reject(&doc, e);
    }

    let ctx = req.context_id.to_string();
    let persona = req.persona_did.to_string();
    let profile_id = req.profile_id.as_ref().map(|p| p.to_string());
    let public = req.public_entries.iter().map(|e| e.to_string()).collect();

    let bound = match store(state)
        .set_binding(
            &ctx,
            &persona,
            profile_id.as_deref(),
            public,
            req.expected_version.map(|v| *v),
        )
        .await
    {
        Ok(b) => b,
        Err(e) => return reject(&doc, e),
    };

    audit_persona(
        state,
        "persona.binding.set",
        auth,
        Some(&persona),
        Some(&ctx),
    )
    .await;
    success_response(
        &doc,
        json!({
            "contextId": ctx,
            "personaDid": persona,
            "profileId": profile_id,
            "version": bound.version,
            "materialisedClaimCount": bound.materialised_claim_count,
            "correlation": {
                // Binding one profile to a second persona makes them the same
                // person by construction, and no later narrowing undoes it.
                "severity": if bound.also_bound_persona_count > 0 { "high" } else { "none" },
                "alsoBoundPersonaCount": bound.also_bound_persona_count,
            },
            "boundAt": chrono::Utc::now().to_rfc3339(),
        }),
    )
}

pub(super) async fn handle_binding_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::binding::get::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ctx = req.context_id.to_string();
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_BINDING_GET_1_0, Some(&ctx)) {
        return reject(&doc, e);
    }

    let persona = req.persona_did.to_string();
    let sum = match store(state).binding_summary(&ctx, &persona).await {
        Ok(s) => s,
        Err(e) => return reject(&doc, e),
    };
    audit_persona(
        state,
        "persona.binding.get",
        auth,
        Some(&persona),
        Some(&ctx),
    )
    .await;
    // Thin by construction: whether bound, the label, a claim count. Never
    // contents — those reach an application only through the disclosure path.
    //
    // Four of the seven members are absent for an *unbound* persona, and
    // absent is not null — see `put_opt`. The bound case conformed; the
    // unbound one emitted four nulls and failed schema validation, which is
    // the reading a caller most needs to be able to trust: "nobody is bound
    // here" is an answer, not an error.
    let mut body = json!({
        "contextId": ctx,
        "personaDid": sum.persona_did,
        "bound": sum.bound,
        // Not optional, and 0 for an unbound persona — a count of nothing is
        // still a count.
        "claimCount": sum.claim_count,
    });
    put_opt(&mut body, "profileId", sum.profile_id);
    put_opt(&mut body, "profileName", sum.profile_name);
    put_opt(&mut body, "boundAt", sum.bound_at);
    success_response(&doc, body)
}

pub(super) async fn handle_binding_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::binding::list::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ctx = req.context_id.to_string();
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_BINDING_LIST_1_0, Some(&ctx)) {
        return reject(&doc, e);
    }

    let sums = match store(state).list_binding_summaries(&ctx).await {
        Ok(s) => s,
        Err(e) => return reject(&doc, e),
    };
    audit_persona(state, "persona.binding.list", auth, None, Some(&ctx)).await;
    let personas: Vec<Value> = sums
        .iter()
        .map(|s| {
            let mut row = json!({
                "personaDid": s.persona_did,
                "bound": s.bound,
                "claimCount": s.claim_count,
            });
            put_opt(&mut row, "profileName", s.profile_name.clone());
            row
        })
        .collect();
    success_response(&doc, json!({ "personas": personas }))
}

// ─── Contacts ────────────────────────────────────────────────────────────

pub(super) async fn handle_contact_put(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::contact::put::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ctx = req.context_id.to_string();
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_CONTACT_PUT_1_0, Some(&ctx)) {
        return reject(&doc, e);
    }

    let document = match serde_json::to_value(&req.document)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
    {
        Some(d) => d,
        None => {
            return reject(
                &doc,
                AppError::Validation("unrecognised contact document".into()),
            );
        }
    };

    let filed = match store(state)
        .file_contact(
            &ctx,
            &req.subject_did.to_string(),
            &req.known_by_persona.to_string(),
            document,
            req.credential_refs.iter().map(|c| c.to_string()).collect(),
        )
        .await
    {
        Ok(f) => f,
        Err(e) => return reject(&doc, e),
    };

    audit_persona(
        state,
        "persona.contact.put",
        auth,
        Some(&filed.contact_id),
        Some(&ctx),
    )
    .await;
    success_response(
        &doc,
        json!({
            "contactId": filed.contact_id,
            "rev": filed.rev,
            "created": filed.created,
            // Types, not values. A producer needing the old value reads the
            // prior revision, which is an explicit act.
            "changedClaims": filed.changed_claims,
        }),
    )
}

pub(super) async fn handle_contact_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::contact::get::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ctx = req.context_id.to_string();
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_CONTACT_GET_1_0, Some(&ctx)) {
        return reject(&doc, e);
    }
    let id = req.contact_id.to_string();
    let s = store(state);

    let Some(contact) = (match s.get_contact(&ctx, &id).await {
        Ok(c) => c,
        Err(e) => return reject(&doc, e),
    }) else {
        return reject(&doc, AppError::NotFound(format!("contact {id}")));
    };

    // A named revision resolves through the store, which distinguishes reaped
    // (Gone) from never-existed (NotFound) — a caller comparing against history
    // must be able to tell those apart.
    let document = match req.rev {
        None => serde_json::to_value(&contact.document).unwrap_or(Value::Null),
        Some(rev) => match s.get_contact_revision(&ctx, &id, rev.get()).await {
            Ok(r) => serde_json::to_value(&r.document).unwrap_or(Value::Null),
            Err(e) => return reject(&doc, e),
        },
    };

    let history = if req.include_history {
        match s.contact_history(&ctx, &id).await {
            // Metadata without documents: a timeline is cheap and the documents
            // behind it are not.
            Ok(h) => Some(
                h.iter()
                    .map(|(rev, at, cited)| json!({ "rev": rev, "receivedAt": at, "cited": cited }))
                    .collect::<Vec<_>>(),
            ),
            Err(e) => return reject(&doc, e),
        }
    } else {
        None
    };

    audit_persona(state, "persona.contact.get", auth, Some(&id), Some(&ctx)).await;
    let mut body = json!({
        "contactId": contact.contact_id,
        "subjectDid": contact.subject_did,
        "knownByPersona": contact.known_by_persona,
        "rev": req.rev.map_or(contact.rev, std::num::NonZeroU64::get),
        "document": document,
        "credentialRefs": contact.credential_refs,
        "notes": contact.notes,
    });
    if let Some(h) = history {
        body["history"] = json!(h);
    }
    success_response(&doc, body)
}

pub(super) async fn handle_contact_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::contact::list::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ctx = req.context_id.to_string();
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_CONTACT_LIST_1_0, Some(&ctx)) {
        return reject(&doc, e);
    }

    let persona = req.known_by_persona.as_ref().map(|p| p.to_string());
    let sums = match store(state)
        .list_contact_summaries(&ctx, persona.as_deref())
        .await
    {
        Ok(s) => s,
        Err(e) => return reject(&doc, e),
    };

    audit_persona(state, "persona.contact.list", auth, None, Some(&ctx)).await;
    success_response(
        &doc,
        json!({
            // Summaries carry no claim values: finding one contact does not
            // require disclosing the details of every contact.
            "contacts": sums.iter().map(|s| json!({
                "contactId": s.contact_id,
                "subjectDid": s.subject_did,
                "knownByPersona": s.known_by_persona,
                "rev": s.rev,
                "claimCount": s.claim_count,
                "receivedAt": s.received_at,
                "hasUnreviewedChange": s.has_unreviewed_change,
            })).collect::<Vec<_>>()
        }),
    )
}

pub(super) async fn handle_contact_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::contact::delete::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ctx = req.context_id.to_string();
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_CONTACT_DELETE_1_0, Some(&ctx)) {
        return reject(&doc, e);
    }
    let id = req.contact_id.to_string();

    let (existed, removed, retained) = match store(state).delete_contact(&ctx, &id).await {
        Ok(o) => o,
        Err(e) => return reject(&doc, e),
    };

    audit_persona(state, "persona.contact.delete", auth, Some(&id), Some(&ctx)).await;
    success_response(
        &doc,
        json!({
            "contactId": id,
            "existed": existed,
            "revisionsRemoved": removed,
            // Reported rather than glossed: an incomplete erasure the holder
            // believes is complete is worse than one they know about.
            "retainedForDisclosure": retained,
        }),
    )
}

// ─── Disclosure history, correlation, renderers ──────────────────────────

pub(super) async fn handle_disclosure_history(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::disclosure::history::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // Holder-only: omitting contextId queries across every context, which only
    // the holder may do and is the reason this sits above the boundary.
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_DISCLOSURE_HISTORY_1_0, None) {
        return reject(&doc, e);
    }

    let ctx = req.context_id.as_ref().map(|c| c.to_string());
    let verifier = req.verifier_did.as_ref().map(|v| v.to_string());
    let claim = req.attribute_type.as_ref().map(|t| t.to_string());
    let since = req.since.map(|s| s.to_rfc3339());

    let records = match store(state)
        .disclosure_history(&vta_persona::HistoryQuery {
            context_id: ctx.as_deref(),
            verifier_did: verifier.as_deref(),
            claim_type: claim.as_deref(),
            since: since.as_deref(),
        })
        .await
    {
        Ok(r) => r,
        Err(e) => return reject(&doc, e),
    };

    audit_persona(
        state,
        "persona.disclosure.history",
        auth,
        None,
        ctx.as_deref(),
    )
    .await;
    success_response(&doc, json!({ "disclosures": records }))
}

pub(super) async fn handle_correlation_analyze(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::correlation::analyze::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // Holder-only: the response is the linkage map between the holder's own
    // identities — the artifact the family exists to keep from being assembled
    // by anyone else.
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_CORRELATION_ANALYZE_1_0, None) {
        return reject(&doc, e);
    }

    let s = store(state);
    let findings = match s
        .analyze_correlation(
            req.attribute_id.as_ref().map(|a| a.to_string()).as_deref(),
            req.candidate
                .as_ref()
                .and_then(|c| serde_json::to_value(&c.value).ok())
                .as_ref(),
        )
        .await
    {
        Ok(f) => f,
        Err(e) => return reject(&doc, e),
    };

    audit_persona(state, "persona.correlation.analyze", auth, None, None).await;
    success_response(&doc, json!({ "findings": findings }))
}

pub(super) async fn handle_renderers_list(
    // Unused: this task describes the agent's declared capabilities, which are
    // a compile-time constant, not stored state. Taking the parameter anyway
    // keeps every handler one shape for the dispatch table.
    _state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let _req: spec::renderers::list::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // `Reach::Any`: authentication is the gate. This response is a
    // compile-time constant and names nothing the caller does not already know
    // about themselves.
    //
    // This used to pass `auth.allowed_contexts.first()` as the context, on the
    // reasoning that a caller should name one so the request is attributable.
    // That reasoning was wrong twice over. The context did not come from the
    // request, so it attributed nothing; and reading the caller's own list
    // inverted the gate — an `Admin` with an unrestricted (empty) list is the
    // most privileged caller there is, and was the only one refused.
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_RENDERERS_LIST_1_0, None) {
        return reject(&doc, e);
    }

    // Two renderers ship. Lossiness is DECLARED rather than discovered, so a
    // preview can tell the holder what a format will not carry before they
    // decide. Sourced from vta_persona::RENDERERS so this response and the
    // negotiation that enforces it cannot disagree.
    success_response(
        &doc,
        json!({
            "renderers": vta_persona::present::RENDERERS.iter().map(|r| json!({
                "id": r.id,
                "canonical": r.canonical,
                "drops": if r.carries_provenance { vec![] } else { vec!["provenance"] },
                "canCarryPredicates": r.carries_predicates,
            })).collect::<Vec<_>>()
        }),
    )
}

// ─── Context-local surface ───────────────────────────────────────────────
//
// Authoring BELOW the boundary is safe; the rule exists to stop reading ACROSS
// it. These are context-callable for that reason, and the store keeps them in
// their own address space so a scan here cannot reach a pool profile.

pub(super) async fn handle_local_profile_put(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::local::profile::put::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ctx = req.context_id.to_string();
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_LOCAL_PROFILE_PUT_1_0, Some(&ctx)) {
        return reject(&doc, e);
    }

    // The schema admits only inline entries, so a reference is unrepresentable
    // rather than rejected. The store re-checks anyway: two independent guards
    // on the property that keeps a context-authored object from acquiring pool
    // reach.
    let entries = match serde_json::to_value(&req.entries)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
    {
        Some(e) => e,
        None => {
            return reject(
                &doc,
                AppError::Validation("unrecognised local entry".into()),
            );
        }
    };

    let mut profile = vta_persona::new_profile(req.name.to_string(), entries);
    if let Some(id) = &req.profile_id {
        profile.profile_id = id.to_string();
    }
    let profile_id = profile.profile_id.clone();
    let s = store(state);

    let written = match s
        .put_local_profile(&ctx, profile, req.expected_version.map(|v| *v))
        .await
    {
        Ok(w) => w,
        Err(e) => return reject(&doc, e),
    };

    // Local profiles ARE correlation-indexed. The naive implementation skips
    // them — "they are local, they do not matter" — and loses the guard exactly
    // where a human most needs it: a throwaway identity is precisely where
    // somebody reuses a real value.
    let matches_pool = match s.get_local_profile(&ctx, &profile_id).await {
        Ok(Some(p)) => {
            let mut found = false;
            for entry in &p.entries {
                if let vta_persona::ProfileEntry::Inline { inline } = entry
                    && s.correlation_count(&inline.value, "").await.unwrap_or(0) > 0
                {
                    found = true;
                    break;
                }
            }
            found
        }
        _ => false,
    };

    audit_persona(
        state,
        "persona.local.profile.put",
        auth,
        Some(&profile_id),
        Some(&ctx),
    )
    .await;
    success_response(
        &doc,
        json!({
            "profileId": profile_id,
            "version": written.version,
            "created": written.created,
            "correlation": {
                "severity": if matches_pool { "high" } else { "none" },
                "matchesPoolValue": matches_pool,
            }
        }),
    )
}

pub(super) async fn handle_local_profile_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::local::profile::get::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ctx = req.context_id.to_string();
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_LOCAL_PROFILE_GET_1_0, Some(&ctx)) {
        return reject(&doc, e);
    }
    let id = req.profile_id.to_string();
    // Resolves nothing against the pool, because a local profile references
    // nothing there.
    match store(state).get_local_profile(&ctx, &id).await {
        Ok(Some(p)) => {
            audit_persona(
                state,
                "persona.local.profile.get",
                auth,
                Some(&id),
                Some(&ctx),
            )
            .await;
            success_response(&doc, json!({ "profile": p }))
        }
        Ok(None) => reject(&doc, AppError::NotFound(format!("local profile {id}"))),
        Err(e) => reject(&doc, e),
    }
}

pub(super) async fn handle_local_profile_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::local::profile::list::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ctx = req.context_id.to_string();
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_LOCAL_PROFILE_LIST_1_0, Some(&ctx)) {
        return reject(&doc, e);
    }
    let profiles = match store(state).list_local_profiles(&ctx).await {
        Ok(p) => p,
        Err(e) => return reject(&doc, e),
    };
    audit_persona(state, "persona.local.profile.list", auth, None, Some(&ctx)).await;
    success_response(
        &doc,
        json!({
            "profiles": profiles.iter().map(|p| json!({
                "profileId": p.profile_id,
                "name": p.name,
                "entryCount": p.entries.len(),
            })).collect::<Vec<_>>()
        }),
    )
}

pub(super) async fn handle_local_profile_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::local::profile::delete::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ctx = req.context_id.to_string();
    if let Err(e) = authorize(
        auth,
        uris::TASK_PERSONA_LOCAL_PROFILE_DELETE_1_0,
        Some(&ctx),
    ) {
        return reject(&doc, e);
    }
    let id = req.profile_id.to_string();
    let s = store(state);

    if req.unbind {
        // Leaves those personas presenting nothing, which is legal and which the
        // holder is told about rather than discovering from the other side.
        if let Err(e) = s.set_local_binding(&ctx, "", None).await {
            tracing::debug!(error = %e, "no local binding to clear");
        }
    }

    let existed = match s.delete_local_profile(&ctx, &id).await {
        Ok(e) => e,
        Err(e) => return reject(&doc, e),
    };
    audit_persona(
        state,
        "persona.local.profile.delete",
        auth,
        Some(&id),
        Some(&ctx),
    )
    .await;
    success_response(&doc, json!({ "profileId": id, "existed": existed }))
}

pub(super) async fn handle_local_binding_set(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::local::binding::set::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ctx = req.context_id.to_string();
    // Safely context-callable — unlike binding/set — because both objects it
    // names live below the boundary.
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_LOCAL_BINDING_SET_1_0, Some(&ctx)) {
        return reject(&doc, e);
    }

    let persona = req.persona_did.to_string();
    let profile_id = req.profile_id.as_ref().map(|p| p.to_string());

    // The store refuses an identifier naming a POOL profile. That refusal is
    // the whole distinction from binding/set, and it lives in one place so this
    // handler cannot forget it.
    let version = match store(state)
        .set_local_binding(&ctx, &persona, profile_id.as_deref())
        .await
    {
        Ok(v) => v,
        Err(e) => return reject(&doc, e),
    };

    audit_persona(
        state,
        "persona.local.binding.set",
        auth,
        Some(&persona),
        Some(&ctx),
    )
    .await;
    success_response(
        &doc,
        json!({
            "contextId": ctx,
            "personaDid": persona,
            "profileId": profile_id,
            "version": version,
        }),
    )
}

// ─── Disclosure: preview, then present ───────────────────────────────────

pub(super) async fn handle_disclosure_preview(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::disclosure::preview::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ctx = req.context_id.to_string();
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_DISCLOSURE_PREVIEW_1_0, Some(&ctx)) {
        return reject(&doc, e);
    }

    let requested: Option<Vec<String>> = if req.requested_claims.is_empty() {
        None
    } else {
        Some(req.requested_claims.iter().map(|c| c.to_string()).collect())
    };

    let preview = match store(state)
        .create_preview(
            &ctx,
            &req.persona_did.to_string(),
            &req.verifier_did.to_string(),
            req.purpose.as_ref().map(|p| p.to_string()).as_deref(),
            requested.as_deref(),
            req.renderer.as_ref().map(|r| r.to_string()).as_deref(),
        )
        .await
    {
        Ok(p) => p,
        Err(e) => return reject(&doc, e),
    };

    // Recorded even though nothing was disclosed: a pattern of previews the
    // holder declined is itself something they may want to see.
    audit_persona(
        state,
        "persona.disclosure.preview",
        auth,
        Some(&preview.preview_id),
        Some(&ctx),
    )
    .await;

    success_response(
        &doc,
        json!({
            "previewId": preview.preview_id,
            "subject": preview.subject,
            "claims": preview.claims,
            "renderer": { "id": preview.renderer_id, "drops": preview.renderer_drops },
            "expiresAt": preview.expires_at,
        }),
    )
}

pub(super) async fn handle_disclosure_present(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: spec::disclosure::present::v1_0::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ctx = req.context_id.to_string();
    if let Err(e) = authorize(auth, uris::TASK_PERSONA_DISCLOSURE_PRESENT_1_0, Some(&ctx)) {
        return reject(&doc, e);
    }

    let durable = req.mint.as_ref().is_some_and(|m| m.durable);

    // The store consumes the preview, refuses an expired one, refuses whole on
    // a stale claim, and writes the disclosure record BEFORE returning the
    // artifact — a crash between signing and recording would release data the
    // holder could never afterwards discover they had released.
    let (artifact, record) = match store(state)
        .present(
            &req.preview_id.to_string(),
            req.challenge.as_ref().map(|c| c.to_string()).as_deref(),
            durable,
        )
        .await
    {
        Ok(o) => o,
        Err(e) => return reject(&doc, e),
    };

    audit_persona(
        state,
        "persona.disclosure.present",
        auth,
        Some(&record.disclosure_id),
        Some(&ctx),
    )
    .await;

    // `credentialId` is present only when the holder asked for the disclosure
    // to be minted as a self-issued credential. It is built member-by-member
    // rather than with `json!`, because `json!` renders a `None` as `null` and
    // the schema types the member `string` — the same defect
    // `payload_null_census` guards against on the request side, where an unset
    // optional must be *absent* rather than null. There is no equivalent
    // census for responses; the response-conformance layer catches it at run
    // time instead, which is how this one was found.
    let mut body = json!({
        "disclosureId": record.disclosure_id,
        "artifact": artifact,
        "subject": record.subject,
        "disclosedAt": record.disclosed_at,
    });
    put_opt(
        &mut body,
        "credentialId",
        record.durable_credential_id.clone(),
    );
    success_response(&doc, body)
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::acl::Role;

    fn claims(role: Role, contexts: &[&str]) -> AuthClaims {
        AuthClaims {
            role,
            allowed_contexts: contexts.iter().map(|s| (*s).to_string()).collect(),
            ..Default::default()
        }
    }

    /// The census. A task cannot join the family without someone deciding which
    /// side of the boundary it is on.
    #[test]
    fn every_persona_task_declares_a_reach() {
        let classified: std::collections::HashSet<&str> = REACH.iter().map(|(u, _)| *u).collect();
        let missing: Vec<&&str> = uris::ALL_URIS
            .iter()
            .filter(|u| u.starts_with("https://trusttasks.org/spec/persona/"))
            .filter(|u| !classified.contains(*u))
            .collect();
        assert!(
            missing.is_empty(),
            "these persona tasks declare no reach — add them to REACH. When unsure, \
             `Holder` is the conservative answer: it refuses too much rather than \
             disclosing the pool to a context. {missing:#?}"
        );
    }

    #[test]
    fn no_reach_without_a_task() {
        let catalog: std::collections::HashSet<&str> = uris::ALL_URIS.iter().copied().collect();
        let orphans: Vec<&&str> = REACH
            .iter()
            .map(|(u, _)| u)
            .filter(|u| !catalog.contains(*u))
            .collect();
        assert!(
            orphans.is_empty(),
            "reach entries for tasks that do not exist: {orphans:#?}"
        );
    }

    /// The trap, asserted directly. This is the test that would have caught a
    /// guard written as `role == Admin`.
    #[test]
    fn a_context_scoped_admin_is_refused_every_holder_task() {
        let scoped_admin = claims(Role::Admin, &["ctx-work"]);
        for (uri, reach) in REACH {
            if *reach != Reach::Holder {
                continue;
            }
            let err = authorize(&scoped_admin, uri, Some("ctx-work")).unwrap_err();
            assert!(
                matches!(err, AppError::Forbidden(_)),
                "{uri} admitted an admin scoped to one context — an admin in ctx-work must be \
                 as powerless over the pool as an application in ctx-work"
            );
        }
    }

    #[test]
    fn an_unscoped_holder_reaches_the_pool() {
        let holder = claims(Role::Admin, &[]);
        for (uri, reach) in REACH {
            if *reach == Reach::Holder {
                authorize(&holder, uri, None).unwrap_or_else(|e| {
                    panic!("{uri} refused an unscoped holder: {e:?}");
                });
            }
        }
    }

    #[test]
    fn every_non_admin_role_is_refused_the_pool() {
        // An empty context list means *unrestricted* for Admin and *nothing at
        // all* for every other role. A gate testing emptiness without the role
        // gets one of those backwards, so both halves are asserted.
        for role in [
            Role::Application,
            Role::Reader,
            Role::Initiator,
            Role::Monitor,
        ] {
            let label = format!("{role:?}");
            let c = claims(role, &[]);
            let err = authorize(&c, uris::TASK_PERSONA_ATTRIBUTE_LIST_1_0, None).unwrap_err();
            assert!(
                matches!(err, AppError::Forbidden(_)),
                "{label} reached the pool"
            );
        }
    }

    #[test]
    fn a_context_task_is_confined_to_its_own_context() {
        let app = claims(Role::Application, &["ctx-a"]);
        authorize(&app, uris::TASK_PERSONA_BINDING_GET_1_0, Some("ctx-a")).expect("own context");
        assert!(
            authorize(&app, uris::TASK_PERSONA_BINDING_GET_1_0, Some("ctx-b")).is_err(),
            "a caller scoped to ctx-a must not learn about ctx-b"
        );
    }

    #[test]
    fn an_unknown_task_is_refused_rather_than_defaulted() {
        let app = claims(Role::Application, &["ctx"]);
        // Built rather than written as a literal, deliberately. `produced_census`
        // scans this crate's source for spec-URI literals and asks who publishes
        // each one — correctly, because a produced document with no schema has
        // validation on neither side. This fixture never goes on a wire, so it
        // takes the `format!` shape the census already documents as "not a URI
        // that goes on a wire", rather than being allowlisted as produced.
        let unknown = format!("https://trusttasks.org/spec/persona/{}/9.9", "made-up");
        let err = authorize(&app, &unknown, Some("ctx")).unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    #[test]
    fn binding_set_is_holder_only_and_local_binding_set_is_not() {
        // The pair that most invites being collapsed. One crosses the boundary
        // and one does not.
        assert_eq!(
            reach_of(uris::TASK_PERSONA_BINDING_SET_1_0),
            Some(Reach::Holder)
        );
        assert_eq!(
            reach_of(uris::TASK_PERSONA_LOCAL_BINDING_SET_1_0),
            Some(Reach::Context)
        );
    }
}
