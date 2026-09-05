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
    (uris::TASK_PERSONA_RENDERERS_LIST_1_0, Reach::Context),
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::acl::Role;

    fn claims(role: Role, contexts: &[&str]) -> AuthClaims {
        let mut c = AuthClaims::default();
        c.role = role;
        c.allowed_contexts = contexts.iter().map(|s| (*s).to_string()).collect();
        c
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
        let err = authorize(
            &app,
            "https://trusttasks.org/spec/persona/made/up/9.9",
            Some("ctx"),
        )
        .unwrap_err();
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

    let written = match s
        .put(attribute, req.expected_version.map(|v| *v as u64))
        .await
    {
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
        .put_profile(profile, req.expected_version.map(|v| *v as u64))
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
        body["resolved"] = json!(
            r.iter()
                .map(|c| json!({
                    "attributeId": c.attribute_id,
                    "type": c.r#type,
                    "value": c.value,
                    "provenance": c.provenance,
                    "stale": c.stale,
                }))
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
    if req.unbind {
        if let Err(e) = s.unbind_everywhere(&id).await {
            return reject(&doc, e);
        }
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
            req.expected_version.map(|v| *v as u64),
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
    success_response(
        &doc,
        json!({
            "contextId": ctx,
            "personaDid": sum.persona_did,
            "bound": sum.bound,
            "profileId": sum.profile_id,
            "profileName": sum.profile_name,
            "claimCount": sum.claim_count,
            "boundAt": sum.bound_at,
        }),
    )
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
    success_response(
        &doc,
        json!({
            "personas": sums.iter().map(|s| json!({
                "personaDid": s.persona_did,
                "bound": s.bound,
                "profileName": s.profile_name,
                "claimCount": s.claim_count,
            })).collect::<Vec<_>>()
        }),
    )
}
