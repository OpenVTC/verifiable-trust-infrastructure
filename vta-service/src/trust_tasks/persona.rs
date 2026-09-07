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

/// Whether this caller has been granted holder authority by name.
///
/// Read from the ACL entry per call rather than from the access token, and the
/// direction matters: a *grant* carried in a JWT outlives its revocation for the
/// life of the token, so revoking holder authority would leave a window in which
/// the pool is still readable. (The capability *narrowing* gate reads per call
/// for the mirror-image reason — see `helpers::require_capability`.)
///
/// A store error is not a grant. It is logged with the real reason and answered
/// as "no", because the alternative — treating an unreadable ACL as permission —
/// turns a database blip into a boundary crossing.
async fn holder_capability_granted(state: &AppState, claims: &AuthClaims) -> bool {
    match vti_common::acl::get_acl_entry(&state.acl_ks, &claims.did).await {
        Ok(Some(entry)) => vti_common::acl::entry_has_capability(
            &entry,
            vti_common::acl::Capability::PersonaHolder,
        ),
        // No entry, no grant. Unlike the narrowing gate, there is no role to
        // fall back to: no role derives this capability.
        Ok(None) => false,
        Err(e) => {
            tracing::error!(
                error = %e, did = %claims.did,
                "could not read the ACL entry for a persona holder check; refusing"
            );
            false
        }
    }
}

/// Gate a persona task on the reach its URI declares.
///
/// `Holder` is satisfied two ways, and only two: an **unscoped holder
/// credential** (`Admin` with unrestricted scope), or an entry granted
/// [`Capability::PersonaHolder`](vti_common::acl::Capability::PersonaHolder) by
/// name. A context-scoped admin holding neither is refused, which is the whole
/// point.
///
/// The capability exists because the first form was, until now, the *only*
/// form: managing your own identity from a client meant giving that client
/// authority over every context on the agent. It grants the pool without
/// granting that.
///
/// The ACL read happens only where it can change the answer — a `Holder` task,
/// for a caller who is not already unscoped — so the context-scoped tasks and
/// the super-admin path cost exactly what they did.
pub async fn authorize(
    state: &AppState,
    claims: &AuthClaims,
    uri: &str,
    context_id: Option<&str>,
) -> Result<(), AppError> {
    let granted = matches!(reach_of(uri), Some(Reach::Holder))
        && !claims.is_super_admin()
        && holder_capability_granted(state, claims).await;
    decide(claims, uri, context_id, granted)
}

/// The decision itself, given whether the caller holds the capability.
///
/// Split from [`authorize`] so the whole matrix — every URI against every role
/// and scope — is testable without standing up a store. The reach table is the
/// thing most likely to be got wrong, and a test that needs an `AppState` to
/// ask about it is a test nobody extends when they add a task.
fn decide(
    claims: &AuthClaims,
    uri: &str,
    context_id: Option<&str>,
    holder_granted: bool,
) -> Result<(), AppError> {
    match reach_of(uri) {
        None => Err(AppError::Forbidden(format!(
            "unknown persona task {uri}: refusing rather than defaulting a reach"
        ))),
        Some(Reach::Holder) => {
            if claims.is_super_admin() || holder_granted {
                return Ok(());
            }
            Err(AppError::Forbidden(
                "this task reads or writes the holder's attribute pool, which sits above every \
                 trust context. It requires an unscoped holder credential, or an ACL entry \
                 granted the `persona-holder` capability; an administrator scoped to a context \
                 and holding neither is refused here exactly as an application would be."
                    .into(),
            ))
        }
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
use vta_persona::{Listing, PersonaStore, Sensitivity, ValueType, ValueVisibility, new_attribute};

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
/// `detail` is a short human-readable sentence saying what the operation
/// *changed*, and it exists because the trail without one is unreadable. Every
/// write in this family used to record action, actor, resource and outcome and
/// nothing else, so an entire console audit pane read `persona.attribute.put`
/// against an opaque ULID, twenty rows deep, with no way to tell a created
/// attribute from an updated one or a cascade delete from a refused one. The
/// console was never the problem: `AuditEnvelope` renders `detail` in full as
/// `detail.reason`, and there was simply nothing to render.
///
/// # The attribute VALUE is never recorded — and the reason is LIFETIME
///
/// The obvious reading of that rule is an access-control one: that whoever
/// reads the audit log is less trusted than whoever reads the pool. That
/// reading is false here, and believing it leads to the wrong conclusion in
/// both directions.
///
/// Persona rows are recorded with `context_id: None`, and
/// [`crate::operations::audit`]'s `authorize` already refuses every entry not
/// confined to a named context to anyone but an **unrestricted (super) admin**
/// — precisely the caller [`Reach::Holder`] admits to `attribute/list`, which
/// hands back the plaintext values on request. So a value written here would
/// disclose nothing to anyone who could not already ask for it directly.
/// Nobody gains a read.
///
/// What they gain is a **second copy with a different lifetime**. The audit
/// keyspace is append-only and pruned on its own retention schedule
/// (`vta_audit::cleanup_expired_logs`); the pool is deleted when the holder
/// deletes an attribute. Copy a value across and `attribute/delete` quietly
/// stops being a delete: the value outlives the record it came from, in a
/// store the holder's delete does not reach and whose whole point is that it
/// is not rewritten afterwards.
///
/// The distinction is spelled out because "don't log values", stated as a bare
/// prohibition, is exactly the rule someone relaxes the first time an operator
/// asks for a more useful trail — and the access-control argument, being
/// false, does not survive that conversation. The lifetime argument does.
///
/// What `detail` may therefore carry: claim **types**, value *types*,
/// provenance kinds, counts, versions, and identifiers. Each of those
/// describes the shape of a change without being the personal data, and each
/// is already reconstructible from the live record — so none of them acquires
/// a life the record does not have.
async fn audit_persona(
    state: &AppState,
    action: &str,
    auth: &AuthClaims,
    resource: Option<&str>,
    context_id: Option<&str>,
    detail: Option<&str>,
) {
    if let Err(e) = audit::record_with_detail(
        &state.audit_sink,
        action,
        &auth.did,
        resource,
        "success",
        Some(super::helpers::TRANSPORT_TRUST_TASK),
        context_id,
        detail,
    )
    .await
    {
        tracing::warn!(error = %e, action = %action, "audit record failed for persona task");
    }
}

/// The `kind` discriminant of a provenance, as the wire spells it.
///
/// Matched rather than serialised because only the tag is wanted: serialising
/// a `CredentialBacked` provenance would carry `credentialId`, `claimPath` and
/// `issuerDid` into the audit row alongside it, and a claim path is a
/// description of what an issuer attested about the holder — a fact with the
/// same lifetime problem as the value itself.
fn provenance_kind(p: &vta_persona::Provenance) -> &'static str {
    match p {
        vta_persona::Provenance::SelfAsserted => "selfAsserted",
        vta_persona::Provenance::CredentialBacked { .. } => "credentialBacked",
        vta_persona::Provenance::Generated { .. } => "generated",
    }
}

/// The wire spelling of a string-valued enum — `string`, `date`, `high`, …
///
/// Via serde rather than a second `match` per enum, so a variant added to
/// `ValueType` or `Sensitivity` cannot end up spelled one way in a response and
/// another in the audit row.
fn wire_name<T: serde::Serialize>(v: T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_ATTRIBUTE_PUT_1_0, None).await {
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

    let provenance: vta_persona::Provenance = match serde_json::to_value(&req.provenance)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
    {
        Some(p) => p,
        None => return reject(&doc, AppError::Validation("unrecognised provenance".into())),
    };

    // Read the discriminant before the value moves into the attribute. Only the
    // tag survives into the audit row; `provenance_kind` says why the rest of a
    // `CredentialBacked` provenance must not.
    let provenance_kind = provenance_kind(&provenance);

    // The holder's own decision, and only where they made one. Absent is not
    // `normal`: it records that nothing was decided, so the default resolves
    // from the claim-type registry at every read and a later tightening of that
    // registry protects the attributes already in the pool.
    //
    // Through the wire spelling rather than a match, for the reason `valueType`
    // above takes the same route: the generated enum is `#[non_exhaustive]`, so
    // a match needs a wildcard arm, and a wildcard arm is where a variant added
    // upstream would land silently.
    let sensitivity: Option<Sensitivity> = match req.sensitivity.as_ref() {
        None => None,
        Some(s) => match serde_json::to_value(s)
            .ok()
            .and_then(|v| serde_json::from_value(v).ok())
        {
            Some(parsed) => Some(parsed),
            None => {
                return reject(
                    &doc,
                    AppError::Validation("unrecognised sensitivity".into()),
                );
            }
        },
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
    attribute.sensitivity = sensitivity;

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

    // A sensitivity override points either way — `normal` on a card is a
    // holder deciding their own tooling may show it — so the row records the
    // decision and not merely that a write happened. Without it a holder
    // reviewing the trail cannot see when the withholding stopped.
    let sensitivity_note = match sensitivity {
        Some(s) => format!(", sensitivity {} set by the holder", wire_name(s)),
        None => String::new(),
    };

    // Type, value TYPE, provenance kind and version — never `value`. See
    // `audit_persona` for why that line is drawn on lifetime rather than on
    // who may read the row.
    let detail = format!(
        "{} attribute {attribute_id}: claim type {}, valueType {}, provenance {}{}, now at \
         version {}",
        if written.created {
            "created"
        } else {
            "updated"
        },
        req.type_.as_str(),
        wire_name(value_type),
        provenance_kind,
        sensitivity_note,
        written.version,
    );
    audit_persona(
        state,
        "persona.attribute.put",
        auth,
        Some(&attribute_id),
        None,
        Some(&detail),
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_ATTRIBUTE_LIST_1_0, None).await {
        return reject(&doc, e);
    }

    // Values are withheld unless asked for: the common case — rendering a
    // picker — needs type and label, not plaintext. `includeSensitive` widens
    // that request and can never be the member that introduces plaintext on its
    // own, so the two collapse into one visibility here rather than travelling
    // as a pair every reader has to remember the fourth state of.
    let visibility = ValueVisibility::from_flags(req.include_values, req.include_sensitive);
    let s = store(state);
    let prefix = req.type_prefix.as_ref().map(|p| p.as_str());
    let listing = match s.list_attributes(prefix, visibility).await {
        Ok(l) => l,
        Err(e) => return reject(&doc, e),
    };

    let detail = list_detail(&listing, visibility, prefix);
    audit_persona(
        state,
        "persona.attribute.list",
        auth,
        None,
        None,
        Some(&detail),
    )
    .await;
    success_response(
        &doc,
        serde_json::json!({ "attributes": listing.attributes }),
    )
}

/// What a listing did, for the audit trail.
///
/// A read is audited at all because this one enumerates the holder's identity;
/// what makes the row worth keeping is which of the three listings it was. A
/// trail in which "showed me the names" and "handed a process every card
/// number" are the same row cannot answer the question a holder reviewing it
/// actually has.
///
/// Counts, a claim-type prefix and the visibility — never a value. See
/// [`audit_persona`] for why that line is drawn on lifetime rather than on who
/// may read the row: `attribute/list` hands the values themselves to exactly
/// the caller who can read the audit log, so a value here would disclose
/// nothing new and would outlive the record it came from.
fn list_detail(listing: &Listing, visibility: ValueVisibility, prefix: Option<&str>) -> String {
    let scope = match prefix {
        Some(p) => format!(" under {p}"),
        None => String::new(),
    };
    let plaintext = match visibility {
        ValueVisibility::Metadata => "metadata only, no values".to_string(),
        ValueVisibility::Ordinary => format!(
            "values included, {} sensitive value(s) withheld",
            listing.withheld_sensitive
        ),
        ValueVisibility::All => "values included, sensitive values included".to_string(),
    };
    format!(
        "listed {} attribute(s){scope}: {plaintext}",
        listing.attributes.len()
    )
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_ATTRIBUTE_DELETE_1_0, None).await {
        return reject(&doc, e);
    }

    let id = req.attribute_id.to_string();
    let out = match store(state).delete(&id, req.cascade).await {
        Ok(o) => o,
        Err(e) => return reject(&doc, e),
    };

    // `existed` is the half a reader cannot reconstruct afterwards: the record
    // is gone either way, so a row that only says "delete" cannot distinguish a
    // removal from a no-op against a typo'd id.
    let detail = format!(
        "attribute {id} {}; cascade {}; removed from {} profile(s)",
        if out.existed {
            "deleted"
        } else {
            "did not exist"
        },
        req.cascade,
        out.referring_profiles.len(),
    );
    audit_persona(
        state,
        "persona.attribute.delete",
        auth,
        Some(&id),
        None,
        Some(&detail),
    )
    .await;
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_PROFILE_PUT_1_0, None).await {
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
    let entry_count = profile.entries.len();

    let written = match store(state)
        .put_profile(profile, req.expected_version.map(|v| *v))
        .await
    {
        Ok(w) => w,
        Err(e) => return reject(&doc, e),
    };

    // The entry COUNT, not the entries. An entry is either a pool reference —
    // an identifier, safe — or an inline value, which is a claim value under
    // another name and carries the whole lifetime problem with it.
    let detail = format!(
        "{} profile {profile_id} with {} entr{}, now at version {}",
        if written.created {
            "created"
        } else {
            "updated"
        },
        entry_count,
        if entry_count == 1 { "y" } else { "ies" },
        written.version,
    );
    audit_persona(
        state,
        "persona.profile.put",
        auth,
        Some(&profile_id),
        None,
        Some(&detail),
    )
    .await;
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_PROFILE_GET_1_0, None).await {
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

    audit_persona(state, "persona.profile.get", auth, Some(&id), None, None).await;
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_PROFILE_LIST_1_0, None).await {
        return reject(&doc, e);
    }
    // No resolve option, deliberately: resolving every profile at once would
    // decrypt the holder's entire pool to answer a question about names.
    let profiles = match store(state).list_profiles().await {
        Ok(p) => p,
        Err(e) => return reject(&doc, e),
    };
    audit_persona(state, "persona.profile.list", auth, None, None, None).await;
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_PROFILE_DELETE_1_0, None).await {
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
    // How many personas were left presenting nothing is the consequence a
    // holder most needs to find later, and it is the one fact that survives
    // nowhere else: the bindings it describes have already been cleared.
    let detail = format!(
        "profile {id} {}; {}; {} persona(s) unbound",
        if existed { "deleted" } else { "did not exist" },
        if req.unbind {
            "unbind requested"
        } else {
            "no unbind requested"
        },
        bound.len(),
    );
    audit_persona(
        state,
        "persona.profile.delete",
        auth,
        Some(&id),
        None,
        Some(&detail),
    )
    .await;
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_BINDING_SET_1_0, None).await {
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

    // The materialised claim count is what changed on the far side of the
    // boundary: this write is a PUSH into a context, and the count is how much
    // that context can now present. "unbound" is spelled out rather than left
    // as an absent profileId, because a binding cleared and a binding never
    // made read identically otherwise.
    let detail = format!(
        "persona {persona} in context {ctx} bound to {}; {} claim(s) materialised, now at \
         version {}",
        profile_id
            .as_deref()
            .map_or_else(|| "unbound".to_string(), |p| format!("profile {p}")),
        bound.materialised_claim_count,
        bound.version,
    );
    audit_persona(
        state,
        "persona.binding.set",
        auth,
        Some(&persona),
        Some(&ctx),
        Some(&detail),
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_BINDING_GET_1_0, Some(&ctx)).await {
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
        None,
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_BINDING_LIST_1_0, Some(&ctx)).await {
        return reject(&doc, e);
    }

    let sums = match store(state).list_binding_summaries(&ctx).await {
        Ok(s) => s,
        Err(e) => return reject(&doc, e),
    };
    audit_persona(state, "persona.binding.list", auth, None, Some(&ctx), None).await;
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_CONTACT_PUT_1_0, Some(&ctx)).await {
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
            req.notes.as_ref().map(|n| n.to_string()),
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
        None,
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_CONTACT_GET_1_0, Some(&ctx)).await {
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

    audit_persona(
        state,
        "persona.contact.get",
        auth,
        Some(&id),
        Some(&ctx),
        None,
    )
    .await;
    let mut body = json!({
        "contactId": contact.contact_id,
        "subjectDid": contact.subject_did,
        "knownByPersona": contact.known_by_persona,
        "rev": req.rev.map_or(contact.rev, std::num::NonZeroU64::get),
        "document": document,
        "credentialRefs": contact.credential_refs,
    });
    // The holder's private annotation is optional, and an unset optional must be
    // absent rather than null — see `put_opt`. Naming it inside `json!` emitted
    // `"notes": null` and failed the response schema.
    put_opt(&mut body, "notes", contact.notes.clone());
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_CONTACT_LIST_1_0, Some(&ctx)).await {
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

    audit_persona(state, "persona.contact.list", auth, None, Some(&ctx), None).await;
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
    if let Err(e) = authorize(
        state,
        auth,
        uris::TASK_PERSONA_CONTACT_DELETE_1_0,
        Some(&ctx),
    )
    .await
    {
        return reject(&doc, e);
    }
    let id = req.contact_id.to_string();

    let (existed, removed, retained) = match store(state).delete_contact(&ctx, &id).await {
        Ok(o) => o,
        Err(e) => return reject(&doc, e),
    };

    audit_persona(
        state,
        "persona.contact.delete",
        auth,
        Some(&id),
        Some(&ctx),
        None,
    )
    .await;
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_DISCLOSURE_HISTORY_1_0, None).await {
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
        None,
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
    if let Err(e) = authorize(
        state,
        auth,
        uris::TASK_PERSONA_CORRELATION_ANALYZE_1_0,
        None,
    )
    .await
    {
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

    audit_persona(state, "persona.correlation.analyze", auth, None, None, None).await;
    success_response(&doc, json!({ "findings": findings }))
}

pub(super) async fn handle_renderers_list(
    // Unused: this task describes the agent's declared capabilities, which are
    // a compile-time constant, not stored state. Taking the parameter anyway
    // keeps every handler one shape for the dispatch table.
    state: &AppState,
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
    if let Err(e) = authorize(state, auth, uris::TASK_PERSONA_RENDERERS_LIST_1_0, None).await {
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
    if let Err(e) = authorize(
        state,
        auth,
        uris::TASK_PERSONA_LOCAL_PROFILE_PUT_1_0,
        Some(&ctx),
    )
    .await
    {
        return reject(&doc, e);
    }

    // The schema admits only inline entries, so a reference is unrepresentable
    // rather than rejected. The store re-checks anyway: two independent guards
    // on the property that keeps a context-authored object from acquiring pool
    // reach.
    //
    // **A context-local entry carries no `provenance`, and the store's does.**
    // The published local shape is `{type, valueType, value, label?}` — narrower
    // than a pool profile's inline entry, which requires `provenance` — so the
    // two types are mapped member by member here rather than round-tripped
    // through JSON. The round-trip is what this used to do, and because
    // `InlineValue::provenance` has no default it failed for *every* valid
    // request, rejecting them all as "unrecognised local entry". Nothing caught
    // it: the only test of this task asserted that an invalid entry is refused,
    // which a handler that refuses everything also passes.
    //
    // `SelfAsserted` is the only honest answer, not a placeholder. A
    // credential-backed provenance names a `credentialId` and a `claimPath`,
    // and the local shape has nowhere to put either — so a value authored
    // inside a context cannot be attested, and presenting one as though it were
    // would let a context assert an issuer's authority over a value that issuer
    // never saw. That is the same boundary the missing `ref` forms enforce,
    // one field along.
    let entries: Option<Vec<vta_persona::ProfileEntry>> = req
        .entries
        .iter()
        .map(|e| {
            // Same JSON round-trip the pool handler uses for `valueType`: the
            // two enums serialise to identical strings, and going through serde
            // keeps the mapping honest if either side ever gains a variant the
            // other lacks.
            let value_type = serde_json::to_string(&e.inline.value_type)
                .ok()
                .and_then(|s| serde_json::from_str::<ValueType>(&s).ok())?;
            Some(vta_persona::ProfileEntry::Inline {
                inline: vta_persona::InlineValue {
                    // Generated newtypes `Deref` to `String` but do not impl
                    // `Display`, so a method call auto-derefs where a function
                    // path does not.
                    r#type: e.inline.type_.to_string(),
                    value_type,
                    value: e.inline.value.clone(),
                    label: e.inline.label.as_ref().map(|l| l.to_string()),
                    provenance: vta_persona::Provenance::SelfAsserted,
                },
            })
        })
        .collect();
    let Some(entries) = entries else {
        return reject(&doc, AppError::Validation("unrecognised valueType".into()));
    };

    let mut profile = vta_persona::new_profile(req.name.to_string(), entries);
    if let Some(id) = &req.profile_id {
        profile.profile_id = id.to_string();
    }
    let profile_id = profile.profile_id.clone();
    let entry_count = profile.entries.len();
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

    // `matchesPoolValue` is carried because it is the reason this task is
    // correlation-indexed at all: a throwaway identity is precisely where
    // somebody reuses a real value, and a holder auditing that later needs to
    // see WHICH local write raised the flag, not merely that one did. The flag
    // is a boolean about a value, never the value.
    let detail = format!(
        "{} context-local profile {profile_id} in context {ctx} with {} entr{}, now at version \
         {}; matches a pool value: {matches_pool}",
        if written.created {
            "created"
        } else {
            "updated"
        },
        entry_count,
        if entry_count == 1 { "y" } else { "ies" },
        written.version,
    );
    audit_persona(
        state,
        "persona.local.profile.put",
        auth,
        Some(&profile_id),
        Some(&ctx),
        Some(&detail),
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
    if let Err(e) = authorize(
        state,
        auth,
        uris::TASK_PERSONA_LOCAL_PROFILE_GET_1_0,
        Some(&ctx),
    )
    .await
    {
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
                None,
            )
            .await;
            // Built member by member rather than serialising the stored
            // `Profile`. The local response schema closes the object to
            // `{profileId, name, entries, version}`, and the stored shape also
            // carries `createdAt`/`updatedAt` — serialising it whole failed
            // response conformance with "Additional properties are not allowed".
            //
            // The narrower shape is right: those timestamps are pool-record
            // metadata, and a context-local profile is not a pool record.
            success_response(
                &doc,
                json!({
                    "profile": {
                        "profileId": p.profile_id,
                        "name": p.name,
                        "entries": p.entries,
                        "version": p.version,
                    }
                }),
            )
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
    if let Err(e) = authorize(
        state,
        auth,
        uris::TASK_PERSONA_LOCAL_PROFILE_LIST_1_0,
        Some(&ctx),
    )
    .await
    {
        return reject(&doc, e);
    }
    let profiles = match store(state).list_local_profiles(&ctx).await {
        Ok(p) => p,
        Err(e) => return reject(&doc, e),
    };
    audit_persona(
        state,
        "persona.local.profile.list",
        auth,
        None,
        Some(&ctx),
        None,
    )
    .await;
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
        state,
        auth,
        uris::TASK_PERSONA_LOCAL_PROFILE_DELETE_1_0,
        Some(&ctx),
    )
    .await
    {
        return reject(&doc, e);
    }
    let id = req.profile_id.to_string();
    let s = store(state);

    let mut unbound = 0usize;
    if req.unbind {
        // Clear every persona bound to this profile in this context.
        //
        // This used to call `set_local_binding(&ctx, "", None)` — with an
        // *empty* persona DID, which clears the binding of nobody. `--unbind`
        // therefore unbound nothing, and the delete either failed on the
        // still-bound personas or left them pointing at a profile that no
        // longer exists. It went unnoticed because nothing exercised the local
        // family beyond asserting that an invalid entry is refused.
        //
        // Leaves those personas presenting nothing, which is legal and which
        // the holder is told about rather than discovering from the other side.
        let bound = match s.personas_bound_to(&ctx, &id).await {
            Ok(p) => p,
            Err(e) => return reject(&doc, e),
        };
        unbound = bound.len();
        for persona_did in bound {
            if let Err(e) = s.set_local_binding(&ctx, &persona_did, None).await {
                return reject(&doc, e);
            }
        }
    }

    let existed = match s.delete_local_profile(&ctx, &id).await {
        Ok(e) => e,
        Err(e) => return reject(&doc, e),
    };
    // The unbind count is the only surviving trace of the silent-unbind bug
    // this handler used to have: `--unbind` cleared nobody, and nothing said
    // so. A row reading "0 persona(s) unbound" against a profile that had
    // bindings is now visible after the fact rather than only reproducible.
    let detail = format!(
        "context-local profile {id} in context {ctx} {}; {unbound} persona(s) unbound",
        if existed { "deleted" } else { "did not exist" },
    );
    audit_persona(
        state,
        "persona.local.profile.delete",
        auth,
        Some(&id),
        Some(&ctx),
        Some(&detail),
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
    if let Err(e) = authorize(
        state,
        auth,
        uris::TASK_PERSONA_LOCAL_BINDING_SET_1_0,
        Some(&ctx),
    )
    .await
    {
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

    // No materialised count here, unlike `binding/set`: a context-local entry
    // IS its own value, so there is no pool projection to count — the store
    // takes the profile's inline entries as the claims directly. Saying so is
    // better than reporting a count that would mean something different from
    // the one on the pool task with the same name.
    let detail = format!(
        "persona {persona} in context {ctx} bound to {}, now at version {version}",
        profile_id.as_deref().map_or_else(
            || "unbound".to_string(),
            |p| format!("context-local profile {p}")
        ),
    );
    audit_persona(
        state,
        "persona.local.binding.set",
        auth,
        Some(&persona),
        Some(&ctx),
        Some(&detail),
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
    if let Err(e) = authorize(
        state,
        auth,
        uris::TASK_PERSONA_DISCLOSURE_PREVIEW_1_0,
        Some(&ctx),
    )
    .await
    {
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
        None,
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
    if let Err(e) = authorize(
        state,
        auth,
        uris::TASK_PERSONA_DISCLOSURE_PRESENT_1_0,
        Some(&ctx),
    )
    .await
    {
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
        None,
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
            let err = decide(&scoped_admin, uri, Some("ctx-work"), false).unwrap_err();
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
                decide(&holder, uri, None, false).unwrap_or_else(|e| {
                    panic!("{uri} refused an unscoped holder: {e:?}");
                });
            }
        }
    }

    /// The capability's whole reason to exist: a context-scoped admin reaches
    /// the pool **only** where holder authority was granted by name.
    ///
    /// Before it there was one way in — an admin with unrestricted scope — so
    /// managing your own identity from a client meant handing that client every
    /// context on the agent.
    #[test]
    fn a_granted_scoped_admin_reaches_the_pool() {
        let scoped_admin = claims(Role::Admin, &["ctx-work"]);
        for (uri, reach) in REACH {
            if *reach != Reach::Holder {
                continue;
            }
            assert!(
                decide(&scoped_admin, uri, Some("ctx-work"), false).is_err(),
                "{uri} admitted a scoped admin who was granted nothing"
            );
            decide(&scoped_admin, uri, Some("ctx-work"), true)
                .unwrap_or_else(|e| panic!("{uri} refused a granted holder: {e:?}"));
        }
    }

    /// The grant is not a role promotion. It opens the holder-scoped tasks and
    /// changes nothing else — a reader granted it is still a reader everywhere
    /// a role is what decides.
    #[test]
    fn the_grant_does_not_widen_a_context_task() {
        let app = claims(Role::Application, &["ctx-a"]);
        assert!(
            decide(
                &app,
                uris::TASK_PERSONA_BINDING_GET_1_0,
                Some("ctx-b"),
                true
            )
            .is_err(),
            "holder authority must not carry a caller into a context it has no claim to"
        );
    }

    /// An unknown task is refused whatever the caller holds. A grant is not a
    /// reason to guess at a reach.
    #[test]
    fn a_granted_holder_is_still_refused_an_unclassified_task() {
        let holder = claims(Role::Admin, &["ctx-work"]);
        // Built rather than written: the produced-URI census sweeps this file's
        // source text, and a literal that looks like a spec URI is reported as
        // a task shipped without a schema. The neighbouring unknown-task test
        // does the same.
        let unknown = format!("https://trusttasks.org/spec/persona/{}/9.9", "not-a-task");
        assert!(decide(&holder, &unknown, None, true).is_err());
    }

    /// No role reaches the pool by being itself — not even one whose empty
    /// context list looks like an unrestricted admin's.
    ///
    /// "Refused" here means *ungranted*. Holder authority is granted by name
    /// and is deliberately not tied to a role: a personal agent running as
    /// `application` can be given it, by a super admin, on purpose. What this
    /// pins is that none of them arrive holding it.
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
            let err = decide(&c, uris::TASK_PERSONA_ATTRIBUTE_LIST_1_0, None, false).unwrap_err();
            assert!(
                matches!(err, AppError::Forbidden(_)),
                "{label} reached the pool"
            );
        }
    }

    #[test]
    fn a_context_task_is_confined_to_its_own_context() {
        let app = claims(Role::Application, &["ctx-a"]);
        decide(
            &app,
            uris::TASK_PERSONA_BINDING_GET_1_0,
            Some("ctx-a"),
            false,
        )
        .expect("own context");
        assert!(
            decide(
                &app,
                uris::TASK_PERSONA_BINDING_GET_1_0,
                Some("ctx-b"),
                false
            )
            .is_err(),
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
        let err = decide(&app, &unknown, Some("ctx"), false).unwrap_err();
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
