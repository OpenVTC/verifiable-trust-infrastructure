use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use tracing::info;

use crate::acl::{
    ActScope, VtcAclEntry, VtcRole, as_vti_role, delete_acl_entry, get_acl_entry,
    is_acl_entry_visible, list_acl_entries, store_acl_entry, validate_acl_modification,
    validate_vtc_role_assignment,
};
use crate::auth::{AdminAuth, AuthClaims, ManageAuth, session::now_epoch};
use crate::error::{AppError, TaskError};
use crate::members::get_member;
use crate::server::AppState;
use vti_common::acl::ContextDirection;
use vti_common::audit::{AclChangeData, AclRevokedData, AdminPromotedData, AuditEvent};
use vti_common::pagination::{Cursor, MAX_LIMIT};

// ---------- GET /acl ----------

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
    /// True when more entries match beyond this page; `cursor` is then
    /// present. Required by canonical `acl/list`.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Canonical `acl/_shared` **AclEntry**.
///
/// Renames from VTC's storage shape: `did` → `subject`,
/// `allowed_contexts` → `scopes`. Timestamps are RFC3339 strings, not
/// unix epochs — canonical types them `format: date-time`, and an
/// integer there would be a silent contract break rather than a
/// cosmetic one.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AclEntryResponse {
    pub subject: String,
    pub role: VtcRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub scopes: Vec<String>,
    pub created_at: String,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// `{ entry: … }` — the shape `acl/{grant,show,change-role}/0.1` publish.
///
/// All three returned the row bare until #1109. The row itself always
/// conformed; only the wrapper was missing, which is the same envelope defect
/// the VTC family carried on eight tasks. It went unseen here for longer
/// because the shared `spec/{acl,audit,auth,config,policy}/*` families are
/// outside the conformance table's census — a stated limit, since both daemons
/// serve them — so no fixture ever described these responses. The
/// response-conformance layer needed no census: it validated what the handler
/// sent.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AclEntryEnvelope {
    pub entry: AclEntryResponse,
}

/// Unix epoch seconds → RFC3339, for canonical `date-time` fields.
fn epoch_to_rfc3339(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .unwrap_or_default()
        .to_rfc3339()
}

impl From<VtcAclEntry> for AclEntryResponse {
    fn from(e: VtcAclEntry) -> Self {
        AclEntryResponse {
            subject: e.did,
            role: e.role,
            label: e.label,
            scopes: e.allowed_contexts,
            created_at: epoch_to_rfc3339(e.created_at),
            created_by: e.created_by,
            updated_at: e.updated_at.map(epoch_to_rfc3339),
            updated_by: e.updated_by,
            expires_at: e.expires_at.map(epoch_to_rfc3339),
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct ListAclQuery {
    /// Return only entries with this role.
    pub role: Option<String>,
    /// Return only entries carrying this scope (canonical name for
    /// what VTC stores as an allowed context).
    pub scope: Option<String>,
    /// Return only entries whose subject starts with this prefix.
    pub subject_prefix: Option<String>,
    /// How `scope` is read over the hierarchy: `acting-in` (the default)
    /// returns entries that may act in it — scoped to it or to an ancestor;
    /// `subtree` returns entries holding a grant at or beneath it; `any` is the
    /// union. Canonical `acl/list/0.1` `direction`.
    #[param(inline)]
    pub direction: Option<ContextDirection>,
    /// Page size. Clamped to `1..=200`. Defaults to 50.
    pub page_size: Option<usize>,
    /// Opaque continuation token from a previous page's `cursor`.
    pub cursor: Option<String>,
}

impl ListAclQuery {
    /// Filters folded into the cursor's HMAC (see
    /// [`vti_common::pagination::Cursor::encode_bound`]) so a page
    /// cannot be resumed under a different filter set — on an ACL that
    /// would silently skip entries an operator believes they reviewed.
    fn cursor_binding(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut field = |v: Option<&str>| {
            let b = v.unwrap_or("").as_bytes();
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(b);
        };
        field(self.role.as_deref());
        field(self.scope.as_deref());
        field(self.subject_prefix.as_deref());
        field(Some(self.direction.unwrap_or_default().as_str()));
        out
    }

    fn matches(&self, e: &VtcAclEntry) -> bool {
        if let Some(role) = &self.role
            && e.role.to_string() != *role
        {
            return false;
        }
        // Hierarchy-aware, as the pre-migration `context` filter was: an
        // entry scoped to an *ancestor* of `scope` does grant `scope`
        // (`docs/05-design-notes/hierarchical-contexts.md`), so it
        // genuinely "carries" it. For flat ids this is exact match.
        //
        // `subtree` reads the other way — a grant at or beneath `scope` — which
        // is the revocation sweep's question: `acting-in` alone would list the
        // ancestors that keep their authority and omit every leaf grant the
        // sweep exists to cut.
        if let Some(scope) = &self.scope {
            use vti_common::context_path::is_ancestor_or_self;
            let direction = self.direction.unwrap_or_default();
            let hit = e.allowed_contexts.iter().any(|allowed| {
                let acting_in = is_ancestor_or_self(allowed, scope);
                let beneath = is_ancestor_or_self(scope, allowed);
                match direction {
                    ContextDirection::ActingIn => acting_in,
                    ContextDirection::Subtree => beneath,
                    ContextDirection::Any => acting_in || beneath,
                }
            });
            if !hit {
                return false;
            }
        }
        if let Some(prefix) = &self.subject_prefix
            && !e.did.starts_with(prefix.as_str())
        {
            return false;
        }
        true
    }
}

/// GET /acl — list ACL entries visible to the caller. Auth: Manage.
#[utoipa::path(
    get, path = "/acl", tag = "acl",
    security(("bearer_jwt" = [])),
    params(ListAclQuery),
    responses(
        (status = 200, description = "Visible ACL entries", body = AclListResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks manage authority"),
    ),
)]
pub async fn list_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Query(query): Query<ListAclQuery>,
) -> Result<Json<AclListResponse>, AppError> {
    list_entries(&state, &auth.0, &query).await.map(Json)
}

/// `acl/list/0.1` for every door: the bearer route above and the signed
/// document the spine dispatches (`trust_tasks::acl_tasks`). `actor` must
/// already hold manage authority.
pub(crate) async fn list_entries(
    state: &AppState,
    actor: &AuthClaims,
    query: &ListAclQuery,
) -> Result<AclListResponse, AppError> {
    let acl = state.acl_ks.clone();
    let limit = query.page_size.unwrap_or(50).clamp(1, MAX_LIMIT);

    // Visibility first (a caller must never learn an entry exists by
    // watching it fall out of a filter), then the caller's filters.
    let mut matching: Vec<VtcAclEntry> = list_acl_entries(&acl)
        .await?
        .into_iter()
        .filter(|e| is_acl_entry_visible(actor, &as_vti_acl_entry(e)))
        .filter(|e| query.matches(e))
        .collect();
    // Stable order so a cursor means the same thing across calls; the
    // subject is unique, so this is a total order.
    matching.sort_by(|a, b| a.did.cmp(&b.did));

    // Cursors are signed with the audit key, but the audit writer is
    // optional — listing the ACL is a core admin function and must not
    // stop working because audit is switched off. Without a key we
    // simply cannot mint or verify a cursor, so the whole visible set
    // is served as one page (which is what this endpoint did before it
    // paginated) and a supplied cursor is rejected rather than trusted
    // unverified.
    let audit_key = match state.audit_writer.as_ref() {
        Some(w) => Some(w.active_key().await?),
        None => None,
    };
    let binding = query.cursor_binding();

    let start = match (&query.cursor, &audit_key) {
        (Some(wire), Some(key)) => {
            let c = Cursor::decode_bound(wire, &key.key, &binding)?;
            matching
                .iter()
                .position(|e| e.did.as_bytes() > c.last_key.as_slice())
                .unwrap_or(matching.len())
        }
        // A cursor we cannot verify is not a cursor.
        (Some(_), None) => return Err(AppError::InvalidCursor),
        (None, _) => 0,
    };

    let take = if audit_key.is_some() {
        limit
    } else {
        matching.len()
    };
    let page: Vec<VtcAclEntry> = matching[start..].iter().take(take).cloned().collect();
    let truncated = start + page.len() < matching.len();
    let cursor = match (&audit_key, truncated) {
        (Some(key), true) => page.last().map(|e| {
            Cursor::new(e.did.as_bytes().to_vec(), matching.len() as u64)
                .encode_bound(&key.key, &binding)
        }),
        _ => None,
    };

    let entries: Vec<AclEntryResponse> = page.into_iter().map(AclEntryResponse::from).collect();
    info!(caller = %actor.did, count = entries.len(), truncated, "ACL listed");
    Ok(AclListResponse {
        entries,
        truncated,
        cursor,
    })
}

// ---------- POST /acl ----------

/// Canonical `acl/grant` request: the entry the maintainer should hold
/// for the subject, plus an optional operator rationale.
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateAclRequest {
    pub entry: GrantEntry,
    /// Operator rationale. Emitted on the service log line for this
    /// change; the audit envelope's data types do not carry a free-text
    /// reason today, so this is deliberately not described as audited.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The writable subset of a canonical `AclEntry`. Server-owned fields
/// (`createdAt`/`createdBy`/`updatedAt`/`updatedBy`) are deliberately
/// absent — a caller must not be able to backdate provenance.
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantEntry {
    pub subject: String,
    pub role: VtcRole,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// RFC3339, per canonical `AclEntry.expiresAt`.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// POST /acl — create a new ACL entry. Auth: Manage.
#[utoipa::path(
    post, path = "/acl", tag = "acl",
    security(("bearer_jwt" = [])),
    request_body = CreateAclRequest,
    responses(
        (status = 201, description = "ACL entry created", body = AclEntryEnvelope),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks manage authority / granting `admin` without a live step-up / granting `admin` to yourself"),
        (status = 409, description = "Entry exists at a different role — use acl/change-role"),
    ),
)]
pub async fn create_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateAclRequest>,
) -> Result<(StatusCode, Json<AclEntryEnvelope>), AppError> {
    // What the consent, if one is needed, is bound to: the grant exactly as
    // asked, so an approval for one grant cannot be spent on another.
    let op_payload = serde_json::to_value(&req)
        .map_err(|e| AppError::Internal(format!("serialise acl/grant body: {e}")))?;
    let plan = plan_grant(&state, &auth.0, req).await?;

    // Conferring `admin` demands a live step-up here too (VTI-OPS-051).
    //
    // `acl/change-role` gets this from the role-change ceremony's host
    // invariant, which is where a transition belongs. A grant is not a
    // transition — it writes an entry where there was none, or rewrites one at
    // the role it already holds — so there is no ceremony to hang an invariant
    // on and the predicate is checked here, one layer further out. It is the
    // same predicate: `elevation::verified` is the single definition of "this
    // caller is elevated right now", so the two gates cannot drift.
    //
    // A rewrite is gated too when it *widens* — a context admin becoming
    // community-wide is an elevation that never changes the role name — but
    // not when it does not, because that is how the console edits an admin's
    // label. `elevation::widens_admin_authority` draws that line;
    // `validate_acl_modification` bounds *which* scopes a caller may confer and
    // has nothing to say about how recently they authenticated.
    //
    // Checked *after* `plan_grant`'s wrong-role conflict on purpose: a caller
    // who meant `acl/change-role` should be told so, not sent off to run a
    // passkey ceremony that would only earn them the same 409. Nothing is
    // written either way.
    //
    // The signed door asks the same question of an operation-bound mark
    // instead of the session — `trust_tasks::handle_acl_grant`.
    if plan.confers_admin && !crate::acl::elevation::verified(&auth.0, &state.sessions_ks).await {
        return Err(crate::acl::elevation::required(&format!(
            "granting the admin role to {}",
            plan.entry.did
        )));
    }

    // Unrestricted authority also needs another admin's agreement
    // (VTI-APV-014) — after the requester's own step-up, so an unelevated
    // session cannot make the other admins' devices ring.
    if plan.confers_unrestricted {
        let consent = crate::acl::admin_consent::require(
            &state,
            &auth.0.did,
            &plan.entry.did,
            crate::acl::admin_consent::Operation {
                type_uri: crate::trust_tasks::ACL_GRANT_TYPE,
                payload: &op_payload,
            },
            &unrestricted_grant_summary(&plan.entry.did),
        )
        .await?;
        consent.spend(&state).await?;
    }

    let (status, envelope) = commit_grant(&state, &auth.0, plan).await?;
    Ok((status, Json(envelope)))
}

/// What an approver is shown for a grant of unrestricted admin.
pub(crate) fn unrestricted_grant_summary(subject: &str) -> String {
    format!("Make {subject} an unrestricted administrator of this community")
}

/// An `acl/grant` that has passed every check deciding whether it may happen,
/// and has not yet been written.
///
/// The split exists for the step-up. Both doors run [`plan_grant`], settle the
/// step-up their own way — the bearer route from the session's live
/// elevation, the signed door from an operation-bound mark — then
/// [`commit_grant`]. Where the gesture is read from is all that differs;
/// everything that decides the operation is one function.
#[derive(Debug)]
pub(crate) struct GrantPlan {
    pub(crate) entry: VtcAclEntry,
    status: StatusCode,
    /// Whether this write gives away admin authority the subject did not
    /// already hold — what needs the gesture. See
    /// [`crate::acl::elevation::widens_admin_authority`].
    pub(crate) confers_admin: bool,
    /// Whether it makes the subject an **unrestricted** admin who was not one —
    /// which also needs another admin's consent (VTI-APV-014). Implies
    /// `confers_admin`. See [`crate::acl::admin_consent::confers_unrestricted`].
    pub(crate) confers_unrestricted: bool,
    /// Whether it rewrites a live unrestricted admin into something less — a
    /// scoped admin — which [`commit_grant`] checks for attrition before
    /// writing ([`crate::acl::admin_consent::check_attrition`]).
    ends_unrestricted: bool,
    /// Whether the rewrite takes authority away from a live entry — a scope
    /// dropped, or an expiry brought forward — so the subject's live sessions,
    /// which still carry the old authority, are revoked with the write.
    reduces: bool,
    /// Which task this write is, for the audit row.
    event: PlanEvent,
    reason: Option<String>,
}

/// The task a [`GrantPlan`] was made for. Both write the same row through the
/// same checks; the audit trail says which one was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlanEvent {
    /// `acl/grant/0.1` — mint or restate an entry.
    Granted,
    /// `acl/update/0.1` — amend an existing entry's non-role attributes.
    Updated,
}

/// Every check `acl/grant` makes before it would write, and the entry it would
/// write. Writes nothing.
pub(crate) async fn plan_grant(
    state: &AppState,
    actor: &AuthClaims,
    req: CreateAclRequest,
) -> Result<GrantPlan, AppError> {
    let req_entry = req.entry;
    // Block non-admin callers from granting Admin — role + context
    // bound checks must run before we touch storage.
    validate_vtc_role_assignment(actor, &req_entry.role)?;
    validate_acl_modification(actor, &as_vti_role(&req_entry.role), &req_entry.scopes)?;

    let granting_admin = matches!(req_entry.role, VtcRole::Admin);
    let expires_at = req_entry.expires_at.map(|t| t.timestamp() as u64);

    // Canonical `acl/grant` is "the entry the maintainer should hold":
    // re-granting the *same* role rewrites the entry's scopes/label,
    // but a role change is `acl/change-role`'s job and is refused here
    // — that task carries the `fromRole` compare-and-swap this one has
    // no way to express.
    let existing = get_acl_entry(&state.acl_ks, &req_entry.subject).await?;
    // Decided before the match consumes `existing`: does this write give away
    // more than the subject already holds? Wider scopes, or a longer life — a
    // time-boxed admin restated with no expiry, or a later one, holds authority
    // it was never granted, and that is the same conferral as a new context
    // (canonical `acl/update`: clearing `expiresAt` is a privilege increase to
    // be gated at least as strictly as the original grant).
    let extends_life = existing
        .as_ref()
        .is_some_and(|p| match (p.expires_at, expires_at) {
            (Some(_), None) => true,
            (Some(was), Some(now)) => now > was,
            (None, _) => false,
        });
    let confers_admin = granting_admin
        && (crate::acl::elevation::widens_admin_authority(existing.as_ref(), &req_entry.scopes)
            || extends_life);
    // …and does it take any away? Then the subject's live sessions, minted
    // under the old entry, must not outlive it.
    let reduces = existing.as_ref().is_some_and(|p| {
        let shortened = match (p.expires_at, expires_at) {
            (None, Some(_)) => true,
            (Some(was), Some(now)) => now < was,
            (_, None) => false,
        };
        shortened
            || is_privilege_reduction(
                &p.role,
                &p.allowed_contexts,
                &req_entry.role,
                &req_entry.scopes,
            )
    });
    let confers_unrestricted = crate::acl::admin_consent::confers_unrestricted(
        existing.as_ref(),
        &req_entry.role,
        &req_entry.scopes,
        now_epoch(),
    );
    // A rewrite keeps the role (a different one is refused below), so what can
    // end an unrestricted admin here is narrowing its scopes.
    let ends_unrestricted = existing
        .as_ref()
        .is_some_and(|p| crate::acl::admin_consent::is_live_unrestricted(p, now_epoch()))
        && !vti_common::acl::act_scope_for(&as_vti_role(&req_entry.role), &req_entry.scopes)
            .is_unrestricted();
    let (created_at, created_by, status) = match existing {
        Some(prev) => {
            // VTI-ACL-052. A rewrite of your own entry is a modification of it,
            // whatever it changes: re-stating it with no expiry makes a
            // time-boxed grant permanent, and re-scoping it moves your own
            // authority. Another administrator makes those changes.
            if req_entry.subject == actor.did {
                return Err(AppError::Forbidden(
                    "you cannot rewrite your own ACL entry (VTI-ACL-052) — another administrator whose scope covers it must make this change"
                        .into(),
                ));
            }
            if !is_acl_entry_visible(actor, &as_vti_acl_entry(&prev)) {
                return Err(AppError::NotFound(format!(
                    "ACL entry not found for DID: {}",
                    req_entry.subject
                )));
            }
            // Visible is overlap; rewriting needs all of it. The rewrite
            // replaces the scope list, so an administrator of `a` rewriting an
            // entry that acts in `[a, b]` would otherwise evict the subject
            // from `b`, which it does not administer.
            if !caller_covers_target(actor, &prev) {
                return Err(not_covered(&req_entry.subject, "rewrite"));
            }
            if prev.role != req_entry.role {
                return Err(AppError::Conflict(format!(
                    "ACL entry for {} already holds role {}; use acl/change-role \
                     (PATCH /v1/acl/{}) to move it to {}",
                    req_entry.subject, prev.role, req_entry.subject, req_entry.role
                )));
            }
            (prev.created_at, prev.created_by, StatusCode::OK)
        }
        None => {
            // Minting yourself an admin entry is self-promotion by another
            // name, and the role-change path refuses it (VTI-OPS-050). A
            // *rewrite* of an entry that already says admin is not covered:
            // that is how a super-admin corrects their own label, and it
            // confers nothing they do not already hold.
            if granting_admin && req_entry.subject == actor.did {
                return Err(AppError::Forbidden(
                    "you cannot grant yourself the admin role; admin elevation requires a \
                     separate admin caller"
                        .into(),
                ));
            }
            (now_epoch(), actor.did.clone(), StatusCode::CREATED)
        }
    };

    // Nothing this caller writes may outlive the caller's own authority
    // (VTI-ACL-053): an administrator whose entry expires cannot grant a
    // permanent entry, or one expiring later, to a DID it also controls.
    let own = caller_entry(state, actor).await?;
    if let Some(mine) = own.expires_at {
        match expires_at {
            None => {
                return Err(AppError::Forbidden(format!(
                    "your entry expires at {mine}, so you cannot write a permanent one — give it an expiry no later than yours (VTI-ACL-053)"
                )));
            }
            Some(theirs) if theirs > mine => {
                return Err(AppError::Forbidden(format!(
                    "this entry would expire at {theirs}, after your own ({mine}) — an entry you write cannot outlive your authority (VTI-ACL-053)"
                )));
            }
            Some(_) => {}
        }
    }

    Ok(GrantPlan {
        entry: VtcAclEntry {
            did: req_entry.subject,
            role: req_entry.role,
            label: req_entry.label,
            allowed_contexts: req_entry.scopes,
            created_at,
            created_by,
            updated_at: (status == StatusCode::OK).then(now_epoch),
            updated_by: (status == StatusCode::OK).then(|| actor.did.clone()),
            expires_at,
        },
        status,
        confers_admin,
        confers_unrestricted,
        ends_unrestricted,
        reduces,
        event: PlanEvent::Granted,
        reason: req.reason,
    })
}

/// Write a planned grant and audit it. Settling the step-up, where the plan
/// needs one, is the caller's job and must happen first.
pub(crate) async fn commit_grant(
    state: &AppState,
    actor: &AuthClaims,
    plan: GrantPlan,
) -> Result<(StatusCode, AclEntryEnvelope), AppError> {
    let GrantPlan {
        entry,
        status,
        reason,
        ends_unrestricted,
        reduces,
        event,
        ..
    } = plan;
    // Narrowing an unrestricted admin is attrition like any removal, checked
    // and written under the same admin-set lock (VTI-APV-009).
    let _admin_set = if ends_unrestricted {
        let guard = crate::ceremony::lock_admin_set().await;
        crate::acl::admin_consent::check_attrition(state, &entry.did).await?;
        Some(guard)
    } else {
        None
    };
    store_acl_entry(&state.acl_ks, &entry).await?;

    // A reduced entry must bind now, not when the subject's access token
    // expires: the `AuthClaims` extractor reads role and contexts from the JWT.
    if reduces {
        let revoked = super::auth::revoke_sessions_for_did(&state.sessions_ks, &entry.did).await?;
        info!(did = %entry.did, revoked, "subject sessions revoked after ACL privilege reduction");
    }

    if let Some(writer) = state.audit_writer.as_ref() {
        let data = AclChangeData {
            did: entry.did.clone(),
            role: entry.role.to_string(),
            contexts: entry.allowed_contexts.clone(),
            expires_at: entry.expires_at.map(|e| e.to_string()),
        };
        // The actor is whoever made *this* write. `entry.created_by` is the
        // entry's original author, which for a rewrite is somebody else — and
        // attributing the change to them is an audit trail that lies.
        writer
            .write(
                &actor.did,
                Some(&entry.did),
                match event {
                    PlanEvent::Granted => AuditEvent::AclGranted(data),
                    PlanEvent::Updated => AuditEvent::AclUpdated(data),
                },
            )
            .await?;
    }

    info!(
        caller = %actor.did,
        did = %entry.did,
        role = %entry.role,
        reason = reason.as_deref().unwrap_or(""),
        created = status == StatusCode::CREATED,
        task = ?event,
        "ACL entry written",
    );
    Ok((
        status,
        AclEntryEnvelope {
            entry: AclEntryResponse::from(entry),
        },
    ))
}

// ---------- acl/update (signed document only) ----------

/// Canonical `acl/update/0.1`: amend an existing entry's non-role attributes.
///
/// Only the members a VTC entry has. `allowedKeys`, `approve` and `stepUp` are
/// VTA entry members with no VTC counterpart, and a role is `acl/change-role`'s
/// — the handler refuses each by name before this parses, so a caller learns
/// what it asked for rather than reading "unknown field". `ext` is accepted and
/// ignored (SPEC §4.5.1).
///
/// `label` and `expiresAt` distinguish **absent** (unchanged) from **`null`**
/// (cleared), which is why they are double options.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdateEntryRequest {
    pub subject: String,
    #[serde(default, deserialize_with = "double_option")]
    pub label: Option<Option<String>>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub expires_at: Option<Option<DateTime<Utc>>>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub ext: Option<serde_json::Value>,
}

/// Absent → `None`, `null` → `Some(None)`, a value → `Some(Some(v))`.
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

/// Every check `acl/update` makes, and the entry it would write. Writes
/// nothing.
///
/// An update is a grant that restates the subject's entry at its **current
/// role** with some members replaced, so it is planned by [`plan_grant`] — the
/// self-modification refusal (VTI-ACL-052), full cover of the entry
/// (VTI-ACL-050), the bound on what the caller may confer and for how long
/// (VTI-ACL-053), and the step-up and consent flags are the same code for both
/// tasks, not two copies that could drift. What this adds is what an amendment
/// alone must refuse: an entry that does not exist (`acl/update:notFound` —
/// this task never creates one), and a scope set that narrows
/// (`acl/update:narrowingNotPermitted` — removing authority is `acl/revoke`'s,
/// which is audited as a revocation).
pub(crate) async fn plan_update(
    state: &AppState,
    actor: &AuthClaims,
    req: UpdateEntryRequest,
) -> Result<GrantPlan, TaskError> {
    use trust_tasks_rs::specs::acl::update::v0_1::error_codes;

    let subject = req.subject;
    let not_found = |subject: &str| {
        TaskError::declared(
            error_codes::NOT_FOUND.code,
            AppError::NotFound(format!(
                "ACL entry not found for DID: {subject} — acl/update amends an existing \
                 entry; use acl/grant to create one"
            )),
        )
    };
    // Invisible reads as absent, as it does for show and revoke.
    let Some(existing) = get_acl_entry(&state.acl_ks, &subject).await? else {
        return Err(not_found(&subject));
    };
    if !is_acl_entry_visible(actor, &as_vti_acl_entry(&existing)) {
        return Err(not_found(&subject));
    }
    // Before the narrowing check, so the answer to "may I touch this entry at
    // all" is never "you asked for the wrong shape of change".
    if subject == actor.did {
        return Err(AppError::Forbidden(
            "you cannot update your own ACL entry (VTI-ACL-052) — another administrator whose \
             scope covers it must make this change"
                .into(),
        )
        .into());
    }
    if !caller_covers_target(actor, &existing) {
        return Err(not_covered(&subject, "update").into());
    }

    let scopes = req
        .scopes
        .unwrap_or_else(|| existing.allowed_contexts.clone());
    if narrows(&existing, &scopes) {
        return Err(TaskError::declared(
            error_codes::NARROWING_NOT_PERMITTED.code,
            AppError::Validation(format!(
                "these scopes remove authority {subject} holds now — removing authority is a \
                 revocation: use acl/revoke with the scopes to drop"
            )),
        ));
    }
    let label = req.label.unwrap_or(existing.label.clone());
    let expires_at = match req.expires_at {
        None => existing
            .expires_at
            .and_then(|t| DateTime::<Utc>::from_timestamp(t as i64, 0)),
        Some(v) => v,
    };

    let mut plan = plan_grant(
        state,
        actor,
        CreateAclRequest {
            entry: GrantEntry {
                subject,
                role: existing.role,
                label,
                scopes,
                expires_at,
            },
            reason: req.reason,
        },
    )
    .await?;
    // The entry went between the read above and `plan_grant`'s own: planned as
    // a creation, which this task never is.
    if plan.status == StatusCode::CREATED {
        return Err(not_found(&plan.entry.did));
    }
    plan.event = PlanEvent::Updated;
    Ok(plan)
}

/// Would `new_scopes`, at `prev`'s role, take away authority `prev` holds?
///
/// Decoded through [`ActScope`], because an empty scope list means
/// *unrestricted* for an admin and *nowhere* for everyone else, and reading
/// the list alone gets one of the two backwards. A new scope that is an
/// ancestor of a held one keeps it (hierarchical containment).
fn narrows(prev: &VtcAclEntry, new_scopes: &[String]) -> bool {
    let next = vti_common::acl::act_scope_for(&as_vti_role(&prev.role), new_scopes);
    match (prev.act_scope(), next) {
        (ActScope::None, _) | (ActScope::All, ActScope::All) => false,
        (ActScope::All, _) => true,
        (ActScope::Contexts(_), ActScope::All) => false,
        (ActScope::Contexts(_), ActScope::None) => true,
        (ActScope::Contexts(held), ActScope::Contexts(next)) => held.iter().any(|have| {
            !next
                .iter()
                .any(|want| vti_common::context_path::is_ancestor_or_self(want, have))
        }),
    }
}

// ---------- GET /acl/{did} ----------

/// GET /acl/{did} — retrieve a single ACL entry. Auth: Manage.
#[utoipa::path(
    get, path = "/acl/{did}", tag = "acl",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Subject DID")),
    responses(
        (status = 200, description = "ACL entry", body = AclEntryEnvelope),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks manage authority"),
        (status = 404, description = "ACL entry not found"),
    ),
)]
pub async fn get_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<AclEntryEnvelope>, AppError> {
    show_entry(&state, &auth.0, &did).await.map(Json)
}

/// `acl/show/0.1` for every door. `actor` must already hold manage authority.
///
/// An entry the caller cannot see is answered exactly as one that does not
/// exist, so the refusal is no oracle for which DIDs hold entries elsewhere.
pub(crate) async fn show_entry(
    state: &AppState,
    actor: &AuthClaims,
    did: &str,
) -> Result<AclEntryEnvelope, AppError> {
    let not_found = || AppError::NotFound(format!("ACL entry not found for DID: {did}"));
    let entry = get_acl_entry(&state.acl_ks, did)
        .await?
        .ok_or_else(not_found)?;
    if !is_acl_entry_visible(actor, &as_vti_acl_entry(&entry)) {
        return Err(not_found());
    }
    info!(caller = %actor.did, did = %did, "ACL entry retrieved");
    Ok(AclEntryEnvelope {
        entry: AclEntryResponse::from(entry),
    })
}

// ---------- PATCH /acl/{did} ----------

/// Canonical `acl/change-role` request.
///
/// Role-only, and `fromRole` is a **compare-and-swap guard**, not
/// decoration: the maintainer must confirm the subject's current role
/// equals it and refuse otherwise. That closes the read-modify-write
/// race the previous partial update had — two admins demoting the same
/// subject concurrently could each read `admin` and write a different
/// result, last-writer-wins, with no signal.
///
/// Label and scope edits are **not** here: they go to `acl/grant` with
/// the subject's existing role, which is what canonical means by "the
/// entry the maintainer should hold".
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateAclRequest {
    pub from_role: VtcRole,
    pub to_role: VtcRole,
    /// Operator rationale. Emitted on the service log line for this
    /// change; the audit envelope's data types do not carry a free-text
    /// reason today, so this is deliberately not described as audited.
    #[serde(default)]
    pub reason: Option<String>,
}

/// PATCH /acl/{did} — modify an ACL entry. Auth: Admin.
#[utoipa::path(
    patch, path = "/acl/{did}", tag = "acl",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Subject DID")),
    request_body = UpdateAclRequest,
    responses(
        (status = 200, description = "Updated ACL entry", body = AclEntryEnvelope),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin / promoting to `admin` without a live step-up / self-promotion / denied by the role-change policy"),
        (status = 404, description = "ACL entry not found"),
        (status = 409, description = "`fromRole` does not match the stored role, or the row moved under the promote lock"),
    ),
)]
pub async fn update_acl(
    // Modifying an ACL entry can downgrade an existing admin or shrink their
    // `allowed_contexts`. Gate on Admin so a non-admin can't tamper with
    // admin entries they happen to see (creation stays on `ManageAuth`).
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<UpdateAclRequest>,
) -> Result<Json<AclEntryEnvelope>, AppError> {
    match change_role_inner(
        &state,
        &auth.0,
        &did,
        req,
        // `change_role_inner` fills in the operation the consent binds to.
        crate::ceremony::StepUpSource::Session { op: None },
    )
    .await?
    {
        ChangeRoleOutcome::Changed(envelope) => Ok(Json(*envelope)),
        // Only a bound source parks a ceremony; a session that is not elevated
        // is refused `step_up_required` inside the pipeline.
        ChangeRoleOutcome::StepUpRequired(_) => Err(AppError::Internal(
            "a session-gated role change produced a bound step-up request".into(),
        )),
    }
}

/// What [`change_role_inner`] produced.
#[derive(Debug)]
pub(crate) enum ChangeRoleOutcome {
    Changed(Box<AclEntryEnvelope>),
    /// A promotion that needs a gesture bound to it, and has none yet. Nothing
    /// was written.
    StepUpRequired(Box<trust_tasks_rs::specs::auth::step_up::approve_request::v0_3::Payload>),
}

/// `acl/change-role` for either door. The bearer route passes
/// [`StepUpSource::Session`](crate::ceremony::StepUpSource::Session); the
/// signed-document door passes the document's type and payload, so a
/// promotion's gesture is bound to that one operation.
///
/// `actor` must already hold the admin role — the bearer route's `AdminAuth`,
/// the signed door's explicit check.
pub(crate) async fn change_role_inner(
    state: &AppState,
    actor: &AuthClaims,
    did: &str,
    req: UpdateAclRequest,
    source: crate::ceremony::StepUpSource<'_>,
) -> Result<ChangeRoleOutcome, AppError> {
    let did = did.to_string();
    // VTI-ACL-052: in either direction. The ceremony refuses self-*promotion*;
    // a subject moving its own role at all is a modification of its own entry.
    if actor.did == did {
        return Err(AppError::Forbidden(
            "you cannot change your own role (VTI-ACL-052) — another administrator whose scope covers your entry must make this change"
                .into(),
        ));
    }
    // The bearer route's operation, as the canonical `acl/change-role` payload
    // it describes — the body plus the subject its path names — so a consent
    // for promoting one subject cannot be spent promoting another. The signed
    // door binds to its own document's payload instead.
    let op_payload = {
        let mut v = serde_json::to_value(&req)
            .map_err(|e| AppError::Internal(format!("serialise acl/change-role body: {e}")))?;
        if let Some(map) = v.as_object_mut() {
            map.insert("subject".into(), serde_json::Value::String(did.clone()));
        }
        v
    };
    let acl = state.acl_ks.clone();
    let entry = get_acl_entry(&acl, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;

    // Context admins can only modify entries they can see
    if !is_acl_entry_visible(actor, &as_vti_acl_entry(&entry)) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }

    // Visibility (overlapping contexts) is enough to *see* an entry but not to
    // change it: a context-admin of `ctx-a` must not be able to move the role
    // of a subject scoped to `[ctx-a, ctx-b]`, and can never touch a
    // super-admin. Only a super-admin, or an admin covering *every* context
    // the target holds, may modify it. This used to apply to admin targets
    // only, which left every other role's entry in `ctx-b` movable by `ctx-a`.
    if !caller_covers_target(actor, &entry) {
        return Err(not_covered(&did, "change the role of"));
    }

    // Snapshot the pre-change authorization so we can detect a privilege
    // reduction after the patch is applied.
    let prev_role = entry.role.clone();
    let prev_contexts = entry.allowed_contexts.clone();

    // Compare-and-swap: the subject's current role MUST equal
    // `fromRole`, else the caller is acting on a stale read.
    if entry.role != req.from_role {
        return Err(AppError::Conflict(format!(
            "state mismatch: {did} currently holds role {}, not {}",
            entry.role, req.from_role
        )));
    }

    validate_vtc_role_assignment(actor, &req.to_role)?;
    // …and the *resulting* entry must be one this caller could have granted.
    //
    // `create_acl` has always run this; this route never did, and the gap is
    // the `allowed_contexts.is_empty()` trap in its usual form: an entry's
    // scopes mean "unrestricted" under `admin` and "nowhere" under every other
    // role. So a context admin could take a scopeless *member* — an entry that
    // can act nowhere — to `admin`, and land a **community-wide super-admin**
    // without ever naming a context they do not hold. `ActScope` is what tells
    // the two apart, and `validate_acl_modification` decodes through it.
    validate_acl_modification(actor, &as_vti_role(&req.to_role), &entry.allowed_contexts)?;

    // The role change itself is the **role-change ceremony**, not a field
    // write (#1645). This route used to set `entry.role` and store it, which
    // skipped everything the ceremony does: the operator's `role_change.rego`,
    // the no-last-admin guard on demotion, the role-VEC re-mint, the
    // serialisation of concurrent promotions — and the host invariants that
    // refuse self-promotion and admin-without-a-step-up. Two doors onto one
    // ACL row disagreed about what a role change costs, and this was the
    // cheaper one.
    let promoting = matches!(req.to_role, VtcRole::Admin);
    let granted = match source {
        crate::ceremony::StepUpSource::Session { .. } => {
            crate::ceremony::role_change_via_pipeline(
                state,
                actor,
                &did,
                &prev_role.to_string(),
                &req.to_role.to_string(),
                Some(crate::acl::admin_consent::Operation {
                    type_uri: crate::trust_tasks::ACL_CHANGE_ROLE_TYPE,
                    payload: &op_payload,
                }),
            )
            .await?
        }
        crate::ceremony::StepUpSource::BoundTo { type_uri, payload } => {
            match crate::ceremony::role_change_via_bound_step_up(
                state,
                actor,
                &did,
                &prev_role.to_string(),
                &req.to_role.to_string(),
                type_uri,
                payload,
            )
            .await?
            {
                crate::ceremony::RoleChangeOutcome::Changed(result) => result,
                crate::ceremony::RoleChangeOutcome::StepUpRequired(request) => {
                    return Ok(ChangeRoleOutcome::StepUpRequired(request));
                }
            }
        }
    };

    // The ceremony's executor owns the role write, so re-read it rather than
    // storing a copy shaped before the ceremony ran, and stamp the provenance
    // canonical `AclEntry` carries.
    let mut entry = get_acl_entry(&acl, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    entry.updated_at = Some(now_epoch());
    entry.updated_by = Some(actor.did.clone());
    store_acl_entry(&acl, &entry).await?;

    if promoting {
        // The admin sister record lets the new admin enrol a device through
        // the existing passkey flow. Empty credential list until
        // `admin/passkeys/register` runs. Carried over from the members/update
        // promotion path — without it a promotion produces an admin who cannot
        // sign in to the console.
        use crate::acl::admin::{AdminEntry, get_admin_entry, store_admin_entry};
        if get_admin_entry(&state.passkey_ks, &did).await?.is_none() {
            store_admin_entry(
                &state.passkey_ks,
                &AdminEntry {
                    did: did.clone(),
                    passkeys: Vec::new(),
                    extensions: serde_json::Value::Null,
                    created_at: Utc::now(),
                },
            )
            .await?;
        }
    }

    // The `AuthClaims` extractor reads role/contexts straight from the
    // still-valid JWT (only `/auth/refresh` re-checks the ACL), so a demoted
    // admin would otherwise keep admin authority for the full access-token TTL.
    // Revoke the subject's live sessions on any privilege reduction so the
    // stale bearer is rejected on its next request.
    if is_privilege_reduction(
        &prev_role,
        &prev_contexts,
        &entry.role,
        &entry.allowed_contexts,
    ) {
        let sessions = state.sessions_ks.clone();
        let revoked = super::auth::revoke_sessions_for_did(&sessions, &did).await?;
        info!(did = %did, revoked, "subject sessions revoked after ACL privilege reduction");
    }

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &actor.did,
                Some(&did),
                AuditEvent::AclUpdated(AclChangeData {
                    did: did.clone(),
                    role: entry.role.to_string(),
                    contexts: entry.allowed_contexts.clone(),
                    expires_at: entry.expires_at.map(|e| e.to_string()),
                }),
            )
            .await?;
        if promoting {
            // Its own variant beside the ACL row's: admin elevation is the
            // highest-privilege grant the community emits and SIEM rules
            // target it directly. `authorising_session_id` is the join key to
            // the `AuthSteppedUp` row recording which credential asserted user
            // verification — the elevation this promotion could not have
            // happened without.
            writer
                .write(
                    &actor.did,
                    Some(&did),
                    AuditEvent::AdminPromoted(AdminPromotedData {
                        previous_role: granted.previous_role.clone(),
                        authorising_credential_id: String::new(),
                        // Empty on the signed door, which has no session: the
                        // gesture there is the `OperationStepUpRecorded` row
                        // under the same actor, written moments before.
                        authorising_session_id: actor.session_id.clone(),
                    }),
                )
                .await?;
        }
    }

    info!(
        did = %did,
        from = %granted.previous_role,
        to = %granted.new_role,
        reason = req.reason.as_deref().unwrap_or(""),
        "ACL role changed",
    );
    Ok(ChangeRoleOutcome::Changed(Box::new(AclEntryEnvelope {
        entry: AclEntryResponse::from(entry),
    })))
}

// ---------- DELETE /acl/{did} ----------

/// Canonical `acl/revoke` parameters. `scopes` is a comma-separated
/// list; when present the entry is scope-reduced rather than removed.
#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct RevokeAclQuery {
    pub scopes: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

impl RevokeAclQuery {
    /// `None` when `scopes` is absent — a full removal. Present, it must name
    /// at least one scope: canonical `acl/revoke` declares `minItems: 1`, and
    /// reading `?scopes=` as "remove the whole entry" would turn an empty list
    /// from a client bug into the most destructive thing this route does.
    fn scopes_list(&self) -> Result<Option<Vec<String>>, AppError> {
        let Some(raw) = self.scopes.as_deref() else {
            return Ok(None);
        };
        let list: Vec<String> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if list.is_empty() {
            return Err(AppError::Validation(
                "`scopes` names no scope — omit it to remove the entry, or name the scopes to \
                 drop"
                    .into(),
            ));
        }
        Ok(Some(list))
    }
}

/// The generated `acl/revoke/0.1` response for the entry the maintainer now
/// holds — `None` after a full removal, the reduced entry after a scope
/// reduction. Built through the wire form, which is the representation the
/// VTC's entry and the published one agree on (the spine's conformance tests
/// hold them to it).
fn revoke_response(
    entry: Option<AclEntryResponse>,
) -> Result<vta_sdk::openapi::AclRevoke01Response, TaskError> {
    serde_json::to_value(&entry)
        .and_then(|entry| serde_json::from_value(serde_json::json!({ "entry": entry })))
        .map(vta_sdk::openapi::AclRevoke01Response)
        .map_err(|e| AppError::Internal(format!("acl/revoke response: {e}")).into())
}

/// DELETE /acl/{did} — revoke: remove the entry, or reduce its scopes
/// when `scopes` is supplied. Auth: Admin.
#[utoipa::path(
    delete, path = "/acl/{did}", tag = "acl",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Subject DID"), RevokeAclQuery),
    responses(
        (status = 200, description = "Entry revoked: `entry` is null after a removal, the reduced entry after a scope reduction", body = vta_sdk::openapi::AclRevoke01Response),
        (status = 400, description = "`scopes` present but empty"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin, or does not administer every context the entry acts in"),
        (status = 404, description = "ACL entry not found (`acl/revoke:subjectNotPresent`), or none of the named scopes are held"),
        (status = 409, description = "Own entry; a member's entry (use the leave ceremony); a reduction that would unscope the entry; or the last unrestricted admin (`acl/revoke:lastAuthorityProtected`)"),
    ),
)]
pub async fn delete_acl(
    // Deletion is strictly more destructive than the `PATCH` edit, yet the
    // previous `ManageAuth` gate let an Initiator delete entries while `PATCH`
    // required Admin. Gate both on Admin so an Initiator can't delete admin
    // entries it happens to see.
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Query(query): Query<RevokeAclQuery>,
) -> Result<Json<vta_sdk::openapi::AclRevoke01Response>, TaskError> {
    let scopes = query.scopes_list()?;
    revoke_entry(
        &state,
        &auth.0,
        &did,
        scopes.as_deref(),
        query.reason.as_deref(),
    )
    .await
    .map(Json)
}

/// `acl/revoke/0.1` for every door: the bearer route above and the signed
/// document (`trust_tasks::acl_tasks`). `actor` must already hold the admin
/// role.
///
/// `scopes: None` removes the entry; `Some` removes those scopes and keeps the
/// rest. Both require the caller to administer **every** context the entry
/// acts in (VTI-ACL-050), and neither may be aimed at the caller's own entry.
pub(crate) async fn revoke_entry(
    state: &AppState,
    actor: &AuthClaims,
    did: &str,
    scopes: Option<&[String]>,
    reason: Option<&str>,
) -> Result<vta_sdk::openapi::AclRevoke01Response, TaskError> {
    use trust_tasks_rs::specs::acl::revoke::v0_1::error_codes;
    let did = did.to_string();

    // Prevent self-deletion
    if actor.did == did {
        return Err(AppError::Conflict("cannot delete your own ACL entry".into()).into());
    }

    let acl = state.acl_ks.clone();

    // Verify entry exists and is visible to the caller. An invisible entry is
    // answered as an absent one, so the refusal is no oracle.
    let not_present = || {
        TaskError::declared(
            error_codes::SUBJECT_NOT_PRESENT.code,
            AppError::NotFound(format!("ACL entry not found for DID: {did}")),
        )
    };
    let Some(entry) = get_acl_entry(&acl, &did).await? else {
        return Err(not_present());
    };
    if !is_acl_entry_visible(actor, &as_vti_acl_entry(&entry)) {
        return Err(not_present());
    }

    // Same guard as `acl/change-role`, for every role: overlapping contexts
    // make an entry *visible* but not *revocable* by a context-admin scoped
    // outside its full context set, and a super-admin can only be revoked by
    // another super-admin. A scope reduction is covered too — without this an
    // administrator of `a` could strip `b` from an entry acting in `[a, b]`.
    if !caller_covers_target(actor, &entry) {
        return Err(not_covered(&did, "revoke").into());
    }

    // Canonical `acl/revoke` has two modes. With `scopes`, this is a
    // *scope reduction*: the entry survives, minus those scopes. Only
    // an omitted `scopes` removes the entry outright. Treating a scope
    // reduction as a full removal would strip far more authority than
    // the operator asked for, so the two paths are kept distinct.
    if let Some(reduce) = scopes {
        if reduce.is_empty() {
            return Err(AppError::Validation(
                "`scopes` names no scope — omit it to remove the entry".into(),
            )
            .into());
        }
        let mut entry = entry;
        let before = entry.allowed_contexts.len();
        entry.allowed_contexts.retain(|s| !reduce.contains(s));
        if entry.allowed_contexts.len() == before {
            return Err(AppError::NotFound(format!(
                "none of the requested scopes are held by {did}"
            ))
            .into());
        }
        // Emptying an entry's scopes leaves it in one of two states, and
        // neither is what "revoke these scopes" asked for: an *admin* is
        // silently promoted to community-wide authority (an empty scope set is
        // how a super-admin is spelled), and any other role is left inert.
        // Decode through `ActScope` so the message can say which happened
        // instead of describing every entry as community-wide.
        match entry.act_scope() {
            ActScope::All => {
                return Err(AppError::Conflict(format!(
                    "revoking every scope of {did} would leave an unscoped \
                     (community-wide) entry; omit `scopes` to remove it instead"
                ))
                .into());
            }
            ActScope::None => {
                return Err(AppError::Conflict(format!(
                    "revoking every scope of {did} would leave an entry that \
                     can act nowhere; omit `scopes` to remove it instead"
                ))
                .into());
            }
            ActScope::Contexts(_) => {}
        }
        entry.updated_at = Some(now_epoch());
        entry.updated_by = Some(actor.did.clone());
        store_acl_entry(&acl, &entry).await?;

        // A shrunk scope set is a privilege reduction; the subject's
        // live tokens still carry the old scopes.
        let sessions = state.sessions_ks.clone();
        let revoked = super::auth::revoke_sessions_for_did(&sessions, &did).await?;

        if let Some(writer) = state.audit_writer.as_ref() {
            writer
                .write(
                    &actor.did,
                    Some(&did),
                    AuditEvent::AclUpdated(AclChangeData {
                        did: did.clone(),
                        role: entry.role.to_string(),
                        contexts: entry.allowed_contexts.clone(),
                        expires_at: entry.expires_at.map(|e| e.to_string()),
                    }),
                )
                .await?;
        }

        info!(
            caller = %actor.did, did = %did, revoked,
            remaining = entry.allowed_contexts.len(),
            reason = reason.unwrap_or(""),
            "ACL scopes reduced",
        );
        return revoke_response(Some(AclEntryResponse::from(entry)));
    }

    // Revoking the ACL of a **member** would orphan their member row.
    //
    // Two surfaces own the ACL row and only one of them knows membership
    // exists. The leave ceremony (`DELETE /v1/members/{did}` →
    // `ceremony::execute::depart`) deletes the ACL, tombstones the member row,
    // *and* flips the revocation bit on their VMC + VEC. This route deletes the
    // ACL and stops — so a revoke aimed at a member left a live member row with
    // no authorization and, worse, credentials that still verify for anyone
    // holding them.
    //
    // The reader already believed this could not happen: `members::read` calls
    // a live member row with no ACL entry "genuine out-of-band corruption (e.g.
    // an interrupted purge)" and warns on every list. It was not corruption. It
    // was this handler, doing exactly what it was asked, on a DID it could see
    // was a member — the audit row it writes even records `priorRole: "member"`.
    //
    // Refused rather than quietly routed to `depart`: removal runs the removal
    // policy, resolves a disposition, and revokes credentials. An operator who
    // asked to revoke an ACL entry should not get all of that without saying
    // so. So this names the command that does. (Scope *reduction* is untouched
    // — it leaves the entry in place and orphans nothing, which is why this
    // guard sits after that branch has already returned.)
    if let Some(member) = get_member(&state.members_ks, &did).await?
        && !member.is_removed()
    {
        return Err(AppError::Conflict(format!(
            "{did} is a member of this community — revoking their ACL entry would leave the \
             member row with no authorization and their membership credentials unrevoked. \
             To remove them from the community, use the leave ceremony instead:\n    \
             DELETE /v1/members/{did}"
        ))
        .into());
    }

    // Removing an unrestricted admin must not leave nobody able to consent to
    // another (VTI-APV-014, VTI-APV-009). This route had no last-admin check at
    // all: an ACL-only admin (no member row, so not refused above) could be
    // revoked down to none. Checked and written under the admin-set lock the
    // executor's own removals hold, so the two cannot race past each other.
    let _admin_set = crate::ceremony::lock_admin_set().await;
    if let Some(live) = get_acl_entry(&acl, &did).await?
        && crate::acl::admin_consent::is_live_unrestricted(&live, now_epoch())
    {
        // The attrition refusal is this task's declared "last authority"
        // outcome; anything else it returns (a store fault) is not.
        crate::acl::admin_consent::check_attrition(state, &did)
            .await
            .map_err(|e| match e {
                AppError::Conflict(_) => {
                    TaskError::declared(error_codes::LAST_AUTHORITY_PROTECTED.code, e)
                }
                other => TaskError::App(other),
            })?;
    }

    delete_acl_entry(&acl, &did).await?;

    // The removed entry's live sessions go with it: the extractor trusts the
    // JWT's role and contexts until it expires, and an entry that no longer
    // exists must stop authorizing now.
    let revoked = super::auth::revoke_sessions_for_did(&state.sessions_ks, &did).await?;

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &actor.did,
                Some(&did),
                AuditEvent::AclRevoked(AclRevokedData {
                    did: did.clone(),
                    prior_role: Some(entry.role.to_string()),
                }),
            )
            .await?;
    }

    info!(
        caller = %actor.did,
        did = %did,
        revoked,
        reason = reason.unwrap_or(""),
        "ACL entry revoked",
    );
    revoke_response(None)
}

/// Translate a `VtcAclEntry` into the `vti_common::acl::AclEntry`
/// shape that the role-agnostic visibility helpers
/// (`is_acl_entry_visible`, `validate_acl_modification`) expect.
/// They only look at `allowed_contexts`, so the role mapping is
/// best-effort — `VtcRole::Admin` → `Role::Admin`, everything else
/// degrades to `Role::Reader` (lowest privilege; only the contexts
/// match), which is fine because these helpers ignore the role
/// field entirely.
pub(crate) fn as_vti_acl_entry(e: &VtcAclEntry) -> vti_common::acl::AclEntry {
    vti_common::acl::AclEntry::new(e.did.clone(), as_vti_role(&e.role), e.created_by.clone())
        .with_label(e.label.clone())
        .with_contexts(e.allowed_contexts.clone())
        .with_created_at(e.created_at)
        .with_expires_at(e.expires_at)
}

/// The caller's own entry — what bounds the entries it writes (VTI-ACL-053).
/// A caller with no live entry of its own writes nothing (VTI-ACL-001).
async fn caller_entry(state: &AppState, actor: &AuthClaims) -> Result<VtcAclEntry, AppError> {
    match get_acl_entry(&state.acl_ks, &actor.did).await? {
        Some(e) if e.is_expired(now_epoch()) => Err(AppError::Forbidden(format!(
            "your ACL entry ({}) has expired; an expired entry confers no authority to grant (VTI-ACL-004)",
            actor.did
        ))),
        Some(e) => Ok(e),
        None => Err(AppError::Forbidden(format!(
            "{} has no ACL entry of its own, so there is no authority to bound this grant by (VTI-ACL-001, VTI-ACL-053)",
            actor.did
        ))),
    }
}

/// The refusal for an entry the caller can see but does not wholly administer.
fn not_covered(did: &str, verb: &str) -> AppError {
    AppError::Forbidden(format!(
        "{did} holds authority outside your contexts — only an administrator whose scope covers every context it acts in can {verb} it"
    ))
}

/// May `caller` modify or revoke `target`, whatever its role?
///
/// Mirrors [`vti_common::acl::delegated_any_approver_covers`]: a super-admin
/// covers any target; a context-admin covers only a context-scoped target
/// **all** of whose contexts fall within the caller's authority. A target with
/// no `allowed_contexts` is either a super-admin or acts nowhere, and in both
/// cases can only be acted on by a super-admin (the non-`Contexts` branch
/// below is `false` for a non-super caller, so it is refused).
fn caller_covers_target(caller: &AuthClaims, target: &VtcAclEntry) -> bool {
    if caller.is_super_admin() {
        return true;
    }
    // Only a context-scoped target is coverable by a context admin. An
    // unrestricted target is itself a super-admin (super-admin caller only,
    // handled above); an acts-nowhere target names no context to check
    // against. `ActScope` makes those two distinguishable rather than both
    // falling out of one `is_empty()`.
    match target.act_scope() {
        ActScope::Contexts(cs) => cs.iter().all(|ctx| caller.has_context_access(ctx)),
        ActScope::All | ActScope::None => false,
    }
}

/// Did an ACL update reduce the subject's authorization?
///
/// A reduction is either losing the `Admin` role, or narrowing the context
/// scope — going from unrestricted (empty `allowed_contexts`, i.e. super-admin)
/// to restricted, or dropping any previously-held context. Widening scope or a
/// lateral role change is not a reduction. Used to decide whether the subject's
/// live sessions must be revoked so the still-valid JWT can't outlive the
/// downgrade.
fn is_privilege_reduction(
    prev_role: &VtcRole,
    prev_contexts: &[String],
    new_role: &VtcRole,
    new_contexts: &[String],
) -> bool {
    let lost_admin = *prev_role == VtcRole::Admin && *new_role != VtcRole::Admin;
    let narrowed = if prev_contexts.is_empty() {
        // Previously unrestricted (super-admin scope); any restriction narrows.
        !new_contexts.is_empty()
    } else {
        // Previously restricted; dropping any held context narrows. (A move to
        // empty/unrestricted is a *widening*, handled by the `false` here.)
        !new_contexts.is_empty() && prev_contexts.iter().any(|c| !new_contexts.contains(c))
    };
    lost_admin || narrowed
}

#[cfg(test)]
mod tests {
    //! Wire-shape tests for the ACL route bodies. Full route integration
    //! (spawning the router with a real AppState) requires a test-support
    //! harness paralleling vta-service/src/test_support.rs; that's tracked
    //! separately. These tests catch serde regressions — e.g. someone
    //! renaming a field, changing a default, or breaking backward
    //! compatibility with the CLI clients that consume these types.
    use super::*;
    use serde_json::json;

    // ── P0.20: admin-target covering guard ─────────────────────────

    fn claims(super_admin: bool, contexts: &[&str]) -> AuthClaims {
        AuthClaims {
            role: vti_common::acl::Role::Admin,
            allowed_contexts: if super_admin {
                vec![]
            } else {
                contexts.iter().map(|c| c.to_string()).collect()
            },
            ..Default::default()
        }
    }

    fn admin_entry(contexts: &[&str]) -> VtcAclEntry {
        VtcAclEntry {
            did: "did:key:zTarget".into(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: contexts.iter().map(|c| c.to_string()).collect(),
            created_at: 0,
            created_by: "did:key:zCreator".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        }
    }

    #[test]
    fn super_admin_covers_any_admin_target() {
        let sa = claims(true, &[]);
        assert!(caller_covers_target(&sa, &admin_entry(&["ctx-a", "ctx-b"])));
        assert!(caller_covers_target(&sa, &admin_entry(&[]))); // super-admin target
    }

    #[test]
    fn context_admin_covers_only_targets_fully_within_its_scope() {
        let ca = claims(false, &["ctx-a"]);
        // Target scoped exactly to ctx-a → covered.
        assert!(caller_covers_target(&ca, &admin_entry(&["ctx-a"])));
        // Accept-criterion: ctx-a admin can't act on an admin scoped to
        // [ctx-a, ctx-b] — ctx-b is outside its authority.
        assert!(!caller_covers_target(
            &ca,
            &admin_entry(&["ctx-a", "ctx-b"])
        ));
        // A context-admin can never act on a super-admin (empty-context) target.
        assert!(!caller_covers_target(&ca, &admin_entry(&[])));
    }

    // ── P0.20: privilege-reduction detection ───────────────────────

    #[test]
    fn losing_admin_role_is_a_reduction() {
        assert!(is_privilege_reduction(
            &VtcRole::Admin,
            &["ctx-a".into()],
            &VtcRole::Member,
            &["ctx-a".into()],
        ));
    }

    #[test]
    fn narrowing_contexts_is_a_reduction() {
        // Drop a held context.
        assert!(is_privilege_reduction(
            &VtcRole::Admin,
            &["ctx-a".into(), "ctx-b".into()],
            &VtcRole::Admin,
            &["ctx-a".into()],
        ));
        // Unrestricted → restricted.
        assert!(is_privilege_reduction(
            &VtcRole::Admin,
            &[],
            &VtcRole::Admin,
            &["ctx-a".into()],
        ));
        // Swap a context (lose ctx-a, gain ctx-b).
        assert!(is_privilege_reduction(
            &VtcRole::Admin,
            &["ctx-a".into()],
            &VtcRole::Admin,
            &["ctx-b".into()],
        ));
    }

    #[test]
    fn widening_or_lateral_change_is_not_a_reduction() {
        // Add a context.
        assert!(!is_privilege_reduction(
            &VtcRole::Admin,
            &["ctx-a".into()],
            &VtcRole::Admin,
            &["ctx-a".into(), "ctx-b".into()],
        ));
        // Restricted → unrestricted (promotion to super-admin scope).
        assert!(!is_privilege_reduction(
            &VtcRole::Admin,
            &["ctx-a".into()],
            &VtcRole::Admin,
            &[],
        ));
        // No change (e.g. a label-only edit).
        assert!(!is_privilege_reduction(
            &VtcRole::Member,
            &["ctx-a".into()],
            &VtcRole::Member,
            &["ctx-a".into()],
        ));
    }

    // ── CreateAclRequest ────────────────────────────────────────────

    #[test]
    fn grant_request_parses_minimal_body() {
        let body = json!({ "entry": { "subject": "did:key:zABC", "role": "admin" } });
        let req: CreateAclRequest = serde_json::from_value(body).expect("minimal body");
        assert_eq!(req.entry.subject, "did:key:zABC");
        assert_eq!(req.entry.role, VtcRole::Admin);
        assert_eq!(req.entry.label, None);
        assert!(req.entry.scopes.is_empty(), "defaults to empty");
        assert_eq!(req.entry.expires_at, None);
        assert_eq!(req.reason, None);
    }

    #[test]
    fn grant_request_parses_full_body() {
        let body = json!({
            "entry": {
                "subject": "did:key:zABC",
                "role": "moderator",
                "label": "ops lead",
                "scopes": ["ctx1", "ctx2"],
                "expiresAt": "2027-01-15T00:00:00Z",
            },
            "reason": "quarterly review",
        });
        let req: CreateAclRequest = serde_json::from_value(body).expect("full body");
        assert_eq!(req.entry.role, VtcRole::Moderator);
        assert_eq!(req.entry.label.as_deref(), Some("ops lead"));
        assert_eq!(req.entry.scopes, vec!["ctx1", "ctx2"]);
        assert!(req.entry.expires_at.is_some());
        assert_eq!(req.reason.as_deref(), Some("quarterly review"));
    }

    /// Server-owned provenance must not be settable by the caller, or a
    /// grant could backdate who added an entry and when.
    #[test]
    fn grant_request_rejects_caller_supplied_provenance() {
        for field in ["createdAt", "createdBy", "updatedAt", "updatedBy"] {
            let body = json!({
                "entry": { "subject": "did:key:zA", "role": "admin", field: "x" }
            });
            serde_json::from_value::<CreateAclRequest>(body)
                .expect_err(&format!("{field} must not be accepted"));
        }
    }

    #[test]
    fn grant_request_rejects_unknown_role() {
        let body = json!({ "entry": { "subject": "did:key:zA", "role": "godmode" } });
        let err = serde_json::from_value::<CreateAclRequest>(body)
            .expect_err("unknown role must not parse");
        let msg = format!("{err}");
        assert!(
            msg.contains("godmode") || msg.contains("unknown"),
            "got {msg}"
        );
    }

    /// `fromRole` is the compare-and-swap guard; omitting it would turn
    /// change-role back into a blind write.
    #[test]
    fn change_role_request_requires_both_roles() {
        let ok: UpdateAclRequest =
            serde_json::from_value(json!({ "fromRole": "member", "toRole": "moderator" }))
                .expect("both roles");
        assert_eq!(ok.from_role, VtcRole::Member);
        assert_eq!(ok.to_role, VtcRole::Moderator);

        serde_json::from_value::<UpdateAclRequest>(json!({ "toRole": "admin" }))
            .expect_err("fromRole is mandatory");
    }

    #[test]
    fn create_acl_request_rejects_missing_required() {
        let body = json!({ "role": "admin" });
        serde_json::from_value::<CreateAclRequest>(body)
            .expect_err("missing `did` must be rejected");
    }

    // ── UpdateAclRequest ───────────────────────────────────────────

    /// The pre-migration partial update (`role`/`label`/
    /// `allowed_contexts`, all optional) is gone: label and scope edits
    /// belong to `acl/grant`, and a role change now demands its CAS
    /// guard. An old client body must fail loudly rather than be read
    /// as some subset of the new one.
    #[test]
    fn change_role_request_rejects_the_pre_migration_body() {
        for body in [
            json!({}),
            json!({ "role": "member" }),
            json!({ "label": "ops", "allowed_contexts": ["ctx-a"] }),
        ] {
            serde_json::from_value::<UpdateAclRequest>(body.clone())
                .expect_err(&format!("legacy body must not parse: {body}"));
        }
    }

    // ── ListAclQuery ───────────────────────────────────────────────

    #[test]
    fn list_acl_query_filters_are_optional() {
        let q: ListAclQuery = serde_json::from_value(json!({})).unwrap();
        assert!(q.scope.is_none());
        assert!(q.role.is_none());
        assert!(q.subject_prefix.is_none());

        let q: ListAclQuery = serde_json::from_value(json!({ "scope": "app1" })).unwrap();
        assert_eq!(q.scope.as_deref(), Some("app1"));
    }

    // ── AclEntryResponse ───────────────────────────────────────────

    #[test]
    fn acl_entry_response_serializes_with_stable_field_names() {
        let entry = VtcAclEntry {
            did: "did:key:zABC".into(),
            role: VtcRole::Admin,
            label: Some("test".into()),
            allowed_contexts: vec!["ctx1".into()],
            created_at: 1_700_000_000,
            created_by: "did:key:zSetup".into(),
            updated_at: None,
            updated_by: None,
            expires_at: Some(1_800_000_000),
        };
        let resp = AclEntryResponse::from(entry);
        let json = serde_json::to_value(&resp).unwrap();
        // Canonical `acl/_shared` AclEntry names.
        assert_eq!(json["subject"], "did:key:zABC");
        assert_eq!(json["role"], "admin");
        assert_eq!(json["label"], "test");
        assert_eq!(json["scopes"], json!(["ctx1"]));
        assert_eq!(json["createdBy"], "did:key:zSetup");
        // Timestamps are RFC3339 strings — canonical types them
        // `format: date-time`, so emitting the raw epoch would be a
        // silent contract break rather than a cosmetic one.
        assert_eq!(json["createdAt"], "2023-11-14T22:13:20+00:00");
        assert_eq!(json["expiresAt"], "2027-01-15T08:00:00+00:00");
        // The pre-migration names must be gone, not merely aliased.
        for old in [
            "did",
            "allowed_contexts",
            "created_at",
            "created_by",
            "expires_at",
        ] {
            assert!(
                json.get(old).is_none(),
                "{old} should not be emitted: {json}"
            );
        }
    }

    #[test]
    fn acl_entry_response_omits_expires_at_when_permanent() {
        let entry = VtcAclEntry {
            did: "did:key:zPerm".into(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: vec![],
            created_at: 1_700_000_000,
            created_by: "did:key:zSetup".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        };
        let resp = AclEntryResponse::from(entry);
        let json = serde_json::to_value(&resp).unwrap();
        assert!(
            json.get("expiresAt").is_none() && json.get("expires_at").is_none(),
            "permanent entries must omit expiresAt — got {json}"
        );
        // Canonical names and RFC3339 timestamps, not the storage shape.
        assert_eq!(json["subject"], "did:key:zPerm");
        assert!(json.get("did").is_none(), "did renamed to subject: {json}");
        assert!(
            json["createdAt"].as_str().unwrap().contains('T'),
            "createdAt must be RFC3339, not an epoch int: {json}"
        );
    }

    // ── AclListResponse round-trip ─────────────────────────────────

    #[test]
    fn acl_list_response_round_trips() {
        let entries = vec![AclEntryResponse {
            subject: "did:key:zA".into(),
            role: VtcRole::Member,
            label: None,
            scopes: vec![],
            created_at: epoch_to_rfc3339(0),
            created_by: "did:key:zS".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        }];
        let resp = AclListResponse {
            entries,
            truncated: false,
            cursor: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""entries":"#), "got {json}");
        assert!(json.contains(r#""role":"member""#));
        // `truncated` is canonical-required and must always serialize.
        assert!(json.contains(r#""truncated":false"#), "got {json}");
    }

    #[test]
    fn custom_role_round_trip_through_request_body() {
        let body = json!({
            "entry": { "subject": "did:key:zEditor", "role": "custom:editor" },
        });
        let req: CreateAclRequest = serde_json::from_value(body).expect("custom role parses");
        assert_eq!(req.entry.role, VtcRole::Custom("editor".into()));
        // Round-trip via the response shape.
        let entry = VtcAclEntry {
            did: req.entry.subject,
            role: req.entry.role,
            label: None,
            allowed_contexts: vec![],
            created_at: 0,
            created_by: "did:key:zS".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        };
        let resp = AclEntryResponse::from(entry);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["role"], "custom:editor");
    }
}
