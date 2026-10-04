//! The ACL operations every `acl/*` door shares, 0.1 and 0.2.
//!
//! A VTC entry carries a community role and an explicit administrative
//! authority (`crate::acl::capability`, `docs/05-design-notes/vtc-admin-roles.md`).
//! `acl/*/0.2` speaks that model directly. `acl/*/0.1` keeps working by the
//! mapping `acl/_shared/0.2` CONVENTIONS §8 describes:
//!
//! - **0.1 → 0.2.** A 0.1 entry is a community role and a `scopes` list. A VTC
//!   holds no contexts (**VTI-VTC-010**), so a non-empty `scopes` is refused;
//!   the role carries the administrative authority it implies
//!   ([`VtcRole::implied_authority`]): `admin` is a `community-admin` with the
//!   full ceiling, `moderator` and `issuer` the matching administrative role,
//!   everything else none. That is the role set rule 2 is applied to.
//! - **0.2 → 0.1.** An entry renders to 0.1 only when its authority is exactly
//!   what its community role implies ([`expressible_in_v0_1`]); 0.1 cannot
//!   express narrowed capabilities, a qualifier, an approve-only entry or a role
//!   its community role does not imply, and an entry that has any of them is
//!   refused rather than rendered lossily (CONVENTIONS §8). A 0.1 **write** to
//!   such an entry is refused for the same reason: it would replace authority
//!   0.1 cannot even describe.
//!
//! Who may write what is [`crate::acl::granting`]: the granter's stored entry
//! bounds the result on every axis (§6.3). Granting an authority-conferring
//! capability waits for the consent of its other holders
//! ([`crate::acl::admin_consent`], **VTI-APV-018**).

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use tracing::info;

use crate::acl::delegation::{self, DelegationReview};
use crate::acl::granting::{self, GrantRefusal};
use crate::acl::{
    AdminAuthority, AdminRole, CapRef, Capability, CapabilityScope, VtcAclEntry, VtcActScope,
    VtcRole, delete_acl_entry, get_acl_entry, list_acl_entries, store_acl_entry,
};
use crate::auth::{AuthClaims, session::now_epoch};
use crate::error::{AppError, TaskError};
use crate::members::get_member;
use crate::server::AppState;
use vti_common::acl::ContextDirection;
use vti_common::audit::{AclChangeData, AclRevokedData, AdminPromotedData, AuditEvent};
use vti_common::pagination::{Cursor, MAX_LIMIT};

/// The `ext` namespace this community's own members live under.
pub(crate) const EXT_NS: &str = "org.openvtc";

/// The 0.2 `role` string for an entry with no administrative role.
pub(crate) const NO_ADMIN_ROLE: &str = "member";

// ---------- 0.1 rendering ----------

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
    /// True when more entries match beyond this page; `cursor` is then
    /// present. Required by canonical `acl/list`.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Canonical `acl/_shared/0.1` **AclEntry**.
///
/// `scopes` is always empty: a VTC holds no contexts (**VTI-VTC-010**), and an
/// entry renders to 0.1 only when its role says everything about its authority
/// ([`expressible_in_v0_1`]) — read under this community's 0.1 convention, an
/// empty list on `admin` is the whole community and on every other role is
/// nowhere, which is exactly what [`VtcRole::implied_authority`] gives.
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

/// Whether 0.1 can express `e`: its authority is exactly what its community
/// role implies (CONVENTIONS §8).
#[must_use]
pub(crate) fn expressible_in_v0_1(e: &VtcAclEntry) -> bool {
    e.admin == e.role.implied_authority()
}

/// The refusal for an entry 0.1 cannot express.
fn inexpressible(did: &str, verb: &str) -> AppError {
    AppError::Conflict(format!(
        "the ACL entry for {did} carries administrative authority acl/*/0.1 cannot express — a \
         narrowed or qualified capability set, or a role its community role does not imply — \
         so it cannot be {verb} at 0.1. Use the 0.2 task instead (acl/_shared/0.2 \
         CONVENTIONS §8)"
    ))
}

/// Render `e` for a 0.1 reader (see [`AclEntryResponse::v0_1`]).
pub(crate) fn render_v0_1(e: VtcAclEntry) -> AclEntryResponse {
    AclEntryResponse::v0_1(e)
}

impl AclEntryResponse {
    /// Render `e` for a 0.1 reader. Does not check [`expressible_in_v0_1`];
    /// callers that may see an inexpressible entry check first.
    fn v0_1(e: VtcAclEntry) -> Self {
        AclEntryResponse {
            subject: e.did,
            role: e.role,
            label: e.label,
            scopes: Vec::new(),
            created_at: epoch_to_rfc3339(e.created_at),
            created_by: e.created_by,
            updated_at: e.updated_at.map(epoch_to_rfc3339),
            updated_by: e.updated_by,
            expires_at: e.expires_at.map(epoch_to_rfc3339),
        }
    }
}

// ---------- 0.2 rendering ----------

/// `e` as an `acl/_shared/0.2` `AclEntry`, as JSON. Every axis is explicit
/// (CONVENTIONS §4): `act`, `keys` (`none` — this community operates no signing
/// oracle) and `capabilities` always, `approve` and `approveCapabilities` always
/// too, so a reader never infers "none" from an omission.
///
/// The community role, and a delegation review if one is open, travel in
/// `ext["org.openvtc"]`; neither confers authority.
///
/// Callers read the result into the generated response type of the task they
/// answer, so the rendering is held to the published schema.
pub(crate) fn render_v0_2(e: &VtcAclEntry, review: Option<&DelegationReview>) -> Value {
    let mut out = json!({
        "subject": e.did,
        "role": e.admin.admin_role.as_ref().map(|r| r.to_string()).unwrap_or_else(|| NO_ADMIN_ROLE.into()),
        "act": e.admin.act,
        "keys": { "scope": "none" },
        "capabilities": e.admin.capabilities,
        "approve": e.admin.approve,
        "approveCapabilities": e.admin.approve_capabilities,
        "createdAt": epoch_to_rfc3339(e.created_at),
        "createdBy": e.created_by,
    });
    let map = out.as_object_mut().expect("an object");
    if let Some(label) = &e.label {
        map.insert("label".into(), json!(label));
    }
    if let Some(by) = &e.delegated_by {
        map.insert("delegatedBy".into(), json!(by));
    }
    if let Some(at) = e.updated_at {
        map.insert("updatedAt".into(), json!(epoch_to_rfc3339(at)));
    }
    if let Some(by) = &e.updated_by {
        map.insert("updatedBy".into(), json!(by));
    }
    if let Some(at) = e.expires_at {
        map.insert("expiresAt".into(), json!(epoch_to_rfc3339(at)));
    }
    let mut ours = json!({ "communityRole": e.role.to_string() });
    // VTI-ACL-052 item 2: a label its subject set is shown as self-set to
    // every other party that reads it.
    if e.label.is_some() && e.label_set_by_subject {
        ours[LABEL_SET_BY_SUBJECT] = json!(true);
    }
    // Resource grants (phase C3): the git rights this entry holds, each a
    // qualified capability with its own granter. A granter's free-text reason
    // is shown only to those who govern the resource (`git-ns/view`), never
    // here.
    if !e.resource_grants.is_empty() {
        ours["resourceGrants"] = Value::Array(
            e.resource_grants
                .iter()
                .map(|g| {
                    let mut v = json!({
                        "capability": g.capability,
                        "resource": g.resource,
                        "delegatedBy": g.delegated_by,
                        "grantedAt": g.granted_at,
                    });
                    if let Some(grade) = g.grade {
                        v["grade"] = json!(grade);
                    }
                    if let Some(at) = g.expires_at {
                        v["expiresAt"] = json!(at);
                    }
                    if g.break_glass.is_some() {
                        v["breakGlass"] = json!(true);
                    }
                    // Recorded for itself under single-administrator mode
                    // (VTI-APV-022, `git_ns::single_admin`).
                    if g.single_admin.is_some() {
                        v[crate::git_ns::single_admin::EXT_MARKER] = json!(true);
                    }
                    if let Some(r) = &g.review {
                        v["review"] = json!({ "granter": r.granter, "deadline": r.deadline });
                    }
                    v
                })
                .collect(),
        );
    }
    if let Some(r) = review {
        ours["delegationReview"] = json!({
            "granter": r.granter,
            "deadline": epoch_to_rfc3339(r.deadline),
        });
    }
    map.insert("ext".into(), json!({ EXT_NS: ours }));
    out
}

/// Read a rendered response into a generated type, held to its schema.
pub(crate) fn conform<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, AppError> {
    serde_json::from_value(value)
        .map_err(|e| AppError::Internal(format!("acl response does not conform: {e}")))
}

// ---------- reading ----------

/// The caller's own live entry, which every ACL read and write is answered
/// from. A caller with no live entry, or with no administrative role, may not
/// read the ACL.
pub(crate) async fn reader_entry(state: &AppState, did: &str) -> Result<VtcAclEntry, AppError> {
    match get_acl_entry(&state.acl_ks, did).await? {
        Some(e) if e.is_administrator() => Ok(e),
        _ => Err(AppError::Forbidden(format!(
            "{did} holds no administrative role, so it may not read this community's ACL"
        ))),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct ListAclQuery {
    /// Return only entries with this role.
    pub role: Option<String>,
    /// Return only entries carrying this scope. A VTC holds no contexts
    /// (VTI-VTC-010), so no entry carries one.
    pub scope: Option<String>,
    /// Return only entries whose subject starts with this prefix.
    pub subject_prefix: Option<String>,
    /// How `scope` is read over the hierarchy (`acl/list/0.1` `direction`).
    #[param(inline)]
    pub direction: Option<ContextDirection>,
    /// Page size. Clamped to `1..=200`. Defaults to 50.
    pub page_size: Option<usize>,
    /// Opaque continuation token from a previous page's `cursor`.
    pub cursor: Option<String>,
}

/// One page of entries, in subject order, under a cursor bound to `binding`.
struct Page {
    entries: Vec<VtcAclEntry>,
    truncated: bool,
    cursor: Option<String>,
}

async fn page(
    state: &AppState,
    matching: Vec<VtcAclEntry>,
    page_size: Option<usize>,
    cursor: Option<&str>,
    binding: &[u8],
) -> Result<Page, AppError> {
    let mut matching = matching;
    matching.sort_by(|a, b| a.did.cmp(&b.did));
    let limit = page_size.unwrap_or(50).clamp(1, MAX_LIMIT);
    // Cursors are signed with the audit key, but the audit writer is optional:
    // without a key the whole set is one page and a supplied cursor is refused
    // rather than trusted unverified.
    let audit_key = match state.audit_writer.as_ref() {
        Some(w) => Some(w.active_key().await?),
        None => None,
    };
    let start = match (cursor, &audit_key) {
        (Some(wire), Some(key)) => {
            let c = Cursor::decode_bound(wire, &key.key, binding)?;
            matching
                .iter()
                .position(|e| e.did.as_bytes() > c.last_key.as_slice())
                .unwrap_or(matching.len())
        }
        (Some(_), None) => return Err(AppError::InvalidCursor),
        (None, _) => 0,
    };
    let take = if audit_key.is_some() {
        limit
    } else {
        matching.len()
    };
    let entries: Vec<VtcAclEntry> = matching[start..].iter().take(take).cloned().collect();
    let truncated = start + entries.len() < matching.len();
    let cursor = match (&audit_key, truncated) {
        (Some(key), true) => entries.last().map(|e| {
            Cursor::new(e.did.as_bytes().to_vec(), matching.len() as u64)
                .encode_bound(&key.key, binding)
        }),
        _ => None,
    };
    Ok(Page {
        entries,
        truncated,
        cursor,
    })
}

fn bind(fields: &[Option<&str>]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in fields {
        let b = v.unwrap_or("").as_bytes();
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// `acl/list/0.1`. Entries 0.1 cannot express are left out of the page rather
/// than rendered lossily (CONVENTIONS §8) — `acl/list/0.2` shows them.
pub(crate) async fn list_entries(
    state: &AppState,
    actor: &AuthClaims,
    query: &ListAclQuery,
) -> Result<AclListResponse, AppError> {
    reader_entry(state, &actor.did).await?;
    let matching: Vec<VtcAclEntry> = list_acl_entries(&state.acl_ks)
        .await?
        .into_iter()
        .filter(expressible_in_v0_1)
        .filter(|e| query.role.as_ref().is_none_or(|r| e.role.to_string() == *r))
        // No VTC entry carries a scope.
        .filter(|_| query.scope.is_none())
        .filter(|e| {
            query
                .subject_prefix
                .as_ref()
                .is_none_or(|p| e.did.starts_with(p.as_str()))
        })
        .collect();
    let binding = bind(&[
        query.role.as_deref(),
        query.scope.as_deref(),
        query.subject_prefix.as_deref(),
        Some(query.direction.unwrap_or_default().as_str()),
    ]);
    let p = page(
        state,
        matching,
        query.page_size,
        query.cursor.as_deref(),
        &binding,
    )
    .await?;
    info!(caller = %actor.did, count = p.entries.len(), truncated = p.truncated, "ACL listed");
    Ok(AclListResponse {
        entries: p.entries.into_iter().map(AclEntryResponse::v0_1).collect(),
        truncated: p.truncated,
        cursor: p.cursor,
    })
}

/// `acl/list/0.2`: every entry the filters match, rendered with every axis.
pub(crate) async fn list_entries_v0_2(
    state: &AppState,
    actor_did: &str,
    q: &trust_tasks_rs::specs::acl::list::v0_2::Payload,
) -> Result<Value, AppError> {
    reader_entry(state, actor_did).await?;
    let capability: Option<Capability> = q.capability.as_deref().map(|c| c.parse()).transpose()?;
    let resource: Option<crate::acl::ResourceQualifier> =
        q.resource.as_deref().map(|r| r.parse()).transpose()?;
    // The spec's own spelling (`actingIn` / `subtree` / `any`).
    let direction_owned = q.direction.map(|d| d.to_string());
    let direction = direction_owned.as_deref();
    let role = q.role.as_deref().map(String::as_str);
    let subject_prefix = q.subject_prefix.as_deref().map(String::as_str);
    let matching: Vec<VtcAclEntry> = list_acl_entries(&state.acl_ks)
        .await?
        .into_iter()
        .filter(|e| {
            role.is_none_or(|r| {
                e.admin
                    .admin_role
                    .as_ref()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| NO_ADMIN_ROLE.into())
                    == r
            })
        })
        // A VTC has no contexts: only an unrestricted act scope "acts in" one,
        // and nothing holds a grant beneath one.
        .filter(|e| {
            q.context.is_none()
                || (matches!(direction, Some("actingIn" | "any")) && e.admin.act.is_all())
        })
        .filter(|e| {
            let mut held: Vec<CapRef> = if e.admin.act.is_all() {
                e.admin.effective()
            } else {
                vec![]
            };
            // Resource grants (phase C3) answer for the capability they hold
            // in full; a maintainer's or creator's grade is not the capability
            // (`crate::acl::resource_grant`).
            let now = chrono::Utc::now();
            held.extend(
                e.resource_grants
                    .iter()
                    .filter(|g| {
                        g.is_live(now)
                            && matches!(
                                g.grade,
                                None | Some(crate::acl::resource_grant::RepoGrade::Own)
                            )
                    })
                    .map(crate::acl::resource_grant::ResourceGrant::cap_ref),
            );
            let of_kind = |c: &&CapRef| capability.is_none_or(|k| c.capability == k);
            match &resource {
                None => capability.is_none() || held.iter().any(|c| of_kind(&c)),
                Some(r) => held.iter().filter(of_kind).any(|c| {
                    let acting_in = c.resource.as_ref().is_none_or(|h| h.covers(r));
                    let beneath = c.resource.as_ref().is_some_and(|h| r.covers(h));
                    match direction {
                        Some("actingIn") => acting_in,
                        Some("subtree") => beneath,
                        _ => acting_in || beneath,
                    }
                }),
            }
        })
        .filter(|e| subject_prefix.is_none_or(|p| e.did.starts_with(p)))
        .collect();
    let binding = bind(&[
        Some("0.2"),
        role,
        q.context.as_deref().map(String::as_str),
        q.capability.as_deref().map(String::as_str),
        q.resource.as_deref().map(String::as_str),
        direction,
        subject_prefix,
    ]);
    let page_size = q
        .page_size
        .map(|n| usize::try_from(n.get()).unwrap_or(usize::MAX));
    let cursor = q.cursor.as_deref().map(String::as_str);
    let p = page(state, matching, page_size, cursor, &binding).await?;
    let reviews = delegation::list(state).await?;
    let entries: Vec<Value> = p
        .entries
        .iter()
        .map(|e| render_v0_2(e, reviews.iter().find(|r| r.subject == e.did)))
        .collect();
    let mut out = json!({ "entries": entries, "truncated": p.truncated });
    if let Some(c) = p.cursor {
        out["cursor"] = json!(c);
    }
    info!(caller = %actor_did, count = entries.len(), "ACL listed (0.2)");
    Ok(out)
}

/// `acl/show/0.1`. An absent entry is `NotFound`; one 0.1 cannot express is
/// refused, naming `acl/show/0.2`.
pub(crate) async fn show_entry(
    state: &AppState,
    actor: &AuthClaims,
    did: &str,
) -> Result<AclEntryEnvelope, AppError> {
    reader_entry(state, &actor.did).await?;
    let entry = get_acl_entry(&state.acl_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    if !expressible_in_v0_1(&entry) {
        return Err(inexpressible(did, "shown"));
    }
    info!(caller = %actor.did, did = %did, "ACL entry retrieved");
    Ok(AclEntryEnvelope {
        entry: AclEntryResponse::v0_1(entry),
    })
}

/// `acl/show/0.2`: `{entry}`, `entry: null` when absent.
pub(crate) async fn show_entry_v0_2(
    state: &AppState,
    actor_did: &str,
    did: &str,
) -> Result<Value, AppError> {
    reader_entry(state, actor_did).await?;
    let entry = get_acl_entry(&state.acl_ks, did).await?;
    let review = delegation::review_for(state, did).await?;
    Ok(json!({ "entry": entry.map(|e| render_v0_2(&e, review.as_ref())) }))
}

// ---------- writing ----------

/// Canonical `acl/grant` request: the entry the maintainer should hold
/// for the subject, plus an optional operator rationale.
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateAclRequest {
    pub entry: GrantEntry,
    /// Operator rationale, emitted on the service log line for this change.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The writable subset of a canonical 0.1 `AclEntry`. Server-owned fields
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

/// What an approver is shown for a grant conferring `conferred` on `subject`.
pub(crate) fn conferral_summary(subject: &str, conferred: &[CapRef]) -> String {
    format!(
        "Give {subject} {} — authority to create authority in this community",
        conferred
            .iter()
            .map(CapRef::display)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// What an approver is shown for a grant of community administrator — kept
/// for the invite door, which makes one.
pub(crate) fn unrestricted_grant_summary(subject: &str) -> String {
    format!("Make {subject} a community administrator of this community")
}

/// Why a planned write is refused. The door renders each in its version's
/// codes.
#[derive(Debug)]
pub(crate) enum WriteError {
    /// The granter's bound or the role's ceiling (§6.3).
    Refused(GrantRefusal),
    Task(TaskError),
}

impl From<AppError> for WriteError {
    fn from(e: AppError) -> Self {
        WriteError::Task(TaskError::App(e))
    }
}

impl From<TaskError> for WriteError {
    fn from(e: TaskError) -> Self {
        WriteError::Task(e)
    }
}

impl From<WriteError> for TaskError {
    fn from(e: WriteError) -> Self {
        match e {
            WriteError::Task(t) => t,
            WriteError::Refused(r) => TaskError::App(AppError::Forbidden(r.to_string())),
        }
    }
}

/// An ACL write that has passed every check deciding whether it may happen,
/// and has not yet been written.
///
/// The split exists for the gate: the door runs [`plan_write`], settles the
/// gesture and any consent, then [`commit_grant`].
#[derive(Debug)]
pub(crate) struct GrantPlan {
    pub(crate) entry: VtcAclEntry,
    pub(crate) prior: Option<VtcAclEntry>,
    status: StatusCode,
    /// The authority-conferring capabilities this write gives that the subject
    /// did not hold — the consent trigger (**VTI-APV-018**).
    pub(crate) conferred: Vec<CapRef>,
    /// Whether this write gives administrative authority the subject did not
    /// hold — a capability, approve authority, or a longer life — which needs
    /// the requester's gesture.
    pub(crate) widens: bool,
    /// The entry as it stands, when the write takes authority away from a live
    /// administrator — which needs the gesture, and for authority-conferring
    /// capabilities their other holders' consent (**VTI-APV-019**).
    pub(crate) reduces_admin: Option<VtcAclEntry>,
    /// Whether the subject stops being a holder of `vtc.roles.assign` — the
    /// attrition check under the admin-set lock.
    ends_assigner: bool,
    /// Whether anything is taken away: the subject's live sessions go.
    reduces: bool,
    event: PlanEvent,
    reason: Option<String>,
    /// Whether, and under which exception, the writer is the subject
    /// (**VTI-ACL-052**).
    pub(crate) self_edit: SelfEdit,
}

/// A subject writing its own entry, under one of the exceptions
/// **VTI-ACL-052** makes to "a subject MUST NOT modify its own entry". The
/// first, the self-service rotation, is `acl/swap-key` ([`swap_key`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelfEdit {
    /// The writer is not the subject.
    No,
    /// Item 2: the label and nothing else. The label confers no authority
    /// (VTI-ACL-001), so nothing gates it; it is audited and marked self-set.
    Label,
    /// Item 3: single-administrator mode (VTI-APV-022), the writer's entry
    /// unrestricted. Authorized by the writer's step-up bound to this
    /// operation (VTI-APV-015), audited at `Critical`
    /// ([`crate::acl::single_admin::authorize_self_edit`]); the write never
    /// leaves the community without an unrestricted entry.
    UnrestrictedInSingleAdminMode,
}

/// Whether `next` differs from `prev` in its label alone — every axis of
/// authority, the community role and the expiry as they were (VTI-ACL-052
/// item 2).
#[must_use]
pub(crate) fn only_label_differs(prev: &VtcAclEntry, next: &VtcAclEntry) -> bool {
    prev.role == next.role && prev.admin == next.admin && prev.expires_at == next.expires_at
}

/// How many live entries other than `did`'s have unrestricted act scope — a
/// `community-admin` acting everywhere with its full ceiling
/// ([`granting::is_unrestricted`]). VTI-ACL-052 item 3 refuses a self-edit
/// that would leave none at all.
pub(crate) async fn other_unrestricted(
    state: &AppState,
    did: &str,
    now: u64,
) -> Result<usize, AppError> {
    Ok(list_acl_entries(&state.acl_ks)
        .await?
        .iter()
        .filter(|e| e.did != did && granting::is_unrestricted(e, now))
        .count())
}

/// The refusal for a subject changing its own entry beyond what VTI-ACL-052
/// lets it — saying what it may do instead.
pub(crate) fn self_edit_refusal(what: &str, single_admin_mode: bool) -> AppError {
    let mode = if single_admin_mode {
        " In single-administrator mode an administrator whose entry is unrestricted (a \
         community-admin acting everywhere with its full ceiling) may edit its own entry with \
         a passkey gesture bound to the change; yours is not."
    } else {
        ""
    };
    AppError::Forbidden(format!(
        "you cannot {what} (VTI-ACL-052) — you may change your entry's label yourself, but \
         any other change must be made by another administrator holding vtc.roles.assign.{mode}"
    ))
}

/// The refusal for a subject moving its own role on a door that carries
/// neither exception of VTI-ACL-052 (`acl/change-role/0.1`,
/// `vtc/members/update`), naming the doors that do.
pub(crate) fn own_role_refusal(single_admin_mode: bool) -> AppError {
    let mode = if single_admin_mode {
        " In single-administrator mode, an administrator whose entry is unrestricted edits its \
         own entry with acl/update/0.2 or acl/change-role/0.2, on a passkey gesture bound to \
         the change."
    } else {
        " Another administrator holding vtc.roles.assign can make this change."
    };
    AppError::Forbidden(format!(
        "you cannot change your own role here (VTI-ACL-052) — you may change your entry's label \
         yourself.{mode}"
    ))
}

/// The task a [`GrantPlan`] was made for, for the audit row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanEvent {
    Granted,
    Updated,
}

/// The actor's own live entry — what bounds every entry it writes
/// (**VTI-ACL-053**). A caller with no live entry writes nothing
/// (**VTI-ACL-001**).
async fn actor_entry(state: &AppState, did: &str) -> Result<VtcAclEntry, AppError> {
    match get_acl_entry(&state.acl_ks, did).await? {
        Some(e) if e.is_expired(now_epoch()) => Err(AppError::Forbidden(format!(
            "your ACL entry ({did}) has expired; an expired entry confers no authority to grant \
             (VTI-ACL-004)"
        ))),
        Some(e) => Ok(e),
        None => Err(AppError::Forbidden(format!(
            "{did} has no ACL entry of its own, so there is no authority to bound this write by \
             (VTI-ACL-001, VTI-ACL-053)"
        ))),
    }
}

/// The refusal for an entry the caller does not wholly administer
/// (**VTI-ACL-050**).
fn not_covered(did: &str, verb: &str) -> AppError {
    AppError::Forbidden(format!(
        "{did} holds authority outside yours — only an administrator holding vtc.roles.assign \
         over everything it holds can {verb} it (VTI-ACL-050)"
    ))
}

/// Every check an ACL write makes, and the entry it would write. Writes
/// nothing.
///
/// `next` is the whole resulting entry: its community role, administrative
/// authority, label and expiry. Provenance (`created*`, `updated*`,
/// `delegatedBy`) is set here, never taken from the caller. `existing` is the
/// subject's entry as read by the caller, `None` for a creation.
pub(crate) async fn plan_write(
    state: &AppState,
    actor_did: &str,
    mut next: VtcAclEntry,
    existing: Option<VtcAclEntry>,
    event: PlanEvent,
    reason: Option<String>,
) -> Result<GrantPlan, WriteError> {
    let now = now_epoch();
    next.role.refuse_unassignable()?;
    // VTI-ACL-052 / VTI-OPS-050, before anything that would leak whether the
    // caller's own entry is coverable.
    if next.did == actor_did {
        return plan_self_write(state, next, existing, event, reason, now).await;
    }
    let actor = actor_entry(state, actor_did).await?;
    if let Some(prev) = existing.as_ref()
        && !granting::covers_entry(&actor, prev, now)
    {
        return Err(not_covered(&prev.did, "rewrite").into());
    }
    // A custom role is bounded by its stored definition, read now — never by
    // anything the caller sent (VTI-ACL-011, VTI-VTC-022).
    crate::acl::roles::resolve(&state.acl_ks, &mut next).await?;
    granting::check_write(&actor, &next, now).map_err(WriteError::Refused)?;

    let (created_at, created_by, status) = match existing.as_ref() {
        Some(prev) => (prev.created_at, prev.created_by.clone(), StatusCode::OK),
        None => (now, actor.did.clone(), StatusCode::CREATED),
    };
    next.created_at = created_at;
    next.created_by = created_by;
    next.updated_at = (status == StatusCode::OK).then_some(now);
    next.updated_by = (status == StatusCode::OK).then(|| actor.did.clone());
    // A grant is a delegation (§6.3): the writer is the granter it is bounded
    // by. An entry with no administrative authority derives from nobody.
    next.delegated_by = next.admin.is_administrator().then(|| actor.did.clone());
    // Anyone but the subject setting the label clears its self-set mark
    // (VTI-ACL-052 item 2); a write that leaves the label alone keeps it.
    next.label_set_by_subject = existing
        .as_ref()
        .is_some_and(|p| p.label == next.label && p.label_set_by_subject);

    let prior_live = existing.as_ref().filter(|p| !p.is_expired(now));
    let conferred = crate::acl::admin_consent::newly_conferred(prior_live, &next, now);
    let extends_life = existing
        .as_ref()
        .is_some_and(|p| match (p.expires_at, next.expires_at) {
            (Some(_), None) => true,
            (Some(was), Some(now)) => now > was,
            (None, _) => false,
        });
    let shortens_life = existing
        .as_ref()
        .is_some_and(|p| match (p.expires_at, next.expires_at) {
            (None, Some(_)) => true,
            (Some(was), Some(now)) => now < was,
            (_, None) => false,
        });
    let widens = next.admin.is_administrator()
        && match prior_live {
            None => true,
            Some(p) => next.admin.widens_from(&p.admin) || extends_life,
        };
    let reduces = prior_live.is_some_and(|p| next.admin.narrows_from(&p.admin) || shortens_life);
    let reduces_admin = prior_live
        .filter(|p| reduces && p.admin.is_administrator())
        .cloned();
    let ends_assigner = prior_live
        .is_some_and(|p| crate::acl::admin_consent::is_live_role_assigner(p, now))
        && !crate::acl::admin_consent::is_live_role_assigner(&next, now);

    Ok(GrantPlan {
        entry: next,
        prior: existing,
        status,
        conferred,
        widens,
        reduces_admin,
        ends_assigner,
        reduces,
        event,
        reason,
        self_edit: SelfEdit::No,
    })
}

/// [`plan_write`] for a subject writing its own entry: refused unless one of
/// the exceptions **VTI-ACL-052** makes applies.
///
/// - Item 2 — the label and nothing else ([`SelfEdit::Label`]). Nothing about
///   authority moves, so nothing is bounded or gated; the label is marked
///   self-set.
/// - Item 3 — single-administrator mode, the subject's entry unrestricted
///   ([`SelfEdit::UnrestrictedInSingleAdminMode`]). A holder of every axis
///   cannot widen itself past anyone, and the mode states that every
///   administrator is the same person (VTI-APV-022), so there is nobody else
///   to make the edit. The entry must still fit its role's ceiling, and the
///   write is refused if it would leave no unrestricted entry: where no other
///   is live, the subject's must stay unrestricted and its life may not
///   shorten. Ending the subject's `vtc.roles.assign` is attrition, checked
///   under the admin-set lock like any other. The gesture and the `Critical`
///   audit row are the door's
///   ([`crate::acl::single_admin::authorize_self_edit`]).
///
/// Anything else is refused, naming what the subject may do instead.
async fn plan_self_write(
    state: &AppState,
    mut next: VtcAclEntry,
    existing: Option<VtcAclEntry>,
    event: PlanEvent,
    reason: Option<String>,
    now: u64,
) -> Result<GrantPlan, WriteError> {
    let mode = crate::acl::admin_consent::single_admin_mode(state).await;
    // A caller always has an entry of its own to amend; one that has none
    // creates nothing for itself.
    let Some(prev) = existing else {
        return Err(self_edit_refusal("write your own ACL entry", mode).into());
    };
    let actor = actor_entry(state, &next.did).await?;
    crate::acl::roles::resolve(&state.acl_ks, &mut next).await?;

    // A rewrite that changes nothing is no label change: refused as before.
    let self_edit = if prev.label != next.label && only_label_differs(&prev, &next) {
        SelfEdit::Label
    } else if mode && granting::is_unrestricted(&prev, now) {
        SelfEdit::UnrestrictedInSingleAdminMode
    } else {
        return Err(self_edit_refusal("change your own ACL entry beyond its label", mode).into());
    };

    if self_edit == SelfEdit::UnrestrictedInSingleAdminMode {
        next.admin
            .validate_against_ceiling()
            .map_err(|e| WriteError::Refused(GrantRefusal::Ceiling(e)))?;
        let shortens_life = match (prev.expires_at, next.expires_at) {
            (None, Some(_)) => true,
            (Some(was), Some(will)) => will < was,
            (_, None) => false,
        };
        if (!granting::is_unrestricted(&next, now) || shortens_life)
            && other_unrestricted(state, &actor.did, now).await? == 0
        {
            return Err(AppError::Forbidden(format!(
                "this change would leave the community with no entry holding unrestricted act \
                 scope (VTI-ACL-052 item 3): yours is its only one, so it must stay a \
                 community-admin acting everywhere with its full ceiling, and its life may not \
                 shorten. It would become: {}. Make another community administrator first",
                crate::acl_cli::describe_authority(&next.admin)
            ))
            .into());
        }
    }

    next.created_at = prev.created_at;
    next.created_by = prev.created_by.clone();
    next.updated_at = Some(now);
    next.updated_by = Some(actor.did.clone());
    // Not a delegation: the subject derives nothing from itself.
    next.delegated_by = prev.delegated_by.clone();
    next.label_set_by_subject = if prev.label == next.label {
        prev.label_set_by_subject
    } else {
        next.label.is_some()
    };
    let reduces = next.admin.narrows_from(&prev.admin);
    let ends_assigner = crate::acl::admin_consent::is_live_role_assigner(&prev, now)
        && !crate::acl::admin_consent::is_live_role_assigner(&next, now);
    Ok(GrantPlan {
        entry: next,
        prior: Some(prev),
        status: StatusCode::OK,
        conferred: Vec::new(),
        widens: false,
        reduces_admin: None,
        ends_assigner,
        reduces,
        event,
        reason,
        self_edit,
    })
}

/// Write a planned grant and audit it. Settling the gesture and any consent,
/// where the plan needs them, is the caller's job and must happen first.
pub(crate) async fn commit_grant(
    state: &AppState,
    actor_did: &str,
    plan: GrantPlan,
) -> Result<(StatusCode, VtcAclEntry), AppError> {
    let GrantPlan {
        entry,
        prior,
        status,
        reason,
        ends_assigner,
        reduces,
        event,
        self_edit,
        ..
    } = plan;
    // Taking `vtc.roles.assign` away is attrition like any removal, checked and
    // written under the same admin-set lock (VTI-APV-009).
    let custom_role = match entry.admin.admin_role.as_ref() {
        Some(crate::acl::AdminRole::Custom(name)) => Some(name.clone()),
        _ => None,
    };
    let _admin_set = if ends_assigner || custom_role.is_some() {
        let guard = crate::ceremony::lock_admin_set().await;
        if ends_assigner {
            crate::acl::admin_consent::check_attrition(state, &entry.did).await?;
        }
        // A grant racing `vtc/roles/delete` of its role: the deletion holds the
        // same lock, so either it counted this holder and refused, or the role
        // is gone now and the grant is refused (`vtc/roles/delete/0.1` item 3).
        if let Some(name) = custom_role.as_deref()
            && crate::acl::roles::get(&state.acl_ks, name).await?.is_none()
        {
            return Err(AppError::Validation(format!(
                "'{name}' is not a role this community can grant — it was deleted \
                 (VTI-ACL-011)"
            )));
        }
        Some(guard)
    } else {
        None
    };
    // The entry's resource grants (git rights, phase C3) are not an `acl/*`
    // axis: each is a delegation of its own, written by `git-ns/*`. An ACL
    // write keeps whatever the stored entry holds now — read under the
    // git-namespace write lock, so a grant written between plan and commit is
    // not lost.
    let mut entry = entry;
    {
        let _git = crate::git_ns::store::write_lock().await;
        entry.resource_grants = get_acl_entry(&state.acl_ks, &entry.did)
            .await?
            .map(|e| e.resource_grants)
            .unwrap_or_default();
        store_acl_entry(&state.acl_ks, &entry).await?;
    }
    crate::admin_actions::record_effect(state).await;
    drop(_admin_set);

    // A reduced entry must bind now: the subject's live sessions go — unless
    // the subject asked for it itself, from the session it is acting in.
    if reduces && self_edit == SelfEdit::No {
        let revoked = super::auth::revoke_sessions_for_did(&state.sessions_ks, &entry.did).await?;
        info!(did = %entry.did, revoked, "subject sessions revoked after ACL privilege reduction");
    }
    // A write by a covering administrator re-affirms a delegation under review
    // (§6.3); a narrowed granter's own grants may no longer be covered. A
    // subject's write to its own entry (VTI-ACL-052) re-affirms nothing: a
    // review is another administrator's to settle, never the subject's.
    if self_edit == SelfEdit::No {
        delegation::clear(state, &entry.did).await?;
    }
    if reduces {
        delegation::on_granter_changed(state, &entry.did, Some(&entry)).await?;
    }

    if let Some(writer) = state.audit_writer.as_ref() {
        let event = if self_edit == SelfEdit::Label {
            // VTI-ACL-052 item 2: recorded as the subject's own label.
            AuditEvent::MemberUpdated(self_label_audit(prior.as_ref(), &entry))
        } else {
            let data = audit_data(&entry);
            match event {
                PlanEvent::Granted => AuditEvent::AclGranted(data),
                PlanEvent::Updated => AuditEvent::AclUpdated(data),
            }
        };
        writer.write(actor_did, Some(&entry.did), event).await?;
    }
    info!(
        caller = %actor_did,
        did = %entry.did,
        role = %entry.role,
        admin_role = ?entry.admin.admin_role,
        reason = reason.as_deref().unwrap_or(""),
        created = status == StatusCode::CREATED,
        was = prior.is_some(),
        task = ?event,
        "ACL entry written",
    );
    Ok((status, entry))
}

/// The audit row for a subject's change to its own label (**VTI-ACL-052**
/// item 2): the label before and after, and the self-set mark, so the row says
/// in itself that the subject set it.
pub(crate) fn self_label_audit(
    prior: Option<&VtcAclEntry>,
    entry: &VtcAclEntry,
) -> vti_common::audit::MemberUpdatedData {
    use vti_common::audit::{FieldChange, MemberUpdatedData};
    let old_label = prior.and_then(|p| p.label.clone());
    let old_mark = prior.is_some_and(|p| p.label_set_by_subject);
    let mut fields_changed = Vec::new();
    let mut changes = Vec::new();
    if old_label != entry.label {
        fields_changed.push("label".to_string());
        changes.push(FieldChange {
            field: "label".into(),
            old: old_label.map(Value::String),
            new: entry.label.clone().map(Value::String),
        });
    }
    fields_changed.push(LABEL_SET_BY_SUBJECT.to_string());
    changes.push(FieldChange {
        field: LABEL_SET_BY_SUBJECT.into(),
        old: Some(Value::Bool(old_mark)),
        new: Some(Value::Bool(entry.label_set_by_subject)),
    });
    MemberUpdatedData {
        fields_changed,
        changes,
    }
}

/// The name the self-set mark goes by on the wire (`ext["org.openvtc"]`) and
/// in audit rows.
pub(crate) const LABEL_SET_BY_SUBJECT: &str = "labelSetBySubject";

/// The audit row's view of an entry: its administrative role (or community
/// role, with none) and the capabilities it holds, in the slot that used to
/// carry context scopes.
fn audit_data(e: &VtcAclEntry) -> AclChangeData {
    AclChangeData {
        did: e.did.clone(),
        role: e
            .admin
            .admin_role
            .as_ref()
            .map(|r| r.to_string())
            .unwrap_or_else(|| e.role.to_string()),
        contexts: if e.admin.act.is_all() {
            e.admin.effective().iter().map(CapRef::display).collect()
        } else {
            Vec::new()
        },
        expires_at: e.expires_at.map(|x| x.to_string()),
    }
}

// ---------- 0.1 writes ----------

/// Refuse a 0.1 `scopes` list: a VTC holds no contexts (**VTI-VTC-010**).
fn refuse_scopes(scopes: &[String]) -> Result<(), AppError> {
    if scopes.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation(format!(
            "a community holds no contexts (VTI-VTC-010), so an entry cannot be scoped to {} — \
             narrow administrative authority with acl/update/0.2 capabilities and qualifiers",
            scopes.join(", ")
        )))
    }
}

/// `acl/grant/0.1`: plan the write the 0.1 entry describes.
pub(crate) async fn plan_grant(
    state: &AppState,
    actor: &AuthClaims,
    req: CreateAclRequest,
) -> Result<GrantPlan, WriteError> {
    let e = req.entry;
    refuse_scopes(&e.scopes)?;
    let existing = get_acl_entry(&state.acl_ks, &e.subject).await?;
    if let Some(prev) = existing.as_ref() {
        if prev.role != e.role {
            return Err(AppError::Conflict(format!(
                "ACL entry for {} already holds role {}; use acl/change-role to move it to {}",
                e.subject, prev.role, e.role
            ))
            .into());
        }
        if !expressible_in_v0_1(prev) {
            return Err(inexpressible(&e.subject, "rewritten").into());
        }
    }
    let mut next = VtcAclEntry::new(
        e.subject,
        e.role.clone(),
        e.role.implied_authority(),
        actor.did.clone(),
    );
    next.label = e.label;
    next.expires_at = e.expires_at.map(|t| t.timestamp() as u64);
    plan_write(
        state,
        &actor.did,
        next,
        existing,
        PlanEvent::Granted,
        req.reason,
    )
    .await
}

/// Canonical `acl/update/0.1`: amend an existing entry's non-role attributes.
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
    pub ext: Option<Value>,
}

/// Absent → `None`, `null` → `Some(None)`, a value → `Some(Some(v))`.
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

/// The existing entry `acl/update` amends, or its declared `notFound`.
async fn existing_for_update(
    state: &AppState,
    subject: &str,
    not_found_code: &'static str,
) -> Result<VtcAclEntry, TaskError> {
    get_acl_entry(&state.acl_ks, subject).await?.ok_or_else(|| {
        TaskError::declared(
            not_found_code,
            AppError::NotFound(format!(
                "ACL entry not found for DID: {subject} — acl/update amends an existing entry; \
                 use acl/grant to create one"
            )),
        )
    })
}

/// `acl/update/0.1`.
pub(crate) async fn plan_update(
    state: &AppState,
    actor: &AuthClaims,
    req: UpdateEntryRequest,
) -> Result<GrantPlan, WriteError> {
    use trust_tasks_rs::specs::acl::update::v0_1::error_codes;
    // A subject's own entry is decided by `plan_write` (VTI-ACL-052).
    let existing = existing_for_update(state, &req.subject, error_codes::NOT_FOUND.code).await?;
    if let Some(scopes) = req.scopes.as_ref() {
        refuse_scopes(scopes)?;
    }
    if !expressible_in_v0_1(&existing) {
        return Err(inexpressible(&req.subject, "updated").into());
    }
    let mut next = existing.clone();
    if let Some(label) = req.label {
        next.label = label;
    }
    if let Some(exp) = req.expires_at {
        next.expires_at = exp.map(|t| t.timestamp() as u64);
    }
    plan_write(
        state,
        &actor.did,
        next,
        Some(existing),
        PlanEvent::Updated,
        req.reason,
    )
    .await
}

// ---------- 0.2 writes ----------

/// Read a 0.2 `AclEntry`-shaped value's administrative axes onto this
/// community's model. Refusals carry their declared codes' meaning.
pub(crate) enum EntryParseError {
    RoleNotRecognized(String),
    InvalidActScope(&'static str, Vec<String>),
    UnknownCapability(Vec<String>),
    Malformed(String),
}

/// Parse a 0.2 `role` string: `member` (no administrative role) or an
/// administrative role this community can grant.
pub(crate) fn parse_admin_role(role: &str) -> Result<Option<AdminRole>, EntryParseError> {
    if role == NO_ADMIN_ROLE {
        return Ok(None);
    }
    match role.parse::<AdminRole>() {
        Ok(r) => Ok(Some(r)),
        _ => Err(EntryParseError::RoleNotRecognized(role.to_string())),
    }
}

/// Parse an `AuthorityScope` onto `all` / `none`. A `contexts` scope cannot be
/// held at a community node (**VTI-VTC-010**; CONVENTIONS §4 rule 4).
pub(crate) fn parse_scope(v: &Value, member: &'static str) -> Result<VtcActScope, EntryParseError> {
    match v.get("scope").and_then(Value::as_str) {
        Some("all") => Ok(VtcActScope::All),
        Some("none") => Ok(VtcActScope::None),
        Some("contexts") => Err(EntryParseError::InvalidActScope(
            member,
            v.get("contexts")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|c| c.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        )),
        _ => Err(EntryParseError::Malformed(format!(
            "`{member}` is not an explicit scope"
        ))),
    }
}

/// Parse a `CapabilityScope` / `ApproveCapabilityScope`. Unknown capabilities
/// are named, all of them, never dropped (VTI-ACL-032).
pub(crate) fn parse_capabilities(v: &Value) -> Result<CapabilityScope, EntryParseError> {
    if v.get("scope").and_then(Value::as_str) == Some("listed")
        && let Some(grants) = v.get("grants").and_then(Value::as_array)
    {
        let unknown: Vec<String> = grants
            .iter()
            .filter_map(|g| g.get("capability").and_then(Value::as_str))
            .filter(|c| c.parse::<Capability>().is_err())
            .map(str::to_string)
            .collect();
        if !unknown.is_empty() {
            return Err(EntryParseError::UnknownCapability(unknown));
        }
    }
    serde_json::from_value(v.clone()).map_err(|e| EntryParseError::Malformed(e.to_string()))
}

/// Refuse a key scope other than `none`: this community operates no signing
/// oracle (`acl/_shared/0.2` `keys`).
fn parse_keys(v: &Value) -> Result<(), EntryParseError> {
    match v.get("scope").and_then(Value::as_str) {
        Some("none") => Ok(()),
        _ => Err(EntryParseError::Malformed(
            "this community operates no signing oracle, so `keys` is {\"scope\": \"none\"}".into(),
        )),
    }
}

/// The community role a 0.2 write names in `ext["org.openvtc"].communityRole`,
/// or `None`.
pub(crate) fn ext_community_role(ext: Option<&Value>) -> Result<Option<VtcRole>, EntryParseError> {
    match ext
        .and_then(|e| e.get(EXT_NS))
        .and_then(|o| o.get("communityRole"))
    {
        None => Ok(None),
        Some(Value::String(s)) => s
            .parse()
            .map(Some)
            .map_err(|e: AppError| EntryParseError::Malformed(e.to_string())),
        Some(_) => Err(EntryParseError::Malformed(
            "ext.org.openvtc.communityRole is a string".into(),
        )),
    }
}

/// The resulting entry an `acl/grant/0.2` payload describes, before
/// provenance.
pub(crate) fn entry_from_v0_2(e: &Value) -> Result<VtcAclEntry, EntryParseError> {
    let subject = e
        .get("subject")
        .and_then(Value::as_str)
        .ok_or_else(|| EntryParseError::Malformed("entry.subject".into()))?;
    let role = parse_admin_role(e.get("role").and_then(Value::as_str).unwrap_or_default())?;
    let act = parse_scope(&e["act"], "act")?;
    parse_keys(&e["keys"])?;
    let capabilities = parse_capabilities(&e["capabilities"])?;
    // Absent approve and approveCapabilities mean none (CONVENTIONS §5).
    let approve = match e.get("approve") {
        None => VtcActScope::None,
        Some(v) => parse_scope(v, "approve")?,
    };
    let approve_capabilities = match e.get("approveCapabilities") {
        None => CapabilityScope::None,
        Some(v) => parse_capabilities(v)?,
    };
    if e.get("stepUp").is_some() {
        return Err(EntryParseError::Malformed(
            "this community keeps no per-entry step-up configuration — its step-up is bound to \
             each operation"
                .into(),
        ));
    }
    let community =
        ext_community_role(e.get("ext"))?.unwrap_or_else(|| VtcRole::implied_by(role.as_ref()));
    let mut entry = VtcAclEntry::new(
        subject,
        community,
        AdminAuthority {
            admin_role: role,
            act,
            capabilities,
            approve,
            approve_capabilities,
            // Resolved against the stored definition by `plan_write`, never
            // taken from the caller.
            custom: None,
        },
        "",
    );
    entry.label = e.get("label").and_then(Value::as_str).map(str::to_string);
    entry.expires_at = e
        .get("expiresAt")
        .and_then(Value::as_str)
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|t| t.timestamp() as u64)
                .map_err(|e| EntryParseError::Malformed(format!("expiresAt: {e}")))
        })
        .transpose()?;
    Ok(entry)
}

/// `acl/grant/0.2`: plan the entry the payload describes. A grant to an
/// existing subject with a different role is refused (`acl/change-role`), and
/// one that would narrow the existing entry is refused too: a grant never
/// narrows (`acl/grant/0.2` item 6).
pub(crate) async fn plan_grant_v0_2(
    state: &AppState,
    actor_did: &str,
    next: VtcAclEntry,
    reason: Option<String>,
) -> Result<GrantPlan, WriteError> {
    let existing = get_acl_entry(&state.acl_ks, &next.did).await?;
    if let Some(prev) = existing.as_ref() {
        if prev.admin.admin_role != next.admin.admin_role {
            return Err(AppError::Forbidden(format!(
                "{} already holds role {}; role changes use acl/change-role/0.2",
                next.did,
                role_string(prev)
            ))
            .into());
        }
        if next.admin.narrows_from(&prev.admin) {
            return Err(AppError::Forbidden(format!(
                "this grant would narrow {}'s entry; a grant never narrows — use acl/update/0.2 \
                 or acl/revoke/0.2",
                next.did
            ))
            .into());
        }
    }
    plan_write(state, actor_did, next, existing, PlanEvent::Granted, reason).await
}

/// The 0.2 role string of an entry.
pub(crate) fn role_string(e: &VtcAclEntry) -> String {
    e.admin
        .admin_role
        .as_ref()
        .map(|r| r.to_string())
        .unwrap_or_else(|| NO_ADMIN_ROLE.into())
}

/// `acl/update/0.2`: the existing entry with the payload's replacements.
/// Narrowing the act scope is a revocation (`narrowingNotPermitted`); every
/// other axis may narrow here, and a narrowing is a privilege reduction.
pub(crate) async fn plan_update_v0_2(
    state: &AppState,
    actor_did: &str,
    payload: &Value,
) -> Result<GrantPlan, UpdateV02Error> {
    use trust_tasks_rs::specs::acl::update::v0_2::error_codes;
    let subject = payload["subject"].as_str().unwrap_or_default().to_string();
    // A subject's own entry is decided by `plan_write` (VTI-ACL-052).
    let existing = existing_for_update(state, &subject, error_codes::NOT_FOUND.code)
        .await
        .map_err(|e| UpdateV02Error::Write(e.into()))?;
    let mut next = existing.clone();
    if let Some(v) = payload.get("act") {
        let act = parse_scope(v, "act").map_err(UpdateV02Error::Parse)?;
        if existing.admin.act.is_all() && act == VtcActScope::None {
            return Err(UpdateV02Error::NarrowingNotPermitted);
        }
        next.admin.act = act;
    }
    if let Some(v) = payload.get("approve") {
        next.admin.approve = parse_scope(v, "approve").map_err(UpdateV02Error::Parse)?;
    }
    if let Some(v) = payload.get("capabilities") {
        next.admin.capabilities = parse_capabilities(v).map_err(UpdateV02Error::Parse)?;
    }
    if let Some(v) = payload.get("approveCapabilities") {
        next.admin.approve_capabilities = parse_capabilities(v).map_err(UpdateV02Error::Parse)?;
    }
    if let Some(v) = payload.get("keys") {
        parse_keys(v).map_err(UpdateV02Error::Parse)?;
    }
    if payload.get("stepUp").is_some() {
        return Err(UpdateV02Error::Parse(EntryParseError::Malformed(
            "this community keeps no per-entry step-up configuration".into(),
        )));
    }
    match payload.get("label") {
        None => {}
        Some(Value::Null) => next.label = None,
        Some(v) => next.label = v.as_str().map(str::to_string),
    }
    match payload.get("expiresAt") {
        None => {}
        Some(Value::Null) => next.expires_at = None,
        Some(v) => {
            next.expires_at = Some(
                v.as_str()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|t| t.timestamp() as u64)
                    .ok_or_else(|| {
                        UpdateV02Error::Parse(EntryParseError::Malformed(
                            "expiresAt is an RFC 3339 date-time".into(),
                        ))
                    })?,
            )
        }
    }
    if let Some(role) = ext_community_role(payload.get("ext")).map_err(UpdateV02Error::Parse)? {
        next.role = role;
    }
    let reason = payload["reason"].as_str().map(str::to_string);
    plan_write(
        state,
        actor_did,
        next,
        Some(existing),
        PlanEvent::Updated,
        reason,
    )
    .await
    .map_err(UpdateV02Error::Write)
}

/// Why `acl/update/0.2` refused.
pub(crate) enum UpdateV02Error {
    Parse(EntryParseError),
    NarrowingNotPermitted,
    Write(WriteError),
}

// ---------- acl/change-role ----------

/// Canonical `acl/change-role` request: a **community** role move, with
/// `fromRole` as a compare-and-swap guard. The administrative authority follows
/// the role under the 0.1 convention ([`VtcRole::implied_authority`]).
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateAclRequest {
    pub from_role: VtcRole,
    pub to_role: VtcRole,
    /// Operator rationale, emitted on the service log line for this change.
    #[serde(default)]
    pub reason: Option<String>,
}

/// What [`change_role_inner`] produced.
#[derive(Debug)]
pub(crate) enum ChangeRoleOutcome {
    Changed(Box<AclEntryEnvelope>),
    /// A promotion that needs a gesture bound to it, and has none yet. Nothing
    /// was written.
    StepUpRequired(Box<crate::acl::bound_step_up::ApproveRequest>),
}

/// `acl/change-role/0.1`: the community role-change ceremony, carrying the
/// administrative authority the role implies.
///
/// The ceremony owns the role-change policy, the role-VAC re-mint and the
/// promotion serialisation; the granting bounds (§6.3), the consent for an
/// authority-conferring capability (**VTI-APV-018**) and the reduction gate
/// (**VTI-APV-019**) run inside it ([`crate::ceremony::role_change_via_pipeline`]).
pub(crate) async fn change_role_inner(
    state: &AppState,
    actor: &AuthClaims,
    did: &str,
    req: UpdateAclRequest,
    source: crate::ceremony::StepUpSource<'_>,
) -> Result<ChangeRoleOutcome, AppError> {
    let did = did.to_string();
    // VTI-ACL-052: in either direction. A role move is not a label (item 2),
    // and item 3 is carried by `acl/update/0.2` and `acl/change-role/0.2`,
    // whose shared plan (`plan_self_write`) holds the unrestricted-entry
    // invariant; this door runs the role-change ceremony, which does not.
    if actor.did == did {
        return Err(own_role_refusal(
            crate::acl::admin_consent::single_admin_mode(state).await,
        ));
    }
    let op_payload = {
        let mut v = serde_json::to_value(&req)
            .map_err(|e| AppError::Internal(format!("serialise acl/change-role body: {e}")))?;
        if let Some(map) = v.as_object_mut() {
            map.insert("subject".into(), Value::String(did.clone()));
        }
        v
    };
    let acl = state.acl_ks.clone();
    let entry = get_acl_entry(&acl, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    if entry.role != req.from_role {
        return Err(AppError::Conflict(format!(
            "state mismatch: {did} currently holds role {}, not {}",
            entry.role, req.from_role
        )));
    }
    if !expressible_in_v0_1(&entry) {
        return Err(inexpressible(&did, "moved"));
    }
    let actor_e = actor_entry(state, &actor.did).await?;
    if !granting::covers_entry(&actor_e, &entry, now_epoch()) {
        return Err(not_covered(&did, "change the role of"));
    }

    req.to_role.refuse_unassignable()?;
    let promoting = matches!(req.to_role, VtcRole::Admin);
    let granted = match source {
        crate::ceremony::StepUpSource::Session { .. } => {
            crate::ceremony::role_change_via_pipeline(
                state,
                actor,
                &did,
                &entry.role.to_string(),
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
                &entry.role.to_string(),
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

    // The ceremony's executor owns the write; re-read and stamp provenance.
    let mut written = get_acl_entry(&acl, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    written.updated_at = Some(now_epoch());
    written.updated_by = Some(actor.did.clone());
    if written.admin.is_administrator() && written.admin != entry.admin {
        written.delegated_by = Some(actor.did.clone());
    }
    store_acl_entry(&acl, &written).await?;

    if written.admin.is_administrator() {
        ensure_admin_sister_record(state, &did).await?;
    }
    let reduced = written.admin.narrows_from(&entry.admin);
    if reduced {
        let revoked = super::auth::revoke_sessions_for_did(&state.sessions_ks, &did).await?;
        info!(did = %did, revoked, "subject sessions revoked after ACL privilege reduction");
        delegation::on_granter_changed(state, &did, Some(&written)).await?;
    }
    delegation::clear(state, &did).await?;

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &actor.did,
                Some(&did),
                AuditEvent::AclUpdated(audit_data(&written)),
            )
            .await?;
        if promoting {
            writer
                .write(
                    &actor.did,
                    Some(&did),
                    AuditEvent::AdminPromoted(AdminPromotedData {
                        previous_role: granted.previous_role.clone(),
                        authorising_credential_id: String::new(),
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
        entry: AclEntryResponse::v0_1(written),
    })))
}

/// The admin sister record that lets a new administrator enrol a device for
/// the console. Empty credential list until `admin/passkeys/register` runs.
pub(crate) async fn ensure_admin_sister_record(
    state: &AppState,
    did: &str,
) -> Result<(), AppError> {
    use crate::acl::admin::{AdminEntry, get_admin_entry, store_admin_entry};
    if get_admin_entry(&state.passkey_ks, did).await?.is_none() {
        store_admin_entry(
            &state.passkey_ks,
            &AdminEntry {
                did: did.to_string(),
                passkeys: Vec::new(),
                extensions: Value::Null,
                created_at: Utc::now(),
            },
        )
        .await?;
    }
    Ok(())
}

/// `acl/change-role/0.2`: move the **administrative** role, with the current
/// role as a compare-and-swap. Every other axis is carried over and re-checked
/// against the new role's ceiling; the community role is unchanged.
pub(crate) async fn plan_change_role_v0_2(
    state: &AppState,
    actor_did: &str,
    subject: &str,
    from: &str,
    to: Option<AdminRole>,
) -> Result<GrantPlan, ChangeRoleV02Error> {
    let existing = get_acl_entry(&state.acl_ks, subject)
        .await?
        .ok_or_else(|| {
            ChangeRoleV02Error::Write(
                AppError::NotFound(format!("ACL entry not found for DID: {subject}")).into(),
            )
        })?;
    let current = role_string(&existing);
    if current != from {
        return Err(ChangeRoleV02Error::StateMismatch(current));
    }
    let mut next = existing.clone();
    next.admin.admin_role = to;
    plan_write(
        state,
        actor_did,
        next,
        Some(existing),
        PlanEvent::Updated,
        None,
    )
    .await
    .map_err(ChangeRoleV02Error::Write)
}

/// Why `acl/change-role/0.2` refused.
pub(crate) enum ChangeRoleV02Error {
    StateMismatch(String),
    Write(WriteError),
}

impl From<AppError> for ChangeRoleV02Error {
    fn from(e: AppError) -> Self {
        ChangeRoleV02Error::Write(e.into())
    }
}

// ---------- acl/revoke ----------

/// The generated `acl/revoke/0.1` response.
fn revoke_response(
    entry: Option<AclEntryResponse>,
) -> Result<vta_sdk::openapi::AclRevoke01Response, TaskError> {
    serde_json::to_value(&entry)
        .and_then(|entry| serde_json::from_value(json!({ "entry": entry })))
        .map(vta_sdk::openapi::AclRevoke01Response)
        .map_err(|e| AppError::Internal(format!("acl/revoke response: {e}")).into())
}

/// `acl/revoke/0.1`. `scopes: Some` names scopes to drop — a community entry
/// holds none, so it is refused as naming nothing held. `None` removes the
/// entry ([`remove_entry`]).
pub(crate) async fn revoke_entry(
    state: &AppState,
    actor: &AuthClaims,
    did: &str,
    scopes: Option<&[String]>,
    reason: Option<&str>,
    op: crate::acl::admin_consent::Operation<'_>,
) -> Result<vta_sdk::openapi::AclRevoke01Response, TaskError> {
    use trust_tasks_rs::specs::acl::revoke::v0_1::error_codes;
    if let Some(scopes) = scopes {
        return Err(AppError::NotFound(format!(
            "none of the requested scopes ({}) are held by {did}: a community entry holds no \
             contexts (VTI-VTC-010)",
            scopes.join(", ")
        ))
        .into());
    }
    remove_entry(
        state,
        &actor.did,
        did,
        reason,
        op,
        error_codes::SUBJECT_NOT_PRESENT.code,
        error_codes::LAST_AUTHORITY_PROTECTED.code,
    )
    .await?;
    revoke_response(None)
}

/// Remove `did`'s entry: every door's full revocation.
///
/// Refused for the caller's own entry, an entry it does not wholly cover
/// (**VTI-ACL-050**), a member (the leave ceremony removes members), and the
/// last holder of `vtc.roles.assign` (**VTI-APV-009**). Removing an
/// administrator takes the requester's gesture, and taking authority-conferring
/// capabilities away takes the consent of their other holders
/// (**VTI-APV-019**).
pub(crate) async fn remove_entry(
    state: &AppState,
    actor_did: &str,
    did: &str,
    reason: Option<&str>,
    op: crate::acl::admin_consent::Operation<'_>,
    not_present_code: &'static str,
    last_authority_code: &'static str,
) -> Result<(), TaskError> {
    let did = did.to_string();
    if actor_did == did {
        return Err(AppError::Conflict("cannot delete your own ACL entry".into()).into());
    }
    let acl = state.acl_ks.clone();
    let not_present = || {
        TaskError::declared(
            not_present_code,
            AppError::NotFound(format!("ACL entry not found for DID: {did}")),
        )
    };
    let Some(entry) = get_acl_entry(&acl, &did).await? else {
        return Err(not_present());
    };
    let actor = actor_entry(state, actor_did).await?;
    if !granting::covers_entry(&actor, &entry, now_epoch()) {
        return Err(not_covered(&did, "revoke").into());
    }
    let prior = entry.clone();

    // Revoking the ACL of a **member** would orphan their member row and leave
    // their credentials unrevoked; the leave ceremony removes members.
    if let Some(member) = get_member(&state.members_ks, &did).await?
        && !member.is_removed()
    {
        return Err(AppError::Conflict(format!(
            "{did} is a member of this community — revoking their ACL entry would leave the \
             member row with no authorization and their membership credentials unrevoked. \
             To remove them from the community, use the leave ceremony instead: \
             vtc/members/admin-remove for {did}"
        ))
        .into());
    }

    let attrition = |e: AppError| match e {
        AppError::Conflict(_) => TaskError::declared(last_authority_code, e),
        other => TaskError::App(other),
    };
    let now = now_epoch();
    if crate::acl::admin_consent::is_live_role_assigner(&prior, now) {
        crate::acl::admin_consent::check_attrition(state, &did)
            .await
            .map_err(attrition)?;
    }
    let agreement = crate::acl::admin_consent::settle_reduction(
        state,
        actor_did,
        &prior,
        None,
        op,
        &format!("Remove administrator {did} from this community's ACL"),
        &format!("Remove administrator {did}"),
    )
    .await?;

    let _admin_set = crate::ceremony::lock_admin_set().await;
    if let Some(live) = get_acl_entry(&acl, &did).await?
        && crate::acl::admin_consent::is_live_role_assigner(&live, now_epoch())
    {
        crate::acl::admin_consent::check_attrition(state, &did)
            .await
            .map_err(attrition)?;
    }
    delete_acl_entry(&acl, &did).await?;
    crate::admin_actions::record_effect(state).await;
    drop(_admin_set);

    let revoked = super::auth::revoke_sessions_for_did(&state.sessions_ks, &did).await?;
    delegation::clear(state, &did).await?;
    delegation::on_granter_changed(state, &did, None).await?;

    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                actor_did,
                Some(&did),
                AuditEvent::AclRevoked(AclRevokedData {
                    did: did.clone(),
                    prior_role: Some(role_string(&entry)),
                }),
            )
            .await?;
    }

    // The removed administrator is told — `revoked`, and whether anyone else
    // agreed — and an unopposed removal is recorded at the highest severity
    // (VTI-APV-019). After the write, so a refusal under the lock leaves no row
    // or notice claiming it happened. A member is never revoked here (refused
    // above in favour of the leave ceremony), so this is never a removal from
    // the community and never sent beside the removal notice.
    if let Some(agreement) = agreement {
        crate::acl::admin_consent::after_reduction(
            state,
            actor_did,
            &prior,
            None,
            agreement,
            op.type_uri,
            reason,
            true,
        )
        .await?;
    }
    info!(
        caller = %actor_did,
        did = %did,
        revoked,
        reason = reason.unwrap_or(""),
        "ACL entry revoked",
    );
    Ok(())
}

/// `acl/revoke/0.2` with `{kind: act}`: narrow the act scope. At a community
/// node that is `all` → `none`.
pub(crate) async fn plan_narrow_act(
    state: &AppState,
    actor_did: &str,
    did: &str,
    act: VtcActScope,
) -> Result<GrantPlan, NarrowActError> {
    let existing = get_acl_entry(&state.acl_ks, did)
        .await?
        .ok_or(NarrowActError::NotPresent)?;
    if !(existing.admin.act.is_all() && act == VtcActScope::None) {
        return Err(NarrowActError::NotNarrowing);
    }
    let mut next = existing.clone();
    next.admin.act = act;
    plan_write(
        state,
        actor_did,
        next,
        Some(existing),
        PlanEvent::Updated,
        None,
    )
    .await
    .map_err(NarrowActError::Write)
}

/// Why an act narrowing was refused.
pub(crate) enum NarrowActError {
    NotPresent,
    NotNarrowing,
    Write(WriteError),
}

impl From<AppError> for NarrowActError {
    fn from(e: AppError) -> Self {
        NarrowActError::Write(e.into())
    }
}

/// May `caller` act on `target` as an administrator of it — revoke its
/// sessions, read its standing? The caller's own entry must cover the target's
/// (**VTI-ACL-050**).
pub(crate) async fn caller_covers_target(
    state: &AppState,
    caller_did: &str,
    target: &VtcAclEntry,
) -> Result<bool, AppError> {
    Ok(match get_acl_entry(&state.acl_ks, caller_did).await? {
        Some(c) => granting::covers_entry(&c, target, now_epoch()),
        None => false,
    })
}

// ---------- acl/swap-key ----------

/// Why `acl/swap-key/0.1` refused — its declared codes, plus the generic ones.
#[derive(Debug)]
pub(crate) enum SwapError {
    /// `notHolder`: the signer is not `currentSubject` (VTI-CLT-027, -030).
    NotHolder(String),
    /// `subjectNotFound`: no live entry for `currentSubject`.
    SubjectNotFound(String),
    /// `subjectAlreadyInUse`: `newSubject` already has an entry or a
    /// membership.
    SubjectAlreadyInUse(String),
    /// `linkProofRequired`: this community requires the new key's consent.
    LinkProofRequired,
    /// `linkProofInvalid`, with the spec's `details.reason`.
    LinkProofInvalid(&'static str, String),
    App(AppError),
}

impl From<AppError> for SwapError {
    fn from(e: AppError) -> Self {
        SwapError::App(e)
    }
}

/// The longest a link proof may live (VTI-CLT-026: short-lived).
const LINK_PROOF_MAX_TTL_SECS: u64 = 900;

/// Roll `current`'s ACL entry to `new` — the subject's own self-service
/// rotation (**VTI-CLT-025 – 032**; the one exception **VTI-ACL-052** makes to
/// "no subject modifies its own entry").
///
/// - Only the subject itself, signing as `current` (no delegated console key):
///   a rotation is a change of name, and a name is changed only by its holder
///   (VTI-CLT-027, -030).
/// - `link_proof` — a VP-JWT signed by `new`, addressed to this community, and
///   short-lived — proves the new key consents and is held (VTI-CLT-026,
///   -028). It is **required**: without it a stolen `current` key could move
///   the entry to a key the thief holds.
/// - The successor carries **exactly** the predecessor's authority: role,
///   capabilities, approve scope, label, expiry and provenance are copied, not
///   re-derived, so a rotation can never be a grant (VTI-CLT-029). Delegations
///   naming `current` as their granter are re-pointed to `new`, so a rotation
///   is not a departure (§6.3).
/// - The rotation is audited **before** it commits, and not committed if it
///   cannot be (VTI-CLT-032), then committed as one move of the row that
///   succeeds only while the entry is exactly as read (VTI-CLT-025; concurrent
///   swaps serialise — one wins, the rest find `subjectNotFound`).
/// - Afterwards `current` has no standing: its sessions are revoked
///   (VTI-CLT-031).
pub(crate) async fn swap_key(
    state: &AppState,
    signer: &str,
    current: &str,
    new: &str,
    link_proof: Option<&Value>,
    reason: Option<&str>,
) -> Result<(VtcAclEntry, u32), SwapError> {
    if signer != current {
        return Err(SwapError::NotHolder(format!(
            "the document is signed by {signer}, not by {current}: only an entry's own subject \
             rolls it to a new key (VTI-CLT-027)"
        )));
    }
    if current == new {
        return Err(
            AppError::Validation("newSubject must differ from currentSubject".into()).into(),
        );
    }
    let now = now_epoch();
    let Some(entry) = get_acl_entry(&state.acl_ks, current).await? else {
        return Err(SwapError::SubjectNotFound(format!(
            "{current} has no ACL entry"
        )));
    };
    if entry.is_expired(now) {
        return Err(SwapError::SubjectNotFound(format!(
            "{current}'s ACL entry has expired; an expired entry confers nothing to roll \
             (VTI-ACL-004)"
        )));
    }
    if get_acl_entry(&state.acl_ks, new).await?.is_some()
        || get_member(&state.members_ks, new).await?.is_some()
    {
        return Err(SwapError::SubjectAlreadyInUse(format!(
            "{new} already has an ACL entry or a membership in this community"
        )));
    }

    // The new key's consent (VTI-CLT-026, -028).
    let proof = match link_proof {
        None => return Err(SwapError::LinkProofRequired),
        Some(Value::String(s)) => s.clone(),
        Some(_) => {
            return Err(SwapError::LinkProofInvalid(
                "format_unsupported",
                "this community accepts a link proof as a compact VP-JWT (an \
                 AclSwapRequest presentation signed by newSubject)"
                    .into(),
            ));
        }
    };
    verify_link_proof(state, &proof, new, now).await?;

    // VTI-CLT-029: everything but the subject is the predecessor's, verbatim.
    let mut successor = entry.clone();
    successor.did = new.to_string();
    successor.updated_at = Some(now);
    successor.updated_by = Some(current.to_string());

    let _admin_set = crate::ceremony::lock_admin_set().await;
    let old_key = format!("acl:{current}");
    let Some(expected) = state.acl_ks.get_raw(old_key.as_bytes()).await? else {
        return Err(SwapError::SubjectNotFound(format!(
            "{current} has no ACL entry"
        )));
    };
    // VTI-CLT-032 (and VTI-ACL-057 for its hand-off sibling): durably audited
    // before the commit, and not committed if it cannot be.
    let writer = state.audit_writer.as_ref().ok_or_else(|| {
        AppError::Internal("the audit log is not available, so nothing was rotated".into())
    })?;
    writer
        .write(
            current,
            Some(new),
            AuditEvent::AclKeyRotated(vti_common::audit::AclKeyRotatedData {
                old_did: current.to_string(),
                new_did: new.to_string(),
                role: role_string(&entry),
                reason: reason.map(str::to_string),
            }),
        )
        .await
        .map_err(|e| {
            AppError::Internal(format!(
                "the rotation could not be audited, so it was not made: {e}"
            ))
        })?;
    match state
        .acl_ks
        .move_if_unchanged(old_key, expected, format!("acl:{new}"), &successor)
        .await?
    {
        vti_common::store::MoveOutcome::Moved => {}
        vti_common::store::MoveOutcome::SourceMissing => {
            return Err(SwapError::SubjectNotFound(format!(
                "{current}'s entry was moved or removed concurrently"
            )));
        }
        vti_common::store::MoveOutcome::SourceChanged => {
            return Err(AppError::Conflict(format!(
                "{current}'s entry changed while it was being rotated; nothing was moved — send \
                 it again"
            ))
            .into());
        }
        vti_common::store::MoveOutcome::TargetExists => {
            return Err(SwapError::SubjectAlreadyInUse(format!(
                "{new} gained an ACL entry concurrently"
            )));
        }
    }
    drop(_admin_set);

    // The membership row follows the entry, as a member's own rotation moves it.
    if let Some(mut m) = get_member(&state.members_ks, current).await? {
        m.did = new.to_string();
        if !state
            .members_ks
            .swap(
                format!("members:{current}").into_bytes(),
                format!("members:{new}").into_bytes(),
                &m,
            )
            .await?
        {
            tracing::warn!(
                current,
                new,
                "the member row could not follow the rotated entry"
            );
        }
    }
    let repointed = delegation::repoint(state, current, new).await?;
    // VTI-CLT-031: the previous key has no standing.
    let revoked = super::auth::revoke_sessions_for_did(&state.sessions_ks, current).await?;
    info!(
        old = %current,
        new = %new,
        repointed,
        revoked,
        "ACL entry rolled to a new key (acl/swap-key)"
    );
    let mut written = successor;
    crate::acl::roles::resolve(&state.acl_ks, &mut written).await?;
    Ok((written, repointed))
}

/// Verify an `acl/swap-key` link proof: a VP-JWT (`AclSwapRequest`) signed by
/// `new`, addressed to this community, live and short-lived.
async fn verify_link_proof(
    state: &AppState,
    jws: &str,
    new: &str,
    now: u64,
) -> Result<(), SwapError> {
    use vta_sdk::protocols::acl_management::swap::{AclSwapError, AclSwapPresentation};
    let invalid = |reason: &'static str, m: String| SwapError::LinkProofInvalid(reason, m);
    let presentation = AclSwapPresentation::new(jws);
    let holder = presentation
        .peek_holder()
        .map_err(|e| invalid("format_unsupported", e.to_string()))?;
    if holder != new {
        return Err(invalid(
            "subject_mismatch",
            format!("the link proof is {holder}'s, not newSubject {new}'s"),
        ));
    }
    if let Some(exp) = link_proof_exp(jws)
        && exp > now.saturating_add(LINK_PROOF_MAX_TTL_SECS)
    {
        return Err(invalid(
            "expired",
            format!(
                "the link proof is valid until {exp}, longer than the {LINK_PROOF_MAX_TTL_SECS} s \
                 this community accepts (VTI-CLT-026: short-lived)"
            ),
        ));
    }
    let audience = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| AppError::Internal("this community has no DID to be addressed by".into()))?;
    let doc = new_subject_document(state, new).await?;
    presentation
        .verify(&doc, &audience, now)
        .map(|_| ())
        .map_err(|e| match e {
            AclSwapError::Expired { .. } => invalid("expired", e.to_string()),
            AclSwapError::WrongAudience { .. } => invalid("nonce_mismatch", e.to_string()),
            AclSwapError::HolderMismatch => invalid("subject_mismatch", e.to_string()),
            AclSwapError::Signature(_) => invalid("signature_invalid", e.to_string()),
            other => invalid("format_unsupported", other.to_string()),
        })
}

/// The `exp` a VP-JWT claims, unverified — only to bound its lifetime.
fn link_proof_exp(jws: &str) -> Option<u64> {
    use base64::Engine as _;
    let payload = jws.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice::<Value>(&bytes).ok()?["exp"].as_u64()
}

/// `new`'s DID document — built locally for a `did:key`, resolved otherwise.
async fn new_subject_document(state: &AppState, new: &str) -> Result<Value, SwapError> {
    if let Some(mb) = new.strip_prefix("did:key:") {
        return Ok(json!({
            "id": new,
            "verificationMethod": [{
                "id": format!("{new}#{mb}"),
                "type": "Multikey",
                "controller": new,
                "publicKeyMultibase": mb,
            }],
        }));
    }
    let resolver = state.did_resolver.as_ref().ok_or_else(|| {
        SwapError::LinkProofInvalid(
            "format_unsupported",
            format!("{new} cannot be resolved here: this community has no DID resolver"),
        )
    })?;
    let resolved = resolver.resolve(new).await.map_err(|e| {
        SwapError::LinkProofInvalid("signature_invalid", format!("resolve {new}: {e}"))
    })?;
    serde_json::to_value(&resolved.doc)
        .map_err(|e| AppError::Internal(format!("serialise {new}'s DID document: {e}")).into())
}

#[cfg(test)]
mod tests {
    //! Wire-shape tests for the ACL bodies and renderings.
    use super::*;

    fn entry(role: VtcRole, admin: AdminAuthority) -> VtcAclEntry {
        VtcAclEntry {
            did: "did:key:zABC".into(),
            role,
            label: Some("test".into()),
            admin,
            delegated_by: None,
            created_at: 1_700_000_000,
            created_by: "did:key:zSetup".into(),
            updated_at: None,
            updated_by: None,
            expires_at: Some(1_800_000_000),
            resource_grants: Vec::new(),
            label_set_by_subject: false,
        }
    }

    #[test]
    fn grant_request_parses_minimal_body() {
        let body = json!({ "entry": { "subject": "did:key:zABC", "role": "admin" } });
        let req: CreateAclRequest = serde_json::from_value(body).expect("minimal body");
        assert_eq!(req.entry.subject, "did:key:zABC");
        assert_eq!(req.entry.role, VtcRole::Admin);
        assert!(req.entry.scopes.is_empty(), "defaults to empty");
    }

    /// Server-owned provenance must not be settable by the caller.
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
        serde_json::from_value::<CreateAclRequest>(body).expect_err("unknown role must not parse");
    }

    #[test]
    fn change_role_request_requires_both_roles() {
        let ok: UpdateAclRequest =
            serde_json::from_value(json!({ "fromRole": "member", "toRole": "moderator" }))
                .expect("both roles");
        assert_eq!(ok.to_role, VtcRole::Moderator);
        serde_json::from_value::<UpdateAclRequest>(json!({ "toRole": "admin" }))
            .expect_err("fromRole is mandatory");
    }

    /// VTI-VTC-010: a 0.1 scope list names contexts a community does not hold.
    #[test]
    fn vti_vtc_010_a_0_1_scope_list_is_refused() {
        assert!(refuse_scopes(&[]).is_ok());
        assert!(matches!(
            refuse_scopes(&["ctx-a".into()]),
            Err(AppError::Validation(_))
        ));
    }

    /// CONVENTIONS §8: an entry renders to 0.1 only when its role says
    /// everything about its authority.
    #[test]
    fn only_a_conventional_entry_is_expressible_in_0_1() {
        assert!(expressible_in_v0_1(&entry(
            VtcRole::Admin,
            AdminAuthority::community_admin()
        )));
        assert!(expressible_in_v0_1(&entry(
            VtcRole::Member,
            AdminAuthority::none()
        )));
        assert!(expressible_in_v0_1(&entry(
            VtcRole::Issuer,
            AdminAuthority::for_role(AdminRole::CredentialOfficer)
        )));
        // A member holding the auditor role: 0.1 cannot say it.
        assert!(!expressible_in_v0_1(&entry(
            VtcRole::Member,
            AdminAuthority::for_role(AdminRole::Auditor)
        )));
        // A narrowed community-admin: 0.1 cannot say it.
        let mut narrow = AdminAuthority::community_admin();
        narrow.capabilities =
            CapabilityScope::listed(vec![CapRef::all(Capability::AuditRead).into()]).unwrap();
        assert!(!expressible_in_v0_1(&entry(VtcRole::Admin, narrow)));
    }

    #[test]
    fn a_0_1_rendering_has_canonical_names_and_no_scopes() {
        let json = serde_json::to_value(AclEntryResponse::v0_1(entry(
            VtcRole::Admin,
            AdminAuthority::community_admin(),
        )))
        .unwrap();
        assert_eq!(json["subject"], "did:key:zABC");
        assert_eq!(json["role"], "admin");
        assert_eq!(json["scopes"], json!([]));
        assert_eq!(json["createdAt"], "2023-11-14T22:13:20+00:00");
        assert_eq!(json["expiresAt"], "2027-01-15T08:00:00+00:00");
        for old in ["did", "allowed_contexts", "created_at", "expires_at"] {
            assert!(json.get(old).is_none(), "{old} should not be emitted");
        }
    }

    /// The 0.2 rendering conforms to the generated `acl/show/0.2` response,
    /// with every axis explicit.
    #[test]
    fn a_0_2_rendering_conforms_and_states_every_axis() {
        use trust_tasks_rs::specs::acl::show::v0_2 as show;
        let mut admin = AdminAuthority::for_role(AdminRole::RepoManager);
        admin.capabilities = CapabilityScope::listed(vec![
            "git.repo.manage@git-ns:github.com/acme"
                .parse::<CapRef>()
                .unwrap()
                .into(),
        ])
        .unwrap();
        let mut e = entry(VtcRole::Member, admin);
        e.delegated_by = Some("did:key:zGranter".into());
        let review = DelegationReview {
            subject: e.did.clone(),
            granter: "did:key:zGranter".into(),
            raised_at: 1,
            deadline: 2,
        };
        let v = render_v0_2(&e, Some(&review));
        assert_eq!(v["role"], "repo-manager");
        assert_eq!(v["act"], json!({"scope": "all"}));
        assert_eq!(v["keys"], json!({"scope": "none"}));
        assert_eq!(v["approve"], json!({"scope": "all"}));
        assert_eq!(v["delegatedBy"], "did:key:zGranter");
        assert_eq!(v["ext"]["org.openvtc"]["communityRole"], "member");
        assert_eq!(
            v["ext"]["org.openvtc"]["delegationReview"]["granter"],
            "did:key:zGranter"
        );
        let _: show::Response = conform(json!({ "entry": v })).expect("conforms");
        // No administrative role renders as `member`.
        let plain = render_v0_2(&entry(VtcRole::Member, AdminAuthority::none()), None);
        assert_eq!(plain["role"], "member");
        let _: show::Response = conform(json!({ "entry": plain })).expect("conforms");
    }

    /// Phase C3: an entry's git rights render as resource grants in `ext`,
    /// each with its granter and grade — never the granter's reason, which
    /// only those governing the resource see (`git-ns/view`).
    #[test]
    fn resource_grants_render_in_ext_without_their_reason() {
        use trust_tasks_rs::specs::acl::show::v0_2 as show;
        let mut e = entry(VtcRole::Member, AdminAuthority::none());
        e.resource_grants
            .push(crate::acl::resource_grant::ResourceGrant {
                capability: Capability::GitRepoManage,
                resource: "git-repo:github.com/acme/repo_1".parse().unwrap(),
                grade: Some(crate::acl::resource_grant::RepoGrade::Own),
                delegated_by: "did:key:zGranter".into(),
                granted_at: "2026-10-01T00:00:00Z".parse().unwrap(),
                expires_at: None,
                reason: Some("private reason".into()),
                subject_was_member: true,
                granter_was_member: true,
                break_glass: None,
                review: None,
                single_admin: None,
            });
        let v = render_v0_2(&e, None);
        let g = &v["ext"]["org.openvtc"]["resourceGrants"][0];
        assert_eq!(g["capability"], "git.repo.manage");
        assert_eq!(g["resource"], "git-repo:github.com/acme/repo_1");
        assert_eq!(g["grade"], "own");
        assert_eq!(g["delegatedBy"], "did:key:zGranter");
        assert!(!v.to_string().contains("private reason"));
        let _: show::Response = conform(json!({ "entry": v })).expect("conforms");
    }

    #[test]
    fn a_0_2_entry_parses_onto_the_model() {
        let e = entry_from_v0_2(&json!({
            "subject": "did:key:zS",
            "role": "vetting-lead",
            "act": {"scope": "all"},
            "keys": {"scope": "none"},
            "capabilities": {"scope": "listed", "grants": [
                {"capability": "vtc.vetting.manage", "resource": "criterion:age-over-18"}
            ]},
        }))
        .ok()
        .unwrap();
        assert_eq!(e.admin.admin_role, Some(AdminRole::VettingLead));
        assert_eq!(e.admin.approve, VtcActScope::None, "absent approve is none");
        assert_eq!(e.role, VtcRole::Member);

        // A name that is no built-in reads as a custom role, and is
        // recognised only once resolved against a stored definition
        // (`plan_write`); unresolved, it is refused (VTI-ACL-011).
        let custom = entry_from_v0_2(&json!({
            "subject": "did:key:zS", "role": "godmode",
            "act": {"scope": "all"}, "keys": {"scope": "none"},
            "capabilities": {"scope": "ceiling"},
        }))
        .ok()
        .unwrap();
        assert_eq!(
            custom.admin.admin_role,
            Some(AdminRole::Custom("godmode".into()))
        );
        assert!(matches!(
            custom.admin.validate_against_ceiling(),
            Err(crate::acl::capability::CeilingError::RoleNotRecognized(_))
        ));
        assert!(matches!(
            entry_from_v0_2(&json!({
                "subject": "did:key:zS", "role": "Not A Role",
                "act": {"scope": "all"}, "keys": {"scope": "none"},
                "capabilities": {"scope": "ceiling"},
            })),
            Err(EntryParseError::RoleNotRecognized(_))
        ));
        assert!(matches!(
            entry_from_v0_2(&json!({
                "subject": "did:key:zS", "role": "auditor",
                "act": {"scope": "contexts", "contexts": ["a"]}, "keys": {"scope": "none"},
                "capabilities": {"scope": "ceiling"},
            })),
            Err(EntryParseError::InvalidActScope("act", _))
        ));
        assert!(matches!(
            entry_from_v0_2(&json!({
                "subject": "did:key:zS", "role": "auditor",
                "act": {"scope": "all"}, "keys": {"scope": "none"},
                "capabilities": {"scope": "listed", "grants": [{"capability": "vtc.everything"}]},
            })),
            Err(EntryParseError::UnknownCapability(_))
        ));
    }
}
