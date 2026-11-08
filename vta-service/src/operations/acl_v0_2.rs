//! The VTA as an AclEntry **0.2** maintainer — `acl/{grant,show,update,
//! change-role,revoke}/0.2` and `acl/list/0.3`.
//!
//! # The explicit model, over the stored one
//!
//! 0.2 states every authority axis explicitly (`acl/_shared/0.2` CONVENTIONS
//! §4–§5). The VTA stores an entry as `(role, allowed_contexts, capabilities,
//! approve_scope, allowed_keys)`, where an empty `allowed_contexts` is
//! unrestricted for `admin` and nowhere for every other role. So each 0.2
//! value maps to exactly one stored value, or to none — and a value the VTA
//! cannot hold is **refused** (`invalidActScope` for act and approve scopes,
//! grant item 2), never approximated:
//!
//! | 0.2 | stored |
//! |---|---|
//! | `act: all` | `allowed_contexts: []` on `admin`; refused on any other role |
//! | `act: none` | `allowed_contexts: []` on a non-admin role; refused on `admin` |
//! | `act: contexts` | `allowed_contexts: contexts` |
//! | `capabilities: ceiling` | `capabilities: []` (no additive grant) |
//! | `capabilities: listed` | the listed names — refused when only additive grants are listed, which 0.2 reads as *no* role capability and the store as the whole role |
//! | `capabilities: none` | refused: the store has no "nothing" |
//! | `approve: none`, or any approve with `approveCapabilities` absent/`none` | `ApproveScope::None` — both confer nothing |
//! | `approve: all|contexts` with `approveCapabilities: ceiling` | `ApproveScope::All|Contexts` |
//! | `approveCapabilities: listed` | refused: the VTA's approve authority has no capability axis |
//! | `keys` | `allowed_keys`: `all` → no filter, `none` → `Some(∅)`, `listed` → the ids |
//!
//! A resource qualifier is refused: the VTA's capabilities name no resource.
//!
//! Because role and act scope are independent in 0.2 (§4 rule 3), nothing
//! here computes one from the other: `acl/change-role/0.2` carries the act
//! scope across unchanged, and refuses a move whose resulting `(role, act)`
//! the store cannot hold — promoting an entry that acts nowhere to `admin`
//! would otherwise make it a super-administrator, exactly the inference 0.2
//! exists to remove.

use std::collections::BTreeSet;

use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;
use vta_sdk::protocols::acl_management::create::CreateAclResultBody;
use vta_sdk::protocols::acl_management::entry::StepUp;
use vta_sdk::protocols::acl_management::v0_2::{
    AclEntry as WireEntry, ApproveCapabilityScope, AuthorityScope, CapabilityGrant,
    CapabilityScope, KeyScope, ListDirection, Revocation, StepUpReplacement,
};

use super::acl::{self as v1, CreateAclParams, UpdateAclParams};
use crate::acl::{
    AclEntry, ApproveScope, Capability, ContextDirection, Role, act_scope_for,
    capabilities_beyond_role, derived_capabilities_for_role, effective_capabilities, get_acl_entry,
    is_acl_entry_auditable, is_additive, list_acl_entries,
};
use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Why a 0.2 request was refused, in terms each handler maps onto the codes
/// its own task declares (CONVENTIONS §3).
#[derive(Debug)]
#[non_exhaustive]
pub enum V02Error {
    /// A role outside `admin | initiator | application | reader | monitor`.
    RoleNotRecognized(String),
    /// An act or approve scope this VTA cannot hold. `member` is `act` or
    /// `approve`.
    InvalidActScope {
        member: &'static str,
        reason: String,
    },
    /// Capabilities this VTA does not recognise.
    UnknownCapability(Vec<String>),
    /// Non-additive capabilities outside the role's ceiling (or an additive
    /// capability not marked so — no role carries it).
    CapabilityOutsideCeiling { role: String, caps: Vec<String> },
    /// `additive: true` on a capability the role's ceiling includes.
    AdditiveWithinCeiling(Vec<String>),
    /// A value the store has no form for that no declared code names.
    Unsupported(String),
    /// `acl/update/0.2` was asked to narrow `act`.
    NarrowingNotPermitted,
    /// `acl/revoke/0.2` was given an act scope not strictly narrower.
    NotNarrowing,
    /// `acl/update/0.2` / `acl/revoke/0.2` named an unknown subject.
    NotFound(String),
    /// `acl/change-role/0.2`'s compare-and-swap failed.
    StateMismatch(String),
    /// `acl/list/0.3` cursor minted under other filters, or not here.
    CursorMismatch,
    /// Everything the shared operations refuse.
    App(AppError),
}

impl From<AppError> for V02Error {
    fn from(e: AppError) -> Self {
        match e {
            AppError::InvalidCursor => Self::CursorMismatch,
            e => Self::App(e),
        }
    }
}

// ─── reading the stored entry out as 0.2 ─────────────────────────────────

fn to_rfc3339(epoch: u64) -> Option<DateTime<Utc>> {
    i64::try_from(epoch)
        .ok()
        .and_then(|s| Utc.timestamp_opt(s, 0).single())
}

fn to_epoch(ts: DateTime<Utc>) -> u64 {
    u64::try_from(ts.timestamp()).unwrap_or(0)
}

fn cap_name(c: Capability) -> String {
    serde_json::to_value(c)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The stored capability list as an explicit 0.2 scope.
///
/// The one stored shape 0.2 has no direct spelling for is "the whole role plus
/// an additive grant" (a list naming only additive capabilities): 0.2's
/// `listed` reads the non-additive part as the narrowing, so it is rendered as
/// the role's ceiling enumerated, plus the additive grants. The effective set
/// is identical.
fn capability_scope(role: &Role, caps: &[Capability]) -> CapabilityScope {
    if caps.is_empty() {
        return CapabilityScope::Ceiling;
    }
    let narrowing: Vec<Capability> = caps.iter().copied().filter(|c| !is_additive(*c)).collect();
    let mut grants: Vec<CapabilityGrant> = if narrowing.is_empty() {
        derived_capabilities_for_role(role)
            .into_iter()
            .map(|c| CapabilityGrant::new(cap_name(c), false))
            .collect()
    } else {
        narrowing
            .into_iter()
            .map(|c| CapabilityGrant::new(cap_name(c), false))
            .collect()
    };
    grants.extend(
        caps.iter()
            .copied()
            .filter(|c| is_additive(*c))
            .map(|c| CapabilityGrant::new(cap_name(c), true)),
    );
    if grants.is_empty() {
        // A role with an empty ceiling and nothing additive holds nothing.
        CapabilityScope::None
    } else {
        CapabilityScope::Listed { grants }
    }
}

/// A stored entry, every axis explicit (show item 2).
pub(crate) fn render(e: &AclEntry) -> WireEntry {
    let act = AuthorityScope::from_act_scope(&e.act_scope());
    let keys = KeyScope::from_allowed_keys(
        e.allowed_keys
            .as_ref()
            .map(|k| k.iter().cloned().collect::<Vec<_>>())
            .as_deref(),
    );
    let mut out = WireEntry::new(
        e.did.clone(),
        e.role.to_string(),
        act,
        keys,
        capability_scope(&e.role, &e.capabilities),
    );
    // Stated even when it confers nothing (grant producer item 2's SHOULD,
    // applied to what this maintainer emits).
    out.approve = Some(AuthorityScope::from_approve_scope(&e.approve_scope));
    // The VTA's approve authority has no capability axis: whatever it confers
    // it confers for the role's whole approve ceiling.
    if !e.approve_scope.confers_nothing() {
        out.approve_capabilities = Some(ApproveCapabilityScope::Ceiling);
    }
    out.label = e.label.clone();
    out.created_at = to_rfc3339(e.created_at);
    out.created_by = Some(e.created_by.clone());
    // `created_by` is the granter (VTI-ACL-053 bounds every write by it);
    // a bootstrap row's creator is not a DID and is no delegator.
    out.delegated_by = e
        .created_by
        .starts_with("did:")
        .then(|| e.created_by.clone());
    out.expires_at = e.expires_at.and_then(to_rfc3339);
    let step_up = StepUp {
        approver: e.step_up_approver.clone().filter(|a| !a.is_empty()),
        require: None,
    };
    out.step_up = step_up.approver.is_some().then_some(step_up);
    if e.handoff.is_some() {
        out.ext = vta_sdk::protocols::acl_management::entry::handoff_into_ext(None, true);
    }
    out
}

/// Re-read the row an operation wrote and render it. The shared operations
/// answer in the flat result body, which has lost nothing but is not the
/// stored type; reading the row back renders what is actually held.
async fn render_stored(acl_ks: &KeyspaceHandle, did: &str) -> Result<WireEntry, V02Error> {
    get_acl_entry(acl_ks, did)
        .await?
        .map(|e| render(&e))
        .ok_or_else(|| {
            V02Error::App(AppError::Internal(format!(
                "the ACL entry for {did} vanished after it was written"
            )))
        })
}

fn render_result(r: &CreateAclResultBody) -> Result<WireEntry, V02Error> {
    let role = parse_role(&r.role)?;
    let mut e = AclEntry::new(&r.did, role, &r.created_by);
    e.label = r.label.clone();
    e.allowed_contexts = r.allowed_contexts.clone();
    e.created_at = r.created_at;
    e.expires_at = r.expires_at;
    e.step_up_approver = r.step_up_approver.clone();
    e.approve_scope = if r.approve_all_contexts {
        ApproveScope::All
    } else if r.approve_contexts.is_empty() {
        ApproveScope::None
    } else {
        ApproveScope::Contexts(r.approve_contexts.clone())
    };
    e.allowed_keys = r
        .allowed_keys
        .as_ref()
        .map(|k| k.iter().cloned().collect::<BTreeSet<_>>());
    e.capabilities = v1::parse_capability_names(&r.capabilities)?;
    Ok(render(&e))
}

// ─── reading a 0.2 value into the stored form ────────────────────────────

fn parse_role(raw: &str) -> Result<Role, V02Error> {
    Role::parse(raw).map_err(|_| V02Error::RoleNotRecognized(raw.to_string()))
}

/// The VTA's role vocabulary, for `roleNotRecognized`'s `knownRoles`.
pub const KNOWN_ROLES: &[&str] = &["admin", "initiator", "application", "reader", "monitor"];

/// `act` as the stored `allowed_contexts` for `role`, or why it cannot be held.
fn act_contexts(role: &Role, act: &AuthorityScope) -> Result<Vec<String>, V02Error> {
    match (act, role) {
        (AuthorityScope::All, Role::Admin) => Ok(Vec::new()),
        (AuthorityScope::All, _) => Err(V02Error::InvalidActScope {
            member: "act",
            reason: format!(
                "this VTA holds an unrestricted act scope only on the admin role; a {role} entry \
                 acts in named contexts or nowhere"
            ),
        }),
        (AuthorityScope::None, Role::Admin) => Err(V02Error::InvalidActScope {
            member: "act",
            reason: "this VTA cannot hold an admin entry that acts nowhere; a least-privilege \
                     approver is a non-admin role with act none and an approve scope"
                .into(),
        }),
        (AuthorityScope::None, _) => Ok(Vec::new()),
        (AuthorityScope::Contexts { contexts }, _) => {
            if contexts.is_empty() {
                // The schema refuses it; a path that skipped validation must
                // not read it as either all or none (CONVENTIONS §4 rule 1).
                return Err(V02Error::App(AppError::Validation(
                    "act.contexts is empty; state {\"scope\":\"none\"} or name a context".into(),
                )));
            }
            for c in contexts {
                vti_common::context_path::validate_context_path(c).map_err(V02Error::App)?;
            }
            Ok(contexts.clone())
        }
    }
}

/// `approve` + `approveCapabilities` as the stored [`ApproveScope`].
fn approve_scope(
    approve: Option<&AuthorityScope>,
    approve_caps: Option<&ApproveCapabilityScope>,
) -> Result<ApproveScope, V02Error> {
    if let Some(ApproveCapabilityScope::Listed { .. }) = approve_caps {
        return Err(V02Error::Unsupported(
            "this VTA's approve authority has no capability axis: approveCapabilities is \
             `ceiling` (approve whatever the approve scope reaches) or `none`"
                .into(),
        ));
    }
    let scope = match approve {
        None => ApproveScope::None,
        Some(a) => {
            if let AuthorityScope::Contexts { contexts } = a {
                if contexts.is_empty() {
                    return Err(V02Error::App(AppError::Validation(
                        "approve.contexts is empty; state {\"scope\":\"none\"} or name a context"
                            .into(),
                    )));
                }
                for c in contexts {
                    vti_common::context_path::validate_context_path(c).map_err(V02Error::App)?;
                }
            }
            a.to_approve_scope()
        }
    };
    // Absent or `none` approvable capabilities confer nothing whatever the
    // scope says (CONVENTIONS §7 rule 2), so the stored scope is none too.
    Ok(match approve_caps {
        Some(ApproveCapabilityScope::Ceiling) => scope,
        _ => ApproveScope::None,
    })
}

/// `capabilities` as the stored list for `role` (grant item 3).
fn capabilities(role: &Role, scope: &CapabilityScope) -> Result<Vec<Capability>, V02Error> {
    let grants = match scope {
        CapabilityScope::Ceiling => return Ok(Vec::new()),
        CapabilityScope::None => {
            return Err(V02Error::Unsupported(
                "this VTA cannot hold an entry with no capabilities at all; list the ones it \
                 should hold, or choose a narrower role"
                    .into(),
            ));
        }
        CapabilityScope::Listed { grants } => grants,
    };
    if grants.is_empty() {
        return Err(V02Error::App(AppError::Validation(
            "capabilities.grants is empty; state {\"scope\":\"none\"} or list a grant".into(),
        )));
    }
    if let Some(g) = grants.iter().find(|g| g.resource.is_some()) {
        return Err(V02Error::Unsupported(format!(
            "this VTA's capabilities name no resource; `{}` cannot be qualified by `{}`",
            g.capability,
            g.resource.as_deref().unwrap_or_default()
        )));
    }
    let mut unknown = Vec::new();
    let mut parsed = Vec::with_capacity(grants.len());
    for g in grants {
        match serde_json::from_value::<Capability>(Value::String(g.capability.clone())) {
            Ok(c) => parsed.push((c, g)),
            Err(_) => unknown.push(g.capability.clone()),
        }
    }
    if !unknown.is_empty() {
        return Err(V02Error::UnknownCapability(unknown));
    }
    let ceiling = derived_capabilities_for_role(role);
    let within: Vec<String> = parsed
        .iter()
        .filter(|(c, g)| g.additive && ceiling.contains(c))
        .map(|(_, g)| g.capability.clone())
        .collect();
    if !within.is_empty() {
        return Err(V02Error::AdditiveWithinCeiling(within));
    }
    // Outside the ceiling: a non-additive capability the role does not carry,
    // and equally one flagged additive that this VTA does not class additive
    // (no role carries it, and the flag is not what confers it), or an
    // additive capability not flagged so.
    let outside: Vec<String> = parsed
        .iter()
        .filter(|(c, g)| {
            if g.additive {
                !is_additive(*c)
            } else {
                !ceiling.contains(c)
            }
        })
        .map(|(_, g)| g.capability.clone())
        .collect();
    if !outside.is_empty() {
        return Err(V02Error::CapabilityOutsideCeiling {
            role: role.to_string(),
            caps: outside,
        });
    }
    let caps: Vec<Capability> = parsed.into_iter().map(|(c, _)| c).collect();
    // A role with an empty ceiling holds exactly its additive grants either
    // way; any other role cannot hold "none of the role, only these".
    if caps.iter().all(|c| is_additive(*c)) && !ceiling.is_empty() {
        return Err(V02Error::Unsupported(
            "a listed scope naming only additive capabilities holds none of the role's; this \
             VTA cannot hold that. List the role capabilities the entry keeps beside them, or \
             state `ceiling` for the whole role"
                .into(),
        ));
    }
    Ok(caps)
}

fn step_up_require(s: Option<&str>) -> Result<Option<String>, V02Error> {
    // The per-entry override is retired (see `parse_step_up_require`); a value
    // is refused rather than stored and consulted by nothing.
    v1::parse_step_up_require(s)?;
    Ok(None)
}

// ─── acl/grant/0.2 ───────────────────────────────────────────────────────

/// `acl/grant/0.2`.
pub async fn grant(
    acl_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    entry: WireEntry,
    channel: &str,
) -> Result<Value, V02Error> {
    let role = parse_role(&entry.role)?;
    let allowed_contexts = act_contexts(&role, &entry.act)?;
    let capabilities = capabilities(&role, &entry.capabilities)?;
    let approve_scope = approve_scope(entry.approve.as_ref(), entry.approve_capabilities.as_ref())?;
    let handoff = vta_sdk::protocols::acl_management::entry::handoff_from_ext(entry.ext.as_ref())
        .map_err(|r| V02Error::App(AppError::Validation(r)))?;
    let step_up = entry.step_up.clone().unwrap_or_default();
    step_up_require(step_up.require.as_deref())?;

    // Grant item 6: an existing subject with a different role is a role
    // change, which only `acl/change-role` makes; with the same role the grant
    // is a re-assertion, or a widening handled as `acl/update/0.2` handles it,
    // and never a narrowing.
    if let Some(existing) = get_acl_entry(acl_ks, &entry.subject).await? {
        if existing.role != role {
            return Err(V02Error::App(AppError::Forbidden(format!(
                "{} already holds role {}; role changes use acl/change-role/0.2",
                entry.subject, existing.role
            ))));
        }
        if handoff {
            return Err(V02Error::App(AppError::Conflict(format!(
                "{} already has an entry; a hand-off marker is set only when an entry is created \
                 (VTI-ACL-054)",
                entry.subject
            ))));
        }
        let held = render(&existing);
        if let Some(axis) = narrowed_axis(&held, &entry) {
            return Err(V02Error::App(AppError::Forbidden(format!(
                "this grant would narrow {}'s {axis}; a grant never narrows — use acl/update/0.2 \
                 or acl/revoke/0.2",
                entry.subject
            ))));
        }
        let body = UpdateBody {
            subject: entry.subject.clone(),
            act: (entry.act != held.act).then(|| entry.act.clone()),
            approve: entry.approve.clone(),
            capabilities: Some(entry.capabilities.clone()),
            approve_capabilities: entry.approve_capabilities.clone(),
            keys: Some(entry.keys.clone()),
            label: entry.label.clone().map(Some),
            expires_at: (entry.expires_at != held.expires_at).then_some(entry.expires_at),
            step_up: entry.step_up.as_ref().map(|s| StepUpReplacement {
                approver: s.approver.clone().map(Some),
                require: None,
            }),
            reason: None,
        };
        return update(acl_ks, audit, contexts_ks, auth, body, channel).await;
    }

    let stored = v1::create_acl(
        acl_ks,
        audit,
        contexts_ks,
        auth,
        CreateAclParams {
            did: entry.subject.clone(),
            role,
            label: entry.label.clone(),
            allowed_contexts,
            expires_at: entry.expires_at.map(to_epoch),
            step_up_approver: step_up.approver,
            step_up_require: None,
            approve_scope,
            allowed_keys: entry
                .keys
                .to_allowed_keys()
                .map(|k| k.into_iter().collect()),
            capabilities,
            handoff,
        },
        channel,
    )
    .await?;
    Ok(serde_json::json!({ "entry": render_result(&stored)? }))
}

/// `acl/grant/0.2` carrying the hand-off rollover flag →
/// [`v1::exercise_handoff`]. The successor carries only subject, role, label,
/// act and capabilities; everything else is refused rather than dropped, and
/// `keys` must be `all` because the successor inherits the marked entry's key
/// filter.
pub async fn rollover(
    acl_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    entry: WireEntry,
    channel: &str,
) -> Result<Value, V02Error> {
    let role = parse_role(&entry.role)?;
    if !entry.subject.starts_with("did:") {
        return Err(V02Error::App(AppError::Validation(format!(
            "a hand-off successor must be a DID, found {}",
            entry.subject
        ))));
    }
    if entry.expires_at.is_some() {
        return Err(V02Error::App(AppError::Validation(
            "a hand-off successor takes the expiry the granter recorded with the marker \
             (VTI-ACL-055); omit `expiresAt`"
                .into(),
        )));
    }
    let approves = !matches!(entry.approve, None | Some(AuthorityScope::None))
        && !matches!(
            entry.approve_capabilities,
            None | Some(ApproveCapabilityScope::None)
        );
    if entry.step_up.is_some() || approves || entry.keys != KeyScope::All {
        return Err(V02Error::App(AppError::Validation(
            "a hand-off successor carries the marked entry's key filter and no step-up or \
             approve authority of its own; omit `stepUp` and `approve`, and state \
             keys {\"scope\":\"all\"}"
                .into(),
        )));
    }
    if vta_sdk::protocols::acl_management::entry::handoff_from_ext(entry.ext.as_ref())
        .map_err(|r| V02Error::App(AppError::Validation(r)))?
    {
        return Err(V02Error::App(AppError::Forbidden(
            "a hand-off successor cannot itself be marked as a hand-off (VTI-ACL-054)".into(),
        )));
    }
    let allowed_contexts = act_contexts(&role, &entry.act)?;
    let capabilities = capabilities(&role, &entry.capabilities)?;
    let stored = v1::exercise_handoff(
        acl_ks,
        audit,
        contexts_ks,
        auth,
        v1::HandOffSuccessor {
            did: entry.subject.clone(),
            role,
            label: entry.label.clone(),
            allowed_contexts,
            capabilities,
        },
        channel,
        None,
    )
    .await?;
    Ok(serde_json::json!({ "entry": render_result(&stored)? }))
}

/// The first axis on which `requested` holds less than `held`, if any — the
/// grant-never-narrows check (grant item 6). Capability and key lists compare
/// as sets; `ceiling` / `all` include every list.
fn narrowed_axis(held: &WireEntry, requested: &WireEntry) -> Option<&'static str> {
    if !requested.act.includes(&held.act) {
        return Some("act scope");
    }
    let approves = |e: &WireEntry| {
        if matches!(
            e.approve_capabilities,
            Some(ApproveCapabilityScope::Ceiling)
        ) {
            e.approve.clone().unwrap_or(AuthorityScope::None)
        } else {
            AuthorityScope::None
        }
    };
    if !approves(requested).includes(&approves(held)) {
        return Some("approve scope");
    }
    let keys_cover = match (&requested.keys, &held.keys) {
        (KeyScope::All, _) | (_, KeyScope::None) => true,
        (_, KeyScope::All) | (KeyScope::None, _) => false,
        (KeyScope::Listed { keys: r }, KeyScope::Listed { keys: h }) => {
            h.iter().all(|k| r.contains(k))
        }
    };
    if !keys_cover {
        return Some("key scope");
    }
    let names = |c: &CapabilityScope| -> Option<Vec<String>> {
        match c {
            CapabilityScope::Ceiling => None,
            CapabilityScope::None => Some(Vec::new()),
            CapabilityScope::Listed { grants } => {
                Some(grants.iter().map(|g| g.capability.clone()).collect())
            }
        }
    };
    let held_additive = matches!(
        &held.capabilities,
        CapabilityScope::Listed { grants } if grants.iter().any(|g| g.additive)
    );
    let caps_cover = match (names(&requested.capabilities), names(&held.capabilities)) {
        // `ceiling` holds no additive grant, so it narrows one that does.
        (None, _) => !held_additive,
        (Some(_), None) => false,
        (Some(r), Some(h)) => h.iter().all(|c| r.contains(c)),
    };
    if !caps_cover {
        return Some("capabilities");
    }
    match (requested.expires_at, held.expires_at) {
        (Some(_), None) => Some("expiry"),
        (Some(r), Some(h)) if r < h => Some("expiry"),
        _ => None,
    }
}

// ─── acl/show/0.2 ────────────────────────────────────────────────────────

/// `acl/show/0.2`. An entry the caller may not audit is `entry: null`, the
/// same answer as an absent one (show item 4), so the read does not disclose
/// existence.
pub async fn show(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    subject: &str,
    channel: &str,
) -> Result<Value, V02Error> {
    auth.require_manage()?;
    let entry = get_acl_entry(acl_ks, subject)
        .await?
        .filter(|e| is_acl_entry_auditable(auth, e));
    tracing::info!(channel, did = %subject, found = entry.is_some(), "ACL entry shown");
    Ok(serde_json::json!({ "entry": entry.as_ref().map(render) }))
}

// ─── acl/list/0.3 ────────────────────────────────────────────────────────

/// Default and ceiling page sizes (list item 5: the responder chooses the
/// default, and MAY impose a ceiling below the schema's 1000).
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 500;

/// An `acl/list/0.3` query, read from its payload.
#[derive(Debug, Default)]
pub struct ListQuery {
    pub role: Option<String>,
    pub context: Option<String>,
    pub capability: Option<String>,
    pub resource: Option<String>,
    pub direction: Option<ListDirection>,
    pub subject_prefix: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<u64>,
}

impl ListQuery {
    /// Read the query out of a payload the dispatcher has already held to the
    /// published schema.
    pub fn from_payload(p: &Value) -> Result<Self, V02Error> {
        let s = |k: &str| p.get(k).and_then(Value::as_str).map(str::to_string);
        let direction = match p.get("direction") {
            None => None,
            Some(v) => Some(serde_json::from_value(v.clone()).map_err(|_| {
                V02Error::App(AppError::Validation(
                    "`direction` is actingIn, subtree or any".into(),
                ))
            })?),
        };
        Ok(Self {
            role: s("role"),
            context: s("context"),
            capability: s("capability"),
            resource: s("resource"),
            direction,
            subject_prefix: s("subjectPrefix"),
            cursor: s("cursor"),
            limit: p.get("limit").and_then(Value::as_u64),
        })
    }
}

/// What a cursor binds: the caller and every filter (list item 5).
fn list_binding(auth: &AuthClaims, q: &ListQuery) -> Vec<u8> {
    serde_json::json!({
        "caller": auth.did,
        "role": q.role,
        "context": q.context,
        "capability": q.capability,
        "resource": q.resource,
        "direction": q.direction.map(|d| d.as_str()),
        "subjectPrefix": q.subject_prefix,
    })
    .to_string()
    .into_bytes()
}

/// `acl/list/0.3`.
pub async fn list(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    q: &ListQuery,
    channel: &str,
) -> Result<Value, V02Error> {
    auth.require_manage()?;
    // List item 2: a hierarchical filter needs a direction, and a direction
    // needs a hierarchical filter. No default is substituted.
    let hierarchical = q.context.is_some() || q.resource.is_some();
    match (hierarchical, q.direction) {
        (true, None) => {
            return Err(V02Error::App(AppError::Validation(
                "`context` and `resource` need a `direction`: actingIn, subtree or any".into(),
            )));
        }
        (false, Some(d)) => {
            return Err(V02Error::App(AppError::Validation(format!(
                "`direction: {}` reads a `context` or `resource` filter, and there is neither",
                d.as_str()
            ))));
        }
        _ => {}
    }
    let direction: Option<ContextDirection> = q.direction.map(Into::into);
    // List item 4: an unknown role or capability matches nothing.
    let role = match q.role.as_deref() {
        Some(r) => match Role::parse(r) {
            Ok(r) => Some(Some(r)),
            Err(_) => Some(None),
        },
        None => None,
    };
    let capability = q
        .capability
        .as_deref()
        .map(|c| serde_json::from_value::<Capability>(Value::String(c.to_string())).ok());

    let cursor_key = vti_common::pagination::CursorKey::new(acl_ks.clone())
        .get()
        .await?;
    let binding = list_binding(auth, q);
    let resume_after = match q.cursor.as_deref() {
        Some(wire) => Some(
            vti_common::pagination::Cursor::decode_bound(wire, &cursor_key, &binding)?.last_key,
        ),
        None => None,
    };

    let mut matching: Vec<AclEntry> = list_acl_entries(acl_ks)
        .await?
        .into_iter()
        .filter(|e| is_acl_entry_auditable(auth, e))
        .filter(|e| match &role {
            None => true,
            Some(None) => false,
            Some(Some(r)) => &e.role == r,
        })
        .filter(|e| match &q.subject_prefix {
            None => true,
            Some(p) => e.did.starts_with(p.as_str()),
        })
        .filter(|e| match (&q.context, direction) {
            (Some(ctx), Some(d)) => crate::acl::acl_entry_matches_context(e, ctx, d),
            _ => true,
        })
        .filter(|e| match &capability {
            None => true,
            Some(None) => false,
            // List item 3: the **effective** set, so an entry holding its
            // role's whole ceiling is found.
            Some(Some(c)) => effective_capabilities(&e.role, &e.capabilities).contains(c),
        })
        .filter(|e| match (&q.resource, direction) {
            // No capability here is qualified, so every effective capability
            // covers every resource: it matches acting-in (an unqualified
            // capability is an ancestor of every qualifier) and never a
            // subtree (it is not *at or beneath* one).
            (Some(_), Some(ContextDirection::Subtree)) => false,
            (Some(_), _) => !effective_capabilities(&e.role, &e.capabilities).is_empty(),
            (None, _) => true,
        })
        .collect();
    matching.sort_by(|a, b| a.did.cmp(&b.did));
    if let Some(after) = &resume_after {
        matching.retain(|e| e.did.as_bytes() > after.as_slice());
    }
    let limit = q
        .limit
        .map(|n| usize::try_from(n).unwrap_or(MAX_LIMIT).clamp(1, MAX_LIMIT))
        .unwrap_or(DEFAULT_LIMIT);
    let more = matching.len() > limit;
    matching.truncate(limit);
    let next_cursor = if more {
        matching.last().map(|e| {
            vti_common::pagination::Cursor::new(e.did.as_bytes().to_vec(), 0)
                .encode_bound(&cursor_key, &binding)
        })
    } else {
        None
    };
    tracing::info!(
        channel,
        caller = %auth.did,
        count = matching.len(),
        more,
        "ACL listed"
    );
    let mut body = serde_json::json!({
        "entries": matching.iter().map(render).collect::<Vec<_>>(),
    });
    if let Some(c) = next_cursor {
        body["nextCursor"] = Value::String(c);
    }
    Ok(body)
}

// ─── acl/update/0.2 ──────────────────────────────────────────────────────

/// An `acl/update/0.2` amendment, read from its payload. Each `Some` replaces
/// the stored member; `label` and `expires_at` are `Some(None)` for an explicit
/// `null`, which the generated payload type cannot tell from absence.
#[derive(Debug)]
pub struct UpdateBody {
    pub subject: String,
    pub act: Option<AuthorityScope>,
    pub approve: Option<AuthorityScope>,
    pub capabilities: Option<CapabilityScope>,
    pub approve_capabilities: Option<ApproveCapabilityScope>,
    pub keys: Option<KeyScope>,
    pub label: Option<Option<String>>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub step_up: Option<StepUpReplacement>,
    pub reason: Option<String>,
}

impl UpdateBody {
    /// Read the amendment out of a payload the dispatcher has already held to
    /// the published schema.
    pub fn from_payload(p: &Value) -> Result<Self, V02Error> {
        fn member<T: serde::de::DeserializeOwned>(
            p: &Value,
            k: &str,
        ) -> Result<Option<T>, V02Error> {
            match p.get(k) {
                None => Ok(None),
                Some(v) => serde_json::from_value(v.clone())
                    .map(Some)
                    .map_err(|e| V02Error::App(AppError::Validation(format!("`{k}`: {e}")))),
            }
        }
        Ok(Self {
            subject: p
                .get("subject")
                .and_then(Value::as_str)
                .ok_or_else(|| V02Error::App(AppError::Validation("`subject` is required".into())))?
                .to_string(),
            act: member(p, "act")?,
            approve: member(p, "approve")?,
            capabilities: member(p, "capabilities")?,
            approve_capabilities: member(p, "approveCapabilities")?,
            keys: member(p, "keys")?,
            label: member::<Option<String>>(p, "label")?,
            expires_at: member::<Option<DateTime<Utc>>>(p, "expiresAt")?,
            step_up: member(p, "stepUp")?,
            reason: member(p, "reason")?,
        })
    }
}

/// `acl/update/0.2`. Each present member replaces the stored value; `act`
/// may only widen (update item 3).
pub async fn update(
    acl_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    body: UpdateBody,
    channel: &str,
) -> Result<Value, V02Error> {
    let stored = get_acl_entry(acl_ks, &body.subject)
        .await?
        .filter(|e| is_acl_entry_auditable(auth, e))
        .ok_or_else(|| V02Error::NotFound(body.subject.clone()))?;

    let allowed_contexts = match &body.act {
        None => None,
        Some(act) => {
            let held = AuthorityScope::from_act_scope(&stored.act_scope());
            if !act.includes(&held) {
                return Err(V02Error::NarrowingNotPermitted);
            }
            Some(act_contexts(&stored.role, act)?)
        }
    };
    let capabilities = match &body.capabilities {
        None => None,
        Some(scope) => Some(capabilities(&stored.role, scope)?),
    };
    // The approve pair is judged as a pair: replacing one keeps the other as
    // stored (an `approve` with `approveCapabilities` left absent keeps the
    // stored `ceiling` when the entry already approves anything).
    let approve = match (&body.approve, &body.approve_capabilities) {
        (None, None) => None,
        (a, c) => {
            let stored_approve = AuthorityScope::from_approve_scope(&stored.approve_scope);
            let stored_caps = (!stored.approve_scope.confers_nothing())
                .then_some(ApproveCapabilityScope::Ceiling);
            let a = a.clone().unwrap_or(stored_approve);
            let c = c
                .clone()
                .or(stored_caps)
                // A scope newly granted with no approvable capabilities
                // stated confers nothing; say so rather than guess `ceiling`.
                .or(Some(ApproveCapabilityScope::None));
            Some(approve_scope(Some(&a), c.as_ref())?)
        }
    };
    let step_up = body.step_up.clone().unwrap_or_default();
    if let Some(Some(r)) = &step_up.require {
        step_up_require(Some(r))?;
    }

    let params = UpdateAclParams {
        role: None,
        label: body.label.clone().map(|l| l.unwrap_or_default()),
        allowed_contexts,
        step_up_approver: step_up.approver.map(|a| a.unwrap_or_default()),
        step_up_require: None,
        approve_scope: approve,
        expires_at: body.expires_at.and_then(|e| e.map(to_epoch)),
        clear_expiry: matches!(body.expires_at, Some(None)),
        reason: body.reason.clone(),
        capabilities,
        allowed_keys: body
            .keys
            .as_ref()
            .map(|k| k.to_allowed_keys().map(|k| k.into_iter().collect())),
    };
    let did = body.subject.clone();
    v1::update_from_params(acl_ks, audit, contexts_ks, auth, &did, params, channel).await?;
    Ok(serde_json::json!({ "entry": render_stored(acl_ks, &did).await? }))
}

// ─── acl/change-role/0.2 ─────────────────────────────────────────────────

/// `acl/change-role/0.2`. The act scope is carried over **as stated** — a
/// move whose resulting `(role, act)` this VTA cannot hold is refused rather
/// than reinterpreted through the new role.
#[allow(clippy::too_many_arguments)]
pub async fn change_role(
    acl_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    subject: &str,
    from_role: &str,
    to_role: &str,
    reason: Option<&str>,
    channel: &str,
) -> Result<Value, V02Error> {
    let from = parse_role(from_role)?;
    let to = parse_role(to_role)?;
    if let Some(stored) = get_acl_entry(acl_ks, subject).await? {
        if stored.role != from {
            return Err(V02Error::StateMismatch(format!(
                "role of {subject} is {}, not {from} — the change was based on stale state",
                stored.role
            )));
        }
        let held = AuthorityScope::from_act_scope(&stored.act_scope());
        let resulting = act_scope_for(&to, &stored.allowed_contexts);
        if AuthorityScope::from_act_scope(&resulting) != held {
            return Err(V02Error::App(AppError::Forbidden(format!(
                "{subject}'s act scope is {}, which this VTA cannot hold on the {to} role — a \
                 role change carries the act scope across unchanged. Narrow it with \
                 acl/revoke/0.2 or widen it with acl/update/0.2 first",
                describe(&held)
            ))));
        }
        let beyond = capabilities_beyond_role(&to, &stored.capabilities);
        if !beyond.is_empty() {
            return Err(V02Error::CapabilityOutsideCeiling {
                role: to.to_string(),
                caps: beyond.into_iter().map(cap_name).collect(),
            });
        }
    }
    v1::change_role_by_subject(
        acl_ks, audit, auth, subject, from_role, to_role, reason, channel,
    )
    .await?;
    Ok(serde_json::json!({ "entry": render_stored(acl_ks, subject).await? }))
}

fn describe(a: &AuthorityScope) -> String {
    match a {
        AuthorityScope::All => "all".into(),
        AuthorityScope::None => "none".into(),
        AuthorityScope::Contexts { contexts } => contexts.join(", "),
    }
}

// ─── acl/revoke/0.2 ──────────────────────────────────────────────────────

/// `acl/revoke/0.2`.
pub async fn revoke(
    acl_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    subject: &str,
    revocation: Revocation,
    reason: Option<String>,
    channel: &str,
) -> Result<Value, V02Error> {
    let stored = get_acl_entry(acl_ks, subject)
        .await?
        .filter(|e| is_acl_entry_auditable(auth, e))
        .ok_or_else(|| V02Error::NotFound(subject.to_string()))?;
    match revocation {
        Revocation::Entry => {
            v1::delete_acl(acl_ks, audit, auth, subject, channel).await?;
            Ok(serde_json::json!({ "entry": null }))
        }
        Revocation::Act { act } => {
            let held = AuthorityScope::from_act_scope(&stored.act_scope());
            // Revoke item 3: strictly narrower.
            if act == held || !held.includes(&act) {
                return Err(V02Error::NotNarrowing);
            }
            let contexts = act_contexts(&stored.role, &act)?;
            // `update_acl` validates each removed context against the caller's
            // scope (the symmetric difference), so a caller cannot narrow an
            // entry out of a context it does not administer.
            let did = subject.to_string();
            v1::update_from_params(
                acl_ks,
                audit,
                contexts_ks,
                auth,
                &did,
                UpdateAclParams {
                    allowed_contexts: Some(contexts),
                    reason,
                    ..UpdateAclParams::unchanged()
                },
                channel,
            )
            .await?;
            Ok(serde_json::json!({ "entry": render_stored(acl_ks, &did).await? }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(cs: &[&str]) -> AuthorityScope {
        AuthorityScope::Contexts {
            contexts: cs.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// CONVENTIONS §4 rule 3: role and act scope are independent, so the two
    /// stored shapes that would *imply* the other reading are refused, never
    /// written as the empty list that means the opposite.
    #[test]
    fn act_scopes_the_store_cannot_hold_are_refused() {
        assert!(matches!(
            act_contexts(&Role::Reader, &AuthorityScope::All),
            Err(V02Error::InvalidActScope { member: "act", .. })
        ));
        assert!(matches!(
            act_contexts(&Role::Admin, &AuthorityScope::None),
            Err(V02Error::InvalidActScope { member: "act", .. })
        ));
        assert_eq!(
            act_contexts(&Role::Admin, &AuthorityScope::All).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            act_contexts(&Role::Reader, &AuthorityScope::None).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            act_contexts(&Role::Reader, &ctx(&["a"])).unwrap(),
            vec!["a".to_string()]
        );
    }

    #[test]
    fn every_stored_shape_renders_explicitly() {
        let admin = AclEntry::new("did:key:zA", Role::Admin, "did:key:zRoot");
        let r = render(&admin);
        assert_eq!(r.act, AuthorityScope::All);
        assert_eq!(r.keys, KeyScope::All);
        assert_eq!(r.capabilities, CapabilityScope::Ceiling);
        assert_eq!(r.approve, Some(AuthorityScope::None));
        assert_eq!(r.approve_capabilities, None);
        assert_eq!(r.delegated_by.as_deref(), Some("did:key:zRoot"));

        let mut reader = AclEntry::new("did:key:zB", Role::Reader, "setup");
        reader.allowed_keys = Some(BTreeSet::new());
        reader.approve_scope = ApproveScope::Contexts(vec!["a".into()]);
        let r = render(&reader);
        assert_eq!(
            r.act,
            AuthorityScope::None,
            "a reader with no contexts acts nowhere"
        );
        assert_eq!(r.keys, KeyScope::None, "Some(∅) is no keys, never all");
        assert_eq!(r.approve, Some(ctx(&["a"])));
        assert_eq!(
            r.approve_capabilities,
            Some(ApproveCapabilityScope::Ceiling)
        );
        assert_eq!(r.delegated_by, None, "a bootstrap creator is no delegator");
    }

    #[test]
    fn stored_entries_round_trip_through_0_2() {
        let mut e = AclEntry::new("did:key:zA", Role::Admin, "did:key:zRoot");
        e.allowed_contexts = vec!["a".into(), "b/c".into()];
        e.capabilities = vec![Capability::Sign];
        let r = render(&e);
        assert_eq!(act_contexts(&e.role, &r.act).unwrap(), e.allowed_contexts);
        assert_eq!(
            capabilities(&e.role, &r.capabilities).unwrap(),
            e.capabilities
        );
        assert_eq!(
            approve_scope(r.approve.as_ref(), r.approve_capabilities.as_ref()).unwrap(),
            ApproveScope::None
        );
    }

    /// The whole role plus an additive grant renders as the enumerated ceiling
    /// plus the grant, and reads back to an entry with the same effective set.
    #[test]
    fn ceiling_plus_additive_renders_as_an_enumerated_ceiling() {
        let mut e = AclEntry::new("did:key:zA", Role::Admin, "did:key:zRoot");
        e.capabilities = vec![Capability::PersonaHolder];
        let r = render(&e);
        let CapabilityScope::Listed { grants } = &r.capabilities else {
            panic!("expected listed, got {:?}", r.capabilities);
        };
        assert!(
            grants
                .iter()
                .any(|g| g.additive && g.capability == "persona-holder")
        );
        let back = capabilities(&e.role, &r.capabilities).unwrap();
        let mut a = effective_capabilities(&e.role, &back);
        let mut b = effective_capabilities(&e.role, &e.capabilities);
        a.sort_by_key(|c| cap_name(*c));
        b.sort_by_key(|c| cap_name(*c));
        assert_eq!(a, b);
    }

    #[test]
    fn capability_checks_name_their_code() {
        let listed = |gs: Vec<CapabilityGrant>| CapabilityScope::Listed { grants: gs };
        assert!(matches!(
            capabilities(
                &Role::Reader,
                &listed(vec![CapabilityGrant::new("no-such-cap", false)])
            ),
            Err(V02Error::UnknownCapability(_))
        ));
        assert!(matches!(
            capabilities(
                &Role::Admin,
                &listed(vec![CapabilityGrant::new("sign", true)])
            ),
            Err(V02Error::AdditiveWithinCeiling(_))
        ));
        assert!(matches!(
            capabilities(
                &Role::Admin,
                &listed(vec![CapabilityGrant::new("persona-holder", false)])
            ),
            Err(V02Error::CapabilityOutsideCeiling { .. })
        ));
        assert!(matches!(
            capabilities(&Role::Admin, &CapabilityScope::None),
            Err(V02Error::Unsupported(_))
        ));
        let mut qualified = CapabilityGrant::new("sign", false);
        qualified.resource = Some("ctx:a".into());
        assert!(matches!(
            capabilities(&Role::Admin, &listed(vec![qualified])),
            Err(V02Error::Unsupported(_))
        ));
    }

    #[test]
    fn approve_without_approvable_capabilities_confers_nothing() {
        assert_eq!(
            approve_scope(Some(&AuthorityScope::All), None).unwrap(),
            ApproveScope::None
        );
        assert_eq!(
            approve_scope(
                Some(&AuthorityScope::All),
                Some(&ApproveCapabilityScope::Ceiling)
            )
            .unwrap(),
            ApproveScope::All
        );
        assert!(matches!(
            approve_scope(
                Some(&AuthorityScope::All),
                Some(&ApproveCapabilityScope::Listed { grants: vec![] })
            ),
            Err(V02Error::Unsupported(_))
        ));
    }

    #[test]
    fn a_list_direction_maps_onto_the_store_s() {
        assert_eq!(
            ContextDirection::from(ListDirection::ActingIn),
            ContextDirection::ActingIn
        );
    }
}
