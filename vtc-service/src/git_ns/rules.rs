//! The fixed rules of the rights model (`git-ns/right/grant/0.3`,
//! *The fixed rules*), as pure functions over a [`Snapshot`].
//!
//! "A VTC **MUST** enforce these in its own code, before and independently of
//! policy. Community policy cannot waive any of them." So they live here, in
//! code no policy upload reaches, and the policy is consulted only after every
//! one has passed ([`super::policy`]). Nothing in this file reads the store or
//! the clock: the caller hands in the snapshot and the instant, which is what
//! makes each rule testable as a table.
//!
//! | Rule | Here |
//! |---|---|
//! | 1. Scope containment | [`authority_to_grant`] (level + containment) |
//! | 2. No escalation | [`authority_to_grant`], [`authority_to_revoke`] |
//! | 3. Last owner | [`is_last_owner`] |
//! | 4. Last admin | [`is_last_admin`] |
//! | 5. Members-only floor | [`members_only`] |
//! | 6. Policy may only narrow | the decision can only deny — [`super::policy`] |
//! | 7. Separation of duties (`grant/0.3`) | [`separation_of_duties`] |

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};

use super::model::{Level, Resource, Right, RightRow, Scope};
use super::store::Snapshot;

/// Why a rule refused. Each maps onto exactly one wire code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The framework's `permissionDenied`: the actor holds no right on or
    /// above the resource at all.
    PermissionDenied(String),
    /// `git-ns:scopeViolation`.
    ScopeViolation(String),
    /// `git-ns:escalation`.
    Escalation(String),
    /// `git-ns:membersOnly`.
    MembersOnly(String),
    /// `git-ns:selfGrantNotAllowed` — fixed rule 7 of `git-ns/right/grant/0.3`.
    SelfGrant(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::PermissionDenied(m)
            | Refusal::ScopeViolation(m)
            | Refusal::Escalation(m)
            | Refusal::MembersOnly(m)
            | Refusal::SelfGrant(m) => f.write_str(m),
        }
    }
}

/// Community-configurable widenings the specification itself names. Read
/// from the active git-namespace policy's `settings` ([`super::policy`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuleSettings {
    /// "`git.repo.maintain` on a repository — nothing, unless the community
    /// has configured maintainers to grant `git.commit.sign` on that
    /// repository." Off by default.
    pub maintainer_grants_commit: bool,
}

/// One explicit, live right of a subject, with the resource it is on.
#[derive(Debug, Clone)]
pub struct Held<'a> {
    pub scope: &'a Scope,
    pub resource: Resource,
    pub row: &'a RightRow,
}

/// Every explicit right `did` holds that has not lapsed.
pub fn explicit_rights<'a>(snap: &'a Snapshot, did: &str, now: DateTime<Utc>) -> Vec<Held<'a>> {
    let mut out = Vec::new();
    for (scope, set) in &snap.rights {
        let Some(resource) = snap.scope_resource(scope) else {
            continue;
        };
        for row in &set.rows {
            if row.subject == did && row.is_live(now) {
                out.push(Held {
                    scope,
                    resource: resource.clone(),
                    row,
                });
            }
        }
    }
    out
}

/// The rights a held right confers on `target`, explicitly or by
/// implication. Empty when `held_on` does not contain `target`.
///
/// *Implied rights*: `own` ⇒ `maintain` ⇒ `commit.sign` on the same resource;
/// `ns.admin` ⇒ `repo.create` on its namespace and `own` on every repository
/// in it — and, per trustoverip/dtgwg-trust-tasks-tf#623, `commit.sign` on the
/// namespace itself, so an admin's own commits pass the namespace fallback.
pub fn conferred(held: Right, held_on: &Resource, target: &Resource) -> BTreeSet<Right> {
    let mut out = BTreeSet::new();
    if !held_on.contains(target) {
        return out;
    }
    let same = held_on == target;
    match held {
        Right::NsAdmin => {
            if same {
                out.extend([Right::NsAdmin, Right::RepoCreate, Right::CommitSign]);
            } else {
                out.extend([Right::RepoOwn, Right::RepoMaintain, Right::CommitSign]);
            }
        }
        Right::RepoCreate => {
            if same {
                out.insert(Right::RepoCreate);
            }
        }
        Right::RepoOwn => {
            out.extend([Right::RepoOwn, Right::RepoMaintain, Right::CommitSign]);
        }
        Right::RepoMaintain => {
            out.extend([Right::RepoMaintain, Right::CommitSign]);
        }
        // A namespace-level `commit.sign` counts on every repository inside
        // it — that is what the verify-trust fallback resource exists for.
        Right::CommitSign => {
            out.insert(Right::CommitSign);
        }
    }
    out
}

/// Every right `did` holds on `target`, explicit or implied.
pub fn effective_on(
    snap: &Snapshot,
    did: &str,
    target: &Resource,
    now: DateTime<Utc>,
) -> BTreeSet<Right> {
    let mut out = BTreeSet::new();
    for held in explicit_rights(snap, did, now) {
        out.extend(conferred(held.row.right, &held.resource, target));
    }
    out
}

/// Whether holding `held` on `held_on` carries the authority to grant
/// `right` on `target` — the *Grant authority* table, with implied rights
/// carrying their authority ("a namespace admin has an owner's authority on
/// every repository in the namespace").
fn carries(
    held: Right,
    held_on: &Resource,
    right: Right,
    target: &Resource,
    settings: RuleSettings,
) -> bool {
    if !held_on.contains(target) {
        return false;
    }
    let same = held_on == target;
    match held {
        Right::NsAdmin => {
            if same {
                matches!(
                    right,
                    Right::NsAdmin | Right::RepoCreate | Right::CommitSign
                )
            } else {
                matches!(
                    right,
                    Right::RepoOwn | Right::RepoMaintain | Right::CommitSign
                )
            }
        }
        // Not re-delegable.
        Right::RepoCreate => false,
        Right::RepoOwn => {
            same && matches!(
                right,
                Right::RepoOwn | Right::RepoMaintain | Right::CommitSign
            )
        }
        Right::RepoMaintain => {
            same && right == Right::CommitSign && settings.maintainer_grants_commit
        }
        Right::CommitSign => false,
    }
}

/// Fixed rules 1 and 2 for a grant of `right` on `target` by `actor`.
///
/// Order is the specification's: the level check and containment first
/// (`scopeViolation`), then authority (`escalation`), with `permissionDenied`
/// for an actor who holds nothing on or above the resource at all.
pub fn authority_to_grant(
    snap: &Snapshot,
    actor: &str,
    right: Right,
    target: &Resource,
    settings: RuleSettings,
    now: DateTime<Utc>,
) -> Result<(), Refusal> {
    match (right.level(), target.is_namespace()) {
        (Level::Namespace, false) => {
            return Err(Refusal::ScopeViolation(format!(
                "{right} applies to a namespace, and {target} is a repository"
            )));
        }
        (Level::Repository, true) => {
            return Err(Refusal::ScopeViolation(format!(
                "{right} applies to a repository, and {target} is a namespace"
            )));
        }
        _ => {}
    }

    let held = explicit_rights(snap, actor, now);
    let covering: Vec<&Held> = held
        .iter()
        .filter(|h| h.resource.contains(target))
        .collect();
    if covering.is_empty() {
        let ns = target.namespace_resource();
        if held.iter().any(|h| ns.contains(&h.resource)) {
            return Err(Refusal::ScopeViolation(format!(
                "{target} is wider than any resource you hold a right on"
            )));
        }
        return Err(Refusal::PermissionDenied(format!(
            "you hold no git right on or above {target}"
        )));
    }
    if covering
        .iter()
        .any(|h| carries(h.row.right, &h.resource, right, target, settings))
    {
        return Ok(());
    }
    Err(Refusal::Escalation(format!(
        "none of your rights on {target} carries the authority to grant or revoke {right}"
    )))
}

/// `git-ns/right/revoke/0.3`, *Authorization*: the granter while still a
/// member and still holding authority over the right, an authority over the
/// resource, or the subject resigning.
///
/// The granter clause needs no arm of its own: "still holding a right whose
/// grant authority covers the right on this resource" is exactly
/// [`authority_to_grant`], and a granter who no longer satisfies it has no
/// more standing than anyone else. Membership is checked for them anyway,
/// because a departed granter's rows are gone and that is what the sweep
/// relies on — but an actor reaching this function is a verified member.
pub fn authority_to_revoke(
    snap: &Snapshot,
    actor: &str,
    row: &RightRow,
    target: &Resource,
    settings: RuleSettings,
    now: DateTime<Utc>,
) -> Result<(), Refusal> {
    if row.subject == actor {
        return Ok(());
    }
    match authority_to_grant(snap, actor, row.right, target, settings, now) {
        Ok(()) => Ok(()),
        Err(Refusal::Escalation(m)) => Err(Refusal::Escalation(m)),
        // Holding rights only *below* the resource is holding none on it.
        Err(Refusal::ScopeViolation(_)) | Err(Refusal::PermissionDenied(_)) => {
            Err(Refusal::PermissionDenied(format!(
                "you hold no git right on {target} that covers {}",
                row.right
            )))
        }
        Err(other) => Err(other),
    }
}

/// Fixed rule 5 of `git-ns/right/grant/0.3`: an elevated right
/// (`git.ns.admin`, `git.repo.create`, `git.repo.own`) goes only to a current
/// member — an unexpired ACL entry and no recorded departure — and is granted
/// only by one. A non-member cannot be reached by the membership lifecycle
/// that revokes rights on departure, and a DID the VTC does not know as a
/// member (a fresh `did:key`) would otherwise let an actor hand an elevated
/// right to a second identity they control. Policy cannot waive it.
pub fn members_only(
    right: Right,
    subject_is_member: bool,
    actor_is_member: bool,
) -> Result<(), Refusal> {
    if !right.is_elevated() {
        return Ok(());
    }
    if !actor_is_member {
        return Err(Refusal::MembersOnly(format!(
            "{right} is granted only by a current member of the community"
        )));
    }
    if !subject_is_member {
        return Err(Refusal::MembersOnly(format!(
            "{right} goes only to a current member of the community, holding standing in its \
             access-control records"
        )));
    }
    Ok(())
}

/// Whether `right` is elevated on `target` for separation of duties:
/// [`Right::is_elevated_in`] under the role map of the namespace holding
/// `target` — so where maintainers get forge `admin`, `git.repo.maintain` is
/// elevated. A manual-mode namespace has no bridge and projects no forge
/// role, so no map can elevate a right there. With no namespace to read a map
/// from, it fails closed as an unknown map does: `git.repo.maintain` counts.
pub fn elevated_on(snap: &Snapshot, right: Right, target: &Resource) -> bool {
    match snap.namespace_containing(target) {
        Some(ns) if ns.mode == super::model::Mode::Manual => right.is_elevated(),
        Some(ns) => right.is_elevated_in(ns, &target.to_string()),
        None => right.is_elevated() || right == Right::RepoMaintain,
    }
}

/// Fixed rule 7 of `git-ns/right/grant/0.3`, *Separation of duties*: an actor
/// never grants an elevated right to themselves. `elevated` is
/// [`elevated_on`]: `git.ns.admin`, `git.repo.create` and `git.repo.own`
/// always, and a right the bridge's role map projects to forge `admin`
/// (`git-ns/bridge/event/0.3`). `actor` is the DID the VTC resolved the
/// signer to — after any console-key delegation — so a delegated key cannot
/// grant its principal what the principal may not grant themselves.
///
/// The refusal names the way to do it: `git-ns/right/break-glass/0.1` for
/// the three rights it carries; for a right elevated only by the role map,
/// another administrator or owner.
pub fn separation_of_duties(
    actor: &str,
    subject: &str,
    right: Right,
    elevated: bool,
    target: &Resource,
) -> Result<(), Refusal> {
    if actor != subject || !(elevated || right.is_elevated()) {
        return Ok(());
    }
    if right.is_elevated() {
        return Err(Refusal::SelfGrant(format!(
            "{right} is an elevated right, and you cannot grant it to yourself: ask another \
             administrator to grant it, or, if nobody else can, break the glass with \
             git-ns/right/break-glass — `cnm git break-glass --right={right} \
             --resource={target} --justification='…'` — which is audited, announced to every administrator, and \
             flagged until another administrator ratifies or revokes it"
        )));
    }
    Err(Refusal::SelfGrant(format!(
        "{right} is elevated on {target}: the bridge's role map projects it to the forge's \
         admin role (or the bridge has not reported its map yet), and you cannot grant it to \
         yourself. Ask another owner or administrator to grant it"
    )))
}

fn live_holders<'a>(
    snap: &'a Snapshot,
    scope: &Scope,
    right: Right,
    now: DateTime<Utc>,
) -> Vec<&'a str> {
    snap.rows(scope)
        .iter()
        .filter(|r| r.right == right && r.is_live(now))
        .map(|r| r.subject.as_str())
        .collect()
}

/// The holders of `right` whose record *counts* — no `expiresAt`, and not an
/// unratified break-glass record (fixed rules 3 and 4 of
/// `git-ns/right/grant/0.3`). An unratified break-glass record is provisional:
/// any other administrator may revoke it, and the invariants must not stop them.
///
/// A record with an `expiresAt` lapses on its own, with nobody asked. If it
/// counted, a namespace could reach "one admin, expiring Friday" by an
/// ordinary revoke of its last permanent admin, and be headless on Saturday
/// without any refusal ever having had the chance to fire. Counting only
/// permanent records keeps the invariant true at every later instant, not just
/// the one the revoke is checked at.
fn permanent_holders<'a>(
    snap: &'a Snapshot,
    scope: &Scope,
    right: Right,
    now: DateTime<Utc>,
) -> Vec<&'a str> {
    snap.rows(scope)
        .iter()
        .filter(|r| r.right == right && r.counts_for_invariants(now))
        .map(|r| r.subject.as_str())
        .collect()
}

/// Fixed rule 3: would removing `subject`'s `own` leave the repository with
/// no owner by explicit, permanent record? An expiring owner does not count
/// toward the invariant, so removing one is never refused by it.
pub fn is_last_owner(snap: &Snapshot, repo_id: &str, subject: &str, now: DateTime<Utc>) -> bool {
    let owners = permanent_holders(snap, &Scope::Repo(repo_id.to_string()), Right::RepoOwn, now);
    owners.contains(&subject) && owners.iter().all(|o| *o == subject)
}

/// Fixed rule 4: would removing `subject`'s `ns.admin` leave the namespace
/// with no admin by explicit, permanent record?
pub fn is_last_admin(snap: &Snapshot, ns_id: &str, subject: &str, now: DateTime<Utc>) -> bool {
    let admins = permanent_holders(
        snap,
        &Scope::Namespace(ns_id.to_string()),
        Right::NsAdmin,
        now,
    );
    admins.contains(&subject) && admins.iter().all(|a| *a == subject)
}

// ── the token policy evaluation requires ────────────────────────────────────

/// Proof that a request passed the fixed rules for its task.
///
/// Its only constructors are the rule functions in this module, and
/// [`super::policy::VerifiedGitNsFacts`] can be built only from one — so a
/// policy sees a request only after the code, not the policy, has
/// admitted it (fixed rule 6: "Policy can refuse … it can never admit a
/// request the rules above refuse"). A caller that skips the rules does not
/// compile:
///
/// ```compile_fail
/// let forged = vtc_service::git_ns::rules::RulesPassed(());
/// ```
///
/// ```compile_fail
/// let forged = vtc_service::git_ns::rules::RulesPassed::new();
/// ```
#[derive(Debug)]
pub struct RulesPassed(());

impl RulesPassed {
    fn new() -> Self {
        RulesPassed(())
    }

    /// For policy unit tests, which exercise the policy alone.
    #[cfg(test)]
    pub fn for_test() -> Self {
        RulesPassed(())
    }
}

/// Grant: fixed rules 1, 2, 7 and 5, in that order (`git-ns/right/grant/0.3`,
/// *Request* item 4: "rule 7 before rule 5").
#[allow(clippy::too_many_arguments)]
pub fn grant_admitted(
    snap: &Snapshot,
    actor: &str,
    subject: &str,
    right: Right,
    target: &Resource,
    subject_is_member: bool,
    actor_is_member: bool,
    settings: RuleSettings,
    now: DateTime<Utc>,
) -> Result<RulesPassed, Refusal> {
    authority_to_grant(snap, actor, right, target, settings, now)?;
    separation_of_duties(
        actor,
        subject,
        right,
        elevated_on(snap, right, target),
        target,
    )?;
    members_only(right, subject_is_member, actor_is_member)?;
    Ok(RulesPassed::new())
}

/// `git-ns/repo/create/0.3`, *Authorization*: who may own what a create
/// makes. The requester may be an owner only when they hold `git.repo.create`
/// on the namespace by explicit, live record (granted by someone else, or a
/// break-glass record); a `git.repo.create` only implied by `git.ns.admin`
/// carries no creator ownership, and naming oneself is a self-grant of
/// `git.repo.own` (fixed rule 7). Every other owner is a grant of `own` under
/// rule 2, and every owner and the requester are members (rule 5).
#[allow(clippy::too_many_arguments)]
pub fn create_owners_admitted(
    snap: &Snapshot,
    actor: &str,
    actor_is_member: bool,
    ns_scope: &Scope,
    ns_res: &Resource,
    target: &Resource,
    owners: &[(String, bool)],
    settings: RuleSettings,
    now: DateTime<Utc>,
) -> Result<RulesPassed, Refusal> {
    let explicit_create =
        explicit_admitted(snap, actor, Right::RepoCreate, ns_scope, now).is_some();
    for (owner, owner_is_member) in owners {
        if owner == actor {
            if !explicit_create {
                return Err(Refusal::SelfGrant(format!(
                    "your git.repo.create on this namespace is only implied by git.ns.admin, \
                     which does not make you the owner of what you create: name another member \
                     in owners, or break the glass once for git.repo.create — `cnm git \
                     break-glass --right=git.repo.create --resource={} \
                     --justification='…'` — which is audited, announced to every administrator, \
                     and flagged until another administrator ratifies or revokes it",
                    ns_res
                )));
            }
        } else {
            authority_to_grant(snap, actor, Right::RepoOwn, target, settings, now)?;
        }
        members_only(Right::RepoOwn, *owner_is_member, actor_is_member)?;
    }
    Ok(RulesPassed::new())
}

/// Which entitlement a break-glass relied on (`git-ns/right/break-glass/0.1`,
/// *Authorization*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakGlassEntitlement {
    /// Grant authority over the right on the resource, per the grant authority
    /// table.
    GrantAuthority,
    /// The community-administrator capability, for `git.ns.admin` on a
    /// headless namespace — `git-ns/namespace/reseat`'s entitlement.
    CommunityAdminHeadless,
}

impl BreakGlassEntitlement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GrantAuthority => "grantAuthority",
            Self::CommunityAdminHeadless => "communityAdministratorHeadless",
        }
    }
}

/// Why a break-glass was refused by the rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakGlassRefusal {
    Rule(Refusal),
    /// `git-ns/right/break-glass:notHeadless`.
    NotHeadless(String),
}

impl From<Refusal> for BreakGlassRefusal {
    fn from(r: Refusal) -> Self {
        BreakGlassRefusal::Rule(r)
    }
}

/// `git-ns/right/break-glass/0.1` steps 3–5: the right's level (rule 1), one
/// of the two entitlements, and the members-only floor (rule 5). Separation of
/// duties is the one rule this task lifts, for this one grant, to the actor.
///
/// `headless` is established by the caller against current membership, under
/// the store lock.
#[allow(clippy::too_many_arguments)]
pub fn break_glass_admitted(
    snap: &Snapshot,
    actor: &str,
    right: Right,
    target: &Resource,
    actor_is_member: bool,
    actor_community_admin: bool,
    headless: bool,
    settings: RuleSettings,
    now: DateTime<Utc>,
) -> Result<(RulesPassed, BreakGlassEntitlement), BreakGlassRefusal> {
    if !right.is_elevated() {
        return Err(Refusal::ScopeViolation(format!(
            "{right} is not elevated; grant it with git-ns/right/grant"
        ))
        .into());
    }
    // Rule 1's level half first, so a wrong-level request is a scope
    // violation whichever entitlement the actor might have.
    if matches!(
        (right.level(), target.is_namespace()),
        (Level::Namespace, false) | (Level::Repository, true)
    ) {
        return Err(Refusal::ScopeViolation(format!(
            "{right} does not apply to a resource at the level of {target}"
        ))
        .into());
    }
    let entitlement = match authority_to_grant(snap, actor, right, target, settings, now) {
        Ok(()) => BreakGlassEntitlement::GrantAuthority,
        Err(refusal) => {
            if right == Right::NsAdmin && target.is_namespace() && actor_community_admin {
                if !headless {
                    return Err(BreakGlassRefusal::NotHeadless(format!(
                        "{target} has a live git.ns.admin, so it is not headless; its admins \
                         grant git.ns.admin with git-ns/right/grant"
                    )));
                }
                BreakGlassEntitlement::CommunityAdminHeadless
            } else {
                return Err(refusal.into());
            }
        }
    };
    members_only(right, actor_is_member, actor_is_member)?;
    Ok((RulesPassed::new(), entitlement))
}

/// `git-ns/right/ratify/0.1`, *Authorization*: never the record's subject;
/// otherwise a community administrator, or a holder of grant authority over
/// the right on the resource through a right that is **not itself** held by an
/// unratified break-glass record. The caller has already refused the subject
/// with `selfRatification`.
pub fn ratify_admitted(
    snap: &Snapshot,
    actor: &str,
    row: &RightRow,
    target: &Resource,
    actor_community_admin: bool,
    settings: RuleSettings,
    now: DateTime<Utc>,
) -> Result<RulesPassed, Refusal> {
    if row.subject == actor {
        return Err(Refusal::PermissionDenied(
            "a break-glass is ratified by someone other than its subject".into(),
        ));
    }
    if actor_community_admin {
        return Ok(RulesPassed::new());
    }
    // Grant authority, counted only through rights that are not themselves an
    // unratified break-glass: a second person whose own authority nobody has
    // confirmed is not a second person.
    let confirmed = snap.without_unratified_break_glass();
    match authority_to_grant(&confirmed, actor, row.right, target, settings, now) {
        Ok(()) => Ok(RulesPassed::new()),
        Err(Refusal::Escalation(m)) => Err(Refusal::Escalation(m)),
        Err(_) => Err(Refusal::PermissionDenied(format!(
            "ratifying {} on {target} needs the community-administrator capability, or a \
             confirmed right on {target} that carries the authority to grant it",
            row.right
        ))),
    }
}

/// Revoking an unratified break-glass record: any community administrator,
/// in addition to everyone `git-ns/right/revoke/0.3` otherwise admits.
pub fn revoke_break_glass_admitted(
    actor_community_admin: bool,
    row: &RightRow,
) -> Option<RulesPassed> {
    (actor_community_admin && row.is_unratified_break_glass()).then(RulesPassed::new)
}

/// Revoke: the revocation authority of `git-ns/right/revoke`.
pub fn revoke_admitted(
    snap: &Snapshot,
    actor: &str,
    row: &RightRow,
    target: &Resource,
    settings: RuleSettings,
    now: DateTime<Utc>,
) -> Result<RulesPassed, Refusal> {
    authority_to_revoke(snap, actor, row, target, settings, now)?;
    Ok(RulesPassed::new())
}

/// Bind: the community-administrator capability (`git-ns/namespace/bind`,
/// *Authorization*).
pub fn bind_admitted(community_admin: bool) -> Result<RulesPassed, Refusal> {
    if !community_admin {
        return Err(Refusal::PermissionDenied(
            "binding a namespace needs the community-administrator capability".into(),
        ));
    }
    Ok(RulesPassed::new())
}

/// Unbind: `git.ns.admin` on the namespace, or the community-administrator
/// capability.
pub fn unbind_admitted(
    snap: &Snapshot,
    actor: &str,
    ns_resource: &Resource,
    community_admin: bool,
    now: DateTime<Utc>,
) -> Result<RulesPassed, Refusal> {
    if community_admin || effective_on(snap, actor, ns_resource, now).contains(&Right::NsAdmin) {
        return Ok(RulesPassed::new());
    }
    Err(Refusal::PermissionDenied(format!(
        "unbinding {ns_resource} needs git.ns.admin on it, or the community-administrator \
         capability"
    )))
}

/// A right the task requires the actor to hold on `on`, explicitly or by
/// implication — `repo.create` to create, `own` to archive.
pub fn holds_admitted(
    snap: &Snapshot,
    actor: &str,
    right: Right,
    on: &Resource,
    now: DateTime<Utc>,
) -> Result<RulesPassed, Refusal> {
    if effective_on(snap, actor, on, now).contains(&right) {
        return Ok(RulesPassed::new());
    }
    Err(Refusal::PermissionDenied(format!(
        "this needs {right} on {on}"
    )))
}

/// An explicit, live record — transfer hands over the caller's own `own`
/// record, and adopt of a reservation needs the reservation's.
pub fn explicit_admitted(
    snap: &Snapshot,
    actor: &str,
    right: Right,
    scope: &Scope,
    now: DateTime<Utc>,
) -> Option<RulesPassed> {
    snap.rows(scope)
        .iter()
        .any(|r| r.subject == actor && r.right == right && r.is_live(now))
        .then(RulesPassed::new)
}

/// The bridge's service grant: `git.commit.sign`, on the namespace, to the
/// namespace's own bridge DID — nothing else.
pub fn service_grant_admitted(
    ns: &super::model::Namespace,
    subject: &str,
    right: Right,
    target: &Resource,
) -> Result<RulesPassed, Refusal> {
    let own_bridge = ns.bridge_did.as_deref() == Some(subject);
    let bound = ns.state == super::model::NamespaceState::Bound;
    if own_bridge && bound && right == Right::CommitSign && *target == ns.resource() {
        return Ok(RulesPassed::new());
    }
    Err(Refusal::Escalation(
        "a service grant is git.commit.sign on a bound namespace, to the bridge it records".into(),
    ))
}

/// `git-ns/drift/resolve` revert: `git.repo.own` on the repository, explicit
/// or implied. (Adopt is admitted as the grant it is, by [`grant_admitted`].)
pub fn drift_revert_admitted(
    snap: &Snapshot,
    actor: &str,
    repo: &Resource,
    now: DateTime<Utc>,
) -> Result<RulesPassed, Refusal> {
    if effective_on(snap, actor, repo, now).contains(&Right::RepoOwn) {
        Ok(RulesPassed::new())
    } else {
        Err(Refusal::PermissionDenied(format!(
            "resolving drift on {repo} needs git.repo.own there"
        )))
    }
}

/// `git-ns/namespace/reseat`: the community-administrator capability,
/// **together with** the namespace being headless, and a current member to
/// receive the right (fixed rule 5). The caller establishes `headless`
/// against current membership, under the store lock.
pub fn reseat_admitted(
    actor_community_admin: bool,
    headless: bool,
    subject_member: bool,
) -> Option<RulesPassed> {
    (actor_community_admin && headless && subject_member).then(RulesPassed::new)
}

/// `git-ns/roles/reproject`: the community-administrator capability, or
/// `git.ns.admin` on the namespace by explicit, live record of a current
/// member — or, for a single repository, `git.repo.own` on it, explicit or
/// implied (`repo_owner`, which the caller computes only for a repository
/// resource). Owning some repositories never admits a whole namespace.
pub fn reproject_admitted(
    actor_community_admin: bool,
    actor_member: bool,
    explicit_ns_admin: bool,
    repo_owner: bool,
) -> Option<RulesPassed> {
    (actor_community_admin || (actor_member && (explicit_ns_admin || repo_owner)))
        .then(RulesPassed::new)
}

/// The explicit owners of a repository, in grant order.
pub fn owners(snap: &Snapshot, repo_id: &str, now: DateTime<Utc>) -> Vec<String> {
    live_holders(snap, &Scope::Repo(repo_id.to_string()), Right::RepoOwn, now)
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// The explicit admins of a namespace.
pub fn admins(snap: &Snapshot, ns_id: &str, now: DateTime<Utc>) -> Vec<String> {
    live_holders(
        snap,
        &Scope::Namespace(ns_id.to_string()),
        Right::NsAdmin,
        now,
    )
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Whether `did` governs `resource` — holds `own` on it or `ns.admin` over
/// it, explicitly or by implication — and so may see every right on it and
/// the reasons they were granted for (`git-ns/view`, *Request* item 3).
pub fn governs(snap: &Snapshot, did: &str, resource: &Resource, now: DateTime<Utc>) -> bool {
    let rights = effective_on(snap, did, resource, now);
    if resource.is_namespace() {
        rights.contains(&Right::NsAdmin)
    } else {
        rights.contains(&Right::RepoOwn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_ns::model::{
        Bootstrap, Mode, Namespace, NamespaceState, Repo, RepoState, RightsSet, SyncState,
        SyncStatus, Visibility,
    };

    const ALICE: &str = "did:key:alice";
    const BOB: &str = "did:key:bob";
    const CAROL: &str = "did:key:carol";
    const DAN: &str = "did:key:dan";

    fn now() -> DateTime<Utc> {
        "2026-09-23T12:00:00Z".parse().unwrap()
    }

    fn row(subject: &str, right: Right) -> RightRow {
        RightRow {
            subject: subject.into(),
            right,
            granted_by: ALICE.into(),
            granted_at: now(),
            expires_at: None,
            reason: None,
            subject_was_member: true,
            granter_was_member: true,
            break_glass: None,
        }
    }

    /// `github.com/acme` bound, Alice admin; `widgets` owned by Carol, Bob
    /// holds `repo.create`, Dan commits to `widgets`.
    fn snap() -> Snapshot {
        let mut s = Snapshot::default();
        s.namespaces.push(Namespace {
            id: "ns1".into(),
            forge: "github.com".into(),
            owner: "acme".into(),
            mode: Mode::Manual,
            state: NamespaceState::Bound,
            owner_id: None,
            kind: None,
            bridge_did: None,
            bind_job_id: None,
            bound_by: ALICE.into(),
            requested_at: now(),
            bound_at: Some(now()),
            roles_digest: None,
            installation_removed: false,
            forge_status: None,
            role_map: None,
        });
        s.repos.push(Repo {
            id: "r1".into(),
            namespace_id: "ns1".into(),
            resource: "github.com/acme/widgets".into(),
            forge_id: None,
            visibility: Visibility::Public,
            description: None,
            state: RepoState::Active,
            created_by: None,
            created_at: now(),
            bootstrap: Bootstrap::default(),
            sync: SyncStatus::new(SyncState::Unchecked),
            failed_step: None,
            last_error: None,
            roles_digest: None,
            forge_report: Default::default(),
        });
        s.rights.insert(
            Scope::Namespace("ns1".into()),
            RightsSet {
                rows: vec![row(ALICE, Right::NsAdmin), row(BOB, Right::RepoCreate)],
            },
        );
        s.rights.insert(
            Scope::Repo("r1".into()),
            RightsSet {
                rows: vec![row(CAROL, Right::RepoOwn), row(DAN, Right::CommitSign)],
            },
        );
        s
    }

    fn res(s: &str) -> Resource {
        Resource::parse(s).unwrap()
    }

    fn grant(actor: &str, right: Right, target: &str) -> Result<(), Refusal> {
        authority_to_grant(
            &snap(),
            actor,
            right,
            &res(target),
            RuleSettings::default(),
            now(),
        )
    }

    #[test]
    fn a_namespace_admin_may_grant_everything_in_the_namespace() {
        for (right, target) in [
            (Right::NsAdmin, "github.com/acme"),
            (Right::RepoCreate, "github.com/acme"),
            (Right::CommitSign, "github.com/acme"),
            (Right::RepoOwn, "github.com/acme/widgets"),
            (Right::RepoMaintain, "github.com/acme/any"),
            (Right::CommitSign, "github.com/acme/widgets"),
        ] {
            assert_eq!(grant(ALICE, right, target), Ok(()), "{right} on {target}");
        }
    }

    #[test]
    fn repo_create_is_not_re_delegable() {
        assert!(matches!(
            grant(BOB, Right::RepoCreate, "github.com/acme"),
            Err(Refusal::Escalation(_))
        ));
    }

    #[test]
    fn an_owner_grants_within_their_repository_only() {
        for right in [Right::RepoOwn, Right::RepoMaintain, Right::CommitSign] {
            assert_eq!(grant(CAROL, right, "github.com/acme/widgets"), Ok(()));
        }
        assert!(matches!(
            grant(CAROL, Right::CommitSign, "github.com/acme"),
            Err(Refusal::ScopeViolation(_))
        ));
        assert!(matches!(
            grant(CAROL, Right::CommitSign, "github.com/acme/gadgets"),
            Err(Refusal::ScopeViolation(_))
        ));
        assert!(matches!(
            grant(CAROL, Right::NsAdmin, "github.com/acme"),
            Err(Refusal::ScopeViolation(_))
        ));
    }

    #[test]
    fn a_right_never_crosses_forges_or_prefix_lookalikes() {
        for target in ["codeberg.org/acme/widgets", "github.com/acme-labs/x"] {
            assert!(matches!(
                grant(ALICE, Right::CommitSign, target),
                Err(Refusal::PermissionDenied(_))
            ));
        }
    }

    #[test]
    fn the_level_must_match_the_right() {
        assert!(matches!(
            grant(ALICE, Right::RepoOwn, "github.com/acme"),
            Err(Refusal::ScopeViolation(_))
        ));
        assert!(matches!(
            grant(ALICE, Right::NsAdmin, "github.com/acme/widgets"),
            Err(Refusal::ScopeViolation(_))
        ));
    }

    #[test]
    fn a_committer_grants_nothing_and_a_maintainer_only_when_configured() {
        assert!(matches!(
            grant(DAN, Right::CommitSign, "github.com/acme/widgets"),
            Err(Refusal::Escalation(_))
        ));
        let mut s = snap();
        s.rights
            .get_mut(&Scope::Repo("r1".into()))
            .unwrap()
            .rows
            .push(row(BOB, Right::RepoMaintain));
        let target = res("github.com/acme/widgets");
        assert!(matches!(
            authority_to_grant(
                &s,
                BOB,
                Right::CommitSign,
                &target,
                RuleSettings::default(),
                now()
            ),
            Err(Refusal::Escalation(_))
        ));
        let widened = RuleSettings {
            maintainer_grants_commit: true,
        };
        assert_eq!(
            authority_to_grant(&s, BOB, Right::CommitSign, &target, widened, now()),
            Ok(())
        );
        assert!(authority_to_grant(&s, BOB, Right::RepoMaintain, &target, widened, now()).is_err());
    }

    #[test]
    fn a_lapsed_right_carries_no_authority() {
        let mut s = snap();
        s.rights.get_mut(&Scope::Repo("r1".into())).unwrap().rows[0].expires_at =
            Some("2026-09-01T00:00:00Z".parse().unwrap());
        assert!(
            authority_to_grant(
                &s,
                CAROL,
                Right::CommitSign,
                &res("github.com/acme/widgets"),
                RuleSettings::default(),
                now()
            )
            .is_err()
        );
    }

    #[test]
    fn implication_is_evaluated_and_ns_admin_implies_namespace_commit() {
        let s = snap();
        let on_ns = effective_on(&s, ALICE, &res("github.com/acme"), now());
        assert!(on_ns.contains(&Right::CommitSign), "trust-tasks-tf#623");
        assert!(on_ns.contains(&Right::RepoCreate));
        let on_repo = effective_on(&s, ALICE, &res("github.com/acme/widgets"), now());
        assert!(on_repo.contains(&Right::RepoOwn));
        let carol = effective_on(&s, CAROL, &res("github.com/acme/widgets"), now());
        assert_eq!(
            carol,
            BTreeSet::from([Right::RepoOwn, Right::RepoMaintain, Right::CommitSign])
        );
    }

    #[test]
    fn revoke_is_open_to_the_subject_and_to_authority_only() {
        let s = snap();
        let dan = row(DAN, Right::CommitSign);
        let widgets = res("github.com/acme/widgets");
        let st = RuleSettings::default();
        assert_eq!(
            authority_to_revoke(&s, DAN, &dan, &widgets, st, now()),
            Ok(())
        );
        assert_eq!(
            authority_to_revoke(&s, CAROL, &dan, &widgets, st, now()),
            Ok(())
        );
        assert_eq!(
            authority_to_revoke(&s, ALICE, &dan, &widgets, st, now()),
            Ok(())
        );
        assert!(matches!(
            authority_to_revoke(&s, BOB, &dan, &widgets, st, now()),
            Err(Refusal::Escalation(_))
        ));
        // An owner cannot revoke a namespace-wide commit right.
        let ns_commit = row(DAN, Right::CommitSign);
        assert!(matches!(
            authority_to_revoke(&s, CAROL, &ns_commit, &res("github.com/acme"), st, now()),
            Err(Refusal::PermissionDenied(_))
        ));
    }

    #[test]
    fn last_owner_and_last_admin_are_detected() {
        let s = snap();
        assert!(is_last_owner(&s, "r1", CAROL, now()));
        assert!(!is_last_owner(&s, "r1", DAN, now()));
        assert!(is_last_admin(&s, "ns1", ALICE, now()));
        assert!(!is_last_admin(&s, "ns1", BOB, now()));
    }

    #[test]
    fn elevated_rights_go_to_and_from_members_only() {
        for right in [Right::NsAdmin, Right::RepoCreate, Right::RepoOwn] {
            assert!(
                members_only(right, false, true).is_err(),
                "{right} to a non-member"
            );
            assert!(
                members_only(right, true, false).is_err(),
                "{right} by a non-member"
            );
            assert!(
                members_only(right, true, true).is_ok(),
                "{right} member to member"
            );
        }
        assert!(members_only(Right::CommitSign, false, false).is_ok());
        assert!(members_only(Right::RepoMaintain, false, false).is_ok());
    }

    /// A service grant is admitted for exactly one shape: `commit.sign`, on a
    /// bound namespace's own resource, to the bridge that namespace records.
    #[test]
    fn a_service_grant_is_admitted_only_to_the_recorded_bridge_of_a_bound_namespace() {
        let mut ns = snap().namespaces[0].clone();
        ns.bridge_did = Some(DAN.into());
        let own = ns.resource();
        let repo = Resource::parse("github.com/acme/widgets").unwrap();
        assert!(service_grant_admitted(&ns, DAN, Right::CommitSign, &own).is_ok());
        assert!(service_grant_admitted(&ns, BOB, Right::CommitSign, &own).is_err());
        assert!(service_grant_admitted(&ns, DAN, Right::RepoOwn, &own).is_err());
        assert!(service_grant_admitted(&ns, DAN, Right::CommitSign, &repo).is_err());
        let other = Resource::parse("github.com/beta").unwrap();
        assert!(service_grant_admitted(&ns, DAN, Right::CommitSign, &other).is_err());
        ns.state = NamespaceState::Pending;
        assert!(service_grant_admitted(&ns, DAN, Right::CommitSign, &own).is_err());
        ns.state = NamespaceState::Bound;
        ns.bridge_did = None;
        assert!(service_grant_admitted(&ns, DAN, Right::CommitSign, &own).is_err());
    }
}
