//! The fixed rules of the rights model (`git-ns/right/grant/0.1`,
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
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::PermissionDenied(m)
            | Refusal::ScopeViolation(m)
            | Refusal::Escalation(m)
            | Refusal::MembersOnly(m) => f.write_str(m),
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

/// `git-ns/right/revoke/0.1`, *Authorization*: the granter while still a
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

/// Fixed rule 5: `git.ns.admin` and `git.repo.create` go only to current
/// members, because a non-member cannot be reached by the membership
/// lifecycle that revokes rights on departure.
pub fn members_only(right: Right, subject_is_member: bool) -> Result<(), Refusal> {
    if right.is_namespace_right() && !subject_is_member {
        return Err(Refusal::MembersOnly(format!(
            "{right} goes only to current members of the community"
        )));
    }
    Ok(())
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

/// Fixed rule 3: would removing `subject`'s `own` leave the repository with
/// no owner by explicit record?
pub fn is_last_owner(snap: &Snapshot, repo_id: &str, subject: &str, now: DateTime<Utc>) -> bool {
    let owners = live_holders(snap, &Scope::Repo(repo_id.to_string()), Right::RepoOwn, now);
    owners.contains(&subject) && owners.iter().all(|o| *o == subject)
}

/// Fixed rule 4: would removing `subject`'s `ns.admin` leave the namespace
/// with no admin by explicit record?
pub fn is_last_admin(snap: &Snapshot, ns_id: &str, subject: &str, now: DateTime<Utc>) -> bool {
    let admins = live_holders(
        snap,
        &Scope::Namespace(ns_id.to_string()),
        Right::NsAdmin,
        now,
    );
    admins.contains(&subject) && admins.iter().all(|a| *a == subject)
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
    fn namespace_rights_go_to_members_only() {
        assert!(members_only(Right::NsAdmin, false).is_err());
        assert!(members_only(Right::RepoCreate, false).is_err());
        assert!(members_only(Right::CommitSign, false).is_ok());
        assert!(members_only(Right::RepoOwn, false).is_ok());
    }
}
