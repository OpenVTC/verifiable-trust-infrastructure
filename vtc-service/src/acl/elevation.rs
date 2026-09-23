//! Admin elevation — the one place that answers "is this caller carrying a
//! live step-up right now?", and the one refusal every admin-conferring path
//! emits when they are not.
//!
//! ## Why this is its own module
//!
//! VTI-OPS-050/051 put a **fresh reauthentication** in front of conferring
//! administrative authority. The VTC had one, on `vtc/members/update` — and
//! only there. `acl/change-role` and `acl/grant` reach the same ACL row, assign
//! the same `admin` role, and asked for nothing, so the gate bounded one route
//! rather than the operation. A gate that one of three doors honours is not a
//! gate.
//!
//! Both halves of the answer live here so they cannot drift apart:
//!
//! - [`verified`] resolves the elevation from the caller's **live session**,
//!   which is the only thing that can be trusted to say so. A route handler
//!   passing a boolean is not evidence; it is the handler's opinion.
//! - [`required`] is the refusal, and it names the ceremony the operator has to
//!   run, because an operator reading "forbidden" has no way to guess that the
//!   fix is a passkey.
//!
//! ## Where each gate lives
//!
//! - `acl/change-role` is a role **transition**, so it runs the role-change
//!   ceremony, and its gate is the host invariant
//!   [`Invariant::StepUpForAdmin`](crate::ceremony::Invariant) — evaluated at
//!   the decision point, around the policy, where an operator's policy edit
//!   cannot reach it. [`verified`] supplies the fact it reads.
//! - `acl/grant` writes an entry rather than moving one. There is no transition
//!   and so no ceremony to hang an invariant on, so it calls [`verified`] /
//!   [`required`] directly — gated on [`widens_admin_authority`], so a rewrite
//!   that confers nothing new (the console's label edit) does not demand a
//!   passkey. Stated plainly rather than hidden: it is the same predicate,
//!   checked one layer further out.
//!
//! Neither depends on policy enforcement being switched on. The VTC has no
//! `policy.enforcement` flag — its decision pipeline always runs, and
//! [`crate::ceremony::decide`] applies the host invariants unconditionally
//! after the policy — so there is no configuration in which these lapse.
//!
//! ## Role is the whole grant here, and that is worth saying out loud
//!
//! On the VTA an ACL entry can hold *less* than its role: `AclEntry.
//! capabilities` narrows a role's derived set, so a role is a ceiling rather
//! than the grant, and a gate reading only the role over-trusts the entry
//! (#1279, #1642). Two questions follow for any promotion gate — what happens
//! to a narrowed set when the role moves, and whether a caller can escalate by
//! widening their own set without touching their role.
//!
//! Neither arises in the VTC, and the reason is structural rather than lucky:
//! [`VtcAclEntry`](crate::acl::VtcAclEntry) has **no** `capabilities` field and
//! `AuthClaims` carries none, so a VTC entry is exactly `(role, scopes)`.
//! Nothing can disagree with the role because nothing else is stored. The
//! analogous widening axis is `scopes`, and it is gated already:
//! `validate_acl_modification` refuses a non-super-admin conferring the
//! unrestricted (community-wide) entry, and bounds a context admin to contexts
//! they hold. What it does not bound is *how recently the caller
//! authenticated*, which is why [`required`] is checked on a re-grant that
//! [`widens_admin_authority`] and not only on a fresh one.
//!
//! If the VTC ever gains per-entry narrowing, this is the note that says what
//! has to be decided with it.

use vti_common::auth::extractor::AuthClaims;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Whether `actor`'s session carries a live step-up elevation **now**.
///
/// Reads the session row rather than the bearer token: the elevation is a
/// bounded window stamped on the session by
/// `auth/passkey/login/finish/0.2` with `purpose: stepUp`, and a token minted
/// before it — or long after it lapsed — says nothing about it.
///
/// A missing session, an expired window and a session that was never elevated
/// are all "not elevated". Failing closed is the only safe reading: the fact
/// this produces is what stands between an admin session and conferring admin.
pub async fn verified(actor: &AuthClaims, sessions: &KeyspaceHandle) -> bool {
    actor.require_fresh_step_up(sessions).await.is_ok()
}

/// Would writing an `admin` entry with `new_scopes` give away more authority
/// than `prev` already holds?
///
/// `acl/grant` is "the entry the maintainer should hold", so it is used both to
/// mint an entry and to rewrite one — and the console rewrites an entry at its
/// existing role to edit a **label**. Demanding a passkey for that would be
/// theatre. What is not theatre is the rewrite that moves an admin from one
/// context to two, or from a context to none at all, which is how a
/// community-wide super-admin is spelled: authority granted without the role
/// ever changing.
///
/// So the question is the widening, not the write:
///
/// - no previous entry → minting an admin, always a conferral;
/// - previously unrestricted → nothing can widen it;
/// - newly unrestricted → a scoped admin just became community-wide;
/// - otherwise → widened iff some new scope is not already covered by one the
///   entry holds (hierarchically: a *descendant* of a held context is not new
///   authority, same rule `acl list --scope` filters by).
#[must_use]
pub fn widens_admin_authority(prev: Option<&super::VtcAclEntry>, new_scopes: &[String]) -> bool {
    use vti_common::acl::ActScope;
    let Some(prev) = prev else {
        return true;
    };
    let held = match prev.act_scope() {
        ActScope::All => return false,
        // An `admin` entry is never `None` (empty scopes read as unrestricted),
        // so this arm is a non-admin previous entry — which `create_acl`'s
        // role-change conflict refuses before reaching here. Treat it as a
        // conferral rather than silently as "no widening".
        ActScope::None => return true,
        ActScope::Contexts(cs) => cs,
    };
    if new_scopes.is_empty() {
        // Unrestricted, and `prev` was not (it had named contexts).
        return true;
    }
    new_scopes.iter().any(|want| {
        !held
            .iter()
            .any(|have| vti_common::context_path::is_ancestor_or_self(have, want))
    })
}

/// The refusal for an admin-conferring call with no live elevation.
///
/// [`AppError::StepUpRequired`] renders as `403 step_up_required`, which is
/// the signal the admin console turns into a passkey prompt; the message names
/// the ceremony for every other caller.
pub fn required(what: &str) -> AppError {
    AppError::StepUpRequired(format!(
        "{what} requires a fresh step-up — run auth/passkey/login/{{start,finish}}/0.2 \
         with `purpose: stepUp`, then retry"
    ))
}
