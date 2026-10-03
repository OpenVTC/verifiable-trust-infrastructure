//! Admin elevation — the one place that answers "is this caller carrying a
//! live step-up right now?", and the one refusal every admin-conferring path
//! emits when they are not.
//!
//! ## Why this is its own module
//!
//! VTI-OPS-050/051 put a **fresh reauthentication** in front of conferring
//! administrative authority. Both halves of the answer live here so they cannot
//! drift apart:
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
//!   [`Invariant::StepUpForAdmin`](crate::ceremony::Invariant). [`verified`]
//!   supplies the fact it reads.
//! - `acl/grant` and `acl/update` write an entry rather than moving one. Their
//!   gate is bound to the operation ([`crate::acl::bound_step_up`]) and asked
//!   only when the write **widens** administrative authority
//!   ([`crate::acl::AdminAuthority::widens_from`]) — so a rewrite that confers
//!   nothing new (the console's label edit) does not demand a passkey.
//!
//! ## A role is a ceiling, and that matters here
//!
//! A VTC entry holds an explicit capability set beneath its administrative
//! role (`vtc-admin-roles.md` §6, VTI-ACL-030): the role is a ceiling, never
//! the grant. So a gate that read only the role would over-trust a narrowed
//! entry, and a widening that never touches the role — `capabilities: listed`
//! back to `ceiling`, a qualifier widened, approve authority added — is a
//! grant like any other. That is why the widening test compares what the entry
//! can exercise and approve before and after, never the role alone.

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
