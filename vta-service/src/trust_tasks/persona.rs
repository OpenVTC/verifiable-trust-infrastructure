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

use vta_sdk::trust_tasks as uris;
use vti_common::error::AppError;

use crate::auth::AuthClaims;

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
        let classified: std::collections::HashSet<&str> =
            REACH.iter().map(|(u, _)| *u).collect();
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
        assert!(orphans.is_empty(), "reach entries for tasks that do not exist: {orphans:#?}");
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
        for role in [Role::Application, Role::Reader, Role::Initiator, Role::Monitor] {
            let label = format!("{role:?}");
            let c = claims(role, &[]);
            let err = authorize(&c, uris::TASK_PERSONA_ATTRIBUTE_LIST_1_0, None).unwrap_err();
            assert!(matches!(err, AppError::Forbidden(_)), "{label} reached the pool");
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
        let err = authorize(&app, "https://trusttasks.org/spec/persona/made/up/9.9", Some("ctx"))
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    #[test]
    fn binding_set_is_holder_only_and_local_binding_set_is_not() {
        // The pair that most invites being collapsed. One crosses the boundary
        // and one does not.
        assert_eq!(reach_of(uris::TASK_PERSONA_BINDING_SET_1_0), Some(Reach::Holder));
        assert_eq!(
            reach_of(uris::TASK_PERSONA_LOCAL_BINDING_SET_1_0),
            Some(Reach::Context)
        );
    }
}
