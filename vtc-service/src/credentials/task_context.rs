//! Trust Task Context Binding — which exchange a credential came out of.
//!
//! DTG Credentials gives every credential an optional `taskContext`: the
//! `threadId` of the trust task exchange it was issued in. On the VWC it is
//! REQUIRED, because a witness attestation only means anything under the
//! conditions it was made under, and those live in the exchange.
//!
//! Security Considerations 5 names the attack this exists to stop —
//! **context collapse**: "A credential presented outside the trust task
//! exchange in which it was issued may be misinterpreted as evidence of a
//! completed ceremony." The credential is genuinely signed, correctly typed,
//! unrevoked and in date. What is false is only the *exchange* it is offered
//! against. Nothing else in a credential says which exchange that was, so
//! without reading `taskContext` a verifier has no way to tell the difference
//! and every ceremony that reasons over presented credentials is exposed.
//!
//! ## Absence is refused; a different thread is reported
//!
//! Those are two different failures and they get two different answers.
//!
//! A VWC with no `taskContext` is **malformed** — the specification marks the
//! property REQUIRED on that type, and `dtg_credentials` refuses to build one
//! without it. So does [`resolve`], and it refuses rather than substituting the
//! current thread: defaulting would manufacture the exact binding the verifier
//! is supposed to be checking, and would do it most eagerly for the credential
//! least entitled to it.
//!
//! A credential naming a *different* thread is refused by nobody, because it is
//! the ordinary case. A VWC's `taskContext` names the exchange the **witnessing**
//! happened in, which is not the join exchange it is later presented in; every
//! honest witness presented at a join is a [`TaskContextBinding::ForeignExchange`].
//! Rejecting on mismatch would refuse all of them. What the verifier must not do
//! is read such a credential as evidence that *this* ceremony completed, which is
//! the specification's own note: a verifier "MUST NOT interpret a
//! `taskContext`-bearing credential as proof that the associated trust task
//! completed unless the matching trust task outcome evidence is also present and
//! verified". So the verdict is surfaced into the ceremony facts and the policy
//! decides what it is allowed to satisfy — the same division of labour as
//! [`crate::credentials::witness`]: the host settles the question, the policy
//! branches on the answer.

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;

/// Whether DTG Credentials marks `taskContext` REQUIRED on the credential being
/// resolved.
///
/// Passed in rather than derived here because the two receipt paths classify a
/// credential differently — `credentials::ingress` reads the JSON-LD `type`
/// array, the presentation path reads an SD-JWT-VC `vct` — and neither should
/// have to agree with the other about how to spell a credential type in order
/// for the requirement to be enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// The VWC. Absence is a rejection.
    Required,
    /// Every other DTG credential type: `taskContext` is OPTIONAL, and a
    /// credential without one "MUST be interpretable standing alone,
    /// independent of any exchange".
    Optional,
}

/// The host's verdict on where a credential's `taskContext` points, relative to
/// the exchange it was presented in. Resolved before policy runs.
///
/// The variants are kept apart because a policy that collapses them loses the
/// only distinction that matters here — between a credential issued *inside*
/// this exchange, which may speak to its outcome, and one issued elsewhere,
/// which may not.
///
/// Serialized exactly like [`crate::credentials::witness::WitnessBinding`]
/// beside it: internally tagged on `state`, camelCase variant names,
/// `snake_case` payload members. The camelCase in this feature is the
/// specification's `taskContext`, read *off the credential*; what is written
/// *into* the facts document follows that document's own contract, which is
/// `snake_case` (see the module doc of [`crate::ceremony::facts`] — the
/// compiled Rego reads those keys literally).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum TaskContextBinding {
    /// The credential names this exchange. The only variant that can support a
    /// claim about *this* ceremony's outcome.
    SameExchange,
    /// The credential names a different exchange, carried here so an operator
    /// reading an audit record can find it. Not an accusation: a witness
    /// attesting an earlier exchange is exactly this, and honest.
    ForeignExchange { thread_id: String },
    /// The credential asserts no `taskContext`. Reachable only where the
    /// property is OPTIONAL — [`Requirement::Required`] turns this into an
    /// error instead.
    Absent,
    /// The credential names an exchange but this ceremony has none to compare
    /// against (a synchronous REST submission, which is not threaded). Distinct
    /// from [`Self::ForeignExchange`]: we are not saying the credential belongs
    /// elsewhere, we are saying there is nothing here for it to belong to.
    Unthreaded,
}

impl TaskContextBinding {
    /// Whether the credential was issued inside the exchange it is being
    /// presented in. The one predicate a policy needs to refuse a credential as
    /// evidence of *this* ceremony's outcome.
    pub fn is_same_exchange(&self) -> bool {
        matches!(self, Self::SameExchange)
    }
}

/// Resolve a presented credential's task-context binding, refusing the absence
/// the specification does not permit.
///
/// `asserted` is the credential's own `taskContext`; `exchange_thread` is the
/// thread of the exchange it arrived on, or `None` for an unthreaded ceremony.
///
/// The two identifiers are compared **verbatim**. DTG Credentials defines
/// `taskContext` as *the* `threadId` and specifies no canonicalization, so
/// there is no sanctioned way to decide that `urn:uuid:x` and `x` are the same
/// thread. Guessing one would be a verifier inventing the equality it is
/// supposed to be testing, and it would fail open — the mistake shows up as a
/// foreign credential accepted as local. Comparing verbatim fails the other
/// way: a peer that spells the thread differently is reported as
/// [`TaskContextBinding::ForeignExchange`] and its credential simply cannot
/// speak to this ceremony's outcome. If a normalization is ever needed it
/// belongs in the specification first.
pub fn resolve(
    requirement: Requirement,
    asserted: Option<&str>,
    exchange_thread: Option<&str>,
) -> Result<TaskContextBinding, AppError> {
    let Some(asserted) = asserted else {
        // Checked before anything about the exchange: a VWC without a
        // `taskContext` is malformed on its own terms, whatever it was
        // presented against.
        return match requirement {
            Requirement::Required => Err(missing()),
            Requirement::Optional => Ok(TaskContextBinding::Absent),
        };
    };
    Ok(match exchange_thread {
        Some(thread) if thread == asserted => TaskContextBinding::SameExchange,
        Some(_) => TaskContextBinding::ForeignExchange {
            thread_id: asserted.to_string(),
        },
        None => TaskContextBinding::Unthreaded,
    })
}

/// The rejection for a credential that must carry a `taskContext` and does not.
///
/// `Validation`, not `Forbidden`: nothing about the credential's cryptography
/// failed. It is structurally not the credential it claims to be, which is the
/// same answer `credentials::ingress` gives a document whose `type` array is
/// wrong.
pub fn missing() -> AppError {
    AppError::Validation(
        "WitnessCredential is missing the required `taskContext`; DTG Credentials \
         marks it REQUIRED on this type and a verifier cannot bind the credential \
         to the exchange it was issued in without it"
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const THREAD: &str = "urn:uuid:0b3f2a8e-1f8c-4a3d-9c1a-6d2f5e7b8c90";

    #[test]
    fn a_credential_naming_this_exchange_is_bound_to_it() {
        assert_eq!(
            resolve(Requirement::Optional, Some(THREAD), Some(THREAD)).unwrap(),
            TaskContextBinding::SameExchange
        );
        assert!(
            resolve(Requirement::Required, Some(THREAD), Some(THREAD))
                .unwrap()
                .is_same_exchange()
        );
    }

    /// The context-collapse case: a genuinely-signed credential from another
    /// exchange. It resolves, and it resolves to something a policy can tell
    /// apart from the local one.
    #[test]
    fn a_credential_from_another_exchange_is_foreign_not_bound() {
        let binding = resolve(Requirement::Optional, Some("urn:uuid:other"), Some(THREAD)).unwrap();
        assert_eq!(
            binding,
            TaskContextBinding::ForeignExchange {
                thread_id: "urn:uuid:other".into()
            }
        );
        assert!(!binding.is_same_exchange());
    }

    /// The whole point of the module: absence is refused, never filled in with
    /// the current thread. An implementation that defaulted would hand back
    /// `SameExchange` here — the strongest possible verdict, awarded to the
    /// credential that earned it least.
    #[test]
    fn a_witness_without_a_task_context_is_refused_not_defaulted() {
        let err = resolve(Requirement::Required, None, Some(THREAD)).unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("taskContext")),
            "{err:?}"
        );
    }

    /// Refused on its own terms — an unthreaded ceremony does not excuse a
    /// missing REQUIRED property, and neither does having nothing to compare
    /// against.
    #[test]
    fn a_witness_without_a_task_context_is_refused_even_unthreaded() {
        assert!(resolve(Requirement::Required, None, None).is_err());
    }

    #[test]
    fn absence_is_fine_where_the_specification_makes_it_optional() {
        assert_eq!(
            resolve(Requirement::Optional, None, Some(THREAD)).unwrap(),
            TaskContextBinding::Absent
        );
    }

    /// An unthreaded ceremony cannot bind anything, and says so rather than
    /// claiming the credential is foreign — there is no local thread for it to
    /// be foreign *to*.
    #[test]
    fn an_unthreaded_ceremony_binds_nothing() {
        assert_eq!(
            resolve(Requirement::Optional, Some(THREAD), None).unwrap(),
            TaskContextBinding::Unthreaded
        );
    }

    /// Verbatim comparison, asserted deliberately: the two spellings of one
    /// UUID are *not* silently the same thread. This test is the record of that
    /// decision, so a later reader adding normalization has to change it on
    /// purpose.
    #[test]
    fn thread_ids_are_compared_verbatim() {
        let bare = "0b3f2a8e-1f8c-4a3d-9c1a-6d2f5e7b8c90";
        assert!(
            !resolve(Requirement::Required, Some(bare), Some(THREAD))
                .unwrap()
                .is_same_exchange()
        );
    }

    /// The verdict rides into the policy `input` document, so its wire shape is
    /// part of the facts contract: tagged on `state`, camelCase variant names
    /// and a `snake_case` payload member, exactly like `WitnessBinding`. A
    /// policy is written against these literals, so drift here breaks rules
    /// that no longer match anything — silently, and in the allow direction for
    /// a rule phrased as a denial.
    #[test]
    fn the_wire_shape_matches_the_facts_contract() {
        assert_eq!(
            serde_json::to_value(TaskContextBinding::SameExchange).unwrap(),
            serde_json::json!({ "state": "sameExchange" })
        );
        assert_eq!(
            serde_json::to_value(TaskContextBinding::ForeignExchange {
                thread_id: "urn:uuid:other".into()
            })
            .unwrap(),
            serde_json::json!({ "state": "foreignExchange", "thread_id": "urn:uuid:other" })
        );
        let parsed: TaskContextBinding =
            serde_json::from_value(serde_json::json!({ "state": "absent" })).unwrap();
        assert_eq!(parsed, TaskContextBinding::Absent);
    }
}
