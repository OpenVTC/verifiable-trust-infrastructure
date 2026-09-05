//! VTA persona store — the holder's own identity, and the contacts peers
//! disclose to them.
//!
//! The fourth holder store, beside the secrets vault, the credential vault and
//! application state. It exists as a distinct store because **disclosure
//! control is its point**, and a maintainer that cannot read a record cannot
//! decide which of its members may leave, cannot audit which ones did, and
//! cannot answer "what have I shared with whom". `vta/app-state` promises never
//! to interpret its records, so it cannot host this; and a namespace there is
//! collision avoidance rather than a trust boundary, so a compromised
//! application sharing a context could remove the holder's identity data.
//!
//! # The boundary is one-way
//!
//! The pool and profiles are **agent-scoped**; bindings, contacts and
//! disclosure records are **context-scoped**. Nothing inside a context may read
//! the pool — the holder pushes a materialised projection down, and a context
//! never pulls.
//!
//! That is a rule about *direction* rather than a permission, because the
//! permission form invites the wrong implementation: a guard written as "is this
//! caller an administrator" passes for an administrator scoped to a single
//! context, who then reads identity data belonging to every other context. An
//! access-control failure over a readable pool discloses everything; a pool no
//! context can address has nothing to disclose.
//!
//! Authorization is enforced at dispatch, not here. What this crate provides is
//! a key layout in which the two scopes are *separately addressable*, so the
//! enforcement is expressible — and so a context-scoped enumeration scans a
//! space that structurally cannot contain an agent-scoped record, rather than
//! scanning everything and filtering. A filter is a line of code that can be
//! got wrong; an address space cannot.
//!
//! # What this crate does not do
//!
//! No cryptography beyond the at-rest wrapper and the correlation index's keyed
//! hash. Rung *selection* lives here; proof *derivation* stays in `vta-vault`,
//! so there is one BBS implementation in the workspace rather than two.

pub mod binding;
pub mod correlation;
pub mod model;
pub mod profile;
pub mod storage;
pub mod store;

pub use binding::{BindingSummary, Bound, MaterialisedClaim};
pub use model::{
    Attribute, Binding, InlineValue, OverrideValue, Profile, ProfileEntry, ProofRung, Provenance,
    StaleReason, Ulid, ValueType, Version,
};
pub use profile::{ResolvedClaim, is_pool_free, new_profile};
pub use store::{Deleted, PersonaStore, Written, new_attribute};

#[cfg(test)]
mod published_types {
    //! The generated payload types are the contract. This asserts the published
    //! crate actually carries the persona family and that our model agrees with
    //! it on the members that matter — so a spec change that lands upstream
    //! without a corresponding change here fails a test rather than a
    //! production dispatch.

    /// Compile-time, not runtime: these are `const`, so a relaxation upstream
    /// should fail the *build* rather than a test run. A `MUST` that became a
    /// `SHOULD` in the spec would otherwise reach production as an accepted
    /// unsigned write.
    const _: () = {
        use trust_tasks_rs::specs::persona::attribute::put::v1_0::Payload;
        assert!(<Payload as trust_tasks_rs::Payload>::IS_PROOF_REQUIRED);
        assert!(<Payload as trust_tasks_rs::Payload>::IS_ISSUED_AT_REQUIRED);
    };

    #[test]
    fn persona_family_is_published_and_addressable() {
        use trust_tasks_rs::specs::persona::attribute::put::v1_0 as put;
        assert_eq!(
            <put::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            "https://trusttasks.org/spec/persona/attribute/put/1.0"
        );
    }

    #[test]
    fn our_value_types_match_the_published_enum() {
        // The store validates values against these; a variant added upstream
        // without a matching arm here would silently reject a legal value.
        use trust_tasks_rs::specs::persona::attribute::put::v1_0 as put;
        for (ours, theirs) in [
            (crate::ValueType::String, put::ValueType::String),
            (crate::ValueType::Number, put::ValueType::Number),
            (crate::ValueType::Boolean, put::ValueType::Boolean),
            (crate::ValueType::Date, put::ValueType::Date),
            (crate::ValueType::Object, put::ValueType::Object),
        ] {
            assert_eq!(
                serde_json::to_value(ours).unwrap(),
                serde_json::to_value(theirs).unwrap(),
                "our ValueType and the published one disagree on the wire"
            );
        }
    }
}
