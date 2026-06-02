//! The ceremony decision pipeline — one pipeline, every community
//! state transition an instance of it.
//!
//! Design: `docs/05-design-notes/vtc-ceremony-pipeline.md` (with the
//! catalog, Rule-IR, and protocol companions). The thesis: a
//! community has many governed transitions — joining, leaving, role
//! changes, directory queries — that share one shape:
//!
//! ```text
//! TRIGGER → GATHER → VERIFY (host) → FACTS → EVALUATE (<purpose>.rego)
//!         → VERDICT → EFFECTS (<purpose>)
//! ```
//!
//! Everything expensive to build — verification, the verdict model,
//! versioning, governance, the visual authoring compiler — is built
//! once here and inherited by every ceremony, rather than wired
//! bespoke per purpose as in the MVP.
//!
//! ## What this module contains (pipeline stage A — the spine)
//!
//! - [`facts`] — the purpose-agnostic [`Facts`] contract (the typed
//!   policy `input`), replacing the MVP's lossy `vp_claims`.
//! - [`verdict`] — the four-valued [`Verdict`] (`allow` / `deny` /
//!   `refer` / `request_more`), replacing the MVP's boolean.
//! - [`verify`] — the [`VerifiedFacts`] typestate: the gate that
//!   guarantees the policy only ever sees verified facts.
//!
//! Still to land on top of this spine (pipeline §11): the
//! `verify → evaluate → effects` driver parameterized by purpose,
//! the host-enforced invariants (privilege ceiling, no-last-admin,
//! step-up, PII boundary), and the per-purpose effect handlers.
//!
//! ## Relationship to the existing `policy` + `join` modules
//!
//! This is the greenfield pipeline; [`crate::policy`] (the regorus
//! engine plus persistence) is **reused** underneath it — `Verdict`
//! parses the decision object [`crate::policy::engine::evaluate`]
//! returns.
//! The MVP's bespoke [`crate::join`] flow and its `vp_claims`
//! projection are what this pipeline supersedes; they remain in place
//! until ceremonies are ported over (build-vs-reuse map, pipeline
//! §10).

pub mod facts;
pub mod verdict;
pub mod verify;

pub use facts::{
    Actor, Context, Credential, CredentialStatus, Evidence, Facts, Invitation, MemberState,
    Presentation, Purpose, State, Subject,
};
pub use verdict::{Allow, Deny, Refer, RequestMore, Verdict};
pub use verify::{VerifiedFacts, VerifyError};
