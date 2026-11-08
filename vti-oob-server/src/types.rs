//! The `auth/oob/*` wire types, generated from the specification
//! (trust-tasks-tf #738) and re-exported under the names the handlers use.
//! Behaviour stays hand-written over them; a type URI comes from the
//! generated payload's `TYPE_URI`.
//!
//! One version of each task is served — the current one: `request/0.2`,
//! `claim/0.2`, `prove/0.3`, `respond/0.3` carrying a `grant/0.3`,
//! `redeem/0.2`, and `identify/0.1` / `cancel/0.1`. The 0.2/0.3 revisions
//! spell every instant an RFC 3339 `…At` (`claimClosesAt`, `decisionClosesAt`,
//! `sessionEndsAt`) where 0.1 had integer epoch seconds; the record keeps
//! epoch seconds and converts at the wire.

use vti_specs_core::auth::oob as spec;

pub use spec::cancel::v0_1::{Payload as CancelPayload, Response as CancelResponse};
pub use spec::claim::v0_2::{Payload as ClaimPayload, Response as Step1, Service as ServiceRef};
pub use spec::grant::v0_3::{Payload as GrantPayload, PayloadDecision as GrantDecision};
pub use spec::identify::v0_1::Payload as IdentifyPayload;
pub use spec::prove::v0_3::{Payload as ProvePayload, Requester, Response as Step2};
pub use spec::redeem::v0_2::{Payload as RedeemPayload, Response as RedeemResponse};
pub use spec::request::v0_2::{Payload as RequestPayload, Response as RequestResponse};
pub use spec::respond::v0_3::{Payload as RespondPayload, Response as RespondResponse};

pub const REQUEST_TYPE: &str = <RequestPayload as trust_tasks_rs::Payload>::TYPE_URI;
pub const CLAIM_TYPE: &str = <ClaimPayload as trust_tasks_rs::Payload>::TYPE_URI;
pub const PROVE_TYPE: &str = <ProvePayload as trust_tasks_rs::Payload>::TYPE_URI;
pub const IDENTIFY_TYPE: &str = <IdentifyPayload as trust_tasks_rs::Payload>::TYPE_URI;
pub const RESPOND_TYPE: &str = <RespondPayload as trust_tasks_rs::Payload>::TYPE_URI;
pub const GRANT_TYPE: &str = <GrantPayload as trust_tasks_rs::Payload>::TYPE_URI;
pub const REDEEM_TYPE: &str = <RedeemPayload as trust_tasks_rs::Payload>::TYPE_URI;
pub const CANCEL_TYPE: &str = <CancelPayload as trust_tasks_rs::Payload>::TYPE_URI;
