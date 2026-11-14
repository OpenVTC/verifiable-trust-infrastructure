//! `vtc/oid4vp/identities/list/0.1` — the administrators' view of the
//! community's OpenID4VP verifier identities (#1988).
//!
//! | task | signed by | authority (the signer's ACL row, read now) |
//! |---|---|---|
//! | `vtc/oid4vp/identities/list/0.1` | an administrator | `vtc.config.admin` — the authority that installs and removes an identity |
//!
//! The work is [`crate::oid4vp::status`]; this module maps the wire to it.

use super::routing::{Routes, on};
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_specs::vtc::oid4vp::identities::list::v0_1 as list;

use super::helpers::{TrustTaskOutcome, app_error_to_reject, success_response};
use super::{JoinAuthCtx, capable_signer, parse_spec_payload};
use crate::acl::Capability;
use crate::server::AppState;

/// Register every task this family serves (#2579).
pub(super) fn register(routes: Routes) -> Routes {
    on!(routes, list::Payload => |state, ctx, doc| handle_identities_list(state, ctx, doc))
}

async fn handle_identities_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Consumer rule 1: the authority that installs an identity.
    if let Err(reject) = capable_signer(state, ctx, &doc, Capability::ConfigAdmin, None).await {
        return reject;
    }
    if let Err(reject) = parse_spec_payload::<list::Payload>(&doc) {
        return reject;
    }
    match crate::oid4vp::status::read(state, chrono::Utc::now()).await {
        Ok(response) => success_response::<_, list::Response>(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}
