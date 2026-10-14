//! `vtc/oid4vp/identities/list/0.1` — the administrators' view of the
//! community's OpenID4VP verifier identities (#1988).
//!
//! | task | signed by | authority (the signer's ACL row, read now) |
//! |---|---|---|
//! | `vtc/oid4vp/identities/list/0.1` | an administrator | `vtc.config.admin` — the authority that installs and removes an identity |
//!
//! The work is [`crate::oid4vp::status`]; this module maps the wire to it.

use serde_json::Value;
use trust_tasks_rs::specs::vtc::oid4vp::identities::list::v0_1 as list;
use trust_tasks_rs::{Payload, TrustTask};

use super::helpers::{TrustTaskOutcome, app_error_to_reject, success_response};
use super::{JoinAuthCtx, capable_signer, parse_spec_payload};
use crate::acl::Capability;
use crate::server::AppState;

pub(crate) const IDENTITIES_LIST_TYPE: &str = <list::Payload as Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[IDENTITIES_LIST_TYPE];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        IDENTITIES_LIST_TYPE => handle_identities_list(state, ctx, doc).await,
        _ => return None,
    })
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
