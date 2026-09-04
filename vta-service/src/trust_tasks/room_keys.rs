//! The room-oracle slice — `spec/rooms/keys/present/0.1`.
//!
//! An agent asks its principal's VTA to mint a presentation for one room operation. The
//! orchestration is [`crate::operations::room_oracle`]; this is the dispatch surface.
//!
//! Three gates, in order, and the order matters:
//!
//! 1. **Capability.** [`Capability::RoomPresent`], registered upstream as `roomPresent`.
//!    Deliberately not [`Capability::Sign`]: an agent that may ask for a scoped,
//!    audience-bound presentation is not thereby an agent that may sign *anything at all*
//!    with its principal's key. Gating an oracle on the generic signing oracle would grant
//!    strictly more than the task needs, which is the opposite of what an oracle is for.
//! 2. **Context**, inside `resolve_holder_keys` — the caller must be permitted to act in the
//!    context that owns the principal's key. That is the privilege boundary a context exists
//!    to draw, and it is enforced where the key is resolved rather than re-derived here.
//! 3. **Attenuation**, inside the credential library — a caller cannot obtain more than the
//!    principal holds, because `attenuate` refuses to widen.
//!
//! # The presenter is the caller, always
//!
//! The minted leaf grants to the DID the *transport* authenticated, never to one named in
//! the payload. A caller cannot ask for a presentation made out to somebody else, which is
//! what stops this becoming a credential-minting service for third parties: the far side's
//! `authorize` refuses a chain whose leaf grants to anyone but the party that signed the
//! request, so a presentation minted for A is worthless to B even if B obtains it.

use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};
use vti_common::acl::{Capability, role_has_capability};

use crate::audit;
use crate::auth::AuthClaims;
use crate::operations::room_oracle;
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, reject_with,
    success_response,
};

/// Refuse unless the caller's role carries `cap`.
fn require_cap(
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    cap: Capability,
) -> Result<(), TrustTaskOutcome> {
    if role_has_capability(&auth.role, cap) {
        Ok(())
    } else {
        Err(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "minting a room presentation denied: role {} does not carry {cap:?}",
                    auth.role
                ),
            },
        ))
    }
}

/// `rooms/keys/present/0.1`.
pub(super) async fn handle_present(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = require_cap(auth, &doc, Capability::RoomPresent) {
        return r;
    }

    let req: trust_tasks_rs::specs::rooms::keys::present::v0_1::Payload = match parse_payload(&doc)
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // The action as its wire string. The generated enum is the spec's own vocabulary, so a
    // value outside it never reaches here — one fewer thing to validate by hand.
    let action = serde_json::to_value(req.action)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();

    let minted = match room_oracle::present(
        state,
        auth,
        &auth.did,
        &req.room_id,
        &action,
        req.audience.as_deref(),
        req.nonce.as_ref().map(|n| n.as_ref()),
    )
    .await
    {
        Ok(m) => m,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // Audited because it is consequential: a presentation was minted on the principal's
    // behalf, and "which agent obtained what standing in which room, and when" is the
    // sentence an incident review needs. The room is the resource; the agent is the actor.
    if let Err(e) = audit::record(
        &state.audit_sink,
        "rooms.keys.present",
        &auth.did,
        Some(&req.room_id),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        None,
    )
    .await
    {
        tracing::error!(error = %e, "failed to record a room-oracle audit entry");
    }

    success_response(&doc, minted)
}
