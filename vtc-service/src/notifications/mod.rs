//! Notifications (VTI-NTF-001 – 063): this community as **originator** of the `election` kind,
//! and as a **recipient** and **relayer** of what other parties notify it of.
//!
//! - [`election`] (feature `voting`): an election under a credential roll naming a member party
//!   is notified to that party once registered, and withdrawn if it is cancelled or closed
//!   before voting closes (VTI-NTF-060, VTI-NTF-061). The notice is recorded before it is sent
//!   and sent by the election sweeper, its one retry owner, through the durable member push
//!   (`crate::member_push`, VTI-NTF-020).
//! - [`inbox`]: a `notifications/notify` or `notifications/relay` addressed to this community,
//!   verified layer by layer, held by the stated acceptance policy, and relayed to the
//!   community's members only when an administrator decides it, after being shown what the
//!   relay discloses (VTI-NTF-040 – 046). Every later revision — a withdrawal included — is
//!   relayed to everyone an earlier one was (VTI-NTF-044).
//!
//! Nothing here reports to an originator whom a notification was relayed to (VTI-NTF-043).

#[cfg(feature = "voting")]
pub mod election;
pub mod inbox;

use serde_json::Value;

use crate::error::AppError;
use crate::server::AppState;

/// Sign `payload` as a `type_uri` document from this community to `recipient` and queue it on
/// the durable member push (TSP > DIDComm > REST, with escalation). `Ok` means queued, never
/// delivered (R1.1); the push engine owns its delivery.
pub(crate) async fn push_signed(
    state: &AppState,
    recipient: &str,
    type_uri: &str,
    payload: Value,
    deliver_by: std::time::Duration,
) -> Result<String, AppError> {
    let vtc_did = own_did(state)
        .await
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?;
    let signer = state
        .credential_signer
        .as_ref()
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;
    let doc = vti_common::capability_client::build_document(&vtc_did, recipient, type_uri, payload);
    let mut value = serde_json::to_value(&doc)
        .map_err(|e| AppError::Internal(format!("serialise a notification document: {e}")))?;
    signer.sign_operational_doc(&mut value).await?;
    crate::member_push::push_trust_task(state, recipient, value, deliver_by).await
}

/// This community's DID, when configured.
pub(crate) async fn own_did(state: &AppState) -> Option<String> {
    state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
}

/// How long a push may take: until `until`, and at least a minute.
pub(crate) fn deliver_by(
    until: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
    otherwise: std::time::Duration,
) -> std::time::Duration {
    match until {
        Some(u) => (u - now)
            .to_std()
            .unwrap_or_default()
            .max(std::time::Duration::from_secs(60)),
        None => otherwise,
    }
}
