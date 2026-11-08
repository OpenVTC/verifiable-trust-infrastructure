//! Held-notification client methods (`vta/notifications/*/0.1`, VTI-NTF-050 – 053).
//!
//! A VTA holds each notification it accepts — directly by `notifications/notify`, or by
//! `notifications/relay` — in the trust context of the DID it was addressed to. A client with
//! standing in that context lists them ([`VtaClient::notifications_list`]), reads one with the
//! document that delivered it ([`VtaClient::notifications_show`]) and dismisses one
//! ([`VtaClient::notifications_dismiss`]). None of these tells anybody anything: the VTA sends
//! nothing to the originator, a relayer or the thing's holder because a client read or dismissed
//! a notification, and opening the thing a notification points at is the client's own step —
//! `subject.openWith` sent to `subject.heldBy` — taken only at the principal's choice
//! (VTI-NTF-053).
//!
//! A notification confers no authority and is no evidence of eligibility (VTI-NTF-004): show
//! one only as what it states — its originator, kind, holder, identifier, audience and period
//! (VTI-NTF-063 for the kind `election`).
//!
//! # Why `show` has a JSON form
//!
//! `show` returns the delivering document **exactly as received**, so the client can verify the
//! originator's proof and every relay itself (VTI-NTF-050). The typed response keeps that
//! document as an opaque object, but a client re-serialising the whole response through typed
//! structs elsewhere would rewrite its timestamps and no longer hold the bytes the proofs cover.
//! [`VtaClient::notifications_show_json`] and [`VtaClient::notifications_list_json`] answer the
//! VTA's JSON unchanged.
//!
//! # Deposit
//!
//! A notification addressed to a persona DID whose mediator socket this client holds arrives
//! here, not at the VTA. [`VtaClient::notifications_deposit_json`] hands it to the VTA **exactly
//! as received** (VTI-NTF-054): pass the received JSON itself, never a value re-serialised from a
//! typed form, and deposit every such document — choosing not to deposit one is declining it,
//! which is the VTA's acceptance policy's decision, not the client's. Answer the sender yourself
//! with the receipt `notifications/notify` defines, the same whatever the VTA answers.
//!
//! Declared refusals (`notificationUnknown`, `notAddressedHere`, `documentInvalid`) arrive as
//! [`VtaError::Rejected`] with their code.

use vti_specs::vta::notifications;

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

/// Round-trip timeout (seconds). Every task reads the VTA's own store only.
const NOTIFICATIONS_TT_TIMEOUT: u64 = 20;

impl VtaClient {
    async fn notifications_call<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        uri: &str,
        payload: &P,
    ) -> Result<R, VtaError> {
        let payload = serde_json::to_value(payload)
            .map_err(|e| VtaError::Validation(format!("{uri} request: {e}")))?;
        let answer = self
            .dispatch_trust_task(uri, payload, NOTIFICATIONS_TT_TIMEOUT)
            .await?;
        serde_json::from_value(answer).map_err(|e| {
            VtaError::Protocol(format!("{uri} response does not match its schema: {e}"))
        })
    }

    /// `vta/notifications/list/0.1` — the notifications held in `contextId`, most recently
    /// received first; dismissed and lapsed ones only when asked for. A page carrying a
    /// `nextCursor` is not the whole listing: pass it back as `cursor`, with the same filters.
    pub async fn notifications_list(
        &self,
        req: &notifications::list::v0_1::Payload,
    ) -> Result<notifications::list::v0_1::Response, VtaError> {
        self.notifications_call(trust_tasks::TASK_VTA_NOTIFICATIONS_LIST_0_1, req)
            .await
    }

    /// [`Self::notifications_list`], with the payload and the answer as JSON.
    pub async fn notifications_list_json(
        &self,
        req: serde_json::Value,
    ) -> Result<serde_json::Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_NOTIFICATIONS_LIST_0_1,
            req,
            NOTIFICATIONS_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/notifications/show/0.1` — one held notification and the document that delivered
    /// it, unchanged. Verify `document` yourself rather than take the VTA's word for
    /// `originator` and `relayedBy` (`notifications/relay` consumer item 2).
    pub async fn notifications_show(
        &self,
        req: &notifications::show::v0_1::Payload,
    ) -> Result<notifications::show::v0_1::Response, VtaError> {
        self.notifications_call(trust_tasks::TASK_VTA_NOTIFICATIONS_SHOW_0_1, req)
            .await
    }

    /// [`Self::notifications_show`], with the payload and the answer as JSON: the answer's
    /// `document` is the delivering document byte for byte as the VTA holds it. See the module
    /// docs for why.
    pub async fn notifications_show_json(
        &self,
        req: serde_json::Value,
    ) -> Result<serde_json::Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_NOTIFICATIONS_SHOW_0_1,
            req,
            NOTIFICATIONS_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/notifications/dismiss/0.1` — dismiss one held notification. `changed` is `false`
    /// when it was already dismissed. It stays readable, and listable when asked for, until it
    /// lapses (VTI-NTF-052).
    pub async fn notifications_dismiss(
        &self,
        req: &notifications::dismiss::v0_1::Payload,
    ) -> Result<notifications::dismiss::v0_1::Response, VtaError> {
        self.notifications_call(trust_tasks::TASK_VTA_NOTIFICATIONS_DISMISS_0_1, req)
            .await
    }

    /// [`Self::notifications_dismiss`], with the payload and the answer as JSON.
    pub async fn notifications_dismiss_json(
        &self,
        req: serde_json::Value,
    ) -> Result<serde_json::Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_NOTIFICATIONS_DISMISS_0_1,
            req,
            NOTIFICATIONS_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/notifications/deposit/0.1` — hand the VTA a `notifications/notify` or
    /// `notifications/relay` document this client received for a DID the VTA holds keys of in
    /// `contextId` (VTI-NTF-054 – 056). The VTA verifies and holds it exactly as a direct
    /// delivery and answers the same receipt whatever it did. Prefer
    /// [`Self::notifications_deposit_json`]: the typed payload keeps `document` as an opaque
    /// map, but only the received JSON is guaranteed to be the bytes its proofs cover.
    pub async fn notifications_deposit(
        &self,
        req: &notifications::deposit::v0_1::Payload,
    ) -> Result<notifications::deposit::v0_1::Response, VtaError> {
        self.notifications_call(trust_tasks::TASK_VTA_NOTIFICATIONS_DEPOSIT_0_1, req)
            .await
    }

    /// [`Self::notifications_deposit`], with the payload and the answer as JSON:
    /// `{"contextId": …, "document": <the document exactly as received>}`.
    pub async fn notifications_deposit_json(
        &self,
        req: serde_json::Value,
    ) -> Result<serde_json::Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_NOTIFICATIONS_DEPOSIT_0_1,
            req,
            NOTIFICATIONS_TT_TIMEOUT,
        )
        .await
    }
}
