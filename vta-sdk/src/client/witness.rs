//! Witnessed-party client methods (`vta/witness/*/0.2`) — the VTA is the participating party of
//! a `witness/session` for its principal: it builds and signs every document as the principal's
//! relationship DID, and verifies and stores what the witness returns. The caller **carries the
//! documents**: it sends each one to the witness *from the relationship DID* (the witness checks
//! that the transport-proven sender is the document's `issuer`, and replies to it) and hands
//! each answer back unaltered. The VTA never contacts the witness.
//!
//! The round (`vta/_shared/0.6/CONVENTIONS.md`):
//!
//! 1. [`VtaClient::witness_open`] — the `witness/session/0.2` document to send;
//! 2. [`VtaClient::witness_present`] — hand back the witness's session `#response`; the
//!    `witness/session/submit/0.2` document to send, the member presentation (if any) in its
//!    `memberPresentation`;
//! 3. [`VtaClient::witness_accept`] — hand back the witness's submit `#response`; the stored
//!    VWC's handle and its evidence.
//!
//! [`VtaClient::witness_list`] (`vta/witness/list/0.1`) reads back every stored VWC with its
//! evidence exactly as stored — how a client that lost `accept`'s answer, or a second device,
//! rebuilds its record of a witnessing.
//!
//! A refusal from the witness ends the session at the caller and is not handed back; open a new
//! session to try again. Every step is safe to repeat (`retry_safety`: `RetrySafe`).
//!
//! Every method takes the task's generated payload type and returns its generated response
//! type (`trust_tasks_rs::specs::vta::witness`). Declared refusals (`sessionUnknown`,
//! `responseInvalid`, `vwcInvalid`, …) arrive as [`VtaError::Rejected`] with their code.

use trust_tasks_rs::specs::vta::witness;

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

/// Round-trip timeout (seconds). Each step resolves the witness's DID to verify its proofs.
const WITNESS_TT_TIMEOUT: u64 = 30;

impl VtaClient {
    async fn witness_call<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        uri: &str,
        payload: &P,
    ) -> Result<R, VtaError> {
        let payload = serde_json::to_value(payload)
            .map_err(|e| VtaError::Validation(format!("{uri} request: {e}")))?;
        let answer = self
            .dispatch_trust_task(uri, payload, WITNESS_TT_TIMEOUT)
            .await?;
        serde_json::from_value(answer).map_err(|e| {
            VtaError::Protocol(format!("{uri} response does not match its schema: {e}"))
        })
    }

    /// `vta/witness/open/0.2` — open a witnessed session for one of the principal's
    /// relationships. Send the returned `document` to the witness from the relationship DID.
    pub async fn witness_open(
        &self,
        req: &witness::open::v0_2::Payload,
    ) -> Result<witness::open::v0_2::Response, VtaError> {
        self.witness_call(trust_tasks::TASK_VTA_WITNESS_OPEN_0_2, req)
            .await
    }

    /// `vta/witness/present/0.2` — hand back the witness's session answer; send the returned
    /// submit `document` to the witness from the relationship DID, and discard it once answered.
    pub async fn witness_present(
        &self,
        req: &witness::present::v0_2::Payload,
    ) -> Result<witness::present::v0_2::Response, VtaError> {
        self.witness_call(trust_tasks::TASK_VTA_WITNESS_PRESENT_0_2, req)
            .await
    }

    /// `vta/witness/list/0.1` — the stored VWCs the caller may read, each with its evidence,
    /// oldest first. Filter by `relationshipDid` when one relationship's are wanted. A page with
    /// `truncated: true` is not the whole listing: pass its `cursor` back for the next.
    pub async fn witness_list(
        &self,
        req: &witness::list::v0_1::Payload,
    ) -> Result<witness::list::v0_1::Response, VtaError> {
        self.witness_call(trust_tasks::TASK_VTA_WITNESS_LIST_0_1, req)
            .await
    }

    /// `vta/witness/accept/0.2` — hand back the witness's answer to the submission; the VTA
    /// verifies the VWC and stores it with its evidence.
    pub async fn witness_accept(
        &self,
        req: &witness::accept::v0_2::Payload,
    ) -> Result<witness::accept::v0_2::Response, VtaError> {
        self.witness_call(trust_tasks::TASK_VTA_WITNESS_ACCEPT_0_2, req)
            .await
    }
}
