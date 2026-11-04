//! Collection client methods (`vta/collection/*/0.1`, VTI-NTF-080 – 093).
//!
//! A VTA holds the keys of the DIDs it mints for its principal — personas — and those DIDs
//! advertise a mediator. The mediator permits **one connection per DID**: a second evicts the
//! first. So at most one party collects for a persona at a time, and the VTA and a client agree
//! which of them it is by a **collection claim**, a lease the VTA records:
//!
//! - [`VtaClient::collection_claim`] makes this client the collector until the claim's end, or
//!   renews the claim it holds. The VTA stops collecting and closes its own connection before it
//!   answers. Open your connection only once you hold the grant, ask for twenty-four hours, renew
//!   once half of it has passed, and close the connection before `endsAt` less your clock-skew
//!   tolerance unless you have renewed (VTI-NTF-083).
//! - [`VtaClient::collection_release`] ends this client's claim at once — **stop collecting
//!   first**, then release — or makes another client's unrenewable, ending at its stated end.
//! - [`VtaClient::collection_list`] shows who collects for each persona of a context: the VTA, a
//!   claimant until when, or nobody and why (`limit`, `conflict`, `disabled`).
//!
//! Claims are served whether or not the VTA's operator has enabled collection by default
//! (VTI-NTF-093), so a client claims before it connects in every case. Holding a claim is not
//! holding the persona's keys, and confers no authority. Hand every `notifications/notify` and
//! `notifications/relay` you collect to the VTA with
//! [`VtaClient::notifications_deposit_json`] (VTI-NTF-092).
//!
//! Declared refusals (`notCollectable`, `claimHeld`, `claimNotRenewable`) arrive as
//! [`VtaError::Rejected`] with their code.

use vti_specs::vta::collection;

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

/// Round-trip timeout (seconds). A claim waits for the VTA to close its own connection for the
/// identifier before it answers, which is bounded on the VTA's side well inside this.
const COLLECTION_TT_TIMEOUT: u64 = 30;

impl VtaClient {
    async fn collection_call<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        uri: &str,
        payload: &P,
    ) -> Result<R, VtaError> {
        let payload = serde_json::to_value(payload)
            .map_err(|e| VtaError::Validation(format!("{uri} request: {e}")))?;
        let answer = self
            .dispatch_trust_task(uri, payload, COLLECTION_TT_TIMEOUT)
            .await?;
        serde_json::from_value(answer).map_err(|e| {
            VtaError::Protocol(format!("{uri} response does not match its schema: {e}"))
        })
    }

    /// `vta/collection/claim/0.1` — become, until the answered `endsAt`, the one collector of
    /// `identifier`'s messages at its mediator, or renew the claim this client holds
    /// (`renewed: true`). Do not connect before this answers.
    pub async fn collection_claim(
        &self,
        req: &collection::claim::v0_1::Payload,
    ) -> Result<collection::claim::v0_1::Response, VtaError> {
        self.collection_call(trust_tasks::TASK_VTA_COLLECTION_CLAIM_0_1, req)
            .await
    }

    /// [`Self::collection_claim`], with the payload and the answer as JSON.
    pub async fn collection_claim_json(
        &self,
        req: serde_json::Value,
    ) -> Result<serde_json::Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_COLLECTION_CLAIM_0_1,
            req,
            COLLECTION_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/collection/release/0.1` — release the collection claim for `identifier`. Released by
    /// its claimant (who has already stopped collecting) it ends at once; released by anyone
    /// else it becomes unrenewable and ends at its stated end. `endsAt` is absent when no claim
    /// was in force.
    pub async fn collection_release(
        &self,
        req: &collection::release::v0_1::Payload,
    ) -> Result<collection::release::v0_1::Response, VtaError> {
        self.collection_call(trust_tasks::TASK_VTA_COLLECTION_RELEASE_0_1, req)
            .await
    }

    /// [`Self::collection_release`], with the payload and the answer as JSON.
    pub async fn collection_release_json(
        &self,
        req: serde_json::Value,
    ) -> Result<serde_json::Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_COLLECTION_RELEASE_0_1,
            req,
            COLLECTION_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/collection/list/0.1` — who collects for each persona of `contextId`. A page carrying
    /// a `nextCursor` is not the whole listing: pass it back as `cursor`, with the same filters.
    pub async fn collection_list(
        &self,
        req: &collection::list::v0_1::Payload,
    ) -> Result<collection::list::v0_1::Response, VtaError> {
        self.collection_call(trust_tasks::TASK_VTA_COLLECTION_LIST_0_1, req)
            .await
    }

    /// [`Self::collection_list`], with the payload and the answer as JSON.
    pub async fn collection_list_json(
        &self,
        req: serde_json::Value,
    ) -> Result<serde_json::Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_COLLECTION_LIST_0_1,
            req,
            COLLECTION_TT_TIMEOUT,
        )
        .await
    }
}
