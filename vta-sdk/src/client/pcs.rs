//! Hidden-vetting PCS engine client methods (`vta/pcs/*/0.1`) — the VTA holds its principal's
//! PCS keys and runs every member-side hidden-vetting operation; the caller carries messages
//! between the VTA, the community and the other party, and never holds a key.
//!
//! This is how a client with no PCS implementation (a mobile wallet) takes part in hidden
//! vetting. The applicant's round:
//!
//! 1. [`VtaClient::pcs_applications_create`] — the application's PCS identifier, which goes in
//!    each `vetting/request`'s `ext` under the community's hidden-vetting namespace;
//! 2. [`VtaClient::pcs_verify_attestation`] — each `vetting/attestation` a vetter sends;
//! 3. [`VtaClient::pcs_prove`] — after `vtc/vetting/pcs-challenge`, the proof that goes in the
//!    join submission's `extensions.hiddenVetting`.
//!
//! A vetter's: [`VtaClient::pcs_root_request`] / [`VtaClient::pcs_root_accept`] around
//! `vtc/vetting/vetters/pcs-root`, [`VtaClient::pcs_tokens_request`] /
//! [`VtaClient::pcs_tokens_accept`] (or [`VtaClient::pcs_tokens_abandon`]) around each tick of
//! `vtc/vetting/vetters/pcs-tokens`, and [`VtaClient::pcs_attest`] after a session.
//!
//! Every method takes the task's generated payload type and returns its generated response
//! type (`trust_tasks_rs::specs::vta::pcs`), so a caller cannot build a request the schema would
//! refuse.

use serde::Serialize;
use serde::de::DeserializeOwned;
use trust_tasks_rs::specs::vta::pcs;

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

/// Round-trip timeout (seconds). Proving and attesting are pairing-heavy, so they get more.
const PCS_TT_TIMEOUT: u64 = 30;
const PCS_PROOF_TIMEOUT: u64 = 90;

impl VtaClient {
    async fn pcs_call<P: Serialize, R: DeserializeOwned>(
        &self,
        uri: &str,
        payload: &P,
        timeout: u64,
    ) -> Result<R, VtaError> {
        let payload = serde_json::to_value(payload)
            .map_err(|e| VtaError::Validation(format!("{uri} request: {e}")))?;
        let answer = self.dispatch_trust_task(uri, payload, timeout).await?;
        serde_json::from_value(answer).map_err(|e| {
            VtaError::Protocol(format!("{uri} response does not match its schema: {e}"))
        })
    }

    /// `vta/pcs/applications/create/0.1` — start a hidden-vetting application.
    pub async fn pcs_applications_create(
        &self,
        req: &pcs::applications::create::v0_1::Payload,
    ) -> Result<pcs::applications::create::v0_1::Response, VtaError> {
        self.pcs_call(
            trust_tasks::TASK_VTA_PCS_APPLICATIONS_CREATE_0_1,
            req,
            PCS_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/pcs/applications/show/0.1`.
    pub async fn pcs_applications_show(
        &self,
        req: &pcs::applications::show::v0_1::Payload,
    ) -> Result<pcs::applications::show::v0_1::Response, VtaError> {
        self.pcs_call(
            trust_tasks::TASK_VTA_PCS_APPLICATIONS_SHOW_0_1,
            req,
            PCS_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/pcs/applications/delete/0.1` — destroys the application's key and attestations.
    pub async fn pcs_applications_delete(
        &self,
        req: &pcs::applications::delete::v0_1::Payload,
    ) -> Result<pcs::applications::delete::v0_1::Response, VtaError> {
        self.pcs_call(
            trust_tasks::TASK_VTA_PCS_APPLICATIONS_DELETE_0_1,
            req,
            PCS_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/pcs/verify-attestation/0.1` — take in an attestation a vetter sent.
    pub async fn pcs_verify_attestation(
        &self,
        req: &pcs::verify_attestation::v0_1::Payload,
    ) -> Result<pcs::verify_attestation::v0_1::Response, VtaError> {
        self.pcs_call(
            trust_tasks::TASK_VTA_PCS_VERIFY_ATTESTATION_0_1,
            req,
            PCS_PROOF_TIMEOUT,
        )
        .await
    }

    /// `vta/pcs/prove/0.1` — the proof a hidden-vetting join submission carries.
    pub async fn pcs_prove(
        &self,
        req: &pcs::prove::v0_1::Payload,
    ) -> Result<pcs::prove::v0_1::Response, VtaError> {
        self.pcs_call(trust_tasks::TASK_VTA_PCS_PROVE_0_1, req, PCS_PROOF_TIMEOUT)
            .await
    }

    /// `vta/pcs/root-request/0.1` — a vetter's blinded enrolment request.
    pub async fn pcs_root_request(
        &self,
        req: &pcs::root_request::v0_1::Payload,
    ) -> Result<pcs::root_request::v0_1::Response, VtaError> {
        self.pcs_call(
            trust_tasks::TASK_VTA_PCS_ROOT_REQUEST_0_1,
            req,
            PCS_PROOF_TIMEOUT,
        )
        .await
    }

    /// `vta/pcs/root-accept/0.1` — unblind the community's answer into a class credential.
    pub async fn pcs_root_accept(
        &self,
        req: &pcs::root_accept::v0_1::Payload,
    ) -> Result<pcs::root_accept::v0_1::Response, VtaError> {
        self.pcs_call(
            trust_tasks::TASK_VTA_PCS_ROOT_ACCEPT_0_1,
            req,
            PCS_PROOF_TIMEOUT,
        )
        .await
    }

    /// `vta/pcs/tokens/request/0.1` — one draw of the token drip.
    pub async fn pcs_tokens_request(
        &self,
        req: &pcs::tokens::request::v0_1::Payload,
    ) -> Result<pcs::tokens::request::v0_1::Response, VtaError> {
        self.pcs_call(
            trust_tasks::TASK_VTA_PCS_TOKENS_REQUEST_0_1,
            req,
            PCS_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/pcs/tokens/accept/0.1` — take the community's answer to a draw into the wallet.
    pub async fn pcs_tokens_accept(
        &self,
        req: &pcs::tokens::accept::v0_1::Payload,
    ) -> Result<pcs::tokens::accept::v0_1::Response, VtaError> {
        self.pcs_call(
            trust_tasks::TASK_VTA_PCS_TOKENS_ACCEPT_0_1,
            req,
            PCS_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/pcs/tokens/abandon/0.1` — discard a draw the community refused.
    pub async fn pcs_tokens_abandon(
        &self,
        req: &pcs::tokens::abandon::v0_1::Payload,
    ) -> Result<pcs::tokens::abandon::v0_1::Response, VtaError> {
        self.pcs_call(
            trust_tasks::TASK_VTA_PCS_TOKENS_ABANDON_0_1,
            req,
            PCS_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/pcs/attest/0.1` — spend a token and attest for an applicant, after the human check.
    pub async fn pcs_attest(
        &self,
        req: &pcs::attest::v0_1::Payload,
    ) -> Result<pcs::attest::v0_1::Response, VtaError> {
        self.pcs_call(trust_tasks::TASK_VTA_PCS_ATTEST_0_1, req, PCS_PROOF_TIMEOUT)
            .await
    }

    /// `vta/pcs/vetter/show/0.1`.
    pub async fn pcs_vetter_show(
        &self,
        req: &pcs::vetter::show::v0_1::Payload,
    ) -> Result<pcs::vetter::show::v0_1::Response, VtaError> {
        self.pcs_call(
            trust_tasks::TASK_VTA_PCS_VETTER_SHOW_0_1,
            req,
            PCS_TT_TIMEOUT,
        )
        .await
    }
}
