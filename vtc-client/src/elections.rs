//! Community elections: `vtc/elections/{create,list,show,close,cancel,certify}/0.1` and
//! `vtc/elections/tickets/issue/0.1` (VTI-VOT-001 – 100).
//!
//! Signed Trust Tasks sent the way every `acl/*` call goes ([`crate::acl`]): over the client's
//! DIDComm or TSP session when it holds one, otherwise signed with a [`HolderKey`] and posted to
//! `POST {base}/trust-tasks`. A binding creation is parked for another holder of
//! `vtc.elections.manage`: that answer is [`VtcError::Parked`], not a refusal.
//!
//! Requests are validated against the published schema before they are sent, and replies are
//! decoded into the generated `Response` types.

use serde_json::{Value, json};
use trust_tasks_rs::validate::ValidatedPayload;

use crate::{HolderKey, VtcClient, VtcError};

/// The generated wire types, re-exported so a caller names the reply types without depending
/// on `trust-tasks-rs` itself.
pub use trust_tasks_rs::specs::vtc::elections::{
    cancel::v0_1 as cancel, certify::v0_1 as certify, close::v0_1 as close, create::v0_1 as create,
    list::v0_1 as list, show::v0_1 as show, tickets::issue::v0_1 as tickets_issue,
};

/// The Type URI of each task, read off the generated payloads.
pub mod task {
    use trust_tasks_rs::Payload;

    pub const CREATE: &str = <super::create::Payload as Payload>::TYPE_URI;
    pub const LIST: &str = <super::list::Payload as Payload>::TYPE_URI;
    pub const SHOW: &str = <super::show::Payload as Payload>::TYPE_URI;
    pub const CLOSE: &str = <super::close::Payload as Payload>::TYPE_URI;
    pub const CANCEL: &str = <super::cancel::Payload as Payload>::TYPE_URI;
    pub const CERTIFY: &str = <super::certify::Payload as Payload>::TYPE_URI;
    pub const TICKETS_ISSUE: &str = <super::tickets_issue::Payload as Payload>::TYPE_URI;
}

impl VtcClient {
    /// `vtc/elections/create/0.1` — create an election from `manifest`, sent as given (its
    /// digest is taken over these bytes).
    ///
    /// # Errors
    /// [`VtcError::InvalidPayload`] for a manifest out of schema, caught before anything is sent;
    /// [`VtcError::Parked`] for a binding election waiting on another administrator's consent;
    /// the VTC's refusal otherwise.
    pub async fn elections_create(
        &self,
        manifest: Value,
        key: &HolderKey,
    ) -> Result<create::Response, VtcError> {
        let payload = checked::<create::Payload>(json!({ "manifest": manifest }))?;
        self.acl_task(task::CREATE, payload, key, create::ERROR_CODES)
            .await
    }

    /// `vtc/elections/list/0.1` — the elections the caller may see, optionally only those in
    /// `state`.
    ///
    /// # Errors
    /// [`VtcError::InvalidPayload`] for an unknown state; the VTC's refusal otherwise.
    pub async fn elections_list(
        &self,
        state: Option<&str>,
        cursor: Option<&str>,
        limit: Option<u32>,
        key: &HolderKey,
    ) -> Result<list::Response, VtcError> {
        let mut body = json!({});
        if let Some(s) = state {
            body["state"] = json!(s);
        }
        if let Some(c) = cursor {
            body["cursor"] = json!(c);
        }
        if let Some(l) = limit {
            body["limit"] = json!(l);
        }
        let payload = checked::<list::Payload>(body)?;
        self.acl_task(task::LIST, payload, key, &[]).await
    }

    /// `vtc/elections/show/0.1` — one election, with its parameters and disclosure.
    ///
    /// # Errors
    /// `electionUnknown` for an election the caller may not see; the VTC's refusal otherwise.
    pub async fn elections_show(
        &self,
        election_id: &str,
        key: &HolderKey,
    ) -> Result<show::Response, VtcError> {
        let payload = checked::<show::Payload>(json!({ "electionId": election_id }))?;
        self.acl_task(task::SHOW, payload, key, show::ERROR_CODES)
            .await
    }

    /// `vtc/elections/close/0.1` — close an election early, where its manifest allows it.
    ///
    /// # Errors
    /// The VTC's refusal.
    pub async fn elections_close(
        &self,
        election_id: &str,
        reason: Option<&str>,
        key: &HolderKey,
    ) -> Result<close::Response, VtcError> {
        let mut body = json!({ "electionId": election_id });
        if let Some(r) = reason {
            body["reason"] = json!(r);
        }
        let payload = checked::<close::Payload>(body)?;
        self.acl_task(task::CLOSE, payload, key, close::ERROR_CODES)
            .await
    }

    /// `vtc/elections/cancel/0.1` — cancel an election.
    ///
    /// # Errors
    /// The VTC's refusal.
    pub async fn elections_cancel(
        &self,
        election_id: &str,
        reason: &str,
        key: &HolderKey,
    ) -> Result<cancel::Response, VtcError> {
        let payload =
            checked::<cancel::Payload>(json!({ "electionId": election_id, "reason": reason }))?;
        self.acl_task(task::CANCEL, payload, key, cancel::ERROR_CODES)
            .await
    }

    /// `vtc/elections/certify/0.1` — certify a tallied election's result, with any auditors'
    /// attestations, kept exactly as given.
    ///
    /// # Errors
    /// The VTC's refusal, naming the first fault its verification of the board found.
    pub async fn elections_certify(
        &self,
        election_id: &str,
        attestations: Vec<Value>,
        key: &HolderKey,
    ) -> Result<certify::Response, VtcError> {
        let payload = checked::<certify::Payload>(
            json!({ "electionId": election_id, "auditAttestations": attestations }),
        )?;
        self.acl_task(task::CERTIFY, payload, key, certify::ERROR_CODES)
            .await
    }

    /// `vtc/elections/tickets/issue/0.1` — ask for a ticket: `request` is the blinded request a
    /// member's VTA built (`vta/pcs/voter/register`), carried as it came.
    ///
    /// # Errors
    /// The VTC's refusal.
    pub async fn elections_ticket(
        &self,
        election_id: &str,
        manifest_digest: &str,
        request: Value,
        key: &HolderKey,
    ) -> Result<tickets_issue::Response, VtcError> {
        let payload = checked::<tickets_issue::Payload>(json!({
            "electionId": election_id,
            "manifestDigest": manifest_digest,
            "request": request,
        }))?;
        self.acl_task(
            task::TICKETS_ISSUE,
            payload,
            key,
            tickets_issue::ERROR_CODES,
        )
        .await
    }
}

impl VtcClient {
    /// Send a request document someone else signed — a member's VTA, through
    /// `vta/pcs/voter/{read,register}` — to the community unchanged, over its HTTPS Trust Task
    /// door, and return the answer's payload. A persona-signed document never rides this
    /// client's own session: it would arrive attributed to the session's DID.
    ///
    /// # Errors
    /// [`VtcError::Http`] for a refusal, carrying the `trust-task-error` document as its body.
    pub async fn send_signed_document(&self, document: &Value) -> Result<Value, VtcError> {
        let resp = self
            .http
            .post(format!("{}/trust-tasks", self.base_url))
            .header("content-type", "application/json")
            .body(serde_json::to_string(document).map_err(|e| VtcError::Url(e.to_string()))?)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(VtcError::Http {
                status: status.as_u16(),
                body: text,
            });
        }
        let doc: trust_tasks_rs::TrustTask<Value> =
            serde_json::from_str(&text).map_err(|e| VtcError::Http {
                status: status.as_u16(),
                body: format!("not a Trust Task document: {e}: {text}"),
            })?;
        Ok(doc.payload)
    }
}

/// `payload`, once it validates against `P`'s published schema.
fn checked<P: ValidatedPayload>(payload: Value) -> Result<Value, VtcError> {
    P::validate_value(&payload).map_err(|e| VtcError::InvalidPayload(e.to_string()))?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_out_of_schema_are_refused_before_sending() {
        assert!(checked::<list::Payload>(json!({ "state": "voting" })).is_ok());
        assert!(checked::<list::Payload>(json!({ "state": "nonsense" })).is_err());
        assert!(checked::<show::Payload>(json!({ "electionId": "agm-2027" })).is_ok());
        assert!(checked::<show::Payload>(json!({ "electionId": "has space" })).is_err());
        assert!(checked::<cancel::Payload>(json!({ "electionId": "agm" })).is_err());
        assert!(checked::<create::Payload>(json!({ "manifest": {} })).is_err());
    }
}
