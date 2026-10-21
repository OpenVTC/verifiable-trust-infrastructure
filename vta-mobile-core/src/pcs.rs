//! Hidden vetting through the holder's VTA (`vta/pcs/*`, the VTA as PCS engine).
//!
//! A community that runs hidden vetting admits an applicant on a zero-knowledge proof, built
//! with a PCS key this device could not hold — there is no mobile PCS implementation. The VTA
//! holds the key and runs the scheme; the device builds each request, carries the messages
//! between the VTA, the community and the vetter, and never sees a key.
//!
//! One builder and one parser cover the sixteen tasks: [`build_pcs_task`] validates the payload
//! JSON against the task's generated type (so a request the schema refuses never leaves the
//! device), wraps it in a holder-signed document, and [`parse_pcs_response`] checks a response
//! against the task's generated response type and hands back its payload JSON.
//!
//! The applicant's round, as the native app drives it:
//!
//! 1. [`PcsTask::ApplicationsCreate`] — the PCS identifier for each `vetting/request`'s `ext`;
//! 2. [`PcsTask::VerifyAttestation`] — each `vetting/attestation` a vetter sends;
//! 3. [`PcsTask::Prove`] — after `vtc/vetting/pcs-challenge`, the join submission's
//!    `extensions.hiddenVetting`.
//!
//! The voter's round (community voting, VTI-VOT-020 – 053):
//!
//! 0. [`PcsTask::VoterRead`] — `vtc/elections/list` or `show`, signed as the member;
//! 1. [`PcsTask::VoterRegister`] — the blinded ticket request for `vtc/elections/tickets/issue`;
//! 2. [`PcsTask::VoterAccept`] — the community's answer, unblinded into the ticket;
//! 3. [`PcsTask::Vote`] — the signed `voting/ballot/cast` document, which the device sends to
//!    the ballot box itself, after a pause, and resends unchanged if the answer is lost;
//! 4. [`PcsTask::VoterReceipt`] — the ballot box's receipt, kept and checked.
//!
//! In a sealed or tallied-encrypted election, step 3 is [`PcsTask::VoteEncrypted`]: the signed
//! `voting/ballot/cast-encrypted` document, built under the election key the ballot box's
//! `voting/trustees/status` reports.

use serde::Serialize;
use serde::de::DeserializeOwned;
use trust_tasks_rs::specs::vta::pcs;
use trust_tasks_rs::{Payload, TrustTask};

use crate::error::FfiError;
use crate::keys::Signer;
use crate::proof::attach_did_signed_proof;
use crate::session::AuthEnvelope;

/// The `vta/pcs/*` task a document is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PcsTask {
    ApplicationsCreate,
    ApplicationsShow,
    ApplicationsDelete,
    VerifyAttestation,
    Prove,
    RootRequest,
    RootAccept,
    TokensRequest,
    TokensAccept,
    TokensAbandon,
    Attest,
    VetterShow,
    VoterRegister,
    VoterAccept,
    Vote,
    VoterReceipt,
    VoterRead,
    VoteEncrypted,
}

fn invalid<E: std::fmt::Display>(e: E) -> FfiError {
    FfiError::InvalidInput {
        reason: e.to_string(),
    }
}

fn decode<E: std::fmt::Display>(e: E) -> FfiError {
    FfiError::Decode {
        reason: format!("not a valid vta/pcs response: {e}"),
    }
}

fn signed<P: Payload + Serialize + DeserializeOwned>(
    env: &AuthEnvelope,
    payload_json: &str,
    signer: &dyn Signer,
) -> Result<String, FfiError> {
    let payload: P = serde_json::from_str(payload_json).map_err(invalid)?;
    let issued_at = chrono::DateTime::parse_from_rfc3339(&env.issued_at)
        .map_err(|e| FfiError::InvalidInput {
            reason: format!("issued_at is not an RFC 3339 timestamp: {e}"),
        })?
        .with_timezone(&chrono::Utc);
    let mut doc = TrustTask::for_payload(env.id.clone(), payload);
    doc.issuer = Some(env.holder_did.clone());
    doc.recipient = Some(env.vta_did.clone());
    doc.issued_at = Some(issued_at);
    attach_did_signed_proof(&mut doc, signer, &env.issued_at)?;
    serde_json::to_string(&doc).map_err(invalid)
}

fn response<R: Serialize + DeserializeOwned>(json: &str) -> Result<String, FfiError> {
    let doc: TrustTask<R> = serde_json::from_str(json).map_err(decode)?;
    serde_json::to_string(&doc.payload).map_err(decode)
}

/// Build a holder-signed `vta/pcs/*` request to the holder's VTA.
///
/// `payload_json` is the task's payload; it is checked against the task's generated type
/// before anything is signed, so an `InvalidInput` here names the schema violation.
#[uniffi::export]
pub fn build_pcs_task(
    env: AuthEnvelope,
    task: PcsTask,
    payload_json: String,
    signer: Box<dyn Signer>,
) -> Result<String, FfiError> {
    let s = &*signer;
    let p = payload_json.as_str();
    match task {
        PcsTask::ApplicationsCreate => {
            signed::<pcs::applications::create::v0_1::Payload>(&env, p, s)
        }
        PcsTask::ApplicationsShow => signed::<pcs::applications::show::v0_1::Payload>(&env, p, s),
        PcsTask::ApplicationsDelete => {
            signed::<pcs::applications::delete::v0_1::Payload>(&env, p, s)
        }
        PcsTask::VerifyAttestation => signed::<pcs::verify_attestation::v0_1::Payload>(&env, p, s),
        PcsTask::Prove => signed::<pcs::prove::v0_1::Payload>(&env, p, s),
        PcsTask::RootRequest => signed::<pcs::root_request::v0_1::Payload>(&env, p, s),
        PcsTask::RootAccept => signed::<pcs::root_accept::v0_1::Payload>(&env, p, s),
        PcsTask::TokensRequest => signed::<pcs::tokens::request::v0_1::Payload>(&env, p, s),
        PcsTask::TokensAccept => signed::<pcs::tokens::accept::v0_1::Payload>(&env, p, s),
        PcsTask::TokensAbandon => signed::<pcs::tokens::abandon::v0_1::Payload>(&env, p, s),
        PcsTask::Attest => signed::<pcs::attest::v0_1::Payload>(&env, p, s),
        PcsTask::VetterShow => signed::<pcs::vetter::show::v0_1::Payload>(&env, p, s),
        PcsTask::VoterRegister => signed::<pcs::voter::register::v0_1::Payload>(&env, p, s),
        PcsTask::VoterAccept => signed::<pcs::voter::accept::v0_1::Payload>(&env, p, s),
        PcsTask::Vote => signed::<pcs::vote::v0_1::Payload>(&env, p, s),
        PcsTask::VoterReceipt => signed::<pcs::voter::receipt::v0_1::Payload>(&env, p, s),
        PcsTask::VoterRead => signed::<pcs::voter::read::v0_1::Payload>(&env, p, s),
        PcsTask::VoteEncrypted => signed::<pcs::vote_encrypted::v0_2::Payload>(&env, p, s),
    }
}

/// Check a `vta/pcs/*#response` against the task's generated response type and return its
/// payload as JSON. A `trust-task-error` answer is not a response and fails here with `Decode`;
/// the native layer reads its `payload.code` (`vta/pcs/prove:noUsableAttestation`, …) itself.
#[uniffi::export]
pub fn parse_pcs_response(task: PcsTask, json: String) -> Result<String, FfiError> {
    let j = json.as_str();
    match task {
        PcsTask::ApplicationsCreate => response::<pcs::applications::create::v0_1::Response>(j),
        PcsTask::ApplicationsShow => response::<pcs::applications::show::v0_1::Response>(j),
        PcsTask::ApplicationsDelete => response::<pcs::applications::delete::v0_1::Response>(j),
        PcsTask::VerifyAttestation => response::<pcs::verify_attestation::v0_1::Response>(j),
        PcsTask::Prove => response::<pcs::prove::v0_1::Response>(j),
        PcsTask::RootRequest => response::<pcs::root_request::v0_1::Response>(j),
        PcsTask::RootAccept => response::<pcs::root_accept::v0_1::Response>(j),
        PcsTask::TokensRequest => response::<pcs::tokens::request::v0_1::Response>(j),
        PcsTask::TokensAccept => response::<pcs::tokens::accept::v0_1::Response>(j),
        PcsTask::TokensAbandon => response::<pcs::tokens::abandon::v0_1::Response>(j),
        PcsTask::Attest => response::<pcs::attest::v0_1::Response>(j),
        PcsTask::VetterShow => response::<pcs::vetter::show::v0_1::Response>(j),
        PcsTask::VoterRegister => response::<pcs::voter::register::v0_1::Response>(j),
        PcsTask::VoterAccept => response::<pcs::voter::accept::v0_1::Response>(j),
        PcsTask::Vote => response::<pcs::vote::v0_1::Response>(j),
        PcsTask::VoterReceipt => response::<pcs::voter::receipt::v0_1::Response>(j),
        PcsTask::VoterRead => response::<pcs::voter::read::v0_1::Response>(j),
        PcsTask::VoteEncrypted => response::<pcs::vote_encrypted::v0_2::Response>(j),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payload the schema refuses never becomes a signed document: the error is raised before
    /// the signer is asked for anything.
    #[test]
    fn a_payload_the_schema_refuses_is_not_signed() {
        struct Refuse;
        impl Signer for Refuse {
            fn did(&self) -> String {
                "did:key:z6MkHolder".into()
            }
            fn sign(&self, _payload: Vec<u8>) -> Result<Vec<u8>, FfiError> {
                panic!("the signer must not be reached");
            }
        }
        let env = AuthEnvelope {
            id: "urn:uuid:1".into(),
            holder_did: "did:key:z6MkHolder".into(),
            vta_did: "did:key:z6MkVta".into(),
            issued_at: "2026-10-12T09:00:00Z".into(),
        };
        let err = build_pcs_task(
            env,
            PcsTask::Prove,
            r#"{"applicationId":"app-1"}"#.into(),
            Box::new(Refuse),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::InvalidInput { .. }), "{err:?}");
    }

    #[test]
    fn a_response_payload_comes_back_as_json() {
        let doc = r#"{"id":"urn:uuid:2","type":"https://trusttasks.org/spec/vta/pcs/applications/delete/0.1#response","payload":{"applicationId":"app-1","deleted":true}}"#;
        let payload = parse_pcs_response(PcsTask::ApplicationsDelete, doc.into()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["deleted"], serde_json::json!(true));
    }
}
