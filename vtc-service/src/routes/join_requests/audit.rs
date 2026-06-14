//! Shared audit emission for the two member-admission paths.
//!
//! Admitting a member mints a VMC + role VEC and consumes a status-list slot.
//! Both the manual-approve path ([`super::decide::approve`]) and the policy
//! auto-admit path ([`super::submit::realize_join_verdict`]) run the *same*
//! admit effect, so both must record the *same* audit envelopes for it:
//! `MemberAdded` + `VmcIssued` + `VecIssued`.
//!
//! Previously only the manual path emitted these — an auto-admitted member's
//! credential issuance left no audit trail. Centralising the emission here
//! closes that gap and keeps the two paths from drifting again. The lifecycle
//! event that *brackets* the admit (`JoinRequestApproved` on the manual path,
//! `JoinRequestSubmitted` on auto-admit) differs per path and stays with each
//! caller.

use affinidi_vc::VerifiableCredential;
use vti_common::audit::{AuditEvent, AuditWriter, CredentialIssuedData, MemberAddedData};
use vti_common::error::AppError;

use crate::ceremony::execute::{AdmitOutcome, top_level_id};
use crate::credentials::vec::VEC_TYPE;
use crate::credentials::vmc::VMC_TYPE;

/// Emit the `MemberAdded` + `VmcIssued` + `VecIssued` envelopes for a completed
/// admit effect. `actor_did` is whoever drove the admission (the approving
/// admin on the manual path; the applicant themselves on policy auto-admit,
/// which has no human actor), `subject_did` is the new member, and `role` is
/// the role actually granted (manual approve always grants member; auto-admit
/// uses the policy verdict's role).
pub(crate) async fn emit_admit_audit(
    audit_writer: &AuditWriter,
    actor_did: &str,
    subject_did: &str,
    creds: &AdmitOutcome,
    role: &str,
    via_join_request_id: Option<String>,
) -> Result<(), AppError> {
    audit_writer
        .write(
            actor_did,
            Some(subject_did),
            AuditEvent::MemberAdded(MemberAddedData {
                role: role.to_string(),
                via_join_request_id,
            }),
        )
        .await?;
    audit_writer
        .write(
            actor_did,
            Some(subject_did),
            AuditEvent::VmcIssued(credential_issued_data(
                &creds.vmc,
                Some(creds.status_list_index),
            )?),
        )
        .await?;
    audit_writer
        .write(
            actor_did,
            Some(subject_did),
            AuditEvent::VecIssued(credential_issued_data(&creds.role_vec, None)?),
        )
        .await?;
    Ok(())
}

/// Build a [`CredentialIssuedData`] payload from a signed VC.
pub(crate) fn credential_issued_data(
    vc: &VerifiableCredential,
    status_list_index: Option<u32>,
) -> Result<CredentialIssuedData, AppError> {
    let id = top_level_id(vc).ok_or_else(|| {
        AppError::Internal("credential is missing top-level `id` — issuance dropped it".into())
    })?;
    let credential_type = vc
        .types
        .iter()
        .find(|t| *t == VMC_TYPE || *t == VEC_TYPE)
        .cloned()
        .ok_or_else(|| AppError::Internal("credential carries neither VMC nor VEC type".into()))?;
    let valid_from = vc
        .valid_from
        .clone()
        .ok_or_else(|| AppError::Internal("credential missing validFrom".into()))?;
    let valid_until = vc
        .valid_until
        .clone()
        .ok_or_else(|| AppError::Internal("credential missing validUntil".into()))?;
    Ok(CredentialIssuedData {
        credential_id: id,
        credential_type,
        valid_from,
        valid_until,
        status_list_index,
    })
}
