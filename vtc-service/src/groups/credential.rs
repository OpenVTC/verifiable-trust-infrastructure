//! A member's group credential (`vtc/groups/members/add` item 3, and every
//! other way a member is admitted).
//!
//! Where the group issues credentials, the community has its VTA sign, **as
//! the group's DID** through `keys/sign-document`, a DTG `MembershipCredential`
//! to the member's membership DID, then offers it — with the community's
//! authority credential to the group, which it chains to — on the
//! credential-exchange path every credential this community issues travels,
//! **before** the membership is recorded.
//!
//! There is no status list per group: a small group's list would single its
//! members out (VTI-CRD-014). The credential is short-lived and renewed while
//! the member stays; leaving stops renewal, and expiry is the revocation.

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use vti_common::error::AppError;

use super::Group;
use super::identity::{self, Failure};
use crate::rooms::community::{HolderError, SIGN_TIMEOUT};
use crate::server::AppState;

/// A member's credential as issued: what this community keeps of it, and the
/// credential itself, which it never keeps.
#[derive(Debug, Clone)]
pub struct Issued {
    pub credential_id: String,
    pub valid_until: DateTime<Utc>,
    pub credential: Value,
}

/// Issue `member_did` its credential of `group`, signed by the VTA as the group.
pub async fn issue(state: &AppState, group: &Group, member_did: &str) -> Result<Issued, Failure> {
    let setup = identity::setup(state)
        .await
        .map_err(|why| Failure::Holder(HolderError::Unavailable(why), None))?;
    let days = state
        .config
        .read()
        .await
        .groups
        .as_ref()
        .map(|g| g.credential_valid_days())
        .unwrap_or(30);
    let valid_from = Utc::now();
    let valid_until = valid_from + Duration::days(i64::from(days));
    let dtg = dtg_credentials::DTGCredential::new_vmc(
        group.group_did.clone(),
        member_did.to_string(),
        valid_from,
        Some(valid_until),
        false,
    );
    dtg.validate().map_err(|e| {
        Failure::Local(AppError::Validation(format!(
            "group membership credential is not conformant: {e}"
        )))
    })?;
    let mut document = serde_json::to_value(dtg.credential()).map_err(|e| {
        Failure::Local(AppError::Internal(format!(
            "group membership credential: {e}"
        )))
    })?;
    let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    document["id"] = json!(credential_id);
    let answer = setup
        .holder
        .ask(
            vta_sdk::trust_tasks::TASK_KEYS_SIGN_DOCUMENT_0_1,
            json!({ "keyId": group.signing_key_id, "document": document }),
            SIGN_TIMEOUT,
        )
        .await
        .map_err(|e| Failure::Holder(e, None))?;
    let signed: vta_sdk::protocols::key_management::sign_document::SignDocumentResponse =
        serde_json::from_value(answer).map_err(|e| {
            Failure::Holder(
                HolderError::Unavailable(format!(
                    "keys/sign-document answered a shape not its own: {e}"
                )),
                None,
            )
        })?;
    Ok(Issued {
        credential_id,
        valid_until,
        credential: Value::Object(signed.document),
    })
}

/// Offer `issued` to `member_did`, with the group's authority credential it
/// chains to, on the credential-exchange path. Best effort, as every delivery
/// here is: the credential is issued, and a holder offline now still receives
/// it from the delivery outbox when they reconnect.
pub async fn offer(state: &AppState, group: &Group, member_did: &str, issued: &Issued) {
    let mut credentials = Vec::with_capacity(2);
    match crate::credentials::dtg::into_typed(issued.credential.clone(), "group VMC") {
        Ok(vc) => credentials.push(vc),
        Err(e) => {
            tracing::warn!(group = %group.group_id, error = %e, "could not offer a group credential");
            return;
        }
    }
    if let Some(vac) = &group.authority_credential
        && let Ok(vc) = crate::credentials::dtg::into_typed(vac.clone(), "group VAC")
    {
        credentials.push(vc);
    }
    let refs: Vec<&affinidi_vc::VerifiableCredential> = credentials.iter().collect();
    if let Err(e) =
        crate::credentials::delivery::deliver_credentials(state, member_did, &refs).await
    {
        tracing::warn!(
            group = %group.group_id,
            error = %e,
            "a group credential was issued but could not be offered yet"
        );
    }
}
