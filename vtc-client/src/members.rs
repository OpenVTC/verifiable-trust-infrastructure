//! Direct admission: `vtc/members/admit/0.1` (*Add a member*) and
//! `vtc/members/make-membership/0.1` (*Make this a membership*) — an
//! administrator admitting a DID without a join request.
//!
//! Both are signed Trust Tasks sent the way every `acl/*` call goes
//! ([`crate::acl`]): over the client's DIDComm or TSP session when it holds
//! one, otherwise signed with a [`HolderKey`] and posted to
//! `POST {base}/trust-tasks`. The community's `admission` policy decides each,
//! and may refer it to another holder of `vtc.members.manage`: that answer is
//! [`VtcError::Parked`], not a refusal.
//!
//! Requests are validated against the published schema before they are sent,
//! and replies are decoded into the generated `Response` types.

use trust_tasks_rs::validate::ValidatedPayload;

use crate::{HolderKey, VtcClient, VtcError};

/// The generated wire types, re-exported so a caller names the reply types
/// without depending on `trust-tasks-rs` itself.
pub use trust_tasks_rs::specs::vtc::members::{
    admit::v0_1 as admit, make_membership::v0_1 as make_membership,
};

/// The Type URI of each task, read off the generated payloads.
pub mod task {
    use trust_tasks_rs::Payload;

    pub const ADMIT: &str = <super::admit::Payload as Payload>::TYPE_URI;
    pub const MAKE_MEMBERSHIP: &str = <super::make_membership::Payload as Payload>::TYPE_URI;
}

/// What *Add a member* asks for.
#[derive(Debug, Clone, Default)]
pub struct AdmitRequest {
    /// The DID to admit.
    pub subject: String,
    /// The community role it will hold (`member`, `moderator`, `issuer`,
    /// `custom:<name>`).
    pub role: String,
    /// The new entry's label.
    pub label: Option<String>,
    /// Why, for the audit trail and any approvers.
    pub reason: Option<String>,
}

impl VtcClient {
    /// `vtc/members/admit/0.1` — admit `req.subject`, which holds no ACL entry
    /// (or only an `application` one), at `req.role`.
    ///
    /// # Errors
    ///
    /// [`VtcError::InvalidPayload`] for a request out of schema, caught before
    /// anything is sent; [`VtcError::Parked`] when the policy referred it; the
    /// VTC's refusal otherwise.
    pub async fn members_admit(
        &self,
        req: &AdmitRequest,
        key: &HolderKey,
    ) -> Result<admit::Response, VtcError> {
        let mut body = serde_json::json!({ "subject": req.subject, "role": req.role });
        if let Some(label) = &req.label {
            body["label"] = serde_json::json!(label);
        }
        if let Some(reason) = &req.reason {
            body["reason"] = serde_json::json!(reason);
        }
        let payload = checked::<admit::Payload>(body)?;
        self.acl_task(task::ADMIT, payload, key, admit::ERROR_CODES)
            .await
    }

    /// `vtc/members/make-membership/0.1` — make `subject`'s existing ACL
    /// entry, which has no member record, a membership at the role it holds.
    ///
    /// # Errors
    ///
    /// As [`members_admit`](Self::members_admit).
    pub async fn members_make_membership(
        &self,
        subject: &str,
        reason: Option<&str>,
        key: &HolderKey,
    ) -> Result<make_membership::Response, VtcError> {
        let mut body = serde_json::json!({ "subject": subject });
        if let Some(reason) = reason {
            body["reason"] = serde_json::json!(reason);
        }
        let payload = checked::<make_membership::Payload>(body)?;
        self.acl_task(
            task::MAKE_MEMBERSHIP,
            payload,
            key,
            make_membership::ERROR_CODES,
        )
        .await
    }
}

/// `payload`, once it validates against `P`'s published schema.
fn checked<P: ValidatedPayload>(payload: serde_json::Value) -> Result<serde_json::Value, VtcError> {
    P::validate_value(&payload).map_err(|e| VtcError::InvalidPayload(e.to_string()))?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_admission_out_of_schema_is_refused_before_sending() {
        let ok = serde_json::json!({ "subject": "did:key:z6Mk", "role": "member" });
        assert!(checked::<admit::Payload>(ok).is_ok());
        for bad in [
            serde_json::json!({ "subject": "not-a-did", "role": "member" }),
            serde_json::json!({ "subject": "did:key:z6Mk", "role": "r".repeat(129) }),
            serde_json::json!({ "subject": "did:key:z6Mk", "role": "member", "label": " " }),
        ] {
            assert!(checked::<admit::Payload>(bad.clone()).is_err(), "{bad}");
        }
        assert!(
            checked::<make_membership::Payload>(serde_json::json!({ "subject": "x" })).is_err()
        );
    }
}
