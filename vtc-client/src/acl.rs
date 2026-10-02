//! The community's ACL: the canonical `acl/{list,show,grant,update,change-role,
//! revoke}/0.1` tasks.
//!
//! Every one of them is a signed Trust Task, sent the way every `cnm access`
//! call goes — over the DIDComm or TSP session when the client holds one
//! ([`VtcClient::connect_tsp`], [`VtcClient::connect_didcomm`]), otherwise
//! signed with a [`HolderKey`] and posted to `POST {base}/trust-tasks`. As for
//! `git-ns/*` ([`crate::git_ns`]): over a session the VTC takes the document
//! only when its proof, its `issuer` and the envelope's sender are the same
//! DID, so `key` must be the session's own identity — a call signed as any
//! other DID is refused here before anything is sent. A refusal reads the
//! same either way — [`VtcError::Refused`] over a session,
//! [`VtcError::Http`]'s body over HTTPS — carrying the `trust-task-error`
//! document as the VTC wrote it.
//!
//! Requests are built from the generated schema and validated against it
//! before they are sent; replies are decoded into the generated `Response`
//! types, so a VTC that answers off-schema is an error here rather than a
//! silently half-read struct.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use trust_tasks_rs::validate::ValidatedPayload;

use crate::{HolderKey, MAX_DOCUMENT_RESPONSE_BYTES, VtcClient, VtcError, decode_payload};

/// The generated wire types for the family, re-exported so a caller names the
/// reply types without depending on `trust-tasks-rs` itself.
pub use trust_tasks_rs::specs::acl::{
    change_role::v0_1 as change_role, grant::v0_1 as grant, list::v0_1 as list,
    revoke::v0_1 as revoke, show::v0_1 as show, update::v0_1 as update,
};

/// The Type URI of each task in the family, read off the generated payloads.
pub mod task {
    use trust_tasks_rs::Payload;

    pub const LIST: &str = <super::list::Payload as Payload>::TYPE_URI;
    pub const SHOW: &str = <super::show::Payload as Payload>::TYPE_URI;
    pub const GRANT: &str = <super::grant::Payload as Payload>::TYPE_URI;
    pub const UPDATE: &str = <super::update::Payload as Payload>::TYPE_URI;
    pub const CHANGE_ROLE: &str = <super::change_role::Payload as Payload>::TYPE_URI;
    pub const REVOKE: &str = <super::revoke::Payload as Payload>::TYPE_URI;
}

/// `acl/list/0.1` filters. Every member is optional; an empty filter lists the
/// first page of every entry the caller may see.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AclListFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// `acting-in` (the default), `subtree` or `any`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    /// The previous page's `cursor`, verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// An `acl/grant/0.1` entry: what the subject should hold.
#[derive(Debug, Clone, Default)]
pub struct AclGrant {
    pub subject: String,
    pub role: String,
    pub scopes: Vec<String>,
    pub label: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: Option<String>,
}

/// An `acl/update/0.1` amendment. `None` leaves a member unchanged; for
/// `label` and `expires_at`, `Some(None)` clears it — which for the expiry
/// makes the entry permanent.
#[derive(Debug, Clone, Default)]
pub struct AclUpdate {
    pub subject: String,
    pub label: Option<Option<String>>,
    /// The **whole** intended set. A set that drops a scope the entry holds is
    /// refused (`acl/update:narrowingNotPermitted`); use [`VtcClient::acl_revoke`].
    pub scopes: Option<Vec<String>>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub reason: Option<String>,
}

impl VtcClient {
    /// One page of the ACL entries this caller may see. Manage authority.
    pub async fn acl_list(
        &self,
        filter: &AclListFilter,
        key: &HolderKey,
    ) -> Result<list::Response, VtcError> {
        let payload = checked::<list::Payload>(serde_json::to_value(filter).map_err(bad)?)?;
        self.acl_task(task::LIST, payload, key, &[]).await
    }

    /// Every ACL entry this caller may see, following the cursor to the end.
    pub async fn acl_list_all(
        &self,
        filter: &AclListFilter,
        key: &HolderKey,
    ) -> Result<Vec<list::AclEntry>, VtcError> {
        let mut filter = filter.clone();
        let mut out = Vec::new();
        loop {
            let page = self.acl_list(&filter, key).await?;
            out.extend(page.entries);
            match (page.truncated, page.cursor) {
                (true, Some(cursor)) => filter.cursor = Some(cursor),
                // Truncated with no cursor: the VTC cannot page from here. Say
                // so rather than return a partial list that reads as complete.
                (true, None) => {
                    return Err(VtcError::Http {
                        status: 200,
                        body: "acl/list answered a truncated page with no cursor".into(),
                    });
                }
                (false, _) => return Ok(out),
            }
        }
    }

    /// One entry. [`VtcError::Http`] 404 (or the document's `notFound`) when
    /// the subject holds none this caller may see.
    pub async fn acl_show(
        &self,
        subject: &str,
        key: &HolderKey,
    ) -> Result<show::Response, VtcError> {
        let payload = checked::<show::Payload>(serde_json::json!({ "subject": subject }))?;
        self.acl_task(task::SHOW, payload, key, &[]).await
    }

    /// Write the entry `grant.subject` should hold. Conferring administrator
    /// authority needs a passkey gesture bound to this grant, and
    /// community-wide authority another administrator's consent; the refusal
    /// carries the ceremony in its `details`.
    pub async fn acl_grant(
        &self,
        grant: &AclGrant,
        key: &HolderKey,
    ) -> Result<grant::Response, VtcError> {
        let mut entry = serde_json::json!({
            "subject": grant.subject,
            "role": grant.role,
            "scopes": grant.scopes,
        });
        if let Some(label) = &grant.label {
            entry["label"] = serde_json::json!(label);
        }
        if let Some(at) = grant.expires_at {
            entry["expiresAt"] = serde_json::json!(at.to_rfc3339());
        }
        let mut body = serde_json::json!({ "entry": entry });
        if let Some(reason) = &grant.reason {
            body["reason"] = serde_json::json!(reason);
        }
        let payload = checked::<grant::Payload>(body)?;
        self.acl_task(task::GRANT, payload, key, &[]).await
    }

    /// Amend an existing entry's label, scopes or expiry.
    pub async fn acl_update(
        &self,
        update: &AclUpdate,
        key: &HolderKey,
    ) -> Result<update::Response, VtcError> {
        let mut body = serde_json::json!({ "subject": update.subject });
        if let Some(label) = &update.label {
            body["label"] = serde_json::json!(label);
        }
        if let Some(scopes) = &update.scopes {
            body["scopes"] = serde_json::json!(scopes);
        }
        if let Some(at) = &update.expires_at {
            body["expiresAt"] = serde_json::json!(at.map(|t| t.to_rfc3339()));
        }
        if let Some(reason) = &update.reason {
            body["reason"] = serde_json::json!(reason);
        }
        let payload = checked::<update::Payload>(body)?;
        self.acl_task(task::UPDATE, payload, key, update::ERROR_CODES)
            .await
    }

    /// Move `subject` from `from_role` to `to_role`, compare-and-swapped on
    /// `from_role`. A promotion to admin needs a bound passkey gesture.
    pub async fn acl_change_role(
        &self,
        subject: &str,
        from_role: &str,
        to_role: &str,
        reason: Option<&str>,
        key: &HolderKey,
    ) -> Result<change_role::Response, VtcError> {
        let mut body = serde_json::json!({
            "subject": subject,
            "fromRole": from_role,
            "toRole": to_role,
        });
        if let Some(reason) = reason {
            body["reason"] = serde_json::json!(reason);
        }
        let payload = checked::<change_role::Payload>(body)?;
        self.acl_task(task::CHANGE_ROLE, payload, key, &[]).await
    }

    /// Remove `subject`'s entry, or — with `scopes` — only those scopes. The
    /// reply's `entry` is `None` after a removal and the reduced entry after a
    /// reduction.
    pub async fn acl_revoke(
        &self,
        subject: &str,
        scopes: Option<&[String]>,
        reason: Option<&str>,
        key: &HolderKey,
    ) -> Result<revoke::Response, VtcError> {
        let mut body = serde_json::json!({ "subject": subject });
        if let Some(scopes) = scopes {
            body["scopes"] = serde_json::json!(scopes);
        }
        if let Some(reason) = reason {
            body["reason"] = serde_json::json!(reason);
        }
        let payload = checked::<revoke::Payload>(body)?;
        self.acl_task(task::REVOKE, payload, key, revoke::ERROR_CODES)
            .await
    }

    /// Sign one `acl/*` document as `key` and send it, over the client's
    /// session when it holds one — `key` must then be the session's identity
    /// — otherwise signed with `key` and posted to the document endpoint.
    /// `declared` is the task's declared error codes, honoured only on the
    /// HTTPS path (a 404 naming one becomes [`VtcError::NotFound`]); a session
    /// refusal is always [`VtcError::Refused`].
    async fn acl_task<R: DeserializeOwned>(
        &self,
        type_uri: &str,
        payload: Value,
        key: &HolderKey,
        declared: &[trust_tasks_rs::DeclaredErrorCode],
    ) -> Result<R, VtcError> {
        #[cfg(feature = "didcomm")]
        if self.documents.is_some() {
            return self
                .acl_over_session(type_uri, payload, key.holder_did())
                .await;
        }
        let doc =
            vta_sdk::trust_task_sign::build_signed_with(type_uri, payload, key, &self.vtc_did)
                .await
                .map_err(|e| VtcError::Signing(e.to_string()))?;
        let reply = self
            .post_document(doc, declared, MAX_DOCUMENT_RESPONSE_BYTES)
            .await?;
        decode_payload(reply, type_uri)
    }

    /// One `acl/*` task over the client's session, attributed to `signer_did`.
    ///
    /// The session signs the document as its own DID and the VTC binds that
    /// proof to the envelope's sender, so a task meant to be signed as any
    /// other DID cannot go this way: it is refused here, before anything is
    /// sent, rather than arrive attributed to the wrong member — the same
    /// guard [`crate::git_ns`] applies to `git-ns/*`.
    #[cfg(feature = "didcomm")]
    async fn acl_over_session<R: DeserializeOwned>(
        &self,
        type_uri: &str,
        payload: Value,
        signer_did: &str,
    ) -> Result<R, VtcError> {
        let (Some(documents), Some(session_did)) = (&self.documents, &self.session_did) else {
            return Err(VtcError::Session("this client holds no session".into()));
        };
        let base = |d: &str| d.split('#').next().unwrap_or(d).to_string();
        if base(signer_did) != base(session_did) {
            return Err(VtcError::Signing(format!(
                "{type_uri} is to be signed as {signer_did}, but this client's session is \
                 {session_did}; over a session the VTC accepts a document only from the DID \
                 that signed it"
            )));
        }
        let reply = documents
            .dispatch_trust_task_document(type_uri, payload, crate::SESSION_TIMEOUT_SECS)
            .await
            .map_err(|e| VtcError::Session(e.to_string()))?;
        let refused = reply
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| t.starts_with("https://trusttasks.org/spec/trust-task-error/"));
        if refused {
            return Err(VtcError::Refused {
                document: reply.to_string(),
            });
        }
        let payload = reply.get("payload").cloned().unwrap_or(Value::Null);
        // Parked for other administrators' approval (VTI-APV-017).
        if let Some(parked) = crate::parked_from_next_step(
            reply
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            &payload,
        ) {
            return Err(parked);
        }
        serde_json::from_value(payload).map_err(|e| VtcError::Http {
            status: 200,
            body: format!("{type_uri} response does not fit its schema: {e}"),
        })
    }
}

/// `payload`, once it validates against `P`'s published schema.
fn checked<P: ValidatedPayload>(payload: serde_json::Value) -> Result<serde_json::Value, VtcError> {
    P::validate_value(&payload).map_err(|e| VtcError::InvalidPayload(e.to_string()))?;
    Ok(payload)
}

fn bad(e: serde_json::Error) -> VtcError {
    VtcError::InvalidPayload(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_filter_is_the_canonical_payload() {
        let filter = AclListFilter {
            scope: Some("ctx-a".into()),
            direction: Some("subtree".into()),
            page_size: Some(10),
            ..Default::default()
        };
        let v = checked::<list::Payload>(serde_json::to_value(&filter).unwrap()).unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "scope": "ctx-a", "direction": "subtree", "pageSize": 10 })
        );
    }

    #[test]
    fn an_unknown_direction_is_refused_before_sending() {
        let filter = AclListFilter {
            direction: Some("sideways".into()),
            ..Default::default()
        };
        assert!(checked::<list::Payload>(serde_json::to_value(&filter).unwrap()).is_err());
    }

    #[test]
    fn an_empty_scope_reduction_is_refused_before_sending() {
        // `minItems: 1` — an empty list must never reach the VTC, where it
        // would be ambiguous with a full removal.
        let body = serde_json::json!({ "subject": "did:key:z6MkA", "scopes": [] });
        assert!(checked::<revoke::Payload>(body).is_err());
    }

    #[test]
    fn the_task_uris_are_the_canonical_family() {
        for uri in [
            task::LIST,
            task::SHOW,
            task::GRANT,
            task::UPDATE,
            task::CHANGE_ROLE,
            task::REVOKE,
        ] {
            assert!(uri.starts_with("https://trusttasks.org/spec/acl/"), "{uri}");
        }
    }
}
