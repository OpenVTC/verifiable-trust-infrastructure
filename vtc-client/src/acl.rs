//! The community's ACL: the canonical `acl/{list,show,grant,update,change-role,
//! revoke}/0.1` tasks.
//!
//! Every one of them is a signed Trust Task the VTC dispatches on its spine,
//! so they go the way every such admin verb goes ([`VtcClient::admin_document`]):
//! over the messaging session when the client has one, otherwise signed with
//! the operator's key and posted to `POST {base}/trust-tasks`. Only a client
//! built from a bare token ([`VtcClient::with_token`]) uses the bearer routes,
//! and `acl/update` has none — it answers [`VtcError::Unsupported`] there.
//!
//! Requests are built from the generated schema and validated against it
//! before they are sent; replies are decoded into the generated `Response`
//! types, so a VTC that answers off-schema is an error here rather than a
//! silently half-read struct.

use chrono::{DateTime, Utc};
use serde::Serialize;
use trust_tasks_rs::validate::ValidatedPayload;

use crate::{MAX_DOCUMENT_RESPONSE_BYTES, VtcClient, VtcError, decode_payload};

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
    pub async fn acl_list(&self, filter: &AclListFilter) -> Result<list::Response, VtcError> {
        let payload = checked::<list::Payload>(serde_json::to_value(filter).map_err(bad)?)?;
        if let Some(reply) = self.acl_document(task::LIST, payload.clone(), &[]).await? {
            return decode_payload(reply, "acl/list");
        }
        let mut url = self.api_url(&["acl"])?;
        if let Some(map) = payload.as_object() {
            let mut q = url.query_pairs_mut();
            for (k, v) in map {
                match v {
                    serde_json::Value::String(s) => q.append_pair(k, s),
                    other => q.append_pair(k, &other.to_string()),
                };
            }
        }
        let resp = self
            .tt(reqwest::Method::GET, url, task::LIST)?
            .send()
            .await?;
        decode_payload(crate::expect_success(resp).await?.json().await?, "acl/list")
    }

    /// Every ACL entry this caller may see, following the cursor to the end.
    pub async fn acl_list_all(
        &self,
        filter: &AclListFilter,
    ) -> Result<Vec<list::AclEntry>, VtcError> {
        let mut filter = filter.clone();
        let mut out = Vec::new();
        loop {
            let page = self.acl_list(&filter).await?;
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
    pub async fn acl_show(&self, subject: &str) -> Result<show::Response, VtcError> {
        let payload = checked::<show::Payload>(serde_json::json!({ "subject": subject }))?;
        if let Some(reply) = self.acl_document(task::SHOW, payload, &[]).await? {
            return decode_payload(reply, "acl/show");
        }
        let url = self.api_url(&["acl", subject])?;
        let resp = self
            .tt(reqwest::Method::GET, url, task::SHOW)?
            .send()
            .await?;
        decode_payload(crate::expect_success(resp).await?.json().await?, "acl/show")
    }

    /// Write the entry `grant.subject` should hold. Conferring administrator
    /// authority needs a passkey gesture bound to this grant, and
    /// community-wide authority another administrator's consent; the refusal
    /// carries the ceremony in its `details`.
    pub async fn acl_grant(&self, grant: &AclGrant) -> Result<grant::Response, VtcError> {
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
        if let Some(reply) = self.acl_document(task::GRANT, payload.clone(), &[]).await? {
            return decode_payload(reply, "acl/grant");
        }
        let url = self.api_url(&["acl"])?;
        let resp = self
            .tt(reqwest::Method::POST, url, task::GRANT)?
            .json(&payload)
            .send()
            .await?;
        decode_payload(
            crate::expect_success(resp).await?.json().await?,
            "acl/grant",
        )
    }

    /// Amend an existing entry's label, scopes or expiry. Signed documents
    /// only: the VTC has no bearer route for it.
    pub async fn acl_update(&self, update: &AclUpdate) -> Result<update::Response, VtcError> {
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
        match self
            .acl_document(task::UPDATE, payload, update::ERROR_CODES)
            .await?
        {
            Some(reply) => decode_payload(reply, "acl/update"),
            None => Err(VtcError::Unsupported(
                "acl/update is a signed Trust Task only — connect with a key or a session",
            )),
        }
    }

    /// Move `subject` from `from_role` to `to_role`, compare-and-swapped on
    /// `from_role`. A promotion to admin needs a bound passkey gesture.
    pub async fn acl_change_role(
        &self,
        subject: &str,
        from_role: &str,
        to_role: &str,
        reason: Option<&str>,
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
        if let Some(reply) = self
            .acl_document(task::CHANGE_ROLE, payload.clone(), &[])
            .await?
        {
            return decode_payload(reply, "acl/change-role");
        }
        let mut rest = payload;
        if let Some(map) = rest.as_object_mut() {
            map.remove("subject");
        }
        let url = self.api_url(&["acl", subject])?;
        let resp = self
            .tt(reqwest::Method::PATCH, url, task::CHANGE_ROLE)?
            .json(&rest)
            .send()
            .await?;
        decode_payload(
            crate::expect_success(resp).await?.json().await?,
            "acl/change-role",
        )
    }

    /// Remove `subject`'s entry, or — with `scopes` — only those scopes. The
    /// reply's `entry` is `None` after a removal and the reduced entry after a
    /// reduction.
    pub async fn acl_revoke(
        &self,
        subject: &str,
        scopes: Option<&[String]>,
        reason: Option<&str>,
    ) -> Result<revoke::Response, VtcError> {
        let mut body = serde_json::json!({ "subject": subject });
        if let Some(scopes) = scopes {
            body["scopes"] = serde_json::json!(scopes);
        }
        if let Some(reason) = reason {
            body["reason"] = serde_json::json!(reason);
        }
        let payload = checked::<revoke::Payload>(body)?;
        if let Some(reply) = self
            .acl_document(task::REVOKE, payload, revoke::ERROR_CODES)
            .await?
        {
            return decode_payload(reply, "acl/revoke");
        }
        let mut url = self.api_url(&["acl", subject])?;
        {
            let mut q = url.query_pairs_mut();
            if let Some(scopes) = scopes {
                q.append_pair("scopes", &scopes.join(","));
            }
            if let Some(reason) = reason {
                q.append_pair("reason", reason);
            }
        }
        let resp = self
            .tt(reqwest::Method::DELETE, url, task::REVOKE)?
            .send()
            .await?;
        decode_payload(
            crate::expect_success(resp).await?.json().await?,
            "acl/revoke",
        )
    }

    async fn acl_document(
        &self,
        type_uri: &str,
        payload: serde_json::Value,
        declared: &[trust_tasks_rs::DeclaredErrorCode],
    ) -> Result<Option<serde_json::Value>, VtcError> {
        self.admin_document(type_uri, payload, declared, MAX_DOCUMENT_RESPONSE_BYTES)
            .await
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
