//! Client surface for the `git-ns/*` Trust Tasks — a community's governance of
//! the forge repositories it has bound.
//!
//! # Two kinds of call
//!
//! **Changes are signed Trust Tasks.** A grant, a revoke, a bind or an
//! adoption is authorized by the *signer's* git rights, which the VTC reads
//! from its own records when the document arrives — not by a bearer token. So
//! these methods take a [`HolderKey`], sign the document with it, and post it
//! to the document endpoint; they never read `self.token`. A community
//! administrator's session does not stand in for a git right: an administrator
//! who holds none grants nothing.
//!
//! **Listings are the administrator's REST reads** (`/v1/git-ns/*`), which need
//! an admin token and return the console's JSON.
//!
//! The payload and response types are the specification's own, generated
//! into `trust_tasks_rs::specs::git_ns` and re-exported here as [`specs`].

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{HolderKey, VtcClient, VtcError};

/// The generated `git-ns/*` wire types.
pub use trust_tasks_rs::specs::git_ns as specs;

use specs::account::{link::v0_1 as link, link_status::v0_1 as link_status};
use specs::drift::resolve::v0_1 as drift_resolve;
use specs::namespace::{bind::v0_1 as bind, reseat::v0_2 as reseat, unbind::v0_1 as unbind};

/// `git-ns/namespace/reseat/0.3`, the only reseat version the VTC serves.
/// TODO(trust-tasks release carrying trust-tasks #635): use the generated
/// `reseat::v0_3` type URI.
pub const RESEAT_TYPE_URI: &str = "https://trusttasks.org/spec/git-ns/namespace/reseat/0.3";
use specs::repo::{
    adopt::v0_1 as adopt, archive::v0_1 as archive, create::v0_1 as create,
    transfer::v0_1 as transfer,
};
use specs::right::{grant::v0_1 as grant, revoke::v0_1 as revoke};
use specs::view::{v0_1 as view, v0_2 as view2};

/// The `Trust-Task` URL every git-namespace admin read is gated on.
pub const GIT_NS_VIEW_TYPE: &str = <view::Payload as trust_tasks_rs::Payload>::TYPE_URI;

impl VtcClient {
    /// Sign one `git-ns/*` document as `key` and send it; returns the
    /// response document's payload.
    ///
    /// A refusal comes back as [`VtcError::Http`] whose body is the
    /// `trust-task-error` document, so a caller can read its `code` — the
    /// specification's (`git-ns:lastOwner`, `git-ns:escalation`, …).
    pub async fn git_ns_task<P: Serialize, R: DeserializeOwned>(
        &self,
        type_uri: &str,
        payload: &P,
        key: &HolderKey,
    ) -> Result<R, VtcError> {
        let payload = serde_json::to_value(payload)
            .map_err(|e| VtcError::Url(format!("serialise {type_uri} payload: {e}")))?;
        let doc =
            vta_sdk::trust_task_sign::build_signed_with(type_uri, payload, key, &self.vtc_did)
                .await
                .map_err(|e| VtcError::Signing(e.to_string()))?;
        if self.base_url.is_empty() {
            return Err(VtcError::NoRestTransport("a git-ns task"));
        }
        let resp = self
            .http
            .post(format!("{}/trust-tasks", self.base_url))
            .header("content-type", "application/json")
            .body(doc)
            .send()
            .await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        let doc: trust_tasks_rs::TrustTask<Value> =
            serde_json::from_str(&text).map_err(|e| VtcError::Http {
                status,
                body: format!("not a Trust Task document ({e}): {text}"),
            })?;
        if doc.type_uri.slug() == "trust-task-error" || !(200..300).contains(&status) {
            return Err(VtcError::Http { status, body: text });
        }
        serde_json::from_value(doc.payload).map_err(|e| VtcError::Http {
            status,
            body: format!("{type_uri} response does not fit its schema: {e}"),
        })
    }

    /// `git-ns/namespace/bind/0.1`. `mode` is `bridge` or `manual`.
    pub async fn git_ns_bind(
        &self,
        forge: &str,
        owner: &str,
        mode: &str,
        key: &HolderKey,
    ) -> Result<bind::Response, VtcError> {
        let payload = serde_json::json!({ "forge": forge, "owner": owner, "mode": mode });
        self.git_ns_task(
            <bind::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            &payload,
            key,
        )
        .await
    }

    /// `git-ns/namespace/unbind/0.1`.
    pub async fn git_ns_unbind(
        &self,
        namespace: &str,
        key: &HolderKey,
    ) -> Result<unbind::Response, VtcError> {
        let payload = serde_json::json!({ "namespace": namespace });
        self.git_ns_task(
            <unbind::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            &payload,
            key,
        )
        .await
    }

    /// `git-ns/repo/create/0.1`.
    pub async fn git_ns_create_repo(
        &self,
        payload: &create::Payload,
        key: &HolderKey,
    ) -> Result<create::Response, VtcError> {
        self.git_ns_task(
            <create::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            payload,
            key,
        )
        .await
    }

    /// `git-ns/repo/adopt/0.1`.
    pub async fn git_ns_adopt(
        &self,
        resource: &str,
        owners: &[String],
        key: &HolderKey,
    ) -> Result<adopt::Response, VtcError> {
        let payload = serde_json::json!({ "resource": resource, "owners": owners });
        self.git_ns_task(
            <adopt::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            &payload,
            key,
        )
        .await
    }

    /// `git-ns/repo/transfer/0.1` — hand `key`'s ownership of `resource` to
    /// `to`.
    pub async fn git_ns_transfer(
        &self,
        resource: &str,
        to: &str,
        key: &HolderKey,
    ) -> Result<transfer::Response, VtcError> {
        let payload = serde_json::json!({ "resource": resource, "to": to });
        self.git_ns_task(
            <transfer::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            &payload,
            key,
        )
        .await
    }

    /// `git-ns/repo/archive/0.1`.
    pub async fn git_ns_archive(
        &self,
        resource: &str,
        key: &HolderKey,
    ) -> Result<archive::Response, VtcError> {
        let payload = serde_json::json!({ "resource": resource });
        self.git_ns_task(
            <archive::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            &payload,
            key,
        )
        .await
    }

    /// `git-ns/right/grant/0.1`.
    pub async fn git_ns_grant(
        &self,
        payload: &grant::Payload,
        key: &HolderKey,
    ) -> Result<grant::Response, VtcError> {
        self.git_ns_task(
            <grant::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            payload,
            key,
        )
        .await
    }

    /// `git-ns/right/revoke/0.1`.
    pub async fn git_ns_revoke(
        &self,
        payload: &revoke::Payload,
        key: &HolderKey,
    ) -> Result<revoke::Response, VtcError> {
        self.git_ns_task(
            <revoke::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            payload,
            key,
        )
        .await
    }

    /// `git-ns/view/0.1` — what `key`'s DID may see, as a member.
    pub async fn git_ns_view(
        &self,
        resource: Option<&str>,
        key: &HolderKey,
    ) -> Result<view::Response, VtcError> {
        let payload = match resource {
            Some(r) => serde_json::json!({ "resource": r }),
            None => serde_json::json!({}),
        };
        self.git_ns_task(GIT_NS_VIEW_TYPE, &payload, key).await
    }

    /// `git-ns/view/0.2` — as [`Self::git_ns_view`], plus the forge accounts
    /// linked to `key`'s own DID.
    pub async fn git_ns_view_v2(
        &self,
        resource: Option<&str>,
        key: &HolderKey,
    ) -> Result<view2::Response, VtcError> {
        let payload = match resource {
            Some(r) => serde_json::json!({ "resource": r }),
            None => serde_json::json!({}),
        };
        self.git_ns_task(
            <view2::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            &payload,
            key,
        )
        .await
    }

    /// `git-ns/drift/resolve/0.1` — adopt or revert one reported drift item.
    pub async fn git_ns_drift_resolve(
        &self,
        payload: &drift_resolve::Payload,
        key: &HolderKey,
    ) -> Result<drift_resolve::Response, VtcError> {
        self.git_ns_task(
            <drift_resolve::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            payload,
            key,
        )
        .await
    }

    /// `git-ns/namespace/reseat/0.3` — a community administrator restores an
    /// admin to a headless namespace. 0.3 is wire-identical to 0.2, whose
    /// generated types are used until a `trust-tasks-rs` release carries
    /// 0.3's (TODO, with trust-tasks #635).
    pub async fn git_ns_reseat(
        &self,
        namespace: &str,
        subject: &str,
        statement: &str,
        key: &HolderKey,
    ) -> Result<reseat::Response, VtcError> {
        let payload = serde_json::json!({
            "namespace": namespace,
            "subject": subject,
            "statement": statement,
        });
        self.git_ns_task(RESEAT_TYPE_URI, &payload, key).await
    }

    /// `git-ns/account/link/0.1`.
    pub async fn git_ns_link_account(
        &self,
        forge: &str,
        key: &HolderKey,
    ) -> Result<link::Response, VtcError> {
        let payload = serde_json::json!({ "forge": forge });
        self.git_ns_task(
            <link::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            &payload,
            key,
        )
        .await
    }

    /// `git-ns/account/link-status/0.1` — where a link `key`'s DID began with
    /// [`Self::git_ns_link_account`] stands. Anyone else's `link_id` is
    /// answered `git-ns/account/link-status:unknownLink`, as a missing one is.
    pub async fn git_ns_link_status(
        &self,
        link_id: &str,
        key: &HolderKey,
    ) -> Result<link_status::Response, VtcError> {
        let payload = serde_json::json!({ "linkId": link_id });
        self.git_ns_task(
            <link_status::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            &payload,
            key,
        )
        .await
    }

    /// `GET /v1/git-ns/namespaces` — admin token. The console's JSON.
    pub async fn git_ns_namespaces(&self) -> Result<Value, VtcError> {
        self.git_ns_get(&["git-ns", "namespaces"], &[]).await
    }

    /// `GET /v1/git-ns/repos` — admin token, optionally one namespace.
    pub async fn git_ns_repos(&self, namespace: Option<&str>) -> Result<Value, VtcError> {
        let query: Vec<(&str, &str)> = namespace.map(|n| ("namespace", n)).into_iter().collect();
        self.git_ns_get(&["git-ns", "repos"], &query).await
    }

    /// `GET /v1/git-ns/view` — admin token: every record and reason.
    pub async fn git_ns_admin_view(&self, resource: Option<&str>) -> Result<Value, VtcError> {
        let query: Vec<(&str, &str)> = resource.map(|r| ("resource", r)).into_iter().collect();
        self.git_ns_get(&["git-ns", "view"], &query).await
    }

    async fn git_ns_get(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<Value, VtcError> {
        let mut url = self.api_url(segments)?;
        for (k, v) in query {
            url.query_pairs_mut().append_pair(k, v);
        }
        let resp = self
            .tt(reqwest::Method::GET, url, GIT_NS_VIEW_TYPE)?
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtcError::Http { status, body });
        }
        Ok(resp.json().await?)
    }
}

/// The `code` and `message` of a `trust-task-error` document carried in a
/// [`VtcError::Http`] body, when it is one.
pub fn task_error(err: &VtcError) -> Option<(String, String)> {
    let VtcError::Http { body, .. } = err else {
        return None;
    };
    let doc: Value = serde_json::from_str(body).ok()?;
    let code = doc.pointer("/payload/code")?.as_str()?.to_string();
    let message = doc
        .pointer("/payload/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Some((code, message))
}
