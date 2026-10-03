//! Client surface for the `git-ns/*` Trust Tasks — a community's governance of
//! the forge repositories it has bound.
//!
//! # Two kinds of call
//!
//! **Changes are signed Trust Tasks.** A grant, a revoke, a bind or an
//! adoption is authorized by the *signer's* git rights, which the VTC reads
//! from its own records when the document arrives — not by a bearer token. So
//! these methods take a [`HolderKey`] and never read `self.token`. A community
//! administrator's session does not stand in for a git right: an administrator
//! who holds none grants nothing.
//!
//! They go the way every Trust Task this client sends goes: over the DIDComm
//! or TSP session when the client holds one ([`VtcClient::connect_tsp`],
//! [`VtcClient::connect_didcomm`]), otherwise signed with the key and posted to
//! `POST {base}/trust-tasks`. The document is the same on every transport —
//! signed, addressed to the community, and bound to its sender: over a session
//! the VTC takes it only when its proof, its `issuer` and the envelope's
//! sender are one DID, so the key must be the session's own identity, and a
//! call whose key names another DID is refused here before anything is sent.
//! A refusal reads the same either way — [`task_error`] and
//! [`step_up_request`] recover its code and details from the
//! `trust-task-error` document whichever transport carried it.
//!
//! **Reads are signed Trust Tasks too**, and go the same way: a member's
//! `git-ns/view`, and the administrator's reads — `git-ns/view/0.5` with
//! `scope: administrator` or `breakGlass: true`, `git-ns/namespace/list/0.1`
//! and `git-ns/repo/list/0.1` — which the VTC answers to a namespace's
//! administrators only, from the signer's standing, never from a bearer token.
//!
//! The payload and response types are the specification's own, generated
//! into `trust_tasks_rs::specs::git_ns` and re-exported here as [`specs`].

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{HolderKey, VtcClient, VtcError};

/// The generated `git-ns/*` wire types.
pub use trust_tasks_rs::specs::git_ns as specs;

use specs::account::{
    link::v0_1 as link, link_status::v0_1 as link_status, unlink::v0_1 as unlink,
};
use specs::drift::resolve::{v0_1 as drift_resolve, v0_3 as drift_resolve3};
use specs::namespace::{
    bind::v0_1 as bind, list::v0_1 as namespace_list, reseat::v0_3 as reseat,
    unbind::v0_1 as unbind,
};

/// `git-ns/namespace/reseat/0.3`, the only reseat version the VTC serves.
pub const RESEAT_TYPE_URI: &str = <reseat::Payload as trust_tasks_rs::Payload>::TYPE_URI;
use specs::repo::{
    adopt::v0_1 as adopt, archive::v0_1 as archive, create::v0_3 as create,
    list::v0_1 as repo_list, transfer::v0_1 as transfer,
};
use specs::right::{
    break_glass::v0_1 as break_glass, grant::v0_3 as grant, ratify::v0_1 as ratify,
    revoke::v0_3 as revoke,
};
use specs::roles::reproject::v0_1 as reproject;
use specs::view::{v0_1 as view, v0_2 as view2, v0_4 as view4, v0_5 as view5};

/// `git-ns/view/0.1`'s type URI.
pub const GIT_NS_VIEW_TYPE: &str = <view::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `git-ns/view/0.5`: 0.4 plus `scope: administrator` and `breakGlass`.
pub const GIT_NS_VIEW_V5_TYPE: &str = <view5::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `git-ns/namespace/list/0.1`: the namespaces the signer administers.
pub const GIT_NS_NAMESPACE_LIST_TYPE: &str =
    <namespace_list::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `git-ns/repo/list/0.1`: the repositories in the namespaces the signer
/// administers.
pub const GIT_NS_REPO_LIST_TYPE: &str = <repo_list::Payload as trust_tasks_rs::Payload>::TYPE_URI;

impl VtcClient {
    /// Sign one `git-ns/*` document as `key` and send it; returns the
    /// response document's payload.
    ///
    /// Over the client's session when it holds one — `key` must then be the
    /// session's identity — otherwise signed with `key` and posted to the
    /// document endpoint.
    ///
    /// A refusal carries the `trust-task-error` document — as
    /// [`VtcError::Refused`] over a session, as [`VtcError::Http`]'s body over
    /// HTTPS — so a caller can read its `code`, the specification's
    /// (`git-ns:lastOwner`, `git-ns:escalation`, …), with [`task_error`].
    pub async fn git_ns_task<P: Serialize, R: DeserializeOwned>(
        &self,
        type_uri: &str,
        payload: &P,
        key: &HolderKey,
    ) -> Result<R, VtcError> {
        #[cfg(feature = "didcomm")]
        if self.documents.is_some() {
            let payload = serde_json::to_value(payload)
                .map_err(|e| VtcError::Url(format!("serialise {type_uri} payload: {e}")))?;
            return self
                .git_ns_over_session(type_uri, payload, key.holder_did())
                .await;
        }
        let doc = self.git_ns_sign(type_uri, payload, key).await?;
        self.git_ns_post_signed(type_uri, &doc).await
    }

    /// Sign one `git-ns/*` document as `key`, without sending it — for a task
    /// that may be refused for want of an operation-bound step-up, where the
    /// same operation must be sent again once the gesture is recorded (the
    /// gesture is bound to the payload's digest; a re-signed document has a
    /// new `id` and `issuedAt`, but the same payload, so either works —
    /// sending the same one over HTTPS keeps the audit trail to one document).
    pub async fn git_ns_sign<P: Serialize>(
        &self,
        type_uri: &str,
        payload: &P,
        key: &HolderKey,
    ) -> Result<String, VtcError> {
        let payload = serde_json::to_value(payload)
            .map_err(|e| VtcError::Url(format!("serialise {type_uri} payload: {e}")))?;
        vta_sdk::trust_task_sign::build_signed_with(type_uri, payload, key, &self.vtc_did)
            .await
            .map_err(|e| VtcError::Signing(e.to_string()))
    }

    /// Send a document [`Self::git_ns_sign`] produced; returns the response
    /// document's payload.
    ///
    /// Over HTTPS the document is posted as it stands. Over a session its
    /// payload goes in the document the session signs — the same DID, which
    /// must be the one `doc` names as `issuer`, addressed to the same
    /// community, so it is the same operation with the same payload digest.
    pub async fn git_ns_send_signed<R: DeserializeOwned>(
        &self,
        type_uri: &str,
        doc: &str,
    ) -> Result<R, VtcError> {
        #[cfg(feature = "didcomm")]
        if self.documents.is_some() {
            let parsed: Value = serde_json::from_str(doc)
                .map_err(|e| VtcError::InvalidPayload(format!("not a Trust Task document: {e}")))?;
            let member = |name: &str| parsed.get(name).and_then(Value::as_str);
            if member("type") != Some(type_uri) {
                return Err(VtcError::InvalidPayload(format!(
                    "the document is not a {type_uri} document"
                )));
            }
            if member("recipient") != Some(self.vtc_did.as_str()) {
                return Err(VtcError::InvalidPayload(format!(
                    "the document is not addressed to {}",
                    self.vtc_did
                )));
            }
            let issuer = member("issuer")
                .ok_or_else(|| VtcError::InvalidPayload("the document names no issuer".into()))?
                .to_string();
            let payload = parsed.get("payload").cloned().unwrap_or(Value::Null);
            return self.git_ns_over_session(type_uri, payload, &issuer).await;
        }
        self.git_ns_post_signed(type_uri, doc).await
    }

    /// One `git-ns/*` task over the client's session, attributed to
    /// `signer_did`.
    ///
    /// The session signs the document as its own DID and the VTC binds that
    /// proof to the envelope's sender, so a task meant to be signed as any
    /// other DID cannot go this way: it is refused here, before anything is
    /// sent, rather than arrive attributed to the wrong member.
    #[cfg(feature = "didcomm")]
    async fn git_ns_over_session<R: DeserializeOwned>(
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
                "{type_uri} is to be signed as {signer_did}, but this client's session is                  {session_did}; over a session the VTC accepts a document only from the DID                  that signed it"
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
        serde_json::from_value(payload).map_err(|e| VtcError::Http {
            status: 200,
            body: format!("{type_uri} response does not fit its schema: {e}"),
        })
    }

    /// POST a signed `git-ns/*` document to the document endpoint.
    async fn git_ns_post_signed<R: DeserializeOwned>(
        &self,
        type_uri: &str,
        doc: &str,
    ) -> Result<R, VtcError> {
        let doc = doc.to_string();
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

    /// `git-ns/repo/create/0.3`.
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

    /// `git-ns/right/grant/0.3` — separation of duties: an elevated right
    /// (`git.ns.admin`, `git.repo.create`, `git.repo.own`) is refused
    /// `git-ns:selfGrantNotAllowed` when the subject is the signer.
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

    /// `git-ns/right/revoke/0.3`.
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

    /// `git-ns/right/ratify/0.1` — ratify another member's break-glass.
    pub async fn git_ns_ratify(
        &self,
        payload: &ratify::Payload,
        key: &HolderKey,
    ) -> Result<ratify::Response, VtcError> {
        self.git_ns_task(
            <ratify::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            payload,
            key,
        )
        .await
    }

    /// `git-ns/view/0.4` — as [`Self::git_ns_view_v2`], with each record's
    /// `breakGlass`, and every unratified break-glass record the signer
    /// administers.
    pub async fn git_ns_view_v4(
        &self,
        resource: Option<&str>,
        key: &HolderKey,
    ) -> Result<view4::Response, VtcError> {
        let payload = match resource {
            Some(r) => serde_json::json!({ "resource": r }),
            None => serde_json::json!({}),
        };
        self.git_ns_task(
            <view4::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            &payload,
            key,
        )
        .await
    }

    /// `git-ns/view/0.5` — 0.4's answer, or with `administrator` every record
    /// and reason in the namespaces `key`'s DID administers; with
    /// `break_glass`, only break-glass records (ratified ones included). The
    /// response is 0.4's.
    pub async fn git_ns_view_v5(
        &self,
        resource: Option<&str>,
        administrator: bool,
        break_glass: bool,
        key: &HolderKey,
    ) -> Result<view4::Response, VtcError> {
        let mut payload = serde_json::Map::new();
        if let Some(r) = resource {
            payload.insert("resource".into(), r.into());
        }
        if administrator {
            payload.insert("scope".into(), "administrator".into());
        }
        if break_glass {
            payload.insert("breakGlass".into(), true.into());
        }
        self.git_ns_task(GIT_NS_VIEW_V5_TYPE, &Value::Object(payload), key)
            .await
    }

    /// `git-ns/namespace/list/0.1` — the namespaces `key`'s DID administers,
    /// or only `namespace`, with admins, bridge, role map and forge status.
    pub async fn git_ns_namespace_list(
        &self,
        namespace: Option<&str>,
        key: &HolderKey,
    ) -> Result<Value, VtcError> {
        let payload = match namespace {
            Some(n) => serde_json::json!({ "namespace": n }),
            None => serde_json::json!({}),
        };
        self.git_ns_task(GIT_NS_NAMESPACE_LIST_TYPE, &payload, key)
            .await
    }

    /// `git-ns/repo/list/0.1` — the repositories in the namespaces `key`'s DID
    /// administers, or in `namespace` only, with owners, right counts,
    /// bootstrap, sync and the bridge's report.
    pub async fn git_ns_repo_list(
        &self,
        namespace: Option<&str>,
        key: &HolderKey,
    ) -> Result<Value, VtcError> {
        let payload = match namespace {
            Some(n) => serde_json::json!({ "namespace": n }),
            None => serde_json::json!({}),
        };
        self.git_ns_task(GIT_NS_REPO_LIST_TYPE, &payload, key).await
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

    /// `git-ns/drift/resolve/0.3` — adopt or revert one reported drift item.
    /// An adopt names the member who receives the right (`subject`); the VTC
    /// adopts nothing unless the account is still linked to exactly them.
    pub async fn git_ns_drift_resolve_v3(
        &self,
        payload: &drift_resolve3::Payload,
        key: &HolderKey,
    ) -> Result<drift_resolve3::Response, VtcError> {
        self.git_ns_task(
            <drift_resolve3::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            payload,
            key,
        )
        .await
    }

    /// `git-ns/drift/resolve/0.1` — revert one reported drift item. A 0.1
    /// adopt names no recipient, and a VTC that serves 0.3 refuses it
    /// (`unsupportedVersion`); adopt with [`Self::git_ns_drift_resolve_v3`].
    #[deprecated(
        note = "a drift/resolve 0.1 adopt names no recipient and is refused; use git_ns_drift_resolve_v3"
    )]
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

    /// `git-ns/roles/reproject/0.1` — a community administrator or namespace
    /// admin has the bridge re-apply the forge roles of a namespace's
    /// repositories, or of one repository. No right changes.
    pub async fn git_ns_reproject(
        &self,
        resource: &str,
        reason: Option<&str>,
        key: &HolderKey,
    ) -> Result<reproject::Response, VtcError> {
        let mut payload = serde_json::json!({ "resource": resource });
        if let Some(r) = reason {
            payload["reason"] = serde_json::json!(r);
        }
        self.git_ns_task(
            <reproject::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            &payload,
            key,
        )
        .await
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

    /// `git-ns/account/unlink/0.1` — remove the account linked to `key`'s DID
    /// on `forge`. With `account_id`, only if that is still the account
    /// linked there (`git-ns/account/unlink:notLinked` otherwise).
    pub async fn git_ns_unlink_account(
        &self,
        forge: &str,
        account_id: Option<&str>,
        key: &HolderKey,
    ) -> Result<unlink::Response, VtcError> {
        let mut payload = serde_json::json!({ "forge": forge });
        if let Some(id) = account_id {
            payload["accountId"] = serde_json::json!(id);
        }
        self.git_ns_task(
            <unlink::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            &payload,
            key,
        )
        .await
    }
}

/// The type URI of `git-ns/right/break-glass/0.1`.
pub const GIT_NS_BREAK_GLASS_TYPE: &str =
    <break_glass::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The type URI of `git-ns/right/grant/0.3`. Signed with
/// [`VtcClient::git_ns_sign`] and sent with [`VtcClient::git_ns_send_signed`]
/// when the caller must be able to answer an operation-bound step-up and
/// re-send the identical document — a self-grant under single-administrator
/// mode, which carries `ext.org.openvtc.selfGrantWaived` in its answer.
pub const GIT_NS_GRANT_TYPE: &str = <grant::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The type URI of `git-ns/repo/create/0.3` (see [`GIT_NS_GRANT_TYPE`]).
pub const GIT_NS_REPO_CREATE_TYPE: &str = <create::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The type URI of `git-ns/repo/adopt/0.1` (see [`GIT_NS_GRANT_TYPE`]).
pub const GIT_NS_REPO_ADOPT_TYPE: &str = <adopt::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The type URI of `git-ns/drift/resolve/0.3` (see [`GIT_NS_GRANT_TYPE`]).
pub const GIT_NS_DRIFT_RESOLVE_V3_TYPE: &str =
    <drift_resolve3::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The `ext.org.openvtc.selfGrantWaived` member of a `git-ns/*` answer: present
/// exactly when the VTC, in single-administrator mode, recorded an elevated
/// right for the signer themselves because nobody else could grant it
/// (VTI-APV-022).
pub fn self_grant_waived(answer: &Value) -> Option<&Value> {
    answer
        .get("ext")?
        .get("org.openvtc")?
        .get("selfGrantWaived")
        .filter(|v| v.is_object())
}

/// The type URI of `auth/step-up/approve-response/0.4`: the answer, signed by
/// the actor with its `assertionMethod` key, to the operation-bound step-up a
/// signed change can be refused for. The passkey assertion it carries is in
/// addition to that proof, never instead of it.
pub const STEP_UP_APPROVE_RESPONSE_TYPE: &str =
    <trust_tasks_rs::specs::auth::step_up::approve_response::v0_4::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The type URI of `auth/passkey/enroll/redeem/start/0.1`: a member redeeming
/// a community administrator's invite to enrol a step-up passkey, signed as
/// the member the invite names.
pub const STEP_UP_PASSKEY_REDEEM_START_TYPE: &str =
    <trust_tasks_rs::specs::auth::passkey::enroll::redeem::start::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The `trust-task-error` document a refusal carries, whichever transport
/// carried it: [`VtcError::Refused`] over a session, [`VtcError::Http`]'s body
/// over HTTPS.
fn refusal_document(err: &VtcError) -> Option<Value> {
    let text = match err {
        VtcError::Http { body, .. } => body,
        VtcError::Refused { document } => document,
        _ => return None,
    };
    serde_json::from_str(text).ok()
}

/// The inline `auth/step-up/approve-request` a refusal carries as
/// `details.stepUpRequest`, when it is one: the operation needs a passkey
/// gesture bound to it before the same operation is sent again.
pub fn step_up_request(err: &VtcError) -> Option<Value> {
    refusal_document(err)?
        .pointer("/payload/details/stepUpRequest")
        .cloned()
}

/// The `code` and `message` of the `trust-task-error` document a refusal
/// carries, on any transport, when it is one.
pub fn task_error(err: &VtcError) -> Option<(String, String)> {
    let doc = refusal_document(err)?;
    let code = doc.pointer("/payload/code")?.as_str()?.to_string();
    let message = doc
        .pointer("/payload/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Some((code, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(code: &str) -> String {
        serde_json::json!({
            "type": "https://trusttasks.org/spec/trust-task-error/0.1",
            "payload": {
                "code": code,
                "message": "no",
                "details": { "stepUpRequest": { "boundTo": "sha-256:abc" } },
            },
        })
        .to_string()
    }

    /// A refusal reads the same whichever transport carried it: the code and
    /// the inline step-up request come off a session's `Refused` document as
    /// they do off the document endpoint's body.
    #[test]
    fn a_refusal_reads_alike_over_a_session_and_over_https() {
        let over_session = VtcError::Refused {
            document: refusal("git-ns:lastOwner"),
        };
        let over_https = VtcError::Http {
            status: 403,
            body: refusal("git-ns:lastOwner"),
        };
        for err in [&over_session, &over_https] {
            assert_eq!(
                task_error(err),
                Some(("git-ns:lastOwner".to_string(), "no".to_string()))
            );
            assert_eq!(
                step_up_request(err).and_then(|r| r["boundTo"].as_str().map(str::to_string)),
                Some("sha-256:abc".to_string())
            );
        }
        assert_eq!(task_error(&VtcError::Session("down".into())), None);
    }
}
