//! The community's ACL: the canonical `acl/*` tasks — `list/0.3`, and
//! `show`, `grant`, `update` and `revoke` at 0.2 (role-based administration:
//! `docs/05-design-notes/vtc-admin-roles.md`) — and `acl/change-role/0.1` for
//! the **community**-role change, which 0.2 (an administrative-role change)
//! does not express.
//!
//! At 0.2 an entry's `role` is its **administrative role** (`community-admin`,
//! `moderator`, `vetting-lead`, `repo-manager`, `credential-officer`,
//! `auditor`, `approver`, or `member` for none), and every axis — `act`,
//! `capabilities`, `approve`, `approveCapabilities`, `keys` — is stated. The
//! community role travels in `ext["org.openvtc"].communityRole`.
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
pub use vti_specs::acl::{
    grant::v0_2 as grant, list::v0_3 as list, revoke::v0_2 as revoke, show::v0_2 as show,
    swap_key::v0_1 as swap_key, update::v0_2 as update,
};
// acl/change-role/0.1 is the community-role door; 0.2 cannot express it (spec gap).
#[allow(deprecated)]
pub use vti_specs::acl::change_role::v0_1 as change_role;

/// The Type URI of each task in the family, read off the generated payloads.
pub mod task {
    use trust_tasks_rs::Payload;

    pub const LIST: &str = <super::list::Payload as Payload>::TYPE_URI;
    pub const SHOW: &str = <super::show::Payload as Payload>::TYPE_URI;
    pub const GRANT: &str = <super::grant::Payload as Payload>::TYPE_URI;
    pub const UPDATE: &str = <super::update::Payload as Payload>::TYPE_URI;
    // acl/change-role/0.1 is the community-role door; 0.2 cannot express it (spec gap).
    #[allow(deprecated)]
    pub const CHANGE_ROLE: &str = <super::change_role::Payload as Payload>::TYPE_URI;
    pub const REVOKE: &str = <super::revoke::Payload as Payload>::TYPE_URI;
    pub const SWAP_KEY: &str = <super::swap_key::Payload as Payload>::TYPE_URI;
}

/// How long a swap link proof lives: the VTC refuses one longer-lived than
/// fifteen minutes (VTI-CLT-026, short-lived), and the swap is sent at once.
pub const SWAP_LINK_PROOF_TTL_SECS: u64 = 300;

/// `acl/list/0.3` filters. Every member is optional. `resource` (and the
/// unused-at-a-community `context`) need a `direction`: `actingIn`, `subtree`
/// or `any`.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AclListFilter {
    /// An administrative role, or `member` for entries holding none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Only entries whose effective capability set includes this capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// A resource qualifier (`git-ns:github.com/acme`), read in `direction`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// The previous page's `nextCursor`, verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// An `acl/grant/0.2` entry: the administrative authority the subject should
/// hold, every axis stated.
#[derive(Debug, Clone, Default)]
pub struct AclGrant {
    pub subject: String,
    /// The administrative role, or `member` for none.
    pub admin_role: String,
    /// `cap` or `cap@resource` — narrows the role's ceiling to these. `None`
    /// holds the full ceiling (`{"scope": "ceiling"}`); an empty list holds
    /// none (`{"scope": "none"}`).
    pub capabilities: Option<Vec<String>>,
    /// Whether the subject may approve, within its role's approve ceiling.
    /// `false` states `{"scope": "none"}` rather than omitting it.
    pub approve: bool,
    /// Whether the subject acts at all. `false` is the least-privilege
    /// approver's `{"scope": "none"}`.
    pub act: bool,
    /// The community role (`member`, `moderator`, …), when it should differ
    /// from the one the administrative role implies.
    pub community_role: Option<String>,
    pub label: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: Option<String>,
}

/// An `acl/update/0.2` amendment. `None` leaves a member unchanged.
#[derive(Debug, Clone, Default)]
pub struct AclUpdate {
    pub subject: String,
    /// Replace the capability set: `Some(None)` returns it to the role's full
    /// ceiling, `Some(Some(list))` lists it (empty: none).
    pub capabilities: Option<Option<Vec<String>>>,
    pub approve: Option<bool>,
    pub label: Option<Option<String>>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub reason: Option<String>,
}

/// `cap` / `cap@resource` strings as a 0.2 capability scope.
pub fn capability_scope(caps: Option<&[String]>) -> serde_json::Value {
    match caps {
        None => serde_json::json!({ "scope": "ceiling" }),
        Some([]) => serde_json::json!({ "scope": "none" }),
        Some(list) => serde_json::json!({
            "scope": "listed",
            "grants": list
                .iter()
                .map(|c| match c.split_once('@') {
                    Some((cap, res)) => serde_json::json!({ "capability": cap, "resource": res }),
                    None => serde_json::json!({ "capability": c }),
                })
                .collect::<Vec<_>>(),
        }),
    }
}

fn explicit_scope(on: bool) -> serde_json::Value {
    serde_json::json!({ "scope": if on { "all" } else { "none" } })
}

impl VtcClient {
    /// Move `subject` from `from_role` to `to_role`, compare-and-swapped on
    /// `from_role`. A promotion to admin needs a bound passkey gesture.
    // acl/change-role/0.1 is the community-role door; 0.2 cannot express it (spec gap).
    #[allow(deprecated)]
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

    /// Remove `subject`'s entry (`acl/revoke/0.2`, `revocation: {kind: entry}`).
    /// The reply's `entry` is `None`.
    pub async fn acl_revoke(
        &self,
        subject: &str,
        reason: Option<&str>,
        key: &HolderKey,
    ) -> Result<revoke::Response, VtcError> {
        let mut body = serde_json::json!({
            "subject": subject,
            "revocation": { "kind": "entry" },
        });
        if let Some(reason) = reason {
            body["reason"] = serde_json::json!(reason);
        }
        let payload = checked::<revoke::Payload>(body)?;
        self.acl_task(task::REVOKE, payload, key, revoke::ERROR_CODES)
            .await
    }

    /// Remove `subject`'s entry **now**, without the cooling-off — offered only
    /// by a VTC in single-administrator mode (`vtc-action-list.md` §8.5). The
    /// request carries `ext["org.openvtc"].immediate`, so the passkey gesture
    /// the VTC asks for is bound to this immediate removal and to nothing
    /// else. `confirm` is what the operator typed: the subject's DID, or —
    /// with `action_id`, to land that open cooling-off now — the action's id.
    pub async fn acl_revoke_now(
        &self,
        subject: &str,
        confirm: &str,
        action_id: Option<&str>,
        reason: Option<&str>,
        key: &HolderKey,
    ) -> Result<revoke::Response, VtcError> {
        let mut immediate = serde_json::json!({ "confirm": confirm });
        if let Some(id) = action_id {
            immediate["actionId"] = serde_json::json!(id);
        }
        let mut body = serde_json::json!({
            "subject": subject,
            "revocation": { "kind": "entry" },
            "ext": { "org.openvtc": { "immediate": immediate } },
        });
        if let Some(reason) = reason {
            body["reason"] = serde_json::json!(reason);
        }
        let payload = checked::<revoke::Payload>(body)?;
        self.acl_task(task::REVOKE, payload, key, revoke::ERROR_CODES)
            .await
    }

    /// One page of the ACL (`acl/list/0.3`) — every entry with every axis
    /// stated. Any administrative role may read it.
    pub async fn acl_list(
        &self,
        filter: &AclListFilter,
        key: &HolderKey,
    ) -> Result<list::Response, VtcError> {
        let payload = checked::<list::Payload>(serde_json::to_value(filter).map_err(bad)?)?;
        self.acl_task(task::LIST, payload, key, list::ERROR_CODES)
            .await
    }

    /// Every ACL entry, following `nextCursor` to the end.
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
            match page.next_cursor {
                Some(cursor) => filter.cursor = Some(cursor.to_string()),
                None => return Ok(out),
            }
        }
    }

    /// One entry (`acl/show/0.2`); `entry` is `None` when the subject holds none.
    pub async fn acl_show(
        &self,
        subject: &str,
        key: &HolderKey,
    ) -> Result<show::Response, VtcError> {
        let payload = checked::<show::Payload>(serde_json::json!({ "subject": subject }))?;
        self.acl_task(task::SHOW, payload, key, &[]).await
    }

    /// Write the entry `grant.subject` should hold (`acl/grant/0.2`). A grant is bounded
    /// by the caller's own entry; widening administrative authority needs a
    /// passkey gesture bound to it, and an authority-conferring capability its
    /// other holders' consent (the refusal or the parked action says so).
    pub async fn acl_grant(
        &self,
        grant: &AclGrant,
        key: &HolderKey,
    ) -> Result<grant::Response, VtcError> {
        let mut entry = serde_json::json!({
            "subject": grant.subject,
            "role": grant.admin_role,
            "act": explicit_scope(grant.act),
            "keys": { "scope": "none" },
            "capabilities": capability_scope(grant.capabilities.as_deref()),
            "approve": explicit_scope(grant.approve),
        });
        if grant.approve {
            entry["approveCapabilities"] = serde_json::json!({ "scope": "ceiling" });
        }
        if let Some(label) = &grant.label {
            entry["label"] = serde_json::json!(label);
        }
        if let Some(at) = grant.expires_at {
            entry["expiresAt"] = serde_json::json!(at.to_rfc3339());
        }
        if let Some(role) = &grant.community_role {
            entry["ext"] = serde_json::json!({ "org.openvtc": { "communityRole": role } });
        }
        let mut body = serde_json::json!({ "entry": entry });
        if let Some(reason) = &grant.reason {
            body["reason"] = serde_json::json!(reason);
        }
        let payload = checked::<grant::Payload>(body)?;
        self.acl_task(task::GRANT, payload, key, grant::ERROR_CODES)
            .await
    }

    /// Amend an existing entry (`acl/update/0.2`): its capabilities, approve scope, label
    /// or expiry. Narrowing is a privilege reduction applied at once.
    pub async fn acl_update(
        &self,
        update: &AclUpdate,
        key: &HolderKey,
    ) -> Result<update::Response, VtcError> {
        let mut body = serde_json::json!({ "subject": update.subject });
        if let Some(caps) = &update.capabilities {
            body["capabilities"] = capability_scope(caps.as_deref());
        }
        if let Some(approve) = update.approve {
            body["approve"] = explicit_scope(approve);
            body["approveCapabilities"] = if approve {
                serde_json::json!({ "scope": "ceiling" })
            } else {
                serde_json::json!({ "scope": "none" })
            };
        }
        if let Some(label) = &update.label {
            body["label"] = serde_json::json!(label);
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

    /// Roll `key`'s own ACL entry onto a new key (`acl/swap-key/0.1`,
    /// VTI-CLT-025 – 032): the entry moves to `new_did` with its authority
    /// exactly as it was, and `key`'s DID loses all standing.
    ///
    /// The document is signed by `key` — the entry's current subject, never a
    /// key acting for it — and carries the link proof the VTC requires: a
    /// short-lived VP-JWT signed by the new key and addressed to this VTC,
    /// proving the new key consents and is held. `new_did` must be the
    /// `did:key` of `new_private_key_multibase`.
    ///
    /// The caller persists the new key **before** this returns to anything
    /// that could fail: once the VTC answers, the old key is worthless.
    pub async fn acl_swap_key(
        &self,
        key: &HolderKey,
        new_did: &str,
        new_private_key_multibase: &str,
        reason: Option<&str>,
    ) -> Result<swap_key::Response, VtcError> {
        let seed = vta_sdk::did_key::decode_private_key_multibase(new_private_key_multibase)
            .map_err(|e| VtcError::Signing(format!("the new key does not decode: {e}")))?;
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let derived = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&signing.verifying_key().to_bytes())
        );
        if derived != new_did {
            return Err(VtcError::Signing(format!(
                "{new_did} is not the did:key of the new private key ({derived})"
            )));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let link_proof = vta_sdk::protocols::acl_management::swap::build_swap_presentation(
            &signing,
            new_did,
            &self.vtc_did,
            now,
            SWAP_LINK_PROOF_TTL_SECS,
            None,
        );
        let mut body = serde_json::json!({
            "currentSubject": key.holder_did(),
            "newSubject": new_did,
            "linkProof": link_proof,
        });
        if let Some(reason) = reason {
            body["reason"] = serde_json::json!(reason);
        }
        let payload = checked::<swap_key::Payload>(body)?;
        self.acl_task(task::SWAP_KEY, payload, key, swap_key::ERROR_CODES)
            .await
    }

    /// Sign one `acl/*` document as `key` and send it, over the client's
    /// session when it holds one — `key` must then be the session's identity
    /// — otherwise signed with `key` and posted to the document endpoint.
    /// `declared` is the task's declared error codes, honoured only on the
    /// HTTPS path (a 404 naming one becomes [`VtcError::NotFound`]); a session
    /// refusal is always [`VtcError::Refused`].
    pub(crate) async fn acl_task<R: DeserializeOwned>(
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
            resource: Some("git-ns:github.com/acme".into()),
            direction: Some("subtree".into()),
            limit: Some(10),
            ..Default::default()
        };
        let v = checked::<list::Payload>(serde_json::to_value(&filter).unwrap()).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "resource": "git-ns:github.com/acme",
                "direction": "subtree",
                "limit": 10
            })
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
    fn a_revocation_states_what_it_revokes() {
        // 0.2 has no implicit full removal: `revocation` is required, and an
        // empty act narrowing is not a scope.
        let bare = serde_json::json!({ "subject": "did:key:z6MkA" });
        assert!(checked::<revoke::Payload>(bare).is_err());
        let empty = serde_json::json!({
            "subject": "did:key:z6MkA",
            "revocation": { "kind": "act", "act": { "scope": "contexts", "contexts": [] } },
        });
        assert!(checked::<revoke::Payload>(empty).is_err());
        let entry = serde_json::json!({
            "subject": "did:key:z6MkA",
            "revocation": { "kind": "entry" },
        });
        assert!(checked::<revoke::Payload>(entry).is_ok());
    }

    /// A 0.2 grant states every axis, and the capability strings become
    /// qualified grants.
    #[test]
    fn a_0_2_grant_states_every_axis() {
        let caps = vec![
            "git.repo.manage@git-ns:github.com/acme".to_string(),
            "git.ns.admin@git-ns:github.com/acme".to_string(),
        ];
        let scope = capability_scope(Some(&caps));
        assert_eq!(scope["scope"], "listed");
        assert_eq!(scope["grants"][0]["resource"], "git-ns:github.com/acme");
        assert_eq!(
            capability_scope(None),
            serde_json::json!({"scope": "ceiling"})
        );
        assert_eq!(
            capability_scope(Some(&[])),
            serde_json::json!({"scope": "none"})
        );
        let body = serde_json::json!({ "entry": {
            "subject": "did:key:z6MkA",
            "role": "repo-manager",
            "act": explicit_scope(true),
            "keys": { "scope": "none" },
            "capabilities": scope,
            "approve": explicit_scope(false),
        }});
        assert!(checked::<grant::Payload>(body).is_ok());
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
