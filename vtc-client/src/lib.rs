//! Client SDK for a Verifiable Trust Community (VTC).
//!
//! The VTA SDK ([`vta_sdk`]) is the client for *VTAs*; this crate is the
//! equivalent for *VTCs*. It lets an operator or an integration drive a VTC's
//! member-facing and admin-facing surface over REST: authenticate, list members
//! (the community roster), run the join ceremony, remove members, and manage
//! community policy.
//!
//! It is deliberately thin: authentication reuses
//! [`vta_sdk::auth_light::challenge_response_light`] (the challenge-response
//! flow is audience-agnostic — pass the VTC's URL and DID and the server binds
//! `aud` to itself), and the join wire types are re-exported from
//! [`vta_sdk::protocols::join_requests`]. Only the VTC-specific REST shapes
//! (member records, pagination) are defined here.
//!
//! ## Mount path
//!
//! A VTC mounts its API under a configurable base (default `/v1`). Pass the
//! **full** API base to [`VtcClient::connect`] / [`VtcClient::with_token`] —
//! e.g. `https://vtc.example.com/v1` — so both `/auth/*` and `/members` resolve.
//!
//! ## Status
//!
//! First cut: authentication + member listing. Join / removal / policy methods
//! are layered on next (the auth + transport plumbing here is what they build
//! on).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Re-export of the published join-request protocol wire types, so a consumer
/// driving the join ceremony depends on one crate.
pub use vta_sdk::protocols::join_requests;

/// Errors surfaced by the VTC client.
#[derive(Debug, thiserror::Error)]
pub enum VtcError {
    /// A request needed a bearer token but the client has none — call
    /// [`VtcClient::connect`] (or construct via [`VtcClient::with_token`]).
    #[error("not authenticated — call VtcClient::connect first")]
    NotAuthenticated,
    /// The VTC returned a non-success HTTP status.
    #[error("VTC returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
    /// A request URL could not be built.
    #[error("invalid request url: {0}")]
    Url(String),
    /// A transport-level error talking to the VTC.
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    /// Challenge-response authentication failed.
    #[error("authentication failed: {0}")]
    Auth(#[from] vta_sdk::error::VtaError),
}

/// A single member of the community, as returned by `GET /members`. Mirrors the
/// VTC's `MemberResponse` (the fields a fleet/operator typically needs);
/// unrecognised fields in the response are ignored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MemberRecord {
    /// The member's DID (for a fleet, the managed VTA's DID).
    pub did: String,
    /// The member's role on the wire (`"admin"`, `"moderator"`, `"member"`,
    /// `"custom:…"`, …).
    pub role: String,
    #[serde(default)]
    pub label: Option<String>,
    pub joined_at: DateTime<Utc>,
    /// Index of the member's revocation slot in the community status list, when
    /// allocated.
    #[serde(default)]
    pub status_list_index: Option<u32>,
    /// Id of the member's current membership credential (VMC), if issued.
    #[serde(default)]
    pub current_vmc_id: Option<String>,
    #[serde(default)]
    pub personhood: bool,
    #[serde(default)]
    pub joined_via_invitation: bool,
    /// Community-defined extensions (opaque JSON). A fleet manager can stash
    /// per-member operational state here — e.g. a `fleet_index` — at enrollment.
    #[serde(default)]
    pub extensions: serde_json::Value,
}

/// One page of a cursor-paginated VTC listing. Mirrors the server's
/// `Paginated<T>` (`items` + `next_cursor`); `total_estimate` is ignored.
#[derive(Debug, Clone, Deserialize)]
struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<String>,
}

/// A join request in the admin work queue (subset of the VTC's `JoinRequest`).
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestSummary {
    /// The request id (used to approve / reject).
    pub id: String,
    /// The DID applying to join (for a fleet, the VTA being enrolled).
    pub applicant_did: String,
    /// Wire status: `"pending"`, `"approved"`, `"rejected"`, `"withdrawn"`.
    pub status: String,
    pub submitted_at: DateTime<Utc>,
}

/// Outcome of approving or rejecting a join request.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DecideResult {
    pub request_id: String,
    pub status: String,
    /// The issued membership credential (VMC) — present on approve.
    #[serde(default)]
    pub vmc: Option<serde_json::Value>,
    /// The issued role credential (VEC) — present on approve when a role applies.
    #[serde(default)]
    pub role_vec: Option<serde_json::Value>,
}

/// Outcome of removing a member (offboarding). The VTC flips the member's
/// status-list revocation bit as part of removal.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RemoveResult {
    pub did: String,
    /// Wire disposition: `"tombstone"`, `"purge"`, `"historical"`.
    pub disposition: String,
    pub removed: bool,
}

/// A client bound to one VTC's API base, holding a bearer token once
/// authenticated.
#[derive(Debug, Clone)]
pub struct VtcClient {
    http: reqwest::Client,
    /// The VTC API base, including the mount (e.g. `https://vtc.example.com/v1`),
    /// trailing slash trimmed.
    base_url: String,
    /// The VTC's own DID (the authentication audience / DIDComm recipient).
    vtc_did: String,
    /// Bearer access token, set after [`connect`](Self::connect).
    token: Option<String>,
}

impl VtcClient {
    /// Authenticate to the VTC as `client_did` (challenge-response, reusing the
    /// VTA SDK's audience-agnostic flow) and return a ready client.
    ///
    /// `base_url` is the full API base including the mount (e.g.
    /// `https://vtc.example.com/v1`); `vtc_did` is the community's DID.
    pub async fn connect(
        base_url: &str,
        vtc_did: &str,
        client_did: &str,
        private_key_multibase: &str,
    ) -> Result<Self, VtcError> {
        let http = reqwest::Client::new();
        let base_url = base_url.trim_end_matches('/').to_string();
        let auth = vta_sdk::auth_light::challenge_response_light(
            &http,
            &base_url,
            client_did,
            private_key_multibase,
            vtc_did,
        )
        .await?;
        Ok(Self {
            http,
            base_url,
            vtc_did: vtc_did.to_string(),
            token: Some(auth.access_token),
        })
    }

    /// Construct a client from an already-obtained bearer token (e.g. a token
    /// minted out of band, or for testing). `base_url` includes the mount.
    pub fn with_token(base_url: &str, vtc_did: &str, token: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            vtc_did: vtc_did.to_string(),
            token: Some(token.into()),
        }
    }

    /// The community's DID this client is bound to.
    pub fn vtc_did(&self) -> &str {
        &self.vtc_did
    }

    /// List every community member, optionally filtered by `role`, following the
    /// cursor to completion. Requires an admin token. This is the fleet roster
    /// when the community's members are managed VTAs.
    pub async fn list_members(&self, role: Option<&str>) -> Result<Vec<MemberRecord>, VtcError> {
        let token = self.token.as_deref().ok_or(VtcError::NotAuthenticated)?;
        let mut out: Vec<MemberRecord> = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let mut params: Vec<(&str, &str)> = Vec::new();
            if let Some(role) = role {
                params.push(("role", role));
            }
            if let Some(cursor) = &cursor {
                params.push(("cursor", cursor.as_str()));
            }
            let url =
                reqwest::Url::parse_with_params(&format!("{}/members", self.base_url), &params)
                    .map_err(|e| VtcError::Url(e.to_string()))?;

            let resp = self.http.get(url).bearer_auth(token).send().await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Err(VtcError::Http { status, body });
            }

            let page: Page<MemberRecord> = resp.json().await?;
            out.extend(page.items);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        Ok(out)
    }

    /// List join requests (the admin work queue), optionally filtered by
    /// `status` (e.g. `"pending"`). Requires an admin token. For a fleet, these
    /// are VTAs awaiting enrollment.
    pub async fn list_join_requests(
        &self,
        status: Option<&str>,
    ) -> Result<Vec<JoinRequestSummary>, VtcError> {
        let token = self.token()?;
        let mut out: Vec<JoinRequestSummary> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut params: Vec<(&str, &str)> = Vec::new();
            if let Some(status) = status {
                params.push(("status", status));
            }
            if let Some(cursor) = &cursor {
                params.push(("cursor", cursor.as_str()));
            }
            let url = reqwest::Url::parse_with_params(
                &format!("{}/join-requests", self.base_url),
                &params,
            )
            .map_err(|e| VtcError::Url(e.to_string()))?;

            let resp = self.http.get(url).bearer_auth(token).send().await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Err(VtcError::Http { status, body });
            }
            let page: Page<JoinRequestSummary> = resp.json().await?;
            out.extend(page.items);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        Ok(out)
    }

    /// Approve a join request — admit the applicant and issue its membership
    /// credential (VMC). Requires an admin token. For a fleet, this enrolls a
    /// VTA that has applied to join.
    pub async fn approve_join(&self, request_id: &str) -> Result<DecideResult, VtcError> {
        self.decide(request_id, "approve").await
    }

    /// Reject a join request. Requires an admin token.
    pub async fn reject_join(&self, request_id: &str) -> Result<DecideResult, VtcError> {
        self.decide(request_id, "reject").await
    }

    async fn decide(&self, request_id: &str, verb: &str) -> Result<DecideResult, VtcError> {
        let token = self.token()?;
        let url = format!("{}/join-requests/{request_id}/{verb}", self.base_url);
        let resp = self.http.post(url).bearer_auth(token).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtcError::Http { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Remove a member (offboarding). The VTC applies its removal disposition and
    /// flips the member's status-list revocation bit. `reason` is an optional
    /// admin note. Requires an admin token. For a fleet, this decommissions a
    /// managed VTA.
    pub async fn remove_member(
        &self,
        did: &str,
        reason: Option<&str>,
    ) -> Result<RemoveResult, VtcError> {
        let token = self.token()?;
        let url = format!("{}/members/{did}", self.base_url);
        let mut req = self.http.delete(url).bearer_auth(token);
        if let Some(reason) = reason {
            req = req.json(&serde_json::json!({ "reason": reason }));
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtcError::Http { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Submit a join request (the applicant side): POST the VP-framed
    /// `body` to `/join-requests`. The VP's holder-binding proof authenticates
    /// the applicant, so this does not require a bearer token. Returns the
    /// verdict (auto-admit issues the VMC inline; otherwise it's queued).
    pub async fn submit_join(
        &self,
        body: &join_requests::JoinRequestSubmitBody,
    ) -> Result<DecideResult, VtcError> {
        let resp = self
            .http
            .post(format!("{}/join-requests", self.base_url))
            .json(body)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtcError::Http { status, body });
        }
        Ok(resp.json().await?)
    }

    /// List the community's policies (opaque JSON descriptors). Admin token.
    pub async fn list_policies(&self) -> Result<Vec<serde_json::Value>, VtcError> {
        let token = self.token()?;
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut params: Vec<(&str, &str)> = Vec::new();
            if let Some(cursor) = &cursor {
                params.push(("cursor", cursor.as_str()));
            }
            let url =
                reqwest::Url::parse_with_params(&format!("{}/policies", self.base_url), &params)
                    .map_err(|e| VtcError::Url(e.to_string()))?;
            let resp = self.http.get(url).bearer_auth(token).send().await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Err(VtcError::Http { status, body });
            }
            let page: Page<serde_json::Value> = resp.json().await?;
            out.extend(page.items);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        Ok(out)
    }

    /// Fetch one policy by id (opaque JSON, incl. the Rego source). Admin token.
    pub async fn get_policy(&self, id: &str) -> Result<serde_json::Value, VtcError> {
        self.get_json(&format!("policies/{id}")).await
    }

    /// Upload a new Rego policy bundle for `purpose` (`"join"`, `"removal"`,
    /// …). Returns the upload descriptor (id, sha256, version). Admin token.
    /// Upload alone does not activate it — call [`activate_policy`](Self::activate_policy).
    pub async fn upload_policy(
        &self,
        purpose: &str,
        rego_source: &str,
    ) -> Result<serde_json::Value, VtcError> {
        self.post_json(
            "policies",
            &serde_json::json!({ "purpose": purpose, "regoSource": rego_source }),
        )
        .await
    }

    /// Activate a previously-uploaded policy (make it live for decisions of its
    /// purpose). Admin token.
    pub async fn activate_policy(&self, id: &str) -> Result<serde_json::Value, VtcError> {
        self.post_json(&format!("policies/{id}/activate"), &serde_json::json!({}))
            .await
    }

    /// Authenticated GET returning JSON.
    async fn get_json(&self, path: &str) -> Result<serde_json::Value, VtcError> {
        let token = self.token()?;
        let resp = self
            .http
            .get(format!("{}/{path}", self.base_url))
            .bearer_auth(token)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtcError::Http { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Authenticated POST of a JSON body returning JSON.
    async fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, VtcError> {
        let token = self.token()?;
        let resp = self
            .http
            .post(format!("{}/{path}", self.base_url))
            .bearer_auth(token)
            .json(body)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtcError::Http { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Bearer token or [`VtcError::NotAuthenticated`].
    fn token(&self) -> Result<&str, VtcError> {
        self.token.as_deref().ok_or(VtcError::NotAuthenticated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_page_deserializes_from_vtc_shape() {
        // A `Paginated<MemberResponse>` as the VTC serialises it (extra fields
        // present to prove they're ignored).
        let json = serde_json::json!({
            "items": [{
                "did": "did:key:z6MkStaffVta",
                "role": "member",
                "label": "Staff VTA",
                "joinedAt": "2026-06-23T00:00:00Z",
                "publishConsent": true,
                "departurePreference": "tombstone",
                "statusListIndex": 7,
                "currentVmcId": "urn:uuid:vmc-1",
                "extensions": {},
                "personhood": false,
                "joinedViaInvitation": true
            }],
            "next_cursor": null
        });
        let page: Page<MemberRecord> = serde_json::from_value(json).unwrap();
        assert_eq!(page.items.len(), 1);
        let m = &page.items[0];
        assert_eq!(m.did, "did:key:z6MkStaffVta");
        assert_eq!(m.role, "member");
        assert_eq!(m.status_list_index, Some(7));
        assert_eq!(m.current_vmc_id.as_deref(), Some("urn:uuid:vmc-1"));
        assert!(m.joined_via_invitation);
        assert!(page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn list_members_without_token_is_not_authenticated() {
        let client = VtcClient {
            http: reqwest::Client::new(),
            base_url: "https://vtc.example.com/v1".into(),
            vtc_did: "did:web:vtc.example.com".into(),
            token: None,
        };
        // The token guard returns before any network I/O.
        let err = client.list_members(None).await;
        assert!(matches!(err, Err(VtcError::NotAuthenticated)), "{err:?}");
    }

    #[test]
    fn decide_result_deserializes_camel_case() {
        let json = serde_json::json!({
            "requestId": "11111111-1111-1111-1111-111111111111",
            "status": "approved",
            "vmc": { "type": ["VerifiableCredential", "MembershipCredential"] },
            "roleVec": null
        });
        let d: DecideResult = serde_json::from_value(json).unwrap();
        assert_eq!(d.request_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(d.status, "approved");
        assert!(d.vmc.is_some());
        assert!(d.role_vec.is_none());
    }

    #[test]
    fn join_request_and_remove_results_deserialize() {
        let jr: JoinRequestSummary = serde_json::from_value(serde_json::json!({
            "id": "22222222-2222-2222-2222-222222222222",
            "applicantDid": "did:key:z6MkApplicant",
            "status": "pending",
            "submittedAt": "2026-06-23T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(jr.applicant_did, "did:key:z6MkApplicant");
        assert_eq!(jr.status, "pending");

        let rm: RemoveResult = serde_json::from_value(serde_json::json!({
            "did": "did:key:z6MkGone",
            "disposition": "tombstone",
            "removed": true
        }))
        .unwrap();
        assert_eq!(rm.did, "did:key:z6MkGone");
        assert!(rm.removed);
    }

    #[tokio::test]
    async fn admin_methods_without_token_are_not_authenticated() {
        let client = VtcClient {
            http: reqwest::Client::new(),
            base_url: "https://vtc.example.com/v1".into(),
            vtc_did: "did:web:vtc.example.com".into(),
            token: None,
        };
        assert!(matches!(
            client.list_join_requests(Some("pending")).await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.approve_join("req-1").await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.remove_member("did:key:x", Some("reason")).await,
            Err(VtcError::NotAuthenticated)
        ));
    }

    #[test]
    fn member_extensions_default_and_parse() {
        let none: MemberRecord = serde_json::from_value(serde_json::json!({
            "did": "did:key:z", "role": "member", "joinedAt": "2026-06-23T00:00:00Z"
        }))
        .unwrap();
        assert!(none.extensions.is_null());
        let with: MemberRecord = serde_json::from_value(serde_json::json!({
            "did": "did:key:z", "role": "member", "joinedAt": "2026-06-23T00:00:00Z",
            "extensions": { "fleet_index": 3 }
        }))
        .unwrap();
        assert_eq!(with.extensions["fleet_index"], 3);
    }

    #[tokio::test]
    async fn policy_admin_methods_without_token_are_not_authenticated() {
        let client = VtcClient {
            http: reqwest::Client::new(),
            base_url: "https://vtc.example.com/v1".into(),
            vtc_did: "did:web:vtc.example.com".into(),
            token: None,
        };
        assert!(matches!(
            client.list_policies().await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.get_policy("p1").await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.upload_policy("join", "package x").await,
            Err(VtcError::NotAuthenticated)
        ));
        assert!(matches!(
            client.activate_policy("p1").await,
            Err(VtcError::NotAuthenticated)
        ));
    }
}
