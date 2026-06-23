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
}

/// One page of a cursor-paginated VTC listing. Mirrors the server's
/// `Paginated<T>` (`items` + `next_cursor`); `total_estimate` is ignored.
#[derive(Debug, Clone, Deserialize)]
struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<String>,
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
}
