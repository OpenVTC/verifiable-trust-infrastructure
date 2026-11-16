//! Wallet sign-in, from the starter's side: the `auth/oob/*` family as the
//! member portal and the operator console drive it, for a client that holds
//! its own key and wants a person's standing.
//!
//! The starter holds an Ed25519 key `K_b` — this client's own signer — and
//! opens a request. A wallet claims it, proves who it is and the number the
//! starter shows, and returns a grant signed by the person's DID naming
//! `K_b`. Only `K_b`'s holder can redeem it (`design-docs/vtc-qr-login-design.md`,
//! `vti-oob-server`). What `redeem` yields depends on the audience the
//! request asked for:
//!
//! - **`member`**: a member-portal session, and a delegation armed for `K_b`
//!   so that documents it signs in the portal's task families are read as
//!   the member's while the session lives.
//! - **`admin`**: an operator-console session bound to `K_b`, so
//!   `auth/whoami` answers for it. Signed administrative documents still need
//!   a signing-key delegation of the administrator's DID.
//!
//! Two things the service checks that a non-browser starter has to get right:
//! the request is accepted only over the HTTPS door, never a messaging
//! session; and only from the community's own portal origin (T19), which
//! the wallet shows the approver together with the starter's user agent. So
//! these calls always post to the HTTPS door, present the portal origin, and
//! identify the starter by name.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{MAX_DOCUMENT_RESPONSE_BYTES, VtcClient, VtcError};

/// The `ext` namespace that names the audience on `auth/oob/request`.
pub const SESSION_EXT: &str = "org.openvtc.session";

/// The Trust Task URIs this module sends.
pub mod task {
    pub const REQUEST: &str = "https://trusttasks.org/spec/auth/oob/request/0.2";
    pub const REDEEM: &str = "https://trusttasks.org/spec/auth/oob/redeem/0.2";
    pub const CANCEL: &str = "https://trusttasks.org/spec/auth/oob/cancel/0.1";
}

/// Which session a sign-in asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInAudience {
    /// The member portal: a member's standing, with `K_b` delegated for the
    /// portal's task families.
    Member,
    /// The operator console: an administrator's session.
    Admin,
}

impl SignInAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "member" => Some(Self::Member),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    /// The audience an `ext` names; `member` when it names none.
    fn of_ext(ext: Option<&Value>) -> Self {
        match ext
            .and_then(|e| e.get(SESSION_EXT))
            .and_then(|ns| ns.get("audience"))
            .and_then(Value::as_str)
        {
            Some("admin") => Self::Admin,
            _ => Self::Member,
        }
    }
}

/// What the community's portal publishes for a starter to build the trigger
/// link (`GET /v1/member/sign-in/config`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SignInConfig {
    /// The community's DID (`_from`).
    pub vtc_did: String,
    /// The link host (`https://<linkHost>/t#…`).
    pub link_host: String,
    /// The flow (`_type`).
    pub flow: String,
    /// Whether the community's DID document lists what a wallet needs
    /// (`ok`, `missing`, `unknown`), as the portal reports it.
    #[serde(default)]
    pub did_document: Value,
}

/// An open sign-in request.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignInRequest {
    pub request_id: String,
    pub audience: SignInAudience,
    /// When the claim window closes, RFC 3339.
    pub claim_closes_at: String,
    /// The trigger link the wallet opens or scans.
    pub trigger_link: String,
}

/// A completed sign-in.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignedIn {
    /// The person's DID.
    pub subject: String,
    pub display_name: Option<String>,
    /// RFC 3339.
    pub session_ends_at: Option<String>,
    pub amr: Vec<String>,
    pub audience: SignInAudience,
}

/// One `redeem` poll's answer.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SignInPoll {
    /// Not approved yet. `state` is `pending`, `claimed`, `identified` or
    /// `approved`; once a wallet has claimed the request, `match_number` is
    /// the number the person compares with the one their wallet shows.
    Pending {
        state: String,
        match_number: Option<String>,
    },
    /// Approved and redeemed.
    SignedIn(SignedIn),
    /// Declined by the wallet, cancelled, or refused by the community;
    /// `reason` when the starter is told why.
    Declined { reason: Option<String> },
    /// The claim window closed with no approval.
    Expired,
}

/// Percent-encode `&`, `=`, `#` and `%`, and nothing else (contract C1).
pub(crate) fn encode_from(did: &str) -> String {
    let mut out = String::with_capacity(did.len());
    for c in did.chars() {
        match c {
            '&' | '=' | '#' | '%' => out.push_str(&format!("%{:02X}", c as u32)),
            other => out.push(other),
        }
    }
    out
}

/// The trigger link (contract C1): ASCII, at most 251 bytes.
pub fn trigger_link(
    cfg: &SignInConfig,
    request_id: &str,
    claim_deadline_epoch: i64,
) -> Result<String, VtcError> {
    let link = format!(
        "https://{}/t#_from={}&_id={request_id}&_exp={claim_deadline_epoch}&_type={}",
        cfg.link_host,
        encode_from(&cfg.vtc_did),
        cfg.flow
    );
    if !link.is_ascii() || link.len() > 251 {
        return Err(VtcError::SignIn {
            code: "linkTooLong".into(),
            message: "this community's sign-in link is too long to show as a code".into(),
            details: Value::Null,
        });
    }
    Ok(link)
}

/// An RFC 3339 instant as epoch seconds.
fn epoch_of(v: &Value) -> Option<i64> {
    v.as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.timestamp())
}

/// The local part of a refusal code: `auth/oob/redeem:pending` → `pending`.
fn local_code(code: &str) -> &str {
    code.rsplit(':').next().unwrap_or(code)
}

impl VtcClient {
    /// The origin a browser on the community's portal would send: the
    /// scheme and authority of this client's HTTPS base.
    fn portal_origin(&self) -> Result<String, VtcError> {
        if self.base_url.is_empty() {
            return Err(VtcError::NoRestTransport("wallet sign-in"));
        }
        let parsed = url::Url::parse(&self.base_url).map_err(|e| VtcError::Url(e.to_string()))?;
        Ok(parsed.origin().ascii_serialization())
    }

    /// Read what the portal publishes for a starter: the link host and flow
    /// the trigger link is made of. Refused when the portal names a
    /// community other than this client's.
    pub async fn sign_in_config(&self) -> Result<SignInConfig, VtcError> {
        if self.base_url.is_empty() {
            return Err(VtcError::NoRestTransport("wallet sign-in"));
        }
        let resp = self
            .http
            .get(format!("{}/member/sign-in/config", self.base_url))
            .send()
            .await?;
        let status = resp.status().as_u16();
        let bytes = vta_sdk::http::read_body_capped(resp, MAX_DOCUMENT_RESPONSE_BYTES)
            .await
            .map_err(|e| VtcError::Http {
                status,
                body: e.to_string(),
            })?;
        if !(200..300).contains(&status) {
            return Err(VtcError::Http {
                status,
                body: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        let cfg: SignInConfig = serde_json::from_slice(&bytes).map_err(|e| VtcError::Http {
            status,
            body: format!("sign-in config has an unexpected shape: {e}"),
        })?;
        if cfg.vtc_did != self.vtc_did {
            return Err(VtcError::SignIn {
                code: "wrongCommunity".into(),
                message: format!(
                    "the portal at {} names {} and this client is bound to {}",
                    self.base_url, cfg.vtc_did, self.vtc_did
                ),
                details: Value::Null,
            });
        }
        Ok(cfg)
    }

    /// Post one `auth/oob/*` document signed by this client's key over the
    /// HTTPS door, as the community's portal would, and classify the answer.
    async fn oob_post(
        &self,
        type_uri: &str,
        payload: Value,
        starter: &str,
    ) -> Result<Result<Value, (String, String, Value)>, VtcError> {
        let Some(key) = &self.signer else {
            return Err(VtcError::NotAuthenticated);
        };
        let origin = self.portal_origin()?;
        let doc =
            vta_sdk::trust_task_sign::build_signed_with(type_uri, payload, key, &self.vtc_did)
                .await
                .map_err(|e| VtcError::Signing(e.to_string()))?;
        let resp = self
            .http
            .post(format!("{}/trust-tasks", self.base_url))
            .header("content-type", "application/json")
            .header("origin", origin)
            .header("user-agent", starter)
            .body(doc)
            .send()
            .await?;
        let status = resp.status().as_u16();
        let bytes = vta_sdk::http::read_body_capped(resp, MAX_DOCUMENT_RESPONSE_BYTES)
            .await
            .map_err(|e| VtcError::Http {
                status,
                body: e.to_string(),
            })?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let body: Value = serde_json::from_str(&text).map_err(|_| VtcError::Http {
            status,
            body: text.clone(),
        })?;
        let is_error = body["type"]
            .as_str()
            .is_some_and(|t| t.contains("/trust-task-error/"));
        if (200..300).contains(&status) && !is_error {
            return Ok(Ok(body["payload"].clone()));
        }
        let payload = &body["payload"];
        let code = payload["code"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("http{status}"));
        let message = payload["message"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("the community refused the sign-in (HTTP {status})"));
        Ok(Err((code, message, payload["details"].clone())))
    }

    /// Open a sign-in request as this client's key, for `audience`, and
    /// return the trigger link the wallet opens or scans.
    ///
    /// `starter` names this client to the approver (the wallet shows the
    /// starter's user agent beside the request), e.g. `vtc-mcp/0.1.0`.
    ///
    /// # Errors
    ///
    /// [`VtcError::NotAuthenticated`] without a key; [`VtcError::NoRestTransport`]
    /// without an HTTPS base; [`VtcError::SignIn`] for a refusal, with the
    /// community's code — `purposeUnsupported`, a wrong origin, too many open
    /// requests — and for a community that did not echo the audience asked for
    /// (one that predates console sign-in would open a member request
    /// instead).
    pub async fn sign_in_request(
        &self,
        audience: SignInAudience,
        starter: &str,
    ) -> Result<SignInRequest, VtcError> {
        let cfg = self.sign_in_config().await?;
        let mut payload = json!({ "purpose": "login", "mode": "scan" });
        if audience == SignInAudience::Admin {
            payload["ext"] = json!({ SESSION_EXT: { "audience": "admin" } });
        }
        let answer = match self.oob_post(task::REQUEST, payload, starter).await? {
            Ok(p) => p,
            Err((code, message, details)) => {
                return Err(VtcError::SignIn {
                    code,
                    message,
                    details,
                });
            }
        };
        if SignInAudience::of_ext(answer.get("ext")) != audience {
            return Err(VtcError::SignIn {
                code: "audienceNotServed".into(),
                message: "this community does not offer wallet sign-in to the operator console"
                    .into(),
                details: Value::Null,
            });
        }
        let request_id = answer["requestId"]
            .as_str()
            .filter(|id| {
                id.len() == 22
                    && id
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            })
            .ok_or_else(|| VtcError::SignIn {
                code: "unexpectedShape".into(),
                message:
                    "the community answered the sign-in request in a shape this client cannot read"
                        .into(),
                details: answer.clone(),
            })?
            .to_string();
        let claim_closes_at = answer["claimClosesAt"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_default();
        let deadline = epoch_of(&answer["claimClosesAt"]).ok_or_else(|| VtcError::SignIn {
            code: "unexpectedShape".into(),
            message: "the community's claimClosesAt is not an RFC 3339 instant".into(),
            details: answer.clone(),
        })?;
        let trigger_link = trigger_link(&cfg, &request_id, deadline)?;
        Ok(SignInRequest {
            request_id,
            audience,
            claim_closes_at,
            trigger_link,
        })
    }

    /// One `redeem` poll: the community holds it for a while and answers with
    /// where the request stands, or the session once approved.
    pub async fn sign_in_redeem(
        &self,
        request_id: &str,
        starter: &str,
    ) -> Result<SignInPoll, VtcError> {
        match self
            .oob_post(task::REDEEM, json!({ "requestId": request_id }), starter)
            .await?
        {
            Ok(p) => Ok(SignInPoll::SignedIn(SignedIn {
                subject: p["subject"].as_str().unwrap_or_default().to_string(),
                display_name: p["displayName"].as_str().map(str::to_string),
                session_ends_at: p["sessionEndsAt"].as_str().map(str::to_string),
                amr: p["amr"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default(),
                audience: SignInAudience::of_ext(p.get("ext")),
            })),
            Err((code, message, details)) => match local_code(&code) {
                "pending" => Ok(SignInPoll::Pending {
                    state: details["state"].as_str().unwrap_or("pending").to_string(),
                    match_number: details["matchNumber"].as_str().map(str::to_string),
                }),
                "declined" => Ok(SignInPoll::Declined {
                    reason: details["reason"].as_str().map(str::to_string),
                }),
                "requestExpired" | "expired" => Ok(SignInPoll::Expired),
                _ => Err(VtcError::SignIn {
                    code,
                    message,
                    details,
                }),
            },
        }
    }

    /// Cancel an open request, by the starter. Best effort: the request ends
    /// on its own clock either way.
    pub async fn sign_in_cancel(&self, request_id: &str, starter: &str) -> Result<(), VtcError> {
        match self
            .oob_post(task::CANCEL, json!({ "requestId": request_id }), starter)
            .await?
        {
            Ok(_) => Ok(()),
            Err((code, message, details)) => Err(VtcError::SignIn {
                code,
                message,
                details,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_trigger_link_is_the_portals() {
        let cfg = SignInConfig {
            vtc_did: "did:webvh:Qm1:vtc.example.com:first".into(),
            link_host: "link.trustoverip.org".into(),
            flow: "vtc-sign-in".into(),
            did_document: Value::Null,
        };
        let link = trigger_link(&cfg, "AAAAAAAAAAAAAAAAAAAAAA", 1_900_000_000).unwrap();
        assert_eq!(
            link,
            "https://link.trustoverip.org/t#_from=did:webvh:Qm1:vtc.example.com:first\
             &_id=AAAAAAAAAAAAAAAAAAAAAA&_exp=1900000000&_type=vtc-sign-in"
        );
        // Only the four reserved characters are encoded.
        assert_eq!(encode_from("did:x:a&b=c#d%e"), "did:x:a%26b%3Dc%23d%25e");
        let long = SignInConfig {
            link_host: "x".repeat(240),
            ..cfg
        };
        assert!(matches!(
            trigger_link(&long, "AAAAAAAAAAAAAAAAAAAAAA", 1),
            Err(VtcError::SignIn { ref code, .. }) if code == "linkTooLong"
        ));
    }

    #[test]
    fn audiences_and_codes_read_as_the_portal_reads_them() {
        assert_eq!(SignInAudience::of_ext(None), SignInAudience::Member);
        assert_eq!(
            SignInAudience::of_ext(Some(&json!({ SESSION_EXT: { "audience": "admin" } }))),
            SignInAudience::Admin
        );
        assert_eq!(
            SignInAudience::of_ext(Some(&json!({ SESSION_EXT: { "audience": "root" } }))),
            SignInAudience::Member
        );
        assert_eq!(local_code("auth/oob/redeem:pending"), "pending");
        assert_eq!(local_code("http403"), "http403");
        assert_eq!(
            epoch_of(&json!("2030-03-17T17:46:40Z")),
            Some(1_900_000_000)
        );
        assert_eq!(epoch_of(&json!(1_900_000_800)), None);
    }
}
