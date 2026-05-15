use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::didcomm::message::pack;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tracing::{debug, info};

use crate::error::AppError;

const WEBVH_AUTHENTICATE_TYPE: &str = "https://affinidi.com/webvh/1.0/authenticate";

pub struct WebvhClient {
    http: reqwest::Client,
    server_url: String,
    access_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestUriResponse {
    #[serde(alias = "did_url")]
    pub did_url: String,
    pub mnemonic: String,
}

#[derive(Debug, Deserialize)]
pub struct CheckPathResponse {
    pub available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebvhAuthState {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    #[serde(alias = "session_id")]
    session_id: String,
    data: ChallengeData,
}

#[derive(Debug, Deserialize)]
struct ChallengeData {
    challenge: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticateResponse {
    data: AuthenticateData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticateData {
    access_token: String,
    access_expires_at: u64,
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefreshResponse {
    data: RefreshData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefreshData {
    access_token: String,
    access_expires_at: u64,
}

impl WebvhClient {
    pub fn new(server_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            server_url: server_url.trim_end_matches('/').to_string(),
            access_token: None,
        }
    }

    pub fn set_access_token(&mut self, token: String) {
        self.access_token = Some(token);
    }

    /// Authenticate to the WebVH REST API using the VTA's signing DID.
    ///
    /// The WebVH control plane expects a DIDComm-signed `authenticate`
    /// message over HTTP (`POST /api/auth/`) after an unauthenticated
    /// challenge request (`POST /api/auth/challenge`).
    pub async fn authenticate(
        &self,
        did: &str,
        secret: &Secret,
        webvh_did: &str,
    ) -> Result<WebvhAuthState, AppError> {
        let private_key_bytes: [u8; 32] = secret
            .get_private_bytes()
            .try_into()
            .map_err(|_| AppError::Internal("webvh auth signing key must be 32 bytes".into()))?;

        let challenge_url = format!("{}/api/auth/challenge", self.server_url);
        info!(method = "POST", %challenge_url, did = %did, "webvh: requesting rest auth challenge");
        let challenge_req = self.http.post(&challenge_url).json(&serde_json::json!({
            "did": did,
        }));
        let challenge_resp: ChallengeResponse = self
            .parse_json(
                self.send(challenge_req, "POST /api/auth/challenge").await?,
                "POST /api/auth/challenge",
            )
            .await?;

        let created_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let msg = Message::build(
            uuid::Uuid::new_v4().to_string(),
            WEBVH_AUTHENTICATE_TYPE.to_string(),
            serde_json::json!({
                "challenge": challenge_resp.data.challenge,
                "session_id": challenge_resp.session_id,
            }),
        )
        .from(did.to_string())
        .to(webvh_did.to_string())
        .created_time(created_time)
        .finalize();

        let packed = pack::pack_signed(&msg, &secret.id, &private_key_bytes)
            .map_err(|e| AppError::Internal(format!("webvh auth pack_signed failed: {e}")))?;

        let auth_url = format!("{}/api/auth/", self.server_url);
        info!(method = "POST", %auth_url, did = %did, target = %webvh_did, "webvh: submitting rest auth response");
        let auth_req = self
            .http
            .post(&auth_url)
            .header("Content-Type", "text/plain")
            .body(packed);
        let auth_resp: AuthenticateResponse = self
            .parse_json(
                self.send(auth_req, "POST /api/auth/").await?,
                "POST /api/auth/",
            )
            .await?;

        debug!(did = %did, target = %webvh_did, "webvh: rest auth succeeded");
        Ok(WebvhAuthState {
            access_token: auth_resp.data.access_token,
            access_expires_at: auth_resp.data.access_expires_at,
            refresh_token: Some(auth_resp.data.refresh_token),
        })
    }

    /// Refresh the access token for an existing WebVH REST session.
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> Result<WebvhAuthState, AppError> {
        let refresh_url = format!("{}/api/auth/refresh", self.server_url);
        info!(method = "POST", %refresh_url, "webvh: refreshing rest access token");
        let refresh_req = self
            .http
            .post(&refresh_url)
            .header("Content-Type", "text/plain")
            .body(refresh_token.to_string());
        let refresh_resp: RefreshResponse = self
            .parse_json(
                self.send(refresh_req, "POST /api/auth/refresh").await?,
                "POST /api/auth/refresh",
            )
            .await?;

        debug!("webvh: rest token refresh succeeded");
        Ok(WebvhAuthState {
            access_token: refresh_resp.data.access_token,
            access_expires_at: refresh_resp.data.access_expires_at,
            refresh_token: Some(refresh_token.to_string()),
        })
    }

    /// Apply authorization header (if set) to a request builder.
    fn with_auth(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref token) = self.access_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        req
    }

    /// Send a request and check for success. Returns an error with context on failure.
    async fn send(
        &self,
        req: reqwest::RequestBuilder,
        context: &str,
    ) -> Result<reqwest::Response, AppError> {
        let resp = req
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "webvh-server {context} failed ({status}): {text}"
            )));
        }
        Ok(resp)
    }

    async fn parse_json<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
        context: &str,
    ) -> Result<T, AppError> {
        resp.json().await.map_err(|e| {
            AppError::Internal(format!("webvh-server {context} response parse error: {e}"))
        })
    }

    /// POST /api/dids — allocate URI (optional path).
    pub async fn request_uri(&self, path: Option<&str>) -> Result<RequestUriResponse, AppError> {
        let url = format!("{}/api/dids", self.server_url);
        info!(method = "POST", %url, "webvh: sending via rest");
        let body = match path {
            Some(p) => serde_json::json!({ "path": p }),
            None => serde_json::json!({}),
        };
        let req = self.with_auth(self.http.post(&url)).json(&body);
        let resp = self.send(req, "POST /api/dids").await?;
        debug!(method = "POST", status = 200, "webvh: received via rest");
        self.parse_json(resp, "POST /api/dids").await
    }

    /// POST /api/dids/register — atomic claim-and-publish.
    ///
    /// Single round-trip equivalent to `request_uri(path)` +
    /// `publish_did(mnemonic, log_content)` but committed in one fjall
    /// batch on the server, so resolvers never see the slot empty
    /// between allocation and content upload. The relevant flow for
    /// promoting an existing serverless DID to a host without a
    /// resolvability gap.
    ///
    /// `force` is honoured only when the caller is an admin replacing a
    /// slot owned by a different DID. The owner re-registering their
    /// own slot is idempotent and needs no force.
    pub async fn register_did_atomic(
        &self,
        path: &str,
        did_log: &str,
        force: bool,
    ) -> Result<RequestUriResponse, AppError> {
        let url = format!("{}/api/dids/register", self.server_url);
        info!(method = "POST", %url, "webvh: sending via rest");
        let req = self
            .with_auth(self.http.post(&url))
            .json(&serde_json::json!({
                "path": path,
                "did_log": did_log,
                "force": force,
            }));
        let resp = self.send(req, "POST /api/dids/register").await?;
        debug!(method = "POST", status = 200, "webvh: received via rest");
        self.parse_json(resp, "POST /api/dids/register").await
    }

    /// PUT /api/dids/{mnemonic} — publish DID log.
    pub async fn publish_did(&self, mnemonic: &str, log_content: &str) -> Result<(), AppError> {
        let url = format!("{}/api/dids/{mnemonic}", self.server_url);
        info!(method = "PUT", %url, "webvh: sending via rest");
        let req = self
            .with_auth(self.http.put(&url))
            .header("Content-Type", "application/jsonl")
            .body(log_content.to_string());
        self.send(req, &format!("PUT /api/dids/{mnemonic}")).await?;
        debug!(method = "PUT", status = 200, "webvh: received via rest");
        Ok(())
    }

    /// DELETE /api/dids/{mnemonic}.
    pub async fn delete_did(&self, mnemonic: &str) -> Result<(), AppError> {
        let url = format!("{}/api/dids/{mnemonic}", self.server_url);
        info!(method = "DELETE", %url, "webvh: sending via rest");
        let req = self.with_auth(self.http.delete(&url));
        self.send(req, &format!("DELETE /api/dids/{mnemonic}"))
            .await?;
        debug!(method = "DELETE", status = 200, "webvh: received via rest");
        Ok(())
    }

    /// POST /api/dids/check — check if a path is available.
    pub async fn check_path(&self, path: &str) -> Result<CheckPathResponse, AppError> {
        let url = format!("{}/api/dids/check", self.server_url);
        let req = self
            .with_auth(self.http.post(&url))
            .json(&serde_json::json!({ "path": path }));
        let resp = self.send(req, "POST /api/dids/check").await?;
        self.parse_json(resp, "POST /api/dids/check").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_response_accepts_webvh_daemon_camel_case() {
        let json = r#"{"sessionId":"sess-123","data":{"challenge":"nonce123"}}"#;
        let resp: ChallengeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.session_id, "sess-123");
        assert_eq!(resp.data.challenge, "nonce123");
    }

    #[test]
    fn challenge_response_still_accepts_snake_case() {
        let json = r#"{"session_id":"sess-123","data":{"challenge":"nonce123"}}"#;
        let resp: ChallengeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.session_id, "sess-123");
        assert_eq!(resp.data.challenge, "nonce123");
    }

    #[test]
    fn request_uri_response_accepts_webvh_daemon_camel_case() {
        let json = r#"{"mnemonic":"services-tgw","didUrl":"http://localhost:8530/services/tgw/did.jsonl"}"#;
        let resp: RequestUriResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.mnemonic, "services-tgw");
        assert_eq!(resp.did_url, "http://localhost:8530/services/tgw/did.jsonl");
    }

    #[test]
    fn request_uri_response_still_accepts_snake_case() {
        let json = r#"{"mnemonic":"services-tgw","did_url":"http://localhost:8530/services/tgw/did.jsonl"}"#;
        let resp: RequestUriResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.mnemonic, "services-tgw");
        assert_eq!(resp.did_url, "http://localhost:8530/services/tgw/did.jsonl");
    }
}
