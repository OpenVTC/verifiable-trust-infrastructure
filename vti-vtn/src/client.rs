use std::time::Duration;

use crate::identity::Identity;
use crate::verify::AUTHENTICATION;
use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The network answered with an error status.
    #[error("{status}: {message}")]
    Http { status: u16, message: String },
    /// The network could not be reached, or answered with something unreadable.
    #[error("transport: {0}")]
    Transport(String),
    /// The network answered, but not as the network the caller expected.
    #[error("{0}")]
    Unexpected(String),
}

impl ClientError {
    pub fn status(&self) -> Option<u16> {
        match self {
            ClientError::Http { status, .. } => Some(*status),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// An HTTP client for one network.
#[derive(Clone)]
pub struct VtnClient {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

impl VtnClient {
    pub fn new(base: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("HTTP client");
        Self::with_http(http, base)
    }

    pub fn with_http(http: reqwest::Client, base: &str) -> Self {
        Self {
            http,
            base: base.trim_end_matches('/').to_string(),
            token: None,
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// The session token, once signed in.
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// The network's public profile (`/.well-known/vtn`).
    pub async fn profile(&self) -> Result<Value> {
        self.get("/.well-known/vtn").await
    }

    /// The network's DID, from its profile.
    pub async fn network_did(&self) -> Result<String> {
        self.profile()
            .await?
            .get("did")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| ClientError::Unexpected(format!("{} names no DID", self.base)))
    }

    /// Sign in to the network `network_did` as `who`, optionally presenting a membership
    /// credential. The signed document names `network_did` as its audience, never what the
    /// server claims, so a sign-in cannot be relayed to another network. Returns the
    /// session grant.
    pub async fn sign_in(
        &mut self,
        who: &Identity,
        network_did: &str,
        membership: Option<Value>,
    ) -> Result<Value> {
        self.sign_in_as(who, network_did, membership).await
    }

    /// [`Self::sign_in`] for any [`crate::identity::Party`].
    pub async fn sign_in_as(
        &mut self,
        who: &dyn crate::identity::Party,
        network_did: &str,
        membership: Option<Value>,
    ) -> Result<Value> {
        let challenge = self
            .post("/v1/auth/challenge", &json!({ "did": who.did() }))
            .await?;
        if challenge["audience"].as_str() != Some(network_did) {
            return Err(ClientError::Unexpected(format!(
                "the challenge is for {}, not {network_did}",
                challenge["audience"]
            )));
        }
        let document = json!({
            "type": "VtnAdminAuthentication",
            "did": who.did(),
            "challenge": challenge["challenge"],
            "audience": network_did,
        });
        let document = who
            .sign_for(document, AUTHENTICATION)
            .await
            .map_err(|e| ClientError::Unexpected(format!("sign the authentication: {e}")))?;
        let mut body = json!({ "authentication": document });
        if let Some(m) = membership {
            body["membership"] = m;
        }
        let grant = self.post("/v1/auth/session", &body).await?;
        self.token = Some(
            grant["token"]
                .as_str()
                .ok_or_else(|| ClientError::Unexpected("no session token".into()))?
                .to_string(),
        );
        Ok(grant)
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        self.send(self.http.get(self.url(path))).await
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.send(self.http.post(self.url(path)).json(body)).await
    }

    /// POST to an absolute URL (a relay endpoint), with this client's session if any.
    pub async fn post_url(&self, url: &str, body: &Value) -> Result<Value> {
        self.send(self.http.post(url).json(body)).await
    }

    /// GET an absolute URL (a status list), with no session.
    pub async fn get_url(&self, url: &str) -> Result<Value> {
        let res = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        Self::read(res).await
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn send(&self, mut req: reqwest::RequestBuilder) -> Result<Value> {
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let res = req
            .send()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        Self::read(res).await
    }

    async fn read(res: reqwest::Response) -> Result<Value> {
        let status = res.status();
        let body: Value = res.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            return Err(ClientError::Http {
                status: status.as_u16(),
                message: body["message"].as_str().unwrap_or("no message").to_string(),
            });
        }
        Ok(body)
    }
}

fn encode(value: &str, keep: impl Fn(u8) -> bool) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') || keep(b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Percent-encode a DID for a path segment (DIDs carry `:` and may carry `%`).
pub fn encode_did(did: &str) -> String {
    encode(did, |b| b == b':')
}

/// Percent-encode a query-string value.
pub fn encode_query(value: &str) -> String {
    encode(value, |_| false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_dids_and_queries() {
        assert_eq!(
            encode_did("did:webvh:Qm%41:x.org"),
            "did:webvh:Qm%2541:x.org"
        );
        assert_eq!(encode_query("new zealand&x"), "new%20zealand%26x");
    }
}
