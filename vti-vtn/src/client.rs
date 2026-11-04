use std::time::Duration;

use serde_json::Value;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    /// The network refused a Trust Task: its `trust-task-error` code (`notFound`,
    /// `vtn/membership/acknowledge:rolesUnregistered`, ...), message and details.
    #[error("{code}: {message}")]
    Refused {
        status: u16,
        code: String,
        message: String,
        details: Option<serde_json::Value>,
    },
}

impl ClientError {
    pub fn status(&self) -> Option<u16> {
        match self {
            ClientError::Http { status, .. } | ClientError::Refused { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The `trust-task-error` code of a refusal, if this is one.
    pub fn code(&self) -> Option<&str> {
        match self {
            ClientError::Refused { code, .. } => Some(code),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// An HTTP client for one network: its profile and fetched artifacts, and (`crate::tasks`)
/// its `vtn/*` Trust Tasks.
#[derive(Clone)]
pub struct VtnClient {
    http: reqwest::Client,
    base: String,
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
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// The HTTP client requests go out on.
    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
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

    pub async fn get(&self, path: &str) -> Result<Value> {
        self.send(self.http.get(self.url(path))).await
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.send(self.http.post(self.url(path)).json(body)).await
    }

    /// POST to an absolute URL (a community's relay endpoint).
    pub async fn post_url(&self, url: &str, body: &Value) -> Result<Value> {
        self.send(self.http.post(url).json(body)).await
    }

    /// GET an absolute URL (a status list).
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

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<Value> {
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
