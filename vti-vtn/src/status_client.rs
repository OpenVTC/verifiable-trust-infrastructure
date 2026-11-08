//! Checking a credential's status against its issuer's Bitstring Status Lists.

use std::collections::HashMap;
use std::sync::Arc;

use crate::status::Bitstring;
use crate::verify::{ASSERTION_METHOD, KeyResolver, verify_document};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::client::{ClientError, VtnClient};

/// What the status lists say about a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialState {
    Valid,
    Suspended,
    Revoked,
}

/// Default time a fetched status list is trusted before refetching. A revocation can take
/// this long to be seen here.
pub const DEFAULT_CACHE_TTL: Duration = Duration::minutes(5);

/// Resolves `credentialStatus`. Clone-cheap; the cache is shared.
#[derive(Clone)]
pub struct StatusChecker {
    client: VtnClient,
    resolver: Arc<dyn KeyResolver>,
    cache: Arc<Mutex<HashMap<String, (DateTime<Utc>, String, Bitstring)>>>,
    ttl: Duration,
}

impl StatusChecker {
    pub fn new(resolver: Arc<dyn KeyResolver>) -> Self {
        Self::with_client(VtnClient::new(""), resolver)
    }

    pub fn with_client(client: VtnClient, resolver: Arc<dyn KeyResolver>) -> Self {
        Self {
            client,
            resolver,
            cache: Arc::default(),
            ttl: DEFAULT_CACHE_TTL,
        }
    }

    /// How long a fetched list is trusted. Zero refetches every time.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// The state of `credential`. A credential with no `credentialStatus` is `Valid`: its
    /// validity window is its control. An entry this checker cannot resolve is an error
    /// (indeterminate), never `Valid`.
    pub async fn check(&self, credential: &Value) -> Result<CredentialState, ClientError> {
        let issuer = credential
            .get("issuer")
            .and_then(Value::as_str)
            .ok_or_else(|| ClientError::Unexpected("credential has no issuer".into()))?;
        let entries: Vec<&Value> = match credential.get("credentialStatus") {
            None | Some(Value::Null) => return Ok(CredentialState::Valid),
            Some(Value::Array(a)) => a.iter().collect(),
            Some(one) => vec![one],
        };
        let mut state = CredentialState::Valid;
        for entry in entries {
            if entry.get("type").and_then(Value::as_str) != Some("BitstringStatusListEntry") {
                return Err(ClientError::Unexpected(format!(
                    "unsupported status entry type {}",
                    entry["type"]
                )));
            }
            let purpose = entry["statusPurpose"].as_str().unwrap_or_default();
            let url = entry["statusListCredential"]
                .as_str()
                .ok_or_else(|| ClientError::Unexpected("status entry has no list".into()))?;
            let index: u32 = entry["statusListIndex"]
                .as_str()
                .and_then(|i| i.parse().ok())
                .ok_or_else(|| ClientError::Unexpected("bad statusListIndex".into()))?;
            let bits = self.list(url, issuer, purpose).await?;
            if bits.get(index) {
                match purpose {
                    "revocation" => return Ok(CredentialState::Revoked),
                    "suspension" => state = CredentialState::Suspended,
                    _ => {}
                }
            }
        }
        Ok(state)
    }

    async fn list(&self, url: &str, issuer: &str, purpose: &str) -> Result<Bitstring, ClientError> {
        let now = Utc::now();
        if let Some((at, cached_issuer, bits)) = self.cache.lock().await.get(url)
            && now - *at < self.ttl
            && cached_issuer == issuer
        {
            return Ok(bits.clone());
        }
        let list = self.client.get_url(url).await?;
        if list.get("issuer").and_then(Value::as_str) != Some(issuer) {
            return Err(ClientError::Unexpected(format!(
                "status list {url} is not issued by {issuer}"
            )));
        }
        verify_document(&list, issuer, ASSERTION_METHOD, self.resolver.as_ref())
            .await
            .map_err(|e| ClientError::Unexpected(format!("status list {url}: {e}")))?;
        let subject = &list["credentialSubject"];
        if subject["statusPurpose"].as_str() != Some(purpose) {
            return Err(ClientError::Unexpected(format!(
                "status list {url} is for {}, not {purpose}",
                subject["statusPurpose"]
            )));
        }
        let bits = Bitstring::decode(subject["encodedList"].as_str().unwrap_or_default())
            .map_err(|e| ClientError::Unexpected(format!("status list {url}: {e}")))?;
        self.cache
            .lock()
            .await
            .insert(url.to_string(), (now, issuer.to_string(), bits.clone()));
        Ok(bits)
    }
}
