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

/// The most status lists the cache holds. Its keys are URLs credentials name, so
/// without a bound anyone presenting credentials could grow it without limit
/// (#2662). Past it, lapsed entries go first, then the oldest.
pub const MAX_CACHED_LISTS: usize = 1024;

/// Resolves `credentialStatus`. Clone-cheap; the cache is shared.
///
/// Status lists are fetched with [`VtnClient::get_url`], which treats the URL
/// as the credential's presenter's — public `https` only by default.
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
            check_status_size(entry.get("statusSize"))?;
            let bits = self.list(url, issuer, purpose).await?;
            // W3C Bitstring Status List v1.0 §3.2 step 10: "If the
            // credentialIndex multiplied by the size is a value outside of the
            // range of the bitstring, a RANGE_ERROR MUST be raised." Not clear.
            if index as usize >= bits.len_bits() {
                return Err(ClientError::Unexpected(format!(
                    "statusListIndex {index} is outside the {}-entry status list {url}",
                    bits.len_bits()
                )));
            }
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
        let mut cache = self.cache.lock().await;
        if cache.len() >= MAX_CACHED_LISTS && !cache.contains_key(url) {
            make_room(&mut cache, now, self.ttl);
        }
        cache.insert(url.to_string(), (now, issuer.to_string(), bits.clone()));
        Ok(bits)
    }
}

/// Free at least one slot in a full cache: every lapsed entry, or else the
/// oldest.
fn make_room(
    cache: &mut HashMap<String, (DateTime<Utc>, String, Bitstring)>,
    now: DateTime<Utc>,
    ttl: Duration,
) {
    cache.retain(|_, (at, _, _)| now - *at < ttl);
    if cache.len() >= MAX_CACHED_LISTS
        && let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, (at, _, _))| *at)
            .map(|(k, _)| k.clone())
    {
        cache.remove(&oldest);
    }
}

/// W3C Bitstring Status List v1.0 §2.1: "If statusSize is not present as a
/// property of the credentialStatus, then statusSize MUST be processed as 1",
/// and "If present, statusSize MUST be an integer greater than zero." §1.3:
/// "Conforming processors MAY choose to only support bitstring entry sizes of
/// 1." Only 1 is read here; a wider entry is refused rather than read as one
/// bit.
fn check_status_size(value: Option<&Value>) -> Result<(), ClientError> {
    match value {
        None => Ok(()),
        Some(v) if v.as_u64() == Some(1) => Ok(()),
        Some(v) => Err(ClientError::Unexpected(format!(
            "statusSize {v} is not supported: only 1-bit status entries are read"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::status::{LIST_BITS, Purpose, status_list_credential};
    use crate::verify::LocalDidKeyResolver;
    use serde_json::json;

    /// Serve `body` as JSON to every request on a local port; the URL to fetch.
    async fn serve_json(body: Value) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn an_index_past_the_end_of_the_list_is_an_error_not_valid() {
        let issuer = Identity::generate();
        let mut bits = Bitstring::default();
        bits.set(5, true).unwrap();
        let unsigned = status_list_credential(
            issuer.did(),
            "http://placeholder",
            Purpose::Revocation,
            &bits,
            Utc::now(),
        )
        .unwrap();
        let signed = issuer.sign_document(unsigned).await.unwrap();
        let base = serve_json(signed).await;
        let url = format!("{base}/list");
        let checker = StatusChecker::with_client(
            VtnClient::new("").allow_private_endpoints(true),
            Arc::new(LocalDidKeyResolver),
        )
        .with_cache_ttl(Duration::zero());

        let credential = |index: usize| {
            json!({
                "issuer": issuer.did(),
                "credentialStatus": {
                    "type": "BitstringStatusListEntry",
                    "statusPurpose": "revocation",
                    "statusListIndex": index.to_string(),
                    "statusListCredential": url,
                },
            })
        };
        assert_eq!(
            checker.check(&credential(5)).await.unwrap(),
            CredentialState::Revoked
        );
        assert_eq!(
            checker.check(&credential(6)).await.unwrap(),
            CredentialState::Valid
        );
        assert_eq!(
            checker.check(&credential(LIST_BITS - 1)).await.unwrap(),
            CredentialState::Valid
        );
        for index in [LIST_BITS, LIST_BITS + 8, u32::MAX as usize] {
            let got = checker.check(&credential(index)).await;
            assert!(
                matches!(&got, Err(ClientError::Unexpected(m)) if m.contains("outside")),
                "{index}: {got:?}"
            );
        }
    }

    /// #2662: the cache never holds more than [`MAX_CACHED_LISTS`] lists.
    #[test]
    fn the_cache_is_bounded() {
        let now = Utc::now();
        let ttl = Duration::hours(2);
        let mut cache = HashMap::new();
        for i in 0..MAX_CACHED_LISTS {
            let at = now - Duration::seconds(i as i64);
            cache.insert(format!("u{i}"), (at, "did:x".into(), Bitstring::default()));
        }
        make_room(&mut cache, now, ttl);
        assert_eq!(cache.len(), MAX_CACHED_LISTS - 1);
        assert!(
            !cache.contains_key(&format!("u{}", MAX_CACHED_LISTS - 1)),
            "oldest goes"
        );
        // Lapsed entries go before anything live.
        cache.insert(
            "old".into(),
            (
                now - Duration::hours(3),
                "did:x".into(),
                Bitstring::default(),
            ),
        );
        make_room(&mut cache, now, ttl);
        assert!(!cache.contains_key("old"));
        assert_eq!(cache.len(), MAX_CACHED_LISTS - 1);
    }

    #[test]
    fn only_one_bit_status_entries_are_read() {
        assert!(check_status_size(None).is_ok());
        assert!(check_status_size(Some(&json!(1))).is_ok());
        for size in [json!(0), json!(2), json!(u64::MAX), json!("1"), json!(-1)] {
            assert!(check_status_size(Some(&size)).is_err(), "{size}");
        }
    }
}
