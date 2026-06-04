//! Holder-side status refresh for held credentials (task 1.6,
//! `docs/05-design-notes/vti-credential-architecture.md` §5 "Track validity",
//! §14 invariant 5).
//!
//! A stored credential may carry a `credentialStatus`
//! ([`BitstringStatusListEntry`][w3c]): a status-list credential URL plus an
//! index into that list's bitstring. This module is the **holder side** of
//! revocation: it resolves the referenced status list, decodes the bitstring
//! via the `affinidi-status-list` crate, reads the bit at the credential's
//! `statusListIndex`, and flips the stored envelope's
//! [`CredentialStatus`] to [`CredentialStatus::Revoked`] when the bit is set —
//! so search ([`super::query`]) can exclude it and present ([`super::present`])
//! continues to refuse it.
//!
//! [w3c]: https://www.w3.org/TR/vc-bitstring-status-list/
//!
//! ## Scope (deliberately holder-side only)
//!
//! This task is the *consumer* of issuer status. It does **not** stand up the
//! VTA-as-issuer status-list allocator, self-minted revocability, or the
//! `status_lists` keyspace (§15) — that is a separate, larger follow-up. Here
//! the VTA is purely a holder reading some *other* issuer's published list.
//!
//! ## No live network in this layer
//!
//! Resolution is behind the injected [`StatusListResolver`] trait. The trait
//! takes the `statusListCredential` URL and returns the decoded-ready
//! [`ResolvedStatusList`] (the encoded bitstring + its size + purpose).
//! Production wires an HTTP-fetching, list-credential-verifying resolver;
//! tests provide a mock, so the refresh path has **no hard network
//! dependency** and is fully unit-testable. Fetching, caching, and
//! verifying the *status-list credential's own* issuer signature are the
//! resolver's responsibility, not this module's.
//!
//! ## Security invariants upheld (§14 invariant 5)
//!
//! - **A set bit revokes.** When the resolved bitstring's bit at the
//!   credential's index is `1`, the stored status becomes
//!   [`CredentialStatus::Revoked`] and is persisted. Combined with the
//!   search exclusion in [`super::query`], a revoked credential can no longer
//!   be surfaced.
//! - **Fail closed on a `revocation` list, fail safe on transient errors.**
//!   A malformed entry, an out-of-bounds index, or a decode failure is
//!   surfaced as an error to the caller rather than silently leaving the
//!   credential `Valid`; the caller decides retry/alert policy. The status is
//!   only ever *written* on a definitive read.
//! - **Suspension is not permanent revocation.** A `suspension`-purpose list
//!   with the bit set marks the credential [`CredentialStatus::Revoked`] for
//!   the duration (search/present must not surface a suspended credential);
//!   a later refresh with the bit clear restores it to
//!   [`CredentialStatus::Valid`]. A `revocation`-purpose set bit is terminal:
//!   once revoked, a subsequent clear read does **not** un-revoke it.

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

#[cfg(feature = "webvh")]
use affinidi_status_list::DEFAULT_BITSTRING_SIZE;
use affinidi_status_list::{BitstringStatusList, StatusPurpose};

use super::model::{CredentialStatus, StoredCredential};
use super::storage;

/// A status-list reference parsed out of a held credential's
/// `credentialStatus` (`BitstringStatusListEntry`).
///
/// Only the fields this holder-side refresh needs are modelled: the URL of
/// the status-list credential and the index into its bitstring. The
/// `statusPurpose` declared on the *entry* is carried for cross-checking
/// against the resolved list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusListRef {
    /// The URI of the status-list credential to resolve.
    pub status_list_credential: String,
    /// The index into the status list's bitstring.
    pub status_list_index: usize,
    /// The purpose declared on the credential's `credentialStatus` entry
    /// (`revocation` | `suspension`), when present.
    pub status_purpose: Option<StatusPurpose>,
}

/// The decoded-ready view of a status list, returned by a
/// [`StatusListResolver`].
///
/// The resolver is responsible for fetching the status-list credential at the
/// entry's URL, verifying *its* issuer signature, and extracting the encoded
/// bitstring plus the parameters needed to decode it. This module then decodes
/// and reads the single bit — it never touches the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedStatusList {
    /// The GZIP-compressed, base64url-encoded bitstring (the `encodedList` of
    /// a `BitstringStatusListCredential`).
    pub encoded_list: String,
    /// The number of entries (bits) in the list. Required to decode the
    /// bitstring unambiguously (the `affinidi-status-list` decoder is
    /// size-parameterised).
    pub size: usize,
    /// The purpose of the resolved list (`revocation` | `suspension`).
    pub status_purpose: StatusPurpose,
}

/// The default live status resolver wired into a running VTA: an HTTP resolver
/// when the `webvh` feature (which pulls in `reqwest`) is built, else `None` —
/// in which case the present path falls back to the stored status tag.
pub fn default_status_resolver() -> Option<std::sync::Arc<dyn StatusListResolver>> {
    #[cfg(feature = "webvh")]
    {
        Some(std::sync::Arc::new(HttpStatusListResolver::new()))
    }
    #[cfg(not(feature = "webvh"))]
    {
        None
    }
}

/// Production [`StatusListResolver`]: HTTP-fetches the `BitstringStatusListCredential`
/// an issuer (e.g. the VTC) publishes at the entry URL and decodes its
/// `credentialSubject` (`encodedList` + `statusPurpose`), using the standard list
/// size ([`DEFAULT_BITSTRING_SIZE`], the W3C minimum the issuers allocate).
///
/// NOTE (hardening follow-up): this does **not** yet verify the status-list
/// credential's own issuer signature — a holder should ideally verify it before
/// trusting the list (needs issuer-key resolution). The present gate falls back
/// to the stored tag on any resolver error, so an outage does not block
/// presentation.
#[cfg(feature = "webvh")]
pub struct HttpStatusListResolver {
    http: reqwest::Client,
}

#[cfg(feature = "webvh")]
impl HttpStatusListResolver {
    /// A resolver over a fresh HTTP client.
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "webvh")]
impl Default for HttpStatusListResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "webvh")]
#[async_trait::async_trait]
impl StatusListResolver for HttpStatusListResolver {
    async fn resolve(&self, url: &str) -> Result<ResolvedStatusList, AppError> {
        let body: serde_json::Value = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("status list fetch `{url}` failed: {e}")))?
            .error_for_status()
            .map_err(|e| AppError::Internal(format!("status list `{url}` returned an error: {e}")))?
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("status list `{url}` is not JSON: {e}")))?;

        let subject = body.get("credentialSubject").ok_or_else(|| {
            AppError::Validation(format!("status list `{url}` has no credentialSubject"))
        })?;
        let encoded_list = subject
            .get("encodedList")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AppError::Validation(format!("status list `{url}` has no encodedList")))?
            .to_string();
        let purpose_str = subject
            .get("statusPurpose")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                AppError::Validation(format!("status list `{url}` has no statusPurpose"))
            })?;
        let status_purpose = parse_purpose(purpose_str).ok_or_else(|| {
            AppError::Validation(format!(
                "status list `{url}` has unknown statusPurpose `{purpose_str}`"
            ))
        })?;
        Ok(ResolvedStatusList {
            encoded_list,
            size: DEFAULT_BITSTRING_SIZE,
            status_purpose,
        })
    }
}

/// Resolves a status-list-credential URL to its decoded-ready bitstring.
///
/// Injected so tests provide a mock (no network) and production wires the
/// HTTP-fetching [`HttpStatusListResolver`]. The single method is `async` so a
/// real resolver can perform I/O.
#[async_trait::async_trait]
pub trait StatusListResolver: Send + Sync {
    /// Fetch and return the status list referenced by `url`.
    ///
    /// Implementations should verify the status-list *credential's* own issuer
    /// signature before returning (the holder must not trust an unverified
    /// list); that verification is out of scope for this module, which only
    /// decodes and reads the bit. Returns an error the caller can surface or
    /// retry; on error this module leaves the stored status unchanged.
    async fn resolve(&self, url: &str) -> Result<ResolvedStatusList, AppError>;
}

/// Extract the `credentialStatus` `BitstringStatusListEntry` from a stored
/// credential's body, if it carries one.
///
/// Returns:
/// - `Ok(Some(_))` — the body parsed and carried a usable
///   `BitstringStatusListEntry`.
/// - `Ok(None)` — the body parsed but declares no `credentialStatus` (the
///   credential is simply not status-list-tracked; nothing to refresh).
/// - `Err(_)` — the body could not be read, or its `credentialStatus` is
///   malformed (e.g. a non-numeric `statusListIndex`). Failing closed here
///   keeps a broken entry from silently leaving a credential `Valid`.
///
/// The body is whatever the holder stored: an SD-JWT-VC compact serialization
/// (the issuer JWS payload carries `status` / `credentialStatus`) or a JSON
/// VC. Both are handled by reading the JWS payload (when compact) or the JSON
/// object directly.
pub fn extract_status_ref(cred: &StoredCredential) -> Result<Option<StatusListRef>, AppError> {
    let payload = decode_body_to_json(&cred.body)?;

    // The W3C VC field is `credentialStatus`; SD-JWT-VC's IETF profile nests
    // it under `status.status_list` (a `StatusListEntry` with `idx` + `uri`),
    // but our issuer/mint path emits the W3C `credentialStatus` shape, so we
    // accept both: `credentialStatus` (W3C) first, then `status.status_list`
    // (SD-JWT-VC IETF) as a fallback.
    if let Some(entry) = payload.get("credentialStatus") {
        return parse_w3c_entry(entry).map(Some);
    }
    if let Some(sl) = payload.get("status").and_then(|s| s.get("status_list")) {
        return parse_sd_jwt_entry(sl).map(Some);
    }

    Ok(None)
}

/// Parse a W3C `BitstringStatusListEntry` object into a [`StatusListRef`].
fn parse_w3c_entry(entry: &serde_json::Value) -> Result<StatusListRef, AppError> {
    let status_list_credential = entry
        .get("statusListCredential")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::Validation(
                "credentialStatus is missing a non-empty `statusListCredential` URL".to_string(),
            )
        })?
        .to_string();

    // `statusListIndex` is a string per the W3C spec; tolerate a JSON number
    // too. Either way it must be a non-negative integer.
    let status_list_index = parse_index(entry.get("statusListIndex"))?;

    let status_purpose = entry
        .get("statusPurpose")
        .and_then(|v| v.as_str())
        .and_then(parse_purpose);

    Ok(StatusListRef {
        status_list_credential,
        status_list_index,
        status_purpose,
    })
}

/// Parse an SD-JWT-VC IETF `status.status_list` object (`{ idx, uri }`).
fn parse_sd_jwt_entry(sl: &serde_json::Value) -> Result<StatusListRef, AppError> {
    let status_list_credential = sl
        .get("uri")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::Validation("status.status_list is missing a non-empty `uri`".to_string())
        })?
        .to_string();
    let status_list_index = parse_index(sl.get("idx"))?;
    Ok(StatusListRef {
        status_list_credential,
        status_list_index,
        // SD-JWT-VC's status_list entry has no per-entry purpose; the list
        // itself carries it. Left `None` so the resolved list decides.
        status_purpose: None,
    })
}

/// Parse a `statusListIndex` / `idx` value that may be a JSON string or a JSON
/// number into a `usize`.
fn parse_index(v: Option<&serde_json::Value>) -> Result<usize, AppError> {
    match v {
        Some(serde_json::Value::String(s)) => s.parse::<usize>().map_err(|_| {
            AppError::Validation(format!(
                "statusListIndex `{s}` is not a non-negative integer"
            ))
        }),
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .map(|u| u as usize)
            .ok_or_else(|| AppError::Validation("statusListIndex is not a u64".to_string())),
        _ => Err(AppError::Validation(
            "credentialStatus is missing a `statusListIndex`".to_string(),
        )),
    }
}

/// Map a `statusPurpose` string to the crate enum.
fn parse_purpose(s: &str) -> Option<StatusPurpose> {
    match s {
        "revocation" => Some(StatusPurpose::Revocation),
        "suspension" => Some(StatusPurpose::Suspension),
        _ => None,
    }
}

/// Decode a stored credential body into a JSON object (the VC / JWS payload).
///
/// Handles two shapes:
/// - **SD-JWT-VC / JWS compact** — `header.payload.sig[~disclosures]`: the
///   payload segment is base64url-decoded and parsed. (We read the issuer
///   payload here only to find `credentialStatus`; this is *not* a
///   verification — the credential's issuer signature was checked at receive
///   time, and the status-list credential's signature is the resolver's job.)
/// - **Raw JSON VC** — the body is a JSON object.
fn decode_body_to_json(body: &[u8]) -> Result<serde_json::Value, AppError> {
    // Try raw JSON first (cheap, and unambiguous when it succeeds).
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body)
        && v.is_object()
    {
        return Ok(v);
    }

    // Otherwise treat it as a compact JWS / SD-JWT-VC and read the payload
    // segment. The SD-JWT form is `<jws>~<disclosure>~...`; the JWS is the
    // part before the first `~`.
    let text = std::str::from_utf8(body)
        .map_err(|_| AppError::Validation("credential body is not UTF-8".to_string()))?;
    let jws = text.split('~').next().unwrap_or(text);
    let mut parts = jws.split('.');
    let _header = parts.next();
    let payload = parts
        .next()
        .ok_or_else(|| AppError::Validation("credential body is not a compact JWS".to_string()))?;

    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| AppError::Validation(format!("JWS payload is not base64url: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Validation(format!("JWS payload is not JSON: {e}")))
}

/// The outcome of a single status refresh, returned so a caller can act on a
/// transition (e.g. invalidate a cached assertion) without re-reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefreshOutcome {
    /// The credential carries no `credentialStatus`; nothing to resolve.
    NotTracked,
    /// Resolved and read; the (possibly unchanged) status is reported.
    Refreshed {
        /// The status the credential held before this refresh.
        previous: CredentialStatus,
        /// The status now persisted.
        current: CredentialStatus,
    },
}

/// Refresh the lifecycle status of a single held credential against its
/// issuer's status list.
///
/// Loads the credential by `id`, extracts its `credentialStatus`, resolves the
/// referenced status list via `resolver`, decodes the bitstring, reads the bit
/// at the credential's `statusListIndex`, and persists the resulting
/// [`CredentialStatus`] via the storage layer.
///
/// Transition rules (this module's design; spec §14 invariant 5 mandates only
/// that a revoked credential is never surfaced and status is re-verified — the
/// suspension/terminal-revocation refinements below are how we satisfy it):
/// - **bit set, list purpose = revocation** → [`CredentialStatus::Revoked`]
///   (terminal).
/// - **bit set, list purpose = suspension** → [`CredentialStatus::Revoked`]
///   for now (search/present must not surface a suspended credential).
/// - **bit clear** → [`CredentialStatus::Valid`], with two exceptions: a
///   credential already `Revoked` under a `revocation` list stays `Revoked`
///   (terminal — a clear read does not resurrect a revoked credential; an
///   already-`Revoked` credential under a `suspension` list **is** restored),
///   and a time-`Expired` credential stays `Expired` (a clear status-list bit
///   is not authority over the credential's own `valid_until`).
///
/// The credential entry's declared `statusPurpose` (when present) MUST match
/// the resolved list's purpose, or the refresh is rejected
/// ([`AppError::Validation`]) before any transition — a mismatched list could
/// otherwise silently flip terminal/reversible semantics.
///
/// Errors (and what they leave behind):
/// - credential `id` not found → [`AppError::NotFound`]; nothing written.
/// - malformed `credentialStatus` → [`AppError::Validation`]; nothing written.
/// - resolver error → propagated; nothing written (the prior status stands).
/// - index out of bounds for the resolved list → [`AppError::Validation`];
///   nothing written.
pub async fn refresh_status<R: StatusListResolver + ?Sized>(
    vault: &KeyspaceHandle,
    id: &str,
    resolver: &R,
) -> Result<RefreshOutcome, AppError> {
    let mut cred = storage::get(vault, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no stored credential with id `{id}`")))?;

    let Some(status_ref) = extract_status_ref(&cred)? else {
        return Ok(RefreshOutcome::NotTracked);
    };

    let resolved = resolver.resolve(&status_ref.status_list_credential).await?;

    // Enforce the declared-purpose binding (W3C vc-bitstring-status-list §). When
    // the credential's entry declares a `statusPurpose`, it MUST match the
    // resolved list's purpose. A mismatch (issuer/resolver misconfig, or a
    // resolver that returned the wrong list) would silently switch the
    // terminal-revocation vs reversible-suspension transition semantics below —
    // e.g. an entry declaring `revocation` read against a `suspension` list
    // would become un-revocable on a later clear read. Reject it. The SD-JWT-VC
    // shape carries no per-entry purpose (`None`); there the resolved list's
    // purpose legitimately stands alone.
    if let Some(entry_purpose) = status_ref.status_purpose
        && entry_purpose != resolved.status_purpose
    {
        return Err(AppError::Validation(format!(
            "status entry purpose {entry_purpose:?} does not match the resolved status \
             list purpose {:?}; refusing to apply",
            resolved.status_purpose
        )));
    }

    // Decode the bitstring and read the single bit. The decoder is
    // size-parameterised; the resolver supplies the authoritative size and
    // purpose for the list it fetched.
    let list = BitstringStatusList::decode(
        &resolved.encoded_list,
        resolved.size,
        resolved.status_purpose,
    )
    .map_err(|e| AppError::Validation(format!("status list failed to decode: {e}")))?;

    let bit_set = list.get(status_ref.status_list_index).map_err(|e| {
        AppError::Validation(format!(
            "statusListIndex {} is out of bounds for the resolved list: {e}",
            status_ref.status_list_index
        ))
    })?;

    let previous = cred.status;
    let new_status = next_status(previous, bit_set, resolved.status_purpose);

    // Persist only when the status actually changed — avoids a needless
    // re-index/rewrite on the (common) unchanged-valid path.
    if new_status != previous {
        cred.status = new_status;
        storage::put(vault, &cred).await?;
    }

    Ok(RefreshOutcome::Refreshed {
        previous,
        current: new_status,
    })
}

/// Compute the new status from the prior status, the read bit, and the list's
/// purpose. Pure, so the transition rules are unit-testable in isolation.
fn next_status(
    previous: CredentialStatus,
    bit_set: bool,
    purpose: StatusPurpose,
) -> CredentialStatus {
    if bit_set {
        // Set bit → revoked/suspended; either way we exclude it from search
        // and refuse it at present, so the stored status is `Revoked`.
        return CredentialStatus::Revoked;
    }

    // Bit clear. A clear status-list bit is authority over *list* state
    // (revoked / suspended) only — never over the orthogonal time-expiry
    // dimension.
    match previous {
        // Time-expiry is not the status list's to undo: a clear bit must not
        // resurrect a credential that expired on its own `valid_until`. Preserve
        // Expired regardless of list purpose.
        CredentialStatus::Expired => CredentialStatus::Expired,
        // A revocation list is terminal: a previously-revoked credential is not
        // resurrected by a later clear read (defends against a tampered or
        // rolled-back list flipping a revoked credential back to valid). A
        // suspension list is reversible, so a previously-suspended (stored as
        // Revoked) credential is restored.
        CredentialStatus::Revoked if purpose == StatusPurpose::Revocation => {
            CredentialStatus::Revoked
        }
        // Fresh/valid/unknown, or a cleared suspension → valid.
        _ => CredentialStatus::Valid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{CredentialFormat, CredentialPurpose};
    use crate::vault::query::{CredentialQuery, search};
    use crate::vault::storage::put;
    use std::collections::BTreeMap;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn fresh_vault() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace("vault").expect("vault keyspace");
        (dir, store, ks)
    }

    /// A small status-list size so tests can allocate fixed indices cheaply
    /// (the decoder is size-parameterised; herd-privacy sizing is the issuer's
    /// concern, not the holder-side reader's).
    const LIST_SIZE: usize = 1024;

    /// Build the encoded bitstring for a list of `LIST_SIZE` with `set_index`
    /// (when `Some`) flipped to 1.
    fn encoded_list_with(set_index: Option<usize>, purpose: StatusPurpose) -> String {
        let mut list = BitstringStatusList::new(LIST_SIZE, purpose);
        if let Some(i) = set_index {
            list.set(i, true).unwrap();
        }
        list.encode().unwrap()
    }

    /// A mock resolver returning a single pre-built list for any URL. Records
    /// whether it was called so a test can assert "no live network, the
    /// injected resolver did the work".
    struct MockResolver {
        list: ResolvedStatusList,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl MockResolver {
        fn new(set_index: Option<usize>, purpose: StatusPurpose) -> Self {
            MockResolver {
                list: ResolvedStatusList {
                    encoded_list: encoded_list_with(set_index, purpose),
                    size: LIST_SIZE,
                    status_purpose: purpose,
                },
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl StatusListResolver for MockResolver {
        async fn resolve(&self, _url: &str) -> Result<ResolvedStatusList, AppError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.list.clone())
        }
    }

    /// A resolver that always errors — proves a transient resolution failure
    /// leaves the stored status untouched.
    struct ErrResolver;

    #[async_trait::async_trait]
    impl StatusListResolver for ErrResolver {
        async fn resolve(&self, _url: &str) -> Result<ResolvedStatusList, AppError> {
            Err(AppError::Internal("status list unreachable".to_string()))
        }
    }

    /// A held credential whose JSON body carries a W3C
    /// `BitstringStatusListEntry` at `index`.
    fn cred_with_status(id: &str, index: usize, purpose: &str) -> StoredCredential {
        let body = serde_json::json!({
            "vct": "https://openvtc.org/credentials/MembershipCredential",
            "iss": "did:web:issuer.example",
            "credentialStatus": {
                "type": "BitstringStatusListEntry",
                "statusPurpose": purpose,
                "statusListIndex": index.to_string(),
                "statusListCredential": "https://issuer.example/status/1",
            },
        });
        StoredCredential {
            id: id.to_string(),
            format: CredentialFormat::SdJwtVc,
            types: vec!["MembershipCredential".into()],
            schema_id: None,
            community_did: Some("did:web:acme".into()),
            subject_did: Some("did:key:zAlice".into()),
            issuer_did: Some("did:web:issuer.example".into()),
            purpose: Some(CredentialPurpose::Membership),
            status: CredentialStatus::Valid,
            valid_from: None,
            valid_until: None,
            received_at: "2026-06-03T00:00:00Z".into(),
            source: None,
            tags: BTreeMap::new(),
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    /// A held credential whose body declares no `credentialStatus` at all.
    fn cred_without_status(id: &str) -> StoredCredential {
        let body = serde_json::json!({
            "vct": "https://openvtc.org/credentials/MembershipCredential",
            "iss": "did:web:issuer.example",
        });
        let mut c = cred_with_status(id, 0, "revocation");
        c.body = serde_json::to_vec(&body).unwrap();
        c
    }

    #[tokio::test]
    async fn set_bit_marks_revoked_and_excludes_from_search() {
        let (_dir, _store, vault) = fresh_vault();
        // The credential's status index is 42; the list has bit 42 SET.
        let cred = cred_with_status("cred-revoked", 42, "revocation");
        put(&vault, &cred).await.unwrap();

        // Before refresh it is Valid and findable.
        let q = CredentialQuery {
            issuer_did: Some("did:web:issuer.example".into()),
            ..Default::default()
        };
        assert_eq!(search(&vault, &q).await.unwrap().len(), 1);

        let resolver = MockResolver::new(Some(42), StatusPurpose::Revocation);
        let outcome = refresh_status(&vault, "cred-revoked", &resolver)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            RefreshOutcome::Refreshed {
                previous: CredentialStatus::Valid,
                current: CredentialStatus::Revoked,
            }
        );
        // The injected resolver was used (no live network).
        assert_eq!(resolver.calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Stored status is now Revoked.
        let stored = storage::get(&vault, "cred-revoked").await.unwrap().unwrap();
        assert_eq!(stored.status, CredentialStatus::Revoked);

        // CRITICAL (§14 invariant 5): the revoked credential is EXCLUDED from search.
        let hits = search(&vault, &q).await.unwrap();
        assert!(
            hits.is_empty(),
            "a revoked credential must not be surfaced by search, got {hits:?}"
        );
    }

    #[tokio::test]
    async fn clear_bit_leaves_valid_and_findable() {
        let (_dir, _store, vault) = fresh_vault();
        // The credential's index is 7; the list has a DIFFERENT bit set (99),
        // so bit 7 is clear → stays Valid.
        let cred = cred_with_status("cred-ok", 7, "revocation");
        put(&vault, &cred).await.unwrap();

        let resolver = MockResolver::new(Some(99), StatusPurpose::Revocation);
        let outcome = refresh_status(&vault, "cred-ok", &resolver).await.unwrap();
        assert_eq!(
            outcome,
            RefreshOutcome::Refreshed {
                previous: CredentialStatus::Valid,
                current: CredentialStatus::Valid,
            }
        );

        let stored = storage::get(&vault, "cred-ok").await.unwrap().unwrap();
        assert_eq!(stored.status, CredentialStatus::Valid);

        // Still findable.
        let q = CredentialQuery {
            issuer_did: Some("did:web:issuer.example".into()),
            ..Default::default()
        };
        let hits = search(&vault, &q).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "cred-ok");
    }

    #[tokio::test]
    async fn empty_list_leaves_valid() {
        let (_dir, _store, vault) = fresh_vault();
        let cred = cred_with_status("cred-ok2", 500, "revocation");
        put(&vault, &cred).await.unwrap();

        // No bit set anywhere.
        let resolver = MockResolver::new(None, StatusPurpose::Revocation);
        refresh_status(&vault, "cred-ok2", &resolver).await.unwrap();

        let stored = storage::get(&vault, "cred-ok2").await.unwrap().unwrap();
        assert_eq!(stored.status, CredentialStatus::Valid);
    }

    #[tokio::test]
    async fn credential_without_status_is_not_tracked() {
        let (_dir, _store, vault) = fresh_vault();
        let cred = cred_without_status("cred-plain");
        put(&vault, &cred).await.unwrap();

        let resolver = MockResolver::new(Some(0), StatusPurpose::Revocation);
        let outcome = refresh_status(&vault, "cred-plain", &resolver)
            .await
            .unwrap();
        assert_eq!(outcome, RefreshOutcome::NotTracked);
        // Resolver was never consulted.
        assert_eq!(resolver.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        // Status untouched.
        let stored = storage::get(&vault, "cred-plain").await.unwrap().unwrap();
        assert_eq!(stored.status, CredentialStatus::Valid);
    }

    #[tokio::test]
    async fn resolver_error_leaves_status_unchanged() {
        let (_dir, _store, vault) = fresh_vault();
        let cred = cred_with_status("cred-x", 1, "revocation");
        put(&vault, &cred).await.unwrap();

        let err = refresh_status(&vault, "cred-x", &ErrResolver)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Internal(_)));

        // The prior status stands; nothing was written.
        let stored = storage::get(&vault, "cred-x").await.unwrap().unwrap();
        assert_eq!(stored.status, CredentialStatus::Valid);
    }

    #[tokio::test]
    async fn missing_credential_is_not_found() {
        let (_dir, _store, vault) = fresh_vault();
        let resolver = MockResolver::new(None, StatusPurpose::Revocation);
        let err = refresh_status(&vault, "nope", &resolver).await.unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn index_out_of_bounds_is_rejected_and_status_unchanged() {
        let (_dir, _store, vault) = fresh_vault();
        // Index beyond LIST_SIZE.
        let cred = cred_with_status("cred-oob", LIST_SIZE + 10, "revocation");
        put(&vault, &cred).await.unwrap();

        let resolver = MockResolver::new(None, StatusPurpose::Revocation);
        let err = refresh_status(&vault, "cred-oob", &resolver)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));

        let stored = storage::get(&vault, "cred-oob").await.unwrap().unwrap();
        assert_eq!(stored.status, CredentialStatus::Valid);
    }

    #[tokio::test]
    async fn suspension_set_then_clear_round_trips_valid() {
        let (_dir, _store, vault) = fresh_vault();
        let cred = cred_with_status("cred-susp", 3, "suspension");
        put(&vault, &cred).await.unwrap();

        // Suspended: bit 3 set on a suspension list → Revoked (excluded).
        let suspend = MockResolver::new(Some(3), StatusPurpose::Suspension);
        refresh_status(&vault, "cred-susp", &suspend).await.unwrap();
        assert_eq!(
            storage::get(&vault, "cred-susp")
                .await
                .unwrap()
                .unwrap()
                .status,
            CredentialStatus::Revoked
        );

        // Un-suspended: bit clear on a suspension list → restored to Valid.
        let restore = MockResolver::new(None, StatusPurpose::Suspension);
        refresh_status(&vault, "cred-susp", &restore).await.unwrap();
        assert_eq!(
            storage::get(&vault, "cred-susp")
                .await
                .unwrap()
                .unwrap()
                .status,
            CredentialStatus::Valid
        );
    }

    #[test]
    fn revocation_is_terminal_but_suspension_is_reversible() {
        // A revocation list never un-revokes on a clear read.
        assert_eq!(
            next_status(CredentialStatus::Revoked, false, StatusPurpose::Revocation),
            CredentialStatus::Revoked
        );
        // A suspension list does.
        assert_eq!(
            next_status(CredentialStatus::Revoked, false, StatusPurpose::Suspension),
            CredentialStatus::Valid
        );
        // A set bit always revokes regardless of prior state.
        assert_eq!(
            next_status(CredentialStatus::Valid, true, StatusPurpose::Revocation),
            CredentialStatus::Revoked
        );
    }

    #[test]
    fn clear_bit_does_not_resurrect_a_time_expired_credential() {
        // A clear status-list bit is authority over list state only, never over
        // the credential's own time-expiry. An Expired credential stays Expired
        // on a clear read, under either list purpose.
        assert_eq!(
            next_status(CredentialStatus::Expired, false, StatusPurpose::Revocation),
            CredentialStatus::Expired
        );
        assert_eq!(
            next_status(CredentialStatus::Expired, false, StatusPurpose::Suspension),
            CredentialStatus::Expired
        );
        // But a set bit still revokes even an expired credential (list state is
        // independent and revocation is the stronger signal for search/present).
        assert_eq!(
            next_status(CredentialStatus::Expired, true, StatusPurpose::Revocation),
            CredentialStatus::Revoked
        );
    }

    #[tokio::test]
    async fn entry_purpose_mismatch_is_rejected_and_status_unchanged() {
        // The credential's entry declares `revocation`, but the resolver returns
        // a `suspension` list. The declared-purpose binding must reject this
        // before any transition, leaving the stored status untouched.
        let (_dir, _store, vault) = fresh_vault();
        let cred = cred_with_status("cred-mismatch", 5, "revocation");
        put(&vault, &cred).await.unwrap();

        let resolver = MockResolver::new(Some(5), StatusPurpose::Suspension);
        let err = refresh_status(&vault, "cred-mismatch", &resolver)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::Validation(_)),
            "a status-list whose purpose differs from the entry's declared purpose \
             must be rejected, got {err:?}"
        );

        // Nothing was written — the credential stays Valid.
        let stored = storage::get(&vault, "cred-mismatch")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, CredentialStatus::Valid);
    }

    #[test]
    fn extract_reads_sd_jwt_ietf_status_list_shape() {
        // SD-JWT-VC IETF `status.status_list` { idx, uri } is also accepted.
        let body = serde_json::json!({
            "vct": "x",
            "status": { "status_list": { "idx": 12, "uri": "https://issuer.example/sl" } },
        });
        let mut c = cred_with_status("c", 0, "revocation");
        c.body = serde_json::to_vec(&body).unwrap();
        let r = extract_status_ref(&c).unwrap().unwrap();
        assert_eq!(r.status_list_credential, "https://issuer.example/sl");
        assert_eq!(r.status_list_index, 12);
    }

    #[test]
    fn extract_reads_compact_jws_body() {
        use base64::Engine;
        // A compact JWS whose payload carries credentialStatus, with a
        // trailing SD-JWT disclosure segment.
        let payload = serde_json::json!({
            "vct": "x",
            "credentialStatus": {
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": "88",
                "statusListCredential": "https://issuer.example/sl",
            },
        });
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let header = b64(br#"{"alg":"EdDSA"}"#);
        let payload_b64 = b64(&serde_json::to_vec(&payload).unwrap());
        let compact = format!("{header}.{payload_b64}.sig~disclosure~");

        let mut c = cred_with_status("c", 0, "revocation");
        c.body = compact.into_bytes();
        let r = extract_status_ref(&c).unwrap().unwrap();
        assert_eq!(r.status_list_credential, "https://issuer.example/sl");
        assert_eq!(r.status_list_index, 88);
        assert_eq!(r.status_purpose, Some(StatusPurpose::Revocation));
    }

    #[test]
    fn malformed_status_entry_fails_closed() {
        // credentialStatus present but missing the URL → error, not silent.
        let body = serde_json::json!({
            "vct": "x",
            "credentialStatus": {
                "type": "BitstringStatusListEntry",
                "statusListIndex": "1",
            },
        });
        let mut c = cred_with_status("c", 0, "revocation");
        c.body = serde_json::to_vec(&body).unwrap();
        let err = extract_status_ref(&c).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }
}
