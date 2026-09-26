//! Forcing a fresh resolution of a DID whose cached document a verification
//! failed against (VTI-KEY-062, VTI-KEY-134).
//!
//! A verifier caches peers' DID documents, and a cached document goes stale
//! the moment its subject rotates. Two things follow, and this module is both:
//!
//! - a proof naming a key the cached document does not list, or failing under
//!   a key it does, is re-checked **once** against a freshly resolved document
//!   before it is refused — so a planned rotation (VTI-KEY-122) is never
//!   mistaken for a forgery;
//! - that refresh is rate-limited per DID, because a failing proof is
//!   something anyone can send, and an unthrottled refresh would let them make
//!   this node fetch someone else's DID document on every request.
//!
//! The cache's own TTL is the other half: it bounds how long a *revoked* key
//! keeps verifying, which no failure-triggered refresh can notice.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::{ResolveResponse, errors::DIDCacheError};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// The least time between two forced re-resolutions of the same DID.
///
/// A forced re-resolution is what lets a verifier follow a rotation it has not
/// yet seen (VTI-KEY-134) — and it is also something an unauthenticated caller
/// can trigger at will, by presenting a proof that fails. Without a floor, every
/// bad proof naming a `did:webvh` would cost the verifier a fetch from that
/// DID's host: a way to aim this node's traffic at someone else's server. Five
/// seconds keeps a genuine rotation invisible (the first failure after it
/// refreshes, and the retry succeeds) while capping what a flood can extract to
/// one fetch per DID per window.
pub const FRESH_RESOLVE_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// Most DIDs tracked for [`FRESH_RESOLVE_MIN_INTERVAL`] at once.
const FRESH_RESOLVE_TRACKED_MAX: usize = 4096;

/// Longest DID a forced refresh will consider. The resolver SDK's own default
/// refuses longer DIDs outright, so no document for one can be in the cache;
/// checking here as well keeps an oversized `skid` from even being hashed.
pub const FRESH_RESOLVE_DID_MAX_LEN: usize = 1_000;

/// The per-DID refresh floor: when each DID was last force-refreshed.
///
/// Only a DID whose document is in the cache is ever offered to it (see
/// [`evict_for_fresh_resolve`]), so it grows only as fast as documents are
/// cached, not as fast as an attacker can invent identifiers. It is still
/// capped: when full, entries past their window go first, and if every entry is
/// live the oldest is forgotten. A genuine refresh is therefore never refused
/// because the table is full. Forgetting an entry early lets that one DID be
/// refetched sooner, but only after [`FRESH_RESOLVE_TRACKED_MAX`] other cached
/// DIDs were refreshed in the meantime, so a flood still cannot aim more than a
/// trickle of fetches at any one host.
struct RefreshFloor {
    last: Mutex<HashMap<String, Instant>>,
    capacity: usize,
}

impl RefreshFloor {
    fn new(capacity: usize) -> Self {
        Self {
            last: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Record a refresh of `did` at `now`, unless it had one within
    /// [`FRESH_RESOLVE_MIN_INTERVAL`]. Returns whether it was admitted.
    fn admit(&self, did: &str, now: Instant) -> bool {
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if last
            .get(did)
            .is_some_and(|t| now.duration_since(*t) < FRESH_RESOLVE_MIN_INTERVAL)
        {
            return false;
        }
        if !last.contains_key(did) && last.len() >= self.capacity {
            last.retain(|_, t| now.duration_since(*t) < FRESH_RESOLVE_MIN_INTERVAL);
            if last.len() >= self.capacity
                && let Some(oldest) = last.iter().min_by_key(|(_, t)| **t).map(|(d, _)| d.clone())
            {
                last.remove(&oldest);
            }
        }
        last.insert(did.to_string(), now);
        true
    }

    #[cfg(test)]
    fn tracks(&self, did: &str) -> bool {
        self.last
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(did)
    }
}

static LAST_FRESH_RESOLVE: LazyLock<RefreshFloor> =
    LazyLock::new(|| RefreshFloor::new(FRESH_RESOLVE_TRACKED_MAX));

/// Whether `resolver`'s cache currently holds a document for `did`.
///
/// Only such a DID can be stale, so only such a DID is worth a forced refresh.
/// An uncached one was, or will be, resolved fresh anyway.
fn is_cached(resolver: &DIDCacheClient, did: &str) -> bool {
    did.len() <= FRESH_RESOLVE_DID_MAX_LEN
        && resolver
            .get_cache()
            .contains_key(&DIDCacheClient::hash_did(did))
}

/// Evict `did` from `resolver`'s cache so its next resolution fetches the
/// current document — VTI-KEY-062's means of forcing re-resolution.
///
/// Returns `false`, evicting nothing and taking no rate-limit slot, when the
/// cache holds no document for `did` (there is nothing stale to drop), or when
/// the same DID was force-refreshed within [`FRESH_RESOLVE_MIN_INTERVAL`] (the
/// document in the cache is then at most that old, so refetching it would buy
/// nothing but load).
///
/// Every clone of a [`DIDCacheClient`] shares one cache, so this evicts for all
/// of them. In network mode (`resolver_url`) it clears only the local cache: the
/// remote resolver answers from its own cache until that entry expires too, so
/// there a refresh follows a rotation only once the remote copy is current.
pub async fn evict_for_fresh_resolve(resolver: &DIDCacheClient, did: &str) -> bool {
    if !is_cached(resolver, did) || !LAST_FRESH_RESOLVE.admit(did, Instant::now()) {
        return false;
    }
    resolver.remove(did).await;
    true
}

/// Whether `doc` lists the verification method `vm`, absolutely or relatively.
fn lists_vm(doc: &affinidi_did_common::Document, vm: &str) -> bool {
    let relative = vm
        .split_once('#')
        .map(|(_, fragment)| format!("#{fragment}"))
        .unwrap_or_default();
    doc.verification_method
        .iter()
        .any(|m| m.id.as_str() == vm || m.id.as_str() == relative)
}

/// Resolve `did` for a proof naming `vm`, re-resolving once — fresh — when the
/// cached document does not list `vm` (VTI-KEY-134).
///
/// The case this exists for is a planned rotation the cache has not seen: the
/// signer publishes a new key and starts using it (VTI-KEY-122), and a verifier
/// holding the older document would refuse a genuine proof as a forgery until
/// its cache entry aged out. A document that was fetched for this call, rather
/// than served from the cache, is not fetched again.
pub async fn resolve_for_vm(
    resolver: &DIDCacheClient,
    did: &str,
    vm: &str,
) -> Result<ResolveResponse, DIDCacheError> {
    let resolved = resolver.resolve(did).await?;
    if resolved.cache_hit
        && !lists_vm(&resolved.doc, vm)
        && evict_for_fresh_resolve(resolver, did).await
    {
        return resolver.resolve(did).await;
    }
    Ok(resolved)
}

/// The DID an authcrypt JWE's protected header names as its sender (`skid`),
/// read **without decrypting or verifying anything**.
///
/// Unauthenticated by construction — it is whatever the sender wrote. Used
/// only to choose which cached document to refresh after an unpack failed; the
/// sender is still proven by the unpack itself (`bind_authcrypt_sender`).
#[cfg(feature = "didcomm")]
pub fn authcrypt_claimed_sender(jwe: &str) -> Option<String> {
    use base64::Engine;
    let envelope: serde_json::Value = serde_json::from_str(jwe).ok()?;
    let protected = envelope.get("protected")?.as_str()?;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(protected.trim_end_matches('='))
        .ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header).ok()?;
    let skid = header.get("skid")?.as_str()?;
    let did = skid.split('#').next()?;
    did.starts_with("did:").then(|| did.to_string())
}

/// `atm.unpack(body)`, re-resolving the claimed sender once — fresh — when the
/// first attempt fails, then failing closed on the second (VTI-KEY-134).
///
/// An authcrypt message is decrypted with the sender's key-agreement key from
/// its DID document. A sender that rotated that key since this node cached its
/// document sends messages the cached copy cannot open, and without this every
/// one of them fails until the cache entry ages out. `resolver` must be the
/// resolver `atm` resolves through, or the eviction reaches a different cache.
///
/// Only a sender whose document was in the cache before the first attempt is
/// refreshed, and the refresh is rate-limited per DID
/// ([`FRESH_RESOLVE_MIN_INTERVAL`]). A body naming no sender, an uncached
/// sender, or a sender refreshed moments ago gets the first error unchanged,
/// with no second attempt.
#[cfg(feature = "didcomm")]
pub async fn unpack_refreshing_sender(
    atm: &affinidi_tdk::messaging::ATM,
    resolver: Option<&DIDCacheClient>,
    body: &str,
) -> Result<
    (
        affinidi_tdk::didcomm::Message,
        affinidi_tdk::messaging::messages::compat::UnpackMetadata,
    ),
    affinidi_tdk::messaging::errors::ATMError,
> {
    // Decide before the first attempt: only a sender whose document was
    // already cached can have been failed by a stale copy. One the first
    // attempt resolves was fetched fresh, and retrying it would only double
    // the fetches a junk message naming a new DID costs this node.
    let target = resolver.and_then(|r| refresh_target(r, body).map(|did| (r, did)));
    let first = match atm.unpack(body).await {
        Ok(unpacked) => return Ok(unpacked),
        Err(e) => e,
    };
    let Some((resolver, sender)) = target else {
        return Err(first);
    };
    if !evict_for_fresh_resolve(resolver, &sender).await {
        return Err(first);
    }
    atm.unpack(body).await
}

/// The sender [`unpack_refreshing_sender`] may refresh if `body` fails to
/// unpack: its claimed `skid` DID, and only while `resolver` holds a cached
/// document for it.
#[cfg(feature = "didcomm")]
fn refresh_target(resolver: &DIDCacheClient, body: &str) -> Option<String> {
    authcrypt_claimed_sender(body).filter(|did| is_cached(resolver, did))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "didcomm")]
    #[test]
    fn the_claimed_sender_is_read_from_the_protected_header() {
        use base64::Engine;
        let header = serde_json::json!({ "alg": "ECDH-1PU+A256KW", "skid": "did:webvh:abc:example.com#key-1" });
        let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let jwe = serde_json::json!({ "protected": protected, "ciphertext": "x" }).to_string();
        assert_eq!(
            authcrypt_claimed_sender(&jwe).as_deref(),
            Some("did:webvh:abc:example.com")
        );
        assert_eq!(authcrypt_claimed_sender("not json"), None);
        let anon = serde_json::json!({ "protected": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"ECDH-ES+A256KW\"}") }).to_string();
        assert_eq!(
            authcrypt_claimed_sender(&anon),
            None,
            "anoncrypt names no sender"
        );
    }

    /// A resolver whose cache holds a document under each of `dids` — any
    /// document; the floor only cares that one is there to go stale.
    async fn resolver_caching(dids: &[&str]) -> DIDCacheClient {
        use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
        let mut resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        for did in dids {
            resolver
                .add_did_document(did, placeholder_doc().await)
                .await;
        }
        resolver
    }

    async fn placeholder_doc() -> affinidi_did_common::Document {
        use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap()
            .resolve("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
            .await
            .unwrap()
            .doc
    }

    fn unique_did(tag: &str) -> String {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("did:web:{tag}-{}-{n}.example", std::process::id())
    }

    /// The refresh floor: a second forced re-resolution of the same DID inside
    /// the window evicts nothing, so a stream of failing proofs costs at most
    /// one fetch per DID per window.
    #[tokio::test]
    async fn a_forced_refresh_is_rate_limited_per_did() {
        let did = unique_did("refresh-floor");
        let other = unique_did("refresh-floor-other");
        let mut resolver = resolver_caching(&[&did, &other]).await;
        assert!(
            evict_for_fresh_resolve(&resolver, &did).await,
            "first refresh"
        );
        // Cached again (the re-resolution), then failing again at once.
        resolver
            .add_did_document(&did, placeholder_doc().await)
            .await;
        assert!(
            !evict_for_fresh_resolve(&resolver, &did).await,
            "a second refresh inside the window is refused"
        );
        assert!(
            evict_for_fresh_resolve(&resolver, &other).await,
            "the floor is per DID"
        );
    }

    /// A DID with no cached document has nothing stale to drop: it is not
    /// evicted and takes no slot in the floor, so a genuine refresh of the same
    /// DID once it is cached still goes through.
    #[tokio::test]
    async fn an_uncached_did_takes_no_refresh_slot() {
        let resolver = resolver_caching(&[]).await;
        let did = unique_did("uncached");
        assert!(!evict_for_fresh_resolve(&resolver, &did).await);
        assert!(!LAST_FRESH_RESOLVE.tracks(&did), "no slot taken");

        let resolver = resolver_caching(&[&did]).await;
        assert!(
            evict_for_fresh_resolve(&resolver, &did).await,
            "cached now, so it refreshes"
        );
    }

    /// An over-long DID is refused before it is hashed or tracked.
    #[tokio::test]
    async fn an_over_long_did_is_not_tracked() {
        let did = format!("did:web:{}.example", "a".repeat(FRESH_RESOLVE_DID_MAX_LEN));
        let resolver = resolver_caching(&[&did]).await;
        assert!(!evict_for_fresh_resolve(&resolver, &did).await);
        assert!(!LAST_FRESH_RESOLVE.tracks(&did));
    }

    /// A flood of uncached DIDs cannot fill the floor: none of them enters it,
    /// and a cached, rotated DID still refreshes afterwards.
    #[tokio::test]
    async fn uncached_dids_cannot_exhaust_the_floor() {
        let resolver = resolver_caching(&[]).await;
        for _ in 0..(FRESH_RESOLVE_TRACKED_MAX + 100) {
            let junk = unique_did("junk");
            assert!(!evict_for_fresh_resolve(&resolver, &junk).await);
            assert!(!LAST_FRESH_RESOLVE.tracks(&junk));
        }
        let rotated = unique_did("rotated");
        let resolver = resolver_caching(&[&rotated]).await;
        assert!(evict_for_fresh_resolve(&resolver, &rotated).await);
    }

    /// Even a floor full of live entries admits a new DID: expired entries go
    /// first, then the oldest, and the window for the DIDs it keeps holds.
    #[test]
    fn a_full_floor_never_refuses_a_new_did() {
        let floor = RefreshFloor::new(3);
        let t0 = Instant::now();
        assert!(floor.admit("did:web:a", t0));
        assert!(floor.admit("did:web:b", t0 + Duration::from_millis(1)));
        assert!(floor.admit("did:web:c", t0 + Duration::from_millis(2)));
        // All live: the oldest ("a") is forgotten and the newcomer admitted.
        let t1 = t0 + Duration::from_millis(3);
        assert!(floor.admit("did:web:d", t1));
        assert!(!floor.tracks("did:web:a"));
        assert!(!floor.admit("did:web:b", t1), "b's window still holds");
        assert!(!floor.admit("did:web:d", t1), "d's window still holds");
        // Once windows pass, expired entries are pruned before anything live.
        let t2 = t0 + FRESH_RESOLVE_MIN_INTERVAL + Duration::from_millis(2);
        assert!(floor.admit("did:web:e", t2));
        assert!(floor.tracks("did:web:d"), "d was live, so it was kept");
        assert!(floor.admit("did:web:b", t2), "b's window has passed");
    }

    /// Before the first unpack attempt, only a sender with a cached document
    /// is chosen for a retry; an uncached `skid` gets none.
    #[cfg(feature = "didcomm")]
    #[tokio::test]
    async fn only_a_cached_sender_is_a_retry_target() {
        use base64::Engine;
        let jwe_from = |did: &str| {
            let header =
                serde_json::json!({ "alg": "ECDH-1PU+A256KW", "skid": format!("{did}#key-1") });
            let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).unwrap());
            serde_json::json!({ "protected": protected, "ciphertext": "x" }).to_string()
        };
        let cached = unique_did("cached-sender");
        let fresh = unique_did("fresh-sender");
        let resolver = resolver_caching(&[&cached]).await;
        assert_eq!(
            refresh_target(&resolver, &jwe_from(&cached)).as_deref(),
            Some(cached.as_str())
        );
        assert_eq!(refresh_target(&resolver, &jwe_from(&fresh)), None);
    }

    /// A cached document that lists the method is used as it is; one that
    /// does not is re-resolved once, fresh (VTI-KEY-134).
    #[tokio::test]
    async fn a_cached_document_missing_the_method_is_re_resolved() {
        use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
        let mut resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        // A did:key resolves locally, so "fresh" is deterministic: seed the
        // cache with a stale copy that lists no methods at all.
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let fresh = resolver.resolve(did).await.unwrap().doc;
        let vm = fresh.verification_method[0].id.to_string();
        let mut stale = fresh.clone();
        stale.verification_method.clear();
        resolver.add_did_document(did, stale).await;
        let before = resolver.resolve(did).await.unwrap();
        assert!(before.cache_hit && before.doc.verification_method.is_empty());

        let resolved = resolve_for_vm(&resolver, did, &vm).await.unwrap();
        assert!(!resolved.cache_hit, "re-resolved rather than served stale");
        assert!(
            resolved
                .doc
                .verification_method
                .iter()
                .any(|m| m.id.as_str() == vm)
        );
    }
}
