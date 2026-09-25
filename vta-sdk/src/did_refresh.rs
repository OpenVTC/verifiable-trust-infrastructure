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

/// Most DIDs tracked for [`FRESH_RESOLVE_MIN_INTERVAL`] before stale entries
/// are pruned — bounds the table an attacker naming many DIDs could grow.
const FRESH_RESOLVE_TRACKED_MAX: usize = 4096;

static LAST_FRESH_RESOLVE: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Evict `did` from `resolver`'s cache so its next resolution fetches the
/// current document — VTI-KEY-062's means of forcing re-resolution.
///
/// Returns `false`, evicting nothing, when the same DID was force-refreshed
/// within [`FRESH_RESOLVE_MIN_INTERVAL`]; the document in the cache is then at
/// most that old, so refetching it would buy nothing but load.
///
/// Every clone of a [`DIDCacheClient`] shares one cache, so this evicts for all
/// of them. In network mode it clears only the local cache; a remote resolver
/// may still answer from its own.
pub async fn evict_for_fresh_resolve(resolver: &DIDCacheClient, did: &str) -> bool {
    {
        let now = Instant::now();
        let mut last = LAST_FRESH_RESOLVE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if last
            .get(did)
            .is_some_and(|t| now.duration_since(*t) < FRESH_RESOLVE_MIN_INTERVAL)
        {
            return false;
        }
        if last.len() >= FRESH_RESOLVE_TRACKED_MAX {
            last.retain(|_, t| now.duration_since(*t) < FRESH_RESOLVE_MIN_INTERVAL);
            if last.len() >= FRESH_RESOLVE_TRACKED_MAX {
                // Every entry is live: a flood across many DIDs. Refuse rather
                // than forget the window, which would reopen the amplification.
                return false;
            }
        }
        last.insert(did.to_string(), now);
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
/// The refresh is rate-limited per DID ([`FRESH_RESOLVE_MIN_INTERVAL`]); a
/// body naming no sender, or a sender refreshed moments ago, gets the first
/// error unchanged.
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
    let first = match atm.unpack(body).await {
        Ok(unpacked) => return Ok(unpacked),
        Err(e) => e,
    };
    let (Some(resolver), Some(sender)) = (resolver, authcrypt_claimed_sender(body)) else {
        return Err(first);
    };
    if !evict_for_fresh_resolve(resolver, &sender).await {
        return Err(first);
    }
    atm.unpack(body).await
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

    /// The refresh floor: a second forced re-resolution of the same DID inside
    /// the window evicts nothing, so a stream of failing proofs costs at most
    /// one fetch per DID per window.
    #[tokio::test]
    async fn a_forced_refresh_is_rate_limited_per_did() {
        use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let did = format!("did:web:refresh-floor-{}.example", std::process::id());
        assert!(
            evict_for_fresh_resolve(&resolver, &did).await,
            "first refresh"
        );
        assert!(
            !evict_for_fresh_resolve(&resolver, &did).await,
            "a second refresh inside the window is refused"
        );
        let other = format!("{did}.other");
        assert!(
            evict_for_fresh_resolve(&resolver, &other).await,
            "the floor is per DID"
        );
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
