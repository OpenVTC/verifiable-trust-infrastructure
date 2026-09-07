//! TTL cache in front of a [`SeedStore`] backend.
//!
//! ## Why
//!
//! The BIP-32 master seed is read on **every** key-touching request. The read
//! goes through `vta_keys::seeds::load_seed_bytes`, which has ~25 call sites
//! covering the signing oracle, key mint/rotate/list, the holder-key paths and
//! every `did:webvh` lifecycle operation — and it calls [`SeedStore::get`]
//! unconditionally, with no memoization.
//!
//! On the local backends (keyring, plaintext, config-seed, TEE) that is cheap.
//! On the cloud backends it is a network round trip per request, and for AWS it
//! is also a *billed* one: every `GetSecretValue` is one KMS `Decrypt` against
//! the key protecting the secret. Uncached, KMS request volume scales with
//! request volume. A VTA sustaining ~22 requests/second bills ~58M KMS requests
//! a month for nothing but re-reading a value that did not change.
//!
//! This decorator makes the seed read scale with wall-clock time instead. At
//! the 60-second default that same VTA makes ~43k backend reads a month.
//!
//! ## What makes it safe
//!
//! The seed for a generation is immutable — it changes only on rotation. So the
//! cache is not gambling on a value that drifts; it is skipping a re-read of a
//! constant. The invariants that keep it honest:
//!
//! - **Writes invalidate.** [`set`](SeedStore::set) and
//!   [`delete`](SeedStore::delete) bump a generation counter and drop the entry.
//!   This is load-bearing, not hygiene: `vta_service::operations::seeds::
//!   rotate_seed` calls `rotate_seed` (which writes the new seed) and then
//!   *immediately* re-reads it to re-encrypt every imported secret. Serving a
//!   stale seed there would re-encrypt them under the wrong key.
//! - **A read in flight across a write is discarded.** A concurrent `get` that
//!   started before a `set` may observe the pre-write value; the generation
//!   counter is re-checked before its result is stored, so it can never install
//!   a superseded seed for a full TTL. This matters because signing requests
//!   run concurrently with rotation.
//! - **Only success is cached.** A missing secret (`Ok(None)`) and every error
//!   are passed straight through. Caching `None` would make a transient backend
//!   outage indistinguishable from an unprovisioned VTA for the whole TTL, and
//!   would race first-boot provisioning.
//! - **The cached copy is zeroized** on eviction and on drop, preserving P0.7.
//!   The TTL doubles as the bound on how long the seed sits resident.
//!
//! Nothing here defends against an *out-of-process* writer, because there is no
//! supported topology with one: runtime rotation is in-process under
//! `ROTATE_LOCK`, and the offline `vta` CLI surfaces require the daemon stopped.

use std::future::Future;
use std::pin::Pin;

use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::debug;
use vti_common::error::AppError;
use zeroize::Zeroizing;

use super::SeedStore;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A cached seed plus the instant it stops being servable.
struct CacheEntry {
    /// Wiped on eviction and on drop (P0.7).
    seed: Zeroizing<Vec<u8>>,
    expires_at: Instant,
}

/// Cache state. `generation` increments on every write so a read that raced a
/// write can tell that its result is stale and decline to store it.
struct CacheState {
    entry: Option<CacheEntry>,
    generation: u64,
}

/// Wraps a [`SeedStore`], serving `get` from memory for up to a TTL.
///
/// Built by [`create_seed_store`](super::create_seed_store) when
/// `secrets.cache_ttl_secs` is non-zero; a zero TTL returns the bare backend
/// rather than a decorator that would never hit.
pub struct CachingSeedStore {
    inner: Box<dyn SeedStore>,
    ttl: Duration,
    state: RwLock<CacheState>,
}

impl CachingSeedStore {
    /// Wrap `inner`, serving reads from memory for `ttl`.
    ///
    /// A zero `ttl` produces a cache that never serves a hit (every entry is
    /// already expired when stored). Callers that want no caching should skip
    /// the wrapper entirely — see `create_seed_store`.
    pub fn new(inner: Box<dyn SeedStore>, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            state: RwLock::new(CacheState {
                entry: None,
                generation: 0,
            }),
        }
    }

    /// Drop any cached seed and bump the generation, so a read already in
    /// flight cannot install its (now superseded) result.
    async fn invalidate(&self) {
        let mut state = self.state.write().await;
        // `Zeroizing` wipes the bytes as the entry drops.
        state.entry = None;
        state.generation = state.generation.wrapping_add(1);
    }
}

impl SeedStore for CachingSeedStore {
    fn get(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            // Fast path: a live entry. The read lock is released before the
            // (possible) backend call below — never held across an await (R1.3).
            let generation_at_start = {
                let state = self.state.read().await;
                if let Some(ref entry) = state.entry
                    && Instant::now() < entry.expires_at
                {
                    return Ok(Some(entry.seed.to_vec()));
                }
                state.generation
            };

            let fetched = self.inner.get().await?;

            let Some(seed) = fetched else {
                // Absent secret: pass through, and drop any expired entry so a
                // deleted secret doesn't linger. Never cached — see module docs.
                let mut state = self.state.write().await;
                state.entry = None;
                return Ok(None);
            };

            {
                let mut state = self.state.write().await;
                if state.generation == generation_at_start {
                    state.entry = Some(CacheEntry {
                        seed: Zeroizing::new(seed.clone()),
                        expires_at: Instant::now() + self.ttl,
                    });
                } else {
                    // A write landed while this read was in flight. The value
                    // in hand may predate it, so return it to *this* caller but
                    // do not install it for anyone else.
                    debug!("seed read raced a write — returning the value but not caching it");
                }
            }

            Ok(Some(seed))
        })
    }

    fn set(&self, secret: &[u8]) -> BoxFuture<'_, Result<(), AppError>> {
        let secret = secret.to_vec();
        Box::pin(async move {
            // Invalidate on both sides of the write. Before, so no reader is
            // served the old value once the write has begun; after, so the
            // entry is gone even if the write failed partway.
            self.invalidate().await;
            let result = self.inner.set(&secret).await;
            self.invalidate().await;
            result
        })
    }

    fn delete(&self) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            self.invalidate().await;
            let result = self.inner.delete().await;
            self.invalidate().await;
            result
        })
    }

    fn set_persists_across_restart(&self) -> bool {
        // A property of the backing store, not of the cache in front of it.
        // Getting this wrong would let seed rotation proceed on a TEE store.
        self.inner.set_persists_across_restart()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A backend that counts reads, so a test can assert how many times the
    /// cache actually went to the store.
    struct CountingStore {
        seed: std::sync::Mutex<Option<Vec<u8>>>,
        reads: Arc<AtomicUsize>,
    }

    impl CountingStore {
        fn new(seed: Option<Vec<u8>>) -> (Self, Arc<AtomicUsize>) {
            let reads = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    seed: std::sync::Mutex::new(seed),
                    reads: reads.clone(),
                },
                reads,
            )
        }
    }

    impl SeedStore for CountingStore {
        fn get(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
            Box::pin(async {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Ok(self.seed.lock().expect("seed lock").clone())
            })
        }

        fn set(&self, secret: &[u8]) -> BoxFuture<'_, Result<(), AppError>> {
            let secret = secret.to_vec();
            Box::pin(async move {
                *self.seed.lock().expect("seed lock") = Some(secret);
                Ok(())
            })
        }

        fn delete(&self) -> BoxFuture<'_, Result<(), AppError>> {
            Box::pin(async {
                *self.seed.lock().expect("seed lock") = None;
                Ok(())
            })
        }
    }

    fn cache(seed: Option<Vec<u8>>, ttl_secs: u64) -> (CachingSeedStore, Arc<AtomicUsize>) {
        let (inner, reads) = CountingStore::new(seed);
        (
            CachingSeedStore::new(Box::new(inner), Duration::from_secs(ttl_secs)),
            reads,
        )
    }

    /// The whole point: repeated reads inside the TTL cost one backend call.
    /// On the AWS backend each avoided call is one avoided billed KMS Decrypt.
    #[tokio::test(start_paused = true)]
    async fn repeated_reads_within_ttl_hit_the_backend_once() {
        let (store, reads) = cache(Some(vec![7u8; 32]), 60);

        for _ in 0..50 {
            assert_eq!(store.get().await.expect("get"), Some(vec![7u8; 32]));
        }

        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "50 reads inside the TTL must consult the backend exactly once"
        );
    }

    /// The TTL is an upper bound on staleness, so it must actually expire.
    #[tokio::test(start_paused = true)]
    async fn read_after_ttl_consults_the_backend_again() {
        let (store, reads) = cache(Some(vec![1u8; 32]), 60);

        store.get().await.expect("first get");
        tokio::time::advance(Duration::from_secs(61)).await;
        store.get().await.expect("second get");

        assert_eq!(
            reads.load(Ordering::SeqCst),
            2,
            "a read past the TTL must go back to the backend"
        );
    }

    /// Load-bearing, not hygiene. `operations::seeds::rotate_seed` writes the
    /// new seed and then immediately re-reads it to re-encrypt every imported
    /// secret; a cache that survived the write would hand back the *old* seed
    /// and silently re-encrypt them under the wrong key.
    #[tokio::test(start_paused = true)]
    async fn write_then_read_returns_the_new_seed_not_the_cached_one() {
        let (store, _reads) = cache(Some(vec![0xAA; 32]), 3600);

        assert_eq!(store.get().await.expect("prime"), Some(vec![0xAA; 32]));
        store.set(&[0xBB; 32]).await.expect("set");

        assert_eq!(
            store.get().await.expect("read back"),
            Some(vec![0xBB; 32]),
            "the read after a write must observe the written seed, even well \
             inside the TTL — this is the seed-rotation re-encryption path"
        );
    }

    /// A delete must not leave the seed servable from memory.
    #[tokio::test(start_paused = true)]
    async fn delete_invalidates_the_cached_seed() {
        let (store, _reads) = cache(Some(vec![0xCC; 32]), 3600);

        store.get().await.expect("prime");
        store.delete().await.expect("delete");

        assert_eq!(
            store.get().await.expect("read back"),
            None,
            "a deleted seed must not keep being served from the cache"
        );
    }

    /// Caching `None` would make a transient backend outage look like an
    /// unprovisioned VTA for the whole TTL (`load_seed_bytes` renders it as
    /// "no seed found in external store") and would race first-boot setup.
    #[tokio::test(start_paused = true)]
    async fn absent_seed_is_never_cached() {
        let (store, reads) = cache(None, 3600);

        for _ in 0..3 {
            assert_eq!(store.get().await.expect("get"), None);
        }

        assert_eq!(
            reads.load(Ordering::SeqCst),
            3,
            "a missing secret must be re-checked every time, never cached"
        );
    }

    /// A store that cannot durably persist a rotated seed (the TEE KMS store)
    /// must still report that through the wrapper — `rotate_seed` refuses on
    /// this, and a wrapper answering `true` would let rotation proceed and
    /// strand every key minted afterwards.
    #[tokio::test(start_paused = true)]
    async fn persistence_flag_is_delegated_to_the_backend() {
        struct Ephemeral;
        impl SeedStore for Ephemeral {
            fn get(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
                Box::pin(async { Ok(None) })
            }
            fn set(&self, _: &[u8]) -> BoxFuture<'_, Result<(), AppError>> {
                Box::pin(async { Ok(()) })
            }
            fn set_persists_across_restart(&self) -> bool {
                false
            }
        }

        let store = CachingSeedStore::new(Box::new(Ephemeral), Duration::from_secs(60));
        assert!(
            !store.set_persists_across_restart(),
            "the wrapper must not claim durability the backend disclaims"
        );
    }
}
