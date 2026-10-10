//! Per-key locks that make the vsock store's multi-step operations atomic.
//!
//! The enclave reaches its store through the parent's storage proxy, which
//! serves single operations only (get, insert, delete, …). `take_raw`,
//! `insert_if_absent`, `swap` and `move_if_unchanged` are therefore sequences
//! of round trips, and without a lock two callers interleave inside them: two
//! presenters of one refresh token both read it before either deletes it, and
//! both rotate (RFC 9700 §4.14.2 reuse detection defeated).
//!
//! The local store closes the same gap with a per-keyspace lock held across
//! each multi-step closure (see `WriteLocks` in `super`). This is its vsock
//! counterpart, with one difference: the lock is per *key* (hashed onto a
//! fixed set of stripes), because a vsock round trip is far longer than a
//! local fjall call and a keyspace-wide lock would serialise unrelated claims.
//!
//! What it guarantees is what the local store guarantees: two multi-step
//! operations on the same key never interleave. Plain `insert`/`remove` do not
//! take it, on either store.
//!
//! It does not rely on the parent behaving. The enclave is the only writer to
//! its store, so excluding its own concurrent callers is the whole of
//! atomicity here; a parent that misbehaves can deny service or replay, which
//! the integrity manifest and anti-rollback anchor address, but it cannot make
//! one enclave claim succeed twice.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use tokio::sync::{Mutex, OwnedMutexGuard};

/// Number of lock stripes. Two keys that hash to one stripe wait for each
/// other — a lost opportunity for concurrency, never a correctness problem.
/// 64 keeps that rare at the enclave's concurrency (tens of in-flight
/// requests) for 64 small mutexes.
const STRIPES: usize = 64;

/// Striped per-key locks, shared by every handle a vsock store hands out.
pub(crate) struct KeyLocks {
    stripes: Vec<Arc<Mutex<()>>>,
}

/// Holds the stripes of one multi-step operation until dropped.
#[must_use = "the lock is released when the guard is dropped"]
pub(crate) struct KeyGuard {
    _held: Vec<OwnedMutexGuard<()>>,
}

impl Default for KeyLocks {
    fn default() -> Self {
        Self {
            stripes: (0..STRIPES).map(|_| Arc::new(Mutex::new(()))).collect(),
        }
    }
}

impl KeyLocks {
    fn stripe(keyspace: &str, key: &[u8]) -> usize {
        // SipHash with fixed keys: deterministic, and the input is ours, so
        // there is nothing to flood.
        let mut h = std::collections::hash_map::DefaultHasher::new();
        keyspace.hash(&mut h);
        key.hash(&mut h);
        (h.finish() as usize) % STRIPES
    }

    /// Lock every key an operation touches (`swap` touches two).
    ///
    /// Stripes are taken in ascending order, once each, so two operations
    /// over overlapping keys can never deadlock, and an operation whose two
    /// keys share a stripe does not wait for itself.
    pub(crate) async fn lock(&self, keyspace: &str, keys: &[&[u8]]) -> KeyGuard {
        let mut idx: Vec<usize> = keys.iter().map(|k| Self::stripe(keyspace, k)).collect();
        idx.sort_unstable();
        idx.dedup();
        let mut held = Vec::with_capacity(idx.len());
        for i in idx {
            held.push(Arc::clone(&self.stripes[i]).lock_owned().await);
        }
        KeyGuard { _held: held }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn same_key_excludes() {
        let locks = Arc::new(KeyLocks::default());
        let g = locks.lock("ks", &[b"k"]).await;
        let l2 = locks.clone();
        let waiter = tokio::spawn(async move {
            let _g = l2.lock("ks", &[b"k"]).await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !waiter.is_finished(),
            "second lock on the same key must wait"
        );
        drop(g);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("released")
            .unwrap();
    }

    #[tokio::test]
    async fn two_keys_on_one_stripe_do_not_self_deadlock() {
        let locks = KeyLocks::default();
        // The same key twice is the extreme case of a shared stripe.
        let _g = tokio::time::timeout(Duration::from_secs(1), locks.lock("ks", &[b"a", b"a"]))
            .await
            .expect("an operation never waits for itself");
    }

    #[tokio::test]
    async fn crossed_two_key_operations_do_not_deadlock() {
        // swap(a -> b) and swap(b -> a) at once: ordered acquisition means one
        // simply waits for the other.
        let locks = Arc::new(KeyLocks::default());
        let mut tasks = Vec::new();
        for i in 0..200u32 {
            let l = locks.clone();
            tasks.push(tokio::spawn(async move {
                let (x, y) = if i % 2 == 0 {
                    (b"a", b"b")
                } else {
                    (b"b", b"a")
                };
                let _g = l.lock("ks", &[x, y]).await;
                tokio::task::yield_now().await;
            }));
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            for t in tasks {
                t.await.unwrap();
            }
        })
        .await
        .expect("no deadlock");
    }
}
