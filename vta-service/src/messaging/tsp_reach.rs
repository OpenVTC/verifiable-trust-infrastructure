//! Learn-from-inbound TSP reachability for device push.
//!
//! A `did:key` device can't advertise a `#tsp` service in a document, and it
//! picks its inbox transport at runtime (the mobile app's DIDComm/TSP toggle),
//! so the VTA can't discover from the document whether a device is *currently*
//! reachable over TSP. Instead it **learns from inbound**: TSP `unpack_bytes`
//! yields a cryptographically-proven `sender_vid`, so any TSP frame a device
//! sends the VTA is proof that DID is, right now, listening on TSP. The inbound
//! dispatcher records that here; the device-push paths read it to prefer TSP
//! over DIDComm for a recently-seen DID.
//!
//! Runtime state only — in-memory, per-process, self-expiring. It never
//! persists: on restart the map is empty and devices re-announce on their next
//! inbound frame, which is exactly the safe default (fall back to DIDComm until
//! we have fresh proof of TSP reachability). The TTL bounds how long a stale
//! entry can misroute after a device flips back to DIDComm — a TSP frame sent
//! to a DID no longer listening on TSP is accepted by the mediator but never
//! unpacked by the device, a silent miss with no error to fall back on, so the
//! window is deliberately short and the device re-announces well within it.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// How long a DID stays "TSP-reachable" after its last inbound TSP frame.
/// Short on purpose (see the module note): the device re-announces on every
/// inbox (re)connect, so a live device stays fresh, while a device that toggled
/// back to DIDComm decays to the DIDComm path within this window.
const TSP_REACH_TTL: Duration = Duration::from_secs(300);

/// In-memory record of which DIDs were last seen sending over TSP.
pub struct TspReachability {
    seen: RwLock<HashMap<String, Instant>>,
    ttl: Duration,
}

impl Default for TspReachability {
    fn default() -> Self {
        Self::new()
    }
}

impl TspReachability {
    /// Production constructor — the standard [`TSP_REACH_TTL`] window.
    pub fn new() -> Self {
        Self::with_ttl(TSP_REACH_TTL)
    }

    /// Construct with an explicit TTL. Used by tests to exercise expiry without
    /// waiting out the production window.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            seen: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Note that `did` just sent us a TSP frame — it is reachable over TSP now.
    /// Called with the **proven** `sender_vid` from TSP unpack, so it can't be
    /// spoofed into marking someone else reachable.
    pub fn record(&self, did: &str) {
        if let Ok(mut seen) = self.seen.write() {
            seen.insert(did.to_string(), Instant::now());
        }
    }

    /// Whether `did` sent a TSP frame within the TTL — i.e. push should prefer
    /// TSP for it. A poisoned lock or a missing/stale entry both read as "not
    /// fresh", so the caller safely falls back to DIDComm.
    pub fn fresh(&self, did: &str) -> bool {
        self.seen
            .read()
            .ok()
            .and_then(|seen| seen.get(did).map(|t| t.elapsed() < self.ttl))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_reads_back_fresh() {
        let r = TspReachability::new();
        assert!(!r.fresh("did:key:zDevice"));
        r.record("did:key:zDevice");
        assert!(r.fresh("did:key:zDevice"));
        assert!(!r.fresh("did:key:zOther"));
    }

    #[test]
    fn entry_expires_after_ttl() {
        // Tiny TTL so the record goes stale almost immediately — this is the
        // decay a device toggling back to DIDComm relies on for push to revert.
        let r = TspReachability::with_ttl(Duration::from_millis(20));
        r.record("did:key:zDevice");
        assert!(r.fresh("did:key:zDevice"), "fresh right after record");
        std::thread::sleep(Duration::from_millis(40));
        assert!(
            !r.fresh("did:key:zDevice"),
            "must go stale once the TTL elapses so push falls back to DIDComm"
        );
    }

    #[test]
    fn record_refreshes_the_window() {
        let r = TspReachability::with_ttl(Duration::from_millis(40));
        r.record("did:key:zDevice");
        std::thread::sleep(Duration::from_millis(25));
        // A re-announce before expiry resets the clock, so the device that keeps
        // announcing stays continuously TSP-reachable.
        r.record("did:key:zDevice");
        std::thread::sleep(Duration::from_millis(25));
        assert!(
            r.fresh("did:key:zDevice"),
            "re-record within the window keeps it fresh past the original expiry"
        );
    }
}
