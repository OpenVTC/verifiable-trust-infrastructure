//! The per-binding issuance rate (`AccountBinding.ratePerMinute`).
//!
//! A fixed one-minute window per `(context, account, consumer)`, held in
//! memory. A restart resets every window, which errs toward allowing a burst
//! after a restart — acceptable for a limit whose job is to make a compromised
//! consumer's minting visible and bounded, not to meter billing.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);

/// `(context, account, consumer)`.
type BindingKey = (String, String, String);

/// Issuance counters, one fixed window per binding.
#[derive(Default)]
pub struct BindingRateLimiter {
    windows: Mutex<HashMap<BindingKey, (Instant, u32)>>,
}

impl BindingRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one issuance against the binding; `false` when its rate is
    /// exhausted for the current window. Never held across an await.
    pub fn try_acquire(
        &self,
        context: &str,
        account: &str,
        consumer: &str,
        per_minute: u32,
    ) -> bool {
        self.try_acquire_at(context, account, consumer, per_minute, Instant::now())
    }

    fn try_acquire_at(
        &self,
        context: &str,
        account: &str,
        consumer: &str,
        per_minute: u32,
        now: Instant,
    ) -> bool {
        let mut windows = self.windows.lock().unwrap_or_else(|p| p.into_inner());
        // Drop windows that have closed, so the map holds active bindings only.
        windows.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
        let entry = windows
            .entry((
                context.to_string(),
                account.to_string(),
                consumer.to_string(),
            ))
            .or_insert((now, 0));
        if entry.1 >= per_minute {
            return false;
        }
        entry.1 += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binding_gets_its_rate_and_no_more_until_the_window_closes() {
        let l = BindingRateLimiter::new();
        let t0 = Instant::now();
        assert!(l.try_acquire_at("c", "a", "did:x", 2, t0));
        assert!(l.try_acquire_at("c", "a", "did:x", 2, t0));
        assert!(!l.try_acquire_at("c", "a", "did:x", 2, t0));
        // Another consumer of the same account has its own window.
        assert!(l.try_acquire_at("c", "a", "did:y", 2, t0));
        assert!(l.try_acquire_at("c", "a", "did:x", 2, t0 + WINDOW));
    }
}
