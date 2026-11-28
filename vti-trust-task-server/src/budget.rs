//! Operation budgets on Trust Task work (VTI-TRN-029: "A node MUST bound the
//! resources any one subject can consume, and MUST bound those available to
//! unauthenticated peers separately"), shared by every VTI node.
//!
//! Three token buckets:
//!
//! | Bucket | Charged to | Absent |
//! |---|---|---|
//! | node | every client with standing, together | unbounded |
//! | per subject | each client with standing, by its DID | the service's default |
//! | unauthenticated | every sender without standing, together | the service's default |
//!
//! The two VTI-TRN-029 requires are always on; nothing here turns one off. A client
//! with standing is charged to its own bucket first and then the node's, so one
//! client's excess is refused before it can spend the budget the others share. A
//! sender without standing is charged to the unauthenticated bucket only, so
//! strangers never spend what clients need.
//!
//! What a task costs (its weight, in signs) is the service's: it is a property of
//! the service's code. The budgets are the service's configuration. This module is
//! the buckets, the clock and the refusal; each service decides who has standing
//! and where in its pipeline the charge falls — always after the caller is proven
//! and before the task runs, so a refused document is not recorded and resending it
//! is a retry (VTI-OPS-026). The spine charges at that point when given a
//! [`BudgetCharge`] ([`crate::Spine::with_budget`]).

use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use governor::clock::Clock;
use governor::middleware::NoOpMiddleware;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

/// At most one warning per bucket per this many seconds while it refuses work. A
/// node shedding load refuses hundreds of requests a second, and a line for each
/// would make logging part of the overload.
const WARN_EVERY_SECS: u64 = 60;

/// How many per-subject charges pass between sweeps of idle subjects' buckets, so
/// the map holds the clients active now, not every DID ever seen.
const SWEEP_EVERY: u64 = 4096;

/// The clock the budgets read: the monotonic clock, or one a test moves by hand, so
/// a test of a budget never depends on how fast it runs.
#[derive(Clone, Debug, Default)]
pub struct BudgetClock(Option<Arc<ManualTime>>);

#[derive(Debug)]
struct ManualTime {
    start: Instant,
    elapsed_nanos: AtomicU64,
}

impl BudgetClock {
    /// A clock that stands still until [`Self::advance`] moves it.
    pub fn manual() -> Self {
        Self(Some(Arc::new(ManualTime {
            start: Instant::now(),
            elapsed_nanos: AtomicU64::new(0),
        })))
    }

    /// Move a [`Self::manual`] clock forward. The monotonic clock is not moved.
    pub fn advance(&self, by: Duration) {
        if let Some(t) = &self.0 {
            let nanos = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
            t.elapsed_nanos.fetch_add(nanos, Ordering::Relaxed);
        }
    }
}

impl Clock for BudgetClock {
    type Instant = Instant;

    fn now(&self) -> Instant {
        match &self.0 {
            None => Instant::now(),
            Some(t) => t.start + Duration::from_nanos(t.elapsed_nanos.load(Ordering::Relaxed)),
        }
    }
}

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, BudgetClock, NoOpMiddleware<Instant>>;
type KeyedLimiter =
    RateLimiter<String, DefaultKeyedStateStore<String>, BudgetClock, NoOpMiddleware<Instant>>;

/// Who a request is charged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller<'a> {
    /// A client with standing, by its DID.
    Client(&'a str),
    /// A sender without standing.
    Unauthenticated,
}

/// Which bucket refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The node's budget, shared by every client with standing.
    Appliance,
    /// One client's own budget.
    Subject,
    /// The budget every sender without standing shares.
    Unauthenticated,
}

impl Scope {
    /// The name a refusal and the metric carry: `operations`, `operations-subject`
    /// or `operations-unauthenticated`.
    pub fn name(self) -> &'static str {
        match self {
            Scope::Appliance => "operations",
            Scope::Subject => "operations-subject",
            Scope::Unauthenticated => "operations-unauthenticated",
        }
    }
}

/// A request a budget refused, which one, and when it will next have room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    /// The bucket that refused.
    pub scope: Scope,
    /// How long until it has room for this request.
    pub retry_after: Duration,
}

impl Refused {
    /// Whole seconds, rounded up and at least 1: a client honouring it must not come
    /// back before the budget has room.
    pub fn retry_after_secs(self) -> u64 {
        let d = self.retry_after;
        let secs = d.as_secs() + u64::from(d.subsec_nanos() > 0);
        secs.max(1)
    }
}

/// The budgets a service configures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetConfig {
    /// The node budget, operations per second; `None` is unbounded.
    pub per_sec: Option<u32>,
    /// The node budget's burst; defaults to one second's worth.
    pub burst: Option<u32>,
    /// Each client's budget, operations per second. Always bounded: a zero is read
    /// as one, never as no bound.
    pub per_subject_per_sec: u32,
    /// The budget for senders without standing, operations per second. Always
    /// bounded, as `per_subject_per_sec`.
    pub unauthenticated_per_sec: u32,
}

/// What the service tells the budgets about its own tasks and logs.
#[derive(Debug, Clone, Copy)]
pub struct BudgetSpec {
    /// What a task costs, in signs, by its Type URI (a fragment is stripped before
    /// it is asked). At least 1 and at most `max_weight`.
    pub weight: fn(&str) -> u32,
    /// The heaviest weight `weight` answers. No burst is below it, or that task
    /// could never be served.
    pub max_weight: u32,
    /// The counter a refusal increments, labelled by `scope`.
    pub metric: &'static str,
    /// Where an operator reads about the budgets, named in the warning.
    pub config_hint: &'static str,
}

/// The quota a `per_sec` / `burst` pair configures, or `None` without a rate.
fn quota(per_sec: Option<u32>, burst: Option<u32>, max_weight: u32) -> Option<Quota> {
    let per_sec = NonZeroU32::new(per_sec?)?;
    let burst = burst.unwrap_or(per_sec.get()).max(max_weight).max(1);
    let burst = NonZeroU32::new(burst).expect("burst is at least 1");
    Some(Quota::per_second(per_sec).allow_burst(burst))
}

fn refusal(
    checked: Result<Result<(), governor::NotUntil<Instant>>, governor::InsufficientCapacity>,
    clock: &BudgetClock,
    scope: Scope,
) -> Result<(), Refused> {
    match checked {
        Ok(Ok(())) => Ok(()),
        Ok(Err(not_until)) => Err(Refused {
            scope,
            retry_after: not_until.wait_time_from(clock.now()),
        }),
        // Unreachable while every burst is at least the heaviest weight; refused with
        // a one-second hint rather than admitted, should a weight outgrow it.
        Err(_) => Err(Refused {
            scope,
            retry_after: Duration::from_secs(1),
        }),
    }
}

/// Throttles a bucket's warning to one per [`WARN_EVERY_SECS`].
#[derive(Default)]
struct Warning {
    refused_since: AtomicU64,
    last_secs: AtomicU64,
}

impl Warning {
    fn note(&self, scope: Scope, hint: &str) {
        let count = self.refused_since.fetch_add(1, Ordering::Relaxed) + 1;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let last = self.last_secs.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= WARN_EVERY_SECS
            && self
                .last_secs
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.refused_since.fetch_sub(count, Ordering::Relaxed);
            tracing::warn!(
                scope = scope.name(),
                refused = count,
                "operation budget exhausted: refusing Trust Tasks (see {hint})"
            );
        }
    }
}

/// The budgets in force for one generation of a service.
pub struct OperationBudget {
    spec: BudgetSpec,
    clock: BudgetClock,
    appliance: Option<DirectLimiter>,
    per_subject: KeyedLimiter,
    unauthenticated: DirectLimiter,
    subject_charges: AtomicU64,
    appliance_warning: Warning,
    subject_warning: Warning,
    unauthenticated_warning: Warning,
}

impl OperationBudget {
    /// The budgets `config` sets, costed by `spec`, on `clock`.
    pub fn new(config: BudgetConfig, spec: BudgetSpec, clock: BudgetClock) -> Self {
        let max_weight = spec.max_weight.max(1);
        // A zero is refused at load by every service; should one get here, it is
        // bounded as tightly as a rate can be rather than read as no bound.
        let bounded = |per_sec: u32| {
            quota(Some(per_sec.max(1)), None, max_weight).expect("a rate of at least 1 has a quota")
        };
        tracing::info!(
            appliance_per_sec = config.per_sec,
            per_subject_per_sec = config.per_subject_per_sec,
            unauthenticated_per_sec = config.unauthenticated_per_sec,
            "operation budgets in force for Trust Tasks"
        );
        Self {
            appliance: quota(config.per_sec, config.burst, max_weight)
                .map(|q| RateLimiter::direct_with_clock(q, clock.clone())),
            per_subject: RateLimiter::new(
                bounded(config.per_subject_per_sec),
                DefaultKeyedStateStore::default(),
                clock.clone(),
            ),
            unauthenticated: RateLimiter::direct_with_clock(
                bounded(config.unauthenticated_per_sec),
                clock.clone(),
            ),
            spec,
            clock,
            subject_charges: AtomicU64::default(),
            appliance_warning: Warning::default(),
            subject_warning: Warning::default(),
            unauthenticated_warning: Warning::default(),
        }
    }

    /// What `type_uri` costs under this budget's spec.
    pub fn weight(&self, type_uri: &str) -> u32 {
        let bare = type_uri.split('#').next().unwrap_or(type_uri);
        (self.spec.weight)(bare).clamp(1, self.spec.max_weight.max(1))
    }

    /// Charge one request for `type_uri` from `caller`.
    ///
    /// A client is charged to its own share first, then to the node budget. Tokens
    /// are taken on success and never returned, so when the node refuses, the
    /// client's share has still been spent; the other order would let one client's
    /// excess spend the budget every client shares, which is the worse failure.
    pub fn charge(&self, caller: Caller<'_>, type_uri: &str) -> Result<(), Refused> {
        let cost = NonZeroU32::new(self.weight(type_uri)).expect("every weight is at least 1");
        let result = match caller {
            Caller::Client(did) => {
                self.charge_subject(did, cost)
                    .and_then(|()| match &self.appliance {
                        None => Ok(()),
                        Some(limiter) => {
                            refusal(limiter.check_n(cost), &self.clock, Scope::Appliance)
                        }
                    })
            }
            Caller::Unauthenticated => refusal(
                self.unauthenticated.check_n(cost),
                &self.clock,
                Scope::Unauthenticated,
            ),
        };
        if let Err(refused) = result {
            metrics::counter!(self.spec.metric, "scope" => refused.scope.name()).increment(1);
            match refused.scope {
                Scope::Appliance => &self.appliance_warning,
                Scope::Subject => &self.subject_warning,
                Scope::Unauthenticated => &self.unauthenticated_warning,
            }
            .note(refused.scope, self.spec.config_hint);
        }
        result
    }

    fn charge_subject(&self, did: &str, cost: NonZeroU32) -> Result<(), Refused> {
        let limiter = &self.per_subject;
        if self.subject_charges.fetch_add(1, Ordering::Relaxed) % SWEEP_EVERY == SWEEP_EVERY - 1 {
            limiter.retain_recent();
            limiter.shrink_to_fit();
        }
        refusal(
            limiter.check_key_n(&did.to_string(), cost),
            &self.clock,
            Scope::Subject,
        )
    }
}

/// A service's charge for a document whose proof has verified, asked by the spine
/// once the signer is proven and before the duplicate-execution record is claimed
/// ([`crate::Spine::with_budget`]). The service decides the signer's standing
/// (whether it is a client of the service) and charges its [`OperationBudget`].
#[async_trait::async_trait]
pub trait BudgetCharge: Send + Sync {
    /// Charge one request for `type_uri` by the verified `signer`.
    async fn charge_verified(&self, signer: &str, type_uri: &str) -> Result<(), Refused>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weight(uri: &str) -> u32 {
        if uri.ends_with("heavy/0.1") { 10 } else { 1 }
    }

    const SPEC: BudgetSpec = BudgetSpec {
        weight,
        max_weight: 10,
        metric: "test_operation_budget_refused_total",
        config_hint: "the test",
    };

    fn budget(per_sec: Option<u32>, subject: u32, anon: u32) -> OperationBudget {
        OperationBudget::new(
            BudgetConfig {
                per_sec,
                burst: None,
                per_subject_per_sec: subject,
                unauthenticated_per_sec: anon,
            },
            SPEC,
            BudgetClock::manual(),
        )
    }

    #[test]
    fn a_client_is_bounded_alone_and_strangers_separately() {
        let b = budget(None, 10, 10);
        for _ in 0..10 {
            b.charge(Caller::Client("did:a"), "x/0.1").unwrap();
        }
        assert_eq!(
            b.charge(Caller::Client("did:a"), "x/0.1")
                .unwrap_err()
                .scope,
            Scope::Subject
        );
        b.charge(Caller::Client("did:b"), "x/0.1").unwrap();
        for _ in 0..10 {
            b.charge(Caller::Unauthenticated, "x/0.1").unwrap();
        }
        assert_eq!(
            b.charge(Caller::Unauthenticated, "x/0.1")
                .unwrap_err()
                .scope,
            Scope::Unauthenticated
        );
        b.charge(Caller::Client("did:c"), "x/0.1").unwrap();
    }

    #[test]
    fn weights_are_charged_and_a_fragment_does_not_change_them() {
        let b = budget(Some(10), 100, 10);
        assert_eq!(b.weight("a/heavy/0.1#request"), 10);
        b.charge(Caller::Client("did:a"), "a/heavy/0.1").unwrap();
        assert_eq!(
            b.charge(Caller::Client("did:a"), "x/0.1")
                .unwrap_err()
                .scope,
            Scope::Appliance
        );
    }

    #[test]
    fn retry_after_rounds_up() {
        let r = Refused {
            scope: Scope::Appliance,
            retry_after: Duration::from_millis(1_200),
        };
        assert_eq!(r.retry_after_secs(), 2);
        let r = Refused {
            scope: Scope::Appliance,
            retry_after: Duration::ZERO,
        };
        assert_eq!(r.retry_after_secs(), 1);
    }
}
