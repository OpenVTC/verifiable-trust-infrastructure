//! The VTA's resource bounds on Trust Task work (VTI-TRN-029: "A node MUST
//! bound the resources any one subject can consume, and MUST bound those
//! available to unauthenticated peers separately").
//!
//! Three token buckets, configured in `[server]`:
//!
//! | Bucket | Charged to | Key | Absent |
//! |---|---|---|---|
//! | appliance | every client with standing, together | `operation_rate_limit_per_sec` | unbounded |
//! | per subject | each client with standing, by its DID | `operation_rate_limit_per_subject_per_sec` | 100 a second |
//! | unauthenticated | every DIDComm / TSP sender without standing, together | `operation_rate_limit_unauthenticated_per_sec` | 50 a second |
//!
//! The two VTI-TRN-029 requires are always on: a VTA nobody sized still bounds
//! each client and its strangers, with defaults generous enough that only a
//! runaway client or a flood meets them. The appliance budget is what keeps an
//! instance below the load at which it stops answering, and its right value is
//! a property of the hardware, so it is the operator's to set.
//!
//! A client has standing when it authenticated with a session (REST bearer) or
//! has an ACL entry (a proven DIDComm / TSP sender). It is charged to its own
//! bucket first and then the appliance's, so one client's excess is refused
//! before it can spend the budget the others share, and the appliance budget
//! still bounds many clients together. A DIDComm / TSP sender without standing
//! — the login steps, a public task, a credential-exchange counterparty, an
//! approver — is charged to the unauthenticated bucket only, so strangers can
//! never spend what clients need. That budget is shared: one sender can use
//! it up and delay everyone else without standing, approvers and DIDComm / TSP
//! logins included, which is the cost of bounding strangers at all. Past it a
//! document gets no reply, so a flood cannot make the VTA sign one per message.
//! An anonymous REST request is not charged
//! here: the per-IP limiters in `routes::rate_limit` already bound it, which
//! DIDComm and TSP have no equivalent of.
//!
//! Every charge happens after the caller is proven and before the task runs,
//! in the REST route (`dispatch_trust_task`) and the DIDComm / TSP spine
//! (`accept_from_proven_sender`, and the pre-session auth family beside it).
//! The REST passkey-VM enrolment routes (the WebAuthn exception, admin-only)
//! are not Trust Tasks and are not charged. A
//! refused request has done no work beyond its authentication, which is the
//! point: without a bound an appliance offered more than it can serve stops
//! answering health checks and the watchdog restarts it, where with one it
//! refuses the excess and serves the rest.
//!
//! ## Weights
//!
//! A task is charged what it costs relative to a sign, measured on Nitro
//! Enclave appliances with 1-CPU and 4-CPU enclaves: a vault release costs
//! about 2 signs, a DID create or delete 9 to 12, and every other task is
//! charged one. The weights are a property of the code, so they live here and
//! change with it; the budgets, which follow the hardware, are configuration.
//! Re-measure them when a release changes what a task does.
//!
//! ## Refusals
//!
//! REST answers with the VTA's `429` (`x-rate-limit-source: vta`,
//! `x-rate-limit-scope: operations` or `operations-subject`, `retry-after`).
//! DIDComm and TSP answer with a signed `unavailable` error carrying
//! `retryAfter`, which the SDK reads as a retryable `VtaError::Unavailable`.
//! The request was not executed and its `id` was not recorded (VTI-OPS-026), so
//! resending the same document is a retry.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use governor::clock::Clock;
use governor::middleware::NoOpMiddleware;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use metrics::counter;
use vta_config::ServerConfig;
#[allow(deprecated)] // `vault/release/0.1` is still served, so still charged.
use vta_sdk::trust_tasks::{
    TASK_VAULT_RELEASE_0_1, TASK_VAULT_RELEASE_0_2, TASK_WEBVH_DIDS_CREATE_1_0,
    TASK_WEBVH_DIDS_CREATE_1_1, TASK_WEBVH_DIDS_DELETE_1_0,
};

/// The heaviest weight in [`weight`]. No burst is below it, or that task could
/// never be served.
const MAX_WEIGHT: u32 = 10;

/// At most one warning per bucket per this many seconds while it refuses work.
/// An appliance shedding load refuses hundreds of requests a second, and a line
/// for each would make logging part of the overload.
const WARN_EVERY_SECS: u64 = 60;

/// How many per-subject charges pass between sweeps of idle subjects' buckets,
/// so the map holds the clients active now, not every DID ever seen.
const SWEEP_EVERY: u64 = 4096;

/// The metric label of the unauthenticated budget. Never a 429 scope: REST
/// callers without standing are bounded per IP instead.
const UNAUTHENTICATED_SCOPE: &str = "operations-unauthenticated";

/// The clock the budgets read: the monotonic clock, or one a test moves by
/// hand, so a test of a budget never depends on how fast it runs.
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

/// What a task costs against a budget, in signs. A task not listed costs one,
/// measured or not: tasks that publish a DID log entry other than create and
/// delete (update, key rotation) and `provision/integration` were not measured.
#[allow(deprecated)]
pub(crate) fn weight(type_uri: &str) -> u32 {
    let bare = type_uri.split('#').next().unwrap_or(type_uri);
    match bare {
        TASK_VAULT_RELEASE_0_1 | TASK_VAULT_RELEASE_0_2 => 2,
        TASK_WEBVH_DIDS_CREATE_1_0 | TASK_WEBVH_DIDS_CREATE_1_1 | TASK_WEBVH_DIDS_DELETE_1_0 => {
            MAX_WEIGHT
        }
        _ => 1,
    }
}

/// Who a request is charged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Caller<'a> {
    /// A client with standing, by its DID.
    Client(&'a str),
    /// A DIDComm / TSP sender without standing.
    Unauthenticated,
}

/// Which bucket refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    Appliance,
    Subject,
    Unauthenticated,
}

impl Scope {
    /// The name a REST 429 and the metric carry. `Unauthenticated` is never
    /// answered over REST.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Scope::Appliance => vta_sdk::rate_limit::OPERATIONS_LIMITER,
            Scope::Subject => vta_sdk::rate_limit::OPERATIONS_SUBJECT_LIMITER,
            Scope::Unauthenticated => UNAUTHENTICATED_SCOPE,
        }
    }
}

/// A request a budget refused, which one, and when it will next have room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refused {
    pub(crate) scope: Scope,
    pub(crate) retry_after: Duration,
}

impl Refused {
    /// Whole seconds, rounded up and at least 1: a client honouring it must not
    /// come back before the budget has room.
    pub(crate) fn retry_after_secs(self) -> u64 {
        crate::routes::rate_limit::ceil_secs(self.retry_after).max(1)
    }
}

/// The quota a `per_sec` / `burst` pair configures, or `None` without a rate.
/// The burst defaults to one second's worth and is never below [`MAX_WEIGHT`].
fn quota(per_sec: Option<u32>, burst: Option<u32>) -> Option<Quota> {
    let per_sec = NonZeroU32::new(per_sec?)?;
    let burst = burst.unwrap_or(per_sec.get()).max(MAX_WEIGHT);
    let burst = NonZeroU32::new(burst).expect("burst is at least MAX_WEIGHT");
    Some(Quota::per_second(per_sec).allow_burst(burst))
}

/// What charging one bucket returned, as a refusal naming `scope`.
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
        // Unreachable while every burst is at least MAX_WEIGHT; refused with a
        // one-second hint rather than admitted, should a weight outgrow it.
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
    fn note(&self, scope: Scope) {
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
                "operation budget exhausted: refusing Trust Tasks (see [server] \
                 operation_rate_limit_* and docs/02-vta/rate-limiting.md)"
            );
        }
    }
}

/// The budgets in force for this generation of the service. Read from
/// `[server]` when the state is built, so a change takes a restart, and a TEE
/// VTA gets them from its tenant overlay on every boot.
pub struct OperationBudget {
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
    /// The budgets `[server]` configures, on the monotonic clock. An absent
    /// appliance rate is unbounded; the per-client and unauthenticated ones
    /// take their defaults.
    pub fn from_config(server: &ServerConfig) -> Self {
        Self::with_clock(server, BudgetClock::default())
    }

    /// [`Self::from_config`] on `clock`: a test passes a
    /// [`BudgetClock::manual`] one.
    pub fn with_clock(server: &ServerConfig, clock: BudgetClock) -> Self {
        let per_subject_per_sec = server.operation_per_subject_per_sec();
        let unauthenticated_per_sec = server.operation_unauthenticated_per_sec();
        // A zero is refused at load; should one get here, it is bounded as
        // tightly as a rate can be rather than read as no bound.
        let bounded = |per_sec: u32| {
            quota(Some(per_sec.max(1)), None).expect("a rate of at least 1 has a quota")
        };
        tracing::info!(
            appliance_per_sec = server.operation_rate_limit_per_sec,
            per_subject_per_sec,
            unauthenticated_per_sec,
            "operation budgets in force for Trust Tasks"
        );
        Self {
            appliance: quota(
                server.operation_rate_limit_per_sec,
                server.operation_rate_limit_burst,
            )
            .map(|q| RateLimiter::direct_with_clock(q, clock.clone())),
            per_subject: RateLimiter::new(
                bounded(per_subject_per_sec),
                DefaultKeyedStateStore::default(),
                clock.clone(),
            ),
            unauthenticated: RateLimiter::direct_with_clock(
                bounded(unauthenticated_per_sec),
                clock.clone(),
            ),
            clock,
            subject_charges: AtomicU64::default(),
            appliance_warning: Warning::default(),
            subject_warning: Warning::default(),
            unauthenticated_warning: Warning::default(),
        }
    }

    /// Charge one request for `type_uri` from `caller`.
    ///
    /// A client is charged to its own share first, then to the appliance
    /// budget. Tokens are taken on success and never returned, so when the
    /// appliance refuses, the client's share has still been spent: under a
    /// saturated appliance, a client that keeps retrying can find itself
    /// refused for its own share next. The other order would let one client's
    /// excess spend the budget every client shares, which is the worse
    /// failure.
    pub(crate) fn charge(&self, caller: Caller<'_>, type_uri: &str) -> Result<(), Refused> {
        let cost = NonZeroU32::new(weight(type_uri)).expect("every weight is at least 1");
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
            counter!("vta_operation_budget_refused_total", "scope" => refused.scope.name())
                .increment(1);
            match refused.scope {
                Scope::Appliance => &self.appliance_warning,
                Scope::Subject => &self.subject_warning,
                Scope::Unauthenticated => &self.unauthenticated_warning,
            }
            .note(refused.scope);
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

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::trust_tasks::TASK_KEYS_SIGN_0_1;

    const ALICE: Caller<'static> = Caller::Client("did:key:z6MkAlice");
    const BOB: Caller<'static> = Caller::Client("did:key:z6MkBob");

    fn server(appliance: Option<u32>, per_subject: Option<u32>, anon: Option<u32>) -> ServerConfig {
        let mut s = ServerConfig::default();
        s.operation_rate_limit_per_sec = appliance;
        s.operation_rate_limit_per_subject_per_sec = per_subject;
        s.operation_rate_limit_unauthenticated_per_sec = anon;
        s
    }

    fn budget(per_sec: u32, burst: Option<u32>) -> OperationBudget {
        let mut s = server(Some(per_sec), None, None);
        s.operation_rate_limit_burst = burst;
        frozen(&s)
    }

    /// The budgets on a clock that stands still, so no token refills while a
    /// test runs, however slowly.
    fn frozen(s: &ServerConfig) -> OperationBudget {
        OperationBudget::with_clock(s, BudgetClock::manual())
    }

    /// VTI-TRN-029 is a MUST: a VTA nobody sized still bounds each client and
    /// its strangers, at the defaults, and leaves the appliance unbounded.
    #[test]
    fn an_unsized_vta_still_bounds_each_client_and_strangers() {
        let b = frozen(&ServerConfig::default());
        let per_subject = vta_config::DEFAULT_OPERATION_RATE_LIMIT_PER_SUBJECT_PER_SEC;
        for i in 0..per_subject {
            assert_eq!(b.charge(ALICE, TASK_KEYS_SIGN_0_1), Ok(()), "alice {i}");
        }
        let refused = b.charge(ALICE, TASK_KEYS_SIGN_0_1).unwrap_err();
        assert_eq!(refused.scope, Scope::Subject);
        // No appliance budget: another client still has its whole share.
        for i in 0..per_subject {
            assert_eq!(b.charge(BOB, TASK_KEYS_SIGN_0_1), Ok(()), "bob {i}");
        }

        let unauthenticated = vta_config::DEFAULT_OPERATION_RATE_LIMIT_UNAUTHENTICATED_PER_SEC;
        for i in 0..unauthenticated {
            assert_eq!(
                b.charge(Caller::Unauthenticated, TASK_KEYS_SIGN_0_1),
                Ok(()),
                "stranger {i}"
            );
        }
        let refused = b
            .charge(Caller::Unauthenticated, TASK_KEYS_SIGN_0_1)
            .unwrap_err();
        assert_eq!(refused.scope, Scope::Unauthenticated);
    }

    #[test]
    fn a_refused_budget_has_room_again_once_its_wait_has_passed() {
        let clock = BudgetClock::manual();
        let b = OperationBudget::with_clock(&server(Some(1), None, None), clock.clone());
        for _ in 0..10 {
            b.charge(ALICE, TASK_KEYS_SIGN_0_1).unwrap();
        }
        let refused = b.charge(ALICE, TASK_KEYS_SIGN_0_1).unwrap_err();
        assert_eq!(refused.retry_after, Duration::from_secs(1));
        clock.advance(refused.retry_after);
        assert_eq!(b.charge(ALICE, TASK_KEYS_SIGN_0_1), Ok(()));
        assert!(
            b.charge(ALICE, TASK_KEYS_SIGN_0_1).is_err(),
            "one token, not two"
        );
    }

    #[test]
    fn the_burst_defaults_to_one_seconds_worth() {
        let b = budget(20, None);
        for i in 0..20 {
            assert_eq!(b.charge(ALICE, TASK_KEYS_SIGN_0_1), Ok(()), "sign {i}");
        }
        assert!(
            b.charge(ALICE, TASK_KEYS_SIGN_0_1).is_err(),
            "the 21st is refused"
        );
    }

    #[test]
    fn a_release_costs_two_and_a_did_create_ten() {
        let b = budget(20, Some(20));
        for i in 0..10 {
            assert_eq!(
                b.charge(ALICE, TASK_VAULT_RELEASE_0_2),
                Ok(()),
                "release {i}"
            );
        }
        assert!(
            b.charge(ALICE, TASK_KEYS_SIGN_0_1).is_err(),
            "ten releases spend 20"
        );

        let b = budget(20, Some(20));
        assert_eq!(b.charge(ALICE, TASK_WEBVH_DIDS_CREATE_1_1), Ok(()));
        assert_eq!(b.charge(ALICE, TASK_WEBVH_DIDS_DELETE_1_0), Ok(()));
        assert!(
            b.charge(ALICE, TASK_KEYS_SIGN_0_1).is_err(),
            "a create and a delete spend 20"
        );
    }

    #[test]
    fn the_burst_is_never_below_the_heaviest_task() {
        let b = budget(1, Some(1));
        assert_eq!(
            b.charge(ALICE, TASK_WEBVH_DIDS_CREATE_1_0),
            Ok(()),
            "an idle appliance serves a DID create whatever the budget"
        );
    }

    #[test]
    fn a_refusal_names_its_bucket_and_when_to_come_back() {
        let b = budget(10, Some(10));
        for _ in 0..10 {
            b.charge(ALICE, TASK_KEYS_SIGN_0_1).unwrap();
        }
        let refused = b.charge(ALICE, TASK_WEBVH_DIDS_CREATE_1_0).unwrap_err();
        assert_eq!(refused.scope, Scope::Appliance);
        assert!(refused.retry_after <= Duration::from_secs(1), "{refused:?}");
        assert_eq!(refused.retry_after_secs(), 1);
        assert_eq!(
            Refused {
                scope: Scope::Appliance,
                retry_after: Duration::from_millis(1_200)
            }
            .retry_after_secs(),
            2,
            "rounded up"
        );
    }

    /// VTI-TRN-029, first clause: one subject cannot take what the others need.
    #[test]
    fn one_client_cannot_take_another_clients_share() {
        let b = frozen(&server(Some(100), Some(10), None));
        for _ in 0..10 {
            b.charge(ALICE, TASK_KEYS_SIGN_0_1).unwrap();
        }
        let refused = b.charge(ALICE, TASK_KEYS_SIGN_0_1).unwrap_err();
        assert_eq!(refused.scope, Scope::Subject);
        for i in 0..10 {
            assert_eq!(b.charge(BOB, TASK_KEYS_SIGN_0_1), Ok(()), "bob {i}");
        }
    }

    /// A client refused for its own share does not spend the appliance budget.
    #[test]
    fn a_subjects_refused_excess_leaves_the_appliance_budget_alone() {
        let b = frozen(&server(Some(20), Some(10), None));
        for _ in 0..50 {
            let _ = b.charge(ALICE, TASK_KEYS_SIGN_0_1);
        }
        for i in 0..10 {
            assert_eq!(b.charge(BOB, TASK_KEYS_SIGN_0_1), Ok(()), "bob {i}");
        }
    }

    /// VTI-TRN-029, second clause: unauthenticated peers are bounded
    /// separately, and never spend the clients' budget.
    #[test]
    fn unauthenticated_peers_have_their_own_bound() {
        let b = frozen(&server(Some(10), None, Some(10)));
        for _ in 0..10 {
            b.charge(Caller::Unauthenticated, TASK_KEYS_SIGN_0_1)
                .unwrap();
        }
        let refused = b
            .charge(Caller::Unauthenticated, TASK_KEYS_SIGN_0_1)
            .unwrap_err();
        assert_eq!(refused.scope, Scope::Unauthenticated);
        for i in 0..10 {
            assert_eq!(b.charge(ALICE, TASK_KEYS_SIGN_0_1), Ok(()), "alice {i}");
        }
    }

    #[test]
    fn a_fragment_does_not_change_the_weight() {
        assert_eq!(weight(&format!("{TASK_VAULT_RELEASE_0_2}#request")), 2);
    }
}
