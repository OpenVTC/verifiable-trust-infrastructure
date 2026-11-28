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

#[cfg(test)]
use std::time::Duration;
use vta_config::ServerConfig;
use vta_sdk::trust_tasks::{
    TASK_ROOMS_KEYS_WATCH_0_1, TASK_ROOMS_KEYS_WATCH_0_2, TASK_VAULT_RELEASE_0_2,
    TASK_WEBVH_DIDS_CREATE_1_2, TASK_WEBVH_DIDS_DELETE_1_0,
};
pub use vti_trust_task_server::budget::{BudgetClock, Caller, Refused, Scope};
use vti_trust_task_server::budget::{BudgetConfig, BudgetSpec};

/// The heaviest weight in [`weight`]. No burst is below it, or that task could
/// never be served.
const MAX_WEIGHT: u32 = 10;

/// What a task costs against a budget, in signs. A task not listed costs one,
/// measured or not: tasks that publish a DID log entry other than create and
/// delete (update, key rotation) and `provision/integration` were not measured.
pub(crate) fn weight(type_uri: &str) -> u32 {
    let bare = type_uri.split('#').next().unwrap_or(type_uri);
    match bare {
        TASK_VAULT_RELEASE_0_2 => 2,
        TASK_WEBVH_DIDS_CREATE_1_2 | TASK_WEBVH_DIDS_DELETE_1_0 => MAX_WEIGHT,
        // Up to 64 rooms, each a presentation minted and signed as the member, a host
        // request and an address minted: not measured, and charged as the heaviest task
        // so one request cannot spend 64 signs for the price of one.
        TASK_ROOMS_KEYS_WATCH_0_1 | TASK_ROOMS_KEYS_WATCH_0_2 => MAX_WEIGHT,
        _ => 1,
    }
}

const SPEC: BudgetSpec = BudgetSpec {
    weight,
    max_weight: MAX_WEIGHT,
    metric: "vta_operation_budget_refused_total",
    config_hint: "[server] operation_rate_limit_* and docs/02-vta/rate-limiting.md",
};

/// The budgets in force for this generation of the service. Read from
/// `[server]` when the state is built, so a change takes a restart, and a TEE
/// VTA gets them from its tenant overlay on every boot. The buckets, the clock
/// and the refusal are the shared engine's
/// ([`vti_trust_task_server::budget`]); the weights and the configuration are
/// this service's.
pub struct OperationBudget(vti_trust_task_server::budget::OperationBudget);

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
        Self(vti_trust_task_server::budget::OperationBudget::new(
            BudgetConfig {
                per_sec: server.operation_rate_limit_per_sec,
                burst: server.operation_rate_limit_burst,
                per_subject_per_sec: server.operation_per_subject_per_sec(),
                unauthenticated_per_sec: server.operation_unauthenticated_per_sec(),
            },
            SPEC,
            clock,
        ))
    }

    /// Charge one request for `type_uri` from `caller`: a client to its own
    /// share first, then to the appliance budget; a sender without standing to
    /// the unauthenticated budget only.
    pub(crate) fn charge(&self, caller: Caller<'_>, type_uri: &str) -> Result<(), Refused> {
        self.0.charge(caller, type_uri)
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
        assert_eq!(b.charge(ALICE, TASK_WEBVH_DIDS_CREATE_1_2), Ok(()));
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
            b.charge(ALICE, TASK_WEBVH_DIDS_CREATE_1_2),
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
        let refused = b.charge(ALICE, TASK_WEBVH_DIDS_CREATE_1_2).unwrap_err();
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
