//! The community's operation budgets on Trust Task work (VTI-TRN-029), on the engine
//! every VTI node shares ([`vti_trust_task_server::budget`]).
//!
//! | Bucket | Charged to | Key | Absent |
//! |---|---|---|---|
//! | node | every client with standing, together | `[server] operation_rate_limit_per_sec` | unbounded |
//! | per subject | each client with standing, by its DID | `operation_rate_limit_per_subject_per_sec` | 100 a second |
//! | without standing | every proven signer without standing, together | `operation_rate_limit_unauthenticated_per_sec` | 50 a second |
//!
//! A signer has **standing** here when it holds a live access-control entry: a member,
//! an administrator, a bridge. It is charged to its own share and then the node's. A
//! signer with no entry — a guest registering for an event (VTI-EVT-154), a
//! credential-exchange counterparty, a party presenting a partner credential — is
//! charged to the budget for signers without standing only, so strangers never spend
//! what members need.
//!
//! The charge is the spine's step 3a'' ([`vti_trust_task_server::Spine::with_budget`]):
//! after the proof has verified and the HTTPS door's per-signer admission, before the
//! duplicate-execution record is claimed, on every transport. A refused document is not
//! recorded, so resending it is a retry. The per-address HTTPS limits
//! (`crate::routing::rate_limit`) stay in front as the pre-authentication layer. A
//! document carrying no proof is not charged here: over HTTPS the per-address limit
//! bounds it, and over DIDComm and TSP the spine refuses it unless its specification
//! makes the proof optional.
//!
//! The budgets are configuration, read once when the state is built (a change takes a
//! restart) and never a `config/patch` key.

use std::sync::Arc;

use vti_trust_task_server::budget::{
    BudgetCharge, BudgetClock, BudgetConfig, BudgetSpec, Caller, OperationBudget, Refused,
};

use crate::config::ServerConfig;
use crate::server::AppState;

/// The heaviest weight in [`weight`].
const MAX_WEIGHT: u32 = 10;

/// What a task costs against a budget, in signs. A task that has the community's VTA
/// mint an identity (a group, a badge's group, a community room) is charged as the
/// heaviest task: not measured, and charged so one request cannot spend a mint for the
/// price of a read. Every other task costs one.
fn weight(type_uri: &str) -> u32 {
    const MINTS: &[&str] = &[
        "https://trusttasks.org/spec/vtc/groups/create/",
        "https://trusttasks.org/spec/vtc/badges/create/",
        "https://trusttasks.org/spec/vtc/rooms/community/create/",
    ];
    if MINTS.iter().any(|p| type_uri.starts_with(p)) {
        MAX_WEIGHT
    } else {
        1
    }
}

const SPEC: BudgetSpec = BudgetSpec {
    weight,
    max_weight: MAX_WEIGHT,
    metric: "vtc_operation_budget_refused_total",
    config_hint: "[server] operation_rate_limit_* and docs/02-vta/rate-limiting.md (On a community)",
};

/// The budgets `[server]` configures, on `clock` (the monotonic one in service; a test
/// passes [`BudgetClock::manual`]).
#[must_use]
pub fn from_config(server: &ServerConfig, clock: BudgetClock) -> Arc<OperationBudget> {
    Arc::new(OperationBudget::new(
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

/// The spine's charge for this community: standing is a live access-control entry.
pub(crate) struct VtcBudget<'a> {
    pub(crate) state: &'a AppState,
}

#[async_trait::async_trait]
impl BudgetCharge for VtcBudget<'_> {
    async fn charge_verified(&self, signer: &str, type_uri: &str) -> Result<(), Refused> {
        let now = vti_common::auth::session::now_epoch();
        // A store failure reads as no standing: the signer is still bounded, by the
        // tighter shared budget, rather than not at all.
        let standing = crate::acl::get_acl_entry(&self.state.acl_ks, signer)
            .await
            .ok()
            .flatten()
            .is_some_and(|e| !e.is_expired(now));
        let caller = if standing {
            Caller::Client(signer)
        } else {
            Caller::Unauthenticated
        };
        self.state.operation_budget.charge(caller, type_uri)
    }
}
