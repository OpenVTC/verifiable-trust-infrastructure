//! Step-up **gate engine** — the AAL2 policy-floor resolution algorithm
//! (P2.4).
//!
//! This is the operations-layer half of the step-up feature: a pure resolution
//! function ([`resolve_step_up`]) that, given the VTA's policy + the caller's
//! ACL entry, decides whether an operation-class is gated and (for delegated
//! modes) who must approve. It deliberately takes `config` + `acl_ks` rather
//! than `&AppState`/`&VtaState` so **both** transports resolve the same policy:
//! the REST `RequireStepUp` extractor + the trust-task `require_step_up`
//! wrapper (`crate::trust_tasks::step_up`, which turn a [`StepUpDecision`] into
//! a `403`/reject + the approve-request push), and the DIDComm message handlers
//! (`messaging::handlers`).
//!
//! Moving the engine here resolves the layering inversion that
//! `operations::step_up_policy` documented — `messaging::handlers` no longer
//! reaches up into `routes::` to resolve a gate. The route/transport concerns
//! (Response shaping, challenge minting, approver push, the approve-response
//! Trust Task handler) stay in `crate::trust_tasks::step_up`.

use vti_common::acl::get_acl_entry;
use vti_common::auth::step_up::StepUpMode;
use vti_common::store::KeyspaceHandle;

use crate::config::AppConfig;

/// Operation-class identifiers for the step-up policy floors. Re-exported from
/// `vti_common` so call sites name them via `operations::step_up::op::*` (and
/// the route module re-exports this in turn for its handlers + extractor).
pub mod op {
    pub use vti_common::auth::step_up::op_class::{
        ACL_CHANGE_ROLE, ACL_GRANT, ACL_REVOKE, ACL_SWAP_KEY, CONTEXT_DELETE, KEY_REVOKE,
        VAULT_PROXY_LOGIN, VAULT_RELEASE, VAULT_SIGN_TRUST_TASK,
    };
}

/// Step-up enforcement decision resolved from the policy floor for an
/// operation-class, plus (for `delegated` modes) the caller's configured
/// approver.
pub enum StepUpDecision {
    /// Not gated — proceed at AAL1 (disabled policy, `none` floor, or the
    /// non-escalation carve-out applied).
    Allow,
    /// Gated — mint an approve-request addressed to `recipient` (the subject
    /// itself for `self` mode, or the delegated approver for `delegated`).
    Require { recipient: String },
    /// Gated under `delegated-any`: any approver meeting the maintainer's
    /// criterion (an admin covering the subject's contexts) may ratify. The
    /// approve-request is addressed to no single party; authorization happens at
    /// approve-response time against the actual issuer.
    RequireAny,
    /// Gated, but no usable step-up method exists (a `delegated` floor with no
    /// approver on the caller's entry) — fail closed.
    Deny,
}

/// Resolve the step-up decision for `op_class` requested by `caller_did`.
///
/// `is_non_escalating` is the structural carve-out signal (true only for
/// self-service ops like `acl/swap-key`); it lets a floor with
/// `allow_aal1_if_non_escalating` admit the op at AAL1.
///
/// Takes `config` + `acl_ks` directly (rather than `&AppState`) so the DIDComm
/// message handlers — which hold a `VtaState`, not an `AppState` — can resolve
/// the same policy.
pub async fn resolve_step_up(
    config: &tokio::sync::RwLock<AppConfig>,
    acl_ks: &KeyspaceHandle,
    op_class: &str,
    caller_did: &str,
    is_non_escalating: bool,
) -> StepUpDecision {
    let (floor_mode, allow_carveout) = {
        let cfg = config.read().await;
        match cfg.auth.step_up.floor_record(op_class) {
            None => return StepUpDecision::Allow,
            Some(f) => (f.mode, f.allow_aal1_if_non_escalating),
        }
    };

    // Compose the system floor with the caller's per-entry override
    // (`stepUp.require`), additive-only: the effective mode is the strictest of
    // the two. The caller's entry is also where a `delegated` approver lives, so
    // fetch it once.
    let entry = get_acl_entry(acl_ks, caller_did).await.ok().flatten();
    let override_mode = entry
        .as_ref()
        .and_then(|e| e.step_up_require)
        .unwrap_or(StepUpMode::None);
    let mode = floor_mode.strictest(override_mode);

    // The non-escalation carve-out is a structural exemption for self-service
    // rotation/enrolment; it applies to the resolved requirement.
    if !mode.requires_aal2() || (allow_carveout && is_non_escalating) {
        return StepUpDecision::Allow;
    }
    match mode {
        StepUpMode::None => StepUpDecision::Allow,
        StepUpMode::SelfApprove => StepUpDecision::Require {
            recipient: caller_did.to_string(),
        },
        // Delegated routes to the caller's single configured approver; absent
        // one, fail closed rather than let the subject self-approve a delegated
        // gate.
        StepUpMode::Delegated => match entry.and_then(|e| e.step_up_approver) {
            Some(approver) => StepUpDecision::Require {
                recipient: approver,
            },
            None => StepUpDecision::Deny,
        },
        // Delegated-any: no single approver — any admin meeting the criterion
        // may ratify (checked at approve-response time against the issuer).
        StepUpMode::DelegatedAny => StepUpDecision::RequireAny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The step-up decision the DIDComm `handle_swap_acl` gate now branches on
    /// (P0.13). swap-key is non-escalating, so a floor only gates it when the
    /// operator declines the carve-out; a disabled policy never gates.
    #[tokio::test]
    async fn resolve_step_up_swap_key_honours_floor_and_carveout() {
        use vti_common::auth::step_up::{StepUpFloor, StepUpPolicy};
        use vti_common::config::StoreConfig;
        use vti_common::store::Store;

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();
        let caller = "did:key:zCaller";

        let mk_config = |allow_carveout: bool, enabled: bool| {
            let mut c: crate::config::AppConfig = toml::from_str("").unwrap();
            c.auth.step_up = StepUpPolicy {
                enabled,
                floors: vec![StepUpFloor {
                    operation: op::ACL_SWAP_KEY.to_string(),
                    mode: StepUpMode::SelfApprove,
                    allow_aal1_if_non_escalating: allow_carveout,
                }],
            };
            tokio::sync::RwLock::new(c)
        };

        // Floor requires step-up, no carve-out → swap-key is gated (the new
        // DIDComm behaviour: this caller, always AAL1, gets rejected).
        let cfg = mk_config(false, true);
        assert!(
            !matches!(
                resolve_step_up(&cfg, &acl_ks, op::ACL_SWAP_KEY, caller, true).await,
                StepUpDecision::Allow
            ),
            "a swap-key floor without the carve-out must gate even a non-escalating request"
        );

        // Same floor WITH the carve-out → admitted at AAL1 (DIDComm proceeds).
        let cfg = mk_config(true, true);
        assert!(
            matches!(
                resolve_step_up(&cfg, &acl_ks, op::ACL_SWAP_KEY, caller, true).await,
                StepUpDecision::Allow
            ),
            "the non-escalation carve-out must admit swap-key at AAL1"
        );

        // Policy disabled (the shipping default) → never gated.
        let cfg = mk_config(false, false);
        assert!(
            matches!(
                resolve_step_up(&cfg, &acl_ks, op::ACL_SWAP_KEY, caller, true).await,
                StepUpDecision::Allow
            ),
            "a disabled policy gates nothing"
        );
    }

    /// P0.13b: a `vault/release` floor gates the op (vault ops are escalating —
    /// `require_step_up` passes `is_non_escalating = false`, so no carve-out),
    /// while an unconfigured vault op is untouched.
    #[tokio::test]
    async fn resolve_step_up_gates_configured_vault_op_only() {
        use vti_common::auth::step_up::{StepUpFloor, StepUpPolicy};
        use vti_common::config::StoreConfig;
        use vti_common::store::Store;

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();
        let caller = "did:key:zCaller";

        let mut c: crate::config::AppConfig = toml::from_str("").unwrap();
        c.auth.step_up = StepUpPolicy {
            enabled: true,
            floors: vec![StepUpFloor {
                operation: op::VAULT_RELEASE.to_string(),
                mode: StepUpMode::SelfApprove,
                allow_aal1_if_non_escalating: false,
            }],
        };
        let cfg = tokio::sync::RwLock::new(c);

        // The configured op is gated (the new vault enforcement).
        assert!(
            !matches!(
                resolve_step_up(&cfg, &acl_ks, op::VAULT_RELEASE, caller, false).await,
                StepUpDecision::Allow
            ),
            "a vault/release floor must gate the op"
        );
        // A different vault op with no floor is not gated.
        assert!(
            matches!(
                resolve_step_up(&cfg, &acl_ks, op::VAULT_PROXY_LOGIN, caller, false).await,
                StepUpDecision::Allow
            ),
            "an op with no configured floor must not be gated"
        );
    }
}
