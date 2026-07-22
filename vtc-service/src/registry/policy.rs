//! `registry.rego` consultation helpers — Phase 3 M3.5 + M3.6.
//!
//! The default `registry.rego` (shipped from M2.5) emits four
//! rules the reconciliation flow needs:
//!
//! - `publish_on_join: bool` — whether a `MemberAdded` event
//!   should produce a `PublishMember` job at all. Operators
//!   can opt out of publish-on-join entirely by overriding
//!   this rule to `false`.
//! - `default_departure: string` — the disposition the
//!   reconciler defaults to when the member didn't pick one.
//! - `departure_options: [string]` — the set the member's
//!   preference must clamp to.
//! - `min_disposition: string` — the floor the operator is
//!   willing to accept. RTBF (`actor == target` Purge)
//!   **always** overrides this floor per spec §8.2.
//!
//! Phase 3 M3.5 wires the `publish_on_join` rule. Phase 3
//! M3.6 wires `min_disposition` clamping + the RTBF override.

use serde_json::{Value as JsonValue, json};
use tracing::warn;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::policy::{
    PolicyPurpose, compile as compile_policy, evaluate as evaluate_policy, get_active_policy_id,
    get_policy,
};

/// Outcome of evaluating `registry.rego` for an incoming
/// `MemberAdded` event. `PublishOnJoin` is the default
/// (the default policy emits `true`); `SkipPublishOnJoin`
/// surfaces only when an operator-uploaded policy explicitly
/// flips the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOnJoinDecision {
    PublishOnJoin,
    SkipPublishOnJoin,
}

/// Evaluate the active `registry.rego.publish_on_join`. Fails
/// open — any error path (no active policy, compile failure,
/// missing rule) returns `PublishOnJoin`. The rationale: if
/// the policy is broken, we'd rather sync (the default
/// behaviour) than silently swallow member additions. The
/// alternative (fail closed) would let a buggy policy upload
/// hide the entire membership graph from the registry — a
/// silent privacy regression.
pub async fn evaluate_publish_on_join(
    policies_ks: &KeyspaceHandle,
    active_policies_ks: &KeyspaceHandle,
) -> Result<PublishOnJoinDecision, AppError> {
    let Some(id) = get_active_policy_id(active_policies_ks, PolicyPurpose::Registry).await? else {
        // No active policy → fall back to the spec default
        // (`publish_on_join: true`). M2.5's installer should
        // always have run by the time the syncer is live, so
        // this is a "daemon misconfigured" path.
        warn!("no active registry.rego — defaulting to publish_on_join=true");
        return Ok(PublishOnJoinDecision::PublishOnJoin);
    };
    let policy = get_policy(policies_ks, id)
        .await?
        .ok_or_else(|| AppError::Internal(format!("active registry policy {id} not found")))?;
    let compiled = compile_policy(&policy.rego_source, policy.id)?;
    let result = evaluate_policy(
        &compiled,
        "data.vtc.registry.publish_on_join",
        JsonValue::Object(Default::default()),
    )?;
    let publish = result
        .pointer("/result/0/expressions/0/value")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    Ok(if publish {
        PublishOnJoinDecision::PublishOnJoin
    } else {
        PublishOnJoinDecision::SkipPublishOnJoin
    })
}

/// Read `data.vtc.registry.min_disposition` from the active
/// `registry.rego`. Returns `None` when the policy is missing
/// / malformed / emits a non-string. Callers (the reconciler)
/// treat `None` as "fall back to the disposition the member
/// asked for".
pub async fn read_min_disposition(
    policies_ks: &KeyspaceHandle,
    active_policies_ks: &KeyspaceHandle,
) -> Option<String> {
    let active_id = get_active_policy_id(active_policies_ks, PolicyPurpose::Registry)
        .await
        .ok()
        .flatten()?;
    let policy = get_policy(policies_ks, active_id).await.ok().flatten()?;
    let compiled = compile_policy(&policy.rego_source, policy.id).ok()?;
    let result = evaluate_policy(
        &compiled,
        "data.vtc.registry.min_disposition",
        JsonValue::Object(Default::default()),
    )
    .ok()?;
    result
        .pointer("/result/0/expressions/0/value")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Disposition preservation level. Used by
/// [`clamp_disposition`] to decide whether a member-requested
/// disposition meets the policy floor. **Higher number =
/// more record preservation**:
///
/// - `purge` (1) — no record kept; row physically gone.
/// - `tombstone` (2) — minimal marker kept ("existed once,
///   now departed"); not visible in active member views.
/// - `historical` (3) — full record kept, flagged inactive;
///   still visible in historical views.
///
/// `min_disposition` is the *operator's preservation floor*
/// — the minimum record retention the operator is willing to
/// publish to the registry. If a member-requested disposition
/// has lower preservation than the floor, [`clamp_disposition`]
/// bumps it up to the floor. RTBF (`actor == target` + `purge`)
/// bypasses this clamp per spec §8.2 — a member's right-to-
/// forget overrides the operator's retention preference.
fn severity(s: &str) -> u8 {
    match s {
        "historical" => 3,
        "tombstone" => 2,
        "purge" => 1,
        _ => 1,
    }
}

/// Result of clamping a member's requested disposition against
/// the policy floor. Returns the effective disposition the
/// reconciler should apply, plus a flag indicating whether the
/// policy floor actually overrode the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClampOutcome {
    pub effective: String,
    pub clamped: bool,
    pub min_floor: Option<String>,
}

/// Clamp a member's requested disposition against the
/// `min_disposition` preservation floor. The floor is the
/// **minimum record retention** the operator is willing to
/// publish; if the member requested less retention than the
/// floor (e.g. `purge` against a `tombstone` floor), bump the
/// effective disposition up to the floor.
///
/// **RTBF doesn't go through here.** A member-initiated
/// `Purge` bypasses the floor entirely (spec §8.2 + M3.6's
/// override path). Use [`is_rtbf_purge`] before calling this.
pub fn clamp_disposition(requested: &str, floor: Option<&str>) -> ClampOutcome {
    let Some(floor) = floor else {
        return ClampOutcome {
            effective: requested.to_string(),
            clamped: false,
            min_floor: None,
        };
    };
    if severity(requested) >= severity(floor) {
        ClampOutcome {
            effective: requested.to_string(),
            clamped: false,
            min_floor: Some(floor.to_string()),
        }
    } else {
        ClampOutcome {
            effective: floor.to_string(),
            clamped: true,
            min_floor: Some(floor.to_string()),
        }
    }
}

/// Detect a member-initiated RTBF Purge. The audit envelope's
/// `actor_did == target_did` (the member ran their own
/// removal) combined with `disposition == "purge"` identifies
/// the RTBF case. Admin-force-purge (different actor)
/// **does not** trigger the override; it goes through the
/// normal clamp.
pub fn is_rtbf_purge(actor_did: &str, target_did: &str, disposition: &str) -> bool {
    actor_did == target_did && disposition == "purge"
}

/// Construct the canonical [`json`] payload for evaluating
/// the rego rule. Exposed for the syncer's tests.
pub fn registry_input(member_did: &str, action: &str) -> JsonValue {
    json!({
        "member": { "did": member_did },
        "action": action,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Policy, PolicyPurpose, set_active_policy_id, store_policy};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_keyspaces() -> (KeyspaceHandle, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let policies = store.keyspace("policies").unwrap();
        let active = store.keyspace("active_policies").unwrap();
        (policies, active, dir)
    }

    async fn install_registry_policy(
        policies: &KeyspaceHandle,
        active: &KeyspaceHandle,
        source: &str,
    ) {
        use sha2::{Digest, Sha256};
        let sha: [u8; 32] = Sha256::digest(source.as_bytes()).into();
        let id = uuid::Uuid::new_v4();
        let policy = Policy {
            id,
            purpose: PolicyPurpose::Registry,
            rego_source: source.into(),
            sha256: sha,
            activated_at: Some(chrono::Utc::now()),
            author_did: "did:key:test".into(),
            created_at: chrono::Utc::now(),
            version: 1,
            name: None,
            description: None,
        };
        store_policy(policies, &policy).await.unwrap();
        set_active_policy_id(active, PolicyPurpose::Registry, id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn publish_on_join_defaults_to_publish_when_no_policy() {
        let (policies, active, _dir) = temp_keyspaces().await;
        let outcome = evaluate_publish_on_join(&policies, &active).await.unwrap();
        assert_eq!(outcome, PublishOnJoinDecision::PublishOnJoin);
    }

    #[tokio::test]
    async fn publish_on_join_reads_true_from_default_policy() {
        let (policies, active, _dir) = temp_keyspaces().await;
        let src = "\
package vtc.registry
import rego.v1
default publish_on_join := true
";
        install_registry_policy(&policies, &active, src).await;
        let outcome = evaluate_publish_on_join(&policies, &active).await.unwrap();
        assert_eq!(outcome, PublishOnJoinDecision::PublishOnJoin);
    }

    #[tokio::test]
    async fn publish_on_join_returns_skip_when_policy_says_false() {
        let (policies, active, _dir) = temp_keyspaces().await;
        let src = "\
package vtc.registry
import rego.v1
default publish_on_join := false
";
        install_registry_policy(&policies, &active, src).await;
        let outcome = evaluate_publish_on_join(&policies, &active).await.unwrap();
        assert_eq!(outcome, PublishOnJoinDecision::SkipPublishOnJoin);
    }

    #[tokio::test]
    async fn min_disposition_returns_none_when_no_policy() {
        let (policies, active, _dir) = temp_keyspaces().await;
        let got = read_min_disposition(&policies, &active).await;
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn min_disposition_reads_from_policy() {
        let (policies, active, _dir) = temp_keyspaces().await;
        let src = "\
package vtc.registry
import rego.v1
default min_disposition := \"tombstone\"
";
        install_registry_policy(&policies, &active, src).await;
        let got = read_min_disposition(&policies, &active).await;
        assert_eq!(got.as_deref(), Some("tombstone"));
    }

    #[test]
    fn clamp_disposition_below_floor_bumps_up_to_floor() {
        // purge (preservation 1) below tombstone floor (2) →
        // clamp UP to tombstone. Operator wanted at least a
        // marker preserved.
        let out = clamp_disposition("purge", Some("tombstone"));
        assert_eq!(out.effective, "tombstone");
        assert!(out.clamped);

        // purge (1) below historical floor (3) — clamp to
        // historical. Operator wanted full preservation.
        let out = clamp_disposition("purge", Some("historical"));
        assert_eq!(out.effective, "historical");
        assert!(out.clamped);

        // tombstone (2) below historical floor (3) — clamp UP.
        let out = clamp_disposition("tombstone", Some("historical"));
        assert_eq!(out.effective, "historical");
        assert!(out.clamped);
    }

    #[test]
    fn clamp_disposition_at_or_above_floor_passes_through() {
        // tombstone (2) == tombstone (2) — no clamp.
        let out = clamp_disposition("tombstone", Some("tombstone"));
        assert_eq!(out.effective, "tombstone");
        assert!(!out.clamped);

        // historical (3) > tombstone floor (2) — more
        // preservation than the floor demands, passes verbatim.
        let out = clamp_disposition("historical", Some("tombstone"));
        assert_eq!(out.effective, "historical");
        assert!(!out.clamped);

        // Default registry.rego ships with floor "purge" (1)
        // — every disposition is at-or-above floor, no clamp.
        let out = clamp_disposition("purge", Some("purge"));
        assert_eq!(out.effective, "purge");
        assert!(!out.clamped);
        let out = clamp_disposition("tombstone", Some("purge"));
        assert_eq!(out.effective, "tombstone");
        assert!(!out.clamped);
    }

    #[test]
    fn clamp_with_no_floor_returns_requested_verbatim() {
        let out = clamp_disposition("purge", None);
        assert_eq!(out.effective, "purge");
        assert!(!out.clamped);
        assert!(out.min_floor.is_none());
    }

    #[test]
    fn is_rtbf_purge_detects_self_purge() {
        assert!(is_rtbf_purge("did:key:zMember", "did:key:zMember", "purge"));
    }

    #[test]
    fn is_rtbf_purge_rejects_admin_force_purge() {
        assert!(!is_rtbf_purge("did:key:zAdmin", "did:key:zMember", "purge"));
    }

    #[test]
    fn is_rtbf_purge_rejects_non_purge_dispositions() {
        assert!(!is_rtbf_purge(
            "did:key:zMember",
            "did:key:zMember",
            "tombstone"
        ));
        assert!(!is_rtbf_purge(
            "did:key:zMember",
            "did:key:zMember",
            "historical"
        ));
    }
}
