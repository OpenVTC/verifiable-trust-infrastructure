//! Default policy bundle — spec §7.1 (M2.5).
//!
//! The workspace ships nine Rego modules — one per
//! [`PolicyPurpose`] — under `vtc-service/policies/default/`.
//! They are embedded at compile time via [`include_str!`] so the
//! binary doesn't read from the filesystem at startup.
//!
//! [`install_defaults`] is idempotent: it walks
//! [`PolicyPurpose::ALL`] and only installs a default for purposes
//! that have **no active policy row** yet. This keeps operator-
//! authored policies untouched across daemon restarts and means
//! re-running the function on an already-installed deployment is a
//! no-op.
//!
//! Defaults carry [`DEFAULTS_AUTHOR`] as their `author_did` so
//! operators can distinguish workspace-shipped policies from their
//! own uploads in `GET /v1/policies`. No audit envelope is emitted
//! when defaults are installed — these are workspace state, not
//! operator actions.
//!
//! ## Why no audit emission
//!
//! `PolicyUploaded` + `PolicyActivated` envelopes record *operator*
//! decisions. A default-policy install happens because the daemon
//! booted with an empty `active_policies:` keyspace, not because an
//! operator did anything. Emitting audit envelopes here would
//! double the audit floor's first-boot footprint without adding any
//! observable signal — the `authorDid` field on the Policy row
//! already tells the story.

use chrono::Utc;
use tracing::{debug, info, warn};
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::engine::{compile, evaluate};
use super::model::{Policy, PolicyPurpose};
use super::storage::{
    get_active_policy_id, get_policy, max_version_for, new_policy, set_active_policy_id,
    store_policy,
};

/// Pseudo-DID stamped on every default policy's `author_did`
/// field. Not a resolvable DID — purely a marker so operators
/// see "this came from the workspace, not from a human admin".
/// Uses the `did:example` method (RFC reserved for non-resolvable
/// illustrative DIDs) rather than `did:key`, which implies a real
/// keypair the daemon can prove control of.
pub const DEFAULTS_AUTHOR: &str = "did:example:vtc-defaults";

/// Embedded source for each default policy, in [`PolicyPurpose::ALL`]
/// order. Compile-time-included so the binary is self-contained.
const DEFAULT_SOURCES: &[(PolicyPurpose, &str)] = &[
    (
        PolicyPurpose::Join,
        include_str!("../../policies/default/join.rego"),
    ),
    (
        PolicyPurpose::Removal,
        include_str!("../../policies/default/removal.rego"),
    ),
    (
        PolicyPurpose::Personhood,
        include_str!("../../policies/default/personhood.rego"),
    ),
    (
        PolicyPurpose::Registry,
        include_str!("../../policies/default/registry.rego"),
    ),
    (
        PolicyPurpose::Directory,
        include_str!("../../policies/default/directory.rego"),
    ),
    (
        PolicyPurpose::RoleDefinitions,
        include_str!("../../policies/default/role_definitions.rego"),
    ),
    (
        PolicyPurpose::CrossCommunityRoles,
        include_str!("../../policies/default/cross_community_roles.rego"),
    ),
    (
        PolicyPurpose::CrossCommunityRelationships,
        include_str!("../../policies/default/cross_community_relationships.rego"),
    ),
    (
        PolicyPurpose::Relationships,
        include_str!("../../policies/default/relationships.rego"),
    ),
    (
        PolicyPurpose::RoleChange,
        include_str!("../../policies/default/role_change.rego"),
    ),
];

/// Number of purposes the workspace ships defaults for. Asserted
/// against [`PolicyPurpose::ALL`] at test time so a missed entry in
/// `DEFAULT_SOURCES` surfaces as a build-time-ish failure rather
/// than a silent runtime gap.
pub const DEFAULT_COUNT: usize = 10;

/// Return the embedded default source for `purpose`. Useful to the
/// admin UX layer that wants to show "reset to default" diffs
/// against the live policy.
pub fn default_source(purpose: PolicyPurpose) -> &'static str {
    DEFAULT_SOURCES
        .iter()
        .find(|(p, _)| *p == purpose)
        .map(|(_, src)| *src)
        .expect("every PolicyPurpose has a shipped default — see DEFAULT_SOURCES")
}

/// Fill gaps in the active-policy set with the workspace defaults.
///
/// Idempotent: only purposes with no current active pointer get a
/// new row installed. Operator-uploaded policies are never
/// overwritten and never touched.
///
/// Returns the number of policies actually installed (`0` on a
/// warm boot where every purpose already has an active policy).
pub async fn install_defaults(
    policies_ks: &KeyspaceHandle,
    active_policies_ks: &KeyspaceHandle,
) -> Result<usize, AppError> {
    let mut installed = 0_usize;
    for (purpose, source) in DEFAULT_SOURCES {
        if get_active_policy_id(active_policies_ks, *purpose)
            .await?
            .is_some()
        {
            debug!(
                purpose = purpose.as_str(),
                "default-policy install skipped — purpose already has an active policy"
            );
            continue;
        }

        let id = Uuid::new_v4();
        let compiled = compile(source, id).map_err(|e| {
            // A default that doesn't compile is a workspace bug,
            // not an operator one — surface as Internal so an
            // operator sees the actual stack instead of a 400.
            AppError::Internal(format!(
                "default policy for {} failed to compile: {e}",
                purpose.as_str()
            ))
        })?;
        let sha = *compiled.source_sha256();

        let mut policy = new_policy(
            *purpose,
            (*source).to_string(),
            sha,
            DEFAULTS_AUTHOR.to_string(),
            1,
        );
        policy.id = id;
        policy.activated_at = Some(Utc::now());

        store_policy(policies_ks, &policy).await?;
        set_active_policy_id(active_policies_ks, *purpose, id).await?;

        installed += 1;
        info!(
            purpose = purpose.as_str(),
            policy_id = %id,
            sha256 = %hex::encode(sha),
            "default policy installed"
        );
    }

    if installed == 0 {
        debug!("no default policies installed — every purpose already has an active row");
    } else if installed < DEFAULT_COUNT {
        // Partial install — the daemon started with a mix of
        // operator + default policies. Worth noting in logs but
        // not an error.
        debug!(
            installed,
            total = DEFAULT_COUNT,
            "partial default-policy install — some purposes already had operator policies"
        );
    }

    if let Err(e) = sanity_check_active_set(active_policies_ks).await {
        // Best-effort post-condition check. We don't fail boot
        // on it — the policies that did install are still
        // load-bearing — but log loudly so the operator sees the
        // gap.
        warn!(error = %e, "default-policy install did not yield a full active set");
    }

    Ok(installed)
}

/// The ceremony purposes the decision pipeline evaluates as
/// `data.<pkg>.decision`. An active policy here that doesn't define a
/// `decision` rule is a pre-migration boolean leftover.
const CEREMONY_DECISION_PACKAGES: &[(PolicyPurpose, &str)] = &[
    (PolicyPurpose::Directory, "vtc.directory"),
    (PolicyPurpose::Join, "vtc.join"),
    (PolicyPurpose::Removal, "vtc.removal"),
    (PolicyPurpose::RoleChange, "vtc.role_change"),
];

/// True when the policy defines a `decision` rule that yields a
/// four-valued verdict (the decision-pipeline shape). A pre-migration
/// boolean policy defines `allow`, not `decision`, so this is false.
fn yields_decision(policy: &Policy, pkg: &str) -> bool {
    let Ok(compiled) = compile(&policy.rego_source, policy.id) else {
        return false;
    };
    match evaluate(
        &compiled,
        &format!("data.{pkg}.decision"),
        serde_json::json!({}),
    ) {
        Ok(results) => results
            .pointer("/result/0/expressions/0/value")
            .and_then(|v| v.get("effect"))
            .and_then(|e| e.as_str())
            .is_some(),
        Err(_) => false,
    }
}

/// Upgrade any ceremony purpose whose **active** policy predates the
/// decision-pipeline migration (defines no `decision` rule) to the
/// shipped decision-shaped default.
///
/// A binary upgrade over an existing data store leaves the old boolean
/// policies active — [`install_defaults`] only fills *missing* pointers,
/// so it won't touch them — but the routes now evaluate
/// `data.<pkg>.decision`, which those policies don't define. The route
/// default-denies and the simulator reports "no decision". This heals
/// that: a legacy ceremony policy is non-functional, so replacing it
/// with the shipped default is strictly a repair. Operator-authored
/// *decision* policies (which define `decision`) are left untouched.
///
/// The replacement is appended fail-forward — a new revision at
/// `max_version + 1`, the active pointer moved to it — never an in-place
/// rewrite. Returns the number of purposes upgraded.
pub async fn upgrade_legacy_ceremony_defaults(
    policies_ks: &KeyspaceHandle,
    active_policies_ks: &KeyspaceHandle,
) -> Result<usize, AppError> {
    let mut upgraded = 0_usize;
    for &(purpose, pkg) in CEREMONY_DECISION_PACKAGES {
        let Some(active_id) = get_active_policy_id(active_policies_ks, purpose).await? else {
            continue; // install_defaults handles the missing case
        };
        let Some(active) = get_policy(policies_ks, active_id).await? else {
            continue;
        };
        if yields_decision(&active, pkg) {
            continue; // already decision-shaped (default or operator's own)
        }

        let source = default_source(purpose);
        let id = Uuid::new_v4();
        let compiled = compile(source, id).map_err(|e| {
            AppError::Internal(format!(
                "default policy for {} failed to compile: {e}",
                purpose.as_str()
            ))
        })?;
        let sha = *compiled.source_sha256();
        let version = max_version_for(policies_ks, purpose).await? + 1;

        let mut policy = new_policy(
            purpose,
            source.to_string(),
            sha,
            DEFAULTS_AUTHOR.to_string(),
            version,
        );
        policy.id = id;
        policy.activated_at = Some(Utc::now());

        store_policy(policies_ks, &policy).await?;
        set_active_policy_id(active_policies_ks, purpose, id).await?;

        upgraded += 1;
        warn!(
            purpose = purpose.as_str(),
            replaced = %active_id,
            policy_id = %id,
            "upgraded a pre-migration ceremony policy to the decision-shaped default"
        );
    }
    Ok(upgraded)
}

/// Verify every [`PolicyPurpose`] has an active pointer. Called
/// after [`install_defaults`] succeeds — under normal boot every
/// purpose should be live. A gap here means a default-install
/// hit an error mid-loop and the boot continued.
async fn sanity_check_active_set(active_policies_ks: &KeyspaceHandle) -> Result<(), AppError> {
    let mut missing = Vec::new();
    for purpose in PolicyPurpose::ALL {
        if get_active_policy_id(active_policies_ks, purpose)
            .await?
            .is_none()
        {
            missing.push(purpose.as_str());
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(AppError::Internal(format!(
            "purposes left without an active policy after install_defaults: {}",
            missing.join(", ")
        )))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::engine::{compile as compile_policy, evaluate};
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_keyspaces() -> (KeyspaceHandle, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        let policies_ks = store.keyspace("policies").expect("policies ks");
        let active_ks = store.keyspace("active_policies").expect("active ks");
        (policies_ks, active_ks, dir)
    }

    /// `DEFAULT_SOURCES` must list every [`PolicyPurpose`] exactly
    /// once — a missing entry would result in `install_defaults`
    /// silently skipping a purpose at boot, which is the kind of
    /// gap that only surfaces in production. Hard-fail at test
    /// time instead.
    #[test]
    fn defaults_cover_every_purpose() {
        assert_eq!(DEFAULT_SOURCES.len(), DEFAULT_COUNT);
        for purpose in PolicyPurpose::ALL {
            assert!(
                DEFAULT_SOURCES.iter().any(|(p, _)| *p == purpose),
                "no default policy shipped for {purpose:?}"
            );
        }
    }

    /// Every default compiles cleanly via the M2.1 harness. Catches
    /// a malformed default before the daemon boots.
    #[test]
    fn every_default_compiles() {
        for (purpose, source) in DEFAULT_SOURCES {
            let id = Uuid::new_v4();
            compile_policy(source, id).unwrap_or_else(|e| {
                panic!(
                    "default policy for {} failed to compile: {e}",
                    purpose.as_str()
                )
            });
        }
    }

    /// First boot: every purpose gets a default. Second call is a
    /// no-op (idempotence).
    #[tokio::test]
    async fn install_defaults_is_idempotent() {
        let (policies_ks, active_ks, _dir) = temp_keyspaces().await;
        let installed = install_defaults(&policies_ks, &active_ks).await.unwrap();
        assert_eq!(installed, DEFAULT_COUNT);
        // Every purpose now has an active pointer.
        for purpose in PolicyPurpose::ALL {
            assert!(
                get_active_policy_id(&active_ks, purpose)
                    .await
                    .unwrap()
                    .is_some(),
                "purpose {purpose:?} should have an active row"
            );
        }
        // Re-run is a no-op.
        let again = install_defaults(&policies_ks, &active_ks).await.unwrap();
        assert_eq!(again, 0, "second install must be a no-op");
    }

    /// A binary-upgrade-over-old-data state: a pre-migration boolean
    /// ceremony policy (defines `allow`, not `decision`) is replaced by
    /// the decision-shaped default, while a healthy decision policy and
    /// the upgrade itself stay idempotent.
    #[tokio::test]
    async fn upgrade_replaces_only_legacy_ceremony_policies() {
        let (policies_ks, active_ks, _dir) = temp_keyspaces().await;

        // A pre-migration boolean policy active for Join.
        let legacy = "package vtc.join\nimport rego.v1\n\ndefault allow := false\n";
        let legacy_id = Uuid::new_v4();
        let sha = *compile_policy(legacy, legacy_id).unwrap().source_sha256();
        let mut p = new_policy(
            PolicyPurpose::Join,
            legacy.to_string(),
            sha,
            "did:key:zOperator".into(),
            1,
        );
        p.id = legacy_id;
        p.activated_at = Some(Utc::now());
        store_policy(&policies_ks, &p).await.unwrap();
        set_active_policy_id(&active_ks, PolicyPurpose::Join, legacy_id)
            .await
            .unwrap();

        // Fill the remaining purposes with the (decision-shaped)
        // defaults. install_defaults skips Join — it has an active row.
        install_defaults(&policies_ks, &active_ks).await.unwrap();
        let removal_before = get_active_policy_id(&active_ks, PolicyPurpose::Removal)
            .await
            .unwrap()
            .unwrap();

        let upgraded = upgrade_legacy_ceremony_defaults(&policies_ks, &active_ks)
            .await
            .unwrap();
        assert_eq!(upgraded, 1, "only the legacy Join policy is upgraded");

        // Join now points at a decision-shaped policy at a fresh version.
        let join_after = get_active_policy_id(&active_ks, PolicyPurpose::Join)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(join_after, legacy_id, "Join active pointer moved forward");
        let join_policy = get_policy(&policies_ks, join_after).await.unwrap().unwrap();
        assert!(
            yields_decision(&join_policy, "vtc.join"),
            "upgraded Join policy yields a decision"
        );
        assert_eq!(join_policy.version, 2, "appended fail-forward");

        // The healthy decision-shaped Removal policy is untouched.
        let removal_after = get_active_policy_id(&active_ks, PolicyPurpose::Removal)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(removal_before, removal_after, "Removal default untouched");

        // Idempotent — a second pass finds nothing to upgrade.
        let again = upgrade_legacy_ceremony_defaults(&policies_ks, &active_ks)
            .await
            .unwrap();
        assert_eq!(again, 0, "second upgrade pass is a no-op");
    }

    /// An operator-uploaded policy already pointed at by the active
    /// pointer is not overwritten by `install_defaults`.
    #[tokio::test]
    async fn install_defaults_preserves_operator_policies() {
        let (policies_ks, active_ks, _dir) = temp_keyspaces().await;

        // Simulate an operator upload of a custom join policy.
        let operator_source = "package vtc.join\nimport rego.v1\n\ndefault allow := false\n";
        let operator_id = Uuid::new_v4();
        let compiled = compile_policy(operator_source, operator_id).unwrap();
        let sha = *compiled.source_sha256();
        let mut operator_policy = new_policy(
            PolicyPurpose::Join,
            operator_source.to_string(),
            sha,
            "did:key:zRealOperator".into(),
            1,
        );
        operator_policy.id = operator_id;
        operator_policy.activated_at = Some(Utc::now());
        store_policy(&policies_ks, &operator_policy).await.unwrap();
        set_active_policy_id(&active_ks, PolicyPurpose::Join, operator_id)
            .await
            .unwrap();

        // Install defaults — only the other 8 purposes get filled.
        let installed = install_defaults(&policies_ks, &active_ks).await.unwrap();
        assert_eq!(installed, DEFAULT_COUNT - 1);

        // Join still points at the operator's policy.
        assert_eq!(
            get_active_policy_id(&active_ks, PolicyPurpose::Join)
                .await
                .unwrap(),
            Some(operator_id)
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Input-contract round-trips per default. Each test compiles
    // the default + evaluates the canonical query for that purpose
    // against the input shape spec §7.3 documents.
    // ──────────────────────────────────────────────────────────────

    fn pluck_bool(result: &serde_json::Value) -> bool {
        result
            .pointer("/result/0/expressions/0/value")
            .and_then(|v| v.as_bool())
            .unwrap_or_else(|| panic!("expected boolean expression value, got {result}"))
    }

    fn compile_default(purpose: PolicyPurpose) -> crate::policy::CompiledPolicy {
        compile_policy(default_source(purpose), Uuid::new_v4()).expect("compile default")
    }

    #[test]
    fn join_default_admits_on_trusted_credential() {
        // The default join policy is now the decision spine: a trusted,
        // valid presented credential auto-admits as a member.
        let c = compile_default(PolicyPurpose::Join);
        let r = evaluate(
            &c,
            "data.vtc.join.decision",
            json!({
                "evidence": {
                    "presentation": {
                        "credentials": [
                            { "type": "WitnessCredential", "issuer_trusted": true, "status": "valid" }
                        ]
                    }
                }
            }),
        )
        .unwrap();
        assert_eq!(
            r.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "allow", "with": { "role": "member" } })),
        );
    }

    #[test]
    fn join_default_admits_on_valid_invitation() {
        // A verified, trusted, unconsumed invitation (VIC) auto-admits as a
        // member — no presented credential needed.
        let c = compile_default(PolicyPurpose::Join);
        let r = evaluate(
            &c,
            "data.vtc.join.decision",
            json!({
                "evidence": {
                    "invitation": {
                        "verified": true,
                        "issuer": "did:webvh:acme.example",
                        "issuer_trusted": true,
                        "consumed": false
                    }
                }
            }),
        )
        .unwrap();
        assert_eq!(
            r.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "allow", "with": { "role": "member" } })),
        );
    }

    #[test]
    fn join_default_grants_invited_role() {
        // A VIC carrying a `role:moderator` scope auto-admits at that role.
        let c = compile_default(PolicyPurpose::Join);
        let r = evaluate(
            &c,
            "data.vtc.join.decision",
            json!({
                "evidence": {
                    "invitation": {
                        "verified": true,
                        "issuer": "did:webvh:acme.example",
                        "issuer_trusted": true,
                        "consumed": false,
                        "scopes": ["role:moderator"]
                    }
                }
            }),
        )
        .unwrap();
        assert_eq!(
            r.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "allow", "with": { "role": "moderator" } })),
        );
    }

    #[test]
    fn join_default_invitation_without_role_scope_grants_member() {
        // A non-role scope (or no scopes) defaults to member.
        let c = compile_default(PolicyPurpose::Join);
        let r = evaluate(
            &c,
            "data.vtc.join.decision",
            json!({
                "evidence": {
                    "invitation": {
                        "verified": true,
                        "issuer": "did:webvh:acme.example",
                        "issuer_trusted": true,
                        "consumed": false,
                        "scopes": ["single-context"]
                    }
                }
            }),
        )
        .unwrap();
        assert_eq!(
            r.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "allow", "with": { "role": "member" } })),
        );
    }

    #[test]
    fn join_default_refers_on_consumed_invitation() {
        // A single-use invitation already redeemed is not a valid admit signal
        // → falls through to moderator review.
        let c = compile_default(PolicyPurpose::Join);
        let r = evaluate(
            &c,
            "data.vtc.join.decision",
            json!({
                "evidence": {
                    "invitation": {
                        "verified": true,
                        "issuer": "did:webvh:acme.example",
                        "issuer_trusted": true,
                        "consumed": true
                    }
                }
            }),
        )
        .unwrap();
        assert_eq!(
            r.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "refer", "with": { "queue": "moderator" } })),
        );
    }

    #[test]
    fn join_default_refers_on_untrusted_invitation_issuer() {
        // A genuinely-verified invitation from an untrusted issuer does not
        // auto-admit — it is referred for human review.
        let c = compile_default(PolicyPurpose::Join);
        let r = evaluate(
            &c,
            "data.vtc.join.decision",
            json!({
                "evidence": {
                    "invitation": {
                        "verified": true,
                        "issuer": "did:key:zStranger",
                        "issuer_trusted": false,
                        "consumed": false
                    }
                }
            }),
        )
        .unwrap();
        assert_eq!(
            r.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "refer", "with": { "queue": "moderator" } })),
        );
    }

    #[test]
    fn join_default_refers_without_trusted_credential() {
        // No trusted credential → referred to the moderator queue
        // (the request lands Pending for admin review).
        let c = compile_default(PolicyPurpose::Join);
        let r = evaluate(
            &c,
            "data.vtc.join.decision",
            json!({
                "evidence": {
                    "presentation": {
                        "credentials": [
                            { "type": "EmailCredential", "issuer_trusted": false, "status": "valid" }
                        ]
                    }
                }
            }),
        )
        .unwrap();
        assert_eq!(
            r.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "refer", "with": { "queue": "moderator" } })),
        );
    }

    #[test]
    fn removal_default_allows_admin_removing_member() {
        // The removal default is now the leave-ceremony decision spine:
        // it returns a {effect, with} object over the verified Facts.
        let c = compile_default(PolicyPurpose::Removal);
        let r = evaluate(
            &c,
            "data.vtc.removal.decision",
            json!({
                "actor": { "did": "did:key:zAdmin" },
                "subject": { "did": "did:key:zMember" },
                "state": { "subject_member": { "role": "member" } }
            }),
        )
        .unwrap();
        assert_eq!(
            r.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "allow", "with": { "disposition": "tombstone" } })),
        );
    }

    #[test]
    fn removal_default_allows_self_leave() {
        // Self-leave (actor == subject) is unconditional.
        let c = compile_default(PolicyPurpose::Removal);
        let r = evaluate(
            &c,
            "data.vtc.removal.decision",
            json!({
                "actor": { "did": "did:key:zSelf" },
                "subject": { "did": "did:key:zSelf" },
                "state": { "subject_member": { "role": "member" } }
            }),
        )
        .unwrap();
        assert_eq!(
            r.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "allow", "with": { "disposition": "tombstone" } })),
        );
    }

    #[test]
    fn removal_default_denies_admin_removing_admin() {
        let c = compile_default(PolicyPurpose::Removal);
        let r = evaluate(
            &c,
            "data.vtc.removal.decision",
            json!({
                "actor": { "did": "did:key:zAdmin" },
                "subject": { "did": "did:key:zOtherAdmin" },
                "state": { "subject_member": { "role": "admin" } }
            }),
        )
        .unwrap();
        assert_eq!(
            r.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "deny", "with": { "code": "removal-denied" } })),
        );
    }

    #[test]
    fn role_change_default_decides_by_target_and_step_up() {
        let c = compile_default(PolicyPurpose::RoleChange);

        // Standard change to a non-admin role → allow that role.
        let std = evaluate(
            &c,
            "data.vtc.role_change.decision",
            json!({ "evidence": { "request": { "target_role": "moderator" } } }),
        )
        .unwrap();
        assert_eq!(
            std.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "allow", "with": { "role": "moderator" } })),
        );

        // Promotion to admin WITH step-up → allow admin.
        let promo = evaluate(
            &c,
            "data.vtc.role_change.decision",
            json!({ "evidence": { "request": { "target_role": "admin", "step_up": true } } }),
        )
        .unwrap();
        assert_eq!(
            promo.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "allow", "with": { "role": "admin" } })),
        );

        // Promotion to admin WITHOUT step-up → refer to step-up.
        let refer = evaluate(
            &c,
            "data.vtc.role_change.decision",
            json!({ "evidence": { "request": { "target_role": "admin" } } }),
        )
        .unwrap();
        assert_eq!(
            refer.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "refer", "with": { "queue": "step-up" } })),
        );
    }

    #[test]
    fn personhood_default_denies_empty_input() {
        let c = compile_default(PolicyPurpose::Personhood);
        let r = evaluate(
            &c,
            "data.vtc.personhood.allow",
            json!({ "applicant_did": "did:key:zX", "vp_claims": {} }),
        )
        .unwrap();
        assert!(
            !pluck_bool(&r),
            "empty input must deny — no WitnessCredential present"
        );
    }

    #[test]
    fn personhood_default_denies_vp_without_witness_credential() {
        let c = compile_default(PolicyPurpose::Personhood);
        let r = evaluate(
            &c,
            "data.vtc.personhood.allow",
            json!({
                "applicant_did": "did:key:zX",
                "vp_claims": {
                    "holder": "did:key:zX",
                    "credentials": [
                        { "type": ["VerifiableCredential"], "issuer": "did:key:zIss" }
                    ]
                }
            }),
        )
        .unwrap();
        assert!(
            !pluck_bool(&r),
            "VC without WitnessCredential type must deny"
        );
    }

    #[test]
    fn personhood_default_denies_witness_credential_with_empty_issuer() {
        let c = compile_default(PolicyPurpose::Personhood);
        let r = evaluate(
            &c,
            "data.vtc.personhood.allow",
            json!({
                "applicant_did": "did:key:zX",
                "vp_claims": {
                    "holder": "did:key:zX",
                    "credentials": [
                        { "type": ["VerifiableCredential", "WitnessCredential"], "issuer": "" }
                    ]
                }
            }),
        )
        .unwrap();
        assert!(
            !pluck_bool(&r),
            "WitnessCredential with empty issuer must deny"
        );
    }

    #[test]
    fn personhood_default_allows_witness_credential_with_issuer() {
        let c = compile_default(PolicyPurpose::Personhood);
        let r = evaluate(
            &c,
            "data.vtc.personhood.allow",
            json!({
                "applicant_did": "did:key:zX",
                "vp_claims": {
                    "holder": "did:key:zX",
                    "credentials": [
                        {
                            "type": ["VerifiableCredential", "WitnessCredential"],
                            "issuer": "did:key:zWitness"
                        }
                    ]
                }
            }),
        )
        .unwrap();
        assert!(
            pluck_bool(&r),
            "WitnessCredential with non-empty issuer must allow"
        );
    }

    #[test]
    fn personhood_default_preserves_current_true_on_renewal() {
        // Renewal-time re-eval: when current_personhood is
        // already true, the default policy preserves it
        // even with empty vp_claims.
        let c = compile_default(PolicyPurpose::Personhood);
        let r = evaluate(
            &c,
            "data.vtc.personhood.allow",
            json!({
                "applicant_did": "did:key:zX",
                "current_personhood": true,
                "asserted_at_seconds_ago": 3600,
                "vp_claims": { "holder": "did:key:zX", "credentials": [] }
            }),
        )
        .unwrap();
        assert!(
            pluck_bool(&r),
            "renewal must preserve current_personhood=true under default policy"
        );
    }

    #[test]
    fn personhood_default_renewal_denies_when_current_false_no_evidence() {
        // Renewal-time re-eval: current=false + no witness
        // credentials → still deny. Operators wanting allow-
        // by-stale-state upload their own rego.
        let c = compile_default(PolicyPurpose::Personhood);
        let r = evaluate(
            &c,
            "data.vtc.personhood.allow",
            json!({
                "applicant_did": "did:key:zX",
                "current_personhood": false,
                "vp_claims": { "holder": "did:key:zX", "credentials": [] }
            }),
        )
        .unwrap();
        assert!(
            !pluck_bool(&r),
            "renewal with no evidence + current=false must deny"
        );
    }

    #[test]
    fn registry_default_publishes_on_join_with_tombstone_default() {
        let c = compile_default(PolicyPurpose::Registry);
        let publish = evaluate(&c, "data.vtc.registry.publish_on_join", json!({})).unwrap();
        assert!(pluck_bool(&publish));
        let default = evaluate(&c, "data.vtc.registry.default_departure", json!({})).unwrap();
        assert_eq!(
            default.pointer("/result/0/expressions/0/value"),
            Some(&json!("tombstone")),
        );
    }

    #[test]
    fn directory_default_projects_fields_by_viewer_role() {
        // The directory default is now the ceremony decision spine: it
        // returns a {effect, with} object whose `with.fields` is the
        // projection, branching on the verified-facts `input.actor`.
        let c = compile_default(PolicyPurpose::Directory);

        // Admin viewer → fuller record.
        let admin = evaluate(
            &c,
            "data.vtc.directory.decision",
            json!({ "actor": { "role": "admin", "authenticated": true } }),
        )
        .unwrap();
        assert_eq!(
            admin.pointer("/result/0/expressions/0/value"),
            Some(&json!({
                "effect": "allow",
                "with": { "fields": ["did", "role", "joined_at", "status"] }
            })),
        );

        // Authenticated non-admin member → did + role only.
        let member = evaluate(
            &c,
            "data.vtc.directory.decision",
            json!({ "actor": { "role": "member", "authenticated": true } }),
        )
        .unwrap();
        assert_eq!(
            member.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "allow", "with": { "fields": ["did", "role"] } })),
        );

        // Unauthenticated / non-member → structural-totality deny.
        let denied = evaluate(
            &c,
            "data.vtc.directory.decision",
            json!({ "actor": { "authenticated": false } }),
        )
        .unwrap();
        assert_eq!(
            denied.pointer("/result/0/expressions/0/value"),
            Some(&json!({ "effect": "deny", "with": { "code": "not-a-member" } })),
        );
    }

    #[test]
    fn role_definitions_default_matches_spec_matrix() {
        let c = compile_default(PolicyPurpose::RoleDefinitions);

        let cases: &[(&str, &str, bool)] = &[
            ("admin", "edit_community_profile", true),
            ("admin", "author_policies", true),
            ("admin", "promote_to_admin", true),
            ("moderator", "approve_join", true),
            ("moderator", "remove_member", true),
            ("moderator", "edit_community_profile", false),
            ("moderator", "promote_to_admin", false),
            ("issuer", "issue_community_credential", true),
            ("issuer", "remove_member", false),
            ("member", "self_remove", true),
            ("member", "renew_vmc", true),
            ("member", "remove_member", false),
            ("member", "approve_join", false),
            // Custom roles get nothing by default.
            ("custom:editor", "renew_vmc", false),
        ];

        for (role, action, expected) in cases {
            let r = evaluate(
                &c,
                "data.vtc.role_definitions.allow",
                json!({ "role": role, "action": action }),
            )
            .unwrap();
            assert_eq!(
                pluck_bool(&r),
                *expected,
                "role={role} action={action}: expected allow={expected}"
            );
        }
    }

    #[test]
    fn cross_community_roles_default_denies_everything() {
        let c = compile_default(PolicyPurpose::CrossCommunityRoles);
        let r = evaluate(
            &c,
            "data.vtc.cross_community_roles.allow",
            json!({
                "foreign_vec": { "issuer": "did:webvh:peer.example", "role": "admin" },
                "target_role": "admin",
                "vtc_state": {}
            }),
        )
        .unwrap();
        assert!(!pluck_bool(&r));
    }

    #[test]
    fn cross_community_relationships_default_denies_everything() {
        let c = compile_default(PolicyPurpose::CrossCommunityRelationships);
        let r = evaluate(
            &c,
            "data.vtc.cross_community_relationships.allow",
            json!({
                "vrc": { "issuer": "did:webvh:peer.example" },
                "viewer_member": { "did": "did:key:zViewer" },
                "vtc_state": {}
            }),
        )
        .unwrap();
        assert!(!pluck_bool(&r));
    }

    #[test]
    fn relationships_default_requires_both_parties_current() {
        let c = compile_default(PolicyPurpose::Relationships);

        let both = evaluate(
            &c,
            "data.vtc.relationships.allow",
            json!({
                "vrc": {},
                "issuer_member": { "did": "did:key:zIssuer", "is_current": true },
                "subject_member": { "did": "did:key:zSubject", "is_current": true },
                "action": "publish"
            }),
        )
        .unwrap();
        assert!(pluck_bool(&both));

        let only_one = evaluate(
            &c,
            "data.vtc.relationships.allow",
            json!({
                "vrc": {},
                "issuer_member": { "did": "did:key:zIssuer", "is_current": true },
                "subject_member": { "did": "did:key:zSubject", "is_current": false },
                "action": "publish"
            }),
        )
        .unwrap();
        assert!(
            !pluck_bool(&only_one),
            "relationships default must deny when one party isn't a member"
        );
    }
}
