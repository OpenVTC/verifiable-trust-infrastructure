//! Default policy bundle — spec §7.1 (M2.5).
//!
//! The workspace ships ten Rego modules — one per
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
    (
        PolicyPurpose::Rooms,
        include_str!("../../policies/default/rooms.rego"),
    ),
    (
        PolicyPurpose::VetterEligibility,
        include_str!("../../policies/default/vetter_eligibility.rego"),
    ),
    (
        PolicyPurpose::GitNamespace,
        include_str!("../../policies/default/git_ns.rego"),
    ),
];

/// Number of purposes the workspace ships defaults for. Asserted
/// against [`PolicyPurpose::ALL`] at test time so a missed entry in
/// `DEFAULT_SOURCES` surfaces as a build-time-ish failure rather
/// than a silent runtime gap.
pub const DEFAULT_COUNT: usize = 13;

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
    (PolicyPurpose::Rooms, "vtc.rooms"),
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

/// A personhood assertion carrying one v1 witness statement — a
/// `StatementCredential` under `witnessed/1` from a non-empty issuer — with
/// the host's binding verdict `state`.
fn witness_statement_probe(state: &str) -> serde_json::Value {
    let mut binding = serde_json::json!({ "state": state });
    if state == "bound" {
        binding["relationship_id"] = serde_json::json!(Uuid::nil());
    }
    serde_json::json!({
        "applicant_did": "did:example:probe-applicant",
        "community_did": "did:example:probe-community",
        "vp_claims": {
            "holder": "did:example:probe-applicant",
            "credentials": [{
                "type": ["VerifiableCredential", "DTGCredential", "StatementCredential"],
                "issuer": "did:example:probe-witness",
                "credentialSubject": {
                    "id": "did:example:probe-applicant",
                    "predicate": dtg_credentials::WITNESSED_V1,
                    "object": { "digestMultibase": "zQmProbe" }
                },
                "witness_binding": binding
            }]
        }
    })
}

/// A personhood assertion carrying one `vetted/1` statement this community
/// issued about the applicant, for this community — the community recording
/// its own identity check, which the shipped default accepts.
fn community_vetted_probe() -> serde_json::Value {
    let community = "did:example:probe-community";
    let applicant = "did:example:probe-applicant";
    serde_json::json!({
        "applicant_did": applicant,
        "community_did": community,
        "vp_claims": {
            "holder": applicant,
            "credentials": [{
                "type": ["VerifiableCredential", "DTGCredential", "StatementCredential"],
                "issuer": community,
                "issuerScope": "public",
                "credentialSubject": {
                    "id": applicant,
                    "predicate": dtg_credentials::VETTED_V1,
                    "object": { "value": {
                        "community": community,
                        "method": "inPerson",
                        "claimsVerified": ["name.legal"],
                        "livenessConfirmed": true
                    } }
                }
            }]
        }
    })
}

/// What `policy` decides on `input`; a policy that will not compile or
/// evaluate allows nothing.
fn personhood_policy_allows(policy: &Policy, input: serde_json::Value) -> bool {
    let Ok(compiled) = compile(&policy.rego_source, policy.id) else {
        return false;
    };
    evaluate(&compiled, "data.vtc.personhood.allow", input)
        .ok()
        .and_then(|r| {
            r.pointer("/result/0/expressions/0/value")
                .and_then(serde_json::Value::as_bool)
        })
        .unwrap_or(false)
}

/// Whether a workspace-shipped personhood default is stale: it grants
/// personhood on a witness whose digest binds nothing (the pre-#1068 rule),
/// or it refuses evidence the shipped default accepts — a witness statement
/// bound to a held edge, which a default written for the retired witness type
/// and endorsement shapes never recognises, or the community's own `vetted/1`
/// statement, which the `IdentityVerificationCredential`-era default (#1859)
/// never recognises.
fn is_stale_personhood_default(policy: &Policy) -> bool {
    personhood_policy_allows(policy, witness_statement_probe("absent"))
        || !personhood_policy_allows(policy, witness_statement_probe("bound"))
        || !personhood_policy_allows(policy, community_vetted_probe())
}

/// Replace a **workspace-shipped** personhood default that the shipped one has
/// superseded: one predating the witness digest binding (#1068), one written
/// for the credential shapes that preceded the DTG v1 context — a witness
/// *type* rather than a `witnessed/1` statement — or one that reads the
/// community's own identity check as a plain `IdentityVerificationCredential`
/// (#1859) rather than as the `vetted/1` statement the community now records.
///
/// [`install_defaults`] only fills missing pointers, so a VTC first booted on
/// an earlier binary keeps the personhood default it installed then. Shipping
/// the fix in the source alone would protect new communities and leave every
/// existing one on a rule that either admits too much or recognises nothing.
///
/// Two conditions, both required, so an operator's policy is never touched:
///
/// 1. the active row's `author_did` is [`DEFAULTS_AUTHOR`] — the workspace
///    installed it, no operator uploaded it; and
/// 2. it **behaves** like a superseded default ([`is_stale_personhood_default`]).
///    Decided by evaluation rather than by a list of historical source
///    hashes, for the same reason [`upgrade_legacy_ceremony_defaults`] asks
///    whether a policy yields a decision rather than what its bytes are.
///
/// Fail-forward like its sibling: a new revision at `max_version + 1`, the
/// active pointer moved to it. Returns whether an upgrade happened.
pub async fn upgrade_stale_personhood_default(
    policies_ks: &KeyspaceHandle,
    active_policies_ks: &KeyspaceHandle,
) -> Result<bool, AppError> {
    let purpose = PolicyPurpose::Personhood;
    let Some(active_id) = get_active_policy_id(active_policies_ks, purpose).await? else {
        return Ok(false); // install_defaults handles the missing case
    };
    let Some(active) = get_policy(policies_ks, active_id).await? else {
        return Ok(false);
    };
    if active.author_did != DEFAULTS_AUTHOR || !is_stale_personhood_default(&active) {
        return Ok(false);
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

    warn!(
        purpose = purpose.as_str(),
        replaced = %active_id,
        policy_id = %id,
        "upgraded the shipped personhood default: it admitted a witness whose digest \
         binds no edge (#1068), predates the DTG v1 credential shapes, or reads the \
         community's identity check as an IdentityVerificationCredential (#1859)"
    );
    Ok(true)
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
                            { "type": "MembershipCredential", "issuer_trusted": true, "status": "valid" }
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

    // ── Peer identity vetting (OpenVTC docs/design/vetting-process.md §10) ──

    fn join_decision(input: serde_json::Value) -> serde_json::Value {
        let c = compile_default(PolicyPurpose::Join);
        evaluate(&c, "data.vtc.join.decision", input)
            .unwrap()
            .pointer("/result/0/expressions/0/value")
            .cloned()
            .expect("join decision value")
    }

    /// Host-assembled vetting facts. `satisfied` is derived here the way the
    /// host derives it, so no test can hand the policy an impossible state.
    fn vetting_facts(consistent: bool, independent: bool, needs: &[&str]) -> serde_json::Value {
        json!({
            "criterion_id": "kernel-developer",
            "requirements_digest": "zDigest",
            "applicant_digest_matches": true,
            "statements": [],
            "distinct_counted_vetters": 2,
            "by_method": { "inPerson": 1, "video": 1 },
            "commitments_consistent": consistent,
            "independence_ok": independent,
            "invitation_required": false,
            "satisfied": consistent && independent && needs.is_empty(),
            "needs": needs,
        })
    }

    fn valid_invitation(scopes: &[&str]) -> serde_json::Value {
        json!({
            "verified": true,
            "issuer": "did:webvh:acme.example",
            "issuer_trusted": true,
            "consumed": false,
            "scopes": scopes,
        })
    }

    #[test]
    fn join_default_admits_when_vetting_is_satisfied() {
        assert_eq!(
            join_decision(json!({ "evidence": { "vetting": vetting_facts(true, true, &[]) } })),
            json!({ "effect": "allow", "with": { "role": "member" } }),
        );
    }

    #[test]
    fn join_default_asks_for_more_vetting_with_the_generic_need() {
        // The host replaces "vetting" with the precise shortfall after deciding.
        assert_eq!(
            join_decision(json!({
                "evidence": { "vetting": vetting_facts(true, true, &["vetting:statements:1"]) }
            })),
            json!({ "effect": "request_more", "with": { "needs": ["vetting"] } }),
        );
    }

    #[test]
    fn join_default_refers_when_vetters_verified_different_identities() {
        assert_eq!(
            join_decision(json!({ "evidence": { "vetting": vetting_facts(false, true, &[]) } })),
            json!({ "effect": "refer", "with": { "queue": "vetting-review" } }),
        );
    }

    #[test]
    fn join_default_refers_when_vetters_are_not_independent() {
        assert_eq!(
            join_decision(json!({ "evidence": { "vetting": vetting_facts(true, false, &[]) } })),
            json!({ "effect": "refer", "with": { "queue": "vetting-review" } }),
        );
    }

    #[test]
    fn join_default_invitation_does_not_bypass_required_vetting() {
        assert_eq!(
            join_decision(json!({
                "evidence": {
                    "invitation": valid_invitation(&[]),
                    "vetting": vetting_facts(true, true, &["vetting:statements:2"]),
                }
            })),
            json!({ "effect": "request_more", "with": { "needs": ["vetting"] } }),
        );
    }

    #[test]
    fn join_default_trusted_credential_does_not_bypass_required_vetting() {
        assert_eq!(
            join_decision(json!({
                "evidence": {
                    "presentation": { "credentials": [
                        { "type": "MembershipCredential", "issuer_trusted": true, "status": "valid" }
                    ]},
                    "vetting": vetting_facts(true, true, &["vetting:method:inPerson:1"]),
                }
            })),
            json!({ "effect": "request_more", "with": { "needs": ["vetting"] } }),
        );
    }

    #[test]
    fn join_default_asks_for_a_required_invitation_once_vetting_is_met() {
        let mut facts = vetting_facts(true, true, &[]);
        facts["invitation_required"] = json!(true);
        assert_eq!(
            join_decision(json!({ "evidence": { "vetting": facts } })),
            json!({ "effect": "request_more", "with": { "needs": ["vetting:invitation"] } }),
        );
    }

    #[test]
    fn join_default_met_vetting_with_an_invitation_admits_at_the_invited_role() {
        let mut facts = vetting_facts(true, true, &[]);
        facts["invitation_required"] = json!(true);
        assert_eq!(
            join_decision(json!({
                "evidence": { "invitation": valid_invitation(&["role:maintainer"]), "vetting": facts }
            })),
            json!({ "effect": "allow", "with": { "role": "maintainer" } }),
        );
    }

    #[test]
    fn join_default_without_vetting_facts_is_unchanged() {
        // A community whose criteria require no vetting keeps the pre-vetting
        // behaviour exactly: invitation admits, everything else is referred.
        assert_eq!(
            join_decision(json!({ "evidence": { "invitation": valid_invitation(&[]) } })),
            json!({ "effect": "allow", "with": { "role": "member" } }),
        );
        assert_eq!(
            join_decision(json!({ "evidence": {} })),
            json!({ "effect": "refer", "with": { "queue": "moderator" } }),
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
            "empty input must deny — no witness statement present"
        );
    }

    #[test]
    fn personhood_default_denies_vp_without_a_witness_statement() {
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
            "a VC that is not a witnessed/1 statement must deny"
        );
    }

    #[test]
    fn personhood_default_denies_a_witness_statement_with_empty_issuer() {
        let mut input = witness_input(Some(json!({
            "state": "bound",
            "relationship_id": Uuid::new_v4()
        })));
        input["vp_claims"]["credentials"][0]["issuer"] = json!("");
        assert!(
            !personhood_allows(input),
            "a witness statement with empty issuer must deny"
        );
    }

    /// A witness classified by type rather than predicate: another statement
    /// under `endorses/1` with a bound-looking verdict is not a witness.
    #[test]
    fn personhood_default_reads_the_predicate_not_the_type() {
        let mut input = witness_input(Some(json!({
            "state": "bound",
            "relationship_id": Uuid::new_v4()
        })));
        input["vp_claims"]["credentials"][0]["credentialSubject"]["predicate"] =
            json!(dtg_credentials::ENDORSES_V1);
        assert!(!personhood_allows(input));
    }

    /// A personhood assertion carrying one `witnessed/1` statement whose host
    /// verdict is `binding` (`None` = no `witness_binding` member at all).
    fn witness_input(binding: Option<serde_json::Value>) -> serde_json::Value {
        let mut cred = json!({
            "type": ["VerifiableCredential", "DTGCredential", "StatementCredential"],
            "issuer": "did:key:zWitness",
            "credentialSubject": {
                "id": "did:key:zX",
                "predicate": dtg_credentials::WITNESSED_V1,
                "object": { "digestMultibase": "zQmEdge" }
            }
        });
        if let Some(b) = binding {
            cred["witness_binding"] = b;
        }
        json!({
            "applicant_did": "did:key:zX",
            "community_did": "did:webvh:community.example",
            "vp_claims": { "holder": "did:key:zX", "credentials": [cred] }
        })
    }

    fn personhood_allows(input: serde_json::Value) -> bool {
        let c = compile_default(PolicyPurpose::Personhood);
        pluck_bool(&evaluate(&c, "data.vtc.personhood.allow", input).unwrap())
    }

    /// DTG Credentials Security Considerations 6 (*Digest integrity*): a VWC
    /// whose digest the host bound to an edge this community holds is evidence
    /// of that edge, and the default admits it (#1068).
    #[test]
    fn personhood_default_allows_a_witness_bound_to_a_held_edge() {
        assert!(personhood_allows(witness_input(Some(json!({
            "state": "bound",
            "relationship_id": Uuid::new_v4()
        })))));
    }

    /// The pre-#1068 rule admitted any witness with a non-empty issuer. Every
    /// verdict short of `bound` is now refused — including
    /// `unresolved`, which is *not* forgery (the edge may live on another
    /// community) but is not something this community can see either; an
    /// operator who trusts foreign edges accepts it in their own policy.
    #[test]
    fn personhood_default_refuses_a_witness_whose_digest_does_not_bind() {
        for state in ["unresolved", "absent", "malformed", "subjectMismatch"] {
            assert!(
                !personhood_allows(witness_input(Some(json!({ "state": state })))),
                "`{state}` must not grant personhood"
            );
        }
    }

    /// No verdict at all — a projection the host never annotated, or an
    /// input from a caller that does not compute one — is not a pass.
    #[test]
    fn personhood_default_refuses_a_witness_with_no_binding_verdict() {
        assert!(!personhood_allows(witness_input(None)));
    }

    /// The verdict is host-owned but the rule must not treat a string lookalike
    /// or a missing `state` as `bound`.
    #[test]
    fn personhood_default_reads_only_a_bound_state() {
        for b in [
            json!("bound"),
            json!({}),
            json!({ "state": "Bound" }),
            json!({ "relationship_id": Uuid::new_v4() }),
        ] {
            assert!(!personhood_allows(witness_input(Some(b.clone()))), "{b}");
        }
    }

    /// A permissive rule of the pre-#1068 kind: any credential with a
    /// non-empty issuer.
    const SUPERSEDED_PERSONHOOD_DEFAULT: &str = r#"package vtc.personhood

import rego.v1

default allow := false

asserted if allow

allow if {
	some i
	cred := input.vp_claims.credentials[i]
	cred.issuer != ""
}

allow if {
	input.current_personhood == true
}
"#;

    /// A binding-aware rule written for a credential type that is not the
    /// v1 witness statement — the shape of the #1068-era default, which
    /// matched a retired witness type and so recognises no v1 VWC.
    const PRE_V1_PERSONHOOD_DEFAULT: &str = r#"package vtc.personhood

import rego.v1

default allow := false

asserted if allow

allow if {
	some i
	cred := input.vp_claims.credentials[i]
	"SomeRetiredWitnessType" in cred.type
	cred.issuer != ""
	cred.witness_binding.state == "bound"
}

allow if {
	input.current_personhood == true
}
"#;

    async fn activate_personhood(
        policies_ks: &KeyspaceHandle,
        active_ks: &KeyspaceHandle,
        source: &str,
        author: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let sha = *compile_policy(source, id).unwrap().source_sha256();
        let mut p = new_policy(
            PolicyPurpose::Personhood,
            source.to_string(),
            sha,
            author.into(),
            1,
        );
        p.id = id;
        p.activated_at = Some(Utc::now());
        store_policy(policies_ks, &p).await.unwrap();
        set_active_policy_id(active_ks, PolicyPurpose::Personhood, id)
            .await
            .unwrap();
        id
    }

    /// A VTC first booted before #1068 keeps the personhood default it
    /// installed then; `install_defaults` never revisits a filled pointer. The
    /// upgrade moves it to the shipped default, fail-forward, once.
    #[tokio::test]
    async fn the_superseded_personhood_default_is_upgraded() {
        let (policies_ks, active_ks, _dir) = temp_keyspaces().await;
        let old = activate_personhood(
            &policies_ks,
            &active_ks,
            SUPERSEDED_PERSONHOOD_DEFAULT,
            DEFAULTS_AUTHOR,
        )
        .await;

        assert!(
            upgrade_stale_personhood_default(&policies_ks, &active_ks)
                .await
                .unwrap()
        );
        let now = get_active_policy_id(&active_ks, PolicyPurpose::Personhood)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(now, old, "the active pointer moved forward");
        let active = get_policy(&policies_ks, now).await.unwrap().unwrap();
        assert_eq!(
            active.rego_source,
            default_source(PolicyPurpose::Personhood)
        );
        assert_eq!(active.version, 2, "a new revision, not an in-place rewrite");
        assert!(
            get_policy(&policies_ks, old).await.unwrap().is_some(),
            "the superseded revision is kept"
        );

        assert!(
            !upgrade_stale_personhood_default(&policies_ks, &active_ks)
                .await
                .unwrap(),
            "idempotent: the shipped default is not itself superseded"
        );
    }

    /// The same permissive source, uploaded by an operator, is the operator's
    /// decision and is never replaced.
    #[tokio::test]
    async fn an_operator_personhood_policy_is_never_upgraded() {
        let (policies_ks, active_ks, _dir) = temp_keyspaces().await;
        let theirs = activate_personhood(
            &policies_ks,
            &active_ks,
            SUPERSEDED_PERSONHOOD_DEFAULT,
            "did:key:zOperator",
        )
        .await;

        assert!(
            !upgrade_stale_personhood_default(&policies_ks, &active_ks)
                .await
                .unwrap()
        );
        assert_eq!(
            get_active_policy_id(&active_ks, PolicyPurpose::Personhood)
                .await
                .unwrap(),
            Some(theirs)
        );
    }

    /// A default that predates the v1 shapes recognises no v1 witness, so it
    /// is upgraded too — it would otherwise refuse every honest assertion.
    #[tokio::test]
    async fn a_pre_v1_personhood_default_is_upgraded() {
        let (policies_ks, active_ks, _dir) = temp_keyspaces().await;
        let old = activate_personhood(
            &policies_ks,
            &active_ks,
            PRE_V1_PERSONHOOD_DEFAULT,
            DEFAULTS_AUTHOR,
        )
        .await;
        assert!(
            upgrade_stale_personhood_default(&policies_ks, &active_ks)
                .await
                .unwrap()
        );
        assert_ne!(
            get_active_policy_id(&active_ks, PolicyPurpose::Personhood)
                .await
                .unwrap(),
            Some(old)
        );
    }

    /// The shipped default as #1859 left it: the community's own identity
    /// check read as a plain `IdentityVerificationCredential`. Kept verbatim
    /// (the rules; the commentary is trimmed) so the upgrade is tested
    /// against what existing VTCs actually run.
    const IDVC_ERA_PERSONHOOD_DEFAULT: &str = r#"package vtc.personhood

import rego.v1

default allow := false

asserted if allow

allow if {
	some i
	cred := input.vp_claims.credentials[i]
	"StatementCredential" in cred.type
	cred.credentialSubject.predicate == "https://registry.trustoverip.org/dtg/vsc/witnessed/1"
	cred.issuer != ""
	cred.witness_binding.state == "bound"
}

allow if {
	some i
	cred := input.vp_claims.credentials[i]
	"IdentityVerificationCredential" in cred.type
	not "DTGCredential" in cred.type
	cred.issuer == input.community_did
	cred.credentialSubject.id == input.applicant_did
}

allow if {
	input.current_personhood == true
}
"#;

    /// A VTC still running the #1859 default would refuse the community's
    /// own `vetted/1` statement — every identity check it records from now on
    /// — so the workspace-shipped copy is replaced, fail-forward.
    #[tokio::test]
    async fn the_identity_verification_credential_era_default_is_upgraded() {
        let (policies_ks, active_ks, _dir) = temp_keyspaces().await;
        let old = activate_personhood(
            &policies_ks,
            &active_ks,
            IDVC_ERA_PERSONHOOD_DEFAULT,
            DEFAULTS_AUTHOR,
        )
        .await;
        assert!(
            upgrade_stale_personhood_default(&policies_ks, &active_ks)
                .await
                .unwrap()
        );
        let now = get_active_policy_id(&active_ks, PolicyPurpose::Personhood)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(now, old);
        assert_eq!(
            get_policy(&policies_ks, now)
                .await
                .unwrap()
                .unwrap()
                .rego_source,
            default_source(PolicyPurpose::Personhood)
        );
    }

    /// The same #1859 source uploaded by an operator is their decision.
    #[tokio::test]
    async fn an_operator_identity_verification_credential_policy_is_kept() {
        let (policies_ks, active_ks, _dir) = temp_keyspaces().await;
        let theirs = activate_personhood(
            &policies_ks,
            &active_ks,
            IDVC_ERA_PERSONHOOD_DEFAULT,
            "did:key:zOperator",
        )
        .await;
        assert!(
            !upgrade_stale_personhood_default(&policies_ks, &active_ks)
                .await
                .unwrap()
        );
        assert_eq!(
            get_active_policy_id(&active_ks, PolicyPurpose::Personhood)
                .await
                .unwrap(),
            Some(theirs)
        );
    }

    /// The probes are only meaningful if the shipped default passes them:
    /// refuses the unbound witness, admits the bound one and the community's
    /// own `vetted/1` statement.
    #[test]
    fn the_shipped_personhood_default_is_not_stale() {
        assert!(!personhood_allows(witness_statement_probe("absent")));
        assert!(personhood_allows(witness_statement_probe("bound")));
        assert!(personhood_allows(community_vetted_probe()));
    }

    const COMMUNITY: &str = "did:webvh:community.example";
    const APPLICANT: &str = "did:key:zApplicant";

    /// The community's own identity check as the policy sees it: a `vetted/1`
    /// statement. Parameterised on issuer / subject / the community the value
    /// names, so each test below can break exactly one binding.
    fn vetted_input(issuer: &str, subject: &str, for_community: &str) -> serde_json::Value {
        json!({
            "applicant_did": APPLICANT,
            "community_did": COMMUNITY,
            "vp_claims": {
                "holder": APPLICANT,
                "credentials": [{
                    "type": ["VerifiableCredential", "DTGCredential", "StatementCredential"],
                    "issuer": issuer,
                    "issuerScope": "public",
                    "credentialSubject": {
                        "id": subject,
                        "predicate": dtg_credentials::VETTED_V1,
                        "object": { "value": {
                            "community": for_community,
                            "method": "inPerson",
                            "claimsVerified": ["name.legal"],
                            "livenessConfirmed": true
                        } }
                    }
                }]
            }
        })
    }

    fn personhood_decides(input: serde_json::Value) -> bool {
        let c = compile_default(PolicyPurpose::Personhood);
        pluck_bool(&evaluate(&c, "data.vtc.personhood.allow", input).unwrap())
    }

    /// The happy path: the community checked the person's identity and
    /// recorded it as its own `vetted/1` statement, which the member presents
    /// over a challenge.
    #[test]
    fn personhood_default_allows_a_community_issued_vetted_statement() {
        assert!(
            personhood_decides(vetted_input(COMMUNITY, APPLICANT, COMMUNITY)),
            "this community's own vetted/1 statement must allow"
        );
    }

    /// The binding that matters most. Anyone can sign a statement under a
    /// public predicate — a member vetter included, whose statement is
    /// admission evidence, not a personhood decision. Only the community's
    /// own statement is its own check.
    #[test]
    fn personhood_default_denies_a_vetted_statement_from_another_issuer() {
        for issuer in ["did:webvh:someone-else.example", "did:key:zMemberVetter"] {
            assert!(
                !personhood_decides(vetted_input(issuer, APPLICANT, COMMUNITY)),
                "a vetted/1 statement issued by {issuer} must not allow"
            );
        }
    }

    /// The statement must name the party asserting: a member cannot present
    /// the check the community made of a different member.
    #[test]
    fn personhood_default_denies_a_vetted_statement_about_someone_else() {
        assert!(!personhood_decides(vetted_input(
            COMMUNITY,
            "did:key:zSomebodyElse",
            COMMUNITY
        )));
    }

    /// `vetted/1` counts for the one community its value names.
    #[test]
    fn personhood_default_denies_a_vetted_statement_for_another_community() {
        assert!(!personhood_decides(vetted_input(
            COMMUNITY,
            APPLICANT,
            "did:webvh:other.example"
        )));
    }

    /// Classified by the predicate: a community-issued statement under any
    /// other predicate, a VMC or a role VAC is not an identity check — and
    /// the retired `IdentityVerificationCredential` no longer is either.
    #[test]
    fn personhood_default_denies_other_community_issued_credentials() {
        let mut endorses = vetted_input(COMMUNITY, APPLICANT, COMMUNITY);
        endorses["vp_claims"]["credentials"][0]["credentialSubject"]["predicate"] =
            json!(dtg_credentials::ENDORSES_V1);
        assert!(!personhood_decides(endorses));

        for types in [
            json!([
                "VerifiableCredential",
                "DTGCredential",
                "AuthorityCredential"
            ]),
            json!([
                "VerifiableCredential",
                "DTGCredential",
                "MembershipCredential"
            ]),
            json!(["VerifiableCredential", "IdentityVerificationCredential"]),
        ] {
            let input = json!({
                "applicant_did": APPLICANT,
                "community_did": COMMUNITY,
                "vp_claims": { "holder": APPLICANT, "credentials": [{
                    "type": types,
                    "issuer": COMMUNITY,
                    "credentialSubject": { "id": APPLICANT, "method": "inPerson" }
                }] }
            });
            assert!(
                !personhood_decides(input),
                "{types} must not double as an identity check"
            );
        }
    }

    /// The seam that no other test crosses: a statement the **real issue
    /// path's builder** signed, projected by the **real extractor**, judged
    /// by the **real policy**. Every other test here hand-writes the
    /// `vp_claims` JSON, so they agree with each other about a shape none of
    /// them obtained from the code that produces it.
    #[tokio::test]
    async fn a_real_community_vetted_statement_satisfies_the_identity_check_rule() {
        use crate::credentials::dtg::issue_vetted_statement;
        use crate::credentials::{CredentialStatusRef, LocalSigner};
        use crate::policy::extract::extract_vp_claims;

        const COMMUNITY_DID: &str = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG";

        let signer = LocalSigner::from_ed25519_seed(COMMUNITY_DID.into(), &[7u8; 32]);
        let request = json!({
            "id": "urn:uuid:issue-request-real",
            "type": "https://trusttasks.org/spec/vtc/endorsements/issue/0.1",
            "issuer": "did:key:zAdmin",
            "recipient": COMMUNITY_DID,
            "issuedAt": "2026-10-01T09:30:00Z",
            "payload": {}
        });
        let vsc = issue_vetted_statement(
            &signer,
            APPLICANT,
            json!({
                "community": COMMUNITY_DID,
                "method": "inPerson",
                "documentClasses": ["nationalId"],
                "claimsVerified": ["name.legal"],
                "livenessConfirmed": true
            }),
            &request,
            "urn:uuid:vetted-real",
            &CredentialStatusRef::revocation(
                "https://vtc.example.com/v1/status-lists/revocation",
                4,
            ),
            chrono::Duration::days(365),
        )
        .await
        .expect("issue the community's vetted/1 statement");

        let vp = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": APPLICANT,
            "verifiableCredential": [vsc],
        });
        assert!(
            personhood_decides(json!({
                "applicant_did": APPLICANT,
                "community_did": COMMUNITY_DID,
                "vp_claims": extract_vp_claims(&vp),
            })),
            "a real community-signed vetted/1 statement must satisfy the default personhood \
             policy; builder and policy have drifted"
        );

        // The same statement, judged by another community: one community's
        // identity check does not confer personhood in another.
        assert!(!personhood_decides(json!({
            "applicant_did": APPLICANT,
            "community_did": "did:key:zSomeOtherCommunity",
            "vp_claims": extract_vp_claims(&vp),
        })));
    }

    /// The policy module reads the same predicates the Rust constants name.
    #[test]
    fn personhood_rego_and_rust_agree_on_the_predicates() {
        let source = super::default_source(PolicyPurpose::Personhood);
        assert!(
            source.contains(&format!("== \"{}\"", dtg_credentials::VETTED_V1)),
            "personhood.rego must match the community's identity check on vetted/1"
        );
        assert!(
            source.contains(&format!("== \"{}\"", dtg_credentials::WITNESSED_V1)),
            "personhood.rego must match witnesses on the witnessed/1 predicate"
        );
        assert!(
            !source.contains("IdentityVerificationCredential"),
            "the retired IdentityVerificationCredential path must not come back"
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
                "foreign_vac": { "issuer": "did:webvh:peer.example", "role": "admin" },
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
    fn relationships_default_attributed_requires_both_parties_current() {
        let c = compile_default(PolicyPurpose::Relationships);

        let both = evaluate(
            &c,
            "data.vtc.relationships.allow",
            json!({
                "vrc": {},
                "identifier_form": "attributed",
                "authenticated_member": { "did": "did:key:zIssuer", "is_current": true },
                "issuer": { "did": "did:key:zIssuer", "is_current": true },
                "subject": { "did": "did:key:zSubject", "is_current": true },
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
                "identifier_form": "attributed",
                "authenticated_member": { "did": "did:key:zIssuer", "is_current": true },
                "issuer": { "did": "did:key:zIssuer", "is_current": true },
                "subject": { "did": "did:key:zSubject", "is_current": false },
                "action": "publish"
            }),
        )
        .unwrap();
        assert!(
            !pluck_bool(&only_one),
            "relationships default must deny when one party isn't a member"
        );
    }

    /// The pairwise form: neither credential party is a member, and the
    /// publish is authorized by the session plus proof of control of the
    /// issuing DID. This is the shape #1054 exists to allow.
    #[test]
    fn relationships_default_allows_pairwise_publish_with_pop() {
        let c = compile_default(PolicyPurpose::Relationships);

        let input = |member_current: bool, pairwise: bool| {
            json!({
                "vrc": {},
                "identifier_form": if pairwise { "pairwise" } else { "attributed" },
                "authenticated_member": { "did": "did:key:zMember", "is_current": member_current },
                // Pairwise DIDs are not members, and are not meant to be.
                "issuer":  { "did": "did:peer:2.zR1", "is_current": false },
                "subject": { "did": "did:peer:2.zR2", "is_current": false },
                "action": "publish"
            })
        };

        let allowed = evaluate(&c, "data.vtc.relationships.allow", input(true, true)).unwrap();
        assert!(
            pluck_bool(&allowed),
            "a current member proving control of the issuing DID must be allowed to publish"
        );

        let no_pop = evaluate(&c, "data.vtc.relationships.allow", input(true, false)).unwrap();
        assert!(
            !pluck_bool(&no_pop),
            "an attributed claim whose named parties are not members must be denied — \
             the pairwise rule must not fire, and the attributed rule must not rescue it"
        );

        let not_a_member =
            evaluate(&c, "data.vtc.relationships.allow", input(false, true)).unwrap();
        assert!(
            !pluck_bool(&not_a_member),
            "proof of control is not membership; a non-member session must be denied"
        );
    }
}
