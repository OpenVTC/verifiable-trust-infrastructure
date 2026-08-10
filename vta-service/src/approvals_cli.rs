//! `vta approvals …` / `vta policy …` — the offline approvals break-glass.
//!
//! Reads and writes the policy keyspace **directly**, with no HTTP, no operator
//! authentication, and no running VTA. Same security model as every other `vta`
//! offline surface (`acl`, `keys`, `services`, `vault`): whoever holds the
//! filesystem holds this.
//!
//! ## Why this exists
//!
//! Approvals are deliberately self-gating. `policy/*` is not exempt from the
//! policy gate, because two-person control over the gate *itself* is a feature —
//! an operator who can silently drop the rule that requires a second approver
//! has no second approver. The cost of that choice is a reachable lockout:
//!
//! - a rule requiring consent for `policy/upsert` whose approver set is empty,
//!   or whose members have all rotated away;
//! - a rule that gates the very task you would use to remove it;
//! - a hand-authored Rego module that denies everything, installed through
//!   `pnm policy upsert` and now denying the `policy/delete` that would remove
//!   it;
//! - `policy.enforcement = true` with no policy that decides — the gate
//!   default-denies, on purpose, and nothing on the wire can fix it.
//!
//! Every one of those is unrecoverable over the wire by construction. The
//! retired `vta step-up disable` used to cover the equivalent case for the
//! config floors; the floors are gone, so this covers it for the rules.
//!
//! ## Read-mostly, and deliberately cannot add a gate
//!
//! `list` diagnoses; `remove` / `disable` / `policy delete` recover. There is no
//! offline command that *creates* an approval rule, and that asymmetry is
//! intentional: adding a gate is never an emergency, and a break-glass path that
//! can install one is a way to plant a control that never went through the
//! authenticated surface. Use `pnm approvals require …` against a running VTA.
//!
//! ## Not for TEE deployments
//!
//! In a Nitro Enclave the fjall store lives behind a vsock proxy and the `vta`
//! binary on the parent host cannot reach it — the same constraint every other
//! offline surface carries. A TEE operator's recovery path is the enclave's own
//! bootstrap, not this.
//!
//! ## Don't run while the VTA is up
//!
//! fjall takes a file-level lock per data dir, so the daemon holding the store
//! makes this fail to open rather than corrupt anything. That is the protection,
//! not the intent: a running VTA also caches nothing of the policy row (it is
//! read per request), so a change made here is picked up without a restart —
//! but stop the daemon anyway, because the lock will refuse you otherwise.

use std::path::PathBuf;

use vta_cli_common::commands::approvals::render_model;
use vta_sdk::approvals::{DECLARATIVE_POLICY_ID, synthesize_rego, validate};

use crate::cli_store::CliStore;
use crate::config::AppConfig;
use crate::policy::approvals::{DeclarativeModel, declarative_row, load as load_model};
use crate::policy::storage;

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// Open the policy keyspace from the config file.
async fn policy_ks(
    config_path: Option<PathBuf>,
) -> Result<vti_common::store::KeyspaceHandle, Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let cs = CliStore::open(&config).await?;
    Ok(cs.keyspace(crate::keyspaces::POLICY)?)
}

/// `vta approvals list` — what this VTA requires, read straight from the store.
///
/// The diagnosis half. An operator staring at an `auth:consent_required` they
/// cannot get past runs this to find out which rule produced it and which
/// approver set it names — the question that started this whole convergence,
/// answerable now even when the wire path is the thing that is broken.
pub async fn run_list(config_path: Option<PathBuf>) -> CliResult {
    list_on(&policy_ks(config_path).await?).await
}

/// [`run_list`] against an already-open keyspace. Split out so the behaviour is
/// testable without a config file on disk; the `run_*` wrappers exist only to
/// open the store.
async fn list_on(ks: &vti_common::store::KeyspaceHandle) -> CliResult {
    // A row whose `ext` will not parse must not abort the listing. That row is
    // *the thing being diagnosed* — a diagnostic command that dies on it leaves
    // the operator with a bare parse error and no idea what else is installed or
    // what to run next. Report it, name the escape hatch, and carry on.
    match load_model(ks).await {
        Ok(model) => render_model(&model.rules, &model.approver_sets)?,
        Err(e) => {
            println!(
                "The declarative approvals row is present but unreadable: {e}\n\
                 Its rules cannot be shown, and `vta approvals remove` cannot edit it.\n\
                 `vta approvals disable` will delete the row outright."
            );
        }
    }

    // Rules are not the only thing that can deny. A hand-authored module is
    // invisible to the declarative view by design — `pnm approvals` refuses to
    // show Rego it did not generate, because a declarative row whose module said
    // something else would make the printout a lie. But an operator diagnosing a
    // lockout needs to know such a module exists, or they will conclude from an
    // empty rule list that nothing is gating them.
    let others: Vec<_> = storage::list_policies(ks)
        .await?
        .into_iter()
        .filter(|p| p.id != DECLARATIVE_POLICY_ID)
        .collect();
    if !others.is_empty() {
        println!("\nOther policy modules (hand-authored Rego — `vta policy list` for detail):");
        for p in &others {
            println!(
                "  {}{}  priority {}",
                p.id,
                if p.enabled { "" } else { "  (disabled)" },
                p.priority
            );
        }
    }
    Ok(())
}

/// `vta approvals remove <task-uri>` — drop the rule(s) for one task type.
///
/// The surgical fix: the operator knows which rule wedged them and keeps every
/// other control in place. Mirrors `pnm approvals remove`, including the
/// re-synthesis and the validation below.
pub async fn run_remove(
    config_path: Option<PathBuf>,
    task_type: String,
    contexts: Option<Vec<String>>,
) -> CliResult {
    remove_on(&policy_ks(config_path).await?, task_type, contexts).await
}

async fn remove_on(
    ks: &vti_common::store::KeyspaceHandle,
    task_type: String,
    contexts: Option<Vec<String>>,
) -> CliResult {
    let existing = storage::get_policy(ks, DECLARATIVE_POLICY_ID).await?;
    let mut model = load_model(ks).await?;

    let before = model.rules.len();
    model.rules.retain(|r| {
        r.task_type != task_type || contexts.as_ref().is_some_and(|c| &r.contexts != c)
    });
    if model.rules.len() == before {
        return Err(format!(
            "no approval rule for {task_type} — run `vta approvals list` to see what is set"
        )
        .into());
    }

    write_model(ks, &model, existing.as_ref()).await?;
    println!(
        "Removed the approval rule for {task_type}. {} rule(s) remain.",
        model.rules.len()
    );
    Ok(())
}

/// `vta approvals disable` — delete the whole declarative row.
///
/// The hammer, for when the operator cannot identify a single culprit or the row
/// itself is unparseable. Every task goes back to running on the caller's own
/// authority, so it is a real reduction in control — the print below says so
/// rather than reporting a bare success, because an operator who reaches for
/// this under pressure should leave knowing what they just switched off.
///
/// Approver sets go with it: they live on the same row, and a set with no rule
/// naming it grants nothing. Re-declare both with `pnm approvals`.
pub async fn run_disable(config_path: Option<PathBuf>) -> CliResult {
    disable_on(&policy_ks(config_path).await?).await
}

async fn disable_on(ks: &vti_common::store::KeyspaceHandle) -> CliResult {
    if storage::get_policy(ks, DECLARATIVE_POLICY_ID)
        .await?
        .is_none()
    {
        println!("No declarative approvals row — nothing to disable.");
        return Ok(());
    }

    // Read the model for the *summary only*, and never let it gate the delete.
    // An earlier version loaded it first and propagated the error, which meant
    // the hammer did not work on an unparseable row — the one state where every
    // other command has already failed and this is all that is left. Counting
    // what was removed is a nicety; removing it is the point.
    let summary = match load_model(ks).await {
        Ok(m) => format!(
            "{} rule(s) and {} approver set(s) are gone",
            m.rules.len(),
            m.approver_sets.len()
        ),
        Err(_) => "its contents were unreadable, so there is nothing to summarise".to_string(),
    };

    storage::delete_policy(ks, DECLARATIVE_POLICY_ID).await?;
    println!("Removed the declarative approvals row: {summary}.");
    println!(
        "Every task now runs on the caller's own authority. Re-declare what you still \
         want with `pnm approvals require …` once the VTA is reachable."
    );
    Ok(())
}

/// `vta policy list` — every stored policy module, declarative or hand-authored.
///
/// The declarative row's Rego is generated and already described by
/// `approvals list`, so this exists for the modules that surface cannot show:
/// operator-authored Rego, which is equally capable of denying everything and
/// has no other offline view.
pub async fn run_policy_list(config_path: Option<PathBuf>, show_module: bool) -> CliResult {
    let ks = policy_ks(config_path).await?;
    let policies = storage::list_policies(&ks).await?;

    if vta_cli_common::render::is_json_output() {
        println!("{}", serde_json::to_string_pretty(&policies)?);
        return Ok(());
    }
    if policies.is_empty() {
        println!("No policy modules stored.");
        return Ok(());
    }
    for p in &policies {
        println!(
            "{}{}  priority {}  v{}",
            p.id,
            if p.enabled { "" } else { "  (disabled)" },
            p.priority,
            p.version
        );
        if let Some(d) = &p.description {
            println!("    {d}");
        }
        if !p.applies_to.is_empty() {
            println!("    contexts  {}", p.applies_to.join(", "));
        }
        if show_module {
            for line in p.module.lines() {
                println!("    | {line}");
            }
        }
    }
    Ok(())
}

/// `vta policy delete <id>` — remove one policy module.
///
/// The recovery path for a hand-authored module that denies what you need to
/// reach. Refuses the declarative row: deleting it here would silently drop the
/// rules *and* the approver sets, which `approvals disable` does deliberately
/// and says so. Two commands, because the operator should have to mean it.
pub async fn run_policy_delete(config_path: Option<PathBuf>, id: String) -> CliResult {
    // The refusal is checked before the store is opened: it is a property of the
    // id, and an operator who typed the wrong one should be told so rather than
    // told the daemon holds the lock.
    if id == DECLARATIVE_POLICY_ID {
        return Err(format!(
            "`{id}` is the declarative approvals row, not a hand-authored module — use \
             `vta approvals remove <task-uri>` to drop one rule, or `vta approvals disable` \
             to drop the row and every approver set with it"
        )
        .into());
    }
    policy_delete_on(&policy_ks(config_path).await?, id).await
}

async fn policy_delete_on(ks: &vti_common::store::KeyspaceHandle, id: String) -> CliResult {
    if storage::get_policy(ks, &id).await?.is_none() {
        return Err(format!("no policy module `{id}` — run `vta policy list` to see them").into());
    }
    storage::delete_policy(ks, &id).await?;
    println!("Deleted policy module `{id}`.");
    Ok(())
}

/// Re-synthesize and store the declarative row after a rule change.
///
/// The Rego is derived here for the same reason the online path derives it: the
/// VTA byte-compares a submitted module against what the rules imply, and a row
/// whose module disagreed with its rules would make every future `approvals
/// list` — online or offline — describe something other than what decides.
/// Writing the rules without regenerating the module would leave exactly that.
///
/// `version` is carried forward rather than reset so the online surface's
/// `expectedVersion` conflict detection still sees a monotonic row after an
/// offline edit; `created_at` likewise survives.
async fn write_model(
    ks: &vti_common::store::KeyspaceHandle,
    model: &DeclarativeModel,
    existing: Option<&crate::policy::types::PolicyModule>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate before writing, exactly as the online path does. A break-glass
    // surface is the wrong place to seat a model the authenticated path would
    // have refused — the operator would "recover" into a row that `pnm
    // approvals` then cannot edit.
    validate(&model.rules, &model.approver_sets)
        .map_err(|e| format!("the resulting rules are invalid: {e}"))?;

    let now = chrono::Utc::now().to_rfc3339();
    let created_at = existing.map(|p| p.created_at.as_str()).unwrap_or(&now);
    let version = existing.map(|p| p.version.saturating_add(1)).unwrap_or(1);
    let row = declarative_row(model, version, &now, created_at);

    // Compile-check for the same reason the seed path does: a module that will
    // not compile is skipped at load time, which silently un-gates every task it
    // named. Recovering from a lockout must not do that quietly.
    crate::policy::engine::compile(&row.module, DECLARATIVE_POLICY_ID)
        .map_err(|e| format!("the regenerated policy module does not compile: {e}"))?;
    debug_assert_eq!(row.module, synthesize_rego(&model.rules));

    storage::store_policy(ks, &row).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::approvals::ApprovalRule;
    use vti_common::config::StoreConfig;
    use vti_common::store::{KeyspaceHandle, Store};

    const POLICY_UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.1";
    const ACL_GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";

    async fn ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace(crate::keyspaces::POLICY).expect("keyspace");
        (ks, dir)
    }

    /// Seat the row an operator would have written with `pnm approvals`.
    async fn seed(ks: &KeyspaceHandle, rules: Vec<ApprovalRule>, sets: &[(&str, &[&str])]) {
        let model = DeclarativeModel {
            rules,
            approver_sets: sets
                .iter()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                    )
                })
                .collect(),
        };
        let row = declarative_row(&model, 1, "2026-08-10T00:00:00Z", "2026-08-10T00:00:00Z");
        storage::store_policy(ks, &row).await.expect("seed");
    }

    /// The lockout this surface exists for, start to finish.
    ///
    /// An operator requires consent for `policy/upsert` from a set whose only
    /// member has since rotated away. The rule now gates the very task that
    /// would remove it — nothing on the wire can help, by construction. The
    /// offline `remove` must clear it and leave a row the online surface can
    /// still edit.
    #[tokio::test]
    async fn removing_the_rule_that_gates_the_gate() {
        let (ks, _d) = ks().await;
        seed(
            &ks,
            vec![
                ApprovalRule::consent(POLICY_UPSERT, "ops"),
                ApprovalRule::reauth(ACL_GRANT),
            ],
            &[("ops", &["did:key:zGoneForever"])],
        )
        .await;

        remove_on(&ks, POLICY_UPSERT.to_string(), None)
            .await
            .expect("the wedging rule comes out");

        let after = load_model(&ks).await.expect("row still readable");
        assert!(
            after.rule_for(POLICY_UPSERT, "default").is_none(),
            "the rule that gated policy/upsert must be gone"
        );
        assert!(
            after.rule_for(ACL_GRANT, "default").is_some(),
            "the surgical fix must leave every other control standing"
        );
        assert!(
            after.approver_sets.contains_key("ops"),
            "approver sets survive a rule removal — they are not what wedged us"
        );

        // The row the online surface will read next must still be coherent: its
        // Rego regenerated from the remaining rules, and its version advanced so
        // `expectedVersion` conflict detection keeps working across the offline
        // edit.
        let row = storage::get_policy(&ks, DECLARATIVE_POLICY_ID)
            .await
            .unwrap()
            .expect("row still present");
        assert_eq!(row.module, synthesize_rego(&after.rules));
        assert_eq!(row.version, 2, "an offline edit must advance the version");
        assert_eq!(
            row.created_at, "2026-08-10T00:00:00Z",
            "created_at belongs to the row, not to this edit"
        );
        assert!(
            crate::policy::engine::compile(&row.module, DECLARATIVE_POLICY_ID).is_ok(),
            "a module that will not compile is skipped at load — which would \
             silently un-gate every rule it still names"
        );
    }

    /// `disable` is the hammer: the row goes, and the approver sets with it.
    #[tokio::test]
    async fn disable_drops_the_row_and_its_sets() {
        let (ks, _d) = ks().await;
        seed(
            &ks,
            vec![ApprovalRule::consent(POLICY_UPSERT, "ops")],
            &[("ops", &["did:key:zApprover"])],
        )
        .await;

        disable_on(&ks).await.expect("disable");

        assert!(
            storage::get_policy(&ks, DECLARATIVE_POLICY_ID)
                .await
                .unwrap()
                .is_none()
        );
        let after = load_model(&ks).await.expect("a missing row reads as empty");
        assert!(after.rules.is_empty());
        assert!(after.approver_sets.is_empty());
    }

    /// Removing the last rule leaves an empty row rather than an unparseable
    /// one — `pnm approvals require` has to be able to write to it afterwards.
    #[tokio::test]
    async fn removing_the_last_rule_leaves_a_usable_row() {
        let (ks, _d) = ks().await;
        seed(&ks, vec![ApprovalRule::reauth(ACL_GRANT)], &[]).await;

        remove_on(&ks, ACL_GRANT.to_string(), None).await.unwrap();

        let row = storage::get_policy(&ks, DECLARATIVE_POLICY_ID)
            .await
            .unwrap()
            .expect("the row survives its last rule");
        assert!(crate::policy::engine::compile(&row.module, DECLARATIVE_POLICY_ID).is_ok());
        assert!(load_model(&ks).await.unwrap().rules.is_empty());
    }

    /// A context-scoped removal takes only the scoped rule.
    #[tokio::test]
    async fn a_scoped_removal_leaves_the_unscoped_rule() {
        let (ks, _d) = ks().await;
        let mut scoped = ApprovalRule::reauth(ACL_GRANT);
        scoped.contexts = vec!["acme".into()];
        seed(&ks, vec![ApprovalRule::reauth(ACL_GRANT), scoped], &[]).await;

        remove_on(&ks, ACL_GRANT.to_string(), Some(vec!["acme".into()]))
            .await
            .unwrap();

        let after = load_model(&ks).await.unwrap();
        assert_eq!(after.rules.len(), 1);
        assert!(
            after.rules[0].contexts.is_empty(),
            "the unscoped rule must survive a scoped removal"
        );
    }

    /// Removing a rule that is not there fails loudly. An operator recovering
    /// from a lockout must not read a silent success as "that fixed it".
    #[tokio::test]
    async fn removing_an_absent_rule_is_an_error() {
        let (ks, _d) = ks().await;
        seed(&ks, vec![ApprovalRule::reauth(ACL_GRANT)], &[]).await;

        let err = remove_on(&ks, POLICY_UPSERT.to_string(), None)
            .await
            .expect_err("no such rule");
        assert!(
            err.to_string().contains("vta approvals list"),
            "the error should point at the command that shows what IS set, got: {err}"
        );
        assert_eq!(
            load_model(&ks).await.unwrap().rules.len(),
            1,
            "a failed removal must not have written anything"
        );
    }

    /// A hand-authored module denying everything is the other half of the
    /// lockout, and `approvals disable` cannot touch it — `policy delete` is
    /// what recovers, and it must leave the declarative row alone.
    #[tokio::test]
    async fn policy_delete_removes_a_hand_authored_module_only() {
        let (ks, _d) = ks().await;
        seed(&ks, vec![ApprovalRule::reauth(ACL_GRANT)], &[]).await;
        storage::store_policy(
            &ks,
            &crate::policy::types::PolicyModule {
                id: "operator-deny-all".into(),
                name: "deny all".into(),
                description: None,
                module: "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"deny\"}"
                    .into(),
                applies_to: vec![],
                priority: 500,
                enabled: true,
                version: 1,
                created_at: "2026-08-10T00:00:00Z".into(),
                updated_at: "2026-08-10T00:00:00Z".into(),
                ext: serde_json::Value::Null,
            },
        )
        .await
        .unwrap();

        policy_delete_on(&ks, "operator-deny-all".into())
            .await
            .expect("the deny-all module comes out");

        assert!(
            storage::get_policy(&ks, "operator-deny-all")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            storage::get_policy(&ks, DECLARATIVE_POLICY_ID)
                .await
                .unwrap()
                .is_some(),
            "the declarative row is not this command's business"
        );
    }

    /// The corrupt-row case, which is where the first draft of this module was
    /// wrong in both commands.
    ///
    /// `list` parsed the row before printing anything, so it died with a bare
    /// serde error on the one row an operator would be running it to inspect.
    /// `disable` parsed the row before deleting it, so the hammer — the last
    /// thing left when every other command has failed — did not work on the
    /// state that most needs it. Both now treat parsing as best-effort.
    #[tokio::test]
    async fn an_unparseable_row_can_still_be_seen_and_cleared() {
        let (ks, _d) = ks().await;
        storage::store_policy(
            &ks,
            &crate::policy::types::PolicyModule {
                id: DECLARATIVE_POLICY_ID.into(),
                name: "corrupt".into(),
                description: None,
                module: "package vta.policy".into(),
                applies_to: vec![],
                priority: 100,
                enabled: true,
                version: 1,
                created_at: "2026-08-10T00:00:00Z".into(),
                updated_at: "2026-08-10T00:00:00Z".into(),
                // `ext` is where the rules live; this one carries none.
                ext: serde_json::json!({ "openvtc.approvals": "not-an-object" }),
            },
        )
        .await
        .unwrap();

        list_on(&ks)
            .await
            .expect("list must report an unreadable row, not fail on it");
        disable_on(&ks).await.expect("disable clears a corrupt row");
        assert!(
            storage::get_policy(&ks, DECLARATIVE_POLICY_ID)
                .await
                .unwrap()
                .is_none()
        );
    }
}
