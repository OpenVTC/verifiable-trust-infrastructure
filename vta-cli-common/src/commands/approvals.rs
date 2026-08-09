//! `… approvals …` — which tasks need an additional human decision.
//!
//! One surface over the reserved declarative policy row: the rules, the named
//! approver sets, and what a given task actually requires. Everything here is a
//! read-modify-write of that one row through the canonical `policy/{get,upsert}`
//! tasks, carrying `expectedVersion` so two operators editing at once get a
//! conflict rather than a silent last-writer-wins.
//!
//! # The Rego is generated here
//!
//! Canonical `policy/upsert` treats `module` as client-authored, so these
//! commands run [`vta_sdk::approvals::synthesize_rego`] over the rules and send
//! the result alongside them. The VTA re-derives and byte-compares. That is why
//! there is no `--module` escape hatch on this surface: a declarative row whose
//! Rego said something other than its rules would make everything printed here
//! a lie. Hand-authored Rego belongs to `… policy upsert`.

use std::collections::BTreeMap;

use vta_sdk::approvals::{
    ApprovalRule, ApproverSets, DECLARATIVE_POLICY_ID, DECLARATIVE_POLICY_NAME,
    DECLARATIVE_POLICY_PRIORITY, EXT_KEY_APPROVER_SETS, EXT_KEY_RULES, Requires, synthesize_rego,
    validate,
};
use vta_sdk::error::VtaError;
use vta_sdk::prelude::*;
use vta_sdk::protocols::policy_management::UpsertPolicyBody;

type CmdResult = Result<(), Box<dyn std::error::Error>>;

/// The declarative row as the CLI holds it: the model plus the version it was
/// read at, so a write can be conditional on nothing having moved underneath.
struct Model {
    rules: Vec<ApprovalRule>,
    approver_sets: ApproverSets,
    /// Version of the stored row; `0` when there is no row yet.
    version: u64,
}

async fn load(client: &VtaClient) -> Result<Model, Box<dyn std::error::Error>> {
    match client.get_policy(DECLARATIVE_POLICY_ID).await {
        Ok(resp) => {
            let ext = &resp.policy.ext;
            let rules = ext
                .get(EXT_KEY_RULES)
                .cloned()
                .map(serde_json::from_value)
                .transpose()?
                .unwrap_or_default();
            let approver_sets = ext
                .get(EXT_KEY_APPROVER_SETS)
                .cloned()
                .map(serde_json::from_value)
                .transpose()?
                .unwrap_or_default();
            Ok(Model {
                rules,
                approver_sets,
                version: resp.policy.version,
            })
        }
        // No row yet: an empty model, which is also the shipping default (a VTA
        // that has never had an approval rule gates nothing).
        Err(VtaError::NotFound(_)) => Ok(Model {
            rules: Vec::new(),
            approver_sets: BTreeMap::new(),
            version: 0,
        }),
        Err(e) => Err(e.into()),
    }
}

/// Validate locally, then write the row back conditionally on `version`.
///
/// Validating client-side first is not a shortcut around the server's check —
/// the VTA validates too, and its answer is the one that counts. It is so an
/// operator sees the same sentence without a round trip, and so a mistyped set
/// name is caught before it is sent.
async fn save(client: &VtaClient, model: Model) -> CmdResult {
    validate(&model.rules, &model.approver_sets)?;
    let module = synthesize_rego(&model.rules);
    client
        .upsert_policy(UpsertPolicyBody {
            id: Some(DECLARATIVE_POLICY_ID.to_string()),
            name: DECLARATIVE_POLICY_NAME.to_string(),
            description: None,
            module,
            applies_to: vec![],
            priority: Some(DECLARATIVE_POLICY_PRIORITY),
            enabled: true,
            expected_version: Some(model.version),
            ext: serde_json::json!({
                EXT_KEY_RULES: model.rules,
                EXT_KEY_APPROVER_SETS: model.approver_sets,
            }),
        })
        .await?;
    Ok(())
}

/// `approvals list` — the rules and the sets they draw on.
pub async fn cmd_list(client: &VtaClient) -> CmdResult {
    let model = load(client).await?;

    if crate::render::is_json_output() {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "rules": model.rules,
                "approverSets": model.approver_sets,
            }))?
        );
        return Ok(());
    }

    if model.rules.is_empty() {
        println!("No approval rules — every task runs on the caller's own authority.");
    } else {
        println!("Approval rules:");
        for rule in &model.rules {
            println!("  {}", rule.task_type);
            match rule.requires {
                Requires::Reauth => {
                    println!("      requires  re-authentication (AAL2) by the caller");
                }
                Requires::Consent => {
                    println!(
                        "      requires  consent — {} approval(s) from set `{}`{}",
                        rule.effective_min_approvals(),
                        rule.approver_set.as_deref().unwrap_or("?"),
                        if rule.effective_exclude_requester() {
                            ", requester excluded"
                        } else {
                            ""
                        }
                    );
                }
            }
            if !rule.contexts.is_empty() {
                println!("      contexts  {}", rule.contexts.join(", "));
            }
        }
    }

    if !model.approver_sets.is_empty() {
        println!("\nApprover sets:");
        for (name, members) in &model.approver_sets {
            println!("  {name}");
            for did in members {
                println!("      {did}");
            }
        }
    }
    Ok(())
}

/// `approvals require <task-uri> …` — add or replace the rule for a task type.
///
/// Replaces rather than appends when a rule with the same task type and the same
/// scope already exists: an operator saying "acl/grant needs consent" after
/// saying "acl/grant needs reauth" means the second, and appending would produce
/// two overlapping guards that `validate` refuses anyway.
pub async fn cmd_require(
    client: &VtaClient,
    task_type: String,
    requires: Requires,
    approver_set: Option<String>,
    min_approvals: Option<u32>,
    exclude_requester: bool,
    contexts: Vec<String>,
) -> CmdResult {
    let mut model = load(client).await?;

    let rule = ApprovalRule {
        task_type: task_type.clone(),
        requires,
        approver_set,
        min_approvals,
        // Only send the flag when set: `Some(false)` and `None` mean the same
        // thing, and the rule shape refuses consent-only members on a reauth
        // rule, so an unconditional `Some(false)` would make `--reauth` fail.
        exclude_requester: exclude_requester.then_some(true),
        contexts: contexts.clone(),
    };

    model
        .rules
        .retain(|r| !(r.task_type == task_type && r.contexts == contexts));
    model.rules.push(rule);

    save(client, model).await?;
    println!("Approval rule set for {task_type}.");
    Ok(())
}

/// `approvals remove <task-uri>` — drop the rule(s) for a task type.
pub async fn cmd_remove(
    client: &VtaClient,
    task_type: String,
    contexts: Option<Vec<String>>,
) -> CmdResult {
    let mut model = load(client).await?;
    let before = model.rules.len();
    model.rules.retain(|r| {
        r.task_type != task_type || contexts.as_ref().is_some_and(|c| &r.contexts != c)
    });
    if model.rules.len() == before {
        return Err(format!("no approval rule for {task_type}").into());
    }
    save(client, model).await?;
    println!("Approval rule removed for {task_type}.");
    Ok(())
}

/// `approvals approvers add <set> <did>`.
pub async fn cmd_approver_add(client: &VtaClient, set: String, did: String) -> CmdResult {
    let mut model = load(client).await?;
    let members = model.approver_sets.entry(set.clone()).or_default();
    if members.contains(&did) {
        println!("{did} is already in `{set}`.");
        return Ok(());
    }
    members.push(did.clone());
    save(client, model).await?;
    println!("Added {did} to approver set `{set}`.");
    Ok(())
}

/// `approvals approvers remove <set> <did>`.
///
/// Refuses a removal that would leave a rule unsatisfiable, rather than letting
/// the set quietly fall below a threshold and discovering it at the next gated
/// request. Server-side `validate` refuses it too; this is the same rule stated
/// early and in the operator's own terms.
pub async fn cmd_approver_remove(client: &VtaClient, set: String, did: String) -> CmdResult {
    let mut model = load(client).await?;
    let Some(members) = model.approver_sets.get_mut(&set) else {
        return Err(format!("no approver set `{set}`").into());
    };
    let before = members.len();
    members.retain(|m| m != &did);
    if members.len() == before {
        return Err(format!("{did} is not in approver set `{set}`").into());
    }
    if members.is_empty() {
        model.approver_sets.remove(&set);
    }
    save(client, model).await?;
    println!("Removed {did} from approver set `{set}`.");
    Ok(())
}

/// `approvals explain <task-uri>` — what does this task require, and can it be
/// satisfied?
///
/// The question that made this whole surface necessary: a `pnm contexts create`
/// failed with `auth:step_up_required`, and the policy the operator was reading
/// was not the policy that fired. This answers from the rules that decide.
pub async fn cmd_explain(
    client: &VtaClient,
    task_type: String,
    context: Option<String>,
) -> CmdResult {
    let model = load(client).await?;
    let ctx = context.as_deref().unwrap_or("default");

    // Same precedence the VTA applies: a context-scoped rule beats an unscoped
    // one for the same task type.
    let matched = model
        .rules
        .iter()
        .find(|r| r.task_type == task_type && r.contexts.iter().any(|c| c == ctx))
        .or_else(|| {
            model
                .rules
                .iter()
                .find(|r| r.task_type == task_type && r.contexts.is_empty())
        });

    println!("{task_type}");
    println!("  context: {ctx}");
    match matched {
        None => {
            println!("  requires: nothing — no rule names this task");
            println!(
                "\n  (a hand-authored policy could still gate it; `{} policy list` shows those)",
                crate::render::bin_name()
            );
        }
        Some(rule) => match rule.requires {
            Requires::Reauth => {
                println!("  requires: re-authentication (AAL2) by the caller");
                println!(
                    "\n  Satisfy it by elevating this session, then re-running the command.\n  \
                     Remove the requirement with:\n    {} approvals remove {task_type}",
                    crate::render::bin_name()
                );
            }
            Requires::Consent => {
                let set = rule.approver_set.as_deref().unwrap_or("?");
                let members = model.approver_sets.get(set);
                let min = rule.effective_min_approvals();
                println!(
                    "  requires: consent — {min} approval(s) from set `{set}`{}",
                    if rule.effective_exclude_requester() {
                        ", requester excluded"
                    } else {
                        ""
                    }
                );
                match members {
                    None => println!(
                        "  approvers: set `{set}` is NOT DEFINED — this task can never run"
                    ),
                    Some(m) if (m.len() as u32) < min => println!(
                        "  approvers: {} member(s) — fewer than the {min} required, so this task \
                         can never run",
                        m.len()
                    ),
                    Some(m) => {
                        println!("  approvers:");
                        for did in m {
                            println!("      {did}");
                        }
                    }
                }
            }
        },
    }
    Ok(())
}
