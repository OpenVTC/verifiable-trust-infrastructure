//! **Dynamic groups**: membership computed from a rule over verified facts
//! (`kind: dynamic`, VTI-DIR-011, VTI-DIR-103).
//!
//! A rule (`DynamicRule`) is a list of conditions that must all hold, each over
//! one fact the community itself vouches for: the community role, an `admin`-
//! or `credential`-sourced directory field, personhood, the join date. It never
//! reads a value a member writes, so nobody joins a group by editing their card
//! — checked when the rule is written (`super::check_rule`) and again at every
//! evaluation, against the field schema as it stands then.
//!
//! # Opt-outs
//!
//! A member may decline any dynamic group: `vtc/groups/leave` records an
//! **opt-out** (`gopt:<groupId>:<entryId>`), an exclusion the rule cannot
//! override, and `vtc/groups/join` withdraws it. An opt-out counts even before
//! the rule reaches the member. A dynamic group never confers authority, so the
//! community never overrides the member's choice.
//!
//! # The recompute
//!
//! [`recompute`] brings one group's memberships into line with its rule: every
//! active member the rule admits and who has not opted out is admitted as a
//! membership with source `rule` — the group's credential issued and offered
//! **first**, as any admission (`members/add` item 3) — and every rule-sourced
//! membership the rule no longer admits, or whose member opted out, ends. A
//! departed member is no subject: departure ends their memberships itself.
//!
//! The sweeper ([`spawn`]) is the one owner of retries: it runs every few
//! minutes and whenever something a rule reads may have changed ([`kick`] —
//! the directory's and groups' writes, a rule change, an opt-out undone). An
//! admission whose credential the VTA did not issue is retried on a capped,
//! jittered backoff kept in memory.

use std::collections::{BTreeSet, HashMap};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use chrono::{DateTime, NaiveDate, Utc};
use serde_json::Value;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::{Group, GroupKind, Membership};
use crate::directory::model::{FieldDef, FieldSource, FieldState};
use crate::directory::project::Subject;
use crate::server::AppState;

/// How a rule admits a member: the membership's `source`.
pub const SOURCE: &str = "rule";
const TICK: Duration = Duration::from_secs(5 * 60);
const FIRST_PASS: Duration = Duration::from_secs(30);
const RETRY_BASE: Duration = Duration::from_secs(60);
const RETRY_CAP: Duration = Duration::from_secs(6 * 60 * 60);

// ─── the rule ─────────────────────────────────────────────────────────────

/// A date fact or value: `YYYY-MM-DD`, or an RFC 3339 instant read as its date.
fn date(v: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(v, "%Y-%m-%d").ok().or_else(|| {
        DateTime::parse_from_rfc3339(v)
            .ok()
            .map(|t| t.with_timezone(&Utc).date_naive())
    })
}

/// A stored card value as the rule compares it: a credential-sourced value
/// carries its claim under `value`.
fn scalar(v: &Value) -> &Value {
    match v {
        Value::Object(o) => o.get("value").unwrap_or(v),
        _ => v,
    }
}

fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Whether a fact `got` (absent: `None`) satisfies `op` with `value` /
/// `values`. A list fact satisfies `equals` and `oneOf` when any of its items
/// does.
fn test(got: Option<&Value>, op: &str, value: Option<&Value>, values: Option<&Value>) -> bool {
    let Some(got) = got.filter(|g| !g.is_null()) else {
        return false;
    };
    if let Value::Array(items) = got {
        return op != "before"
            && op != "after"
            && (op == "exists" && !items.is_empty()
                || items.iter().any(|i| test(Some(i), op, value, values)));
    }
    match op {
        "exists" => got != &Value::Bool(false) && got != &Value::String(String::new()),
        "equals" => match (got, value) {
            (Value::Bool(a), Some(Value::Bool(b))) => a == b,
            (_, Some(v)) => as_text(got).is_some() && as_text(got) == as_text(v),
            _ => false,
        },
        "oneOf" => {
            let Some(t) = as_text(got) else { return false };
            values
                .and_then(Value::as_array)
                .is_some_and(|vs| vs.iter().any(|v| v.as_str() == Some(t.as_str())))
        }
        "before" | "after" => {
            let (Some(a), Some(b)) = (
                got.as_str().and_then(date),
                value.and_then(Value::as_str).and_then(date),
            ) else {
                return false;
            };
            if op == "before" { a < b } else { a > b }
        }
        _ => false,
    }
}

/// The counts a badge group's rule may read (VTI-BDG-015), each from the
/// community's own records: kudos the member accepted, ideas of theirs a board
/// selected, elections it issued them a ticket in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub kudos_received: u64,
    pub ideas_selected: u64,
    pub election_tickets: u64,
}

/// The facts only a badge group's rule reads (VTI-BDG-015).
pub const COUNT_FACTS: [&str; 3] = ["kudosReceived", "ideasSelected", "electionTickets"];

/// Whether `rule` reads any of [`COUNT_FACTS`].
pub fn reads_counts(rule: &Value) -> bool {
    rule.get("all").and_then(Value::as_array).is_some_and(|cs| {
        cs.iter().any(|c| {
            c.get("fact")
                .and_then(Value::as_str)
                .is_some_and(|f| COUNT_FACTS.contains(&f))
        })
    })
}

/// Whether `rule` admits `subject` now, reading the field schema as it stands:
/// a condition on a field that is no longer an active `admin`- or
/// `credential`-sourced one holds for nobody. A malformed rule admits nobody, and
/// a count holds for nobody here: only [`admits_counting`] reads one.
pub fn admits(rule: &Value, subject: &Subject, schema: &[FieldDef]) -> bool {
    admits_counting(rule, subject, schema, None)
}

/// [`admits`], with the subject's badge counts where the group is a badge's.
pub fn admits_counting(
    rule: &Value,
    subject: &Subject,
    schema: &[FieldDef],
    counts: Option<&Counts>,
) -> bool {
    let Some(conditions) = rule
        .get("all")
        .and_then(Value::as_array)
        .filter(|c| !c.is_empty())
    else {
        return false;
    };
    conditions.iter().all(|c| {
        let op = c.get("op").and_then(Value::as_str).unwrap_or_default();
        let value = c.get("value");
        let values = c.get("values");
        let role;
        let joined;
        let personhood;
        let got: Option<&Value> = match c.get("fact").and_then(Value::as_str) {
            Some("role") => {
                role = Value::String(subject.role.clone());
                Some(&role)
            }
            Some("joinedAt") => {
                joined = Value::String(subject.joined_at.format("%Y-%m-%d").to_string());
                Some(&joined)
            }
            Some("personhood") => {
                // `exists`: a personhood assertion is on file.
                personhood = Value::Bool(subject.personhood);
                if op == "exists" {
                    return subject.personhood;
                }
                Some(&personhood)
            }
            Some(fact @ ("kudosReceived" | "ideasSelected" | "electionTickets")) => {
                let Some(counts) = counts else {
                    return false;
                };
                let n = match fact {
                    "kudosReceived" => counts.kudos_received,
                    "ideasSelected" => counts.ideas_selected,
                    _ => counts.election_tickets,
                };
                return op == "atLeast"
                    && c.get("count")
                        .and_then(Value::as_u64)
                        .is_some_and(|v| n >= v);
            }
            Some("field") => {
                let key = c.get("field").and_then(Value::as_str).unwrap_or_default();
                let verified = schema.iter().any(|f| {
                    f.key == key
                        && f.state == FieldState::Active
                        && matches!(f.source, FieldSource::Admin | FieldSource::Credential)
                });
                if !verified {
                    return false;
                }
                subject.card.values.get(key).map(scalar)
            }
            _ => return false,
        };
        test(got, op, value, values)
    })
}

// ─── opt-outs ─────────────────────────────────────────────────────────────

fn opt_key(group_id: &str, entry_id: &str) -> Vec<u8> {
    format!("gopt:{group_id}:{entry_id}").into_bytes()
}

/// Whether `entry_id` has opted out of `group_id`.
pub async fn opted_out(
    ks: &KeyspaceHandle,
    group_id: &str,
    entry_id: &str,
) -> Result<bool, AppError> {
    Ok(ks.get_raw(opt_key(group_id, entry_id)).await?.is_some())
}

/// Record `entry_id`'s opt-out of `group_id` (leave item 3).
pub async fn opt_out(ks: &KeyspaceHandle, group_id: &str, entry_id: &str) -> Result<(), AppError> {
    ks.insert_raw(opt_key(group_id, entry_id), b"1".to_vec())
        .await
}

/// Withdraw `entry_id`'s opt-out of `group_id` (join item 3).
pub async fn withdraw_opt_out(
    ks: &KeyspaceHandle,
    group_id: &str,
    entry_id: &str,
) -> Result<(), AppError> {
    ks.remove(opt_key(group_id, entry_id)).await
}

/// The entries that opted out of `group_id`.
async fn opt_outs(ks: &KeyspaceHandle, group_id: &str) -> Result<BTreeSet<String>, AppError> {
    let prefix = format!("gopt:{group_id}:");
    Ok(ks
        .prefix_keys(prefix.clone().into_bytes())
        .await?
        .into_iter()
        .map(|k| String::from_utf8_lossy(&k[prefix.len()..]).into_owned())
        .collect())
}

/// The groups `entry_id` opted out of.
pub async fn opted_out_of(
    ks: &KeyspaceHandle,
    entry_id: &str,
) -> Result<BTreeSet<String>, AppError> {
    let suffix = format!(":{entry_id}");
    Ok(ks
        .prefix_keys(b"gopt:".to_vec())
        .await?
        .into_iter()
        .filter_map(|k| {
            let name = String::from_utf8_lossy(&k).into_owned();
            name.strip_prefix("gopt:")?
                .strip_suffix(&suffix)
                .map(str::to_string)
        })
        .collect())
}

/// Forget every opt-out of `group_id` (it was deleted), or of `entry_id` (they
/// left the community).
pub async fn forget_opt_outs(
    ks: &KeyspaceHandle,
    group_id: Option<&str>,
    entry_id: Option<&str>,
) -> Result<(), AppError> {
    let prefix = match group_id {
        Some(g) => format!("gopt:{g}:"),
        None => "gopt:".to_string(),
    };
    for k in ks.prefix_keys(prefix.into_bytes()).await? {
        let name = String::from_utf8_lossy(&k).into_owned();
        if entry_id.is_none_or(|e| name.ends_with(&format!(":{e}"))) {
            ks.remove(k).await?;
        }
    }
    Ok(())
}

// ─── the recompute ────────────────────────────────────────────────────────

/// What a recompute did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// Entries admitted.
    pub admitted: Vec<String>,
    /// Entries whose rule-sourced membership ended.
    pub ended: Vec<String>,
    /// Admissions the VTA did not issue a credential for, to retry.
    pub failed: usize,
}

static RETRIES: LazyLock<Mutex<HashMap<String, (u32, DateTime<Utc>)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn due(step: &str, now: DateTime<Utc>) -> bool {
    RETRIES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(step)
        .is_none_or(|(_, next)| *next <= now)
}

fn failed(step: &str, now: DateTime<Utc>) -> u32 {
    use rand::RngExt as _;
    let mut map = RETRIES.lock().unwrap_or_else(|p| p.into_inner());
    let attempts = map.get(step).map_or(0, |(a, _)| *a) + 1;
    let factor = 1u32
        .checked_shl(attempts.saturating_sub(1))
        .unwrap_or(u32::MAX);
    let ceiling = RETRY_BASE.saturating_mul(factor).min(RETRY_CAP).as_secs();
    let half = ceiling / 2;
    let secs = half + rand::rng().random_range(0..=ceiling - half);
    map.insert(
        step.to_string(),
        (attempts, now + chrono::Duration::seconds(secs as i64)),
    );
    attempts
}

fn succeeded(step: &str) {
    RETRIES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(step);
}

/// Bring `group`'s memberships into line with its rule (module docs). A static
/// group is left alone.
pub async fn recompute(
    state: &AppState,
    group: &Group,
    now: DateTime<Utc>,
) -> Result<Report, AppError> {
    if group.kind != GroupKind::Dynamic || group.rule.is_none() {
        return Ok(Report::default());
    }
    let subjects = crate::directory::read::subjects(state).await?;
    recompute_over(state, group, &subjects, now).await
}

/// [`recompute`] over `subjects` read once for a whole pass, so a pass over G
/// dynamic groups reads every member once rather than G times (#2600). The
/// pass is short next to the sweeper's tick, and a fact that moves during it
/// moves the bus and wakes the next pass.
async fn recompute_over(
    state: &AppState,
    group: &Group,
    subjects: &[crate::directory::project::Subject],
    now: DateTime<Utc>,
) -> Result<Report, AppError> {
    let mut report = Report::default();
    let (GroupKind::Dynamic, Some(rule)) = (group.kind, &group.rule) else {
        return Ok(report);
    };
    let ks = state.directory.ks();
    let schema = crate::directory::fields::schema(ks).await?;
    let excluded = opt_outs(ks, &group.group_id).await?;
    // A badge group's rule may read counts of the community's own records (VTI-BDG-015).
    let counts = if group.badge_id.is_some() && reads_counts(rule) {
        crate::badges::rule_counts(state, subjects).await?
    } else {
        HashMap::new()
    };
    let wanted: BTreeSet<String> = subjects
        .iter()
        .filter(|s| s.active && !excluded.contains(&s.card.entry_id))
        .filter(|s| {
            let c = counts.get(&s.card.entry_id).copied().unwrap_or_default();
            admits_counting(rule, s, &schema, Some(&c))
        })
        .map(|s| s.card.entry_id.clone())
        .collect();
    let held: HashMap<String, Membership> = super::members_of(ks, &group.group_id)
        .await?
        .into_iter()
        .map(|m| (m.entry_id.clone(), m))
        .collect();

    for s in subjects
        .iter()
        .filter(|s| wanted.contains(&s.card.entry_id))
    {
        let entry_id = &s.card.entry_id;
        if held.contains_key(entry_id) {
            continue;
        }
        let step = format!("{}:{entry_id}", group.group_id);
        if !due(&step, now) {
            continue;
        }
        match admit(state, group, &s.card.did, entry_id, now).await {
            Ok(true) => {
                succeeded(&step);
                report.admitted.push(entry_id.clone());
            }
            Ok(false) => succeeded(&step),
            Err(e) => {
                let attempts = failed(&step, now);
                tracing::warn!(group = %group.group_id, attempts, error = %e,
                    "a dynamic group's admission could not be completed; retrying later");
                report.failed += 1;
            }
        }
    }

    for (entry_id, m) in &held {
        if m.source != SOURCE || wanted.contains(entry_id) {
            continue;
        }
        let _guard = crate::directory::WRITE_LOCK.lock().await;
        if super::membership(ks, &group.group_id, entry_id)
            .await?
            .is_some_and(|m| m.source == SOURCE)
        {
            super::remove_membership(ks, &group.group_id, entry_id).await?;
            report.ended.push(entry_id.clone());
        }
    }
    // An automatic badge's holding ends with the rule's admission (VTI-BDG-013, 063).
    if group.badge_id.is_some() {
        let actor = state
            .config
            .read()
            .await
            .vtc_did
            .clone()
            .unwrap_or_default();
        for entry_id in &report.ended {
            crate::badges::on_group_exit(
                state,
                group,
                entry_id,
                &actor,
                crate::badges::GroupExit::Removed,
            )
            .await?;
        }
    }
    if !report.admitted.is_empty() || !report.ended.is_empty() {
        audit(state, group, &report).await;
        super::bindings::kick();
    }
    Ok(report)
}

/// Admit `did` (at `entry_id`) as the rule does: credential first where the
/// group issues them, then the membership. `false`: a membership appeared
/// meanwhile, and stands.
pub async fn admit(
    state: &AppState,
    group: &Group,
    did: &str,
    entry_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, AppError> {
    let issued = if group.issues_credentials {
        let issued = super::credential::issue_admitting(state, group, did, entry_id, None)
            .await
            .map_err(|f| match f {
                super::identity::Failure::Local(e) => e,
                super::identity::Failure::Holder(e, _) => AppError::ServiceError {
                    status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    message: format!("the community's VTA did not issue the credential: {e:?}"),
                },
            })?;
        super::credential::offer(state, group, did, &issued).await;
        Some(issued)
    } else {
        None
    };
    let ks = state.directory.ks();
    let _guard = crate::directory::WRITE_LOCK.lock().await;
    if super::membership(ks, &group.group_id, entry_id)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    super::put_membership(
        ks,
        &Membership {
            group_id: group.group_id.clone(),
            entry_id: entry_id.to_string(),
            source: SOURCE.into(),
            since: now,
            state: "active".into(),
            credential_id: issued.as_ref().map(|i| i.credential_id.clone()),
            credential_valid_until: issued.as_ref().map(|i| i.valid_until),
        },
    )
    .await?;
    Ok(true)
}

/// One `GroupMembershipChanged` row per change, by reference, as the
/// community itself (it decided, under the rule).
async fn audit(state: &AppState, group: &Group, report: &Report) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    let community = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_default();
    let rows = report
        .admitted
        .iter()
        .map(|e| (e, "ruleAdmitted"))
        .chain(report.ended.iter().map(|e| (e, "ruleEnded")));
    for (entry_id, change) in rows {
        let event = vti_common::audit::AuditEvent::GroupMembershipChanged(
            vti_common::audit::GroupMembershipChangedData {
                group_id: group.group_id.clone(),
                entry_id: entry_id.clone(),
                change: change.into(),
                reason: None,
            },
        );
        if let Err(e) = writer.write(&community, None, event).await {
            tracing::warn!(error = %e, "a dynamic group's membership change could not be audited");
        }
    }
}

/// [`recompute`] every dynamic group.
///
/// The members are read once for the pass ([`recompute_over`]), and not at
/// all while no dynamic group exists.
pub async fn recompute_all(state: &AppState, now: DateTime<Utc>) -> Result<(), AppError> {
    let dynamic: Vec<Group> = super::all(state.directory.ks())
        .await?
        .into_iter()
        .filter(|g| g.kind == GroupKind::Dynamic)
        .collect();
    if dynamic.is_empty() {
        return Ok(());
    }
    let subjects = crate::directory::read::subjects(state).await?;
    for group in &dynamic {
        if let Err(e) = recompute_over(state, group, &subjects, now).await {
            tracing::warn!(group = %group.group_id, error = %e, "a dynamic group could not be recomputed");
        }
    }
    Ok(())
}

static WAKE: LazyLock<tokio::sync::Notify> = LazyLock::new(tokio::sync::Notify::new);

/// How long a kicked sweeper waits before its pass, so a burst of writes (a
/// bulk admission writes a member, an ACL entry and a card per admission) is
/// one recompute rather than one per write (#2600).
const KICK_DEBOUNCE: Duration = Duration::from_secs(2);

/// Wake the sweeper: something a rule reads may have changed.
pub fn kick() {
    WAKE.notify_one();
}

/// Run the sweeper until shutdown. Always spawned: it does nothing while no
/// dynamic group exists.
pub fn spawn(state: AppState, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut wait = FIRST_PASS;
        loop {
            let kicked = tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(wait) => false,
                _ = WAKE.notified() => true,
            };
            if kicked {
                // Coalesce the burst: wait a moment, then take the permit any
                // kick in that moment left, which this pass answers too.
                tokio::select! {
                    _ = shutdown.changed() => return,
                    _ = tokio::time::sleep(KICK_DEBOUNCE) => {}
                }
                tokio::select! {
                    biased;
                    _ = WAKE.notified() => {}
                    _ = std::future::ready(()) => {}
                }
            }
            wait = TICK;
            if let Err(e) = recompute_all(&state, Utc::now()).await {
                tracing::warn!(error = %e, "dynamic groups could not be recomputed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_condition_tests_its_fact() {
        let s = |v: Value| Some(v);
        assert!(test(
            s(json!("moderator")).as_ref(),
            "equals",
            Some(&json!("moderator")),
            None
        ));
        assert!(!test(
            s(json!("member")).as_ref(),
            "equals",
            Some(&json!("moderator")),
            None
        ));
        assert!(test(
            s(json!("Sydney")).as_ref(),
            "oneOf",
            None,
            Some(&json!(["Sydney", "Melbourne"]))
        ));
        assert!(test(
            s(json!(["a", "Sydney"])).as_ref(),
            "oneOf",
            None,
            Some(&json!(["Sydney"]))
        ));
        assert!(test(
            s(json!(true)).as_ref(),
            "equals",
            Some(&json!(true)),
            None
        ));
        assert!(!test(None, "exists", None, None));
        assert!(test(s(json!("x")).as_ref(), "exists", None, None));
        assert!(test(
            s(json!("2026-01-01")).as_ref(),
            "before",
            Some(&json!("2026-06-01")),
            None
        ));
        assert!(test(
            s(json!("2026-07-01")).as_ref(),
            "after",
            Some(&json!("2026-06-01T00:00:00Z")),
            None
        ));
        assert!(!test(
            s(json!("soon")).as_ref(),
            "before",
            Some(&json!("2026-06-01")),
            None
        ));
    }

    #[test]
    fn a_credential_value_is_compared_by_its_claim() {
        let v = json!({ "value": "REG-1", "issuer": "did:example:i" });
        assert_eq!(scalar(&v), &json!("REG-1"));
        assert_eq!(scalar(&json!("plain")), &json!("plain"));
    }
}
