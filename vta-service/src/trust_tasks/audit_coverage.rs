//! Census: every consequential dispatched task leaves an audit trail.
//!
//! ## Why this exists
//!
//! "Is auditing fully implemented?" had no answer before this file, and could
//! not be given one by reading the code.
//!
//! [`audit_sink`](../../tests/audit_sink.rs) proves the sink *mechanism* — that
//! entries reach an installed sink rather than the keyspace. It says nothing
//! about which tasks emit one. And the emitting is scattered by design: the
//! dispatch spine audits the vault family centrally (`vault_audit`, `None`
//! elsewhere, with the comment that the rest "audit through their own
//! handlers/ops"), while everything else records in its handler, or down in
//! `operations/`, or through the `audit!` macro. Three shapes, no index.
//!
//! Grep cannot settle it — following delegation is the whole difficulty, and a
//! count of `audit::record` in `trust_tasks/` undercounts every task that
//! audits one layer down. So the census is a **runtime** sweep: drive the task
//! and see whether an entry appears.
//!
//! ## What it asserts, and why that shape
//!
//! For every URI in [`dispatched_uris`] whose declared class is not
//! `SideEffectLevel::None`, dispatching it must produce at least one audit
//! entry — **whatever the outcome**.
//!
//! Success is deliberately not required. Setting up the preconditions for
//! ~100 tasks (an ACL entry here, a stored key there) would make this a
//! fixture-maintenance project rather than a census, and it would test the
//! wrong thing: a *refused* privileged attempt is exactly what an incident
//! review goes looking for. "Somebody with these claims asked to wipe a device
//! and was denied" is a sentence the trail has to be able to produce.
//!
//! Reads are exempt by class rather than by name. `vta/credentials/list` audits
//! anyway — enumerating an issuance log is worth a line — but requiring that of
//! every read would demand an entry for every `whoami` poll, which buries the
//! signal it exists to preserve.
//!
//! ## Three helpers, two destinations
//!
//! The first thing this census exposed is that "audits" means two different
//! things in this codebase, and the call site does not say which:
//!
//! - the `audit!` macro emits a `tracing` event on the `audit` target — a **log
//!   line**. It never touches the `AuditSink`, so nothing it records reaches
//!   `audit/list` or an operator's external sink.
//! - `record_with_detail` writes to the sink — the **queryable trail**.
//! - the ceremony helper in `vta-audit` does both.
//!
//! So a handler calling `audit!` and nothing else looks audited when read and
//! is absent from the trail an operator actually queries. `session.revoke` was
//! exactly that, and it took a runtime sweep to notice: the source says
//! `audit!("session.revoke", …)` three lines above the response.
//!
//! ## The exception list is the finding
//!
//! [`NO_AUDIT_BY_DESIGN`] was seeded from what the first run actually reported,
//! not from what anyone believed. Each entry names why, and **the list may only
//! shrink** — a stale one fails the same as a missing entry, so discharging a
//! gap is a diff rather than a quiet edit.
//!
//! Request fixtures come from [`super::conformance::table`], which already
//! holds a schema-valid payload per dispatched URI. Inventing a second set here
//! would be a second thing to keep true.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::Value;
use trust_tasks_rs::{TrustTask, TypeUri};
use vta_sdk::protocols::audit_management::list::AuditLogEntry;
use vti_common::error::AppError;

use crate::policy::SideEffectLevel;
use crate::test_support::{build_signing_test_app_state_with_sink, super_admin_claims};

/// Tasks that dispatch without recording, each with the reason.
///
/// An entry is a claim that *no* trail is the correct behaviour for this task —
/// not that adding one is inconvenient, and not that nobody has got to it. A
/// gap belongs in the issue tracker and out of this list.
const NO_AUDIT_BY_DESIGN: &[(&str, &str)] = &[];

/// A sink that keeps what it is given. Deliberately not backed by a keyspace,
/// so "reached storage" cannot be mistaken for "reached the sink".
#[derive(Default)]
struct Recording {
    seen: Mutex<Vec<AuditLogEntry>>,
}

#[async_trait]
impl vta_audit::AuditSink for Recording {
    async fn record(&self, entry: &AuditLogEntry) -> Result<(), AppError> {
        self.seen.lock().unwrap().push(entry.clone());
        Ok(())
    }
}

/// The consequential half of the dispatch table, in declaration order.
fn consequential_uris() -> Vec<&'static str> {
    super::dispatched_uris()
        .into_iter()
        .filter(|u| {
            super::class_for(u).is_some_and(|class| class.side_effects != SideEffectLevel::None)
        })
        .collect()
}

/// The conformance witness's request payload for `uri`, when it has one.
fn request_fixture(uri: &str) -> Option<Value> {
    super::conformance::request_payload_for(uri)
}

#[tokio::test]
async fn every_consequential_task_records_an_audit_entry() {
    let uris = consequential_uris();
    assert!(
        uris.len() > 40,
        "only {} consequential URIs — the dispatch table walk is broken, and a \
         census that inspects nothing passes vacuously",
        uris.len()
    );

    // Silence is split by what the dispatch actually did, because the two mean
    // very different things and a single number conflates them:
    //
    //   - **succeeded and recorded nothing** — an unambiguous gap. The task did
    //     its work and left no trace.
    //   - **failed and recorded nothing** — the handler audits on success only.
    //     Weaker, and still a finding: a refused privileged attempt is exactly
    //     what an incident review looks for, and this is the shape that hides
    //     it. Separated so the fix can be sized honestly rather than sounding
    //     larger than it is.
    let mut silent_on_success: Vec<&str> = Vec::new();
    let mut silent_on_failure: Vec<&str> = Vec::new();
    let mut unfixtured: Vec<&str> = Vec::new();
    let mut checked = 0usize;

    for uri in &uris {
        let Some(payload) = request_fixture(uri) else {
            // No conformance witness means no schema-valid payload to send.
            // Reported rather than skipped: the two sweeps are meant to cover
            // the same surface, and a URI in neither is invisible to both.
            unfixtured.push(uri);
            continue;
        };

        let sink = Arc::new(Recording::default());
        let (state, _dir) = build_signing_test_app_state_with_sink(Some(
            sink.clone() as vta_audit::SharedAuditSink
        ))
        .await;

        let type_uri: TypeUri = uri.parse().expect("dispatched URI parses");
        let doc = TrustTask::new(
            format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            type_uri,
            payload,
        );

        // Driven through `dispatch_trust_task_core`, NOT `dispatch_typed`.
        //
        // The spine is where the vault family's central audit lives
        // (`vault_audit`), so a census that called the match arm directly would
        // report every `vault/*` and `vault/credentials/*` task as silent —
        // false positives for the one family that audits most thoroughly. I
        // made exactly that mistake writing this, and "fixed" a task that was
        // never broken before catching it.
        let body = serde_json::to_vec(&doc).expect("serialize fixture document");
        let outcome = super::dispatch_trust_task_core(
            &state,
            &super_admin_claims(),
            &body,
            super::transport::TransportConfidentiality::EndToEnd,
        )
        .await;

        checked += 1;
        if sink.seen.lock().unwrap().is_empty() && !NO_AUDIT_BY_DESIGN.iter().any(|(u, _)| u == uri)
        {
            if outcome.status.is_success() {
                silent_on_success.push(uri);
            } else {
                silent_on_failure.push(uri);
            }
        }
    }

    assert!(
        checked > 30,
        "only {checked} tasks were actually driven — too few for this to mean \
         anything; check that conformance fixtures still resolve"
    );

    let stale: Vec<&str> = NO_AUDIT_BY_DESIGN
        .iter()
        .map(|(u, _)| *u)
        .filter(|u| !uris.contains(u))
        .collect();
    assert!(
        stale.is_empty(),
        "these NO_AUDIT_BY_DESIGN entries no longer name a consequential \
         dispatched task — remove them, the list may only shrink:\n  {}",
        stale.join("\n  ")
    );

    let fmt = |v: &[&str]| {
        if v.is_empty() {
            "  (none)".to_string()
        } else {
            format!("  {}", v.join("\n  "))
        }
    };

    // ── The hard invariant ───────────────────────────────────────────────
    //
    // A task that did its work and left no trace is a gap with no defensible
    // reading. This one never gets a tolerated count.
    assert!(
        silent_on_success.is_empty(),
        "{} consequential task(s) SUCCEEDED and recorded no audit entry — the \
         work happened and left no trace:\n{}\n\nRecord one (see \
         `credentials::handle_list` for the handler form, or the `vault_audit` \
         arm on the spine for the central one), or add a NO_AUDIT_BY_DESIGN \
         entry stating why no trail is correct here.",
        silent_on_success.len(),
        fmt(&silent_on_success)
    );

    // ── The ratchet ──────────────────────────────────────────────────────
    //
    // Auditing only on success is the weaker defect, and the more common one:
    // a *refused* privileged attempt leaves nothing, and "who tried to wipe
    // this device and was denied" is precisely the sentence an incident review
    // needs. Fixing all of them at once would be ~60 handlers in one diff, so
    // it is a budget that may only shrink rather than a wall.
    //
    // Lower this number in the same commit that fixes one. Never raise it: a
    // new handler auditing on success only is a new instance of a defect this
    // file exists to retire, not a reason to move the line.
    const AUDIT_ON_SUCCESS_ONLY_BUDGET: usize = 72;
    assert!(
        silent_on_failure.len() <= AUDIT_ON_SUCCESS_ONLY_BUDGET,
        "{} consequential task(s) were REFUSED and recorded nothing, over the \
         budget of {}. These audit on success only, so a denied privileged \
         attempt leaves no trail:\n{}",
        silent_on_failure.len(),
        AUDIT_ON_SUCCESS_ONLY_BUDGET,
        fmt(&silent_on_failure)
    );
    assert!(
        silent_on_failure.len() == AUDIT_ON_SUCCESS_ONLY_BUDGET,
        "the audit-on-success-only budget is {} but only {} task(s) hit it — \
         some were fixed. Lower the constant to {} in this commit, so the \
         ratchet keeps its teeth.",
        AUDIT_ON_SUCCESS_ONLY_BUDGET,
        silent_on_failure.len(),
        silent_on_failure.len()
    );

    // ── Reported, not asserted ───────────────────────────────────────────
    //
    // A URI with no conformance witness is invisible to this sweep *and* to the
    // schema one. Not failed here — the schema sweep owns that gap and says so
    // in its own words — but printed, because a census that quietly skips is
    // the thing this file exists not to be.
    if !unfixtured.is_empty() {
        eprintln!(
            "audit-coverage census: {} consequential task(s) had no conformance \
             fixture and were not driven:\n{}",
            unfixtured.len(),
            fmt(&unfixtured)
        );
    }
}
