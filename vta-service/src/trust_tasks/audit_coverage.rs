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
//! dispatch spine audits centrally, while everything else records in its
//! handler, or down in `operations/`, or through the `audit!` macro. Three
//! shapes, no index.
//!
//! Grep cannot settle it — following delegation is the whole difficulty, and a
//! count of `audit::record` in `trust_tasks/` undercounts every task that
//! audits one layer down. So the census is a **runtime** sweep: drive the task
//! and see whether an entry appears.
//!
//! ## The first version of this file measured nothing, and said 72
//!
//! Worth keeping, because the failure is not obvious and the output looked
//! entirely plausible.
//!
//! It built each document with `TrustTask::new(id, type_uri, payload)` and
//! dispatched it. That envelope carries no `issuer`, `recipient`, `issuedAt`
//! or `proof` — and the spine enforces all four *before* dispatch. So every
//! one of the 72 documents was refused `422 expired` at the freshness check,
//! and **not a single handler ran**. The sweep then reported that 72
//! consequential tasks were refused and recorded nothing, and concluded those
//! 72 handlers "audit on success only", with a budget and a note that fixing
//! them would be ~60 handlers in one diff.
//!
//! Every part of that was wrong except the count. There was one unaudited code
//! path, exercised once per task. The `silent_on_success` invariant next to it
//! passed *vacuously*, for the same reason: nothing ever succeeded, so nothing
//! could succeed silently.
//!
//! A census whose fixtures cannot get past the front door reports the door,
//! once per caller, and looks like a survey. Hence [`conforming envelopes`],
//! and hence the assertion below that some tasks actually succeed — a sweep
//! where nothing does is measuring the gate again.
//!
//! [`conforming envelopes`]: every_consequential_task_records_an_audit_entry
//!
//! ## What it asserts, and why that shape
//!
//! For every URI in [`super::dispatched_uris`] whose declared class is not
//! `SideEffectLevel::None`, dispatching it must produce at least one audit
//! entry — **whatever the outcome**.
//!
//! Success is deliberately not required of every task. Setting up the
//! preconditions for ~84 tasks (an ACL entry here, a stored key there) would
//! make this a fixture-maintenance project rather than a census. But *some*
//! must succeed, or the sweep has silently gone back to measuring one gate.
//!
//! Refusal is where the security value is. "Somebody with these claims asked
//! to wipe a device and was denied" is a sentence the trail has to be able to
//! produce, and it is the sentence that was missing for every task in every
//! family until the dispatch audit moved one frame up.
//!
//! Reads are exempt by class rather than by name. `vta/credentials/list`
//! audits anyway — enumerating an issuance log is worth a line — but requiring
//! that of every read would demand an entry for every `whoami` poll, which
//! buries the signal it exists to preserve.
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
//! is absent from the trail an operator actually queries.
//!
//! ## Two exception lists, and they claim different things
//!
//! [`NO_AUDIT_BY_DESIGN`] says no trail is ever correct for a task.
//! [`NO_AUDIT_WHEN_NO_OP`] says the task audits when it changes something, and
//! this sweep's empty store makes it a no-op. Conflating them would license
//! "fixing" a handler into recording work it did not do.
//!
//! Both may only shrink — a stale entry fails the same as a missing one, so
//! discharging a gap is a diff rather than a quiet edit.
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

/// Tasks whose audit is conditional on having *done* something, listed with
/// what makes the census's run a no-op.
///
/// Separate from [`NO_AUDIT_BY_DESIGN`], and the distinction is the point.
/// That list claims no trail is ever correct for a task. These tasks audit
/// perfectly well when they change something — they are here because the
/// census drives an **empty store**, so each takes a documented early-return
/// arm where there was nothing to revoke, and not recording a no-op is a
/// decision each handler states in its own words.
///
/// This is a limit of the census, not a defect in the handlers, and it is
/// named rather than folded into the other list so that nobody later "fixes"
/// a handler into auditing work it did not do.
const NO_AUDIT_WHEN_NO_OP: &[(&str, &str)] = &[
    (
        "https://trusttasks.org/spec/auth/revoke-session/0.1",
        "The fixture names a session that does not exist, so the handler takes \
         its no-session arm: a `tracing` line with outcome=\"no-op\" and no \
         sink row. The path that actually deletes a session records both forms, \
         and says why they are not redundant.",
    ),
    (
        "https://trusttasks.org/spec/consent/revoke/1.0",
        "The fixture names a subject with no grant, so the handler returns \
         `notFound` as a status before reaching its audit call — deliberately: \
         \"a revoke that deleted nothing is not a state change worth a line\".",
    ),
];

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
    let mut failures = 0usize;
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
        let mut doc = TrustTask::new(
            format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            type_uri,
            payload,
        );

        // The envelope has to CONFORM, or this census measures one gate.
        //
        // A bare `TrustTask::new` carries no `issuer`, `recipient`, `issuedAt`
        // or `proof`. The spine enforces all four before dispatch (§7.2 items
        // 5b/6/7a, §7.3 item 17), so the first version of this file sent 72
        // documents and had all 72 refused `422 expired` at the freshness
        // check. **No handler ever ran.** The census still reported a number,
        // and the number read like a finding about handlers: it was one
        // refusal path, counted once per task. See the module header.
        //
        // So: issued now, addressed to this agent, and issued by the same DID
        // the claims authenticate — §7.2 item 6 refuses a document whose
        // in-band issuer disagrees with the authenticated identity, which is a
        // second gate that would swallow the run just as quietly.
        doc.issuer = Some(super_admin_claims().did);
        doc.recipient = state.config.read().await.vta_did.clone();
        doc.issued_at = Some(chrono::Utc::now());
        crate::test_support::sign_as_test_admin(&mut doc);

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
        if !outcome.status.is_success() {
            failures += 1;
        }
        let excused = NO_AUDIT_BY_DESIGN.iter().any(|(u, _)| u == uri)
            || NO_AUDIT_WHEN_NO_OP.iter().any(|(u, _)| u == uri);
        if sink.seen.lock().unwrap().is_empty() && !excused {
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

    // A sweep where nothing succeeds is measuring the gate, not the handlers —
    // which is exactly what this file did on its first outing, plausibly and
    // silently. This is the assertion that would have caught it.
    let succeeded = checked - failures;
    assert!(
        succeeded >= 5,
        "only {succeeded} of {checked} task(s) reached a handler and succeeded. \
         The envelope is being refused before dispatch again — check `issuer`, \
         `recipient`, `issuedAt` and the proof, and see the module header."
    );

    let stale: Vec<&str> = NO_AUDIT_BY_DESIGN
        .iter()
        .chain(NO_AUDIT_WHEN_NO_OP.iter())
        .map(|(u, _)| *u)
        .filter(|u| !uris.contains(u))
        .collect();
    assert!(
        stale.is_empty(),
        "these NO_AUDIT_BY_DESIGN / NO_AUDIT_WHEN_NO_OP entries no longer name \
         a consequential dispatched task — remove them, the lists may only \
         shrink:\n  {}",
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

    // ── The second hard invariant ─────────────────────────────────────────
    //
    // This used to be a *budget* of 72, "audit-on-success-only handlers", with
    // a note that fixing them would be ~60 handlers in one diff. Both the
    // number and the diagnosis were wrong, and the fix was one line in a
    // different file.
    //
    // The 72 were not 72 handlers. They were 72 tasks refused at the same
    // freshness gate, because the census sent envelopes with no `issuedAt` —
    // one code path, counted once per task, mistaken for a per-handler
    // finding. With conforming envelopes (above) the documents reach handlers,
    // and the real number of consequential tasks that get refused and record
    // nothing is **zero**: the dispatch audit sits one frame up from the
    // function whose dozen early returns used to skip it, so a refusal cannot
    // return without passing it.
    //
    // A budget was the right shape for a debt paid down over many commits. A
    // gap that is closed structurally gets an invariant instead — anything
    // else invites the number back up.
    assert!(
        silent_on_failure.is_empty(),
        "{} consequential task(s) were REFUSED and recorded nothing. A denied \
         privileged attempt is exactly what an incident review looks for, and \
         this is the shape that hides it:\n{}\n\nThe spine records every \
         refusal (`DispatchAudit::record` in `trust_tasks/mod.rs`), so a task \
         reaching here means something returned without passing it.",
        silent_on_failure.len(),
        fmt(&silent_on_failure)
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
