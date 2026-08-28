//! Artifact lifecycle: the vocabulary, and the one rule that says which state
//! controls when an artifact and a later event about it disagree.
//!
//! ## The gap this closes
//!
//! #1075 fixed an instance — an expired VRC became a permanent graph edge
//! because `routes/relationships.rs` read neither `validFrom` nor
//! `validUntil`. It did not fix the class. Nothing in this workspace
//! established **precedence between a cryptographically valid but stale
//! artifact and a later lifecycle event**, and the relationship graph had no
//! vocabulary beyond "the row exists" and "the row was deleted" (#1079).
//!
//! The absence of revocation is what makes precedence load-bearing rather than
//! decorative. A VRC deliberately carries no `credentialStatus` — planning
//! review D7, because a status-list host learns which verifier checked which
//! credential and when, which is the correlation the pairwise work exists to
//! remove. Where a credential type omits status for privacy reasons, effective
//! time and event precedence are not a refinement layered on top of revocation;
//! they are the only lifecycle mechanism left.
//!
//! ## Two clocks, and which one wins
//!
//! An artifact carries two independent notions of time, and conflating them is
//! how "still valid" and "no longer in force" got treated as one question:
//!
//! - **validity time** — the window the issuer stated *inside* the artifact,
//!   fixed at issuance and covered by its signature. [`ValidityWindow`].
//! - **transaction time** — when this service *recorded* something about the
//!   artifact afterwards. [`LifecycleLog`], append-only.
//!
//! [`resolve`] combines them under one rule, stated once here so no call site
//! has to re-derive it:
//!
//! > A later recorded event takes precedence over the artifact's own earlier
//! > assertion, but only in the restrictive direction. An event can put an
//! > artifact out of force at any time; **no event can put an artifact into
//! > force that its own window excludes.**
//!
//! The asymmetry is the whole design. Precedence exists so that a community
//! can end an artifact's effect without waiting for its window and without a
//! status list; letting it run the other way would let a recorded event
//! manufacture validity the issuer never signed for, which is a far worse
//! failure than an edge that lingers. So [`LifecycleEventKind::Restored`]
//! returns an artifact to the governance of its own window — it does not
//! extend it. Restoring a credential that expired while suspended yields
//! [`InForce::Expired`], not [`InForce::Yes`].
//!
//! ## Restoration versus replacement
//!
//! [`LifecycleEventKind::Restored`] reverses a suspension and nothing else.
//! [`LifecycleEventKind::Withdrawn`] and [`LifecycleEventKind::Superseded`]
//! are terminal: once recorded, no further event is accepted against that
//! artifact.
//!
//! This is a deliberate boundary, not a limitation. "Un-withdraw" and
//! "un-supersede" read like the inverse of the verbs they undo, but they are
//! not: the party relying on the artifact between the withdrawal and the
//! reversal was entitled to treat it as gone, and a log that can take a
//! terminal state back cannot be used to answer "was this in force at time T"
//! — which is the question the log exists to answer. The supported way to give
//! effect back to a withdrawn or superseded relationship is to issue a fresh
//! artifact, which produces a new signature, a new window, and a record that
//! says a *new* assertion was made rather than an old one quietly resumed.
//!
//! ## Deliberately undiscoverable current state
//!
//! [`resolve`] is a *local* answer: it reports what this service has recorded.
//! A verifier elsewhere holding the same VRC has no way to reach this log, by
//! design — that is the same privacy decision that removed `credentialStatus`.
//! Such a verifier is entitled to conclude only that the artifact was validly
//! issued and is inside its window; it is **not** entitled to conclude the
//! artifact is in force, because it cannot see whether a later event displaced
//! it. Anything that must be relied on without discovery has to carry its own
//! bound window, which is why the VIC and recognition paths *require*
//! `validUntil` where this module treats it as optional
//! (`credentials::ingress::check_validity_window`).
//!
//! ## Where it is applied
//!
//! Relationships are wired up: [`crate::relationships::Relationship`] carries
//! a log, the graph view resolves both halves before calling an edge complete,
//! and the suspend / restore / supersede routes are the producers. The types
//! here are deliberately artifact-agnostic — they take a window and a log, not
//! a `Relationship` — so a VPC, a VDC or a VMC can be brought under the same
//! rule without a second precedence implementation appearing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vti_common::error::AppError;

/// The validity window an artifact asserts about itself.
///
/// Read from a credential by `credentials::ingress::validity_window`, which
/// owns the parsing (both the VC 2.0 and VC 1.1 spellings, and the rejection
/// of a document stating both). The type lives here rather than there because
/// the window is half of the vocabulary this module defines; the reader lives
/// there because ingress is where documents from outside are parsed.
///
/// Both bounds are optional, because both are optional in W3C VC 2.0. An
/// absent bound states no bound — it is not treated as "now".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ValidityWindow {
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
}

impl ValidityWindow {
    /// An artifact that states neither bound. Its window can never exclude it,
    /// so its state is decided entirely by its lifecycle log.
    pub const UNBOUNDED: Self = Self {
        valid_from: None,
        valid_until: None,
    };

    /// Where `now` sits relative to the stated bounds.
    ///
    /// **Half-open: `validFrom <= now < validUntil`.** The same boundary
    /// `credentials::ingress::check_validity_window`,
    /// `credentials::invitation_verify` and `recognition::verify` all use. A
    /// credential whose `validUntil` is exactly `now` is expired. Disagreeing
    /// with those three by a single instant would make an artifact publishable
    /// and simultaneously out of force, which no caller could act on.
    pub fn state_at(&self, now: DateTime<Utc>) -> InForce {
        if let Some(from) = self.valid_from
            && now < from
        {
            return InForce::NotYetValid { valid_from: from };
        }
        if let Some(until) = self.valid_until
            && now >= until
        {
            return InForce::Expired { valid_until: until };
        }
        InForce::Yes
    }
}

/// A lifecycle event recorded against an artifact after it was issued.
///
/// The variants are the vocabulary #1079 says is missing. They are separate
/// variants rather than a `status: String` because the transition rules in
/// [`LifecycleLog::record`] have to distinguish them, and a stringly-typed
/// state machine is one typo away from accepting a transition it rejects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", tag = "event")]
pub enum LifecycleEventKind {
    /// Temporarily ineffective, not withdrawn. The distinction matters to the
    /// party being suspended as much as to a verifier: a suspension says the
    /// relying party should stop relying *for now*, and leaves a supported
    /// route back.
    Suspended {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Reverses a suspension, returning the artifact to the governance of its
    /// own window. Never valid against any other standing state — see the
    /// module doc on restoration versus replacement.
    Restored {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// A later artifact has displaced this one. Terminal.
    ///
    /// `by` names the displacing artifact by digest rather than by row id, so
    /// the record stays meaningful to a reader who holds the credential but
    /// not this service's storage — the same reason `vrcDigestMultibase` is
    /// the identifier the publish response returns.
    Superseded { by: String },
    /// Withdrawn by the party who controls it, or by the community. Terminal.
    ///
    /// Distinct from deleting the row: a withdrawal that is *recorded* can be
    /// resolved against a past instant, where a deletion can only be observed
    /// as an absence.
    Withdrawn {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

impl LifecycleEventKind {
    /// Whether this event ends the artifact's life permanently.
    ///
    /// Terminal states are the ones no later event may follow. Asked as a
    /// predicate rather than matched at each call site so that adding a fifth
    /// verb cannot silently be treated as reversible by one caller and
    /// terminal by another.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Superseded { .. } | Self::Withdrawn { .. })
    }

    /// Wire/operator name of the verb, for audit entries and log lines.
    pub fn verb(&self) -> &'static str {
        match self {
            Self::Suspended { .. } => "suspended",
            Self::Restored { .. } => "restored",
            Self::Superseded { .. } => "superseded",
            Self::Withdrawn { .. } => "withdrawn",
        }
    }
}

/// One entry in an artifact's lifecycle log: what happened, and when this
/// service recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleEvent {
    #[serde(flatten)]
    pub kind: LifecycleEventKind,
    /// Transaction time: when this service recorded the event, **not** when
    /// the underlying decision was taken. [`resolve`] ignores events recorded
    /// after the instant being asked about, which is what makes "was this in
    /// force at T" answerable at all.
    pub recorded_at: DateTime<Utc>,
}

/// The append-only lifecycle log of one artifact, oldest first.
///
/// Append-only and monotonic in `recorded_at`, both enforced by
/// [`Self::record`]. Order in the vector *is* the precedence order, so an
/// out-of-order insert would silently change the answer for every instant
/// after it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
pub struct LifecycleLog(Vec<LifecycleEvent>);

impl LifecycleLog {
    /// No events recorded. Also the `skip_serializing_if` predicate on the
    /// stored relationship row, so an artifact that has had no lifecycle
    /// event serialises exactly as it did before this module existed.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn events(&self) -> &[LifecycleEvent] {
        &self.0
    }

    /// The event that controls at `now`: the most recent one recorded at or
    /// before that instant.
    ///
    /// Filtering on `recorded_at` rather than taking the last entry is what
    /// makes this bitemporal. Resolving a past instant must not be affected by
    /// what has been learned since — otherwise a suspension recorded today
    /// would retroactively make yesterday's decision look wrong, and the audit
    /// trail could no longer be reconciled against the decisions it records.
    pub fn standing_at(&self, now: DateTime<Utc>) -> Option<&LifecycleEvent> {
        self.0.iter().rev().find(|e| e.recorded_at <= now)
    }

    /// The last event recorded, whenever that was. This is the state the next
    /// [`Self::record`] transitions *from*, which is deliberately a different
    /// question from [`Self::standing_at`]: appending is about the log's head,
    /// resolving is about a point in time.
    fn latest(&self) -> Option<&LifecycleEvent> {
        self.0.last()
    }

    /// Whether a terminal event has been recorded, so this artifact can never
    /// take another one.
    pub fn is_terminal(&self) -> bool {
        self.latest().is_some_and(|e| e.kind.is_terminal())
    }

    /// Append an event, enforcing the transition rules.
    ///
    /// Rejections are [`AppError::Conflict`] rather than `Validation`: the
    /// request is well-formed and the caller may well be entitled to make it —
    /// it is the artifact's current state that refuses, and a retry after the
    /// state changes could succeed. That is the distinction the workspace's
    /// error type already draws (`vti_common::error::AppError::Gone` exists
    /// precisely because `Conflict` promises a retry might work).
    ///
    /// `now` is passed in rather than read here so that every check in one
    /// request evaluates at a single instant — the same rule
    /// `credentials::ingress::require_dtg_type` and the VRC publish handler
    /// follow.
    pub fn record(
        &mut self,
        kind: LifecycleEventKind,
        now: DateTime<Utc>,
    ) -> Result<&LifecycleEvent, AppError> {
        if let Some(last) = self.latest() {
            // Monotonic, because the vector order is the precedence order. A
            // backwards timestamp would produce a log in which `standing_at`
            // returns an event that a *later* index has already superseded,
            // and every answer after that point would depend on which of two
            // equally "current" entries was scanned first.
            if now < last.recorded_at {
                return Err(AppError::Conflict(format!(
                    "lifecycle event recorded at {now} predates the last recorded \
                     event at {} — the log is append-only and ordered by record time",
                    last.recorded_at
                )));
            }
            if last.kind.is_terminal() {
                return Err(AppError::Conflict(format!(
                    "artifact was {} at {} and that is terminal — give effect back \
                     by issuing a fresh artifact, not by reversing the record",
                    last.kind.verb(),
                    last.recorded_at
                )));
            }
        }

        let standing_is_suspension = matches!(
            self.latest().map(|e| &e.kind),
            Some(LifecycleEventKind::Suspended { .. })
        );
        match &kind {
            LifecycleEventKind::Suspended { .. } if standing_is_suspension => {
                return Err(AppError::Conflict(
                    "artifact is already suspended; a second suspension records \
                     nothing a reader could act on"
                        .into(),
                ));
            }
            LifecycleEventKind::Restored { .. } if !standing_is_suspension => {
                return Err(AppError::Conflict(
                    "restoration reverses a suspension, and this artifact is not \
                     suspended — an artifact that is merely expired is restored by \
                     re-issuance, not by a lifecycle event"
                        .into(),
                ));
            }
            _ => {}
        }

        self.0.push(LifecycleEvent {
            kind,
            recorded_at: now,
        });
        Ok(self.0.last().expect("just pushed"))
    }
}

/// Whether an artifact is currently in force, and if not, why not.
///
/// A single enum rather than a `bool` plus a reason string, for the reason
/// `credentials::witness::WitnessBinding` gives for the same choice: the
/// variants distinguish situations a caller genuinely needs to tell apart, and
/// collapsing them loses the one distinction that matters most — between an
/// artifact whose own issuer bounded it and one this community stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum InForce {
    /// Inside its window, with no standing event against it.
    Yes,
    /// Its `validFrom` has not arrived.
    #[serde(rename_all = "camelCase")]
    NotYetValid { valid_from: DateTime<Utc> },
    /// Its `validUntil` has passed. Reported even when a `Restored` event
    /// stands, because restoration returns an artifact to its window rather
    /// than extending it.
    #[serde(rename_all = "camelCase")]
    Expired { valid_until: DateTime<Utc> },
    /// Temporarily ineffective. Reversible, and the only non-`Yes` state that
    /// is.
    Suspended { since: DateTime<Utc> },
    /// Displaced by a later artifact, named by digest.
    Superseded { at: DateTime<Utc>, by: String },
    /// Withdrawn. Terminal.
    Withdrawn { at: DateTime<Utc> },
    /// The artifact's own window could not be read, so no honest answer is
    /// available.
    ///
    /// Reachable on rows written before #1075, which entered the graph without
    /// their window ever being parsed. Surfaced rather than defaulted, for the
    /// reason `credentials::ingress::rejects_an_unparseable_bound` pins: the
    /// failure mode that makes a temporal guard useless is treating an
    /// unreadable bound as "no bound stated". [`Self::is_in_force`] is false
    /// here, so the safe reading is the automatic one.
    Indeterminate { reason: String },
}

impl InForce {
    /// The one predicate most callers want. Every non-`Yes` variant answers
    /// false, including [`Self::Indeterminate`].
    pub fn is_in_force(&self) -> bool {
        matches!(self, Self::Yes)
    }
}

/// Resolve an artifact's current state from its own window and everything
/// recorded against it — the precedence rule, in one place.
///
/// The rule, restated so it can be checked against the code beneath it: a
/// standing event decides, except that a standing `Restored` hands the
/// decision back to the window. Nothing here can return [`InForce::Yes`] for
/// an artifact whose window excludes `now`.
///
/// Call sites do not re-implement any part of this. That is the point: before
/// #1079 the VRC publish path, the VIC path and the recognition path each had
/// their own temporal check and the graph read had none at all, so the same
/// credential could be in force on one surface and not on another.
pub fn resolve(window: &ValidityWindow, log: &LifecycleLog, now: DateTime<Utc>) -> InForce {
    if let Some(event) = log.standing_at(now) {
        match &event.kind {
            LifecycleEventKind::Suspended { .. } => {
                return InForce::Suspended {
                    since: event.recorded_at,
                };
            }
            LifecycleEventKind::Superseded { by } => {
                return InForce::Superseded {
                    at: event.recorded_at,
                    by: by.clone(),
                };
            }
            LifecycleEventKind::Withdrawn { .. } => {
                return InForce::Withdrawn {
                    at: event.recorded_at,
                };
            }
            // Restoration returns the artifact to its window; it does not
            // grant it anything the window does not.
            LifecycleEventKind::Restored { .. } => {}
        }
    }
    window.state_at(now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn window(from_days_ago: i64, until_days_ahead: Option<i64>) -> ValidityWindow {
        let now = Utc::now();
        ValidityWindow {
            valid_from: Some(now - Duration::days(from_days_ago)),
            valid_until: until_days_ahead.map(|d| now + Duration::days(d)),
        }
    }

    fn suspended() -> LifecycleEventKind {
        LifecycleEventKind::Suspended { reason: None }
    }

    fn restored() -> LifecycleEventKind {
        LifecycleEventKind::Restored { reason: None }
    }

    // ─── The precedence rule itself ──────────────────────────

    /// The claim #1079 says nothing in the workspace establishes: a later
    /// event beats a still-valid artifact. The credential's signature is
    /// intact and its window is open, and it is still not in force.
    #[test]
    fn a_later_event_beats_an_artifact_that_is_still_inside_its_window() {
        let now = Utc::now();
        let w = window(30, Some(365));
        assert_eq!(
            w.state_at(now),
            InForce::Yes,
            "precondition: window is open"
        );

        let mut log = LifecycleLog::default();
        log.record(suspended(), now).unwrap();
        assert!(matches!(resolve(&w, &log, now), InForce::Suspended { .. }));
    }

    /// The asymmetry that makes the rule safe. An artifact whose window has
    /// closed cannot be brought back by anything recorded against it — a
    /// restoration returns it to a window that has already ended.
    #[test]
    fn no_event_can_put_an_artifact_back_inside_a_window_that_has_closed() {
        let now = Utc::now();
        // Suspended while valid, then expires, then restored.
        let w = ValidityWindow {
            valid_from: Some(now - Duration::days(30)),
            valid_until: Some(now - Duration::days(1)),
        };
        let mut log = LifecycleLog::default();
        log.record(suspended(), now - Duration::days(10)).unwrap();
        log.record(restored(), now).unwrap();

        match resolve(&w, &log, now) {
            InForce::Expired { .. } => {}
            other => panic!("restoration must not extend a closed window: {other:?}"),
        }
    }

    /// The converse direction, which is the one that must keep working:
    /// restoration inside an open window genuinely restores.
    #[test]
    fn restoration_inside_an_open_window_returns_the_artifact_to_force() {
        let now = Utc::now();
        let w = window(30, Some(365));
        let mut log = LifecycleLog::default();
        log.record(suspended(), now - Duration::days(2)).unwrap();
        assert!(!resolve(&w, &log, now).is_in_force());
        log.record(restored(), now - Duration::days(1)).unwrap();
        assert_eq!(resolve(&w, &log, now), InForce::Yes);
    }

    /// With no events at all the answer is exactly the window's — so wiring a
    /// log onto an existing artifact type changes nothing for artifacts that
    /// have never had an event.
    #[test]
    fn an_empty_log_defers_entirely_to_the_window() {
        let now = Utc::now();
        let empty = LifecycleLog::default();
        assert_eq!(resolve(&window(30, Some(1)), &empty, now), InForce::Yes);
        assert!(matches!(
            resolve(&window(30, Some(-1)), &empty, now),
            InForce::Expired { .. }
        ));
        assert!(matches!(
            resolve(&window(-1, Some(30)), &empty, now),
            InForce::NotYetValid { .. }
        ));
    }

    /// An artifact stating no bounds is decided entirely by its log. This is
    /// the shape most VRC fixtures in this repo have (`valid_until: None`),
    /// and it is the case where precedence is the *only* lifecycle mechanism
    /// there is.
    #[test]
    fn an_unbounded_artifact_is_governed_only_by_its_log() {
        let now = Utc::now();
        let mut log = LifecycleLog::default();
        assert_eq!(resolve(&ValidityWindow::UNBOUNDED, &log, now), InForce::Yes);
        log.record(LifecycleEventKind::Withdrawn { reason: None }, now)
            .unwrap();
        assert!(matches!(
            resolve(&ValidityWindow::UNBOUNDED, &log, now),
            InForce::Withdrawn { .. }
        ));
    }

    /// Half-open, matching `credentials::ingress::check_validity_window` and
    /// the two paths it was written to agree with. A one-instant disagreement
    /// here would make an artifact publishable and simultaneously out of
    /// force.
    #[test]
    fn window_boundaries_are_valid_from_inclusive_and_valid_until_exclusive() {
        let now = Utc::now();
        let w = ValidityWindow {
            valid_from: Some(now),
            valid_until: Some(now + Duration::days(1)),
        };
        assert_eq!(w.state_at(now), InForce::Yes, "validFrom == now is inside");

        let ends_now = ValidityWindow {
            valid_from: Some(now - Duration::days(1)),
            valid_until: Some(now),
        };
        assert!(
            matches!(ends_now.state_at(now), InForce::Expired { .. }),
            "validUntil == now is outside"
        );
    }

    // ─── Transaction time ────────────────────────────────────

    /// Resolving a past instant must not see an event recorded after it.
    /// Without this the audit trail could not be reconciled against the
    /// decisions it records: every past decision would be re-judged against
    /// facts that did not exist when it was taken.
    #[test]
    fn an_event_does_not_apply_before_it_was_recorded() {
        let now = Utc::now();
        let w = window(30, Some(365));
        let mut log = LifecycleLog::default();
        log.record(suspended(), now).unwrap();

        assert_eq!(
            resolve(&w, &log, now - Duration::hours(1)),
            InForce::Yes,
            "an hour before the suspension was recorded, the edge was in force"
        );
        assert!(!resolve(&w, &log, now).is_in_force());
    }

    /// The standing event at an instant is the latest one recorded at or
    /// before it — not the latest one in the log.
    #[test]
    fn the_standing_event_is_the_latest_one_recorded_by_that_instant() {
        let now = Utc::now();
        let w = window(30, Some(365));
        let mut log = LifecycleLog::default();
        log.record(suspended(), now - Duration::days(3)).unwrap();
        log.record(restored(), now - Duration::days(1)).unwrap();

        assert!(matches!(
            resolve(&w, &log, now - Duration::days(2)),
            InForce::Suspended { .. }
        ));
        assert_eq!(resolve(&w, &log, now), InForce::Yes);
    }

    #[test]
    fn a_backwards_timestamp_is_refused() {
        let now = Utc::now();
        let mut log = LifecycleLog::default();
        log.record(suspended(), now).unwrap();
        let err = log
            .record(restored(), now - Duration::days(1))
            .expect_err("the log is ordered by record time");
        assert!(format!("{err:?}").contains("append-only"), "{err:?}");
    }

    // ─── Restoration versus replacement ──────────────────────

    /// Nothing follows a withdrawal — including a second withdrawal, which
    /// would otherwise be a silent no-op that moved `recordedAt` forward and
    /// changed the answer to "when did this stop being in force".
    #[test]
    fn a_withdrawal_is_terminal() {
        let now = Utc::now();
        let mut log = LifecycleLog::default();
        log.record(LifecycleEventKind::Withdrawn { reason: None }, now)
            .unwrap();
        for attempt in [
            suspended(),
            restored(),
            LifecycleEventKind::Superseded { by: "zX".into() },
            LifecycleEventKind::Withdrawn { reason: None },
        ] {
            let verb = attempt.verb();
            assert!(
                log.record(attempt, now).is_err(),
                "`{verb}` after a withdrawal must be refused"
            );
        }
        assert_eq!(log.events().len(), 1, "no refused event may have landed");
    }

    #[test]
    fn a_supersession_is_terminal() {
        let now = Utc::now();
        let mut log = LifecycleLog::default();
        log.record(LifecycleEventKind::Superseded { by: "zNew".into() }, now)
            .unwrap();
        let err = log
            .record(restored(), now)
            .expect_err("a superseded artifact is replaced, not restorable");
        assert!(format!("{err:?}").contains("terminal"), "{err:?}");
        assert!(log.is_terminal());
    }

    /// Restoration reverses a suspension and nothing else. An artifact that
    /// merely expired has no suspension to reverse, and letting this through
    /// would be the exact inversion the module doc rules out — an event
    /// manufacturing validity the issuer never signed for.
    #[test]
    fn restoration_requires_a_standing_suspension() {
        let now = Utc::now();
        let mut fresh = LifecycleLog::default();
        let err = fresh
            .record(restored(), now)
            .expect_err("nothing to restore");
        assert!(
            format!("{err:?}").contains("reverses a suspension"),
            "{err:?}"
        );

        let mut reinstated = LifecycleLog::default();
        reinstated.record(suspended(), now).unwrap();
        reinstated.record(restored(), now).unwrap();
        let err = reinstated
            .record(restored(), now)
            .expect_err("already restored");
        assert!(
            format!("{err:?}").contains("reverses a suspension"),
            "{err:?}"
        );
    }

    #[test]
    fn a_second_suspension_is_refused() {
        let now = Utc::now();
        let mut log = LifecycleLog::default();
        log.record(suspended(), now).unwrap();
        let err = log.record(suspended(), now).expect_err("already suspended");
        assert!(format!("{err:?}").contains("already suspended"), "{err:?}");
    }

    /// A suspended artifact may still be withdrawn or superseded — suspension
    /// is not a dead end, it is the one reversible state.
    #[test]
    fn a_suspended_artifact_can_still_be_withdrawn_or_superseded() {
        let now = Utc::now();
        for terminal in [
            LifecycleEventKind::Withdrawn { reason: None },
            LifecycleEventKind::Superseded { by: "zNew".into() },
        ] {
            let mut log = LifecycleLog::default();
            log.record(suspended(), now).unwrap();
            log.record(terminal, now)
                .expect("a suspension does not block a terminal event");
            assert!(log.is_terminal());
        }
    }

    // ─── Wire shape ──────────────────────────────────────────

    /// The log serialises as a bare array and an absent log is `is_empty`, so
    /// a stored row that has never had a lifecycle event serialises exactly as
    /// it did before this module existed. Rows written before it must decode.
    #[test]
    fn an_absent_log_decodes_as_an_empty_one() {
        let log: LifecycleLog =
            serde_json::from_value(serde_json::json!([])).expect("empty array decodes");
        assert!(log.is_empty());
        assert_eq!(
            serde_json::to_value(LifecycleLog::default()).unwrap(),
            serde_json::json!([])
        );
    }

    /// Field names are camelCase and the verb is the discriminator, so an
    /// operator reading a stored row sees `{"event":"suspended","recordedAt":…}`
    /// rather than a positional shape only this code can interpret.
    #[test]
    fn events_serialise_camel_case_with_the_verb_as_discriminator() {
        let now = Utc::now();
        let mut log = LifecycleLog::default();
        log.record(
            LifecycleEventKind::Suspended {
                reason: Some("under moderation".into()),
            },
            now,
        )
        .unwrap();
        let v = serde_json::to_value(&log).unwrap();
        assert_eq!(v[0]["event"], "suspended");
        assert_eq!(v[0]["reason"], "under moderation");
        assert!(v[0]["recordedAt"].is_string());

        let round_tripped: LifecycleLog = serde_json::from_value(v).unwrap();
        assert_eq!(round_tripped, log);
    }

    #[test]
    fn resolved_state_serialises_with_a_readable_discriminator() {
        let now = Utc::now();
        let v = serde_json::to_value(InForce::Superseded {
            at: now,
            by: "zNew".into(),
        })
        .unwrap();
        assert_eq!(v["state"], "superseded");
        assert_eq!(v["by"], "zNew");
        assert_eq!(serde_json::to_value(InForce::Yes).unwrap()["state"], "yes");
    }

    /// Every non-`Yes` variant answers false, including `Indeterminate` — the
    /// safe reading has to be the automatic one, because the case exists
    /// precisely for rows nobody has looked at.
    #[test]
    fn only_yes_is_in_force() {
        let now = Utc::now();
        assert!(InForce::Yes.is_in_force());
        for state in [
            InForce::NotYetValid { valid_from: now },
            InForce::Expired { valid_until: now },
            InForce::Suspended { since: now },
            InForce::Superseded {
                at: now,
                by: "zX".into(),
            },
            InForce::Withdrawn { at: now },
            InForce::Indeterminate {
                reason: "unreadable".into(),
            },
        ] {
            assert!(!state.is_in_force(), "{state:?} must not be in force");
        }
    }
}
