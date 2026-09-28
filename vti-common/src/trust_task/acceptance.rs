//! The acceptance window a VTI node applies to a Trust Task document's
//! `issuedAt` (VTI-OPS-024), as **one value** read by everything that has to
//! agree on it.
//!
//! Three parties read it:
//!
//! - **the consumer** — the VTA's and the VTC's dispatch spines, through
//!   [`AcceptanceWindow::freshness_policy`];
//! - **the responder** — the same two nodes answering
//!   `trust-task-discovery/0.3`, through [`AcceptanceWindow::advertised`]
//!   (VTI-TRN-047);
//! - **the producer** — the push engine ([`crate::trust_task_push`]), which
//!   issues a new attempt rather than put a document on the wire past it
//!   (VTI-TRN-044, VTI-TRN-045).
//!
//! VTI-TRN-047 forbids a node to advertise a window longer than it applies.
//! Deriving the advertisement and the policy from the one constant,
//! [`VTI_ACCEPTANCE_WINDOW`], is what makes that hold by construction rather
//! than by two numbers kept equal by hand; each node pins it with a test that
//! reads the window back out of its own discovery answer.

use chrono::{DateTime, TimeDelta, Utc};
use trust_tasks_rs::FreshnessPolicy;
use trust_tasks_rs::freshness::DEFAULT_SKEW;
use trust_tasks_rs::specs::trust_task_discovery::v0_3 as wire;

/// A consumer's acceptance window: how long after its `issuedAt` a document is
/// still accepted, and the clock-skew tolerance applied in both directions
/// (`trust-task-discovery/0.3`, *Acceptance window*).
///
/// A document received at `now` is refused when
/// `now > issuedAt + max_age + clock_skew`, and when
/// `issuedAt > now + clock_skew`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptanceWindow {
    /// The greatest age of `issuedAt` at which a document is still accepted,
    /// before any tolerance.
    pub max_age: TimeDelta,
    /// The clock-skew tolerance, applied in both directions.
    pub clock_skew: TimeDelta,
}

/// The window every VTI node applies as a consumer: [`super::ACCEPTANCE_WINDOW`]
/// (ten minutes) with `trust_tasks_rs`'s [`DEFAULT_SKEW`] (sixty seconds,
/// SPEC §4.2's "typically ≤ 60s").
///
/// It is also the "documented constant" of VTI-TRN-045: the window a VTI
/// producer assumes for a recipient that has advertised none, and the only
/// one the push engine reads today (see the module docs of
/// [`crate::trust_task_push`], *Freshness*).
pub const VTI_ACCEPTANCE_WINDOW: AcceptanceWindow = AcceptanceWindow {
    max_age: super::ACCEPTANCE_WINDOW,
    clock_skew: DEFAULT_SKEW,
};

impl AcceptanceWindow {
    /// The freshness policy a consumer applying this window uses: its
    /// `max_age` and its skew, nothing else. A node adds its own posture on
    /// top (both VTI nodes add `requiring_issued_at`).
    pub fn freshness_policy(&self) -> FreshnessPolicy {
        FreshnessPolicy::default()
            .with_max_age(self.max_age)
            .with_skew(self.clock_skew)
    }

    /// The window as `trust-task-discovery/0.3` states it, in whole seconds.
    ///
    /// Rounded **down**: VTI-TRN-047 (and discovery 0.3's responder rule 1)
    /// forbid advertising a window wider than the one applied, and a narrower
    /// one only costs a producer a new attempt it did not need. `None` when the
    /// window cannot be stated — a `max_age` under one second (the schema's
    /// minimum is 1) or a negative skew — in which case the responder says
    /// nothing, and the discoverer falls back as it would for any responder
    /// that does not advertise.
    pub fn advertised(&self) -> Option<wire::AcceptanceWindow> {
        let max_age = u64::try_from(self.max_age.num_seconds()).ok()?;
        let clock_skew_seconds = u64::try_from(self.clock_skew.num_seconds()).ok()?;
        wire::AcceptanceWindow::builder()
            .clock_skew_seconds(clock_skew_seconds)
            .max_age_seconds(std::num::NonZeroU64::new(max_age)?)
            .try_into()
            .ok()
    }

    /// The window a responder advertised, read back — what a discoverer that
    /// has authenticated the response acts on.
    pub fn from_advertised(window: &wire::AcceptanceWindow) -> Self {
        // An absurd advertisement is clamped to the largest `TimeDelta` rather
        // than panicking; the predicates below use checked arithmetic, so it
        // then reads as "not yet past", which is what it claims.
        let secs = |s: u64| {
            i64::try_from(s)
                .ok()
                .and_then(TimeDelta::try_seconds)
                .unwrap_or(TimeDelta::MAX)
        };
        Self {
            max_age: secs(window.max_age_seconds.get()),
            clock_skew: secs(window.clock_skew_seconds),
        }
    }

    /// Whether a document issued at `issued_at` is past `max_age` by `now`:
    /// the point after which a producer **SHOULD NOT** send it (discovery 0.3,
    /// discoverer rule 2), and issues a new attempt instead.
    pub fn past_max_age(&self, issued_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        issued_at
            .checked_add_signed(self.max_age)
            .is_some_and(|edge| now >= edge)
    }

    /// Whether a consumer applying this window refuses a document issued at
    /// `issued_at` when it receives it at `now`, skew tolerance included: the
    /// point after which a producer **MUST NOT** send it.
    pub fn refuses(&self, issued_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        issued_at
            .checked_add_signed(self.max_age)
            .and_then(|t| t.checked_add_signed(self.clock_skew))
            .is_some_and(|edge| now > edge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The VTI window is advertised exactly: ten minutes and sixty seconds are
    /// whole seconds, so rounding down loses nothing (VTI-TRN-047).
    #[test]
    fn vti_trn_047_the_vti_window_is_advertised_exactly() {
        let wire = VTI_ACCEPTANCE_WINDOW.advertised().expect("advertisable");
        assert_eq!(wire.max_age_seconds.get(), 600);
        assert_eq!(wire.clock_skew_seconds, 60);
        assert_eq!(
            AcceptanceWindow::from_advertised(&wire),
            VTI_ACCEPTANCE_WINDOW
        );
    }

    /// A fractional window is rounded down, never up: an advertisement wider
    /// than the window applied makes producers deliver documents the
    /// responder then refuses (VTI-TRN-047).
    #[test]
    fn vti_trn_047_a_fractional_window_is_never_advertised_wider() {
        let w = AcceptanceWindow {
            max_age: TimeDelta::milliseconds(90_999),
            clock_skew: TimeDelta::milliseconds(1_500),
        };
        let wire = w.advertised().expect("advertisable");
        assert_eq!(wire.max_age_seconds.get(), 90);
        assert_eq!(wire.clock_skew_seconds, 1);
        let back = AcceptanceWindow::from_advertised(&wire);
        assert!(back.max_age <= w.max_age && back.clock_skew <= w.clock_skew);
    }

    /// A window the schema cannot state is not stated.
    #[test]
    fn an_unstatable_window_is_not_advertised() {
        let sub_second = AcceptanceWindow {
            max_age: TimeDelta::milliseconds(500),
            clock_skew: TimeDelta::zero(),
        };
        assert!(sub_second.advertised().is_none());
        let negative_skew = AcceptanceWindow {
            max_age: TimeDelta::minutes(1),
            clock_skew: TimeDelta::seconds(-1),
        };
        assert!(negative_skew.advertised().is_none());
    }

    /// The policy the consumers apply is the window, and the two predicates the
    /// producer reads agree with it at the boundary: a document the policy
    /// still accepts is one `refuses` says is accepted, and the first second
    /// past it is refused by both.
    #[test]
    fn vti_trn_045_the_producer_predicates_agree_with_the_consumer_policy() {
        let w = VTI_ACCEPTANCE_WINDOW;
        let policy = w.freshness_policy();
        assert_eq!(policy.max_age, Some(w.max_age));
        assert_eq!(policy.skew, w.clock_skew);

        let now = chrono::SubsecRound::trunc_subsecs(Utc::now(), 0);
        let at_edge = now - w.max_age - w.clock_skew;
        let past_edge = at_edge - TimeDelta::seconds(1);
        let doc = |issued: DateTime<Utc>| {
            let mut d = trust_tasks_rs::TrustTask::new(
                "urn:uuid:00000000-0000-4000-8000-000000000000".to_string(),
                "https://trusttasks.org/spec/acl/list/0.1".parse().unwrap(),
                serde_json::json!({}),
            );
            d.issued_at = Some(issued);
            d
        };
        assert!(doc(at_edge).validate_freshness(now, &policy).is_ok());
        assert!(!w.refuses(at_edge, now));
        assert!(doc(past_edge).validate_freshness(now, &policy).is_err());
        assert!(w.refuses(past_edge, now));
        assert!(w.past_max_age(now - w.max_age, now));
        assert!(!w.past_max_age(now - w.max_age + TimeDelta::seconds(1), now));
    }
}
