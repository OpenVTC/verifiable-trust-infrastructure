//! The acceptance window a VTI node applies to a Trust Task document's
//! `issuedAt` (VTI-OPS-024), as **one value** read by everything that has to
//! agree on it.
//!
//! Three parties read it:
//!
//! - **the consumer** — the VTA's and the VTC's dispatch spines, through
//!   [`AcceptanceWindow::freshness_policy`];
//! - **the responder** — the same two nodes answering
//!   `trust-task-discovery/0.4`, through [`AcceptanceWindow::advertised`]
//!   (VTI-TRN-047), and the superseded 0.3 through
//!   [`AcceptanceWindow::advertised_v0_3`];
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
use trust_tasks_rs::freshness::{DEFAULT_EXPIRY_HORIZON, DEFAULT_SKEW};
use trust_tasks_rs::specs::trust_task_discovery::v0_4 as wire;

/// A consumer's acceptance window: how long after its `issuedAt` a document
/// that states no `expiresAt` is still accepted, how far after it a stated
/// `expiresAt` is honoured instead, and the clock-skew tolerance applied in
/// both directions (`trust-task-discovery/0.4`, *Acceptance window*).
///
/// A document without an `expiresAt`, received at `now`, is refused when
/// `now > issuedAt + max_age + clock_skew`. One with an `expiresAt` is accepted
/// until then, whatever the maximum age, but no later than the expiry horizon
/// after its `issuedAt` (VTI-OPS-024, VTI-OPS-028). Without a horizon the
/// maximum age applies to every document. Either is refused when
/// `issuedAt > now + clock_skew`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptanceWindow {
    /// The greatest age of `issuedAt` at which a document is still accepted,
    /// before any tolerance.
    pub max_age: TimeDelta,
    /// The clock-skew tolerance, applied in both directions.
    pub clock_skew: TimeDelta,
    /// How long after its `issuedAt` a stated `expiresAt` is honoured in
    /// place of `max_age`; a later one is applied as the horizon. `None`: the
    /// maximum age applies to every document.
    pub expiry_horizon: Option<TimeDelta>,
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
    expiry_horizon: Some(EXPIRY_HORIZON),
};

/// A document's expiry horizon (**VTI-OPS-028**): thirty days after its
/// `issuedAt`. A stated `expiresAt` later than that is applied as the horizon,
/// not refused.
///
/// Fixed by the specification rather than per node, because a sender has to
/// know it without asking; it is also `trust_tasks_rs`'s
/// [`DEFAULT_EXPIRY_HORIZON`], which a test pins.
pub const EXPIRY_HORIZON: TimeDelta = DEFAULT_EXPIRY_HORIZON;

/// How long a consumer applying `policy` must keep its record of having
/// accepted `doc` (**VTI-OPS-029**): the document's acceptance end, plus the
/// clock-skew tolerance. `None` only when `policy` bounds nothing.
///
/// The acceptance end is `FreshnessPolicy::record_expiry`: `issuedAt + max_age`
/// (the skew already added) without an `expiresAt`; the `expiresAt` with one;
/// the expiry horizon (the skew already added) when the `expiresAt` lies beyond
/// it. The skew is added here to the middle case, which `record_expiry` returns
/// bare.
///
/// Never shorter: a record dropped while its document is still acceptable lets
/// a replay run twice. A stated expiry is honoured up to thirty days
/// (VTI-OPS-028), so a record capped at `issuedAt + max_age` would be exactly
/// that. The horizon is what stops a producer choosing how long a consumer
/// must remember an `id`, which is why both VTI nodes require `issuedAt`: the
/// horizon is counted from it.
pub fn retain_until<P>(
    policy: &FreshnessPolicy,
    doc: &trust_tasks_rs::TrustTask<P>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let end = policy.record_expiry(doc, now)?;
    Some(match doc.expires_at {
        Some(expires_at) if end == expires_at => expires_at + policy.skew,
        _ => end,
    })
}

impl AcceptanceWindow {
    /// The freshness policy a consumer applying this window uses: its
    /// `max_age`, its skew and its expiry horizon. A node adds its own posture
    /// on top (both VTI nodes add `requiring_issued_at`).
    pub fn freshness_policy(&self) -> FreshnessPolicy {
        let policy = FreshnessPolicy::default()
            .with_max_age(self.max_age)
            .with_skew(self.clock_skew);
        match self.expiry_horizon {
            Some(horizon) => policy.with_expiry_horizon(horizon),
            None => policy,
        }
    }

    /// The window as `trust-task-discovery/0.4` states it, in whole seconds.
    ///
    /// Rounded **down**: VTI-TRN-047 (and discovery 0.4's responder rule 1)
    /// forbid advertising a window wider than the one applied, and a narrower
    /// one only costs a producer a new attempt it did not need. `None` when the
    /// window cannot be stated — a `max_age` under one second (the schema's
    /// minimum is 1) or a negative skew — in which case the responder says
    /// nothing, and the discoverer falls back as it would for any responder
    /// that does not advertise.
    ///
    /// A horizon under one second is left out, which states that the maximum
    /// age applies to every document: narrower than applied, never wider.
    pub fn advertised(&self) -> Option<wire::AcceptanceWindow> {
        let (max_age, clock_skew_seconds) = self.whole_seconds()?;
        let expiry_horizon_seconds = self
            .expiry_horizon
            .and_then(|h| u64::try_from(h.num_seconds()).ok())
            .and_then(std::num::NonZeroU64::new);
        wire::AcceptanceWindow::builder()
            .clock_skew_seconds(clock_skew_seconds)
            .max_age_seconds(max_age)
            .expiry_horizon_seconds(expiry_horizon_seconds)
            .try_into()
            .ok()
    }

    /// The window as the superseded `trust-task-discovery/0.3` states it, for
    /// a client that still asks it. 0.3 has no horizon, and its window governs
    /// `issuedAt` alone, so this states only the maximum age and skew: a
    /// narrower window than applied, which 0.3 permits, never a wider one.
    #[allow(deprecated)]
    pub fn advertised_v0_3(
        &self,
    ) -> Option<trust_tasks_rs::specs::trust_task_discovery::v0_3::AcceptanceWindow> {
        let (max_age, clock_skew_seconds) = self.whole_seconds()?;
        trust_tasks_rs::specs::trust_task_discovery::v0_3::AcceptanceWindow::builder()
            .clock_skew_seconds(clock_skew_seconds)
            .max_age_seconds(max_age)
            .try_into()
            .ok()
    }

    /// `max_age` and the skew in whole seconds, rounded down; `None` when
    /// either cannot be stated.
    fn whole_seconds(&self) -> Option<(std::num::NonZeroU64, u64)> {
        let max_age = u64::try_from(self.max_age.num_seconds()).ok()?;
        let clock_skew_seconds = u64::try_from(self.clock_skew.num_seconds()).ok()?;
        Some((std::num::NonZeroU64::new(max_age)?, clock_skew_seconds))
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
            expiry_horizon: window.expiry_horizon_seconds.map(|h| secs(h.get())),
        }
    }

    /// Whether a document issued at `issued_at` is past `max_age` by `now`:
    /// the point after which a producer **SHOULD NOT** send it (discovery 0.4,
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
            wire.expiry_horizon_seconds.map(|h| h.get()),
            Some(30 * 24 * 60 * 60)
        );
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
            expiry_horizon: Some(TimeDelta::milliseconds(3_600_999)),
        };
        let wire = w.advertised().expect("advertisable");
        assert_eq!(wire.max_age_seconds.get(), 90);
        assert_eq!(wire.clock_skew_seconds, 1);
        assert_eq!(wire.expiry_horizon_seconds.map(|h| h.get()), Some(3_600));
        let back = AcceptanceWindow::from_advertised(&wire);
        assert!(back.max_age <= w.max_age && back.clock_skew <= w.clock_skew);
        assert!(back.expiry_horizon <= w.expiry_horizon);
    }

    /// A horizon too short to state in whole seconds is left out, which says
    /// the maximum age applies to everything: narrower than applied, never
    /// wider (VTI-TRN-047).
    #[test]
    fn vti_trn_047_a_sub_second_horizon_is_not_advertised() {
        let w = AcceptanceWindow {
            expiry_horizon: Some(TimeDelta::milliseconds(999)),
            ..VTI_ACCEPTANCE_WINDOW
        };
        assert_eq!(
            w.advertised().expect("advertisable").expiry_horizon_seconds,
            None
        );
    }

    /// The superseded 0.3 answer states the maximum age and skew, and no
    /// horizon, which 0.3 has no member for.
    #[test]
    fn vti_trn_047_the_v0_3_window_omits_the_horizon() {
        let wire = VTI_ACCEPTANCE_WINDOW
            .advertised_v0_3()
            .expect("advertisable");
        assert_eq!(wire.max_age_seconds.get(), 600);
        assert_eq!(wire.clock_skew_seconds, 60);
    }

    /// **VTI-OPS-028** fixes the horizon at thirty days.
    #[test]
    fn vti_ops_028_the_expiry_horizon_is_thirty_days() {
        assert_eq!(EXPIRY_HORIZON, TimeDelta::days(30));
        assert_eq!(
            VTI_ACCEPTANCE_WINDOW.freshness_policy().expiry_horizon,
            Some(EXPIRY_HORIZON)
        );
    }

    /// **VTI-OPS-024 / VTI-OPS-028.** A stated expiry replaces the maximum age:
    /// a document that says it stands for a day is accepted an hour later, and
    /// one that states a year is accepted until the horizon and refused after
    /// it, never refused for stating it.
    #[test]
    fn vti_ops_028_a_stated_expiry_replaces_the_maximum_age_up_to_the_horizon() {
        let policy = VTI_ACCEPTANCE_WINDOW.freshness_policy();
        let issued = chrono::SubsecRound::trunc_subsecs(Utc::now(), 0);
        let doc = |expires: DateTime<Utc>| {
            let mut d = trust_tasks_rs::TrustTask::new(
                "urn:uuid:00000000-0000-4000-8000-000000000000".to_string(),
                "https://trusttasks.org/spec/acl/list/0.1".parse().unwrap(),
                serde_json::json!({}),
            );
            d.issued_at = Some(issued);
            d.expires_at = Some(expires);
            d
        };
        let day = doc(issued + TimeDelta::days(1));
        assert!(
            day.validate_freshness(issued + TimeDelta::hours(1), &policy)
                .is_ok()
        );
        let year = doc(issued + TimeDelta::days(365));
        assert!(year.validate_freshness(issued, &policy).is_ok());
        assert!(
            year.validate_freshness(issued + EXPIRY_HORIZON, &policy)
                .is_ok()
        );
        assert!(
            year.validate_freshness(
                issued + EXPIRY_HORIZON + DEFAULT_SKEW + TimeDelta::seconds(1),
                &policy
            )
            .is_err()
        );
    }

    /// **VTI-OPS-029** at each of the three acceptance ends.
    #[test]
    fn vti_ops_029_the_record_outlasts_every_acceptance_end_by_the_skew() {
        let policy = VTI_ACCEPTANCE_WINDOW.freshness_policy();
        let issued = chrono::SubsecRound::trunc_subsecs(Utc::now(), 0);
        let doc = |expires: Option<DateTime<Utc>>| {
            let mut d = trust_tasks_rs::TrustTask::new(
                "urn:uuid:00000000-0000-4000-8000-000000000000".to_string(),
                "https://trusttasks.org/spec/acl/list/0.1".parse().unwrap(),
                serde_json::json!({}),
            );
            d.issued_at = Some(issued);
            d.expires_at = expires;
            d
        };
        let skew = DEFAULT_SKEW;
        assert_eq!(
            retain_until(&policy, &doc(None), issued),
            Some(issued + VTI_ACCEPTANCE_WINDOW.max_age + skew),
            "no expiry: the maximum age"
        );
        let day = issued + TimeDelta::days(1);
        assert_eq!(
            retain_until(&policy, &doc(Some(day)), issued),
            Some(day + skew),
            "a stated expiry inside the horizon, past the maximum age"
        );
        let soon = issued + TimeDelta::minutes(2);
        assert_eq!(
            retain_until(&policy, &doc(Some(soon)), issued),
            Some(soon + skew),
            "a stated expiry inside the maximum age"
        );
        assert_eq!(
            retain_until(&policy, &doc(Some(issued + TimeDelta::days(3650))), issued),
            Some(issued + EXPIRY_HORIZON + skew),
            "a stated expiry beyond the horizon"
        );
    }

    /// A window the schema cannot state is not stated.
    #[test]
    fn an_unstatable_window_is_not_advertised() {
        let sub_second = AcceptanceWindow {
            max_age: TimeDelta::milliseconds(500),
            clock_skew: TimeDelta::zero(),
            expiry_horizon: None,
        };
        assert!(sub_second.advertised().is_none());
        assert!(sub_second.advertised_v0_3().is_none());
        let negative_skew = AcceptanceWindow {
            max_age: TimeDelta::minutes(1),
            clock_skew: TimeDelta::seconds(-1),
            expiry_horizon: None,
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
