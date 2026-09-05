//! When a room stops being live, and what that does — §9 of the design note.
//!
//! # The host never decides
//!
//! No host can promise to hold every room forever, and on a sealed room the host is the
//! worst-placed party to judge value: it cannot read the content, and inactivity is not
//! worthlessness. So nothing in this module is a judgement. Every transition is a function
//! of two numbers the room already carries — when its epoch expires, and how long its owner
//! said to keep it afterwards — and every one of them is undone by a single renewal until
//! the last.
//!
//! That is why [`Lifecycle`] is **computed, not stored**. A stored state is a decision
//! somebody made and can get wrong; a computed one cannot drift from the facts, and there
//! is no code path where a host marks a room dormant. Ask [`Room::lifecycle`] at the moment
//! you need to know.
//!
//! # The clock is the epoch
//!
//! MLS epochs have a maximum lifetime, and renewal is a commit — so a room that is being
//! used renews itself in the course of being used, and one that nobody has committed to in
//! a year has said something real about itself. `epoch_expires_at` is set when an epoch is
//! minted; nothing else moves it.
//!
//! ```text
//!   Live  ──epoch expires──▶  Lapsed  ──grace──▶  Dormant  ──retention──▶  Reclaimable
//!    ▲                          │                    │                        │
//!    └──────────────────────────┴────────────────────┴─── a single renewal ───┘
//! ```
//!
//! - **Live** — normal.
//! - **Lapsed** — read-only. Nothing is destroyed and nothing is even hidden; the room
//!   simply stops accepting writes, which is a state a member can notice and fix.
//! - **Dormant** — the owner has been notified and a notice belongs in the room. Still
//!   read-only, still complete.
//! - **Reclaimable** — the retention period stated *at creation* has run out. Even here
//!   this module only reports; deleting is a separate, deliberate act.
//!
//! Reads do not extend anything, and that is deliberate against a plausible-sounding
//! alternative. §9 says read activity counts as liveness — but a *host* counting reads
//! would mean a sealed room's lifecycle depended on the one signal the host can see, which
//! is exactly the correlation the tiers exist to deny. Liveness is expressed by renewing,
//! and a room being read is a room whose members can renew it.
//!
//! # What this module is not
//!
//! It does not anchor renewals in the room's witnessed DID log, and it cannot: that log is
//! controlled by the room's DID controller, which is the **owner**, not the host. The
//! anchoring in §9 — epoch authenticator and version watermark, per renewal — is a client
//! and owner concern. What a host contributes is the half above: never deciding, and never
//! destroying anything a renewal could have saved.

use serde::{Deserialize, Serialize};

use crate::Room;

/// How long a lapsed room waits before it is called dormant.
///
/// A grace window rather than an immediate transition, because "lapsed" is frequently just
/// somebody being on holiday, and notifying an owner that their room is dormant the minute
/// an epoch expires trains them to ignore the notice.
pub const DORMANT_AFTER_LAPSE_DAYS: u32 = 30;

/// Default maximum epoch lifetime, in days.
///
/// The MLS layer imposes its own; this is the room's, and it is the clock §9 refers to. A
/// year is long enough that renewal is not busywork and short enough that a room nobody has
/// touched says something by not being renewed.
pub const DEFAULT_EPOCH_LIFETIME_DAYS: u32 = 365;

const DAY: u64 = 24 * 60 * 60;

/// Where a room is in its life. Computed from the room's own timestamps — never stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lifecycle {
    /// Normal: reads and writes.
    Live,
    /// The epoch expired. Read-only; nothing destroyed, nothing hidden.
    Lapsed,
    /// Lapsed long enough that the owner should have been told.
    Dormant,
    /// The retention period stated at creation has run out.
    Reclaimable,
}

impl Lifecycle {
    /// Whether a room in this state accepts writes.
    ///
    /// The single question the authorization layer asks. Curation and epoch minting are
    /// writes too — but minting is how a room is *renewed*, so it is exempted at the call
    /// site rather than here: a state machine that refused the one operation that escapes
    /// it would have no exit.
    pub fn accepts_writes(&self) -> bool {
        matches!(self, Lifecycle::Live)
    }

    /// Whether a room in this state still serves reads.
    ///
    /// True everywhere, including `Reclaimable`. A room whose retention has run out is one
    /// a host *may* delete, and until it does the members' choice is renew or export — so
    /// reading has to keep working right up to the moment the bytes are gone. §9: "the
    /// members' choice is renew or take it with you."
    pub fn serves_reads(&self) -> bool {
        true
    }

    /// Whether a nominated successor may claim a room in this state.
    ///
    /// **Dormant, not merely lapsed.** An epoch expiring is frequently somebody on holiday;
    /// a room still unrenewed after the grace window is a room whose owner has stopped, and
    /// has had a notice saying so. Allowing a claim the instant an epoch lapsed would make
    /// every holiday a takeover window.
    ///
    /// `Reclaimable` counts too: a room past its retention is more claimable, not less —
    /// refusing there would mean the only party who could save it loses the right at exactly
    /// the moment it matters.
    pub fn admits_a_claim(&self) -> bool {
        matches!(self, Lifecycle::Dormant | Lifecycle::Reclaimable)
    }

    /// The wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Lifecycle::Live => "live",
            Lifecycle::Lapsed => "lapsed",
            Lifecycle::Dormant => "dormant",
            Lifecycle::Reclaimable => "reclaimable",
        }
    }
}

impl Room {
    /// Where this room is at `now` (unix seconds).
    ///
    /// A room whose `epoch_expires_at` is `None` never lapses. That is the shape a room
    /// created before this existed has, and treating a missing expiry as "expired" would
    /// have made every one of them read-only on deploy — the wrong direction for a
    /// migration to fail in.
    pub fn lifecycle(&self, now: u64) -> Lifecycle {
        let Some(expires) = self.epoch_expires_at else {
            return Lifecycle::Live;
        };
        if now < expires {
            return Lifecycle::Live;
        }

        let lapsed_for = now - expires;
        let grace = u64::from(DORMANT_AFTER_LAPSE_DAYS) * DAY;
        if lapsed_for < grace {
            return Lifecycle::Lapsed;
        }

        // Retention runs from the **lapse**, not from the dormancy notice: the period
        // stated at creation is what the owner agreed to, and starting its clock at a later
        // internal transition would quietly turn 90 days into 120.
        //
        // The floor is the other half of that. A room whose retention is shorter than the
        // grace window would otherwise become reclaimable before its owner was ever told it
        // was dormant, which makes the notice pointless and is the surprise §9 exists to
        // prevent. So reclamation never happens sooner than the notice — a short retention
        // skips `Dormant` entirely rather than reclaiming early. Erring later destroys
        // nothing; erring earlier destroys a room somebody would have renewed.
        let reclaim_after = std::cmp::max(u64::from(self.retention_days) * DAY, grace);
        if lapsed_for < reclaim_after {
            return Lifecycle::Dormant;
        }
        Lifecycle::Reclaimable
    }

    /// When this room's current epoch expires, if it ever does.
    pub fn expires_at(&self) -> Option<u64> {
        self.epoch_expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Visibility;

    const NOW: u64 = 1_800_000_000;

    fn room(expires_at: Option<u64>, retention_days: u32) -> Room {
        Room {
            room_id: "did:key:zRoom".into(),
            owner_did: "did:key:zOwner".into(),
            visibility: Visibility::Open,
            epoch: 1,
            next_version: 1,
            retention_days,
            epoch_expires_at: expires_at,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn a_room_inside_its_epoch_is_live() {
        assert_eq!(room(Some(NOW + DAY), 90).lifecycle(NOW), Lifecycle::Live);
    }

    #[test]
    fn the_states_follow_the_two_clocks() {
        let r = room(Some(NOW), 90);
        assert_eq!(r.lifecycle(NOW), Lifecycle::Lapsed, "the moment it expires");
        assert_eq!(
            r.lifecycle(NOW + 29 * DAY),
            Lifecycle::Lapsed,
            "still inside the grace window"
        );
        assert_eq!(
            r.lifecycle(NOW + 31 * DAY),
            Lifecycle::Dormant,
            "past the grace window, inside retention"
        );
        assert_eq!(
            r.lifecycle(NOW + 91 * DAY),
            Lifecycle::Reclaimable,
            "past the retention stated at creation"
        );
    }

    /// Retention runs from the lapse, not from the dormancy notice — otherwise the period
    /// an owner agreed to at creation would silently be retention + grace.
    #[test]
    fn retention_runs_from_the_lapse_not_from_dormancy() {
        let r = room(Some(NOW), 90);
        assert_eq!(r.lifecycle(NOW + 90 * DAY), Lifecycle::Reclaimable);
        assert_ne!(
            r.lifecycle(NOW + 90 * DAY),
            Lifecycle::Dormant,
            "90 days of retention must not become 120"
        );
    }

    /// A retention shorter than the grace window does not reclaim early. It reclaims at
    /// the notice and skips `Dormant` — a room must never be reclaimable before its owner
    /// could have been told, or the notice means nothing.
    #[test]
    fn a_short_retention_never_reclaims_before_the_notice() {
        let r = room(Some(NOW), 7);
        assert_eq!(r.lifecycle(NOW + DAY), Lifecycle::Lapsed);
        assert_eq!(
            r.lifecycle(NOW + 8 * DAY),
            Lifecycle::Lapsed,
            "past its stated retention, but the owner has not been told yet"
        );
        assert_eq!(
            r.lifecycle(NOW + 31 * DAY),
            Lifecycle::Reclaimable,
            "reclaimable at the notice, with no dormant period"
        );
    }

    /// The migration direction that matters: a room stored before expiry existed must not
    /// become read-only the moment this ships.
    #[test]
    fn a_room_with_no_expiry_never_lapses() {
        let r = room(None, 1);
        assert_eq!(r.lifecycle(NOW), Lifecycle::Live);
        assert_eq!(r.lifecycle(NOW + 10_000 * DAY), Lifecycle::Live);
    }

    /// Reads keep working in every state, including the last one. Until the bytes are
    /// deleted the members' choice is renew or export, and both need reading.
    #[test]
    fn every_state_still_serves_reads() {
        for s in [
            Lifecycle::Live,
            Lifecycle::Lapsed,
            Lifecycle::Dormant,
            Lifecycle::Reclaimable,
        ] {
            assert!(s.serves_reads(), "{s:?} must still serve reads");
        }
    }

    /// The window a claim opens in, and the one it must not.
    #[test]
    fn a_claim_needs_dormancy_not_merely_a_lapse() {
        let r = room(Some(NOW), 90);

        assert!(
            !r.lifecycle(NOW + DAY).admits_a_claim(),
            "an epoch expiring is often somebody on holiday, not an abandoned room"
        );
        assert!(
            !r.lifecycle(NOW + 29 * DAY).admits_a_claim(),
            "still inside the grace window"
        );
        assert!(
            r.lifecycle(NOW + 31 * DAY).admits_a_claim(),
            "past the grace window, and the owner has had their notice"
        );
        assert!(
            r.lifecycle(NOW + 91 * DAY).admits_a_claim(),
            "a room past retention is more claimable, not less — the only party who could \
             save it must not lose the right exactly when it matters"
        );
    }

    /// Renewing is what cancels a pending claim, which is the property that makes an absent
    /// owner safe without them ever thinking about it.
    #[test]
    fn a_live_room_is_never_claimable() {
        assert!(!room(Some(NOW + DAY), 90).lifecycle(NOW).admits_a_claim());
        assert!(
            !room(None, 90)
                .lifecycle(NOW + 10_000 * DAY)
                .admits_a_claim(),
            "a room that never lapses is never claimable"
        );
    }

    #[test]
    fn only_a_live_room_accepts_writes() {
        assert!(Lifecycle::Live.accepts_writes());
        for s in [
            Lifecycle::Lapsed,
            Lifecycle::Dormant,
            Lifecycle::Reclaimable,
        ] {
            assert!(!s.accepts_writes(), "{s:?} must be read-only");
        }
    }
}
