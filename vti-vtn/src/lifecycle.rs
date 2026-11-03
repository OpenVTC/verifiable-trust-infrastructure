//! The entry state machine.
//!
//! ```text
//!            List                Acknowledge
//!  (none) ─────────► Listed ─────────────────► Acknowledged ◄──┐
//!                     │  │                      │   │   │       │ Reinstate
//!           Repudiate │  │ Remove        Depart │   │   └─► Suspended
//!                     ▼  ▼                      ▼   │ Remove   │ Depart / Remove
//!               Repudiated ──Remove──► Removed  Departed ◄──────┘
//!                     │                  │        │
//!                     └──── List ────────┴────────┘ (re-listing starts over at Listed)
//! ```
//!
//! Rules carried by the machine:
//! - Membership (`Acknowledged`) is reachable only through the listed party's
//!   acknowledgement (VTI-VTN-013).
//! - The network can always remove; it can never make a party acknowledge, depart or
//!   repudiate. Those events are only accepted with the party's own signature, which the
//!   service checks before calling [`transition`].

use serde::{Deserialize, Serialize};

use crate::error::{Result, VtnError};
use crate::model::EntryState;

/// Something that happens to an entry.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Event {
    /// The network lists, or re-lists, the party.
    List,
    /// The party acknowledges the listing (signs the VMC acknowledgement).
    Acknowledge,
    /// The party repudiates the listing.
    Repudiate,
    /// The network suspends a membership.
    Suspend,
    /// The network lifts a suspension.
    Reinstate,
    /// The network delists the party.
    Remove,
    /// The member withdraws (repudiates its grant).
    Depart,
    /// The network edits the entry's directory profile. No state change.
    Update,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Event::List => "list",
            Event::Acknowledge => "acknowledge",
            Event::Repudiate => "repudiate",
            Event::Suspend => "suspend",
            Event::Reinstate => "reinstate",
            Event::Remove => "remove",
            Event::Depart => "depart",
            Event::Update => "update",
        }
    }
}

/// The state after `event`, from `from` (`None` for an entry that does not exist yet).
pub fn transition(from: Option<EntryState>, event: Event) -> Result<EntryState> {
    use EntryState::*;
    let to = match (from, event) {
        (None, Event::List) => Listed,
        (Some(Repudiated | Removed | Departed), Event::List) => Listed,
        (Some(Listed), Event::Acknowledge) => Acknowledged,
        (Some(Listed), Event::Repudiate) => Repudiated,
        (Some(Acknowledged), Event::Suspend) => Suspended,
        (Some(Suspended), Event::Reinstate) => Acknowledged,
        (Some(Acknowledged | Suspended), Event::Depart) => Departed,
        (Some(Listed | Acknowledged | Suspended | Repudiated), Event::Remove) => Removed,
        (Some(state), Event::Update) if state.is_published() => state,
        (Some(from), event) => {
            return Err(VtnError::InvalidTransition {
                from,
                event: event.as_str(),
            });
        }
        (None, event) => {
            return Err(VtnError::Rejected(format!(
                "no entry to apply `{}` to",
                event.as_str()
            )));
        }
    };
    Ok(to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use EntryState::*;

    #[test]
    fn happy_path_to_membership_and_out() {
        let s = transition(None, Event::List).unwrap();
        assert_eq!(s, Listed);
        let s = transition(Some(s), Event::Acknowledge).unwrap();
        assert!(s.is_membership());
        let s = transition(Some(s), Event::Suspend).unwrap();
        assert!(!s.is_membership());
        let s = transition(Some(s), Event::Reinstate).unwrap();
        assert_eq!(transition(Some(s), Event::Depart).unwrap(), Departed);
    }

    #[test]
    fn membership_only_via_acknowledgement() {
        for from in [Repudiated, Suspended, Removed, Departed] {
            assert!(
                transition(Some(from), Event::Acknowledge).is_err(),
                "{from}"
            );
        }
    }

    #[test]
    fn network_cannot_double_list_or_remove_twice() {
        assert!(transition(Some(Listed), Event::List).is_err());
        assert!(transition(Some(Acknowledged), Event::List).is_err());
        assert!(transition(Some(Removed), Event::Remove).is_err());
    }

    #[test]
    fn relisting_after_exit_starts_over() {
        for from in [Repudiated, Removed, Departed] {
            assert_eq!(transition(Some(from), Event::List).unwrap(), Listed);
        }
    }

    #[test]
    fn repudiate_only_an_unacknowledged_listing() {
        // A member leaves by departing (repudiating the grant), not by repudiating the listing.
        assert!(transition(Some(Acknowledged), Event::Repudiate).is_err());
    }
}
