//! Who may register a room on this host, and how many.
//!
//! `rooms/create` is the one task no room-issued chain can authorize, so
//! `vti_rooms::authz::authorize_create` checks only that the signer is the owner it names,
//! and leaves bounding registration to whoever hosts. This is that bound: an allowlist of
//! the parties this host registers rooms for, and a ceiling on rooms per owner and in
//! total. Every room counts toward storage, so without one a host serves as many rooms as
//! anyone with a fresh `did:key` cares to register.

use std::collections::BTreeSet;

/// Rooms one owner may hold on a host unless its operator says otherwise.
///
/// A courtesy limit, not a bound: it counts rooms by their current owner, so a party can
/// step around it by registering under more DIDs, or by transferring rooms it owns. What
/// bounds a host is who may register at all ([`Creators`]) and [`DEFAULT_MAX_ROOMS`].
pub const DEFAULT_MAX_ROOMS_PER_OWNER: u64 = 100;

/// Rooms a host holds in total unless its operator says otherwise.
pub const DEFAULT_MAX_ROOMS: u64 = 10_000;

/// Which parties a host registers rooms for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Creators {
    /// Nobody: every `rooms/create` is refused. Rooms already registered, and mirrors,
    /// are served as before.
    None,
    /// Only these DIDs, compared with any `#fragment` removed.
    Only(BTreeSet<String>),
    /// Any party that signs as the owner it names. The operator's explicit choice, for a
    /// host open to the public; the room ceilings still apply.
    Any,
}

/// The host's room-registration policy ([`crate::HostState::set_room_creation`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomCreation {
    /// Who may register.
    pub creators: Creators,
    /// Rooms one owner may hold here, counted at registration by current owner. A
    /// courtesy limit ([`DEFAULT_MAX_ROOMS_PER_OWNER`]).
    pub max_rooms_per_owner: u64,
    /// Rooms this host holds in total, mirrors included.
    pub max_rooms: u64,
}

impl Default for RoomCreation {
    /// What a host gets from [`crate::open_state`] until told otherwise: nobody may
    /// register, within the default ceilings. An embedder names creators, or opts into
    /// [`RoomCreation::any_creator`], with [`crate::HostState::set_room_creation`].
    fn default() -> Self {
        Self {
            creators: Creators::None,
            max_rooms_per_owner: DEFAULT_MAX_ROOMS_PER_OWNER,
            max_rooms: DEFAULT_MAX_ROOMS,
        }
    }
}

impl RoomCreation {
    /// Any signer may register, within the default ceilings: for a host open to anyone,
    /// and for tests and examples that register rooms as whoever they mint.
    pub fn any_creator() -> Self {
        Self {
            creators: Creators::Any,
            ..Self::default()
        }
    }

    /// Only `dids` may register, compared with any `#fragment` or `?query` removed.
    pub fn only(dids: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            creators: Creators::Only(
                dids.into_iter()
                    .map(|d| bare_did(d.as_ref()).to_string())
                    .collect(),
            ),
            ..Self::default()
        }
    }
}

/// Why a registration was refused before any room was counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreationRefused {
    /// The signer is not one this host registers rooms for.
    NotACreator,
    /// The owner already holds `max` rooms here.
    OwnerAtLimit { max: u64 },
    /// The host already holds `max` rooms.
    HostAtLimit { max: u64 },
}

impl RoomCreation {
    /// Whether `presenter` may register a room at all.
    pub fn admits(&self, presenter: &str) -> bool {
        match &self.creators {
            Creators::None => false,
            Creators::Any => true,
            Creators::Only(dids) => dids.contains(bare_did(presenter)),
        }
    }

    /// Refuse a registration by `presenter` for `owner`, given the rooms this host holds
    /// now (`total`) and how many `owner` holds (`owned`).
    pub fn check(&self, presenter: &str, total: u64, owned: u64) -> Result<(), CreationRefused> {
        if !self.admits(presenter) {
            return Err(CreationRefused::NotACreator);
        }
        if owned >= self.max_rooms_per_owner {
            return Err(CreationRefused::OwnerAtLimit {
                max: self.max_rooms_per_owner,
            });
        }
        if total >= self.max_rooms {
            return Err(CreationRefused::HostAtLimit {
                max: self.max_rooms,
            });
        }
        Ok(())
    }
}

/// `did` without a `#fragment` or `?query`.
pub fn bare_did(did: &str) -> &str {
    did.split(['#', '?']).next().unwrap_or(did)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn only(dids: &[&str]) -> RoomCreation {
        RoomCreation::only(dids)
    }

    #[test]
    fn nobody_registers_when_no_creator_is_named() {
        let policy = RoomCreation::default();
        assert_eq!(
            policy.check("did:key:z6Mk", 0, 0),
            Err(CreationRefused::NotACreator)
        );
    }

    #[test]
    fn a_named_creator_registers_and_others_do_not() {
        // Named with a fragment, compared without.
        let policy = only(&["did:key:zAlice#zAlice"]);
        assert!(policy.check("did:key:zAlice", 0, 0).is_ok());
        assert!(policy.check("did:key:zAlice#zAlice", 0, 0).is_ok());
        assert_eq!(
            policy.check("did:key:zMallory", 0, 0),
            Err(CreationRefused::NotACreator)
        );
    }

    #[test]
    fn the_owner_ceiling_and_the_host_ceiling_hold() {
        let policy = RoomCreation {
            creators: Creators::Any,
            max_rooms_per_owner: 2,
            max_rooms: 5,
        };
        assert!(policy.check("did:key:zA", 4, 1).is_ok());
        assert_eq!(
            policy.check("did:key:zA", 4, 2),
            Err(CreationRefused::OwnerAtLimit { max: 2 })
        );
        assert_eq!(
            policy.check("did:key:zA", 5, 0),
            Err(CreationRefused::HostAtLimit { max: 5 })
        );
    }
}
