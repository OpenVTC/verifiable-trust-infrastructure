//! The VTN domain model.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What kind of party an entry lists (VTI-VTN-031): a community whose members are
/// subjects, or a network whose members are further entries.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum EntryKind {
    Community,
    Network,
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EntryKind::Community => "community",
            EntryKind::Network => "network",
        })
    }
}

/// Where an entry is in its lifecycle. See [`crate::lifecycle`].
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum EntryState {
    /// Listed by the network; the listed party has not responded (VTI-VTN-011).
    Listed,
    /// The listed party acknowledged: the VMC pair is complete. This is membership.
    Acknowledged,
    /// The listed party repudiated the listing. Still published, with the repudiation
    /// (VTI-VTN-012).
    Repudiated,
    /// Membership paused by the network under its governance framework.
    Suspended,
    /// The network delisted the party. Every credential it issued for the entry is revoked
    /// (VTI-VTN-053).
    Removed,
    /// The member withdrew by repudiating its membership grant.
    Departed,
}

impl EntryState {
    /// Is this entry membership, i.e. backed by a complete VMC pair in force?
    /// Only `Acknowledged` is; VTI-VTN-013 forbids calling anything else membership.
    pub fn is_membership(self) -> bool {
        self == EntryState::Acknowledged
    }

    /// Is the entry still published in the network index?
    pub fn is_published(self) -> bool {
        !matches!(self, EntryState::Removed | EntryState::Departed)
    }
}

impl fmt::Display for EntryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EntryState::Listed => "listed",
            EntryState::Acknowledged => "acknowledged",
            EntryState::Repudiated => "repudiated",
            EntryState::Suspended => "suspended",
            EntryState::Removed => "removed",
            EntryState::Departed => "departed",
        })
    }
}

/// The governance framework an entry or answer is made under (VTI-VTN-002, VTI-VTN-024).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Framework {
    /// IRI of the published governance framework.
    pub iri: String,
    /// Version of it relied on.
    pub version: String,
}

/// The network's own public description.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NetworkProfile {
    pub did: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Identified owner (VTI-VTN-002).
    pub owner: String,
    pub framework: Framework,
}

/// Index of a credential's slot in the network's status lists. One index is allocated per
/// credential and used in both the revocation and the suspension list.
pub type StatusIndex = u32;

/// A credential the network issued, with its status slot.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Issued {
    pub credential: Value,
    pub status_index: StatusIndex,
}

/// A state change, kept for audit and shown in the entry's history.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StateChange {
    pub at: DateTime<Utc>,
    pub from: Option<EntryState>,
    pub to: EntryState,
    pub reason: Option<String>,
}

/// What the network says about an entry in its directory. Curated by the network's
/// admins; not part of any credential, so editing it re-issues nothing.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct EntryProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The party's public site, or for a network its own landing page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Free-form search terms: sector, jurisdiction, specialty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Who may read the network's published set: the directory, the index and the graph.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Anyone.
    #[default]
    Public,
    /// The network's members: a member VTC or VTN signed in as itself, or a person holding
    /// a membership credential from a member community. Admins too.
    Members,
    /// The network's administrators only.
    Admins,
}

/// One entry in the network's published set: a listed community or network.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Entry {
    pub did: String,
    pub kind: EntryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub profile: EntryProfile,
    pub state: EntryState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    /// The listing VSC (network → party). Always present.
    pub listing: Issued,
    /// The membership offer: the unsigned VMC grant the party acknowledges. See
    /// [`crate::credentials::membership_offer`] for why it is unsigned (assumption A2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer: Option<Issued>,
    /// The signed VMC grant (network → party), once acknowledged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Issued>,
    /// The VMC acknowledgement (party → network), signed by the party.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<Value>,
    /// The party's repudiation VSC, of the listing or of the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repudiation: Option<Value>,

    #[serde(default)]
    pub history: Vec<StateChange>,
}

impl Entry {
    /// Credential `id` of the listing.
    pub fn listing_id(&self) -> Option<&str> {
        self.listing.credential.get("id").and_then(Value::as_str)
    }

    /// Credential `id` of the grant, if signed.
    pub fn grant_id(&self) -> Option<&str> {
        self.grant
            .as_ref()
            .and_then(|g| g.credential.get("id"))
            .and_then(Value::as_str)
    }
}
