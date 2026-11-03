//! The network index: the published set (VTI-VTN-011/012/024/031).
//!
//! Each answer carries the framework it is made under and its determination time. Every
//! entry states its kind and whether it is acknowledged. Repudiated entries are published
//! with the repudiation. Removed and departed entries are not published.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{Entry, EntryKind, EntryProfile, EntryState, Framework, NetworkProfile};

pub const INDEX_TYPE: &str = "VerifiableTrustNetworkIndex";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IndexEntry {
    pub did: String,
    pub kind: EntryKind,
    pub state: EntryState,
    /// `true` only for a complete membership edge. Consumers MUST check this before relying
    /// on an entry (VTI-VTN-021).
    pub acknowledged: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The network's directory description of the entry. Searchable by a parent network, and
    /// `url` is how a parent reaches a member network's own index.
    #[serde(default)]
    pub profile: EntryProfile,
    pub listing: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledgement: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repudiation: Option<Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkIndex {
    #[serde(rename = "type")]
    pub type_: String,
    pub network: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub owner: String,
    pub framework: Framework,
    /// When the network determined this answer (VTI-REG-011).
    pub determined_at: DateTime<Utc>,
    pub entries: Vec<IndexEntry>,
}

impl IndexEntry {
    pub fn from_entry(entry: &Entry) -> Self {
        Self {
            did: entry.did.clone(),
            kind: entry.kind,
            state: entry.state,
            acknowledged: entry.state.is_membership(),
            label: entry.label.clone(),
            profile: entry.profile.clone(),
            listing: entry.listing.credential.clone(),
            grant: entry.grant.as_ref().map(|g| g.credential.clone()),
            acknowledgement: entry.ack.clone(),
            repudiation: entry.repudiation.clone(),
        }
    }
}

/// Build the (unsigned) index from the network's entries.
pub fn build<'a>(
    profile: &NetworkProfile,
    entries: impl IntoIterator<Item = &'a Entry>,
    determined_at: DateTime<Utc>,
) -> NetworkIndex {
    let mut entries: Vec<IndexEntry> = entries
        .into_iter()
        .filter(|e| e.state.is_published())
        .map(IndexEntry::from_entry)
        .collect();
    entries.sort_by(|a, b| a.did.cmp(&b.did));
    NetworkIndex {
        type_: INDEX_TYPE.to_string(),
        network: profile.did.clone(),
        name: profile.name.clone(),
        description: profile.description.clone(),
        owner: profile.owner.clone(),
        framework: profile.framework.clone(),
        determined_at,
        entries,
    }
}
