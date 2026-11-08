//! The member directory: the network's published set, searchable.
//!
//! A directory row says what the network lists and in what state, with the ack state
//! foremost (VTI-VTN-021): a consumer must be able to tell a member from a party the
//! network merely lists. Removed and departed entries are not published.

use serde::{Deserialize, Serialize};

use crate::index::{IndexEntry, NetworkIndex};
use crate::model::{Entry, EntryKind, EntryState};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryEntry {
    pub did: String,
    pub kind: EntryKind,
    pub state: EntryState,
    /// A complete, unsuspended membership edge.
    pub acknowledged: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

impl DirectoryEntry {
    pub fn from_entry(entry: &Entry) -> Self {
        Self {
            did: entry.did.clone(),
            kind: entry.kind,
            state: entry.state,
            acknowledged: entry.state.is_membership(),
            label: entry.label.clone(),
            description: entry.profile.description.clone(),
            url: entry.profile.url.clone(),
            tags: entry.profile.tags.clone(),
            listing_id: entry.listing_id().map(str::to_string),
            grant_id: entry.grant_id().map(str::to_string),
        }
    }

    pub fn from_index_entry(entry: &IndexEntry) -> Self {
        let id = |v: &Option<serde_json::Value>| {
            v.as_ref()
                .and_then(|c| c.get("id"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        };
        Self {
            did: entry.did.clone(),
            kind: entry.kind,
            state: entry.state,
            acknowledged: entry.acknowledged,
            label: entry.label.clone(),
            description: entry.profile.description.clone(),
            url: entry.profile.url.clone(),
            tags: entry.profile.tags.clone(),
            listing_id: id(&Some(entry.listing.clone())),
            grant_id: id(&entry.grant),
        }
    }

    fn matches_text(&self, needle: &str) -> bool {
        let hit = |s: &str| s.to_lowercase().contains(needle);
        hit(&self.did)
            || self.label.as_deref().is_some_and(hit)
            || self.description.as_deref().is_some_and(hit)
            || self.tags.iter().any(|t| hit(t))
    }
}

/// A directory search.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectoryQuery {
    /// Free text: matched case-insensitively against DID, name, description and tags.
    /// Every whitespace-separated term must match.
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub kind: Option<EntryKind>,
    #[serde(default)]
    pub state: Option<EntryState>,
    /// Only complete memberships.
    #[serde(default)]
    pub members_only: bool,
}

/// Counts that may be shown even when the directory itself is restricted.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectorySummary {
    pub communities: usize,
    pub networks: usize,
    pub acknowledged: usize,
    pub unacknowledged: usize,
}

/// Search `entries`. Members come first, then by name.
pub fn search<'a>(
    entries: impl IntoIterator<Item = &'a Entry>,
    query: &DirectoryQuery,
) -> Vec<DirectoryEntry> {
    filter_rows(
        entries
            .into_iter()
            .filter(|e| e.state.is_published())
            .map(DirectoryEntry::from_entry),
        query,
    )
}

/// Search another network's (verified) index.
pub fn search_index(index: &NetworkIndex, query: &DirectoryQuery) -> Vec<DirectoryEntry> {
    filter_rows(
        index
            .entries
            .iter()
            .filter(|e| e.state.is_published())
            .map(DirectoryEntry::from_index_entry),
        query,
    )
}

/// One step on the way to a federated result: a network, and its entry in the network
/// before it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PathHop {
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// That network's entry state in the network before it on the path. Evaluated per hop,
    /// never inferred from another (VTI-VTN-032).
    pub state: EntryState,
    pub acknowledged: bool,
}

/// A directory row found through member networks. `path` is empty for this network's own
/// entries. Otherwise it names each network between this one and the network that lists
/// the row, so the row is never presented as this network's own (VTI-VTN-033).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FederatedEntry {
    #[serde(flatten)]
    pub entry: DirectoryEntry,
    /// The network that lists this row.
    pub listed_by: String,
    pub path: Vec<PathHop>,
}

/// A member network whose index could not be read: indeterminate, not absent
/// (VTI-REG-012).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Unreachable {
    pub network: String,
    pub path: Vec<PathHop>,
    pub reason: String,
}

fn filter_rows(
    rows: impl Iterator<Item = DirectoryEntry>,
    query: &DirectoryQuery,
) -> Vec<DirectoryEntry> {
    let terms: Vec<String> = query
        .q
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_lowercase)
        .collect();
    let mut rows: Vec<DirectoryEntry> = rows
        .filter(|row| query.kind.is_none_or(|k| row.kind == k))
        .filter(|row| query.state.is_none_or(|s| row.state == s))
        .filter(|row| !query.members_only || row.acknowledged)
        .filter(|row| terms.iter().all(|t| row.matches_text(t)))
        .collect();
    rows.sort_by(|a, b| {
        b.acknowledged.cmp(&a.acknowledged).then_with(|| {
            let name = |r: &DirectoryEntry| r.label.clone().unwrap_or_else(|| r.did.clone());
            name(a).to_lowercase().cmp(&name(b).to_lowercase())
        })
    });
    rows
}

pub fn summary<'a>(entries: impl IntoIterator<Item = &'a Entry>) -> DirectorySummary {
    let mut s = DirectorySummary::default();
    for e in entries.into_iter().filter(|e| e.state.is_published()) {
        match e.kind {
            EntryKind::Community => s.communities += 1,
            EntryKind::Network => s.networks += 1,
        }
        if e.state.is_membership() {
            s.acknowledged += 1;
        } else {
            s.unacknowledged += 1;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EntryProfile, Issued};
    use chrono::Utc;
    use serde_json::json;

    fn entry(did: &str, label: &str, kind: EntryKind, state: EntryState, tags: &[&str]) -> Entry {
        Entry {
            did: did.into(),
            kind,
            label: Some(label.into()),
            profile: EntryProfile {
                description: Some(format!("{label} description")),
                url: None,
                tags: tags.iter().map(|t| t.to_string()).collect(),
            },
            state,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            listing: Issued {
                credential: json!({ "id": format!("urn:uuid:{did}") }),
                status_index: 0,
            },
            offer: None,
            grant: None,
            ack: None,
            repudiation: None,
            history: vec![],
        }
    }

    fn fixture() -> Vec<Entry> {
        vec![
            entry(
                "did:ex:au",
                "Health-AU",
                EntryKind::Network,
                EntryState::Acknowledged,
                &["australia"],
            ),
            entry(
                "did:ex:nz",
                "Health-NZ",
                EntryKind::Network,
                EntryState::Listed,
                &["new zealand"],
            ),
            entry(
                "did:ex:msf",
                "MSF",
                EntryKind::Community,
                EntryState::Acknowledged,
                &["ngo", "emergency"],
            ),
            entry(
                "did:ex:gone",
                "Gone",
                EntryKind::Community,
                EntryState::Removed,
                &[],
            ),
        ]
    }

    #[test]
    fn members_first_and_exited_hidden() {
        let rows = search(&fixture(), &DirectoryQuery::default());
        let names: Vec<_> = rows.iter().map(|r| r.label.clone().unwrap()).collect();
        assert_eq!(names, ["Health-AU", "MSF", "Health-NZ"]);
    }

    #[test]
    fn text_terms_all_match_across_fields() {
        let q = |text: &str| DirectoryQuery {
            q: Some(text.into()),
            ..Default::default()
        };
        assert_eq!(search(&fixture(), &q("emergency")).len(), 1);
        assert_eq!(search(&fixture(), &q("HEALTH zealand")).len(), 1);
        assert_eq!(search(&fixture(), &q("did:ex:")).len(), 3);
        assert!(search(&fixture(), &q("gone")).is_empty());
    }

    #[test]
    fn filters_and_summary() {
        let rows = search(
            &fixture(),
            &DirectoryQuery {
                kind: Some(EntryKind::Network),
                members_only: true,
                ..Default::default()
            },
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(
            summary(&fixture()),
            DirectorySummary {
                communities: 1,
                networks: 2,
                acknowledged: 2,
                unacknowledged: 1
            }
        );
    }
}
