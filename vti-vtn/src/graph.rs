//! The DTG graph export: one edge per credential.
//!
//! The graph is assembled from credentials, never flattened into triples: each edge
//! carries the credential that is its evidence, and its own status. The two halves of a
//! membership edge are two edges. Nested networks appear as nodes of kind `network`; a
//! viewer expands one by fetching that network's own export, so its entries stay
//! attributed to it (VTI-VTN-033).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::index::NetworkIndex;
use crate::model::{Entry, EntryKind, EntryState, NetworkProfile, StatusIndex};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NodeKind {
    Network,
    Community,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The entry state, for listed nodes; `None` for the exporting network itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<EntryState>,
    /// `true` for the network this export belongs to.
    pub root: bool,
    /// For a member network: where its own graph and index are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EdgeRole {
    Listing,
    Grant,
    Acknowledgement,
    Repudiation,
}

/// Status as far as this network can determine it.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EdgeStatus {
    Valid,
    Suspended,
    Revoked,
    /// Issued by the listed party, whose status the network does not hold.
    Unchecked,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Edge {
    /// The credential `id`.
    pub id: String,
    pub source: String,
    pub target: String,
    pub role: EdgeRole,
    pub cred_type: String,
    pub status: EdgeStatus,
    pub credential: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

/// Looks up a network-issued credential's status bits.
pub trait StatusLookup {
    fn status(&self, index: StatusIndex) -> EdgeStatus;
}

impl<F: Fn(StatusIndex) -> EdgeStatus> StatusLookup for F {
    fn status(&self, index: StatusIndex) -> EdgeStatus {
        self(index)
    }
}

fn cred_type(credential: &Value) -> String {
    credential
        .get("type")
        .and_then(Value::as_array)
        .and_then(|t| t.last())
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

fn edge(credential: &Value, role: EdgeRole, status: EdgeStatus) -> Option<Edge> {
    let source = credential.get("issuer")?.as_str()?.to_string();
    let target = credential
        .get("credentialSubject")?
        .get("id")?
        .as_str()?
        .to_string();
    Some(Edge {
        id: credential.get("id")?.as_str()?.to_string(),
        source,
        target,
        role,
        cred_type: cred_type(credential),
        status,
        credential: credential.clone(),
    })
}

/// Export the graph of `profile`'s network. `include_exited` adds removed and departed
/// entries (for the admin view); the public view leaves them out.
pub fn export<'a>(
    profile: &NetworkProfile,
    entries: impl IntoIterator<Item = &'a Entry>,
    status: &dyn StatusLookup,
    include_exited: bool,
) -> Graph {
    let mut nodes = vec![Node {
        id: profile.did.clone(),
        kind: NodeKind::Network,
        label: Some(profile.name.clone()),
        state: None,
        root: true,
        url: None,
    }];
    let mut edges = Vec::new();

    for entry in entries {
        if !include_exited && !entry.state.is_published() {
            continue;
        }
        nodes.push(Node {
            id: entry.did.clone(),
            kind: match entry.kind {
                EntryKind::Community => NodeKind::Community,
                EntryKind::Network => NodeKind::Network,
            },
            label: entry.label.clone(),
            state: Some(entry.state),
            root: false,
            url: entry.profile.url.clone(),
        });
        edges.extend(edge(
            &entry.listing.credential,
            EdgeRole::Listing,
            status.status(entry.listing.status_index),
        ));
        if let Some(grant) = &entry.grant {
            edges.extend(edge(
                &grant.credential,
                EdgeRole::Grant,
                status.status(grant.status_index),
            ));
        }
        if let Some(ack) = &entry.ack {
            edges.extend(edge(ack, EdgeRole::Acknowledgement, EdgeStatus::Unchecked));
        }
        if let Some(repudiation) = &entry.repudiation {
            edges.extend(edge(
                repudiation,
                EdgeRole::Repudiation,
                EdgeStatus::Unchecked,
            ));
        }
    }
    Graph { nodes, edges }
}

/// The graph of another network, from its verified signed index. Its credentials' status
/// is not held here, so every edge is `Unchecked`. A viewer that wants live status resolves
/// it against that network's status lists.
pub fn from_index(index: &NetworkIndex) -> Graph {
    let mut nodes = vec![Node {
        id: index.network.clone(),
        kind: NodeKind::Network,
        label: Some(index.name.clone()),
        state: None,
        root: true,
        url: None,
    }];
    let mut edges = Vec::new();
    for entry in &index.entries {
        nodes.push(Node {
            id: entry.did.clone(),
            kind: match entry.kind {
                EntryKind::Community => NodeKind::Community,
                EntryKind::Network => NodeKind::Network,
            },
            label: entry.label.clone(),
            state: Some(entry.state),
            root: false,
            url: entry.profile.url.clone(),
        });
        edges.extend(edge(
            &entry.listing,
            EdgeRole::Listing,
            EdgeStatus::Unchecked,
        ));
        for (credential, role) in [
            (&entry.grant, EdgeRole::Grant),
            (&entry.acknowledgement, EdgeRole::Acknowledgement),
            (&entry.repudiation, EdgeRole::Repudiation),
        ] {
            if let Some(c) = credential {
                edges.extend(edge(c, role, EdgeStatus::Unchecked));
            }
        }
    }
    Graph { nodes, edges }
}
