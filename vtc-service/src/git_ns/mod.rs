//! **VTC git namespaces** — the community governs repositories on the forges
//! it has bound, and publishes who may do what there.
//!
//! Normative: the `git-ns/*` Trust Task family in dtgwg-trust-tasks-tf
//! (`specs/git-ns/**`), whose rights model lives in `git-ns/right/grant/0.1`.
//! Design: `design-docs/vtc-git-namespaces-design.md`. Where the two differ,
//! the specification is followed and the design is not.
//!
//! # Shape
//!
//! ```text
//!  member / admin ── git-ns/* ──▶ tasks ─▶ ops (fixed rules → consent → policy)
//!                                              │ writes records + an audit row
//!                                              ▼
//!                            store (GIT_NS)  ──▶ projector (audit-tail driven)
//!                                                  ├─▶ Trust Registry: registry/record/{put,delete}
//!                                                  ├─▶ bridge jobs (git-ns/bridge/job over DIDComm/TSP)
//!                                                  └─▶ lifecycle: departures, expiry
//!  bridge ── git-ns/bridge/{result,event} ──▶ bridge::handle_* ─▶ store
//! ```
//!
//! - **The VTC is the source of truth.** Rights live in [`store`]; the
//!   registry and the forge are projections of it, each rebuildable from it.
//! - **The fixed rules are code** ([`rules`]). The community's policy
//!   ([`policy`]) is evaluated only after they pass, and can only refuse.
//! - **Rights are keyed by repository, not by name.** A rename on the forge
//!   moves them; a new repository at the old name inherits nothing.

pub mod bridge;
pub mod drift;
pub mod lifecycle;
pub mod model;
pub mod ops;
pub mod policy;
pub mod projection;
pub mod reseat_v0_3;
pub mod rules;
pub mod store;
pub mod tasks;
pub mod view;
pub mod wire;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vti_common::store::KeyspaceHandle;

/// `[git_ns]` in the service configuration.
///
/// Absent ⇒ every default below: no bridges (manual-mode namespaces only),
/// and elevated git-namespace actions restricted to community administrators.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GitNsConfig {
    /// Forge host → the DID of the bridge that serves it for this community
    /// (`github.com = "did:webvh:…:bridge"`). A bridge-mode bind on a forge
    /// with no entry is refused with `git-ns/namespace/bind:noBridge`.
    #[serde(default)]
    pub bridges: BTreeMap<String, String>,
    /// The consent-class fallback (design §6).
    ///
    /// The design puts grants of `own` and `repo.create`, transfer, archive
    /// and adopt behind a **step-up**, and bind, unbind and grants of
    /// `ns.admin` behind step-up plus confirmation. This VTC has no step-up a
    /// member can perform on a signed Trust Task: its step-up is a passkey
    /// elevation on an administrator's *session*, and a signed document has
    /// no session. Until a member step-up exists, an elevated or destructive
    /// git-namespace action is accepted only from a community administrator
    /// when this is `true` (the default). Setting it `false` drops the gate
    /// and leaves only the rights model — a community choosing that should
    /// know it is choosing to run without the design's step-up.
    #[serde(default = "default_true")]
    pub elevated_requires_admin: bool,
    /// How often the projector reconciles, in seconds. Default 5; the
    /// registry reconciliation itself runs when the audit log shows a change
    /// and at least once a minute regardless.
    #[serde(default = "default_tick")]
    pub tick_seconds: u64,
}

fn default_true() -> bool {
    true
}

fn default_tick() -> u64 {
    5
}

impl Default for GitNsConfig {
    fn default() -> Self {
        Self {
            bridges: BTreeMap::new(),
            elevated_requires_admin: true,
            tick_seconds: default_tick(),
        }
    }
}

/// The git-namespace handles the service state carries.
#[derive(Clone)]
pub struct GitNsHandles {
    /// Namespaces, repositories, rights, link attempts — the source of truth.
    pub ks: KeyspaceHandle,
    /// Bridge jobs.
    pub jobs_ks: KeyspaceHandle,
    /// What has been published to the Trust Registry, and the audit cursor.
    pub projection_ks: KeyspaceHandle,
    /// Sends `git-ns/bridge/job` documents to bridges.
    pub bridge: Arc<dyn bridge::BridgeClient>,
}

impl GitNsHandles {
    /// Open the three keyspaces with a bridge client that has no messaging
    /// behind it — every job answers `Transient`, as for an unreachable
    /// bridge. For offline tools and fixtures that build an `AppState` by hand.
    pub fn open_unconnected(
        store: &vti_common::store::Store,
    ) -> Result<Self, vti_common::error::AppError> {
        use crate::store::keyspaces;
        Ok(Self {
            ks: store.keyspace(keyspaces::GIT_NS)?,
            jobs_ks: store.keyspace(keyspaces::GIT_NS_JOBS)?,
            projection_ks: store.keyspace(keyspaces::GIT_NS_PROJECTION)?,
            bridge: Arc::new(bridge::MessagingBridgeClient::new(
                Arc::new(tokio::sync::OnceCell::new()),
                None,
                crate::hooks::PendingReplies::new(),
                None,
            )),
        })
    }
}
