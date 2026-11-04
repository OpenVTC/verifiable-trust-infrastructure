//! **Collection** of the principal's identifiers (VTI-NTF-080 – 093,
//! `vta/collection/{claim,release,list}/0.1`).
//!
//! A message addressed to a persona DID waits at the mediator its document
//! advertises until some party collects it, and the mediator permits one
//! connection per DID. This module decides **who** that party is for each
//! identifier the VTA holds keys of: the VTA itself, or one client of the
//! principal under a lease — a **collection claim** — or nobody, and why.
//!
//! # What lives here
//!
//! - The candidate set VTI-NTF-080 names ([`candidates`]): every `did:webvh`
//!   this VTA holds in one of its principal's contexts whose current document
//!   advertises a transport through a mediator, less its own DID, any DID that
//!   is itself the subject of an ACL entry (a node or client that collects for
//!   itself), any identity provision-integration minted for another party
//!   ([`mark_provisioned`]), and any DID the operator excludes.
//! - The claims ([`ClaimRecord`]), their grant, renewal and release
//!   ([`claim`], [`release`]), and the listing ([`list`]).
//! - The plan the collector follows ([`plan`]): a pure function of the
//!   candidates, the claims, the conflicts, the setting and the bound, so the
//!   listing and the collector can never disagree about who collects.
//! - [`CollectionControl`]: the handle the claim path and the collector share.
//!   A grant stops collection **under the identifier's lock** before it is
//!   answered (VTI-NTF-082), and the collector re-reads the claim under the
//!   same lock before it opens a connection, so no interleaving leaves both a
//!   claim in force and a connection of the VTA's own.
//!
//! The connections themselves are `crate::messaging::collector`'s.
//!
//! # The setting (VTI-NTF-093)
//!
//! `[collection] collect_by_default` is **off** unless the operator enables it.
//! While off the VTA collects for nothing, and still grants, renews, releases
//! and lists claims, listing every unclaimed identifier as collected by nobody
//! because collection is disabled. A change is audited by [`record_setting`] at
//! the boot that applies it.
//!
//! # Store layout ([`crate::keyspaces::COLLECTION`])
//!
//! - `claim:<contextId>\0<logDid>` → [`ClaimRecord`]
//! - `conflict:<contextId>\0<logDid>` → [`ConflictRecord`]
//! - `provisioned:<did>` → `true`
//! - `setting` → the last applied value of `collect_by_default`

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use vta_sdk::notifications::identity;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::auth::AuthClaims;
use crate::server::AppState;

/// Default page of [`list`].
pub const LIST_DEFAULT_PAGE: usize = 50;
/// Largest page of [`list`] (the schema's `limit` maximum).
pub const LIST_MAX_PAGE: usize = 200;

const CLAIM_PREFIX: &str = "claim:";
const CONFLICT_PREFIX: &str = "conflict:";
const PROVISIONED_PREFIX: &str = "provisioned:";
const SETTING_KEY: &str = "setting";

fn claim_key(context: &str, log_did: &str) -> String {
    format!("{CLAIM_PREFIX}{context}\0{log_did}")
}

fn conflict_key(context: &str, log_did: &str) -> String {
    format!("{CONFLICT_PREFIX}{context}\0{log_did}")
}

fn provisioned_key(did: &str) -> String {
    format!("{PROVISIONED_PREFIX}{}", identity(did))
}

// ── Records ────────────────────────────────────────────────────────────────

/// A collection claim: `claimant` is the one collector of `identifier` until
/// `ends_at` (VTI-NTF-082).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimRecord {
    pub context_id: String,
    /// The `did:webvh` log the claim is on. A claim names the identifier, not a
    /// key, so a rotation leaves it in place (VTI-NTF-090).
    pub log_did: String,
    /// The ACL subject the claim was granted to. Carried to its successor on a
    /// rollover or a key swap (VTI-NTF-084, [`carry_claims`]).
    pub claimant: String,
    pub granted_at: DateTime<Utc>,
    /// When the claim ends unless renewed. A release by the claimant moves it
    /// to the instant of the release.
    pub ends_at: DateTime<Utc>,
    /// Who released the claim, when someone did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_by: Option<String>,
}

impl ClaimRecord {
    /// In force: not yet at its end (VTI-NTF-084). A claim released by its
    /// claimant ended at the release.
    #[must_use]
    pub fn in_force(&self, now: DateTime<Utc>) -> bool {
        now < self.ends_at
    }

    /// Released by its own claimant, who had stopped collecting first
    /// (VTI-NTF-083): the VTA may resume at once.
    #[must_use]
    pub fn released_by_claimant(&self) -> bool {
        self.released_by.as_deref() == Some(self.claimant.as_str())
    }

    /// Released by a party other than its claimant: unrenewable, and still ends
    /// at its end (VTI-NTF-084).
    #[must_use]
    pub fn released_by_other(&self) -> bool {
        self.released_by
            .as_deref()
            .is_some_and(|r| r != self.claimant)
    }

    /// Whether the VTA must still keep off the identifier: while the claim is in
    /// force and, unless the claimant released it, until its end plus the VTA's
    /// clock-skew tolerance — the claimant stops by its own clock, not the
    /// VTA's (VTI-NTF-084).
    #[must_use]
    pub fn keeps_vta_off(&self, now: DateTime<Utc>, skew: Duration) -> bool {
        self.in_force(now) || (!self.released_by_claimant() && now < self.ends_at + skew)
    }
}

/// An identifier the VTA stopped collecting for after another connection kept
/// closing its own (VTI-NTF-085). Cleared when a client claims it — the way the
/// principal settles the conflict — and then the VTA tries again once the claim
/// has ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictRecord {
    pub context_id: String,
    pub log_did: String,
    pub since: DateTime<Utc>,
    /// How many times another connection closed the VTA's before it stopped.
    pub closures: u32,
}

/// An identifier VTI-NTF-080 names: one the VTA would collect for unless a
/// client has claimed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub context_id: String,
    /// The DID as the principal gives it out: the `did:scid` form when the log
    /// is presented as one, the `did:webvh` DID otherwise.
    pub identifier: String,
    /// The `did:webvh` log the identifier is.
    pub log_did: String,
    /// The mediator its document advertises a transport through.
    pub mediator_did: String,
    /// The identifier's current document, which names the keys to collect with.
    pub document: serde_json::Value,
}

impl Candidate {
    /// A fingerprint of what a connection for this identifier is built from —
    /// the mediator and the published methods — so a key rotation or a mediator
    /// change rebuilds it (VTI-NTF-090).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.mediator_did.as_bytes());
        h.update(b"\0");
        h.update(serde_json::to_vec(&self.document["verificationMethod"]).unwrap_or_default());
        h.update(b"\0");
        h.update(serde_json::to_vec(&self.document["keyAgreement"]).unwrap_or_default());
        vta_sdk::hex::lower(&h.finalize())
    }

    fn matches(&self, did: &str) -> bool {
        let wanted = identity(did);
        wanted == identity(&self.identifier) || wanted == identity(&self.log_did)
    }
}

// ── The control handle the claim path and the collector share ─────────────

/// A connection the VTA holds for one identifier. Closing it stops the
/// identifier's websocket — every protocol on it — before it returns.
pub trait CollectingSession: Send + Sync {
    /// Stop collecting and close every connection for the identifier.
    fn close(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
    /// The fingerprint of the candidate the session was built from.
    fn fingerprint(&self) -> &str;
}

/// Why [`CollectionControl::insert`] refused a session.
#[derive(Debug, PartialEq, Eq)]
pub enum InsertRefused {
    /// The VTA already holds a connection for this identifier. The mediator
    /// permits one per DID, so a second is an eviction, not capacity.
    AlreadyCollecting,
}

/// Shared between the Trust Task handlers and the collector (see the module
/// docs). Not feature-gated: a build without a messaging transport still
/// grants and lists claims, it simply never holds a session.
pub struct CollectionControl {
    enabled: AtomicBool,
    locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    sessions: std::sync::Mutex<HashMap<String, Arc<dyn CollectingSession>>>,
    kick: tokio::sync::Notify,
}

impl std::fmt::Debug for CollectionControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectionControl")
            .field("enabled", &self.enabled())
            .field("collecting", &self.collecting().len())
            .finish()
    }
}

impl CollectionControl {
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            locks: std::sync::Mutex::new(HashMap::new()),
            sessions: std::sync::Mutex::new(HashMap::new()),
            kick: tokio::sync::Notify::new(),
        }
    }

    /// The operator's "collection by default" setting as this process applies
    /// it (VTI-NTF-093).
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Change the setting for this process. Turning it off makes the next pass
    /// of the collector close every connection it holds (VTI-NTF-093).
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
        self.kick();
    }

    /// The identifier's lock. Held by a grant across "record the claim, stop
    /// collecting", and by the collector across "re-read the claim, open the
    /// connection, record it", which is what makes VTI-NTF-081 hold under any
    /// interleaving.
    pub async fn lock_identifier(&self, log_did: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(
                locks
                    .entry(identity(log_did))
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        lock.lock_owned().await
    }

    /// Record a session for `log_did`. Refused when one is already held: the
    /// one-socket-per-DID invariant is enforced here, not hoped for.
    pub fn insert(
        &self,
        log_did: &str,
        session: Arc<dyn CollectingSession>,
    ) -> Result<(), InsertRefused> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let key = identity(log_did);
        if sessions.contains_key(&key) {
            return Err(InsertRefused::AlreadyCollecting);
        }
        sessions.insert(key, session);
        Ok(())
    }

    /// Whether the VTA holds a connection for `log_did`.
    #[must_use]
    pub fn is_collecting(&self, log_did: &str) -> bool {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&identity(log_did))
    }

    /// The fingerprint of the session held for `log_did`, if any.
    #[must_use]
    pub fn session_fingerprint(&self, log_did: &str) -> Option<String> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&identity(log_did))
            .map(|s| s.fingerprint().to_string())
    }

    /// Every identifier the VTA holds a connection for.
    #[must_use]
    pub fn collecting(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        out.sort();
        out
    }

    /// Stop collecting for `log_did` and close its connection, returning once
    /// it is closed. The session leaves the map before the close is awaited,
    /// so no lock is held across it.
    pub async fn stop(&self, log_did: &str) {
        let session = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&identity(log_did));
        if let Some(session) = session {
            session.close().await;
        }
    }

    /// Stop every session (shutdown, or the setting turned off).
    pub async fn stop_all(&self) {
        for did in self.collecting() {
            let _guard = self.lock_identifier(&did).await;
            self.stop(&did).await;
        }
    }

    /// Ask the collector to reconcile now rather than on its next tick.
    pub fn kick(&self) {
        self.kick.notify_one();
    }

    /// Resolves when [`kick`](Self::kick) is called.
    pub async fn kicked(&self) {
        self.kick.notified().await;
    }
}

// ── The candidate set (VTI-NTF-080) ────────────────────────────────────────

/// The mediator a document advertises a transport through: the `TSPTransport`
/// or `DIDCommMessaging` endpoint that names a DID — matched on the service
/// `type`, never the fragment. TSP first, as the workspace prefers it; both
/// ride the one connection.
#[must_use]
pub fn mediator_of(document: &serde_json::Value) -> Option<String> {
    let caps = vta_sdk::protocol::matching::ServiceCapabilities::from_did_document(document);
    [caps.tsp, caps.didcomm]
        .into_iter()
        .flatten()
        .find(|e| e.starts_with("did:"))
}

/// Whether the last entry of a `did:webvh` log deactivates it.
fn log_deactivated(log: &str) -> bool {
    log.lines()
        .rfind(|l| !l.trim().is_empty())
        .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .is_some_and(|e| e["parameters"]["deactivated"].as_bool() == Some(true))
}

/// The identities the VTA never collects for, whatever they advertise: its own
/// DID, every ACL subject, every identity provisioned for another party, the
/// mediator it is configured with, and the operator's exclusions.
async fn excluded(state: &AppState) -> Result<HashSet<String>, AppError> {
    let mut out = HashSet::new();
    {
        let config = state.config.read().await;
        if let Some(did) = config.vta_did.as_deref() {
            out.insert(identity(did));
        }
        if let Some(m) = config.messaging.as_ref() {
            out.insert(identity(&m.mediator_did));
        }
        for did in &config.collection.exclude {
            out.insert(identity(did));
        }
    }
    for entry in vti_common::acl::list_acl_entries(&state.acl_ks).await? {
        out.insert(identity(&entry.did));
    }
    for key in state.collection_ks.prefix_keys(PROVISIONED_PREFIX).await? {
        if let Ok(k) = String::from_utf8(key)
            && let Some(did) = k.strip_prefix(PROVISIONED_PREFIX)
        {
            out.insert(did.to_string());
        }
    }
    Ok(out)
}

/// Every identifier VTI-NTF-080 names, in `context` or in every context,
/// ordered by context and then log DID — the order the bound of VTI-NTF-088 is
/// applied in.
pub async fn candidates(
    state: &AppState,
    context: Option<&str>,
) -> Result<Vec<Candidate>, AppError> {
    #[cfg(feature = "webvh")]
    {
        let excluded = excluded(state).await?;
        let is_excluded = |did: &str| excluded.contains(&identity(did));
        let mut out = Vec::new();
        for rec in crate::webvh_store::list_dids(&state.webvh_ks).await? {
            if context.is_some_and(|c| c != rec.context_id) {
                continue;
            }
            // Only the principal's contexts: a record whose context is gone is
            // being cleaned up, not collected for.
            if crate::contexts::get_context(&state.contexts_ks, &rec.context_id)
                .await?
                .is_none()
            {
                continue;
            }
            let scid = crate::webvh_store::get_scid_identity(&state.webvh_ks, &rec.did).await?;
            let identifier = scid
                .as_ref()
                .filter(|s| s.presented)
                .map(|s| s.identity().to_string())
                .unwrap_or_else(|| rec.did.clone());
            if is_excluded(&rec.did)
                || is_excluded(&identifier)
                || scid.as_ref().is_some_and(|s| is_excluded(&s.scid_did))
            {
                continue;
            }
            let Some(log) = crate::webvh_store::get_did_log(&state.webvh_ks, &rec.did).await?
            else {
                continue;
            };
            if log_deactivated(&log) {
                continue;
            }
            let Ok(document) =
                crate::operations::protocol::document::current_document_from_log(&log)
            else {
                continue;
            };
            let Some(mediator_did) = mediator_of(&document) else {
                continue;
            };
            out.push(Candidate {
                context_id: rec.context_id.clone(),
                identifier,
                log_did: rec.did.clone(),
                mediator_did,
                document,
            });
        }
        out.sort_by(|a, b| {
            (a.context_id.as_str(), a.log_did.as_str())
                .cmp(&(b.context_id.as_str(), b.log_did.as_str()))
        });
        Ok(out)
    }
    #[cfg(not(feature = "webvh"))]
    {
        // A build that publishes no `did:webvh` holds no persona to collect for.
        let _ = (excluded(state).await?, context);
        Ok(Vec::new())
    }
}

/// The candidate in `context` that `did` names, in whatever form it is given.
pub async fn find_candidate(
    state: &AppState,
    context: &str,
    did: &str,
) -> Result<Option<Candidate>, AppError> {
    // A did:scid names its log through the identity recorded for it.
    #[cfg(feature = "webvh")]
    let log_did = crate::webvh_store::log_did_for(&state.webvh_ks, did).await?;
    #[cfg(not(feature = "webvh"))]
    let log_did: Option<String> = None;
    Ok(candidates(state, Some(context))
        .await?
        .into_iter()
        .find(|c| c.matches(did) || log_did.as_deref().is_some_and(|l| c.matches(l))))
}

/// Record that `did` was minted for another party, which collects for it
/// itself (VTI-NTF-080 item 2). Called by provision-integration.
pub async fn mark_provisioned(ks: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    ks.insert(provisioned_key(did), &true).await
}

// ── Reading the store ──────────────────────────────────────────────────────

async fn read_all<T: serde::de::DeserializeOwned>(
    ks: &KeyspaceHandle,
    prefix: &str,
) -> Result<Vec<T>, AppError> {
    Ok(ks
        .prefix_iter_raw(prefix.to_string())
        .await?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect())
}

/// Every claim, keyed by log DID identity.
pub async fn all_claims(ks: &KeyspaceHandle) -> Result<HashMap<String, ClaimRecord>, AppError> {
    Ok(read_all::<ClaimRecord>(ks, CLAIM_PREFIX)
        .await?
        .into_iter()
        .map(|c| (identity(&c.log_did), c))
        .collect())
}

/// Every conflict, keyed by log DID identity.
pub async fn all_conflicts(
    ks: &KeyspaceHandle,
) -> Result<HashMap<String, ConflictRecord>, AppError> {
    Ok(read_all::<ConflictRecord>(ks, CONFLICT_PREFIX)
        .await?
        .into_iter()
        .map(|c| (identity(&c.log_did), c))
        .collect())
}

pub async fn get_claim(
    ks: &KeyspaceHandle,
    context: &str,
    log_did: &str,
) -> Result<Option<ClaimRecord>, AppError> {
    ks.get(claim_key(context, log_did)).await
}

pub async fn get_conflict(
    ks: &KeyspaceHandle,
    context: &str,
    log_did: &str,
) -> Result<Option<ConflictRecord>, AppError> {
    ks.get(conflict_key(context, log_did)).await
}

/// Record that the VTA stopped collecting for an identifier because another
/// connection kept closing its own (VTI-NTF-085).
pub async fn record_conflict(ks: &KeyspaceHandle, record: &ConflictRecord) -> Result<(), AppError> {
    ks.insert(conflict_key(&record.context_id, &record.log_did), record)
        .await
}

// ── The plan ───────────────────────────────────────────────────────────────

/// Why nobody collects for an identifier (the shared `NotCollectedReason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotCollected {
    /// At the bound on identifiers collected for (VTI-NTF-088).
    Limit,
    /// Another connection kept closing the VTA's (VTI-NTF-085).
    Conflict,
    /// Collection by default is off (VTI-NTF-093).
    Disabled,
}

impl NotCollected {
    #[must_use]
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Limit => "limit",
            Self::Conflict => "conflict",
            Self::Disabled => "disabled",
        }
    }
}

/// Who collects for one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assignment {
    /// A client, under a claim in force.
    Client(ClaimRecord),
    /// The VTA. Includes the interval after a claim ended and before the VTA's
    /// skew tolerance has passed: nobody else may collect then, and the VTA is
    /// about to.
    Vta {
        /// Whether the VTA may open its connection now.
        open_now: bool,
    },
    /// Nobody, for this reason.
    Nobody(NotCollected),
}

/// The inputs to [`plan`] other than the candidates.
pub struct PlanInputs<'a> {
    pub claims: &'a HashMap<String, ClaimRecord>,
    pub conflicts: &'a HashMap<String, ConflictRecord>,
    pub enabled: bool,
    pub max_identifiers: usize,
    pub skew: Duration,
    pub now: DateTime<Utc>,
}

/// Who collects for each candidate. The bound of VTI-NTF-088 is applied in the
/// candidates' order, over every context together, and counts only what the
/// VTA itself would collect for.
#[must_use]
pub fn plan(candidates: &[Candidate], inputs: &PlanInputs<'_>) -> Vec<Assignment> {
    let mut collected = 0usize;
    candidates
        .iter()
        .map(|c| {
            let key = identity(&c.log_did);
            let claim = inputs
                .claims
                .get(&key)
                .filter(|cl| cl.context_id == c.context_id);
            if let Some(cl) = claim
                && cl.in_force(inputs.now)
            {
                return Assignment::Client(cl.clone());
            }
            if !inputs.enabled {
                return Assignment::Nobody(NotCollected::Disabled);
            }
            if inputs.conflicts.contains_key(&key) {
                return Assignment::Nobody(NotCollected::Conflict);
            }
            if collected >= inputs.max_identifiers {
                return Assignment::Nobody(NotCollected::Limit);
            }
            collected += 1;
            let open_now = claim.is_none_or(|cl| !cl.keeps_vta_off(inputs.now, inputs.skew));
            Assignment::Vta { open_now }
        })
        .collect()
}

/// The plan for every candidate, read from the store and the configuration.
pub async fn current_plan(
    state: &AppState,
    now: DateTime<Utc>,
) -> Result<Vec<(Candidate, Assignment)>, AppError> {
    let candidates = candidates(state, None).await?;
    let claims = all_claims(&state.collection_ks).await?;
    let conflicts = all_conflicts(&state.collection_ks).await?;
    let (max_identifiers, skew) = {
        let config = state.config.read().await;
        (
            config.collection.max_identifiers,
            Duration::seconds(config.collection.clock_skew_secs as i64),
        )
    };
    let assignments = plan(
        &candidates,
        &PlanInputs {
            claims: &claims,
            conflicts: &conflicts,
            enabled: state.collection.enabled(),
            max_identifiers,
            skew,
            now,
        },
    );
    Ok(candidates.into_iter().zip(assignments).collect())
}

// ── Claim, release, list ───────────────────────────────────────────────────

/// A refusal of a claim, release or list.
#[derive(Debug)]
#[non_exhaustive]
pub enum CollectionError {
    /// No standing in the context (VTI-NTF-082, VTI-NTF-091).
    PermissionDenied,
    /// Not an identifier VTI-NTF-080 names in the context.
    NotCollectable,
    /// Another client's claim is in force (VTI-NTF-081).
    ClaimHeld,
    /// The caller's own claim was released by another party (VTI-NTF-084).
    ClaimNotRenewable,
    /// A cursor this VTA did not issue for these filters.
    CursorInvalid,
    App(AppError),
}

impl From<AppError> for CollectionError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

/// A granted claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub identifier: String,
    pub ends_at: DateTime<Utc>,
    pub renewed: bool,
}

/// Whole seconds, so the end the VTA answers with is the end it keeps.
fn whole_seconds(t: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp(t.timestamp(), 0).unwrap_or(t)
}

/// `vta/collection/claim/0.1` (VTI-NTF-082): grant or renew a claim, having
/// stopped collecting for the identifier and closed its connection first.
pub async fn claim(
    state: &AppState,
    auth: &AuthClaims,
    context: &str,
    did: &str,
    duration_seconds: Option<i64>,
    now: DateTime<Utc>,
) -> Result<Grant, CollectionError> {
    if !auth.has_context_access(context) {
        return Err(CollectionError::PermissionDenied);
    }
    let cand = find_candidate(state, context, did)
        .await?
        .ok_or(CollectionError::NotCollectable)?;
    let (stated_max, default) = {
        let config = state.config.read().await;
        (
            config.collection.stated_max_claim_secs(),
            config.collection.default_claim_secs,
        )
    };
    let wanted = duration_seconds
        .and_then(|d| u64::try_from(d).ok())
        .unwrap_or(default);
    let granted = wanted.clamp(60, stated_max);
    let ends_at = whole_seconds(now + Duration::seconds(granted as i64));

    let _guard = state.collection.lock_identifier(&cand.log_did).await;
    let existing = get_claim(&state.collection_ks, context, &cand.log_did).await?;
    let renewed = match existing.as_ref().filter(|c| c.in_force(now)) {
        Some(c) if c.claimant != auth.did => return Err(CollectionError::ClaimHeld),
        Some(c) if c.released_by_other() => return Err(CollectionError::ClaimNotRenewable),
        Some(_) => true,
        None => false,
    };
    let record = ClaimRecord {
        context_id: context.to_string(),
        log_did: cand.log_did.clone(),
        claimant: auth.did.clone(),
        granted_at: existing
            .as_ref()
            .filter(|_| renewed)
            .map_or(now, |c| c.granted_at),
        ends_at,
        released_by: None,
    };
    // The claim first, so the collector's next look sees it; then the
    // connection closed — both under the identifier's lock, so no session can
    // be opened between them — and only then the answer (VTI-NTF-082).
    state
        .collection_ks
        .insert(claim_key(context, &cand.log_did), &record)
        .await?;
    // A claim is how the principal settles a conflict (VTI-NTF-085).
    state
        .collection_ks
        .remove(conflict_key(context, &cand.log_did))
        .await?;
    state.collection.stop(&cand.log_did).await;
    debug_assert!(!state.collection.is_collecting(&cand.log_did));
    Ok(Grant {
        identifier: cand.identifier,
        ends_at,
        renewed,
    })
}

/// The outcome of a release: who held the claim, and when it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Released {
    pub identifier: String,
    /// Absent when no claim was in force.
    pub ends_at: Option<DateTime<Utc>>,
    /// The claimant of the claim released, for the audit trail.
    pub claimant: Option<String>,
}

/// `vta/collection/release/0.1` (VTI-NTF-084).
pub async fn release(
    state: &AppState,
    auth: &AuthClaims,
    context: &str,
    did: &str,
    now: DateTime<Utc>,
) -> Result<Released, CollectionError> {
    if !auth.has_context_access(context) {
        return Err(CollectionError::PermissionDenied);
    }
    let cand = find_candidate(state, context, did)
        .await?
        .ok_or(CollectionError::NotCollectable)?;
    let _guard = state.collection.lock_identifier(&cand.log_did).await;
    let Some(mut record) = get_claim(&state.collection_ks, context, &cand.log_did)
        .await?
        .filter(|c| c.in_force(now))
    else {
        return Ok(Released {
            identifier: cand.identifier,
            ends_at: None,
            claimant: None,
        });
    };
    let ends_at = if record.claimant == auth.did {
        // The claimant stopped collecting before it asked (VTI-NTF-083): the
        // claim ends now and the VTA may resume at once.
        record.ends_at = whole_seconds(now);
        record.released_by = Some(auth.did.clone());
        record.ends_at
    } else {
        // Its claimant is still connected until its own clock says stop, so the
        // claim keeps its end and only stops being renewable.
        if record.released_by.is_none() {
            record.released_by = Some(auth.did.clone());
        }
        record.ends_at
    };
    state
        .collection_ks
        .insert(claim_key(context, &cand.log_did), &record)
        .await?;
    state.collection.kick();
    Ok(Released {
        identifier: cand.identifier,
        ends_at: Some(ends_at),
        claimant: Some(record.claimant),
    })
}

/// One entry of a listing (the shared `CollectionEntry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub identifier: String,
    pub assignment: Assignment,
    /// For a client's claim: whether its claimant may still renew it.
    pub renewable: bool,
}

impl Entry {
    /// The wire `CollectionEntry`: `claim` exactly when `collector` is
    /// `client`, `notCollectedReason` exactly when it is `none`.
    #[must_use]
    pub fn to_wire(&self) -> serde_json::Value {
        use serde_json::json;
        match &self.assignment {
            Assignment::Client(c) => json!({
                "identifier": self.identifier,
                "collector": "client",
                "claim": {
                    "claimant": c.claimant,
                    "endsAt": c.ends_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    "renewable": self.renewable,
                },
            }),
            Assignment::Vta { .. } => json!({
                "identifier": self.identifier,
                "collector": "vta",
            }),
            Assignment::Nobody(r) => json!({
                "identifier": self.identifier,
                "collector": "none",
                "notCollectedReason": r.as_wire(),
            }),
        }
    }

    fn collector(&self) -> &'static str {
        match self.assignment {
            Assignment::Client(_) => "client",
            Assignment::Vta { .. } => "vta",
            Assignment::Nobody(_) => "none",
        }
    }
}

/// Whether `claim`'s claimant may still renew it: not released by another
/// party, and its ACL entry still gives it standing in the context
/// (VTI-NTF-084).
pub async fn renewable(state: &AppState, claim: &ClaimRecord) -> Result<bool, AppError> {
    if claim.released_by_other() {
        return Ok(false);
    }
    let now_unix = u64::try_from(Utc::now().timestamp()).unwrap_or_default();
    Ok(
        vti_common::acl::get_acl_entry(&state.acl_ks, &claim.claimant)
            .await?
            .is_some_and(|e| !e.is_expired(now_unix) && e.can_act_in(&claim.context_id)),
    )
}

/// The filters of a listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListFilter {
    pub identifier: Option<String>,
    pub collector: Option<String>,
}

impl ListFilter {
    fn digest(&self, context: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for part in [
            context,
            self.identifier.as_deref().unwrap_or(""),
            self.collector.as_deref().unwrap_or(""),
        ] {
            h.update(part.as_bytes());
            h.update(b"\0");
        }
        vta_sdk::hex::lower(&h.finalize())[..16].to_string()
    }
}

#[derive(Serialize, Deserialize)]
struct Cursor {
    f: String,
    after: String,
}

/// One page of a listing.
#[derive(Debug)]
pub struct Page {
    pub items: Vec<Entry>,
    pub next_cursor: Option<String>,
}

/// `vta/collection/list/0.1` (VTI-NTF-091): every identifier of `context`
/// VTI-NTF-080 names, whether or not collection by default is enabled, with
/// who collects for it.
pub async fn list(
    state: &AppState,
    auth: &AuthClaims,
    context: &str,
    filter: &ListFilter,
    cursor: Option<&str>,
    limit: Option<usize>,
    now: DateTime<Utc>,
) -> Result<Page, CollectionError> {
    use base64::Engine;
    if !auth.has_context_access(context) {
        return Err(CollectionError::PermissionDenied);
    }
    let fdigest = filter.digest(context);
    let after = match cursor {
        None => None,
        Some(c) => {
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(c)
                .map_err(|_| CollectionError::CursorInvalid)?;
            let cur: Cursor =
                serde_json::from_slice(&bytes).map_err(|_| CollectionError::CursorInvalid)?;
            if cur.f != fdigest {
                return Err(CollectionError::CursorInvalid);
            }
            Some(cur.after)
        }
    };
    let limit = limit.unwrap_or(LIST_DEFAULT_PAGE).clamp(1, LIST_MAX_PAGE);
    let mut items = Vec::new();
    for (cand, assignment) in current_plan(state, now).await? {
        if cand.context_id != context {
            continue;
        }
        if filter
            .identifier
            .as_deref()
            .is_some_and(|d| !cand.matches(d))
        {
            continue;
        }
        if after.as_deref().is_some_and(|a| cand.log_did.as_str() <= a) {
            continue;
        }
        let renewable = match &assignment {
            Assignment::Client(c) => renewable(state, c).await?,
            _ => false,
        };
        let entry = Entry {
            identifier: cand.identifier.clone(),
            assignment,
            renewable,
        };
        if filter
            .collector
            .as_deref()
            .is_some_and(|c| c != entry.collector())
        {
            continue;
        }
        items.push((cand.log_did, entry));
        if items.len() > limit {
            break;
        }
    }
    let more = items.len() > limit;
    items.truncate(limit);
    let next_cursor = more.then(|| items.last()).flatten().map(|(log_did, _)| {
        let cur = Cursor {
            f: fdigest.clone(),
            after: log_did.clone(),
        };
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&cur).unwrap_or_default())
    });
    Ok(Page {
        items: items.into_iter().map(|(_, e)| e).collect(),
        next_cursor,
    })
}

// ── Lifecycle ──────────────────────────────────────────────────────────────

/// Remove every claim and conflict of `context` (a context deletion,
/// VTI-NTF-090). Returns how many records went.
pub async fn purge_context(ks: &KeyspaceHandle, context: &str) -> Result<usize, AppError> {
    let mut n = 0;
    for prefix in [CLAIM_PREFIX, CONFLICT_PREFIX] {
        for key in ks.prefix_keys(format!("{prefix}{context}\0")).await? {
            ks.remove(key).await?;
            n += 1;
        }
    }
    Ok(n)
}

/// Carry every claim held by `from` to `to`: a rollover of the claimant's entry
/// or a rotation of its key (VTI-NTF-084). Returns how many moved.
pub async fn carry_claims(ks: &KeyspaceHandle, from: &str, to: &str) -> Result<usize, AppError> {
    if from == to {
        return Ok(0);
    }
    let mut n = 0;
    for (key, value) in ks.prefix_iter_raw(CLAIM_PREFIX.to_string()).await? {
        let Ok(mut claim) = serde_json::from_slice::<ClaimRecord>(&value) else {
            continue;
        };
        if claim.claimant != from {
            continue;
        }
        claim.claimant = to.to_string();
        if claim.released_by.as_deref() == Some(from) {
            claim.released_by = Some(to.to_string());
        }
        ks.insert(key, &claim).await?;
        n += 1;
    }
    Ok(n)
}

/// Remove claims that no longer keep the VTA off their identifier, and claims
/// and conflicts on identifiers that are no longer candidates — keys gone, the
/// identifier deactivated, its context deleted — which are not in force
/// (VTI-NTF-090). Returns how many records went.
pub async fn sweep(
    state: &AppState,
    candidates: &[Candidate],
    now: DateTime<Utc>,
) -> Result<usize, AppError> {
    let skew = Duration::seconds(state.config.read().await.collection.clock_skew_secs as i64);
    let live: HashSet<(String, String)> = candidates
        .iter()
        .map(|c| (c.context_id.clone(), identity(&c.log_did)))
        .collect();
    let mut n = 0;
    for (key, value) in state
        .collection_ks
        .prefix_iter_raw(CLAIM_PREFIX.to_string())
        .await?
    {
        let Ok(c) = serde_json::from_slice::<ClaimRecord>(&value) else {
            continue;
        };
        let gone = !live.contains(&(c.context_id.clone(), identity(&c.log_did)));
        if gone || !c.keeps_vta_off(now, skew) {
            state.collection_ks.remove(key).await?;
            n += 1;
        }
    }
    for (key, value) in state
        .collection_ks
        .prefix_iter_raw(CONFLICT_PREFIX.to_string())
        .await?
    {
        let Ok(c) = serde_json::from_slice::<ConflictRecord>(&value) else {
            continue;
        };
        if !live.contains(&(c.context_id.clone(), identity(&c.log_did))) {
            state.collection_ks.remove(key).await?;
            n += 1;
        }
    }
    Ok(n)
}

/// Audit a change of the "collection by default" setting, once, at the boot
/// that applies it (VTI-NTF-093). The first boot audits only an enabled
/// setting: off is where every VTA starts.
pub async fn record_setting(state: &AppState) -> Result<(), AppError> {
    let enabled = state.collection.enabled();
    let previous: Option<bool> = state.collection_ks.get(SETTING_KEY).await?;
    if previous == Some(enabled) || (previous.is_none() && !enabled) {
        if previous.is_none() {
            state.collection_ks.insert(SETTING_KEY, &enabled).await?;
        }
        return Ok(());
    }
    let action = if enabled {
        "collection.enabled"
    } else {
        "collection.disabled"
    };
    vta_audit::record_with_detail_best_effort(
        &state.audit_sink,
        action,
        "operator:config",
        None,
        "success",
        Some("config"),
        None,
        Some(if enabled {
            "collection by default enabled: the VTA collects for every unclaimed persona"
        } else {
            "collection by default disabled: the VTA collects for no unclaimed persona"
        }),
    )
    .await;
    tracing::info!(enabled, "collection by default changed (VTI-NTF-093)");
    state.collection_ks.insert(SETTING_KEY, &enabled).await
}

// ── Keys to collect with ───────────────────────────────────────────────────

/// One secret of a collected identifier: the id it is registered under, the
/// key's type, and its private half.
pub struct CollectionSecret {
    pub id: String,
    pub secret: affinidi_tdk::secrets_resolver::secrets::Secret,
}

impl std::fmt::Debug for CollectionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectionSecret")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The ids a secret is registered under: the method id the document gives it
/// and, where the identifier is presented as a `did:scid` DID URL, the same
/// fragment under that form (VTI-KEY-161, VTI-KEY-163).
fn secret_ids(cand: &Candidate, vm_id: &str) -> Vec<String> {
    let mut ids = vec![vm_id.to_string()];
    if let Some((_, fragment)) = vm_id.split_once('#') {
        for form in [
            vta_sdk::did_scid::strip_src(&cand.identifier).to_string(),
            cand.identifier.clone(),
        ] {
            let id = format!("{form}#{fragment}");
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    ids
}

/// The messaging secrets of `cand`, for the collector — loaded under internal
/// authority, because collecting is the VTA using a key it holds for its
/// principal, inside the boundary that holds it (VTI-NTF-089), and every load
/// is audited as `key.internal_use`. Also the id of the key the VTA signs its
/// replies with as the identifier: the first Ed25519 `authentication` (or
/// `assertionMethod`) method.
pub async fn collection_secrets(
    state: &AppState,
    cand: &Candidate,
) -> Result<(Vec<CollectionSecret>, Option<String>), AppError> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    let methods = cand.document["verificationMethod"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let absolute = |id: &str| {
        if id.starts_with('#') {
            format!("{}{id}", cand.log_did)
        } else {
            id.to_string()
        }
    };
    let mut out = Vec::new();
    let mut loaded: HashSet<String> = HashSet::new();
    for vm in &methods {
        let Some(vm_id) = vm["id"].as_str().map(absolute) else {
            continue;
        };
        let record: Option<vta_sdk::keys::KeyRecord> =
            state.keys_ks.get(crate::keys::store_key(&vm_id)).await?;
        let Some(record) = record else {
            continue;
        };
        // Only the identifier's own context's keys: the record must be where
        // the identifier is.
        if record.context_id.as_deref() != Some(cand.context_id.as_str()) {
            continue;
        }
        let secret = match super::keys::get_key_secret_internal(
            &state.keys_ks,
            &state.imported_ks,
            &state.contexts_ks,
            &*state.seed_store,
            &state.audit_sink,
            super::internal_authority::InternalAuthority::new("collection"),
            &vm_id,
            "collection",
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(identifier = %cand.identifier, key = %vm_id, error = %e,
                    "a key of a collected identifier could not be loaded; collecting without it");
                continue;
            }
        };
        for id in secret_ids(cand, &vm_id) {
            match Secret::from_multibase(&secret.private_key_multibase, Some(&id)) {
                Ok(s) => out.push(CollectionSecret {
                    id: id.clone(),
                    secret: s,
                }),
                Err(e) => {
                    tracing::warn!(key = %vm_id, error = %e, "a collected identifier's key did not parse");
                }
            }
        }
        loaded.insert(vm_id);
    }
    let reference = |v: &serde_json::Value| -> Option<String> {
        v.as_str()
            .map(absolute)
            .or_else(|| v["id"].as_str().map(absolute))
    };
    let signing = ["authentication", "assertionMethod"]
        .iter()
        .flat_map(|rel| {
            cand.document[*rel]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| reference(&v))
                .collect::<Vec<_>>()
        })
        .find(|id| loaded.contains(id));
    Ok((out, signing))
}

#[cfg(test)]
#[path = "collection_tests.rs"]
pub(crate) mod tests;
