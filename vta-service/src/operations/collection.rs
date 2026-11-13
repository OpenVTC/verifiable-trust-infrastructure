//! **Collection** of the principal's identifiers (VTI-NTF-080 – 098,
//! `vta/collection/{claim,release,list}/0.1`,
//! `vta/collection/settings/{show,set}/0.1`).
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
//!   candidates, the claims, the conflicts, each context's setting, the
//!   operator's suspension and the bound, so the listing and the collector can
//!   never disagree about who collects.
//! - Each context's setting ([`ContextSetting`], [`show_setting`],
//!   [`set_setting`]) and the operator's suspension ([`record_suspension`]).
//! - [`CollectionControl`]: the handle the claim path and the collector share.
//!   A grant stops collection **under the identifier's lock** before it is
//!   answered (VTI-NTF-082), and the collector re-reads the claim under the
//!   same lock before it opens a connection, so no interleaving leaves both a
//!   claim in force and a connection of the VTA's own.
//!
//! The connections themselves are `crate::messaging::collector`'s.
//!
//! # The setting (VTI-NTF-094 – 098)
//!
//! Collection by default is a **stored setting of each trust context**,
//! enabled for a context unless a party with administrative authority over it
//! (VTI-ACL-022) has disabled it there (VTI-NTF-094, VTI-NTF-095). A context
//! with no record is enabled; the setting is not inherited by descendants.
//! [`set_setting`] applies a change before it answers: disabling writes the
//! record and then closes every connection the VTA holds for the context's
//! identifiers, each under the identifier's lock (the collector re-reads the
//! setting under the same lock before it opens one); enabling clears the
//! context's conflicts (VTI-NTF-085) and asks the collector to begin. While
//! disabled the VTA collects for nothing unclaimed there, and still grants,
//! renews, releases and lists claims (VTI-NTF-097).
//!
//! The operator keeps one off-only switch, `[collection] suspend`
//! (VTI-NTF-098): while it is in force every context is treated as disabled,
//! and no context's setting changes. It is read at boot and audited by
//! [`record_suspension`] at the boot that engages or lifts it.
//!
//! # Store layout ([`crate::keyspaces::COLLECTION`])
//!
//! - `claim:<contextId>\0<logDid>` → [`ClaimRecord`]
//! - `conflict:<contextId>\0<logDid>` → [`ConflictRecord`]
//! - `context-setting:<contextId>` → [`ContextSetting`], once the context's
//!   setting has been changed; absent means enabled (VTI-NTF-094)
//! - `provisioned:<did>` → `true`
//! - `suspension` → the operator's suspension as last applied at boot
//! - `backfill:provisioned` → [`BackfillRecord`], once [`backfill_provisioned`]
//!   has run
//!
//! The retired `setting` row (the last applied value of VTI-NTF-093's
//! `collect_by_default`) is removed at boot.

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
const CONTEXT_SETTING_PREFIX: &str = "context-setting:";
const SUSPENSION_KEY: &str = "suspension";
const BACKFILL_KEY: &str = "backfill:provisioned";
/// The row VTI-NTF-093's operator setting was recorded under; retired.
const RETIRED_SETTING_KEY: &str = "setting";

fn claim_key(context: &str, log_did: &str) -> String {
    format!("{CLAIM_PREFIX}{context}\0{log_did}")
}

fn conflict_key(context: &str, log_did: &str) -> String {
    format!("{CONFLICT_PREFIX}{context}\0{log_did}")
}

fn context_setting_key(context: &str) -> String {
    format!("{CONTEXT_SETTING_PREFIX}{context}")
}

/// The lock key a context's setting changes are serialised under. Disjoint from
/// every identifier's key: a DID's identity never starts with a NUL.
fn setting_lock_key(context: &str) -> String {
    format!("\0setting\0{context}")
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
/// has ended; and cleared when collection by default is enabled for its context
/// (VTI-NTF-095) or the operator's suspension is lifted (VTI-NTF-098).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictRecord {
    pub context_id: String,
    pub log_did: String,
    pub since: DateTime<Utc>,
    /// How many times another connection closed the VTA's before it stopped.
    pub closures: u32,
}

/// A trust context's collection-by-default setting, as stored once a party with
/// administrative authority over the context has changed it (VTI-NTF-094 –
/// 096). A context with no record is enabled and has never been changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextSetting {
    pub context_id: String,
    pub collect_by_default: bool,
    /// The subject of the ACL entry that last changed it.
    pub changed_by: String,
    pub changed_at: DateTime<Utc>,
}

/// What [`backfill_provisioned`] did, kept so it runs once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackfillRecord {
    pub ran_at: DateTime<Utc>,
    /// The identifiers it recorded as provisioned for another party.
    pub recorded: Vec<String>,
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
        h.update(
            serde_json_canonicalizer::to_vec(&self.document["verificationMethod"])
                .unwrap_or_default(),
        );
        h.update(b"\0");
        h.update(
            serde_json_canonicalizer::to_vec(&self.document["keyAgreement"]).unwrap_or_default(),
        );
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
    suspended: AtomicBool,
    locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    sessions: std::sync::Mutex<HashMap<String, Arc<dyn CollectingSession>>>,
    kick: tokio::sync::Notify,
    /// The candidate set as last built, and what it was built from (#2628).
    candidates: std::sync::Mutex<Option<CachedCandidates>>,
    /// How many times the candidate set was built — for tests.
    #[cfg(test)]
    pub(crate) candidate_builds: std::sync::atomic::AtomicUsize,
}

/// A built candidate set, valid while nothing it was read from has changed:
/// the store keyspaces under their write tickets
/// ([`KeyspaceHandle::cache_ticket`]) and the configuration it reads.
struct CachedCandidates {
    key: CandidateInputs,
    candidates: Arc<Vec<Candidate>>,
}

/// What [`candidates`] reads: the write tickets of the webvh, ACL, contexts
/// and collection keyspaces, and the configured identities it excludes.
#[derive(PartialEq, Eq)]
struct CandidateInputs {
    tickets: [u64; 4],
    vta_did: Option<String>,
    mediator_did: Option<String>,
    exclude: Vec<String>,
}

impl std::fmt::Debug for CollectionControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectionControl")
            .field("suspended", &self.suspended())
            .field("collecting", &self.collecting().len())
            .finish()
    }
}

impl CollectionControl {
    /// `suspended` is the operator's suspension as read at boot
    /// (`[collection] suspend`, VTI-NTF-098).
    #[must_use]
    pub fn new(suspended: bool) -> Self {
        Self {
            suspended: AtomicBool::new(suspended),
            locks: std::sync::Mutex::new(HashMap::new()),
            sessions: std::sync::Mutex::new(HashMap::new()),
            kick: tokio::sync::Notify::new(),
            candidates: std::sync::Mutex::new(None),
            #[cfg(test)]
            candidate_builds: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Whether the operator's suspension of collection by default is in force
    /// (VTI-NTF-098). Fixed at boot: there is no run-time way to lift it, and
    /// nothing anywhere enables collection for a context whose setting
    /// disables it.
    #[must_use]
    pub fn suspended(&self) -> bool {
        self.suspended.load(Ordering::SeqCst)
    }

    /// Change the suspension for this process — tests only; an operator
    /// changes it in configuration, read at boot.
    #[cfg(test)]
    pub(crate) fn set_suspended(&self, suspended: bool) {
        self.suspended.store(suspended, Ordering::SeqCst);
        self.kick();
    }

    /// The lock a change of `context`'s setting is made under, so two changes
    /// of one context apply in the order they are recorded.
    pub async fn lock_setting(&self, context: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(
                locks
                    .entry(setting_lock_key(context))
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        lock.lock_owned().await
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

    /// Stop every session (shutdown).
    pub async fn stop_all(&self) {
        for did in self.collecting() {
            let _guard = self.lock_identifier(&did).await;
            self.stop(&did).await;
        }
    }

    /// Ask the collector to reconcile now rather than on its next tick, and
    /// rebuild the candidate set when it does.
    pub fn kick(&self) {
        self.forget_candidates();
        self.kick.notify_one();
    }

    fn forget_candidates(&self) {
        *self.candidates.lock().unwrap_or_else(|e| e.into_inner()) = None;
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

/// What the candidate set is built from, as it stands now; `None` while a
/// write to any of its keyspaces is in flight (nothing may be cached then).
async fn candidate_inputs(state: &AppState) -> Option<CandidateInputs> {
    let tickets = [
        state.webvh_ks.cache_ticket()?,
        state.acl_ks.cache_ticket()?,
        state.contexts_ks.cache_ticket()?,
        state.collection_ks.cache_ticket()?,
    ];
    let config = state.config.read().await;
    Some(CandidateInputs {
        tickets,
        vta_did: config.vta_did.clone(),
        mediator_did: config.messaging.as_ref().map(|m| m.mediator_did.clone()),
        exclude: config.collection.exclude.clone(),
    })
}

/// [`candidates`] in every context, rebuilt only when something it reads has
/// changed or the collector was kicked (#2628).
///
/// The build walks every ACL entry and every `did:webvh` record and reads each
/// one's whole log; the collector asked for it every 30 seconds, with nothing to
/// collect as readily as with something. The set is kept under the write
/// tickets of the keyspaces it reads and the configuration it reads, so a DID
/// created or deactivated, an ACL change, a context removed, a provisioned
/// mark or a claim is seen on the next pass exactly as before, and a quiet
/// store costs one comparison.
pub async fn cached_candidates(state: &AppState) -> Result<Arc<Vec<Candidate>>, AppError> {
    let before = candidate_inputs(state).await;
    if let Some(key) = &before
        && let Some(hit) = state
            .collection
            .candidates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .filter(|c| c.key == *key)
    {
        return Ok(Arc::clone(&hit.candidates));
    }
    #[cfg(test)]
    state
        .collection
        .candidate_builds
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let built = Arc::new(candidates(state, None).await?);
    // Kept only if nothing was written while it was being built.
    if let Some(key) = before
        && candidate_inputs(state).await.is_some_and(|now| now == key)
    {
        *state
            .collection
            .candidates
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(CachedCandidates {
            key,
            candidates: Arc::clone(&built),
        });
    }
    Ok(built)
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
    Ok(cached_candidates(state)
        .await?
        .iter()
        .find(|c| {
            c.context_id == context
                && (c.matches(did) || log_did.as_deref().is_some_and(|l| c.matches(l)))
        })
        .cloned())
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
    /// Collection by default is disabled for the identifier's context, or the
    /// operator has suspended it everywhere (VTI-NTF-097, VTI-NTF-098).
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
    /// The contexts whose setting disables collection by default
    /// (VTI-NTF-094); every other context is enabled.
    pub disabled_contexts: &'a HashSet<String>,
    /// The operator's suspension (VTI-NTF-098): every context disabled.
    pub suspended: bool,
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
            if inputs.suspended || inputs.disabled_contexts.contains(&c.context_id) {
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
    let candidates = cached_candidates(state).await?;
    let claims = all_claims(&state.collection_ks).await?;
    let conflicts = all_conflicts(&state.collection_ks).await?;
    let disabled_contexts = disabled_contexts(&state.collection_ks).await?;
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
            disabled_contexts: &disabled_contexts,
            suspended: state.collection.suspended(),
            max_identifiers,
            skew,
            now,
        },
    );
    Ok(candidates.iter().cloned().zip(assignments).collect())
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
/// VTI-NTF-080 names, whether or not collection by default is enabled for it,
/// with who collects for it.
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
/// VTI-NTF-090), and its setting, so a context created again under the same id
/// starts enabled (VTI-NTF-094). Returns how many records went.
pub async fn purge_context(ks: &KeyspaceHandle, context: &str) -> Result<usize, AppError> {
    let mut n = 0;
    if ks.get_raw(context_setting_key(context)).await?.is_some() {
        ks.remove(context_setting_key(context)).await?;
        n += 1;
    }
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

// ── The setting of each context (VTI-NTF-094 – 097) ───────────────────────

/// `context`'s stored setting, or `None` while it has never been changed — and
/// so is enabled (VTI-NTF-094).
pub async fn get_setting(
    ks: &KeyspaceHandle,
    context: &str,
) -> Result<Option<ContextSetting>, AppError> {
    ks.get(context_setting_key(context)).await
}

/// Whether collection by default is enabled for `context` by its own setting —
/// not its ancestors' or descendants' (VTI-NTF-094). The operator's suspension
/// is separate: [`CollectionControl::suspended`].
pub async fn context_collects_by_default(
    ks: &KeyspaceHandle,
    context: &str,
) -> Result<bool, AppError> {
    Ok(get_setting(ks, context)
        .await?
        .is_none_or(|s| s.collect_by_default))
}

/// Every context whose setting disables collection by default.
pub async fn disabled_contexts(ks: &KeyspaceHandle) -> Result<HashSet<String>, AppError> {
    Ok(read_all::<ContextSetting>(ks, CONTEXT_SETTING_PREFIX)
        .await?
        .into_iter()
        .filter(|s| !s.collect_by_default)
        .map(|s| s.context_id)
        .collect())
}

/// A context's setting as `vta/collection/settings/{show,set}/0.1` answer it
/// (the shared `CollectionSetting`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingView {
    pub context_id: String,
    pub collect_by_default: bool,
    pub suspended_by_operator: bool,
    /// Who last changed it and when; `None` while it never has been.
    pub changed: Option<(String, DateTime<Utc>)>,
}

impl SettingView {
    fn of(context: &str, record: Option<&ContextSetting>, suspended: bool) -> Self {
        Self {
            context_id: context.to_string(),
            collect_by_default: record.is_none_or(|r| r.collect_by_default),
            suspended_by_operator: suspended,
            changed: record.map(|r| (r.changed_by.clone(), r.changed_at)),
        }
    }

    /// The wire `CollectionSetting`: `changedBy` and `changedAt` together, or
    /// neither.
    #[must_use]
    pub fn to_wire(&self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "contextId": self.context_id,
            "collectByDefault": self.collect_by_default,
            "suspendedByOperator": self.suspended_by_operator,
        });
        if let Some((by, at)) = &self.changed {
            v["changedBy"] = serde_json::json!(by);
            v["changedAt"] =
                serde_json::json!(at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        }
        v
    }
}

/// The outcome of [`set_setting`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingChange {
    pub setting: SettingView,
    /// False when the context already held the value asked for (VTI-NTF-095).
    pub changed: bool,
    /// For a change that disabled it: how many connections were closed first.
    pub closed: usize,
    /// For a change that enabled it: how many conflicts it cleared.
    pub conflicts_cleared: usize,
}

async fn require_context_exists(state: &AppState, context: &str) -> Result<(), CollectionError> {
    if crate::contexts::get_context(&state.contexts_ks, context)
        .await?
        .is_none()
    {
        return Err(CollectionError::App(AppError::NotFound(format!(
            "context not found: {context}"
        ))));
    }
    Ok(())
}

/// `vta/collection/settings/show/0.1` (VTI-NTF-096): `context`'s setting, who
/// last changed it and when, and whether the operator's suspension is in force.
/// Needs standing in the context (an act scope covering it).
pub async fn show_setting(
    state: &AppState,
    auth: &AuthClaims,
    context: &str,
) -> Result<SettingView, CollectionError> {
    if !auth.has_context_access(context) {
        return Err(CollectionError::PermissionDenied);
    }
    require_context_exists(state, context).await?;
    let record = get_setting(&state.collection_ks, context).await?;
    Ok(SettingView::of(
        context,
        record.as_ref(),
        state.collection.suspended(),
    ))
}

/// Administrative authority over `context` (VTI-ACL-022, VTI-NTF-095): an
/// administrative role whose act scope covers it — a context administrator of
/// it or of an ancestor, or a super-administrator. Standing alone is not.
fn administers(auth: &AuthClaims, context: &str) -> bool {
    auth.role == crate::acl::Role::Admin && auth.has_context_access(context)
}

/// `vta/collection/settings/set/0.1` (VTI-NTF-095, VTI-NTF-096): change
/// `context`'s setting, applying it before this returns.
///
/// - Disabling: the record first, so the collector's re-read under each
///   identifier's lock sees it, then every connection the VTA holds for the
///   context's identifiers closed, each under its identifier's lock.
/// - Enabling: the record, the context's conflicts cleared (VTI-NTF-085 is
///   settled by the principal's decision to collect), and the collector asked
///   to begin. It does not wait for connections to open (Consumer item 4).
/// - The value already held: nothing changes and `changed` is false.
///
/// The change is recorded in the audit trail **before** it is applied, and
/// refused if it cannot be: an unrecorded change is not permitted
/// (VTI-NTF-096). A change made while the operator's suspension is in force is
/// stored and answered, and collects nothing until it is lifted (Consumer
/// item 7).
pub async fn set_setting(
    state: &AppState,
    auth: &AuthClaims,
    context: &str,
    collect_by_default: bool,
    now: DateTime<Utc>,
) -> Result<SettingChange, CollectionError> {
    if !administers(auth, context) {
        return Err(CollectionError::PermissionDenied);
    }
    require_context_exists(state, context).await?;
    let suspended = state.collection.suspended();
    let _setting_guard = state.collection.lock_setting(context).await;
    let previous = get_setting(&state.collection_ks, context).await?;
    if previous.as_ref().is_none_or(|r| r.collect_by_default) == collect_by_default {
        return Ok(SettingChange {
            setting: SettingView::of(context, previous.as_ref(), suspended),
            changed: false,
            closed: 0,
            conflicts_cleared: 0,
        });
    }
    let record = ContextSetting {
        context_id: context.to_string(),
        collect_by_default,
        changed_by: auth.did.clone(),
        changed_at: whole_seconds(now),
    };
    vta_audit::record_with_detail(
        &state.audit_sink,
        if collect_by_default {
            "collection.setting.enabled"
        } else {
            "collection.setting.disabled"
        },
        &auth.did,
        None,
        "success",
        Some("trust-task"),
        Some(context),
        Some(&format!(
            "collection by default {} for context {context}{}",
            if collect_by_default {
                "enabled"
            } else {
                "disabled"
            },
            if suspended {
                "; the operator's suspension is in force, so nothing is collected until it is lifted"
            } else {
                ""
            }
        )),
    )
    .await
    .map_err(|e| {
        CollectionError::App(AppError::Internal(format!(
            "the change was not made: it could not be recorded in the audit trail, and an \
             unrecorded change is not permitted (VTI-NTF-096): {e}"
        )))
    })?;
    state
        .collection_ks
        .insert(context_setting_key(context), &record)
        .await?;

    let mut closed = 0;
    let mut conflicts_cleared = 0;
    if collect_by_default {
        conflicts_cleared = clear_conflicts(&state.collection_ks, context).await?;
        state.collection.kick();
    } else {
        // Every identifier of the context, whatever the plan said about it: a
        // session may be held for one the plan has since moved elsewhere.
        for cand in candidates(state, Some(context)).await? {
            let _guard = state.collection.lock_identifier(&cand.log_did).await;
            if state.collection.is_collecting(&cand.log_did) {
                state.collection.stop(&cand.log_did).await;
                closed += 1;
            }
            debug_assert!(!state.collection.is_collecting(&cand.log_did));
        }
        state.collection.kick();
    }
    tracing::info!(
        context,
        collect_by_default,
        changed_by = %auth.did,
        closed,
        conflicts_cleared,
        "collection by default changed for a context (VTI-NTF-095)"
    );
    Ok(SettingChange {
        setting: SettingView::of(context, Some(&record), suspended),
        changed: true,
        closed,
        conflicts_cleared,
    })
}

/// Remove `context`'s conflict records (VTI-NTF-085), so the VTA tries those
/// identifiers again. Returns how many went.
async fn clear_conflicts(ks: &KeyspaceHandle, context: &str) -> Result<usize, AppError> {
    let mut n = 0;
    for key in ks
        .prefix_keys(format!("{CONFLICT_PREFIX}{context}\0"))
        .await?
    {
        ks.remove(key).await?;
        n += 1;
    }
    Ok(n)
}

// ── The operator's suspension (VTI-NTF-098) ───────────────────────────────

/// Audit the operator's suspension once, at the boot that engages or lifts it
/// (VTI-NTF-098), and remove the retired VTI-NTF-093 row. A first boot audits
/// only a suspension: not suspended is where every VTA starts. Lifting it
/// resumes collection as a change that enables it does — the conflicts of every
/// context whose setting enables it are cleared — and changes no context's
/// setting.
pub async fn record_suspension(state: &AppState) -> Result<(), AppError> {
    if state
        .collection_ks
        .get_raw(RETIRED_SETTING_KEY)
        .await?
        .is_some()
    {
        state.collection_ks.remove(RETIRED_SETTING_KEY).await?;
    }
    let suspended = state.collection.suspended();
    let previous: Option<bool> = state.collection_ks.get(SUSPENSION_KEY).await?;
    if previous.unwrap_or(false) == suspended {
        if previous.is_none() {
            state
                .collection_ks
                .insert(SUSPENSION_KEY, &suspended)
                .await?;
        }
        return Ok(());
    }
    let mut cleared = 0;
    if !suspended {
        let disabled = disabled_contexts(&state.collection_ks).await?;
        for (key, value) in state
            .collection_ks
            .prefix_iter_raw(CONFLICT_PREFIX.to_string())
            .await?
        {
            let Ok(c) = serde_json::from_slice::<ConflictRecord>(&value) else {
                continue;
            };
            if !disabled.contains(&c.context_id) {
                state.collection_ks.remove(key).await?;
                cleared += 1;
            }
        }
    }
    vta_audit::record_with_detail(
        &state.audit_sink,
        if suspended {
            "collection.suspended"
        } else {
            "collection.suspension_lifted"
        },
        "operator:config",
        None,
        "success",
        Some("config"),
        None,
        Some(if suspended {
            "the operator suspended collection by default: the VTA collects for no unclaimed \
             persona in any context, and no context's setting is changed"
        } else {
            "the operator lifted the suspension of collection by default: each context's own \
             setting applies again"
        }),
    )
    .await?;
    tracing::info!(
        suspended,
        conflicts_cleared = cleared,
        "the operator's suspension of collection by default changed (VTI-NTF-098)"
    );
    state.collection_ks.insert(SUSPENSION_KEY, &suspended).await
}

// ── Upgrade: integrations provisioned before `provisioned:` existed ───────

/// Whether a key record's label is the one `provision/integration` gives the
/// keys of a `did:webvh` it mints for another party: the holder's `did:key`,
/// then ` signing key` or ` key-agreement key` (`did_webvh::create_did_webvh`
/// with `label: Some(client_did)`).
fn provisioned_key_label(label: &str) -> bool {
    [" signing key", " key-agreement key"].iter().any(|suffix| {
        label.strip_suffix(suffix).is_some_and(|holder| {
            holder.starts_with("did:key:z") && !holder.contains(char::is_whitespace)
        })
    })
}

/// Record as provisioned for another party (VTI-NTF-080 item 2) every
/// `did:webvh` this VTA holds that its own records show `provision/integration`
/// minted before it began recording that — so that collection, enabled by
/// default (VTI-NTF-094), never becomes the second connection to an
/// integration's DID. Runs once: a `backfill:provisioned` row marks it done,
/// and a second call changes nothing. The evidence, either of which suffices:
///
/// - a `key.secret_export` audit row on the `provision-integration` channel —
///   the export of one of the DID's keys into a provisioning bundle;
/// - a key record of the DID labelled as provisioning labels them (the
///   holder's `did:key` and the key's role).
///
/// An identifier neither shows (audit rows pruned, an external audit sink, a
/// key relabelled) stays a candidate; `[collection] exclude` is the operator's
/// remedy, and `docs/02-vta/collection.md` says so. The VTA's own DID is never
/// recorded.
pub async fn backfill_provisioned(state: &AppState) -> Result<Option<BackfillRecord>, AppError> {
    if state.collection_ks.get_raw(BACKFILL_KEY).await?.is_some() {
        return Ok(None);
    }
    let own = state.config.read().await.vta_did.as_deref().map(identity);
    let mut found: Vec<(String, &'static str)> = Vec::new();

    let mut exported: HashSet<String> = HashSet::new();
    for row in crate::operations::audit::successful_rows_on_channel(
        &state.audit_ks,
        "key.secret_export",
        "provision-integration",
    )
    .await?
    {
        if let Some(key_id) = row.resource.as_deref() {
            let did = key_id.split('#').next().unwrap_or(key_id);
            if did.starts_with("did:") {
                exported.insert(identity(did));
            }
        }
    }

    #[cfg(feature = "webvh")]
    for rec in crate::webvh_store::list_dids(&state.webvh_ks).await? {
        let did = identity(&rec.did);
        if own.as_deref() == Some(did.as_str()) {
            continue;
        }
        if exported.contains(&did) {
            found.push((rec.did.clone(), "audit"));
            continue;
        }
        let Some(log) = crate::webvh_store::get_did_log(&state.webvh_ks, &rec.did).await? else {
            continue;
        };
        let Ok(document) = crate::operations::protocol::document::current_document_from_log(&log)
        else {
            continue;
        };
        let mut labelled = false;
        for vm in document["verificationMethod"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let Some(id) = vm["id"].as_str() else {
                continue;
            };
            let vm_id = if id.starts_with('#') {
                format!("{}{id}", rec.did)
            } else {
                id.to_string()
            };
            let record: Option<vta_sdk::keys::KeyRecord> =
                state.keys_ks.get(crate::keys::store_key(&vm_id)).await?;
            if record
                .and_then(|r| r.label)
                .is_some_and(|l| provisioned_key_label(&l))
            {
                labelled = true;
                break;
            }
        }
        if labelled {
            found.push((rec.did.clone(), "key-label"));
        }
    }
    #[cfg(not(feature = "webvh"))]
    let _ = (&own, &exported);

    let mut recorded = Vec::new();
    for (did, evidence) in found {
        if state
            .collection_ks
            .get_raw(provisioned_key(&did))
            .await?
            .is_some()
        {
            continue;
        }
        mark_provisioned(&state.collection_ks, &did).await?;
        tracing::info!(identifier = %did, evidence,
            "recorded an identifier provision-integration minted before this release as \
             provisioned for another party; the VTA does not collect for it (VTI-NTF-080)");
        recorded.push(did);
    }
    let record = BackfillRecord {
        ran_at: whole_seconds(Utc::now()),
        recorded,
    };
    vta_audit::record_with_detail_best_effort(
        &state.audit_sink,
        "collection.provisioned_backfilled",
        "operator:upgrade",
        None,
        "success",
        Some("boot"),
        None,
        Some(&format!(
            "recorded {} identifier(s) provision-integration minted before this release as \
             provisioned for another party{}{}",
            record.recorded.len(),
            if record.recorded.is_empty() { "" } else { ": " },
            record.recorded.join(", ")
        )),
    )
    .await;
    state.collection_ks.insert(BACKFILL_KEY, &record).await?;
    Ok(Some(record))
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
