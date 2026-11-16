//! Witnessing: `witness/session/0.2` and `witness/session/submit/0.2`
//! (design note §3.2–§3.4).
//!
//! Only 0.2 is served. The versions pair one to one (`witness/session/0.2`,
//! *how the versions pair*): a session opened at 0.2 declares
//! `submit/0.2#response` as its outcome evidence, so a submission is taken only
//! on a session whose stored document is a `witness/session/0.2` — anything
//! else is `challengeMismatch`.
//!
//! # `witness/session/0.2`
//!
//! Cheap checks only, then a session (§3.3):
//!
//! 1. the session document names its own thread (`threadId` = `id`, party
//!    conformance item 1) — else `malformedRequest`, because no VWC could ever
//!    cite it;
//! 2. the opener (the transport-proven issuer) is one of `parties`, and the two
//!    parties differ (witness conformance item 2);
//! 3. **independence** (§3.2): neither party is one of this service's own
//!    witness DIDs, the operator's VTA, or an excluded DID;
//! 4. the identity witnesses somebody (`communities` is not empty), and the
//!    optional allow-list admits the opener;
//! 5. the caps: open sessions per opener, and at this identity. An identity
//!    with no allow-list makes room at its cap by closing a surplus session of
//!    an opener holding several, or else one older than a minute
//!    ([`EVICTION_MIN_AGE_SECS`]); a party's only, recent session is never
//!    closed for room. One with an allow-list refuses.
//!
//! Any of 2–5 is `witness/session:refused`, always with the same message: a
//! refusal that said *which* rule failed would answer "is this DID one the
//! operator excluded?", which is the correlation independence exists to avoid.
//! The rule is logged locally.
//!
//! Then a fresh 32-byte challenge from the OS RNG, the domain (this identity's
//! DID), and the session — opener, parties, challenge, domain, the document as
//! received, expiry — stored before the `#response` is returned.
//!
//! # `witness/session/submit/0.2`
//!
//! **Binding first** (submit conformance items 2–3): the document is on a live
//! session's thread, from that session's opener, and the VP's `nonce` (or
//! `challenge`) and `domain` are the session's. Any failure is
//! `challengeMismatch`, before the presentation is examined at all.
//!
//! **Then the presentation** ([`crate::presentation`]), and the payload's
//! `memberPresentation` where this identity relies on one (the member link, for
//! a party whose membership credential names its member DID rather than its
//! relationship DID): `presentationInvalid`. The member DID goes nowhere — not
//! into the VWC, the attestation record or a log line.
//!
//! A submission whose presentation does not verify leaves the session open,
//! up to [`MAX_FAILED_SUBMITS`] of them; then it is closed. A failure while a
//! DID could not be resolved counts separately, up to
//! [`MAX_INCONCLUSIVE_SUBMITS`].
//!
//! **Then the session is taken** — an atomic get-and-delete, so of two
//! submissions racing on one session exactly one goes on to mint; the other
//! finds no session and is `challengeMismatch`. Verification (which resolves
//! DIDs over the network) runs before the take and under no lock (R1.3).
//!
//! **Then the VWC**: `DTGCredential::new_witnessed_vsc` over the relationship
//! credential the witness verified and the session document it stored, then
//! `issuerScope: public`, an `id`, and the identity's `assertionMethod` proof
//! (`eddsa-jcs-2022`). `vwcDigestMultibase` is over the signed VWC, proof
//! included. An attestation record is written before the answer goes out; the
//! presentation is dropped.

use std::collections::BTreeSet;
use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityError, ResolvedKey};
use chrono::{DateTime, TimeDelta, Utc};
use dtg_credentials::{DTGCredential, IssuerScope};
use serde_json::Value;
use sha2::{Digest, Sha256};
use trust_tasks_rs::validate::ValidatedPayload;
use trust_tasks_rs::{ErrorPayload, RejectReason, StandardCode, TrustTask};
use vta_sdk::trust_task_proof::{
    ProofPurpose, PurposeVmResolver, TrustTaskVmResolver, is_unretrievable,
};
use vta_sdk::trust_task_sign::{HolderKey, sign_object_for_assertion};
use vti_specs::witness::session;

use crate::config::{ANY_COMMUNITY, SessionLimits, WitnessConfig, WitnessIdentity};
use crate::presentation::{self, Expected};
use crate::store::{AttestationRecord, SessionRecord, WitnessStore};

/// A refusal: the error a task answers with. Boxed, because `ErrorPayload`
/// is large and the success path is the common one.
pub(crate) type Refusal = Box<ErrorPayload>;

/// The one message every `witness/session:refused` carries.
const REFUSED_MESSAGE: &str = "this witness declines to open a session for this exchange";

/// One identity's witnessing policy, resolved from the configuration.
#[derive(Debug, Clone)]
pub struct WitnessPolicy {
    /// `None` = anyone (`communities = ["*"]`); `Some(empty)` = nobody.
    communities: Option<BTreeSet<String>>,
    allowed_parties: Option<BTreeSet<String>>,
    excluded: BTreeSet<String>,
    limits: SessionLimits,
}

impl WitnessPolicy {
    /// The policy `identity` serves under `config`: its own settings, plus the
    /// service-wide exclusions, every witness DID of this service, and the
    /// operator's VTA (§3.2 — a witness never witnesses itself or its operator).
    pub fn from_config(config: &WitnessConfig, identity: &WitnessIdentity) -> Self {
        let mut excluded: BTreeSet<String> = config.independence.exclude.iter().cloned().collect();
        excluded.extend(identity.independence.exclude.iter().cloned());
        excluded.extend(config.witnesses.iter().map(|w| w.did.clone()));
        excluded.insert(config.operator_vta_did.clone());
        Self::new(
            identity.communities.clone(),
            identity.allowed_parties.clone(),
            excluded,
            identity.sessions.clone(),
        )
    }

    /// A policy from its parts. `communities` is as in the configuration.
    pub fn new(
        communities: Vec<String>,
        allowed_parties: Option<Vec<String>>,
        excluded: impl IntoIterator<Item = String>,
        limits: SessionLimits,
    ) -> Self {
        let communities = if communities.iter().any(|c| c == ANY_COMMUNITY) {
            None
        } else {
            Some(communities.into_iter().collect())
        };
        Self {
            communities,
            allowed_parties: allowed_parties.map(|a| a.into_iter().collect()),
            excluded: excluded.into_iter().collect(),
            limits,
        }
    }

    /// Whether `did` may not be witnessed (§3.2).
    pub fn is_excluded(&self, did: &str) -> bool {
        self.excluded.contains(did)
    }

    /// Whether membership evidence is waived (`communities = ["*"]`).
    pub fn witnesses_anyone(&self) -> bool {
        self.communities.is_none()
    }

    /// Whether this identity witnesses nobody (`communities` empty).
    pub fn witnesses_nobody(&self) -> bool {
        self.communities.as_ref().is_some_and(BTreeSet::is_empty)
    }

    /// Whether a membership credential issued by `community` counts.
    pub fn accepts_community(&self, community: &str) -> bool {
        !self.is_excluded(community)
            && self
                .communities
                .as_ref()
                .is_some_and(|c| c.contains(community))
    }

    /// Whether any opener is admitted (no allow-list).
    fn admits_any_opener(&self) -> bool {
        self.allowed_parties.is_none()
    }

    fn admits_opener(&self, opener: &str) -> bool {
        self.allowed_parties
            .as_ref()
            .is_none_or(|allowed| allowed.contains(opener))
    }
}

/// Everything one identity needs to witness: its policy, the store, and the
/// lock that makes the cap check and the session insert one step.
pub struct Witnessing {
    policy: WitnessPolicy,
    store: WitnessStore,
    /// Held across the count and the insert of a new session, and nothing
    /// else — both are local store calls, never a network await (R1.3).
    opening: tokio::sync::Mutex<()>,
}

impl Witnessing {
    /// An identity's witnessing state.
    pub fn new(policy: WitnessPolicy, store: WitnessStore) -> Self {
        Self {
            policy,
            store,
            opening: tokio::sync::Mutex::new(()),
        }
    }

    /// The policy.
    pub fn policy(&self) -> &WitnessPolicy {
        &self.policy
    }

    /// The store.
    pub fn store(&self) -> &WitnessStore {
        &self.store
    }

    /// The duplicate-execution record (SPEC §7.2 item 11, VTI-OPS-025 … 029), shared by every
    /// identity this service holds: a document `id` is its producer's, unique whoever it is
    /// addressed to.
    pub(crate) fn accepted_ids(&self) -> vti_trust_task_server::StoreAcceptedIds {
        vti_trust_task_server::StoreAcceptedIds::new(self.store.accepted_ids().clone())
    }
}

/// Who is answering: the identity's DID, its key, and its witnessing state.
pub(crate) struct Witness<'a> {
    pub did: &'a str,
    pub name: &'a str,
    pub key: &'a HolderKey,
    pub state: &'a Arc<Witnessing>,
}

fn refused(rule: &str, witness: &Witness<'_>) -> Refusal {
    tracing::info!(identity = %witness.name, rule, "witness/session refused");
    Box::new(ErrorPayload::from(session::v0_2::error_codes::REFUSED).with_message(REFUSED_MESSAGE))
}

fn challenge_mismatch(why: &str) -> Refusal {
    Box::new(
        ErrorPayload::from(session::submit::v0_2::error_codes::CHALLENGE_MISMATCH).with_message(
            format!("the submission is not bound to a live session this party opened: {why}"),
        ),
    )
}

fn presentation_invalid(why: &str) -> Refusal {
    Box::new(
        ErrorPayload::from(session::submit::v0_2::error_codes::PRESENTATION_INVALID)
            .with_message(format!("the presentation did not verify: {why}")),
    )
}

fn malformed(reason: impl Into<String>) -> Refusal {
    Box::new(
        RejectReason::MalformedRequest {
            reason: reason.into(),
        }
        .into(),
    )
}

fn internal(what: &str, e: impl std::fmt::Display) -> Refusal {
    tracing::error!(error = %e, "{what}");
    Box::new(ErrorPayload::new(StandardCode::InternalError).with_message(what.to_string()))
}

/// `witness/session/0.2`. `received` is the document's bytes as they arrived.
pub(crate) async fn open_session(
    witness: &Witness<'_>,
    doc: &TrustTask<Value>,
    received: &[u8],
    sender: &str,
    now: DateTime<Utc>,
) -> Result<Value, Refusal> {
    if let Err(e) = session::v0_2::Payload::validate_value(&doc.payload) {
        return Err(malformed(format!("payload: {e}")));
    }
    let payload: session::v0_2::Payload = serde_json::from_value(doc.payload.clone())
        .map_err(|e| malformed(format!("payload: {e}")))?;

    // The document is the session's name, and the VWC cites it only if it
    // names its own thread (party conformance item 1; `new_witnessed_vsc`
    // refuses any other). Caught now, not after the party has submitted.
    if doc.thread_id.as_deref() != Some(doc.id.as_str()) {
        return Err(malformed(
            "a witness/session document opens its own exchange: its threadId must equal its id",
        ));
    }

    let parties: Vec<String> = payload.parties.iter().map(|p| p.to_string()).collect();
    let policy = witness.state.policy();
    if parties[0] == parties[1] {
        return Err(refused("parties-identical", witness));
    }
    if !parties.iter().any(|p| p == sender) {
        return Err(refused("opener-not-a-party", witness));
    }
    if parties.iter().any(|p| policy.is_excluded(p)) {
        return Err(refused("independence", witness));
    }
    if policy.witnesses_nobody() {
        return Err(refused("no-communities", witness));
    }
    if !policy.admits_opener(sender) {
        return Err(refused("allow-list", witness));
    }

    let challenge = fresh_challenge().map_err(|e| internal("could not draw a challenge", e))?;
    // Kept verbatim: the VWC's task digest is computed over this document,
    // and the holder will ship these same bytes for a verifier to recompute.
    let document = String::from_utf8(received.to_vec())
        .map_err(|e| internal("could not keep the session document", e))?;
    let limits = &policy.limits;
    let record = SessionRecord {
        identity_did: witness.did.to_string(),
        session_id: doc.id.clone(),
        opener_did: sender.to_string(),
        parties,
        challenge: challenge.clone(),
        domain: witness.did.to_string(),
        document,
        opened_at: now,
        expires_at: now + TimeDelta::seconds(limits.ttl_secs as i64),
        failed_submits: 0,
        inconclusive_submits: 0,
    };

    {
        // The caps and the insert, as one step: two openers racing on the last
        // slot must not both get it.
        let _opening = witness.state.opening.lock().await;
        let open = witness
            .state
            .store()
            .open_sessions(witness.did, now)
            .await
            .map_err(|e| internal("could not read the open sessions", e))?;
        if open.iter().filter(|s| s.opener_did == sender).count() >= limits.max_open_per_party {
            return Err(refused("capacity-per-party", witness));
        }
        // No separate bound on sessions naming one party as the counterparty:
        // anyone can name anyone, so such a cap would let one opener lock a
        // party out of being named by everyone else. Per (opener,
        // counterparty) pair the per-opener cap above already holds.
        if open.len() >= limits.max_open {
            // An identity that admits any opener cannot let whoever opened
            // first hold every slot for a session lifetime: a session makes
            // way ([`evictable`]). One with an allow-list holds only sessions
            // its named parties opened, and refuses instead.
            if !policy.admits_any_opener() {
                return Err(refused("capacity", witness));
            }
            let excess = (open.len() + 1).saturating_sub(limits.max_open);
            let to_close = evictable(&open, excess, now);
            if to_close.len() < excess {
                return Err(refused("capacity", witness));
            }
            close_sessions(witness, &to_close).await?;
        }
        let inserted = witness
            .state
            .store()
            .insert_session(&record)
            .await
            .map_err(|e| internal("could not store the session", e))?;
        if !inserted {
            // A session under this `id` already exists: the duplicate record
            // answers a replay before this, so this is another document.
            return Err(Box::new(RejectReason::IdConflict.into()));
        }
    }

    let response = session::v0_2::Response::builder()
        .challenge(challenge)
        .domain(witness.did.to_string());
    let response: session::v0_2::Response = response
        .try_into()
        .map_err(|e| internal("could not build the session response", e))?;
    serde_json::to_value(response).map_err(|e| internal("could not encode the response", e))
}

/// How long a session is protected from being closed to make room while an
/// older one can be closed instead. A party that opens a session submits
/// within seconds; this keeps a session in progress from being closed under it
/// by openers churning the identity's capacity.
pub const EVICTION_MIN_AGE_SECS: i64 = 60;

/// Up to `needed` sessions of `open` to close for room, in order:
///
/// 1. surplus sessions older than [`EVICTION_MIN_AGE_SECS`] — of openers
///    holding more than one, every one but each opener's newest — oldest first;
/// 2. then any other session older than that, oldest first;
/// 3. only then recent surplus sessions, oldest first.
///
/// An opener's newest session, opened less than a minute ago, is never
/// chosen, so a party's only session in progress survives. A recent surplus
/// session goes only when nothing older can. Fewer than `needed` means the
/// identity is full of recent sessions each its opener's newest, and the
/// caller refuses.
fn evictable(open: &[SessionRecord], needed: usize, now: DateTime<Utc>) -> Vec<String> {
    use std::collections::{BTreeMap, HashSet};
    let mut by_opener: BTreeMap<&str, Vec<&SessionRecord>> = BTreeMap::new();
    for s in open {
        by_opener.entry(s.opener_did.as_str()).or_default().push(s);
    }
    let mut surplus: HashSet<&str> = HashSet::new();
    for sessions in by_opener.values_mut() {
        sessions.sort_by_key(|s| s.opened_at);
        // Every session but the newest is surplus.
        let keep = sessions.len().saturating_sub(1);
        surplus.extend(sessions.iter().take(keep).map(|s| s.session_id.as_str()));
    }
    let cutoff = now - TimeDelta::seconds(EVICTION_MIN_AGE_SECS);
    let aged = |s: &SessionRecord| s.opened_at <= cutoff;
    let is_surplus = |s: &SessionRecord| surplus.contains(s.session_id.as_str());

    let mut by_age: Vec<&SessionRecord> = open.iter().collect();
    by_age.sort_by_key(|s| s.opened_at);
    let phases: [&dyn Fn(&SessionRecord) -> bool; 3] =
        [&|s| aged(s) && is_surplus(s), &|s| aged(s), &|s| {
            is_surplus(s)
        }];
    let mut chosen: Vec<String> = Vec::new();
    for phase in phases {
        for s in &by_age {
            if chosen.len() >= needed {
                return chosen;
            }
            if phase(s) && !chosen.contains(&s.session_id) {
                chosen.push(s.session_id.clone());
            }
        }
    }
    chosen
}

/// Close `sessions` to make room. The caller holds the `opening` lock.
async fn close_sessions(witness: &Witness<'_>, sessions: &[String]) -> Result<(), Refusal> {
    for id in sessions {
        witness
            .state
            .store()
            .take_session(witness.did, id)
            .await
            .map_err(|e| internal("could not close an old session", e))?;
    }
    tracing::info!(
        identity = %witness.name,
        closed = sessions.len(),
        "session capacity reached: sessions were closed to make room"
    );
    Ok(())
}

/// After this many submissions whose presentation definitely did not verify,
/// a session is closed. Each verification resolves DIDs; a party with a valid
/// presentation needs one attempt, and a few more absorb a mistake.
pub const MAX_FAILED_SUBMITS: u32 = 3;

/// After this many submissions that failed while a DID could not be resolved
/// — which may be the network rather than the party — a session is closed.
/// Higher than [`MAX_FAILED_SUBMITS`], so an outage does not cost a party its
/// session at once, but finite, so a submission that never resolves cannot be
/// repeated for the session's whole lifetime.
pub const MAX_INCONCLUSIVE_SUBMITS: u32 = 10;

/// A resolver that remembers whether any resolution failed, so a submission
/// that failed for that reason is not counted as a definite failure.
struct ObservedResolver<'r> {
    inner: &'r (dyn PurposeVmResolver + 'r),
    failed: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl PurposeVmResolver for ObservedResolver<'_> {
    async fn resolve_vm_for_purpose(
        &self,
        vm: &str,
        purpose: ProofPurpose,
    ) -> Result<ResolvedKey, DataIntegrityError> {
        let r = self.inner.resolve_vm_for_purpose(vm, purpose).await;
        // Only a key that could not be *retrieved*. Every other resolver
        // refusal — a key not under the purpose, a `did:key` fragment that
        // does not match, a malformed method — is a verdict on the proof.
        if r.as_ref().is_err_and(is_unretrievable) {
            self.failed
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        r
    }
}

/// Count a failed submission against the session on `thread` with `challenge`
/// — as definite, or as `inconclusive` when a DID could not be resolved —
/// closing it at [`MAX_FAILED_SUBMITS`] / [`MAX_INCONCLUSIVE_SUBMITS`]. Logged,
/// never an error to the party: its answer is the presentation's refusal
/// either way.
async fn note_failed_submit(
    witness: &Witness<'_>,
    thread: &str,
    challenge: &str,
    inconclusive: bool,
) {
    let store = witness.state.store();
    // The `opening` lock serialises this read-modify-write against another
    // failure on the same session; it guards only local store calls (R1.3).
    let _counting = witness.state.opening.lock().await;
    let mut session = match store.session(witness.did, thread).await {
        // The same session, not one a later open put under this id.
        Ok(Some(s)) if s.challenge == challenge => s,
        Ok(_) => return,
        Err(e) => {
            tracing::warn!(error = %e, "could not count a failed submission");
            return;
        }
    };
    if inconclusive {
        session.inconclusive_submits = session.inconclusive_submits.saturating_add(1);
    } else {
        session.failed_submits = session.failed_submits.saturating_add(1);
    }
    let result = if session.failed_submits >= MAX_FAILED_SUBMITS
        || session.inconclusive_submits >= MAX_INCONCLUSIVE_SUBMITS
    {
        tracing::info!(
            identity = %witness.name,
            failed = session.failed_submits,
            inconclusive = session.inconclusive_submits,
            "session closed after repeated submissions that did not verify"
        );
        store.take_session(witness.did, thread).await.map(|_| ())
    } else {
        store.replace_session(&session).await
    };
    if let Err(e) = result {
        tracing::warn!(error = %e, "could not count a failed submission");
    }
}

/// `witness/session/submit/0.2`.
pub(crate) async fn submit(
    witness: &Witness<'_>,
    doc: &TrustTask<Value>,
    sender: &str,
    resolver: &TrustTaskVmResolver,
    now: DateTime<Utc>,
) -> Result<Value, Refusal> {
    if let Err(e) = session::submit::v0_2::Payload::validate_value(&doc.payload) {
        return Err(malformed(format!("payload: {e}")));
    }
    let payload: session::submit::v0_2::Payload = serde_json::from_value(doc.payload.clone())
        .map_err(|e| malformed(format!("payload: {e}")))?;
    let vp = Value::Object(payload.vp);
    // Read from the payload as received: the generated type folds an empty
    // object into "absent", and a member presentation that was sent is one the
    // witness must judge, not skip.
    let member_presentation = doc.payload.get(MEMBER_PRESENTATION).cloned();
    let store = witness.state.store();

    // ── Binding first (items 2–3) ──────────────────────────────────────
    let Some(thread) = doc.thread_id.as_deref() else {
        return Err(challenge_mismatch("the document names no session thread"));
    };
    let session = store
        .session(witness.did, thread)
        .await
        .map_err(|e| internal("could not read the session", e))?
        .filter(|s| !s.is_expired_at(now))
        .ok_or_else(|| challenge_mismatch("there is no open session on this thread"))?;
    if session.opener_did != sender {
        return Err(challenge_mismatch(
            "the session was opened by another party",
        ));
    }
    // The versions pair one to one: a submit/0.2 completes only a session
    // opened as witness/session/0.2, whose declared outcome evidence it is.
    if !opened_at_this_version(&session) {
        return Err(challenge_mismatch(
            "the session was not opened as witness/session/0.2",
        ));
    }
    bound_to(&vp, &session)?;

    // ── Then the presentation ──────────────────────────────────────────
    let counterparty = session
        .parties
        .iter()
        .find(|p| *p != sender)
        .cloned()
        .unwrap_or_default();
    let observed = ObservedResolver {
        inner: resolver,
        failed: std::sync::atomic::AtomicBool::new(false),
    };
    let verified = presentation::verify(
        &vp,
        member_presentation.as_ref(),
        &Expected {
            submitter: sender,
            counterparty: &counterparty,
            witness: witness.did,
            challenge: &session.challenge,
            domain: &session.domain,
        },
        witness.state.policy(),
        &observed,
        now,
    )
    .await;
    let verified = match verified {
        Ok(v) => v,
        Err(why) => {
            let inconclusive = observed.failed.load(std::sync::atomic::Ordering::Relaxed);
            note_failed_submit(witness, thread, &session.challenge, inconclusive).await;
            return Err(presentation_invalid(&why));
        }
    };
    drop(vp);
    drop(member_presentation);

    // ── Take the session: single use ───────────────────────────────────
    let taken = store
        .take_session(witness.did, thread)
        .await
        .map_err(|e| internal("could not claim the session", e))?;
    let Some(taken) = taken.filter(|t| t.challenge == session.challenge) else {
        return Err(challenge_mismatch("the session has already been used"));
    };
    if taken.is_expired_at(Utc::now()) {
        return Err(challenge_mismatch("the session expired"));
    }

    // ── Mint ───────────────────────────────────────────────────────────
    match mint(witness, &taken, &verified.relationship_credential, now).await {
        Ok(answer) => Ok(answer),
        Err(e) => {
            // Nothing was issued: give the party its session back.
            if let Err(restore) = store.restore_session(&taken).await {
                tracing::error!(error = %restore, "could not restore a session after a failed mint");
            }
            Err(e)
        }
    }
}

/// The payload member carrying the member presentation
/// (`witness/session/submit/0.2`, *The member presentation*).
const MEMBER_PRESENTATION: &str = "memberPresentation";

/// Whether `session` was opened as `witness/session/0.2`, read off the
/// document the witness stored as received.
fn opened_at_this_version(session: &SessionRecord) -> bool {
    serde_json::from_str::<Value>(&session.document)
        .ok()
        .and_then(|d| d.get("type").and_then(Value::as_str).map(str::to_owned))
        .is_some_and(|t| t == <session::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI)
}

/// The VP is bound to `session`: its `domain` is the session's, and its
/// `nonce` (the member the workspace's VP builder signs the challenge into) or
/// `challenge` is the session's challenge. Both members sit inside the
/// presentation its holder proof covers, which the next step verifies.
fn bound_to(vp: &Value, session: &SessionRecord) -> Result<(), Refusal> {
    let carried: Vec<&str> = ["nonce", "challenge"]
        .iter()
        .filter_map(|m| vp.get(*m).and_then(Value::as_str))
        .collect();
    if carried.is_empty() || carried.iter().any(|c| *c != session.challenge) {
        return Err(challenge_mismatch(
            "the presentation is not bound to this session's challenge",
        ));
    }
    if vp.get("domain").and_then(Value::as_str) != Some(session.domain.as_str()) {
        return Err(challenge_mismatch(
            "the presentation is not bound to this session's domain",
        ));
    }
    Ok(())
}

/// Build, sign and record the VWC; answer `{ vwc, vwcDigestMultibase }`.
async fn mint(
    witness: &Witness<'_>,
    session: &SessionRecord,
    relationship_credential: &Value,
    now: DateTime<Utc>,
) -> Result<Value, Refusal> {
    let session_document: Value = serde_json::from_str(&session.document)
        .map_err(|e| internal("the stored session document does not parse", e))?;
    let vwc_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let vwc = DTGCredential::new_witnessed_vsc(
        witness.did.to_string(),
        IssuerScope::Public,
        relationship_credential,
        &session_document,
        now,
        None,
        None,
    )
    .map_err(|e| internal("could not build the witness credential", e))?
    .with_id(vwc_id.clone());
    vwc.validate()
        .map_err(|e| internal("the witness credential does not validate", e))?;

    let mut vwc = serde_json::to_value(&vwc)
        .map_err(|e| internal("could not encode the witness credential", e))?;
    sign_object_for_assertion(&mut vwc, witness.key)
        .await
        .map_err(|e| internal("could not sign the witness credential", e))?;
    let digest = vwc_digest_multibase(&vwc)
        .map_err(|e| internal("could not digest the witness credential", e))?;

    // The record that lets this VWC be revoked later — written before the
    // credential leaves, so nothing is issued that the witness cannot name.
    witness
        .state
        .store()
        .record_attestation(&AttestationRecord {
            vwc_id,
            vwc_digest_multibase: digest.clone(),
            submitter_did: session.opener_did.clone(),
            session_id: session.session_id.clone(),
            identity_did: witness.did.to_string(),
            issued_at: now,
        })
        .await
        .map_err(|e| internal("could not record the attestation", e))?;

    let Value::Object(vwc) = vwc else {
        return Err(internal("the witness credential is not an object", ""));
    };
    let response: session::submit::v0_2::Response = session::submit::v0_2::Response::builder()
        .vwc(vwc)
        .vwc_digest_multibase(digest)
        .try_into()
        .map_err(|e| internal("could not build the submit response", e))?;
    serde_json::to_value(response).map_err(|e| internal("could not encode the response", e))
}

/// `vwcDigestMultibase` (`witness/session/submit/0.2` response schema): over
/// the RFC 8785 canonicalization of the delivered credential **whole, proof
/// included** — unlike every `dtg-credentials` digest, which drops the
/// top-level proof — as a `sha2-256` multihash, base58btc.
pub fn vwc_digest_multibase(vwc: &Value) -> anyhow::Result<String> {
    let canonical = serde_json_canonicalizer::to_vec(vwc)?;
    let mut multihash = Vec::with_capacity(34);
    multihash.extend_from_slice(&[0x12, 0x20]);
    multihash.extend_from_slice(&Sha256::digest(&canonical));
    Ok(multibase::encode(multibase::Base::Base58Btc, multihash))
}

/// 32 bytes from the OS RNG, hex-encoded (64 characters; the schema asks for
/// at least 16).
fn fresh_challenge() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = r#"
data_dir = "/var/lib/vti-witness"
operator_vta_did = "did:webvh:QmVTA:vta.operator.example"

[secrets]
backend = "keyring"

[independence]
exclude = ["did:webvh:QmC:community.operator.example"]

[[witness]]
name = "a"
did = "did:webvh:QmA:w.example:a"
mediator_did = "did:webvh:QmM:m.example"
communities = ["did:webvh:QmV:vtc.example"]

[witness.independence]
exclude = ["did:key:z6MkOwnRelationship"]

[[witness]]
name = "b"
did = "did:webvh:QmB:w.example:b"
mediator_did = "did:webvh:QmM:m.example"
"#;

    /// §3.2: an identity never witnesses any witness of this service, the
    /// operator's VTA, or a DID excluded service-wide or for it.
    #[test]
    fn the_policy_excludes_every_own_witness_the_operator_and_the_configured_dids() {
        let config = WitnessConfig::from_toml_str(RAW).unwrap();
        let a = WitnessPolicy::from_config(&config, &config.witnesses[0]);
        for did in [
            "did:webvh:QmA:w.example:a",
            "did:webvh:QmB:w.example:b",
            "did:webvh:QmVTA:vta.operator.example",
            "did:webvh:QmC:community.operator.example",
            "did:key:z6MkOwnRelationship",
        ] {
            assert!(a.is_excluded(did), "{did}");
        }
        assert!(!a.is_excluded("did:key:z6MkSomeoneElse"));
        assert!(a.accepts_community("did:webvh:QmV:vtc.example"));
        assert!(!a.witnesses_anyone() && !a.witnesses_nobody());

        // Per-identity exclusions stay with their identity.
        let b = WitnessPolicy::from_config(&config, &config.witnesses[1]);
        assert!(!b.is_excluded("did:key:z6MkOwnRelationship"));
        assert!(b.witnesses_nobody(), "no communities: nobody");
    }

    /// An excluded community never counts, even when listed.
    #[test]
    fn exclusion_wins_over_a_listed_community() {
        let p = WitnessPolicy::new(
            vec!["did:example:vtc".into()],
            None,
            vec!["did:example:vtc".to_string()],
            SessionLimits::default(),
        );
        assert!(!p.accepts_community("did:example:vtc"));
    }

    #[test]
    fn the_vwc_digest_covers_the_proof() {
        let a = serde_json::json!({ "a": 1, "proof": { "proofValue": "z1" } });
        let b = serde_json::json!({ "a": 1, "proof": { "proofValue": "z2" } });
        assert_ne!(
            vwc_digest_multibase(&a).unwrap(),
            vwc_digest_multibase(&b).unwrap()
        );
        let reordered = serde_json::json!({ "proof": { "proofValue": "z1" }, "a": 1 });
        assert_eq!(
            vwc_digest_multibase(&a).unwrap(),
            vwc_digest_multibase(&reordered).unwrap(),
            "RFC 8785: member order is not a difference"
        );
    }

    #[test]
    fn challenges_are_32_random_bytes() {
        let a = fresh_challenge().unwrap();
        let b = fresh_challenge().unwrap();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    fn session(id: &str, opener: &str, opened_at: DateTime<Utc>) -> SessionRecord {
        SessionRecord {
            identity_did: "did:example:w".into(),
            session_id: id.into(),
            opener_did: opener.into(),
            parties: vec![opener.into(), "did:example:other".into()],
            challenge: String::new(),
            domain: String::new(),
            document: String::new(),
            opened_at,
            expires_at: opened_at + TimeDelta::seconds(600),
            failed_submits: 0,
            inconclusive_submits: 0,
        }
    }

    #[test]
    fn room_is_made_from_aged_sessions_before_recent_surplus_never_a_recent_newest() {
        let now = Utc::now();
        let ago = |s: i64| now - TimeDelta::seconds(s);
        let old = EVICTION_MIN_AGE_SECS + 10;
        let open = vec![
            session("only-recent", "did:example:a", ago(5)),
            // A party holding three recent sessions: two are surplus.
            session("p-1", "did:example:p", ago(7)),
            session("p-2", "did:example:p", ago(6)),
            session("p-3", "did:example:p", ago(5)),
            session("only-aged", "did:example:b", ago(old)),
            session("q-aged-surplus", "did:example:q", ago(old + 5)),
            session("q-recent", "did:example:q", ago(4)),
        ];
        // Aged surplus first, then other aged sessions.
        assert_eq!(evictable(&open, 1, now), vec!["q-aged-surplus".to_string()]);
        assert_eq!(
            evictable(&open, 2, now),
            vec!["q-aged-surplus".to_string(), "only-aged".to_string()]
        );
        // Recent surplus only after everything aged, oldest first.
        assert_eq!(
            evictable(&open, 4, now),
            vec![
                "q-aged-surplus".to_string(),
                "only-aged".to_string(),
                "p-1".to_string(),
                "p-2".to_string(),
            ]
        );
        // Never an opener's newest recent session.
        let all = evictable(&open, open.len(), now);
        assert_eq!(all.len(), 4, "{all:?}");
        for kept in ["only-recent", "p-3", "q-recent"] {
            assert!(!all.contains(&kept.to_string()), "{kept}: {all:?}");
        }
    }

    /// A party's surplus sessions, even only seconds old, outlast an aged
    /// session of anyone else.
    #[test]
    fn a_recent_surplus_session_outlasts_an_aged_one() {
        let now = Utc::now();
        let open = vec![
            session("p-1", "did:example:p", now - TimeDelta::seconds(5)),
            session("p-2", "did:example:p", now - TimeDelta::seconds(4)),
            session(
                "aged",
                "did:example:b",
                now - TimeDelta::seconds(EVICTION_MIN_AGE_SECS + 1),
            ),
        ];
        assert_eq!(evictable(&open, 1, now), vec!["aged".to_string()]);
    }

    /// Fails every resolution: as a key that could not be retrieved (`true`),
    /// or with a verdict on the proof carried in the same variant (`false`).
    struct Failing(bool);

    #[async_trait::async_trait]
    impl PurposeVmResolver for Failing {
        async fn resolve_vm_for_purpose(
            &self,
            _vm: &str,
            _purpose: ProofPurpose,
        ) -> Result<ResolvedKey, DataIntegrityError> {
            Err(if self.0 {
                vta_sdk::trust_task_proof::unretrievable("the DID did not resolve")
            } else {
                DataIntegrityError::Resolver(
                    "verification method is not listed under assertionMethod".into(),
                )
            })
        }
    }

    #[tokio::test]
    async fn only_an_unretrievable_key_marks_a_submission_inconclusive() {
        let unreachable = Failing(true);
        let observed = ObservedResolver {
            inner: &unreachable,
            failed: std::sync::atomic::AtomicBool::new(false),
        };
        let _ = observed
            .resolve_vm_for_purpose("did:web:x#k", ProofPurpose::AssertionMethod)
            .await;
        assert!(observed.failed.load(std::sync::atomic::Ordering::Relaxed));

        let bad = Failing(false);
        let observed = ObservedResolver {
            inner: &bad,
            failed: std::sync::atomic::AtomicBool::new(false),
        };
        let _ = observed
            .resolve_vm_for_purpose("did:key:z#k", ProofPurpose::AssertionMethod)
            .await;
        assert!(!observed.failed.load(std::sync::atomic::Ordering::Relaxed));
    }
}
