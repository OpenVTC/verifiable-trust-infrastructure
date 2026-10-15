//! Witnessing: `witness/session/0.1` and `witness/session/submit/0.1`
//! (design note §3.2–§3.4).
//!
//! # `witness/session/0.1`
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
//! 5. the caps: open sessions at this identity, and per opener.
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
//! # `witness/session/submit/0.1`
//!
//! **Binding first** (submit conformance items 2–3): the document is on a live
//! session's thread, from that session's opener, and the VP's `nonce` (or
//! `challenge`) and `domain` are the session's. Any failure is
//! `challengeMismatch`, before the presentation is examined at all.
//!
//! **Then the presentation** ([`crate::presentation`]), and the member
//! presentation if `ext["org.openvtc.witness"]` carries one (the member link,
//! for a party whose membership credential names its member DID rather than its
//! relationship DID): `presentationInvalid`.
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

use chrono::{DateTime, TimeDelta, Utc};
use dtg_credentials::{DTGCredential, IssuerScope};
use serde_json::Value;
use sha2::{Digest, Sha256};
use trust_tasks_rs::specs::witness::session;
use trust_tasks_rs::validate::ValidatedPayload;
use trust_tasks_rs::{ErrorPayload, RejectReason, StandardCode, TrustTask};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::trust_task_sign::{HolderKey, sign_object_for_assertion};

use crate::config::{ANY_COMMUNITY, SessionLimits, WitnessConfig, WitnessIdentity};
use crate::presentation::{self, Expected};
use crate::replay::AcceptedIds;
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

    /// The duplicate-execution record for documents addressed to `identity_did`.
    pub(crate) fn accepted_ids(&self, identity_did: &str) -> AcceptedIds {
        AcceptedIds::new(self.store.accepted_ids().clone(), identity_did)
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
    Box::new(ErrorPayload::from(session::v0_1::error_codes::REFUSED).with_message(REFUSED_MESSAGE))
}

fn challenge_mismatch(why: &str) -> Refusal {
    Box::new(
        ErrorPayload::from(session::submit::v0_1::error_codes::CHALLENGE_MISMATCH).with_message(
            format!("the submission is not bound to a live session this party opened: {why}"),
        ),
    )
}

fn presentation_invalid(why: &str) -> Refusal {
    Box::new(
        ErrorPayload::from(session::submit::v0_1::error_codes::PRESENTATION_INVALID)
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

/// `witness/session/0.1`. `received` is the document's bytes as they arrived.
pub(crate) async fn open_session(
    witness: &Witness<'_>,
    doc: &TrustTask<Value>,
    received: &[u8],
    sender: &str,
    now: DateTime<Utc>,
) -> Result<Value, Refusal> {
    if let Err(e) = session::v0_1::Payload::validate_value(&doc.payload) {
        return Err(malformed(format!("payload: {e}")));
    }
    let payload: session::v0_1::Payload = serde_json::from_value(doc.payload.clone())
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
        if open.len() >= limits.max_open {
            return Err(refused("capacity", witness));
        }
        if open.iter().filter(|s| s.opener_did == sender).count() >= limits.max_open_per_party {
            return Err(refused("capacity-per-party", witness));
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

    let response = session::v0_1::Response::builder()
        .challenge(challenge)
        .domain(witness.did.to_string());
    let response: session::v0_1::Response = response
        .try_into()
        .map_err(|e| internal("could not build the session response", e))?;
    serde_json::to_value(response).map_err(|e| internal("could not encode the response", e))
}

/// `witness/session/submit/0.1`.
pub(crate) async fn submit(
    witness: &Witness<'_>,
    doc: &TrustTask<Value>,
    sender: &str,
    resolver: &TrustTaskVmResolver,
    now: DateTime<Utc>,
) -> Result<Value, Refusal> {
    if let Err(e) = session::submit::v0_1::Payload::validate_value(&doc.payload) {
        return Err(malformed(format!("payload: {e}")));
    }
    let payload: session::submit::v0_1::Payload = serde_json::from_value(doc.payload.clone())
        .map_err(|e| malformed(format!("payload: {e}")))?;
    let vp = Value::Object(payload.vp);
    let member_presentation = member_presentation(&doc.payload)?;
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
    bound_to(&vp, &session)?;

    // ── Then the presentation ──────────────────────────────────────────
    let counterparty = session
        .parties
        .iter()
        .find(|p| *p != sender)
        .cloned()
        .unwrap_or_default();
    let verified = presentation::verify(
        &vp,
        member_presentation.as_ref(),
        &Expected {
            submitter: sender,
            counterparty: &counterparty,
            challenge: &session.challenge,
            domain: &session.domain,
        },
        witness.state.policy(),
        resolver,
        now,
    )
    .await
    .map_err(|why| presentation_invalid(&why))?;
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

/// The member presentation, if the payload carries one in
/// `ext["org.openvtc.witness"]` ([`presentation::MEMBER_LINK_EXT`]). Any other
/// member of that namespace is refused, as an unknown field would be.
fn member_presentation(payload: &Value) -> Result<Option<Value>, Refusal> {
    let Some(ns) = payload
        .get("ext")
        .and_then(|e| e.get(presentation::MEMBER_LINK_EXT))
    else {
        return Ok(None);
    };
    let Some(ns) = ns.as_object() else {
        return Err(malformed(format!(
            "ext.{}: must be an object",
            presentation::MEMBER_LINK_EXT
        )));
    };
    if let Some(unknown) = ns.keys().find(|k| *k != presentation::MEMBER_PRESENTATION) {
        return Err(malformed(format!(
            "ext.{}: unknown member `{unknown}`",
            presentation::MEMBER_LINK_EXT
        )));
    }
    match ns.get(presentation::MEMBER_PRESENTATION) {
        None => Ok(None),
        Some(mp @ Value::Object(_)) => Ok(Some(mp.clone())),
        Some(_) => Err(malformed(format!(
            "ext.{}.{}: must be an object",
            presentation::MEMBER_LINK_EXT,
            presentation::MEMBER_PRESENTATION
        ))),
    }
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
    let response: session::submit::v0_1::Response = session::submit::v0_1::Response::builder()
        .vwc(vwc)
        .vwc_digest_multibase(digest)
        .try_into()
        .map_err(|e| internal("could not build the submit response", e))?;
    serde_json::to_value(response).map_err(|e| internal("could not encode the response", e))
}

/// `vwcDigestMultibase` (`witness/session/submit/0.1` response schema): over
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
}
