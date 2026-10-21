//! What the registrar does, apart from the wire: each `vtc/elections/*` rule over the records,
//! the registrar key and the link to the ballot box. The task handlers
//! (`trust_tasks::election_tasks`) map these errors to each task's declared codes.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use serde_json::{Value, json};
use sha2::Sha256;
use trust_tasks_rs::specs::voting::election::register::v0_1::Manifest;
use vti_voting::{
    election::{Election, ElectionId},
    registrar::Registrar,
    rules::{self, RuleError},
    steps::ProvenRequests,
};

use super::link::{BoxAnswer, LinkError};
use super::store::{self, Delivery, ElectionRecord, Standing, TicketIssued};
use crate::error::AppError;
use crate::server::AppState;

/// HKDF info for the voting registrar's secret. Versioned: changing it changes the community's
/// voting key, and every ticket of an open election stops verifying.
const KEY_INFO: &[u8] = b"vtc-voting-pcs-secret/v1";

/// The PCS suite every ticket is issued under (`VotingParameters.suite`).
pub const SUITE: &str = "ps-ddh-bls12381";

const SPEC: &str = "https://trusttasks.org/spec/";

/// This community's DID.
pub async fn community_did(state: &AppState) -> String {
    state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_default()
}

/// The registrar: the voting helper key, derived from the master secret the credential signer
/// uses, with an info string of its own — so the hidden-vetting key and this one are unrelated,
/// and there is no second secret to provision or back up.
///
/// # Errors
/// [`AppError::Internal`] when the VTC holds no signing key yet.
pub async fn registrar(state: &AppState) -> Result<Arc<Registrar>, AppError> {
    let community = community_did(state).await;
    state
        .elections
        .registrar
        .get_or_try_init(|| async {
            let signer = state.credential_signer.as_ref().ok_or_else(|| {
                AppError::Internal(
                    "credential signer not initialised — cannot derive the voting key (run setup \
                     first)"
                        .into(),
                )
            })?;
            let master = signer.ed25519_signing_key().ok_or_else(|| {
                AppError::Internal("the credential signer holds no Ed25519 key".into())
            })?;
            let mut secret = zeroize::Zeroizing::new([0u8; 32]);
            Hkdf::<Sha256>::new(None, &master.to_bytes())
                .expand(KEY_INFO, secret.as_mut())
                .map_err(|e| AppError::Internal(format!("derive the voting secret: {e}")))?;
            Registrar::derive(&community, &secret)
                .map(Arc::new)
                .map_err(|e| AppError::Internal(format!("voting keys: {e}")))
        })
        .await
        .cloned()
}

/// `VotingParameters`: what a member's agent takes a ticket under (VTI-VOT-020).
///
/// # Errors
/// As [`registrar`].
pub async fn parameters(state: &AppState) -> Result<Value, AppError> {
    let reg = registrar(state).await?;
    let key = reg
        .public_text()
        .map_err(|e| AppError::Internal(format!("encode the voting key: {e}")))?;
    Ok(json!({ "suite": SUITE, "votingKey": key }))
}

/// `Disclosure` (VTI-VOT-090): generated from the manifest and the trusted ballot box's entry,
/// never written by hand.
pub async fn disclosure(state: &AppState, rec: &ElectionRecord) -> Value {
    let config = state.config.read().await;
    let (operator, same) = config.voting.trusted(&rec.ballot_box).map_or_else(
        // No longer trusted: still described, as its operator unknown and possibly this one.
        || ("unknown".to_string(), true),
        |b| (b.operator.clone(), b.same_operator),
    );
    let m = &rec.manifest;
    let mut d = json!({
        "ballotBox": rec.ballot_box,
        "ballotBoxOperator": operator,
        "sameOperator": same,
        "boardVisibility": m["board"]["visibility"],
        "auditors": m["board"]["auditors"],
        "revote": m["revote"],
        "coercionResistance": false,
    });
    if let Some(t) = m.get("trustees") {
        d["trustees"] = t.clone();
    }
    d
}

// ─── who may see an election ─────────────────────────────────────────────

/// Whether the roll rule admits `did` now (VTI-VOT-021): an active member under `members` and
/// `membersAndListed`, a DID the manifest lists under `membersAndListed` and `listed`.
///
/// # Errors
/// A store failure.
pub async fn roll_admits(
    state: &AppState,
    rec: &ElectionRecord,
    did: &str,
) -> Result<bool, AppError> {
    let rule = rec.manifest["roll"]["rule"].as_str().unwrap_or_default();
    let listed = rec.manifest["roll"]["listed"]
        .as_array()
        .is_some_and(|l| l.iter().any(|d| d.as_str() == Some(did)));
    let members = matches!(rule, "members" | "membersAndListed");
    let lists = matches!(rule, "listed" | "membersAndListed");
    if lists && listed {
        return Ok(true);
    }
    if members {
        return Ok(crate::member_portal::active::active_member(state, did)
            .await?
            .is_some());
    }
    Ok(false)
}

/// Whether `did` may see `rec`: a manager sees every election, anyone else a registered one
/// whose roll admits them now (list items 1 – 2, show item 1).
///
/// # Errors
/// A store failure.
pub async fn may_see(
    state: &AppState,
    rec: &ElectionRecord,
    did: &str,
    manager: bool,
) -> Result<bool, AppError> {
    if manager {
        return Ok(true);
    }
    if !rec.is_registered() && rec.standing != Standing::Cancelled {
        return Ok(false);
    }
    roll_admits(state, rec, did).await
}

// ─── create ──────────────────────────────────────────────────────────────

/// Why a creation was refused (create items 2 – 8).
#[derive(Debug)]
pub enum CreateError {
    InvalidManifest(String),
    UnsupportedSecrecy,
    CommunityMismatch,
    BallotBoxNotTrusted,
    ElectionExists,
    BallotBoxRefused { code: String, message: String },
    App(AppError),
}

impl From<AppError> for CreateError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

/// A manifest that passed items 2 – 5: its typed form and digest.
pub struct CheckedManifest {
    pub manifest: Manifest,
    pub digest: [u8; 32],
}

/// Items 2 – 6, against the community and the clock as they are now — run on the request, and
/// again when a parked binding creation executes (item 7).
///
/// # Errors
/// The first rule broken.
pub async fn check_create(
    state: &AppState,
    manifest: &Value,
    now: DateTime<Utc>,
) -> Result<CheckedManifest, CreateError> {
    let m: Manifest = serde_json::from_value(manifest.clone())
        .map_err(|e| CreateError::InvalidManifest(e.to_string()))?;
    rules::check_manifest(&m, None).map_err(|e| match e {
        RuleError::UnsupportedSecrecy(_) => CreateError::UnsupportedSecrecy,
        RuleError::InvalidManifest(why) => CreateError::InvalidManifest(why),
        other => CreateError::InvalidManifest(other.to_string()),
    })?;
    if m.voting_closes <= now {
        return Err(CreateError::InvalidManifest(
            "votingCloses is already past".into(),
        ));
    }
    if m.community.as_str() != community_did(state).await {
        return Err(CreateError::CommunityMismatch);
    }
    if state
        .config
        .read()
        .await
        .voting
        .trusted(m.ballot_box.as_str())
        .is_none()
    {
        return Err(CreateError::BallotBoxNotTrusted);
    }
    if store::get(state.elections.ks(), m.election_id.as_str())
        .await?
        .is_some()
    {
        return Err(CreateError::ElectionExists);
    }
    let digest = rules::manifest_digest(manifest)
        .map_err(|e| CreateError::InvalidManifest(e.to_string()))?;
    Ok(CheckedManifest {
        manifest: m,
        digest,
    })
}

/// Item 8: record the election `pendingRegistration`, then deliver the registration once. The
/// answer it returns is the record as it then stands.
///
/// # Errors
/// [`CreateError::ElectionExists`] when another creation won the identifier;
/// [`CreateError::BallotBoxRefused`] when the ballot box refused (the record is discarded).
pub async fn create(
    state: &AppState,
    requester: &str,
    manifest: &Value,
    checked: CheckedManifest,
    action_id: Option<String>,
    now: DateTime<Utc>,
) -> Result<ElectionRecord, CreateError> {
    let m = &checked.manifest;
    let rec = ElectionRecord {
        election_id: m.election_id.as_str().to_string(),
        manifest: manifest.clone(),
        manifest_digest: rules::digest_multibase(&checked.digest),
        standing: Standing::PendingRegistration,
        binding: m.binding,
        ballot_box: m.ballot_box.as_str().to_string(),
        registration_opens: m.registration_opens,
        voting_opens: m.voting_opens,
        voting_closes: m.voting_closes,
        created_by: requester.to_string(),
        created_at: now,
        action_id,
        issuance_stopped: false,
        close_in_flight: false,
        tickets_issued: 0,
        delivery: Some(Delivery {
            attempts: 0,
            next_at: now,
            last_error: None,
        }),
        refusal: None,
        checkpoints: Vec::new(),
        final_checkpoint: false,
        certified: None,
        election_key: None,
        ceremony: None,
        decryption_authorized: false,
    };
    if !store::put_new(state.elections.ks(), &rec).await? {
        return Err(CreateError::ElectionExists);
    }
    match deliver_registration(state, rec, now).await? {
        Delivered::Registered(rec) | Delivered::Pending(rec) => Ok(rec),
        Delivered::Refused { rec, code, message } => {
            store::remove(state.elections.ks(), &rec.election_id).await?;
            Err(CreateError::BallotBoxRefused { code, message })
        }
    }
}

/// What one delivery of a registration came to.
pub enum Delivered {
    Registered(ElectionRecord),
    /// Not answered: kept for the next delivery, with a capped backoff.
    Pending(ElectionRecord),
    /// Refused. The record is returned as it stood; the caller decides what refusal means — on
    /// the first delivery the record is discarded, on a later one it is kept as refused.
    Refused {
        rec: ElectionRecord,
        code: String,
        message: String,
    },
}

/// First wait between deliveries, and the cap.
const DELIVERY_BASE_SECS: i64 = 30;
const DELIVERY_CAP_SECS: i64 = 3600;

fn delivery_backoff(attempts: u32) -> chrono::Duration {
    let factor = 1i64.checked_shl(attempts.min(16)).unwrap_or(i64::MAX);
    chrono::Duration::seconds(
        DELIVERY_BASE_SECS
            .saturating_mul(factor)
            .min(DELIVERY_CAP_SECS),
    )
}

/// Send `voting/election/register` for `rec`, signed as the community, and record what came of
/// it. Registration is idempotent at the ballot box for the same manifest (CONVENTIONS §8.2), so
/// a repeat delivery is safe.
///
/// # Errors
/// A store failure, or the voting key cannot be derived.
pub async fn deliver_registration(
    state: &AppState,
    mut rec: ElectionRecord,
    now: DateTime<Utc>,
) -> Result<Delivered, AppError> {
    let payload = json!({
        "community": community_did(state).await,
        "manifest": rec.manifest,
        "manifestDigest": rec.manifest_digest,
        "parameters": parameters(state).await?,
    });
    let answer = match state.elections.link() {
        Some(link) => {
            link.exchange(
                &rec.ballot_box,
                &format!("{SPEC}voting/election/register/0.1"),
                &payload,
            )
            .await
        }
        None => Err(LinkError::Unavailable(
            "this VTC has no messaging link to ballot boxes yet".into(),
        )),
    };
    let delivery = rec.delivery.take().unwrap_or(Delivery {
        attempts: 0,
        next_at: now,
        last_error: None,
    });
    let out = match answer {
        Ok(BoxAnswer::Success { .. }) => {
            rec.standing = Standing::Registered;
            rec.refusal = None;
            Delivered::Registered(rec.clone())
        }
        // A repeat of the same manifest is answered as the first (an earlier delivery whose
        // answer was lost); `alreadyRegistered` means another manifest or key, a refusal.
        Ok(BoxAnswer::Refused { code, message }) => {
            rec.delivery = None;
            Delivered::Refused {
                rec: rec.clone(),
                code,
                message,
            }
        }
        Err(e) => {
            let attempts = delivery.attempts.saturating_add(1);
            rec.delivery = Some(Delivery {
                attempts,
                next_at: now + delivery_backoff(attempts),
                last_error: Some(e.to_string()),
            });
            Delivered::Pending(rec.clone())
        }
    };
    match &out {
        Delivered::Registered(r) | Delivered::Pending(r) => {
            store::put(state.elections.ks(), r).await?
        }
        // The caller decides: discard on the first delivery, keep as refused on a later one.
        Delivered::Refused { .. } => {}
    }
    Ok(out)
}

// ─── tickets ─────────────────────────────────────────────────────────────

/// Why a ticket was refused (tickets/issue items 2 – 7).
#[derive(Debug)]
pub enum IssueError {
    ElectionUnknown,
    NotOpen,
    ManifestMismatch,
    NotEligible,
    AlreadyIssued,
    RequestInvalid(String),
    App(AppError),
}

impl From<AppError> for IssueError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

/// One request for a ticket, as received.
pub struct TicketAsk<'a> {
    pub signer: &'a str,
    pub manager: bool,
    pub election_id: &'a str,
    pub manifest_digest: &'a str,
    /// `{label, id, request}`.
    pub request: &'a Value,
    pub doc_id: &'a str,
    pub doc_digest: &'a str,
}

/// Issue a ticket blind, recording it first (tickets/issue items 1 – 10). Returns the
/// pre-credential, multibase, and whether this was a resend answered from the record.
///
/// # Errors
/// The first rule broken, in the specification's order.
pub async fn issue_ticket(
    state: &AppState,
    ask: TicketAsk<'_>,
    now: DateTime<Utc>,
) -> Result<(String, bool), IssueError> {
    let ks = state.elections.ks();
    // Item 8: one critical section for items 6 – 10.
    let _guard = state.elections.issue_lock.lock().await;

    // Item 1: a resend of the document already answered.
    if let Some(t) = store::ticket(ks, ask.election_id, ask.signer).await?
        && t.doc_id == ask.doc_id
        && t.doc_digest == ask.doc_digest
        && let Some(pre) = t.pre_credential
    {
        return Ok((pre, true));
    }

    // Item 2: unknown and unseen are the same answer.
    let Some(mut rec) = store::get(ks, ask.election_id).await? else {
        return Err(IssueError::ElectionUnknown);
    };
    if !may_see(state, &rec, ask.signer, ask.manager).await? {
        return Err(IssueError::ElectionUnknown);
    }
    // Item 3 (VTI-VOT-024).
    let open = rec.standing == Standing::Registered
        && !rec.issuance_stopped
        && !rec.close_in_flight
        && now >= rec.registration_opens
        && now < rec.voting_closes;
    if !open {
        return Err(IssueError::NotOpen);
    }
    // Item 4.
    if ask.manifest_digest != rec.manifest_digest {
        return Err(IssueError::ManifestMismatch);
    }
    // Item 5: the roll as the records stand now.
    if !roll_admits(state, &rec, ask.signer).await? {
        return Err(IssueError::NotEligible);
    }
    // Item 6 (VTI-VOT-022).
    if store::ticket(ks, ask.election_id, ask.signer)
        .await?
        .is_some()
    {
        return Err(IssueError::AlreadyIssued);
    }
    // Item 7.
    let label = format!("voter/{}", rec.election_id);
    if ask.request["label"].as_str() != Some(label.as_str()) {
        return Err(IssueError::RequestInvalid(format!(
            "the request is for {:?}, not {label}",
            ask.request["label"]
        )));
    }
    let id =
        vti_vetting_pcs::scheme::point_from_text(ask.request["id"].as_str().unwrap_or_default())
            .map_err(|e| IssueError::RequestInvalid(format!("id: {e}")))?;
    let request: vti_voting::voter::TicketRequest =
        serde_json::from_value(ask.request["request"].clone())
            .map_err(|e| IssueError::RequestInvalid(format!("request: {e}")))?;
    let digest = rules::digest_from_multibase(&rec.manifest_digest)
        .ok_or_else(|| AppError::Internal("a stored manifest digest does not decode".into()))?;
    let election = Election::new(
        &community_did(state).await,
        ElectionId::new(&rec.election_id)
            .map_err(|e| AppError::Internal(format!("a stored election id: {e}")))?,
        digest,
    )
    .map_err(|e| AppError::Internal(format!("election: {e}")))?;

    // Item 9: blind.
    let reg = registrar(state).await?;
    let pre = reg
        .issue_ticket(&election, &id, &request, &mut vti_voting::rand::rngs::OsRng)
        .map_err(|e| IssueError::RequestInvalid(e.to_string()))?;
    let pre = vti_vetting_pcs::scheme::enc(&pre)
        .map_err(|e| AppError::Internal(format!("encode the pre-credential: {e}")))?;

    // Item 10: record before answering.
    let ticket = TicketIssued {
        election_id: rec.election_id.clone(),
        signer: ask.signer.to_string(),
        issued_at: now,
        doc_id: ask.doc_id.to_string(),
        doc_digest: ask.doc_digest.to_string(),
        pre_credential: Some(pre.clone()),
    };
    if !store::put_ticket(ks, &ticket).await? {
        return Err(IssueError::AlreadyIssued);
    }
    rec.tickets_issued = rec.tickets_issued.saturating_add(1);
    store::put(ks, &rec).await?;
    Ok((pre, false))
}

// ─── close and cancel ────────────────────────────────────────────────────

/// Why a close or cancel was refused.
#[derive(Debug)]
pub enum EndError {
    ElectionUnknown,
    NotOpen,
    EarlyCloseNotAllowed,
    BallotBoxUnavailable(String),
    BallotBoxRefused { code: String, message: String },
    App(AppError),
}

impl From<AppError> for EndError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

/// Close `election_id` early (close items 2 – 5). Returns the ballot box's state.
///
/// # Errors
/// As the close specification lists.
pub async fn close(
    state: &AppState,
    election_id: &str,
    reason: Option<&str>,
    now: DateTime<Utc>,
) -> Result<String, EndError> {
    let ks = state.elections.ks();
    let Some(mut rec) = store::get(ks, election_id).await? else {
        return Err(EndError::ElectionUnknown);
    };
    if rec.state(now) != "voting" {
        return Err(EndError::NotOpen);
    }
    if !rec.manifest["allowEarlyClose"].as_bool().unwrap_or(false) {
        return Err(EndError::EarlyCloseNotAllowed);
    }
    // Item 4: no ticket while the close is in flight.
    rec.close_in_flight = true;
    store::put(ks, &rec).await?;
    let mut payload = json!({ "community": community_did(state).await, "electionId": election_id });
    if let Some(r) = reason {
        payload["reason"] = json!(r);
    }
    let answer = exchange(state, &rec.ballot_box, "voting/election/close", &payload).await;
    let mut rec = store::get(ks, election_id).await?.unwrap_or(rec);
    rec.close_in_flight = false;
    match answer {
        Ok(BoxAnswer::Success { payload, .. }) => {
            rec.standing = Standing::Closed;
            store::put(ks, &rec).await?;
            // Item 5: keep the final head.
            checkpoint(state, election_id, true).await;
            Ok(payload["election"]["state"]
                .as_str()
                .unwrap_or("closed")
                .to_string())
        }
        Ok(BoxAnswer::Refused { code, message }) => {
            store::put(ks, &rec).await?;
            Err(EndError::BallotBoxRefused { code, message })
        }
        Err(e) => {
            store::put(ks, &rec).await?;
            Err(EndError::BallotBoxUnavailable(e.to_string()))
        }
    }
}

/// Cancel `election_id` (cancel items 2 – 5). Returns the ballot box's state.
///
/// # Errors
/// As the cancel specification lists.
pub async fn cancel(
    state: &AppState,
    election_id: &str,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<String, EndError> {
    let ks = state.elections.ks();
    let Some(mut rec) = store::get(ks, election_id).await? else {
        return Err(EndError::ElectionUnknown);
    };
    if matches!(rec.state(now), "closed" | "tallied" | "cancelled") {
        return Err(EndError::NotOpen);
    }
    // Item 3: stop issuing, durably, before anything else; item 5: stop delivering.
    let unregistered = !rec.is_registered();
    rec.issuance_stopped = true;
    rec.delivery = None;
    store::put(ks, &rec).await?;
    let payload = json!({
        "community": community_did(state).await,
        "electionId": election_id,
        "reason": reason,
    });
    match exchange(state, &rec.ballot_box, "voting/election/cancel", &payload).await {
        Ok(BoxAnswer::Success { payload, .. }) => {
            rec.standing = Standing::Cancelled;
            store::put(ks, &rec).await?;
            Ok(payload["election"]["state"]
                .as_str()
                .unwrap_or("cancelled")
                .to_string())
        }
        // Item 5: nothing at the ballot box to cancel.
        Ok(BoxAnswer::Refused { code, .. })
            if unregistered && code.ends_with(":electionUnknown") =>
        {
            rec.standing = Standing::Cancelled;
            store::put(ks, &rec).await?;
            Ok("cancelled".to_string())
        }
        Ok(BoxAnswer::Refused { code, message }) => {
            Err(EndError::BallotBoxRefused { code, message })
        }
        Err(e) => Err(EndError::BallotBoxUnavailable(e.to_string())),
    }
}

/// Read the ballot box's head and keep it, with the signed document that carried it (show item
/// 5); `final_head` when voting has closed, so it is the head certification ends at. Best effort:
/// a head that cannot be read is skipped, and the sweeper takes it on a later pass.
pub async fn checkpoint(state: &AppState, election_id: &str, final_head: bool) {
    let ks = state.elections.ks();
    let Ok(Some(rec)) = store::get(ks, election_id).await else {
        return;
    };
    let payload = json!({ "community": community_did(state).await, "electionId": election_id });
    let Ok(BoxAnswer::Success { payload, document }) =
        exchange(state, &rec.ballot_box, "voting/board/head", &payload).await
    else {
        return;
    };
    let head = payload["head"].clone();
    // Re-read: a close or a certify may have written meanwhile.
    let Ok(Some(mut rec)) = store::get(ks, election_id).await else {
        return;
    };
    let repeat = rec.checkpoints.last().is_some_and(|c| c["head"] == head);
    if !repeat {
        // At most 256 kept; the final head always is, in place of the oldest after the first
        // if need be — it is the one certification ends at.
        if rec.checkpoints.len() >= 256 && final_head {
            rec.checkpoints.remove(1);
        }
        if rec.checkpoints.len() < 256 {
            rec.checkpoints
                .push(json!({ "head": head, "document": document }));
        }
    }
    rec.final_checkpoint |= final_head;
    if let Err(e) = store::put(ks, &rec).await {
        tracing::warn!(election = election_id, error = %e, "could not keep a board checkpoint");
    }
}

/// Form a sealed or tallied-encrypted election's key from the board and keep it, so voters who
/// cannot read a private board get it from `show` (show item 6, CONVENTIONS §9.6). The community
/// reads the board through its `electionKey` entry and replays the ceremony from the trustees'
/// own signed steps, each proof verified here: a key is kept only when the entry states the key
/// that replay forms. Nothing the ballot box asserts is believed — a key it holds can only come
/// from steps no trustee signed, and those do not count.
pub async fn read_election_key(state: &AppState, election_id: &str) {
    let ks = state.elections.ks();
    let Ok(Some(rec)) = store::get(ks, election_id).await else {
        return;
    };
    if rec.election_key.is_some() || rec.manifest.get("trustees").is_none() {
        return;
    }
    let community = community_did(state).await;
    let sel = json!({ "community": community, "electionId": election_id });
    let Ok((_, entries)) = read_board(state, &rec.ballot_box, &sel).await else {
        return;
    };
    let proven = prove_trustee_steps(state, &entries).await;
    let key = match vti_voting::audit::election_key(&rec.manifest, &community, &entries, &proven) {
        Ok(Some(key)) => key,
        Ok(None) => return,
        Err(why) => {
            tracing::warn!(election = election_id, %why, "the board's key ceremony does not hold; no election key kept");
            return;
        }
    };
    // The steps the key forms from, for voters' VTAs to form it themselves (show item 6).
    let ceremony: Vec<Value> = entries
        .iter()
        .take_while(|e| e["kind"] != "electionKey")
        .filter(|e| e["kind"] == vti_voting::steps::KIND)
        .map(|e| e["request"].clone())
        .collect();
    // Re-read: a close or a certify may have written meanwhile.
    let Ok(Some(mut rec)) = store::get(ks, election_id).await else {
        return;
    };
    rec.election_key = Some(key);
    rec.ceremony = Some(Value::Array(ceremony));
    if let Err(e) = store::put(ks, &rec).await {
        tracing::warn!(election = election_id, error = %e, "could not keep the election key");
    }
}

/// Authorize the decryption of a closed sealed or tallied-encrypted election (CONVENTIONS §9.7):
/// read the board, check it through its closing entry as certification does, compute the targets
/// here, and send their digest under the closing head. A trustee's VTA decrypts nothing else, so
/// a ballot box cannot ask the trustees to open one voter's ballot. Best effort: the sweeper calls
/// it again until the ballot box has accepted it.
pub async fn authorize_decryption(state: &AppState, election_id: &str) {
    let ks = state.elections.ks();
    let Ok(Some(rec)) = store::get(ks, election_id).await else {
        return;
    };
    if rec.decryption_authorized || rec.manifest.get("trustees").is_none() {
        return;
    }
    let community = community_did(state).await;
    let sel = json!({ "community": community, "electionId": election_id });
    let Ok((_, entries)) = read_board(state, &rec.ballot_box, &sel).await else {
        return;
    };
    let proven = prove_trustee_steps(state, &entries).await;
    let Ok(reg) = registrar(state).await else {
        return;
    };
    let closing = match vti_voting::audit::decryption(
        &rec.manifest,
        &reg.params(),
        &entries,
        &proven,
    ) {
        Ok(Some(c)) => c,
        Ok(None) => return,
        Err(why) => {
            tracing::warn!(election = election_id, %why, "the closed board does not hold; decryption not authorized");
            return;
        }
    };
    let size = closing.index as usize + 1;
    let mut board = vti_voting::board::Board::new();
    for e in &entries[..size.min(entries.len())] {
        let Ok(bytes) = serde_json_canonicalizer::to_vec(e) else {
            return;
        };
        board.append(&bytes);
    }
    let Ok(root) = board.root(size) else {
        return;
    };
    let values = closing.target_values();
    let Ok(digest) = vti_voting::audit::targets_digest(&values) else {
        return;
    };
    let payload = json!({
        "community": community,
        "electionId": election_id,
        "manifestDigest": rec.manifest_digest,
        // Fixed by the board alone, so a resend is the same request.
        "head": { "electionId": election_id, "treeSize": size,
                  "rootHash": rules::digest_multibase(&root), "issuedAt": closing.at },
        "closedAt": closing.at,
        "targetCount": values.len(),
        "targetsDigest": digest,
    });
    match exchange(
        state,
        &rec.ballot_box,
        "voting/trustees/authorize",
        &payload,
    )
    .await
    {
        Ok(BoxAnswer::Success { .. }) => {}
        Ok(BoxAnswer::Refused { code, message }) => {
            tracing::warn!(election = election_id, %code, %message, "the ballot box refused the decryption authorization");
            return;
        }
        Err(e) => {
            tracing::warn!(election = election_id, error = %e, "could not authorize the decryption yet");
            return;
        }
    }
    let Ok(Some(mut rec)) = store::get(ks, election_id).await else {
        return;
    };
    rec.decryption_authorized = true;
    if let Err(e) = store::put(ks, &rec).await {
        tracing::warn!(election = election_id, error = %e, "could not record the decryption authorization");
    }
}

/// The signer of each trustee step on a board: the DID its request's proof verifies as
/// (framework SPEC §4.7), resolved here. A request whose proof does not verify is not vouched
/// for, and the audit refuses its step (CONVENTIONS §9.6 item 4).
async fn prove_trustee_steps(state: &AppState, entries: &[Value]) -> ProvenRequests {
    let resolver = state.trust_task_vm_resolver();
    let resolver = &resolver;
    ProvenRequests::prove(entries, |request| async move {
        vti_common::auth::verify_trust_task_proof_value(&request, resolver)
            .await
            .ok()
    })
    .await
}

/// The ballot box's current head and every entry under it, read from the ballot box itself.
async fn read_board(
    state: &AppState,
    ballot_box: &str,
    sel: &Value,
) -> Result<(Value, Vec<Value>), CertifyError> {
    let unavailable = |e: LinkError| CertifyError::BallotBoxUnavailable(e.to_string());
    let head = match exchange(state, ballot_box, "voting/board/head", sel).await {
        Ok(BoxAnswer::Success { payload, .. }) => payload["head"].clone(),
        Ok(BoxAnswer::Refused { message, .. }) => {
            return Err(CertifyError::BallotBoxUnavailable(message));
        }
        Err(e) => return Err(unavailable(e)),
    };
    let tree_size = vti_voting::audit::HeadRef::from_wire(&head)
        .map_err(|e| CertifyError::BallotBoxUnavailable(e.to_string()))?
        .tree_size;
    let mut entries: Vec<Value> = Vec::new();
    while (entries.len() as u64) < tree_size {
        let mut page = sel.clone();
        page["from"] = json!(entries.len());
        page["limit"] = json!(READ_PAGE);
        page["treeSize"] = json!(tree_size);
        let read = match exchange(state, ballot_box, "voting/board/read", &page).await {
            Ok(BoxAnswer::Success { payload, .. }) => payload,
            Ok(BoxAnswer::Refused { message, .. }) => {
                return Err(CertifyError::BallotBoxUnavailable(message));
            }
            Err(e) => return Err(unavailable(e)),
        };
        let got = read["entries"].as_array().cloned().unwrap_or_default();
        if got.is_empty() {
            return Err(CertifyError::BallotBoxUnavailable(
                "the board read returned no entries".into(),
            ));
        }
        entries.extend(got.into_iter().map(|e| e["entry"].clone()));
    }
    Ok((head, entries))
}

// ─── certify ─────────────────────────────────────────────────────────────

/// Why a certification was refused (certify items 2 – 10).
#[derive(Debug)]
pub enum CertifyError {
    ElectionUnknown,
    NotTallied,
    AlreadyCertified,
    BallotBoxUnavailable(String),
    /// `boardInconsistent`, with its `details`.
    BoardInconsistent(Value),
    CastInvalid(u64),
    ResultMismatch(String),
    CountExceedsTickets {
        counted: u64,
        issued: u64,
    },
    AuditAttestationInvalid {
        index: usize,
        reason: String,
    },
    App(AppError),
}

impl From<AppError> for CertifyError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

/// What a certification recorded.
pub struct Certified {
    pub result: Value,
    pub head: Value,
    pub certified_at: DateTime<Utc>,
    pub attestations: Vec<Value>,
    pub attestation_issuers: Vec<String>,
}

/// The most entries one `voting/board/read` asks for.
const READ_PAGE: u64 = 1000;

/// Certify `election_id`: read the result, the head and every entry from the ballot box itself —
/// never from the requester — verify the board from the community's own voting key, check each
/// auditor's attestation, and only then record (certify items 2 – 11).
///
/// # Errors
/// As the certify specification lists, the first failure found.
pub async fn certify(
    state: &AppState,
    election_id: &str,
    attestations: &[Value],
    now: DateTime<Utc>,
) -> Result<Certified, CertifyError> {
    use vti_voting::audit::{AuditFailure, Evidence, HeadRef};
    let ks = state.elections.ks();
    let Some(rec) = store::get(ks, election_id).await? else {
        return Err(CertifyError::ElectionUnknown);
    };
    // Item 2.
    if rec.certified.is_some() {
        return Err(CertifyError::AlreadyCertified);
    }
    if !rec.is_registered() {
        return Err(CertifyError::NotTallied);
    }
    let community = community_did(state).await;
    let sel = json!({ "community": community, "electionId": election_id });
    let unavailable = |e: LinkError| CertifyError::BallotBoxUnavailable(e.to_string());

    // Item 3: the result, the head, every entry under it.
    let result = match exchange(state, &rec.ballot_box, "voting/result/show", &sel).await {
        Ok(BoxAnswer::Success { payload, .. })
            if payload["state"] == "tallied" && payload["provisional"] == false =>
        {
            payload["result"].clone()
        }
        Ok(_) => return Err(CertifyError::NotTallied),
        Err(e) => return Err(unavailable(e)),
    };
    let (head, entries) = read_board(state, &rec.ballot_box, &sel).await?;
    let final_head =
        HeadRef::from_wire(&head).map_err(|e| CertifyError::BallotBoxUnavailable(e.to_string()))?;
    // Item 8, the encrypted levels: every trustee step is verified as its trustee's.
    let proven = prove_trustee_steps(state, &entries).await;

    // Items 4 – 9.
    let checkpoints: Vec<HeadRef> = rec
        .checkpoints
        .iter()
        .filter_map(|c| HeadRef::from_wire(&c["head"]).ok())
        .collect();
    let reg = registrar(state).await?;
    let params = reg.params();
    vti_voting::audit::audit(Evidence {
        manifest: &rec.manifest,
        params: &params,
        entries: &entries,
        head: final_head,
        checkpoints: &checkpoints,
        result: &result,
        tickets_issued: rec.tickets_issued,
        proven: &proven,
    })
    .map_err(|f| match f {
        AuditFailure::RootMismatch => {
            CertifyError::BoardInconsistent(json!({ "fault": "rootMismatch" }))
        }
        AuditFailure::CheckpointInconsistent { tree_size } => CertifyError::BoardInconsistent(
            json!({ "fault": "checkpointInconsistent", "checkpointTreeSize": tree_size }),
        ),
        AuditFailure::TagRepeated { index } => {
            CertifyError::BoardInconsistent(json!({ "fault": "tagRepeated", "index": index }))
        }
        AuditFailure::ReplacementInvalid { index, .. } => CertifyError::BoardInconsistent(
            json!({ "fault": "replacementInvalid", "index": index }),
        ),
        AuditFailure::OrderInvalid { index, .. } => {
            CertifyError::BoardInconsistent(json!({ "fault": "orderInvalid", "index": index }))
        }
        AuditFailure::CeremonyInvalid { index, .. } => {
            CertifyError::BoardInconsistent(json!({ "fault": "ceremonyInvalid", "index": index }))
        }
        AuditFailure::CastInvalid { index, .. } => CertifyError::CastInvalid(index),
        AuditFailure::CountExceedsTickets { counted, issued } => {
            CertifyError::CountExceedsTickets { counted, issued }
        }
        AuditFailure::ResultMismatch(why) => CertifyError::ResultMismatch(why),
        other => CertifyError::ResultMismatch(other.to_string()),
    })?;

    // Item 10: each attestation, beside the community's own verification, never instead of it.
    let counted_head = result["head"].clone();
    let auditors: Vec<&str> = rec.manifest["board"]["auditors"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let resolver = crate::credentials::vm_resolver::DidVmResolver::new(state.did_resolver.clone());
    let mut issuers = Vec::with_capacity(attestations.len());
    for (index, vc) in attestations.iter().enumerate() {
        let bad = |reason: String| CertifyError::AuditAttestationInvalid { index, reason };
        let issuer = vc["issuer"]
            .as_str()
            .or_else(|| vc["issuer"]["id"].as_str())
            .ok_or_else(|| bad("it names no issuer".into()))?;
        if !auditors.contains(&issuer) {
            return Err(bad(format!(
                "{issuer} is not an auditor the manifest names"
            )));
        }
        crate::credentials::proof_set::verify_issued(vc, issuer, &resolver)
            .await
            .map_err(bad)?;
        // The subject names the election, the community and the head the result counts; a
        // manifest digest, where it names one, must be this election's.
        let subject = &vc["credentialSubject"];
        let attests = subject["electionId"] == election_id
            && subject["community"] == community.as_str()
            && subject["treeSize"] == counted_head["treeSize"]
            && subject["rootHash"] == counted_head["rootHash"]
            && subject
                .get("manifestDigest")
                .is_none_or(|d| d == rec.manifest_digest.as_str());
        if !attests {
            return Err(bad(
                "it does not attest this election's result at the verified head".into(),
            ));
        }
        issuers.push(issuer.to_string());
    }

    // Item 11: record, then answer.
    let mut rec = store::get(ks, election_id)
        .await?
        .ok_or(CertifyError::ElectionUnknown)?;
    if rec.certified.is_some() {
        return Err(CertifyError::AlreadyCertified);
    }
    rec.certified = Some(json!({
        "result": result,
        "certifiedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "auditAttestations": attestations,
    }));
    rec.standing = Standing::Tallied;
    store::put(ks, &rec).await?;
    Ok(Certified {
        result,
        head: counted_head,
        certified_at: now,
        attestations: attestations.to_vec(),
        attestation_issuers: issuers,
    })
}

async fn exchange(
    state: &AppState,
    ballot_box: &str,
    task: &str,
    payload: &Value,
) -> Result<BoxAnswer, LinkError> {
    // Every request to a ballot box goes to one this community still trusts (VTI-VOT-082): a box
    // dropped from the list after an election was created is sent nothing more.
    if state
        .config
        .read()
        .await
        .voting
        .trusted(ballot_box)
        .is_none()
    {
        return Err(LinkError::Unavailable(format!(
            "{ballot_box} is no longer a ballot box this community trusts"
        )));
    }
    match state.elections.link() {
        Some(link) => {
            link.exchange(ballot_box, &format!("{SPEC}{task}/0.1"), payload)
                .await
        }
        None => Err(LinkError::Unavailable(
            "this VTC has no messaging link to ballot boxes".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_delivery_backoff_grows_to_its_cap() {
        assert_eq!(delivery_backoff(0).num_seconds(), DELIVERY_BASE_SECS);
        assert_eq!(delivery_backoff(1).num_seconds(), DELIVERY_BASE_SECS * 2);
        assert_eq!(delivery_backoff(40).num_seconds(), DELIVERY_CAP_SECS);
    }
}
