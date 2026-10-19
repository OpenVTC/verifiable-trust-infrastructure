//! The **voter** role of the PCS engine (`vta/pcs/voter/*`, `vta/pcs/vote`) — operations layer.
//!
//! The third member-side role beside vetter and applicant: the VTA holds its principal's voter
//! key for each election, unblinds the ticket the community issues, and builds the cast — so a
//! client with no PCS implementation can vote, and never holds a key or a ticket
//! (VTI-VOT-020 – 033; conventions `voting/_shared/0.1/CONVENTIONS.md` in trust-tasks-tf).
//!
//! - **A key per election.** The first `voter/register` for a (context, community, election)
//!   allocates a fresh path under the context's base (VTI-VOT-023, VTI-KEY-030); the key is
//!   re-derived from it on every use and never stored.
//! - **No secret leaves.** The blinding state, the ticket and the one-time key that signs a cast
//!   are never returned (conventions §5.1). The cast document is returned whole and signed; the
//!   client sends it from its own connection (VTI-VOT-003, VTI-VOT-033).
//! - **Receipts are checked, not trusted.** A receipt counts only if the ballot box signed it
//!   and it names a cast this engine built (by its board leaf hash), and an inclusion proof is
//!   checked against a head the community kept (VTI-VOT-053).
//!
//! Records (`pcs_engine` keyspace, beside the vetter and applicant records):
//!
//! | Key | Value |
//! |---|---|
//! | `voter:<digest(context, community, election)>` | [`VoterRecord`] — public |
//! | `secret:voter:…` | the wrapped [`VoterState`]: blinding state, ticket, receipts |

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::voting::{
    ballot::cast::v0_1 as cast, election::register::v0_1 as register,
};
use vti_voting::{
    board,
    election::{Election, ElectionId},
    rules::{self, RuleError},
    scheme::{Hvk, VotingParams},
    voter::{Ticket, TicketState, Voter},
};
use zeroize::Zeroizing;

use super::pcs::{
    Caller, PcsError, Result, allocate_member_path, load_secret_json, member_seed, proto,
    store_secret_json, write_lock,
};
use crate::error::AppError;
use crate::server::AppState;

const VOTER_STATE_TYPE: &str = "pcs-voter-state";
const SUITE: &str = "ps-ddh-bls12381";
const CAST_TYPE: &str = "https://trusttasks.org/spec/voting/ballot/cast/0.1#request";
const RECEIPT_TYPE: &str = "https://trusttasks.org/spec/voting/ballot/cast/0.1#response";
const HEAD_TYPE: &str = "https://trusttasks.org/spec/voting/board/head/0.1#response";

/// A voter engine's public record: one per (context, community, election).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoterRecord {
    pub context_id: String,
    pub community: String,
    pub election_id: String,
    /// The registered manifest's digest, multibase multihash.
    pub manifest_digest: String,
    pub voting_key: String,
    pub ballot_box: String,
    pub voting_closes: DateTime<Utc>,
    pub suite: String,
    /// The derivation path of this election's voter key, under the context's base.
    pub path: String,
    pub seed_id: u32,
    /// The voter's PCS identifier — public (the registrar sees it in the request).
    pub id: String,
    /// The ticket request as sent: answered again unchanged until the ticket is held, so the
    /// community's replayed answer can still be unblinded.
    pub request: Value,
    pub ticket_held: bool,
    /// The board leaf hash of every cast this engine built, multibase — how a receipt is
    /// recognised as this voter's without recomputing the tag.
    #[serde(default)]
    pub cast_leaves: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// The wrapped state: as secret as the key.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct VoterState {
    /// The blinding state of the request in flight, multibase.
    #[serde(default)]
    blinding: Option<String>,
    /// The ticket, multibase.
    #[serde(default)]
    ticket: Option<String>,
    /// Receipts as received, kept whole: each carries a bearer token for a private board.
    #[serde(default)]
    receipts: Vec<Value>,
}

/// Written by hand: a derived `Debug` would print the ticket.
impl std::fmt::Debug for VoterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoterState")
            .field("blinding", &self.blinding.as_ref().map(|_| "<redacted>"))
            .field("ticket", &self.ticket.as_ref().map(|_| "<redacted>"))
            .field("receipts", &self.receipts.len())
            .finish()
    }
}

fn voter_key(context_id: &str, community: &str, election_id: &str) -> String {
    let mut h = Sha256::new();
    for f in [context_id, community, election_id] {
        h.update((f.len() as u64).to_be_bytes());
        h.update(f.as_bytes());
    }
    format!("voter:{}", hex::encode(h.finalize()))
}

fn malformed(why: impl Into<String>) -> PcsError {
    PcsError::App(AppError::Validation(why.into()))
}

/// The community's published voting parameters, read and checked.
fn voting_params(community: &str, published: &Value) -> Result<(VotingParams, String)> {
    let suite = published
        .get("suite")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if suite != SUITE {
        return Err(PcsError::UnsupportedSuite(suite.to_string()));
    }
    let key = published
        .get("votingKey")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let hvk: Hvk = vti_vetting_pcs::scheme::dec(&key)
        .map_err(|e| PcsError::ParametersInvalid(e.to_string()))?;
    let params = VotingParams::new(community, hvk)
        .map_err(|e| PcsError::ParametersInvalid(e.to_string()))?;
    Ok((params, key))
}

fn rule(e: RuleError) -> PcsError {
    match e {
        RuleError::ManifestMismatch => PcsError::ManifestMismatch,
        RuleError::BallotInvalid(why) => PcsError::BallotInvalid(why),
        RuleError::UnsupportedSecrecy(s) => PcsError::UnsupportedSecrecy(s),
        other => malformed(other.to_string()),
    }
}

async fn record(state: &AppState, key: &str) -> Result<Option<VoterRecord>> {
    Ok(state.pcs_engine_ks.get(key.to_string()).await?)
}

async fn voter(
    state: &AppState,
    caller: &Caller<'_>,
    r: &VoterRecord,
    params: &VotingParams,
) -> Result<Voter> {
    let seed = member_seed(state, caller, &r.context_id, &r.path, r.seed_id).await?;
    Voter::from_seed(params, &seed)
        .map_err(|e| PcsError::App(AppError::Internal(format!("voter key: {e}"))))
}

fn election_of(r: &VoterRecord) -> Result<Election> {
    let digest = rules::digest_from_multibase(&r.manifest_digest)
        .ok_or_else(|| PcsError::App(AppError::Internal("stored manifest digest".into())))?;
    let id = ElectionId::new(&r.election_id).map_err(|e| malformed(e.to_string()))?;
    Election::new(&r.community, id, digest).map_err(|e| malformed(e.to_string()))
}

/// `vta/pcs/voter/register`: the blinded ticket request under this election's voter key,
/// creating the key on first use.
pub async fn register(
    state: &AppState,
    caller: &Caller<'_>,
    context_id: &str,
    community: &str,
    published: &Value,
    manifest_value: &Value,
) -> Result<Value> {
    let (params, voting_key) = voting_params(community, published)?;
    let manifest: register::Manifest = serde_json::from_value(manifest_value.clone())
        .map_err(|e| malformed(format!("manifest: {e}")))?;
    if manifest.community.as_str() != community {
        return Err(malformed("the manifest names another community"));
    }
    if manifest.secrecy != register::SecrecyLevel::Open {
        return Err(PcsError::UnsupportedSecrecy(manifest.secrecy.to_string()));
    }
    let digest = rules::manifest_digest(manifest_value).map_err(rule)?;
    let digest_text = rules::digest_multibase(&digest);
    let election_id = manifest.election_id.as_str().to_string();
    let key = voter_key(context_id, community, &election_id);

    let _guard = write_lock().await;
    if let Some(existing) = record(state, &key).await? {
        if existing.manifest_digest != digest_text || existing.voting_key != voting_key {
            return Err(PcsError::ElectionChanged);
        }
        if existing.ticket_held {
            return Err(PcsError::TicketHeld);
        }
        return Ok(json!({
            "electionId": election_id,
            "manifestDigest": digest_text,
            "request": existing.request,
        }));
    }

    let (path, seed_id) = allocate_member_path(state, context_id).await?;
    let seed = member_seed(state, caller, context_id, &path, seed_id).await?;
    let v = Voter::from_seed(&params, &seed)
        .map_err(|e| PcsError::App(AppError::Internal(format!("voter key: {e}"))))?;
    let election = Election::new(
        community,
        ElectionId::new(&election_id).map_err(|e| malformed(e.to_string()))?,
        digest,
    )
    .map_err(|e| malformed(e.to_string()))?;
    let mut rng = vti_voting::rand::rngs::OsRng;
    let (req, blinding) = v
        .ticket_request(&params, &election, &mut rng)
        .map_err(|e| PcsError::App(AppError::Internal(format!("ticket request: {e}"))))?;
    let blinding = predicate_credential_system::serialization::to_multibase(
        &blinding.to_bytes().map_err(|e| proto(e.into()))?,
    );
    let request = json!({
        "label": format!("voter/{election_id}"),
        "id": vti_voting::scheme::point_text(v.id()).map_err(proto)?,
        "request": serde_json::to_value(&req).map_err(|e| AppError::Internal(e.to_string()))?,
    });
    let rec = VoterRecord {
        context_id: context_id.to_string(),
        community: community.to_string(),
        election_id: election_id.clone(),
        manifest_digest: digest_text.clone(),
        voting_key,
        ballot_box: manifest.ballot_box.as_str().to_string(),
        voting_closes: manifest.voting_closes,
        suite: SUITE.to_string(),
        path,
        seed_id,
        id: request["id"].as_str().unwrap_or_default().to_string(),
        request: request.clone(),
        ticket_held: false,
        cast_leaves: Vec::new(),
        created_at: Utc::now(),
    };
    store_secret_json(
        state,
        &key,
        VOTER_STATE_TYPE,
        seed_id,
        &VoterState {
            blinding: Some(blinding),
            ..VoterState::default()
        },
    )
    .await?;
    state.pcs_engine_ks.insert(key, &rec).await?;
    Ok(json!({ "electionId": election_id, "manifestDigest": digest_text, "request": request }))
}

/// `vta/pcs/voter/accept`: unblind the community's answer into the ticket and keep it wrapped.
pub async fn accept(
    state: &AppState,
    caller: &Caller<'_>,
    context_id: &str,
    community: &str,
    election_id: &str,
    published: &Value,
    answer: &Value,
) -> Result<Value> {
    let (params, voting_key) = voting_params(community, published)?;
    let label = answer["label"].as_str().unwrap_or_default();
    if answer["electionId"].as_str() != Some(election_id) || label != format!("voter/{election_id}")
    {
        return Err(malformed("the answer is for another election"));
    }
    let key = voter_key(context_id, community, election_id);
    let _guard = write_lock().await;
    let mut rec = record(state, &key).await?.ok_or(PcsError::NotFound)?;
    if rec.voting_key != voting_key {
        return Err(PcsError::ParametersInvalid(
            "another voting key than registered".into(),
        ));
    }
    let mut st: VoterState = load_secret_json(state, &key, VOTER_STATE_TYPE, rec.seed_id).await?;
    let Some(encoded) = st.blinding.clone() else {
        return Err(PcsError::NoRequestInFlight);
    };
    let bytes = Zeroizing::new(
        predicate_credential_system::serialization::from_multibase(&encoded)
            .map_err(|e| proto(e.into()))?,
    );
    let blinding = TicketState::from_bytes(&bytes).map_err(|e| proto(e.into()))?;
    let pre = vti_vetting_pcs::scheme::dec(answer["preCredential"].as_str().unwrap_or_default())
        .map_err(|e| PcsError::CredentialInvalid(e.to_string()))?;
    let election = election_of(&rec)?;
    let v = voter(state, caller, &rec, &params).await?;
    let ticket = v
        .accept_ticket(&params, &election, &pre, &blinding)
        .map_err(|e| PcsError::CredentialInvalid(e.to_string()))?;
    st.ticket = Some(
        ticket
            .to_text()
            .map_err(|e| PcsError::App(AppError::Internal(e.to_string())))?,
    );
    st.blinding = None;
    store_secret_json(state, &key, VOTER_STATE_TYPE, rec.seed_id, &st).await?;
    rec.ticket_held = true;
    state.pcs_engine_ks.insert(key, &rec).await?;
    Ok(json!({ "electionId": election_id, "ticketHeld": true }))
}

/// `vta/pcs/vote`: validate the ballot, build the cast, sign it as a key made for this cast
/// alone, and return the document for the client to send.
#[allow(clippy::too_many_arguments)]
pub async fn vote(
    state: &AppState,
    caller: &Caller<'_>,
    context_id: &str,
    community: &str,
    published: &Value,
    manifest_value: &Value,
    ballot_value: &Value,
    now: DateTime<Utc>,
) -> Result<Value> {
    let (params, voting_key) = voting_params(community, published)?;
    let manifest: register::Manifest = serde_json::from_value(manifest_value.clone())
        .map_err(|e| malformed(format!("manifest: {e}")))?;
    let ballot: cast::Ballot = serde_json::from_value(ballot_value.clone())
        .map_err(|e| malformed(format!("ballot: {e}")))?;
    let election_id = manifest.election_id.as_str().to_string();
    let key = voter_key(context_id, community, &election_id);

    let _guard = write_lock().await;
    let mut rec = record(state, &key).await?.ok_or(PcsError::NotFound)?;
    if rec.voting_key != voting_key {
        return Err(PcsError::ParametersInvalid(
            "another voting key than registered".into(),
        ));
    }
    let digest = rules::manifest_digest(manifest_value).map_err(rule)?;
    if rules::digest_multibase(&digest) != rec.manifest_digest {
        return Err(PcsError::ManifestMismatch);
    }
    rules::check_ballot(&manifest, &digest, &ballot).map_err(rule)?;
    if now < manifest.voting_opens || now >= manifest.voting_closes {
        return Err(PcsError::NotOpen);
    }
    let st: VoterState = load_secret_json(state, &key, VOTER_STATE_TYPE, rec.seed_id).await?;
    let Some(ticket_text) = st.ticket else {
        return Err(PcsError::NotFound);
    };
    let ticket = Ticket::from_text(election_of(&rec)?, &ticket_text)
        .map_err(|e| PcsError::App(AppError::Internal(e.to_string())))?;
    let v = voter(state, caller, &rec, &params).await?;
    let mut rng = vti_voting::rand::rngs::OsRng;
    let cast = v
        .cast_wire(&params, &ticket, ballot_value, &mut rng)
        .map_err(|e| PcsError::App(AppError::Internal(format!("cast: {e}"))))?;

    let document = sign_as_one_time_key(&rec, &cast, now).await?;
    let entry = serde_json::to_vec(&json!({ "kind": "cast", "cast": cast }))
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let entry_jcs = serde_json_canonicalizer::to_vec(
        &serde_json::from_slice::<Value>(&entry).map_err(|e| AppError::Internal(e.to_string()))?,
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;
    rec.cast_leaves
        .push(rules::digest_multibase(&board::leaf_hash(&entry_jcs)));
    state.pcs_engine_ks.insert(key, &rec).await?;
    Ok(json!({ "castDocument": document, "tag": cast["tag"] }))
}

/// The `voting/ballot/cast` request, signed by a `did:key` made here and dropped here: no
/// record of it outlives this call (VTI-VOT-003).
async fn sign_as_one_time_key(
    rec: &VoterRecord,
    cast: &Value,
    now: DateTime<Utc>,
) -> Result<Value> {
    let mut seed = Zeroizing::new([0u8; 32]);
    vti_voting::rand::RngCore::fill_bytes(&mut vti_voting::rand::rngs::OsRng, &mut *seed);
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&public)
    );
    let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(
        &did,
        multibase::encode(multibase::Base::Base58Btc, *seed),
    )
    .map_err(|e| AppError::Internal(format!("one-time key: {e}")))?;
    let doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": CAST_TYPE,
        "issuer": did,
        "recipient": rec.ballot_box,
        "issuedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "expiresAt": rec.voting_closes.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": { "community": rec.community, "electionId": rec.election_id, "cast": cast },
    });
    let mut typed: TrustTask<Value> =
        serde_json::from_value(doc).map_err(|e| AppError::Internal(e.to_string()))?;
    vta_sdk::trust_task_sign::sign_in_place_with(&mut typed, &key)
        .await
        .map_err(|e| AppError::Internal(format!("signing the cast: {e}")))?;
    Ok(serde_json::to_value(&typed).map_err(|e| AppError::Internal(e.to_string()))?)
}

/// The issuer a received document's proof verifies as, over the document as received.
async fn proven_issuer(state: &AppState, doc: &Value) -> std::result::Result<String, String> {
    let signer =
        vti_common::auth::verify_trust_task_proof_value(doc, &state.trust_task_vm_resolver())
            .await
            .map_err(|e| e.to_string())?;
    if doc["issuer"].as_str() != Some(signer.as_str()) {
        return Err("the proof is not the issuer's".into());
    }
    Ok(signer)
}

/// `vta/pcs/voter/receipt`: keep a receipt, and say whether a head the community kept includes
/// it.
#[allow(clippy::too_many_arguments)]
pub async fn receipt(
    state: &AppState,
    context_id: &str,
    community: &str,
    election_id: &str,
    receipt: &Value,
    checkpoint: Option<&Value>,
    inclusion: Option<&Value>,
) -> Result<Value> {
    let key = voter_key(context_id, community, election_id);
    let rec = record(state, &key).await?.ok_or(PcsError::NotFound)?;

    // The receipt: the ballot box's signed answer to a cast this engine built.
    if receipt["type"].as_str() != Some(RECEIPT_TYPE) {
        return Err(PcsError::ReceiptInvalid(
            "not a voting/ballot/cast response".into(),
        ));
    }
    let signer = proven_issuer(state, receipt)
        .await
        .map_err(PcsError::ReceiptInvalid)?;
    if signer != rec.ballot_box {
        return Err(PcsError::ReceiptInvalid(
            "not signed by the registered ballot box".into(),
        ));
    }
    let payload = &receipt["payload"];
    if payload["electionId"].as_str() != Some(election_id) {
        return Err(PcsError::ReceiptInvalid("for another election".into()));
    }
    let entry_hash = payload["entryHash"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if !rec.cast_leaves.contains(&entry_hash) {
        return Err(PcsError::ReceiptInvalid(
            "names no cast this engine built".into(),
        ));
    }
    let leaf_index = payload["leafIndex"].as_u64().unwrap_or_default();

    {
        let _guard = write_lock().await;
        let mut st: VoterState =
            load_secret_json(state, &key, VOTER_STATE_TYPE, rec.seed_id).await?;
        if !st.receipts.contains(receipt) {
            st.receipts.push(receipt.clone());
            store_secret_json(state, &key, VOTER_STATE_TYPE, rec.seed_id, &st).await?;
        }
    }

    let (Some(checkpoint), Some(inclusion)) = (checkpoint, inclusion) else {
        return Ok(json!({ "electionId": election_id, "status": "kept", "leafIndex": leaf_index }));
    };
    let evidence = |why: &str| PcsError::EvidenceInvalid(why.to_string());
    if checkpoint["type"].as_str() != Some(HEAD_TYPE) {
        return Err(evidence(
            "the checkpoint is not a voting/board/head response",
        ));
    }
    let head_signer = proven_issuer(state, checkpoint)
        .await
        .map_err(PcsError::EvidenceInvalid)?;
    if head_signer != rec.ballot_box {
        return Err(evidence(
            "the checkpoint is not signed by the registered ballot box",
        ));
    }
    let head = &checkpoint["payload"]["head"];
    if head["electionId"].as_str() != Some(election_id) {
        return Err(evidence("the checkpoint is for another election"));
    }
    let tree_size = head["treeSize"].as_u64().unwrap_or_default();
    if inclusion["leafIndex"].as_u64() != Some(leaf_index)
        || inclusion["treeSize"].as_u64() != Some(tree_size)
    {
        return Err(evidence("the inclusion proof is for another leaf or head"));
    }
    let root = rules::digest_from_multibase(head["rootHash"].as_str().unwrap_or_default())
        .ok_or_else(|| evidence("the head's root cannot be read"))?;
    let leaf = rules::digest_from_multibase(&entry_hash)
        .ok_or_else(|| evidence("the leaf hash cannot be read"))?;
    let path = inclusion["path"]
        .as_array()
        .map(|p| {
            p.iter()
                .map(|h| h.as_str().and_then(rules::digest_from_multibase))
                .collect::<Option<Vec<_>>>()
        })
        .unwrap_or(Some(Vec::new()))
        .ok_or_else(|| evidence("the audit path cannot be read"))?;
    let included = leaf_index < tree_size
        && board::verify_inclusion(leaf_index as usize, tree_size as usize, &leaf, &path, &root);
    Ok(json!({
        "electionId": election_id,
        "status": if included { "included" } else { "notIncluded" },
        "leafIndex": leaf_index,
    }))
}
