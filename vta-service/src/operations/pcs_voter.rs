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
const CAST_ENCRYPTED_TYPE: &str =
    "https://trusttasks.org/spec/voting/ballot/cast-encrypted/0.1#request";
const RECEIPT_TYPE: &str = "https://trusttasks.org/spec/voting/ballot/cast/0.1#response";
const ENCRYPTED_RECEIPT_TYPE: &str =
    "https://trusttasks.org/spec/voting/ballot/cast-encrypted/0.1#response";
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
    /// The `vtc/elections/tickets/issue` document signed as each member this request was asked
    /// for, kept so a repeat returns it unchanged and the community answers a resend with its
    /// first answer.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub ticket_documents: std::collections::BTreeMap<String, Value>,
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

/// Signs the `vtc/elections/tickets/issue` request as the member (`vta/pcs/voter/register`
/// item 9). Built by the task handler once it has found the member's `authentication` key and
/// checked the caller may act as it — so a refused `member` allocates nothing here.
#[async_trait::async_trait]
pub trait TicketSigner: Send + Sync {
    /// The member DID the document is issued as.
    fn did(&self) -> &str;
    /// Attach the member's `authentication` proof to `doc`.
    async fn sign(&self, doc: &mut Value) -> Result<()>;
}

/// [`TicketSigner`] as a persona this VTA holds: the member's `authentication` key, through the
/// gated oracle as `ProtocolDefined` input the VTA built itself, exactly as the witnessed party
/// signs (`operations::witness`). It signs one document type with one payload, and nothing else.
pub struct PersonaTicketSigner<'a> {
    state: &'a AppState,
    auth: &'a crate::auth::AuthClaims,
    did: String,
    key_id: String,
    verification_method: String,
}

impl<'a> PersonaTicketSigner<'a> {
    /// The signer for `did`, when this VTA holds an `authentication` key of it the caller may
    /// act as.
    ///
    /// # Errors
    /// [`PcsError::MemberNotHeld`], the same whether the DID is unknown here or held for a
    /// context the caller may not act in.
    pub async fn for_member(
        state: &'a AppState,
        auth: &'a crate::auth::AuthClaims,
        did: &str,
    ) -> Result<Self> {
        use crate::operations::persona::{PersonaStores, Relationship, persona_key_for};
        let not_held = || PcsError::MemberNotHeld(did.to_string());
        let key = persona_key_for(
            PersonaStores::from_state(state),
            auth,
            did,
            Relationship::Authentication,
        )
        .await
        .map_err(|_| not_held())?
        .ok_or_else(not_held)?;
        crate::operations::keys::require_key_nameable(
            &state.keys_ks,
            &state.acl_ks,
            auth,
            &key.key_id,
        )
        .await
        .map_err(|_| not_held())?;
        Ok(Self {
            state,
            auth,
            did: did.to_string(),
            key_id: key.key_id,
            verification_method: key.verification_method,
        })
    }
}

#[async_trait::async_trait]
impl TicketSigner for PersonaTicketSigner<'_> {
    fn did(&self) -> &str {
        &self.did
    }

    async fn sign(&self, doc: &mut Value) -> Result<()> {
        use crate::operations::room_issuance::{SigningContext, VtaKeySigner};
        let ctx = SigningContext {
            keys_ks: &self.state.keys_ks,
            imported_ks: &self.state.imported_ks,
            internal_ks: &self.state.internal_ks,
            contexts_ks: &self.state.contexts_ks,
            acl_ks: &self.state.acl_ks,
            seed_store: &self.state.seed_store,
            audit: &self.state.audit_sink,
            auth: self.auth,
        };
        let signer = VtaKeySigner::new(ctx, &self.key_id, &self.verification_method);
        let proof = affinidi_data_integrity::DataIntegrityProof::sign(
            &*doc,
            &signer,
            affinidi_data_integrity::SignOptions::new()
                .with_proof_purpose("authentication")
                .with_created(Utc::now()),
        )
        .await
        .map_err(|e| AppError::Internal(format!("sign the ticket request as {}: {e}", self.did)))?;
        doc["proof"] = serde_json::to_value(proof)
            .map_err(|e| AppError::Internal(format!("encode the proof: {e}")))?;
        Ok(())
    }
}

/// The tickets/issue Type URI, bare: every community dispatches it in this form.
const TICKETS_ISSUE: &str = "https://trusttasks.org/spec/vtc/elections/tickets/issue/0.1";

/// The request to the community, signed as `signer` (item 9): a fresh id, the community as
/// recipient, expiring no later than voting closes, and exactly this answer's payload.
async fn ticket_document(
    signer: &dyn TicketSigner,
    community: &str,
    voting_closes: DateTime<Utc>,
    answer: &Value,
) -> Result<Value> {
    let now = Utc::now();
    let expires = (now + chrono::Duration::hours(1)).min(voting_closes);
    let stamp = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": TICKETS_ISSUE,
        "issuer": signer.did(),
        "recipient": community,
        "issuedAt": stamp(now),
        "expiresAt": stamp(expires.max(now)),
        "payload": {
            "electionId": answer["electionId"],
            "manifestDigest": answer["manifestDigest"],
            "request": answer["request"],
        },
    });
    signer.sign(&mut doc).await?;
    Ok(doc)
}

/// `vta/pcs/voter/read` items 4 – 6: one of the two election reads, signed as `member`, and
/// nothing else. The caller has already held `type_uri` to `list` or `show` and the payload to
/// that read's schema.
///
/// # Errors
/// [`PcsError::MemberNotHeld`] for a DID this VTA holds no authentication key of the caller may
/// act as.
pub async fn sign_read(
    state: &AppState,
    auth: &crate::auth::AuthClaims,
    member: &str,
    community: &str,
    type_uri: &str,
    payload: Value,
) -> Result<Value> {
    let signer = PersonaTicketSigner::for_member(state, auth, member).await?;
    let now = Utc::now();
    let stamp = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuer": member,
        "recipient": community,
        "issuedAt": stamp(now),
        "expiresAt": stamp(now + chrono::Duration::hours(1)),
        "payload": payload,
    });
    signer.sign(&mut doc).await?;
    Ok(doc)
}

/// `vta/pcs/voter/register`: the blinded ticket request under this election's voter key,
/// creating the key on first use — and, with a `member`, the request to the community signed as
/// that member.
pub async fn register(
    state: &AppState,
    caller: &Caller<'_>,
    context_id: &str,
    community: &str,
    published: &Value,
    manifest_value: &Value,
    member: Option<&dyn TicketSigner>,
) -> Result<Value> {
    let (params, voting_key) = voting_params(community, published)?;
    let manifest: register::Manifest = serde_json::from_value(manifest_value.clone())
        .map_err(|e| malformed(format!("manifest: {e}")))?;
    if manifest.community.as_str() != community {
        return Err(malformed("the manifest names another community"));
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
        let mut answer = json!({
            "electionId": election_id,
            "manifestDigest": digest_text,
            "request": existing.request,
        });
        if let Some(signer) = member {
            let mut existing = existing;
            let doc = match existing.ticket_documents.get(signer.did()) {
                Some(kept) => kept.clone(),
                None => {
                    let doc =
                        ticket_document(signer, community, existing.voting_closes, &answer).await?;
                    existing
                        .ticket_documents
                        .insert(signer.did().to_string(), doc.clone());
                    state.pcs_engine_ks.insert(key, &existing).await?;
                    doc
                }
            };
            answer["ticketDocument"] = doc;
        }
        return Ok(answer);
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
        ticket_documents: Default::default(),
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
    let mut answer =
        json!({ "electionId": election_id, "manifestDigest": digest_text, "request": request });
    let mut rec = rec;
    if let Some(signer) = member {
        let doc = ticket_document(signer, community, rec.voting_closes, &answer).await?;
        rec.ticket_documents
            .insert(signer.did().to_string(), doc.clone());
        answer["ticketDocument"] = doc;
    }
    state.pcs_engine_ks.insert(key, &rec).await?;
    Ok(answer)
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
    if manifest.secrecy != register::SecrecyLevel::Open {
        return Err(malformed(
            "a sealed or tallied-encrypted election is cast with vta/pcs/vote-encrypted",
        ));
    }
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

    let document = sign_as_one_time_key(&rec, CAST_TYPE, &cast, now).await?;
    remember_leaf(&mut rec, "cast", &cast)?;
    state.pcs_engine_ks.insert(key, &rec).await?;
    Ok(json!({ "castDocument": document, "tag": cast["tag"] }))
}

/// Record the board leaf hash of a cast this engine built, so its receipt is recognised.
fn remember_leaf(rec: &mut VoterRecord, kind: &str, cast: &Value) -> Result<()> {
    let entry_jcs = serde_json_canonicalizer::to_vec(&json!({ "kind": kind, "cast": cast }))
        .map_err(|e| AppError::Internal(e.to_string()))?;
    rec.cast_leaves
        .push(rules::digest_multibase(&board::leaf_hash(&entry_jcs)));
    Ok(())
}

/// `vta/pcs/vote-encrypted`: `vta/pcs/vote` for the sealed and tallied-encrypted levels — the
/// ballot sealed to the election key, or encrypted option by option with its proofs, and the
/// attestation over the encrypted form (CONVENTIONS §9.4 – 9.5). The plaintext ballot never
/// leaves.
#[allow(clippy::too_many_arguments)]
pub async fn vote_encrypted(
    state: &AppState,
    caller: &Caller<'_>,
    context_id: &str,
    community: &str,
    published: &Value,
    manifest_value: &Value,
    election_key: &Value,
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
    let Some(trustees) = manifest
        .trustees
        .as_ref()
        .filter(|_| manifest.secrecy != register::SecrecyLevel::Open)
    else {
        return Err(PcsError::WrongLevel);
    };
    let th = vti_voting::trustees::Threshold::new(
        u32::try_from(trustees.threshold).unwrap_or(0),
        u32::try_from(trustees.dids.len()).unwrap_or(0),
    )
    .map_err(|e| PcsError::ElectionKeyInvalid(e.to_string()))?;
    let ek = vti_voting::wire::election_key(election_key, th)
        .map_err(|e| PcsError::ElectionKeyInvalid(e.to_string()))?;
    if ek.qualified.is_empty()
        || ek.qualified.iter().any(|q| *q == 0 || *q > th.n)
        || !ek.verification.keys().copied().eq(1..=th.n)
    {
        return Err(PcsError::ElectionKeyInvalid(
            "its trustees are not the manifest's".into(),
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
    let election = election_of(&rec)?;
    let ticket = Ticket::from_text(election.clone(), &ticket_text)
        .map_err(|e| PcsError::App(AppError::Internal(e.to_string())))?;
    let v = voter(state, caller, &rec, &params).await?;
    let mut rng = vti_voting::rand::rngs::OsRng;
    let form = vti_voting::voter::encrypted_form(&manifest, &election, &ek, ballot_value, &mut rng)
        .map_err(|e| PcsError::BallotInvalid(e.to_string()))?;
    let cast = v
        .cast_encrypted_wire(&params, &ticket, &form, &mut rng)
        .map_err(|e| PcsError::App(AppError::Internal(format!("cast: {e}"))))?;
    let document = sign_as_one_time_key(&rec, CAST_ENCRYPTED_TYPE, &cast, now).await?;
    remember_leaf(&mut rec, "encryptedCast", &cast)?;
    state.pcs_engine_ks.insert(key, &rec).await?;
    Ok(json!({ "castDocument": document, "tag": cast["tag"] }))
}

/// The `voting/ballot/cast` request, signed by a `did:key` made here and dropped here: no
/// record of it outlives this call (VTI-VOT-003).
async fn sign_as_one_time_key(
    rec: &VoterRecord,
    type_uri: &str,
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
        "type": type_uri,
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
    if !matches!(
        receipt["type"].as_str(),
        Some(RECEIPT_TYPE | ENCRYPTED_RECEIPT_TYPE)
    ) {
        return Err(PcsError::ReceiptInvalid(
            "not a voting/ballot/cast or cast-encrypted response".into(),
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
