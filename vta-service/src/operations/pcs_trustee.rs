//! The **trustee** role of the PCS engine (`vta/pcs/trustee/*`) — operations layer.
//!
//! A trustee of a sealed or tallied-encrypted election holds a transport key and a share of the
//! election key; together with `t − 1` other trustees it decrypts the result after close, and no
//! fewer can (VTI-VOT-062, VTI-VOT-063; `voting/_shared/0.1/CONVENTIONS.md` §9). The VTA is the
//! custodian of both, so a trustee's client never holds either:
//!
//! - **Derived, not stored, where it can be.** The first `trustee/enrol` for a (context,
//!   community, election, trustee) allocates a fresh path under the context's base
//!   (VTI-KEY-030). The transport secret and the dealing's polynomial are re-derived from it on
//!   every use, domain-separated, so a repeated `deal` is the same dealing and a `justify` reveals
//!   exactly the share that was dealt.
//! - **The key share is kept wrapped**, under the seed-derived KEK like every engine secret
//!   (`secret:trustee:…`): it is the sum of the other trustees' shares and cannot be re-derived.
//! - **Signed as the trustee persona, and nothing else.** Every answer is one `voting/trustees/*`
//!   request this engine built, signed with the trustee's `authentication` key through the gated
//!   oracle — never caller-supplied bytes.
//! - **Acting on evidence only** (CONVENTIONS §9.6 – 9.7). The ceremony arrives as the trustees'
//!   signed steps, each verified here; the transport keys dealt to are pinned at the first deal; a
//!   share is revealed only to a complaint its complainant signed; a key share once held is never
//!   replaced; and a decryption needs the community's signed authorization, once per election.
//!   Nothing a ballot box merely reports is believed.
//!
//! | Key | Value |
//! |---|---|
//! | `trustee:<digest(context, community, election, trustee)>` | [`TrusteeRecord`] — public |
//! | `secret:trustee:…` | the wrapped key share |

use std::collections::BTreeSet;

use vti_voting::{ceremony::Ceremony, steps};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use trust_tasks_rs::specs::voting::election::register::v0_1 as register;
use vti_voting::{
    election::{Election, ElectionId},
    rand::{SeedableRng, rngs::OsRng, rngs::StdRng},
    rules,
    trustees::{
        Dealing, Share, Threshold, TransportKey, TransportSecret, TrusteeKey, deal, open_share,
        partial_decrypt, scalar_text, seal_share, verify_dealing, verify_share,
    },
    wire,
};
use zeroize::Zeroizing;

use super::pcs::{
    Caller, PcsError, Result, allocate_member_path, load_secret_json, member_seed,
    store_secret_json, write_lock,
};
use super::pcs_voter::{PersonaTicketSigner, TicketSigner};
use crate::error::AppError;
use crate::server::AppState;

const TRUSTEE_STATE_TYPE: &str = "pcs-trustee-state";
const DOMAIN_TRANSPORT_SECRET: &[u8] = b"vti/vote/trustee/transport-secret/v1";
const DOMAIN_DEAL: &[u8] = b"vti/vote/trustee/deal/v1";

/// The `voting/trustees/*` request types, bare: a ballot box dispatches them in this form.
fn task_uri(task: &str) -> String {
    format!("https://trusttasks.org/spec/voting/trustees/{task}/0.1")
}

/// A trustee engine's public record: one per (context, community, election, trustee).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrusteeRecord {
    pub context_id: String,
    pub community: String,
    pub election_id: String,
    pub trustee: String,
    /// This trustee's index in the manifest's `trustees.dids`, from 1.
    pub index: u32,
    pub threshold: u32,
    pub trustees: u32,
    pub manifest_digest: String,
    pub ballot_box: String,
    pub voting_closes: DateTime<Utc>,
    pub path: String,
    pub seed_id: u32,
    /// The published transport key, as the wire carries it.
    pub transport_key: Value,
    pub dealt: bool,
    pub key_held: bool,
    pub created_at: DateTime<Utc>,
    /// A digest of the transport keys the first dealing was sealed to: no later dealing goes to
    /// any others (deal/0.2 item 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dealt_to: Option<String>,
    /// The `targetsDigest` of the one authorized set this trustee decrypted (decrypt/0.2 item 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decrypted: Option<String>,
}

/// The wrapped state: as secret as the key.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct TrusteeState {
    /// The trustee's share of the election key, multibase.
    #[serde(default)]
    key_share: Option<String>,
}

/// Written by hand: a derived `Debug` would print the share.
impl std::fmt::Debug for TrusteeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrusteeState")
            .field("key_share", &self.key_share.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

fn trustee_key(context_id: &str, community: &str, election_id: &str, trustee: &str) -> String {
    let mut h = Sha256::new();
    for f in [context_id, community, election_id, trustee] {
        h.update((f.len() as u64).to_be_bytes());
        h.update(f.as_bytes());
    }
    format!("trustee:{}", hex::encode(h.finalize()))
}

fn malformed(why: impl Into<String>) -> PcsError {
    PcsError::App(AppError::Validation(why.into()))
}

fn internal(why: impl std::fmt::Display) -> PcsError {
    PcsError::App(AppError::Internal(why.to_string()))
}

fn threshold(r: &TrusteeRecord) -> Result<Threshold> {
    Threshold::new(r.threshold, r.trustees).map_err(internal)
}

fn election_ctx(r: &TrusteeRecord) -> Result<Vec<u8>> {
    let digest = rules::digest_from_multibase(&r.manifest_digest)
        .ok_or_else(|| internal("stored manifest digest"))?;
    let id = ElectionId::new(&r.election_id).map_err(|e| malformed(e.to_string()))?;
    Ok(Election::new(&r.community, id, digest)
        .map_err(|e| malformed(e.to_string()))?
        .trustee_context())
}

/// The signer for `trustee`, when this VTA holds an `authentication` key of it the caller may act
/// as — the same rule as the voter's member, answered as this role's code.
async fn signer<'a>(
    state: &'a AppState,
    auth: &'a crate::auth::AuthClaims,
    trustee: &str,
) -> Result<PersonaTicketSigner<'a>> {
    PersonaTicketSigner::for_member(state, auth, trustee)
        .await
        .map_err(|_| PcsError::TrusteeNotHeld(trustee.to_string()))
}

/// One `voting/trustees/<task>` request to the ballot box, signed as the trustee.
async fn document(
    signer: &dyn TicketSigner,
    r: &TrusteeRecord,
    task: &str,
    mut payload: Value,
) -> Result<Value> {
    let now = Utc::now();
    let stamp = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    payload["community"] = json!(r.community);
    payload["electionId"] = json!(r.election_id);
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": task_uri(task),
        "issuer": r.trustee,
        "recipient": r.ballot_box,
        "issuedAt": stamp(now),
        "expiresAt": stamp(now + chrono::Duration::hours(1)),
        "payload": payload,
    });
    signer.sign(&mut doc).await?;
    Ok(doc)
}

/// `vta/pcs/trustee/read` items 3 – 5: `voting/trustees/status` or `voting/election/show` for
/// one election, signed as `trustee` and addressed to `ballot_box` — nothing else, and nothing
/// kept. `read` has already been held to the two the task names.
///
/// # Errors
/// [`PcsError::TrusteeNotHeld`] for a DID this VTA holds no authentication key of the caller may
/// act as.
pub async fn sign_read(
    state: &AppState,
    auth: &crate::auth::AuthClaims,
    trustee: &str,
    community: &str,
    election_id: &str,
    ballot_box: &str,
    read: &str,
) -> Result<Value> {
    let type_uri = match read {
        "status" => task_uri("status"),
        "election" => "https://trusttasks.org/spec/voting/election/show/0.1".to_string(),
        other => {
            return Err(malformed(format!(
                "`{other}` is not a read this task signs"
            )));
        }
    };
    let signer = signer(state, auth, trustee).await?;
    let now = Utc::now();
    let stamp = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuer": trustee,
        "recipient": ballot_box,
        "issuedAt": stamp(now),
        "expiresAt": stamp(now + chrono::Duration::hours(1)),
        "payload": { "community": community, "electionId": election_id },
    });
    signer.sign(&mut doc).await?;
    Ok(doc)
}

/// The transport secret and the dealing's randomness, both from this election's member seed,
/// each under its own domain.
fn transport_secret(seed: &[u8; 32], index: u32) -> Result<TransportSecret> {
    let wide: [u8; 64] = Sha512::new()
        .chain_update(DOMAIN_TRANSPORT_SECRET)
        .chain_update(seed)
        .finalize()
        .into();
    TransportSecret::from_wide(index, &wide).map_err(internal)
}

fn deal_rng(seed: &[u8; 32]) -> StdRng {
    let s: [u8; 32] = Sha256::new()
        .chain_update(DOMAIN_DEAL)
        .chain_update(seed)
        .finalize()
        .into();
    StdRng::from_seed(s)
}

async fn record(state: &AppState, key: &str) -> Result<TrusteeRecord> {
    state
        .pcs_engine_ks
        .get::<TrusteeRecord>(key.to_string())
        .await?
        .ok_or(PcsError::NotEnrolled)
}

/// Check `manifest_value` is the one enrolled under.
fn same_manifest(r: &TrusteeRecord, manifest_value: &Value) -> Result<()> {
    let digest = rules::manifest_digest(manifest_value).map_err(|e| malformed(e.to_string()))?;
    if rules::digest_multibase(&digest) != r.manifest_digest {
        return Err(PcsError::ElectionChanged);
    }
    Ok(())
}

/// `vta/pcs/trustee/enrol`: this election's transport key, created on first use, and the
/// enrolment signed as the trustee.
pub async fn enrol(
    state: &AppState,
    caller: &Caller<'_>,
    auth: &crate::auth::AuthClaims,
    context_id: &str,
    community: &str,
    trustee: &str,
    manifest_value: &Value,
) -> Result<Value> {
    let signer = signer(state, auth, trustee).await?;
    let manifest: register::Manifest = serde_json::from_value(manifest_value.clone())
        .map_err(|e| malformed(format!("manifest: {e}")))?;
    if manifest.community.as_str() != community {
        return Err(malformed("the manifest names another community"));
    }
    let Some(trustees) = &manifest.trustees else {
        return Err(PcsError::NotTrustee);
    };
    let Some(pos) = trustees.dids.iter().position(|d| d.as_str() == trustee) else {
        return Err(PcsError::NotTrustee);
    };
    let index = pos as u32 + 1;
    let n = trustees.dids.len() as u32;
    let t = u32::try_from(trustees.threshold).map_err(|_| malformed("threshold"))?;
    Threshold::new(t, n).map_err(|e| malformed(e.to_string()))?;
    let digest = rules::manifest_digest(manifest_value).map_err(|e| malformed(e.to_string()))?;
    let digest_text = rules::digest_multibase(&digest);
    let election_id = manifest.election_id.as_str().to_string();
    let key = trustee_key(context_id, community, &election_id, trustee);

    let _guard = write_lock().await;
    let rec = match state
        .pcs_engine_ks
        .get::<TrusteeRecord>(key.clone())
        .await?
    {
        Some(existing) => {
            if existing.manifest_digest != digest_text {
                return Err(PcsError::ElectionChanged);
            }
            existing
        }
        None => {
            let (path, seed_id) = allocate_member_path(state, context_id).await?;
            let mut rec = TrusteeRecord {
                context_id: context_id.to_string(),
                community: community.to_string(),
                election_id,
                trustee: trustee.to_string(),
                index,
                threshold: t,
                trustees: n,
                manifest_digest: digest_text,
                ballot_box: manifest.ballot_box.as_str().to_string(),
                voting_closes: manifest.voting_closes,
                path,
                seed_id,
                transport_key: Value::Null,
                dealt: false,
                key_held: false,
                created_at: Utc::now(),
                dealt_to: None,
                decrypted: None,
            };
            let seed = member_seed(state, caller, context_id, &rec.path, seed_id).await?;
            let secret = transport_secret(&seed, index)?;
            let tk = secret.publish(&election_ctx(&rec)?, &mut OsRng);
            rec.transport_key = wire::transport_key_value(&tk);
            state.pcs_engine_ks.insert(key, &rec).await?;
            rec
        }
    };
    let doc = document(
        &signer,
        &rec,
        "enrol",
        json!({ "transportKey": rec.transport_key }),
    )
    .await?;
    Ok(json!({ "document": doc }))
}

/// The ceremony as its signed steps establish it (CONVENTIONS §9.6): every request verified
/// here — its proof resolved and checked by this VTA, never taken as passed along — then replayed,
/// with the deadline once `votingOpens` has come.
async fn ceremony_from(
    state: &AppState,
    rec: &TrusteeRecord,
    manifest: &register::Manifest,
    requests: &Value,
    now: DateTime<Utc>,
) -> Result<Ceremony> {
    let requests = requests
        .as_array()
        .ok_or_else(|| PcsError::CeremonyInvalid("not a list of steps".into()))?;
    let resolver = state.trust_task_vm_resolver();
    let resolver = &resolver;
    let proven = steps::ProvenRequests::prove_requests(requests, |r| async move {
        vti_common::auth::verify_trust_task_proof_value(&r, resolver)
            .await
            .ok()
    })
    .await;
    let dids: Vec<&str> = manifest
        .trustees
        .as_ref()
        .map(|t| t.dids.iter().map(|d| d.as_str()).collect())
        .unwrap_or_default();
    steps::replay(
        requests,
        steps::Election {
            community: &rec.community,
            election_id: &rec.election_id,
            trustees: &dids,
        },
        threshold(rec)?,
        election_ctx(rec)?,
        &proven,
        now >= manifest.voting_opens,
    )
    .map_err(PcsError::CeremonyInvalid)
}

fn manifest_of(rec: &TrusteeRecord, manifest_value: &Value) -> Result<register::Manifest> {
    same_manifest(rec, manifest_value)?;
    serde_json::from_value(manifest_value.clone()).map_err(|e| malformed(format!("manifest: {e}")))
}

/// This trustee's dealing, the same on every call: commitments, proof and every share sealed to
/// its recipient's transport key.
fn dealing_for(
    r: &TrusteeRecord,
    seed: &[u8; 32],
    transport_keys: &[TransportKey],
) -> Result<(vti_voting::ceremony::SealedDealing, Vec<Share>)> {
    let th = threshold(r)?;
    let ctx = election_ctx(r)?;
    let mut rng = deal_rng(seed);
    let (dealing, shares) = deal(r.index, th, &ctx, &mut rng).map_err(internal)?;
    let mut sealed = std::collections::BTreeMap::new();
    for s in &shares {
        let to = transport_keys
            .iter()
            .find(|k| k.trustee == s.recipient)
            .ok_or_else(|| {
                PcsError::CeremonyInvalid(format!("no transport key for {}", s.recipient))
            })?;
        sealed.insert(
            s.recipient,
            seal_share(s, to, &ctx, &mut rng).map_err(internal)?,
        );
    }
    Ok((
        vti_voting::ceremony::SealedDealing {
            dealing,
            shares: sealed,
        },
        shares,
    ))
}

/// `vta/pcs/trustee/deal/0.2`: the dealing, sealed to the transport keys the ceremony's signed
/// enrolments establish — and only ever to those first dealt to.
#[allow(clippy::too_many_arguments)]
pub async fn deal_task(
    state: &AppState,
    caller: &Caller<'_>,
    auth: &crate::auth::AuthClaims,
    context_id: &str,
    community: &str,
    trustee: &str,
    manifest_value: &Value,
    ceremony: &Value,
    now: DateTime<Utc>,
) -> Result<Value> {
    let signer = signer(state, auth, trustee).await?;
    let election_id = manifest_value["electionId"].as_str().unwrap_or_default();
    let key = trustee_key(context_id, community, election_id, trustee);
    let _guard = write_lock().await;
    let mut rec = record(state, &key).await?;
    let manifest = manifest_of(&rec, manifest_value)?;
    let c = ceremony_from(state, &rec, &manifest, ceremony, now).await?;
    let tks: Vec<TransportKey> = c.transport_keys().copied().collect();
    if tks.len() != rec.trustees as usize {
        return Err(PcsError::CeremonyInvalid(
            "not every trustee has enrolled".into(),
        ));
    }
    if tks
        .iter()
        .find(|k| k.trustee == rec.index)
        .map(wire::transport_key_value)
        .as_ref()
        != Some(&rec.transport_key)
    {
        return Err(PcsError::CeremonyInvalid(
            "this trustee's transport key is not the one it published".into(),
        ));
    }
    let set: Vec<Value> = tks.iter().map(wire::transport_key_value).collect();
    let set_digest = hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&set).map_err(internal)?,
    ));
    match &rec.dealt_to {
        Some(d) if *d != set_digest => return Err(PcsError::CeremonyChanged),
        Some(_) => {}
        None => {
            rec.dealt_to = Some(set_digest);
            rec.dealt = true;
            state.pcs_engine_ks.insert(key, &rec).await?;
        }
    }
    let seed = member_seed(state, caller, context_id, &rec.path, rec.seed_id).await?;
    let (sd, _) = dealing_for(&rec, &seed, &tks)?;
    let doc = document(
        &signer,
        &rec,
        "deal",
        json!({ "dealing": wire::dealing_value(&sd) }),
    )
    .await?;
    Ok(json!({ "document": doc }))
}

/// `vta/pcs/trustee/keys/0.2`: open and check the shares dealt to this trustee, confirm, and — once
/// the ceremony forms the key — compute and keep this trustee's key share, never replacing one held.
#[allow(clippy::too_many_arguments)]
pub async fn keys(
    state: &AppState,
    caller: &Caller<'_>,
    auth: &crate::auth::AuthClaims,
    context_id: &str,
    community: &str,
    trustee: &str,
    manifest_value: &Value,
    ceremony: &Value,
    now: DateTime<Utc>,
) -> Result<Value> {
    let signer = signer(state, auth, trustee).await?;
    let election_id = manifest_value["electionId"].as_str().unwrap_or_default();
    let key = trustee_key(context_id, community, election_id, trustee);
    let _guard = write_lock().await;
    let mut rec = record(state, &key).await?;
    let manifest = manifest_of(&rec, manifest_value)?;
    let c = ceremony_from(state, &rec, &manifest, ceremony, now).await?;
    let th = threshold(&rec)?;
    let ctx = election_ctx(&rec)?;
    let dealt: Vec<_> = c.dealings().cloned().collect();
    if dealt.len() != th.n as usize {
        return Err(PcsError::CeremonyInvalid(
            "not every trustee has dealt".into(),
        ));
    }
    let seed = member_seed(state, caller, context_id, &rec.path, rec.seed_id).await?;
    let secret = transport_secret(&seed, rec.index)?;
    let mut complaints = BTreeSet::new();
    let mut opened: Vec<Share> = Vec::new();
    for sd in &dealt {
        let dealer = sd.dealing.dealer;
        let share = verify_dealing(&sd.dealing, th, &ctx)
            .ok()
            .and_then(|()| sd.shares.get(&rec.index))
            .and_then(|s| open_share(&secret, dealer, s, &ctx).ok())
            .filter(|s| verify_share(&sd.dealing, s).is_ok());
        match share {
            Some(s) => opened.push(s),
            None => {
                complaints.insert(dealer);
            }
        }
    }

    if !c.confirmed().any(|j| j == rec.index) {
        let doc = document(
            &signer,
            &rec,
            "confirm",
            json!({ "trustee": rec.index, "complaints": complaints }),
        )
        .await?;
        return Ok(json!({ "complaints": complaints, "keyHeld": rec.key_held, "document": doc }));
    }
    let Some(ek) = c.key().cloned() else {
        return Ok(json!({ "complaints": complaints, "keyHeld": rec.key_held }));
    };
    // A share a dealer revealed on the board in answer to this trustee's complaint replaces the
    // one that failed; the ceremony checked it against the commitments.
    for k in c.complaints() {
        if k.recipient != rec.index {
            continue;
        }
        if let Some(value) = k.justified {
            opened.retain(|o| o.dealer != k.dealer);
            opened.push(Share {
                dealer: k.dealer,
                recipient: rec.index,
                value,
            });
            complaints.remove(&k.dealer);
        }
    }
    let qualified: Vec<Dealing> = dealt
        .iter()
        .filter(|d| ek.qualified.contains(&d.dealing.dealer))
        .map(|d| d.dealing.clone())
        .collect();
    let mine: Vec<Share> = opened
        .into_iter()
        .filter(|s| ek.qualified.contains(&s.dealer))
        .collect();
    let share = TrusteeKey::from_shares(rec.index, &mine, &qualified, &ek)
        .map_err(|_| PcsError::KeyMismatch)?;
    let text = multibase::encode(multibase::Base::Base58Btc, share.to_bytes());
    if rec.key_held {
        // Never replaced: a ceremony that forms another share for this trustee is refused.
        let st: TrusteeState =
            load_secret_json(state, &key, TRUSTEE_STATE_TYPE, rec.seed_id).await?;
        if st.key_share.as_deref() != Some(text.as_str()) {
            return Err(PcsError::KeyMismatch);
        }
        return Ok(json!({ "complaints": complaints, "keyHeld": true }));
    }
    store_secret_json(
        state,
        &key,
        TRUSTEE_STATE_TYPE,
        rec.seed_id,
        &TrusteeState {
            key_share: Some(text),
        },
    )
    .await?;
    rec.key_held = true;
    state.pcs_engine_ks.insert(key, &rec).await?;
    Ok(json!({ "complaints": complaints, "keyHeld": true }))
}

/// `vta/pcs/trustee/justify/0.2`: the share this trustee dealt to `recipient`, in the clear — only
/// for a complaint that `recipient` itself signed (CONVENTIONS §9.6).
#[allow(clippy::too_many_arguments)]
pub async fn justify(
    state: &AppState,
    caller: &Caller<'_>,
    auth: &crate::auth::AuthClaims,
    context_id: &str,
    community: &str,
    trustee: &str,
    manifest_value: &Value,
    ceremony: &Value,
    recipient: u32,
    now: DateTime<Utc>,
) -> Result<Value> {
    let signer = signer(state, auth, trustee).await?;
    let election_id = manifest_value["electionId"].as_str().unwrap_or_default();
    let key = trustee_key(context_id, community, election_id, trustee);
    let rec = record(state, &key).await?;
    if !rec.dealt {
        return Err(PcsError::NoDealing);
    }
    let manifest = manifest_of(&rec, manifest_value)?;
    let c = ceremony_from(state, &rec, &manifest, ceremony, now).await?;
    if !c
        .complaints()
        .iter()
        .any(|k| k.dealer == rec.index && k.recipient == recipient)
    {
        return Err(PcsError::NoComplaint);
    }
    let th = threshold(&rec)?;
    let seed = member_seed(state, caller, context_id, &rec.path, rec.seed_id).await?;
    // The polynomial alone, from the same randomness the dealing drew it with.
    let (_, shares) =
        deal(rec.index, th, &election_ctx(&rec)?, &mut deal_rng(&seed)).map_err(internal)?;
    let share = shares
        .iter()
        .find(|s| s.recipient == recipient)
        .ok_or_else(|| internal("share"))?;
    let doc = document(
        &signer,
        &rec,
        "justify",
        json!({ "dealer": rec.index, "recipient": recipient, "share": scalar_text(&share.value) }),
    )
    .await?;
    Ok(json!({ "document": doc }))
}

/// The community's `voting/trustees/authorize` request (CONVENTIONS §9.7), checked here: its
/// proof the community's, for this election and manifest, closed no later than now, pinning
/// exactly `targets`. Returns the `targetsDigest` it pins.
async fn authorized(
    state: &AppState,
    rec: &TrusteeRecord,
    authorization: &Value,
    targets: &Value,
    now: DateTime<Utc>,
) -> Result<String> {
    let bad = |why: &str| PcsError::AuthorizationInvalid(why.to_string());
    if authorization["type"].as_str() != Some(task_uri("authorize").as_str())
        || authorization["issuer"].as_str() != Some(rec.community.as_str())
    {
        return Err(bad("not the community's voting/trustees/authorize"));
    }
    let signer = vti_common::auth::verify_trust_task_proof_value(
        authorization,
        &state.trust_task_vm_resolver(),
    )
    .await
    .map_err(|e| bad(&format!("its proof does not verify: {e}")))?;
    if signer != rec.community {
        return Err(bad("its proof is not the community's"));
    }
    let p = &authorization["payload"];
    if p["community"].as_str() != Some(rec.community.as_str())
        || p["electionId"].as_str() != Some(rec.election_id.as_str())
        || p["manifestDigest"].as_str() != Some(rec.manifest_digest.as_str())
    {
        return Err(bad("another election's"));
    }
    let closed_at: DateTime<Utc> = p["closedAt"]
        .as_str()
        .and_then(|t| t.parse().ok())
        .ok_or_else(|| bad("closedAt"))?;
    if closed_at > now {
        return Err(bad("voting has not closed"));
    }
    let list = targets.as_array().ok_or_else(|| malformed("targets"))?;
    let digest = vti_voting::audit::targets_digest(list).map_err(|e| malformed(e.to_string()))?;
    if p["targetCount"].as_u64() != Some(list.len() as u64)
        || p["targetsDigest"].as_str() != Some(digest.as_str())
    {
        return Err(bad("the targets are not the ones it pins"));
    }
    Ok(digest)
}

/// `vta/pcs/trustee/decrypt/0.2`: this trustee's partial decryption of exactly the targets the
/// community authorized, once per election (VTI-VOT-063; CONVENTIONS §9.7).
#[allow(clippy::too_many_arguments)]
pub async fn decrypt(
    state: &AppState,
    auth: &crate::auth::AuthClaims,
    context_id: &str,
    community: &str,
    election_id: &str,
    trustee: &str,
    targets: &Value,
    authorization: &Value,
    now: DateTime<Utc>,
) -> Result<Value> {
    let signer = signer(state, auth, trustee).await?;
    let key = trustee_key(context_id, community, election_id, trustee);
    let _guard = write_lock().await;
    let mut rec = record(state, &key)
        .await
        .map_err(|_| PcsError::KeyNotHeld)?;
    if !rec.key_held {
        return Err(PcsError::KeyNotHeld);
    }
    let digest = authorized(state, &rec, authorization, targets, now).await?;
    match &rec.decrypted {
        Some(d) if *d != digest => return Err(PcsError::AlreadyDecrypted),
        Some(_) => {}
        None => {
            rec.decrypted = Some(digest);
            state.pcs_engine_ks.insert(key.clone(), &rec).await?;
        }
    }
    let st: TrusteeState = load_secret_json(state, &key, TRUSTEE_STATE_TYPE, rec.seed_id).await?;
    let text = Zeroizing::new(st.key_share.ok_or(PcsError::KeyNotHeld)?);
    let (_, bytes) = multibase::decode(text.as_str()).map_err(internal)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| internal("key share"))?;
    let tk = TrusteeKey::from_bytes(rec.index, bytes).map_err(internal)?;
    let ctx = election_ctx(&rec)?;
    let partials = targets
        .as_array()
        .ok_or_else(|| malformed("targets"))?
        .iter()
        .map(|v| {
            let (t, ct) = wire::target(v).map_err(|e| malformed(e.to_string()))?;
            let p = partial_decrypt(&tk, &ct, &ctx, &mut OsRng);
            Ok(wire::partial_value(&t, &ct, &p))
        })
        .collect::<Result<Vec<_>>>()?;
    let doc = document(
        &signer,
        &rec,
        "decrypt",
        json!({ "trustee": rec.index, "partials": partials }),
    )
    .await?;
    Ok(json!({ "document": doc }))
}
