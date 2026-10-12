//! The hidden-vetting **PCS engine** (`vta/pcs/*`) — operations layer.
//!
//! A community that runs hidden vetting admits an applicant on a zero-knowledge proof that
//! distinct eligible vetters vetted them. Every vetter and every applicant holds a PCS secret
//! key, `usk`. This module holds those keys for the VTA's principal and runs every member-side
//! operation, so the client carrying the messages — a wallet with no PCS implementation — never
//! holds one (design `vetting-hidden-vetters-pcs.md` §13 C7). The engines themselves are
//! `vti_vetting_pcs::{vetter, applicant}`; this module is custody, persistence and the checks
//! the specifications name.
//!
//! The rules are in the family's conventions (`vta/_shared/0.4/CONVENTIONS.md` in
//! trust-tasks-tf). The ones this module carries:
//!
//! - **No `usk` is ever stored, and none is ever returned.** Each member key is derived from its
//!   context's base (VTI-KEY-030) at a path allocated from the same counter key records use, and
//!   rebuilt from that path on every use through
//!   [`key_custody::derive_pcs_member_seed`](super::key_custody::derive_pcs_member_seed), which
//!   holds the path to the context.
//! - **One vetter key per (context, community)**, for the engine's whole life: the first root
//!   request creates it and records the member DID; a later member DID that differs is refused.
//! - **An applicant key per application**, at a fresh path.
//! - **Everything else secret is wrapped** under the seed-derived KEK (`vta_keys::imported`) in
//!   the engine's own keyspace: class credentials, unspent tokens, draws and enrolments in
//!   flight, attestations held.
//!
//! Records (`pcs_engine` keyspace):
//!
//! | Key | Value |
//! |---|---|
//! | `vetter:<digest(context, community)>` | [`VetterRecord`] — public: who, where, the key path |
//! | `app:<applicationId>` | [`ApplicationRecord`] — the same for an application |
//! | `secret:vetter:…` / `secret:app:…` | the wrapped engine state |

use std::collections::BTreeMap;
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

use vti_vetting_pcs::{
    ProtoError,
    applicant::ApplicantEngine,
    community::CommunityParams,
    issuer::{RootCredentialWire, TokenBatchWire},
    meta::StatementMeta,
    scheme::{member_key_from_seed, point_from_text, point_text},
    snapshot::{ApplicantSnapshot, HeldAttestation, VetterSnapshot},
    vetter::{EnrolmentBlinding, VetterEngine},
    wire::{SUITE, SubmissionWire},
};

use crate::error::AppError;
use crate::server::AppState;

const VETTER_STATE_TYPE: &str = "pcs-vetter-state";
const APPLICANT_STATE_TYPE: &str = "pcs-applicant-state";

/// Why the engine refused. Each maps to a code the task's specification declares.
#[derive(Debug)]
pub enum PcsError {
    NotFound,
    UnsupportedSuite(String),
    ParametersInvalid(String),
    MemberMismatch,
    LabelNotLive(String),
    NoRequestInFlight,
    CredentialInvalid(String),
    CountExceedsDrip { asked: usize, drip: usize },
    AlreadyInFlight,
    NoDrawInFlight,
    TokensInvalid(String),
    NotEnrolled,
    NoToken,
    ApplicantInvalid,
    CommunityMismatch,
    AttestationInvalid(String),
    NoUsableAttestation,
    App(AppError),
}

impl From<AppError> for PcsError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

impl std::fmt::Display for PcsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such engine"),
            Self::UnsupportedSuite(s) => write!(f, "suite {s} is not implemented"),
            Self::ParametersInvalid(e) => write!(f, "community parameters cannot be read: {e}"),
            Self::MemberMismatch => f.write_str(
                "a vetter engine exists for this context and community under another member DID",
            ),
            Self::LabelNotLive(l) => write!(f, "label {l} is not live in the parameters"),
            Self::NoRequestInFlight => f.write_str("no enrolment is in flight for this label"),
            Self::CredentialInvalid(e) => write!(f, "the answer does not unblind: {e}"),
            Self::CountExceedsDrip { asked, drip } => {
                write!(
                    f,
                    "{asked} tokens asked for; the community's drip is {drip}"
                )
            }
            Self::AlreadyInFlight => f.write_str("a draw for this label and tick is in flight"),
            Self::NoDrawInFlight => f.write_str("no draw is in flight for this label and tick"),
            Self::TokensInvalid(e) => write!(f, "the community's answer does not verify: {e}"),
            Self::NotEnrolled => {
                f.write_str("no class credential under a label the parameters name as live")
            }
            Self::NoToken => f.write_str("no free token under a live label"),
            Self::ApplicantInvalid => f.write_str("the applicant identifier is not valid"),
            Self::CommunityMismatch => f.write_str("meta.community is not the engine's community"),
            Self::AttestationInvalid(e) => write!(f, "the attestation does not verify: {e}"),
            Self::NoUsableAttestation => {
                f.write_str("no held attestation is usable under the parameters as they stand")
            }
            Self::App(e) => write!(f, "{e}"),
        }
    }
}

type Result<T> = std::result::Result<T, PcsError>;

/// Serialise engine read-modify-writes. One lock for the engine: its traffic is a person's
/// pace (a session, a drip a few times a day), and an interleaved write would lose a token or
/// an attestation.
static WRITE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

async fn write_lock() -> MutexGuard<'static, ()> {
    WRITE_LOCK.lock().await
}

// ─── Records ─────────────────────────────────────────────────────────────────

/// A vetter engine's public record: everything but the secret state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VetterRecord {
    pub context_id: String,
    pub community: String,
    pub member_did: String,
    pub suite: String,
    /// The derivation path of the vetter's key, under the context's base.
    pub path: String,
    /// The seed generation the key and the KEK are derived from.
    pub seed_id: u32,
    /// The vetter's PCS identifier — public.
    pub id: String,
    pub created_at: DateTime<Utc>,
}

/// An applicant engine's public record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationRecord {
    pub application_id: String,
    pub context_id: String,
    pub community: String,
    pub join_did: String,
    pub suite: String,
    pub path: String,
    pub seed_id: u32,
    pub id: String,
    pub created_at: DateTime<Utc>,
}

/// A vetter engine's secret state. The snapshot's `usk` is always empty at rest.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VetterState {
    snapshot: VetterSnapshot,
    /// Enrolments in flight: class label → the multibase of the blinding state that unblinds
    /// the community's answer. As secret as the key.
    #[serde(default)]
    enrolments: BTreeMap<String, String>,
}

/// An applicant engine's secret state.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ApplicantState {
    held: Vec<HeldAttestation>,
}

fn vetter_key(context_id: &str, community: &str) -> String {
    let mut h = Sha256::new();
    h.update(context_id.as_bytes());
    h.update([0]);
    h.update(community.as_bytes());
    format!("vetter:{}", hex::encode(h.finalize()))
}

fn app_key(application_id: &str) -> String {
    format!("app:{application_id}")
}

/// Who asked, and over which channel: what a custody refusal is audited against.
pub struct Caller<'a> {
    pub did: &'a str,
    pub channel: &'a str,
}

async fn load_secret_json<T: serde::de::DeserializeOwned>(
    state: &AppState,
    key: &str,
    key_type: &str,
    seed_id: u32,
) -> Result<T> {
    let seed = vta_keys::seeds::load_seed_bytes(&state.keys_ks, &*state.seed_store, Some(seed_id))
        .await
        .map_err(|e| AppError::Internal(format!("load seed: {e}")))?;
    let bytes = Zeroizing::new(
        vta_keys::imported::load_secret(&state.pcs_engine_ks, &state.keys_ks, &seed, key, key_type)
            .await?,
    );
    serde_json::from_slice(&bytes).map_err(|e| {
        AppError::Internal(format!("stored PCS engine state is unreadable: {e}")).into()
    })
}

async fn store_secret_json<T: Serialize>(
    state: &AppState,
    key: &str,
    key_type: &str,
    seed_id: u32,
    value: &T,
) -> Result<()> {
    let seed = vta_keys::seeds::load_seed_bytes(&state.keys_ks, &*state.seed_store, Some(seed_id))
        .await
        .map_err(|e| AppError::Internal(format!("load seed: {e}")))?;
    let bytes = Zeroizing::new(
        serde_json::to_vec(value)
            .map_err(|e| AppError::Internal(format!("serialise PCS engine state: {e}")))?,
    );
    vta_keys::imported::store_secret(
        &state.pcs_engine_ks,
        &state.keys_ks,
        &seed,
        key,
        key_type,
        &bytes,
    )
    .await?;
    Ok(())
}

// ─── Parameters ──────────────────────────────────────────────────────────────

/// The community's published parameters, read and checked: the suite this build implements,
/// keys that decode.
pub fn community_params(community: &str, published: &Value) -> Result<CommunityParams> {
    let s = |k: &str| published.get(k).and_then(Value::as_str).unwrap_or_default();
    let labels = |k: &str| -> Vec<String> {
        published
            .get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let suite = s("suite");
    if suite != SUITE {
        return Err(PcsError::UnsupportedSuite(suite.to_string()));
    }
    let drip = published
        .get("dripPerTick")
        .and_then(Value::as_u64)
        .and_then(|d| usize::try_from(d).ok())
        .unwrap_or(1);
    CommunityParams::published(
        community,
        s("helperKey"),
        s("tokenKey"),
        labels("vetterLabels"),
        labels("tokenLabels"),
        drip,
    )
    .map_err(|e| PcsError::ParametersInvalid(e.to_string()))
}

fn proto(e: ProtoError) -> PcsError {
    PcsError::App(AppError::Internal(format!("PCS engine: {e}")))
}

// ─── Key derivation ──────────────────────────────────────────────────────────

/// Allocate a fresh path under the context's base, for a new member key. The counter is the
/// one key records use, so no record is ever given this path.
async fn allocate_member_path(state: &AppState, context_id: &str) -> Result<(String, u32)> {
    let ctx = crate::contexts::get_context(&state.contexts_ks, context_id)
        .await?
        .ok_or(PcsError::NotFound)?;
    let path = vta_keys::paths::allocate_path(&state.keys_ks, &ctx.base_path).await?;
    let seed_id = vta_keys::seeds::get_active_seed_id(&state.keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("active seed id: {e}")))?;
    Ok((path, seed_id))
}

async fn member_seed(
    state: &AppState,
    caller: &Caller<'_>,
    context_id: &str,
    path: &str,
    seed_id: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    Ok(super::key_custody::derive_pcs_member_seed(
        &state.contexts_ks,
        &state.keys_ks,
        &*state.seed_store,
        &state.audit_sink,
        caller.did,
        context_id,
        path,
        Some(seed_id),
        caller.channel,
    )
    .await?)
}

// ─── Vetter ──────────────────────────────────────────────────────────────────

/// A loaded vetter engine with its record and the state that is not in the engine.
struct LoadedVetter {
    record: VetterRecord,
    engine: VetterEngine,
    enrolments: BTreeMap<String, String>,
}

async fn vetter_record(
    state: &AppState,
    context_id: &str,
    community: &str,
) -> Result<Option<VetterRecord>> {
    Ok(state
        .pcs_engine_ks
        .get(vetter_key(context_id, community))
        .await?)
}

async fn load_vetter_state(state: &AppState, record: &VetterRecord) -> Result<VetterState> {
    load_secret_json(
        state,
        &vetter_key(&record.context_id, &record.community),
        VETTER_STATE_TYPE,
        record.seed_id,
    )
    .await
}

async fn load_vetter(
    state: &AppState,
    caller: &Caller<'_>,
    record: VetterRecord,
) -> Result<LoadedVetter> {
    let mut st = load_vetter_state(state, &record).await?;
    let seed = member_seed(
        state,
        caller,
        &record.context_id,
        &record.path,
        record.seed_id,
    )
    .await?;
    let (id, usk) = member_key_from_seed(&record.community, &seed).map_err(proto)?;
    let keyed = VetterSnapshot::new(&record.member_did, &usk, &id).map_err(proto)?;
    st.snapshot.usk = keyed.usk;
    st.snapshot.id = keyed.id;
    let engine = VetterEngine::restore(&st.snapshot, &record.community).map_err(proto)?;
    Ok(LoadedVetter {
        record,
        engine,
        enrolments: st.enrolments,
    })
}

async fn save_vetter(state: &AppState, v: &LoadedVetter) -> Result<()> {
    let mut snapshot = v.engine.snapshot().map_err(proto)?;
    snapshot.usk = String::new();
    store_secret_json(
        state,
        &vetter_key(&v.record.context_id, &v.record.community),
        VETTER_STATE_TYPE,
        v.record.seed_id,
        &VetterState {
            snapshot,
            enrolments: v.enrolments.clone(),
        },
    )
    .await
}

/// The wire summary of a vetter engine: labels and counts, never its key, credentials or
/// tokens.
fn vetter_summary(
    record: &VetterRecord,
    snap: &VetterSnapshot,
    enrolments: &BTreeMap<String, String>,
) -> Value {
    let mut enrolled: Vec<String> = snap
        .credentials
        .keys()
        .map(|p| format!("vetter/{p}"))
        .collect();
    enrolled.sort_unstable_by(|a, b| b.cmp(a));
    let draws: Vec<Value> = snap
        .pending
        .iter()
        .map(|p| json!({ "label": p.label, "tick": p.tick }))
        .collect();
    json!({
        "contextId": record.context_id,
        "community": record.community,
        "memberDid": record.member_did,
        "suite": record.suite,
        "id": record.id,
        "enrolledLabels": enrolled,
        "pendingLabels": enrolments.keys().collect::<Vec<_>>(),
        "tokensFree": snap.tokens.len(),
        "tokensHeld": snap.tokens.len(),
        "drawsInFlight": draws,
        "attested": snap.log.len(),
    })
}

fn loaded_summary(v: &LoadedVetter) -> Result<Value> {
    let snap = v.engine.snapshot().map_err(proto)?;
    Ok(vetter_summary(&v.record, &snap, &v.enrolments))
}

/// `vta/pcs/root-request`: the blinded enrolment request for `label`, creating the vetter
/// engine on first use.
pub async fn root_request(
    state: &AppState,
    caller: &Caller<'_>,
    context_id: &str,
    community: &str,
    member_did: &str,
    published: &Value,
    label: &str,
) -> Result<Value> {
    let params = community_params(community, published)?;
    if !params.vetter_labels().iter().any(|l| l == label) {
        return Err(PcsError::LabelNotLive(label.to_string()));
    }
    let _guard = write_lock().await;
    let mut v = match vetter_record(state, context_id, community).await? {
        Some(record) if record.member_did != member_did => return Err(PcsError::MemberMismatch),
        Some(record) => load_vetter(state, caller, record).await?,
        None => {
            let (path, seed_id) = allocate_member_path(state, context_id).await?;
            let seed = member_seed(state, caller, context_id, &path, seed_id).await?;
            let engine =
                VetterEngine::enrol_from_seed(member_did, &params, &seed).map_err(proto)?;
            let record = VetterRecord {
                context_id: context_id.to_string(),
                community: community.to_string(),
                member_did: member_did.to_string(),
                suite: SUITE.to_string(),
                path,
                seed_id,
                id: point_text(engine.id()).map_err(proto)?,
                created_at: Utc::now(),
            };
            state
                .pcs_engine_ks
                .insert(vetter_key(context_id, community), &record)
                .await?;
            LoadedVetter {
                record,
                engine,
                enrolments: BTreeMap::new(),
            }
        }
    };
    let period = label.trim_start_matches("vetter/");
    let mut rng = vti_vetting_pcs::rand::rngs::OsRng;
    let (wire, blinding) = v
        .engine
        .enrolment_request(&params, period, &mut rng)
        .map_err(proto)?;
    let blinding = blinding
        .to_bytes()
        .map_err(|e| proto(ProtoError::from(e)))?;
    v.enrolments.insert(
        label.to_string(),
        predicate_credential_system::serialization::to_multibase(&blinding),
    );
    save_vetter(state, &v).await?;
    Ok(serde_json::to_value(&wire).map_err(|e| AppError::Internal(e.to_string()))?)
}

/// `vta/pcs/root-accept`: unblind the community's answer into the vetter's class credential.
pub async fn root_accept(
    state: &AppState,
    caller: &Caller<'_>,
    context_id: &str,
    community: &str,
    published: &Value,
    label: &str,
    pre_credential: &str,
) -> Result<Value> {
    let params = community_params(community, published)?;
    let _guard = write_lock().await;
    let record = vetter_record(state, context_id, community)
        .await?
        .ok_or(PcsError::NotFound)?;
    let mut v = load_vetter(state, caller, record).await?;
    let Some(encoded) = v.enrolments.get(label).cloned() else {
        return Err(PcsError::NoRequestInFlight);
    };
    let bytes = Zeroizing::new(
        predicate_credential_system::serialization::from_multibase(&encoded)
            .map_err(|e| proto(ProtoError::from(e)))?,
    );
    let blinding = EnrolmentBlinding::from_bytes(&bytes).map_err(|e| proto(ProtoError::from(e)))?;
    v.engine
        .accept_enrolment(
            &params,
            &RootCredentialWire {
                label: label.to_string(),
                pre_credential: pre_credential.to_string(),
            },
            &blinding,
        )
        .map_err(|e| PcsError::CredentialInvalid(e.to_string()))?;
    v.enrolments.remove(label);
    save_vetter(state, &v).await?;
    loaded_summary(&v)
}

/// `vta/pcs/tokens/request`: one draw of the drip, recorded as in flight.
#[allow(clippy::too_many_arguments)]
pub async fn tokens_request(
    state: &AppState,
    caller: &Caller<'_>,
    context_id: &str,
    community: &str,
    published: &Value,
    label: &str,
    tick: u32,
    count: usize,
) -> Result<Value> {
    let params = community_params(community, published)?;
    if !params.tokens().live_labels().contains(label) {
        return Err(PcsError::LabelNotLive(label.to_string()));
    }
    if count > params.drip_per_tick() {
        return Err(PcsError::CountExceedsDrip {
            asked: count,
            drip: params.drip_per_tick(),
        });
    }
    let _guard = write_lock().await;
    let record = vetter_record(state, context_id, community)
        .await?
        .ok_or(PcsError::NotFound)?;
    let mut v = load_vetter(state, caller, record).await?;
    if v.engine
        .draws_in_flight()
        .iter()
        .any(|(l, t)| l == label && *t == tick)
    {
        return Err(PcsError::AlreadyInFlight);
    }
    let mut rng = vti_vetting_pcs::rand::rngs::OsRng;
    let wire = v
        .engine
        .drip_request(&params, tick, label, count, &mut rng)
        .map_err(proto)?;
    save_vetter(state, &v).await?;
    Ok(serde_json::to_value(&wire).map_err(|e| AppError::Internal(e.to_string()))?)
}

/// `vta/pcs/tokens/accept`: take the community's answer to a draw into the wallet.
pub async fn tokens_accept(
    state: &AppState,
    caller: &Caller<'_>,
    context_id: &str,
    community: &str,
    published: &Value,
    answer: TokenBatchWire,
) -> Result<(usize, Value)> {
    let params = community_params(community, published)?;
    let _guard = write_lock().await;
    let record = vetter_record(state, context_id, community)
        .await?
        .ok_or(PcsError::NotFound)?;
    let mut v = load_vetter(state, caller, record).await?;
    if !v
        .engine
        .draws_in_flight()
        .iter()
        .any(|(l, t)| *l == answer.label && *t == answer.tick)
    {
        return Err(PcsError::NoDrawInFlight);
    }
    // On a refusal nothing is saved, so the draw stays in flight at rest, as the
    // specification asks: a correct answer can still be taken.
    let received = v
        .engine
        .accept_drip(&params, &answer)
        .map_err(|e| PcsError::TokensInvalid(e.to_string()))?;
    save_vetter(state, &v).await?;
    Ok((received, loaded_summary(&v)?))
}

/// `vta/pcs/tokens/abandon`: discard a draw the community refused. Needs no parameters and no
/// key: it edits the stored state alone.
pub async fn tokens_abandon(
    state: &AppState,
    context_id: &str,
    community: &str,
    label: &str,
    tick: u32,
) -> Result<Value> {
    let _guard = write_lock().await;
    let record = vetter_record(state, context_id, community)
        .await?
        .ok_or(PcsError::NotFound)?;
    let mut st = load_vetter_state(state, &record).await?;
    let before = st.snapshot.pending.len();
    st.snapshot
        .pending
        .retain(|p| !(p.label == label && p.tick == tick));
    if st.snapshot.pending.len() == before {
        return Err(PcsError::NoDrawInFlight);
    }
    store_secret_json(
        state,
        &vetter_key(context_id, community),
        VETTER_STATE_TYPE,
        record.seed_id,
        &st,
    )
    .await?;
    Ok(vetter_summary(&record, &st.snapshot, &st.enrolments))
}

/// `vta/pcs/attest`: spend a token and attest for `applicant_id`. Returns the attestation in
/// its wire form (`vetting/attestation/0.1`, without `ext`).
#[allow(clippy::too_many_arguments)]
pub async fn attest(
    state: &AppState,
    caller: &Caller<'_>,
    context_id: &str,
    community: &str,
    published: &Value,
    applicant_id: &str,
    meta: StatementMeta,
    prefer_label: Option<&str>,
) -> Result<Value> {
    let params = community_params(community, published)?;
    if meta.community != community {
        return Err(PcsError::CommunityMismatch);
    }
    let id = point_from_text(applicant_id).map_err(|_| PcsError::ApplicantInvalid)?;
    let _guard = write_lock().await;
    let record = vetter_record(state, context_id, community)
        .await?
        .ok_or(PcsError::NotFound)?;
    let mut v = load_vetter(state, caller, record).await?;
    // Enrolment before a token is reserved: a vetter with no live credential has nothing to
    // attest under, and "no token" would send it to wait for a drip that cannot help.
    let snap = v.engine.snapshot().map_err(proto)?;
    let enrolled = params.vetter_labels().iter().any(|l| {
        snap.credentials
            .contains_key(l.trim_start_matches("vetter/"))
    });
    if !enrolled {
        return Err(PcsError::NotEnrolled);
    }
    let preferred = prefer_label.filter(|l| params.tokens().live_labels().contains(*l));
    let reservation = v.engine.accept(preferred, 0).map_err(|e| match e {
        ProtoError::AtCapacity { .. } => PcsError::NoToken,
        other => proto(other),
    })?;
    let mut rng = vti_vetting_pcs::rand::rngs::OsRng;
    let attestation = match v.engine.attest(&params, &reservation, &id, meta, &mut rng) {
        Ok(a) => a,
        Err(ProtoError::NoLiveCredential) => return Err(PcsError::NotEnrolled),
        Err(ProtoError::AtCapacity { .. }) => return Err(PcsError::NoToken),
        Err(e) => return Err(proto(e)),
    };
    save_vetter(state, &v).await?;
    let held = HeldAttestation::of(&attestation).map_err(proto)?;
    Ok(attestation_wire(&held))
}

/// `vta/pcs/vetter/show`. Reads stored state alone: no key is derived.
pub async fn vetter_show(state: &AppState, context_id: &str, community: &str) -> Result<Value> {
    let record = vetter_record(state, context_id, community)
        .await?
        .ok_or(PcsError::NotFound)?;
    let st = load_vetter_state(state, &record).await?;
    Ok(vetter_summary(&record, &st.snapshot, &st.enrolments))
}

// ─── Applicant ───────────────────────────────────────────────────────────────

/// An attestation in its wire form (`vetting/attestation/0.1` without `ext`).
fn attestation_wire(held: &HeldAttestation) -> Value {
    json!({
        "suite": SUITE,
        "attestation": held.attestation,
        "meta": held.meta,
        "token": {
            "label": held.token_label,
            "serial": held.token_serial,
            "shown": held.token_shown,
        },
    })
}

/// The inverse of [`attestation_wire`].
fn held_from_wire(wire: &Value) -> Result<HeldAttestation> {
    let suite = wire
        .get("suite")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if suite != SUITE {
        return Err(PcsError::UnsupportedSuite(suite.to_string()));
    }
    let t = |k: &str| {
        wire.pointer(&format!("/token/{k}"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let meta: StatementMeta = serde_json::from_value(wire.get("meta").cloned().unwrap_or_default())
        .map_err(|e| PcsError::AttestationInvalid(e.to_string()))?;
    Ok(HeldAttestation {
        attestation: wire
            .get("attestation")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        meta,
        token_label: t("label"),
        token_serial: t("serial"),
        token_shown: t("shown"),
    })
}

fn application_summary(record: &ApplicationRecord, held: &[HeldAttestation]) -> Value {
    json!({
        "applicationId": record.application_id,
        "contextId": record.context_id,
        "community": record.community,
        "joinDid": record.join_did,
        "suite": record.suite,
        "id": record.id,
        "attestations": held.iter().map(|h| &h.meta).collect::<Vec<_>>(),
        "createdAt": record.created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}

/// The application with this handle, if the caller may see it. A handle in a context the caller
/// has no standing in reads as absent, so a refusal does not confirm that it exists.
pub async fn application_record(
    state: &AppState,
    application_id: &str,
    may_act_in: impl Fn(&str) -> bool,
) -> Result<ApplicationRecord> {
    let record: ApplicationRecord = state
        .pcs_engine_ks
        .get(app_key(application_id))
        .await?
        .ok_or(PcsError::NotFound)?;
    if !may_act_in(&record.context_id) {
        return Err(PcsError::NotFound);
    }
    Ok(record)
}

async fn load_applicant_state(
    state: &AppState,
    record: &ApplicationRecord,
) -> Result<ApplicantState> {
    load_secret_json(
        state,
        &app_key(&record.application_id),
        APPLICANT_STATE_TYPE,
        record.seed_id,
    )
    .await
}

async fn load_applicant(
    state: &AppState,
    caller: &Caller<'_>,
    record: &ApplicationRecord,
) -> Result<ApplicantEngine> {
    let st = load_applicant_state(state, record).await?;
    let seed = member_seed(
        state,
        caller,
        &record.context_id,
        &record.path,
        record.seed_id,
    )
    .await?;
    let (id, usk) = member_key_from_seed(&record.community, &seed).map_err(proto)?;
    let mut snap = ApplicantSnapshot::new(&usk, &id, &record.join_did).map_err(proto)?;
    snap.held = st.held;
    ApplicantEngine::restore(&snap).map_err(proto)
}

async fn save_applicant(
    state: &AppState,
    record: &ApplicationRecord,
    held: Vec<HeldAttestation>,
) -> Result<()> {
    store_secret_json(
        state,
        &app_key(&record.application_id),
        APPLICANT_STATE_TYPE,
        record.seed_id,
        &ApplicantState { held },
    )
    .await
}

/// `vta/pcs/applications/create`.
pub async fn create_application(
    state: &AppState,
    caller: &Caller<'_>,
    context_id: &str,
    community: &str,
    join_did: &str,
    published: &Value,
) -> Result<Value> {
    let params = community_params(community, published)?;
    let (path, seed_id) = allocate_member_path(state, context_id).await?;
    let seed = member_seed(state, caller, context_id, &path, seed_id).await?;
    let engine = ApplicantEngine::from_seed(&params, join_did, &seed).map_err(proto)?;
    let record = ApplicationRecord {
        application_id: uuid::Uuid::new_v4().to_string(),
        context_id: context_id.to_string(),
        community: community.to_string(),
        join_did: join_did.to_string(),
        suite: SUITE.to_string(),
        path,
        seed_id,
        id: point_text(engine.id()).map_err(proto)?,
        created_at: Utc::now(),
    };
    let _guard = write_lock().await;
    save_applicant(state, &record, Vec::new()).await?;
    state
        .pcs_engine_ks
        .insert(app_key(&record.application_id), &record)
        .await?;
    Ok(application_summary(&record, &[]))
}

/// `vta/pcs/applications/show`. Reads stored state alone: no key is derived.
pub async fn show_application(state: &AppState, record: &ApplicationRecord) -> Result<Value> {
    let st = load_applicant_state(state, record).await?;
    Ok(application_summary(record, &st.held))
}

/// `vta/pcs/applications/delete`: the record and the wrapped state. The key goes with them —
/// it was never stored, and nothing names its path any more.
pub async fn delete_application(state: &AppState, record: &ApplicationRecord) -> Result<()> {
    let _guard = write_lock().await;
    vta_keys::imported::delete_secret(&state.pcs_engine_ks, &app_key(&record.application_id))
        .await?;
    state
        .pcs_engine_ks
        .remove(app_key(&record.application_id))
        .await?;
    Ok(())
}

/// `vta/pcs/verify-attestation`: check an attestation against the application and keep it,
/// replacing an earlier one from the same vetter. Returns the summary and the metadata taken.
pub async fn verify_attestation(
    state: &AppState,
    caller: &Caller<'_>,
    record: &ApplicationRecord,
    published: &Value,
    attestation: &Value,
) -> Result<(Value, Value)> {
    let params = community_params(&record.community, published)?;
    let held = held_from_wire(attestation)?;
    if held.meta.community != record.community {
        return Err(PcsError::AttestationInvalid(
            "the attestation is for another community".into(),
        ));
    }
    let att = held
        .restore()
        .map_err(|e| PcsError::AttestationInvalid(e.to_string()))?;
    let _guard = write_lock().await;
    let mut engine = load_applicant(state, caller, record).await?;
    engine
        .replace(&params, att)
        .map_err(|e| PcsError::AttestationInvalid(e.to_string()))?;
    let snap = engine.snapshot().map_err(proto)?;
    save_applicant(state, record, snap.held.clone()).await?;
    let accepted =
        serde_json::to_value(&held.meta).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok((application_summary(record, &snap.held), accepted))
}

/// `vta/pcs/prove`: the `extensions.hiddenVetting` member of a join submission.
pub async fn prove(
    state: &AppState,
    caller: &Caller<'_>,
    record: &ApplicationRecord,
    published: &Value,
    requirements_digest: &str,
    challenge: &str,
) -> Result<Value> {
    let params = community_params(&record.community, published)?;
    let engine = load_applicant(state, caller, record).await?;
    if engine.usable(&params).map_err(proto)? == 0 {
        return Err(PcsError::NoUsableAttestation);
    }
    let mut rng = vti_vetting_pcs::rand::rngs::OsRng;
    let submission = engine
        .submit(&params, requirements_digest, challenge, &mut rng)
        .map_err(proto)?;
    let wire = SubmissionWire::from_submission(&submission).map_err(proto)?;
    Ok(serde_json::to_value(&wire).map_err(|e| AppError::Internal(e.to_string()))?)
}
