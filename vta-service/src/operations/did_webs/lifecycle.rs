//! Update, rotate and delete a `did:webs` this VTA holds (`vta/webs/dids/*`,
//! step 5 of `docs/05-design-notes/did-webs-in-the-vta.md`).
//!
//! # Rules every write keeps
//!
//! - **Remote first (R2.1).** The host accepts the new stream before anything
//!   here changes. A refused or unreachable host leaves the record as it was.
//! - **A rotation is staged.** It is signed, then stored in the record with the
//!   new successor's key record, then published, then committed. The successor
//!   that signed it cannot sign a second, different rotation, so a staged one is
//!   only ever published again, never replaced: the next rotation answers with
//!   it (`resumed`), and every other write completes it first.
//! - **Keys a record names are re-derived through key custody**
//!   (`key_custody::derive_record_key`); only a key minted fresh here (a new
//!   successor, a new key agreement key) touches the seed, through
//!   [`super::fresh_key`].
//! - **A deactivated identifier signs nothing more.**

use affinidi_did_webs::key_roles::{KeyRole, KeyRoles, VerificationKey};
use affinidi_did_webs::{
    Artifacts, Change, ControlledUpdate, DesignatedService, Kels, KeyAgreementKey,
    complete_rotation, designated_aliases, designated_key_agreement, designated_services,
    prepare_rotation, update_controlled,
};
use affinidi_keri::controller::{ControllerState, KeySigner, NextKey, Rotation};
use affinidi_keri_core::threshold::Threshold;
use affinidi_keri_crypto::Signer;
use chrono::Utc;
use serde_json::{Value, json};
use vta_sdk::keys::{KeyRecord, KeyStatus};

use super::{
    DIDCOMM_FRAGMENT, WebsDeps, WebsError, WebsHost, WebsRefusal, ed25519_qb64, ed25519_raw,
    ed25519_signer, fresh_key,
};
use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::keys::{self, KeyType, store_key};
use crate::operations::protocol::document::{TSP_SERVICE_FRAGMENT, TSP_SERVICE_TYPE};
use crate::store::KeyspaceHandle;
use crate::webs_store::{self, StagedRotation, WebsDidRecord};
use vta_sdk::protocol::matching::DIDCOMM_SERVICE_TYPE;

/// The version a write is based on: `<sn>:<said>` of the latest committed
/// event (the `vta/dids` webs profile §3).
pub fn version_id(state: &ControllerState) -> String {
    format!("{}:{}", state.sn, state.last_said)
}

/// The whole designated service set an update asks for.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct WebsServices {
    /// `#didcomm`, `DIDCommMessaging`, through this VTA's mediator.
    pub mediator: bool,
    /// `#tsp`, `TSPTransport`, through this VTA's mediator.
    pub tsp: bool,
    /// Any further services.
    pub additional: Vec<DesignatedService>,
}

impl WebsServices {
    pub fn new(mediator: bool, tsp: bool, additional: Vec<DesignatedService>) -> Self {
        Self {
            mediator,
            tsp,
            additional,
        }
    }
}

/// `vta/webs/dids/update/0.1`.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct UpdateDidWebsParams {
    pub did: String,
    /// Replaces the whole designated service set.
    pub services: Option<WebsServices>,
    /// Designate a freshly derived X25519 key in place of the current one.
    pub rotate_key_agreement_key: bool,
    /// Replaces the further aliases; the DID itself stays first.
    pub also_known_as: Option<Vec<String>>,
    /// Refuse unless this names the latest committed event (`<sn>:<said>`).
    pub expected_version_id: Option<String>,
    pub label: Option<String>,
}

impl UpdateDidWebsParams {
    pub fn new(did: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpdateDidWebsResult {
    pub did: String,
    /// What changed: `aliases`, `keyAgreement`, `services`.
    pub replaced: Vec<String>,
    pub sequence_number: u64,
    pub version_id: String,
    pub key_agreement_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RotateDidWebsResult {
    pub did: String,
    pub sequence_number: u64,
    pub version_id: String,
    /// The key record of the key the rotation installed.
    pub signing_key_id: String,
    /// That key, qb64.
    pub signing_public_key: String,
    pub next_key_id: String,
    pub retired_key_id: String,
    /// The rotation answered was one already staged.
    pub resumed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeleteDidWebsResult {
    pub did: String,
    pub deactivated: bool,
    /// False when the DID was already deactivated before this request.
    pub newly_deactivated: bool,
    pub version_id: String,
    pub slot_removed: bool,
    /// Why the host did not confirm removing the slot. Not an error: the
    /// deactivation is committed either way.
    pub host_cleanup_error: Option<String>,
}

fn deactivated_error(did: &str) -> WebsError {
    WebsError::refused(
        WebsRefusal::Deactivated,
        format!("deactivated: {did} is deactivated, and nothing more is signed as it"),
    )
}

/// The record of `did`, for a caller who may act in its context.
async fn held(
    deps: &WebsDeps<'_>,
    auth: &AuthClaims,
    did: &str,
) -> Result<WebsDidRecord, WebsError> {
    webs_store::get(deps.webs_ks, did)
        .await?
        .filter(|r| auth.has_context_access(&r.context_id))
        .ok_or_else(|| {
            WebsError::refused(WebsRefusal::NotFound, format!("did:webs not found: {did}"))
        })
}

fn check_expected(record: &WebsDidRecord, expected: Option<&str>) -> Result<(), WebsError> {
    let current = version_id(&record.state);
    match expected {
        Some(expected) if expected != current => Err(WebsError::refused(
            WebsRefusal::VersionConflict,
            format!(
                "versionConflict: {} is at {current}, not {expected}",
                record.did
            ),
        )),
        _ => Ok(()),
    }
}

/// A signer for the key `key_id` names, through key custody: the record must
/// be an active Ed25519 key of the DID's own context.
async fn signer_for(
    deps: &WebsDeps<'_>,
    auth: &AuthClaims,
    record: &WebsDidRecord,
    key_id: &str,
    channel: &str,
) -> Result<Signer, AppError> {
    let key: KeyRecord = deps.keys_ks.get(store_key(key_id)).await?.ok_or_else(|| {
        AppError::Internal(format!(
            "the key record {key_id} of {} is missing; the identifier cannot sign",
            record.did
        ))
    })?;
    if key.status != KeyStatus::Active
        || key.key_type != KeyType::Ed25519
        || key.context_id.as_deref() != Some(record.context_id.as_str())
    {
        return Err(AppError::Internal(format!(
            "the key record {key_id} is not an active Ed25519 key of {}'s context",
            record.did
        )));
    }
    let derived = crate::operations::key_custody::derive_record_key(
        deps.contexts_ks,
        deps.keys_ks,
        deps.seed_store,
        deps.audit,
        &auth.did,
        &key,
        channel,
    )
    .await?;
    let bytes = derived.ed25519_signing_key_bytes()?;
    ed25519_signer(bytes.as_slice())
}

fn artifacts(keri_cesr: &[u8]) -> Artifacts {
    // Only the stream carries authority; `did_json` is re-derived from it.
    Artifacts {
        keri_cesr: keri_cesr.to_vec(),
        did_json: Vec::new(),
    }
}

async fn publish<H: WebsHost>(
    host: &H,
    record: &WebsDidRecord,
    keri_cesr: &[u8],
) -> Result<(), WebsError> {
    let text = std::str::from_utf8(keri_cesr).map_err(|_| {
        AppError::Internal("the key event stream is not text; it cannot be published".into())
    })?;
    let published = host
        .publish(&record.mnemonic, text, record.domain.as_deref())
        .await
        .map_err(WebsError::from_host)?;
    if published.did_url != record.did {
        return Err(AppError::Internal(format!(
            "the hosting server published {} for slot {}, not {}",
            published.did_url, record.mnemonic, record.did
        ))
        .into());
    }
    Ok(())
}

/// Commit a staged rotation the host has accepted.
///
/// Each step is idempotent, so a commit cut short is finished by running it
/// again; the row, which says the rotation is staged, is written last.
async fn commit_staged(
    keys_ks: &KeyspaceHandle,
    webs_ks: &KeyspaceHandle,
    mut record: WebsDidRecord,
) -> Result<(WebsDidRecord, Option<String>), WebsError> {
    let Some(staged) = record.staged.take() else {
        return Ok((record, None));
    };
    let retired_key_id = staged.retired_key_id.clone();
    let now = Utc::now();
    // The installed successor becomes the signing key, under its VM id.
    if staged.signing_key_id != record.next_key_id
        && let Some(mut successor) = keys_ks
            .get::<KeyRecord>(store_key(&record.next_key_id))
            .await?
    {
        successor.key_id = staged.signing_key_id.clone();
        successor.status = KeyStatus::Active;
        successor.updated_at = now;
        keys_ks
            .insert(store_key(&staged.signing_key_id), &successor)
            .await?;
        keys_ks.remove(store_key(&record.next_key_id)).await?;
    }
    if let Some(mut retired) = keys_ks
        .get::<KeyRecord>(store_key(&staged.retired_key_id))
        .await?
    {
        retired.status = KeyStatus::Revoked;
        retired.updated_at = now;
        keys_ks
            .insert(store_key(&staged.retired_key_id), &retired)
            .await?;
    }
    record.keri_cesr = staged.keri_cesr;
    record.state = staged.state;
    record.signing_key_id = staged.signing_key_id;
    match staged.next_key_id {
        Some(next) => record.next_key_id = next,
        None => {
            record.deactivated = true;
            record.next_key_id = String::new();
        }
    }
    record.updated_at = now.to_rfc3339();
    webs_store::put(webs_ks, &record).await?;
    Ok((record, Some(retired_key_id)))
}

/// Publish the staged rotation of `record` again and commit it, answering the
/// key record it retired (`None` when nothing was staged).
async fn complete_staged<H: WebsHost>(
    deps: &WebsDeps<'_>,
    host: &H,
    record: WebsDidRecord,
) -> Result<(WebsDidRecord, Option<String>), WebsError> {
    let Some(staged) = record.staged.as_ref() else {
        return Ok((record, None));
    };
    publish(host, &record, &staged.keri_cesr).await?;
    commit_staged(deps.keys_ks, deps.webs_ks, record).await
}

/// The DIDs with a rotation staged and not yet committed: each is published
/// again and committed by its next write. Listed at startup, because finishing
/// one needs its host, which is reached only once the node is up.
pub async fn staged_webs_rotations(webs_ks: &KeyspaceHandle) -> Result<Vec<String>, AppError> {
    Ok(webs_store::list(webs_ks)
        .await?
        .into_iter()
        .filter(|r| r.staged.is_some())
        .map(|r| r.did)
        .collect())
}

/// Sign, stage, publish and commit a rotation installing the committed
/// successor, committing `next` (none: the identifier is deactivated).
async fn rotate_to<H: WebsHost>(
    deps: &WebsDeps<'_>,
    auth: &AuthClaims,
    host: &H,
    mut record: WebsDidRecord,
    channel: &str,
    deactivate: bool,
) -> Result<(WebsDidRecord, Option<String>), WebsError> {
    let ctx = crate::contexts::get_context(deps.contexts_ks, &record.context_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {}", record.context_id)))?;
    let successor = signer_for(deps, auth, &record, &record.next_key_id, channel).await?;
    let successor_qb64 = successor
        .public_key()
        .map_err(|e| AppError::Internal(format!("encode the successor: {e}")))?;
    let label = record
        .label
        .clone()
        .unwrap_or_else(|| format!("did:webs in {}", record.context_id));

    let (rotation, next) = if deactivate {
        (
            Rotation::new(Threshold::Simple(1), Vec::new(), Threshold::Simple(0)),
            None,
        )
    } else {
        let (key, seed_id) = fresh_key(deps, &ctx.base_path, &label).await?;
        let qb64 = ed25519_qb64(&key.public_key)?;
        (
            Rotation::new(
                Threshold::Simple(1),
                vec![NextKey::PublicKey(qb64)],
                Threshold::Simple(1),
            ),
            Some((key, seed_id)),
        )
    };
    let mut pending = prepare_rotation(
        &record.did,
        &artifacts(&record.keri_cesr),
        &record.state,
        std::slice::from_ref(&successor_qb64),
        &rotation,
    )
    .map_err(|e| AppError::Internal(format!("prepare the rotation of {}: {e}", record.did)))?;
    pending
        .sign_with(&successor as &dyn KeySigner)
        .map_err(|e| AppError::Internal(format!("sign the rotation: {e}")))?;
    drop(successor);
    let rotated = complete_rotation(&record.did, &artifacts(&record.keri_cesr), pending)
        .map_err(|e| AppError::Internal(format!("complete the rotation of {}: {e}", record.did)))?;
    let (rotated, state) = rotated.into_parts();

    // Stage: the new successor's key record, then the signed event.
    let next_key_id = match next {
        Some((key, seed_id)) => {
            let id = format!("{}#pre-rotation-{}", record.did, state.sn);
            keys::save_key_record(
                deps.keys_ks,
                &id,
                &key.path,
                KeyType::Ed25519,
                &key.public_key,
                &key.label,
                Some(&record.context_id),
                Some(seed_id),
            )
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
            Some(id)
        }
        None => None,
    };
    record.staged = Some(StagedRotation {
        keri_cesr: rotated.keri_cesr,
        state,
        signing_key_id: format!("{}#{successor_qb64}", record.did),
        next_key_id,
        retired_key_id: record.signing_key_id.clone(),
    });
    webs_store::put(deps.webs_ks, &record).await?;

    complete_staged(deps, host, record).await
}

/// Rotate `did` to its committed successor and commit a fresh one
/// (`vta/webs/dids/rotate-keys/0.1`).
///
/// # Errors
/// `NotFound`, `Conflict` (`deactivated`, `versionConflict`), or the host's
/// refusal, which leaves the rotation staged.
pub async fn rotate_did_webs_keys<H: WebsHost>(
    deps: &WebsDeps<'_>,
    auth: &AuthClaims,
    did: &str,
    expected_version_id: Option<&str>,
    host: &H,
    channel: &str,
) -> Result<RotateDidWebsResult, WebsError> {
    // As `webvh/dids/rotate-keys`: an admin of the DID's context.
    auth.require_admin()?;
    let record = held(deps, auth, did).await?;
    if record.deactivated {
        return Err(deactivated_error(did));
    }
    let ((record, retired), resumed) = if record.staged.is_some() {
        (complete_staged(deps, host, record).await?, true)
    } else {
        check_expected(&record, expected_version_id)?;
        (
            rotate_to(deps, auth, host, record, channel, false).await?,
            false,
        )
    };
    vta_audit::record_best_effort(
        deps.audit,
        "did.rotate.webs",
        &auth.did,
        Some(did),
        "success",
        Some(channel),
        Some(&record.context_id),
    )
    .await;
    let signing_key = record
        .signing_key_id
        .rsplit_once('#')
        .map(|(_, k)| k.to_string())
        .unwrap_or_default();
    let retired_key_id = retired.unwrap_or_default();
    Ok(RotateDidWebsResult {
        did: record.did.clone(),
        sequence_number: record.state.sn,
        version_id: version_id(&record.state),
        signing_key_id: record.signing_key_id.clone(),
        signing_public_key: signing_key,
        next_key_id: record.next_key_id.clone(),
        retired_key_id,
        resumed,
    })
}

/// The further aliases in force: the designation less the three every
/// `did:webs` designates for itself (itself, its `did:web` twin, `did:keri`).
fn further_aliases(record: &WebsDidRecord, aliases: &[String]) -> Vec<String> {
    let web = record.did.replacen("did:webs:", "did:web:", 1);
    let keri = format!("did:keri:{}", record.aid);
    aliases
        .iter()
        .filter(|a| **a != record.did && **a != web && **a != keri)
        .cloned()
        .collect()
}

/// A service in a comparable form: its fragment, its types sorted, its
/// endpoint.
fn service_key(id: &str, type_: &Value, endpoint: &Value) -> (String, Vec<String>, String) {
    let fragment = id.rsplit_once('#').map_or(id, |(_, f)| f).to_string();
    let mut types: Vec<String> = match type_ {
        Value::Array(a) => a
            .iter()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect(),
        Value::String(t) => vec![t.clone()],
        _ => Vec::new(),
    };
    types.sort();
    (fragment, types, endpoint.to_string())
}

fn desired_services(
    deps: &WebsDeps<'_>,
    services: &WebsServices,
) -> Result<Vec<DesignatedService>, WebsError> {
    let mediator = deps
        .config
        .messaging
        .as_ref()
        .map(|m| m.mediator_did.trim().to_string())
        .filter(|did| !did.is_empty());
    let mut out = Vec::new();
    if services.mediator || services.tsp {
        let mediator = mediator.ok_or_else(|| {
            AppError::Validation(
                "a #didcomm or #tsp service routes through this VTA's mediator, and none is \
                 configured (`[messaging] mediator_did`)"
                    .into(),
            )
        })?;
        if services.mediator {
            out.push(DesignatedService::new(
                DIDCOMM_FRAGMENT,
                DIDCOMM_SERVICE_TYPE,
                json!([{ "accept": ["didcomm/v2"], "uri": mediator }]),
            ));
        }
        if services.tsp {
            out.push(DesignatedService::new(
                TSP_SERVICE_FRAGMENT,
                TSP_SERVICE_TYPE,
                json!(mediator),
            ));
        }
    }
    out.extend(services.additional.iter().cloned());
    // In transport-preference order, as a create designates them.
    super::sort_designated_services(&mut out);
    let mut ids = std::collections::BTreeSet::new();
    for s in &out {
        if !ids.insert(s.id.clone()) {
            return Err(WebsError::refused(
                WebsRefusal::ServiceIdConflict,
                format!("serviceIdConflict: two services have the id {}", s.id),
            ));
        }
    }
    Ok(out)
}

/// Replace designations of `did` without touching its keys
/// (`vta/webs/dids/update/0.1`).
///
/// Each replacement is applied with `affinidi_did_webs::update_controlled`,
/// which anchors it in interaction events: one change per call, so an update
/// asking for several writes the events of each in turn.
///
/// # Errors
/// `NotFound`, `Conflict` (`deactivated`, `versionConflict`,
/// `serviceIdConflict`), `Validation` (`noChange`), or the host's refusal,
/// which leaves the record as it was.
pub async fn update_did_webs<H: WebsHost>(
    deps: &WebsDeps<'_>,
    auth: &AuthClaims,
    params: UpdateDidWebsParams,
    host: &H,
    channel: &str,
) -> Result<UpdateDidWebsResult, WebsError> {
    // As `webvh/dids/update`: an admin of the DID's context.
    auth.require_admin()?;
    let record = held(deps, auth, &params.did).await?;
    if record.deactivated {
        return Err(deactivated_error(&params.did));
    }
    let (mut record, _) = complete_staged(deps, host, record).await?;
    if record.deactivated {
        return Err(deactivated_error(&params.did));
    }
    check_expected(&record, params.expected_version_id.as_deref())?;

    let kels = Kels::parse(&record.keri_cesr)
        .map_err(|e| AppError::Internal(format!("read the stream of {}: {e}", record.did)))?;
    let mut changes = Vec::new();
    let mut replaced = Vec::new();

    if let Some(aliases) = &params.also_known_as {
        let current = designated_aliases(&kels, &record.aid)
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        let mut have = further_aliases(&record, &current.aliases);
        let mut want = aliases.clone();
        have.sort();
        want.sort();
        if have != want {
            changes.push(Change::AlsoKnownAs(aliases.clone()));
            replaced.push("aliases".to_string());
        }
    }

    let mut new_ka = None;
    if params.rotate_key_agreement_key {
        let ctx = crate::contexts::get_context(deps.contexts_ks, &record.context_id)
            .await?
            .ok_or_else(|| {
                AppError::NotFound(format!("context not found: {}", record.context_id))
            })?;
        let label = format!(
            "{} key-agreement key",
            record.label.clone().unwrap_or_else(|| record.did.clone())
        );
        let (key, seed_id) = fresh_key(deps, &ctx.base_path, &label).await?;
        let (_, ed) =
            multibase::decode(&key.public_key).map_err(|e| AppError::Internal(format!("{e}")))?;
        let ed: [u8; 32] = ed
            .strip_prefix(&[0xed, 0x01][..])
            .and_then(|raw| raw.try_into().ok())
            .ok_or_else(|| AppError::Internal("a derived key is not Ed25519".into()))?;
        let x = affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&ed)
            .map_err(|e| AppError::Internal(format!("X25519 image: {e}")))?;
        let ka = KeyAgreementKey::X25519(x);
        let cesr = ka
            .to_cesr()
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        let current = designated_key_agreement(&kels, &record.aid)
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        if current.keys.contains(&cesr) {
            return Err(AppError::Internal(
                "a freshly derived key agreement key is already designated".into(),
            )
            .into());
        }
        changes.push(Change::KeyAgreement(vec![ka]));
        replaced.push("keyAgreement".to_string());
        new_ka = Some((key, seed_id, cesr, x));
    }

    if let Some(services) = &params.services {
        let want = desired_services(deps, services)?;
        let current = designated_services(&kels, &record.aid)
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        let mut have: Vec<_> = current
            .services
            .iter()
            .map(|s| {
                service_key(
                    s["id"].as_str().unwrap_or_default(),
                    &s["type"],
                    &s["serviceEndpoint"],
                )
            })
            .collect();
        let mut wanted: Vec<_> = want
            .iter()
            .map(|s| service_key(&s.id, &s.type_, &s.service_endpoint))
            .collect();
        have.sort();
        wanted.sort();
        if have != wanted {
            changes.push(Change::DesignatedServices(want));
            replaced.push("services".to_string());
        }
    }

    if changes.is_empty() {
        return Err(WebsError::refused(
            WebsRefusal::NoChange,
            format!(
                "noChange: the update sets what {} already designates",
                record.did
            ),
        ));
    }

    let signer = signer_for(deps, auth, &record, &record.signing_key_id, channel).await?;
    let mut stream = record.keri_cesr.clone();
    let mut state = record.state.clone();
    for change in changes {
        let updated = update_controlled(
            ControlledUpdate::new(record.did.clone(), artifacts(&stream), state, change),
            &[&signer as &dyn KeySigner],
        )
        .map_err(|e| AppError::Internal(format!("update {}: {e}", record.did)))?;
        let (a, s) = updated.into_parts();
        stream = a.keri_cesr;
        state = s;
    }
    drop(signer);

    // ── Publish, then commit (R2.1) ────────────────────────────────────
    publish(host, &record, &stream).await?;
    if let Some((key, seed_id, cesr, x)) = new_ka {
        let id = format!("{}#{cesr}", record.did);
        keys::save_key_record(
            deps.keys_ks,
            &id,
            &key.path,
            KeyType::X25519,
            &keys::encode_public_multibase(&KeyType::X25519, &x),
            &key.label,
            Some(&record.context_id),
            Some(seed_id),
        )
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
        // The replaced key stays held, to decrypt what was already sent to it,
        // and is never designated again.
        record.key_agreement_key_id = id;
    }
    record.keri_cesr = stream;
    record.state = state;
    if params.label.is_some() {
        record.label = params.label.clone();
    }
    record.updated_at = Utc::now().to_rfc3339();
    webs_store::put(deps.webs_ks, &record).await?;

    vta_audit::record_best_effort(
        deps.audit,
        "did.update.webs",
        &auth.did,
        Some(&record.did),
        "success",
        Some(channel),
        Some(&record.context_id),
    )
    .await;

    Ok(UpdateDidWebsResult {
        did: record.did.clone(),
        replaced,
        sequence_number: record.state.sn,
        version_id: version_id(&record.state),
        key_agreement_key_id: record.key_agreement_key_id.clone(),
    })
}

/// What a role-key rotation replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RotateRoleKeysResult {
    pub did: String,
    /// The roles whose key was replaced (`attestation`, `operational`,
    /// `messaging`).
    pub rotated: Vec<String>,
    pub attestation_key_id: String,
    pub operational_key_id: String,
    pub key_agreement_key_id: String,
    pub sequence_number: u64,
    pub version_id: String,
    /// The DID is this VTA's own identity: the keys it authenticates,
    /// attests and decrypts with have changed ids, and only a restart loads
    /// them into every component that holds them (the bridge's signer, the
    /// DIDComm profile, TSP). The caller restarts the VTA.
    pub own_identity: bool,
}

/// Replace the keys bound to `roles` of a key-role did:webs (VTI-KEY-072,
/// VTI-KEY-173): planned rotation of role keys, by a new key-role designation
/// anchored in the key event log (`Change::KeyRoles`). Roles not named keep
/// their key. The key event log's own keys are untouched — that is
/// [`rotate_did_webs_keys`].
///
/// A replaced attestation or operational key is retired (its record revoked:
/// it signs nothing more); a replaced messaging key stays held, to decrypt
/// what was already sent to it, and is never designated again. New keys are
/// minted on fresh paths: a role key is never one of another role, nor a key
/// of the log (VTI-KEY-071), and the messaging key is the X25519 image of an
/// Ed25519 key on its own path that is published nowhere (VTI-KEY-184).
///
/// Published before it is recorded (R2.1); the host's refusal leaves the
/// record as it was.
///
/// # Errors
/// `NotFound`; `Conflict` (`deactivated`, `versionConflict`); `Validation`
/// for an identifier without key roles or an empty `roles`; the host's
/// refusal.
pub async fn rotate_did_webs_role_keys<H: WebsHost>(
    deps: &WebsDeps<'_>,
    auth: &AuthClaims,
    did: &str,
    roles: &[KeyRole],
    expected_version_id: Option<&str>,
    host: &H,
    channel: &str,
) -> Result<RotateRoleKeysResult, WebsError> {
    auth.require_admin()?;
    if roles.is_empty() {
        return Err(AppError::Validation("name at least one key role to rotate".into()).into());
    }
    let record = held(deps, auth, did).await?;
    if record.deactivated {
        return Err(deactivated_error(did));
    }
    let (mut record, _) = complete_staged(deps, host, record).await?;
    if record.deactivated {
        return Err(deactivated_error(did));
    }
    check_expected(&record, expected_version_id)?;
    let (Some(attestation_id), Some(operational_id)) = (
        record.attestation_key_id.clone(),
        record.operational_key_id.clone(),
    ) else {
        return Err(AppError::Validation(format!(
            "{did} is not a key-role identity: it has no role keys to rotate"
        ))
        .into());
    };
    let fragment = |id: &str| -> Result<String, AppError> {
        id.split_once('#')
            .map(|(_, f)| f.to_string())
            .ok_or_else(|| AppError::Internal(format!("key id {id} has no fragment")))
    };
    let verification = |id: &str| -> Result<VerificationKey, AppError> {
        VerificationKey::from_cesr(&fragment(id)?)
            .map_err(|e| AppError::Internal(format!("role key {id}: {e}")))
    };
    let mut attestation = verification(&attestation_id)?;
    let mut operational = verification(&operational_id)?;
    let mut messaging = KeyAgreementKey::from_cesr(&fragment(&record.key_agreement_key_id)?)
        .map_err(|e| AppError::Internal(format!("messaging key: {e}")))?;

    let ctx = crate::contexts::get_context(deps.contexts_ks, &record.context_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {}", record.context_id)))?;
    let label = record.label.clone().unwrap_or_else(|| record.did.clone());
    // (role, new key record id, path, key type, public multibase, label, seed)
    let mut minted: Vec<(KeyRole, String, String, KeyType, String, String, u32)> = Vec::new();
    for role in roles {
        if minted.iter().any(|m| m.0 == *role) {
            continue;
        }
        let (key, seed_id) = fresh_key(
            deps,
            &ctx.base_path,
            &format!("{label} {} key", role.name()),
        )
        .await?;
        match role {
            KeyRole::Attestation | KeyRole::Operational => {
                let vk = VerificationKey::Ed25519(ed25519_raw(&key.public_key)?);
                let cesr = vk
                    .to_cesr()
                    .map_err(|e| AppError::Internal(format!("encode a role key: {e}")))?;
                minted.push((
                    *role,
                    format!("{did}#{cesr}"),
                    key.path.clone(),
                    KeyType::Ed25519,
                    key.public_key.clone(),
                    key.label.clone(),
                    seed_id,
                ));
                if *role == KeyRole::Attestation {
                    attestation = vk;
                } else {
                    operational = vk;
                }
            }
            KeyRole::Messaging => {
                let ed = ed25519_raw(&key.public_key)?;
                let x = affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&ed)
                    .map_err(|e| AppError::Internal(format!("X25519 image: {e}")))?;
                let ka = KeyAgreementKey::X25519(x);
                let cesr = ka
                    .to_cesr()
                    .map_err(|e| AppError::Internal(format!("{e}")))?;
                minted.push((
                    *role,
                    format!("{did}#{cesr}"),
                    key.path.clone(),
                    KeyType::X25519,
                    keys::encode_public_multibase(&KeyType::X25519, &x),
                    key.label.clone(),
                    seed_id,
                ));
                messaging = ka;
            }
            other => {
                return Err(AppError::Validation(format!(
                    "the `{}` role is not one a node's identity holds",
                    other.name()
                ))
                .into());
            }
        }
    }

    let designation = KeyRoles::new()
        .with_attestation(attestation)
        .with_operational(operational)
        .with_messaging(messaging);
    let signer = signer_for(deps, auth, &record, &record.signing_key_id, channel).await?;
    let updated = update_controlled(
        ControlledUpdate::new(
            record.did.clone(),
            artifacts(&record.keri_cesr),
            record.state.clone(),
            Change::KeyRoles(designation),
        ),
        &[&signer as &dyn KeySigner],
    )
    .map_err(|e| AppError::Internal(format!("designate new role keys for {did}: {e}")))?;
    drop(signer);
    let (artifacts, state) = updated.into_parts();

    // ── Publish, then commit (R2.1) ────────────────────────────────────
    publish(host, &record, &artifacts.keri_cesr).await?;
    let mut rotated = Vec::new();
    for (role, id, path, key_type, public, key_label, seed_id) in minted {
        keys::save_key_record(
            deps.keys_ks,
            &id,
            &path,
            key_type,
            &public,
            &key_label,
            Some(&record.context_id),
            Some(seed_id),
        )
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
        let retired = match role {
            KeyRole::Attestation => Some(record.attestation_key_id.replace(id)),
            KeyRole::Operational => Some(record.operational_key_id.replace(id)),
            _ => {
                // The replaced messaging key stays held, for what was sent to it.
                record.key_agreement_key_id = id;
                None
            }
        };
        if let Some(Some(old)) = retired
            && let Some(mut old_record) = deps.keys_ks.get::<KeyRecord>(store_key(&old)).await?
        {
            old_record.status = KeyStatus::Revoked;
            deps.keys_ks.insert(store_key(&old), &old_record).await?;
        }
        rotated.push(role.name().to_string());
    }
    record.keri_cesr = artifacts.keri_cesr;
    record.state = state;
    record.updated_at = Utc::now().to_rfc3339();
    webs_store::put(deps.webs_ks, &record).await?;

    vta_audit::record_best_effort(
        deps.audit,
        "did.rotate_roles.webs",
        &auth.did,
        Some(did),
        "success",
        Some(channel),
        Some(&record.context_id),
    )
    .await;

    Ok(RotateRoleKeysResult {
        did: record.did.clone(),
        rotated,
        attestation_key_id: record.attestation_key_id.clone().unwrap_or_default(),
        operational_key_id: record.operational_key_id.clone().unwrap_or_default(),
        key_agreement_key_id: record.key_agreement_key_id.clone(),
        sequence_number: record.state.sn,
        version_id: version_id(&record.state),
        own_identity: deps.config.vta_did.as_deref() == Some(did),
    })
}

/// End `did`: a rotation committing to no next keys, then the slot removed
/// (`vta/webs/dids/delete/0.1`). The record is kept, deactivated, with the
/// final stream. Deleting a deactivated DID retries the slot's removal.
///
/// # Errors
/// `NotFound`, `Conflict` (`versionConflict`), or the host's refusal of the
/// deactivation, which leaves the DID live. A failed slot removal is not an
/// error: it is reported in the result.
pub async fn delete_did_webs<H: WebsHost>(
    deps: &WebsDeps<'_>,
    auth: &AuthClaims,
    did: &str,
    expected_version_id: Option<&str>,
    host: &H,
    channel: &str,
) -> Result<DeleteDidWebsResult, WebsError> {
    // As `webvh/dids/delete`: an admin of the DID's context.
    auth.require_admin()?;
    // Deactivating this VTA's own identity would leave it with no DID a peer
    // can resolve and no key to recover with: a node's identity is retired by
    // re-identifying it, never by a delete addressed to it.
    if deps.config.vta_did.as_deref() == Some(did) {
        return Err(WebsError::App(AppError::Forbidden(format!(
            "`{did}` is this VTA's own DID; it cannot be deleted while it is. Set up the VTA \
             under another DID first (`vta setup`), then delete this one"
        ))));
    }
    let record = held(deps, auth, did).await?;
    let newly_deactivated = !record.deactivated;
    let mut record = if record.deactivated {
        record
    } else {
        let (record, _) = complete_staged(deps, host, record).await?;
        if record.deactivated {
            // The staged rotation completed was itself the deactivation.
            record
        } else {
            check_expected(&record, expected_version_id)?;
            rotate_to(deps, auth, host, record, channel, true).await?.0
        }
    };

    let mut host_cleanup_error = None;
    if !record.slot_removed {
        match host
            .delete(&record.mnemonic, record.domain.as_deref())
            .await
        {
            Ok(()) => {
                record.slot_removed = true;
                record.updated_at = Utc::now().to_rfc3339();
                webs_store::put(deps.webs_ks, &record).await?;
            }
            Err(e) => host_cleanup_error = Some(e.to_string()),
        }
    }

    vta_audit::record_best_effort(
        deps.audit,
        "did.delete.webs",
        &auth.did,
        Some(did),
        "success",
        Some(channel),
        Some(&record.context_id),
    )
    .await;

    Ok(DeleteDidWebsResult {
        did: record.did.clone(),
        deactivated: true,
        newly_deactivated,
        version_id: version_id(&record.state),
        slot_removed: record.slot_removed,
        host_cleanup_error,
    })
}
