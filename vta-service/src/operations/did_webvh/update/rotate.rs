//! `rotate_did_webvh_keys` — replace the key material behind every
//! verification method of a `did:webvh`, then append the document through
//! [`super::update_did_webvh`].
//!
//! # What a rotation must preserve, and what it must replace
//!
//! A rotation replaces **key material**. Everything a relying party or one of
//! this VTA's own subsystems addresses a key *by* stays exactly as it was:
//!
//! - **the algorithm** (VTI-KEY-012), read from the method's key record, which
//!   must hold the key the document publishes. An X25519 key-agreement method
//!   is replaced by an X25519 key, an ML-DSA-44 method by an ML-DSA-44 key. A
//!   method whose key the VTA holds no record for is left untouched; a method
//!   id outside the DID, or a record of another context, is refused. The first version
//!   of this function minted Ed25519 for every method, so rotating a DID with a
//!   key-agreement key published an Ed25519 key under an X25519 method — a DID
//!   nobody could encrypt to afterwards;
//! - **the method ids, and so every relationship** (VTI-KEY-020). The first
//!   version renumbered each method to a fresh `#key-N` and remapped only
//!   `authentication`, `assertionMethod` and `keyAgreement`, so
//!   `capabilityInvocation` and `capabilityDelegation` were left naming methods
//!   the document no longer carried. Renumbering also broke every consumer that
//!   addresses its own keys by id — the VTA's `{vta_did}#key-0` issuer key and
//!   `#key-1` DIDComm key, the VTC's `vtc_did#key-0` / `#key-1` — so rotating
//!   either node's DID left it unable to sign or decrypt as itself. Keeping the
//!   id and replacing the key keeps every reference valid by construction;
//!   `did:webvh`'s versioned history is what distinguishes the key an id named at
//!   one version from the key it names now, which is why a signature made before
//!   the rotation still verifies against the entry current when it was made;
//! - **the custody properties of the key**: a method whose key was marked
//!   non-exportable gets a replacement marked non-exportable; one whose key is an
//!   internal (non-extractable) key is refused rather than downgraded to a derived
//!   key the seed can reproduce.
//!
//! # Records: the new key is findable, the old one is retired, nothing is lost
//!
//! Each new key gets a [`KeyRecord`] under the method id, so `keys/sign`,
//! `keys/export-secret` and the VTA's own key loads find it. The first version
//! wrote none — the keys it published existed only as consumed derivation-path
//! indices. The record it replaces is kept, under `{method id}@{versionId it was
//! current at}`, with status `revoked`, so the audit trail can still say which key
//! an id named at a given version, and the VTA refuses to sign with it
//! (VTI-KEY-042).
//!
//! The new keys' derivation paths are written as inert (`revoked`) staging
//! records before the log entry is appended, and promoted only once it is: a
//! crash between the two leaves the paths recorded rather than a published key
//! nobody can re-derive, and a failed append leaves the active records exactly
//! as they were.
//!
//! The authorization keys and the pre-rotation commitment rotate as a
//! consequence of the document update (see [`super::update_did_webvh`]),
//! except on an entry that *activates* pre-rotation, where the authorization
//! keys stay in force because the commitment this entry publishes is what
//! authorizes the next one.

use chrono::Utc;
use didwebvh_rs::log_entry::LogEntryMethods;
use serde_json::Value;
use vta_sdk::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};

use super::errors::UpdateDidWebvhError;
use super::options::{RotateDidWebvhKeysOptions, UpdateDidWebvhOptions, UpdateDidWebvhResult};
use super::orchestrator::{Commit, update_did_webvh_tracked};
use super::state::{find_record_by_scid, state_from_jsonl};
use crate::auth::AuthClaims;
use crate::keys::derivation::Bip32Extension;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::keys::{encode_public_multibase, store_key};
use crate::store::KeyspaceHandle;
use crate::webvh_store;

/// The relationships a verification method can be referenced from, or
/// embedded in. All five of DID Core's — a rotation that skips one leaves it
/// naming a key the document no longer publishes.
const RELATIONSHIPS: [&str; 5] = [
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
];

/// One method the rotation replaces the key of.
struct Rotated {
    /// Absolute method id (`did:webvh:…#frag`), the key record's id.
    vm_id: String,
    key_type: KeyType,
    path: String,
    public_key: String,
    /// The record being replaced, when the VTA holds one.
    previous: Option<KeyRecord>,
}

/// Rotate the key behind every verification method (preserving each method's
/// id, type and algorithm), then drive the doc-bearing [`super::update_did_webvh`]
/// path. See the module docs for what is preserved and why.
pub async fn rotate_did_webvh_keys(
    deps: &super::super::WebvhDeps<'_>,
    auth: &AuthClaims,
    scid: &str,
    opts: RotateDidWebvhKeysOptions,
    vta_did: Option<&str>,
    identity_secrets: Option<&affinidi_tdk::secrets_resolver::ThreadedSecretsResolver>,
    channel: &str,
) -> Result<UpdateDidWebvhResult, UpdateDidWebvhError> {
    // 1. Load record + log.
    let record = find_record_by_scid(deps.webvh_ks, scid)
        .await?
        .ok_or_else(|| UpdateDidWebvhError::NotFound(format!("SCID {scid} not found")))?;
    auth.require_admin()
        .map_err(|e| UpdateDidWebvhError::Forbidden(format!("admin required: {e}")))?;
    auth.require_context(&record.context_id).map_err(|_| {
        UpdateDidWebvhError::Forbidden(format!(
            "caller has no admin role in context `{}`",
            record.context_id
        ))
    })?;

    let did_log = webvh_store::get_did_log(deps.webvh_ks, &record.did)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_did_log: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::Library(format!("DID log missing for {}", record.did))
        })?;
    let state = state_from_jsonl(&did_log)?;
    let last = state.log_entries().last().ok_or_else(|| {
        UpdateDidWebvhError::Library(format!("DID {} has no log entries", record.did))
    })?;
    // Pinned for the append below: a concurrent update between this read and
    // the append is refused, so two rotations cannot both promote keys for the
    // same method ids.
    let prior_version_id = last.get_version_id().to_string();
    let current_doc = last.log_entry.get_did_document().map_err(|e| {
        UpdateDidWebvhError::Library(format!("extract document from last entry: {e}"))
    })?;

    // 2. Resolve context base path — every new key is derived under it
    //    (VTI-KEY-030), which is also what key custody checks on every later use.
    let context = crate::contexts::get_context(deps.contexts_ks, &record.context_id)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_context: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::Library(format!(
                "context `{}` referenced by DID is missing",
                record.context_id
            ))
        })?;

    // 3. Replace the key of every method, wherever it is declared.
    let mut new_doc = current_doc.clone();
    let seed_id = get_active_seed_id(deps.keys_ks).await.map_err(|e| {
        UpdateDidWebvhError::Persistence(format!("could not load active seed id: {e}"))
    })?;
    let seed = load_seed_bytes(deps.keys_ks, deps.seed_store, Some(seed_id))
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("could not load seed: {e}")))?;
    let root = vti_common::slip10::ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("BIP-32 root derivation: {e}")))?;

    let mut rotated: Vec<Rotated> = Vec::new();
    {
        let obj = new_doc.as_object_mut().ok_or_else(|| {
            UpdateDidWebvhError::Library("current document is not a JSON object".into())
        })?;
        // Declared methods, and methods embedded in a relationship array. A
        // string entry in a relationship is a reference, and keeps pointing at
        // the same id, so it needs nothing.
        let mut methods: Vec<&mut Value> = Vec::new();
        for (field, value) in obj.iter_mut() {
            let Value::Array(entries) = value else {
                continue;
            };
            if field == "verificationMethod" {
                methods.extend(entries.iter_mut());
            } else if RELATIONSHIPS.contains(&field.as_str()) {
                methods.extend(entries.iter_mut().filter(|e| e.is_object()));
            }
        }
        if methods.is_empty() {
            return Err(UpdateDidWebvhError::Library(
                "current document declares no verification methods to rotate".into(),
            ));
        }

        for (i, vm) in methods.into_iter().enumerate() {
            let Some(entry) = rotate_one(
                deps.keys_ks,
                &root,
                &context.base_path,
                &record.did,
                &record.context_id,
                i,
                vm,
            )
            .await?
            else {
                continue;
            };
            if rotated.iter().any(|r| r.vm_id == entry.vm_id) {
                return Err(UpdateDidWebvhError::InvalidDocument(format!(
                    "verification method `{}` is declared more than once",
                    entry.vm_id
                )));
            }
            rotated.push(entry);
        }
    }

    if rotated.is_empty() {
        return Err(UpdateDidWebvhError::InvalidDocument(format!(
            "{} declares no verification method whose key this VTA holds; there is nothing \
             it can rotate",
            record.did
        )));
    }

    // 4. Stage the new keys' paths durably, inert, before anything is published.
    //    Staging ids are unique to this rotation, so a concurrent rotation that
    //    loses the version race cleans up only its own staging records.
    let rotation_id = uuid::Uuid::new_v4();
    for r in &rotated {
        let id = staging_id(&r.vm_id, &rotation_id);
        deps.keys_ks
            .insert(
                store_key(&id),
                &new_record(r, &id, &record.context_id, seed_id, false),
            )
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("stage rotated key: {e}")))?;
    }

    // 5. Drive the generic update path. The doc-bearing branch rotates the
    //    authorization keys + pre-rotation as a side effect (see the note above
    //    for the one entry where it does not).
    let label = opts
        .label
        .or_else(|| Some(format!("rotate-keys for {}", record.did)));
    let result = update_did_webvh_tracked(
        deps,
        auth,
        scid,
        UpdateDidWebvhOptions {
            document: Some(new_doc),
            pre_rotation_count: opts.pre_rotation_count,
            witnesses: None,
            watchers: None,
            ttl: None,
            label,
            expected_version_id: Some(prior_version_id.clone()),
        },
        vta_did,
        channel,
    )
    .await;
    let result = match result {
        Ok(result) => result,
        Err((e, Commit::NotCommitted)) => {
            // Nothing was written: unstage, leaving the active records as
            // they were.
            for r in &rotated {
                let _ = deps
                    .keys_ks
                    .remove(store_key(&staging_id(&r.vm_id, &rotation_id)))
                    .await;
            }
            return Err(e);
        }
        Err((e, Commit::Committed)) => {
            // The entry publishing the new keys is the DID's local head, and a
            // later step (handles, record, publish) failed. The keys are the
            // DID's now: promote their records so the VTA holds one for every
            // key its log publishes, and return the error — the next update's
            // reconcile republishes the head. Unstaging here would leave
            // published keys nobody can re-derive.
            tracing::warn!(
                did = %record.did, error = %e,
                "rotation committed locally but a later step failed; promoting its key \
                 records so the published keys stay usable"
            );
            promote(
                deps,
                &rotated,
                &prior_version_id,
                &rotation_id,
                &record.context_id,
                seed_id,
            )
            .await?;
            if vta_did == Some(record.did.as_str())
                && let Some(resolver) = identity_secrets
            {
                reload_own_identity(resolver, &root, &rotated).await;
            }
            return Err(e);
        }
    };

    // 6. Promote.
    promote(
        deps,
        &rotated,
        &prior_version_id,
        &rotation_id,
        &record.context_id,
        seed_id,
    )
    .await?;

    // 7. The VTA's own DID: swap the new keys into the live secrets resolver
    //    now, so DIDComm and TSP decrypt what peers encrypt to the new
    //    key-agreement key and sign with the new signing key from this moment
    //    (VTI-KEY-122: from the first use of the new key, never sign with the
    //    retiring one). Waiting for a restart left the VTA unable to read
    //    anything sent to it after the rotation published.
    if vta_did == Some(record.did.as_str()) {
        match identity_secrets {
            Some(resolver) => reload_own_identity(resolver, &root, &rotated).await,
            None => tracing::warn!(
                did = %record.did,
                "rotated this VTA's own DID on a path with no live secrets resolver; \
                 restart the VTA to load the new keys"
            ),
        }
    }

    crate::audit::record_best_effort(
        deps.audit,
        "did.webvh.rotate_keys",
        &auth.did,
        Some(&record.did),
        "success",
        Some(channel),
        Some(&record.context_id),
    )
    .await;
    tracing::info!(
        channel,
        did = %record.did,
        scid = %scid,
        methods = rotated.len(),
        version = %result.new_version_id,
        "did:webvh keys rotated"
    );

    Ok(result)
}

/// Insert the rotated keys of the VTA's own DID into the live resolver, under
/// their (unchanged) method ids, replacing the retired secrets.
///
/// A key agreement key replaced in place cannot stay decryptable alongside its
/// successor: both carry the same method id, and the resolver answers one
/// secret per id. A message encrypted to the retired key and still in transit
/// when the rotation lands fails to decrypt and must be resent. Keeping the
/// retiring key usable for decryption (VTI-KEY-122's overlap) needs the new
/// key-agreement key under a new method id, which the VTA's and VTC's fixed
/// `#key-1` addressing does not yet allow.
async fn reload_own_identity(
    resolver: &affinidi_tdk::secrets_resolver::ThreadedSecretsResolver,
    root: &vti_common::slip10::ExtendedSigningKey,
    rotated: &[Rotated],
) {
    use affinidi_tdk::secrets_resolver::SecretsResolver;
    for r in rotated {
        let secret = match r.key_type {
            KeyType::Ed25519 => root.derive_ed25519(&r.path),
            KeyType::X25519 => root.derive_x25519(&r.path),
            KeyType::MlDsa44 => root.derive_ml_dsa_44(&r.path),
            KeyType::MlDsa65 => root.derive_ml_dsa_65(&r.path),
            _ => {
                tracing::warn!(
                    vm_id = %r.vm_id,
                    "rotated a {:?} key on this VTA's own DID; it is not held by the \
                     messaging resolver and is loaded on its next use",
                    r.key_type
                );
                continue;
            }
        };
        match secret {
            Ok(mut secret) => {
                secret.id = r.vm_id.clone();
                resolver.insert(secret).await;
                tracing::info!(vm_id = %r.vm_id, "live secret replaced after rotation");
            }
            Err(e) => tracing::error!(
                vm_id = %r.vm_id, error = %e,
                "could not derive the rotated key for the live resolver; restart the VTA"
            ),
        }
    }
}

/// The id a rotated key's path is staged under until the entry publishing it
/// is appended — unique to one rotation.
fn staging_id(vm_id: &str, rotation_id: &uuid::Uuid) -> String {
    format!("{vm_id}@rotating-{rotation_id}")
}

/// Retire each replaced record under the version it was current at, install
/// the new one under the method id, drop the staging copy.
async fn promote(
    deps: &super::super::WebvhDeps<'_>,
    rotated: &[Rotated],
    prior_version_id: &str,
    rotation_id: &uuid::Uuid,
    context_id: &str,
    seed_id: u32,
) -> Result<(), UpdateDidWebvhError> {
    let now = Utc::now();
    for r in rotated {
        if let Some(previous) = &r.previous {
            let retired_id = format!("{}@{prior_version_id}", r.vm_id);
            let mut retired = previous.clone();
            retired.key_id = retired_id.clone();
            retired.status = KeyStatus::Revoked;
            retired.updated_at = now;
            deps.keys_ks
                .insert(store_key(&retired_id), &retired)
                .await
                .map_err(|e| UpdateDidWebvhError::Persistence(format!("retire key: {e}")))?;
        }
        deps.keys_ks
            .insert(
                store_key(&r.vm_id),
                &new_record(r, &r.vm_id, context_id, seed_id, true),
            )
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("install rotated key: {e}")))?;
        let _ = deps
            .keys_ks
            .remove(store_key(&staging_id(&r.vm_id, rotation_id)))
            .await;
    }
    Ok(())
}

/// The record for a rotated key: `active` once promoted, `revoked` (inert)
/// while staged. Inherits the replaced key's label and exportability.
fn new_record(
    r: &Rotated,
    key_id: &str,
    context_id: &str,
    seed_id: u32,
    active: bool,
) -> KeyRecord {
    let now = Utc::now();
    KeyRecord {
        key_id: key_id.to_string(),
        derivation_path: r.path.clone(),
        key_type: r.key_type.clone(),
        status: if active {
            KeyStatus::Active
        } else {
            KeyStatus::Revoked
        },
        public_key: r.public_key.clone(),
        label: Some(
            r.previous
                .as_ref()
                .and_then(|p| p.label.clone())
                .unwrap_or_else(|| r.vm_id.clone()),
        ),
        context_id: Some(context_id.to_string()),
        seed_id: Some(seed_id),
        // A restriction survives the rotation: the replacement of a key an
        // operator marked non-exportable is non-exportable too.
        exportable: r.previous.as_ref().and_then(|p| p.exportable),
        origin: KeyOrigin::Derived,
        created_at: now,
        updated_at: now,
    }
}

/// Replace the key of one verification method in place, returning what the
/// records need — or `None` for a method whose key this VTA does not hold,
/// which is left exactly as it is.
///
/// Refuses, rather than rotates:
/// - a method whose id is not under this DID. `validate_document_for_update`
///   refuses such a document now, but a log written before that check could
///   still carry one, and a foreign id here would let this rotation rewrite
///   another DID's key record — another context's key — as this DID's;
/// - a method whose record belongs to another context, for the same reason;
/// - a method whose record does not hold the key the document publishes. A
///   stale record would otherwise decide the replacement's algorithm.
async fn rotate_one(
    keys_ks: &KeyspaceHandle,
    root: &vti_common::slip10::ExtendedSigningKey,
    base_path: &str,
    did: &str,
    context_id: &str,
    index: usize,
    vm: &mut Value,
) -> Result<Option<Rotated>, UpdateDidWebvhError> {
    let obj = vm.as_object_mut().ok_or_else(|| {
        UpdateDidWebvhError::InvalidDocument(format!(
            "verification method {index} is not an object"
        ))
    })?;
    let raw_id = obj
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            UpdateDidWebvhError::InvalidDocument(format!("verification method {index} has no id"))
        })?
        .to_string();
    let vm_id = if raw_id.starts_with('#') {
        format!("{did}{raw_id}")
    } else {
        raw_id
    };
    if !vm_id.starts_with(&format!("{did}#")) {
        return Err(UpdateDidWebvhError::InvalidDocument(format!(
            "verification method `{vm_id}` is not a method of {did}; rotation replaces only \
             this DID's own keys"
        )));
    }
    let Some(current_public) = obj
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return Err(UpdateDidWebvhError::InvalidDocument(format!(
            "verification method `{vm_id}` carries no publicKeyMultibase; rotation replaces \
             multibase keys only"
        )));
    };

    let previous: Option<KeyRecord> = keys_ks
        .get(store_key(&vm_id))
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("load key record: {e}")))?;
    let Some(previous) = previous else {
        // Not a key this VTA holds (an externally hosted key the document
        // lists). It cannot be re-derived, and guessing its algorithm from the
        // multicodec would mint a VTA key under a method someone else
        // controls. Left untouched.
        tracing::info!(vm_id = %vm_id, "rotation skipped a method whose key this VTA does not hold");
        return Ok(None);
    };
    if previous.key_id != vm_id {
        return Err(UpdateDidWebvhError::Forbidden(format!(
            "the key record stored for `{vm_id}` names another key (`{}`); refusing to \
             rotate it",
            previous.key_id
        )));
    }
    if previous.context_id.as_deref() != Some(context_id) {
        return Err(UpdateDidWebvhError::Forbidden(format!(
            "the key record for `{vm_id}` does not belong to this DID's context; refusing to \
             rotate it"
        )));
    }
    if previous.public_key != current_public {
        return Err(UpdateDidWebvhError::InvalidDocument(format!(
            "the key record for `{vm_id}` holds a different key than the document publishes; \
             realign the records (webvh/dids/realign-keys) before rotating"
        )));
    }
    if previous.origin == KeyOrigin::Internal {
        return Err(UpdateDidWebvhError::InvalidDocument(format!(
            "verification method `{vm_id}` is backed by an internal (non-extractable) key; \
             rotating it here would replace it with a key the seed can reproduce, which is \
             weaker. Mint a new internal key and publish it with vta/webvh/dids/update instead"
        )));
    }
    // The algorithm comes from the record, which is checked above to hold the
    // published key (VTI-KEY-012).
    let key_type = previous.key_type.clone();

    let path = crate::keys::paths::allocate_path(keys_ks, base_path)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("allocate_path: {e}")))?;
    let public_key = derive_public(root, &key_type, &path)?;
    obj.insert(
        "publicKeyMultibase".into(),
        Value::String(public_key.clone()),
    );

    Ok(Some(Rotated {
        vm_id,
        key_type,
        path,
        public_key,
        previous: Some(previous),
    }))
}

/// The public key at `path` for `key_type`, multicodec-prefixed multibase — the
/// same derivation key custody performs when the key is later used, so what is
/// published is what signs and decrypts.
fn derive_public(
    root: &vti_common::slip10::ExtendedSigningKey,
    key_type: &KeyType,
    path: &str,
) -> Result<String, UpdateDidWebvhError> {
    let err = |e: crate::error::AppError| {
        UpdateDidWebvhError::Persistence(format!("derive {key_type:?} at `{path}`: {e}"))
    };
    let secret = match key_type {
        KeyType::Ed25519 => root.derive_ed25519(path).map_err(err)?,
        KeyType::X25519 => root.derive_x25519(path).map_err(err)?,
        KeyType::MlDsa44 => root.derive_ml_dsa_44(path).map_err(err)?,
        KeyType::MlDsa65 => root.derive_ml_dsa_65(path).map_err(err)?,
        KeyType::P256 => {
            use p256::elliptic_curve::sec1::ToSec1Point;
            let secret = root.derive_p256(path).map_err(err)?;
            let point = secret.secret_key.public_key().to_sec1_point(true);
            return Ok(encode_public_multibase(&KeyType::P256, point.as_bytes()));
        }
        #[allow(unreachable_patterns)]
        other => {
            return Err(UpdateDidWebvhError::InvalidDocument(format!(
                "rotation cannot mint a {other:?} key"
            )));
        }
    };
    secret
        .get_public_keymultibase()
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("public key encoding: {e}")))
}
