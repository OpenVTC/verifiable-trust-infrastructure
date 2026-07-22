//! BIP-32 derivation, hashing, install, and lookup helpers for webvh
//! authorization keys.
//!
//! `derive_webvh_keys` is phase 1 (no persistence — the version-id is
//! not yet known); `install_derived_webvh_keys` is phase 2 (called
//! after `didwebvh_rs::update_did` returns). `load_active_update_key`
//! and `load_pre_rotation_signing_key` resolve the secret that will
//! sign the next log entry; `derive_secret_for_handle` re-derives the
//! actual key bytes from the seed plus a stored handle.

use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::Utc;
use didwebvh_rs::multibase_type::Multibase;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};

use super::errors::UpdateDidWebvhError;
use super::legacy::{legacy_lookup_by_public_key, legacy_lookup_pre_rotation_by_hash};
use super::options::DerivedWebvhKey;
use crate::keys::paths::{allocate_paths, path_at, peek_path_counter, peek_paths};
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::operations::did_webvh::webvh_keys::{self, WebvhKeyHandle, WebvhKeyRole};
use crate::store::KeyspaceHandle;

/// Derive `count` Ed25519 keys via BIP-32 under `base_path`. Pure —
/// **allocates** `count` derivation paths, consuming them from the group's
/// counter. Pair with [`install_derived_webvh_keys`] to persist once the
/// consuming `update_did` call has produced the new log entry's `version_id`.
///
/// For a read-only prediction of what this *would* derive, use
/// [`peek_webvh_keys`] — it shares the derivation below, so the two cannot
/// disagree about the key at a given path.
pub(in crate::operations::did_webvh) async fn derive_webvh_keys(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    base_path: &str,
    count: u32,
) -> Result<Vec<DerivedWebvhKey>, UpdateDidWebvhError> {
    derive_webvh_keys_block(keys_ks, seed_store, base_path, count, None).await
}

/// Allocate and derive `count` keys as **one contiguous block**, optionally
/// asserting the block starts at `expected_start`.
///
/// This is the sound version of [`derive_webvh_keys`], and the two differences
/// from a loop of single allocations are the two halves of the race this closes:
///
/// - **one block, not `count` allocations** — so a concurrent update cannot split
///   the auth key from the pre-rotation keys, which a plan peeked as adjacent;
/// - **`expected_start`** — so if anything moved the counter between the plan that
///   was shown to a human and this execution, the allocation fails with a
///   `Conflict` rather than silently installing keys the approver never saw.
///
/// `expected_start` is the value the plan peeked
/// ([`crate::keys::paths::peek_path_counter`]). Passing it is what turns "the
/// keys the approver saw are *probably* the keys that execute" into a guarantee.
pub(in crate::operations::did_webvh) async fn derive_webvh_keys_block(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    base_path: &str,
    count: u32,
    expected_start: Option<u32>,
) -> Result<Vec<DerivedWebvhKey>, UpdateDidWebvhError> {
    if count == 0 {
        return Ok(vec![]);
    }
    let paths = allocate_paths(keys_ks, base_path, count, expected_start)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("allocate_paths: {e}")))?;
    derive_webvh_keys_at(keys_ks, seed_store, &paths).await
}

/// Predict the keys [`derive_webvh_keys`] would produce, **without** allocating.
/// Genuinely pure: no keyspace writes.
///
/// This is what lets a caller show someone which key a rotation will install
/// before committing to it. Deriving via [`derive_webvh_keys`] to do that would
/// be self-defeating — it consumes the path, so the subsequent real run
/// allocates the *next* one and installs a **different** key than the one that
/// was shown, while every signature over it still verifies.
///
/// A peek reserves nothing. A caller whose correctness depends on the prediction
/// holding must pin the counter ([`crate::keys::paths::peek_path_counter`]) and
/// re-check it before committing.
pub(in crate::operations::did_webvh) async fn peek_webvh_keys(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    base_path: &str,
    count: u32,
) -> Result<Vec<DerivedWebvhKey>, UpdateDidWebvhError> {
    if count == 0 {
        return Ok(vec![]);
    }
    let paths = peek_paths(keys_ks, base_path, count)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("peek_paths: {e}")))?;
    derive_webvh_keys_at(keys_ks, seed_store, &paths).await
}

/// The derivation itself: seed → BIP-32 root → one key per path. Shared by the
/// allocating and peeking entry points above so a prediction and the run it
/// predicts cannot drift apart. Pure with respect to the keyspace.
async fn derive_webvh_keys_at(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    paths: &[String],
) -> Result<Vec<DerivedWebvhKey>, UpdateDidWebvhError> {
    let seed_id = get_active_seed_id(keys_ks).await.map_err(|e| {
        UpdateDidWebvhError::Persistence(format!("could not load active seed id: {e}"))
    })?;
    let seed = load_seed_bytes(keys_ks, seed_store, Some(seed_id))
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("could not load seed: {e}")))?;

    let root = ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("BIP-32 root derivation: {e}")))?;

    let mut derived = Vec::with_capacity(paths.len());
    for path in paths {
        let parsed: DerivationPath = path.parse().map_err(|e| {
            UpdateDidWebvhError::Persistence(format!("parse derivation path `{path}`: {e}"))
        })?;
        let key = root
            .derive(&parsed)
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("derive at `{path}`: {e}")))?;
        let secret = Secret::generate_ed25519(None, Some(key.signing_key.as_bytes()));
        let public_key = secret
            .get_public_keymultibase()
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("public key encoding: {e}")))?;
        let hash = secret
            .get_public_keymultibase_hash()
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("public key hash: {e}")))?;
        derived.push(DerivedWebvhKey {
            public_key,
            hash,
            derivation_path: path.clone(),
            seed_id,
        });
    }

    Ok(derived)
}

/// Persist [`DerivedWebvhKey`]s into `webvh_keys` under the new
/// log-entry's `version_id`. Called after `didwebvh_rs::update_did`
/// returns successfully.
#[allow(clippy::too_many_arguments)]
pub(in crate::operations::did_webvh) async fn install_derived_webvh_keys(
    keys_ks: &KeyspaceHandle,
    scid: &str,
    version_id: &str,
    role: WebvhKeyRole,
    derived: &[DerivedWebvhKey],
    label_prefix: &str,
) -> Result<(), UpdateDidWebvhError> {
    let now = Utc::now();
    for (i, key) in derived.iter().enumerate() {
        let handle = WebvhKeyHandle {
            scid: scid.to_string(),
            version_id: version_id.to_string(),
            hash: key.hash.clone(),
            public_key: key.public_key.clone(),
            derivation_path: key.derivation_path.clone(),
            seed_id: Some(key.seed_id),
            role,
            label: format!("{label_prefix} #{i}"),
            created_at: now,
        };
        webvh_keys::install(keys_ks, &handle)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("install webvh handle: {e}")))?;
    }
    Ok(())
}

/// Compute the multihash that webvh stores in `next_key_hashes` for a
/// given multibase-encoded public key. Standalone helper so we can hash
/// a public key we don't have the secret for (e.g. an `update_keys`
/// entry from the current log).
fn hash_public_key_multibase(pubkey_multibase: &str) -> Result<String, UpdateDidWebvhError> {
    Secret::base58_hash_string(pubkey_multibase).map_err(|e| {
        UpdateDidWebvhError::Library(format!(
            "could not hash public key `{pubkey_multibase}`: {e}"
        ))
    })
}

/// Resolve the active webvh authorization key for a DID — the secret
/// that signs the next log entry.
///
/// Strategy:
/// 1. Iterate the current log entry's `update_keys` (each is a
///    multibase-encoded public key).
/// 2. For each, compute its hash and look it up in the new
///    [`webvh_keys`] convention (fast path).
/// 3. If not found, fall back to the legacy `key:*` keyspace —
///    `KeyRecord`s indexed by `key_id` carry the multibase public key,
///    so we scan for a match. This is a one-shot path for DIDs created
///    before the `webvh_keys` convention existed; the caller should
///    install the returned handle into `webvh_keys` after a successful
///    update so subsequent calls hit the fast path.
///
/// Returns the [`WebvhKeyHandle`] for whichever update_key matched.
/// The caller still needs to re-derive the secret bytes from
/// `derivation_path` + the active seed.
pub(in crate::operations::did_webvh) async fn load_active_update_key(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    base_path: &str,
    scid: &str,
    update_keys: &[Multibase],
) -> Result<WebvhKeyHandle, UpdateDidWebvhError> {
    if update_keys.is_empty() {
        return Err(UpdateDidWebvhError::Library(
            "log entry has no update_keys — DID is deactivated or malformed".into(),
        ));
    }

    for pubkey_mb in update_keys {
        let pubkey_str = pubkey_mb.as_ref();
        let hash = hash_public_key_multibase(pubkey_str)?;

        // Fast path: webvh_keys convention.
        match webvh_keys::find_handle_by_hash(keys_ks, scid, &hash).await {
            Ok(Some(handle)) => {
                if matches!(handle.role, WebvhKeyRole::UpdateKey)
                    || matches!(handle.role, WebvhKeyRole::PreRotation)
                {
                    return Ok(handle);
                }
                // A Verification handle with the same hash means the
                // operator chose to use a doc VM as the update key —
                // also acceptable for signing.
                return Ok(handle);
            }
            Ok(None) => {}
            Err(e) => {
                return Err(UpdateDidWebvhError::Persistence(format!(
                    "webvh_keys lookup failed: {e}"
                )));
            }
        }

        // Legacy fallback: scan `key:*` for a KeyRecord whose
        // multibase public_key matches.
        if let Some(handle) = legacy_lookup_by_public_key(keys_ks, scid, pubkey_str, &hash).await? {
            return Ok(handle);
        }

        // Recovery fallback: the handle cache doesn't have it. Re-derive from
        // the seed. See `recover_signing_key_by_hash`.
        if let Some(handle) =
            recover_signing_key_by_hash(keys_ks, seed_store, base_path, scid, &hash).await?
        {
            return Ok(handle);
        }
    }

    Err(UpdateDidWebvhError::Library(format!(
        "no active update key for DID with SCID {scid} found in keys keyspace, and none of \
         its committed keys could be re-derived from the seed"
    )))
}

/// Recover a signing key the handle cache can no longer find, by re-deriving it
/// from the seed.
///
/// [`webvh_keys::find_handle_by_hash`] only searches the *active* prefix, and
/// [`webvh_keys::supersede_keys_for_version`] moves a version's handles to
/// `superseded:` when a later version rotates past it. A DID that committed
/// local-only versions that never reached the host (a failed-publish loop) can
/// therefore end up with the key the host's current entry still requires sitting
/// in `superseded:` — invisible to the resolver, so every later update fails at
/// signing and loops.
///
/// But webvh keys are deterministic BIP-32 derivations, so the seed *is* the
/// backup: scan the indices the counter has handed out, derive each, and match
/// the committed hash. On a hit, return a handle for it (the caller re-derives
/// the secret from its path). `None` if the hash matches no index the seed
/// produced — genuinely foreign key material, not ours to sign with.
async fn recover_signing_key_by_hash(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    base_path: &str,
    scid: &str,
    target_hash: &str,
) -> Result<Option<WebvhKeyHandle>, UpdateDidWebvhError> {
    let counter = peek_path_counter(keys_ks, base_path).await.map_err(|e| {
        UpdateDidWebvhError::Persistence(format!("peek_path_counter for key recovery: {e}"))
    })?;
    for i in 0..=counter {
        let path = path_at(base_path, i);
        let derived =
            derive_webvh_keys_at(keys_ks, seed_store, std::slice::from_ref(&path)).await?;
        let Some(key) = derived.into_iter().find(|k| k.hash == target_hash) else {
            continue;
        };
        tracing::info!(
            scid,
            target_hash,
            path = %key.derivation_path,
            "recovered a signing key by re-deriving it from the seed (handle cache miss)"
        );
        return Ok(Some(WebvhKeyHandle {
            scid: scid.to_string(),
            // Cosmetic: the resolver matches by hash, and the caller signs via
            // the derivation path. It becomes a normal active handle again the
            // moment the next version installs and supersedes.
            version_id: format!("recovered-{i}"),
            hash: key.hash,
            public_key: key.public_key,
            derivation_path: key.derivation_path,
            seed_id: Some(key.seed_id),
            role: WebvhKeyRole::UpdateKey,
            label: "re-derived from seed (handle cache miss)".to_string(),
            created_at: Utc::now(),
        }));
    }
    Ok(None)
}

/// Resolve a webvh signing key whose hash is committed in
/// `previous.next_key_hashes` (pre-rotation reveal path).
///
/// Iterates each committed hash and tries:
/// 1. Fast path: `webvh_keys::find_handle_by_hash` (works for DIDs created
///    after the genesis-pre-rotation install fix in `create_did_webvh`).
/// 2. Legacy fallback: scan `key:{did}#pre-rotation-N` records, hash each
///    record's `public_key`, and return the first match (handles DIDs
///    that predate the `webvh_keys` index).
///
/// Returns the [`WebvhKeyHandle`] for the matched key — the caller
/// re-derives the secret via [`derive_secret_for_handle`].
pub(in crate::operations::did_webvh) async fn load_pre_rotation_signing_key(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    base_path: &str,
    scid: &str,
    committed_hashes: &[String],
) -> Result<WebvhKeyHandle, UpdateDidWebvhError> {
    if committed_hashes.is_empty() {
        return Err(UpdateDidWebvhError::Library(
            "previous entry has empty next_key_hashes — pre-rotation reveal impossible".into(),
        ));
    }
    tracing::debug!(
        scid,
        hashes = ?committed_hashes,
        "load_pre_rotation_signing_key: searching for committed pre-rotation candidate"
    );
    for hash in committed_hashes {
        // Fast path.
        match webvh_keys::find_handle_by_hash(keys_ks, scid, hash).await {
            Ok(Some(handle)) => {
                tracing::debug!(
                    scid,
                    hash,
                    role = ?handle.role,
                    public_key = %handle.public_key,
                    "load_pre_rotation_signing_key: fast-path hit"
                );
                return Ok(handle);
            }
            Ok(None) => {}
            Err(e) => {
                return Err(UpdateDidWebvhError::Persistence(format!(
                    "webvh_keys lookup by hash: {e}"
                )));
            }
        }
        // Legacy fallback.
        if let Some(handle) = legacy_lookup_pre_rotation_by_hash(keys_ks, scid, hash).await? {
            tracing::debug!(
                scid,
                hash,
                public_key = %handle.public_key,
                "load_pre_rotation_signing_key: legacy fallback hit"
            );
            return Ok(handle);
        }

        // Recovery fallback: re-derive the committed pre-rotation key from the
        // seed when the handle cache lost it (superseded by a local-only
        // version). See `recover_signing_key_by_hash`.
        if let Some(handle) =
            recover_signing_key_by_hash(keys_ks, seed_store, base_path, scid, hash).await?
        {
            return Ok(handle);
        }
    }
    Err(UpdateDidWebvhError::Library(format!(
        "no pre-rotation key found for any committed hash, and none could be re-derived from \
         the seed: {committed_hashes:?}"
    )))
}

/// Re-derive the secret material for a [`WebvhKeyHandle`] from the seed
/// plus its BIP-32 path. The handle stores the path; the seed lives in
/// the seed store.
///
/// The returned [`Secret`]'s `id` is set to a proper `did:key`
/// verification-method form (`did:key:<mb>#<mb>`) — the
/// `affinidi-data-integrity::Signer::verification_method()` impl on
/// `Secret` returns `&self.id`, and `didwebvh-rs::update_did` parses
/// the `#`-separated multibase out of it to verify the signing key is
/// in the previous entry's `update_keys` set. Secrets minted with the
/// default kid (a random base64url u64) fail this check with
/// `verification_method 'X' must contain '#' with multibase key`.
pub(in crate::operations::did_webvh) async fn derive_secret_for_handle(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    handle: &WebvhKeyHandle,
) -> Result<Secret, UpdateDidWebvhError> {
    let seed = load_seed_bytes(keys_ks, seed_store, handle.seed_id)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("load seed: {e}")))?;
    let root = ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("BIP-32 root: {e}")))?;
    let path: DerivationPath = handle.derivation_path.parse().map_err(|e| {
        UpdateDidWebvhError::Persistence(format!("parse path `{}`: {e}", handle.derivation_path))
    })?;
    let derived = root.derive(&path).map_err(|e| {
        UpdateDidWebvhError::Persistence(format!("derive at `{}`: {e}", handle.derivation_path))
    })?;
    let mut secret = Secret::generate_ed25519(None, Some(derived.signing_key.as_bytes()));
    secret.id = format!("did:key:{mb}#{mb}", mb = handle.public_key);
    Ok(secret)
}
