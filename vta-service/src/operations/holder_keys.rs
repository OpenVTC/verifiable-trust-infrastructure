//! ACL-gated holder-key resolution for credential presentation (Phase 3).
//!
//! To sign a presentation server-side — the SD-JWT-VC holder `kb-jwt`, and the
//! Data-Integrity proof on a consent record — the VTA needs the holder subject
//! key's private material. That key is **VTA-managed** (derived from the master
//! seed), looked up by the subject `did:key`, and — the load-bearing constraint
//! — only usable **within the context the caller's ACL allows**. The VTA must
//! refuse to sign with a key outside the caller's authorised context(s): the
//! privilege boundary (memory `vta-holder-key-acl-gated-signing`).
//!
//! This reuses the **exact** ACL gate ([`AuthClaims::require_context`]) and
//! BIP-32 derivation the signing oracle uses — the boundary is not reinvented.

use std::sync::Arc;

use affinidi_sd_jwt::error::SdJwtError;
use affinidi_secrets_resolver::secrets::Secret;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey};
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use serde_json::Value;
use vta_sdk::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};
use zeroize::Zeroize;

use crate::auth::AuthClaims;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::load_seed_bytes;
use crate::store::KeyspaceHandle;
use vti_common::error::AppError;

/// A production Ed25519 SD-JWT [`JwtSigner`](affinidi_sd_jwt::signer::JwtSigner)
/// wrapping a derived holder key — used to sign the presentation `kb-jwt`.
///
/// `Debug` is derived; `ed25519_dalek::SigningKey`'s own `Debug` redacts the key.
#[derive(Debug)]
pub struct HolderSdJwtSigner {
    key: SigningKey,
    kid: String,
}

impl affinidi_sd_jwt::signer::JwtSigner for HolderSdJwtSigner {
    fn algorithm(&self) -> &str {
        "EdDSA"
    }
    fn key_id(&self) -> Option<&str> {
        Some(&self.kid)
    }
    fn sign_jwt(&self, header: &Value, payload: &Value) -> Result<String, SdJwtError> {
        let h = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(header).map_err(|e| SdJwtError::Verification(e.to_string()))?,
        );
        let p = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(payload).map_err(|e| SdJwtError::Verification(e.to_string()))?,
        );
        let input = format!("{h}.{p}");
        let sig: Signature = self.key.sign(input.as_bytes());
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        ))
    }
}

/// The holder's signing material for presenting `subject_did`'s credentials —
/// the SD-JWT `kb-jwt` signer and the consent-record DI secret, both over the
/// same derived key.
#[derive(Debug)]
pub struct HolderKeys {
    /// SD-JWT-VC `kb-jwt` signer.
    pub signer: HolderSdJwtSigner,
    /// Data-Integrity secret for signing a (query-scoped) consent record.
    pub consent_secret: Secret,
}

/// Resolve the VTA-managed holder key for `subject_did`, **gated by the caller's
/// ACL** for the key's context.
///
/// - The subject must be a `did:key` whose (derived, active, Ed25519) key the
///   VTA manages — else `NotFound` / `Validation`.
/// - The caller must have ACL access to the key's `context_id` (or be
///   super-admin for a context-less key) — else `Forbidden`. **This is the
///   privilege boundary**: it stops a caller minting presentations from keys
///   outside their authorised context.
/// - The key is then derived from the master seed exactly as the signing oracle
///   derives it.
pub async fn resolve_holder_keys(
    keys_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    auth: &AuthClaims,
    subject_did: &str,
) -> Result<HolderKeys, AppError> {
    let multibase = subject_did.strip_prefix("did:key:").ok_or_else(|| {
        AppError::Validation(format!("holder subject `{subject_did}` is not a did:key"))
    })?;
    // did:key VMs are `<did>#<multibase>` (the multibase IS the did suffix).
    let key_id = format!("{subject_did}#{multibase}");

    let record: KeyRecord = keys_ks
        .get(crate::keys::store_key(&key_id))
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "holder key for `{subject_did}` is not managed by this VTA"
            ))
        })?;

    if record.key_type != KeyType::Ed25519 {
        return Err(AppError::Validation(format!(
            "holder key `{key_id}` is not an Ed25519 key"
        )));
    }
    if record.status != KeyStatus::Active {
        return Err(AppError::Validation(format!(
            "holder key `{key_id}` is not active"
        )));
    }
    if record.origin != KeyOrigin::Derived {
        return Err(AppError::Validation(
            "imported holder keys are not supported for presentation yet".into(),
        ));
    }

    // ── Privilege boundary: only sign with a key in an authorised context. ──
    match &record.context_id {
        Some(ctx) => auth.require_context(ctx)?,
        None => auth.require_super_admin()?,
    }

    // Derive the raw signing key from the master seed (same path the oracle uses).
    let mut seed = load_seed_bytes(keys_ks, &**seed_store, record.seed_id)
        .await
        .map_err(|e| AppError::Internal(format!("seed load: {e}")))?;
    let bip32 = ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| AppError::Internal(format!("BIP-32 root key: {e}")))?;
    seed.zeroize();

    let path: DerivationPath = record.derivation_path.parse().map_err(|e| {
        AppError::Internal(format!(
            "invalid derivation path `{}`: {e}",
            record.derivation_path
        ))
    })?;
    let derived = bip32
        .derive(&path)
        .map_err(|e| AppError::Internal(format!("derive: {e}")))?;
    let signing_key = derived.signing_key;

    let signer = HolderSdJwtSigner {
        key: signing_key.clone(),
        kid: key_id.clone(),
    };
    let mut consent_secret = Secret::generate_ed25519(Some(&key_id), Some(signing_key.as_bytes()));
    consent_secret.id = key_id;

    Ok(HolderKeys {
        signer,
        consent_secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Role;
    use affinidi_sd_jwt::signer::JwtSigner;
    use chrono::Utc;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn admin_of(ctx: &str) -> AuthClaims {
        AuthClaims {
            role: Role::Admin,
            allowed_contexts: vec![ctx.to_string()],
            ..Default::default()
        }
    }
    fn super_admin() -> AuthClaims {
        AuthClaims {
            role: Role::Admin,
            allowed_contexts: Vec::new(),
            ..Default::default()
        }
    }

    /// Open a keys keyspace + seed store, derive an Ed25519 key at
    /// `m/26'/2'/0'/0'` in `context`, store its `KeyRecord`, and return the
    /// pieces plus the derived subject `did:key`.
    async fn setup(
        context: Option<&str>,
    ) -> (
        tempfile::TempDir,
        Store,
        KeyspaceHandle,
        Arc<dyn SeedStore>,
        String,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let keys_ks = store.keyspace("keys").unwrap();

        let seed = vec![42u8; 64];
        let seed_store: Arc<dyn SeedStore> =
            Arc::new(crate::test_support::TestSeedStore(seed.clone()));

        let path = "m/26'/2'/0'/0'";
        let bip32 = ExtendedSigningKey::from_seed(&seed).unwrap();
        let derived = bip32
            .derive(&path.parse::<DerivationPath>().unwrap())
            .unwrap();
        let subject_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(
            derived.signing_key.verifying_key().as_bytes(),
        );
        let multibase = subject_did.strip_prefix("did:key:").unwrap();
        let key_id = format!("{subject_did}#{multibase}");

        let record = KeyRecord {
            key_id: key_id.clone(),
            derivation_path: path.to_string(),
            key_type: KeyType::Ed25519,
            status: KeyStatus::Active,
            public_key: multibase.to_string(),
            label: None,
            context_id: context.map(str::to_string),
            seed_id: None,
            origin: KeyOrigin::Derived,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        keys_ks
            .insert(crate::keys::store_key(&key_id), &record)
            .await
            .unwrap();

        (dir, store, keys_ks, seed_store, subject_did)
    }

    #[tokio::test]
    async fn resolves_within_an_authorised_context() {
        let (_d, _s, keys_ks, seed_store, subject_did) = setup(Some("acme")).await;
        let keys = resolve_holder_keys(&keys_ks, &seed_store, &admin_of("acme"), &subject_did)
            .await
            .expect("resolve");
        let multibase = subject_did.strip_prefix("did:key:").unwrap();
        let key_id = format!("{subject_did}#{multibase}");
        assert_eq!(keys.signer.key_id(), Some(key_id.as_str()));
        assert_eq!(keys.consent_secret.id, key_id);
    }

    #[tokio::test]
    async fn refuses_a_key_outside_the_callers_context() {
        let (_d, _s, keys_ks, seed_store, subject_did) = setup(Some("acme")).await;
        // The privilege boundary: an admin of `other` must NOT sign with `acme`'s key.
        let err = resolve_holder_keys(&keys_ks, &seed_store, &admin_of("other"), &subject_did)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    }

    #[tokio::test]
    async fn parent_admin_resolves_a_descendant_context_key() {
        let (_d, _s, keys_ks, seed_store, subject_did) = setup(Some("acme/eng")).await;
        // Folder authority (ties to hierarchical contexts): an admin of `acme`
        // reaches a key whose context is `acme/eng`.
        assert!(
            resolve_holder_keys(&keys_ks, &seed_store, &admin_of("acme"), &subject_did)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn unknown_subject_is_not_found() {
        let (_d, _s, keys_ks, seed_store, _subject) = setup(Some("acme")).await;
        let err = resolve_holder_keys(
            &keys_ks,
            &seed_store,
            &super_admin(),
            "did:key:zUnknownHolder",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "{err:?}");
    }
}
