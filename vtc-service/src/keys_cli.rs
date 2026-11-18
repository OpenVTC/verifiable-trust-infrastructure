//! `vtc keys {request,refresh}` — take over the keys of a `did:webs` VTC after
//! its VTA rotated them (`pnm webs rotate`).
//!
//! The VTC keeps no VTA credential, so the new keys reach it by the sealed
//! hand-off every other secret between these tools uses
//! (`crate::setup::refresh` says what is checked):
//!
//! 1. `vtc keys request` writes a sealed-transfer request and keeps its private
//!    half beside the store (0600).
//! 2. On the admin workstation: `pnm keys bundle <context> --recipient
//!    request.json > bundle.armor`. The digest is printed there; carry it here
//!    separately from the bundle.
//! 3. `vtc keys refresh --bundle bundle.armor --digest <hex>` opens the bundle,
//!    resolves this VTC's DID afresh, checks each key against the document,
//!    and replaces the stored bundle, keeping its derivation root.
//!
//! Offline: run on a **stopped** daemon, which loads the bundle at boot.

use std::path::{Path, PathBuf};

use vta_sdk::sealed_transfer::{
    BootstrapRequest, SealedPayloadV1, armor, ed25519_seed_to_x25519_secret,
    generate_ed25519_keypair, open_bundle,
};

use crate::config::AppConfig;
use crate::keys::seed_store::create_secret_store;
use crate::setup::VtcKeyBundle;
use crate::setup::refresh::{Refresh, successor_bundle};

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// The file holding a pending request's private seed and nonce.
fn request_key_path(config: &AppConfig) -> PathBuf {
    config
        .store
        .data_dir
        .join("keys")
        .join("refresh.request-key")
}

/// `vtc keys request [--out <file>]`.
pub async fn run_request(config_path: Option<PathBuf>, out: Option<PathBuf>) -> CliResult {
    let config = AppConfig::load(config_path)?;
    let did = config
        .vtc_did
        .clone()
        .ok_or("this VTC has no DID yet; run `vtc setup` first")?;
    let key_path = request_key_path(&config);
    if let Some(dir) = key_path.parent() {
        std::fs::create_dir_all(dir)?;
        crate::secure_file::restrict_dir_to_owner(dir)?;
    }

    let (seed, public) = generate_ed25519_keypair();
    let nonce: [u8; 16] = rand::random();
    // The seed and the nonce the bundle must be addressed to, together: a
    // bundle sealed to another request does not open with this key.
    let mut stored = seed.to_vec();
    stored.extend_from_slice(&nonce);
    std::fs::write(&key_path, &stored)?;
    crate::secure_file::restrict_file_to_owner(&key_path)?;

    let request = BootstrapRequest::new(public, nonce, Some("vtc keys refresh".into()));
    let json = serde_json::to_string_pretty(&request)?;
    match &out {
        Some(path) => std::fs::write(path, &json)?,
        None => println!("{json}"),
    }

    let context = config.vta_context.as_deref().unwrap_or("<context>");
    eprintln!();
    eprintln!(
        "Request for the keys of {did} written{}.",
        match &out {
            Some(p) => format!(" to {}", p.display()),
            None => String::new(),
        }
    );
    eprintln!("Its private half stays here: {}", key_path.display());
    eprintln!();
    eprintln!("On the admin workstation, seal this VTC's current keys to it:");
    eprintln!("  pnm keys bundle {context} --recipient <this request file> > bundle.armor");
    eprintln!();
    eprintln!("Then, with this VTC stopped:");
    eprintln!("  vtc keys refresh --bundle bundle.armor --digest <digest pnm printed>");
    Ok(())
}

/// `vtc keys refresh --bundle <file> --digest <hex>`.
pub async fn run_refresh(
    config_path: Option<PathBuf>,
    bundle_path: PathBuf,
    digest: String,
) -> CliResult {
    let mut config = AppConfig::load(config_path)?;
    let did = config
        .vtc_did
        .clone()
        .ok_or("this VTC has no DID yet; run `vtc setup` first")?;
    let key_path = request_key_path(&config);
    let secrets = open_secrets(&key_path, &bundle_path, &digest)?;

    let secret_store = create_secret_store(&config)
        .map_err(|e| format!("failed to construct the secret store: {e}"))?;
    let stored = secret_store
        .get()
        .await
        .map_err(|e| format!("failed to read the stored key bundle: {e}"))?
        .ok_or("the secret store holds no key bundle; run `vtc setup` first")?;
    let current = VtcKeyBundle::from_secret_store_bytes(&stored)?;
    if current.integration_did != did {
        return Err(format!(
            "the stored bundle is for {}, not this VTC's {did}",
            current.integration_did
        )
        .into());
    }

    let document = resolve_afresh(&config, &did).await?;
    let next = match successor_bundle(&current, &secrets, &document)? {
        Refresh::Current => {
            let _ = std::fs::remove_file(&key_path);
            println!("{did}: the stored keys are the ones its document publishes; nothing to do.");
            return Ok(());
        }
        Refresh::Successor(next) => next,
    };

    // As setup and restore write it: the config-secret backend keeps the bundle
    // inline in config.toml; every other backend takes a `set`.
    let bytes = next.to_secret_store_bytes()?;
    if config.secrets.secret.is_some() {
        config.secrets.secret = Some(hex::encode(&bytes));
        config.save()?;
    } else {
        secret_store
            .set(&bytes)
            .await
            .map_err(|e| format!("failed to store the new key bundle: {e}"))?;
    }
    // The request is spent: its key opened exactly this bundle.
    let _ = std::fs::remove_file(&key_path);

    println!("Took over the keys of {did}:");
    println!(
        "  signing        {} (was {})",
        next.ed25519_key_id, current.ed25519_key_id
    );
    println!("  key agreement  {}", next.x25519_key_id);
    println!("The at-rest storage, install-token and audit keys are unchanged.");
    println!("Start the VTC to load them.");
    Ok(())
}

/// Open the sealed bundle at `bundle_path` with the pending request's key.
fn open_secrets(
    key_path: &Path,
    bundle_path: &Path,
    digest: &str,
) -> Result<vta_sdk::did_secrets::DidSecretsBundle, Box<dyn std::error::Error>> {
    let stored = std::fs::read(key_path).map_err(|e| {
        format!(
            "no pending request at {} ({e}); run `vtc keys request` first",
            key_path.display()
        )
    })?;
    if stored.len() != 48 {
        return Err(format!("{} is not a request key", key_path.display()).into());
    }
    let seed: [u8; 32] = stored[..32].try_into().expect("length checked");
    let nonce: [u8; 16] = stored[32..].try_into().expect("length checked");

    let armored = std::fs::read_to_string(bundle_path)
        .map_err(|e| format!("read {}: {e}", bundle_path.display()))?;
    let bundles = armor::decode(&armored)?;
    let [bundle] = bundles.as_slice() else {
        return Err(format!("expected one sealed bundle, found {}", bundles.len()).into());
    };
    if bundle.bundle_id != nonce {
        return Err(
            "this bundle was sealed to a different request; run `vtc keys request` \
                    and seal to the request it writes"
                .into(),
        );
    }
    let opened = open_bundle(
        &ed25519_seed_to_x25519_secret(&seed),
        bundle,
        Some(digest.trim()),
    )?;
    match opened.payload {
        SealedPayloadV1::DidSecrets(secrets) => Ok(*secrets),
        _ => Err(
            "the bundle carries no DID secrets; seal it with `pnm keys bundle <context>`".into(),
        ),
    }
}

/// This VTC's document as its host serves it now, through a resolver with
/// nothing cached.
async fn resolve_afresh(
    config: &AppConfig,
    did: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
        vta_sdk::resolver::build_verifier_did_cache_config(
            None,
            config.did_cache.ttl_secs,
            config.did_cache.capacity,
        ),
    )
    .await
    .map_err(|e| format!("failed to create a DID resolver: {e}"))?;
    let resolved = resolver.resolve(did).await.map_err(|e| {
        format!(
            "could not resolve {did} ({e}); its host must serve it before its keys can be checked"
        )
    })?;
    Ok(serde_json::to_value(&resolved.doc)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::did_secrets::DidSecretsBundle;
    use vta_sdk::sealed_transfer::{
        AssertionProof, InMemoryNonceStore, ProducerAssertion, bundle_digest, seal_payload,
    };

    const DID: &str = "did:webs:vtc.example:EAbc";

    /// A pending request's key file and a bundle sealed to it, as `request`
    /// and `pnm keys bundle` would leave them.
    async fn sealed(dir: &Path, payload: SealedPayloadV1) -> (PathBuf, PathBuf, String) {
        let (seed, public) = generate_ed25519_keypair();
        let nonce = [5u8; 16];
        let key_path = dir.join("refresh.request-key");
        let mut stored = seed.to_vec();
        stored.extend_from_slice(&nonce);
        std::fs::write(&key_path, &stored).unwrap();

        let request = BootstrapRequest::new(public, nonce, None);
        let (_p, producer_pk) = generate_ed25519_keypair();
        let bundle = seal_payload(
            &request.decode_client_x25519_pub().unwrap(),
            nonce,
            ProducerAssertion {
                producer_did: affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer_pk),
                proof: AssertionProof::PinnedOnly,
            },
            &payload,
            &InMemoryNonceStore::new(),
        )
        .await
        .unwrap();
        let bundle_path = dir.join("bundle.armor");
        std::fs::write(&bundle_path, armor::encode(&bundle)).unwrap();
        (key_path, bundle_path, bundle_digest(&bundle))
    }

    fn secrets() -> SealedPayloadV1 {
        SealedPayloadV1::DidSecrets(Box::new(DidSecretsBundle {
            did: DID.into(),
            secrets: Vec::new(),
        }))
    }

    #[tokio::test]
    async fn the_sealed_secrets_open_with_the_request_key_and_digest() {
        let dir = tempfile::tempdir().unwrap();
        let (key, bundle, digest) = sealed(dir.path(), secrets()).await;
        let opened = open_secrets(&key, &bundle, &digest).unwrap();
        assert_eq!(opened.did, DID);
    }

    #[tokio::test]
    async fn a_wrong_digest_opens_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (key, bundle, _) = sealed(dir.path(), secrets()).await;
        assert!(open_secrets(&key, &bundle, &"00".repeat(32)).is_err());
    }

    #[tokio::test]
    async fn a_bundle_for_another_request_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (_, bundle, digest) = sealed(dir.path(), secrets()).await;
        let other = dir.path().join("other.request-key");
        let mut stored = vec![1u8; 32];
        stored.extend_from_slice(&[6u8; 16]);
        std::fs::write(&other, &stored).unwrap();
        let err = open_secrets(&other, &bundle, &digest).unwrap_err();
        assert!(err.to_string().contains("different request"), "{err}");
    }

    #[tokio::test]
    async fn without_a_request_the_error_names_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let (_, bundle, digest) = sealed(dir.path(), secrets()).await;
        let err = open_secrets(&dir.path().join("missing"), &bundle, &digest).unwrap_err();
        assert!(err.to_string().contains("vtc keys request"), "{err}");
    }
}
