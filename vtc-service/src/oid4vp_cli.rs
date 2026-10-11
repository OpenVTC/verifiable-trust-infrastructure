//! `vtc oid4vp {request,install,list,remove}` — install the key of an
//! OpenID4VP verifier identity this VTC presents to wallets (`crate::oid4vp`).
//!
//! The VTA mints the identity and its key; the VTC keeps no VTA credential, so
//! the key reaches it by a sealed hand-off the operator relays, the same shape
//! as every other secret that moves between these tools:
//!
//! 1. `vtc oid4vp request --identity swiyu` writes a sealed-transfer request
//!    and keeps its private half here (0600).
//! 2. On the admin workstation: mint the identity —
//!    `pnm did-mgmt dids create --context <ctx> --template swiyu-verifier --did-url <swiyu slot URL>`
//!    — upload its `did.jsonl` to the swiyu slot, then seal its keys to the
//!    request: `pnm keys bundle <ctx> --recipient request.json`. The digest is
//!    printed there; carry it here separately from the bundle.
//! 3. `vtc oid4vp install --identity swiyu --bundle bundle.armor --digest <hex>`
//!    opens the bundle, keeps the P-256 request-signing key, and stores it
//!    encrypted in `oid4vp_keys`.
//!
//! Offline: run on a **stopped** daemon, which holds the store's lock and
//! loads the identities at boot. Not for TEE deployments (the VTC has none).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use vta_sdk::keys::KeyType;
use vta_sdk::sealed_transfer::{
    BootstrapRequest, SealedPayloadV1, armor, ed25519_seed_to_x25519_secret,
    generate_ed25519_keypair, open_bundle,
};

use crate::config::AppConfig;
use crate::oid4vp::{
    LocalP256Signer, VerifierIdentityRecord, VerifierKind, delete_identity, get_identity,
    list_identities, put_identity,
};
use crate::store::keyspaces;

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// The file holding a pending request's private seed, beside the store.
fn request_key_path(config: &AppConfig, identity: &str) -> PathBuf {
    config
        .store
        .data_dir
        .join("oid4vp")
        .join(format!("{identity}.request-key"))
}

fn check_identity_name(identity: &str) -> Result<(), String> {
    if identity.is_empty()
        || identity.len() > 64
        || !identity
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "identity '{identity}' must be 1-64 characters of [a-z0-9-]"
        ));
    }
    Ok(())
}

/// `vtc oid4vp request --identity <id> [--out <file>]`.
pub async fn run_request(
    config_path: Option<PathBuf>,
    identity: String,
    out: Option<PathBuf>,
) -> CliResult {
    check_identity_name(&identity)?;
    let config = AppConfig::load(config_path)?;
    let key_path = request_key_path(&config, &identity);
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

    let request = BootstrapRequest::new(public, nonce, Some(format!("vtc oid4vp {identity}")));
    let json = serde_json::to_string_pretty(&request)?;
    match &out {
        Some(path) => std::fs::write(path, &json)?,
        None => println!("{json}"),
    }

    eprintln!();
    eprintln!(
        "Request for verifier identity '{identity}' written{}.",
        match &out {
            Some(p) => format!(" to {}", p.display()),
            None => String::new(),
        }
    );
    eprintln!("Its private half stays here: {}", key_path.display());
    eprintln!();
    eprintln!("On the admin workstation, for a swiyu verifier:");
    eprintln!(
        "  pnm did-mgmt dids create --context <context> --template swiyu-verifier \
         --did-url <swiyu identifier-registry slot URL>"
    );
    eprintln!("  # upload the printed did.jsonl to that slot with your swiyu API token, then:");
    eprintln!("  pnm keys bundle <context> --recipient <this request file> > bundle.armor");
    eprintln!();
    eprintln!("Then, with this VTC stopped:");
    eprintln!(
        "  vtc oid4vp install --identity {identity} --bundle <bundle file> --digest <digest pnm \
         printed>"
    );
    Ok(())
}

/// `vtc oid4vp install --identity <id> --bundle <file> --digest <hex>`.
pub async fn run_install(
    config_path: Option<PathBuf>,
    identity: String,
    bundle_path: PathBuf,
    digest: String,
    kid: Option<String>,
) -> CliResult {
    check_identity_name(&identity)?;
    let config = AppConfig::load(config_path)?;
    let key_path = request_key_path(&config, &identity);
    let record = open_and_select(&key_path, &bundle_path, &digest, &identity, kid.as_deref())?;

    // The record must be one the daemon can sign with before it is stored.
    LocalP256Signer::from_record(&record)?;

    let storage_key = crate::server::offline_storage_key(&config).await?;
    let store = crate::store::offline::open_offline(&config.store)?;
    let ks = store
        .keyspace(keyspaces::OID4VP_KEYS)?
        .with_encryption(storage_key);
    let replaced = get_identity(&ks, &identity).await?.is_some();
    put_identity(&ks, &record).await?;
    store.persist().await?;
    // The request is spent: its key opened exactly this bundle.
    let _ = std::fs::remove_file(&key_path);

    println!(
        "{} verifier identity '{identity}'.",
        if replaced { "Replaced" } else { "Installed" }
    );
    println!("  DID:       {}", record.did);
    println!("  Key:       {}", record.kid);
    println!("  client_id: {}", record.client_id());
    println!("Start the VTC to load it.");
    Ok(())
}

/// Open the sealed bundle with the pending request's key and pick out the
/// P-256 key the identity signs its request objects with.
///
/// Split from [`run_install`] so the selection rules are testable without a
/// secret store.
fn open_and_select(
    key_path: &Path,
    bundle_path: &Path,
    digest: &str,
    identity: &str,
    kid: Option<&str>,
) -> Result<VerifierIdentityRecord, Box<dyn std::error::Error>> {
    let stored = std::fs::read(key_path).map_err(|e| {
        format!(
            "no pending request for identity '{identity}' at {} ({e}); run `vtc oid4vp request \
             --identity {identity}` first",
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
        return Err("this bundle was sealed to a different request".into());
    }
    let opened = open_bundle(
        &ed25519_seed_to_x25519_secret(&seed),
        bundle,
        Some(digest.trim()),
    )?;
    let SealedPayloadV1::DidSecrets(secrets) = opened.payload else {
        return Err(
            "the bundle does not carry DID secrets; seal it with `pnm keys bundle <context>`"
                .into(),
        );
    };

    let p256: Vec<_> = secrets
        .secrets
        .iter()
        .filter(|s| s.key_type == KeyType::P256)
        .filter(|s| kid.is_none_or(|k| s.key_id == k))
        .collect();
    let entry = match p256.as_slice() {
        [one] => *one,
        [] => {
            return Err(format!(
                "the bundle for {} holds no P-256 key{}; a swiyu verifier signs its requests \
                 with ES256",
                secrets.did,
                kid.map(|k| format!(" named {k}")).unwrap_or_default()
            )
            .into());
        }
        many => {
            return Err(format!(
                "the bundle holds {} P-256 keys; name the request-signing one with --kid ({})",
                many.len(),
                many.iter()
                    .map(|s| s.key_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .into());
        }
    };
    if !entry.key_id.starts_with(&format!("{}#", secrets.did)) {
        return Err(format!(
            "key {} is not a verification method of {}",
            entry.key_id, secrets.did
        )
        .into());
    }

    let secret = affinidi_tdk::secrets_resolver::secrets::Secret::from_multibase(
        &entry.private_key_multibase,
        Some(&entry.key_id),
    )?;
    let public = secret.get_public_keymultibase()?;
    let jwk = affinidi_crypto::JWK::from_multikey(&public)?;
    let mut public_jwk = serde_json::to_value(&jwk)?;
    if let Some(obj) = public_jwk.as_object_mut() {
        obj.remove("d");
        obj.remove("kid");
        obj.retain(|_, v| !v.is_null());
    }

    Ok(VerifierIdentityRecord {
        id: identity.to_string(),
        kind: VerifierKind::Swiyu,
        did: secrets.did.clone(),
        kid: entry.key_id.clone(),
        public_jwk,
        private_key_multibase: entry.private_key_multibase.clone(),
        installed_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

/// `vtc oid4vp list`.
pub async fn run_list(config_path: Option<PathBuf>) -> CliResult {
    let config = AppConfig::load(config_path)?;
    let storage_key = crate::server::offline_storage_key(&config).await?;
    let store = crate::store::offline::open_offline(&config.store)?;
    let ks = store
        .keyspace(keyspaces::OID4VP_KEYS)?
        .with_encryption(storage_key);
    let identities = list_identities(&ks).await?;
    if identities.is_empty() {
        println!("No verifier identities installed.");
        return Ok(());
    }
    for r in identities {
        println!("{}", r.id);
        println!("  kind:      {:?}", r.kind);
        println!("  client_id: {}", r.client_id());
        println!("  key:       {}", r.kid);
    }
    Ok(())
}

/// `vtc oid4vp remove --identity <id>`.
pub async fn run_remove(config_path: Option<PathBuf>, identity: String) -> CliResult {
    let config = AppConfig::load(config_path)?;
    let storage_key = crate::server::offline_storage_key(&config).await?;
    let store = crate::store::offline::open_offline(&config.store)?;
    let ks = store
        .keyspace(keyspaces::OID4VP_KEYS)?
        .with_encryption(storage_key);
    if delete_identity(&ks, &identity).await? {
        store.persist().await?;
        println!("Removed verifier identity '{identity}'.");
    } else {
        println!("No verifier identity '{identity}'.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
    use vta_sdk::sealed_transfer::{
        AssertionProof, InMemoryNonceStore, ProducerAssertion, bundle_digest, seal_payload,
    };

    const DID: &str = "did:webvh:Qm1:identifier-reg.example:api:v1:did:abc";

    fn p256_entry(fragment: &str, seed: u8) -> SecretEntry {
        let kp = affinidi_crypto::p256::generate(Some(&[seed; 32])).unwrap();
        let secret = affinidi_tdk::secrets_resolver::secrets::Secret::generate_p256(
            None,
            Some(&kp.private_bytes),
        )
        .unwrap();
        SecretEntry {
            key_id: format!("{DID}#{fragment}"),
            key_type: KeyType::P256,
            private_key_multibase: secret.get_private_keymultibase().unwrap(),
        }
    }

    /// A pending request's key file and a bundle sealed to it, as `request`
    /// and `pnm keys bundle` would leave them.
    async fn sealed(dir: &Path, secrets: Vec<SecretEntry>) -> (PathBuf, PathBuf, String) {
        let (seed, public) = generate_ed25519_keypair();
        let nonce = [9u8; 16];
        let key_path = dir.join("swiyu.request-key");
        let mut stored = seed.to_vec();
        stored.extend_from_slice(&nonce);
        std::fs::write(&key_path, &stored).unwrap();

        let request = BootstrapRequest::new(public, nonce, None);
        let payload = SealedPayloadV1::DidSecrets(Box::new(DidSecretsBundle {
            did: DID.into(),
            secrets,
        }));
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

    /// The P-256 key comes out of the bundle as a record its own signer
    /// accepts, named by the DID and verification method it was sealed under.
    #[tokio::test]
    async fn the_request_signing_key_is_taken_from_the_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let (key, bundle, digest) =
            sealed(dir.path(), vec![p256_entry("verifier-key-1", 0x31)]).await;
        let record = open_and_select(&key, &bundle, &digest, "swiyu", None).unwrap();
        assert_eq!(record.did, DID);
        assert_eq!(record.kid, format!("{DID}#verifier-key-1"));
        assert_eq!(record.public_jwk["crv"], "P-256");
        assert!(record.public_jwk.get("d").is_none());
        LocalP256Signer::from_record(&record).expect("a usable signer");
    }

    #[tokio::test]
    async fn a_wrong_digest_or_a_different_request_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (key, bundle, _digest) =
            sealed(dir.path(), vec![p256_entry("verifier-key-1", 0x31)]).await;
        assert!(open_and_select(&key, &bundle, &"00".repeat(32), "swiyu", None).is_err());

        // Another request's key file cannot open it.
        let other = tempfile::tempdir().unwrap();
        let (other_key, _b, _d) = sealed(other.path(), vec![p256_entry("k", 0x32)]).await;
        let (_k, bundle2, digest2) = sealed(dir.path(), vec![p256_entry("k", 0x33)]).await;
        assert!(open_and_select(&other_key, &bundle2, &digest2, "swiyu", None).is_err());
    }

    /// No P-256 key, or more than one without `--kid`, is refused by name.
    #[tokio::test]
    async fn the_key_must_be_unambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let (key, bundle, digest) = sealed(
            dir.path(),
            vec![p256_entry("a", 0x31), p256_entry("b", 0x32)],
        )
        .await;
        let err = open_and_select(&key, &bundle, &digest, "swiyu", None).unwrap_err();
        assert!(err.to_string().contains("--kid"), "{err}");

        let dir = tempfile::tempdir().unwrap();
        let (key, bundle, digest) = sealed(
            dir.path(),
            vec![p256_entry("a", 0x31), p256_entry("b", 0x32)],
        )
        .await;
        let record =
            open_and_select(&key, &bundle, &digest, "swiyu", Some(&format!("{DID}#b"))).unwrap();
        assert_eq!(record.kid, format!("{DID}#b"));
    }

    #[test]
    fn identity_names_are_bounded() {
        assert!(check_identity_name("swiyu").is_ok());
        assert!(check_identity_name("../x").is_err());
        assert!(check_identity_name("").is_err());
    }
}
