use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::Utc;
use dialoguer::Input;
use zeroize::Zeroizing;

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::cli_store::CliStore;
use crate::config::AppConfig;
use crate::contexts::{self, get_context};
use crate::keys;
use crate::keys::seed_store::create_seed_store;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};

pub struct CreateDidKeyArgs {
    pub config_path: Option<PathBuf>,
    pub context: String,
    pub admin: bool,
    pub label: Option<String>,
    /// When set, import the external Ed25519 private key held in this file
    /// (64 hex chars = 32 bytes) as the context's signing key, instead of
    /// deriving a fresh key from the VTA seed. Makes the resulting `did:key`
    /// deterministic in the supplied key material.
    ///
    /// A file rather than a flag value on purpose: an argv-borne secret is
    /// visible in `ps`, shell history, and container/CI process listings.
    pub private_key_file: Option<PathBuf>,
}

pub async fn run_create_did_key(args: CreateDidKeyArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let cs = CliStore::open(&config).await?;
    let keys_ks = cs.keyspace(crate::keyspaces::KEYS)?;
    let contexts_ks = cs.keyspace(crate::keyspaces::CONTEXTS)?;

    // Load seed from configured backend using the active generation
    let seed_store = create_seed_store(&config)?;
    let active_seed_id = get_active_seed_id(&keys_ks).await?;
    let seed = load_seed_bytes(&keys_ks, &*seed_store, Some(active_seed_id)).await?;

    // Resolve context
    let ctx = match get_context(&contexts_ks, &args.context).await? {
        Some(ctx) => ctx,
        None => {
            eprintln!("Context '{}' does not exist.", args.context);
            let name: String = Input::new()
                .with_prompt("Create it with name")
                .default(args.context.clone())
                .interact_text()?;
            let ctx = contexts::create_context(&contexts_ks, &args.context, &name).await?;
            eprintln!("Created context: {} ({})", ctx.id, ctx.base_path);
            ctx
        }
    };

    let label = args.label.as_deref().unwrap_or("did:key");

    // Derive (or import) and store the did:key.
    let (did, private_key_multibase) = match args.private_key_file.as_deref() {
        Some(path) => import_ed25519_did_key(&cs, &keys_ks, &seed, &ctx.id, label, path).await?,
        None => {
            keys::derive_and_store_did_key(
                &seed,
                &ctx.base_path,
                &ctx.id,
                label,
                &keys_ks,
                Some(active_seed_id),
            )
            .await?
        }
    };

    // Optionally create ACL entry
    if args.admin {
        let acl_ks = cs.keyspace(crate::keyspaces::ACL)?;
        let entry = AclEntry::new(did.clone(), Role::Admin, "cli:create-did-key")
            .with_label(args.label.clone())
            .with_contexts(vec![args.context.clone()]);
        store_acl_entry(&acl_ks, &entry).await?;
        eprintln!(
            "ACL entry created: {} (admin, context: {})",
            did, args.context
        );
    }

    // Persist all writes
    cs.persist().await?;

    eprintln!("DID: {did}");

    // When --admin is set, print a credential bundle to stdout
    if args.admin {
        let vta_did = config.vta_did.unwrap_or_default();
        let mut bundle = serde_json::json!({
            "did": did,
            "privateKeyMultibase": private_key_multibase,
            "vtaDid": vta_did,
        });
        if let Some(url) = &config.public_url {
            bundle["vtaUrl"] = serde_json::json!(url);
        }
        let bundle_json = serde_json::to_string(&bundle)?;
        let credential = BASE64.encode(bundle_json.as_bytes());
        eprintln!();
        eprintln!("Credential:");
        println!("{credential}");
    }

    Ok(())
}

/// Read a 32-byte Ed25519 private key from a hex file.
///
/// The file holds 64 hex chars (surrounding whitespace / a trailing newline are
/// tolerated). Both the raw text and the decoded bytes are wrapped in
/// [`Zeroizing`] so neither survives this function — matching the discipline
/// `vta_sdk::protocols::backup_management` applies to the same material.
///
/// Warns (but does not fail) when the file is group- or world-readable: the
/// operator may be mid-pipeline and a hard error would be unhelpful, but a
/// 0644 key file is worth saying out loud.
fn read_private_key_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o077;
            if mode != 0 {
                eprintln!(
                    "\x1b[1;33mwarning:\x1b[0m {} is readable beyond its owner (mode {:o}) — \
                     private key material should be 0600",
                    path.display(),
                    meta.permissions().mode() & 0o777
                );
            }
        }
    }

    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read --private-key-file {}: {e}", path.display()))?,
    );
    let decoded = Zeroizing::new(
        hex::decode(text.trim())
            .map_err(|e| format!("{} does not contain valid hex: {e}", path.display()))?,
    );
    if decoded.len() != 32 {
        return Err(format!(
            "{} must contain 32 bytes (64 hex chars); got {} bytes",
            path.display(),
            decoded.len()
        )
        .into());
    }
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    key_bytes.copy_from_slice(&decoded);
    Ok(key_bytes)
}

/// Store an EXTERNALLY-supplied Ed25519 key as a `did:key` in `context_id`,
/// under key_id = the standard did:key VM (`{did}#{multibase_pubkey}`), so a
/// vault `did-self-issued` entry can reference it and the VTA can load its
/// secret to sign.
///
/// Unlike [`keys::derive_and_store_did_key`] the key material comes from the
/// caller rather than a counter-allocated path off the VTA seed, so the
/// `did:key` is DETERMINISTIC in the supplied bytes — re-runs on a fresh volume
/// reproduce the same DID with no reseed churn. That is the point: it lets a
/// persona DID whose key is held off-box survive a redeploy.
///
/// The secret is encrypted at rest with the VTA seed via
/// [`keys::imported::store_secret`], exactly like any other imported key, and
/// the record is marked [`KeyOrigin::Imported`] with no derivation path.
///
/// Idempotent: `key_id` is derived from the key material, so an identical
/// re-run overwrites the same record with the same value.
async fn import_ed25519_did_key(
    cs: &CliStore,
    keys_ks: &crate::store::KeyspaceHandle,
    seed: &[u8],
    context_id: &str,
    label: &str,
    path: &Path,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let key_bytes = read_private_key_file(path)?;

    let (did, key_id, multibase_pubkey) = ed25519_did_key_ids(&key_bytes);
    let private_key_multibase = keys::encode_private_multibase(&KeyType::Ed25519, &*key_bytes);

    let now = Utc::now();
    let record = KeyRecord {
        key_id: key_id.clone(),
        derivation_path: String::new(),
        key_type: KeyType::Ed25519,
        status: KeyStatus::Active,
        public_key: multibase_pubkey.clone(),
        label: Some(label.to_string()),
        context_id: Some(context_id.to_string()),
        seed_id: None,
        origin: KeyOrigin::Imported,
        created_at: now,
        updated_at: now,
    };
    keys_ks.insert(keys::store_key(&key_id), &record).await?;

    let imported_ks = cs.keyspace(crate::keyspaces::IMPORTED_SECRETS)?;
    keys::imported::store_secret(&imported_ks, keys_ks, seed, &key_id, "ed25519", &*key_bytes)
        .await?;

    eprintln!("Imported external Ed25519 signing key as {key_id}");
    Ok((did, private_key_multibase))
}

/// Compute the `did:key`, its verification-method id (`{did}#{multibase}`) and
/// the multibase public key for an Ed25519 private key (32-byte seed). The
/// mapping is deterministic and standard (RFC-8032 public key + `did:key`
/// multicodec), so identical key material always yields the identical DID.
fn ed25519_did_key_ids(key_bytes: &[u8; 32]) -> (String, String, String) {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(key_bytes);
    let public_key = signing_key.verifying_key().to_bytes();
    let multibase_pubkey = keys::ed25519_multibase_pubkey(&public_key);
    let did = format!("did:key:{multibase_pubkey}");
    let key_id = format!("{did}#{multibase_pubkey}");
    (did, key_id, multibase_pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_did_key_ids_is_deterministic_and_well_formed() {
        let key = [7u8; 32];
        let (did, key_id, mb) = ed25519_did_key_ids(&key);
        // did:key ed25519 DIDs carry the z6Mk multibase+multicodec prefix.
        assert!(did.starts_with("did:key:z6Mk"), "unexpected did: {did}");
        // The VM id repeats the multibase after '#'.
        assert_eq!(key_id, format!("{did}#{mb}"));
        // Deterministic: the same key yields the same ids. This is the property
        // the whole feature exists for — a redeploy must reproduce the DID.
        let (did2, key_id2, _) = ed25519_did_key_ids(&key);
        assert_eq!(did, did2);
        assert_eq!(key_id, key_id2);
        // A different key yields a different DID.
        let (did_other, _, _) = ed25519_did_key_ids(&[9u8; 32]);
        assert_ne!(did, did_other);
    }

    #[test]
    fn read_private_key_file_accepts_64_hex_chars_with_trailing_newline() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("key.hex");
        std::fs::write(&path, format!("{}\n", hex::encode([3u8; 32]))).unwrap();

        let key = read_private_key_file(&path).expect("valid key file");
        assert_eq!(*key, [3u8; 32]);
    }

    #[test]
    fn read_private_key_file_rejects_wrong_length_and_bad_hex() {
        let dir = tempfile::TempDir::new().unwrap();

        let short = dir.path().join("short.hex");
        std::fs::write(&short, hex::encode([1u8; 16])).unwrap();
        let err = read_private_key_file(&short).expect_err("16 bytes must be rejected");
        assert!(err.to_string().contains("32 bytes"), "got: {err}");

        let bad = dir.path().join("bad.hex");
        std::fs::write(&bad, "not hex at all").unwrap();
        let err = read_private_key_file(&bad).expect_err("non-hex must be rejected");
        assert!(err.to_string().contains("valid hex"), "got: {err}");

        let missing = dir.path().join("nope.hex");
        let err = read_private_key_file(&missing).expect_err("missing file must be rejected");
        assert!(err.to_string().contains("cannot read"), "got: {err}");
    }
}
