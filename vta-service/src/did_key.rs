use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::Utc;
use dialoguer::Input;

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
    /// When set, import this external Ed25519 private key (32 bytes, hex) as the
    /// context's signing key instead of deriving a fresh key from the VTA seed.
    /// Makes the resulting did:key deterministic in the supplied key material.
    pub private_key_hex: Option<String>,
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
    let (did, private_key_multibase) = if let Some(hex_str) = args.private_key_hex.as_deref() {
        import_ed25519_did_key(&cs, &keys_ks, &seed, &ctx.id, label, hex_str).await?
    } else {
        keys::derive_and_store_did_key(
            &seed,
            &ctx.base_path,
            &ctx.id,
            label,
            &keys_ks,
            Some(active_seed_id),
        )
        .await?
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

/// Store an EXTERNALLY-supplied Ed25519 key as a `did:key` in `context_id`,
/// under key_id = the standard did:key VM (`{did}#{multibase_pubkey}`), so a
/// vault `did-self-issued` entry can reference it and the VTA can load its
/// secret to sign. Unlike [`keys::derive_and_store_did_key`] the key material
/// comes from the caller (not a counter-allocated path off the VTA seed), so the
/// did:key is DETERMINISTIC in `private_key_hex` — re-runs on a fresh volume
/// reproduce the same DID (no reseed churn). The secret is encrypted at rest
/// with the VTA seed via [`keys::imported::store_secret`], exactly like an
/// imported key. Idempotent: an identical re-run overwrites with the same value.
async fn import_ed25519_did_key(
    cs: &CliStore,
    keys_ks: &crate::store::KeyspaceHandle,
    seed: &[u8],
    context_id: &str,
    label: &str,
    private_key_hex: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let private_bytes = hex::decode(private_key_hex.trim())
        .map_err(|e| format!("--private-key-hex is not valid hex: {e}"))?;
    if private_bytes.len() != 32 {
        return Err(format!(
            "--private-key-hex must be 32 bytes (64 hex chars); got {} bytes",
            private_bytes.len()
        )
        .into());
    }
    let key_bytes: [u8; 32] = private_bytes.as_slice().try_into().unwrap();

    let (did, key_id, multibase_pubkey) = ed25519_did_key_ids(&key_bytes);
    let private_key_multibase = keys::encode_private_multibase(&KeyType::Ed25519, &key_bytes);

    // Key record: an Imported key (no derivation path / seed generation). Use a
    // plain insert (overwrite) so a deterministic re-run is a no-op rather than a
    // conflict.
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
    keys::imported::store_secret(&imported_ks, keys_ks, seed, &key_id, "ed25519", &key_bytes)
        .await?;

    eprintln!("Imported external Ed25519 signing key as {key_id}");
    Ok((did, private_key_multibase))
}

/// Compute the `did:key`, its verification-method id (`{did}#{multibase}`) and
/// the multibase public key for an Ed25519 private key (32-byte seed). The
/// mapping is deterministic and standard (RFC-8032 public key + did:key
/// multicodec), so identical key material always yields the identical DID —
/// this is what lets an imported app-root persona key reproduce the SAME
/// signing DID across fresh volumes / redeploys.
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
        // RFC-8032 test vector secret key (all-zero seed is valid).
        let key = [7u8; 32];
        let (did, key_id, mb) = ed25519_did_key_ids(&key);
        // did:key ed25519 DIDs start with the z6Mk multibase multicodec prefix.
        assert!(did.starts_with("did:key:z6Mk"), "unexpected did: {did}");
        // VM id repeats the multibase after '#'.
        assert_eq!(key_id, format!("{did}#{mb}"));
        // Deterministic: same key -> same ids.
        let (did2, key_id2, _) = ed25519_did_key_ids(&key);
        assert_eq!(did, did2);
        assert_eq!(key_id, key_id2);
        // A different key yields a different DID.
        let (did_other, _, _) = ed25519_did_key_ids(&[9u8; 32]);
        assert_ne!(did, did_other);
    }
}
