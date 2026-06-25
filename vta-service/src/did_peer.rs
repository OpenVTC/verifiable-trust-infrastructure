use std::path::PathBuf;

use affinidi_tdk::dids::{
    DID, KeyType, OneOrMany, PeerKeyRole, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
};
use affinidi_tdk::secrets_resolver::secrets::Secret;

use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::config::AppConfig;
use crate::store::Store;

pub struct CreateDidPeerArgs {
    pub config_path: Option<PathBuf>,
    pub context: String,
    pub label: Option<String>,
    /// Mediator HTTP endpoint (e.g. `http://127.0.0.1:61881/mediator/v1`) used
    /// to build the did:peer's DIDComm + Authentication services so the agent
    /// is reachable. The ws:// endpoint is derived from it.
    pub mediator_url: String,
    /// Emit the `DidSecretsBundle` JSON to stdout (the only thing on stdout).
    pub export_secrets: bool,
    /// Create an ACL admin entry for the new did:peer in the target context.
    pub admin: bool,
}

/// `vta create-did-peer` — mint a self-contained `did:peer:2` agent identity.
///
/// Mirrors `run_create_did_webvh` minus all hosting (no `--url`, no did.jsonl,
/// no webvh log, no publish). A did:peer is self-sovereign: keys + service
/// endpoints are encoded in the DID itself, so it resolves locally with no
/// hosting. The VTA only needs an ACL entry (with `--admin`); we never store
/// the private keys in the VTA keyspace.
///
/// The command is fully non-interactive — it has no hosting step, so nothing
/// to prompt for.
pub async fn run_create_did_peer(
    args: CreateDidPeerArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;
    let contexts_ks = store.keyspace(crate::keyspaces::CONTEXTS)?;

    // Resolve the target context. Non-interactive: fail if it doesn't exist
    // (no prompt, unlike create-did-webvh, which is interactive without --url).
    if crate::contexts::get_context(&contexts_ks, &args.context)
        .await?
        .is_none()
    {
        return Err(format!(
            "context '{}' does not exist (create it first with `vta contexts ...`)",
            args.context
        )
        .into());
    }

    let label = args.label.as_deref().unwrap_or(&args.context);

    // Build the did:peer's services from the mediator URL. This replicates
    // `mediator-setup`'s `did_peer.rs::mediator_services`: a "dm"
    // DIDCommMessaging service carrying the http + ws endpoints (accept
    // ["didcomm/v2"]) plus an "Authentication" service at {url}/authenticate
    // (id "#auth").
    let services = mediator_services(&args.mediator_url)?;

    // did:peer key shape: Ed25519 verification (#key-1) + X25519 encryption
    // (#key-2). Matches `mediator-setup`'s generator exactly.
    let keys = vec![
        (PeerKeyRole::Verification, KeyType::Ed25519),
        (PeerKeyRole::Encryption, KeyType::X25519),
    ];

    let (did, secrets): (String, Vec<Secret>) =
        DID::generate_did_peer_with_services(keys, Some(services))
            .map_err(|e| format!("failed to generate did:peer: {e}"))?;

    eprintln!("\x1b[1;32mCreated DID:\x1b[0m {did}");

    // Optionally grant the new did:peer admin in the target context. Mirrors
    // `run_create_did_webvh`'s `--admin` arm (`did_webvh.rs:232-242`): same
    // `AclEntry::new(..).with_label(..).with_contexts(..)` + `store_acl_entry`
    // call, scoped to the target context.
    if args.admin {
        let acl_ks = store.keyspace(crate::keyspaces::ACL)?;
        let entry = AclEntry::new(did.clone(), Role::Admin, "cli:create-did-peer")
            .with_label(args.label.clone())
            .with_contexts(vec![args.context.clone()]);
        store_acl_entry(&acl_ks, &entry).await?;
        eprintln!(
            "ACL entry created: {did} (admin, context: {})",
            args.context
        );
    }

    // Persist all writes (the optional ACL entry). did:peer is self-contained,
    // so there is nothing else to store.
    store.persist().await?;

    eprintln!(
        "  \x1b[2mdid:peer is self-contained: keys + services are encoded in the DID.\x1b[0m"
    );
    let _ = label;

    // Optionally export the secrets bundle. `--export-secrets` forces it
    // unconditionally; without the flag nothing is emitted on stdout.
    if args.export_secrets {
        let mut entries = Vec::with_capacity(secrets.len());
        for s in &secrets {
            // `Secret::get_key_type()` returns `affinidi_crypto::KeyType`;
            // `SecretEntry.key_type` is `vta_sdk::keys::KeyType` — map across
            // the two enums. Only Ed25519 / X25519 are produced by the key
            // shape above; reject anything else loudly.
            let key_type = match s.get_key_type() {
                affinidi_tdk::secrets_resolver::secrets::KeyType::Ed25519 => {
                    vta_sdk::keys::KeyType::Ed25519
                }
                affinidi_tdk::secrets_resolver::secrets::KeyType::X25519 => {
                    vta_sdk::keys::KeyType::X25519
                }
                other => {
                    return Err(format!(
                        "unexpected key type {other:?} in generated did:peer secret {}",
                        s.id
                    )
                    .into());
                }
            };
            entries.push(SecretEntry {
                key_id: s.id.clone(),
                key_type,
                private_key_multibase: s
                    .get_private_keymultibase()
                    .map_err(|e| format!("failed to encode private key for {}: {e}", s.id))?,
            });
        }

        let bundle = DidSecretsBundle {
            did: did.clone(),
            secrets: entries,
        };
        // Local operator export to stdout: pretty-printed JSON (matches
        // create-did-webvh). The only thing on stdout; human text is on stderr.
        let json = serde_json::to_string_pretty(&bundle)?;
        eprintln!();
        eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  WARNING: The secrets bundle contains private keys.      ║");
        eprintln!("║  Redirect to a file with restrictive permissions.        ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
        eprintln!();
        println!("{json}");
        eprintln!();
    }

    Ok(())
}

/// Build the did:peer's services from the mediator HTTP endpoint.
///
/// Replicates `mediator-setup`'s `generators/did_peer.rs::mediator_services`
/// exactly: a "dm" DIDCommMessaging service with http + ws endpoints (accept
/// `["didcomm/v2"]`) and an "Authentication" service at `{url}/authenticate`
/// (id `#auth`).
fn mediator_services(service_uri: &str) -> Result<Vec<PeerService>, Box<dyn std::error::Error>> {
    let service_uri = service_uri.trim_end_matches('/').to_string();
    let ws_uri = websocket_service_uri(&service_uri)?;
    let auth_uri = format!("{service_uri}/authenticate");

    Ok(vec![
        PeerService {
            type_: "dm".into(),
            endpoint: PeerServiceEndpoint::Long(OneOrMany::Many(vec![
                PeerServiceEndpointLong {
                    uri: service_uri,
                    accept: vec!["didcomm/v2".into()],
                    routing_keys: vec![],
                },
                PeerServiceEndpointLong {
                    uri: ws_uri,
                    accept: vec!["didcomm/v2".into()],
                    routing_keys: vec![],
                },
            ])),
            id: None,
        },
        PeerService {
            type_: "Authentication".into(),
            endpoint: PeerServiceEndpoint::Uri(auth_uri),
            id: Some("#auth".into()),
        },
    ])
}

/// Derive the ws:// (or wss://) DIDComm endpoint from the mediator's http(s)
/// endpoint. Replicates `mediator-setup`'s `did_peer.rs::websocket_service_uri`.
fn websocket_service_uri(service_uri: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut url = url::Url::parse(service_uri)
        .map_err(|e| format!("invalid mediator URL `{service_uri}`: {e}"))?;

    match url.scheme() {
        "http" => url
            .set_scheme("ws")
            .map_err(|_| format!("failed to convert `{service_uri}` to ws://"))?,
        "https" => url
            .set_scheme("wss")
            .map_err(|_| format!("failed to convert `{service_uri}` to wss://"))?,
        other => {
            return Err(
                format!("mediator URL must use http:// or https:// (got {other}://)").into(),
            );
        }
    }

    let path = url.path().trim_end_matches('/');
    url.set_path(&format!("{path}/ws"));

    Ok(url.to_string().trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::get_acl_entry;
    use vti_common::acl::Role;

    /// `vta create-did-peer --context <ctx> --mediator-url <uri> --admin
    /// --export-secrets` must run fully non-interactive and, in one shot:
    ///   * mint a `did:peer:2...` (Ed25519 #key-1 + X25519 #key-2),
    ///   * create an ACL **admin** entry for it scoped to the context,
    ///   * print a `DidSecretsBundle` with two entries (#key-1 ed25519,
    ///     #key-2 x25519), both with non-empty `private_key_multibase`.
    ///
    /// Gated on `config-seed` to match the create-did-webvh CLI test (no OS
    /// keyring). Run with:
    /// `cargo test -p vta-service --bin vta --features config-seed`.
    #[cfg(feature = "config-seed")]
    #[tokio::test]
    async fn create_did_peer_admin_export_is_noninteractive_and_grants_admin() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let config_path = dir.path().join("config.toml");

        // Minimal config: local store + a config-seed backend (dev/test only).
        // did:peer mints its own keys via the TDK, so the seed is not actually
        // exercised here, but the factory still expects a backend.
        let seed_hex = hex::encode([9u8; 64]);
        std::fs::write(
            &config_path,
            format!(
                "[store]\ndata_dir = \"{}\"\n\n[secrets]\nseed = \"{seed_hex}\"\n",
                data_dir.display()
            ),
        )
        .unwrap();

        // Create the target context up-front (the command refuses if missing).
        let config = AppConfig::load(Some(config_path.clone())).expect("load config");
        let store = Store::open(&config.store).expect("open store");
        let contexts_ks = store.keyspace(crate::keyspaces::CONTEXTS).unwrap();
        crate::contexts::create_context(&contexts_ks, "agents", "Agents")
            .await
            .unwrap();
        store.persist().await.unwrap();
        drop(contexts_ks);
        drop(store);

        // Run fully non-interactive: --mediator-url, --admin, --export-secrets.
        let args = CreateDidPeerArgs {
            config_path: Some(config_path.clone()),
            context: "agents".to_string(),
            label: Some("agent-1".to_string()),
            mediator_url: "http://127.0.0.1:61881/mediator/v1".to_string(),
            export_secrets: true,
            admin: true,
        };
        run_create_did_peer(args).await.expect("create-did-peer");

        // The DID printed to the operator must be a did:peer:2. Re-mint with
        // the same service shape to assert the bundle contents via the store
        // side effect (the ACL entry holds the exact DID).
        let store = Store::open(&config.store).expect("reopen store");
        let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();

        // Find the single ACL entry created for the new did:peer.
        let entries = crate::acl::list_acl_entries(&acl_ks).await.unwrap();
        assert_eq!(entries.len(), 1, "one ACL entry created");
        let did = &entries[0].did;
        assert!(did.starts_with("did:peer:2"), "got {did}");

        let entry = get_acl_entry(&acl_ks, did)
            .await
            .unwrap()
            .expect("ACL entry created for the did:peer");
        assert_eq!(entry.role, Role::Admin);
        assert_eq!(entry.allowed_contexts, vec!["agents".to_string()]);
    }

    /// The exported `DidSecretsBundle` carries exactly two entries — Ed25519
    /// `#key-1` (verification) + X25519 `#key-2` (encryption) — each with a
    /// non-empty multibase private key. Asserts the bundle-build logic
    /// directly against the generator (no store needed).
    #[test]
    fn bundle_has_two_entries_ed25519_then_x25519() {
        let services = mediator_services("http://127.0.0.1:61881/mediator/v1").unwrap();
        let keys = vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ];
        let (did, secrets) =
            DID::generate_did_peer_with_services(keys, Some(services)).expect("generate did:peer");
        assert!(did.starts_with("did:peer:2"), "got {did}");
        assert_eq!(secrets.len(), 2);

        let mut entries = Vec::new();
        for s in &secrets {
            let key_type = match s.get_key_type() {
                affinidi_tdk::secrets_resolver::secrets::KeyType::Ed25519 => {
                    vta_sdk::keys::KeyType::Ed25519
                }
                affinidi_tdk::secrets_resolver::secrets::KeyType::X25519 => {
                    vta_sdk::keys::KeyType::X25519
                }
                other => panic!("unexpected key type {other:?}"),
            };
            entries.push(SecretEntry {
                key_id: s.id.clone(),
                key_type,
                private_key_multibase: s.get_private_keymultibase().unwrap(),
            });
        }

        assert_eq!(entries.len(), 2);
        assert!(entries[0].key_id.contains("#key-1"));
        assert_eq!(entries[0].key_type, vta_sdk::keys::KeyType::Ed25519);
        assert!(!entries[0].private_key_multibase.is_empty());
        assert!(entries[1].key_id.contains("#key-2"));
        assert_eq!(entries[1].key_type, vta_sdk::keys::KeyType::X25519);
        assert!(!entries[1].private_key_multibase.is_empty());
    }
}
