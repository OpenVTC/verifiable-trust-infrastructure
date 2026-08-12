use std::path::PathBuf;

use affinidi_tdk::dids::{OneOrMany, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong};
use affinidi_tdk::secrets_resolver::secrets::Secret;

use vta_sdk::did_secrets::DidSecretsBundle;

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::config::AppConfig;
use crate::operations::did_peer::{
    mediator_did_didcomm_service, mint_did_peer_with_services, peer_secrets_to_entries,
};
use crate::store::Store;

pub struct CreateDidPeerArgs {
    pub config_path: Option<PathBuf>,
    pub context: String,
    pub label: Option<String>,
    /// Mediator HTTP endpoint (e.g. `http://127.0.0.1:61881/mediator/v1`) used
    /// to build the did:peer's DIDComm + Authentication services so the agent
    /// is reachable. The ws:// endpoint is derived from it. Produces a
    /// **URL-style** DIDComm service. Mutually exclusive with `mediator_did`;
    /// exactly one of the two must be set.
    pub mediator_url: Option<String>,
    /// Mediator DID (e.g. `did:webvh:…:mediator`). Produces a **DID-style**
    /// DIDComm service (`serviceEndpoint.uri = <MEDIATOR_DID>`), matching how
    /// the built-in `ai-agent` did:webvh template and the online
    /// provision-integration path advertise DIDComm. Required for mediators
    /// that route by DID. Mutually exclusive with `mediator_url`.
    pub mediator_did: Option<String>,
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

    // Build the did:peer's DIDComm services. Two mutually-exclusive shapes —
    // see `select_services` for which to use when. Clap already enforces
    // exactly-one at the CLI; this re-checks because `CreateDidPeerArgs` is
    // also constructed directly by library callers and tests.
    let services = select_services(args.mediator_did.as_deref(), args.mediator_url.as_deref())?;

    // did:peer key shape (Ed25519 #key-1 + X25519 #key-2) and the actual
    // did:peer:2 encoding live in the shared library construction
    // (`operations::did_peer::mint_did_peer_with_services`) so this offline
    // CLI and the online provision-integration path can't drift. Only the
    // `services` differ (URL-style vs MEDIATOR_DID-style).
    let (did, secrets): (String, Vec<Secret>) = mint_did_peer_with_services(services)?;

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
        // Map the generated secrets to bundle entries via the shared helper
        // (Ed25519 #key-1 then X25519 #key-2; rejects any other key type).
        let entries = peer_secrets_to_entries(&secrets)?;

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

/// Pick the DIDComm service shape from the two mutually-exclusive mediator
/// flags. Exactly one must be set.
///
/// * `mediator_did` → **DID-style** ([`mediator_did_didcomm_service`]):
///   a `DIDCommMessaging` service whose `serviceEndpoint.uri` is the mediator's
///   own DID. This is what the online provision-integration path and the
///   built-in `ai-agent` did:webvh template emit, and what a DID-routing
///   mediator requires: such a mediator treats a hop as locally-mediated only
///   when the hop's DIDComm endpoint equals the mediator's DID. A URL endpoint
///   is classified as a *remote* hop, so the mediator anonymously self-forwards
///   the inbound reply to its own `/inbound`, which then rejects it with
///   `e.p.authorization.did.session_mismatch` — the agent never receives a
///   reply, observed as a DIDComm response timeout.
/// * `mediator_url` → **URL-style** ([`mediator_services`]): the original shape,
///   still correct for mediators that route by URL.
///
/// Sharing `mediator_did_didcomm_service` with the online path is deliberate —
/// the offline CLI and the online provisioner cannot drift on service shape.
fn select_services(
    mediator_did: Option<&str>,
    mediator_url: Option<&str>,
) -> Result<Vec<PeerService>, Box<dyn std::error::Error>> {
    match (mediator_did, mediator_url) {
        (Some(_), Some(_)) => {
            Err("--mediator-did and --mediator-url are mutually exclusive; pass exactly one".into())
        }
        (Some(did), None) => Ok(mediator_did_didcomm_service(
            did,
            vec!["didcomm/v2".into()],
            vec![],
        )),
        (None, Some(url)) => mediator_services(url),
        (None, None) => Err("one of --mediator-did or --mediator-url is required".into()),
    }
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
    // Only the `config-seed`-gated test below reads an ACL entry back; `Role`
    // already arrives via `use super::*`.
    #[cfg(feature = "config-seed")]
    use crate::acl::get_acl_entry;

    const MEDIATOR_DID: &str = "did:webvh:QmExample:mediator.example.com";

    /// `--mediator-did` must produce the **DID-style** service: a single
    /// `DIDCommMessaging` entry whose `serviceEndpoint.uri` is the mediator's
    /// DID verbatim. A DID-routing mediator only treats a hop as
    /// locally-mediated when that uri equals its own DID — a URL there makes it
    /// self-forward and reject the reply, so this assertion is the whole point
    /// of the flag.
    #[test]
    fn mediator_did_selects_the_did_style_didcomm_service() {
        let services = select_services(Some(MEDIATOR_DID), None).expect("did-style services");

        assert_eq!(services.len(), 1, "expected exactly one service");
        assert_eq!(services[0].type_, "DIDCommMessaging");
        match &services[0].endpoint {
            PeerServiceEndpoint::Long(OneOrMany::One(ep)) => {
                assert_eq!(
                    ep.uri, MEDIATOR_DID,
                    "endpoint uri must be the mediator DID"
                );
                assert_eq!(ep.accept, vec!["didcomm/v2".to_string()]);
                assert!(ep.routing_keys.is_empty());
            }
            other => panic!("expected a single long-form endpoint, got {other:?}"),
        }
    }

    /// `--mediator-url` keeps the original URL-style shape: a "dm" service
    /// carrying http + ws, plus the `#auth` Authentication service. Guards
    /// against the new flag changing the existing path.
    #[test]
    fn mediator_url_still_selects_the_url_style_services() {
        let services = select_services(None, Some("http://127.0.0.1:61881/mediator/v1"))
            .expect("url-style services");

        assert_eq!(services.len(), 2);
        assert_eq!(services[0].type_, "dm");
        assert_eq!(services[1].type_, "Authentication");
        assert_eq!(services[1].id.as_deref(), Some("#auth"));
    }

    /// The two flags are mutually exclusive and one is mandatory. Clap enforces
    /// this at the CLI, but `CreateDidPeerArgs` is public to library callers, so
    /// the runtime guard has to hold on its own.
    #[test]
    fn mediator_flags_require_exactly_one() {
        let both = select_services(Some(MEDIATOR_DID), Some("http://127.0.0.1:61881"))
            .expect_err("both flags must be rejected");
        assert!(
            both.to_string().contains("mutually exclusive"),
            "unexpected message: {both}"
        );

        let neither = select_services(None, None).expect_err("neither flag must be rejected");
        assert!(
            neither.to_string().contains("required"),
            "unexpected message: {neither}"
        );
    }

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
            mediator_url: Some("http://127.0.0.1:61881/mediator/v1".to_string()),
            mediator_did: None,
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
        let (did, secrets) = mint_did_peer_with_services(services).expect("generate did:peer");
        assert!(did.starts_with("did:peer:2"), "got {did}");
        assert_eq!(secrets.len(), 2);

        let entries = peer_secrets_to_entries(&secrets).expect("map secrets to entries");

        assert_eq!(entries.len(), 2);
        assert!(entries[0].key_id.contains("#key-1"));
        assert_eq!(entries[0].key_type, vta_sdk::keys::KeyType::Ed25519);
        assert!(!entries[0].private_key_multibase.is_empty());
        assert!(entries[1].key_id.contains("#key-2"));
        assert_eq!(entries[1].key_type, vta_sdk::keys::KeyType::X25519);
        assert!(!entries[1].private_key_multibase.is_empty());
    }
}
