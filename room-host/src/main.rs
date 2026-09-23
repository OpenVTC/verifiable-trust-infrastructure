//! The `room-host` binary: parse the flags, open the store, serve.
//!
//! Everything else is in the library beside this, so the same router can be driven from a
//! test or the `data_room` example without a socket.

use clap::Parser;

/// The wrapper a `[secrets]` table arrives in, so the file reads the same as every other
/// service's config rather than being a bare table this binary alone would accept.
#[cfg(any(feature = "didcomm", feature = "onboarding"))]
#[derive(serde::Deserialize)]
struct SecretsFile {
    #[serde(default)]
    secrets: vti_secrets::SecretsConfig,
}

/// Parse a `--secrets` file, returning the dotted path of every key it carries
/// that [`SecretsFile`] does not read.
#[cfg(any(feature = "didcomm", feature = "onboarding"))]
fn parse_secrets_file(text: &str) -> anyhow::Result<(SecretsFile, Vec<String>)> {
    let mut unknown_keys = Vec::new();
    let file = serde_ignored::deserialize(toml::Deserializer::parse(text)?, |key| {
        unknown_keys.push(key.to_string())
    })?;
    Ok((file, unknown_keys))
}

use room_host::{open_state_with_resolver, router_with_origins};

#[derive(Parser, Debug)]
#[command(name = "room-host", about = "Store and serve data-room records")]
struct Args {
    /// Where the record store lives.
    #[arg(long, default_value = "./room-host-data")]
    data_dir: std::path::PathBuf,
    /// Serve Trust Tasks over HTTP at this address.
    ///
    /// **Opt-in**, and deliberately: a host reached through a mediator needs no HTTP surface
    /// at all, and this used to default to `127.0.0.1:8300` — so a deployment that had
    /// carefully arranged to need no ingress bound a port anyway, and announced it in a log
    /// line naming an address nobody passed. The same rule the `didcomm` feature already
    /// follows: a host not asked to be reachable somewhere does not open a socket there.
    ///
    /// Pass it for the HTTP mode, where the owner registers rooms over REST, or when
    /// something local needs `/health`. A member reached by DID needs none of it.
    #[arg(long)]
    listen: Option<String>,
    /// Resolve credential issuers over the network as well as locally.
    ///
    /// Off by default. A room's credentials are normally issued by a `did:webvh` room, so a
    /// host without this serves almost nothing — but turning network resolution on means an
    /// unauthenticated request can make this host fetch, so it is a decision an operator
    /// makes rather than a default they inherit.
    #[arg(long)]
    resolve_dids: bool,
    /// Origins allowed to reach this host from a browser. Repeatable.
    ///
    /// Off by default, and explicit origins only — no wildcard. A room's member may be a
    /// web page, and without this a browser cannot reach this host at all: the response is
    /// discarded before any script sees it, so the failure reads as a network error with
    /// nothing in it about origins. Which sites may ask is an operator's decision; what the
    /// answer is remains the credentials'.
    #[arg(long = "allow-origin")]
    allow_origin: Vec<String>,
    /// Rooms this host **mirrors**: a JSON file naming each room's write-primary
    /// and the read credentials this mirror presents to it.
    ///
    /// A mirrored room serves reads from the copy and refuses every write,
    /// naming its primary. The file holds a private key, so it is hardened to
    /// owner-only on load.
    #[arg(long)]
    mirror_config: Option<std::path::PathBuf>,
    /// Be reachable at this mediator, as well as at `--listen`.
    ///
    /// The host connects as its own `did:peer:2` — minted into the data directory on first
    /// use and stable thereafter, because a member's saved address names it — and serves the
    /// same Trust Tasks over DIDComm and TSP that it serves over HTTP. What authorizes a
    /// request does not change: the presenter is the document's own proof either way.
    ///
    /// Off by default. A host that is not asked to be reachable opens no socket and mints no
    /// identity, which is the same posture `--resolve-dids` and `--allow-origin` take: a
    /// capability is a decision an operator makes rather than one they inherit.
    #[cfg(feature = "didcomm")]
    #[arg(long)]
    mediator_did: Option<String>,

    /// A TOML file carrying a `[secrets]` table, in the shape the VTA and VTC take.
    ///
    /// Omitted, the host keeps its identity in a plaintext file under `--data-dir`. That is
    /// the right default for running this on a laptop and the wrong one for a deployment: it
    /// is a private key on whatever volume the container was given.
    #[cfg(any(feature = "didcomm", feature = "onboarding"))]
    #[arg(long)]
    secrets: Option<std::path::PathBuf>,

    /// Enrol with this VTA, so it can authorize this host to serve the rooms it governs.
    ///
    /// On first use the host mints a throwaway `did:key` and prints it for an operator to
    /// grant; on the next start, once granted, it connects and rotates the throwaway away.
    /// Off by default — a host serves rooms by the credentials they issued, and needs no VTA
    /// of its own unless one is going to govern it.
    #[cfg(feature = "onboarding")]
    #[arg(long)]
    vta_did: Option<String>,

    /// The VTA context this host serves rooms for.
    ///
    /// Its DID is what this host serves *as*: the VTA mints it, publishes it, and holds the
    /// keys, and this host fetches them at startup. So the identity a member resolves and
    /// the identity this host seals with are the same by construction.
    ///
    /// The grant an operator makes on enrolment is for this context, and it is an `admin`
    /// role **scoped to it**: the host fetches its DID's private keys at startup, and
    /// releasing keys needs the `key-export` capability, which only an admin derives
    /// (VTI-VTA-003). Scope it — an admin with no context is a super-admin.
    #[cfg(feature = "onboarding")]
    #[arg(long, default_value = "rooms")]
    vta_context: String,

    /// Seconds between mirror pulls.
    ///
    /// A mirror is not latency-critical — it serves a copy, and a client that
    /// needs the newest record reads the primary — so the default is unhurried.
    /// Shorter intervals cost the primary a listing per room per pass.
    #[arg(long, default_value_t = 300)]
    mirror_interval_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "room_host=info".into()),
        )
        .init();

    // The keyring is a process-wide default that the *consuming binary* installs — a
    // library cannot, because the choice of platform store is the binary's. Without this,
    // `--features session-keyring` compiles and then fails at the first session read with
    // `No default store has been set, so cannot search or create entries`, which names the
    // keyring crate's internals rather than the missing call. `vti-secrets`' own feature
    // comment says to do this; nothing here did.
    #[cfg(feature = "session-keyring")]
    if let Err(e) = vta_sdk::keyring_init::install_default_store() {
        anyhow::bail!(
            "could not open the OS keyring for session storage: {e}. Build with \
             `--features config-session` instead to keep sessions in a file under \
             --data-dir, which is what a container or a headless server wants anyway."
        );
    }

    let args = Args::parse();
    let resolver = if args.resolve_dids {
        use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
        vti_common::auth::TrustTaskVmResolver::new(client)
    } else {
        vti_common::auth::TrustTaskVmResolver::did_key_only()
    };
    let state = open_state_with_resolver(&args.data_dir, resolver)?;

    // Mirrors start before the listener: a host that is going to serve a copy
    // should begin catching up before it starts answering reads from it, and a
    // config that does not parse is a startup failure rather than a warning
    // discovered later.
    if let Some(path) = &args.mirror_config {
        let config = room_host::mirror::MirrorConfig::load(path)?;
        tracing::info!(
            rooms = config.rooms.len(),
            interval_secs = args.mirror_interval_secs,
            "mirroring rooms from their write-primaries"
        );
        tokio::spawn(room_host::mirror::run(
            state.clone(),
            config,
            args.mirror_interval_secs,
        ));
    }

    // One secrets store, used by both the VTA-identity cache and the self-minted identity.
    // The same `[secrets]` shape the VTA and VTC take: with none configured this is a
    // plaintext file under `--data-dir`, which is right for a laptop; a deployment points it
    // at the secret manager it already runs.
    #[cfg(any(feature = "didcomm", feature = "onboarding"))]
    let identity_store = {
        let secrets = match &args.secrets {
            Some(path) => {
                let text = std::fs::read_to_string(path)?;
                // A key the schema does not read — a typo'd `[secret]` table,
                // say — would otherwise leave the default (plaintext) backend in
                // place without a word. Warn with its dotted path (Keyring VTI-06).
                let (file, unknown_keys) = parse_secrets_file(&text)?;
                for key in &unknown_keys {
                    tracing::warn!(
                        "unknown key `{key}` in {} — ignored. Check for a typo or a key \
                         placed in the wrong [section]; a key placed after a [table] \
                         header belongs to that table.",
                        path.display()
                    );
                }
                file.secrets
            }
            // No `[secrets]` given: keep the identity in a cleartext file under `--data-dir`,
            // and say so rather than doing it quietly. `vti-secrets` gates plaintext behind
            // an explicit opt-in because for a VTA the secret is a BIP-32 master seed; for a
            // host it is one service identity that holds no room keys and can read no record.
            // That makes the default defensible, not invisible — an operator who is going to
            // deploy this should be told once, here, rather than find out from the volume.
            None => {
                let mut config = vti_secrets::SecretsConfig::default();
                config.backend = Some(vti_secrets::SecretBackend::Plaintext);
                config.allow_plaintext = true;
                tracing::warn!(
                    data_dir = %args.data_dir.display(),
                    "no --secrets given, so this host's identity is kept in a cleartext file \
                     under --data-dir. Pass --secrets with a `[secrets]` table to use the \
                     keyring or a secret manager, in the same shape the VTA and VTC take."
                );
                config
            }
        };
        vti_secrets::create_seed_store(&secrets, &args.data_dir)?
    };

    // Enrolment first, because it can stop. A host awaiting a grant has nothing to serve
    // and no identity to serve it under, and minting one before finding that out leaves a
    // `did:peer` in the data directory that the VTA-governed path will never use.
    //
    // An operator who has to authorize this host should also find that out from the first
    // line of output, not after a page of startup that implies it is working.
    #[cfg(feature = "onboarding")]
    let vta_identity = match args.vta_did.as_deref() {
        None => None,
        Some(vta_did) => match room_host::onboarding::enrol(&args.data_dir, vta_did)? {
            room_host::onboarding::Enrolment::AwaitingGrant { ephemeral_did } => {
                println!(
                    "{}",
                    room_host::onboarding::grant_instructions(&ephemeral_did, vta_did)
                );
                return Ok(());
            }
            room_host::onboarding::Enrolment::Enrolled => {
                tracing::info!(vta = %vta_did, "enrolled with the VTA");
                // The identity this host actually serves as. Fetched rather than minted:
                // the VTA holds the context's DID and its keys, so what a member resolves
                // and what this host seals with are the same by construction.
                //
                // The cache is the same secrets store the minted identity would use, so a
                // VTA that is unreachable at boot costs this host nothing — it comes up on
                // the identity it fetched last time. Without that, a VTA outage would stop
                // every host enrolled with it, which is a far larger blast radius than the
                // outage itself.
                let identity = room_host::onboarding::fetch_identity(
                    &args.data_dir,
                    vta_did,
                    &args.vta_context,
                    identity_store.as_ref(),
                )
                .await?;
                if !identity.fresh {
                    tracing::warn!(
                        did = %identity.did,
                        "serving on the cached VTA identity — the VTA could not be reached"
                    );
                }
                Some(identity)
            }
        },
    };

    // Before the listener, for the same reason mirrors start first: a host that is going to
    // be reachable at a mediator should be reachable *by the time* it starts answering, and
    // an identity that will not load is a startup failure rather than something discovered
    // by the first member who cannot reach it.
    #[cfg(feature = "didcomm")]
    let mut mediator_task: Option<tokio::task::JoinHandle<()>> = None;
    #[cfg(feature = "didcomm")]
    if let Some(mediator_did) = args.mediator_did.clone() {
        // Governed by a VTA: serve as the DID it holds for this context.
        #[cfg(feature = "onboarding")]
        let from_vta = vta_identity
            .map(|vta| room_host::didcomm::HostIdentity::from_vta(vta.did, vta.secrets));
        // Built without onboarding, there is no VTA to be governed by and nothing to fetch.
        #[cfg(not(feature = "onboarding"))]
        let from_vta: Option<room_host::didcomm::HostIdentity> = None;

        let identity = match from_vta {
            Some(identity) => identity,
            // Ungoverned: mint a `did:peer:2` of this host's own, which encodes the mediator
            // so `?at=<did>` remains a complete address with nothing to resolve.
            None => {
                room_host::didcomm::HostIdentity::load_or_mint(
                    identity_store.as_ref(),
                    &mediator_did,
                )
                .await?
            }
        };
        // Printed, not only logged. It is this host's *address* — the thing a member puts
        // after `?at=` — and an operator has to be able to copy it out of a terminal.
        println!("host DID: {}", identity.did);
        let state = state.clone();
        mediator_task = Some(tokio::spawn(async move {
            if let Err(e) = room_host::didcomm::serve(state, identity, mediator_did).await {
                // Said in full because of what does *not* happen next: this task ends, the
                // HTTP listener does not, and nothing retries. So the process stays up and
                // a health check on `--listen` keeps passing while every member addressing
                // this host by DID times out. An operator reading one line needs to know
                // the host is half-dead rather than merely noisy.
                tracing::error!(
                    error = %e,
                    "the mediator connection ended — this host is NO LONGER REACHABLE by DID, \
                     and does not retry. HTTP on --listen is unaffected, so a health check \
                     against that port will still pass. Restart the host."
                );
            }
        }));
    }

    let Some(listen) = args.listen.clone() else {
        // No HTTP surface at all. This is the arrangement the design is about — the host
        // dials the mediator and nothing dials in — so it is a normal way to run rather
        // than a misconfiguration. What it is *not* is a way to run with nothing serving
        // anything, which is why the mediator task has to exist for this to be allowed.
        #[cfg(feature = "didcomm")]
        if let Some(task) = mediator_task {
            if !args.allow_origin.is_empty() {
                tracing::warn!(
                    "--allow-origin was given without --listen, so there is no HTTP surface \
                     for it to apply to and it has no effect"
                );
            }
            tracing::info!(
                data_dir = %args.data_dir.display(),
                network_resolution = args.resolve_dids,
                "room host ready — reachable by DID only, with no HTTP listener"
            );
            // Awaiting the mediator task means this exits when the connection ends, rather
            // than idling as a process nothing can reach. With a listener the two are
            // independent and that asymmetry is deliberate: there, something is still being
            // served; here there would be nothing at all.
            task.await?;
            return Ok(());
        }
        anyhow::bail!(
            "this host was asked to serve nobody: pass --listen <addr> to serve Trust Tasks \
             over HTTP, or --mediator-did <did> to be reachable by DID (which needs \
             `--features didcomm`)."
        );
    };

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(
        listen = %listen,
        data_dir = %args.data_dir.display(),
        network_resolution = args.resolve_dids,
        "room host ready — storing records for rooms it does not govern"
    );
    axum::serve(listener, router_with_origins(state, &args.allow_origin)).await?;
    Ok(())
}

#[cfg(all(test, any(feature = "didcomm", feature = "onboarding")))]
mod secrets_file_tests {
    use super::parse_secrets_file;

    /// Keyring VTI-06: a misspelt table leaves the default backend in place;
    /// the key is reported with its dotted path instead of vanishing.
    #[test]
    fn a_misplaced_key_is_reported_with_its_dotted_path() {
        let (_, unknown) = parse_secrets_file("[secret]\nbackend = \"keyring\"\n").unwrap();
        assert_eq!(unknown, vec!["secret".to_string()]);
    }

    #[test]
    fn a_valid_file_reports_nothing() {
        let (_, unknown) = parse_secrets_file("[secrets]\n").unwrap();
        assert!(unknown.is_empty(), "{unknown:?}");
    }
}
