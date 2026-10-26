//! `vti-voting-service run`: serve the ballot box until the process is told to stop — over TSP
//! and DIDComm through the identity's mediator session, and over HTTPS for sessionless casts.

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use tokio::sync::watch;
use tracing::{info, warn};
use vti_voting::service::BallotBox;

use crate::config::VotingConfig;
use crate::dispatch::AppState;
use crate::identity::{Identity, load_keys};
use crate::journal::FileJournal;
use crate::messaging::{BallotBoxResponder, IdentitySession, Shared, supervise};

/// How long a stop waits for the mediator session to close its socket.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

/// Serve `config` until SIGINT or SIGTERM.
///
/// # Errors
/// If the identity's keys are missing, the journal cannot be restored, or the listener cannot
/// bind.
pub async fn run(config: VotingConfig) -> anyhow::Result<()> {
    let did_resolver = DIDCacheClient::new(vta_sdk::resolver::build_did_cache_config(
        config.resolver_url.as_deref(),
    ))
    .await
    .map_err(|e| anyhow::anyhow!("build the DID resolver: {e}"))?;

    // The identity: provisioned, or the test did:key. A provisioned identity whose keys are
    // missing is refused rather than run half-configured.
    let (identity, session_keys) = match &config.identity {
        Some(provisioned) => {
            let store = vti_secrets::create_seed_store(&config.secrets, &config.data_dir)
                .map_err(|e| anyhow::anyhow!("open the secret store: {e}"))?;
            let bundle = load_keys(&*store).await?.ok_or_else(|| {
                anyhow::anyhow!(
                    "{} has no keys in the configured secret store; run `vti-voting-service \
                     setup`",
                    provisioned.did
                )
            })?;
            if bundle.did != provisioned.did {
                anyhow::bail!(
                    "the secret store holds keys for {}, not the configured {}",
                    bundle.did,
                    provisioned.did
                );
            }
            let secrets = vta_sdk::did_key::secrets_from_bundle(&bundle)
                .map_err(|e| anyhow::anyhow!("identity keys: {e}"))?;
            (
                Identity::from_bundle(&bundle)?,
                Some((provisioned.mediator_did.clone(), secrets)),
            )
        }
        None => {
            warn!(
                "no [identity] configured: serving as a did:key over HTTPS only. A community \
                 cannot reach this service over TSP or DIDComm; provision one with \
                 `vti-voting-service setup`"
            );
            (Identity::load_or_mint(&config.data_dir)?, None)
        }
    };
    // Printed, not only logged: it is what a community names as `ballotBox`.
    println!("ballot box DID: {}", identity.did);

    let journal = Arc::new(FileJournal::open(&config.data_dir.join("journal"))?);
    let restored = journal.load()?;
    let elections = restored.len();
    let ballot_box = BallotBox::restore(&identity.did, journal, restored)
        .map_err(|f| anyhow::anyhow!("restoring the journal: {} ({})", f.reason, f.local))?;

    if !config.communities.allow_any && config.communities.allowed.is_empty() {
        warn!(
            "no [communities] configured: every registration is refused. Name the communities \
             this box serves in [communities] allowed"
        );
    }
    let state = Arc::new(AppState::new(
        ballot_box,
        identity,
        vti_common::auth::TrustTaskVmResolver::new(did_resolver.clone()),
        config.communities.clone(),
    ));

    let (stop, stopped) = watch::channel(false);
    let session = session_keys.map(|(mediator_did, secrets)| {
        let shared = Arc::new(Shared {
            did_resolver: did_resolver.clone(),
            resolver_url: config.resolver_url.clone(),
        });
        let session = IdentitySession::new(
            BallotBoxResponder::new(state.clone()),
            mediator_did,
            secrets,
        );
        tokio::spawn(supervise(session, shared, stopped.clone()))
    });

    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    info!(
        listen = %config.listen,
        data_dir = %config.data_dir.display(),
        elections,
        messaging = session.is_some(),
        "voting service ready — holding ballots it cannot attribute"
    );
    let mut http_stopped = stopped.clone();
    axum::serve(listener, crate::http::router(state))
        .with_graceful_shutdown(async move {
            tokio::select! {
                () = shutdown_signal() => {}
                _ = http_stopped.changed() => {}
            }
        })
        .await?;

    info!("stopping: closing the mediator session");
    let _ = stop.send(true);
    if let Some(task) = session
        && tokio::time::timeout(SHUTDOWN_GRACE, task).await.is_err()
    {
        warn!("the mediator session did not close within {SHUTDOWN_GRACE:?}");
    }
    did_resolver.stop();
    Ok(())
}

/// SIGINT, or SIGTERM where there is one.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
