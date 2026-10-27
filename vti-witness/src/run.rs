//! `vti-witness run`: serve every enabled witness identity until the process
//! is told to stop.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{info, warn};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::trust_task_sign::HolderKey;

use crate::config::WitnessConfig;
use crate::correlation::{self, OperatorFootprint};
use crate::dispatch::IdentityContext;
use crate::keys::WitnessKeyring;
use crate::messaging::{IdentitySession, Shared, WitnessResponder, supervise};
use crate::store::WitnessStore;
use crate::witness::{WitnessPolicy, Witnessing};

/// How long a stop waits for every session to close its socket.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

/// Load the configuration and keys, then supervise one mediator session per
/// enabled identity until SIGINT or SIGTERM.
pub async fn run(config_path: &Path) -> anyhow::Result<()> {
    let config = WitnessConfig::load(config_path)?;
    let enabled: Vec<_> = config.enabled().cloned().collect();
    if enabled.is_empty() {
        warn!(
            config = %config_path.display(),
            configured = config.witnesses.len(),
            "no witness identity is enabled — set `enabled = true` on the ones to serve. \
             Nothing to do."
        );
        return Ok(());
    }

    // The keys: refuse to start an identity whose keys are missing rather
    // than run it half-configured.
    let store = vti_secrets::create_seed_store(&config.secrets, &config.data_dir)
        .map_err(|e| anyhow::anyhow!("open the secret store: {e}"))?;
    let keyring = WitnessKeyring::load(&*store).await?;
    let witness_store = WitnessStore::open(&config.data_dir)?;
    // Built before the identities: each verifies its proofs through this one
    // resolver, and every ATM resolves through it too.
    let did_resolver = DIDCacheClient::new(vta_sdk::resolver::build_did_cache_config(
        config.resolver_url.as_deref(),
    ))
    .await
    .map_err(|e| anyhow::anyhow!("build the DID resolver: {e}"))?;
    let vm_resolver = TrustTaskVmResolver::new(did_resolver.clone());
    let mut sessions = Vec::with_capacity(enabled.len());
    for witness in &enabled {
        let bundle = keyring.get(&witness.did).ok_or_else(|| {
            anyhow::anyhow!(
                "witness {:?} ({}) has no keys in the configured secret store",
                witness.name,
                witness.did
            )
        })?;
        let signing = bundle.trust_task_signing_key().ok_or_else(|| {
            anyhow::anyhow!("witness {:?} has no Ed25519 signing key", witness.name)
        })?;
        let holder = HolderKey::new(&signing.key_id, &signing.private_key_multibase)
            .map_err(|e| anyhow::anyhow!("witness {:?}: {e}", witness.name))?;
        if witness.communities.is_empty() {
            warn!(
                identity = %witness.name,
                "enabled, but `communities` is empty, so this identity witnesses nobody: every \
                 witness/session is refused. Name the VTC DIDs whose members it witnesses, or \
                 `[\"*\"]` for anyone"
            );
        }
        let witnessing = Witnessing::new(
            WitnessPolicy::from_config(&config, witness),
            witness_store.clone(),
        );
        let identity = IdentityContext::new(&witness.name, &witness.did, holder, witnessing)?;
        let secrets = vta_sdk::did_key::secrets_from_bundle(bundle)
            .map_err(|e| anyhow::anyhow!("witness {:?}: {e}", witness.name))?;
        sessions.push(IdentitySession::new(
            WitnessResponder::new(identity, vm_resolver.clone()),
            witness.mediator_did.clone(),
            secrets,
        ));
    }

    let shared = Arc::new(Shared {
        did_resolver: did_resolver.clone(),
        resolver_url: config.resolver_url.clone(),
    });

    let (stop, stopped) = watch::channel(false);
    let mut tasks = JoinSet::new();

    // The correlation warnings resolve the operator's VTA, which can take a
    // while; spawned, so nothing on this path delays the signal wait below.
    {
        let config = config.clone();
        tasks.spawn(async move {
            let operator = OperatorFootprint::resolve(&config.operator_vta_did).await;
            for w in &config.witnesses {
                for warning in correlation::check(&w.name, Some(&w.did), &w.mediator_did, &operator)
                {
                    warn!(identity = %w.name, "{warning}");
                }
            }
        });
    }

    for session in sessions {
        tasks.spawn(supervise(session, shared.clone(), stopped.clone()));
    }
    tasks.spawn(sweep(witness_store, stopped.clone()));
    info!(
        identities = enabled.len(),
        "vti-witness started — one mediator session per enabled identity"
    );

    shutdown_signal().await;
    info!("stopping: closing every mediator session");
    let _ = stop.send(true);
    if tokio::time::timeout(SHUTDOWN_GRACE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        warn!("sessions did not close within {SHUTDOWN_GRACE:?}; aborting them");
        tasks.abort_all();
    }
    did_resolver.stop();
    Ok(())
}

/// How often expired sessions and duplicate records are reaped.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Reap expired sessions and duplicate-execution records until told to stop.
/// An expired session is already unsubmittable (every read checks its
/// expiry); the sweep only keeps it from lingering on disk.
async fn sweep(store: WitnessStore, mut stopped: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(SWEEP_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stopped.changed() => return,
        }
        if *stopped.borrow() {
            return;
        }
        match store.sweep(chrono::Utc::now()).await {
            Ok(0) => {}
            Ok(n) => tracing::debug!(removed = n, "swept expired witness sessions and records"),
            Err(e) => warn!(error = %e, "the witness sweep failed; retrying next interval"),
        }
    }
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
