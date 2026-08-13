//! VTA binary for AWS Nitro Enclaves (TEE mode).
//!
//! This binary handles TEE-specific bootstrapping:
//! - VsockStore connection to parent's persistent storage proxy
//! - KMS secret bootstrap (seed + JWT key generation/decryption)
//! - TEE provider initialization (Nitro/SEV-SNP/Simulated)
//! - Mnemonic export guard
//! - Automatic did:webvh identity generation
//!
//! After bootstrapping, it calls vta_service::server::run() with
//! the TeeContext — the same server code as the local VTA binary.

#[cfg(feature = "vsock-log")]
mod vsock_log;

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use clap::Parser;
use sha2::{Digest, Sha384};
use tracing::info;

use vta_service::config::AppConfig;
use vta_service::keys::seed_store::{KmsTeeSeedStore, SeedStore};
use vta_service::server::TeeContext;
use vta_service::store;
use vta_service::tee;

#[cfg(not(any(feature = "rest", feature = "didcomm")))]
compile_error!("At least one of 'rest' or 'didcomm' must be enabled.");

#[derive(Parser)]
#[command(name = "vta", about = "Verifiable Trust Agent (TEE Enclave mode)")]
struct Cli {
    /// Path to config file
    #[arg(long, short)]
    config: Option<std::path::PathBuf>,
}

/// Connect to the parent instance's vsock storage proxy, retrying with bounded
/// backoff so a boot-ordering race isn't an outage.
///
/// On a cold boot the enclave and the parent-side storage proxy start
/// concurrently; if the enclave's connect races ahead of the proxy binding its
/// vsock port, a single attempt would `exit(1)` — and Nitro does **not** restart
/// the enclave, so a benign ordering race becomes an outage on every unattended
/// host reboot. Wait for the dependency instead, giving up only after the proxy
/// is clearly not coming up (~80s total).
#[cfg(feature = "vsock-store")]
async fn connect_vsock_with_retry() -> Result<store::VsockStore, String> {
    use std::time::Duration;
    const MAX_ATTEMPTS: u32 = 30;
    const BASE_DELAY: Duration = Duration::from_millis(250);
    const MAX_DELAY: Duration = Duration::from_secs(3);

    let mut delay = BASE_DELAY;
    for attempt in 1..=MAX_ATTEMPTS {
        match store::VsockStore::connect(None).await {
            Ok(vs) => {
                if attempt > 1 {
                    tracing::info!("connected to vsock storage proxy on attempt {attempt}");
                }
                return Ok(vs);
            }
            Err(e) if attempt < MAX_ATTEMPTS => {
                tracing::warn!(
                    "vsock storage proxy not ready (attempt {attempt}/{MAX_ATTEMPTS}): {e}; \
                     retrying in {delay:?}"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_DELAY);
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    unreachable!("the loop returns on the final attempt")
}

#[tokio::main]
async fn main() {
    // Pin rustls to the aws-lc-rs backend before any TLS object is built;
    // see `vta_sdk::crypto_init` (re-exported by vta-service). Without this,
    // rustls 0.23 panics on backend auto-detection when both backends are
    // compiled in.
    vta_service::crypto_init::install_default_crypto_provider();

    eprintln!("VTA enclave binary starting...");

    let cli = Cli::parse();

    // Load config — resolve the path first so we can print diagnostics on failure
    let config_path = cli
        .config
        .clone()
        .or_else(|| {
            std::env::var("VTA_CONFIG_PATH")
                .ok()
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| std::path::PathBuf::from("config.toml"));
    eprintln!("Loading config from: {}", config_path.display());
    if config_path.exists() {
        eprintln!(
            "Config file exists ({} bytes)",
            std::fs::metadata(&config_path)
                .map(|m| m.len())
                .unwrap_or(0)
        );
    } else {
        eprintln!("Config file NOT FOUND at {}", config_path.display());
    }
    let config = match AppConfig::load(cli.config) {
        Ok(c) => {
            eprintln!("Config loaded successfully");
            c
        }
        Err(e) => {
            eprintln!("FATAL: failed to load config: {e}");
            // Print the raw config file for debugging
            if let Ok(raw) = std::fs::read_to_string(&config_path) {
                eprintln!("--- config file contents ---\n{raw}\n--- end config ---");
            }
            std::process::exit(1);
        }
    };

    eprintln!("Config loaded. Initializing tracing...");

    // Initialize tracing. When vsock-log is enabled, logs are tee'd to both
    // stderr (visible in debug mode) and a vsock channel on port 5700 (visible
    // via enclave-proxy in production mode). The initial connection is awaited
    // (with a 2s timeout) so early boot logs are forwarded before bootstrap.
    #[cfg(feature = "vsock-log")]
    {
        eprintln!("vsock-log feature enabled, starting vsock writer...");
        let vsock_writer = vsock_log::start().await;
        eprintln!("vsock writer started, initializing tracing...");
        vta_service::init_tracing_with_writer(&config, vsock_writer);
    }
    #[cfg(not(feature = "vsock-log"))]
    {
        eprintln!("vsock-log feature NOT enabled, using stderr tracing");
        vta_service::init_tracing(&config);
    }
    eprintln!("Tracing initialized.");
    print_banner();

    // Are we on real Nitro hardware? Drives every un-baked-config security floor
    // and the attestation anchor below (all no-ops in simulated/dev, where the
    // config is trusted local input rather than parent-delivered).
    let on_nitro = std::path::Path::new("/dev/nsm").exists();

    // ── Tenant-config overlay (un-baked fleet build only) ──
    // In a `BAKE_CONFIG=false` build the image bakes a fleet-policy base config
    // with placeholders; the tenant-scoped fields arrive at runtime as a typed,
    // allowlisted overlay fetched over vsock:5800 and applied here, in place,
    // BEFORE the floor check and BEFORE KMS bootstrap (which reads key_arn /
    // region). `deny_unknown_fields` on the overlay makes any field outside the
    // allowlist a hard parse error, so the parent cannot deliver `admin_did`,
    // `mode`, or any `allow_*` flag. Fail-closed on real Nitro. See design note
    // §3.1/§3.8. A `BAKE_CONFIG=true` (self-host) build does not compile this in.
    #[cfg(feature = "tenant-overlay")]
    let (config, overlay_applied) = {
        let mut config = config;
        match vta_tee::tenant_overlay::fetch_and_apply_overlay(&mut config).await {
            Ok(()) => (config, true),
            Err(e) if on_nitro => {
                tracing::error!(
                    "FATAL: tenant-config overlay fetch/apply failed: {e}. Refusing to boot."
                );
                std::process::exit(1);
            }
            Err(e) => {
                tracing::warn!(
                    "tenant-config overlay fetch/apply failed (not on Nitro — continuing with \
                     the baked base config for local/dev): {e}"
                );
                (config, false)
            }
        }
    };

    // Config provenance for the security floor below. A parent-delivered
    // (untrusted) config must face the floor; a fully-baked/mounted config is
    // committed to PCR0 (or a trusted local mount) and is exempt.
    // - fleet build: parent-influenced iff an overlay was actually applied.
    // - self-host build (no overlay feature): the config is baked → trusted.
    #[cfg(feature = "tenant-overlay")]
    let parent_delivered = overlay_applied;
    #[cfg(not(feature = "tenant-overlay"))]
    let parent_delivered = false;

    // ── Security floor for a parent-delivered (un-baked) config ──
    // The tenant config is authored by the untrusted parent, so on real Nitro
    // hardware (and only for a parent-delivered source) refuse to boot if it would
    // (a) weaken `[tee] mode` below `required` (the default is `Optional`, which
    // silently continues without TEE), (b) omit `[tee.kms]` — which silently
    // disables KMS bootstrap and lets the seed come from the parent-supplied
    // `[secrets]` block (a full bypass of the property the floor protects), or
    // (c) set `[tee.kms] admin_did` (a parent-supplied super-admin is not
    // attested). The attested path for admin is sealed-bootstrap Mode B. See
    // `config_floor_violation` for the exact rules (unit-tested).
    if let Some(violation) = config_floor_violation(
        on_nitro,
        parent_delivered,
        &config.tee.mode,
        config.tee.kms.is_some(),
        config
            .tee
            .kms
            .as_ref()
            .and_then(|kms| kms.admin_did.as_deref()),
    ) {
        tracing::error!("FATAL: {violation}. Refusing to boot.");
        std::process::exit(1);
    }

    // `[hardened] enabled = true` is silently ignored by this binary — the enclave
    // derives its storage-encryption key and JWT signing key from the TEE KMS
    // bootstrap above, not from the HKDF seed path that `hardened_bootstrap` uses.
    // Warn loudly so a misconfigured enclave config doesn't leave an operator
    // wondering why the hardened key derivation log messages never appear.
    if config.hardened.enabled {
        tracing::warn!(
            "hardened.enabled = true is set but has no effect in the TEE enclave binary \
             — storage encryption and JWT key management are handled by TEE KMS bootstrap. \
             Remove [hardened] from the enclave config.toml to suppress this warning."
        );
    }

    // ── Open store (vsock-proxied or local) ──
    #[cfg(feature = "vsock-store")]
    let store = if config.tee.kms.is_some() {
        match connect_vsock_with_retry().await {
            Ok(vs) => store::Store::Vsock(vs),
            Err(e) => {
                tracing::error!("failed to connect to vsock storage proxy after retries: {e}");
                std::process::exit(1);
            }
        }
    } else {
        match store::Store::open(&config.store) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("failed to open store: {e}");
                std::process::exit(1);
            }
        }
    };
    #[cfg(not(feature = "vsock-store"))]
    let store = match store::Store::open(&config.store) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("failed to open store: {e}");
            std::process::exit(1);
        }
    };

    // ── KMS secret bootstrap (uses the store for ciphertext K/V storage) ──
    let tee_bootstrap = if let Some(ref kms_config) = config.tee.kms {
        match tee::kms_bootstrap::bootstrap_secrets(
            kms_config,
            &config.tee.storage_key_salt,
            &store,
        )
        .await
        {
            Ok(secrets) => Some(secrets),
            Err(e) => {
                tracing::error!("TEE KMS bootstrap failed: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // ── Seed store ──
    let seed_store: Arc<dyn SeedStore> = if let Some(ref bootstrap) = tee_bootstrap {
        let kms_config = match config.tee.kms.as_ref() {
            Some(c) => c,
            None => {
                tracing::error!("KMS config missing after successful bootstrap");
                std::process::exit(1);
            }
        };
        Arc::new(KmsTeeSeedStore::new(
            bootstrap.seed.clone(),
            kms_config.key_arn.clone(),
            kms_config.region.clone(),
        ))
    } else {
        match vta_service::keys::seed_store::create_seed_store(&config) {
            Ok(store) => Arc::from(store),
            Err(e) => {
                tracing::error!("failed to create seed store: {e}");
                std::process::exit(1);
            }
        }
    };

    // ── JWT signing key + storage encryption key from bootstrap ──
    let (mut config, storage_encryption_key) = if let Some(ref bootstrap) = tee_bootstrap {
        let mut config = config;
        let jwt_b64 = BASE64.encode(bootstrap.jwt_signing_key);
        config.auth.jwt_signing_key = Some(jwt_b64);
        (config, Some(bootstrap.storage_key))
    } else {
        (config, None)
    };

    // ── Mnemonic export guard ──
    let mnemonic_guard = {
        let export_window: Option<u64> = std::env::var("VTA_MNEMONIC_EXPORT_WINDOW")
            .ok()
            .and_then(|v| v.parse().ok());

        if let Some(ref bootstrap) = tee_bootstrap {
            if let (Some(entropy), Some(window_secs)) = (bootstrap.entropy, export_window) {
                Some(Arc::new(tee::mnemonic_guard::MnemonicExportGuard::new(
                    entropy,
                    window_secs,
                )))
            } else if bootstrap.entropy.is_some() && export_window.is_none() {
                info!(
                    "first boot but VTA_MNEMONIC_EXPORT_WINDOW not set — mnemonic export disabled"
                );
                Some(Arc::new(tee::mnemonic_guard::MnemonicExportGuard::empty()))
            } else {
                Some(Arc::new(tee::mnemonic_guard::MnemonicExportGuard::empty()))
            }
        } else {
            None
        }
    };

    // ── Auto-generate DID identity on first boot ──
    if let Err(e) = tee::did_autogen::maybe_generate_vta_did(
        &mut config,
        &*seed_store,
        &store,
        storage_encryption_key,
    )
    .await
    {
        tracing::warn!("VTA DID auto-generation failed: {e}");
    }

    // ── Backfill the serverless did:webvh identity into the webvh keyspace ──
    // Auto-gen persists the DID + did.jsonl only under the KEYS/BOOTSTRAP
    // keyspaces; `list_services`, the self-DID resolver preload, and
    // `/.well-known/did.jsonl` read the record + log from the webvh keyspace via
    // `webvh_store`. Idempotent: no-op once populated, so it also repairs an
    // already-generated DID on a rebuild + restore.
    if let Some(vta_did) = config.vta_did.clone()
        && let Err(e) = vta_service::tee_webvh::backfill_serverless_webvh_identity(
            &store,
            storage_encryption_key,
            &vta_did,
        )
        .await
    {
        tracing::warn!("webvh identity backfill failed: {e}");
    }

    // ── Auto-bootstrap super-admin credential on first boot ──
    if let Err(e) =
        tee::admin_bootstrap::maybe_bootstrap_admin(&config, &store, storage_encryption_key).await
    {
        tracing::warn!("admin credential bootstrap failed: {e}");
    }

    // ── Initialize TEE provider + build context ──
    let tee_context = {
        let tee_state = match tee::init_tee(&config.tee) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("TEE initialization failed: {e}");
                std::process::exit(1);
            }
        };

        // ── Config attestation anchor (un-baked config hardening) ──
        // The tenant config is delivered by the untrusted parent, so it is no
        // longer committed to PCR0. Commit a SHA-384 digest of the exact config
        // this enclave booted into an NSM attestation document (`user_data`). PCR0
        // stays tenant-agnostic (one image / one PCR0), while a verifier who
        // obtains this AWS-signed document can pin `(PCR0, config-digest)`.
        //
        // SCOPE: this only *produces* the signed evidence and logs it; it does not
        // yet expose it to verifiers on demand. The log flows over the vsock-log
        // channel to the (untrusted) parent, which can withhold it, and the empty
        // nonce gives no freshness. An attested pull path (a REST endpoint that
        // returns the current digest bound to a caller-supplied nonce) is the
        // follow-up that makes the verifier story complete — see README.
        //
        // The digest is over the config *file bytes* (which is what is un-baked),
        // not the effective config; the two allowed env overrides
        // (VTA_LOG_LEVEL / VTA_LOG_FORMAT) are not reflected and are not security
        // relevant. Additive and non-fatal: a failure here does not block boot
        // (the KMS bootstrap already hard-requires attestation on real hardware).
        if let Some(state) = tee_state.as_ref().filter(|_| on_nitro) {
            // Use the path AppConfig actually loaded (`config.config_path`), not a
            // re-derived one, so the digest can't hash a different file than the
            // one in effect. This is also the file POST /attestation/config-report
            // digests, so the boot anchor and the pull endpoint agree.
            match std::fs::read(&config.config_path) {
                Ok(raw) => {
                    let digest = Sha384::digest(&raw);
                    let digest_b64 = BASE64.encode(digest);
                    match state.provider.attest(digest.as_slice(), &[]) {
                        Ok(report) => {
                            info!(
                                config_sha384_b64url = %digest_b64,
                                "config attestation anchor — signed NSM document committing the config digest generated; a tenant/verifier MUST check (PCR0, config-digest), incl. that key_arn is theirs, before onboarding (see deploy/nitro/README.md)"
                            );
                            // Full multi-KB document at debug to keep boot logs lean.
                            tracing::debug!(
                                attestation_doc_b64 = %report.evidence,
                                "config attestation document"
                            );
                        }
                        Err(e) => {
                            tracing::warn!("config attestation anchor failed (non-fatal): {e}")
                        }
                    }
                }
                Err(e) => tracing::warn!(
                    "config attestation anchor skipped — could not read {} for digest: {e}",
                    config.config_path.display()
                ),
            }
        }

        tee_state.map(|state| TeeContext {
            state,
            mnemonic_guard,
        })
    };

    // ── Start the server ──
    // `allow_degraded = true`: in a TEE the signing identity is established
    // earlier in this boot by KMS autogen (`maybe_generate_vta_did`) +
    // admin-bootstrap, and a degraded first boot is an existing, documented
    // state (see the TEE-required warning in `server::run`). The
    // missing-identity hard-fail (P0.9b) is a guard for the local `vta`
    // daemon, which exposes the `--allow-degraded` opt-out on its CLI; the
    // enclave has no such CLI surface.
    if let Err(e) = vta_service::server::run(
        config,
        store,
        seed_store,
        storage_encryption_key,
        tee_context,
        true,
        false, // flush_queues: not applicable to ephemeral enclave boots
    )
    .await
    {
        tracing::error!("server error: {e}");
        std::process::exit(1);
    }
}

// init_tracing is in vta_service::init_tracing (shared with all front-ends)

/// Security floor for a runtime-delivered (un-baked) tenant config.
///
/// Only a parent-authored config is untrusted: the floor applies when
/// `nsm_present` (real Nitro) **and** `parent_delivered` (config came over vsock
/// / env-fallback, not baked into the PCR0-measured image). A baked/mounted
/// config is trusted (in PCR0 when baked), so it is never blocked here — that is
/// what keeps this consistent with the "a baked config.toml wins" precedence.
/// Returns a human-readable violation message, or `None` when acceptable.
///
/// Rules (only when `nsm_present && parent_delivered`):
/// - `[tee] mode` must be `Required` (its default is `Optional`, which silently
///   continues without TEE).
/// - `[tee.kms]` must be present (`kms_present`) — without it the enclave skips
///   KMS bootstrap and takes its seed from the parent-supplied `[secrets]` block,
///   a full bypass of `mode = required`.
/// - `[tee.kms] admin_did` must be unset — a parent-supplied super-admin is not
///   attested. The attested path is sealed-bootstrap Mode B
///   (`POST /bootstrap/request`).
fn config_floor_violation(
    nsm_present: bool,
    parent_delivered: bool,
    mode: &vta_service::config::TeeMode,
    kms_present: bool,
    admin_did: Option<&str>,
) -> Option<String> {
    use vta_service::config::TeeMode;

    if !nsm_present || !parent_delivered {
        return None;
    }
    if !matches!(mode, TeeMode::Required) {
        return Some(format!(
            "/dev/nsm is present but [tee] mode = {mode:?} (not `required`) — a runtime-delivered \
             config must not weaken TEE enforcement"
        ));
    }
    if !kms_present {
        // Without `[tee.kms]` the enclave skips KMS bootstrap entirely: the seed
        // comes from the parent-supplied `[secrets]` block, the store is local
        // (not vsock), the env-override lockdown turns off, and the admin
        // carve-out stays open. `mode = "required"` without `[tee.kms]` is
        // therefore a silent bypass — refuse it.
        return Some(
            "/dev/nsm is present and [tee] mode = required but [tee.kms] is absent — the enclave \
             would skip KMS bootstrap and take its seed from the parent-supplied [secrets] block. \
             A runtime-delivered config must include [tee.kms] (region + key_arn)"
                .to_string(),
        );
    }
    if admin_did.is_some() {
        return Some(
            "/dev/nsm is present and the delivered config sets [tee.kms] admin_did — a \
             runtime-delivered admin_did is not attested and must not grant super-admin; leave it \
             unset and use the attested sealed-bootstrap flow (Mode B: POST /bootstrap/request)"
                .to_string(),
        );
    }
    None
}

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let red = "\x1b[31m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan} ██╗   ██╗{magenta}████████╗{yellow} █████╗{reset}
{cyan} ██║   ██║{magenta}╚══██╔══╝{yellow}██╔══██╗{reset}
{cyan} ██║   ██║{magenta}   ██║   {yellow}███████║{reset}
{cyan} ╚██╗ ██╔╝{magenta}   ██║   {yellow}██╔══██║{reset}
{cyan}  ╚████╔╝ {magenta}   ██║   {yellow}██║  ██║{reset}
{cyan}   ╚═══╝  {magenta}   ╚═╝   {yellow}╚═╝  ╚═╝{reset}
{dim}  Verifiable Trust Agent v{version}{reset}  {red}[TEE ENCLAVE]{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

#[cfg(test)]
mod tests {
    use super::config_floor_violation;
    use vta_service::config::TeeMode;

    #[test]
    fn no_enforcement_off_real_hardware() {
        // Simulated/dev (no /dev/nsm): config is trusted local input — never blocked.
        assert!(
            config_floor_violation(
                false,
                true,
                &TeeMode::Optional,
                false,
                Some("did:key:zAdmin")
            )
            .is_none()
        );
        assert!(config_floor_violation(false, true, &TeeMode::Simulated, false, None).is_none());
    }

    #[test]
    fn baked_config_is_never_blocked_on_nitro() {
        // A baked/mounted config is in PCR0 (trusted). Even a weak mode / admin_did
        // must NOT be rejected here — it is attested, and the floor is only for
        // parent-delivered configs.
        assert!(
            config_floor_violation(
                true,
                false,
                &TeeMode::Optional,
                false,
                Some("did:key:zAdmin")
            )
            .is_none()
        );
        assert!(config_floor_violation(true, false, &TeeMode::Required, true, None).is_none());
    }

    #[test]
    fn required_mode_with_kms_and_no_admin_is_accepted_on_nitro() {
        assert!(config_floor_violation(true, true, &TeeMode::Required, true, None).is_none());
    }

    #[test]
    fn weakened_mode_is_rejected_on_nitro() {
        for mode in [TeeMode::Optional, TeeMode::Simulated] {
            let v = config_floor_violation(true, true, &mode, true, None)
                .expect("weakened mode must be rejected on real Nitro");
            assert!(v.contains("mode"), "message should mention mode: {v}");
        }
    }

    #[test]
    fn missing_tee_kms_is_rejected_on_nitro_even_when_mode_required() {
        // mode = required but [tee.kms] absent must NOT pass — it silently
        // disables KMS bootstrap (seed from parent [secrets]).
        let v = config_floor_violation(true, true, &TeeMode::Required, false, None)
            .expect("mode=required with [tee.kms] absent must be rejected on real Nitro");
        assert!(
            v.contains("[tee.kms]"),
            "message should mention [tee.kms]: {v}"
        );
    }

    #[test]
    fn admin_did_is_rejected_on_nitro_even_when_mode_required() {
        let v =
            config_floor_violation(true, true, &TeeMode::Required, true, Some("did:key:zAdmin"))
                .expect("a parent-supplied admin_did must be rejected on real Nitro");
        assert!(
            v.contains("admin_did"),
            "message should mention admin_did: {v}"
        );
        assert!(
            v.contains("Mode B"),
            "message should point to the attested path: {v}"
        );
    }

    #[test]
    fn mode_floor_takes_precedence() {
        // Multiple violations present: the mode message is returned first.
        let v = config_floor_violation(
            true,
            true,
            &TeeMode::Optional,
            false,
            Some("did:key:zAdmin"),
        )
        .unwrap();
        assert!(
            v.contains("mode"),
            "mode violation should be reported first: {v}"
        );
    }

    #[test]
    fn missing_kms_takes_precedence_over_admin_did() {
        // kms-absent is checked before admin_did (admin_did lives under kms anyway).
        let v = config_floor_violation(
            true,
            true,
            &TeeMode::Required,
            false,
            Some("did:key:zAdmin"),
        )
        .unwrap();
        assert!(
            v.contains("[tee.kms]"),
            "missing-kms should be reported before admin_did: {v}"
        );
    }
}
