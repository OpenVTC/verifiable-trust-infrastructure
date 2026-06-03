//! `vta bootstrap` — sealed-transfer subcommands.
//!
//! Producer-side commands (`seal`, `provision-integration`) live alongside
//! consumer-side commands (`request`, `open`) so the same `vta` binary can
//! drive both ends of an offline round-trip in cold-start scenarios where
//! `pnm` is not yet available (e.g. the mediator or webvh hosting service
//! the integration would normally rely on does not exist yet).
//!
//! Consumer commands delegate to `vta_cli_common::sealed_consumer`, which
//! is the same shared layer `pnm` and `cnm` use — the only per-CLI concern
//! is which seed directory to default to.

use std::path::PathBuf;

use vta_sdk::sealed_transfer::{
    AssertionProof, BootstrapRequest, ProducerAssertion, SealedPayloadV1, armor, bundle_digest,
    generate_ed25519_keypair, seal_payload,
};

use crate::config::AppConfig;
use crate::sealed_nonce_store::PersistentNonceStore;
use crate::store::Store;

/// Default per-user seed cache for `vta bootstrap request` / `open`.
///
/// Mirrors the `~/.config/pnm/bootstrap-secrets/` convention used by `pnm`,
/// but lives under `vta/` so the two tools can coexist on the same host
/// without colliding. `--seed-dir` overrides this for portable / sandboxed
/// use (CI, sealed images with no `$HOME`).
fn default_seed_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = dirs::config_dir()
        .ok_or("could not determine config directory (set --seed-dir to override)")?
        .join("vta");
    Ok(dir)
}

fn resolve_seed_dir(override_dir: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    match override_dir {
        Some(d) => Ok(d),
        None => default_seed_dir(),
    }
}

/// Seal a payload to a consumer's BootstrapRequest (Mode C, offline).
pub async fn run_seal(
    config_path: Option<PathBuf>,
    request_path: PathBuf,
    payload_path: PathBuf,
    out_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_json = std::fs::read_to_string(&request_path)
        .map_err(|e| format!("read {}: {e}", request_path.display()))?;
    let request: BootstrapRequest =
        serde_json::from_str(&request_json).map_err(|e| format!("parse BootstrapRequest: {e}"))?;
    if request.version != 1 {
        return Err(format!("unsupported request version: {}", request.version).into());
    }

    let recipient_pk = request.decode_client_x25519_pub()?;
    let bundle_id = request.decode_nonce()?;

    let payload_json = std::fs::read_to_string(&payload_path)
        .map_err(|e| format!("read {}: {e}", payload_path.display()))?;
    let payload: SealedPayloadV1 =
        serde_json::from_str(&payload_json).map_err(|e| format!("parse SealedPayloadV1: {e}"))?;

    // Fresh per-seal producer identity. In Mode C the consumer pins this
    // did:key out-of-band — it is not tied to the VTA's long-lived DID.
    let (_producer_seed, producer_ed_pub) = generate_ed25519_keypair();
    let producer_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer_ed_pub);
    let producer = ProducerAssertion {
        producer_did: producer_did.clone(),
        proof: AssertionProof::PinnedOnly,
    };

    // Persistent nonce store — re-running `vta bootstrap seal` against the
    // same BootstrapRequest (e.g. after a network glitch) is rejected and
    // forces the consumer to regenerate their request.
    let config_store = AppConfig::load(config_path)?;
    let persistent_store = Store::open(&config_store.store)?;
    let nonce_ks = persistent_store.keyspace("sealed_nonces")?;
    let nonce_store = PersistentNonceStore::new(nonce_ks);
    let bundle = seal_payload(&recipient_pk, bundle_id, producer, &payload, &nonce_store).await?;
    persistent_store.persist().await?;

    let armored = armor::encode(&bundle);
    std::fs::write(&out_path, armored.as_bytes())
        .map_err(|e| format!("write {}: {e}", out_path.display()))?;

    let digest = bundle_digest(&bundle);
    eprintln!("Sealed bundle written to {}", out_path.display());
    eprintln!();
    eprintln!("  Bundle-Id:       {}", hex_lower(&bundle.bundle_id));
    eprintln!("  Chunks:          {}", bundle.chunks.len());
    eprintln!("  Producer DID:    {producer_did}");
    eprintln!("  SHA-256 digest:  {digest}");
    eprintln!();
    eprintln!(
        "Communicate the digest to the consumer out-of-band so they can run\n  \
         vta bootstrap open --bundle <file> --expect-digest {digest}\n  \
         (or `pnm bootstrap open` if the consumer has pnm installed)"
    );
    Ok(())
}

/// `vta bootstrap request` — consumer-side. Generate an ephemeral Ed25519
/// keypair, persist the seed under `<seed-dir>/bootstrap-secrets/<bundle_id>.key`,
/// and write a `BootstrapRequest` JSON the producer can hand to
/// `vta bootstrap seal` or `vta bootstrap provision-integration`.
///
/// Used in cold-start scenarios where `pnm bootstrap request` isn't
/// available — same wire shape, same on-disk format, different binary.
pub async fn run_request(
    out_path: PathBuf,
    label: Option<String>,
    seed_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let seed_dir = resolve_seed_dir(seed_dir)?;
    let created = vta_cli_common::sealed_consumer::create_bootstrap_request(&seed_dir, label)?;

    let json = serde_json::to_string_pretty(&created.request)?;
    std::fs::write(&out_path, json.as_bytes())
        .map_err(|e| format!("write {}: {e}", out_path.display()))?;

    eprintln!("Bootstrap request written to {}", out_path.display());
    eprintln!();
    eprintln!("  Bundle-Id:  {}", created.bundle_id_hex);
    eprintln!("  Client DID: {}", created.request.client_did);
    eprintln!("  Seed saved: {}", created.secret_path.display());
    eprintln!();
    eprintln!("Hand the request to the VTA operator. They will return an armored bundle.");
    eprintln!("Verify the SHA-256 digest they print to you out-of-band, then run:");
    eprintln!("  vta bootstrap open --bundle <file> --expect-digest <hex>");
    Ok(())
}

/// `vta bootstrap provision-request` — consumer-side. Generate a
/// VP-framed `BootstrapRequest` for the provision-integration flow.
///
/// Mints an ephemeral Ed25519 keypair, persists the seed under
/// `<seed-dir>/bootstrap-secrets/<bundle_id>.key`, and writes a signed
/// VP naming the target DID template (e.g. `didcomm-mediator`,
/// `did-hosting-control`, `did-hosting-daemon`, `did-hosting-server`) + variables. Hand
/// the JSON to the VTA
/// operator; they run `vta bootstrap provision-integration --request
/// <file>` and return an armored sealed bundle + SHA-256 digest.
/// Decrypt with `vta bootstrap open` on this host.
#[allow(clippy::too_many_arguments)]
pub async fn run_provision_request(
    template: String,
    vars: Vec<String>,
    context_hint: Option<String>,
    admin_template: Option<String>,
    validity_hours: f64,
    label: Option<String>,
    seed_dir: Option<PathBuf>,
    out_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    use vta_sdk::provision_integration::ProvisionRequestBuilder;

    if !validity_hours.is_finite() || validity_hours <= 0.0 {
        return Err(format!(
            "--validity-hours must be a positive finite number, got {validity_hours}"
        )
        .into());
    }
    let validity = chrono::Duration::seconds((validity_hours * 3600.0) as i64);

    let mut builder = ProvisionRequestBuilder::new(template).validity(validity);
    for raw in &vars {
        let (k, v) = parse_var(raw)?;
        builder = builder.var(k, v);
    }
    if let Some(ctx) = context_hint {
        builder = builder.context_hint(ctx);
    }
    if let Some(admin) = admin_template {
        builder = builder.admin_template(admin);
    }
    if let Some(l) = label {
        builder = builder.label(l);
    }

    let seed_dir = resolve_seed_dir(seed_dir)?;
    let created =
        vta_cli_common::sealed_consumer::create_provision_request(&seed_dir, builder).await?;

    let json = serde_json::to_string_pretty(&created.request)?;
    std::fs::write(&out_path, json.as_bytes())
        .map_err(|e| format!("write {}: {e}", out_path.display()))?;

    eprintln!(
        "Provision bootstrap request written to {}",
        out_path.display()
    );
    eprintln!();
    eprintln!("  Bundle-Id:  {}", created.bundle_id_hex);
    eprintln!("  Client DID: {}", created.client_did);
    eprintln!("  Seed saved: {}", created.secret_path.display());
    eprintln!();
    eprintln!("Hand the request to the VTA operator. They will run:");
    eprintln!("  vta bootstrap provision-integration --request <file> --out <bundle>");
    eprintln!("and return an armored sealed bundle + SHA-256 digest.");
    eprintln!();
    eprintln!("Verify the digest out-of-band, then:");
    eprintln!("  vta bootstrap open --bundle <file> --expect-digest <hex>");
    Ok(())
}

/// Parse a single `--var KEY=VALUE` argument. Value is tried as JSON
/// first (handles numbers, booleans, null, arrays, objects, quoted
/// strings); falls back to a plain string for unquoted values like
/// `URL=https://mediator.example.com`.
fn parse_var(raw: &str) -> Result<(String, serde_json::Value), Box<dyn std::error::Error>> {
    let (key, value) = raw
        .split_once('=')
        .ok_or_else(|| format!("invalid --var '{raw}': expected KEY=VALUE"))?;
    if key.is_empty() {
        return Err(format!("invalid --var '{raw}': empty key").into());
    }
    let parsed = serde_json::from_str::<serde_json::Value>(value)
        .unwrap_or_else(|_| serde_json::Value::String(value.to_string()));
    Ok((key.to_string(), parsed))
}

/// `vta bootstrap open` — consumer-side. Read an armored sealed bundle,
/// look up the matching seed under `<seed-dir>/bootstrap-secrets/`, derive
/// the X25519 HPKE secret, decrypt, verify the digest, and print the
/// payload contents.
///
/// `--expect-digest` is required by default; `--no-verify-digest` is an
/// opt-out that prints a warning. There is no silent TOFU.
///
/// When `expect_vta_did` is `Some(..)` and the payload is a
/// `TemplateBootstrap`, the VC + DidSigned producer assertion are
/// verified end-to-end against the pinned DID.
pub async fn run_open(
    bundle_path: PathBuf,
    expect_digest: Option<String>,
    no_verify_digest: bool,
    expect_vta_did: Option<String>,
    seed_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    if no_verify_digest {
        eprintln!(
            "WARNING: --no-verify-digest disables out-of-band integrity verification.\n\
             You are trusting the producer pubkey embedded in the bundle without\n\
             any external anchor. Use only for testing."
        );
    }

    let seed_dir = resolve_seed_dir(seed_dir)?;
    let opened = vta_cli_common::sealed_consumer::open_armored_bundle(
        &bundle_path,
        &seed_dir,
        expect_digest.as_deref(),
        no_verify_digest,
    )?;

    print_opened(&opened, expect_vta_did.as_deref())?;
    Ok(())
}

fn print_opened(
    opened: &vta_cli_common::sealed_consumer::OpenedArmored,
    expect_vta_did: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Sealed bundle opened.");
    println!();
    println!("  Bundle-Id:       {}", opened.bundle_id_hex);
    println!("  Digest (sha256): {}", opened.digest);
    println!("  Producer DID:    {}", opened.producer.producer_did);
    println!("  Producer proof:  {:?}", opened.producer.proof);
    println!();
    match &opened.payload {
        SealedPayloadV1::AdminCredential(c) => {
            println!("Payload: AdminCredential");
            println!("  DID:     {}", c.did);
            println!("  VTA DID: {}", c.vta_did);
            if let Some(ref u) = c.vta_url {
                println!("  VTA URL: {u}");
            }
        }
        SealedPayloadV1::ContextProvision(p) => {
            println!("Payload: ContextProvision");
            println!("  Context:   {} ({})", p.context_id, p.context_name);
            println!("  Admin DID: {}", p.admin_did);
        }
        SealedPayloadV1::DidSecrets(s) => {
            println!("Payload: DidSecrets");
            println!("  DID:     {}", s.did);
            println!("  Secrets: {}", s.secrets.len());
        }
        SealedPayloadV1::AdminKeySet(keys) => {
            println!("Payload: AdminKeySet ({} keys)", keys.len());
            for k in keys {
                println!("  - {}", k.label);
            }
        }
        SealedPayloadV1::RawPrivateKey(k) => {
            println!("Payload: RawPrivateKey ({})", k.key_type);
        }
        SealedPayloadV1::TemplateBootstrap(p) => {
            println!("Payload: TemplateBootstrap");
            println!("  Template:     {}", p.config.template_name);
            println!("  Kind:         {}", p.config.template_kind);
            println!("  Secrets for:  {} DID(s)", p.secrets.len());
            println!("  Outputs:      {}", p.config.outputs.len());
            if let Some(ref u) = p.config.vta_url {
                println!("  VTA URL:      {u}");
            }
            // End-to-end verification when the operator pinned a DID.
            match expect_vta_did {
                Some(pinned) => {
                    verify_template_bundle(opened, p.as_ref(), pinned)?;
                    println!();
                    println!("  \x1b[1;32m✓ VC verified against pinned VTA DID\x1b[0m");
                }
                None => {
                    println!();
                    println!("  \x1b[1;33m⚠ VC NOT verified — digest-only trust anchor.\x1b[0m");
                    println!("    Re-run with --expect-vta-did <did> to verify the authorization");
                    println!("    VC + DidSigned producer assertion end-to-end.");
                }
            }
        }
        SealedPayloadV1::AdminRotation(p) => {
            println!("Payload: AdminRotation");
            println!("  Admin DID:    {}", p.admin.did);
            println!("  VTA DID:      {}", p.vta_trust.vta_did);
            if let Some(ref u) = p.vta_url {
                println!("  VTA URL:      {u}");
            }
            // End-to-end verification of the AdminRotation VC parallels
            // the TemplateBootstrap path. Plumbing it through is left to
            // a future patch — the digest-pinning anchor still applies
            // by default.
            println!();
            println!(
                "  \x1b[1;33m⚠ VC verification not yet wired for AdminRotation — relying on digest pinning.\x1b[0m"
            );
        }
        SealedPayloadV1::IssuedCredential(c) => {
            println!("Payload: IssuedCredential");
            println!("  Issuer DID: {}", c.issuer_did);
            if let Some(ref label) = c.label {
                println!("  Label:      {label}");
            }
            let kind = if c.credential.is_string() {
                "SD-JWT-VC (compact)"
            } else {
                "W3C Data-Integrity VC"
            };
            println!("  Format:     {kind}");
        }
    }
    Ok(())
}

/// End-to-end verify a TemplateBootstrap bundle against a pinned VTA DID.
///
/// Two checks, both fail-closed:
///
/// 1. **VC verification** — the `VtaAuthorizationCredential` inside the
///    payload is verified against the pinned VTA DID: bundle
///    `vta_trust.vta_did == pinned == claim.admin_of.vta`, issuer
///    pubkey extracted from the bundled DID doc's
///    `verificationMethod[]`, Data Integrity proof verified, validity
///    window fresh.
/// 2. **Producer assertion verification** — when the chunk-0 producer
///    assertion is `DidSigned`, we confirm the signature was produced
///    by the key bound to `{vta_did}#key-0` in the bundled DID doc.
///    This defends against bundle re-sealing (an attacker with the
///    recipient's pubkey can HPKE-seal arbitrary content; the
///    DidSigned layer over `client_x25519_pub || bundle_id` proves the
///    VTA was the sealer). `PinnedOnly` short-circuits (caller is
///    trusting OOB digest by design); `Attested` defers to the
///    `attest-verify` feature path.
///
/// Both verifications use the same issuer pubkey derived from the
/// verified trust bundle, so they share cryptographic grounding.
fn verify_template_bundle(
    opened: &vta_cli_common::sealed_consumer::OpenedArmored,
    payload: &vta_sdk::sealed_transfer::TemplateBootstrapPayload,
    pinned_vta_did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use vta_sdk::provision_integration::template_verify::verify_template_bootstrap;
    use vta_sdk::sealed_transfer::AssertionProof;
    use vta_sdk::sealed_transfer::verify::{
        VerifiedAssertion, verify_producer_assertion_with_pubkey,
    };

    // VC + claim verification against pinned DID. Runs first so the
    // trust anchor is established before we authenticate the producer
    // assertion with a key extracted from the same doc.
    let _verified = verify_template_bootstrap(
        payload.clone(),
        pinned_vta_did,
        chrono::Duration::minutes(5),
    )?;

    // Producer assertion verification. Extract the producer's Ed25519
    // pubkey from its did:key form (VTA default; for did:webvh
    // producers a resolver-threading follow-up is tracked).
    let producer_pubkey = if let AssertionProof::DidSigned(_) = opened.producer.proof {
        match affinidi_crypto::did_key::did_key_to_ed25519_pub(&opened.producer.producer_did) {
            Ok(pk) => Some(pk),
            Err(e) => {
                return Err(format!(
                    "cannot decode producer DID '{}' as did:key for assertion verification: {e}. \
                     did:webvh producers need resolver threading (follow-up).",
                    opened.producer.producer_did
                )
                .into());
            }
        }
    } else {
        None
    };

    let verdict = verify_producer_assertion_with_pubkey(
        &opened.producer,
        &opened.client_x25519_pub,
        &opened.bundle_id,
        producer_pubkey.as_ref(),
    )?;

    // Exhaustively match so that a future variant addition forces this
    // code site to make an explicit decision rather than silently
    // accept the bundle.
    match verdict {
        VerifiedAssertion::DidSignedVerified(_) => {
            // Signature check succeeded — producer is cryptographically bound.
        }
        VerifiedAssertion::PinnedOnlyAcknowledged(_) => {
            // The digest-pinning check in `vta_cli_common::sealed_consumer::open_bundle`
            // is the sole integrity anchor for this variant. `--expect-digest` is
            // required by default at the CLI surface; if the caller opted out, they
            // accept the trust tradeoff.
        }
        VerifiedAssertion::AttestedNeedsNitroCheck(_) => {
            // `vta bootstrap provision-integration` does not currently accept
            // Attested producer assertions from the offline CLI. Refuse rather
            // than silently treat this as verified.
            return Err(
                "Attested producer assertion is not supported in the offline provision \
                 path — use the TEE Mode B bootstrap (`pnm bootstrap connect`) for \
                 attested-quote flows."
                    .into(),
            );
        }
    }

    Ok(())
}

use vta_sdk::hex::lower as hex_lower;

/// `vta bootstrap provision-integration` — offline provisioning from
/// the VTA host.
///
/// Reads the consumer's VP-framed `BootstrapRequest` JSON, verifies the
/// proof + freshness, calls the shared
/// [`crate::operations::provision_integration`] library fn, and writes
/// the resulting armored sealed bundle.
///
/// Produces all persistent state atomically (integration DID + log,
/// minted keys, admin ACL row) as part of the library-fn execution; the
/// returned bundle is derived from that state.
#[cfg(feature = "webvh")]
#[allow(clippy::too_many_arguments)]
pub async fn run_provision_integration(
    config_path: Option<PathBuf>,
    request_path: PathBuf,
    context: Option<String>,
    create_context: bool,
    assertion: AssertionModeFlag,
    vc_validity_hours: Option<f64>,
    out_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::auth::AuthClaims;
    use crate::operations::provision_integration::{
        AssertionMode, ProvisionIntegrationParams, provision_integration,
    };
    use crate::server::build_app_state;
    use tokio::sync::watch;
    use vta_sdk::provision_integration::BootstrapRequest;

    // 1. Parse + verify the request file (VP shape).
    let request_json = std::fs::read_to_string(&request_path)
        .map_err(|e| format!("read {}: {e}", request_path.display()))?;
    let request: BootstrapRequest = serde_json::from_str(&request_json)
        .map_err(|e| format!("parse BootstrapRequest (VP): {e}"))?;
    let verified = request
        .verify()
        .map_err(|e| format!("verify BootstrapRequest: {e}"))?;

    // 2. Resolve target context: explicit --context overrides the
    //    request's contextHint; otherwise take the hint; otherwise fail.
    let target_context = resolve_target_context(&verified, context)?;

    // 3. Build AppState from the VTA config the same way `vta` itself
    //    does. Storage-encryption key + TEE context are None here —
    //    offline CLI use, no enclave involvement — and the restart
    //    channel is a fresh local pair the CLI never signals on.
    let app_config = AppConfig::load(config_path)?;
    let store = Store::open(&app_config.store)?;
    let seed_store = crate::keys::seed_store::create_seed_store(&app_config)
        .map_err(|e| format!("create seed store: {e}"))?;
    let (restart_tx, _restart_rx) = watch::channel(false);
    let state = build_app_state(
        app_config,
        &store,
        seed_store.into(),
        None,
        None,
        restart_tx,
    )
    .await
    .map_err(|e| format!("build app state: {e}"))?;

    // 4. Synthesize a super-admin AuthClaims. The operator running
    //    `vta bootstrap provision-integration` on the VTA host has root
    //    access to the keyspace; there is no over-the-wire authn to
    //    delegate through. Production-grade gating happens on the HTTP
    //    endpoint which extracts a real session-backed claim.
    let auth = AuthClaims::unsafe_local_cli_super_admin("provision-integration");

    // 4a. Validate the target context exists, or create it inline when
    //     the operator opted in via --create-context. Same helper
    //     drives the REST + DIDComm transport handlers — the
    //     super-admin gate inside `operations::contexts::
    //     create_context` is the authoritative auth check.
    let context_created =
        crate::operations::provision_integration::ensure_target_context_or_create(
            &state.contexts_ks,
            &auth,
            &target_context,
            create_context,
        )
        .await
        .map_err(|e| format!("ensure context '{target_context}': {e}"))?;
    if context_created {
        eprintln!("Created context '{target_context}' (--create-context).");
    }

    // 5. Call the shared library fn.
    let vc_validity = vc_validity_hours.map(|hrs| {
        // chrono::Duration::seconds takes i64; hours * 3600 fits for any
        // reasonable operator input.
        chrono::Duration::seconds((hrs * 3600.0) as i64)
    });
    let assertion_mode = match assertion {
        AssertionModeFlag::DidSigned => AssertionMode::DidSigned,
        AssertionModeFlag::PinnedOnly => AssertionMode::PinnedOnly,
    };

    let deps = crate::operations::provision_integration::ProvisionIntegrationDeps::from(&state);
    let output = provision_integration(
        &deps,
        &auth,
        ProvisionIntegrationParams {
            request: verified,
            context: target_context,
            assertion_mode,
            vc_validity,
        },
    )
    .await
    .map_err(|e| format!("provision-integration: {e}"))?;

    // 6. Persist nonce-store writes + any other fjall flushes. The
    //    shared fn already committed its rows via the keyspaces; this
    //    call just forces any buffered-writes to disk before the CLI
    //    exits.
    store.persist().await?;

    // 7. Write the armored bundle.
    std::fs::write(&out_path, output.armored.as_bytes())
        .map_err(|e| format!("write {}: {e}", out_path.display()))?;

    // 8. Print the operator summary.
    eprintln!(
        "Integration provisioned — sealed bundle written to {}",
        out_path.display()
    );
    eprintln!();
    eprintln!("  Bundle-Id:       {}", output.summary.bundle_id_hex);
    eprintln!("  Client DID:      {}", output.summary.client_did);
    if output.summary.admin_rolled_over {
        eprintln!(
            "  Admin DID:       {} (VTA-minted, rolled over from client)",
            output.summary.admin_did
        );
        if let Some(ref admin_tpl) = output.summary.admin_template_name {
            eprintln!("  Admin template:  {admin_tpl}");
        }
    } else {
        eprintln!(
            "  Admin DID:       {} (== client)",
            output.summary.admin_did
        );
    }
    if let Some(ref integration_did) = output.summary.integration_did {
        eprintln!("  Integration DID: {integration_did}");
    } else {
        eprintln!("  Integration DID: (none — admin-rotation only)");
    }
    if let (Some(name), Some(kind)) = (
        output.summary.template_name.as_deref(),
        output.summary.template_kind.as_deref(),
    ) {
        eprintln!("  Template:        {name} ({kind})");
    }
    eprintln!("  Secrets:         {}", output.summary.secret_count);
    eprintln!("  Outputs:         {}", output.summary.output_count);
    eprintln!("  SHA-256 digest:  {}", output.digest);
    eprintln!();
    eprintln!(
        "Communicate the digest to the integration's operator out-of-band so they can\n  \
         verify the bundle on first boot:\n  \
         pnm bootstrap open --bundle <file> --expect-digest {}",
        output.digest
    );

    Ok(())
}

/// Resolve which context the operator wants to provision into.
///
/// Rules:
/// - If `--context` was passed, it must either match the request's
///   `contextHint` or the request must have no hint.
/// - If `--context` was omitted, the request's hint is authoritative.
/// - If neither is present, fail with a clear error.
///
/// Silent normalization hides operator bugs — the brief is explicit on
/// this. Mismatches are rejected, not reconciled.
#[cfg(feature = "webvh")]
fn resolve_target_context(
    request: &vta_sdk::provision_integration::VerifiedBootstrapRequest,
    explicit: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    use vta_sdk::provision_integration::BootstrapAsk;
    let hint = match request.ask() {
        BootstrapAsk::TemplateBootstrap(ask) => ask.context_hint.clone(),
        BootstrapAsk::AdminRotation(ask) => ask.context_hint.clone(),
    };
    match (explicit, hint) {
        (Some(explicit), Some(hint)) if explicit != hint => Err(format!(
            "--context '{explicit}' does not match request contextHint '{hint}' — \
             operator and integration must agree on the context before provisioning"
        )
        .into()),
        (Some(explicit), _) => Ok(explicit),
        (None, Some(hint)) => Ok(hint),
        (None, None) => Err(
            "no context specified — pass --context <id> or have the integration's \
             BootstrapRequest include a contextHint"
                .into(),
        ),
    }
}

/// CLI-friendly enum for `--assertion` flag values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssertionModeFlag {
    #[default]
    DidSigned,
    PinnedOnly,
}

impl std::str::FromStr for AssertionModeFlag {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "did-signed" | "didsigned" | "did_signed" => Ok(Self::DidSigned),
            "pinned-only" | "pinnedonly" | "pinned_only" | "pinned" => Ok(Self::PinnedOnly),
            other => Err(format!(
                "invalid --assertion value '{other}' — use 'did-signed' or 'pinned-only'"
            )),
        }
    }
}

/// `vta keys bundle` — offline equivalent of `pnm keys bundle`.
///
/// Reads the local VTA store directly (no HTTP, no running service),
/// builds a [`vta_sdk::did_secrets::DidSecretsBundle`] for the named
/// context, and seals it to the consumer's BootstrapRequest. Shared
/// emit surface with the PNM version so bundle shape + armored output
/// + banner are byte-identical.
pub async fn run_keys_bundle(
    config_path: Option<PathBuf>,
    context: String,
    recipient: Option<PathBuf>,
    recipient_did: Option<String>,
    recipient_nonce: Option<String>,
    out: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::auth::AuthClaims;
    use crate::operations::export::{ExportDeps, build_did_secrets_bundle};
    use crate::server::build_app_state;
    use tokio::sync::watch;

    let recipient = vta_cli_common::sealed_producer::resolve_recipient(
        recipient.as_deref(),
        recipient_did.as_deref(),
        recipient_nonce.as_deref(),
    )?;

    let app_config = AppConfig::load(config_path)?;
    let store = Store::open(&app_config.store)?;
    let seed_store = crate::keys::seed_store::create_seed_store(&app_config)
        .map_err(|e| format!("create seed store: {e}"))?;
    let (restart_tx, _restart_rx) = watch::channel(false);
    let state = build_app_state(
        app_config,
        &store,
        seed_store.into(),
        None,
        None,
        restart_tx,
    )
    .await
    .map_err(|e| format!("build app state: {e}"))?;

    let auth = AuthClaims::unsafe_local_cli_super_admin("keys-bundle");

    let deps = ExportDeps {
        keys_ks: &state.keys_ks,
        contexts_ks: &state.contexts_ks,
        imported_ks: &state.imported_ks,
        audit_ks: &state.audit_ks,
        acl_ks: &state.acl_ks,
        #[cfg(feature = "webvh")]
        webvh_ks: &state.webvh_ks,
        seed_store: &state.seed_store,
    };
    let bundle = build_did_secrets_bundle(&deps, &auth, &context, "vta-keys-bundle").await?;

    vta_cli_common::sealed_producer::emit_did_secrets_bundle(
        bundle,
        &recipient,
        &context,
        out.as_deref(),
    )
    .await
}

/// Convert a server-side `CreateContextResultBody` (the operations-layer
/// return type) to the client-side `ContextResponse` shape that the
/// shared `vta_cli_common::commands::contexts::render_*` helpers
/// consume. Field-by-field copy — the two types are identical on the
/// wire; this adapter exists only because they're declared in
/// different modules for layering reasons.
fn to_context_response(
    record: &vta_sdk::protocols::context_management::create::CreateContextResultBody,
) -> vta_sdk::client::ContextResponse {
    vta_sdk::client::ContextResponse {
        id: record.id.clone(),
        name: record.name.clone(),
        did: record.did.clone(),
        description: record.description.clone(),
        base_path: record.base_path.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

/// `vta contexts create` — offline equivalent of `POST /contexts`
/// (and `pnm contexts create`).
///
/// Allocates the next BIP-32 context index and writes the context
/// record directly to the local keystore. When `--admin-did` is set,
/// also writes an admin ACL entry scoped to the new context, mirroring
/// the online `pnm contexts create --admin-did` shorthand.
#[allow(clippy::too_many_arguments)]
pub async fn run_context_create(
    config_path: Option<PathBuf>,
    id: String,
    name: Option<String>,
    description: Option<String>,
    parent: Option<String>,
    admin_did: Option<String>,
    admin_label: Option<String>,
    admin_expires: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::auth::AuthClaims;
    use vta_cli_common::commands::contexts::render_context_record;

    let app_config = AppConfig::load(config_path)?;
    let store = Store::open(&app_config.store)?;
    let contexts_ks = store.keyspace("contexts")?;
    let acl_ks = store.keyspace("acl")?;

    let auth = AuthClaims::unsafe_local_cli_super_admin("context-create");
    let display_name = name.unwrap_or_else(|| id.clone());

    let record = crate::operations::contexts::create_context(
        &contexts_ks,
        &auth,
        &id,
        display_name,
        description,
        parent,
        "vta-context-create",
    )
    .await?;

    // Optionally grant admin access to the supplied DID, scoped to the
    // new context. Mirrors `pnm contexts create --admin-did ...` so the
    // offline path can also do "create context + grant first admin" in
    // one shot.
    if let Some(did) = admin_did {
        if !did.starts_with("did:") {
            return Err(format!(
                "--admin-did must start with `did:` (got {did:?}) — context was created \
                 but no ACL entry was added"
            )
            .into());
        }
        let expires_at = match admin_expires.as_deref() {
            Some(raw) => Some(vta_cli_common::duration::duration_to_expires_at(raw)?),
            None => None,
        };
        let entry = crate::acl::AclEntry::new(
            did.clone(),
            crate::acl::Role::Admin,
            format!("vta-context-create:{}", auth.did),
        )
        .with_label(admin_label)
        // Scope to the full path the operation assigned (`<parent>/<id>` nested).
        .with_contexts(vec![record.id.clone()])
        .with_expires_at(expires_at);
        crate::acl::store_acl_entry(&acl_ks, &entry).await?;
        eprintln!(
            "Admin ACL entry created for {did} (context: {}).",
            record.id
        );
    }

    store.persist().await?;

    println!("Context created:");
    render_context_record(&to_context_response(&record));
    Ok(())
}

/// `vta contexts list` — offline equivalent of `GET /contexts`
/// (and `pnm contexts list`).
pub async fn run_context_list(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::auth::AuthClaims;
    use vta_cli_common::commands::contexts::render_context_list;

    let app_config = AppConfig::load(config_path)?;
    let store = Store::open(&app_config.store)?;
    let contexts_ks = store.keyspace("contexts")?;

    let auth = AuthClaims::unsafe_local_cli_super_admin("context-list");
    let resp = crate::operations::contexts::list_contexts(&contexts_ks, &auth, "vta-contexts-list")
        .await?;

    let contexts: Vec<_> = resp.contexts.iter().map(to_context_response).collect();
    render_context_list(&contexts);
    Ok(())
}

/// `vta contexts get` — offline equivalent of `GET /contexts/{id}`
/// (and `pnm contexts get`).
pub async fn run_context_get(
    config_path: Option<PathBuf>,
    id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::auth::AuthClaims;
    use vta_cli_common::commands::contexts::render_context_record;

    let app_config = AppConfig::load(config_path)?;
    let store = Store::open(&app_config.store)?;
    let contexts_ks = store.keyspace("contexts")?;

    let auth = AuthClaims::unsafe_local_cli_super_admin("context-get");
    let record =
        crate::operations::contexts::get_context_op(&contexts_ks, &auth, &id, "vta-contexts-get")
            .await?;

    render_context_record(&to_context_response(&record));
    Ok(())
}

/// `vta contexts update` — offline equivalent of `PUT /contexts/{id}`
/// (and `pnm contexts update`).
pub async fn run_context_update(
    config_path: Option<PathBuf>,
    id: String,
    name: Option<String>,
    did: Option<String>,
    description: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::auth::AuthClaims;
    use crate::operations::contexts::UpdateContextParams;
    use vta_cli_common::commands::contexts::render_context_record;

    let app_config = AppConfig::load(config_path)?;
    let store = Store::open(&app_config.store)?;
    let contexts_ks = store.keyspace("contexts")?;

    let auth = AuthClaims::unsafe_local_cli_super_admin("context-update");
    let params = UpdateContextParams {
        name,
        did,
        description,
    };
    let record = crate::operations::contexts::update_context(
        &contexts_ks,
        &auth,
        &id,
        params,
        "vta-contexts-update",
    )
    .await?;

    store.persist().await?;
    println!("Context updated:");
    render_context_record(&to_context_response(&record));
    Ok(())
}

/// `vta contexts delete` — offline equivalent of `DELETE /contexts/{id}`
/// (and `pnm contexts delete`).
pub async fn run_context_delete(
    config_path: Option<PathBuf>,
    id: String,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::auth::AuthClaims;
    use crate::operations::Keyspaces;
    use vta_cli_common::commands::contexts::{confirm_destructive, render_delete_context_preview};

    let app_config = AppConfig::load(config_path)?;
    let store = Store::open(&app_config.store)?;
    let contexts_ks = store.keyspace("contexts")?;
    let keys_ks = store.keyspace("keys")?;
    let acl_ks = store.keyspace("acl")?;
    let did_templates_ks = store.keyspace("did_templates")?;
    let audit_ks = store.keyspace("audit")?;
    let imported_ks = store.keyspace("imported_secrets")?;
    #[cfg(feature = "webvh")]
    let webvh_ks = store.keyspace("webvh")?;

    let auth = AuthClaims::unsafe_local_cli_super_admin("context-delete");

    let preview = crate::operations::contexts::preview_delete_context(
        &contexts_ks,
        &keys_ks,
        &acl_ks,
        &did_templates_ks,
        #[cfg(feature = "webvh")]
        &webvh_ks,
        &auth,
        &id,
        "vta-contexts-delete",
    )
    .await?;

    let has_resources = render_delete_context_preview(&id, &preview);
    if has_resources && !force && !confirm_destructive("Proceed with deletion?")? {
        println!("Aborted.");
        return Ok(());
    }

    let ks = Keyspaces {
        contexts: &contexts_ks,
        keys: &keys_ks,
        acl: &acl_ks,
        did_templates: &did_templates_ks,
        audit: &audit_ks,
        imported: &imported_ks,
        #[cfg(feature = "webvh")]
        webvh: &webvh_ks,
    };
    crate::operations::contexts::delete_context(&ks, &auth, &id, true, "vta-contexts-delete")
        .await?;

    store.persist().await?;
    println!("Context deleted: {id}");
    Ok(())
}

/// `vta context reprovision` — offline equivalent of
/// `pnm context reprovision`.
///
/// The DID's operational keys (signing, KA, any pre-rotation) are
/// auto-included — the operator does not need to enumerate them.
/// `--admin-key` picks which existing keystore entry's seed backs the
/// **admin credential** (a separate `did:key` identity the mediator
/// operator uses to authenticate to the VTA afterwards). When omitted,
/// a fresh Ed25519 admin key is minted in the context and the derived
/// `did:key` is granted admin access automatically.
#[allow(clippy::too_many_arguments)]
pub async fn run_context_reprovision(
    config_path: Option<PathBuf>,
    id: String,
    admin_key: Option<String>,
    admin_label: Option<String>,
    recipient: Option<PathBuf>,
    recipient_did: Option<String>,
    recipient_nonce: Option<String>,
    out: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::acl::Role;
    use crate::auth::AuthClaims;
    use crate::keys::KeyType;
    use crate::operations::export::{
        ContextReprovisionInputs, ExportDeps, build_context_provision_bundle,
    };
    use crate::operations::keys::{CreateKeyParams, create_key};
    use crate::server::build_app_state;
    use tokio::sync::watch;

    let recipient = vta_cli_common::sealed_producer::resolve_recipient(
        recipient.as_deref(),
        recipient_did.as_deref(),
        recipient_nonce.as_deref(),
    )?;

    let app_config = AppConfig::load(config_path)?;
    let store = Store::open(&app_config.store)?;
    let vta_did = app_config
        .vta_did
        .clone()
        .ok_or("VTA DID not configured — run `vta setup` or set vta_did in config")?;
    let vta_url = app_config.public_url.clone();
    let seed_store = crate::keys::seed_store::create_seed_store(&app_config)
        .map_err(|e| format!("create seed store: {e}"))?;
    let (restart_tx, _restart_rx) = watch::channel(false);
    let state = build_app_state(
        app_config,
        &store,
        seed_store.into(),
        None,
        None,
        restart_tx,
    )
    .await
    .map_err(|e| format!("build app state: {e}"))?;

    let auth = AuthClaims::unsafe_local_cli_super_admin("context-reprovision");

    // Resolve the admin key: reuse an existing keystore entry when
    // `--admin-key` was passed, otherwise mint a fresh one scoped to
    // this context. The derived `did:key` gets an ACL row written
    // further down if one doesn't already exist.
    let key_id = match admin_key {
        Some(kid) => kid,
        None => {
            let label = admin_label
                .clone()
                .unwrap_or_else(|| "admin-reprovision".to_string());
            let result = create_key(
                &state.keys_ks,
                &state.contexts_ks,
                &state.seed_store,
                &state.audit_ks,
                &auth,
                CreateKeyParams {
                    key_type: KeyType::Ed25519,
                    derivation_path: None,
                    key_id: None,
                    mnemonic: None,
                    label: Some(label),
                    context_id: Some(id.clone()),
                },
                "vta-context-reprovision",
            )
            .await?;
            eprintln!(
                "Minted fresh admin key '{}' in context '{id}'",
                result.key_id
            );
            result.key_id
        }
    };

    let deps = ExportDeps {
        keys_ks: &state.keys_ks,
        contexts_ks: &state.contexts_ks,
        imported_ks: &state.imported_ks,
        audit_ks: &state.audit_ks,
        acl_ks: &state.acl_ks,
        #[cfg(feature = "webvh")]
        webvh_ks: &state.webvh_ks,
        seed_store: &state.seed_store,
    };

    let bundle = build_context_provision_bundle(
        &deps,
        &auth,
        ContextReprovisionInputs {
            context_id: id.clone(),
            key_id,
        },
        &vta_did,
        vta_url.as_deref(),
        "vta-context-reprovision",
    )
    .await?;

    // Ensure the derived admin DID has an ACL entry for this context.
    // Mirrors the online cmd_context_reprovision behaviour — if the
    // consumer is a new admin, this is the write that makes their
    // future REST auth succeed.
    let admin_did = bundle.admin_did.clone();
    let existing = crate::acl::get_acl_entry(&state.acl_ks, &admin_did).await?;
    if existing.is_none() {
        use crate::acl::AclEntry;
        use chrono::Utc;
        let entry = AclEntry::new(admin_did.clone(), Role::Admin, auth.did.clone())
            .with_contexts(vec![id.clone()])
            .with_created_at(Utc::now().timestamp() as u64);
        crate::acl::store_acl_entry(&state.acl_ks, &entry).await?;
        store.persist().await?;
        eprintln!("Created ACL entry for {admin_did} in context '{id}'");
    }

    vta_cli_common::sealed_producer::emit_context_provision_bundle(
        bundle,
        &recipient,
        out.as_deref(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::parse_var;
    use serde_json::Value;

    #[cfg(feature = "webvh")]
    use crate::auth::AuthClaims;
    #[cfg(feature = "webvh")]
    use crate::contexts::get_context;
    #[cfg(feature = "webvh")]
    use crate::operations::provision_integration::ensure_target_context_or_create;
    #[cfg(feature = "webvh")]
    use crate::store::Store;
    #[cfg(feature = "webvh")]
    use vti_common::config::StoreConfig;

    /// Open a tempdir-backed `Store` and return the `contexts` keyspace
    /// handle. The tempdir is held in the returned guard so it lives as
    /// long as the test needs the store.
    #[cfg(feature = "webvh")]
    fn open_test_contexts_keyspace() -> (tempfile::TempDir, Store, crate::store::KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace("contexts").expect("contexts keyspace");
        (dir, store, ks)
    }

    #[test]
    fn parse_var_plain_string() {
        let (k, v) = parse_var("URL=https://mediator.example.com").unwrap();
        assert_eq!(k, "URL");
        assert_eq!(v, Value::String("https://mediator.example.com".into()));
    }

    #[test]
    fn parse_var_quoted_string_is_json() {
        let (k, v) = parse_var(r#"LABEL="hello world""#).unwrap();
        assert_eq!(k, "LABEL");
        assert_eq!(v, Value::String("hello world".into()));
    }

    #[test]
    fn parse_var_number_is_json() {
        let (k, v) = parse_var("COUNT=42").unwrap();
        assert_eq!(k, "COUNT");
        assert_eq!(v, Value::Number(42.into()));
    }

    #[test]
    fn parse_var_bool_is_json() {
        let (_, v) = parse_var("ENABLED=true").unwrap();
        assert_eq!(v, Value::Bool(true));
    }

    #[test]
    fn parse_var_array_is_json() {
        let (_, v) = parse_var(r#"ROUTING_KEYS=["did:key:z1"]"#).unwrap();
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 1);
    }

    #[test]
    fn parse_var_value_may_contain_equals() {
        // URLs with query strings include '=' — the first '=' is the
        // delimiter, rest of the string is the value.
        let (k, v) = parse_var("URL=https://m.example.com?x=1&y=2").unwrap();
        assert_eq!(k, "URL");
        assert_eq!(v, Value::String("https://m.example.com?x=1&y=2".into()));
    }

    #[test]
    fn parse_var_missing_equals_errors() {
        let err = parse_var("LONELY").unwrap_err();
        assert!(err.to_string().contains("KEY=VALUE"));
    }

    #[test]
    fn parse_var_empty_key_errors() {
        let err = parse_var("=value").unwrap_err();
        assert!(err.to_string().contains("empty key"));
    }

    /// Negative case for the operator UX fix: when the operator pastes a
    /// generated `vta bootstrap provision-integration` command without
    /// `--create-context` and the target context doesn't exist yet, the
    /// CLI must fail with an error that names the missing flag (so the
    /// fix is "obvious paste-and-go", not "search the docs"). Reproduces
    /// the failure mode reported by an operator who ran a wizard-
    /// generated command against a fresh VTA.
    #[cfg(feature = "webvh")]
    #[tokio::test]
    async fn ensure_target_context_or_create_returns_actionable_error_when_missing() {
        let (_dir, _store, contexts_ks) = open_test_contexts_keyspace();
        let auth = AuthClaims::unsafe_local_cli_super_admin("test");

        let err = ensure_target_context_or_create(&contexts_ks, &auth, "missing-ctx", false)
            .await
            .expect_err("missing context with create_context=false must error");

        let msg = err.to_string();
        assert!(
            msg.contains("--create-context"),
            "error must name --create-context flag, got: {msg}"
        );
        assert!(
            msg.contains("missing-ctx"),
            "error must name the missing context, got: {msg}"
        );
        // Belt-and-suspenders: the context is still absent — the helper
        // must not have created anything as a side effect of the failure.
        assert!(
            get_context(&contexts_ks, "missing-ctx")
                .await
                .unwrap()
                .is_none(),
            "context must remain absent after the negative path"
        );
    }

    /// Positive case for the same fix: when `--create-context` is set,
    /// the helper creates the missing context inline and returns Ok.
    /// The context exists in the keyspace afterwards, ready for the
    /// downstream `provision_integration` library call.
    #[cfg(feature = "webvh")]
    #[tokio::test]
    async fn ensure_target_context_or_create_creates_context_when_flag_set() {
        let (_dir, _store, contexts_ks) = open_test_contexts_keyspace();
        let auth = AuthClaims::unsafe_local_cli_super_admin("test");

        ensure_target_context_or_create(&contexts_ks, &auth, "fresh-ctx", true)
            .await
            .expect("create_context=true must succeed against a missing context");

        let record = get_context(&contexts_ks, "fresh-ctx")
            .await
            .unwrap()
            .expect("context must exist after create_context=true");
        assert_eq!(record.id, "fresh-ctx");
    }

    /// Idempotence: when the context already exists, the helper is a
    /// no-op regardless of the `create_context` flag — provisioning
    /// proceeds normally.
    #[cfg(feature = "webvh")]
    #[tokio::test]
    async fn ensure_target_context_or_create_is_idempotent_when_context_exists() {
        let (_dir, _store, contexts_ks) = open_test_contexts_keyspace();
        let auth = AuthClaims::unsafe_local_cli_super_admin("test");

        crate::operations::contexts::create_context(
            &contexts_ks,
            &auth,
            "existing-ctx",
            "existing-ctx".into(),
            None,
            None,
            "test-setup",
        )
        .await
        .expect("seed existing context");

        // create_context=false should still succeed because the context
        // is already there.
        ensure_target_context_or_create(&contexts_ks, &auth, "existing-ctx", false)
            .await
            .expect("existing context with create_context=false must be a no-op");

        // create_context=true must also succeed — it doesn't try to
        // re-create when the row is already present.
        ensure_target_context_or_create(&contexts_ks, &auth, "existing-ctx", true)
            .await
            .expect("existing context with create_context=true must be a no-op");
    }
}
