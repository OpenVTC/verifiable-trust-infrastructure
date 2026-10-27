//! `pnm bootstrap` — sealed-transfer consumer commands.
//!
//! Thin pnm-side wrapper over `vta_cli_common::sealed_consumer`. The shared
//! crate owns the seed-file conventions (`<config_dir>/bootstrap-secrets/<bundle_id>.key`,
//! 0600 on Unix, owner-only DACL on Windows), the armor-decode/HPKE-open
//! pipeline, and the `--no-verify-digest` warning text. This module only
//! adds pnm-specific glue: payload pretty-printing for `bootstrap open`,
//! the online TEE attest/connect flow, and the authed REST bridge for
//! `provision-integration`.
//!
//! Offline opening requires `--expect-digest` or an explicit warning-bearing
//! `--no-verify-digest`. Online connect is not a sealed transfer at all since
//! #2066 — the VTA enrols the claim DID and returns an attested
//! acknowledgement with no key in it — so its anchor is the pinned enclave
//! image (`--expect-pcr0`), not a digest.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use vta_sdk::sealed_transfer::SealedPayloadV1;
use vta_sdk::tee_bootstrap::{FirstBootAck, FirstBootClaim, FirstBootClaimInfo};

use crate::auth;
use crate::config;

/// `pnm bootstrap request --out <PATH> [--label <NAME>]`
pub async fn run_request(
    out: PathBuf,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = config::config_dir()?;
    let created = vta_cli_common::sealed_consumer::create_bootstrap_request(&config_dir, label)?;
    let json = serde_json::to_string_pretty(&created.request)?;
    fs::write(&out, json.as_bytes())?;

    println!("Bootstrap request written to {}", out.display());
    println!();
    println!("  Bundle-Id:  {}", created.bundle_id_hex);
    println!("  Client DID: {}", created.request.client_did);
    println!("  Seed saved: {}", created.secret_path.display());
    println!();
    println!("Hand the request to the producer. They will return an armored bundle.");
    println!("Verify the SHA-256 digest they print to you out-of-band, then run:");
    println!("  pnm bootstrap open --bundle <file> --expect-digest <hex>");
    Ok(())
}

/// `pnm bootstrap provision-request` — consumer-side. Generate a
/// VP-framed `BootstrapRequest` for the provision-integration flow.
///
/// Mints an ephemeral Ed25519 keypair, persists the seed under
/// `~/.config/pnm/bootstrap-secrets/<bundle_id>.key`, and writes a
/// signed VP naming the target DID template + variables. Hand the JSON
/// to the VTA operator's `vta bootstrap provision-integration` or
/// `pnm bootstrap provision-integration` (authed bridge) and decrypt
/// the returned bundle with `pnm bootstrap open`.
#[allow(clippy::too_many_arguments)]
pub async fn run_provision_request(
    template: String,
    vars: Vec<String>,
    context_hint: Option<String>,
    admin_template: Option<String>,
    validity_hours: f64,
    label: Option<String>,
    out: PathBuf,
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

    let config_dir = config::config_dir()?;
    let created =
        vta_cli_common::sealed_consumer::create_provision_request(&config_dir, builder).await?;

    let json = serde_json::to_string_pretty(&created.request)?;
    fs::write(&out, json.as_bytes())?;

    println!("Provision bootstrap request written to {}", out.display());
    println!();
    println!("  Bundle-Id:  {}", created.bundle_id_hex);
    println!("  Client DID: {}", created.client_did);
    println!("  Seed saved: {}", created.secret_path.display());
    println!();
    println!("Hand the request to the VTA operator. They will run:");
    println!("  vta bootstrap provision-integration --request <file> --out <bundle>");
    println!("(or `pnm bootstrap provision-integration` over REST against a live VTA).");
    println!();
    println!("Verify the returned digest out-of-band, then:");
    println!("  pnm bootstrap open --bundle <file> --expect-digest <hex>");
    Ok(())
}

/// Parse a single `--var KEY=VALUE` argument. Value is tried as JSON
/// first; falls back to a plain string for unquoted values.
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

/// `pnm bootstrap open --bundle <PATH> [--expect-digest <HEX>] [--no-verify-digest]`
pub async fn run_open(
    bundle_path: PathBuf,
    out: Option<PathBuf>,
    expect_digest: Option<String>,
    no_verify_digest: bool,
    expect_vta_did: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = config::config_dir()?;
    // The request seed is consumed only once something is written (`--out`).
    // Opening to look is not installing, and the seed is the only key that
    // opens the bundle again (VTI-53).
    let (opened, secret) = vta_cli_common::sealed_consumer::open_armored_bundle_keeping_secret(
        &bundle_path,
        &config_dir,
        expect_digest.as_deref(),
        no_verify_digest,
    )?;

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
            if out.is_none() {
                println!();
                println!("Nothing was written. To install this credential either:");
                println!("  - re-open with --out <path> for a file-based consumer, or");
                println!(
                    "  - use the online flow: pnm bootstrap connect --vta-did <did> \
                     --expect-pcr0 <hex> [--expect-pcr8 <hex>]"
                );
                println!(
                    "    (--vta-url <url> is the fallback when the DID log is not yet \
                     resolvable; it does not pin the VTA's identity)"
                );
            }
        }
        SealedPayloadV1::ContextProvision(p) => {
            println!("Payload: ContextProvision");
            println!("  Context:   {} ({})", p.context_id, p.context_name);
            println!("  Admin DID: {}", p.admin_did);
            if out.is_none() {
                println!();
                println!(
                    "Nothing was written — this payload carries an admin credential. \
                     Re-open with --out <path> to write it as JSON."
                );
            }
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
            match expect_vta_did.as_deref() {
                Some(pinned) => {
                    use vta_sdk::provision_integration::template_verify::verify_template_bootstrap;
                    verify_template_bootstrap((**p).clone(), pinned, chrono::Duration::minutes(5))?;
                    println!();
                    println!("  \x1b[1;32m✓ VC verified against pinned VTA DID\x1b[0m");
                }
                None => {
                    println!();
                    println!("  \x1b[1;33m⚠ VC NOT verified — digest-only trust anchor.\x1b[0m");
                    println!(
                        "    Re-run with --expect-vta-did <did> to verify the authorization VC."
                    );
                }
            }
            println!();
            println!("Install via the provision-integration flow on the integration host.");
        }
        SealedPayloadV1::TemplateBootstrapV2(p) => {
            println!("Payload: TemplateBootstrapV2");
            println!("  Template:     {}", p.config.template_name);
            println!("  Kind:         {}", p.config.template_kind);
            println!("  Secrets for:  {} DID(s)", p.secrets.len());
            println!("  Outputs:      {}", p.config.outputs.len());
            // The reason this variant exists — say what each DID actually
            // holds, so an operator can see that the post-quantum key is there
            // before installing, rather than discovering it by its absence.
            for (did, material) in &p.secrets {
                println!("  {did}");
                println!(
                    "    {} (signing, {:?})",
                    material.signing_key.slot, material.signing_key.key_type
                );
                for extra in &material.additional_signing_keys {
                    println!("    {} (signing, {:?})", extra.slot, extra.key_type);
                }
                println!(
                    "    {} (key agreement, {:?})",
                    material.ka_key.slot, material.ka_key.key_type
                );
            }
            if let Some(ref u) = p.config.vta_url {
                println!("  VTA URL:      {u}");
            }
            println!();
            println!("Install via the provision-integration flow on the integration host.");
        }
        SealedPayloadV1::AdminRotation(p) => {
            println!("Payload: AdminRotation");
            println!("  Admin DID:    {}", p.admin.did);
            println!("  VTA DID:      {}", p.vta_trust.vta_did);
            if let Some(ref u) = p.vta_url {
                println!("  VTA URL:      {u}");
            }
            // VC verification for AdminRotation parallels the
            // TemplateBootstrap path but isn't yet plumbed through —
            // digest pinning remains the trust anchor for now.
            println!();
            println!(
                "  \x1b[1;33m⚠ VC verification not yet wired for AdminRotation — digest-only.\x1b[0m"
            );
            println!();
            println!("Install via the provision-integration flow on the integration host.");
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
            println!();
            println!(
                "Receive this credential into the holder vault via the credential-exchange flow."
            );
        }
        SealedPayloadV1::MessagingBridgeCredentials(b) => {
            println!("Payload: MessagingBridgeCredentials");
            println!("  Platform:   {}", b.platform);
            println!("  Fields:     {}", b.fields.len());
            println!();
            println!(
                "Load these platform secrets into the messaging-bridge connector's secret store."
            );
        }
        SealedPayloadV1::SeedMnemonic(m) => {
            println!("Payload: SeedMnemonic");
            if let Some(ref did) = m.vta_did {
                println!("  VTA DID: {did}");
            }
            println!();
            println!(
                "\x1b[1;33m⚠ This is the VTA's root seed. Write it down offline, then clear this \
                 terminal. It will not be shown again.\x1b[0m"
            );
            println!();
            println!("  {}", m.mnemonic);
        }
        // The secret and the credential are never printed.
        SealedPayloadV1::ExternalSecret(b) => {
            println!("Payload: ExternalSecret");
            println!("  Account: {}/{}", b.context, b.account);
            println!(
                "  Set it on the VTA with external/accounts/secret/set; it is not shown here."
            );
        }
        SealedPayloadV1::ExternalCredential(c) => {
            println!("Payload: ExternalCredential");
            println!("  Expires at: {}", c.expires_at());
        }
        // `SealedPayloadV1` is `#[non_exhaustive]`: a payload kind newer than
        // this `pnm` is opened but not described.
        _ => {
            println!("Payload: a kind this version of pnm does not describe");
        }
    }

    if let Some(path) = out {
        // Writing the credential out installs it for a file-based consumer, so
        // the bundle must be anchored first: the out-of-band digest, or a
        // signature by `--expect-vta-did` (see `verify_admin_bundle`). This
        // also rejects any payload variant that isn't an admin identity, with
        // a per-variant message. The seed survives a refusal here, so a
        // rejected bundle does not cost the operator a fresh request cycle.
        let bundle = vta_cli_common::sealed_consumer::verify_admin_bundle(
            opened,
            expect_digest.as_deref(),
            expect_vta_did.as_deref(),
        )?;
        write_credential_bundle(&path, &bundle)?;
        vta_cli_common::sealed_consumer::consume_request_secret(&secret);
        println!();
        println!("Credential written to {} (0600).", path.display());
    } else {
        println!();
        println!(
            "The request seed was kept at {} so the bundle can still be installed.",
            secret.display()
        );
    }

    Ok(())
}

/// Serialize a [`CredentialBundle`] to `path`, owner-readable only.
///
/// Field names come from the type's serde renames (`privateKeyMultibase`,
/// `vtaDid`, `vtaUrl`), so the output is exactly the shape file-based
/// consumers expect — e.g. the trust registry's `TR_VTA_CREDENTIAL`.
fn write_credential_bundle(
    path: &std::path::Path,
    bundle: &vta_sdk::credentials::CredentialBundle,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_vec_pretty(bundle)?;

    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    // Open at 0600 so the private key is never briefly world-readable
    // between create and chmod — same rationale as `write_secret` in
    // vta-cli-common's sealed_consumer.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(&json)?;
    file.write_all(b"\n")?;
    drop(file);

    if let Err(e) = vta_cli_common::secure_file::restrict_file_to_owner(path) {
        eprintln!(
            "warning: could not restrict {} to owner ({e}) — the private key may be \
             readable by other local users",
            path.display()
        );
    }
    Ok(())
}

// ── online flow (Mode B — TEE first-boot claim, wire version 2) ──────────

/// Resolve without the session helper's URL-guessing fallback. Bootstrap must
/// fail closed on an invalid WebVH log, not silently trust the DID's DNS host.
/// Use a local resolver so SCID/log verification happens on the operator's
/// machine rather than trusting a remote resolver's returned document.
async fn resolve_connect_url(
    vta_did: &str,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
) -> Result<String, Box<dyn std::error::Error>> {
    resolve_connect_url_with_policy(
        vta_did,
        resolver,
        vta_sdk::http::EndpointPolicy::process_default(),
    )
    .await
}

/// Deliberately ignores `PNM_RESOLVER_URL` / `[resolver_url]`, which every
/// other `DIDCacheClient` in PNM honours (see `main.rs`). The document
/// resolved here selects the endpoint that is handed the VTA's single-use
/// first-boot claim — a remote resolver returning a document of its choosing
/// would pick that endpoint on the operator's behalf, once, irreversibly.
/// Local mode verifies the SCID and the signed log chain on this machine
/// instead. The resolution error names the exception, because an operator
/// whose egress only reaches a resolver sidecar would otherwise be told to
/// wait for a DID log that is already published.
async fn resolve_connect_url_with_policy(
    vta_did: &str,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    policy: vta_sdk::http::EndpointPolicy,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = async {
        let resolved = resolver.resolve(vta_did).await?;
        let doc = serde_json::to_value(&resolved.doc)?;
        if doc["id"].as_str() != Some(vta_did) {
            return Err("resolved DID document does not match requested VTA DID".into());
        }
        vta_sdk::protocol::matching::ServiceCapabilities::from_did_document(&doc)
            .rest
            .ok_or_else(|| "VTA DID document does not advertise a REST endpoint".into())
    }
    .await
    .map_err(|e: Box<dyn std::error::Error>| {
        format!(
            "Could not resolve bootstrap endpoint for VTA DID {vta_did}: {e}. \
             Resolution is always local here — a configured PNM_RESOLVER_URL / \
             [resolver_url] is not used for bootstrap, so a reachable resolver \
             sidecar does not satisfy this. Retry once its DID log is published \
             and reachable from this machine, or explicitly use --vta-url <URL> \
             instead of --vta-did (without DID identity pinning)."
        )
    })?;
    // An authentic DID document can still advertise an unsafe destination. The
    // guard's own message carries the remedy (`--allow-private-endpoints` /
    // `VTA_ALLOW_PRIVATE_ENDPOINTS`); do NOT append a `--vta-url` suggestion
    // to it. That flag is not guarded, so offering it as the fix for a guard
    // failure teaches operators to route around the control instead of making
    // a decision about it.
    vta_sdk::http::guard_vta_endpoint(&url, policy).map_err(|e| {
        format!("VTA DID {vta_did} advertises a REST endpoint that is not safe to call: {e}")
    })?;
    Ok(url.trim_end_matches('/').to_string())
}

/// The connect anchor is the attested enclave image: the acknowledgement
/// carries no key, no bundle and so no digest to pin (#2066). `--expect-pcr0`
/// pins it; `--no-verify-pcr0` is the explicit, warned opt-out. PCR8 alone is
/// not an image pin.
///
/// Every pin is syntax-checked here, before any network I/O, because
/// `/bootstrap/request` closes `BOOTSTRAP_CARVEOUT_CLOSED_KEY` server-side
/// *before* it answers (`routes/bootstrap.rs`). A pin that is only rejected
/// later, at `VerifiedAttestation::check_pcrs`, is rejected after the VTA's
/// one-shot first boot has already been spent. Malformed in, nothing sent.
fn validate_connect_anchor(
    no_verify_pcr0: bool,
    expect_pcr0: Option<&str>,
    expect_pcr8: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(pcr0) = expect_pcr0 {
        vta_sdk::attestation::validate_expected_pcr(0, pcr0)?;
    }
    if let Some(pcr8) = expect_pcr8 {
        vta_sdk::attestation::validate_expected_pcr(8, pcr8)?;
    }
    match (expect_pcr0.is_some(), no_verify_pcr0) {
        (true, false) => Ok(()),
        (true, true) => Err("--expect-pcr0 and --no-verify-pcr0 are mutually exclusive".into()),
        (false, true) => {
            eprintln!(
                "WARNING: --no-verify-pcr0 — any genuine Nitro enclave image will be accepted. \
                 The acknowledgement has no other anchor: an enclave built from different code \
                 could answer this claim. Use only for testing."
            );
            Ok(())
        }
        (false, false) => Err(
            "connect requires --expect-pcr0 <hex>, or --no-verify-pcr0 (explicit opt-out with \
             a warning). The VTA's acknowledgement carries no key material and no digest; the \
             pinned enclave image measurement is what makes it trustworthy."
                .into(),
        ),
    }
}

/// For a VTA whose enclave predates claim wire version 2 (vta-service 0.63).
const OLDER_VTA_HINT: &str = "This VTA's enclave predates vta-service 0.63 and its first-boot \
     claim format, which this pnm no longer speaks. If its claim key was created with --slug, \
     claim it with pnm-cli 0.42; otherwise recreate the VTA on a newer enclave. The carve-out \
     is not spent.";

/// Largest bootstrap response read into memory: an acknowledgement plus an
/// attestation document, a few KiB in practice.
const MAX_BOOTSTRAP_RESPONSE_BYTES: usize = 1024 * 1024;

/// With `--vta-url` there is no DID to sign, so ask the VTA which DID a claim
/// on it names (`GET /bootstrap/request`).
///
/// Trusting the server's answer weakens nothing that `--vta-url` had not
/// already given up. The claim signature binds the DID, and a pinned enclave
/// image refuses a claim naming any DID but its own, so the acknowledgement of
/// a claim on this DID can only come from an enclave holding it: a host that
/// lies here gets a claim no genuine enclave accepts. What it cannot tell you
/// is *which* VTA you reached — that is what `--vta-did` pins.
async fn fetch_claim_vta_did(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("{base_url}/bootstrap/request");
    let resp = client.get(&url).send().await?;
    let status = resp.status();
    let bytes = vta_sdk::http::read_body_capped(resp, MAX_BOOTSTRAP_RESPONSE_BYTES)
        .await
        .map_err(|e| format!("bootstrap claim info ({status}): {e}"))?;
    if !status.is_success() {
        // A VTA before wire version 2 serves only the POST.
        let hint = match status {
            reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::METHOD_NOT_ALLOWED => {
                format!("\n{OLDER_VTA_HINT}")
            }
            _ => String::new(),
        };
        return Err(format!(
            "could not learn the VTA's DID from {url} ({status}): {}{hint}",
            String::from_utf8_lossy(&bytes)
        )
        .into());
    }
    let info: FirstBootClaimInfo = serde_json::from_slice(&bytes)?;
    if info.version != vta_sdk::tee_bootstrap::CLAIM_VERSION {
        return Err(format!(
            "the VTA speaks bootstrap claim version {}, this pnm speaks {}",
            info.version,
            vta_sdk::tee_bootstrap::CLAIM_VERSION
        )
        .into());
    }
    Ok(info.vta_did)
}

/// `pnm bootstrap connect (--vta-did <DID> | --vta-url <URL> --slug <SLUG>)
///   --claim-did <DID> (--expect-pcr0 <HEX> | --no-verify-pcr0) [--expect-pcr8 <HEX>]`
///
/// Online TEE first-boot bootstrap (#2066):
///
/// 1. Load the key of `--claim-did`, created by `pnm bootstrap claim-did
///    create`, from the OS keyring.
/// 2. Sign a claim on the VTA's DID with it and POST it to
///    `/bootstrap/request`. The VTA enrols the claim DID itself as an
///    expiring, hand-off-marked bootstrap admin — it mints no key for us
///    (VTI-CLT-002) — and answers with an attested acknowledgement, which is
///    checked against the claim and the pinned enclave image.
/// 3. Mint the long-term did:key here, persist it, and — authenticated as the
///    claim DID — exercise the hand-off onto it (VTI-CLT-017; see
///    [`hand_over_claim`]).
/// 4. Destroy the claim key (VTI-CLT-034).
///
/// A 403 at step 2 is the substitution signal (VTI-CLT-016). A 410 means the
/// carve-out is spent; if this machine's earlier run got as far as an
/// acknowledgement, the hand-over is resumed instead.
///
/// For non-TEE VTAs use `pnm setup` (temp did:key + admin grant via
/// `vta acl create` + auto-rotate on first authenticated connect).
#[allow(clippy::too_many_arguments)]
pub async fn run_connect(
    vta_did: Option<String>,
    vta_url: Option<String>,
    no_verify_pcr0: bool,
    expect_pcr0: Option<String>,
    expect_pcr8: Option<String>,
    claim_did: Option<String>,
    vta_slug: Option<String>,
    pnm_config: &mut crate::config::PnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_connect_anchor(
        no_verify_pcr0,
        expect_pcr0.as_deref(),
        expect_pcr8.as_deref(),
    )?;

    // Resolved before any network I/O: the slug only names the VTA locally.
    let slug = connect_slug(vta_slug, vta_did.as_deref())?;
    let claim = crate::bootstrap_claim::load_for_connect(claim_did.as_deref(), &slug)?;

    // The SDK client: finite timeouts, and no redirect off the VTA's origin.
    let client = vta_sdk::http::rest_client();
    let (base_url, target_vta_did) = match (vta_did, vta_url) {
        (Some(did), None) => {
            let resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
                vta_sdk::resolver::build_did_cache_config(None),
            )
            .await?;
            (resolve_connect_url(&did, &resolver).await?, did)
        }
        (None, Some(url)) => {
            let url = url.trim_end_matches('/').to_string();
            let did = fetch_claim_vta_did(&client, &url).await?;
            eprintln!(
                "The VTA at {url} names itself {did}. --vta-url does not pin which VTA this is; \
                 the claim is bound to that DID, so only an enclave holding it can accept."
            );
            (url, did)
        }
        _ => return Err("provide exactly one of --vta-did or --vta-url".into()),
    };

    let nonce: [u8; 16] = rand::random();
    // The claim is checked locally too: the typed claim is what the
    // acknowledgement is verified against.
    let signed = FirstBootClaim::new_signed(&claim.seed, &target_vta_did, nonce, None);
    let verified_claim = signed.verify()?;

    let url = format!("{base_url}/bootstrap/request");
    let resp = client.post(&url).json(&signed).send().await?;
    let status = resp.status();
    // Capture the headers before the body consumes the response: a 429 from the
    // VTA's unauth limiter carries `x-rate-limit-source` / `retry-after`, which
    // `rate_limited_from_http` reads to attribute the refusal.
    let headers = resp.headers().clone();
    let bytes = vta_sdk::http::read_body_capped(resp, MAX_BOOTSTRAP_RESPONSE_BYTES)
        .await
        .map_err(|e| format!("bootstrap request ({status}): {e}"))?;
    if !status.is_success() {
        let body = String::from_utf8_lossy(&bytes);
        // A rate limit must stay typed, or its message reads as a bootstrap
        // failure and sends the operator to check the enclave. The limiter runs
        // *before* the carve-out is touched, so the one-shot first boot is not
        // spent — retrying after the wait is safe.
        if let Some(rl) =
            vta_sdk::error::VtaError::rate_limited_from_http(status, &headers, &body, &url)
        {
            eprintln!(
                "The rate limit rejected this request before the enclave did anything, \
                 so the one-time bootstrap is not spent — retry after the wait."
            );
            return Err(rl.into());
        }
        if status == reqwest::StatusCode::GONE {
            // An earlier run of this command reached the acknowledgement and
            // was interrupted before the hand-over finished: resume it. Only
            // when that run recorded an *attested* acknowledgement for this
            // slug and VTA — an unauthenticated 410 could come from anyone,
            // so it never discards the claim key on its own.
            if pending_hand_over(pnm_config, &slug, &target_vta_did) {
                eprintln!(
                    "The claim on {target_vta_did} was already accepted by an earlier run; \
                     resuming the hand-over."
                );
                return finish_connect(&slug, &claim, &target_vta_did, &base_url).await;
            }
            eprintln!(
                "This VTA's first-boot claim is already used. If its claim DID is no longer \
                 needed, remove it with: pnm bootstrap claim-did discard {}",
                claim.discard_arg()
            );
        }
        // VTI-CLT-016: an enrolled bootstrap identity that is refused is the
        // signal that the registration was substituted, not a transport fault.
        if status == reqwest::StatusCode::FORBIDDEN {
            eprintln!(
                "The VTA refused this claim before enrolling anything. Check that the DID it was \
                 created with is this claim DID:\n  {}\n\
                 and that {target_vta_did} is the VTA you meant to claim.\n\
                 If both are right and the VTA still refuses, the VTA is not configured with \
                 your claim DID — someone else may hold its first admin. Do not trust this VTA; \
                 recreate it.",
                claim.did
            );
        }
        // A VTA before wire version 2 cannot parse a v2 claim at all.
        if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
            eprintln!("{OLDER_VTA_HINT}");
        }
        if status == reqwest::StatusCode::BAD_REQUEST && body.contains("version") {
            eprintln!(
                "The VTA and this pnm speak different first-boot claim versions. Wire version 2 \
                 (#2066) is a clean break: upgrade whichever side is older. The carve-out is \
                 not spent."
            );
        }
        return Err(format!("bootstrap request failed ({status}): {body}").into());
    }
    let ack: FirstBootAck = serde_json::from_slice(&bytes)?;

    // The quote binds the did:key-visible bytes end-to-end —
    // SHA256(client_ed25519 || nonce || producer_ed25519) — and the ack must
    // acknowledge *this* claim: same claim DID, same signed VTA DID.
    let verified = ack.verify(&verified_claim)?;
    // Client-side PCR pinning (P3.4): refuse a genuine-but-WRONG enclave image
    // / signing cert.
    let attest = verified.attestation();
    attest
        .check_pcrs(expect_pcr0.as_deref(), expect_pcr8.as_deref())
        .map_err(|e| {
            format!(
                "{e}. The attestation is cryptographically valid but the enclave does not \
                 match the pinned measurement — refusing to bootstrap. Confirm the expected \
                 PCR against the deployed EIF / KMS key policy. The claim DID is enrolled on \
                 that enclave; do not use it."
            )
        })?;
    println!("TEE attestation verified.");
    println!("  Enclave module: {}", attest.module_id);
    if !attest.pcr0_hex.is_empty() {
        let pinned = if expect_pcr0.is_some() {
            " (pinned ✓)"
        } else {
            ""
        };
        println!("  PCR0:           {}{pinned}", attest.pcr0_hex);
    }
    if !attest.pcr8_hex.is_empty() {
        let pinned = if expect_pcr8.is_some() {
            " (pinned ✓)"
        } else {
            ""
        };
        println!("  PCR8:           {}{pinned}", attest.pcr8_hex);
    }
    println!(
        "  Bootstrap admin: {} (valid until {} unless handed over)",
        verified.ack().admin_did,
        format_epoch(verified.ack().expires_at)
    );

    // Recorded before the hand-over, so an interrupted run can resume it: the
    // VTA is registered only once a genuine, pinned enclave has acknowledged
    // this claim on this DID.
    pnm_config.vtas.insert(
        slug.clone(),
        crate::config::VtaConfig {
            name: slug.clone(),
            vta_did: Some(target_vta_did.clone()),
            url: None,
            mediator_did: None,
        },
    );
    if pnm_config.default_vta.is_none() {
        pnm_config.default_vta = Some(slug.clone());
    }
    crate::config::save_config(pnm_config)?;

    finish_connect(&slug, &claim, &target_vta_did, &base_url).await
}

/// The hand-over and the summary — shared by a fresh connect and a resumed one.
async fn finish_connect(
    slug: &str,
    claim: &crate::bootstrap_claim::ClaimKey,
    vta_did: &str,
    base_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let admin_did = hand_over_claim(slug, claim, vta_did, base_url).await?;
    println!();
    println!("Bootstrap complete.");
    println!("  VTA slug:   {slug}");
    println!("  Admin DID:  {admin_did}");
    println!("  VTA DID:    {vta_did}");
    Ok(())
}

/// Whether this slug holds an acknowledged-but-unfinished claim on `vta_did`:
/// the config registered it (which happens only after a verified, pinned
/// acknowledgement) and the claim key, which a finished hand-over destroys,
/// is still here (the caller loaded it).
fn pending_hand_over(pnm_config: &crate::config::PnmConfig, slug: &str, vta_did: &str) -> bool {
    pnm_config.vtas.get(slug).and_then(|v| v.vta_did.as_deref()) == Some(vta_did)
}

/// Hand the claim DID's bootstrap entry over to a long-term did:key minted
/// here, then destroy the claim key. Returns the long-term DID.
///
/// Ordering (VTI-CLT-033 – VTI-CLT-035):
///
/// 1. **Mint and persist** the long-term key as this slug's session *before*
///    anything is committed. If a previous run already staged one for this
///    VTA, reuse it — it may be the DID a lost-response commit already
///    enrolled. Persisting first closes the window VTI-CLT-033 is about: at
///    the commit the replacement key is already durable.
/// 2. **Commit**: authenticated as the claim DID, `acl/grant` with the
///    hand-off rollover (VTI-ACL-054 – VTI-ACL-057). Not `acl/swap-key`: a
///    rotation preserves expiry exactly (VTI-CLT-029), so rotating off the
///    expiring bootstrap entry would leave the VTA's only administrator
///    expiring with it. The rollover writes the successor bounded by the
///    first-boot authority instead — a permanent unrestricted admin.
/// 3. **Confirm** by authenticating as the long-term DID. This, not the
///    grant's answer, is the evidence: a retried grant after a lost response
///    is refused (the claim DID no longer has an entry) although the commit
///    happened.
/// 4. **Destroy** the claim key (VTI-CLT-034).
async fn hand_over_claim(
    slug: &str,
    claim: &crate::bootstrap_claim::ClaimKey,
    vta_did: &str,
    base_url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let keyring_key = crate::config::vta_keyring_key(slug);

    // 1. Stage the long-term key.
    let staged = auth::loaded_session(&keyring_key)
        .filter(|s| s.vta_did.as_deref() == Some(vta_did) && s.client_did != claim.did);
    let admin_did = match staged {
        Some(s) => s.client_did,
        None => {
            let (did, private_key_multibase) =
                vta_cli_common::local_keygen::generate_unbound_admin_did_key();
            auth::store_session(&keyring_key, &did, &private_key_multibase, vta_did)?;
            did
        }
    };

    // 2. Commit, as the claim DID.
    let committed = async {
        let token = vta_sdk::session::challenge_response(
            base_url,
            &claim.did,
            &claim.private_key_multibase,
            vta_did,
        )
        .await?;
        let client = vta_sdk::client::VtaClient::authenticated(
            base_url,
            vta_sdk::client::ClientIdentity {
                client_did: claim.did.clone(),
                private_key_multibase: claim.private_key_multibase.to_string(),
                vta_did: vta_did.to_string(),
                verification_method: None,
            },
            token.access_token,
        )
        .await;
        client
            .roll_over_handoff(
                &admin_did,
                "admin",
                Vec::new(),
                Some("TEE first-boot admin".to_string()),
            )
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    // 3. Confirm as the long-term DID, whatever the commit reported.
    match auth::ensure_authenticated(base_url, &keyring_key).await {
        Ok(_) => {}
        Err(confirm) => {
            let cause = match committed {
                Err(e) => e.to_string(),
                Ok(()) => confirm.to_string(),
            };
            return Err(format!(
                "the VTA enrolled the claim DID, but handing its entry over to the long-term \
                 DID {admin_did} did not complete: {cause}\n\n\
                 The claim key is kept. Re-run the same `pnm bootstrap connect` command before \
                 the bootstrap entry expires to resume the hand-over."
            )
            .into());
        }
    }

    // 4. The claim DID has no standing left; its key goes (VTI-CLT-034).
    crate::bootstrap_claim::discard_after_claim(claim);
    Ok(admin_did)
}

/// Epoch seconds as RFC 3339, for messages.
fn format_epoch(epoch: u64) -> String {
    chrono::DateTime::from_timestamp(epoch as i64, 0)
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| epoch.to_string())
}

/// `pnm bootstrap provision-integration` — bridge a VP-framed
/// BootstrapRequest to the VTA over whichever transport the client
/// is currently using (REST or DIDComm), writing the returned
/// armored bundle to disk.
///
/// The VTA runs the same shared library fn for every transport and
/// the offline `vta bootstrap provision-integration` CLI.
/// `VtaClient::provision_integration` sends the signed
/// `provision/integration/0.3` Trust Task over whichever transport the
/// open session holds (TSP, DIDComm, or HTTPS on `/trust-tasks`). The
/// relayer (this session) and the VP holder may differ: the bundle is
/// sealed to the holder, so the relayer cannot open it.
#[allow(clippy::too_many_arguments)]
pub async fn run_provision_integration(
    client: &vta_sdk::client::VtaClient,
    request: PathBuf,
    context: Option<String>,
    assertion: String,
    vc_validity_seconds: Option<i64>,
    out: PathBuf,
    create_context: bool,
    admin_scope: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use vta_sdk::provision_integration::http::{
        AdminScope, AssertionMode as WireAssertionMode, ProvisionIntegrationRequest,
    };

    // 1. Parse the integration's VP (but don't verify locally — the
    //    server does the authoritative verification).
    //
    //    Two views of the same document, deliberately. `vp_raw` is what
    //    goes on the wire: this VP was signed by the integration, not by
    //    us, so relaying the typed struct would re-render it in the SDK's
    //    casing and the maintainer would verify bytes the holder never
    //    signed. `vp` is a local read-only view, used only to resolve the
    //    context hint below.
    let request_json =
        fs::read_to_string(&request).map_err(|e| format!("read {}: {e}", request.display()))?;
    let vp_raw: serde_json::Value = serde_json::from_str(&request_json)
        .map_err(|e| format!("parse BootstrapRequest (VP): {e}"))?;
    let vp: vta_sdk::provision_integration::BootstrapRequest =
        serde_json::from_value(vp_raw.clone())
            .map_err(|e| format!("parse BootstrapRequest (VP): {e}"))?;

    // 2. Resolve context: explicit > hint > fail. If both present they
    //    must agree.
    let target_context = resolve_target_context_wire(&vp, context)?;

    // 3. Map assertion flag.
    let assertion_mode = match assertion.as_str() {
        "did-signed" | "didsigned" | "did_signed" => WireAssertionMode::DidSigned,
        "pinned-only" | "pinnedonly" | "pinned_only" | "pinned" => WireAssertionMode::PinnedOnly,
        other => {
            return Err(format!(
                "invalid --assertion value '{other}' — use 'did-signed' or 'pinned-only'"
            )
            .into());
        }
    };

    // 3b. Map the admin-scope flag. Clap's `value_parser` already rejects
    //     anything outside the pair, so the fallthrough is a wiring bug rather
    //     than operator input — say so instead of inventing a default, which
    //     would silently narrow a grant someone asked to widen.
    let admin_scope = match admin_scope.as_str() {
        "context" => AdminScope::Context,
        "unrestricted" => AdminScope::Unrestricted,
        other => {
            return Err(format!(
                "invalid --admin-scope value '{other}' — use 'context' or 'unrestricted'"
            )
            .into());
        }
    };

    // 4. Submit.
    let resp = client
        .provision_integration(ProvisionIntegrationRequest {
            request: vp_raw,
            // `--context` is required on the pnm-cli surface today, so
            // we always pass a concrete value. The wire field is
            // `Option<String>` per the canonical spec; future flag
            // changes can pass `None` to opt into VTA-side inference.
            context: Some(target_context.clone()),
            assertion: Some(assertion_mode),
            vc_validity_seconds,
            create_context,
            admin_scope,
        })
        .await?;

    // 5. Write bundle + print summary.
    fs::write(&out, resp.bundle.as_bytes()).map_err(|e| format!("write {}: {e}", out.display()))?;

    eprintln!(
        "Integration provisioned via {} — sealed bundle written to {}",
        client.endpoint_label(),
        out.display()
    );
    eprintln!();
    eprintln!("  Bundle-Id:       {}", resp.summary.bundle_id_hex);
    if resp.summary.context_created {
        eprintln!("  Context:         {target_context} (created inline via --create-context)");
    } else if create_context {
        eprintln!(
            "  Context:         {target_context} (already existed; --create-context was a no-op)"
        );
    } else {
        eprintln!("  Context:         {target_context}");
    }
    eprintln!("  Client DID:      {}", resp.summary.client_did);
    if resp.summary.admin_rolled_over {
        eprintln!(
            "  Admin DID:       {} (VTA-minted, rolled over from client)",
            resp.summary.admin_did
        );
        if let Some(ref admin_tpl) = resp.summary.admin_template_name {
            eprintln!("  Admin template:  {admin_tpl}");
        }
    } else {
        eprintln!("  Admin DID:       {} (== client)", resp.summary.admin_did);
    }
    if let Some(ref integration_did) = resp.summary.integration_did {
        eprintln!("  Integration DID: {integration_did}");
    } else {
        eprintln!("  Integration DID: (none — admin-rotation only)");
    }
    if let (Some(name), Some(kind)) = (
        resp.summary.template_name.as_deref(),
        resp.summary.template_kind.as_deref(),
    ) {
        eprintln!("  Template:        {name} ({kind})");
    }
    eprintln!("  Secrets:         {}", resp.summary.secret_count);
    eprintln!("  Outputs:         {}", resp.summary.output_count);
    // Printed as hex, because that is what `--expect-digest` takes and what an
    // operator reads out loud. The wire carries a multibase multihash as of
    // `provision/integration/0.3`; the two are the same digest in two
    // encodings, and the human-facing one should not change under an operator
    // mid-migration.
    let digest_hex = resp
        .digest_multibase
        .as_deref()
        .map(vta_sdk::sealed_transfer::multibase_digest_to_hex)
        .transpose()
        .unwrap_or(None);
    match digest_hex {
        Some(hex) => {
            eprintln!("  SHA-256 digest:  {hex}");
            eprintln!();
            eprintln!(
                "Communicate the digest to the integration's operator out-of-band so they can\n  \
                 verify the bundle on first boot:\n  \
                 pnm bootstrap open --bundle <file> --expect-digest {hex}",
            );
        }
        // The member is OPTIONAL from 0.3 on. Say so rather than print an empty
        // line an operator might read as a digest of nothing.
        None => {
            eprintln!("  SHA-256 digest:  (not supplied by this VTA)");
            eprintln!();
        }
    }
    Ok(())
}

fn resolve_target_context_wire(
    request: &vta_sdk::provision_integration::BootstrapRequest,
    explicit: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    use vta_sdk::provision_integration::BootstrapAsk;
    let hint = match &request.ask {
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

/// `--slug`, else the VTA DID's tail. `--vta-url` has no DID to derive from.
fn connect_slug(
    explicit: Option<String>,
    vta_did: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    match (explicit, vta_did) {
        (Some(slug), _) => Ok(slug),
        (None, Some(did)) => Ok(default_slug(did)),
        (None, None) => {
            Err("--slug is required with --vta-url: it names the VTA in pnm config".into())
        }
    }
}

fn default_slug(vta_did: &str) -> String {
    vta_did.rsplit(':').next().unwrap_or("vta").to_string()
}

#[cfg(test)]
mod tests {
    use super::parse_var;
    use serde_json::Value;

    const CLAIM_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const VTA_DID: &str =
        "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.example.com";

    async fn fixture_resolver(doc: Value) -> affinidi_did_resolver_cache_sdk::DIDCacheClient {
        let mut resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
            vta_sdk::resolver::build_did_cache_config(None),
        )
        .await
        .unwrap();
        // These fixtures exercise endpoint selection, not log verification.
        resolver
            .add_did_document(VTA_DID, serde_json::from_value(doc).unwrap())
            .await;
        resolver
    }

    #[tokio::test]
    async fn connect_resolves_advertised_rest_host_port_and_path() {
        let resolver = fixture_resolver(serde_json::json!({
            "id": VTA_DID,
            "service": [
                {"id": format!("{VTA_DID}#tsp"), "type": "TSPTransport", "serviceEndpoint": "did:example:mediator"},
                {"id": format!("{VTA_DID}#custom-rest"), "type": "VTARest", "serviceEndpoint": "https://api.example.com:8443/vta/"}
            ]
        })).await;
        assert_eq!(
            super::resolve_connect_url(VTA_DID, &resolver)
                .await
                .unwrap(),
            "https://api.example.com:8443/vta"
        );
    }

    #[tokio::test]
    async fn connect_guards_did_advertised_rest_endpoints() {
        use vta_sdk::http::EndpointPolicy;

        for (url, public_allowed, private_allowed) in [
            ("https://api.example.com:8443/vta/", true, true),
            ("http://localhost:8100/vta/", true, true),
            ("http://127.0.0.1:8100/", true, true),
            ("http://[::1]:8100/", true, true),
            ("http://api.example.com/", false, false),
            ("http://10.0.0.5/", false, false),
            ("https://169.254.169.254/latest/meta-data/", false, false),
            ("https://[fe80::1]/", false, false),
            ("https://[fd00:ec2::254]/", false, false),
            ("https://metadata.google.internal/", false, false),
            (
                "https://operator:fixture-secret@api.example.com/",
                false,
                false,
            ),
            ("https://[::ffff:10.0.0.5]/", false, false),
            ("https://[::ffff:169.254.169.254]/", false, false),
            ("https://0.0.0.0/", false, false),
            ("https://192.0.2.1/", false, false),
            ("https://10.0.0.5:8443/vta/", false, true),
            ("https://192.168.1.10/", false, true),
            ("https://[fd00::1]/", false, true),
            ("https://100.64.0.1/", false, true),
            ("https://vta.internal/", false, true),
            ("file:///tmp/vta", false, false),
        ] {
            let resolver = fixture_resolver(serde_json::json!({
                "id": VTA_DID,
                "service": [{
                    "id": format!("{VTA_DID}#custom-rest"),
                    "type": "VTARest",
                    "serviceEndpoint": url,
                }],
            }))
            .await;
            for (policy, allowed) in [
                (EndpointPolicy::public_only(), public_allowed),
                (EndpointPolicy::private_allowed(), private_allowed),
            ] {
                let result =
                    super::resolve_connect_url_with_policy(VTA_DID, &resolver, policy).await;
                if allowed {
                    assert_eq!(result.unwrap(), url.trim_end_matches('/'));
                } else {
                    let error = result
                        .expect_err("unsafe DID endpoint must not fall back to its host")
                        .to_string();
                    assert!(error.contains(VTA_DID), "{error}");
                    assert!(!error.contains("fixture-secret"), "{error}");
                    // A guard rejection must not advertise --vta-url as its
                    // remedy: that flag skips this guard entirely, so
                    // suggesting it here would teach operators to route
                    // around the control rather than decide about it.
                    assert!(!error.contains("--vta-url"), "{error}");
                    if private_allowed {
                        assert!(error.contains("VTA_ALLOW_PRIVATE_ENDPOINTS"), "{error}");
                        assert!(error.contains("--allow-private-endpoints"), "{error}");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn connect_refuses_missing_rest_or_wrong_document_instead_of_guessing_url() {
        for doc in [
            serde_json::json!({"id": VTA_DID}),
            serde_json::json!({"id": "did:web:other.example.com", "service": [
                {"id": "did:web:other.example.com#rest", "type": "VTARest", "serviceEndpoint": "https://api.example.com"}
            ]}),
        ] {
            let resolver = fixture_resolver(doc).await;
            let error = super::resolve_connect_url(VTA_DID, &resolver)
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains(VTA_DID));
            // Bootstrap resolution is local-only by design; say so, or an
            // operator whose egress reaches only a resolver sidecar reads
            // this as "the DID log is not published yet".
            assert!(error.contains("PNM_RESOLVER_URL"), "{error}");
            assert!(error.contains("--vta-url"));
        }
    }

    #[tokio::test]
    async fn connect_resolution_failure_names_did_and_explicit_fallback() {
        let resolver = fixture_resolver(serde_json::json!({"id": VTA_DID})).await;
        let did = "did:unsupported:bootstrap-target";
        let error = super::resolve_connect_url(did, &resolver)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(did));
        assert!(error.contains("--vta-url"));
    }

    #[test]
    fn connect_slug_needs_a_source() {
        assert_eq!(
            super::connect_slug(Some("acme".into()), Some(VTA_DID)).unwrap(),
            "acme"
        );
        assert_eq!(
            super::connect_slug(None, Some(VTA_DID)).unwrap(),
            "identity.example.com"
        );
        let error = super::connect_slug(None, None).unwrap_err().to_string();
        assert!(error.contains("--slug"), "{error}");
    }

    #[test]
    fn connect_anchor_flag_matrix() {
        let valid = "ab12".repeat(24);
        for opt_out in [false, true] {
            for pcr0 in [None, Some(valid.as_str())] {
                // PCR8 is an additional pin, never an anchor on its own:
                // it measures the signing certificate, not the image.
                for pcr8 in [None, Some(valid.as_str())] {
                    let expected = pcr0.is_some() != opt_out;
                    assert_eq!(
                        super::validate_connect_anchor(opt_out, pcr0, pcr8).is_ok(),
                        expected,
                        "opt_out={opt_out}, pcr0={pcr0:?}, pcr8={pcr8:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn connect_accepts_valid_normalized_pcr0_as_sole_anchor() {
        let pcr0 = "ab12".repeat(24);
        for value in [
            pcr0.clone(),
            pcr0.to_uppercase(),
            format!("0x{pcr0}"),
            format!(" \t0X{}\n ", "AB12 \t".repeat(24)),
        ] {
            super::validate_connect_anchor(false, Some(&value), None).unwrap();
            super::validate_connect_anchor(false, Some(&value), Some(&value)).unwrap();
        }
    }

    /// Both pins, not just PCR0. `/bootstrap/request` closes the first-boot
    /// carve-out server-side before it answers, so a pin rejected
    /// only at `check_pcrs` — after the POST — is rejected once the VTA's
    /// one-shot bootstrap has already been spent. A typo'd `--expect-pcr8`
    /// must therefore fail here, with nothing sent.
    #[tokio::test]
    async fn connect_rejects_malformed_pcrs_before_resolving_or_posting() {
        let valid = "ab12".repeat(24);
        for value in [
            "".to_string(),
            " ".to_string(),
            "0x".to_string(),
            " \t0X\n".to_string(),
            "abcd".to_string(),
            "a".repeat(95),
            "a".repeat(97),
            format!("{}g", "a".repeat(95)),
        ] {
            // `which` names the malformed pin; the other is well-formed, so a
            // failure can only come from the one under test.
            for (which, pcr0, pcr8) in [
                (0u8, Some(value.clone()), None),
                (0, Some(value.clone()), Some(valid.clone())),
                (8, Some(valid.clone()), Some(value.clone())),
                // A malformed PCR8 alongside another valid anchor still fails:
                // the pin is checked, not merely consulted when it is load-bearing.
                (8, None, Some(value.clone())),
            ] {
                for opt_out in [false, true] {
                    for by_did in [true, false] {
                        let mut config = crate::config::PnmConfig::default();
                        // Invalid targets fail differently if preflight is skipped.
                        // Neither target can contact an external service in a regression.
                        let error = super::run_connect(
                            by_did.then(|| "did:unsupported:bootstrap-target".into()),
                            (!by_did).then(|| "not-a-url".into()),
                            opt_out,
                            pcr0.clone(),
                            pcr8.clone(),
                            Some(CLAIM_DID.into()),
                            None,
                            &mut config,
                        )
                        .await
                        .unwrap_err();
                        assert!(
                            matches!(
                                error.downcast_ref::<vta_sdk::attestation::ConfigAttestationVerifyError>(),
                                Some(vta_sdk::attestation::ConfigAttestationVerifyError::InvalidExpectedPcr { which: actual, .. })
                                    if *actual == which
                            ),
                            "which={which}, value={value:?}, error={error}"
                        );
                        assert!(config.vtas.is_empty());
                        assert!(config.default_vta.is_none());
                    }
                }
            }
        }
    }

    /// A claim DID that is not an Ed25519 `did:key` (a pasted private key, a
    /// typo) is refused with nothing resolved, sent or registered.
    #[tokio::test]
    async fn connect_rejects_malformed_claim_did_before_resolving_or_posting() {
        let pcr0 = "ab12".repeat(24);
        for bad in [
            "",
            "did:web:example.com",
            "z3u2en7t5LR2WtQH5PfsRMFLNBXLXmkDTqQr4nvXcrJ8e",
        ] {
            let mut config = crate::config::PnmConfig::default();
            let error = super::run_connect(
                Some("did:unsupported:bootstrap-target".into()),
                None,
                false,
                Some(pcr0.clone()),
                None,
                Some(bad.into()),
                None,
                &mut config,
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(error.contains("Ed25519 did:key"), "{bad}: {error}");
            assert!(config.vtas.is_empty());
            assert!(config.default_vta.is_none());
        }
    }

    #[test]
    fn connect_missing_anchor_explains_all_routes() {
        // PCR8 alone leaves the image unpinned, so it must land on the same
        // error rather than reading as a satisfied anchor.
        for pcr8 in [None, Some("ab12".repeat(24))] {
            let error = super::validate_connect_anchor(false, None, pcr8.as_deref())
                .unwrap_err()
                .to_string();
            for route in ["--expect-pcr0", "--no-verify-pcr0"] {
                assert!(error.contains(route), "{error}");
            }
            assert!(error.contains("no key material"), "{error}");
        }
    }

    /// A resume is offered only for a VTA this slug registered — which pnm
    /// does only after a verified, pinned acknowledgement.
    #[test]
    fn hand_over_resumes_only_an_acknowledged_claim() {
        let mut config = crate::config::PnmConfig::default();
        assert!(!super::pending_hand_over(&config, "acme", VTA_DID));
        config.vtas.insert(
            "acme".into(),
            crate::config::VtaConfig {
                name: "acme".into(),
                vta_did: Some(VTA_DID.into()),
                url: None,
                mediator_did: None,
            },
        );
        assert!(super::pending_hand_over(&config, "acme", VTA_DID));
        assert!(!super::pending_hand_over(
            &config,
            "acme",
            "did:web:other.example.com"
        ));
        assert!(!super::pending_hand_over(&config, "other", VTA_DID));
    }

    #[test]
    fn parse_var_plain_string() {
        let (k, v) = parse_var("URL=https://mediator.example.com").unwrap();
        assert_eq!(k, "URL");
        assert_eq!(v, Value::String("https://mediator.example.com".into()));
    }

    #[test]
    fn parse_var_json_types_round_trip() {
        assert_eq!(parse_var("N=42").unwrap().1, Value::Number(42.into()));
        assert_eq!(parse_var("B=true").unwrap().1, Value::Bool(true));
        assert!(parse_var(r#"A=[1,2]"#).unwrap().1.is_array());
    }

    #[test]
    fn parse_var_value_may_contain_equals() {
        let (_, v) = parse_var("URL=https://m.example.com?x=1").unwrap();
        assert_eq!(v.as_str(), Some("https://m.example.com?x=1"));
    }

    #[test]
    fn parse_var_missing_equals_errors() {
        assert!(parse_var("LONELY").is_err());
    }

    #[test]
    fn parse_var_empty_key_errors() {
        assert!(parse_var("=value").is_err());
    }

    fn scratch_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("pnm-open-out-{name}-{}.json", std::process::id()));
        p
    }

    fn sample_bundle() -> vta_sdk::credentials::CredentialBundle {
        vta_sdk::credentials::CredentialBundle {
            did: "did:key:z6MkTest".into(),
            private_key_multibase: "z3SecretTest".into(),
            vta_did: "did:webvh:QmTest:vta.example.com:vta".into(),
            vta_url: Some("https://vta.example.com".into()),
        }
    }

    /// The on-disk field names are the contract with file-based consumers
    /// (the trust registry's `TR_VTA_CREDENTIAL` parses exactly these), so
    /// assert the serde renames rather than the Rust field names.
    #[test]
    fn written_credential_uses_wire_field_names() {
        let path = scratch_path("fields");
        super::write_credential_bundle(&path, &sample_bundle()).unwrap();

        let v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(v["did"], "did:key:z6MkTest");
        assert_eq!(v["privateKeyMultibase"], "z3SecretTest");
        assert_eq!(v["vtaDid"], "did:webvh:QmTest:vta.example.com:vta");
        assert_eq!(v["vtaUrl"], "https://vta.example.com");

        std::fs::remove_file(&path).ok();
    }

    /// `vtaUrl` is `skip_serializing_if = "Option::is_none"`, so an absent
    /// URL must omit the key entirely rather than emit `null` — the
    /// registry's loader treats an explicit null as a parse error.
    #[test]
    fn written_credential_omits_absent_vta_url() {
        let path = scratch_path("nourl");
        let mut bundle = sample_bundle();
        bundle.vta_url = None;
        super::write_credential_bundle(&path, &bundle).unwrap();

        let v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(v.get("vtaUrl").is_none());

        std::fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn written_credential_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let path = scratch_path("perms");
        super::write_credential_bundle(&path, &sample_bundle()).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "credential file must not be group/world readable"
        );

        std::fs::remove_file(&path).ok();
    }

    /// Writing must overwrite, not append — re-running against an existing
    /// path would otherwise produce trailing garbage after valid JSON.
    #[cfg(unix)]
    #[test]
    fn written_credential_truncates_existing_file() {
        let path = scratch_path("truncate");
        std::fs::write(&path, vec![b'x'; 4096]).unwrap();
        super::write_credential_bundle(&path, &sample_bundle()).unwrap();

        // Parses cleanly => no leftover bytes from the longer previous file.
        let v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(v["did"], "did:key:z6MkTest");

        std::fs::remove_file(&path).ok();
    }
}
