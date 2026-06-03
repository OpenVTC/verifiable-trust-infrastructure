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
//! `--expect-digest <hex>` is required by default. `--no-verify-digest` is
//! available but prints a warning — there is no silent TOFU.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use vta_sdk::attestation::verify_nitro_assertion;
use vta_sdk::sealed_transfer::{
    BootstrapRequest, SealedPayloadV1, armor, bundle_digest, ed25519_seed_to_x25519_secret,
    generate_ed25519_keypair, open_bundle,
};

use crate::auth;
use crate::config;

use vta_sdk::hex::lower as hex_lower;

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
    expect_digest: Option<String>,
    no_verify_digest: bool,
    expect_vta_did: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = config::config_dir()?;
    let opened = vta_cli_common::sealed_consumer::open_armored_bundle(
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
            println!();
            println!("To install this credential, use the online bootstrap flow:");
            println!("  pnm bootstrap connect --vta-url <url> [--expect-digest <sha256>]");
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
    }

    Ok(())
}

// ── online flow (Mode B — TEE first-boot attestation) ──────────────────

#[derive(Debug, Deserialize)]
struct BootstrapResponseWire {
    bundle: String,
    digest: String,
}

/// `pnm bootstrap connect --vta-url <URL> [--expect-digest <HEX>]`
///
/// Online TEE first-boot bootstrap. Generates an ephemeral Ed25519 keypair,
/// POSTs the `did:key` as `client_did` to `/bootstrap/request`, verifies
/// the attestation quote, installs the minted admin credential, and
/// registers the VTA under a slug in `pnm` config. Only the first successful
/// call against a fresh TEE VTA succeeds — the carve-out closes on success.
///
/// For non-TEE VTAs use `pnm setup` (temp did:key + admin grant via
/// `vta acl create` + auto-rotate on first authenticated connect).
pub async fn run_connect(
    vta_url: String,
    expect_digest: Option<String>,
    no_verify_digest: bool,
    vta_slug: Option<String>,
    pnm_config: &mut crate::config::PnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    // Digest pinning is mandatory at the CLI; --no-verify-digest is the only
    // explicit opt-out and prints a warning. There is no silent TOFU.
    vta_cli_common::sealed_consumer::validate_digest_flags(
        expect_digest.as_deref(),
        no_verify_digest,
    )?;

    let (ed_seed, ed_pub) = generate_ed25519_keypair();
    let nonce: [u8; 16] = rand::random();
    let bundle_id_hex = hex_lower(&nonce);

    // Reuse the SDK's canonical wire type so pnm speaks the same shape the
    // server `BootstrapRequestBody` deserializes. Emits `client_did` as a
    // `did:key:z6Mk…` string.
    let body = BootstrapRequest::new(ed_pub, nonce, None);

    let url = format!("{}/bootstrap/request", vta_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client.post(&url).json(&body).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("bootstrap request failed ({status}): {body}").into());
    }
    let wire: BootstrapResponseWire = resp.json().await?;

    // Optional client-side digest verification. Attestation + TLS give the
    // primary integrity anchor; this is a belt-and-suspenders check the
    // operator can opt into by communicating the digest out-of-band.
    if let Some(expected) = &expect_digest
        && !expected.eq_ignore_ascii_case(&wire.digest)
    {
        return Err(format!(
            "server-reported digest {} does not match expected {}",
            wire.digest, expected
        )
        .into());
    }

    let bundles = armor::decode(&wire.bundle)?;
    if bundles.len() != 1 {
        return Err(format!(
            "expected exactly one armored bundle from server, got {}",
            bundles.len()
        )
        .into());
    }
    let bundle = &bundles[0];
    if hex_lower(&bundle.bundle_id) != bundle_id_hex {
        return Err("server-returned bundle_id does not match our nonce".into());
    }

    // HPKE decryption uses the X25519 secret derived from our Ed25519 seed.
    let x_secret = ed25519_seed_to_x25519_secret(&ed_seed);
    let opened = open_bundle(&x_secret, bundle, expect_digest.as_deref())?;

    // The attestation quote binds the did:key-visible bytes end-to-end:
    //   SHA256(client_ed25519 || bundle_id || producer_ed25519)
    // so we pass the raw Ed25519 pubkey we generated (the same bytes the
    // server decoded from `client_did`) rather than any X25519 derivative.
    let attest = verify_nitro_assertion(&opened.producer, &ed_pub, &nonce)?;
    println!("TEE attestation verified.");
    println!("  Enclave module: {}", attest.module_id);
    if !attest.pcr0_hex.is_empty() {
        println!("  PCR0:           {}", attest.pcr0_hex);
    }
    if !attest.pcr8_hex.is_empty() {
        println!("  PCR8:           {}", attest.pcr8_hex);
    }

    let credential = match opened.payload {
        SealedPayloadV1::AdminCredential(c) => c,
        other => {
            return Err(format!(
                "expected AdminCredential payload from online bootstrap, got {}",
                variant_name(&other)
            )
            .into());
        }
    };

    let slug = vta_slug.unwrap_or_else(|| default_slug(&credential.vta_did));
    pnm_config.vtas.insert(
        slug.clone(),
        crate::config::VtaConfig {
            name: slug.clone(),
            vta_did: Some(credential.vta_did.clone()),
            url: None,
        },
    );
    if pnm_config.default_vta.is_none() {
        pnm_config.default_vta = Some(slug.clone());
    }
    crate::config::save_config(pnm_config)?;

    // The bootstrap URL is only needed for the immediate `auth::ensure_authenticated`
    // call below — every subsequent command resolves the REST endpoint
    // from the VTA DID document at runtime.
    let keyring_key = crate::config::vta_keyring_key(&slug);
    auth::store_session(
        &keyring_key,
        &credential.did,
        &credential.private_key_multibase,
        &credential.vta_did,
    )?;
    // Verify the credential works end-to-end before declaring success.
    auth::ensure_authenticated(&vta_url, &keyring_key).await?;

    println!();
    println!("Bootstrap complete.");
    println!("  VTA slug:   {slug}");
    println!("  Client DID: {}", credential.did);
    println!("  VTA DID:    {}", credential.vta_did);
    println!("  Digest:     {}", bundle_digest(bundle));
    Ok(())
}

/// `pnm bootstrap provision-integration` — bridge a VP-framed
/// BootstrapRequest to the VTA over whichever transport the client
/// is currently using (REST or DIDComm), writing the returned
/// armored bundle to disk.
///
/// The VTA runs the same shared library fn for both transports and
/// the offline `vta bootstrap provision-integration` CLI; the only
/// difference between paths is the wire form of the request /
/// response. `VtaClient::provision_integration` dispatches:
/// - REST → `POST /bootstrap/provision-integration` with the
///   bearer token from the open session.
/// - DIDComm → `provision-integration/1.0` message over the open
///   authcrypt session. The VTA enforces that the DIDComm sender
///   DID matches the VP holder before issuing the bundle
///   (privilege-laundering guard).
#[allow(clippy::too_many_arguments)]
pub async fn run_provision_integration(
    client: &vta_sdk::client::VtaClient,
    request: PathBuf,
    context: Option<String>,
    assertion: String,
    vc_validity_seconds: Option<i64>,
    out: PathBuf,
    create_context: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use vta_sdk::provision_integration::http::{
        AssertionMode as WireAssertionMode, ProvisionIntegrationRequest,
    };

    // 1. Parse the integration's VP (but don't verify locally — the
    //    server does the authoritative verification).
    let request_json =
        fs::read_to_string(&request).map_err(|e| format!("read {}: {e}", request.display()))?;
    let vp: vta_sdk::provision_integration::BootstrapRequest = serde_json::from_str(&request_json)
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

    // 4. Submit.
    let resp = client
        .provision_integration(ProvisionIntegrationRequest {
            request: vp,
            // `--context` is required on the pnm-cli surface today, so
            // we always pass a concrete value. The wire field is
            // `Option<String>` per the canonical spec; future flag
            // changes can pass `None` to opt into VTA-side inference.
            context: Some(target_context.clone()),
            assertion: Some(assertion_mode),
            vc_validity_seconds,
            create_context,
        })
        .await?;

    // 5. Write bundle + print summary.
    fs::write(&out, resp.bundle.as_bytes()).map_err(|e| format!("write {}: {e}", out.display()))?;

    eprintln!(
        "Integration provisioned via {} — sealed bundle written to {}",
        client.base_url(),
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
    eprintln!("  SHA-256 digest:  {}", resp.digest);
    eprintln!();
    eprintln!(
        "Communicate the digest to the integration's operator out-of-band so they can\n  \
         verify the bundle on first boot:\n  \
         pnm bootstrap open --bundle <file> --expect-digest {}",
        resp.digest
    );
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

fn variant_name(p: &SealedPayloadV1) -> &'static str {
    match p {
        SealedPayloadV1::AdminCredential(_) => "AdminCredential",
        SealedPayloadV1::ContextProvision(_) => "ContextProvision",
        SealedPayloadV1::DidSecrets(_) => "DidSecrets",
        SealedPayloadV1::AdminKeySet(_) => "AdminKeySet",
        SealedPayloadV1::RawPrivateKey(_) => "RawPrivateKey",
        SealedPayloadV1::TemplateBootstrap(_) => "TemplateBootstrap",
        SealedPayloadV1::AdminRotation(_) => "AdminRotation",
        SealedPayloadV1::IssuedCredential(_) => "IssuedCredential",
    }
}

fn default_slug(vta_did: &str) -> String {
    vta_did.rsplit(':').next().unwrap_or("vta").to_string()
}

#[cfg(test)]
mod tests {
    use super::parse_var;
    use serde_json::Value;

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
}
