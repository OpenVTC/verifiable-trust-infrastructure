//! Non-interactive `vtc setup --from <file>` (P3.10).
//!
//! The interactive [`wizard`](super::wizard) gathers operator decisions
//! via prompts and live VTA round-trips, then hands a fully-resolved
//! [`WizardPlan`](super::wizard::WizardPlan) to the shared
//! [`apply`](super::wizard::apply) effect driver. This module is the
//! second front-end: it parses a TOML file into the *same* plan and
//! feeds it to the *same* `apply`, so a CI image, an immutable build, or
//! any unattended provisioner can stand up a VTC with no TTY.
//!
//! ## The ACL-grant seam
//!
//! Provisioning a VTC authenticates to the VTA with an ephemeral
//! `did:key`, and that DID must already be ACL-authorised at the VTA.
//! The interactive wizard generates the key and *pauses* for the
//! operator to grant the ACL. A non-interactive run can't pause, so the
//! key has to be authorised out of band first. The flow is two-phase:
//!
//! 1. Generate + persist an ephemeral setup key (e.g. via the
//!    provision-client's `EphemeralSetupKey::persist_to`, the same file
//!    `pnm` writes), then grant its DID an admin ACL at the VTA
//!    (`pnm contexts create --admin-did <did>` / `pnm acl create`).
//! 2. Run `vtc setup --from <toml>`, pointing `setup_key_file` at that
//!    persisted key. `apply` loads it (`load_from`) and provisions — the
//!    grant is already in place, so no prompt is needed.
//!
//! This mirrors the VTA's deferred-setup / `pnm setup continue` pattern;
//! the `EphemeralSetupKey` persist/reload bridge was built for exactly
//! this race between ACL provisioning and connection verification.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vta_sdk::provision_client::EphemeralSetupKey;
use vti_common::error::AppError;

use crate::config::{MessagingConfig, SecretsConfig};

use super::wizard::{
    SetupOutcome, WebvhTarget, WizardInputs, WizardPlan, apply, refuse_if_already_set_up,
};

/// TOML schema for `vtc setup --from <file>`.
///
/// `Serialize` is derived alongside `Deserialize` so the shipped example
/// and round-trip tests can assert structural stability; production only
/// ever deserializes. `deny_unknown_fields` makes a typo'd key a hard
/// error rather than a silently-ignored setting.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VtcWizardInputs {
    /// Output path for the generated `config.toml`. Setup refuses to
    /// overwrite a config that already names a `vtc_did` — move it aside
    /// to re-provision.
    pub config_path: PathBuf,

    /// The VTC daemon's public base URL (e.g. `https://vtc.example.com`),
    /// no trailing slash and no `/v1`. All three surfaces (API, admin UX,
    /// website) mount under it in the default path mode; it's stored as
    /// `public_url` and passed as the `vtc-host` template's `URL` var. A
    /// trailing slash is trimmed for you.
    pub base_url: String,

    /// DID of the VTA that mints this VTC's DID + key material (e.g.
    /// `did:webvh:vta.example.com:abc`). Its transport endpoints are
    /// resolved from the DID document — no separate VTA URL is needed.
    pub vta_did: String,

    /// Context name at the VTA this community provisions under. Defaults
    /// to `default`.
    #[serde(default = "default_context")]
    pub context: String,

    /// Where the VTC's `did:webvh` is published. All fields optional; an
    /// empty `[webvh]` table (or omitting it) reproduces the serverless
    /// default — the VTC self-hosts its `did.jsonl` at `base_url` with a
    /// server-assigned path.
    #[serde(default)]
    pub webvh: WebvhTarget,

    /// DIDComm mediator the VTC routes through. Omit for no messaging
    /// (the daemon stays healthy on REST and logs a one-line warning).
    /// `mediator_did` is required when present; `mediator_url` /
    /// `mediator_host` are optional (the endpoint is resolved from the
    /// DID document).
    #[serde(default)]
    pub messaging: Option<MessagingConfig>,

    /// Secret-store backend for the VTC's key bundle. Required — the
    /// choice is security-sensitive and there is no safe implicit
    /// default. Same shape as the `[secrets]` block in `config.toml`; the
    /// backend's own factory validates feature availability at load.
    pub secrets: SecretsConfig,

    /// Path to a JSON file holding a previously-persisted ephemeral setup
    /// key (`EphemeralSetupKey::persist_to` format) whose `did:key` has
    /// *already* been ACL-authorised at the VTA. This is the two-phase
    /// bridge that replaces the interactive ACL-grant pause — see the
    /// module docs.
    pub setup_key_file: PathBuf,
}

fn default_context() -> String {
    "default".to_string()
}

/// Read + parse a setup TOML into a fully-resolved [`WizardPlan`]: the
/// same plan the interactive collector produces, ready for [`apply`].
/// Validates the inputs and loads (does not generate) the pre-authorised
/// ephemeral setup key.
pub(crate) fn parse_from_toml(file_path: &Path) -> Result<WizardPlan, AppError> {
    let raw = std::fs::read_to_string(file_path)
        .map_err(|e| AppError::Config(format!("read setup file {}: {e}", file_path.display())))?;
    let inputs: VtcWizardInputs = toml::from_str(&raw)
        .map_err(|e| AppError::Config(format!("parse setup file {}: {e}", file_path.display())))?;

    validate(&inputs)?;

    // Guard before touching the VTA or the setup key: a config that
    // already names a vtc_did means this VTC is provisioned.
    refuse_if_already_set_up(&inputs.config_path)?;

    let setup_key = EphemeralSetupKey::load_from(&inputs.setup_key_file).map_err(|e| {
        AppError::Config(format!(
            "load setup key {}: {e}. Generate + persist an ephemeral setup key and grant its \
             did:key an admin ACL at the VTA before running `vtc setup --from` (see the \
             non-interactive setup docs).",
            inputs.setup_key_file.display()
        ))
    })?;

    Ok(WizardPlan {
        config_path: inputs.config_path,
        inputs: WizardInputs {
            base_url: inputs.base_url.trim_end_matches('/').to_string(),
            vta_did: inputs.vta_did,
            context: inputs.context,
        },
        webvh: inputs.webvh,
        secrets: inputs.secrets,
        messaging: inputs.messaging,
        setup_key,
    })
}

/// Cross-field validation, accumulating every problem so the operator
/// fixes them in one pass rather than one-error-at-a-time.
fn validate(inputs: &VtcWizardInputs) -> Result<(), AppError> {
    let mut errors: Vec<String> = Vec::new();

    let base = inputs.base_url.trim_end_matches('/');
    if base.is_empty() {
        errors.push("base_url must not be empty".into());
    } else {
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            errors.push(format!(
                "base_url must start with http:// or https:// (got {:?})",
                inputs.base_url
            ));
        }
        if base.ends_with("/v1") {
            errors.push(
                "base_url must be the host base, without the /v1 API prefix (the template \
                 appends API paths itself)"
                    .into(),
            );
        }
    }

    if !inputs.vta_did.starts_with("did:") {
        errors.push(format!(
            "vta_did must be a DID starting with `did:` (got {:?})",
            inputs.vta_did
        ));
    }

    if inputs.context.trim().is_empty() {
        errors.push("context must not be empty".into());
    }

    if let Some(messaging) = inputs.messaging.as_ref()
        && messaging.mediator_did.trim().is_empty()
    {
        errors.push("messaging.mediator_did must not be empty when [messaging] is present".into());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation(format!(
            "setup file has {} validation error(s):\n  - {}",
            errors.len(),
            errors.join("\n  - ")
        )))
    }
}

/// `vtc setup --from <file>`: parse → [`apply`] → terse summary. The
/// non-interactive counterpart to [`run_setup_wizard`](super::wizard::run_setup_wizard).
pub async fn run_setup_from_file(file_path: PathBuf) -> Result<(), AppError> {
    eprintln!(
        "Running non-interactive VTC setup from {} ...",
        file_path.display()
    );
    let plan = parse_from_toml(&file_path)?;
    let outcome = apply(plan).await?;
    print_setup_summary_terse(&outcome);
    Ok(())
}

/// Print a terse, scrape-friendly completion block. Unlike the
/// interactive summary this never prompts and never prints the admin
/// private key (no TTY to consciously confirm a reveal); the install URL
/// + claim code are the actionable outputs.
fn print_setup_summary_terse(outcome: &SetupOutcome) {
    println!("VTC setup complete.");
    println!("vtc_did={}", outcome.vtc_did);
    println!("admin_did={}", outcome.admin_did);
    println!("config_path={}", outcome.config_path.display());
    println!("data_dir={}", outcome.data_dir.display());
    println!("install_url={}", outcome.install_url);
    println!("claim_code={}", outcome.claim_code);
    if outcome.admin_key_json.is_some() {
        println!(
            "admin_key=<not printed in non-interactive mode; re-run interactively if you need it>"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid TOML (keyring backend, serverless DID, no
    /// messaging) parses and applies defaults.
    fn minimal_toml(config_path: &str, setup_key_file: &str) -> String {
        format!(
            r#"
config_path = "{config_path}"
base_url    = "https://vtc.example.com"
vta_did     = "did:webvh:vta.example.com:abc"
setup_key_file = "{setup_key_file}"

[secrets]
keyring_service = "vtc-test"
"#
        )
    }

    /// Persist a fresh ephemeral key so `parse_from_toml` can load it,
    /// returning (path, did).
    fn persist_setup_key(dir: &Path) -> (PathBuf, String) {
        let key = EphemeralSetupKey::generate().expect("generate setup key");
        let did = key.did.clone();
        let path = dir.join("setup-key.json");
        key.persist_to(&path).expect("persist setup key");
        (path, did)
    }

    #[test]
    fn minimal_inputs_parse_and_default() {
        let toml = minimal_toml("/srv/vtc/config.toml", "/tmp/key.json");
        let inputs: VtcWizardInputs = toml::from_str(&toml).expect("parse");
        assert_eq!(inputs.context, "default", "context defaults to `default`");
        assert!(inputs.messaging.is_none());
        assert!(inputs.webvh.server_id.is_none());
        assert_eq!(inputs.secrets.keyring_service, "vtc-test");
    }

    #[test]
    fn unknown_field_rejected() {
        let toml = r#"
config_path = "/srv/vtc/config.toml"
base_url    = "https://vtc.example.com"
vta_did     = "did:web:vta.example.com"
setup_key_file = "/tmp/key.json"
bogus_field = true

[secrets]
"#;
        let err = toml::from_str::<VtcWizardInputs>(toml).unwrap_err();
        assert!(
            err.to_string().contains("bogus_field"),
            "deny_unknown_fields should reject bogus_field, got: {err}"
        );
    }

    #[test]
    fn full_inputs_parse() {
        let toml = r#"
config_path = "/srv/vtc/config.toml"
base_url    = "https://vtc.example.com/"
vta_did     = "did:webvh:vta.example.com:abc"
context     = "acme"
setup_key_file = "/secrets/vtc-setup-key.json"

[webvh]
server_id = "host-1"
domain    = "tenant.example.com"
path      = "communities/acme"

[messaging]
mediator_did = "did:web:mediator.example.com"

[secrets]
keyring_service = "vtc-acme"
"#;
        let inputs: VtcWizardInputs = toml::from_str(toml).expect("parse");
        assert_eq!(inputs.context, "acme");
        assert_eq!(inputs.webvh.server_id.as_deref(), Some("host-1"));
        assert_eq!(inputs.webvh.domain.as_deref(), Some("tenant.example.com"));
        assert_eq!(inputs.webvh.path.as_deref(), Some("communities/acme"));
        assert_eq!(
            inputs.messaging.as_ref().unwrap().mediator_did,
            "did:web:mediator.example.com"
        );
    }

    #[test]
    fn validate_rejects_bad_base_url_and_vta_did() {
        let inputs: VtcWizardInputs = toml::from_str(
            r#"
config_path = "/srv/vtc/config.toml"
base_url    = "vtc.example.com/v1"
vta_did     = "not-a-did"
setup_key_file = "/tmp/key.json"

[secrets]
"#,
        )
        .expect("parse");
        let err = validate(&inputs).unwrap_err().to_string();
        assert!(err.contains("base_url must start with http"), "{err}");
        assert!(err.contains("/v1"), "{err}");
        assert!(err.contains("vta_did must be a DID"), "{err}");
    }

    #[test]
    fn validate_rejects_empty_mediator_did() {
        let inputs: VtcWizardInputs = toml::from_str(
            r#"
config_path = "/srv/vtc/config.toml"
base_url    = "https://vtc.example.com"
vta_did     = "did:web:vta.example.com"
setup_key_file = "/tmp/key.json"

[messaging]
mediator_did = ""

[secrets]
"#,
        )
        .expect("parse");
        let err = validate(&inputs).unwrap_err().to_string();
        assert!(err.contains("messaging.mediator_did"), "{err}");
    }

    /// End-to-end of the *headless* half: a TOML pointing at a persisted,
    /// pre-authorised setup key parses into a `WizardPlan` with no TTY —
    /// up to the VTA network boundary `apply` would cross. This is the
    /// "completes with no TTY" guarantee minus the live VTA.
    #[test]
    fn parse_from_toml_builds_plan_with_loaded_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (key_path, key_did) = persist_setup_key(dir.path());
        // base_url carries a trailing slash to assert it's trimmed.
        let toml = format!(
            r#"
config_path = "{cfg}"
base_url    = "https://vtc.example.com/"
vta_did     = "did:webvh:vta.example.com:abc"
setup_key_file = "{key}"

[secrets]
keyring_service = "vtc-test"
"#,
            cfg = dir.path().join("config.toml").display(),
            key = key_path.display(),
        );
        let toml_path = dir.path().join("setup.toml");
        std::fs::write(&toml_path, toml).expect("write toml");

        let plan = parse_from_toml(&toml_path).expect("parse_from_toml");
        assert_eq!(
            plan.setup_key.did, key_did,
            "the plan must carry the pre-authorised key loaded from disk"
        );
        assert_eq!(
            plan.inputs.base_url, "https://vtc.example.com",
            "trailing slash trimmed"
        );
        assert_eq!(plan.inputs.context, "default");
    }

    #[test]
    fn parse_from_toml_reports_missing_setup_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let toml = minimal_toml(
            dir.path().join("config.toml").to_str().unwrap(),
            dir.path().join("does-not-exist.json").to_str().unwrap(),
        );
        let toml_path = dir.path().join("setup.toml");
        std::fs::write(&toml_path, toml).expect("write toml");

        // `WizardPlan` deliberately holds the setup key and isn't `Debug`,
        // so match rather than `unwrap_err()` (which needs `T: Debug`).
        let err = match parse_from_toml(&toml_path) {
            Ok(_) => panic!("expected a missing-setup-key error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("load setup key"), "{err}");
        assert!(err.contains("admin ACL"), "actionable hint present: {err}");
    }

    /// The shipped example file must parse — keeps the docs honest.
    #[test]
    fn shipped_example_parses() {
        let example = include_str!("../../../docs/03-vtc/examples/vtc-setup.example.toml");
        let inputs: VtcWizardInputs = toml::from_str(example).expect("shipped example must parse");
        // Sanity on a couple of fields so an accidental gut of the
        // example is caught too.
        assert!(inputs.base_url.starts_with("http"));
        assert!(inputs.vta_did.starts_with("did:"));
        validate(&inputs).expect("shipped example must validate");
    }
}
