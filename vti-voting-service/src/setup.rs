//! `vti-voting-service setup`: the two-phase, VTA-provisioned setup every host service uses.
//!
//! 1. `vti-voting-service setup --setup-key-out <path> [--context <id>]` mints an ephemeral
//!    `did:key`, stores it (0600) and prints the `pnm` grant the operator runs at their VTA
//!    ([`run_phase1`], through `vta_sdk::provision_client::driver::run_phase1_init`).
//! 2. *(out of band)* the operator grants that DID admin of the context. The service never
//!    holds a VTA admin credential of its own.
//! 3. `vti-voting-service setup --from <toml>` provisions the identity from the operator's VTA
//!    with the `ballot-box` template, opens the sealed bundle, keeps the keys in the `[secrets]`
//!    store and writes `config.toml` ([`run_from_file`]).
//!
//! As for the witness, no admin-DID hand-off: the service administers nothing at the VTA, which
//! is its key custodian and not a party. The setup DID's grant runs out at its
//! `--admin-expires`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use tokio::sync::mpsc;
use vta_sdk::provision_client::{
    EphemeralSetupKey, OperatorMessages, ProvisionAsk, ProvisionResultV2, VtaEvent, VtaIntent,
    VtaReply, run_connection_test, run_provision_flight,
};
use vti_secrets::{SecretBackend, SecretsConfig};

use crate::config::{DEFAULT_LISTEN, ServiceIdentity, VotingConfig};
use crate::identity::{bundle_from_material, load_keys, save_keys};

/// The VTA context the identity is provisioned into unless the operator names another.
pub const DEFAULT_CONTEXT: &str = "voting";

/// How setup names itself, and the grant it asks the operator to run.
pub struct VotingMessages;

impl OperatorMessages for VotingMessages {
    fn integration_label(&self) -> &str {
        "Voting service"
    }
    fn integration_label_lower(&self) -> &str {
        "voting service"
    }
    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        format!(
            "pnm contexts create --id {context_id} --name \"Voting service\" \\\n  \
             --admin-did {setup_did} --admin-expires 1h --admin-handoff"
        )
    }
}

/// Phase 1: mint and store the ephemeral setup key, and print the grant.
///
/// # Errors
/// If the key cannot be minted or written.
pub async fn run_phase1(out_path: &Path, context: &str) -> anyhow::Result<()> {
    let finalise = format!(
        "vti-voting-service setup --from <your-setup.toml>   (with setup_key_file = \"{}\")",
        out_path.display()
    );
    vta_sdk::provision_client::driver::run_phase1_init(
        &mut std::io::stderr(),
        out_path,
        context,
        &VotingMessages,
        Some(&finalise),
    )
    .await
    .map_err(|e| anyhow::anyhow!("mint the setup key: {e}"))
}

/// The setup file for `vti-voting-service setup --from <toml>`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupInputs {
    /// Where to write `config.toml`. Setup refuses to overwrite one.
    pub config_path: PathBuf,
    /// The service's data directory. Defaults to `data/` beside `config_path`.
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    /// The address the HTTPS binding is served on.
    #[serde(default)]
    pub listen: Option<String>,
    /// The operator's VTA, which mints the identity.
    pub vta_did: String,
    /// The VTA context to provision into. Defaults to `voting`.
    #[serde(default = "default_context")]
    pub context: String,
    /// The phase-1 key file, whose DID has been granted admin of `context`.
    pub setup_key_file: PathBuf,
    /// A DID resolver sidecar for `run` to resolve through.
    #[serde(default)]
    pub resolver_url: Option<String>,
    /// Where the identity's keys are kept.
    pub secrets: SecretsConfig,
    /// The mediator the DID document names, and the socket connects to.
    pub mediator_did: String,
    /// The public HTTPS base of the cast door (`<https_url>/trust-tasks`), advertised as
    /// `TrustTaskHTTPS` (VTI-VOT-004).
    pub https_url: String,
    /// A registered DID-hosting server to publish the DID log to.
    #[serde(default)]
    pub webvh_server: Option<String>,
    /// A tenant domain on that server.
    #[serde(default)]
    pub webvh_domain: Option<String>,
    /// A path on that server.
    #[serde(default)]
    pub webvh_path: Option<String>,
    /// Serverless: the URL the operator will serve the DID log from.
    #[serde(default)]
    pub url: Option<String>,
}

fn default_context() -> String {
    DEFAULT_CONTEXT.to_string()
}

impl SetupInputs {
    /// Parse and validate a setup file, refusing unknown keys at any depth.
    ///
    /// # Errors
    /// Listing every rule broken.
    pub fn from_toml_str(raw: &str) -> anyhow::Result<Self> {
        let mut ignored = Vec::new();
        let de = toml::Deserializer::parse(raw)?;
        let inputs: Self = serde_ignored::deserialize(de, |path| ignored.push(path.to_string()))?;
        if !ignored.is_empty() {
            anyhow::bail!("unknown key(s) in the setup file: {}", ignored.join(", "));
        }
        inputs.validate()?;
        Ok(inputs)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        for (what, did) in [
            ("vta_did", &self.vta_did),
            ("mediator_did", &self.mediator_did),
        ] {
            if !did.starts_with("did:") {
                errors.push(format!("{what} must be a DID (got {did:?})"));
            }
        }
        if self.mediator_did == self.vta_did {
            errors.push("mediator_did is the VTA's own DID, not a mediator".to_string());
        }
        if !self.https_url.starts_with("https://") {
            errors.push(format!(
                "https_url must start with https:// (got {:?}): it is where voters post casts",
                self.https_url
            ));
        }
        if self.context.trim().is_empty() {
            errors.push("context must not be empty".to_string());
        }
        if matches!(self.secrets.backend, Some(SecretBackend::ConfigSeed)) {
            errors.push(
                "secrets.backend = \"config_seed\" would keep the identity's keys in config.toml"
                    .to_string(),
            );
        }
        match (&self.webvh_server, &self.url) {
            (None, None) => errors.push(
                "name webvh_server (a registered DID-hosting server) or url (where you will \
                 serve the DID log yourself): the VTA needs one to know where the log goes"
                    .to_string(),
            ),
            (_, Some(url)) if !url.starts_with("https://") => {
                errors.push(format!("url must start with https:// (got {url:?})"));
            }
            _ => {}
        }
        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(
                "the setup file has {} error(s):\n  - {}",
                errors.len(),
                errors.join("\n  - ")
            )
        }
    }

    /// The data directory: as given, or `data/` beside `config.toml`.
    pub fn data_dir(&self) -> PathBuf {
        self.data_dir.clone().unwrap_or_else(|| {
            self.config_path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .join("data")
        })
    }

    /// The provisioning ask: the `ballot-box` template at the mediator and cast door, where its
    /// log is published, and no admin hand-off.
    pub fn ask(&self) -> ProvisionAsk {
        let mut ask = ProvisionAsk::ballot_box(&self.context, &self.mediator_did, &self.https_url)
            .with_label("vti-voting-service");
        for (key, value) in [
            ("URL", &self.url),
            ("WEBVH_SERVER", &self.webvh_server),
            ("WEBVH_DOMAIN", &self.webvh_domain),
            ("WEBVH_PATH", &self.webvh_path),
        ] {
            if let Some(value) = value {
                ask.integration_template_vars
                    .insert(key.to_string(), Value::String(value.clone()));
            }
        }
        ask.admin_template = None;
        ask.admin_template_vars.clear();
        ask
    }
}

/// Phase 2: provision the identity, keep its keys, write the configuration.
///
/// # Errors
/// If the file is invalid, a configuration already exists, the store already holds keys, or
/// provisioning fails.
pub async fn run_from_file(path: &Path) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
    let inputs =
        SetupInputs::from_toml_str(&raw).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    if inputs.config_path.exists() {
        anyhow::bail!(
            "{} already exists. Setup does not overwrite a configuration; move it aside to \
             provision a new identity.",
            inputs.config_path.display()
        );
    }
    let setup_key = EphemeralSetupKey::load_from(&inputs.setup_key_file).map_err(|e| {
        anyhow::anyhow!(
            "load the setup key {}: {e}. Run `vti-voting-service setup --setup-key-out <path>` \
             first and grant the DID it prints.",
            inputs.setup_key_file.display()
        )
    })?;

    // The store first, so a misconfigured backend fails before anything is minted; and empty,
    // because these keys are this host's only copy.
    let data_dir = inputs.data_dir();
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", data_dir.display()))?;
    let store = vti_secrets::create_seed_store(&inputs.secrets, &data_dir)
        .map_err(|e| anyhow::anyhow!("open the secret store: {e}"))?;
    if load_keys(&*store).await?.is_some() {
        anyhow::bail!(
            "the configured secret store already holds identity keys. Setup does not overwrite \
             them; point [secrets] at an empty entry."
        );
    }

    eprintln!(
        "Provisioning the ballot-box identity from {} ...",
        inputs.vta_did
    );
    let result = provision(&inputs.vta_did, &setup_key, inputs.ask()).await?;
    let (Some(did), Some(material)) = (result.integration_did(), result.integration_key()) else {
        anyhow::bail!("the VTA's bundle carries no integration DID or keys");
    };
    let did = did.to_string();

    // Keys first, then the configuration that names them.
    save_keys(&*store, &bundle_from_material(material)).await?;
    if !store.set_persists_across_restart() {
        eprintln!(
            "warning: the configured secret store does not survive a restart; the identity's \
             keys will be lost with this process"
        );
    }
    let did_log = match result.webvh_log() {
        Some(log) => {
            let p = data_dir.join("did.jsonl");
            std::fs::write(&p, log).map_err(|e| anyhow::anyhow!("write {}: {e}", p.display()))?;
            Some(p)
        }
        None => None,
    };

    let config = VotingConfig {
        data_dir: data_dir.clone(),
        listen: inputs
            .listen
            .clone()
            .unwrap_or_else(|| DEFAULT_LISTEN.to_string()),
        operator_vta_did: Some(inputs.vta_did.clone()),
        resolver_url: inputs.resolver_url.clone(),
        secrets: inputs.secrets.clone(),
        identity: Some(ServiceIdentity {
            did: did.clone(),
            mediator_did: inputs.mediator_did.clone(),
        }),
        communities: Default::default(),
    };
    config.validate()?;
    if let Some(parent) = inputs
        .config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(&inputs.config_path, config.to_toml_string()?)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", inputs.config_path.display()))?;
    vti_common::secure_file::restrict_file_to_owner(&inputs.config_path)
        .map_err(|e| anyhow::anyhow!("restrict {}: {e}", inputs.config_path.display()))?;

    println!("Voting service setup complete.");
    println!("config_path={}", inputs.config_path.display());
    println!("ballot_box_did={did}");
    if let Some(p) = did_log {
        println!(
            "did_log={}  (serve it at the URL the DID names)",
            p.display()
        );
    }
    println!(
        "The setup DID {} keeps its grant until --admin-expires; remove it sooner with \
         `pnm acl delete --did {}`.",
        setup_key.did, setup_key.did
    );
    println!(
        "It registers no community's elections until you name them in {}:\n  [communities]\n  \
         allowed = [\"<community DID>\"]",
        inputs.config_path.display()
    );
    println!(
        "Start the service: vti-voting-service run --config {}",
        inputs.config_path.display()
    );
    Ok(())
}

async fn provision(
    vta_did: &str,
    setup_key: &EphemeralSetupKey,
    ask: ProvisionAsk,
) -> anyhow::Result<ProvisionResultV2> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(run_connection_test(
        VtaIntent::FullSetup,
        vta_did.to_string(),
        setup_key.did.clone(),
        setup_key.private_key_multibase().to_string(),
        ask.clone(),
        None,
        tx,
    ));
    let reply = 'outer: loop {
        match rx.recv().await {
            Some(VtaEvent::Connected { reply, .. }) => break reply,
            Some(VtaEvent::Failed(msg)) => return Err(provision_failed(&msg)),
            Some(VtaEvent::PreflightDone {
                rest_url,
                mediator_did,
                ..
            }) => {
                let (ftx, mut frx) = mpsc::unbounded_channel();
                tokio::spawn(run_provision_flight(
                    vta_did.to_string(),
                    setup_key.did.clone(),
                    setup_key.private_key_multibase().to_string(),
                    mediator_did,
                    rest_url,
                    ask.clone(),
                    None,
                    None,
                    Arc::new(VotingMessages),
                    ftx,
                ));
                loop {
                    match frx.recv().await {
                        Some(VtaEvent::Connected { reply, .. }) => break 'outer reply,
                        Some(VtaEvent::Failed(msg)) => return Err(provision_failed(&msg)),
                        Some(_) => {}
                        None => {
                            return Err(provision_failed(
                                "provisioning ended without a terminal event",
                            ));
                        }
                    }
                }
            }
            Some(_) => {}
            None => {
                return Err(provision_failed(
                    "provisioning ended without a terminal event",
                ));
            }
        }
    };
    match reply {
        VtaReply::Full(result) => Ok(*result),
        VtaReply::AdminOnly(_) => Err(anyhow::anyhow!(
            "the VTA answered with an admin credential only; the ballot-box template needs a \
             full provisioning reply"
        )),
    }
}

fn provision_failed(msg: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "VTA provisioning failed: {msg}. Check the VTA DID, and that the setup DID was granted \
         admin of the context (`pnm contexts create … --admin-did <setup DID>`, or `pnm acl \
         create` if the context already exists)."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SETUP: &str = r#"
        config_path = "/etc/vti-voting/config.toml"
        vta_did = "did:webvh:QmVTA:vta.example.com"
        setup_key_file = "/etc/vti-voting/setup.key"
        mediator_did = "did:webvh:QmMED:mediator.example.org:mediator"
        https_url = "https://votes.example.net"
        url = "https://votes.example.net/did"

        [secrets]
        backend = "plaintext"
    "#;

    #[test]
    fn the_ask_names_the_ballot_box_template_and_both_endpoints() {
        let inputs = SetupInputs::from_toml_str(SETUP).unwrap();
        assert_eq!(inputs.context, DEFAULT_CONTEXT);
        let ask = inputs.ask();
        let vars = &ask.integration_template_vars;
        assert_eq!(
            vars["MEDIATOR_DID"],
            "did:webvh:QmMED:mediator.example.org:mediator"
        );
        assert_eq!(vars["HTTPS_URL"], "https://votes.example.net");
        assert_eq!(vars["URL"], "https://votes.example.net/did");
        assert!(
            ask.admin_template.is_none(),
            "no VTA credential reaches this host"
        );
    }

    #[test]
    fn a_plain_http_cast_door_is_refused() {
        let raw = SETUP.replace(
            "https_url = \"https://votes.example.net\"",
            "https_url = \"http://votes.example.net\"",
        );
        let err = SetupInputs::from_toml_str(&raw).unwrap_err();
        assert!(err.to_string().contains("https_url"), "{err}");
    }
}
