//! `vti-witness setup`: the two-phase, VTA-provisioned setup every
//! integration uses (the VTC, the mediator, did-hosting).
//!
//! 1. `vti-witness setup --setup-key-out <path> [--context <id>]` mints an
//!    ephemeral `did:key`, stores it (0600) and prints the `pnm` grant the
//!    operator runs at their VTA ([`run_phase1`], through the shared
//!    `vta_sdk::provision_client::driver::run_phase1_init`).
//! 2. *(out of band)* the operator grants that DID admin of the witness
//!    context. The witness never holds a VTA admin credential of its own.
//! 3. `vti-witness setup --from <toml>` provisions each witness identity from
//!    the operator's VTA with the `dtg-witness` template, opens each sealed
//!    bundle, keeps the keys in the `[secrets]` store and writes
//!    `config.toml` ([`run_from_file`]).
//!
//! # No admin-DID hand-off
//!
//! Every other integration asks the VTA to roll its setup DID over to a
//! long-term admin DID, because it goes on to administer something at the VTA.
//! A witness administers nothing there: its VTA is a key custodian, not a
//! party (design note §3.5). So each ask sets no admin template — no long-term
//! admin DID is minted, no VTA credential reaches this host, and one setup key
//! provisions every identity. The setup DID's grant simply runs out at its
//! `--admin-expires`; the summary prints how to remove it sooner.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use vta_sdk::provision_client::{
    EphemeralSetupKey, OperatorMessages, ProvisionAsk, ProvisionResultV2, VtaEvent, VtaIntent,
    VtaReply, run_connection_test, run_provision_flight,
};
use vti_secrets::{SecretBackend, SecretsConfig};

use crate::config::{WitnessConfig, WitnessIdentity, identity_errors};
use crate::correlation::{self, OperatorFootprint};
use crate::keys::{WitnessKeyring, bundle_from_material};

/// The VTA context witness identities are provisioned into unless the
/// operator names another.
pub const DEFAULT_CONTEXT: &str = "witness";

/// The `OperatorMessages` for the witness integration kind: how setup names
/// itself, and the grant it asks the operator to run.
pub struct WitnessMessages;

impl OperatorMessages for WitnessMessages {
    fn integration_label(&self) -> &str {
        "Witness"
    }
    fn integration_label_lower(&self) -> &str {
        "witness"
    }
    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        format!(
            "pnm contexts create --id {context_id} --name \"Witness\" \\\n  \
             --admin-did {setup_did} --admin-expires 1h --admin-handoff"
        )
    }
}

/// Phase 1: mint and store the ephemeral setup key, and print the grant.
pub async fn run_phase1(out_path: &Path, context: &str) -> anyhow::Result<()> {
    let finalise = format!(
        "vti-witness setup --from <your-setup.toml>   (with setup_key_file = \"{}\")",
        out_path.display()
    );
    vta_sdk::provision_client::driver::run_phase1_init(
        &mut std::io::stderr(),
        out_path,
        context,
        &WitnessMessages,
        Some(&finalise),
    )
    .await
    .map_err(|e| anyhow::anyhow!("mint the setup key: {e}"))
}

/// The setup file for `vti-witness setup --from <toml>`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetupInputs {
    /// Where to write `config.toml`. Setup refuses to overwrite one.
    pub config_path: PathBuf,
    /// The service's data directory. Defaults to `data/` beside `config_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<PathBuf>,
    /// The operator's VTA, which mints every identity.
    pub vta_did: String,
    /// The VTA context to provision into. Defaults to `witness`.
    #[serde(default = "default_context")]
    pub context: String,
    /// The phase-1 key file, whose DID has been granted admin of `context`.
    pub setup_key_file: PathBuf,
    /// A DID resolver sidecar for `run` to resolve through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_url: Option<String>,
    /// Where the identities' keys are kept. Same table as `config.toml`'s.
    pub secrets: SecretsConfig,
    /// The identities to provision, as `[[witness]]` tables: 1 to 10.
    #[serde(rename = "witness")]
    pub witnesses: Vec<SetupWitness>,
}

/// One `[[witness]]` table in the setup file.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetupWitness {
    /// The operator's local name for the identity.
    pub name: String,
    /// The mediator its DID document names, and its socket connects to.
    pub mediator_did: String,
    /// Whether `run` serves it. Default `false`.
    #[serde(default)]
    pub enabled: bool,
    /// A registered DID-hosting server to publish the DID log to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webvh_server: Option<String>,
    /// A tenant domain on that server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webvh_domain: Option<String>,
    /// A path on that server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webvh_path: Option<String>,
    /// Serverless: the URL the operator will serve the DID log from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

fn default_context() -> String {
    DEFAULT_CONTEXT.to_string()
}

impl SetupInputs {
    /// Parse and validate a setup file — refusing unknown keys at any depth.
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
        let mut errors = identity_errors(
            self.witnesses
                .iter()
                .map(|w| (w.name.as_str(), None, w.mediator_did.as_str())),
            None,
        );
        if self.witnesses.is_empty() {
            errors.push("name at least one [[witness]] to provision".to_string());
        }
        if !self.vta_did.starts_with("did:") {
            errors.push(format!("vta_did must be a DID (got {:?})", self.vta_did));
        }
        if self.context.trim().is_empty() {
            errors.push("context must not be empty".to_string());
        }
        if matches!(self.secrets.backend, Some(SecretBackend::ConfigSeed)) {
            errors.push(
                "secrets.backend = \"config_seed\" would keep the witness keys in config.toml"
                    .to_string(),
            );
        }
        for w in &self.witnesses {
            match (&w.webvh_server, &w.url) {
                (None, None) => errors.push(format!(
                    "witness {:?}: name webvh_server (a registered DID-hosting server) or url \
                     (where you will serve the DID log yourself) — the VTA needs one to know \
                     where the log is published",
                    w.name
                )),
                (_, Some(url)) if !(url.starts_with("https://") || url.starts_with("http://")) => {
                    errors.push(format!(
                        "witness {:?}: url must start with https:// (got {url:?})",
                        w.name
                    ))
                }
                _ => {}
            }
            if w.mediator_did == self.vta_did {
                errors.push(format!(
                    "witness {:?}: mediator_did is the VTA's own DID, not a mediator",
                    w.name
                ));
            }
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
}

/// The provisioning ask for one identity: the `dtg-witness` template at its
/// mediator, where its log is published, and no admin hand-off.
pub fn witness_ask(context: &str, witness: &SetupWitness) -> ProvisionAsk {
    let mut ask = ProvisionAsk::dtg_witness(context, &witness.mediator_did)
        .with_label(format!("vti-witness {}", witness.name));
    let vars: &mut BTreeMap<String, Value> = &mut ask.integration_template_vars;
    for (key, value) in [
        ("URL", &witness.url),
        // Sideband hints the VTA reads before rendering: where the log goes.
        ("WEBVH_SERVER", &witness.webvh_server),
        ("WEBVH_DOMAIN", &witness.webvh_domain),
        ("WEBVH_PATH", &witness.webvh_path),
    ] {
        if let Some(value) = value {
            vars.insert(key.to_string(), Value::String(value.clone()));
        }
    }
    // See the module docs: a witness takes no VTA admin credential.
    ask.admin_template = None;
    ask.admin_template_vars.clear();
    ask
}

/// One provisioned identity, before anything is written.
struct Provisioned {
    identity: WitnessIdentity,
    did_log: Option<String>,
}

/// Phase 2: provision every identity, then keep the keys and write the config.
pub async fn run_from_file(path: &Path) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
    let inputs =
        SetupInputs::from_toml_str(&raw).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;

    if inputs.config_path.exists() {
        anyhow::bail!(
            "{} already exists. Setup does not overwrite a witness configuration; move it aside \
             to provision a new one.",
            inputs.config_path.display()
        );
    }
    let setup_key = EphemeralSetupKey::load_from(&inputs.setup_key_file).map_err(|e| {
        anyhow::anyhow!(
            "load the setup key {}: {e}. Run `vti-witness setup --setup-key-out <path>` first \
             and grant the DID it prints.",
            inputs.setup_key_file.display()
        )
    })?;

    // The store first: a misconfigured backend fails here, before anything
    // is minted at the VTA. And it must be empty — these keys are the only
    // copy this host has, and overwriting another setup's would orphan it.
    let data_dir = inputs.data_dir();
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", data_dir.display()))?;
    let store = vti_secrets::create_seed_store(&inputs.secrets, &data_dir)
        .map_err(|e| anyhow::anyhow!("open the secret store: {e}"))?;
    if !WitnessKeyring::load(&*store).await?.is_empty() {
        anyhow::bail!(
            "the configured secret store already holds witness keys. Setup does not overwrite \
             them; point [secrets] at an empty entry (e.g. another keyring_service)."
        );
    }

    let operator = OperatorFootprint::resolve(&inputs.vta_did).await;
    let mut keyring = WitnessKeyring::default();
    let mut provisioned: Vec<Provisioned> = Vec::new();

    for witness in &inputs.witnesses {
        eprintln!(
            "Provisioning witness {:?} from {} ...",
            witness.name, inputs.vta_did
        );
        let result = match provision(
            &inputs.vta_did,
            &setup_key,
            witness_ask(&inputs.context, witness),
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                report_orphans(&provisioned);
                return Err(e.context(format!("provision witness {:?}", witness.name)));
            }
        };
        let (Some(did), Some(material)) = (result.integration_did(), result.integration_key())
        else {
            report_orphans(&provisioned);
            anyhow::bail!(
                "the VTA's bundle for witness {:?} carries no integration DID or keys",
                witness.name
            );
        };
        keyring.insert(bundle_from_material(material));
        provisioned.push(Provisioned {
            identity: WitnessIdentity::provisioned(
                witness.name.clone(),
                did.to_string(),
                witness.mediator_did.clone(),
                witness.enabled,
            ),
            did_log: result.webvh_log().map(str::to_string),
        });
    }

    // Keys first, then the config that names them: a config.toml never
    // names an identity whose keys were not kept.
    keyring.save(&*store).await?;
    if !store.set_persists_across_restart() {
        eprintln!(
            "warning: the configured secret store does not survive a restart; the witness keys \
             will be lost with this process"
        );
    }

    let mut did_logs = Vec::new();
    for p in &provisioned {
        if let Some(log) = &p.did_log {
            let path = write_did_log(&data_dir, &p.identity.name, log)?;
            did_logs.push((p.identity.name.clone(), path));
        }
    }

    let config = WitnessConfig {
        data_dir: data_dir.clone(),
        operator_vta_did: inputs.vta_did.clone(),
        resolver_url: inputs.resolver_url.clone(),
        secrets: inputs.secrets.clone(),
        independence: Default::default(),
        witnesses: provisioned.iter().map(|p| p.identity.clone()).collect(),
    };
    config.validate()?;
    write_config(&inputs.config_path, &config)?;

    print_summary(&inputs, &setup_key, &config, &did_logs, &operator);
    Ok(())
}

/// Drive one `provision-integration` to its reply, honouring the explicit
/// webvh choice in `ask` (the DIDComm flight is given no server or path of
/// its own, so the ask's sideband vars pass through untouched) — the same
/// drive `vtc setup` uses.
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
            // TSP and REST complete here.
            Some(VtaEvent::Connected { reply, .. }) => break reply,
            Some(VtaEvent::Failed(msg)) => return Err(provision_failed(&msg)),
            // DIDComm: the preflight is done; fly the ask as written.
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
                    Arc::new(WitnessMessages),
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
            "the VTA answered with an admin credential only; the dtg-witness template needs a full \
             provisioning reply"
        )),
    }
}

fn provision_failed(msg: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "VTA provisioning failed: {msg}. Check the VTA DID, and that the setup DID was granted \
         admin of the witness context (`pnm contexts create … --admin-did <setup DID>`, or \
         `pnm acl create` if the context already exists)."
    )
}

/// Identities minted at the VTA before a later one failed are not kept here.
/// Name them, so the operator can remove them at the VTA.
fn report_orphans(provisioned: &[Provisioned]) {
    if provisioned.is_empty() {
        return;
    }
    eprintln!(
        "Setup stopped part-way. These identities were minted at the VTA but nothing was saved \
         on this host, so they are unused — remove them at the VTA (`pnm did-mgmt dids …`) \
         before re-running setup:"
    );
    for p in provisioned {
        eprintln!("  {}  {}", p.identity.name, p.identity.did);
    }
}

fn write_did_log(data_dir: &Path, name: &str, log: &str) -> anyhow::Result<PathBuf> {
    let dir = data_dir.join("did");
    std::fs::create_dir_all(&dir).map_err(|e| anyhow::anyhow!("create {}: {e}", dir.display()))?;
    let path = dir.join(format!("{name}.jsonl"));
    std::fs::write(&path, log).map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))?;
    Ok(path)
}

fn write_config(path: &Path, config: &WitnessConfig) -> anyhow::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("create {}: {e}", parent.display()))?;
    }
    let body = config.to_toml_string()?;
    std::fs::write(path, body).map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))?;
    // It names the secret store; owner-only, as every service config here is.
    vti_common::secure_file::restrict_file_to_owner(path)
        .map_err(|e| anyhow::anyhow!("restrict {}: {e}", path.display()))?;
    Ok(())
}

fn print_summary(
    inputs: &SetupInputs,
    setup_key: &EphemeralSetupKey,
    config: &WitnessConfig,
    did_logs: &[(String, PathBuf)],
    operator: &OperatorFootprint,
) {
    println!("Witness setup complete.");
    println!("config_path={}", inputs.config_path.display());
    println!("data_dir={}", config.data_dir.display());
    for w in &config.witnesses {
        println!(
            "witness name={} did={} mediator={} enabled={}",
            w.name, w.did, w.mediator_did, w.enabled
        );
    }
    for (name, path) in did_logs {
        println!(
            "did_log name={name} path={} — the VTA returned this log; if this witness is \
             serverless, serve it where its DID resolves",
            path.display()
        );
    }
    for w in &config.witnesses {
        for warning in correlation::check(&w.name, Some(&w.did), &w.mediator_did, operator) {
            eprintln!("warning: {warning}");
        }
    }
    println!(
        "setup_did={} — never handed off: the witness holds no VTA credential. Its grant ends \
         at its --admin-expires; remove it sooner with `pnm acl delete {}`.",
        setup_key.did, setup_key.did
    );
    if config.enabled().count() == 0 {
        println!(
            "next: set enabled = true on the identities to serve in {}, then run \
             `vti-witness run --config {}`",
            inputs.config_path.display(),
            inputs.config_path.display()
        );
    } else {
        println!(
            "next: vti-witness run --config {}",
            inputs.config_path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_toml(witnesses: &str) -> String {
        format!(
            r#"
config_path = "/etc/vti-witness/config.toml"
vta_did = "did:webvh:QmVTA:vta.operator.example"
setup_key_file = "/secrets/witness-setup-key.json"

[secrets]
keyring_service = "vti-witness"
{witnesses}"#
        )
    }

    const ONE: &str = r#"
[[witness]]
name = "community-a"
mediator_did = "did:webvh:QmMED:mediator.elsewhere.example"
webvh_server = "prod"
"#;

    #[test]
    fn a_setup_file_parses_with_defaults() {
        let inputs = SetupInputs::from_toml_str(&setup_toml(ONE)).expect("parses");
        assert_eq!(inputs.context, DEFAULT_CONTEXT);
        assert_eq!(inputs.witnesses.len(), 1);
        assert!(!inputs.witnesses[0].enabled, "off unless asked");
        assert_eq!(inputs.data_dir(), PathBuf::from("/etc/vti-witness/data"));
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let raw = setup_toml(&format!("{ONE}colour = \"blue\"\n"));
        let err = SetupInputs::from_toml_str(&raw).unwrap_err();
        assert!(err.to_string().contains("colour"), "{err}");
    }

    #[test]
    fn eleven_witnesses_are_refused() {
        let many: String = (0..11)
            .map(|i| {
                format!(
                    "\n[[witness]]\nname = \"w{i}\"\nmediator_did = \"did:web:m.example\"\nurl = \"https://w{i}.example\"\n"
                )
            })
            .collect();
        let err = SetupInputs::from_toml_str(&setup_toml(&many)).unwrap_err();
        assert!(err.to_string().contains("at most 10"), "{err}");
    }

    #[test]
    fn a_witness_needs_somewhere_to_publish_its_log() {
        let raw = setup_toml("\n[[witness]]\nname = \"a\"\nmediator_did = \"did:web:m.example\"\n");
        let err = SetupInputs::from_toml_str(&raw).unwrap_err();
        assert!(err.to_string().contains("webvh_server"), "{err}");
    }

    /// Each identity is the `dtg-witness` template at its own mediator, its log
    /// target passed through, and no admin hand-off.
    #[test]
    fn the_ask_is_the_dtg_witness_template_with_no_admin_hand_off() {
        let inputs = SetupInputs::from_toml_str(&setup_toml(ONE)).unwrap();
        let ask = witness_ask(&inputs.context, &inputs.witnesses[0]);
        assert_eq!(ask.integration_template.as_deref(), Some("dtg-witness"));
        assert_eq!(ask.context, "witness");
        assert_eq!(
            ask.integration_template_vars["MEDIATOR_DID"],
            Value::String("did:webvh:QmMED:mediator.elsewhere.example".into())
        );
        assert_eq!(
            ask.integration_template_vars["WEBVH_SERVER"],
            Value::String("prod".into())
        );
        assert!(!ask.integration_template_vars.contains_key("URL"));
        assert!(
            ask.admin_template.is_none(),
            "a witness takes no VTA admin credential"
        );
    }

    #[test]
    fn the_grant_names_the_witness_context() {
        let hint = WitnessMessages.pnm_admin_command_hint("witness", "did:key:z6MkExample");
        assert!(hint.contains("pnm contexts create --id witness"), "{hint}");
        assert!(hint.contains("--admin-did did:key:z6MkExample"), "{hint}");
    }

    #[tokio::test]
    async fn phase1_writes_a_loadable_setup_key() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("witness-setup-key.json");
        run_phase1(&out, DEFAULT_CONTEXT).await.expect("phase 1");
        let key = EphemeralSetupKey::load_from(&out).expect("loadable");
        assert!(key.did.starts_with("did:key:z6Mk"), "{}", key.did);
    }
}
