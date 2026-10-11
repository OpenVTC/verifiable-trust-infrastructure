//! `pnm external …` (and any CLI that adopts it) — external accounts: identities
//! a VTA holds at clouds and third-party services for the integrations bound to
//! them (`external/*/0.1`; design `docs/05-design-notes/vta-external-accounts.md`).
//!
//! Every request is built as the task's generated payload type, so a value the
//! schema refuses is caught here, with the schema's own words, before anything
//! is sent. Answers print as JSON: an account is a nested structure, and the
//! console that renders it nicely is the VTC's.
//!
//! A secret never appears on a command line. `secret-set` reads it from the
//! terminal without echo (or from stdin when piped), seals it in this process
//! to a single-use wrapping key the VTA hands out, and sends only the armor.

use std::io::{IsTerminal, Read};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use trust_tasks_rs::specs::external as ext;
use vta_sdk::prelude::*;

use crate::render::print_json;

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// Build a generated payload from JSON, refusing what its schema refuses.
fn payload<P: DeserializeOwned>(task: &str, v: Value) -> Result<P, Box<dyn std::error::Error>> {
    serde_json::from_value(v).map_err(|e| format!("{task}: the request is not valid: {e}").into())
}

/// Settings as JSON text, or `@path` to read them from a file.
fn settings_arg(raw: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let text = match raw.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?,
        None => raw.to_string(),
    };
    serde_json::from_str(&text).map_err(|e| format!("--settings is not JSON: {e}").into())
}

fn show<T: serde::Serialize>(v: &T) -> CliResult {
    print_json(v)?;
    Ok(())
}

/// `list`.
pub async fn cmd_list(
    client: &VtaClient,
    context: &str,
    state: Option<&str>,
    model: Option<&str>,
) -> CliResult {
    let mut v = json!({ "context": context });
    if let Some(s) = state {
        v["state"] = json!(s);
    }
    if let Some(m) = model {
        v["model"] = json!(m);
    }
    let req = payload::<ext::accounts::list::v0_1::Payload>("external/accounts/list", v)?;
    show(&client.external_accounts_list(&req).await?)
}

/// `get`.
pub async fn cmd_get(client: &VtaClient, context: &str, id: &str) -> CliResult {
    let req = payload::<ext::accounts::get::v0_1::Payload>(
        "external/accounts/get",
        json!({ "context": context, "id": id }),
    )?;
    show(&client.external_accounts_get(&req).await?)
}

/// `create`.
pub async fn cmd_create(
    client: &VtaClient,
    context: &str,
    id: &str,
    label: &str,
    settings: &str,
) -> CliResult {
    let req = payload::<ext::accounts::create::v0_1::Payload>(
        "external/accounts/create",
        json!({ "context": context, "id": id, "label": label, "settings": settings_arg(settings)? }),
    )?;
    show(&client.external_accounts_create(&req).await?)
}

/// `update`.
pub async fn cmd_update(
    client: &VtaClient,
    context: &str,
    id: &str,
    label: Option<&str>,
    settings: Option<&str>,
) -> CliResult {
    let mut v = json!({ "context": context, "id": id });
    if let Some(l) = label {
        v["label"] = json!(l);
    }
    if let Some(s) = settings {
        v["settings"] = settings_arg(s)?;
    }
    let req = payload::<ext::accounts::update::v0_1::Payload>("external/accounts/update", v)?;
    show(&client.external_accounts_update(&req).await?)
}

/// `secret-set`: read the secret without echo, seal it here, send the armor.
pub async fn cmd_secret_set(client: &VtaClient, context: &str, id: &str) -> CliResult {
    // The account's access key id goes inside the seal, so the VTA refuses a
    // secret that belongs to another key.
    let account = client
        .external_accounts_get(&payload(
            "external/accounts/get",
            json!({ "context": context, "id": id }),
        )?)
        .await?;
    let access_key_id = serde_json::to_value(&account.account.settings)?
        .get("accessKeyId")
        .and_then(Value::as_str)
        .map(str::to_string);
    let secret = zeroize::Zeroizing::new(if std::io::stdin().is_terminal() {
        dialoguer::Password::new()
            .with_prompt(format!("Secret for {context}/{id}"))
            .interact()?
    } else {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s.trim_end_matches(['\r', '\n']).to_string()
    });
    if secret.is_empty() {
        return Err("no secret was given".into());
    }
    let wrapping = client.get_wrapping_key().await?;
    let armored = vta_sdk::client::seal_external_secret(
        &wrapping.wrapping_key,
        context,
        id,
        &secret,
        access_key_id.as_deref(),
    )
    .await?;
    drop(secret);
    let req = payload::<ext::accounts::secret::set::v0_1::Payload>(
        "external/accounts/secret/set",
        json!({ "context": context, "id": id, "wrappingKeyId": wrapping.key_id, "sealedSecret": armored }),
    )?;
    show(&client.external_accounts_secret_set(&req).await?)
}

/// `bind`: grant (or replace) a consumer's binding.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_bind(
    client: &VtaClient,
    context: &str,
    id: &str,
    consumer: &str,
    prefixes: &[String],
    actions: &[String],
    max_ttl_seconds: u32,
    rate_per_minute: u32,
) -> CliResult {
    let mut binding = json!({
        "consumer": consumer,
        "maxTtlSeconds": max_ttl_seconds,
        "ratePerMinute": rate_per_minute,
    });
    if !prefixes.is_empty() || !actions.is_empty() {
        binding["scopeCeiling"] = json!({ "prefixes": prefixes, "actions": actions });
    }
    let req = payload::<ext::accounts::bindings::grant::v0_1::Payload>(
        "external/accounts/bindings/grant",
        json!({ "context": context, "id": id, "binding": binding }),
    )?;
    show(&client.external_accounts_bindings_grant(&req).await?)
}

/// `unbind`.
pub async fn cmd_unbind(client: &VtaClient, context: &str, id: &str, consumer: &str) -> CliResult {
    let req = payload::<ext::accounts::bindings::revoke::v0_1::Payload>(
        "external/accounts/bindings/revoke",
        json!({ "context": context, "id": id, "consumer": consumer }),
    )?;
    show(&client.external_accounts_bindings_revoke(&req).await?)
}

/// `setup`: what to do at the provider, with each artifact's content.
pub async fn cmd_setup(client: &VtaClient, context: &str, id: &str) -> CliResult {
    let req = payload::<ext::accounts::setup::v0_1::Payload>(
        "external/accounts/setup",
        json!({ "context": context, "id": id }),
    )?;
    show(&client.external_accounts_setup(&req).await?)
}

/// `probe`.
pub async fn cmd_probe(client: &VtaClient, context: &str, id: &str) -> CliResult {
    let req = payload::<ext::accounts::probe::v0_1::Payload>(
        "external/accounts/probe",
        json!({ "context": context, "id": id }),
    )?;
    show(&client.external_accounts_probe(&req).await?)
}

/// The lifecycle verbs, which share one shape.
#[derive(Debug, Clone, Copy)]
pub enum Lifecycle {
    Suspend,
    Resume,
    Archive,
    Restore,
    Delete,
}

/// `suspend` / `resume` / `archive` / `restore` / `delete`.
pub async fn cmd_lifecycle(
    client: &VtaClient,
    verb: Lifecycle,
    context: &str,
    id: &str,
    reason: Option<&str>,
) -> CliResult {
    let mut v = json!({ "context": context, "id": id });
    if let Some(r) = reason {
        v["reason"] = json!(r);
    }
    match verb {
        Lifecycle::Suspend => show(
            &client
                .external_accounts_suspend(&payload("external/accounts/suspend", v)?)
                .await?,
        ),
        Lifecycle::Resume => show(
            &client
                .external_accounts_resume(&payload("external/accounts/resume", v)?)
                .await?,
        ),
        Lifecycle::Archive => show(
            &client
                .external_accounts_archive(&payload("external/accounts/archive", v)?)
                .await?,
        ),
        Lifecycle::Restore => show(
            &client
                .external_accounts_restore(&payload("external/accounts/restore", v)?)
                .await?,
        ),
        Lifecycle::Delete => show(
            &client
                .external_accounts_delete(&payload("external/accounts/delete", v)?)
                .await?,
        ),
    }
}

/// `issue`: a credential for this CLI's own identity, as a bound consumer.
/// The answer is printed still sealed — it is for the consumer's process, and
/// a terminal is not where a provider credential should be opened.
pub async fn cmd_issue(
    client: &VtaClient,
    context: &str,
    account: &str,
    prefix: Option<&str>,
    actions: &[String],
    object_key: Option<&str>,
    ttl_seconds: u32,
) -> CliResult {
    let mut scope = json!({});
    if let Some(p) = prefix {
        scope["prefix"] = json!(p);
    }
    if !actions.is_empty() {
        scope["actions"] = json!(actions);
    }
    if let Some(k) = object_key {
        scope["objectKey"] = json!(k);
    }
    let req = payload::<ext::credentials::issue::v0_1::Payload>(
        "external/credentials/issue",
        json!({ "context": context, "account": account, "scope": scope, "ttlSeconds": ttl_seconds }),
    )?;
    show(&client.external_credentials_issue(&req).await?)
}
