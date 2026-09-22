//! `cnm did-log install` — hand a self-hosted community a new log for its own
//! DID (`did-management/did/register/0.1`, Keyring VTI-35).
//!
//! A community whose DID is `did:webvh:<scid>:<host>` serves its own
//! `did.jsonl`, but the VTA holds the keys that extend it and cannot reach the
//! community's copy. So after the VTA appends an entry — `pnm did-mgmt dids
//! edit` adding a transport, say — the operator fetches the log and delivers
//! it here. The community verifies it before serving it, so a log its key
//! holder did not sign is refused whoever delivers it.
//!
//! A community on a DID host needs none of this: the VTA publishes each new
//! entry to the host itself.

use std::path::{Path, PathBuf};

use clap::Subcommand;
use vta_cli_common::render::{BOLD, DIM, GREEN, RESET, bin_name};
use vtc_client::VtcClient;
use vtc_client::did_register::v0_1 as register;

use crate::auth;

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum DidLogCommands {
    /// Deliver the community DID's complete log, for it to verify and serve.
    ///
    /// Fetch the log from the VTA holding the DID's keys first:
    ///   pnm did-mgmt dids get-log <community-did> --out did.jsonl
    ///
    /// This authenticates to the community as this community profile's own DID,
    /// which needs a super-admin entry in the VTC's ACL (`vtc acl` on the VTC
    /// host). The community's URL is `https://<host>/v1` from its DID; pass
    /// `--url` before the subcommand to override it.
    Install {
        /// The complete did.jsonl — every entry from the first.
        #[arg(long)]
        file: PathBuf,
    },
}

pub async fn run(command: DidLogCommands, keyring_key: &str, url: Option<&str>) -> CliResult {
    match command {
        DidLogCommands::Install { file } => cmd_install(keyring_key, url, &file).await,
    }
}

/// The DID a log is for: the `id` in its last entry's document.
fn log_did(log: &str) -> Option<String> {
    let last = log.lines().rev().find(|l| !l.trim().is_empty())?;
    let entry: serde_json::Value = serde_json::from_str(last).ok()?;
    entry["state"]["id"].as_str().map(String::from)
}

/// `https://<host>/v1` for a root `did:webvh:<scid>:<host>` — the REST base a
/// self-hosted community serves (the `vtc-host` template's default). `None`
/// for a DID with a path: a DID host publishes that one.
fn community_api(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:webvh:")?;
    let parts: Vec<&str> = rest.split(':').collect();
    match parts.as_slice() {
        [scid, host] if !scid.is_empty() && !host.is_empty() => Some(format!(
            "https://{}/v1",
            host.replace("%3A", ":").replace("%3a", ":")
        )),
        _ => None,
    }
}

async fn cmd_install(keyring_key: &str, url: Option<&str>, file: &Path) -> CliResult {
    let log = std::fs::read_to_string(file).map_err(|e| format!("read {}: {e}", file.display()))?;
    let did = log_did(&log).ok_or_else(|| {
        format!(
            "{} is not a did:webvh log — its last line has no `state.id`",
            file.display()
        )
    })?;
    let base = match url {
        Some(u) => u.trim_end_matches('/').to_string(),
        None => community_api(&did).ok_or_else(|| {
            format!(
                "{did} has a path, so a DID host publishes its log, and the VTA already sent \
                 the new entry there. There is nothing to install."
            )
        })?,
    };
    let payload: register::Payload = register::Payload::builder()
        .path(".well-known")
        .method("webvh")
        .did_data(register::PayloadDidData::String(
            log.parse()
                .map_err(|e| format!("{}: {e}", file.display()))?,
        ))
        .force(false)
        .try_into()
        .map_err(|e| format!("build the register request: {e}"))?;

    // Not the profile's VTA session: that authenticates with the *VTA's* DID
    // as the audience, which a VTC refuses. The same identity, authenticated
    // to the community with the community's DID as the audience.
    let session = auth::loaded_session(keyring_key).ok_or_else(|| {
        format!(
            "no stored identity for this community profile. Run `{} setup` first.",
            bin_name()
        )
    })?;
    let vtc = VtcClient::connect(
        &base,
        &did,
        &session.client_did,
        &session.private_key_multibase,
    )
    .await
    .map_err(|e| {
        format!(
            "could not authenticate to {base} as {}: {e}\n\nThat DID needs a super-admin \
                 entry in the community's ACL — on the VTC host, `vtc acl` can add it.",
            session.client_did
        )
    })?;
    let response = vtc.install_did_log(&payload).await.map_err(|e| {
        format!(
            "{e}\n\nThe community refuses a log that does not verify, is for another DID, or \
             drops or rewrites an entry it serves. Fetch the current log with \
             `pnm did-mgmt dids get-log {did} --out did.jsonl` and retry."
        )
    })?;
    let record = &response.record;
    println!("{GREEN}DID log installed.{RESET}");
    println!("  {BOLD}DID{RESET}        {did}");
    println!("  {BOLD}Entries{RESET}    {}", record.version_count);
    if let Some(url) = &record.did_url {
        println!("  {BOLD}Served at{RESET}  {url}");
    }
    println!(
        "  {DIM}Served now, with no restart. Resolvers see the new version as their cache \
         expires.{RESET}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{community_api, log_did};

    #[test]
    fn a_root_did_names_its_api_and_a_pathful_one_does_not() {
        assert_eq!(
            community_api("did:webvh:Qm:vtc.example.com").as_deref(),
            Some("https://vtc.example.com/v1")
        );
        assert_eq!(
            community_api("did:webvh:Qm:localhost%3A8100").as_deref(),
            Some("https://localhost:8100/v1")
        );
        assert_eq!(community_api("did:webvh:Qm:dids.example.com:vtc"), None);
    }

    #[test]
    fn the_log_names_its_did() {
        let log =
            "{\"state\":{\"id\":\"did:webvh:Qm:a\"}}\n{\"state\":{\"id\":\"did:webvh:Qm:b\"}}\n\n";
        assert_eq!(log_did(log).as_deref(), Some("did:webvh:Qm:b"));
        assert_eq!(log_did("not json"), None);
    }
}
