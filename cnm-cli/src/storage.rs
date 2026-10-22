//! `cnm storage …` — where the community keeps its rooms' files
//! (`vtc/storage/configs/*/0.2`, `vtc/storage/credentials/set/0.2`).
//!
//! Reads (`list`, `get`) answer a holder of `vtc.rooms.admin`. `credentials set` is the
//! discouraged fallback for a community with no VTA account: it seals a `sealed`
//! config's long-lived credential **here**, to the community's DID — the X25519
//! derivation of the Ed25519 key its own DID document lists — with `sealed_transfer`,
//! so no transport, relay or log between this terminal and the community can read it.
//! The community keeps it encrypted, shows it only as a fingerprint, and never returns
//! it. It does not protect the credential from whoever operates the community's
//! machine, which must be able to use it. Like every storage change it takes a passkey
//! gesture and is parked for another administrator's approval.

use std::io::Read;

use clap::Subcommand;
use serde_json::{Value, json};
use trust_tasks_rs::specs::vtc::storage::configs::{get::v0_2 as get, list::v0_2 as list};
use trust_tasks_rs::specs::vtc::storage::credentials::set::v0_2 as set;
use vta_cli_common::render::{BOLD, DIM, RESET, bin_name, is_json_output, print_json};
use vta_sdk::sealed_transfer::{
    AssertionProof, InMemoryNonceStore, ProducerAssertion, SealedPayloadV1,
    StorageCredentialPayload, armor, bundle_digest_multibase, seal_payload,
};
use vta_sdk::session::TransportChoice;
use vtc_client::git_ns::task_error;
use vtc_client::{HolderKey, VtcClient, VtcError};

use crate::git::{send_change, signing_key, terminal_safe};
use crate::vtc::{self as vtc_target, VtcTarget};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const LIST: &str = <list::Payload as trust_tasks_rs::Payload>::TYPE_URI;
const GET: &str = <get::Payload as trust_tasks_rs::Payload>::TYPE_URI;
const SET: &str = <set::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `cnm storage …`
#[derive(Subcommand)]
pub enum StorageCommands {
    /// Every storage config, with what it holds and how it authenticates.
    List,
    /// One storage config.
    Get {
        /// The config's identifier.
        config: String,
    },
    /// A `sealed` config's long-lived credential.
    Credentials {
        #[command(subcommand)]
        command: CredentialCommands,
    },
}

/// `cnm storage credentials …`
#[derive(Subcommand)]
pub enum CredentialCommands {
    /// Seal a `sealed` config's credential to the community and set it. Discouraged:
    /// prefer an external account at the community's VTA. The credential protects
    /// against every administrator, never against whoever operates the community's
    /// machine.
    Set {
        /// The config's identifier.
        #[arg(long)]
        config: String,
        /// A JSON file holding the credential, `-` for standard input: for `s3`
        /// `{"accessKeyId", "secretAccessKey"[, "sessionToken"]}`; for `gcs` the
        /// service-account key file exactly as Google issued it; for `walrus`
        /// `{"suiPrivateKey"}`.
        #[arg(long)]
        file: String,
        /// Why — recorded in the audit trail and shown to the approvers. Never a secret.
        #[arg(long)]
        reason: String,
    },
}

pub async fn run(
    command: StorageCommands,
    keyring_key: &str,
    target: &VtcTarget,
    transport: TransportChoice,
) -> CliResult {
    let vtc = vtc_target::connect_for_tasks(keyring_key, target, transport).await?;
    let outcome = run_task(command, &vtc.client, keyring_key, target).await;
    vtc.client.shutdown().await;
    outcome
}

fn explain(err: VtcError) -> Box<dyn std::error::Error> {
    match task_error(&err) {
        Some((code, message)) => {
            let hint = match code.as_str() {
                "vtc/storage/credentials/set:authNotAllowed" => {
                    "\nThe community's host does not permit `sealed`: its operator sets \
                     `[rooms.files.auth] sealed = true`, or the config moves to a VTA account."
                }
                "vtc/storage/credentials/set:notSealedMode" => {
                    "\nOnly a `sealed` config takes a credential here; a VTA account's is set \
                     at the VTA (`pnm external …`)."
                }
                "permissionDenied" => "\nThis needs `vtc.rooms.admin` on this profile's entry.",
                _ => "",
            };
            format!(
                "the community refused it ({}): {}{hint}",
                terminal_safe(&code),
                terminal_safe(&message)
            )
            .into()
        }
        None => err.to_string().into(),
    }
}

async fn read(
    client: &VtcClient,
    type_uri: &str,
    payload: Value,
    key: &HolderKey,
) -> CliResult<Value> {
    let doc = client.git_ns_sign(type_uri, &payload, key).await?;
    client
        .git_ns_send_signed::<Value>(type_uri, &doc)
        .await
        .map_err(explain)
}

/// How a config authenticates, never the credential.
fn credential_line(c: &Value) -> String {
    match c["status"].as_str().unwrap_or_default() {
        "vta-account" => format!(
            "VTA account {}/{}",
            terminal_safe(c["context"].as_str().unwrap_or("?")),
            terminal_safe(c["account"].as_str().unwrap_or("?"))
        ),
        "ambient" => "this machine's cloud identity".into(),
        "sealed" => format!(
            "stored credential {} (set {}) — recoverable by whoever operates the community's \
             machine",
            terminal_safe(c["fingerprint"].as_str().unwrap_or("?")),
            terminal_safe(c["setAt"].as_str().unwrap_or("?"))
        ),
        "required" => "credential required".into(),
        "notAllowed" => "a mode the community's host no longer permits: change its auth".into(),
        "none" => "none needed".into(),
        other => terminal_safe(other),
    }
}

fn print_config(item: &Value) {
    let c = &item["config"];
    let f = &item["facts"];
    println!(
        "{BOLD}{}{RESET}  {}  {DIM}{} · {}{RESET}",
        terminal_safe(c["id"].as_str().unwrap_or_default()),
        terminal_safe(c["label"].as_str().unwrap_or_default()),
        terminal_safe(c["settings"]["kind"].as_str().unwrap_or_default()),
        terminal_safe(c["state"].as_str().unwrap_or_default()),
    );
    if let Some(role) = c["auth"]["roleArn"].as_str() {
        println!("  {DIM}assumes {}{RESET}", terminal_safe(role));
    }
    println!(
        "  {DIM}{} rooms · {} files · credential: {}{RESET}",
        f["rooms"],
        f["files"],
        credential_line(&f["credential"])
    );
}

/// The X25519 key the community opens what is sealed to it with: the derivation of
/// the Ed25519 key its own DID document lists (`#key-0` first).
async fn community_x25519(did: &str) -> CliResult<[u8; 32]> {
    let resolver = vta_sdk::resolver::shared_did_resolver_from_env().await?;
    let resolved = resolver.resolve(did).await?;
    let doc = serde_json::to_value(&resolved.doc)?;
    let methods = doc["verificationMethod"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let ed25519 = |m: &Value| {
        m["publicKeyMultibase"]
            .as_str()
            .and_then(|mb| vta_sdk::did_key::decode_ed25519_public_key_multibase(mb).ok())
    };
    let key = methods
        .iter()
        .find(|m| m["id"].as_str().is_some_and(|i| i.ends_with("#key-0")))
        .and_then(ed25519)
        .or_else(|| methods.iter().find_map(ed25519))
        .ok_or_else(|| format!("{did}'s DID document lists no Ed25519 key to seal to"))?;
    vta_sdk::didcomm_light::ed25519_pub_to_x25519_pub(&key)
}

/// The `SealedStorageCredential` for `config` of `kind` from the operator's file: read
/// as the generated type, so a malformed one is refused before anything is sealed.
fn cleartext(kind: &str, config: &str, file: Value) -> CliResult<Value> {
    let mut v = match kind {
        "gcs" => json!({ "serviceAccountKey": file }),
        "s3" | "walrus" => file,
        other => return Err(format!("a `{other}` config takes no credential").into()),
    };
    let obj = v
        .as_object_mut()
        .ok_or("the credential file must hold a JSON object")?;
    obj.insert("kind".into(), json!(kind));
    obj.insert("configId".into(), json!(config));
    // Checked against the specification's type; never echoed on failure.
    serde_json::from_value::<set::SealedStorageCredential>(v.clone()).map_err(|_| {
        format!(
            "the file is not a `{kind}` credential: see `{} storage credentials set --help`",
            bin_name()
        )
    })?;
    Ok(v)
}

async fn run_task(
    command: StorageCommands,
    client: &VtcClient,
    keyring_key: &str,
    target: &VtcTarget,
) -> CliResult {
    let (did, key) = signing_key(keyring_key)?;
    match command {
        StorageCommands::List => {
            let v = read(client, LIST, json!({ "limit": 100 }), &key).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            for item in v["items"].as_array().cloned().unwrap_or_default() {
                print_config(&item);
            }
            Ok(())
        }
        StorageCommands::Get { config } => {
            let v = read(client, GET, json!({ "configId": config }), &key).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            print_config(&v);
            Ok(())
        }
        StorageCommands::Credentials {
            command:
                CredentialCommands::Set {
                    config,
                    file,
                    reason,
                },
        } => {
            let got = read(client, GET, json!({ "configId": config }), &key).await?;
            let kind = got["config"]["settings"]["kind"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            if got["config"]["auth"]["mode"] != "sealed" {
                return Err(format!(
                    "`{}` does not use `sealed` authentication; change its auth first",
                    terminal_safe(&config)
                )
                .into());
            }
            let mut text = String::new();
            if file == "-" {
                std::io::stdin().read_to_string(&mut text)?;
            } else {
                text = std::fs::read_to_string(&file)?;
            }
            let parsed: Value =
                serde_json::from_str(&text).map_err(|_| "the credential file is not JSON")?;
            let cleartext = cleartext(&kind, &config, parsed)?;
            let recipient = community_x25519(&target.did).await?;
            let bundle_id = uuid::Uuid::new_v4().into_bytes();
            let bundle = seal_payload(
                &recipient,
                bundle_id,
                ProducerAssertion {
                    producer_did: did.clone(),
                    // The request's own proof covers the block and its digest.
                    proof: AssertionProof::PinnedOnly,
                },
                &SealedPayloadV1::StorageCredential(Box::new(StorageCredentialPayload(cleartext))),
                &InMemoryNonceStore::new(),
            )
            .await?;
            let payload = json!({
                "configId": config,
                "sealed": armor::encode(&bundle),
                "digestMultibase": bundle_digest_multibase(&bundle),
                "reason": reason,
            });
            let payload = serde_json::to_value(serde_json::from_value::<set::Payload>(payload)?)?;
            let v = send_change(client, &target.base, SET, &payload, &did, &key).await?;
            if is_json_output() {
                return Ok(print_json(&v)?);
            }
            match v["credentialState"]["status"].as_str() {
                Some(_) => {
                    println!("Set: {}", credential_line(&v["credentialState"]));
                    if let Some(ok) = v["probeOk"].as_bool() {
                        println!(
                            "Probe with the new credential: {}",
                            if ok { "ok" } else { "failed" }
                        );
                    }
                }
                None => println!("Sent for approval."),
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_file_is_read_as_the_specification_s_type() {
        let s3 = cleartext(
            "s3",
            "r2",
            json!({ "accessKeyId": "AKID", "secretAccessKey": "s3cret" }),
        )
        .unwrap();
        assert_eq!(s3["kind"], "s3");
        assert_eq!(s3["configId"], "r2");
        let err = cleartext("s3", "r2", json!({ "secretAccessKey": "s3cret" }))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("s3cret"), "{err}");
        assert!(cleartext("local", "x", json!({})).is_err());
        let gcs = cleartext(
            "gcs",
            "g",
            json!({
                "type": "service_account",
                "client_email": "a@b.iam.gserviceaccount.com",
                "private_key_id": "abc",
                "private_key": format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", "A".repeat(64)),
            }),
        )
        .unwrap();
        assert_eq!(gcs["serviceAccountKey"]["type"], "service_account");
    }
}
