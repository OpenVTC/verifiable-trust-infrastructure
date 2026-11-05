//! `cnm networks …` — the community's memberships of Verifiable Trust Networks
//! (`vtc/networks/{list,show,join,leave,repudiate}/0.2`, docs/03-vtc/networks.md).
//!
//! A network lists a community first (VTI-VTN-010) and sends its administrators the
//! network's URL and DID. `join` is the community's acknowledgement (VTI-VTN-013), and the
//! credential exchange: the community verifies the network's listing of it, registers a
//! group for each of the network's roles, signs the acknowledgement of the network's
//! offer, and verifies the grant the network answers with. `repudiate` rejects a listing;
//! `leave` departs by repudiating the grant. Every write needs `vtc.config.admin` and the
//! administrator's passkey gesture bound to the one document, asked for only once every
//! check that would refuse it has passed. The admin console's **Networks** page
//! (`/admin/networks`) does the same.

use clap::Subcommand;
use serde_json::{Value, json};
use vta_cli_common::render::{BOLD, DIM, RESET, is_json_output, print_json};
use vta_sdk::session::TransportChoice;
use vtc_client::git_ns::task_error;
use vtc_client::{HolderKey, VtcClient, VtcError};
use vti_specs::vtc::networks::{
    join::v0_2 as join, leave::v0_2 as leave, list::v0_2 as list, repudiate::v0_2 as repudiate,
    show::v0_2 as show,
};

use crate::git::{send_change, signing_key, terminal_safe};
use crate::vtc::{self as vtc_target, VtcTarget};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const LIST: &str = <list::Payload as trust_tasks_rs::Payload>::TYPE_URI;
const SHOW: &str = <show::Payload as trust_tasks_rs::Payload>::TYPE_URI;
const JOIN: &str = <join::Payload as trust_tasks_rs::Payload>::TYPE_URI;
const LEAVE: &str = <leave::Payload as trust_tasks_rs::Payload>::TYPE_URI;
const REPUDIATE: &str = <repudiate::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `cnm networks …`
#[derive(Subcommand)]
pub enum NetworksCommands {
    /// The networks this community is, or was, a member of.
    List,
    /// One membership, with the credentials that evidence it.
    Show {
        /// The network's DID.
        network: String,
    },
    /// Accept a network's listing of this community and become a member.
    Join {
        /// The network's URL, as its invitation gives it.
        url: String,
        /// The network's DID, as its invitation gives it.
        #[arg(long)]
        network: String,
        /// A group to serve one of the network's roles, `role=groupId`. Repeat for each
        /// role; every role the network requires needs one.
        #[arg(long = "group", value_name = "ROLE=GROUP_ID")]
        groups: Vec<String>,
    },
    /// Leave a network, by repudiating its membership grant.
    Leave {
        /// The network's DID.
        network: String,
        /// Kept in this community's audit trail; not sent to the network.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Reject a network's listing of this community (VTI-VTN-012).
    Repudiate {
        /// The network's URL.
        url: String,
        /// The network's DID.
        #[arg(long)]
        network: String,
        /// Kept in this community's audit trail; not sent to the network.
        #[arg(long)]
        reason: Option<String>,
    },
}

pub async fn run(
    command: NetworksCommands,
    keyring_key: &str,
    target: &VtcTarget,
    transport: TransportChoice,
) -> CliResult {
    let vtc = vtc_target::connect_for_tasks(keyring_key, target, transport).await?;
    let outcome = run_task(command, &vtc.client, keyring_key, target).await;
    vtc.client.shutdown().await;
    outcome
}

/// What a refusal means, and what to do about it.
fn hint(code: &str) -> &'static str {
    match code.rsplit(':').next().unwrap_or_default() {
        "notListed" => {
            "\nThe network does not list this community yet: ask its administrators to list \
             (invite) it first."
        }
        "networkMismatch" => {
            "\nThe network at that URL answers as another DID: check both against the invitation."
        }
        "roleUnassigned" => {
            "\nThe network requires a group for that role: add `--group <role>=<groupId>`, \
             naming a group with a DID of its own."
        }
        "unknownGroup" => "\nThat group does not exist here, or has no DID of its own yet.",
        "isMember" => "\nThis community is a member of that network: `cnm networks leave` instead.",
        "notMember" => "\nThis community is not a member of that network.",
        "permissionDenied" => "\nThis needs `vtc.config.admin` on this profile's entry.",
        _ => "",
    }
}

fn explain(err: VtcError) -> Box<dyn std::error::Error> {
    match task_error(&err) {
        Some((code, message)) => format!(
            "the community refused it ({}): {}{}",
            terminal_safe(&code),
            terminal_safe(&message),
            hint(&code)
        )
        .into(),
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

/// `role=groupId` pairs as `join`'s `groups`.
fn assignments(groups: &[String]) -> CliResult<Vec<Value>> {
    groups
        .iter()
        .map(|g| {
            let (role, group) = g
                .split_once('=')
                .filter(|(r, id)| !r.is_empty() && !id.is_empty())
                .ok_or_else(|| format!("`--group {g}`: expected `role=groupId`"))?;
            Ok(json!({ "role": role, "groupId": group }))
        })
        .collect()
}

fn print_membership(m: &Value, full: bool) {
    let state = match m["state"].as_str().unwrap_or_default() {
        "acknowledged" => "member",
        "repudiated" => "listing rejected",
        "departed" => "left",
        other => other,
    };
    println!(
        "{BOLD}{}{RESET}  {}  {DIM}{}{RESET}",
        terminal_safe(m["name"].as_str().unwrap_or("(unnamed network)")),
        terminal_safe(state),
        terminal_safe(m["network"].as_str().unwrap_or_default()),
    );
    println!(
        "  {DIM}{} · updated {}{RESET}",
        terminal_safe(m["url"].as_str().unwrap_or_default()),
        terminal_safe(m["updatedAt"].as_str().unwrap_or_default()),
    );
    for g in m["groups"].as_array().into_iter().flatten() {
        println!(
            "  {DIM}role{RESET} {} → {} {DIM}{}{RESET}",
            terminal_safe(g["role"].as_str().unwrap_or_default()),
            terminal_safe(g["groupId"].as_str().unwrap_or_default()),
            terminal_safe(g["groupDid"].as_str().unwrap_or_default()),
        );
    }
    if full {
        for (label, field) in [
            ("listing", "listing"),
            ("grant", "grant"),
            ("acknowledgement", "acknowledgement"),
            ("repudiation", "repudiation"),
        ] {
            if m[field].is_object() {
                println!(
                    "  {DIM}{label}{RESET} {}",
                    terminal_safe(m[field]["id"].as_str().unwrap_or("(held)"))
                );
            }
        }
    }
}

async fn run_task(
    command: NetworksCommands,
    client: &VtcClient,
    keyring_key: &str,
    target: &VtcTarget,
) -> CliResult {
    let (did, key) = signing_key(keyring_key)?;
    let v = match command {
        NetworksCommands::List => {
            let v = read(client, LIST, json!({ "limit": 100 }), &key).await?;
            if !is_json_output() {
                let items = v["items"].as_array().cloned().unwrap_or_default();
                if items.is_empty() {
                    println!("This community is in no network.");
                }
                for m in &items {
                    print_membership(m, false);
                }
                return Ok(());
            }
            v
        }
        NetworksCommands::Show { network } => {
            let v = read(client, SHOW, json!({ "network": network }), &key).await?;
            if !is_json_output() {
                print_membership(&v["membership"], true);
                return Ok(());
            }
            v
        }
        NetworksCommands::Join {
            url,
            network,
            groups,
        } => {
            let mut payload = json!({ "url": url.trim_end_matches('/'), "network": network });
            let groups = assignments(&groups)?;
            if !groups.is_empty() {
                payload["groups"] = json!(groups);
            }
            let payload = serde_json::to_value(serde_json::from_value::<join::Payload>(payload)?)?;
            send_change(client, &target.base, JOIN, &payload, &did, &key).await?
        }
        NetworksCommands::Leave { network, reason } => {
            let mut payload = json!({ "network": network });
            if let Some(r) = reason {
                payload["reason"] = json!(r);
            }
            let payload = serde_json::to_value(serde_json::from_value::<leave::Payload>(payload)?)?;
            send_change(client, &target.base, LEAVE, &payload, &did, &key).await?
        }
        NetworksCommands::Repudiate {
            url,
            network,
            reason,
        } => {
            let mut payload = json!({ "url": url.trim_end_matches('/'), "network": network });
            if let Some(r) = reason {
                payload["reason"] = json!(r);
            }
            let payload =
                serde_json::to_value(serde_json::from_value::<repudiate::Payload>(payload)?)?;
            send_change(client, &target.base, REPUDIATE, &payload, &did, &key).await?
        }
    };
    if is_json_output() {
        return Ok(print_json(&v)?);
    }
    print_membership(&v["membership"], true);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_assignments_read_role_equals_group() {
        assert_eq!(
            assignments(&["admins=g_1".into()]).unwrap(),
            vec![json!({ "role": "admins", "groupId": "g_1" })]
        );
        assert!(assignments(&["admins".into()]).is_err());
        assert!(assignments(&["=g_1".into()]).is_err());
    }

    #[test]
    fn refusals_say_what_to_do() {
        assert!(hint("vtc/networks/join:roleUnassigned").contains("--group"));
        assert!(hint("vtc/networks/join:notListed").contains("list"));
        assert_eq!(hint("vtc/networks/join:other"), "");
    }
}
