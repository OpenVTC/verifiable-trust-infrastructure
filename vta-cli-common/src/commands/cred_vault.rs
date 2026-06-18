//! `cred-vault …` operator/agent commands (online, via the trust-task
//! dispatcher) for the **credential store** — the W3C credentials a holder
//! *holds* (invitations, memberships, roles, …), distinct from the
//! password-manager `vault` commands.
//!
//! Thin wrappers over the `VtaClient::cred_vault_*` methods. Credential bodies
//! are presentable VCs (plain JSON), so — unlike the secrets `vault` — there
//! is no sealed envelope to build or open here.
//!
//! Capability gates (server-side): query/get → `VaultRead`, receive →
//! `VaultWrite`, archive/unarchive/delete/restore/purge → `CredentialWrite`.

use serde_json::Value;
use vta_sdk::client::VtaClient;

use crate::render::{DIM, RESET, is_json_output, print_json};

fn print_result(label: &str, value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    if is_json_output() {
        print_json(value)?;
    } else {
        println!("{label}");
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

/// `cred-vault receive` — verify + store a received credential. `credential`
/// is the VC JSON; `id` overrides the storage id (defaults to the VC's `id`).
pub async fn cmd_cred_receive(
    client: &VtaClient,
    credential: Value,
    id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.cred_vault_receive(credential, id.as_deref()).await?;
    print_result("Stored credential:", &result)
}

/// `cred-vault query` — filtered search over held credentials. `filter` is a
/// DCQL-shaped object (at least one of `type`, `communityDid`, `issuerDid`,
/// `purpose`, `status`); an unfiltered query is refused server-side.
pub async fn cmd_cred_query(
    client: &VtaClient,
    filter: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.cred_vault_query(filter).await?;
    print_result("Credentials:", &result)
}

/// `cred-vault get` — fetch one held credential's full body by id.
pub async fn cmd_cred_get(
    client: &VtaClient,
    id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.cred_vault_get(&id).await?;
    print_result("Credential:", &result)
}

/// `cred-vault archive` — soft-disable a credential (restorable with
/// `cred-vault unarchive`).
pub async fn cmd_cred_archive(
    client: &VtaClient,
    id: String,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.cred_vault_archive(&id, reason.as_deref()).await?;
    println!("{DIM}Credential {id} archived — restore with `cred-vault unarchive {id}`.{RESET}");
    print_result("Result:", &result)
}

/// `cred-vault unarchive` — return an archived credential to active.
pub async fn cmd_cred_unarchive(
    client: &VtaClient,
    id: String,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.cred_vault_unarchive(&id, reason.as_deref()).await?;
    println!("{DIM}Credential {id} unarchived.{RESET}");
    print_result("Result:", &result)
}

/// `cred-vault delete` — recoverable soft-delete by default; `force`
/// hard-deletes irreversibly.
pub async fn cmd_cred_delete(
    client: &VtaClient,
    id: String,
    force: bool,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client
        .cred_vault_delete(&id, force, reason.as_deref())
        .await?;
    if force {
        println!("{DIM}Credential {id} permanently hard-deleted (no recovery).{RESET}");
    } else {
        let grace = result.get("graceUntil").and_then(Value::as_str);
        match grace {
            Some(g) => println!(
                "{DIM}Credential {id} moved to trash — recoverable with `cred-vault restore {id}` until {g}.{RESET}"
            ),
            None => println!(
                "{DIM}Credential {id} soft-deleted — recoverable with `cred-vault restore {id}`.{RESET}"
            ),
        }
    }
    print_result("Result:", &result)
}

/// `cred-vault restore` — undelete a soft-deleted credential (only within the
/// grace window).
pub async fn cmd_cred_restore(
    client: &VtaClient,
    id: String,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.cred_vault_restore(&id, reason.as_deref()).await?;
    println!("{DIM}Credential {id} restored to active.{RESET}");
    print_result("Result:", &result)
}

/// `cred-vault purge` — irreversibly hard-delete a credential, skipping any
/// grace window.
pub async fn cmd_cred_purge(
    client: &VtaClient,
    id: String,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.cred_vault_purge(&id, reason.as_deref()).await?;
    println!("{DIM}Credential {id} permanently purged (no recovery).{RESET}");
    print_result("Result:", &result)
}
