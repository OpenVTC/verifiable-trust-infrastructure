//! `vault …` operator/agent commands (online, via the trust-task dispatcher).
//!
//! Thin wrappers over the `VtaClient::vault_*` methods plus the seal/open
//! helpers. Secret-bearing operations use `didcomm-authcrypt` sealed envelopes
//! and therefore require the DIDComm transport (the seal is produced with the
//! caller's own keys):
//! - `upsert` seals the cleartext secret to the VTA before sending.
//! - `release` opens the JWE the VTA seals back to the caller.
//!
//! Capability gates (server-side): list/get → `VaultRead`, upsert/delete →
//! `VaultWrite`, release → `FillRelease`, proxy-login → `ProxyLogin`,
//! sign-trust-task → `SignTrustTask`.

use serde_json::{Value, json};
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

/// `vault list` — metadata only (no secrets). `filters` is the wire filter
/// object (`None` → all entries).
pub async fn cmd_vault_list(
    client: &VtaClient,
    filters: Option<Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client
        .vault_list(filters.unwrap_or_else(|| json!({})))
        .await?;
    print_result("Vault entries:", &result)
}

/// `vault get` — a single entry's metadata by id.
pub async fn cmd_vault_get(
    client: &VtaClient,
    id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.vault_get(&id).await?;
    print_result("Vault entry:", &result)
}

/// `vault delete` — delete an entry by id, with optional optimistic-concurrency
/// version check.
pub async fn cmd_vault_delete(
    client: &VtaClient,
    id: String,
    expected_version: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.vault_delete(&id, expected_version).await?;
    println!("{DIM}Vault entry {id} deleted.{RESET}");
    print_result("Result:", &result)
}

/// `vault upsert` — create/update an entry. `entry` is the entry-fields payload
/// (`contextId`, `targets`, `label`, `secretKind`, …); `secret`, when present,
/// is the cleartext `VaultSecret` JSON, sealed here to the VTA before sending.
///
/// Sealing requires the DIDComm transport — a clear error is returned on REST.
pub async fn cmd_vault_upsert(
    client: &VtaClient,
    entry: Value,
    secret: Option<Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sealed_secret = match secret {
        Some(s) => {
            let jwe = client.seal_vault_secret(s).await?;
            Some(json!({ "envelope": "didcomm-authcrypt", "jwe": jwe }))
        }
        None => None,
    };
    let result = client.vault_upsert(entry, sealed_secret).await?;
    print_result("Upserted entry:", &result)
}

/// `vault release` — release a secret sealed to the caller. Fetches the sealed
/// envelope, opens it locally, and prints the cleartext `VaultSecret`. `target`
/// is the optional site target the release is scoped to.
pub async fn cmd_vault_release(
    client: &VtaClient,
    id: String,
    target: Option<Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = json!({ "id": id });
    if let Some(t) = target {
        payload["target"] = t;
    }
    let response = client.vault_release(payload).await?;

    // The released secret rides in a `didcomm-authcrypt` envelope; open it with
    // the caller's keys. Walk the documented shape
    // (`sealedSecret.jwe`) and fall back to printing the raw response if the
    // VTA emitted an envelope variant this client can't open.
    let jwe = response
        .get("sealedSecret")
        .and_then(|s| s.get("jwe"))
        .and_then(|j| j.as_str());
    match jwe {
        Some(jwe) => {
            let secret = client.open_sealed_secret(jwe).await?;
            print_result("Released secret (cleartext):", &secret)
        }
        None => {
            eprintln!("{DIM}(no didcomm-authcrypt sealedSecret in response — printing raw){RESET}");
            print_result("Release response:", &response)
        }
    }
}

/// `vault proxy-login` — mint a session as the entry's principal. `payload` is
/// the full wire request (entry id + login parameters).
pub async fn cmd_vault_proxy_login(
    client: &VtaClient,
    payload: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.vault_proxy_login(payload).await?;
    print_result("Proxy-login result:", &result)
}

/// `vault sign-trust-task` — sign a Trust Task envelope as the entry's
/// principal DID. `payload` is the full wire request (entry id + envelope).
pub async fn cmd_vault_sign_trust_task(
    client: &VtaClient,
    payload: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.vault_sign_trust_task(payload).await?;
    print_result("Signed envelope:", &result)
}
