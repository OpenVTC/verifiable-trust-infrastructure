//! `pnm did-mgmt agent-names …` — bind and inspect agent names.
//!
//! An agent name is a human-memorable `domain/@name` that resolves to a DID.
//! Binding one edits the DID document's `alsoKnownAs` and republishes the
//! signed log; the hosting server then serves `/@name` as a redirect to the
//! DID — but *only* for a name the signed document claims, which it re-derives
//! from the log on every publish. So the claim in the document is not a hint,
//! it is the authorisation.
//!
//! That is one half of the binding. The other half — confirming a name leads
//! back to the DID that claims it — is what
//! [`vta_sdk::display_name::agent_name`] does on the reading side, and why
//! `--resolve-agent-names` exists.

use vta_sdk::prelude::*;

use crate::display::shorten_did;
use crate::render::{BOLD, CYAN, DIM, GREEN, RESET, YELLOW, is_json_output, print_json};

/// The full name as an operator would type or read it, e.g.
/// `webvh.storm.ws/@ops`.
///
/// Derived from the DID's host rather than asked for, because the domain is
/// not the operator's to choose — it is wherever the DID is hosted, and the
/// hosting server keys its index on exactly that.
fn qualified(did: &str, name: &str) -> String {
    match domain_of(did) {
        Some(domain) => format!("{domain}/@{name}"),
        None => format!("@{name}"),
    }
}

/// The host component of a `did:webvh` / `did:web` identifier.
///
/// `did:webvh:<scid>:<host>[:<path>…]`, with the host percent-decoded because
/// a port is encoded (`localhost%3A8534`).
fn domain_of(did: &str) -> Option<String> {
    let mut parts = did.split(':');
    if parts.next()? != "did" {
        return None;
    }
    let method = parts.next()?;
    if method != "webvh" && method != "web" {
        return None;
    }
    let _scid = parts.next()?;
    let host = parts.next()?;
    Some(host.replace("%3A", ":").replace("%3a", ":"))
}

pub async fn cmd_agent_name_set(
    client: &VtaClient,
    did: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.set_agent_name(did, name).await?;
    if is_json_output() {
        print_json(&result)?;
        return Ok(());
    }
    println!("{GREEN}\u{2713}{RESET} Agent name bound.");
    println!(
        "  {CYAN}Name:{RESET}   {BOLD}{}{RESET}",
        qualified(did, name)
    );
    println!("  {CYAN}DID:{RESET}    {did}");
    println!(
        "  {DIM}The DID document now claims this name; the hosting server \
         serves it as a redirect.{RESET}"
    );
    Ok(())
}

pub async fn cmd_agent_name_remove(
    client: &VtaClient,
    did: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.remove_agent_name(did, name).await?;
    if is_json_output() {
        print_json(&result)?;
        return Ok(());
    }
    println!(
        "{GREEN}\u{2713}{RESET} Agent name released: {}",
        qualified(did, name)
    );
    println!(
        "  {DIM}The claim is gone from the DID document and the name is free \
         for anyone to claim. Use `disable` instead to keep it reserved.{RESET}"
    );
    Ok(())
}

pub async fn cmd_agent_name_disable(
    client: &VtaClient,
    did: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.disable_agent_name(did, name).await?;
    if is_json_output() {
        print_json(&result)?;
        return Ok(());
    }
    println!(
        "{GREEN}\u{2713}{RESET} Agent name parked: {}",
        qualified(did, name)
    );
    println!(
        "  {DIM}It no longer resolves, but stays reserved to this DID. \
         Re-enable with `agent-names enable`.{RESET}"
    );
    Ok(())
}

pub async fn cmd_agent_name_enable(
    client: &VtaClient,
    did: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.enable_agent_name(did, name).await?;
    if is_json_output() {
        print_json(&result)?;
        return Ok(());
    }
    println!(
        "{GREEN}\u{2713}{RESET} Agent name back in service: {}",
        qualified(did, name)
    );
    Ok(())
}

pub async fn cmd_agent_name_list(
    client: &VtaClient,
    did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.list_agent_names(did).await?;
    if is_json_output() {
        print_json(&result)?;
        return Ok(());
    }

    if result.names.is_empty() {
        println!("No agent names bound to {}.", shorten_did(did));
        println!("  {DIM}Bind one with `agent-names set --did <did> --name <name>`.{RESET}");
        return Ok(());
    }

    println!();
    println!("{BOLD}Agent names for {}{RESET}", shorten_did(did));
    println!();
    for entry in &result.names {
        // A parked name is deliberately absent from the DID document, so it
        // would be invisible if we only read the document — this listing comes
        // from the hosting registry, which is why it can show them at all.
        let state = if entry.enabled {
            format!("{GREEN}resolves{RESET}")
        } else {
            format!("{YELLOW}parked{RESET}")
        };
        println!("  {BOLD}{}{RESET}  {state}", qualified(did, &entry.name));
    }
    println!();
    Ok(())
}

pub async fn cmd_agent_name_check(
    client: &VtaClient,
    did: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.check_agent_name(did, name).await?;
    if is_json_output() {
        print_json(&result)?;
        return Ok(());
    }

    let full = format!("{}/@{}", result.domain, result.name);
    if result.reserved {
        println!("{YELLOW}\u{2717}{RESET} {full} is reserved.");
        println!(
            "  {DIM}Reserved names (admin, api, support, …) are withheld to \
             make impersonation harder.{RESET}"
        );
    } else if result.available {
        println!("{GREEN}\u{2713}{RESET} {full} is available.");
        println!(
            "  {DIM}Advisory only — it can be taken before you bind it, so \
             `set` reports its own conflict.{RESET}"
        );
    } else {
        println!("{YELLOW}\u{2717}{RESET} {full} is taken.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_comes_from_the_did_not_the_operator() {
        assert_eq!(
            domain_of("did:webvh:QmScid:webvh.storm.ws:glenn-vta").as_deref(),
            Some("webvh.storm.ws")
        );
        assert_eq!(
            domain_of("did:web:QmScid:example.com").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn a_ported_host_is_percent_decoded() {
        // Hosting encodes the colon; rendering it raw would print a name no
        // operator could paste back.
        assert_eq!(
            domain_of("did:webvh:QmScid:localhost%3A8534").as_deref(),
            Some("localhost:8534")
        );
    }

    #[test]
    fn a_non_web_did_has_no_domain() {
        assert!(domain_of("did:key:z6MkfrQjWz").is_none());
        assert!(domain_of("not-a-did").is_none());
    }

    #[test]
    fn qualified_falls_back_to_the_bare_local_part() {
        // Better than inventing a domain we cannot derive.
        assert_eq!(qualified("did:key:z6MkfrQjWz", "ops"), "@ops");
        assert_eq!(
            qualified("did:webvh:QmScid:webvh.storm.ws", "ops"),
            "webvh.storm.ws/@ops"
        );
    }
}
