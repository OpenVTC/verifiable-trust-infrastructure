//! `did:webs` DIDs (`vta/webs/dids/*/0.1`): create, show, list, update, rotate
//! and deactivate a persona, relationship or integration DID on KERI. Alpha.
//!
//! `create`, `update` and `rotate` each append to a public key event log, so
//! they run under [`VtaClient::idempotent`]: a lost reply is answered from the
//! VTA's record of the first attempt, never executed twice.
//!
//! A refusal the operator can fix (`methodDisabled`, `hostDoesNotHostWebs`, …)
//! prints its fix (`vta_sdk::client::webs_refusal_fix`, via
//! `render::print_cli_error`).

use serde_json::{Value, json};
use vta_sdk::client::VtaClient;
use vti_specs::vta::webs::dids;

use crate::render::{is_json_output, print_json};

type CmdResult = Result<(), Box<dyn std::error::Error>>;

fn payload<T: serde::de::DeserializeOwned>(
    task: &str,
    v: Value,
) -> Result<T, Box<dyn std::error::Error>> {
    serde_json::from_value(v).map_err(|e| format!("invalid {task} request: {e}").into())
}

/// The arguments of `webs create`.
#[derive(Debug, Default, Clone)]
pub struct CreateArgs {
    pub context: String,
    pub server: String,
    pub path: Option<String>,
    pub domain: Option<String>,
    pub label: Option<String>,
    pub didcomm: bool,
    pub tsp: Option<bool>,
    pub also_known_as: Vec<String>,
    pub set_primary: bool,
}

pub async fn cmd_webs_create(client: &VtaClient, args: CreateArgs) -> CmdResult {
    let mut v = json!({
        "contextId": args.context,
        "serverId": args.server,
        "addMediatorService": args.didcomm,
        "setPrimary": args.set_primary,
    });
    for (k, val) in [
        ("path", &args.path),
        ("domain", &args.domain),
        ("label", &args.label),
    ] {
        if let Some(val) = val {
            v[k] = json!(val);
        }
    }
    if let Some(tsp) = args.tsp {
        v["addTspService"] = json!(tsp);
    }
    if !args.also_known_as.is_empty() {
        v["alsoKnownAs"] = json!(args.also_known_as);
    }
    let req: dids::create::v0_1::Payload = payload("create", v)?;
    let r = client.idempotent(|| client.create_did_webs(&req)).await?;
    if is_json_output() {
        print_json(&r)?;
        return Ok(());
    }
    println!("did:webs created (alpha):");
    println!("  DID:            {}", *r.did);
    println!("  Context:        {}", r.context_id);
    println!("  Hosted at:      {}", r.keri_cesr_url);
    println!("  Signing key:    {}", r.signing_key_id);
    println!("  Key agreement:  {}", r.key_agreement_key_id);
    println!("  Version:        {}", *r.version_id);
    if !r.service_ids.is_empty() {
        println!("  Services:       {}", r.service_ids.join(", "));
    }
    Ok(())
}

pub async fn cmd_webs_get(client: &VtaClient, did: &str, keri_cesr: bool) -> CmdResult {
    let req: dids::get::v0_1::Payload =
        payload("get", json!({ "did": did, "includeKeriCesr": keri_cesr }))?;
    let r = client.get_did_webs(&req).await?;
    if is_json_output() {
        print_json(&r)?;
        return Ok(());
    }
    let rec = serde_json::to_value(&r.record)?;
    let field = |k: &str| rec.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    println!("did:webs:");
    println!("  DID:            {}", field("did"));
    println!("  Context:        {}", field("contextId"));
    println!("  Server:         {}", field("serverId"));
    println!("  Hosted at:      {}", field("keriCesrUrl"));
    println!("  Version:        {}", field("versionId"));
    println!("  Signing key:    {}", field("signingKeyId"));
    println!("  Key agreement:  {}", field("keyAgreementKeyId"));
    let deactivated = rec.get("deactivated").and_then(Value::as_bool) == Some(true);
    println!(
        "  Deactivated:    {}",
        if deactivated { "yes" } else { "no" }
    );
    if r.rotation_staged == Some(true) {
        println!("  A rotation is staged; the next write completes it.");
    }
    if let Some(stream) = r.keri_cesr {
        println!("\n{stream}");
    }
    Ok(())
}

pub async fn cmd_webs_list(
    client: &VtaClient,
    context: Option<&str>,
    server: Option<&str>,
    include_deactivated: bool,
) -> CmdResult {
    let mut cursor: Option<String> = None;
    let mut all = Vec::new();
    loop {
        let mut v = json!({ "includeDeactivated": include_deactivated });
        if let Some(c) = context {
            v["contextId"] = json!(c);
        }
        if let Some(s) = server {
            v["serverId"] = json!(s);
        }
        if let Some(c) = &cursor {
            v["cursor"] = json!(c);
        }
        let req: dids::list::v0_1::Payload = payload("list", v)?;
        let page = client.list_dids_webs(&req).await?;
        for d in &page.dids {
            all.push(serde_json::to_value(d)?);
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    if is_json_output() {
        print_json(&json!({ "dids": all }))?;
        return Ok(());
    }
    if all.is_empty() {
        println!("No did:webs DIDs found.");
        return Ok(());
    }
    for d in &all {
        let s = |k: &str| d.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let gone = if d.get("deactivated").and_then(Value::as_bool) == Some(true) {
            "  (deactivated)"
        } else {
            ""
        };
        println!("{}  [{}]{gone}", s("did"), s("contextId"));
    }
    Ok(())
}

/// The arguments of `webs update`.
#[derive(Debug, Default, Clone)]
pub struct UpdateArgs {
    pub did: String,
    /// The whole service set, when given: `#didcomm` and/or `#tsp`.
    pub services: Option<(bool, bool)>,
    pub rotate_key_agreement: bool,
    /// The further aliases, replacing those in force, when given.
    pub also_known_as: Option<Vec<String>>,
    pub expected_version: Option<String>,
}

pub async fn cmd_webs_update(client: &VtaClient, args: UpdateArgs) -> CmdResult {
    let mut v = json!({ "did": args.did });
    if let Some((mediator, tsp)) = args.services {
        v["services"] = json!({ "mediator": mediator, "tsp": tsp });
    }
    if args.rotate_key_agreement {
        v["rotateKeyAgreementKey"] = json!(true);
    }
    if let Some(aliases) = args.also_known_as {
        v["alsoKnownAs"] = json!(aliases);
    }
    if let Some(e) = args.expected_version {
        v["expectedVersionId"] = json!(e);
    }
    let req: dids::update::v0_1::Payload = payload("update", v)?;
    let r = client.idempotent(|| client.update_did_webs(&req)).await?;
    if is_json_output() {
        print_json(&r)?;
        return Ok(());
    }
    let replaced: Vec<String> = serde_json::to_value(&r.replaced)?
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    println!("did:webs updated: {}", r.did);
    println!("  Replaced:       {}", replaced.join(", "));
    println!("  Version:        {}", *r.version_id);
    println!("  Key agreement:  {}", r.key_agreement_key_id);
    println!("  Services:       {}", r.service_ids.join(", "));
    Ok(())
}

pub async fn cmd_webs_rotate(
    client: &VtaClient,
    did: &str,
    expected_version: Option<&str>,
) -> CmdResult {
    let mut v = json!({ "did": did });
    if let Some(e) = expected_version {
        v["expectedVersionId"] = json!(e);
    }
    let req: dids::rotate_keys::v0_1::Payload = payload("rotate-keys", v)?;
    let r = client
        .idempotent(|| client.rotate_did_webs_keys(&req))
        .await?;
    if is_json_output() {
        print_json(&r)?;
        return Ok(());
    }
    println!(
        "did:webs keys rotated{}: {}",
        if r.resumed {
            " (a staged rotation, completed)"
        } else {
            ""
        },
        r.did
    );
    println!("  Signing key:    {}", r.signing_key_id);
    println!("  Retired:        {}", r.retired_key_id);
    println!("  Version:        {}", *r.version_id);
    Ok(())
}

pub async fn cmd_webs_delete(
    client: &VtaClient,
    did: &str,
    expected_version: Option<&str>,
) -> CmdResult {
    let mut v = json!({ "did": did });
    if let Some(e) = expected_version {
        v["expectedVersionId"] = json!(e);
    }
    let req: dids::delete::v0_1::Payload = payload("delete", v)?;
    let r = client.delete_did_webs(&req).await?;
    if is_json_output() {
        print_json(&r)?;
        return Ok(());
    }
    if r.newly_deactivated {
        println!("did:webs deactivated for good: {}", r.did);
    } else {
        println!("did:webs was already deactivated: {}", r.did);
    }
    if r.slot_removed {
        println!("  Its slot was removed from the hosting server.");
    } else if let Some(e) = r.host_cleanup_error {
        println!("  The hosting server did not remove its slot: {e}");
        println!("  Run the same delete again to retry the removal.");
    }
    Ok(())
}
