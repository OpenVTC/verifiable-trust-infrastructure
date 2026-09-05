//! `persona …` operator commands — the holder's own identity.
//!
//! Thin wrappers over the `VtaClient::persona_*` methods, with one exception
//! worth knowing about before reading further: [`cmd_disclosure_preview`]
//! renders its response rather than dumping it, because that response is the
//! only thing standing between an automated request and the holder's name
//! leaving the machine. Everything else prints the payload.
//!
//! ## Scope, and the error an operator will actually hit
//!
//! Eleven of these are holder-scoped — the attribute pool, profiles,
//! correlation, renderers — and the VTA requires *unrestricted* authority for
//! them. An operator whose credential is scoped to one trust context gets
//! `e.p.msg.forbidden`, and that is the boundary working: the pool sits above
//! every context and is not any one context's to read. The context-scoped
//! commands all take `--context`.

use serde_json::Value;
use vta_sdk::client::VtaClient;
use vta_sdk::protocols::persona::{
    ContactDocument, LocalProfileEntry, ProfileEntry, Provenance, ValueType,
};

use crate::render::{BOLD, CYAN, DIM, RED, RESET, YELLOW, is_json_output, print_json};

type CmdResult = Result<(), Box<dyn std::error::Error>>;

fn print_result(label: &str, value: &Value) -> CmdResult {
    if is_json_output() {
        print_json(value)?;
    } else {
        println!("{label}");
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The pool
// ---------------------------------------------------------------------------

/// `persona attribute put` — store one fact about the holder.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_attribute_put(
    client: &VtaClient,
    claim_type: String,
    value: Value,
    value_type: ValueType,
    provenance: Provenance,
    label: Option<String>,
    attribute_id: Option<String>,
    expected_version: Option<u64>,
) -> CmdResult {
    let result = client
        .persona_attribute_put(
            &claim_type,
            value,
            value_type,
            provenance,
            label.as_deref(),
            attribute_id.as_deref(),
            expected_version,
        )
        .await?;
    print_result("Attribute:", &result)
}

/// `persona attribute list` — enumerate the pool.
///
/// Metadata-only unless `--values` is given. The default is not timidity: a
/// listing that returns values is a read of the holder's identity, and the
/// command that does it should be the one the operator typed on purpose.
pub async fn cmd_attribute_list(
    client: &VtaClient,
    type_prefix: Option<String>,
    include_values: bool,
    include_stale: Option<bool>,
    limit: Option<std::num::NonZeroU64>,
    cursor: Option<String>,
) -> CmdResult {
    let result = client
        .persona_attribute_list(
            type_prefix.as_deref(),
            include_values,
            include_stale,
            limit,
            cursor.as_deref(),
        )
        .await?;
    if !is_json_output() && !include_values {
        println!("{DIM}Metadata only — add --values to include the values themselves.{RESET}");
    }
    print_result("Attributes:", &result)
}

/// `persona attribute delete` — remove one attribute.
pub async fn cmd_attribute_delete(
    client: &VtaClient,
    attribute_id: String,
    cascade: bool,
    expected_version: Option<u64>,
) -> CmdResult {
    let result = client
        .persona_attribute_delete(&attribute_id, cascade, expected_version)
        .await?;
    if !is_json_output() && cascade {
        println!("{DIM}Cascaded: profile entries referencing {attribute_id} were removed.{RESET}");
    }
    print_result("Result:", &result)
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

/// `persona profile put` — create or update a projection over the pool.
pub async fn cmd_profile_put(
    client: &VtaClient,
    name: String,
    entries: Vec<ProfileEntry>,
    credential_refs: Vec<String>,
    profile_id: Option<String>,
    expected_version: Option<u64>,
) -> CmdResult {
    let result = client
        .persona_profile_put(
            &name,
            entries,
            credential_refs,
            profile_id.as_deref(),
            expected_version,
        )
        .await?;
    print_result("Profile:", &result)
}

/// `persona profile get` — read one profile.
pub async fn cmd_profile_get(client: &VtaClient, profile_id: String, resolve: bool) -> CmdResult {
    let result = client.persona_profile_get(&profile_id, resolve).await?;
    if !is_json_output() && !resolve {
        println!(
            "{DIM}Showing how the profile is built — add --resolve to see what it would present.{RESET}"
        );
    }
    print_result("Profile:", &result)
}

/// `persona profile list` — enumerate profiles.
pub async fn cmd_profile_list(
    client: &VtaClient,
    limit: Option<std::num::NonZeroU64>,
    cursor: Option<String>,
) -> CmdResult {
    let result = client
        .persona_profile_list(limit, cursor.as_deref())
        .await?;
    print_result("Profiles:", &result)
}

/// `persona profile delete` — remove a profile.
pub async fn cmd_profile_delete(
    client: &VtaClient,
    profile_id: String,
    unbind: bool,
    expected_version: Option<u64>,
) -> CmdResult {
    let result = client
        .persona_profile_delete(&profile_id, unbind, expected_version)
        .await?;
    if !is_json_output() && unbind {
        println!(
            "{YELLOW}Unbound: every persona presenting under {profile_id} now presents nothing until rebound.{RESET}"
        );
    }
    print_result("Result:", &result)
}

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

/// `persona binding set` — decide what a context sees.
pub async fn cmd_binding_set(
    client: &VtaClient,
    context_id: String,
    persona_did: String,
    profile_id: Option<String>,
    public_entries: Vec<String>,
    expected_version: Option<u64>,
) -> CmdResult {
    let clearing = profile_id.is_none();
    let result = client
        .persona_binding_set(
            &context_id,
            &persona_did,
            profile_id.as_deref(),
            public_entries,
            expected_version,
        )
        .await?;
    if !is_json_output() {
        if clearing {
            println!(
                "{DIM}Binding cleared — {persona_did} now presents nothing in {context_id}.{RESET}"
            );
        } else {
            println!(
                "{DIM}A copy of the profile's values was written into {context_id}. Editing the \
                 pool refreshes it; nothing inside the context can read back the other way.{RESET}"
            );
        }
    }
    print_result("Binding:", &result)
}

/// `persona binding get` — what one persona presents in one context.
pub async fn cmd_binding_get(
    client: &VtaClient,
    context_id: String,
    persona_did: String,
) -> CmdResult {
    let result = client
        .persona_binding_get(&context_id, &persona_did)
        .await?;
    print_result("Binding:", &result)
}

/// `persona binding list` — every persona bound in one context.
pub async fn cmd_binding_list(
    client: &VtaClient,
    context_id: String,
    limit: Option<std::num::NonZeroU64>,
    cursor: Option<String>,
) -> CmdResult {
    let result = client
        .persona_binding_list(&context_id, limit, cursor.as_deref())
        .await?;
    print_result("Bindings:", &result)
}

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

/// `persona contact put` — record what someone disclosed.
pub async fn cmd_contact_put(
    client: &VtaClient,
    context_id: String,
    subject_did: String,
    known_by_persona: String,
    document: ContactDocument,
    credential_refs: Vec<String>,
    notes: Option<String>,
) -> CmdResult {
    let result = client
        .persona_contact_put(
            &context_id,
            &subject_did,
            &known_by_persona,
            document,
            credential_refs,
            notes.as_deref(),
        )
        .await?;
    print_result("Contact:", &result)
}

/// `persona contact get` — read one contact.
pub async fn cmd_contact_get(
    client: &VtaClient,
    context_id: String,
    contact_id: String,
    rev: Option<std::num::NonZeroU64>,
    include_history: bool,
) -> CmdResult {
    let result = client
        .persona_contact_get(&context_id, &contact_id, rev, include_history)
        .await?;
    print_result("Contact:", &result)
}

/// `persona contact list` — enumerate contacts.
pub async fn cmd_contact_list(
    client: &VtaClient,
    context_id: String,
    known_by_persona: Option<String>,
    changed_since: Option<String>,
    limit: Option<std::num::NonZeroU64>,
    cursor: Option<String>,
) -> CmdResult {
    let result = client
        .persona_contact_list(
            &context_id,
            known_by_persona.as_deref(),
            changed_since.as_deref(),
            limit,
            cursor.as_deref(),
        )
        .await?;
    print_result("Contacts:", &result)
}

/// `persona contact delete` — forget a contact.
pub async fn cmd_contact_delete(
    client: &VtaClient,
    context_id: String,
    contact_id: String,
) -> CmdResult {
    let result = client
        .persona_contact_delete(&context_id, &contact_id)
        .await?;
    print_result("Result:", &result)
}

// ---------------------------------------------------------------------------
// Disclosure
// ---------------------------------------------------------------------------

/// `persona disclosure preview` — what would this reveal, and to whom?
///
/// Signs nothing and sends nothing. This is the only place the holder sees
/// what is about to leave, so the response is rendered rather than dumped —
/// and rendered by *rank*, not as a flat list. A preview that shows fourteen
/// fields with fourteen equal weights is a notice-and-consent dialog, which is
/// the pattern that teaches people to click through.
pub async fn cmd_disclosure_preview(
    client: &VtaClient,
    context_id: String,
    persona_did: String,
    verifier_did: String,
    requested_claims: Vec<String>,
    purpose: Option<String>,
    renderer: Option<String>,
) -> CmdResult {
    let result = client
        .persona_disclosure_preview(
            &context_id,
            &persona_did,
            &verifier_did,
            requested_claims,
            purpose.as_deref(),
            renderer.as_deref(),
        )
        .await?;

    if is_json_output() {
        print_json(&result)?;
        return Ok(());
    }
    render_preview(&result, &context_id, &verifier_did, purpose.as_deref());
    Ok(())
}

/// Render a preview for a human, falling back to the raw payload if the
/// response is not the shape this function knows how to read.
///
/// The fallback is the point. A renderer that quietly showed an empty claim
/// table on an unfamiliar response would tell the holder "nothing will be
/// disclosed" about a disclosure that is about to happen — the one lie this
/// screen must not tell. Better an ugly payload than a confident wrong
/// summary.
fn render_preview(result: &Value, context_id: &str, verifier_did: &str, purpose: Option<&str>) {
    let (Some(preview_id), Some(claims)) = (
        result.get("previewId").and_then(Value::as_str),
        result.get("claims").and_then(Value::as_array),
    ) else {
        println!(
            "{YELLOW}Preview response was not in the expected shape; showing it as received.{RESET}"
        );
        println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_else(|_| format!("{result:?}"))
        );
        return;
    };

    println!();
    println!("{BOLD}Disclosure preview{RESET} — nothing has been sent.");
    println!();
    println!("  {DIM}To{RESET}         {verifier_did}");
    println!("  {DIM}Context{RESET}    {context_id}");
    if let Some(p) = purpose {
        println!("  {DIM}Purpose{RESET}    {p}");
    }
    if let Some(subject) = result.get("subject").and_then(Value::as_str) {
        println!("  {DIM}As{RESET}         {subject}");
    }

    // What the chosen renderer cannot carry. Declared, not discovered.
    if let Some(r) = result.get("renderer") {
        let id = r.get("id").and_then(Value::as_str).unwrap_or("?");
        let drops: Vec<&str> = r
            .get("drops")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if drops.is_empty() {
            println!("  {DIM}Format{RESET}     {id} {DIM}(carries everything){RESET}");
        } else {
            println!(
                "  {DIM}Format{RESET}     {id} {YELLOW}— discards: {}{RESET}",
                drops.join(", ")
            );
        }
    }

    // Correlation. The inversion is easy to get backwards, so the reason the
    // VTA supplies is printed rather than re-derived here.
    if let Some(c) = result.get("correlation") {
        let severity = c.get("severity").and_then(Value::as_str).unwrap_or("none");
        let colour = match severity {
            "high" => RED,
            "low" => YELLOW,
            _ => DIM,
        };
        let reason = c.get("reason").and_then(Value::as_str).unwrap_or("");
        println!(
            "  {DIM}Linkable{RESET}   {colour}{}{RESET} {reason}",
            severity.to_uppercase()
        );
    }

    let anomalous: Vec<&str> = result
        .get("anomalous")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    println!();
    if claims.is_empty() {
        println!("  {DIM}No claims would be disclosed.{RESET}");
    }
    for claim in claims {
        let ty = claim.get("type").and_then(Value::as_str).unwrap_or("?");
        let provenance = claim
            .get("provenance")
            .and_then(Value::as_str)
            .unwrap_or("");
        let rung = claim.get("rung").and_then(Value::as_str).unwrap_or("");
        let stale = claim.get("stale").and_then(Value::as_bool).unwrap_or(false);
        let fresh = claim
            .get("newToThisVerifier")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let odd = anomalous.contains(&ty);

        // A predicate claim carries no value, and that absence is the whole
        // point of the rung — never render it as missing data.
        let shown = if let Some(p) = claim.get("predicate") {
            let op = p.get("op").and_then(Value::as_str).unwrap_or("?");
            let arg = p.get("arg").map(render_scalar).unwrap_or_default();
            format!("{DIM}proves {op} {arg} — the value itself is not sent{RESET}")
        } else if stale {
            format!("{YELLOW}stale — will NOT be sent{RESET}")
        } else {
            claim.get("value").map(render_scalar).unwrap_or_default()
        };

        let mark = if odd || fresh {
            format!("{RED}!{RESET}")
        } else {
            " ".into()
        };
        println!("  {mark} {CYAN}{ty}{RESET}");
        println!("      {shown}");
        let mut notes: Vec<String> = Vec::new();
        if !provenance.is_empty() {
            notes.push(provenance.to_string());
        }
        if !rung.is_empty() {
            notes.push(rung.to_string());
        }
        if fresh {
            notes.push("new to this verifier".into());
        }
        if odd {
            notes.push("unusual for the stated purpose".into());
        }
        if !notes.is_empty() {
            println!("      {DIM}{}{RESET}", notes.join(" · "));
        }
    }

    println!();
    if let Some(expiry) = result.get("expiresAt").and_then(Value::as_str) {
        println!("  {DIM}This preview expires at {expiry} and can be used once.{RESET}");
    }
    println!(
        "  Disclose with: {BOLD}persona disclosure present --context {context_id} \
         --preview-id {preview_id}{RESET}"
    );
    println!();
}

/// Render a JSON scalar the way a person reads it — a string without its
/// quotes, anything else as compact JSON.
fn render_scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `persona disclosure present` — hand over what the preview showed.
pub async fn cmd_disclosure_present(
    client: &VtaClient,
    context_id: String,
    preview_id: String,
    challenge: Option<String>,
    mint: Option<Value>,
) -> CmdResult {
    let result = client
        .persona_disclosure_present(&context_id, &preview_id, challenge.as_deref(), mint)
        .await?;

    // The document the VTA returns is unsigned; signing belongs to the key
    // custodian. Say so, rather than letting an operator hand a verifier
    // something that looks presentable and is not.
    if !is_json_output()
        && result
            .get("document")
            .and_then(|d| d.get("unsigned"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        println!(
            "{YELLOW}This document is UNSIGNED. Sign it with the persona's key \
             (`keys derive-and-sign-document`) before sending it to a verifier.{RESET}"
        );
    }
    print_result("Disclosure:", &result)
}

/// `persona disclosure history` — what was disclosed, to whom, when.
pub async fn cmd_disclosure_history(
    client: &VtaClient,
    context_id: Option<String>,
    verifier_did: Option<String>,
    attribute_type: Option<String>,
    since: Option<String>,
    limit: Option<std::num::NonZeroU64>,
    cursor: Option<String>,
) -> CmdResult {
    let result = client
        .persona_disclosure_history(
            context_id.as_deref(),
            verifier_did.as_deref(),
            attribute_type.as_deref(),
            since.as_deref(),
            limit,
            cursor.as_deref(),
        )
        .await?;
    print_result("Disclosures:", &result)
}

// ---------------------------------------------------------------------------
// Correlation and renderers
// ---------------------------------------------------------------------------

/// `persona correlate` — how linkable would this make the holder?
pub async fn cmd_correlate(
    client: &VtaClient,
    attribute_id: Option<String>,
    profile_id: Option<String>,
    candidate: Option<Value>,
) -> CmdResult {
    let result = client
        .persona_correlation_analyze(attribute_id.as_deref(), profile_id.as_deref(), candidate)
        .await?;
    print_result("Correlation:", &result)
}

/// `persona renderers` — the output formats, and what each one discards.
pub async fn cmd_renderers(client: &VtaClient) -> CmdResult {
    let result = client.persona_renderers_list().await?;
    print_result("Renderers:", &result)
}

// ---------------------------------------------------------------------------
// Context-local profiles and bindings
// ---------------------------------------------------------------------------

/// `persona local profile put` — a profile that lives inside one context.
pub async fn cmd_local_profile_put(
    client: &VtaClient,
    context_id: String,
    name: String,
    entries: Vec<LocalProfileEntry>,
    profile_id: Option<String>,
    expected_version: Option<u64>,
) -> CmdResult {
    let result = client
        .persona_local_profile_put(
            &context_id,
            &name,
            entries,
            profile_id.as_deref(),
            expected_version,
        )
        .await?;
    print_result("Local profile:", &result)
}

/// `persona local profile get` — read one context-local profile.
pub async fn cmd_local_profile_get(
    client: &VtaClient,
    context_id: String,
    profile_id: String,
) -> CmdResult {
    let result = client
        .persona_local_profile_get(&context_id, &profile_id)
        .await?;
    print_result("Local profile:", &result)
}

/// `persona local profile list` — enumerate a context's own profiles.
pub async fn cmd_local_profile_list(
    client: &VtaClient,
    context_id: String,
    limit: Option<std::num::NonZeroU64>,
    cursor: Option<String>,
) -> CmdResult {
    let result = client
        .persona_local_profile_list(&context_id, limit, cursor.as_deref())
        .await?;
    print_result("Local profiles:", &result)
}

/// `persona local profile delete` — remove a context-local profile.
pub async fn cmd_local_profile_delete(
    client: &VtaClient,
    context_id: String,
    profile_id: String,
    unbind: bool,
) -> CmdResult {
    let result = client
        .persona_local_profile_delete(&context_id, &profile_id, unbind)
        .await?;
    print_result("Result:", &result)
}

/// `persona local binding set` — bind a persona to a context-local profile.
pub async fn cmd_local_binding_set(
    client: &VtaClient,
    context_id: String,
    persona_did: String,
    profile_id: Option<String>,
    expected_version: Option<u64>,
) -> CmdResult {
    let result = client
        .persona_local_binding_set(
            &context_id,
            &persona_did,
            profile_id.as_deref(),
            expected_version,
        )
        .await?;
    print_result("Local binding:", &result)
}
