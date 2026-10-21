//! A member's side of a community election (VTI-VOT-020 – 053): read the elections, take a
//! ticket, vote, keep the receipt — with every key in the member's VTA.
//!
//! The VTA signs as the member for the two parties that need the member: the community's reads
//! (`vta/pcs/voter/read`) and the ticket request (`vta/pcs/voter/register`'s `ticketDocument`).
//! This client only carries those documents, over the community's HTTPS Trust Task door — a
//! persona-signed document never rides this client's own session. The ticket is unblinded into
//! the VTA (`voter/accept`); the cast is built and signed there under a key made for that cast
//! alone (`vta/pcs/vote`), and this client posts it to the ballot box itself, from its own
//! connection, after a pause, so the ballot box never sees the member and the community never
//! sees the ballot (VTI-VOT-001 – 004). The receipt goes back to the VTA (`voter/receipt`).

use std::path::PathBuf;
use std::time::Duration;

use rand::RngExt as _;
use serde_json::{Value, json};
use vta_sdk::client::VtaClient;
use vtc_client::VtcClient;

use crate::render::{BOLD, DIM, GREEN, RESET, YELLOW, is_json_output, print_json};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The community, and who the member is there.
pub struct VoteTarget<'a> {
    /// Base URL of the community's Trust Task endpoint (e.g. `https://vtc.example.com/v1`).
    pub vtc_url: &'a str,
    /// The community's DID.
    pub vtc_did: &'a str,
    /// The member's DID at the community: a persona this VTA holds.
    pub member: &'a str,
    /// The VTA context the member's voter keys are derived in.
    pub context: &'a str,
}

/// The longest pause before a cast is sent, so its arrival is not timed to the ticket's.
const MAX_CAST_DELAY: Duration = Duration::from_secs(20);

fn community(t: &VoteTarget<'_>) -> VtcClient {
    VtcClient::anonymous(t.vtc_url, t.vtc_did)
}

/// Have the VTA sign one election read as the member, and send it to the community.
async fn read(
    client: &VtaClient,
    t: &VoteTarget<'_>,
    which: &str,
    payload: Value,
) -> CliResult<Value> {
    let req = serde_json::from_value(json!({
        "contextId": t.context, "community": t.vtc_did, "member": t.member,
        "read": which, "payload": payload,
    }))?;
    let signed = client
        .pcs_voter_read(&req)
        .await
        .map_err(|e| hint_member(e.to_string(), t.member))?;
    let document = serde_json::to_value(&signed.document)?;
    Ok(community(t)
        .send_signed_document(&document)
        .await
        .map_err(|e| format!("{}: {e}", t.vtc_did))?)
}

fn hint_member(text: String, member: &str) -> Box<dyn std::error::Error> {
    if text.contains("memberNotHeld") {
        return format!(
            "{text}\n\nYour VTA holds no authentication key of {member} that you may act as. Pass \
             the persona DID the community knows you by as --member, and the context it lives \
             in as --context."
        )
        .into();
    }
    text.into()
}

/// `pnm elections list`.
pub async fn cmd_list(client: &VtaClient, t: VoteTarget<'_>) -> CliResult {
    let answer = read(client, &t, "list", json!({})).await?;
    if is_json_output() {
        return Ok(print_json(&answer)?);
    }
    let items = answer["elections"].as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        println!("{DIM}no elections you may vote in{RESET}");
    }
    for e in items {
        println!(
            "{BOLD}{}{RESET}  {}  {} → {}{}  {DIM}{}{RESET}",
            e["electionId"].as_str().unwrap_or_default(),
            e["state"].as_str().unwrap_or_default(),
            e["votingOpens"].as_str().unwrap_or_default(),
            e["votingCloses"].as_str().unwrap_or_default(),
            if e["ticketHeld"] == true {
                "  (ticket held)"
            } else {
                ""
            },
            e["title"].as_str().unwrap_or_default(),
        );
    }
    Ok(())
}

/// What a member is told about an election before taking a ticket (VTI-VOT-090).
fn print_disclosure(shown: &Value) {
    let m = &shown["manifest"];
    let d = &shown["disclosure"];
    println!(
        "{BOLD}{}{RESET}  {}",
        m["title"]
            .as_str()
            .unwrap_or(m["electionId"].as_str().unwrap_or_default()),
        shown["state"].as_str().unwrap_or_default()
    );
    println!(
        "  voting      {} → {}",
        m["votingOpens"].as_str().unwrap_or_default(),
        m["votingCloses"].as_str().unwrap_or_default()
    );
    println!(
        "  ballot box  {} (run by {})",
        d["ballotBox"].as_str().unwrap_or_default(),
        d["ballotBoxOperator"].as_str().unwrap_or_default()
    );
    if d["sameOperator"] == true {
        println!(
            "  {YELLOW}the same operator runs this community and the ballot box: they could link \
             your ticket to your ballot{RESET}"
        );
    }
    println!(
        "  board       {}; a later vote {}",
        d["boardVisibility"].as_str().unwrap_or_default(),
        if d["revote"] == "replace" {
            "replaces the earlier one"
        } else {
            "is refused"
        }
    );
    println!(
        "  {DIM}you can prove how you voted, so this election cannot protect you against being made to vote a certain way{RESET}"
    );
    for q in m["questions"].as_array().into_iter().flatten() {
        let opts: Vec<&str> = q["options"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|o| o["key"].as_str())
            .collect();
        println!(
            "  {BOLD}{}{RESET}  {}  [{}]{}",
            q["key"].as_str().unwrap_or_default(),
            q["text"].as_str().unwrap_or_default(),
            opts.join(", "),
            if q["optional"] == true {
                " (optional)"
            } else {
                ""
            }
        );
    }
}

/// `pnm elections show <id>`.
pub async fn cmd_show(client: &VtaClient, t: VoteTarget<'_>, election_id: &str) -> CliResult {
    let shown = read(client, &t, "show", json!({ "electionId": election_id })).await?;
    if is_json_output() {
        return Ok(print_json(&shown)?);
    }
    print_disclosure(&shown);
    Ok(())
}

/// The ballot from `--answer question=option` pairs (choice questions), every other question
/// abstained where it is optional.
fn ballot_from_answers(manifest: &Value, digest: &str, answers: &[String]) -> CliResult<Value> {
    let mut picked = std::collections::BTreeMap::new();
    for a in answers {
        let (q, o) = a
            .split_once('=')
            .ok_or_else(|| format!("--answer {a:?}: write it as question=option"))?;
        picked
            .entry(q.to_string())
            .or_insert_with(Vec::new)
            .push(o.to_string());
    }
    let mut out = Vec::new();
    for q in manifest["questions"].as_array().into_iter().flatten() {
        let key = q["key"].as_str().unwrap_or_default();
        match picked.remove(key) {
            Some(choice) => {
                if q["type"] != "choice" {
                    return Err(format!(
                        "question {key} is a {} question: give the whole ballot with --ballot",
                        q["type"]
                    )
                    .into());
                }
                out.push(json!({ "question": key, "choice": choice }));
            }
            None if q["optional"] == true => out.push(json!({ "question": key, "abstain": true })),
            None => {
                return Err(
                    format!("question {key} needs an answer: --answer {key}=<option>").into(),
                );
            }
        }
    }
    if let Some(q) = picked.keys().next() {
        return Err(format!("the election asks no question {q}").into());
    }
    Ok(json!({
        "electionId": manifest["electionId"],
        "manifestDigest": digest,
        "answers": out,
    }))
}

/// The ballot box's HTTPS Trust Task base, from its DID document (`TrustTaskHTTPS`) — the door
/// a cast from a one-time key is always accepted on (VTI-VOT-004).
pub(crate) async fn ballot_box_url(did: &str) -> CliResult<String> {
    let resolver = vta_sdk::resolver::shared_did_resolver_from_env()
        .await
        .map_err(|e| format!("build a DID resolver: {e}"))?;
    let resolved = resolver
        .resolve(did)
        .await
        .map_err(|e| format!("resolve the ballot box {did}: {e}"))?;
    let doc = serde_json::to_value(&resolved.doc)?;
    vta_sdk::protocol::matching::ServiceCapabilities::from_did_document(&doc)
        .rest
        .filter(|u| vta_sdk::protocol::matching::is_https_or_loopback(u))
        .ok_or_else(|| {
            format!("the ballot box {did} advertises no https TrustTaskHTTPS endpoint to cast on")
                .into()
        })
}

/// `pnm elections vote <id>`: read, take the ticket if not held, vote, keep the receipt.
pub async fn cmd_vote(
    client: &VtaClient,
    t: VoteTarget<'_>,
    election_id: &str,
    answers: &[String],
    ballot_file: Option<&PathBuf>,
    no_delay: bool,
) -> CliResult {
    // 1. The election as the community shows the member.
    let shown = read(client, &t, "show", json!({ "electionId": election_id })).await?;
    if !is_json_output() {
        print_disclosure(&shown);
    }
    let manifest = shown["manifest"].clone();
    let parameters = shown["parameters"].clone();
    let digest = shown["manifestDigest"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let ballot = match ballot_file {
        Some(p) => serde_json::from_str(&std::fs::read_to_string(p)?)?,
        None => ballot_from_answers(&manifest, &digest, answers)?,
    };

    // 2. The ticket, unless the VTA already holds it.
    let base = json!({ "contextId": t.context, "community": t.vtc_did });
    let mut reg = base.clone();
    reg["parameters"] = parameters.clone();
    reg["manifest"] = manifest.clone();
    reg["member"] = json!(t.member);
    match client
        .pcs_voter_register(&serde_json::from_value(reg)?)
        .await
    {
        Ok(registered) => {
            let registered = serde_json::to_value(&registered)?;
            if registered["manifestDigest"] != digest.as_str() {
                return Err(
                    "your VTA computed another manifest digest than the community shows; \
                            not voting"
                        .into(),
                );
            }
            let issued = community(&t)
                .send_signed_document(&registered["ticketDocument"])
                .await
                .map_err(|e| format!("{}: {e}", t.vtc_did))?;
            let mut accept = base.clone();
            accept["electionId"] = json!(election_id);
            accept["parameters"] = parameters.clone();
            accept["response"] = issued;
            client
                .pcs_voter_accept(&serde_json::from_value(accept)?)
                .await?;
            if !is_json_output() {
                println!("{GREEN}ticket taken{RESET} — the community signed it blind");
            }
        }
        Err(e) if e.to_string().contains("ticketHeld") => {}
        Err(e) => return Err(hint_member(e.to_string(), t.member)),
    }

    // 3. The cast, built and signed in the VTA under a key made for it alone — sealed or
    //    encrypted under the trustees' election key where the manifest says so.
    let ballot_box = manifest["ballotBox"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let url = ballot_box_url(&ballot_box).await?;
    let mut vote = base.clone();
    vote["parameters"] = parameters;
    vote["manifest"] = manifest.clone();
    vote["ballot"] = ballot;
    let cast = if manifest["secrecy"] == "open" {
        serde_json::to_value(client.pcs_vote(&serde_json::from_value(vote)?).await?)?
    } else {
        // From the community, which reads it from the ballot box: a voter cannot read a
        // private board (show item 6).
        vote["electionKey"] = shown
            .get("electionKey")
            .cloned()
            .ok_or("the trustees have not formed the election key yet; vote once voting opens")?;
        serde_json::to_value(
            client
                .pcs_vote_encrypted(&serde_json::from_value(vote)?)
                .await?,
        )?
    };
    let cast_doc = &cast["castDocument"];

    // 4. To the ballot box, from this connection, after a pause.
    if !no_delay {
        let ms = rand::rng().random_range(0..MAX_CAST_DELAY.as_millis() as u64);
        if !is_json_output() {
            println!(
                "{DIM}waiting {:.1}s before casting{RESET}",
                ms as f64 / 1000.0
            );
        }
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
    let http = vta_sdk::http::foreign_fetch_client();
    let resp = http
        .post(format!("{}/trust-tasks", url.trim_end_matches('/')))
        .header("content-type", "application/json")
        .body(serde_json::to_string(cast_doc)?)
        .send()
        .await
        .map_err(|e| format!("the ballot box did not answer ({e}); run the same command again to resend the same cast"))?;
    let status = resp.status();
    let receipt: Value = resp.json().await?;
    if !status.is_success() {
        return Err(format!(
            "the ballot box refused the cast: {}",
            receipt["payload"]["code"].as_str().unwrap_or("unknown")
        )
        .into());
    }

    // 5. The receipt, kept and checked by the VTA.
    let mut keep = base;
    keep["electionId"] = json!(election_id);
    keep["receipt"] = receipt.clone();
    let kept = serde_json::to_value(
        client
            .pcs_voter_receipt(&serde_json::from_value(keep)?)
            .await?,
    )?;
    if is_json_output() {
        return Ok(print_json(&json!({ "receipt": receipt, "kept": kept }))?);
    }
    println!(
        "{GREEN}voted{RESET} in {election_id}: {} (board entry {})",
        receipt["payload"]["outcome"].as_str().unwrap_or("counted"),
        receipt["payload"]["leafIndex"]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Value {
        json!({
            "electionId": "agm",
            "questions": [
                { "key": "chair", "type": "choice", "options": [{ "key": "a" }, { "key": "b" }], "optional": false },
                { "key": "budget", "type": "choice", "options": [{ "key": "yes" }, { "key": "no" }], "optional": true }
            ]
        })
    }

    #[test]
    fn answers_build_a_ballot_and_optional_questions_are_abstained() {
        let b = ballot_from_answers(&manifest(), "zDigest", &["chair=a".into()]).unwrap();
        assert_eq!(
            b["answers"][0],
            json!({ "question": "chair", "choice": ["a"] })
        );
        assert_eq!(
            b["answers"][1],
            json!({ "question": "budget", "abstain": true })
        );
        assert_eq!(b["manifestDigest"], "zDigest");
    }

    #[test]
    fn a_required_question_unanswered_or_an_unknown_one_is_refused() {
        assert!(ballot_from_answers(&manifest(), "z", &[]).is_err());
        assert!(
            ballot_from_answers(&manifest(), "z", &["chair=a".into(), "nope=x".into()]).is_err()
        );
        assert!(ballot_from_answers(&manifest(), "z", &["chair".into()]).is_err());
    }
}
