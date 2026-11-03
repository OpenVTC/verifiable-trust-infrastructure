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
//!
//! Taking the ticket and casting are separate runs (CONVENTIONS §6 item 3): the community knows
//! when it issued a member's ticket and the ballot box when a cast arrived, so a cast sent
//! straight after its ticket can be paired by the two clocks. `vote` with no ticket held takes
//! one and stops, unless told `--now`.

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

/// A membership credential the member chose to present (VTI-VOT-016, VTI-VOT-090): its handle
/// in their VTA's vault, and the DID they were told the election's credential roll names.
#[derive(Debug, Clone, Copy, Default)]
pub struct Presenting<'a> {
    /// `membershipCredential`: the vault handle (`vault/credentials/query`).
    pub credential: Option<&'a str>,
    /// `memberOf`: the party whose membership the read proves; the VTA presents the credential
    /// only where that party issued it.
    pub member_of: Option<&'a str>,
}

/// The longest pause before a cast is sent, so its arrival is not timed to the ticket's.
const MAX_CAST_DELAY: Duration = Duration::from_secs(20);

// The VTA's voter tasks go through the SDK's `_json` forms (`pcs_voter_read_json`, …), never
// the typed ones: those re-serialise timestamps, so a manifest would reach the VTA with another
// digest and a signed read or cast would no longer be the bytes its proof covers.

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
    read_presenting(client, t, which, payload, Presenting::default()).await
}

/// [`read`], presenting the member's membership credential in a `show` (`vta/pcs/voter/read/0.6`,
/// VTI-VOT-015): to read an election put to the members of a party that is itself a member of
/// the community, which the community shows nobody else.
async fn read_presenting(
    client: &VtaClient,
    t: &VoteTarget<'_>,
    which: &str,
    payload: Value,
    presenting: Presenting<'_>,
) -> CliResult<Value> {
    let mut req = json!({
        "contextId": t.context, "community": t.vtc_did, "member": t.member,
        "read": which, "payload": payload,
    });
    if let Some(c) = presenting.credential {
        req["membershipCredential"] = json!(c);
        if let Some(m) = presenting.member_of {
            req["memberOf"] = json!(m);
        }
    }
    let signed = client
        .pcs_voter_read_json(req)
        .await
        .map_err(|e| hint_member(e.to_string(), t.member))?;
    community(t)
        .send_signed_document(&signed["document"])
        .await
        .map_err(|e| community_refusal(t.vtc_did, &e.to_string()))
}

/// A community's refusal, with what to do about an `indeterminate` answer: a check the
/// community makes on a presentation could not be completed (a status list or a DID document
/// it could not fetch), nothing was recorded, and the same request may be made again later
/// (VTI-VOT-018).
fn community_refusal(vtc_did: &str, text: &str) -> Box<dyn std::error::Error> {
    if text.contains("\"indeterminate\"") {
        return format!(
            "{vtc_did}: {text}\n\nThe community could not complete a check of your membership \
             credential just now (its issuer's status list or DID document could not be read). \
             Nothing was recorded: run the same command again in a little while."
        )
        .into();
    }
    format!("{vtc_did}: {text}").into()
}

fn hint_member(text: String, member: &str) -> Box<dyn std::error::Error> {
    if text.contains("membershipCredentialRequired") {
        return format!(
            "{text}\n\nThis election's roll is the holders of a membership credential: claim \
             your ticket with `pnm elections ticket <id> --membership-credential <handle>`, \
             naming the credential in your VTA's vault the roll names."
        )
        .into();
    }
    if text.contains("membershipCredentialMismatch") {
        return format!(
            "{text}\n\nThat credential was not issued by the --member-of DID. Your VTA presents \
             nothing unrelated to the election: name the credential that party issued you."
        )
        .into();
    }
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
            e["votingOpensAt"].as_str().unwrap_or_default(),
            e["votingClosesAt"].as_str().unwrap_or_default(),
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
        m["votingOpensAt"].as_str().unwrap_or_default(),
        m["votingClosesAt"].as_str().unwrap_or_default()
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
    if let Some(roll) = roll_credential(d) {
        println!("  roll        {roll}");
        println!(
            "  {YELLOW}{}{RESET}",
            roll_credential_warning(d).unwrap_or_default()
        );
    }
    if let Some(release) = written_answers(m) {
        println!("  written     {release}");
    }
    if let Some(warning) = written_answers_warning(m) {
        println!("  {YELLOW}{warning}{RESET}");
    }
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

/// When the manifest `m` releases written answers, if it asks for any or releases them below
/// the SHOULD of 10 (VTI-VOT-065).
fn written_answers(m: &Value) -> Option<String> {
    let threshold = m["textReleaseThreshold"].as_u64()?;
    let asks = m["questions"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|q| q["type"] == "text");
    (asks || threshold < 10).then(|| {
        format!(
            "released once {threshold} ballot{} counted, never while voting is open",
            if threshold == 1 { " is" } else { "s are" }
        )
    })
}

/// What a member must be told before taking a ticket when `m` releases written answers after
/// fewer than 10 ballots: that it does, and that a written answer may identify its author
/// (VTI-VOT-065, VTI-VOT-090). `None` at 10 or more.
fn written_answers_warning(m: &Value) -> Option<String> {
    let threshold = m["textReleaseThreshold"].as_u64()?;
    (threshold < 10).then(|| {
        format!(
            "written answers are released after only {threshold} ballot{}, fewer than the 10 \
             recommended: a written answer may identify who wrote it",
            if threshold == 1 { "" } else { "s" }
        )
    })
}

/// Whose membership credential admits a voter, under a credential roll: the disclosure's
/// `rollCredential` (VTI-VOT-090). `None` under every other rule.
fn roll_credential(d: &Value) -> Option<String> {
    let r = d.get("rollCredential")?;
    let did = r["memberOf"].as_str()?;
    let what = match r["memberOfKind"].as_str() {
        Some("thisCommunity") => "this community",
        Some("communityGroup") => "a group of this community",
        Some("memberParty") => "a party that is itself a member of this community",
        _ => "a party",
    };
    let name = r["memberOfName"]
        .as_str()
        .map(|n| format!(" \"{n}\""))
        .unwrap_or_default();
    Some(format!(
        "holders of a membership credential issued by {what}{name} ({did})"
    ))
}

/// What claiming a ticket under a credential roll shows the community (VTI-VOT-025,
/// VTI-VOT-090). `None` under every other rule.
fn roll_credential_warning(d: &Value) -> Option<String> {
    d.get("rollCredential")?;
    Some(
        "claiming a ticket presents that credential: the community learns that you are a \
         member of that party"
            .to_string(),
    )
}

/// `pnm elections show <id>`.
pub async fn cmd_show(client: &VtaClient, t: VoteTarget<'_>, election_id: &str) -> CliResult {
    cmd_show_presenting(client, t, election_id, Presenting::default()).await
}

/// `pnm elections show <id> --membership-credential <handle> [--member-of <did>]`: the read
/// presents the member's membership credential, which the community needs to show an election
/// put to the members of a party that is itself its member (VTI-VOT-015). Reading it this way
/// shows the community that membership before the member has seen the election.
pub async fn cmd_show_presenting(
    client: &VtaClient,
    t: VoteTarget<'_>,
    election_id: &str,
    presenting: Presenting<'_>,
) -> CliResult {
    let shown = read_presenting(
        client,
        &t,
        "show",
        json!({ "electionId": election_id }),
        presenting,
    )
    .await?;
    if is_json_output() {
        return Ok(print_json(&shown)?);
    }
    print_disclosure(&shown);
    if let Some(told) = presenting.member_of
        && let Some(names) = shown["manifest"]["roll"]["memberOf"].as_str()
        && names != told
    {
        println!(
            "  {YELLOW}you were told this election is put to the members of {told}, but its roll \
             names {names}{RESET}"
        );
    }
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

/// Take the member's ticket for the election `shown` describes, unless the VTA already holds
/// one. True when this call took it.
async fn take_ticket(
    client: &VtaClient,
    t: &VoteTarget<'_>,
    shown: &Value,
    credential: Option<&str>,
) -> CliResult<bool> {
    let election_id = &shown["manifest"]["electionId"];
    let mut reg = register_payload(t, shown);
    if let Some(c) = credential {
        reg["membershipCredential"] = json!(c);
    }
    let registered = match client.pcs_voter_register_json(reg).await {
        Ok(registered) => registered,
        Err(e) if e.to_string().contains("ticketHeld") => return Ok(false),
        Err(e) => return Err(hint_member(e.to_string(), t.member)),
    };
    if registered["manifestDigest"] != shown["manifestDigest"] {
        return Err(
            "your VTA computed another manifest digest than the community shows; not taking a \
             ticket"
                .into(),
        );
    }
    let issued = community(t)
        .send_signed_document(&registered["ticketDocument"])
        .await
        .map_err(|e| community_refusal(t.vtc_did, &e.to_string()))?;
    // The payload of the community's answer, without its ext (voter/accept item 1).
    let mut response = issued;
    if let Some(obj) = response.as_object_mut() {
        obj.remove("ext");
    }
    let accept = json!({
        "contextId": t.context, "community": t.vtc_did, "electionId": election_id,
        "parameters": shown["parameters"], "response": response,
    });
    client.pcs_voter_accept_json(accept).await?;
    Ok(true)
}

/// `vta/pcs/voter/register` for the election `shown` describes: the manifest and parameters
/// exactly as the community published them, so the VTA's digest is the community's.
fn register_payload(t: &VoteTarget<'_>, shown: &Value) -> Value {
    json!({
        "contextId": t.context, "community": t.vtc_did, "member": t.member,
        "parameters": shown["parameters"], "manifest": shown["manifest"],
    })
}

/// What a member is told after taking a ticket in a run that does not cast.
fn print_ticket_taken(election_id: &str) {
    println!("{GREEN}ticket taken{RESET} — the community signed it blind");
    println!(
        "{DIM}vote later with `pnm elections vote {election_id} …`: a cast sent now could be paired \
         with your ticket by when each arrived{RESET}"
    );
}

/// `pnm elections ticket <id>`: take the ticket, and nothing else — ahead of voting, so the cast
/// that follows is not timed to it.
pub async fn cmd_ticket(client: &VtaClient, t: VoteTarget<'_>, election_id: &str) -> CliResult {
    cmd_ticket_presenting(client, t, election_id, Presenting::default()).await
}

/// `pnm elections ticket <id> --membership-credential <handle> [--member-of <did>]`: under a
/// credential roll, the VTA presents that credential in the ticket request (VTI-VOT-025). With
/// `member_of`, the read of the election presents it too, as an election put to a member
/// party's members is shown to nobody else (VTI-VOT-015).
pub async fn cmd_ticket_presenting(
    client: &VtaClient,
    t: VoteTarget<'_>,
    election_id: &str,
    presenting: Presenting<'_>,
) -> CliResult {
    // The read presents only where the member said whose roll it is: an election they can
    // already see is read without showing the community anything (VTI-VOT-016).
    let read_with = if presenting.member_of.is_some() {
        presenting
    } else {
        Presenting::default()
    };
    let shown = read_presenting(
        client,
        &t,
        "show",
        json!({ "electionId": election_id }),
        read_with,
    )
    .await?;
    if !is_json_output() {
        print_disclosure(&shown);
    }
    let taken = take_ticket(client, &t, &shown, presenting.credential).await?;
    if is_json_output() {
        return Ok(print_json(
            &json!({ "electionId": election_id, "ticketHeld": true, "taken": taken }),
        )?);
    }
    if taken {
        print_ticket_taken(election_id);
    } else {
        println!("{DIM}your VTA already holds a ticket for {election_id}{RESET}");
    }
    Ok(())
}

/// `pnm elections vote <id>`: read, vote with the ticket the VTA holds, keep the receipt. With no
/// ticket held, take one and stop — or, with `now`, cast in the same run.
pub async fn cmd_vote(
    client: &VtaClient,
    t: VoteTarget<'_>,
    election_id: &str,
    answers: &[String],
    ballot_file: Option<&PathBuf>,
    now: bool,
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

    // 2. The ticket, unless the VTA already holds it — and then no cast in this run.
    if take_ticket(client, &t, &shown, None).await? {
        if !now {
            if is_json_output() {
                return Ok(print_json(
                    &json!({ "electionId": election_id, "ticketHeld": true, "voted": false }),
                )?);
            }
            print_ticket_taken(election_id);
            return Ok(());
        }
        if !is_json_output() {
            println!(
                "{GREEN}ticket taken{RESET} — {YELLOW}casting in the same run: the community and \
                 the ballot box could pair the two by time{RESET}"
            );
        }
    }
    let base = json!({ "contextId": t.context, "community": t.vtc_did });

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
        client.pcs_vote_json(vote).await?
    } else {
        // The trustees' signed steps, from the community (show item 6): the VTA forms the key
        // from them itself and encrypts under no other (CONVENTIONS §9.6).
        vote["ceremony"] = shown
            .get("ceremony")
            .cloned()
            .ok_or("the trustees have not formed the election key yet; vote once voting opens")?;
        client.pcs_vote_encrypted_json(vote).await?
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
    let kept = client.pcs_voter_receipt_json(keep).await?;
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

    /// The manifest reaches the VTA as the community published it: a typed round trip would
    /// rewrite `.000Z` timestamps and the VTA would compute another manifest's digest.
    #[test]
    fn the_manifest_is_registered_byte_for_byte() {
        let shown = json!({
            "manifest": { "electionId": "agm", "votingOpensAt": "2027-01-01T00:00:00.000Z" },
            "parameters": { "suite": "ps-ddh-bls12381" },
        });
        let t = VoteTarget {
            vtc_url: "https://v",
            vtc_did: "did:web:v",
            member: "did:web:m",
            context: "c",
        };
        let reg = register_payload(&t, &shown);
        assert_eq!(
            serde_json::to_string(&reg["manifest"]).unwrap(),
            r#"{"electionId":"agm","votingOpensAt":"2027-01-01T00:00:00.000Z"}"#
        );
        assert_eq!(reg["parameters"], shown["parameters"]);
    }

    #[test]
    fn a_required_question_unanswered_or_an_unknown_one_is_refused() {
        assert!(ballot_from_answers(&manifest(), "z", &[]).is_err());
        assert!(
            ballot_from_answers(&manifest(), "z", &["chair=a".into(), "nope=x".into()]).is_err()
        );
        assert!(ballot_from_answers(&manifest(), "z", &["chair".into()]).is_err());
    }

    /// VTI-VOT-090: below a threshold of 10 the member is told, before taking a ticket, that
    /// written answers come out after so few ballots and may identify their authors.
    #[test]
    fn vti_vot_090_a_threshold_below_ten_is_disclosed_with_its_warning() {
        let mut m = manifest();
        m["textReleaseThreshold"] = json!(10);
        assert_eq!(written_answers(&m), None, "no text question, threshold 10");
        assert_eq!(written_answers_warning(&m), None);

        m["questions"][1]["type"] = json!("text");
        assert_eq!(
            written_answers(&m).as_deref(),
            Some("released once 10 ballots are counted, never while voting is open")
        );
        assert_eq!(written_answers_warning(&m), None);

        m["textReleaseThreshold"] = json!(1);
        assert_eq!(
            written_answers(&m).as_deref(),
            Some("released once 1 ballot is counted, never while voting is open")
        );
        let warning = written_answers_warning(&m).unwrap();
        assert!(warning.contains("only 1 ballot,"), "{warning}");
        assert!(warning.contains("may identify who wrote it"), "{warning}");
    }

    /// VTI-VOT-090: under a credential roll the member is told whose membership credential
    /// admits them, what that party is to the community, and that claiming shows the community
    /// their membership of it; under any other rule nothing is said.
    #[test]
    fn vti_vot_090_a_credential_roll_is_disclosed_with_what_claiming_shows() {
        let d = json!({
            "rollCredential": {
                "memberOf": "did:webvh:QmG:vtc.example:groups:g7",
                "memberOfKind": "communityGroup",
                "memberOfName": "Engineering",
                "presenterDisclosed": true,
            }
        });
        let roll = roll_credential(&d).unwrap();
        assert!(roll.contains("a group of this community"), "{roll}");
        assert!(roll.contains("\"Engineering\""), "{roll}");
        assert!(
            roll.contains("did:webvh:QmG:vtc.example:groups:g7"),
            "{roll}"
        );
        let warning = roll_credential_warning(&d).unwrap();
        assert!(warning.contains("member of that party"), "{warning}");

        let party = json!({ "rollCredential": {
            "memberOf": "did:webvh:QmB:b.example", "memberOfKind": "memberParty",
            "presenterDisclosed": true } });
        assert!(
            roll_credential(&party)
                .unwrap()
                .contains("itself a member of this community")
        );
        assert_eq!(roll_credential(&json!({})), None);
        assert_eq!(roll_credential_warning(&json!({})), None);
    }

    /// VTI-VOT-018: an `indeterminate` answer is explained as retryable, never as a refusal.
    #[test]
    fn vti_vot_018_an_indeterminate_answer_says_to_try_again() {
        let text =
            community_refusal("did:c", r#"{"code":"indeterminate","retryable":true}"#).to_string();
        assert!(text.contains("run the same command again"), "{text}");
        let other = community_refusal("did:c", "electionUnknown").to_string();
        assert!(!other.contains("run the same command again"));
    }
}
