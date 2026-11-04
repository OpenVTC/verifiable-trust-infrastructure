//! A member's side of a community board (`vtc/boards/*`, VTI-BRD-010 – 060): read the boards,
//! propose and withdraw ideas, add and withdraw notes, and take the tickets for a board's open
//! ideas — with every key in the member's VTA.
//!
//! **The VTA signs as the member.** Each document is built here unsigned, checked against its
//! published schema, and handed to the VTA's `vault/sign-trust-task`, which signs it as the
//! principal DID of the member's vault entry for the community — their identity there — with a
//! key that never leaves the VTA. Exactly what was built comes back, with a proof; anything
//! else is refused before it reaches the community. This client only carries the signed
//! document, over the community's HTTPS Trust Task door ([`VtcClient::send_signed_document`]):
//! a member-signed document never rides this client's own session.
//!
//! **Voting is not a board task.** An open idea is an election (`election.electionId`); its
//! ticket and ballot go through `pnm elections`, the member's VTA and the ballot box, never
//! through the board. `take-tickets` takes each open idea's ticket in its own request, a random
//! pause apart, so the community does not receive them as one burst (VTI-BRD-034).
//!
//! A facilitator's acts (`create`, `update`, `decide`, `select`, `hide`) are `cnm boards`, signed
//! with an operator key — never a member's portal or wallet key (VTI-BRD-051).

use std::time::Duration;

use rand::RngExt as _;
use serde_json::{Value, json};
use vta_sdk::client::VtaClient;
use vtc_client::VtcClient;
use vtc_client::boards::{self as wire, task};

use crate::commands::elections::{self, VoteTarget};
use crate::render::{BOLD, DIM, GREEN, RESET, YELLOW, is_json_output, print_json};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The community, and who the member is there.
pub struct BoardTarget<'a> {
    /// Base URL of the community's Trust Task endpoint (e.g. `https://vtc.example.com/v1`).
    pub vtc_url: &'a str,
    /// The community's DID.
    pub vtc_did: &'a str,
    /// The member's DID at the community: the principal of a vault entry this VTA holds.
    pub member: &'a str,
    /// The vault entry to sign as. Found from the community and `member` when absent.
    pub entry: Option<&'a str>,
    /// The VTA context the member's voter keys are derived in (`take-tickets` only).
    pub context: Option<&'a str>,
}

/// The random pause between two ticket requests of one `take-tickets`, `[min, max)` seconds.
const TICKET_SPACING_SECS: (u64, u64) = (1, 6);

// ── Signing and sending ─────────────────────────────────────────────────────

/// The vault entry the member signs as at this community: the one named, or the single active
/// entry for the community whose principal is `member`.
async fn entry_id(client: &VtaClient, t: &BoardTarget<'_>) -> CliResult<String> {
    if let Some(e) = t.entry {
        return Ok(e.to_string());
    }
    let listed = client
        .vault_list(json!({ "targetDid": t.vtc_did, "status": "active" }))
        .await?;
    let ours: Vec<&str> = listed["entries"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|e| e["principalDid"].as_str() == Some(t.member))
        .filter_map(|e| e["id"].as_str())
        .collect();
    match ours.as_slice() {
        [one] => Ok((*one).to_string()),
        [] => Err(format!(
            "your VTA holds no vault entry for {} as {}. Sign in to the community once from your \
             wallet, or name the entry with --entry (list them with \
             `echo '{{\"targetDid\":\"{}\"}}' | pnm vault list --filters-file -`).",
            t.vtc_did, t.member, t.vtc_did
        )
        .into()),
        many => Err(format!(
            "your VTA holds {} vault entries for {} as {}: name one with --entry ({}).",
            many.len(),
            t.vtc_did,
            t.member,
            many.join(", ")
        )
        .into()),
    }
}

/// The signed envelope is the one built, with a proof added: nothing else is sent on.
fn same_but_proof(built: &Value, signed: &Value) -> bool {
    let mut s = signed.clone();
    let Some(obj) = s.as_object_mut() else {
        return false;
    };
    obj.remove("proof").is_some() && &s == built
}

/// Build `payload` as `type_uri` from the member to the community, have the VTA sign it as the
/// member, and send it. The answer's payload.
async fn send(
    client: &VtaClient,
    t: &BoardTarget<'_>,
    entry: &str,
    type_uri: &str,
    payload: Value,
) -> CliResult<Value> {
    let payload = wire::checked(type_uri, payload)?;
    let built = vta_sdk::trust_task_sign::build_unsigned(type_uri, payload, t.member, t.vtc_did)
        .map_err(|e| format!("could not build the {type_uri} document: {e:?}"))?;
    let built = serde_json::to_value(&built)?;
    let signed = client
        .vault_sign_trust_task(json!({ "entryId": entry, "unsignedEnvelope": built }))
        .await
        .map_err(|e| sign_refusal(e.to_string()))?;
    let signed = &signed["signedEnvelope"];
    if !same_but_proof(&built, signed) {
        return Err(
            "your VTA returned a document other than the one asked for: not sending it".into(),
        );
    }
    VtcClient::anonymous(t.vtc_url, t.vtc_did)
        .send_signed_document(signed)
        .await
        .map_err(|e| format!("{}: {e}", t.vtc_did).into())
}

fn sign_refusal(text: String) -> Box<dyn std::error::Error> {
    if text.contains("SignTrustTask") || text.contains("permission") {
        return format!(
            "{text}\n\nYour VTA did not let this client sign as you: it needs the SignTrustTask \
             capability on this client's ACL entry."
        )
        .into();
    }
    text.into()
}

/// One task, from first to last page, collecting `field`.
async fn all_pages(
    client: &VtaClient,
    t: &BoardTarget<'_>,
    entry: &str,
    type_uri: &str,
    base: Value,
    field: &str,
) -> CliResult<(Value, Vec<Value>)> {
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut body = base.clone();
        body["limit"] = json!(200);
        if let Some(c) = &cursor {
            body["cursor"] = json!(c);
        }
        let page = send(client, t, entry, type_uri, body).await?;
        items.extend(page[field].as_array().cloned().unwrap_or_default());
        match page["nextCursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => return Ok((page, items)),
        }
    }
}

// ── Rendering ───────────────────────────────────────────────────────────────

fn author(a: &Value) -> String {
    if a["formerMember"] == json!(true) {
        "a former member".into()
    } else if a["you"] == json!(true) {
        "you".into()
    } else {
        a["name"].as_str().unwrap_or("a member").to_string()
    }
}

fn lane(state: &str) -> &'static str {
    match state {
        "proposed" => "Proposed",
        "open" => "Open for votes",
        "selected" => "Selected",
        "notSelected" => "Not this time",
        "declined" => "Declined",
        "merged" => "Merged",
        _ => "Withdrawn",
    }
}

/// An idea's election as one line: its stage, the ballots on its board, or its result.
fn election_line(e: &Value) -> String {
    if let Some(r) = e.get("result").filter(|r| !r.is_null()) {
        let counted = r["ballotsCounted"].as_u64().unwrap_or(0);
        let choice = &r["questions"][0]["choice"];
        let total: u64 = choice
            .as_object()
            .map(|m| m.values().filter_map(Value::as_u64).sum())
            .unwrap_or(0);
        let yes = choice["yes"].as_u64();
        let share = match (yes, total) {
            (Some(y), t) if t > 0 => format!(" · {}% yes", y * 100 / t),
            _ => String::new(),
        };
        let certified = if e["certified"] == json!(true) {
            " · certified"
        } else {
            " · not certified"
        };
        return format!("{counted} counted{share}{certified}");
    }
    match e["ballotsOnBoard"].as_u64() {
        Some(n) => format!(
            "{} · {n} ballots on the board",
            e["state"].as_str().unwrap_or("")
        ),
        None => e["state"].as_str().unwrap_or("").to_string(),
    }
}

fn print_idea(i: &Value) {
    let id = i["ideaId"].as_str().unwrap_or("");
    let title = i["title"].as_str().unwrap_or("");
    let mut meta = vec![author(&i["proposer"])];
    for k in ["format", "topic"] {
        if let Some(v) = i[k].as_str() {
            meta.push(v.to_string());
        }
    }
    meta.push(format!("{} notes", i["noteCount"].as_u64().unwrap_or(0)));
    println!("  {BOLD}{title}{RESET}  {DIM}{id}{RESET}");
    println!("    {DIM}{}{RESET}", meta.join(" · "));
    if let Some(e) = i.get("election").filter(|e| !e.is_null()) {
        println!(
            "    election {} — {}",
            e["electionId"].as_str().unwrap_or(""),
            election_line(e)
        );
    } else if i.get("opening").is_some_and(|o| !o.is_null()) {
        println!("    {YELLOW}its election is opening{RESET}");
    }
    if let Some(d) = i.get("decision").filter(|d| !d.is_null())
        && let Some(r) = d["reason"].as_str()
    {
        println!("    {DIM}{r}{RESET}");
    }
}

// ── Commands ────────────────────────────────────────────────────────────────

/// `pnm boards list`: the boards the member may see.
pub async fn cmd_list(client: &VtaClient, t: BoardTarget<'_>, status: Option<&str>) -> CliResult {
    let entry = entry_id(client, &t).await?;
    let mut base = json!({});
    if let Some(s) = status {
        base["status"] = json!(s);
    }
    let (_, boards) = all_pages(client, &t, &entry, task::LIST, base, "boards").await?;
    if is_json_output() {
        return Ok(print_json(&json!({ "boards": boards }))?);
    }
    if boards.is_empty() {
        println!("{DIM}there are no boards you can see{RESET}");
    }
    for b in &boards {
        println!(
            "{BOLD}{}{RESET}  {DIM}{}{RESET}",
            b["title"].as_str().unwrap_or(""),
            b["boardId"].as_str().unwrap_or("")
        );
        println!(
            "  {} · proposals until {} · votes close {}",
            b["status"].as_str().unwrap_or(""),
            b["proposals"]["closesAt"].as_str().unwrap_or(""),
            b["voting"]["closesAt"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

/// `pnm boards show <board>`: the board and its ideas, lane by lane.
pub async fn cmd_show(
    client: &VtaClient,
    t: BoardTarget<'_>,
    board_id: &str,
    states: &[String],
) -> CliResult {
    let entry = entry_id(client, &t).await?;
    let mut base = json!({ "boardId": board_id });
    if !states.is_empty() {
        base["state"] = json!(states);
    }
    let (page, ideas) = all_pages(client, &t, &entry, task::SHOW, base, "ideas").await?;
    let board = &page["board"];
    if is_json_output() {
        return Ok(print_json(&json!({ "board": board, "ideas": ideas }))?);
    }
    println!("{BOLD}{}{RESET}", board["title"].as_str().unwrap_or(""));
    if let Some(d) = board["description"].as_str() {
        println!("{DIM}{d}{RESET}");
    }
    println!(
        "{} · proposals {} → {} · voting {} → {}",
        board["status"].as_str().unwrap_or(""),
        board["proposals"]["opensAt"].as_str().unwrap_or(""),
        board["proposals"]["closesAt"].as_str().unwrap_or(""),
        board["voting"]["opensAt"].as_str().unwrap_or(""),
        board["voting"]["closesAt"].as_str().unwrap_or("")
    );
    if let Some(r) = board["selectionRule"].as_str() {
        println!("{DIM}how ideas are chosen: {r}{RESET}");
    }
    for state in [
        "proposed",
        "open",
        "selected",
        "notSelected",
        "declined",
        "merged",
        "withdrawn",
    ] {
        let lane_ideas: Vec<&Value> = ideas.iter().filter(|i| i["state"] == state).collect();
        if lane_ideas.is_empty() {
            continue;
        }
        println!("\n{BOLD}{}{RESET} ({})", lane(state), lane_ideas.len());
        for i in lane_ideas {
            print_idea(i);
        }
    }
    Ok(())
}

/// What a proposal or a change to one says.
#[derive(Default)]
pub struct Proposal<'a> {
    pub title: Option<&'a str>,
    pub description: Option<&'a str>,
    pub format: Option<&'a str>,
    pub topic: Option<&'a str>,
}

impl Proposal<'_> {
    fn into_body(self, mut body: Value) -> Value {
        for (k, v) in [
            ("title", self.title),
            ("description", self.description),
            ("format", self.format),
            ("topic", self.topic),
        ] {
            if let Some(v) = v {
                body[k] = json!(v);
            }
        }
        body
    }
}

/// What the member is told before they first write on a board (VTI-BRD-070).
fn disclose() {
    if !is_json_output() {
        eprintln!(
            "{DIM}What you write is shown under your name to everyone who can see this board, and \
             its facilitators can decline, merge or hide it. Voting on an idea is a separate \
             election: the board never learns whether you voted.{RESET}"
        );
    }
}

fn print_one(label: &str, answer: &Value, key: &str) -> CliResult {
    if is_json_output() {
        return Ok(print_json(answer)?);
    }
    let v = &answer[key];
    let id = v["ideaId"]
        .as_str()
        .or_else(|| v["noteId"].as_str())
        .unwrap_or("");
    println!("{GREEN}{label}{RESET} {BOLD}{id}{RESET}");
    if key == "idea" {
        print_idea(v);
    }
    Ok(())
}

/// `pnm boards propose <board> --title … --description …`.
pub async fn cmd_propose(
    client: &VtaClient,
    t: BoardTarget<'_>,
    board_id: &str,
    proposal: Proposal<'_>,
) -> CliResult {
    let entry = entry_id(client, &t).await?;
    disclose();
    let body = proposal.into_body(json!({ "boardId": board_id }));
    let answer = send(client, &t, &entry, task::IDEAS_PROPOSE, body).await?;
    print_one("proposed", &answer, "idea")
}

/// `pnm boards update <idea> …`: change the member's own idea while it is still proposed.
pub async fn cmd_update(
    client: &VtaClient,
    t: BoardTarget<'_>,
    idea_id: &str,
    proposal: Proposal<'_>,
) -> CliResult {
    let entry = entry_id(client, &t).await?;
    let body = proposal.into_body(json!({ "ideaId": idea_id }));
    let answer = send(client, &t, &entry, task::IDEAS_UPDATE, body).await?;
    print_one("updated", &answer, "idea")
}

/// `pnm boards withdraw <idea>`.
pub async fn cmd_withdraw(client: &VtaClient, t: BoardTarget<'_>, idea_id: &str) -> CliResult {
    let entry = entry_id(client, &t).await?;
    let answer = send(
        client,
        &t,
        &entry,
        task::IDEAS_WITHDRAW,
        json!({ "ideaId": idea_id }),
    )
    .await?;
    print_one("withdrawn", &answer, "idea")
}

/// `pnm boards notes <board> [--idea <idea>] [--all]`.
pub async fn cmd_notes(
    client: &VtaClient,
    t: BoardTarget<'_>,
    board_id: &str,
    idea_id: Option<&str>,
    all: bool,
) -> CliResult {
    let entry = entry_id(client, &t).await?;
    let mut base = json!({ "boardId": board_id });
    match idea_id {
        Some(i) => base["ideaId"] = json!(i),
        None => base["scope"] = json!(if all { "all" } else { "board" }),
    }
    let (_, notes) = all_pages(client, &t, &entry, task::NOTES_LIST, base, "notes").await?;
    if is_json_output() {
        return Ok(print_json(&json!({ "notes": notes }))?);
    }
    if notes.is_empty() {
        println!("{DIM}no notes{RESET}");
    }
    for n in &notes {
        let text = match (n["state"].as_str(), n["text"].as_str()) {
            (Some("visible"), Some(t)) => t.to_string(),
            (Some("hidden"), _) => format!(
                "{YELLOW}hidden by a facilitator: {}{RESET}",
                n["hiddenReason"].as_str().unwrap_or("")
            ),
            _ => format!("{DIM}withdrawn{RESET}"),
        };
        println!("  {text}");
        println!(
            "    {DIM}{} · {} · {}{RESET}",
            author(&n["author"]),
            n["createdAt"].as_str().unwrap_or(""),
            n["noteId"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

/// `pnm boards note <board> <text> [--idea <idea>]`: add a note.
pub async fn cmd_note(
    client: &VtaClient,
    t: BoardTarget<'_>,
    board_id: &str,
    text: &str,
    idea_id: Option<&str>,
) -> CliResult {
    let entry = entry_id(client, &t).await?;
    disclose();
    let mut body = json!({ "boardId": board_id, "text": text });
    if let Some(i) = idea_id {
        body["ideaId"] = json!(i);
    }
    let answer = send(client, &t, &entry, task::NOTES_ADD, body).await?;
    print_one("added note", &answer, "note")
}

/// `pnm boards withdraw-note <note>`.
pub async fn cmd_withdraw_note(client: &VtaClient, t: BoardTarget<'_>, note_id: &str) -> CliResult {
    let entry = entry_id(client, &t).await?;
    let answer = send(
        client,
        &t,
        &entry,
        task::NOTES_WITHDRAW,
        json!({ "noteId": note_id }),
    )
    .await?;
    print_one("withdrew note", &answer, "note")
}

/// `pnm boards take-tickets <board>`: the ticket for every idea open for votes, each its own
/// request, a random pause apart (VTI-BRD-034). One that fails does not stop the rest.
pub async fn cmd_take_tickets(client: &VtaClient, t: BoardTarget<'_>, board_id: &str) -> CliResult {
    let context = t
        .context
        .ok_or("take-tickets needs --context: the VTA context your voter keys live in")?;
    let entry = entry_id(client, &t).await?;
    let (_, ideas) = all_pages(
        client,
        &t,
        &entry,
        task::SHOW,
        json!({ "boardId": board_id, "state": ["open"] }),
        "ideas",
    )
    .await?;
    let elections: Vec<(String, String)> = ideas
        .iter()
        .filter_map(|i| {
            Some((
                i["election"]["electionId"].as_str()?.to_string(),
                i["title"].as_str().unwrap_or("").to_string(),
            ))
        })
        .collect();
    let vote = VoteTarget {
        vtc_url: t.vtc_url,
        vtc_did: t.vtc_did,
        member: t.member,
        context,
    };
    let mut outcomes = Vec::new();
    for (n, (election_id, title)) in elections.iter().enumerate() {
        if n > 0 {
            let (lo, hi) = TICKET_SPACING_SECS;
            let secs = rand::rng().random_range(lo..hi);
            tokio::time::sleep(Duration::from_secs(secs)).await;
        }
        let outcome = match elections::ticket_for(client, &vote, election_id).await {
            Ok(true) => json!({ "electionId": election_id, "outcome": "taken" }),
            Ok(false) => json!({ "electionId": election_id, "outcome": "held" }),
            Err(e) => {
                json!({ "electionId": election_id, "outcome": "failed", "error": e.to_string() })
            }
        };
        if !is_json_output() {
            let word = match outcome["outcome"].as_str() {
                Some("taken") => format!("{GREEN}ticket taken{RESET}"),
                Some("held") => format!("{DIM}already held{RESET}"),
                _ => format!(
                    "{YELLOW}failed{RESET}: {}",
                    outcome["error"].as_str().unwrap_or("")
                ),
            };
            println!("  {title} — {word}");
        }
        outcomes.push(outcome);
    }
    if is_json_output() {
        return Ok(print_json(&json!({ "tickets": outcomes }))?);
    }
    if elections.is_empty() {
        println!("{DIM}no idea on this board is open for votes yet{RESET}");
    } else {
        println!(
            "{DIM}vote later, one idea at a time, with `pnm elections vote <electionId> …`: a vote \
             sent straight after its ticket could be paired with it by when each arrived{RESET}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_document_is_the_built_one_with_a_proof_added() {
        let built = json!({ "id": "urn:uuid:1", "type": "t", "payload": { "a": 1 } });
        let mut signed = built.clone();
        signed["proof"] = json!({ "type": "DataIntegrityProof" });
        assert!(same_but_proof(&built, &signed));
        // No proof at all.
        assert!(!same_but_proof(&built, &built));
        // A member changed on the way.
        let mut changed = signed.clone();
        changed["payload"]["a"] = json!(2);
        assert!(!same_but_proof(&built, &changed));
    }

    #[test]
    fn an_election_line_says_the_result_or_the_ballots_on_the_board() {
        let open = json!({ "electionId": "e", "state": "voting", "ballotsOnBoard": 12 });
        assert_eq!(election_line(&open), "voting · 12 ballots on the board");
        let tallied = json!({
            "electionId": "e", "state": "tallied", "certified": false,
            "result": { "ballotsCounted": 10, "questions": [{ "choice": { "yes": 7, "no": 3 } }] }
        });
        assert_eq!(
            election_line(&tallied),
            "10 counted · 70% yes · not certified"
        );
    }

    #[test]
    fn a_proposal_carries_only_what_was_given() {
        let body = Proposal {
            title: Some("T"),
            topic: Some("Identity"),
            ..Default::default()
        }
        .into_body(json!({ "ideaId": "x" }));
        assert_eq!(
            body,
            json!({ "ideaId": "x", "title": "T", "topic": "Identity" })
        );
    }
}
