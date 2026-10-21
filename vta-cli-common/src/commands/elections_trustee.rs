//! A trustee's side of a sealed or tallied-encrypted election (VTI-VOT-060 – 063, CONVENTIONS
//! §9.6 – 9.7): generate the election key with the other trustees, then decrypt after close —
//! with every key in the trustee's VTA.
//!
//! The VTA holds the transport key, the polynomial and the key share, and signs each
//! `voting/trustees/*` request as the trustee (`vta/pcs/trustee/*`); it also signs the trustee's
//! reads of the ballot box (`vta/pcs/trustee/read`), which a private board answers only to a
//! trustee. This client carries every document to the ballot box's HTTPS Trust Task door and
//! works out the next step from what the ballot box reports, so `step` can be run again and
//! again — or with `--watch` — until the ceremony needs nothing more of this trustee.

use std::time::Duration;

use serde_json::{Value, json};
use vta_sdk::client::VtaClient;

use super::elections::ballot_box_url;
use crate::render::{BOLD, DIM, GREEN, RESET, YELLOW, is_json_output, print_json};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The election, and who the trustee is.
pub struct TrusteeTarget<'a> {
    /// The community's DID: the registrar that registered the election.
    pub community: &'a str,
    /// The ballot box's DID (the manifest's `ballotBox`).
    pub ballot_box: &'a str,
    /// The trustee's DID: a persona this VTA holds, named in the manifest's `trustees.dids`.
    pub trustee: &'a str,
    /// The VTA context that persona lives in.
    pub context: &'a str,
}

/// How often `--watch` asks again.
const WATCH_EVERY: Duration = Duration::from_secs(30);

/// A ballot box reached over its HTTPS door.
struct BallotBox {
    url: String,
}

impl BallotBox {
    /// Post one signed document; the answer's payload, or the ballot box's refusal.
    async fn send(&self, doc: &Value) -> CliResult<Value> {
        let resp = vta_sdk::http::foreign_fetch_client()
            .post(format!("{}/trust-tasks", self.url.trim_end_matches('/')))
            .header("content-type", "application/json")
            .body(serde_json::to_string(doc)?)
            .send()
            .await
            .map_err(|e| {
                format!("the ballot box did not answer ({e}); run the same command again")
            })?;
        let status = resp.status();
        let answer: Value = resp.json().await?;
        if !status.is_success() {
            return Err(format!(
                "the ballot box refused {}: {} {}",
                doc["type"].as_str().unwrap_or_default(),
                answer["payload"]["code"].as_str().unwrap_or("unknown"),
                answer["payload"]["message"].as_str().unwrap_or_default(),
            )
            .into());
        }
        Ok(answer["payload"].clone())
    }
}

fn base(t: &TrusteeTarget<'_>, election_id: &str) -> Value {
    json!({
        "contextId": t.context,
        "community": t.community,
        "electionId": election_id,
        "trustee": t.trustee,
    })
}

fn hint_trustee(text: String, trustee: &str) -> Box<dyn std::error::Error> {
    if text.contains("trusteeNotHeld") {
        return format!(
            "{text}\n\nYour VTA holds no authentication key of {trustee} that you may act as. \
             Pass the persona DID the manifest names as a trustee as --trustee, and the context \
             it lives in as --context."
        )
        .into();
    }
    text.into()
}

/// One of the trustee's two reads, signed as the trustee by the VTA and sent to the ballot box.
async fn read(
    client: &VtaClient,
    bb: &BallotBox,
    t: &TrusteeTarget<'_>,
    election_id: &str,
    which: &str,
) -> CliResult<Value> {
    let mut req = base(t, election_id);
    req["ballotBox"] = json!(t.ballot_box);
    req["read"] = json!(which);
    let signed = client
        .pcs_trustee_read(&serde_json::from_value(req)?)
        .await
        .map_err(|e| hint_trustee(e.to_string(), t.trustee))?;
    bb.send(&serde_json::to_value(&signed.document)?).await
}

/// The election and where its ceremony stands, as the ballot box reports them to the trustee.
struct View {
    manifest: Value,
    status: Value,
    /// This trustee's index in the manifest's `trustees.dids`, from 1.
    index: u64,
}

impl View {
    fn phase(&self) -> &str {
        self.status["phase"].as_str().unwrap_or_default()
    }

    fn mine(&self, list: &str, field: &str) -> bool {
        self.status[list]
            .as_array()
            .into_iter()
            .flatten()
            .any(|v| v[field].as_u64() == Some(self.index))
    }

    fn confirmed(&self) -> bool {
        self.status["confirmed"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|v| v.as_u64() == Some(self.index))
    }

    fn decrypted(&self) -> bool {
        self.status["decrypted"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|v| v.as_u64() == Some(self.index))
    }

    /// The shares dealers revealed in answer to this trustee's complaints.
    fn justifications(&self) -> Vec<Value> {
        self.status["complaints"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["recipient"].as_u64() == Some(self.index) && c["justified"] == true)
            .map(|c| json!({ "dealer": c["dealer"], "share": c["share"] }))
            .collect()
    }

    /// The trustees who complained of this trustee's dealing and have no answer yet.
    fn unanswered(&self) -> Vec<u64> {
        self.status["complaints"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["dealer"].as_u64() == Some(self.index) && c["justified"] != true)
            .filter_map(|c| c["recipient"].as_u64())
            .collect()
    }
}

async fn view(
    client: &VtaClient,
    bb: &BallotBox,
    t: &TrusteeTarget<'_>,
    election_id: &str,
) -> CliResult<View> {
    let shown = read(client, bb, t, election_id, "election").await?;
    let manifest = shown["manifest"].clone();
    let index = manifest["trustees"]["dids"]
        .as_array()
        .and_then(|dids| dids.iter().position(|d| d.as_str() == Some(t.trustee)))
        .map(|i| i as u64 + 1)
        .ok_or_else(|| {
            format!(
                "the manifest of {election_id} does not name {} as a trustee",
                t.trustee
            )
        })?;
    let status = read(client, bb, t, election_id, "status").await?;
    Ok(View {
        manifest,
        status,
        index,
    })
}

/// What one pass did, and what it waits for.
#[derive(Default)]
struct Pass {
    did: Vec<String>,
    waiting: Option<String>,
    finished: bool,
}

/// One pass: every step the ceremony needs of this trustee now.
async fn pass(
    client: &VtaClient,
    bb: &BallotBox,
    t: &TrusteeTarget<'_>,
    election_id: &str,
) -> CliResult<Pass> {
    let v = view(client, bb, t, election_id).await?;
    let mut out = Pass::default();
    let mut req = base(t, election_id);
    req["manifest"] = v.manifest.clone();
    match v.phase() {
        "enrolling" if !v.mine("transportKeys", "trustee") => {
            let r = client
                .pcs_trustee_enrol(&serde_json::from_value(req)?)
                .await
                .map_err(|e| hint_trustee(e.to_string(), t.trustee))?;
            bb.send(&serde_json::to_value(&r.document)?).await?;
            out.did.push("enrolled: published the transport key".into());
            out.waiting = Some("the other trustees to enrol".into());
        }
        "enrolling" => out.waiting = Some("the other trustees to enrol".into()),
        "dealing" if !v.mine("dealings", "dealer") => {
            req["transportKeys"] = v.status["transportKeys"].clone();
            let r = client
                .pcs_trustee_deal(&serde_json::from_value(req)?)
                .await
                .map_err(|e| hint_trustee(e.to_string(), t.trustee))?;
            bb.send(&serde_json::to_value(&r.document)?).await?;
            out.did
                .push("dealt: published the commitments and sealed shares".into());
            out.waiting = Some("the other trustees to deal".into());
        }
        "dealing" => out.waiting = Some("the other trustees to deal".into()),
        "confirming" => {
            // Answer every complaint against this trustee's dealing: the share in the clear.
            for recipient in v.unanswered() {
                let mut j = base(t, election_id);
                j["recipient"] = json!(recipient);
                let r = client
                    .pcs_trustee_justify(&serde_json::from_value(j)?)
                    .await
                    .map_err(|e| hint_trustee(e.to_string(), t.trustee))?;
                bb.send(&serde_json::to_value(&r.document)?).await?;
                out.did.push(format!(
                    "answered trustee {recipient}'s complaint with its share"
                ));
            }
            if !v.confirmed() {
                req["dealings"] = v.status["dealings"].clone();
                req["justifications"] = json!(v.justifications());
                let r = serde_json::to_value(
                    client
                        .pcs_trustee_keys(&serde_json::from_value(req)?)
                        .await
                        .map_err(|e| hint_trustee(e.to_string(), t.trustee))?,
                )?;
                if r["document"].is_object() {
                    bb.send(&r["document"]).await?;
                }
                let complaints = r["complaints"].as_array().map_or(0, Vec::len);
                out.did.push(if complaints == 0 {
                    "confirmed: every share dealt to this trustee checks".into()
                } else {
                    format!(
                        "confirmed, complaining of {complaints} dealer(s): {}",
                        r["complaints"]
                    )
                });
            }
            out.waiting =
                Some("the other trustees to confirm, and complaints to be answered".into());
        }
        "done" => out.finished = true,
        "keyed" | "decrypting" => {
            // Keep the key share once the key has formed; the VTA answers a repeat at once.
            req["dealings"] = v.status["dealings"].clone();
            req["justifications"] = json!(v.justifications());
            req["electionKey"] = v.status["electionKey"].clone();
            let r = serde_json::to_value(
                client
                    .pcs_trustee_keys(&serde_json::from_value(req)?)
                    .await
                    .map_err(|e| hint_trustee(e.to_string(), t.trustee))?,
            )?;
            if r["keyHeld"] != true {
                return Err("the election key formed, but this trustee's share does not match its verification key".into());
            }
            match v.phase() {
                "keyed" => out.waiting = Some("voting to close; then decrypt".into()),
                "decrypting" if !v.decrypted() => {
                    let mut d = base(t, election_id);
                    d["targets"] = v.status["targets"].clone();
                    // A private board does not show this trustee when voting closed early; the
                    // ballot box is decrypting, so it closed no later than now, and no later
                    // than the manifest's votingCloses.
                    let closes: chrono::DateTime<chrono::Utc> = v.manifest["votingCloses"]
                        .as_str()
                        .unwrap_or_default()
                        .parse()
                        .map_err(|e| format!("the manifest's votingCloses: {e}"))?;
                    let closed = closes.min(chrono::Utc::now());
                    d["closedAt"] =
                        json!(closed.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
                    let r = client
                        .pcs_trustee_decrypt(&serde_json::from_value(d)?)
                        .await
                        .map_err(|e| hint_trustee(e.to_string(), t.trustee))?;
                    let answer = bb.send(&serde_json::to_value(&r.document)?).await?;
                    out.did
                        .push("decrypted: published this trustee's partial decryptions".into());
                    if answer["phase"] == "done" {
                        out.finished = true;
                    } else {
                        out.waiting = Some("enough other trustees to decrypt".into());
                    }
                }
                _ => out.waiting = Some("enough other trustees to decrypt".into()),
            }
        }
        "failed" => {
            return Err(
                "the ceremony failed: no election key formed by votingOpens, so the community \
                 cancels the election"
                    .into(),
            );
        }
        other => return Err(format!("the ballot box reports an unknown phase {other:?}").into()),
    }
    Ok(out)
}

/// `pnm elections trustee status <id>`: where the ceremony stands, as the ballot box reports it.
pub async fn cmd_status(client: &VtaClient, t: TrusteeTarget<'_>, election_id: &str) -> CliResult {
    let bb = BallotBox {
        url: ballot_box_url(t.ballot_box).await?,
    };
    let v = view(client, &bb, &t, election_id).await?;
    if is_json_output() {
        return Ok(print_json(
            &json!({ "trustee": v.index, "status": v.status }),
        )?);
    }
    let count = |k: &str| v.status[k].as_array().map_or(0, Vec::len);
    let n = v.manifest["trustees"]["dids"]
        .as_array()
        .map_or(0, Vec::len);
    println!(
        "{BOLD}{election_id}{RESET}  phase {}  — you are trustee {} of {n}, threshold {}",
        v.phase(),
        v.index,
        v.status["threshold"]
    );
    println!(
        "  enrolled {}/{n}   dealt {}/{n}   confirmed {}/{n}   decrypted {}",
        count("transportKeys"),
        count("dealings"),
        count("confirmed"),
        count("decrypted"),
    );
    let open = v.unanswered();
    if !open.is_empty() {
        println!("  {YELLOW}complaints against your dealing to answer: {open:?}{RESET}");
    }
    if v.status.get("electionKey").is_some() {
        println!("  {DIM}the election key has formed{RESET}");
    }
    Ok(())
}

/// `pnm elections trustee step <id> [--watch]`: take every step the ceremony needs of this
/// trustee now; with `--watch`, again every 30 seconds until it needs nothing more.
pub async fn cmd_step(
    client: &VtaClient,
    t: TrusteeTarget<'_>,
    election_id: &str,
    watch: bool,
) -> CliResult {
    let bb = BallotBox {
        url: ballot_box_url(t.ballot_box).await?,
    };
    loop {
        let p = pass(client, &bb, &t, election_id).await?;
        if is_json_output() {
            print_json(&json!({ "did": p.did, "waiting": p.waiting, "finished": p.finished }))?;
        } else {
            for d in &p.did {
                println!("{GREEN}{d}{RESET}");
            }
            match (&p.waiting, p.finished) {
                (_, true) => {
                    println!("{GREEN}nothing more is needed of you: the result is out{RESET}")
                }
                (Some(w), _) => println!("{DIM}waiting for {w}{RESET}"),
                (None, _) => {}
            }
        }
        if p.finished || !watch {
            return Ok(());
        }
        tokio::time::sleep(WATCH_EVERY).await;
    }
}
