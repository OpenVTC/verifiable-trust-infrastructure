//! `cnm actions watch` — the administrator console's live channel, on a
//! terminal: `vtc/admin/events/subscribe/0.1` over the HTTPS binding's
//! streamed response (0.3 §2.1), printing each hint as it arrives.
//!
//! A hint says which topic changed and, for the badge topics, your count —
//! never what changed. Read the topic to see it (`cnm actions list`, `cnm
//! vtc join-requests`, …). HTTPS only: no other binding defines a streamed
//! response, so `--transport` does not apply.
//!
//! The stream is re-opened with a freshly signed subscribe carrying `since`
//! whenever it ends or goes silent for twice its heartbeat, backing off
//! exponentially. A refusal retrying cannot fix (`streamUnavailable`,
//! `notAdministrator`, `permissionDenied`, `unsupportedType`) ends the command.

use std::time::Duration;

use serde_json::{Value, json};
use vta_cli_common::render::{BOLD, DIM, GREEN, RESET, YELLOW};
use vta_sdk::trust_task_sign::{HolderKey, build_unsigned, sign_in_place_with};

use crate::vtc::VtcTarget;

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

const SUBSCRIBE: &str = "https://trusttasks.org/spec/vtc/admin/events/subscribe/0.1";
const EVENT: &str = "https://trusttasks.org/spec/vtc/admin/events/event/0.1";
const STREAM_ACCEPT: &str = "text/event-stream, application/json;q=0.5";
const ALL_TOPICS: [&str; 6] = [
    "actions",
    "acknowledgements",
    "joinRequests",
    "members",
    "singleAdminMode",
    "config",
];
/// The longest heartbeat the specification allows; the silence watchdog
/// starts from it until the response names the real one.
const MAX_HEARTBEAT: Duration = Duration::from_secs(60);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Refusals after which re-subscribing cannot help.
const FINAL: [&str; 5] = [
    "streamUnavailable",
    "notAdministrator",
    "permissionDenied",
    "unsupportedType",
    "unsupportedVersion",
];

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum WatchTopic {
    Actions,
    Acknowledgements,
    JoinRequests,
    Members,
    SingleAdminMode,
    Config,
}

impl WatchTopic {
    fn wire(self) -> &'static str {
        match self {
            Self::Actions => "actions",
            Self::Acknowledgements => "acknowledgements",
            Self::JoinRequests => "joinRequests",
            Self::Members => "members",
            Self::SingleAdminMode => "singleAdminMode",
            Self::Config => "config",
        }
    }
}

pub async fn watch(
    keyring_key: &str,
    target: &VtcTarget,
    topics: &[WatchTopic],
    as_json: bool,
) -> CliResult<()> {
    let session = crate::auth::loaded_session(keyring_key).ok_or_else(|| {
        format!(
            "no stored identity for this community profile. Run `{} setup` first.",
            vta_cli_common::render::bin_name()
        )
    })?;
    let key = HolderKey::from_did_key(&session.client_did, &session.private_key_multibase)?;
    let topics: Vec<&str> = if topics.is_empty() {
        ALL_TOPICS.to_vec()
    } else {
        topics.iter().map(|t| t.wire()).collect()
    };
    // No whole-request timeout — the response is a stream that lives for up
    // to an hour — but a bounded connect, and a read timeout past the longest
    // heartbeat the specification allows (R1.2).
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(MAX_HEARTBEAT * 2 + Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let mut since: Option<String> = None;
    let mut attempt: u32 = 0;
    loop {
        let run = once(
            &http,
            target,
            &session.client_did,
            &key,
            &topics,
            &mut since,
            as_json,
        );
        let outcome = tokio::select! {
            r = run => r,
            _ = tokio::signal::ctrl_c() => return Ok(()),
        };
        match outcome {
            Ok(true) => attempt = 0,
            Ok(false) => {}
            Err(Stop(message)) => return Err(message.into()),
        }
        let wait = BACKOFF_MAX.min(Duration::from_secs(1) * 2u32.saturating_pow(attempt));
        // Jitter, so several watchers do not reconnect in step.
        let jitter = Duration::from_millis(
            u64::from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_millis())
                    .unwrap_or(0),
            ) % (wait.as_millis() as u64 / 2 + 1),
        );
        eprintln!(
            "{DIM}offline — re-subscribing in {}s (polling `cnm actions list` meanwhile shows the same){RESET}",
            (wait / 2 + jitter).as_secs()
        );
        attempt = attempt.saturating_add(1).min(16);
        tokio::select! {
            _ = tokio::time::sleep(wait / 2 + jitter) => {}
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

/// A refusal that ends the command.
struct Stop(String);

/// One subscribe and the stream it opens. `Ok(true)` when it went live.
async fn once(
    http: &reqwest::Client,
    target: &VtcTarget,
    did: &str,
    key: &HolderKey,
    topics: &[&str],
    since: &mut Option<String>,
    as_json: bool,
) -> Result<bool, Stop> {
    let mut payload = json!({ "topics": topics });
    if let Some(s) = since.as_deref() {
        payload["since"] = json!(s);
    }
    // A fresh document every time: a re-sent one is a retry of a request
    // already answered, not a reconnection (binding 0.3 §2.1.3).
    let mut doc = build_unsigned(SUBSCRIBE, payload, did, &target.did)
        .map_err(|e| Stop(format!("could not build the subscribe: {e}")))?;
    sign_in_place_with(&mut doc, key)
        .await
        .map_err(|e| Stop(format!("could not sign the subscribe: {e}")))?;

    let mut req = http
        .post(format!("{}/trust-tasks", target.base))
        .header("content-type", "application/json")
        .header("accept", STREAM_ACCEPT)
        .json(&doc);
    if let Some(s) = since.as_deref() {
        req = req.header("last-event-id", s);
    }
    let mut res = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{YELLOW}could not reach the VTC: {e}{RESET}");
            return Ok(false);
        }
    };
    let streamed = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream"));
    if !streamed {
        let status = res.status();
        let body: Value = res.json().await.unwrap_or(Value::Null);
        let code = body["payload"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let local = code.rsplit(':').next().unwrap_or_default();
        let message = body["payload"]["message"].as_str().unwrap_or_default();
        if FINAL.contains(&local) || (status.is_success() && code.is_empty()) {
            return Err(Stop(format!(
                "the VTC will not stream to this identity ({}{}{}). Poll instead: `cnm actions list`.",
                if code.is_empty() {
                    status.as_str()
                } else {
                    &code
                },
                if message.is_empty() { "" } else { ": " },
                message,
            )));
        }
        eprintln!("{YELLOW}refused ({status} {code}) {message}{RESET}");
        return Ok(false);
    }

    let mut heartbeat = MAX_HEARTBEAT;
    let mut buf = String::new();
    let mut live = false;
    loop {
        let chunk = match tokio::time::timeout(heartbeat * 2, res.chunk()).await {
            Err(_) => {
                eprintln!(
                    "{YELLOW}silent for {}s — treating the stream as dead{RESET}",
                    (heartbeat * 2).as_secs()
                );
                return Ok(live);
            }
            Ok(Err(_)) | Ok(Ok(None)) => return Ok(live),
            Ok(Ok(Some(bytes))) => bytes,
        };
        buf.push_str(&String::from_utf8_lossy(&chunk));
        let normalized = buf.replace("\r\n", "\n");
        buf = normalized;
        while let Some(end) = buf.find("\n\n") {
            let block: String = buf.drain(..end + 2).collect();
            let data: Vec<&str> = block
                .lines()
                .filter_map(|l| l.strip_prefix("data:").map(str::trim_start))
                .collect();
            if data.is_empty() {
                continue; // a heartbeat comment
            }
            let Ok(doc) = serde_json::from_str::<Value>(data.join("\n").as_str()) else {
                return Ok(live); // a framing fault: the stream cannot be trusted
            };
            if doc["issuer"].as_str() != Some(target.did.as_str())
                || doc["recipient"].as_str() != Some(did)
            {
                return Ok(live);
            }
            let p = &doc["payload"];
            if !live {
                if doc["type"].as_str() != Some(&format!("{SUBSCRIBE}#response")) {
                    return Ok(false);
                }
                live = true;
                heartbeat =
                    Duration::from_secs(p["heartbeatSeconds"].as_u64().unwrap_or(60).clamp(5, 60));
                *since = p["resumeToken"].as_str().map(str::to_string);
                if as_json {
                    println!(
                        "{}",
                        json!({ "live": true, "topics": p["topics"], "resumed": p["resumed"] })
                    );
                } else {
                    let names: Vec<&str> = p["topics"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .collect();
                    println!(
                        "{GREEN}● live{RESET} — {}{}",
                        names.join(", "),
                        if p["resumed"] == true {
                            " (resumed)"
                        } else {
                            ""
                        }
                    );
                }
                continue;
            }
            if doc["type"].as_str() != Some(EVENT) {
                continue;
            }
            *since = p["resumeToken"]
                .as_str()
                .map(str::to_string)
                .or(since.take());
            if as_json {
                println!(
                    "{}",
                    json!({ "topic": p["topic"], "at": p["at"], "count": p.get("count") })
                );
            } else {
                let count = p
                    .get("count")
                    .and_then(Value::as_u64)
                    .map(|c| format!("  {BOLD}{c}{RESET}"))
                    .unwrap_or_default();
                println!(
                    "{DIM}{}{RESET}  {}{count}",
                    p["at"].as_str().unwrap_or_default(),
                    p["topic"].as_str().unwrap_or_default()
                );
            }
        }
    }
}
