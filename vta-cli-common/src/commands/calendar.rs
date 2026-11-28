//! `pnm calendar …` — the member's calendar the VTA keeps (`vta/calendar/*/0.1`,
//! VTI-CAL-001 – 071).
//!
//! `list` shows the events you registered for (`mine`, read from each community as your
//! membership identifier there) and those you hold only a notification of (`notified`), across
//! every trust context you have standing in. `sync` reads the communities now; `settings`
//! turns reading on or off per context and sets default reminders and quiet hours; `alerts`
//! sets one event's own reminders; `feeds` manages private iCalendar subscriptions; `export`
//! writes an `.ics` file and the receipts kept.
//!
//! A refusal whose fix is another command prints that command (workspace rule: operator
//! errors suggest the fix).

use serde_json::{Value, json};
use vta_sdk::error::VtaError;
use vta_sdk::prelude::*;
use vta_sdk::trust_tasks as tt;

use crate::render::{BOLD, CYAN, DIM, GREEN, RESET, YELLOW, is_json_output, print_json};

type CmdResult = Result<(), Box<dyn std::error::Error>>;

/// The local part of a declared refusal's code (`…:eventNotHeld` → `eventNotHeld`).
fn local_code(e: &VtaError) -> Option<&str> {
    e.rejection_code()
        .map(|c| c.rsplit_once(':').map_or(c, |(_, l)| l))
}

/// The command that fixes a refusal, when the operator's intent maps to one.
fn fix_for(code: &str, context: Option<&str>) -> Option<String> {
    let ctx = context.unwrap_or("<context>");
    Some(match code {
        "syncOff" => format!(
            "Busy times come from the synced calendar. Turn reading on first:\n    \
             pnm calendar settings update --context {ctx} --sync on"
        ),
        "eventNotHeld" => format!(
            "The calendar does not hold that event yet. Read your communities, then list:\n    \
             pnm calendar sync --context {ctx}\n    pnm calendar list --context {ctx}"
        ),
        "limitReached" => "Revoke a feed you no longer use first:\n    \
             pnm calendar feeds list\n    pnm calendar feeds revoke <feed-id>"
            .to_string(),
        "expiryInvalid" => {
            "A feed expires after now and within a year, e.g. --expires 90d".to_string()
        }
        "alreadyRevoked" => {
            "Nothing to do; `pnm calendar feeds create` makes a new one.".to_string()
        }
        "feedNotFound" => {
            "List the feeds you may see:\n    pnm calendar feeds list --include-revoked".to_string()
        }
        "quietHoursInvalid" => "Quiet hours take HH:MM times and an IANA zone, e.g.\n    \
             --quiet 22:00-07:00 --time-zone Europe/Berlin"
            .to_string(),
        "rangeInvalid" => "`--to` must come after `--from` (at most 400 days later).".to_string(),
        _ => return None,
    })
}

/// Pass `r` through, adding the fix to a refusal that has one.
fn explain<T>(
    r: Result<T, VtaError>,
    context: Option<&str>,
) -> Result<T, Box<dyn std::error::Error>> {
    match r {
        Ok(v) => Ok(v),
        Err(e) => {
            if let Some(fix) = local_code(&e).and_then(|c| fix_for(c, context)) {
                Err(format!("{e}\n  {fix}").into())
            } else {
                Err(Box::new(e))
            }
        }
    }
}

async fn call(
    client: &VtaClient,
    uri: &str,
    payload: Value,
    context: Option<&str>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let timeout = if uri == tt::TASK_VTA_CALENDAR_SYNC_0_1 {
        120
    } else {
        20
    };
    explain(
        client.dispatch_trust_task(uri, payload, timeout).await,
        context,
    )
}

/// A duration such as `90d`, `12h` or `30m`.
fn parse_span(s: &str) -> Result<chrono::Duration, String> {
    let (n, unit) = s.split_at(s.len().saturating_sub(1));
    let n: i64 = n
        .parse()
        .map_err(|_| format!("`{s}` is not a duration like 90d, 12h or 30m"))?;
    match unit {
        "d" => Ok(chrono::Duration::days(n)),
        "h" => Ok(chrono::Duration::hours(n)),
        "m" => Ok(chrono::Duration::minutes(n)),
        _ => Err(format!("`{s}` is not a duration like 90d, 12h or 30m")),
    }
}

/// Options for `calendar list`.
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    pub contexts: Vec<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub tiers: Vec<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

/// `list` → `vta/calendar/list/0.1`.
pub async fn cmd_calendar_list(client: &VtaClient, opts: &ListOptions) -> CmdResult {
    let mut req = json!({});
    if !opts.contexts.is_empty() {
        req["contextIds"] = json!(opts.contexts);
    }
    if let Some(f) = &opts.from {
        req["from"] = json!(f);
    }
    if let Some(t) = &opts.to {
        req["to"] = json!(t);
    }
    if !opts.tiers.is_empty() {
        req["tiers"] = json!(opts.tiers);
    }
    if let Some(l) = opts.limit {
        req["limit"] = json!(l);
    }
    if let Some(c) = &opts.cursor {
        req["cursor"] = json!(c);
    }
    let ctx = opts.contexts.first().map(String::as_str);
    let resp = call(client, tt::TASK_VTA_CALENDAR_LIST_0_1, req, ctx).await?;
    if is_json_output() {
        return Ok(print_json(&resp)?);
    }
    let items = resp["items"].as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        println!("Nothing in the calendar for this range.");
        if opts.tiers.is_empty() || opts.tiers.iter().any(|t| t == "mine") {
            println!(
                "{DIM}Registered events appear once the communities are read: \
                 `pnm calendar sync`.{RESET}"
            );
        }
    } else {
        println!();
        for item in &items {
            println!("  {}", entry_line(item));
        }
        println!();
    }
    if let Some(c) = resp["nextCursor"].as_str() {
        println!("{DIM}More remain: pass --cursor {c}{RESET}");
    }
    Ok(())
}

fn entry_line(item: &Value) -> String {
    let tier = item["tier"].as_str().unwrap_or("?");
    let start = item
        .pointer("/period/startsAt")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let title = item
        .pointer("/event/title")
        .and_then(Value::as_str)
        .unwrap_or("(notified)");
    let mut flags = Vec::new();
    if item["overlaps"].as_bool() == Some(true) {
        flags.push(format!("{YELLOW}overlaps{RESET}"));
    }
    if let Some(s) = item["registrationStatus"].as_str() {
        flags.push(s.to_string());
    }
    if item["withdrawn"].as_bool() == Some(true) {
        flags.push("withdrawn".into());
    }
    format!(
        "{CYAN}{start}{RESET}  {BOLD}{title}{RESET}  {DIM}[{tier}] {} · {} · {}{}{RESET}",
        item["contextId"].as_str().unwrap_or("?"),
        item["community"].as_str().unwrap_or("?"),
        item["eventId"].as_str().unwrap_or("?"),
        if flags.is_empty() {
            String::new()
        } else {
            format!(" · {}", flags.join(", "))
        },
    )
}

/// `sync` → `vta/calendar/sync/0.1`.
pub async fn cmd_calendar_sync(client: &VtaClient, context: Option<&str>) -> CmdResult {
    let mut req = json!({});
    if let Some(c) = context {
        req["contextId"] = json!(c);
    }
    let resp = call(client, tt::TASK_VTA_CALENDAR_SYNC_0_1, req, context).await?;
    if is_json_output() {
        return Ok(print_json(&resp)?);
    }
    let results = resp["results"].as_array().cloned().unwrap_or_default();
    if results.is_empty() {
        println!(
            "No community was read: no context with reading on holds a membership credential.\n\
             {DIM}Turn reading on with `pnm calendar settings update --context <id> --sync on`.{RESET}"
        );
    }
    for r in &results {
        println!(
            "  {} {}  {DIM}{}{}{}{RESET}",
            r["status"].as_str().unwrap_or("?"),
            r["community"].as_str().unwrap_or("?"),
            r["contextId"].as_str().unwrap_or("?"),
            r["changed"]
                .as_u64()
                .map_or(String::new(), |n| format!(" · {n} changed")),
            r["code"]
                .as_str()
                .map_or(String::new(), |c| format!(" · {c}")),
        );
    }
    Ok(())
}

/// `settings show` → `vta/calendar/settings/show/0.1`.
pub async fn cmd_calendar_settings_show(client: &VtaClient, context: &str) -> CmdResult {
    let resp = call(
        client,
        tt::TASK_VTA_CALENDAR_SETTINGS_SHOW_0_1,
        json!({ "contextId": context }),
        Some(context),
    )
    .await?;
    if is_json_output() {
        return Ok(print_json(&resp)?);
    }
    print_settings(&resp["settings"]);
    Ok(())
}

fn print_settings(s: &Value) {
    println!();
    println!(
        "  {BOLD}{}{RESET}  sync {}",
        s["contextId"].as_str().unwrap_or("?"),
        if s["sync"].as_bool() == Some(true) {
            "on"
        } else {
            "off"
        }
    );
    println!(
        "  default reminders (minutes before): {}",
        s["defaultReminderMinutes"]
    );
    match s.get("quietHours") {
        Some(q) if !q.is_null() => println!(
            "  quiet hours {}–{} {}",
            q["startsAt"].as_str().unwrap_or("?"),
            q["endsAt"].as_str().unwrap_or("?"),
            q["timeZone"].as_str().unwrap_or("?")
        ),
        _ => println!("  {DIM}no quiet hours{RESET}"),
    }
    println!();
}

/// Options for `calendar settings update`.
#[derive(Debug, Clone, Default)]
pub struct SettingsUpdate {
    pub sync: Option<bool>,
    pub default_reminders: Option<Vec<u32>>,
    /// `HH:MM-HH:MM`; `Some("")` or `Some("none")` clears quiet hours.
    pub quiet: Option<String>,
    pub time_zone: Option<String>,
}

/// `settings update` → `vta/calendar/settings/update/0.1`.
pub async fn cmd_calendar_settings_update(
    client: &VtaClient,
    context: &str,
    upd: &SettingsUpdate,
) -> CmdResult {
    let mut req = json!({ "contextId": context });
    if let Some(s) = upd.sync {
        req["sync"] = json!(s);
    }
    if let Some(d) = &upd.default_reminders {
        req["defaultReminderMinutes"] = json!(d);
    }
    if let Some(q) = &upd.quiet {
        if q.is_empty() || q == "none" {
            req["quietHours"] = Value::Null;
        } else {
            let (a, b) = q
                .split_once('-')
                .ok_or("--quiet takes HH:MM-HH:MM, or `none` to clear")?;
            let Some(tz) = &upd.time_zone else {
                return Err(
                    "--quiet needs --time-zone (an IANA zone such as Europe/Berlin)".into(),
                );
            };
            req["quietHours"] = json!({ "startsAt": a, "endsAt": b, "timeZone": tz });
        }
    }
    let resp = call(
        client,
        tt::TASK_VTA_CALENDAR_SETTINGS_UPDATE_0_1,
        req,
        Some(context),
    )
    .await?;
    if is_json_output() {
        return Ok(print_json(&resp)?);
    }
    println!("{GREEN}\u{2713}{RESET} Settings saved.");
    print_settings(&resp["settings"]);
    Ok(())
}

/// `alerts set` → `vta/calendar/alerts/set/0.1`. An empty `minutes` means no reminders.
pub async fn cmd_calendar_alerts_set(
    client: &VtaClient,
    context: &str,
    community: &str,
    event_id: &str,
    minutes: &[u32],
) -> CmdResult {
    let resp = call(
        client,
        tt::TASK_VTA_CALENDAR_ALERTS_SET_0_1,
        json!({
            "contextId": context,
            "community": community,
            "eventId": event_id,
            "reminderMinutes": minutes,
        }),
        Some(context),
    )
    .await?;
    if is_json_output() {
        return Ok(print_json(&resp)?);
    }
    if minutes.is_empty() {
        println!("{GREEN}\u{2713}{RESET} No reminders for {BOLD}{event_id}{RESET}.");
    } else {
        println!(
            "{GREEN}\u{2713}{RESET} Reminders for {BOLD}{event_id}{RESET}: {minutes:?} minutes before."
        );
    }
    Ok(())
}

/// `alerts clear` → `vta/calendar/alerts/clear/0.1`.
pub async fn cmd_calendar_alerts_clear(
    client: &VtaClient,
    context: &str,
    community: &str,
    event_id: &str,
) -> CmdResult {
    let resp = call(
        client,
        tt::TASK_VTA_CALENDAR_ALERTS_CLEAR_0_1,
        json!({ "contextId": context, "community": community, "eventId": event_id }),
        Some(context),
    )
    .await?;
    if is_json_output() {
        return Ok(print_json(&resp)?);
    }
    if resp["changed"].as_bool() == Some(true) {
        println!(
            "{GREEN}\u{2713}{RESET} {event_id} follows the context's default reminders again."
        );
    } else {
        println!("{event_id} had no reminders of its own.");
    }
    Ok(())
}

/// Options for `calendar feeds create`.
#[derive(Debug, Clone, Default)]
pub struct FeedCreate {
    pub contexts: Vec<String>,
    pub label: Option<String>,
    pub detail: Option<String>,
    pub tiers: Vec<String>,
    pub expires: String,
}

/// `feeds create` → `vta/calendar/feeds/create/0.1`. The URL is printed once.
pub async fn cmd_calendar_feeds_create(client: &VtaClient, opts: &FeedCreate) -> CmdResult {
    let span = parse_span(&opts.expires)?;
    let expires = (chrono::Utc::now() + span).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut req = json!({ "contextIds": opts.contexts, "expiresAt": expires });
    if let Some(l) = &opts.label {
        req["label"] = json!(l);
    }
    if let Some(d) = &opts.detail {
        req["detail"] = json!(d);
    }
    if !opts.tiers.is_empty() {
        req["tiers"] = json!(opts.tiers);
    }
    let ctx = opts.contexts.first().map(String::as_str);
    let resp = call(client, tt::TASK_VTA_CALENDAR_FEEDS_CREATE_0_1, req, ctx).await?;
    if is_json_output() {
        return Ok(print_json(&resp)?);
    }
    println!(
        "{GREEN}\u{2713}{RESET} Feed {BOLD}{}{RESET} expires {}.",
        resp["feed"]["feedId"].as_str().unwrap_or("?"),
        resp["feed"]["expiresAt"].as_str().unwrap_or("?")
    );
    println!();
    println!("  {}", resp["url"].as_str().unwrap_or("?"));
    println!();
    println!(
        "{YELLOW}This address is the credential and is shown only now.{RESET} Give it to your \
         calendar application and keep it nowhere else; anyone holding it reads the feed until \
         `pnm calendar feeds revoke`."
    );
    Ok(())
}

/// `feeds list` → `vta/calendar/feeds/list/0.1`.
pub async fn cmd_calendar_feeds_list(client: &VtaClient, include_revoked: bool) -> CmdResult {
    let resp = call(
        client,
        tt::TASK_VTA_CALENDAR_FEEDS_LIST_0_1,
        json!({ "includeRevoked": include_revoked }),
        None,
    )
    .await?;
    if is_json_output() {
        return Ok(print_json(&resp)?);
    }
    let items = resp["items"].as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        println!("No feeds. `pnm calendar feeds create --context <id>` makes one.");
    }
    for f in &items {
        println!(
            "  {CYAN}{}{RESET}  {BOLD}{}{RESET}  {DIM}{} · expires {} · last read {} ({} reads){}{RESET}",
            f["feedId"].as_str().unwrap_or("?"),
            f["label"].as_str().unwrap_or(""),
            f["detail"].as_str().unwrap_or("?"),
            f["expiresAt"].as_str().unwrap_or("?"),
            f["lastFetchedAt"].as_str().unwrap_or("never"),
            f["fetchCount"].as_u64().unwrap_or(0),
            if f.get("revokedAt").is_some_and(|v| !v.is_null()) {
                " · revoked"
            } else {
                ""
            },
        );
    }
    Ok(())
}

/// `feeds revoke` → `vta/calendar/feeds/revoke/0.1`.
pub async fn cmd_calendar_feeds_revoke(client: &VtaClient, feed_id: &str) -> CmdResult {
    let resp = call(
        client,
        tt::TASK_VTA_CALENDAR_FEEDS_REVOKE_0_1,
        json!({ "feedId": feed_id }),
        None,
    )
    .await?;
    if is_json_output() {
        return Ok(print_json(&resp)?);
    }
    println!(
        "{GREEN}\u{2713}{RESET} Feed {BOLD}{feed_id}{RESET} revoked; its address reads nothing from now on."
    );
    Ok(())
}

/// `export` → `vta/calendar/export/0.1`: the iCalendar object to `out` (`-` for stdout), and
/// the receipts, exactly as received, to `receipts_out` when given.
pub async fn cmd_calendar_export(
    client: &VtaClient,
    contexts: &[String],
    out: &str,
    receipts_out: Option<&str>,
) -> CmdResult {
    let mut req = json!({ "includeReceipts": receipts_out.is_some() });
    if !contexts.is_empty() {
        req["contextIds"] = json!(contexts);
    }
    let ctx = contexts.first().map(String::as_str);
    let resp = call(client, tt::TASK_VTA_CALENDAR_EXPORT_0_1, req, ctx).await?;
    if is_json_output() {
        return Ok(print_json(&resp)?);
    }
    let ics = resp["ics"].as_str().unwrap_or_default();
    if out == "-" {
        print!("{ics}");
    } else {
        std::fs::write(out, ics)?;
        println!("{GREEN}\u{2713}{RESET} Wrote {out}.");
    }
    if let Some(path) = receipts_out {
        // As received: the receipts' proofs cover these bytes (VTI-CAL-030).
        std::fs::write(path, serde_json::to_vec_pretty(&resp["receipts"])?)?;
        println!("{GREEN}\u{2713}{RESET} Wrote the receipts to {path}.");
        if let Some(c) = resp["nextCursor"].as_str() {
            println!(
                "{DIM}More receipts remain (cursor {c}); pass `--json` to `pnm calendar export` to see them.{RESET}"
            );
        }
    }
    Ok(())
}
