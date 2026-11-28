// Handlers share the `Result<_, Response>` shape via `parse_payload`.
#![allow(clippy::result_large_err)]

//! The member's calendar (`vta/calendar/*/0.1`, VTI-CAL-001 – 071; trust-tasks-tf #1409).
//!
//! Every task answers only for the trust contexts the caller has standing in, and a listing
//! never says another context holds anything (VTI-CAL-001, VTI-CAL-002). A task naming one
//! context the caller has no standing in is `permissionDenied`, before anything is read.
//! The domain logic is [`crate::operations::calendar`].

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, TrustTask};
use vti_specs::vta::calendar as spec;

use crate::auth::AuthClaims;
use crate::operations::calendar::{self as cal, Alert, BusyShare, QuietHours};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, reject_declared,
    reject_with, success_response,
};

type Doc = TrustTask<Value>;

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn strings(v: &Value, key: &str) -> Option<Vec<String>> {
    v.get(key).and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    })
}

fn minutes(v: &Value, key: &str) -> Option<Vec<u32>> {
    v.get(key).and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_u64)
            .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
            .collect()
    })
}

fn instant(v: &Value, key: &str) -> Option<DateTime<Utc>> {
    str_of(v, key)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc))
}

fn denied(doc: &Doc, why: &str) -> TrustTaskOutcome {
    reject_with(
        doc,
        RejectReason::PermissionDenied {
            reason: why.to_string(),
        },
    )
}

fn respond<R: serde::de::DeserializeOwned + serde::Serialize>(
    doc: &Doc,
    value: Value,
) -> TrustTaskOutcome {
    match serde_json::from_value::<R>(value) {
        Ok(r) => success_response(doc, r),
        Err(e) => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("{} response does not match its schema: {e}", doc.type_uri),
            },
        ),
    }
}

/// VTI-CAL-071: feed creation and revocation, sharing choices and settings changes are
/// audited — by reference, never an entry's title, a receipt's content or a reminder.
async fn audit(state: &AppState, action: &str, actor: &str, context: Option<&str>, detail: &str) {
    vta_audit::record_with_detail_best_effort(
        &state.audit_sink,
        action,
        actor,
        None,
        "success",
        Some(TRANSPORT_TRUST_TASK),
        context,
        Some(detail),
    )
    .await;
}

/// An opaque offset cursor bound to the caller and the question.
fn cursor_for(auth: &AuthClaims, binding: &str, offset: usize) -> String {
    use base64::Engine as _;
    let tag = cal_digest(&format!("{}\0{binding}", auth.did));
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{tag}:{offset}"))
}

fn offset_of(auth: &AuthClaims, binding: &str, cursor: Option<&str>) -> Result<usize, ()> {
    let Some(c) = cursor else {
        return Ok(0);
    };
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(c)
        .map_err(|_| ())?;
    let s = String::from_utf8(raw).map_err(|_| ())?;
    let (tag, off) = s.split_once(':').ok_or(())?;
    if tag != cal_digest(&format!("{}\0{binding}", auth.did)) {
        return Err(());
    }
    off.parse().map_err(|_| ())
}

fn cal_digest(s: &str) -> String {
    use sha2::Digest as _;
    hex::encode(&sha2::Sha256::digest(s.as_bytes())[..12])
}

fn foreign_cursor(doc: &Doc) -> TrustTaskOutcome {
    app_error_to_reject(
        doc,
        vti_common::error::AppError::Validation(
            "this cursor is not this caller's for these filters".into(),
        ),
    )
}

fn page<T: Clone>(items: &[T], offset: usize, limit: usize) -> (Vec<T>, Option<usize>) {
    let start = offset.min(items.len());
    let end = (start + limit).min(items.len());
    (
        items[start..end].to_vec(),
        (end < items.len()).then_some(end),
    )
}

fn limit_of(p: &Value, max: usize) -> usize {
    p.get("limit")
        .and_then(Value::as_u64)
        .map_or(50, |n| n as usize)
        .clamp(1, max)
}

/// The contexts a task names, each one the caller must have standing in.
fn one_context<'a>(doc: &'a Doc, auth: &AuthClaims) -> Result<&'a str, TrustTaskOutcome> {
    let ctx = str_of(&doc.payload, "contextId").unwrap_or_default();
    if auth.has_context_access(ctx) {
        Ok(ctx)
    } else {
        Err(denied(doc, "no standing in this trust context"))
    }
}

// ─── list, sync, settings ────────────────────────────────────────────────

pub(super) async fn handle_list(state: &AppState, auth: &AuthClaims, doc: Doc) -> TrustTaskOutcome {
    use spec::list::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let now = Utc::now();
    let from = instant(&p, "from").unwrap_or(now);
    let to = instant(&p, "to").unwrap_or(from + Duration::days(60));
    if to <= from || to - from > Duration::days(400) {
        return reject_declared(
            &doc,
            t::error_codes::RANGE_INVALID,
            "`to` comes after `from`, at most 400 days later",
        );
    }
    let named = strings(&p, "contextIds");
    let contexts = match cal::contexts_for(state, auth, named.as_deref()).await {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let tiers = strings(&p, "tiers").unwrap_or_default();
    let all = match cal::list(state, &contexts, from, to, &tiers).await {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let binding = format!("list|{contexts:?}|{from}|{to}|{tiers:?}");
    let Ok(offset) = offset_of(auth, &binding, str_of(&p, "cursor")) else {
        return foreign_cursor(&doc);
    };
    let (items, next) = page(&all, offset, limit_of(&p, 200));
    let mut body = json!({ "items": items.iter().map(|l| l.wire.clone()).collect::<Vec<_>>() });
    if let Some(n) = next {
        body["nextCursor"] = json!(cursor_for(auth, &binding, n));
    }
    respond::<t::Response>(&doc, body)
}

pub(super) async fn handle_sync(state: &AppState, auth: &AuthClaims, doc: Doc) -> TrustTaskOutcome {
    use spec::sync::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let named = str_of(&doc.payload, "contextId").map(|c| vec![c.to_string()]);
    if let Some(n) = &named
        && !auth.has_context_access(&n[0])
    {
        return denied(&doc, "no standing in this trust context");
    }
    let contexts = match cal::contexts_for(state, auth, named.as_deref()).await {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let mut results = Vec::new();
    for ctx in contexts {
        match cal::sync_context(state, &ctx, Utc::now()).await {
            Ok(r) => results.extend(r),
            Err(e) => return app_error_to_reject(&doc, e),
        }
    }
    results.truncate(500);
    // A read of the communities speaks to them as the principal's identifiers: audited by
    // count, never naming an event.
    audit(
        state,
        "calendar.sync",
        &auth.did,
        named.as_ref().map(|n| n[0].as_str()),
        &format!("{} communities", results.len()),
    )
    .await;
    respond::<t::Response>(
        &doc,
        json!({ "results": results.iter().map(cal::SyncResult::to_wire).collect::<Vec<_>>() }),
    )
}

pub(super) async fn handle_settings_show(
    state: &AppState,
    auth: &AuthClaims,
    doc: Doc,
) -> TrustTaskOutcome {
    use spec::settings::show::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let ctx = match one_context(&doc, auth) {
        Ok(c) => c.to_string(),
        Err(r) => return r,
    };
    match cal::settings(&state.calendar_ks, &ctx).await {
        Ok(s) => respond::<t::Response>(&doc, json!({ "settings": s.to_wire() })),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

pub(super) async fn handle_settings_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: Doc,
) -> TrustTaskOutcome {
    use spec::settings::update::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let ctx = match one_context(&doc, auth) {
        Ok(c) => c.to_string(),
        Err(r) => return r,
    };
    let p = doc.payload.clone();
    let quiet = match p.get("quietHours") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(v) => match serde_json::from_value::<QuietHours>(v.clone()) {
            Ok(q) if q.is_valid() => Some(Some(q)),
            _ => {
                return reject_declared(
                    &doc,
                    t::error_codes::QUIET_HOURS_INVALID,
                    "quiet hours name a known zone and a period that is not empty",
                );
            }
        },
    };
    let s = match cal::update_settings(
        state,
        &ctx,
        &auth.did,
        p.get("sync").and_then(Value::as_bool),
        minutes(&p, "defaultReminderMinutes"),
        quiet,
        Utc::now(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    audit(
        state,
        "calendar.settings.update",
        &auth.did,
        Some(&ctx),
        &format!("sync {}", s.sync),
    )
    .await;
    respond::<t::Response>(&doc, json!({ "settings": s.to_wire() }))
}

// ─── alerts ──────────────────────────────────────────────────────────────

pub(super) async fn handle_alerts_set(
    state: &AppState,
    auth: &AuthClaims,
    doc: Doc,
) -> TrustTaskOutcome {
    use spec::alerts::set::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let ctx = match one_context(&doc, auth) {
        Ok(c) => c.to_string(),
        Err(r) => return r,
    };
    let p = &doc.payload;
    let community = str_of(p, "community").unwrap_or_default().to_string();
    let event = str_of(p, "eventId").unwrap_or_default().to_string();
    match cal::holds_event(state, &ctx, &community, &event).await {
        Ok(true) => {}
        Ok(false) => {
            return reject_declared(
                &doc,
                t::error_codes::EVENT_NOT_HELD,
                "this calendar holds no such event in this context",
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    }
    let a = Alert {
        context_id: ctx,
        community,
        event_id: event,
        reminder_minutes: minutes(p, "reminderMinutes").unwrap_or_default(),
    };
    if let Err(e) = cal::set_alert(state, &a).await {
        return app_error_to_reject(&doc, e);
    }
    // By reference only — never the event's title (VTI-CAL-071).
    audit(
        state,
        "calendar.alert.set",
        &auth.did,
        Some(&a.context_id),
        &format!("event {}", a.event_id),
    )
    .await;
    respond::<t::Response>(
        &doc,
        json!({ "alert": {
            "contextId": a.context_id,
            "community": a.community,
            "eventId": a.event_id,
            "reminderMinutes": a.reminder_minutes,
        } }),
    )
}

pub(super) async fn handle_alerts_clear(
    state: &AppState,
    auth: &AuthClaims,
    doc: Doc,
) -> TrustTaskOutcome {
    use spec::alerts::clear::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let ctx = match one_context(&doc, auth) {
        Ok(c) => c.to_string(),
        Err(r) => return r,
    };
    let p = &doc.payload;
    let community = str_of(p, "community").unwrap_or_default();
    let event = str_of(p, "eventId").unwrap_or_default();
    match cal::clear_alert(state, &ctx, community, event).await {
        Ok(changed) => {
            audit(
                state,
                "calendar.alert.clear",
                &auth.did,
                Some(&ctx),
                &format!("event {event} changed {changed}"),
            )
            .await;
            respond::<t::Response>(
                &doc,
                json!({ "contextId": ctx, "community": community, "eventId": event, "changed": changed }),
            )
        }
        Err(e) => app_error_to_reject(&doc, e),
    }
}

// ─── feeds ───────────────────────────────────────────────────────────────

/// A party with standing in every context the feed covers (VTI-CAL-050, 052, 054).
fn covers_all(auth: &AuthClaims, feed: &cal::Feed) -> bool {
    feed.context_ids.iter().all(|c| auth.has_context_access(c))
}

pub(super) async fn handle_feeds_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: Doc,
) -> TrustTaskOutcome {
    use spec::feeds::create::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let contexts = strings(&p, "contextIds").unwrap_or_default();
    if contexts.is_empty() || !contexts.iter().all(|c| auth.has_context_access(c)) {
        return denied(
            &doc,
            "a feed covers only contexts the caller has standing in",
        );
    }
    let now = Utc::now();
    let Some(expires) =
        instant(&p, "expiresAt").filter(|e| *e > now && *e <= now + Duration::days(365))
    else {
        return reject_declared(
            &doc,
            t::error_codes::EXPIRY_INVALID,
            "a feed expires after now and at most a year from now (VTI-CAL-052)",
        );
    };
    let Some(base) = state.config.read().await.public_url.clone() else {
        return app_error_to_reject(
            &doc,
            vti_common::error::AppError::Conflict(
                "this VTA has no public URL to serve a feed at; set `public_url`".into(),
            ),
        );
    };
    match cal::feeds(&state.calendar_ks).await {
        Ok(f) if f.iter().filter(|x| x.live(now)).count() >= cal::MAX_LIVE_FEEDS => {
            return reject_declared(
                &doc,
                t::error_codes::LIMIT_REACHED,
                format!("this VTA keeps at most {} live feeds", cal::MAX_LIVE_FEEDS),
            );
        }
        Ok(_) => {}
        Err(e) => return app_error_to_reject(&doc, e),
    }
    let detail = str_of(&p, "detail").unwrap_or("titles").to_string();
    let tiers = strings(&p, "tiers").unwrap_or_else(|| vec!["mine".into()]);
    let label = str_of(&p, "label").unwrap_or_default().to_string();
    let (feed, token) = match cal::create_feed(
        state, &auth.did, &label, contexts, &detail, tiers, expires, now,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    audit(
        state,
        "calendar.feed.create",
        &auth.did,
        None,
        &format!("feed {}", feed.feed_id),
    )
    .await;
    let url = format!("{}/calendar/feeds/{token}.ics", base.trim_end_matches('/'));
    respond::<t::Response>(&doc, json!({ "feed": feed.to_wire(), "url": url }))
}

pub(super) async fn handle_feeds_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: Doc,
) -> TrustTaskOutcome {
    use spec::feeds::list::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let now = Utc::now();
    let include_revoked = p
        .get("includeRevoked")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut all: Vec<cal::Feed> = match cal::feeds(&state.calendar_ks).await {
        Ok(f) => f
            .into_iter()
            .filter(|f| covers_all(auth, f) && (include_revoked || f.live(now)))
            .collect(),
        Err(e) => return app_error_to_reject(&doc, e),
    };
    all.sort_by(|a, b| (b.created_at, &b.feed_id).cmp(&(a.created_at, &a.feed_id)));
    let binding = format!("feeds|{include_revoked}");
    let Ok(offset) = offset_of(auth, &binding, str_of(&p, "cursor")) else {
        return foreign_cursor(&doc);
    };
    let (items, next) = page(&all, offset, limit_of(&p, 100));
    let mut body = json!({ "items": items.iter().map(cal::Feed::to_wire).collect::<Vec<_>>() });
    if let Some(n) = next {
        body["nextCursor"] = json!(cursor_for(auth, &binding, n));
    }
    respond::<t::Response>(&doc, body)
}

pub(super) async fn handle_feeds_revoke(
    state: &AppState,
    auth: &AuthClaims,
    doc: Doc,
) -> TrustTaskOutcome {
    use spec::feeds::revoke::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let id = str_of(&doc.payload, "feedId").unwrap_or_default();
    let mut feed = match cal::get_feed(state, id).await {
        Ok(Some(f)) if covers_all(auth, &f) => f,
        Ok(_) => {
            return reject_declared(
                &doc,
                t::error_codes::FEED_NOT_FOUND,
                "no feed you may see has this identifier",
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    };
    if feed.revoked_at.is_some() {
        return reject_declared(
            &doc,
            t::error_codes::ALREADY_REVOKED,
            "this feed was already revoked",
        );
    }
    feed.revoked_at = Some(Utc::now());
    if let Err(e) = cal::put_feed(state, &feed).await {
        return app_error_to_reject(&doc, e);
    }
    audit(
        state,
        "calendar.feed.revoke",
        &auth.did,
        None,
        &format!("feed {}", feed.feed_id),
    )
    .await;
    respond::<t::Response>(&doc, json!({ "feed": feed.to_wire() }))
}

// ─── export, receipts ────────────────────────────────────────────────────

pub(super) async fn handle_export(
    state: &AppState,
    auth: &AuthClaims,
    doc: Doc,
) -> TrustTaskOutcome {
    use spec::export::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let p = doc.payload.clone();
    let from = instant(&p, "from");
    let to = instant(&p, "to");
    if let (Some(f), Some(t)) = (from, to)
        && t <= f
    {
        return reject_declared(
            &doc,
            t::error_codes::RANGE_INVALID,
            "`to` comes after `from`",
        );
    }
    let named = strings(&p, "contextIds");
    let contexts = match cal::contexts_for(state, auth, named.as_deref()).await {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let lo = from.unwrap_or(DateTime::<Utc>::MIN_UTC);
    let hi = to.unwrap_or(DateTime::<Utc>::MAX_UTC);
    let listed = match cal::list(state, &contexts, lo, hi, &["mine".into()]).await {
        Ok(l) => l,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let now = Utc::now();
    let ics = cal::to_ics(&listed, "titles", &auth.did, now);
    let mut body = json!({ "ics": ics });
    if p.get("includeReceipts")
        .and_then(Value::as_bool)
        .unwrap_or(true)
    {
        let mut all = Vec::new();
        for ctx in &contexts {
            match cal::receipts(&state.calendar_ks, ctx).await {
                Ok(r) => all.extend(r),
                Err(e) => return app_error_to_reject(&doc, e),
            }
        }
        all.retain(|r| {
            from.is_none_or(|f| r.received_at >= f) && to.is_none_or(|t| r.received_at < t)
        });
        all.sort_by(|a, b| (b.received_at, &b.receipt_id).cmp(&(a.received_at, &a.receipt_id)));
        let binding = format!("export|{contexts:?}|{from:?}|{to:?}");
        let Ok(offset) = offset_of(auth, &binding, str_of(&p, "cursor")) else {
            return foreign_cursor(&doc);
        };
        let (items, next) = page(&all, offset, limit_of(&p, 200));
        body["receipts"] = json!(items.iter().map(cal::Receipt::to_wire).collect::<Vec<_>>());
        if let Some(n) = next {
            body["nextCursor"] = json!(cursor_for(auth, &binding, n));
        }
    }
    respond::<t::Response>(&doc, body)
}

pub(super) async fn handle_receipts_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: Doc,
) -> TrustTaskOutcome {
    use spec::receipts::list::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let ctx = match one_context(&doc, auth) {
        Ok(c) => c.to_string(),
        Err(r) => return r,
    };
    let p = doc.payload.clone();
    let community = str_of(&p, "community");
    let event = str_of(&p, "eventId");
    let mut all: Vec<cal::Receipt> = match cal::receipts(&state.calendar_ks, &ctx).await {
        Ok(r) => r
            .into_iter()
            .filter(|r| community.is_none_or(|c| r.community == c))
            .filter(|r| event.is_none_or(|e| r.event_id.as_deref() == Some(e)))
            .collect(),
        Err(e) => return app_error_to_reject(&doc, e),
    };
    all.sort_by(|a, b| (b.received_at, &b.receipt_id).cmp(&(a.received_at, &a.receipt_id)));
    let binding = format!("receipts|{ctx}|{community:?}|{event:?}");
    let Ok(offset) = offset_of(auth, &binding, str_of(&p, "cursor")) else {
        return foreign_cursor(&doc);
    };
    let (items, next) = page(&all, offset, limit_of(&p, 200));
    let mut body = json!({ "items": items.iter().map(cal::Receipt::to_wire).collect::<Vec<_>>() });
    if let Some(n) = next {
        body["nextCursor"] = json!(cursor_for(auth, &binding, n));
    }
    respond::<t::Response>(&doc, body)
}

pub(super) async fn handle_receipts_deposit(
    state: &AppState,
    auth: &AuthClaims,
    doc: Doc,
) -> TrustTaskOutcome {
    use spec::receipts::deposit::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let ctx = match one_context(&doc, auth) {
        Ok(c) => c.to_string(),
        Err(r) => return r,
    };
    // The carried document exactly as received — never the parsed payload (VTI-CAL-030).
    let received = super::received::document_as_received(&doc);
    let document = received
        .get("payload")
        .and_then(|p| p.get("document"))
        .cloned()
        .unwrap_or(Value::Null);
    match cal::deposit_receipt(state, &ctx, &document, Utc::now()).await {
        Ok((receipt, already)) => respond::<t::Response>(
            &doc,
            json!({ "receipt": receipt.to_wire(), "alreadyKept": already }),
        ),
        Err(cal::ReceiptError::NotAReply(why)) => {
            reject_declared(&doc, t::error_codes::NOT_A_REPLY, why)
        }
        Err(cal::ReceiptError::NotAddressed) => reject_declared(
            &doc,
            t::error_codes::NOT_ADDRESSED,
            "the reply is addressed to no identifier this VTA holds in this context",
        ),
        Err(cal::ReceiptError::ProofInvalid(why)) => {
            reject_with(&doc, RejectReason::ProofInvalid { reason: why })
        }
        Err(cal::ReceiptError::Store(e)) => app_error_to_reject(&doc, e),
    }
}

// ─── busy times ──────────────────────────────────────────────────────────

pub(super) async fn handle_busy_share(
    state: &AppState,
    auth: &AuthClaims,
    doc: Doc,
) -> TrustTaskOutcome {
    use spec::busy::share::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let ctx = match one_context(&doc, auth) {
        Ok(c) => c.to_string(),
        Err(r) => return r,
    };
    let p = doc.payload.clone();
    let enabled = p.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    let holder = p
        .pointer("/target/holder")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let page_id = p
        .pointer("/target/pageId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if enabled {
        match cal::settings(&state.calendar_ks, &ctx).await {
            Ok(s) if s.sync => {}
            Ok(_) => {
                return reject_declared(
                    &doc,
                    t::error_codes::SYNC_OFF,
                    "busy times come from the synced calendar; turn sync on for this context first",
                );
            }
            Err(e) => return app_error_to_reject(&doc, e),
        }
    }
    let prior = cal::busy_share(state, &ctx, &holder, &page_id)
        .await
        .ok()
        .flatten();
    let share = BusyShare {
        context_id: ctx.clone(),
        holder,
        page_id,
        enabled,
        last_shared_at: prior.and_then(|s| s.last_shared_at),
        updated_by: auth.did.clone(),
        updated_at: Utc::now(),
    };
    if let Err(e) = cal::set_busy_share(state, &share).await {
        return app_error_to_reject(&doc, e);
    }
    audit(
        state,
        "calendar.busy.share",
        &auth.did,
        Some(&ctx),
        &format!("enabled {enabled}"),
    )
    .await;
    respond::<t::Response>(&doc, json!({ "share": share.to_wire() }))
}

#[cfg(test)]
#[path = "calendar_tests.rs"]
mod tests;
