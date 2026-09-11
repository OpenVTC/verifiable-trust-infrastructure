//! Vetter profiles and the vetter listing
//! (`vtc/vetting/vetters/profile/0.1`, `vtc/vetting/vetters/list/0.1`).
//!
//! A vetter publishes a profile — languages, place, methods, the documentation
//! they accept, events they will vet at — so an applicant can find a vetter
//! near them before asking for a ticket. The profile is the vetter's own
//! statement; the community stores it and decides only who may publish one
//! and who appears in a listing.
//!
//! Both tasks' payloads and responses are the generated
//! `vta_sdk::protocols::vetting::vetters::{profile, list}::v0_1` types, and a
//! stored profile is the profile payload as published.
//!
//! ## Who may publish, and who is listed
//!
//! Publishing needs what counting a statement needs: an active member holding a
//! live, unrevoked vetter grant recorded during this membership
//! ([`super::vetters::live_grant`]). A listing shows exactly those vetters whose
//! profile says `listed: true` — checked when the listing is read, so a profile
//! left behind by a grant that expired quietly is never shown.
//!
//! A profile is deleted when its vetter no longer holds a live grant because a
//! grant was revoked or they departed ([`delete_unless_granted_locked`]). An
//! expired grant keeps the profile, unlisted until the vetter is granted again.
//!
//! ## What a listing discloses
//!
//! The published profile (events already over are left out), the vetter's DID
//! and the grant's expiry. Nothing about the member row, their other
//! credentials or how they joined. A listing row is read as the listing
//! schema's own `ListedVetter`, which is closed: a profile member the listing
//! does not define fails the read instead of being disclosed.
//!
//! ## Order and pages
//!
//! With an event filter, earliest matching event first; otherwise, and among
//! equal dates, by `displayName` — vetters without one last — then by DID, both
//! compared by Unicode code point (dtgwg-trust-tasks-tf `vtc/vetting/vetters/
//! list/0.1`, Conformance 4).
//!
//! A listing is computed whole, ordered, then paged. The cursor is the position
//! of the next page in that ordering, bound to the filters it was issued for:
//! a cursor sent with different filters is refused. It names no entry. A
//! profile published or withdrawn between two pages can shift one entry across
//! the boundary — a listing is a directory, not a ledger.
//!
//! ## Stale documents
//!
//! A profile replaces the stored one, so a replayed older document would
//! restore what a vetter removed. When both carry `issuedAt`, a document older
//! than the one the stored profile came from is refused (the specification's
//! MAY, Conformance 4).

use std::cmp::Ordering;
use std::num::NonZeroU64;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

use vta_sdk::protocols::vetting::vetters::{
    list::v0_1 as list_wire, profile::v0_1 as profile_wire,
};
use vta_sdk::protocols::vetting::{
    CheckShape, DEFAULT_VETTER_LIST_LIMIT, VetterProfileSummary, has_event_filter,
};
use vti_common::audit::{AuditEvent, VetterProfileDeletedData, VetterProfileUpdatedData};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::vetters;
use crate::server::AppState;

/// Key prefix of a profile row in the `vetter_profiles` keyspace.
const PREFIX: &str = "profile:";

/// Cursor payload prefix; the rest is the offset of the next page.
const CURSOR_PREFIX: &str = "offset:";

/// Why a profile was deleted, as the audit record names it.
pub const DELETED_GRANT_REVOKED: &str = "grantRevoked";
/// See [`DELETED_GRANT_REVOKED`].
pub const DELETED_DEPARTED: &str = "departed";

/// A stored profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredProfile {
    /// The vetter — the authenticated sender who published it.
    pub vetter_did: String,
    /// The profile as published: the `vtc/vetting/vetters/profile/0.1` payload.
    pub profile: profile_wire::Payload,
    /// When it was published.
    pub updated_at: DateTime<Utc>,
    /// The publishing document's `issuedAt`, when it carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
}

impl StoredProfile {
    /// What an admin sees of it.
    pub fn summary(&self) -> VetterProfileSummary {
        let p = &self.profile;
        VetterProfileSummary {
            listed: p.listed,
            display_name: p.display_name.as_ref().map(|n| n.as_str().to_owned()),
            country: p.location.as_ref().map(|l| l.country.as_str().to_owned()),
            languages: p.languages.iter().map(|l| l.as_str().to_owned()).collect(),
            methods: p.methods.0.clone(),
            event_count: u32::try_from(p.events.len()).unwrap_or(u32::MAX),
            updated_at: self.updated_at,
        }
    }
}

fn key(vetter_did: &str) -> String {
    format!("{PREFIX}{vetter_did}")
}

/// The profile `vetter_did` published, if any.
pub async fn get_profile(
    ks: &KeyspaceHandle,
    vetter_did: &str,
) -> Result<Option<StoredProfile>, AppError> {
    match ks.get_raw(key(vetter_did).into_bytes()).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| AppError::Internal(format!("vetter profile decode: {e}"))),
        None => Ok(None),
    }
}

/// Every stored profile. A row that does not decode is skipped and logged.
pub async fn list_profiles(ks: &KeyspaceHandle) -> Result<Vec<StoredProfile>, AppError> {
    let rows = ks.prefix_iter_raw(PREFIX.as_bytes().to_vec()).await?;
    Ok(rows
        .into_iter()
        .filter_map(|(_k, v)| match serde_json::from_slice(&v) {
            Ok(p) => Some(p),
            Err(e) => {
                warn!(error = %e, "skipping an undecodable vetter profile row");
                None
            }
        })
        .collect())
}

/// Delete `vetter_did`'s profile. `true` when there was one.
pub async fn delete_profile(ks: &KeyspaceHandle, vetter_did: &str) -> Result<bool, AppError> {
    let k = key(vetter_did);
    let existed = ks.get_raw(k.clone().into_bytes()).await?.is_some();
    if existed {
        ks.remove(k.into_bytes()).await?;
    }
    Ok(existed)
}

/// Publish `body` as `vetter_did`'s profile, replacing any before it.
/// `issued_at` is the publishing document's `issuedAt`.
///
/// # Errors
///
/// [`AppError::Validation`] for a body that breaks its specification or a
/// document older than the one the stored profile came from, and
/// [`AppError::Forbidden`] when the sender is not an active member holding a
/// live vetter grant — the Trust Task dispatcher answers that with
/// `vtc/vetting/vetters/profile:notEligible`.
pub async fn publish(
    state: &AppState,
    vetter_did: &str,
    body: &profile_wire::Payload,
    issued_at: Option<DateTime<Utc>>,
) -> Result<profile_wire::Response, AppError> {
    body.check_shape()
        .map_err(|e| AppError::Validation(e.to_string()))?;
    let now = Utc::now();
    let stored = StoredProfile {
        vetter_did: vetter_did.to_string(),
        profile: body.clone(),
        updated_at: now,
        issued_at,
    };
    {
        // Under the grant lock: a revocation that deletes profiles either ran
        // before this check, and the check fails, or runs after this write and
        // deletes it.
        let _guard = vetters::GRANT_LOCK.lock().await;
        if vetters::live_grant(state, vetter_did, now).await?.is_none() {
            return Err(AppError::Forbidden(format!(
                "{vetter_did} is not an active member holding a live vetter grant"
            )));
        }
        if let Some(new) = issued_at
            && let Some(held) = get_profile(&state.vetter_profiles_ks, vetter_did)
                .await?
                .and_then(|p| p.issued_at)
            && new < held
        {
            return Err(AppError::Validation(
                "this profile document is older than the one the community holds".into(),
            ));
        }
        state
            .vetter_profiles_ks
            .insert(key(vetter_did), &stored)
            .await?;
    }
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                vetter_did,
                Some(vetter_did),
                AuditEvent::VetterProfileUpdated(VetterProfileUpdatedData {
                    listed: body.listed,
                }),
            )
            .await?;
    }
    info!(vetter = %vetter_did, listed = body.listed, "vetter profile published");
    profile_wire::Response::try_from(
        profile_wire::Response::builder()
            .listed(body.listed)
            .updated_at(now),
    )
    .map_err(|e| AppError::Internal(format!("vetter profile response: {e}")))
}

/// Delete `vetter_did`'s profile when they no longer hold a live grant, and
/// audit it. The caller holds [`vetters::GRANT_LOCK`]. `true` when a profile
/// was deleted.
pub(crate) async fn delete_unless_granted_locked(
    state: &AppState,
    actor_did: &str,
    vetter_did: &str,
    reason: &str,
) -> Result<bool, AppError> {
    if vetters::live_grant(state, vetter_did, Utc::now())
        .await?
        .is_some()
    {
        return Ok(false);
    }
    if !delete_profile(&state.vetter_profiles_ks, vetter_did).await? {
        return Ok(false);
    }
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                actor_did,
                Some(vetter_did),
                AuditEvent::VetterProfileDeleted(VetterProfileDeletedData {
                    reason: reason.to_string(),
                }),
            )
            .await?;
    }
    info!(vetter = %vetter_did, reason, "vetter profile deleted");
    Ok(true)
}

/// After a grant of `vetter_did`'s was revoked: take the grant lock and delete
/// their profile unless another live grant remains.
pub(crate) async fn after_grant_revoked(
    state: &AppState,
    actor_did: &str,
    vetter_did: &str,
) -> Result<bool, AppError> {
    let _guard = vetters::GRANT_LOCK.lock().await;
    delete_unless_granted_locked(state, actor_did, vetter_did, DELETED_GRANT_REVOKED).await
}

/// Answer a `vtc/vetting/vetters/list/0.1` request.
///
/// # Errors
///
/// [`AppError::Validation`] for a request that breaks its specification or
/// carries a cursor this community did not issue for these filters.
pub async fn list(
    state: &AppState,
    body: &list_wire::Payload,
) -> Result<list_wire::Response, AppError> {
    body.check_shape()
        .map_err(|e| AppError::Validation(e.to_string()))?;
    let tag = filter_tag(body);
    let offset = match body.cursor.as_deref() {
        Some(cursor) => decode_cursor(cursor, &tag)?,
        None => 0,
    };
    let limit = usize::try_from(
        body.limit
            .map_or(DEFAULT_VETTER_LIST_LIMIT, NonZeroU64::get),
    )
    .unwrap_or(usize::MAX)
    .max(1);
    let now = Utc::now();
    let today = now.date_naive();

    let live = vetters::live_grants(state, now).await?;
    let mut rows: Vec<(SortKey, list_wire::ListedVetter)> = Vec::new();
    for stored in list_profiles(&state.vetter_profiles_ks).await? {
        if !stored.profile.listed {
            continue;
        }
        let Some(grant) = live.get(&stored.vetter_did) else {
            continue;
        };
        let Some(grant_valid_until) = grant.valid_until else {
            continue;
        };
        let Some(event_date) = matches(&stored.profile, body, today) else {
            continue;
        };
        let sort = SortKey {
            event_date,
            name: stored
                .profile
                .display_name
                .as_ref()
                .map(|n| n.as_str().to_owned()),
            did: stored.vetter_did.clone(),
        };
        rows.push((sort, listed(stored, grant_valid_until, today)?));
    }
    rows.sort_by(|(a, _), (b, _)| a.cmp(b));

    let total = rows.len();
    let vetters: Vec<list_wire::ListedVetter> = rows
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|(_, v)| v)
        .collect();
    let next = offset.saturating_add(limit);
    let next_cursor = (next < total)
        .then(|| encode_cursor(next, &tag))
        .map(list_wire::ResponseNextCursor::try_from)
        .transpose()
        .map_err(|e| AppError::Internal(format!("vetter listing cursor: {e}")))?;
    list_wire::Response::try_from(
        list_wire::Response::builder()
            .vetters(vetters)
            .next_cursor(next_cursor),
    )
    .map_err(|e| AppError::Internal(format!("vetter listing: {e}")))
}

/// The listing order: earliest matching event first when the request filters
/// on events (every key then has a date); otherwise, and among equal dates,
/// vetters with a display name before those without, by name, then by DID —
/// names and DIDs by Unicode code point.
#[derive(Debug, PartialEq, Eq)]
struct SortKey {
    event_date: Option<NaiveDate>,
    name: Option<String>,
    did: String,
}

impl Ord for SortKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let name = match (&self.name, &other.name) {
            (Some(a), Some(b)) => a.cmp(b),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };
        self.event_date
            .cmp(&other.event_date)
            .then(name)
            .then_with(|| self.did.cmp(&other.did))
    }
}

impl PartialOrd for SortKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Does `profile` satisfy every filter in `body`? `None` when it does not;
/// otherwise the earliest matching event's start date when the request filters
/// on events, and `Some(None)` when it does not.
fn matches(
    profile: &profile_wire::Payload,
    body: &list_wire::Payload,
    today: NaiveDate,
) -> Option<Option<NaiveDate>> {
    if let Some(language) = &body.language {
        let wanted = language.to_ascii_lowercase();
        let prefix = format!("{wanted}-");
        let any = profile.languages.iter().any(|tag| {
            let tag = tag.to_ascii_lowercase();
            tag == wanted || tag.starts_with(&prefix)
        });
        if !any {
            return None;
        }
    }
    let location = profile.location.as_ref();
    if let Some(country) = &body.country
        && location.map(|l| l.country.as_str()) != Some(country.as_str())
    {
        return None;
    }
    if let Some(region) = &body.region
        && !location
            .and_then(|l| l.region.as_ref())
            .is_some_and(|r| same_text(r, region))
    {
        return None;
    }
    if let Some(city) = &body.city
        && !location
            .and_then(|l| l.city.as_ref())
            .is_some_and(|c| same_text(c, city))
    {
        return None;
    }
    // Each schema generates its own `VettingMethod` from the one shared
    // vocabulary; they compare by wire value.
    if let Some(method) = body.method
        && !profile
            .methods
            .iter()
            .any(|m| m.to_string() == method.to_string())
    {
        return None;
    }
    if !has_event_filter(body) {
        return Some(None);
    }
    let name = body.event_name.as_ref().map(|n| n.to_lowercase());
    profile
        .events
        .iter()
        .filter(|e| e.end_date.0 >= today)
        .filter(|e| {
            body.event_from
                .as_ref()
                .is_none_or(|from| e.end_date.0 >= from.0)
        })
        .filter(|e| {
            body.event_to
                .as_ref()
                .is_none_or(|to| e.start_date.0 <= to.0)
        })
        .filter(|e| {
            name.as_deref()
                .is_none_or(|n| e.name.to_lowercase().contains(n))
        })
        .map(|e| e.start_date.0)
        .min()
        .map(Some)
}

fn same_text(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// One listing row: the published profile with only the events that have not
/// ended, the vetter's DID and the grant's expiry.
///
/// The profile is read as the listing schema's `ListedVetter`. The two
/// schemas share their member definitions, and `ListedVetter` is closed, so a
/// member a profile gains that a listing does not define fails here rather than
/// reaching an applicant.
fn listed(
    stored: StoredProfile,
    grant_valid_until: DateTime<Utc>,
    today: NaiveDate,
) -> Result<list_wire::ListedVetter, AppError> {
    let internal =
        |e: &dyn std::fmt::Display| AppError::Internal(format!("vetter listing row: {e}"));
    let current: Vec<&profile_wire::VetterEvent> = stored
        .profile
        .events
        .iter()
        .filter(|e| e.end_date.0 >= today)
        .collect();
    let events = serde_json::to_value(current).map_err(|e| internal(&e))?;
    let mut row = serde_json::to_value(&stored.profile).map_err(|e| internal(&e))?;
    let fields = row
        .as_object_mut()
        .ok_or_else(|| internal(&"a profile is not an object"))?;
    // Not part of a listing entry: that the profile is listed (it is), and the
    // profile document's extensions.
    fields.remove("listed");
    fields.remove("ext");
    fields.insert("events".into(), events);
    fields.insert("vetterDid".into(), Value::String(stored.vetter_did));
    fields.insert(
        "grantValidUntil".into(),
        serde_json::to_value(grant_valid_until).map_err(|e| internal(&e))?,
    );
    fields.insert(
        "updatedAt".into(),
        serde_json::to_value(stored.updated_at).map_err(|e| internal(&e))?,
    );
    serde_json::from_value(row).map_err(|e| internal(&e))
}

/// A short digest of the request's filters — everything but `limit`, `cursor`
/// and `ext` — that a cursor is bound to.
fn filter_tag(body: &list_wire::Payload) -> String {
    use sha2::{Digest, Sha256};
    let mut filters = body.clone();
    filters.limit = None;
    filters.cursor = None;
    filters.ext = None;
    let bytes = serde_json::to_vec(&filters).unwrap_or_default();
    hex::encode(&Sha256::digest(&bytes)[..8])
}

fn encode_cursor(offset: usize, tag: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{CURSOR_PREFIX}{offset}:{tag}"))
}

fn decode_cursor(cursor: &str, tag: &str) -> Result<usize, AppError> {
    let refused =
        || AppError::Validation("cursor is not one this community issued for these filters".into());
    let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| refused())?;
    let text = String::from_utf8(bytes).map_err(|_| refused())?;
    let rest = text.strip_prefix(CURSOR_PREFIX).ok_or_else(refused)?;
    let (digits, bound) = rest.split_once(':').ok_or_else(refused)?;
    if bound != tag
        || digits.is_empty()
        || digits.len() > 9
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(refused());
    }
    digits.parse().map_err(|_| refused())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn profile(value: serde_json::Value) -> profile_wire::Payload {
        serde_json::from_value(value).unwrap()
    }

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 9, 11).unwrap()
    }

    fn carol() -> profile_wire::Payload {
        profile(json!({
            "listed": true,
            "displayName": "Carol",
            "languages": ["de-AT", "en"],
            "location": { "country": "AT", "region": "Wien", "city": "Wien" },
            "methods": ["inPerson"],
            "acceptsDocumentation": ["passport"],
            "events": [
                { "name": "Old Meetup", "startDate": "2026-08-01", "endDate": "2026-08-02" },
                { "name": "Kernel Maintainer Summit", "startDate": "2026-10-05", "endDate": "2026-10-08" },
                { "name": "Plumbers", "startDate": "2026-11-10", "endDate": "2026-11-12" }
            ]
        }))
    }

    fn filter(value: serde_json::Value) -> list_wire::Payload {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn a_language_matches_itself_or_as_a_primary_subtag_prefix() {
        let p = carol();
        assert!(matches(&p, &filter(json!({ "language": "de" })), today()).is_some());
        assert!(matches(&p, &filter(json!({ "language": "DE-at" })), today()).is_some());
        assert!(matches(&p, &filter(json!({ "language": "en" })), today()).is_some());
        assert!(matches(&p, &filter(json!({ "language": "de-CH" })), today()).is_none());
        assert!(matches(&p, &filter(json!({ "language": "fr" })), today()).is_none());
    }

    #[test]
    fn place_and_method_filters_are_exact_and_region_city_ignore_case() {
        let p = carol();
        assert!(matches(&p, &filter(json!({ "country": "AT" })), today()).is_some());
        assert!(matches(&p, &filter(json!({ "country": "DE" })), today()).is_none());
        assert!(
            matches(
                &p,
                &filter(json!({ "region": "WIEN", "city": "wien" })),
                today()
            )
            .is_some()
        );
        assert!(matches(&p, &filter(json!({ "city": "Wiener Neustadt" })), today()).is_none());
        assert!(matches(&p, &filter(json!({ "city": "Wie" })), today()).is_none());
        assert!(matches(&p, &filter(json!({ "method": "inPerson" })), today()).is_some());
        assert!(matches(&p, &filter(json!({ "method": "video" })), today()).is_none());
        let mut nowhere = carol();
        nowhere.location = None;
        assert!(matches(&nowhere, &filter(json!({ "region": "Wien" })), today()).is_none());
    }

    #[test]
    fn an_event_filter_matches_overlap_and_names_the_earliest_start() {
        let p = carol();
        let date = |from: Option<&str>, to: Option<&str>, name: Option<&str>| {
            let mut f = json!({});
            if let Some(v) = from {
                f["eventFrom"] = json!(v);
            }
            if let Some(v) = to {
                f["eventTo"] = json!(v);
            }
            if let Some(v) = name {
                f["eventName"] = json!(v);
            }
            matches(&p, &filter(f), today())
        };
        let d = |s: &str| Some(Some(s.parse::<NaiveDate>().unwrap()));
        // Overlap at either end counts.
        assert_eq!(
            date(Some("2026-10-08"), Some("2026-10-20"), None),
            d("2026-10-05")
        );
        assert_eq!(
            date(Some("2026-09-01"), Some("2026-10-05"), None),
            d("2026-10-05")
        );
        // An open end is unbounded.
        assert_eq!(date(Some("2026-10-09"), None, None), d("2026-11-10"));
        assert_eq!(date(None, Some("2026-12-31"), None), d("2026-10-05"));
        // Nothing in range.
        assert_eq!(date(Some("2026-10-09"), Some("2026-11-09"), None), None);
        // An event already over neither matches nor sorts.
        assert_eq!(date(Some("2026-08-01"), Some("2026-08-02"), None), None);
        // A name alone is an event filter; the same event must satisfy both.
        assert_eq!(date(None, None, Some("PLUMB")), d("2026-11-10"));
        assert_eq!(
            date(Some("2026-10-01"), Some("2026-10-31"), Some("plumbers")),
            None
        );
        assert_eq!(date(None, None, Some("old meetup")), None);
        // No event filter at all.
        assert_eq!(
            matches(&p, &list_wire::Payload::default(), today()),
            Some(None)
        );
    }

    #[test]
    fn listing_order_is_event_date_then_named_before_unnamed_then_did_by_code_point() {
        let key = |date: Option<&str>, name: Option<&str>, did: &str| SortKey {
            event_date: date.map(|d| d.parse().unwrap()),
            name: name.map(str::to_string),
            did: did.into(),
        };
        let mut keys = [
            key(None, None, "did:key:a"),
            key(None, Some("alice"), "did:key:z"),
            key(None, Some("Zed"), "did:key:b"),
            key(None, Some("Alice"), "did:key:d"),
            key(None, Some("Alice"), "did:key:c"),
        ];
        keys.sort();
        let dids: Vec<&str> = keys.iter().map(|k| k.did.as_str()).collect();
        // Code point: "Alice" < "Zed" < "alice"; no name last; equal names by DID.
        assert_eq!(
            dids,
            [
                "did:key:c",
                "did:key:d",
                "did:key:b",
                "did:key:z",
                "did:key:a"
            ]
        );

        let mut by_event = [
            key(Some("2026-11-01"), Some("Alice"), "did:key:a"),
            key(Some("2026-10-05"), None, "did:key:e"),
            key(Some("2026-10-05"), Some("Carol"), "did:key:c"),
        ];
        by_event.sort();
        let dids: Vec<&str> = by_event.iter().map(|k| k.did.as_str()).collect();
        assert_eq!(dids, ["did:key:c", "did:key:e", "did:key:a"]);
    }

    #[test]
    fn a_listed_vetter_shows_only_events_that_have_not_ended() {
        let stored = StoredProfile {
            vetter_did: "did:key:zCarol".into(),
            profile: carol(),
            updated_at: Utc::now(),
            issued_at: None,
        };
        let row = listed(stored, Utc::now(), today()).unwrap();
        let names: Vec<&str> = row.events.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["Kernel Maintainer Summit", "Plumbers"]);
        assert_eq!(row.methods.0, vec![list_wire::VettingMethod::InPerson]);
        assert_eq!(row.vetter_did.as_str(), "did:key:zCarol");
        let wire = serde_json::to_value(&row).unwrap();
        assert!(wire.get("listed").is_none() && wire.get("ext").is_none());
    }

    #[test]
    fn cursors_round_trip_bound_to_their_filters_and_foreign_ones_are_refused() {
        let body = filter(json!({ "language": "de", "limit": 10 }));
        let tag = filter_tag(&body);
        assert_eq!(decode_cursor(&encode_cursor(50, &tag), &tag).unwrap(), 50);
        assert!(encode_cursor(usize::MAX, &tag).len() <= 512);

        // Paging with another limit keeps the cursor; other filters do not.
        let more = filter(json!({ "language": "de", "limit": 20, "cursor": "x" }));
        assert_eq!(filter_tag(&more), tag);
        let other = filter_tag(&filter(json!({ "language": "en" })));
        assert!(decode_cursor(&encode_cursor(50, &tag), &other).is_err());

        for bad in [
            String::new(),
            "!!".into(),
            URL_SAFE_NO_PAD.encode("offset:"),
            URL_SAFE_NO_PAD.encode(format!("offset::{tag}")),
            URL_SAFE_NO_PAD.encode(format!("offset:-1:{tag}")),
            URL_SAFE_NO_PAD.encode(format!("offset:1e3:{tag}")),
            URL_SAFE_NO_PAD.encode(format!("offset:9999999999:{tag}")),
            URL_SAFE_NO_PAD.encode("offset:5"),
            URL_SAFE_NO_PAD.encode(format!("page:2:{tag}")),
            URL_SAFE_NO_PAD.encode([0xff, 0xfe]),
        ] {
            assert!(decode_cursor(&bad, &tag).is_err(), "accepted {bad:?}");
        }
    }
}
