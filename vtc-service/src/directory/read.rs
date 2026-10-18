//! Reading the directory: `vtc/directory/entries/{list,show}/0.1`, and
//! `vtc/directory/query/0.1` answered through the same projection.
//!
//! Every entry a read returns is a [`super::project::project`] for the
//! caller. Search and filters match only what that projection shows, so a
//! query can never test a value the caller may not see (VTI-DIR-113).

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use serde_json::{Map, Value, json};
use vti_common::error::AppError;
use vti_common::pagination::Cursor;

use super::cards;
use super::fields;
use super::model::{FieldDef, FieldState, SearchMode};
use super::project::{self, Projection, ProjectionContext, Reached, Subject, Viewer};
use crate::acl::{Capability, get_acl_entry};
use crate::members::{get_member, list_members};
use crate::policy::load_active_compiled;
use crate::policy::model::PolicyPurpose;
use crate::server::AppState;

/// A search needs this many characters unless it is an exact nickname
/// (VTI-DIR-045).
pub const MIN_QUERY_CHARS: usize = 3;
/// At most this many matches to one search, across all its pages.
pub const MAX_SEARCH_MATCHES: usize = 50;
pub const DEFAULT_PAGE: usize = 25;
pub const MAX_PAGE: usize = 100;

/// `did` as a directory viewer: the audiences they are in, read now.
pub async fn viewer(state: &AppState, did: &str) -> Result<Viewer, AppError> {
    let entry = get_acl_entry(&state.acl_ks, did).await?;
    let active_member = crate::member_portal::active::active_member(state, did)
        .await?
        .is_some();
    let connected = if active_member {
        crate::relationships::storage::counterparties_in_force(
            &state.relationships_ks,
            &state.relationships_by_did_ks,
            did,
            Utc::now(),
        )
        .await?
    } else {
        BTreeSet::new()
    };
    Ok(Viewer {
        did: did.to_string(),
        role: entry.as_ref().map(|e| e.role.to_string()),
        active_member,
        directory_admin: entry
            .as_ref()
            .is_some_and(|e| e.can(Capability::DirectoryAdmin, None)),
        members_manage: entry
            .as_ref()
            .is_some_and(|e| e.can(Capability::MembersManage, None)),
        connected,
        groups: BTreeSet::new(),
    })
}

/// Every member with a card, as a projection subject. A member who has none
/// gets one now: every member has a card (`card/show` item 3). A card whose
/// member record is gone is skipped — nothing is left to project.
pub async fn subjects(state: &AppState) -> Result<Vec<Subject>, AppError> {
    let dir = &state.directory;
    let settings = dir.settings();
    let mut out = Vec::new();
    for member in list_members(&state.members_ks).await? {
        let entry = get_acl_entry(&state.acl_ks, &member.did).await?;
        let card = match cards::by_did(dir.ks(), &member.did).await? {
            Some(c) => c,
            // A departed member's card is never created after the fact.
            None if member.is_removed() => continue,
            None => {
                let own = entry
                    .as_ref()
                    .filter(|e| e.label_set_by_subject)
                    .and_then(|e| e.label.clone());
                cards::ensure(dir.ks(), &member.did, &settings, own.as_deref()).await?
            }
        };
        out.push(Subject::from_records(card, entry.as_ref(), Some(&member)));
    }
    Ok(out)
}

/// One subject by member DID, with a card made if they have none.
pub async fn subject_by_did(state: &AppState, did: &str) -> Result<Option<Subject>, AppError> {
    let Some(member) = get_member(&state.members_ks, did).await? else {
        return Ok(None);
    };
    let entry = get_acl_entry(&state.acl_ks, did).await?;
    let card = match cards::by_did(state.directory.ks(), did).await? {
        Some(c) => c,
        None if member.is_removed() => return Ok(None),
        None => {
            let own = entry
                .as_ref()
                .filter(|e| e.label_set_by_subject)
                .and_then(|e| e.label.clone());
            cards::ensure(
                state.directory.ks(),
                did,
                &state.directory.settings(),
                own.as_deref(),
            )
            .await?
        }
    };
    Ok(Some(Subject::from_records(
        card,
        entry.as_ref(),
        Some(&member),
    )))
}

async fn subject_by_entry(state: &AppState, entry_id: &str) -> Result<Option<Subject>, AppError> {
    let Some(card) = cards::get(state.directory.ks(), entry_id).await? else {
        return Ok(None);
    };
    let member = get_member(&state.members_ks, &card.did).await?;
    let entry = get_acl_entry(&state.acl_ks, &card.did).await?;
    if member.is_none() {
        return Ok(None);
    }
    Ok(Some(Subject::from_records(
        card,
        entry.as_ref(),
        member.as_ref(),
    )))
}

/// What a read needs once, whatever it projects.
pub struct ReadContext {
    pub schema: Vec<FieldDef>,
    pub policy: crate::policy::engine::CompiledPolicy,
    pub community_did: String,
    pub member_count: u64,
}

pub async fn read_context(state: &AppState) -> Result<ReadContext, AppError> {
    Ok(ReadContext {
        schema: fields::schema(state.directory.ks()).await?,
        policy: load_active_compiled(
            &state.active_policies_ks,
            &state.policies_ks,
            PolicyPurpose::Directory,
        )
        .await?,
        community_did: crate::community::profile::load_profile(&state.community_ks)
            .await?
            .map(|p| p.community_did)
            .unwrap_or_default(),
        member_count: state.member_count(),
    })
}

impl ReadContext {
    fn projection(&self) -> ProjectionContext<'_> {
        ProjectionContext {
            schema: &self.schema,
            policy: &self.policy,
            community_did: &self.community_did,
            member_count: self.member_count,
            now: Utc::now(),
        }
    }
}

/// Why a list was refused — one variant per declared error code.
#[derive(Debug)]
pub enum ListError {
    PermissionDenied,
    QueryTooShort,
    CursorInvalid,
    NotFound,
    RateLimited,
    Internal(AppError),
}

impl From<AppError> for ListError {
    fn from(e: AppError) -> Self {
        ListError::Internal(e)
    }
}

/// `entries/list`'s question.
#[derive(Debug, Clone, Default)]
pub struct ListQuery {
    pub query: Option<String>,
    pub filters: Vec<(String, Vec<String>)>,
    pub group: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

impl ListQuery {
    pub fn from_payload(p: &Value) -> Self {
        let filters = p
            .get("filters")
            .and_then(Value::as_array)
            .map(|fs| {
                fs.iter()
                    .filter_map(|f| {
                        let field = f.get("field")?.as_str()?.to_string();
                        let values = f
                            .get("values")?
                            .as_array()?
                            .iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect();
                        Some((field, values))
                    })
                    .collect()
            })
            .unwrap_or_default();
        ListQuery {
            query: p.get("query").and_then(Value::as_str).map(str::to_string),
            filters,
            group: p.get("group").and_then(Value::as_str).map(str::to_string),
            cursor: p.get("cursor").and_then(Value::as_str).map(str::to_string),
            limit: p.get("limit").and_then(Value::as_u64).map(|l| l as usize),
        }
    }

    /// The bytes a cursor is bound to: the caller and the whole question
    /// (VTI-DIR-112, VTI-ACL-066). Filters are sorted so their order in the
    /// document does not matter.
    fn binding(&self, viewer: &str) -> Vec<u8> {
        let mut filters: Vec<(String, Vec<String>)> = self
            .filters
            .iter()
            .map(|(f, v)| {
                let mut v = v.clone();
                v.sort();
                (f.clone(), v)
            })
            .collect();
        filters.sort();
        serde_json::to_vec(&json!({
            "task": "vtc/directory/entries/list/0.1",
            "viewer": viewer,
            "query": self.query.as_deref().map(str::trim),
            "filters": filters,
            "group": self.group,
        }))
        .unwrap_or_default()
    }
}

fn text_of(v: &Value) -> Vec<&str> {
    match v {
        Value::String(s) => vec![s.as_str()],
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    }
}

/// Whether `subject`, as `fields` projects them to the viewer, matches `q`
/// under the subject's search setting (`entries/list` items 2 and 4).
fn matches(
    q: &str,
    exact_only: bool,
    viewer: &Viewer,
    subject: &Subject,
    fields: &Map<String, Value>,
    schema: &[FieldDef],
) -> bool {
    let q = q.to_lowercase();
    let card = &subject.card;
    let nickname_is = |n: Option<&Value>| {
        n.and_then(Value::as_str)
            .is_some_and(|n| n.to_lowercase() == q)
    };
    if viewer.is_admin() {
        // An administrator may match any value, the DID included.
        return card.did.to_lowercase() == q
            || card
                .values
                .values()
                .flat_map(text_of)
                .any(|s| s.to_lowercase().contains(&q));
    }
    match card.discoverability.search {
        SearchMode::Off => false,
        // The member's handle, found by those who know it, whether or not the
        // nickname is shown to them.
        SearchMode::ExactNickname => nickname_is(card.values.get("nickname")),
        SearchMode::ByName if exact_only => nickname_is(card.values.get("nickname")),
        SearchMode::ByName => {
            let searchable: BTreeSet<&str> = schema
                .iter()
                .filter(|f| f.searchable && f.state == FieldState::Active)
                .map(|f| f.key.as_str())
                .collect();
            // Never a DID for a non-administrator (VTI-DIR-044), and only
            // what this viewer is shown.
            nickname_is(card.values.get("nickname"))
                || fields.iter().any(|(k, v)| {
                    k != "did"
                        && searchable.contains(k.as_str())
                        && text_of(v).iter().any(|s| s.to_lowercase().contains(&q))
                })
        }
    }
}

/// The order entries are returned in: by the name the viewer is shown, then
/// by entry identifier, so the order is total and a cursor can resume it.
fn sort_key(entry_id: &str, fields: &Map<String, Value>) -> String {
    let name = fields
        .get("displayName")
        .or_else(|| fields.get("nickname"))
        .and_then(Value::as_str)
        .unwrap_or("\u{10FFFF}")
        .to_lowercase();
    format!("{name}\u{0}{entry_id}")
}

/// `vtc/directory/entries/list/0.1`.
pub async fn list(state: &AppState, viewer: &Viewer, q: &ListQuery) -> Result<Value, ListError> {
    if !viewer.may_read() {
        return Err(ListError::PermissionDenied);
    }
    if !state.directory.admit_list_request(&viewer.did) {
        return Err(ListError::RateLimited);
    }
    let query = q.query.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let exact_only = query.is_some_and(|s| s.chars().count() < MIN_QUERY_CHARS);
    if exact_only && viewer.is_admin() {
        // Administrators have no nickname-only mode to fall back on.
        return Err(ListError::QueryTooShort);
    }
    // No community groups exist before groups ship: any named group is one
    // the caller may not see, answered exactly as a missing one.
    if q.group.is_some() {
        return Err(ListError::NotFound);
    }

    let ctx = read_context(state).await?;
    let pctx = ctx.projection();
    let filter_fields: BTreeMap<&str, &FieldDef> = ctx
        .schema
        .iter()
        .filter(|f| f.facet && f.state == FieldState::Active)
        .map(|f| (f.key.as_str(), f))
        .collect();
    let how = if query.is_some() {
        Reached::Search
    } else {
        Reached::Browse
    };

    let mut matched: Vec<(String, String, Projection)> = Vec::new();
    for subject in subjects(state).await? {
        // Browsing lists only complete cards; a search finds incomplete ones.
        if how == Reached::Browse
            && !viewer.is_admin()
            && !cards::required_complete(&subject.card, &ctx.schema)
        {
            continue;
        }
        let projection = project::project(&pctx, viewer, &subject, how)?;
        let Projection::Some { fields, .. } = &projection else {
            continue;
        };
        if let Some(text) = query
            && !matches(text, exact_only, viewer, &subject, fields, &ctx.schema)
        {
            continue;
        }
        let passes = q.filters.iter().all(|(field, wanted)| {
            // A filter matches only a value this viewer is shown; on a field
            // that is not a facet nothing matches.
            filter_fields.contains_key(field.as_str())
                && fields
                    .get(field)
                    .is_some_and(|v| text_of(v).iter().any(|s| wanted.iter().any(|w| w == s)))
        });
        if !passes {
            continue;
        }
        matched.push((
            sort_key(&subject.card.entry_id, fields),
            subject.card.entry_id.clone(),
            projection,
        ));
    }
    matched.sort_by(|a, b| a.0.cmp(&b.0));
    if query.is_some() {
        matched.truncate(MAX_SEARCH_MATCHES);
    }

    let facets = facet_counts(
        &matched,
        &filter_fields,
        state.directory.settings().facet_threshold,
    );

    // Pagination, bound to this caller and this question.
    let binding = q.binding(&viewer.did);
    let key = match state.audit_writer.as_ref() {
        Some(w) => Some(w.active_key().await?),
        None => None,
    };
    let start = match (&q.cursor, &key) {
        (Some(wire), Some(k)) => {
            let c = Cursor::decode_bound(wire, &k.key, &binding)
                .map_err(|_| ListError::CursorInvalid)?;
            matched
                .iter()
                .position(|(sk, _, _)| sk.as_bytes() > c.last_key.as_slice())
                .unwrap_or(matched.len())
        }
        (Some(_), None) => return Err(ListError::CursorInvalid),
        (None, _) => 0,
    };
    let limit = q.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    // Without a cursor key the whole result is one page, never an unbound
    // cursor.
    let take = if key.is_some() { limit } else { MAX_PAGE };
    let page: Vec<&(String, String, Projection)> = matched[start..].iter().take(take).collect();
    let more = start + page.len() < matched.len();
    let next = match (&key, more, page.last()) {
        (Some(k), true, Some(last)) => Some(
            Cursor::new(last.0.as_bytes().to_vec(), matched.len() as u64)
                .encode_bound(&k.key, &binding),
        ),
        _ => None,
    };
    let items: Vec<Value> = page
        .iter()
        .filter_map(|(_, id, p)| project::entry_wire(id, p))
        .collect();
    let mut body = json!({ "items": items, "nextCursor": next });
    if !facets.is_empty() {
        body["facets"] = Value::Array(facets);
    }
    Ok(body)
}

/// Counts for each facet field over the whole result, counting only values
/// the entries show this viewer; a count below `k` is never exact
/// (VTI-DIR-113).
fn facet_counts(
    matched: &[(String, String, Projection)],
    facet_fields: &BTreeMap<&str, &FieldDef>,
    k: u32,
) -> Vec<Value> {
    let mut out = Vec::new();
    for field in facet_fields.keys().take(16) {
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for (_, _, p) in matched {
            if let Projection::Some { fields, .. } = p
                && let Some(v) = fields.get(*field)
            {
                for s in text_of(v).into_iter().collect::<BTreeSet<_>>() {
                    *counts.entry(s.to_string()).or_default() += 1;
                }
            }
        }
        if counts.is_empty() {
            continue;
        }
        let values: Vec<Value> = counts
            .into_iter()
            .take(256)
            .map(|(value, n)| {
                if n < u64::from(k) {
                    json!({ "value": value, "fewerThan": k })
                } else {
                    json!({ "value": value, "count": n })
                }
            })
            .collect();
        out.push(json!({ "field": field, "values": values }));
    }
    out
}

/// How `entries/show` names its entry.
#[derive(Debug, Clone)]
pub enum ShowBy {
    Entry(String),
    Did(String),
}

/// Why a show was refused.
#[derive(Debug)]
pub enum ShowError {
    PermissionDenied,
    NotFound,
    Internal(AppError),
}

impl From<AppError> for ShowError {
    fn from(e: AppError) -> Self {
        ShowError::Internal(e)
    }
}

/// `vtc/directory/entries/show/0.1`: the entry, projected for `viewer`.
pub async fn show(state: &AppState, viewer: &Viewer, by: &ShowBy) -> Result<Value, ShowError> {
    if !viewer.may_read() {
        return Err(ShowError::PermissionDenied);
    }
    let subject = match by {
        ShowBy::Entry(id) => subject_by_entry(state, id).await?,
        // Item 2: the capability is checked before the DID is looked up, so
        // the refusal says nothing about the DID.
        ShowBy::Did(did) => {
            if !(viewer.directory_admin || viewer.members_manage) {
                return Err(ShowError::PermissionDenied);
            }
            subject_by_did(state, did).await?
        }
    };
    let Some(subject) = subject else {
        return Err(ShowError::NotFound);
    };
    let ctx = read_context(state).await?;
    let projection = project::project(&ctx.projection(), viewer, &subject, Reached::Identifier)?;
    project::entry_wire(&subject.card.entry_id, &projection)
        .map(|entry| json!({ "entry": entry }))
        .ok_or(ShowError::NotFound)
}

/// `vtc/directory/query/0.1`, answered through the projection so it never
/// disagrees with `entries/show`.
///
/// It addresses a member by DID, which is the membership oracle the directory
/// is built not to be. So a caller who may not address entries by DID is
/// answered only when the projection would show them that DID anyway — when
/// the member chose to show it to them. Everyone else gets `None`, which the
/// task answers `notFound`, exactly as for a DID that is no member.
pub async fn query_by_did(
    state: &AppState,
    viewer: &Viewer,
    did: &str,
) -> Result<Option<Map<String, Value>>, AppError> {
    if !viewer.may_read() {
        return Ok(None);
    }
    let Some(subject) = subject_by_did(state, did).await? else {
        return Ok(None);
    };
    let ctx = read_context(state).await?;
    let projection = project::project(&ctx.projection(), viewer, &subject, Reached::Identifier)?;
    let Projection::Some { fields, .. } = projection else {
        return Ok(None);
    };
    let may_address = viewer.directory_admin || viewer.members_manage || viewer.did == did;
    if !may_address && !fields.contains_key("did") {
        return Ok(None);
    }
    Ok(Some(fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_is_bound_to_the_whole_question() {
        let a = ListQuery {
            query: Some("caro".into()),
            filters: vec![("org.x".into(), vec!["b".into(), "a".into()])],
            ..ListQuery::default()
        };
        let mut reordered = a.clone();
        reordered.filters = vec![("org.x".into(), vec!["a".into(), "b".into()])];
        assert_eq!(a.binding("did:v"), reordered.binding("did:v"));
        assert_ne!(
            a.binding("did:v"),
            a.binding("did:w"),
            "bound to the viewer"
        );
        let mut other = a.clone();
        other.query = Some("dave".into());
        assert_ne!(a.binding("did:v"), other.binding("did:v"));
        let mut grouped = a.clone();
        grouped.group = Some("grp_aaaaaaaaaaaaaaaa".into());
        assert_ne!(a.binding("did:v"), grouped.binding("did:v"));
    }

    #[test]
    fn vti_dir_113_small_counts_are_not_exact() {
        let mut fields_a = Map::new();
        fields_a.insert("org.chapter".into(), json!("sydney"));
        let p = |f: Map<String, Value>| Projection::Some {
            fields: f,
            connected: false,
            shared_groups: vec![],
        };
        let mut matched = vec![];
        for i in 0..6 {
            matched.push((format!("{i}"), format!("e{i}"), p(fields_a.clone())));
        }
        let mut fields_b = Map::new();
        fields_b.insert("org.chapter".into(), json!("berlin"));
        matched.push(("7".into(), "e7".into(), p(fields_b)));
        let mut def = super::fields::base_fields()[0].clone();
        def.key = "org.chapter".into();
        def.facet = true;
        let mut ff = BTreeMap::new();
        ff.insert("org.chapter", &def);
        let got = facet_counts(&matched, &ff, 5);
        assert_eq!(
            got,
            vec![json!({ "field": "org.chapter", "values": [
                { "value": "berlin", "fewerThan": 5 },
                { "value": "sydney", "count": 6 },
            ]})]
        );
    }
}
