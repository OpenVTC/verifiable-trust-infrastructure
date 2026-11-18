//! `GET /v1/members` + `GET /v1/members/{did}` — admin-gated
//! member read endpoints (M1.4.1).
//!
//! The response shape joins the [`crate::members::Member`] metadata
//! row with its matching [`crate::acl::VtcAclEntry`]'s role + label
//! so callers don't need a second round-trip. Phase 1 has no
//! privacy gating beyond `AdminAuth`; spec §12.3's PMF lands in
//! Phase 2+.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use vti_common::pagination::{Cursor, MAX_LIMIT, Paginated};

use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, list_acl_entries};
use crate::error::{AppError, TaskError};
use crate::members::{Disposition, Member, get_member};
use crate::server::AppState;
use vti_common::store::ScanOpts;

/// Wire shape returned by both endpoints. Joins `members:<did>`
/// + `acl:<did>` so a caller doesn't need a second request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct MemberResponse {
    pub did: String,
    pub role: VtcRole,
    pub label: Option<String>,
    pub joined_at: DateTime<Utc>,
    pub publish_consent: bool,
    pub departure_preference: Disposition,
    pub status_list_index: Option<u32>,
    pub current_vmc_id: Option<String>,
    pub current_role_vac_id: Option<String>,
    /// Serialised as `{}` when the member has none.
    ///
    /// The canonical component makes `extensions` **required** and types it
    /// `object`, so `null` is a violation and omitting it is a violation too —
    /// an empty object is the only conforming way to say "none". A stored
    /// member that never had extensions holds `JsonValue::Null`, and this went
    /// out as `null` until #1107. The conformance fixture set
    /// `{"org": "acme"}`, so a hand-typed non-empty object hid it; the
    /// response-conformance layer on real traffic is what surfaced it.
    #[serde(serialize_with = "empty_object_if_null")]
    pub extensions: JsonValue,
    /// Personhood flag (Phase 4 M4.1). Surfaces the Member row's
    /// `personhood` field. Read-only on this response —
    /// `POST /v1/members/{did}/personhood/assert` flips it (M4.3),
    /// `DELETE /v1/members/{did}/personhood` clears it (M4.4),
    /// and renewal-policy downgrade clears it (M4.2.2).
    pub personhood: bool,
    /// Timestamp of the most recent assert. Operator-private —
    /// the value is included on Admin-gated responses (this
    /// route is `AdminAuth`) so operators can audit; the
    /// public member-facing renewal response carries only the
    /// `personhood` flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub personhood_asserted_at: Option<DateTime<Utc>>,
    /// Whether the member auto-joined by presenting a verified
    /// Invitation Credential (VIC). Surfaced so the admin UI can
    /// badge invitation-joined members.
    #[serde(default)]
    pub joined_via_invitation: bool,
    /// Top-level `id` of the member-issued reciprocal VMC (member → community
    /// half of the pair), once the member has sent it over `members/vmc/1.0`.
    /// `None` until then. The VMC body itself is not echoed on this response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_vmc_id: Option<String>,
    /// When the member VMC was received + stored. Paired with
    /// [`Self::member_vmc_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_vmc_received_at: Option<DateTime<Utc>>,
}

/// Serialise `JsonValue::Null` as `{}`.
///
/// For members the spec requires and types `object`: absent and null are both
/// refused, so the empty object is the only conforming spelling of "none".
fn empty_object_if_null<S: serde::Serializer>(v: &JsonValue, s: S) -> Result<S::Ok, S::Error> {
    use serde::Serialize;
    match v {
        JsonValue::Null => serde_json::Map::new().serialize(s),
        other => other.serialize(s),
    }
}

impl MemberResponse {
    fn from_pair(acl: VtcAclEntry, member: Member) -> Self {
        debug_assert_eq!(
            acl.did, member.did,
            "ACL + Member rows must share their DID — caller is responsible for the join"
        );
        Self {
            did: member.did,
            role: acl.role,
            label: acl.label,
            joined_at: member.joined_at,
            publish_consent: member.publish_consent,
            departure_preference: member.departure_preference,
            status_list_index: member.status_list_index,
            current_vmc_id: member.current_vmc_id,
            current_role_vac_id: member.current_role_vac_id,
            extensions: member.extensions,
            personhood: member.personhood,
            personhood_asserted_at: member.personhood_asserted_at,
            joined_via_invitation: member.joined_via_invitation,
            member_vmc_id: member.member_vmc_id,
            member_vmc_received_at: member.member_vmc_received_at,
        }
    }
}

// ---------------------------------------------------------------------------
// GET /v1/members
// ---------------------------------------------------------------------------

/// The paginated member list, `vtc/members/list/0.2`: the signed document the
/// spine serves (`trust_tasks::community_tasks`).
pub(crate) async fn list_members_inner(
    state: &AppState,
    query: vti_specs::vtc::members::list::v0_2::Payload,
) -> Result<Paginated<MemberResponse>, AppError> {
    let limit = crate::wire::page_limit(query.limit, 50, MAX_LIMIT);

    // Phase 1 reads the audit_key out of AppState's writer. The
    // writer is `Some` for every Phase 0 + Phase 1 path — install
    // bootstrap ensures the initial key exists. A daemon that
    // started before that initial-key derivation would 503 here.
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let audit_key = audit_writer.active_key().await?;

    let decoded_cursor = match &query.cursor {
        Some(s) => Some(Cursor::decode(s, &audit_key.key)?),
        None => None,
    };

    // A member is listed when it has an ACL entry (a tombstoned / historical
    // departure keeps its member row but not its entry) whose role matches the
    // filter. The filter is applied **before** paging, so the cursor walks only
    // the members listed and a page is never empty while one lies further on.
    //
    // Read by seek, a chunk of member rows at a time from the cursor, with the
    // ACL row of each member read (one lookup) — never the whole member list
    // and the whole ACL decoded on every page, which made walking every page
    // quadratic in the community's size (#2601). The cursor is the one this
    // listing always issued (the last member key returned), so a cursor issued
    // before this resumes where it left off.
    let mut opts = ScanOpts::new(crate::members::MEMBERS_PREFIX.to_vec(), MEMBER_SCAN_CHUNK);
    if let Some(c) = &decoded_cursor {
        opts = opts.after(c.last_key.clone());
    }
    let mut pager = state.members_ks.scan_pager(opts);
    let mut page: Vec<(VtcAclEntry, Member)> = Vec::with_capacity(limit);
    let mut last_key: Option<Vec<u8>> = None;
    let mut more = false;
    'walk: loop {
        let rows = pager.next_page().await?;
        if rows.is_empty() {
            break;
        }
        let mut chunk: Vec<(Vec<u8>, Member, VtcAclEntry)> = Vec::new();
        for (key, value) in rows {
            let member: Member = match serde_json::from_slice(&value) {
                Ok(m) => m,
                Err(err) => {
                    tracing::warn!(error = %err, "skipping unparseable member row");
                    continue;
                }
            };
            let Some(entry) = acl_row(state, &member).await? else {
                continue;
            };
            if query
                .role
                .as_ref()
                .is_some_and(|filter| entry.role.to_string() != filter.as_str())
            {
                continue;
            }
            chunk.push((key, member, entry));
        }
        let mut entries: Vec<VtcAclEntry> = chunk.iter().map(|(_, _, e)| e.clone()).collect();
        crate::acl::storage::resolve_entries(&state.acl_ks, &mut entries).await?;
        for ((key, member, _), entry) in chunk.into_iter().zip(entries) {
            if page.len() == limit {
                more = true;
                break 'walk;
            }
            page.push((entry, member));
            last_key = Some(key);
        }
    }

    // `totalEstimate`: the count of members listed, taken on the first page —
    // where the console's count reads it (`limit: 1`) — and carried in the
    // signed cursor's `snapshotId` to every page after it. Counting means
    // reading every row's key (and, for a role filter, every entry's role), so
    // a walk of the whole list costs one count, not one per page; a member
    // admitted mid-walk is in the next walk's count, which is what an
    // estimate is for.
    let total = match &decoded_cursor {
        Some(c) => c.snapshot_id,
        None => count_listed(state, query.role.as_ref().map(|r| r.as_str())).await?,
    };
    let total_estimate = Some(total);
    let next_cursor = if more {
        last_key.map(|k| Cursor::new(k, total).encode(&audit_key.key))
    } else {
        None
    };
    Ok(Paginated {
        items: page
            .into_iter()
            .map(|(entry, member)| MemberResponse::from_pair(entry, member))
            .collect(),
        next_cursor,
        total_estimate,
    })
}

/// Member rows read per step while a page of `vtc/members/list` is filled.
const MEMBER_SCAN_CHUNK: usize = 256;

/// `member`'s ACL entry as stored (resolved later, for the page), or `None`
/// when it has none — a departure that kept the member row, which is expected
/// and quiet, or a live row with no entry, which is corruption and warned.
async fn acl_row(state: &AppState, member: &Member) -> Result<Option<VtcAclEntry>, AppError> {
    let raw = state
        .acl_ks
        .get_raw(format!("acl:{}", member.did).into_bytes())
        .await?;
    let Some(raw) = raw else {
        if member.removed_at.is_some() {
            // Expected: a Tombstone / Historical departure deletes the ACL row
            // but retains the Member row (PII cleared, `removed_at` set) as a
            // "who was a member" record, left out of the active-member list.
            tracing::debug!(
                did = %member.did,
                "skipping tombstoned/historical member (no ACL) in list response"
            );
        } else {
            // A *live* member row with no ACL row is genuine out-of-band
            // corruption (e.g. an interrupted purge). Log + skip rather than
            // 500 — the page should still be returnable.
            tracing::warn!(
                did = %member.did,
                "member row has no matching ACL entry; skipping in list response"
            );
        }
        return Ok(None);
    };
    match serde_json::from_slice::<VtcAclEntry>(&raw) {
        Ok(e) => Ok(Some(e)),
        Err(err) => {
            tracing::warn!(did = %member.did, error = %err, "skipping unparseable acl entry");
            Ok(None)
        }
    }
}

/// How many members `vtc/members/list` lists under `role`: member rows whose
/// DID has an ACL entry (of that role). Keys only — no member row is decoded,
/// and an ACL row only for its role when a role is asked about.
async fn count_listed(state: &AppState, role: Option<&str>) -> Result<u64, AppError> {
    let prefix = crate::members::MEMBERS_PREFIX;
    let members: std::collections::HashSet<Vec<u8>> = state
        .members_ks
        .prefix_keys(prefix.to_vec())
        .await?
        .into_iter()
        .map(|k| k[prefix.len()..].to_vec())
        .collect();
    let mut count = 0u64;
    match role {
        None => {
            for k in state.acl_ks.prefix_keys(b"acl:".to_vec()).await? {
                if members.contains(&k[b"acl:".len()..]) {
                    count += 1;
                }
            }
        }
        Some(filter) => {
            /// The one field a role count reads.
            #[derive(Deserialize)]
            struct RoleOnly {
                role: VtcRole,
            }
            for (k, v) in state.acl_ks.prefix_iter_raw(b"acl:".to_vec()).await? {
                if members.contains(&k[b"acl:".len()..])
                    && serde_json::from_slice::<RoleOnly>(&v)
                        .is_ok_and(|r| r.role.to_string() == filter)
                {
                    count += 1;
                }
            }
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// GET /v1/members/removed
// ---------------------------------------------------------------------------

/// A departed member whose Member row was retained (Tombstone / Historical
/// disposition) after its ACL was deleted. Surfaced so operators can see who
/// left and purge the lingering rows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RemovedMember {
    pub did: String,
    /// When the member departed.
    pub removed_at: DateTime<Utc>,
    /// Revocation slot the member held (for audit / re-flip), if any.
    pub status_list_index: Option<u32>,
    /// Always `"removed"` — present so the UI can render a uniform status.
    pub status: String,
}

/// GET /members/removed — members whose row was kept as a tombstone after
/// departure (no ACL). Auth: Admin. Full scan (departed members are few and
/// this is an operator view), newest-departed first.
pub(crate) async fn list_removed(state: &AppState) -> Result<RemovedMembersResponse, AppError> {
    let mut removed: Vec<RemovedMember> = crate::members::list_members(&state.members_ks)
        .await?
        .into_iter()
        .filter_map(|m| {
            m.removed_at.map(|removed_at| RemovedMember {
                did: m.did,
                removed_at,
                status_list_index: m.status_list_index,
                status: "removed".to_string(),
            })
        })
        .collect();
    removed.sort_by_key(|b| std::cmp::Reverse(b.removed_at));
    Ok(RemovedMembersResponse { removed })
}

/// `{ removed: [...] }` — the shape `vtc/members/removed/0.1` publishes.
///
/// The handler returned a top-level array until #1059's witness compared it
/// with its schema. The rows themselves always conformed.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RemovedMembersResponse {
    pub removed: Vec<RemovedMember>,
}

// ---------------------------------------------------------------------------
// GET /v1/members/{did}
// ---------------------------------------------------------------------------

/// `vtc/members/show:notFound` — no member with that DID in this community.
pub const SHOW_ERR_NOT_FOUND: &str =
    vti_specs::vtc::members::show::v0_1::error_codes::NOT_FOUND.code;

/// GET /members/{did} — single member. Auth: Admin.
pub(crate) async fn show_member(state: &AppState, did: &str) -> Result<MemberEnvelope, TaskError> {
    vti_common::identifier::validate_did("did", did)?;
    let member = get_member(&state.members_ks, did).await?.ok_or_else(|| {
        TaskError::declared(
            SHOW_ERR_NOT_FOUND,
            AppError::NotFound(format!("member not found: {did}")),
        )
    })?;
    let acl = get_acl_entry(&state.acl_ks, did).await?.ok_or_else(|| {
        // Same out-of-band corruption case as the list path —
        // surface as 404 because the *member* isn't presentable.
        TaskError::declared(
            SHOW_ERR_NOT_FOUND,
            AppError::NotFound(format!("member not found (no ACL row): {did}")),
        )
    })?;
    Ok(MemberEnvelope {
        member: MemberResponse::from_pair(acl, member),
    })
}

/// Unused-listing helper kept to ensure `list_acl_entries` stays
/// linked when the foundation PR's pruning passes try to flag it
/// dead. Will be the production filter path once "list ACL
/// without member metadata" arrives in Phase 2+.
#[allow(dead_code)]
pub(crate) async fn list_admin_dids(state: &AppState) -> Result<Vec<String>, AppError> {
    let entries = list_acl_entries(&state.acl_ks).await?;
    Ok(entries
        .into_iter()
        .filter(|e| e.admin.is_administrator())
        .map(|e| e.did)
        .collect())
}

/// `{ member: … }` — the shape `vtc/members/show/0.1` publishes. The row was
/// returned bare until #1093; the row itself always conformed.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MemberEnvelope {
    pub member: MemberResponse,
}
