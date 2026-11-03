//! The credential roll (`roll.rule = "credential"`, VTI-VOT-025 – VTI-VOT-029): whose
//! membership credential admits a party to a ticket, and whether this community still trusts
//! that party for it — read from the community's own records alone, so nothing here can be
//! indeterminate (tickets/issue/0.3 Conformance item 6.2).

use chrono::{DateTime, Utc};

use super::store::{ElectionRecord, RollParty};
use crate::error::AppError;
use crate::server::AppState;

/// What `did` is to this community, for a credential roll naming it (create/0.5 Conformance
/// item 6, VTI-VOT-026): the community itself, one of its groups, or a party that is itself an
/// active member holding an unrevoked membership credential this community issued it. `None`
/// for any other DID — including one a trust registry recognises (VTI-REG-020), which is not
/// membership.
///
/// # Errors
/// A store failure.
pub async fn classify(state: &AppState, did: &str) -> Result<Option<RollParty>, AppError> {
    if did == super::ops::community_did(state).await {
        return Ok(Some(RollParty::ThisCommunity));
    }
    if let Some(g) = crate::groups::all(state.directory.ks())
        .await?
        .into_iter()
        .find(|g| g.group_did == did)
    {
        return Ok(Some(RollParty::CommunityGroup {
            group_id: g.group_id,
        }));
    }
    if member_party_active(state, did).await? {
        return Ok(Some(RollParty::MemberParty));
    }
    Ok(None)
}

/// Whether `did` is an active member of this community — its entry live, not suspended, not an
/// `application`, its member record not removed — holding a membership credential this
/// community issued it whose slot in its own revocation list is clear (VTI-VOT-026,
/// tickets/issue item 6.2). The status is this community's own record, never fetched.
///
/// # Errors
/// A store failure.
pub async fn member_party_active(state: &AppState, did: &str) -> Result<bool, AppError> {
    let Some(active) = crate::member_portal::active::active_member(state, did).await? else {
        return Ok(false);
    };
    if active.member.current_vmc_id.is_none() {
        return Ok(false);
    }
    match active.member.status_list_index {
        Some(slot) => Ok(!own_revocation_bit(state, slot).await?),
        None => Ok(true),
    }
}

/// Whether `slot` is set in this community's own revocation list.
async fn own_revocation_bit(state: &AppState, slot: u32) -> Result<bool, AppError> {
    let row = crate::status_list::get_state(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
    )
    .await?;
    Ok(row.is_some_and(|r| r.is_set(slot as usize)))
}

/// Whether the party a credential roll names is still trusted for it now (tickets/issue item
/// 6.2, VTI-VOT-025 item 6, VTI-VOT-029): the community always; a group only while the
/// community still holds it under that DID — a deleted group is never re-read as a party
/// outside the community; a member party only while its own membership is active.
///
/// # Errors
/// A store failure.
pub async fn still_trusted(state: &AppState, rec: &ElectionRecord) -> Result<bool, AppError> {
    let Some(member_of) = rec.roll_member_of() else {
        return Ok(false);
    };
    match &rec.roll_party {
        Some(RollParty::ThisCommunity) => Ok(member_of == super::ops::community_did(state).await),
        Some(RollParty::CommunityGroup { group_id }) => Ok(group(state, group_id)
            .await?
            .is_some_and(|g| g.group_did == member_of)),
        Some(RollParty::MemberParty) => member_party_active(state, member_of).await,
        None => Ok(false),
    }
}

/// The group a roll names, while the community still holds it.
pub async fn group(
    state: &AppState,
    group_id: &str,
) -> Result<Option<crate::groups::Group>, AppError> {
    crate::groups::get(state.directory.ks(), group_id).await
}

/// Whether the community's authority credential to `group` is live by its own record of it:
/// issued, within its validity, and its slot in the revocation list clear (tickets/issue item
/// 6.3 `authorization`, VTI-DIR-083, VTI-DIR-086).
///
/// # Errors
/// A store failure.
pub async fn group_authorized(
    state: &AppState,
    group: &crate::groups::Group,
    now: DateTime<Utc>,
) -> Result<bool, AppError> {
    let Some(a) = &group.authority else {
        return Ok(false);
    };
    if !group.issues_credentials || a.valid_until <= now {
        return Ok(false);
    }
    Ok(!own_revocation_bit(state, a.status_list_index).await?)
}

/// Whether `did` is an active member of this community who belongs to `group_id` in its
/// records (tickets/issue item 6.5; list/0.5 item 1 for a group roll).
///
/// # Errors
/// A store failure.
pub async fn active_in_group(
    state: &AppState,
    group_id: &str,
    did: &str,
) -> Result<bool, AppError> {
    if crate::member_portal::active::active_member(state, did)
        .await?
        .is_none()
    {
        return Ok(false);
    }
    let ks = state.directory.ks();
    let Some(entry) = crate::directory::cards::entry_of(ks, did).await? else {
        return Ok(false);
    };
    Ok(crate::groups::membership(ks, group_id, &entry)
        .await?
        .is_some_and(|m| m.state == "active"))
}

/// Whether the community's records show a credential roll could admit `did` without a
/// presentation (list/0.5 item 1): an active member for the community's roll, an active group
/// member for a group's, and, for a member party's, only the party itself.
///
/// # Errors
/// A store failure.
pub async fn records_could_admit(
    state: &AppState,
    rec: &ElectionRecord,
    did: &str,
) -> Result<bool, AppError> {
    match &rec.roll_party {
        Some(RollParty::ThisCommunity) => {
            Ok(crate::member_portal::active::active_member(state, did)
                .await?
                .is_some())
        }
        // A deleted group admits nobody (VTI-VOT-029).
        Some(RollParty::CommunityGroup { group_id }) => {
            if !still_trusted(state, rec).await? {
                return Ok(false);
            }
            active_in_group(state, group_id, did).await
        }
        Some(RollParty::MemberParty) => {
            Ok(rec.roll_member_of() == Some(did) && member_party_active(state, did).await?)
        }
        None => Ok(false),
    }
}
