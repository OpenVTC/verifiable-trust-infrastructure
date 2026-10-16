//! Which **member** a room request acts as — the persona whose group state it reads.
//!
//! One VTA serves several principals, each in their own trust context, and a person may
//! hold several personas. Two of them can be members of one room: a family on one VTA, a
//! team on a company one. Each is a different leaf in the room's MLS group, so this VTA
//! keeps a group per member ([`room_groups::Member`]), and every task that touches one has
//! to say whose. This module is where that is decided, because it is where the caller's
//! contexts are known.
//!
//! # The rule
//!
//! - Where the request names the member — an invitation's subject (`key-package`,
//!   `welcome`), the owner persona the room's credentials name (`rooms/owner/group/*`, the
//!   presentation tasks) — that persona, and nothing else ([`member_as`]).
//! - Otherwise ([`acting`]): **exactly one** persona the caller may act as
//!   ([`crate::operations::persona::persona_signing_key`]) holding group state for the room.
//!   Two is a refusal asking the caller to act from the context of the one they mean, as
//!   [`crate::operations::room_oracle::principal`] refuses. Never the client's own DID.
//!
//! # Context isolation
//!
//! A persona in a context the caller cannot act in is not a candidate, and its group is
//! invisible: the answer is the same "no group state" a room nobody here belongs to gets.
//! So a caller in context A can neither read, advance nor learn of the group a persona in
//! context B holds for the same room.
//!
//! # Upgrade
//!
//! A build before this keyed everything by room alone. Its rows are moved under their
//! member on first touch ([`migrate_for`]): the member is the persona the group's **own
//! leaf** identifies, when the caller may act as it. A group joined before members were
//! personas carries the client's DID on its leaf; that one is attributed to the persona
//! the room's credentials name, and only when the caller *is* that client — the one party
//! that provably joined with it. Anyone else leaves the row where it is, untouched.

use vti_common::error::AppError;
use vti_rooms::mls::RoomGroup;

use crate::auth::AuthClaims;
use crate::operations::room_groups::{self, Member, RoomGroupRecord};
use crate::server::AppState;

/// Whether `did` is a persona the caller may act as.
async fn may_act_as(state: &AppState, auth: &AuthClaims, did: &str) -> Result<bool, AppError> {
    let stores = crate::operations::persona::PersonaStores::from_state(state);
    Ok(
        crate::operations::persona::persona_signing_key(stores, auth, did)
            .await?
            .is_some(),
    )
}

/// Who a row the per-room build wrote belongs to, as far as this caller can show — or
/// `None`, which leaves it alone.
async fn attribute_legacy(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
    record: &RoomGroupRecord,
) -> Result<Option<String>, AppError> {
    // The group's own leaf is the authority on whose it is; the stored DID is believed only
    // where the group agrees.
    let leaf_is_member = RoomGroup::restore(&record.snapshot)
        .map(|g| g.leaf_of(&record.member_did).is_some())
        .unwrap_or(false);
    if leaf_is_member && may_act_as(state, auth, &record.member_did).await? {
        return Ok(Some(record.member_did.clone()));
    }
    // Joined before members were personas: the leaf is the client that joined. That
    // client, and only it, may attribute the group to the persona its room credentials
    // name. Any other caller would be claiming a group it has no tie to.
    if record.member_did == auth.did {
        return match crate::operations::room_oracle::principal(state, auth, room_id).await {
            Ok(p) => Ok(Some(p.did)),
            Err(e @ AppError::Internal(_)) => Err(e),
            Err(_) => Ok(None),
        };
    }
    Ok(None)
}

/// Move `room_id`'s rows from before per-member keying under their member, if this caller
/// can show whose they are. Idempotent; a no-op once moved.
pub async fn migrate_for(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
) -> Result<(), AppError> {
    let groups = &state.room_groups_ks;
    let Some(record) = room_groups::legacy_group(groups, room_id).await? else {
        return Ok(());
    };
    let Some(persona) = attribute_legacy(state, auth, room_id, &record).await? else {
        return Ok(());
    };
    room_groups::migrate_legacy(groups, &Member::new(room_id, &persona)?).await?;
    Ok(())
}

/// The member for a persona the request already names — after moving any row of the
/// room's from before per-member keying, so it is found where it now lives.
///
/// The caller has established that `persona` is one it may act as; this does not ask again.
pub async fn member_as(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
    persona: &str,
) -> Result<Member, AppError> {
    migrate_for(state, auth, room_id).await?;
    Member::new(room_id, persona)
}

/// The one member the caller acts as with group state for `room_id`, `None` if there is
/// none, or a refusal if there are several.
pub async fn acting(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
) -> Result<Option<Member>, AppError> {
    migrate_for(state, auth, room_id).await?;
    let mut mine = Vec::new();
    for m in room_groups::holders(&state.room_groups_ks, room_id).await? {
        if may_act_as(state, auth, m.persona()).await? {
            mine.push(m);
        }
    }
    match mine.len() {
        0 => Ok(None),
        1 => Ok(mine.pop()),
        n => Err(AppError::Conflict(format!(
            "you may act as {n} personas holding group state for room `{room_id}`; which one \
             is acting is not a question this can answer safely — act from the context of \
             the one you mean"
        ))),
    }
}

/// [`acting`], with "none" as the refusal every key task gives for a room it holds nothing
/// for — the same whether nobody here belongs to the room or only somebody the caller
/// cannot act as does.
pub async fn require_acting(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
) -> Result<Member, AppError> {
    require_acting_as(state, auth, room_id, None).await
}

/// The `ext` namespace in which a member's own client names the member a `rooms/keys/*`
/// request acts as: `ext["org.openvtc.rooms"].member`, a persona DID.
///
/// `rooms/keys/act` names the member in its document's `issuer`; the custody tasks
/// (`browse`, `read`, `open`, `file-key`, `backfill`, `chain`, `seal` 0.1) carry no member
/// of their own, and their specifications say the recipient "acts as the one its caller
/// acts as, and refuses rather than choose" (`rooms/keys/read/0.1`). This is how a caller
/// that may act as several members of one room — an administrator whose VTA also holds
/// the community's own place in it — says which one it acts as. It only ever narrows:
/// the named persona must be one [`acting`] would have considered, and naming none keeps
/// the refusal for two.
pub const MEMBER_EXT: &str = "org.openvtc.rooms";

/// The member a request's payload names in `ext["org.openvtc.rooms"].member`, if any.
///
/// `Err` is a malformed request: the member is present but is not a DID (a DID URL is not
/// one — no credential or leaf carries `did#fragment`).
pub fn named_member(payload: &serde_json::Value) -> Result<Option<String>, String> {
    let Some(ns) = payload.get("ext").and_then(|e| e.get(MEMBER_EXT)) else {
        return Ok(None);
    };
    match ns.get("member") {
        None => Ok(None),
        Some(serde_json::Value::String(did)) if did.starts_with("did:") && !did.contains('#') => {
            Ok(Some(did.clone()))
        }
        Some(_) => Err(format!(
            "`ext[\"{MEMBER_EXT}\"].member` must be the DID of the member to act as"
        )),
    }
}

/// [`acting`], or — where the request names the member ([`named_member`]) — exactly that
/// member, if it is a persona the caller may act as holding group state for `room_id`, and
/// `None` otherwise. A named member nobody here holds and one the caller may not act as get
/// the same `None`: naming a persona must not tell a caller who else this VTA serves.
pub async fn acting_as(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
    named: Option<&str>,
) -> Result<Option<Member>, AppError> {
    let Some(named) = named else {
        return acting(state, auth, room_id).await;
    };
    migrate_for(state, auth, room_id).await?;
    for m in room_groups::holders(&state.room_groups_ks, room_id).await? {
        if m.persona() == named && may_act_as(state, auth, named).await? {
            return Ok(Some(m));
        }
    }
    Ok(None)
}

/// [`acting_as`], with "none" as the refusal [`require_acting`] gives.
pub async fn require_acting_as(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
    named: Option<&str>,
) -> Result<Member, AppError> {
    acting_as(state, auth, room_id, named)
        .await?
        .ok_or_else(|| match named {
            Some(did) => AppError::NotFound(format!(
                "this VTA holds no group state for room `{room_id}` as `{did}`"
            )),
            None => AppError::NotFound(format!(
                "this VTA holds no group state for room `{room_id}`"
            )),
        })
}

/// Every member the caller may act as, across rooms — what `rooms/keys/list` reports.
pub async fn held_by_caller(state: &AppState, auth: &AuthClaims) -> Result<Vec<Member>, AppError> {
    let groups = &state.room_groups_ks;
    for room_id in room_groups::legacy_rooms(groups).await? {
        migrate_for(state, auth, &room_id).await?;
    }
    let mut mine = Vec::new();
    for m in room_groups::held_members(groups).await? {
        if may_act_as(state, auth, m.persona()).await? {
            mine.push(m);
        }
    }
    Ok(mine)
}
