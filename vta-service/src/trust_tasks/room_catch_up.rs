//! Repairing a key holder's epoch state before refusing a record (`rooms/keys/read/0.1`,
//! *Opening, and when it cannot*).
//!
//! A key holder misses an epoch key in two ordinary ways, and in a room of more than two
//! members both are the normal state rather than faults:
//!
//! - **It is behind.** Every membership change leaves every other member one commit short
//!   until they apply it. The host relays the commits (`rooms/epoch/commits`).
//! - **It joined late.** A member's group starts at the epoch it joined, so everything
//!   sealed before needs the epoch links the host keeps (`rooms/epoch/chain`).
//!
//! The member's surface reaches their agent and nothing else, so this agent is the only
//! party that can repair either. It does so as the same principal, under the same `read`
//! grant, from the same host the read was addressed to — the repair discloses nothing the
//! read did not. A removed member is never repaired: no commit and no link will open what
//! was sealed after the removal.
//!
//! **The record's epoch chooses which state is repaired** (`rooms/keys/open/0.2`): the
//! current group, or a prior membership. A member idle when it was removed and admitted
//! again holds a prior membership whose removal it never saw (`rooms/keys/welcome/0.1`,
//! *Rejoining after a removal*); a record sealed above the epoch that state holds and below
//! the re-admission is `notDelivered` from it, and catching it up applies the room's commits
//! to *that* state until the removing one fixes its removal epoch. The host serves them under
//! the member's current `read` grant: `rooms/epoch/commits` takes any `sinceEpoch` from a
//! presenter it authorizes now, and keeps every commit, so the re-admitted member's fresh
//! credentials reach the commits from before their `validFrom`. Sealing only ever uses the
//! current group, so nothing here is a way to write under prior state.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use crate::operations::room_groups::{self, OpenError, PriorCommit, RepairTarget};
use crate::server::AppState;
use vti_common::auth::AuthClaims;

use super::room_group::{PresentingMember, send_as_member, send_as_member_typed};

/// The most pages one repair asks for. A host serving a page that moves nothing is
/// stopped by the progress check; this bounds a host that keeps moving one step at a time.
const MAX_PAGES: usize = 32;

/// How long a read waits for another read's repair of the same member before refusing
/// with what it has. The repair holds its lock across the host round-trips (it is
/// single-flight on purpose), so a waiter must be able to give up: a wedged host stalls
/// one repair, never every read of the room behind it (R1.3).
const REPAIR_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

/// One lock per member of a room. A surface opens many records at once (the portal opens
/// the newest 25 for their titles), and each would otherwise fetch and apply the same
/// commits — racing writes of one group's state. Entries are never removed: one small
/// mutex per room this VTA holds.
static LOCKS: LazyLock<std::sync::Mutex<HashMap<(String, String), Arc<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(Default::default);

fn lock_for(member: &room_groups::Member) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = LOCKS.lock().unwrap_or_else(|p| p.into_inner());
    locks
        .entry((member.room_id().to_string(), member.persona().to_string()))
        .or_default()
        .clone()
}

/// Try to make the epoch `refused` names openable, from `host`.
///
/// Returns why the repair did not complete, for the refusal's message; `Ok(())` means it
/// did what it could and the caller should open the record again. Never repairs
/// [`OpenError::Removed`] or [`OpenError::App`].
pub(super) async fn repair(
    state: &AppState,
    auth: &AuthClaims,
    member: &PresentingMember,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    host: &str,
    refused: &OpenError,
) -> Result<(), String> {
    let lock = lock_for(&member.member);
    let Ok(_one_repair) = tokio::time::timeout(REPAIR_WAIT, lock.lock()).await else {
        return Err("another read of this room is still fetching from the host".into());
    };

    let epoch = match *refused {
        OpenError::NotDelivered { epoch, .. } | OpenError::BeyondChain { epoch, .. } => epoch,
        OpenError::Removed { .. } | OpenError::App(_) => return Err("nothing to repair".into()),
    };
    // Which state the record's epoch chooses, read under the lock: another request may have
    // repaired it while we waited, or fixed a prior membership's removal.
    let Some(held) = room_groups::repair_state(&state.room_groups_ks, &member.member, epoch)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Err("no group state of this member's holds that epoch".into());
    };
    match *refused {
        OpenError::NotDelivered { epoch, .. } if held.epoch >= epoch => Ok(()),
        OpenError::NotDelivered { .. } => {
            catch_up(
                state,
                auth,
                member,
                resolver,
                host,
                &held.target,
                held.epoch,
            )
            .await
        }
        OpenError::BeyondChain { epoch, .. } if held.earliest_readable_epoch <= epoch => Ok(()),
        // Links are stored to the current group; a prior membership's chain is what it
        // accrued while it was held.
        OpenError::BeyondChain { epoch, .. } if held.target == RepairTarget::Current => {
            extend_chain(
                state,
                auth,
                member,
                resolver,
                host,
                held.earliest_readable_epoch,
                epoch,
            )
            .await
        }
        _ => Err("nothing to repair".into()),
    }
}

/// Apply every commit the host relays above `held` (a room epoch), in order, to `target`.
///
/// For a prior membership, until the commit that removed the member: that one fixes its
/// removal epoch, and nothing after it is the membership's.
async fn catch_up(
    state: &AppState,
    auth: &AuthClaims,
    member: &PresentingMember,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    host: &str,
    target: &RepairTarget,
    held: u32,
) -> Result<(), String> {
    let room_id = member.member.room_id();
    let mut at = held;
    for _ in 0..MAX_PAGES {
        let reply = send_as_member(
            state,
            auth,
            member,
            resolver,
            host,
            vti_rooms::wire::ROOMS_EPOCH_COMMITS_TYPE,
            serde_json::json!({ "roomId": room_id, "sinceEpoch": at }),
        )
        .await
        .map_err(|e| format!("fetching the room's commits: {e}"))?;
        let page: vti_rooms::wire::CommitsResponse =
            serde_json::from_value(reply).map_err(|e| {
                format!("room host `{host}` served commits this agent cannot read: {e}")
            })?;
        if page.commits.is_empty() {
            return if at < page.room_epoch {
                Err(format!(
                    "the host holds no commit producing room epoch {}",
                    at + 1
                ))
            } else {
                Ok(())
            };
        }
        let before = at;
        for c in &page.commits {
            use base64::Engine as _;
            let commit = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(c.commit.trim())
                .map_err(|e| format!("room host `{host}` served an undecodable commit: {e}"))?;
            // Room epoch N is produced by the commit at MLS epoch N - 1.
            let Some(mls) = u64::from(c.epoch).checked_sub(1) else {
                return Err(format!("room host `{host}` served a commit for epoch 0"));
            };
            let applied = match target {
                RepairTarget::Current => room_groups::apply_commit(
                    &state.room_groups_ks,
                    &member.member,
                    &commit,
                    mls,
                    super::room_group::now(),
                )
                .await
                .map_err(|e| format!("applying the commit for room epoch {}: {e}", c.epoch))?,
                RepairTarget::Prior { signature_key } => match room_groups::apply_prior_commit(
                    &state.room_groups_ks,
                    &member.member,
                    signature_key,
                    &commit,
                    mls,
                    super::room_group::now(),
                )
                .await
                .map_err(|e| {
                    format!(
                        "applying the commit for room epoch {} to a prior membership: {e}",
                        c.epoch
                    )
                })? {
                    PriorCommit::Applied(applied) => applied,
                    // The removal is known now; the open that follows answers by it.
                    PriorCommit::Removed { .. } => return Ok(()),
                },
            };
            at = u32::try_from(applied + 1).unwrap_or(u32::MAX);
        }
        if at == before || at >= page.room_epoch {
            return Ok(());
        }
    }
    Ok(())
}

/// Fetch and keep epoch links until the chain reaches `target`, or the host has no more.
async fn extend_chain(
    state: &AppState,
    auth: &AuthClaims,
    member: &PresentingMember,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    host: &str,
    mut reach: u32,
    target: u32,
) -> Result<(), String> {
    let room_id = member.member.room_id();
    // From what is already reached, down: rungs above it are held, and a page of them
    // would move nothing and read as a gap.
    for _ in 0..MAX_PAGES {
        let payload = serde_json::json!({ "roomId": room_id, "fromEpoch": reach });
        // `rooms/epoch/chain/0.2` carries the room's epoch floor, which a key holder catching
        // up SHOULD learn (`EpochFloor`). A host that does not serve 0.2 is not read from.
        let reply = send_as_member_typed(
            state,
            auth,
            member,
            resolver,
            host,
            vti_rooms::wire::ROOMS_EPOCH_CHAIN_V2_TYPE,
            payload,
        )
        .await
        .map_err(|e| format!("fetching the room's epoch links: {}", e.into_app_error()))?;
        // The floor before the rungs: nothing at or below it is kept, and a repair never
        // restores what lies below it (`rooms/keys/read/0.1`).
        let floor = match reply.get("epochFloor").and_then(serde_json::Value::as_u64) {
            Some(f) => room_groups::apply_epoch_floor(
                &state.room_groups_ks,
                &member.member,
                u32::try_from(f).unwrap_or(u32::MAX),
                super::room_group::now(),
            )
            .await
            .map_err(|e| e.to_string())?,
            None => 0,
        };
        if target < floor {
            return Err(format!(
                "room epoch {target} is below the room's epoch floor {floor}: the room has \
                 forgotten it"
            ));
        }
        let links: Vec<vti_rooms::wire::EpochLink> = serde_json::from_value(
            reply.get("links").cloned().unwrap_or_default(),
        )
        .map_err(|e| format!("room host `{host}` served links this agent cannot read: {e}"))?;
        let served = links.len();
        let (earliest, _) = room_groups::store_links(
            &state.room_groups_ks,
            &member.member,
            links,
            super::room_group::now(),
        )
        .await
        .map_err(|e| e.to_string())?;
        if earliest <= target {
            return Ok(());
        }
        // Nothing served, or nothing moved: a gap the host cannot fill.
        if served == 0 || earliest >= reach {
            return Err(format!(
                "the host holds no epoch link below room epoch {earliest}"
            ));
        }
        reach = earliest;
    }
    Ok(())
}
