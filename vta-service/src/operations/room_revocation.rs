//! A room's revocation list, as its key holder keeps it (`rooms/owner/revoke/0.1`,
//! `rooms/owner/group/remove/0.3`, trust-tasks-tf #804).
//!
//! The list is the **room's** statement — signed with the room's key, cumulative, numbered —
//! and this agent is where it is made: it holds the room's key, so only it can sign the
//! next list. Three things follow, each a requirement of `rooms/owner/revoke`:
//!
//! - **Kept with the room's key** (item 4): stored here, in `room_groups`, which is backed up
//!   and encrypted like the group secrets beside it. A key holder that lost its list could
//!   not sign a later one keeping the live entries; restored from an old backup, it
//!   recovers the highest list a host holds ([`adopt`]).
//! - **One list per sequence** (item 3): building and signing a room's next list happens
//!   under the room's [`signing_lock`], so two requests never sign two lists at one
//!   position — which every host would see as the room's key equivocating.
//! - **Signed as the room, through the gated oracle**: [`sign_next`] signs with
//!   [`RoomKeySigner`], which reaches the key only through `keys::sign_payload` — the same
//!   path, and the same custody gates, that mint the room's credentials.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use affinidi_data_integrity::DataIntegrityProof;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_rooms::revocation::{Entry, RevocationList, next_unsigned};

use crate::operations::room_issuance::{RoomKeySigner, SigningContext};

/// Prefix of a room's list in `room_groups`: `room-revocations/<roomId>`. Keyed by the
/// room, not by a member: a room has one list and one sequence, whichever persona on this
/// agent signs for it.
const LIST_PREFIX: &str = "room-revocations/";

/// Prefix of a room's tier, as this agent registered it: `room-tier/<roomId>`. What
/// `rooms/owner/revoke` item 2 means by "unless it already knows it from registering the
/// room".
const TIER_PREFIX: &str = "room-tier/";

/// Prefix of an outstanding delivery: `room-revocation-delivery/<roomId>|<host>`
/// (`rooms/owner/register/0.2`, *The room's revocation list* item 4). `|` appears in no DID.
const DELIVERY_PREFIX: &str = "room-revocation-delivery/";

fn list_key(room_id: &str) -> String {
    format!("{LIST_PREFIX}{room_id}")
}

fn delivery_key(room_id: &str, host: &str) -> String {
    format!("{DELIVERY_PREFIX}{room_id}|{host}")
}

/// A room's revocation list that did not reach a host the room was registered with —
/// `rooms/owner/register/0.2` item 4: the recipient goes on delivering a `pending` list on
/// its own, and "keeps for this only the room, the host and the sequence, and only until"
/// the host answers with its head or refuses it.
///
/// `persona` is the one thing kept beside those three, and it is not a fact about the room
/// or where it lives: it is which of the identities this agent already holds for the room
/// signs the delivery — the persona whose `admin` grant the first delivery presented. A
/// redelivery made as anyone else would be a different party speaking to the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutstandingDelivery {
    pub room_id: String,
    pub host: String,
    /// The list's sequence when it was first delivered. Each attempt delivers the latest
    /// list held, which keeps every live entry of this one.
    pub sequence: u64,
    pub persona: String,
}

/// Retain `delivery` durably — **before** the delivery it stands for is attempted, so a
/// process that dies mid-delivery leaves the record for the redelivery sweeper rather than a
/// host silently serving the room without its withdrawals.
pub async fn retain_delivery(
    groups: &KeyspaceHandle,
    delivery: &OutstandingDelivery,
) -> Result<(), AppError> {
    groups
        .insert(delivery_key(&delivery.room_id, &delivery.host), delivery)
        .await?;
    groups.persist().await
}

/// Every outstanding delivery, in key order. A row that does not read is one no build can
/// act on, and is dropped rather than retried forever.
pub async fn outstanding_deliveries(
    groups: &KeyspaceHandle,
) -> Result<Vec<OutstandingDelivery>, AppError> {
    let mut out = Vec::new();
    for (key, raw) in groups.prefix_iter_raw(DELIVERY_PREFIX).await? {
        match serde_json::from_slice::<OutstandingDelivery>(&raw) {
            Ok(d) => out.push(d),
            Err(e) => {
                tracing::warn!(error = %e, "an outstanding revocation-list delivery does not read; dropped");
                groups.remove(key).await?;
            }
        }
    }
    Ok(out)
}

/// The outstanding delivery of `room_id`'s list to `host`, if there is one.
pub async fn outstanding_delivery(
    groups: &KeyspaceHandle,
    room_id: &str,
    host: &str,
) -> Result<Option<OutstandingDelivery>, AppError> {
    groups.get(delivery_key(room_id, host)).await
}

/// Forget the outstanding delivery of `room_id`'s list to `host`: the host has the list, or
/// refused it (register/0.2 item 5: a refused list is never delivered again on its own).
pub async fn drop_delivery(
    groups: &KeyspaceHandle,
    room_id: &str,
    host: &str,
) -> Result<(), AppError> {
    groups.remove(delivery_key(room_id, host)).await?;
    groups.persist().await
}

/// `host` answered with the head of `room_id`'s list at `accepted`: an outstanding delivery
/// of that list or an earlier one is done, whoever delivered it. Returns whether one was.
pub async fn settle_delivery(
    groups: &KeyspaceHandle,
    room_id: &str,
    host: &str,
    accepted: u64,
) -> Result<bool, AppError> {
    match outstanding_delivery(groups, room_id, host).await? {
        Some(d) if d.sequence <= accepted => {
            drop_delivery(groups, room_id, host).await?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn tier_key(room_id: &str) -> String {
    format!("{TIER_PREFIX}{room_id}")
}

/// The stored row: the list exactly as signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    list: Value,
}

/// The list this agent holds for `room_id`, if any.
pub async fn held(
    groups: &KeyspaceHandle,
    room_id: &str,
) -> Result<Option<RevocationList>, AppError> {
    let Some(stored) = groups.get::<Stored>(list_key(room_id)).await? else {
        return Ok(None);
    };
    RevocationList::parse(&stored.list, room_id)
        .map(Some)
        .map_err(|e| {
            AppError::Internal(format!(
                "this agent's revocation list for room `{room_id}` does not read: {e}"
            ))
        })
}

/// Keep `list` as the room's list, durably (`rooms/owner/revoke` item 4: retained before
/// it is delivered anywhere). Called under [`signing_lock`].
pub async fn keep(groups: &KeyspaceHandle, list: &RevocationList) -> Result<(), AppError> {
    groups
        .insert(
            list_key(list.room_id()),
            &Stored {
                list: list.raw().clone(),
            },
        )
        .await?;
    groups.persist().await
}

/// Undo [`keep`] of `signed`, restoring `previous` — only while `signed` is still the list
/// held, so a later list built on it is never lost. `rooms/owner/group/remove/0.3` item 6:
/// a list no host accepted is discarded with the removal it was for. Called under
/// [`signing_lock`].
pub async fn discard_unaccepted(
    groups: &KeyspaceHandle,
    signed: &RevocationList,
    previous: Option<&Value>,
) -> Result<(), AppError> {
    let room_id = signed.room_id();
    match held(groups, room_id).await? {
        Some(current) if current.head() == signed.head() => match previous {
            Some(prev) => {
                groups
                    .insert(list_key(room_id), &Stored { list: prev.clone() })
                    .await?;
                groups.persist().await
            }
            None => {
                groups.remove(list_key(room_id)).await?;
                groups.persist().await
            }
        },
        _ => Ok(()),
    }
}

/// Adopt `recovered` — a list a host holds — if it is the room's (`roomId`, and a proof by
/// the room's own key, `public_key` being the key this agent signs as the room with) and
/// its sequence is above the one held (`rooms/revocations/get`, *reader*; `rooms/owner/
/// revoke` item 4). Returns whether it was adopted. Called under [`signing_lock`].
pub async fn adopt(
    groups: &KeyspaceHandle,
    room_id: &str,
    recovered: &Value,
    public_key: &[u8],
) -> Result<bool, AppError> {
    let Ok(list) = RevocationList::parse(recovered, room_id) else {
        return Ok(false);
    };
    if !signed_by_room(recovered, room_id, public_key) {
        tracing::warn!(room = %room_id, security_alert = true,
            "a host served a revocation list the room did not sign; not adopted");
        return Ok(false);
    }
    let ahead = match held(groups, room_id).await? {
        Some(h) => list.sequence() > h.sequence(),
        None => true,
    };
    if ahead {
        keep(groups, &list).await?;
    }
    Ok(ahead)
}

/// Whether `document`'s proof is by `room_id` with `public_key` — the room's own key, a
/// method under the room's DID, `assertionMethod`, over every other member.
fn signed_by_room(document: &Value, room_id: &str, public_key: &[u8]) -> bool {
    let Some(proof) = document
        .get("proof")
        .cloned()
        .and_then(|p| serde_json::from_value::<DataIntegrityProof>(p).ok())
    else {
        return false;
    };
    if proof.proof_purpose != "assertionMethod"
        || vti_common::auth::check_issuer_binding(&proof.verification_method, room_id).is_err()
    {
        return false;
    }
    let mut unsigned = document.clone();
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("proof");
    }
    proof
        .verify_with_public_key(
            &unsigned,
            public_key,
            affinidi_data_integrity::VerifyOptions::new(),
        )
        .is_ok()
}

/// Build and sign the room's next list (`rooms/owner/revoke` item 3): every entry of `held`
/// except those lapsed more than a day ago, then `added`, at the next sequence — signed as
/// `room_id` with `signing_key_id`, and **not yet kept**. Called under [`signing_lock`].
pub async fn sign_next(
    ctx: SigningContext<'_>,
    signing_key_id: &str,
    room_id: &str,
    held: Option<&RevocationList>,
    added: &[Entry],
    now: DateTime<Utc>,
) -> Result<RevocationList, AppError> {
    let mut document = next_unsigned(room_id, held, added, now);
    let signer = RoomKeySigner::new(ctx, signing_key_id, room_id);
    let proof = DataIntegrityProof::sign(
        &document,
        &signer,
        affinidi_data_integrity::SignOptions::new(),
    )
    .await
    .map_err(|e| {
        let mut cause = String::new();
        let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
        while let Some(inner) = src {
            cause = format!("{cause}: {inner}");
            src = inner.source();
        }
        AppError::Internal(format!(
            "sign room `{room_id}`'s revocation list: {e}{cause}"
        ))
    })?;
    document["proof"] = serde_json::to_value(proof)
        .map_err(|e| AppError::Internal(format!("serialise the list's proof: {e}")))?;
    RevocationList::parse(&document, room_id)
        .map_err(|e| AppError::Internal(format!("this agent built a list it cannot read: {e}")))
}

/// Record the tier a room was registered at.
pub async fn record_tier(
    groups: &KeyspaceHandle,
    room_id: &str,
    tier: &str,
) -> Result<(), AppError> {
    groups.insert(tier_key(room_id), &tier.to_string()).await
}

/// The tier this agent registered `room_id` at, if it did.
pub async fn known_tier(
    groups: &KeyspaceHandle,
    room_id: &str,
) -> Result<Option<String>, AppError> {
    groups.get(tier_key(room_id)).await
}

/// The lock that serializes building and signing one room's lists in this process
/// (`rooms/owner/revoke` item 3). Held from reading the held list until the next one is
/// kept; never across a delivery.
pub async fn signing_lock(room_id: &str) -> OwnedMutexGuard<()> {
    static LOCKS: LazyLock<Mutex<HashMap<String, Weak<AsyncMutex<()>>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    let lock = {
        let mut locks = LOCKS.lock().unwrap_or_else(|p| p.into_inner());
        match locks.get(room_id).and_then(Weak::upgrade) {
            Some(l) => l,
            None => {
                if locks.len() >= 1024 {
                    locks.retain(|_, w| w.strong_count() > 0);
                }
                let l = Arc::new(AsyncMutex::new(()));
                locks.insert(room_id.to_string(), Arc::downgrade(&l));
                l
            }
        }
    };
    lock.lock_owned().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_rooms_dtg::test_support::{Party, sign_as};

    async fn ks() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::ROOM_GROUPS).unwrap();
        (dir, ks)
    }

    fn pk(p: &Party) -> Vec<u8> {
        vta_sdk::did_key::decode_ed25519_public_key_multibase(
            p.did.strip_prefix("did:key:").unwrap(),
        )
        .unwrap()
        .to_vec()
    }

    async fn list(room: &Party, sequence: u64) -> Value {
        sign_as(
            room,
            serde_json::json!({
                "roomId": room.did, "sequence": sequence,
                "issuedAt": "2026-10-16T09:00:00Z", "entries": [],
            }),
        )
        .await
    }

    /// `rooms/revocations/get`, *reader*: a recovered list is adopted only if the room
    /// signed it and it is ahead of what is held.
    #[tokio::test]
    async fn only_a_later_list_the_room_signed_is_adopted() {
        let (_d, groups) = ks().await;
        let room = Party::new();
        let other = Party::new();
        assert!(
            adopt(&groups, &room.did, &list(&room, 3).await, &pk(&room))
                .await
                .unwrap()
        );
        assert_eq!(
            held(&groups, &room.did).await.unwrap().unwrap().sequence(),
            3
        );
        assert!(
            !adopt(&groups, &room.did, &list(&room, 2).await, &pk(&room))
                .await
                .unwrap()
        );
        // Signed by another key, however valid.
        let mut forged = list(&room, 9).await;
        forged.as_object_mut().unwrap().remove("proof");
        let forged = sign_as(&other, forged).await;
        assert!(
            !adopt(&groups, &room.did, &forged, &pk(&room))
                .await
                .unwrap()
        );
        assert_eq!(
            held(&groups, &room.did).await.unwrap().unwrap().sequence(),
            3
        );
    }

    /// `group/remove/0.2` item 6: an unaccepted list is discarded only while nothing was
    /// built on it.
    #[tokio::test]
    async fn an_unaccepted_list_is_rolled_back_only_while_it_is_still_the_head() {
        let (_d, groups) = ks().await;
        let room = Party::new();
        let first = RevocationList::parse(&list(&room, 1).await, &room.did).unwrap();
        keep(&groups, &first).await.unwrap();
        let second = RevocationList::parse(&list(&room, 2).await, &room.did).unwrap();
        keep(&groups, &second).await.unwrap();
        discard_unaccepted(&groups, &second, Some(first.raw()))
            .await
            .unwrap();
        assert_eq!(
            held(&groups, &room.did).await.unwrap().unwrap().sequence(),
            1
        );

        keep(&groups, &second).await.unwrap();
        let third = RevocationList::parse(&list(&room, 3).await, &room.did).unwrap();
        keep(&groups, &third).await.unwrap();
        discard_unaccepted(&groups, &second, Some(first.raw()))
            .await
            .unwrap();
        assert_eq!(
            held(&groups, &room.did).await.unwrap().unwrap().sequence(),
            3,
            "a list built on the discarded one stays"
        );
    }

    /// `rooms/owner/register/0.2` item 4: an outstanding delivery is kept per room and host
    /// until a host answers with that list or a later one.
    #[tokio::test]
    async fn an_outstanding_delivery_is_settled_only_by_its_list_or_a_later_one() {
        let (_d, groups) = ks().await;
        let d = OutstandingDelivery {
            room_id: "did:example:room".into(),
            host: "did:example:host".into(),
            sequence: 3,
            persona: "did:example:owner".into(),
        };
        retain_delivery(&groups, &d).await.unwrap();
        assert_eq!(
            outstanding_deliveries(&groups).await.unwrap(),
            vec![d.clone()]
        );
        assert!(
            !settle_delivery(&groups, &d.room_id, "did:example:other", 9)
                .await
                .unwrap()
        );
        assert!(
            !settle_delivery(&groups, &d.room_id, &d.host, 2)
                .await
                .unwrap()
        );
        assert!(
            settle_delivery(&groups, &d.room_id, &d.host, 3)
                .await
                .unwrap()
        );
        assert!(outstanding_deliveries(&groups).await.unwrap().is_empty());
    }
}
