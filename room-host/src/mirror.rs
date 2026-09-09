//! Pulling a room from its write-primary — §7.3's read mirrors.
//!
//! # What a mirror is, and what it is not
//!
//! A mirror holds a **read-only copy** of a room primaried somewhere else. It
//! serves reads from that copy and refuses every write, naming the primary
//! (`vti_rooms::authz`). It is not a replica in the multi-writer sense: a room
//! has exactly one write-primary, MLS needs a single sequencer anyway, and
//! multi-primary replication is a stated non-goal.
//!
//! What a mirror **cannot** do is tamper. Records are signed and their AEAD
//! binds `roomId | key | version | epoch`, so a mirror that altered or
//! relocated one produces something that does not verify and does not open. The
//! only failures available to it are being **stale** or being **silent**, and
//! both are visible to a client watching the version watermark.
//!
//! # A mirror pulls as a member, because there is no other way to read
//!
//! This is the design decision the note left implicit, and it is worth stating
//! plainly: **a mirror presents a room-issued chain conferring `read`**, exactly
//! as any other reader does. There is no mirror-shaped exemption at the primary
//! and no new verb — the room admits the mirror the same way it admits a person,
//! and can stop admitting it the same way.
//!
//! Two consequences follow, and neither is hidden:
//!
//! - On `attributed` / `private` the mirror reads **ciphertext**, which is all
//!   it needs to store and all it can ever have. Mirroring one of those rooms
//!   gives the mirror operator nothing the primary's operator does not already
//!   have.
//! - On `open` the mirror reads cleartext, because everything on that tier is
//!   cleartext to whoever holds it. Mirroring an `open` room to a host you would
//!   not let read it is not a thing this can do, and pretending otherwise would
//!   be the dishonest option.
//!
//! # Credentials come from a file, deliberately
//!
//! A mirror is a service, not an agent: nothing mints presentations for it, so
//! it holds its own room credentials. They are read from an operator-supplied
//! file rather than a flag, because a credential on a command line is a
//! credential in the process table and in the shell history.

use std::path::Path;

use serde::{Deserialize, Serialize};
use vtc_client::VtcClient;
use vtc_client::rooms::RoomSession;
use vti_rooms::{Record, storage};

use crate::HostState;

/// One room this host mirrors, and everything needed to keep it current.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MirroredRoom {
    /// The room's DID — the same identifier the primary knows it by. A mirror
    /// that renamed what it copied would be a different room.
    pub room_id: String,
    /// Base URL of the write-primary.
    pub primary_url: String,
    /// The primary's DID, when known. Used to bind this mirror's presentation
    /// to it, so a captured one is worthless elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_did: Option<String>,
    /// The membership credential the room issued this mirror.
    pub membership: String,
    /// Its authority chain, leaf first, conferring `read`.
    pub authority: Vec<String>,
    /// The DID this mirror signs its requests as — the party the chain's leaf
    /// grants to. A mismatch is refused at the primary, correctly and
    /// confusingly, so the two travel together.
    pub signer_did: String,
    /// That DID's private key, multibase.
    pub signer_key_multibase: String,
}

/// The file an operator points `--mirror-config` at.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MirrorConfig {
    #[serde(default)]
    pub rooms: Vec<MirroredRoom>,
}

impl MirrorConfig {
    /// Read the config, hardening it to owner-only first.
    ///
    /// It holds a private key and a room's credentials, so it gets the same
    /// treatment as every other secret this workspace writes to disk. The
    /// hardening is applied rather than merely asserted: a config an operator
    /// created with a permissive umask is the common case, and refusing to
    /// start over it would teach them to `chmod` and move on rather than fixing
    /// anything. A failure to tighten is *not* fatal — it is logged, because a
    /// filesystem that cannot express the mode (a mounted volume, a container
    /// overlay) is not a reason to refuse to mirror.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if let Err(e) = vti_common::secure_file::restrict_file_to_owner(path) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "could not restrict the mirror config to its owner; it holds a private key"
            );
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }
}

/// What one pull did, for the log and for the tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PullOutcome {
    /// Records copied.
    pub copied: usize,
    /// The watermark this mirror now holds.
    pub watermark: u64,
}

/// Pull everything the primary has that this mirror does not.
///
/// Resumes from the mirror's own watermark, so a pull is incremental and
/// interrupting one costs at most the records it had not yet stored. Tombstones
/// come through like any other record — that is why they exist, and a mirror
/// that skipped them would resurrect deletions on its next full rebuild.
///
/// # Failure is stale, never wrong
///
/// Any error leaves the mirror exactly as current as it was: each record is
/// stored as it arrives, and the watermark only advances past a record already
/// written. A mirror that cannot reach its primary keeps serving what it has,
/// which is the failure mode the design allows it — silent or stale, never
/// forged.
pub async fn pull_once(state: &HostState, mirror: &MirroredRoom) -> anyhow::Result<PullOutcome> {
    let room = storage::get_room(state.rooms(), &mirror.room_id).await?;
    if !room.is_mirror() {
        anyhow::bail!(
            "room `{}` is not registered here as a mirror; refusing to pull into a primary",
            mirror.room_id
        );
    }

    let client = VtcClient::anonymous(
        &mirror.primary_url,
        mirror.primary_did.as_deref().unwrap_or("did:key:zPrimary"),
    );
    let session = RoomSession::new(
        &mirror.room_id,
        mirror.membership.clone(),
        mirror.authority.clone(),
    )?;

    let since = room.watermark();
    let listing = client
        .list_records(
            &session,
            None,
            Some(since),
            &mirror.signer_did,
            &mirror.signer_key_multibase,
        )
        .await?;

    let mut outcome = PullOutcome {
        copied: 0,
        watermark: since,
    };

    // Ordered by version so an interrupted pull leaves a prefix rather than a
    // hole: the watermark then resumes from the last record actually stored,
    // and nothing between it and the primary's head is silently skipped.
    let mut pending: Vec<serde_json::Value> = listing.records;
    pending.sort_by_key(|r| {
        r.get("version")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    });

    for meta in pending {
        let Some(key) = meta.get("key").and_then(serde_json::Value::as_str) else {
            continue;
        };
        // The listing carries metadata only, so the body is a second call. That
        // is the same shape a member's read takes, and it is why a mirror needs
        // `read` rather than some listing-only grant.
        let full = client
            .get_record(
                &session,
                key,
                &mirror.signer_did,
                &mirror.signer_key_multibase,
            )
            .await?;
        // The wire is not this host's storage format. It used to be — a get
        // response deserialised straight into `Record`, which worked only
        // because the response *was* the storage record — and that coupling is
        // what put a storage type on the wire. `Record::from_wire` is the stated
        // inverse of `Record::committed`, so the mirror now reads a response and
        // rebuilds a record, rather than assuming they are one thing.
        let wire: vti_rooms::wire::GetRecordResponse = serde_json::from_value(full)?;
        let record = Record::from_wire(&wire.record)?;
        let version = record.version;

        match storage::store_mirrored_record(
            state.rooms(),
            state.records(),
            &mirror.room_id,
            record,
            now(),
        )
        .await
        {
            Ok(_) => {
                outcome.copied += 1;
                outcome.watermark = version;
            }
            // A record the mirror already has is not an error: two pulls can
            // overlap, and refusing to go backwards is the storage layer doing
            // its job rather than a fault to abort on.
            Err(vti_common::error::AppError::Conflict(_)) => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(outcome)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Keep every configured mirror current, forever.
///
/// One sequential pass per interval rather than a task per room: a mirror is
/// not latency-critical (it serves a copy, and a client that needs the newest
/// record reads the primary), and a task per room turns one unreachable primary
/// into unbounded concurrent retries.
pub async fn run(state: std::sync::Arc<HostState>, config: MirrorConfig, interval_secs: u64) {
    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    loop {
        for mirror in &config.rooms {
            match pull_once(&state, mirror).await {
                Ok(outcome) if outcome.copied > 0 => tracing::info!(
                    room = %mirror.room_id,
                    copied = outcome.copied,
                    watermark = outcome.watermark,
                    "mirror pulled from primary"
                ),
                Ok(_) => tracing::debug!(room = %mirror.room_id, "mirror already current"),
                // Logged and carried on: an unreachable primary makes this
                // mirror stale, which is a state the design allows it to be and
                // a client can detect. Stopping the loop would make every other
                // mirror stale too.
                Err(e) => tracing::warn!(
                    room = %mirror.room_id,
                    primary = %mirror.primary_url,
                    error = %e,
                    "mirror pull failed; serving what we have"
                ),
            }
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MirroredRoom {
        MirroredRoom {
            room_id: "did:webvh:room.example".into(),
            primary_url: "https://primary.example.org".into(),
            primary_did: Some("did:web:primary.example.org".into()),
            membership: "vmc".into(),
            authority: vec!["vac-read".into()],
            signer_did: "did:key:zMirror".into(),
            signer_key_multibase: "z6Mk…".into(),
        }
    }

    /// The config is operator-authored JSON, so its member names are a contract.
    #[test]
    fn the_config_round_trips_under_its_wire_names() {
        let config = MirrorConfig {
            rooms: vec![sample()],
        };
        let v = serde_json::to_value(&config).unwrap();
        let room = &v["rooms"][0];
        assert!(room.get("roomId").is_some(), "{v}");
        assert!(room.get("primaryUrl").is_some(), "{v}");
        assert!(room.get("signerKeyMultibase").is_some(), "{v}");

        let back: MirrorConfig = serde_json::from_value(v).unwrap();
        assert_eq!(back.rooms[0].room_id, sample().room_id);
    }

    /// A primary's DID is optional, and its absence must not read as an empty
    /// string — that would bind the presentation to a party named "".
    #[test]
    fn an_absent_primary_did_stays_absent() {
        let json = serde_json::json!({
            "rooms": [{
                "roomId": "did:webvh:room.example",
                "primaryUrl": "https://primary.example.org",
                "membership": "vmc",
                "authority": ["vac"],
                "signerDid": "did:key:zMirror",
                "signerKeyMultibase": "z6Mk",
            }]
        });
        let config: MirrorConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.rooms[0].primary_did, None);
    }

    /// An empty config is a valid one: a host with no mirrors is the ordinary
    /// case, and it must not need the member spelled out.
    #[test]
    fn an_empty_config_is_valid() {
        let config: MirrorConfig = serde_json::from_str("{}").unwrap();
        assert!(config.rooms.is_empty());
    }
}
