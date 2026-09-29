//! `vta tsp-relationships …` — offline inspection and clearing of this VTA's
//! persisted TSP relationships (Rev 3 §7.2.2).
//!
//! ## What a relationship is here
//!
//! Each endpoint keeps its own half of every relationship, in its own store (the
//! encrypted `relationships` keyspace here). The mediator holds none of it, so
//! wiping the mediator resets nothing: to make two nodes meet as strangers again,
//! both halves have to go — this VTA's (these commands) and the peer's (its own
//! equivalent, e.g. a DID hosting service's `tsp-relationship-delete`).
//!
//! ## Reset versus delete
//!
//! - **reset** puts our half back to `None` and clears the thread digests —
//!   exactly what the SDK's `reset_relationship` does in the D6 reply-timeout
//!   recovery. The cached peer capability survives. The next send re-invites.
//! - **delete** removes every facet of the record (state, digests, reply path,
//!   capability, last-active), as the idle-eviction sweep does.
//!
//! Both are purely local. A peer that kept its half re-forms the relationship on
//! the next invite (D2 reconcile); a peer that sends first is dropped by our gate
//! until its own recovery re-invites.
//!
//! ## Offline, sealed, not for TEE
//!
//! Opens the store directly through [`CliStore`], so the keyspace decrypts under
//! hardened configuration. fjall's lock refuses the open while the daemon runs;
//! stop it first. `reset` and `delete` modify state and are refused on a sealed
//! VTA; `list` is not. A Nitro Enclave's store is unreachable from the parent
//! host, as for every offline surface.
//!
//! Every read and write goes through the SDK's `PersistentRelationshipStore`,
//! which owns the key layout; nothing here decodes a key itself.

use std::path::PathBuf;

use affinidi_messaging_sdk::protocols::tsp::{RelationshipState, RelationshipStore, ThreadDigests};
use vti_common::relationship_store::{KeyspaceRelationshipKv, KeyspaceRelationshipStore};
use vti_common::store::KeyspaceHandle;

use crate::cli_store::CliStore;
use crate::config::AppConfig;

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// Which relationships a reset or delete applies to.
pub enum Target {
    /// Every relationship this VTA holds with `peer`. With `our`, only the one
    /// held under that local VID — the way to reach a half-formed pair, which the
    /// store can enumerate only once it is established.
    Peer { peer: String, our: Option<String> },
    /// Every record in the relationships keyspace, established or not.
    All,
}

/// Open the (decrypting) relationships keyspace. The [`CliStore`] is returned
/// too: it holds the storage key and must outlive the writes, which it then
/// persists.
async fn open(
    config_path: Option<PathBuf>,
) -> Result<(CliStore, KeyspaceHandle), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let cs = CliStore::open(&config).await?;
    let ks = cs.keyspace(crate::keyspaces::RELATIONSHIPS)?;
    Ok((cs, ks))
}

fn store_over(ks: &KeyspaceHandle) -> KeyspaceRelationshipStore {
    KeyspaceRelationshipStore::new(KeyspaceRelationshipKv::new(ks.clone()))
}

/// `vta tsp-relationships list` — the relationships this VTA has established.
pub async fn run_list(config_path: Option<PathBuf>) -> CliResult {
    let (_cs, ks) = open(config_path).await?;
    list_on(&ks).await
}

async fn list_on(ks: &KeyspaceHandle) -> CliResult {
    let relationships = store_over(ks);
    let established = relationships.established_relationships().await?;
    let records = ks.prefix_iter_raw(Vec::new()).await?.len();

    eprintln!();
    if established.is_empty() {
        eprintln!("  No established TSP relationships.");
    } else {
        let now_ms = now_ms();
        for (our, their) in &established {
            eprintln!("  {their}");
            eprintln!("    local VID   : {our}");
            match relationships.last_active(our, their).await? {
                Some(at_ms) => eprintln!(
                    "    last active : {} ago",
                    format_age(now_ms.saturating_sub(at_ms) / 1000)
                ),
                None => eprintln!("    last active : never recorded"),
            }
            eprintln!();
        }
    }
    if records > 0 {
        eprintln!(
            "  {records} stored record(s) in total. A half-formed relationship (invite sent or\n  \
             received, never accepted) is stored but not listed; `vta tsp-relationships delete\n  \
             --all` clears it, or target it with `--peer <did> --our <vid>`."
        );
        eprintln!();
    }
    Ok(())
}

/// `vta tsp-relationships reset` — put our half back to `None`, so the next send
/// re-invites.
pub async fn run_reset(
    config_path: Option<PathBuf>,
    peer: String,
    our: Option<String>,
) -> CliResult {
    let (cs, ks) = open(config_path).await?;
    reset_on(&ks, &peer, our).await?;
    cs.persist().await?;
    eprintln!("  The next send to the peer re-invites; restart the VTA to pick this up.");
    Ok(())
}

async fn reset_on(ks: &KeyspaceHandle, peer: &str, our: Option<String>) -> CliResult {
    let relationships = store_over(ks);
    for (our, their) in pairs_for(&relationships, peer, our).await? {
        relationships
            .set(&our, &their, RelationshipState::None)
            .await?;
        relationships
            .set_thread_digests(&our, &their, ThreadDigests::default())
            .await?;
        eprintln!("  Reset relationship with {their} (local VID {our}).");
    }
    Ok(())
}

/// `vta tsp-relationships delete` — remove relationship records outright.
///
/// `--all` without `yes` only reports what it would remove.
pub async fn run_delete(config_path: Option<PathBuf>, target: Target, yes: bool) -> CliResult {
    let (cs, ks) = open(config_path).await?;
    if delete_on(&ks, target, yes).await? {
        cs.persist().await?;
        eprintln!("  Peers that kept their half re-form it on the next invite.");
    }
    Ok(())
}

/// Returns whether anything was written.
async fn delete_on(
    ks: &KeyspaceHandle,
    target: Target,
    yes: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let relationships = store_over(ks);
    match target {
        Target::Peer { peer, our } => {
            for (our, their) in pairs_for(&relationships, &peer, our).await? {
                relationships.forget(&our, &their).await?;
                eprintln!("  Deleted relationship with {their} (local VID {our}).");
            }
            Ok(true)
        }
        Target::All => {
            // The whole keyspace, not just the established pairs: a half-formed
            // relationship is exactly what an operator clearing state wants gone,
            // and it cannot be enumerated through the store.
            let keys: Vec<Vec<u8>> = ks
                .prefix_iter_raw(Vec::new())
                .await?
                .into_iter()
                .map(|(k, _)| k)
                .collect();
            let established = relationships.established_relationships().await?.len();
            if keys.is_empty() {
                eprintln!("  No TSP relationship records; nothing to delete.");
                return Ok(false);
            }
            if !yes {
                eprintln!(
                    "  Would delete {} record(s) ({established} established relationship(s)). \
                     Re-run with --yes to delete.",
                    keys.len()
                );
                return Ok(false);
            }
            for key in &keys {
                ks.remove(key.clone()).await?;
            }
            eprintln!(
                "  Deleted {} record(s) ({established} established relationship(s)).",
                keys.len()
            );
            Ok(true)
        }
    }
}

/// The `(our_vid, their_vid)` pairs a `--peer` target names.
///
/// With `our`, exactly that pair — whatever state it is in. Without it, every
/// established pair with the peer; a peer with no established relationship is
/// an error rather than a silent no-op, so a typo in the DID is noticed.
async fn pairs_for(
    relationships: &KeyspaceRelationshipStore,
    peer: &str,
    our: Option<String>,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    if let Some(our) = our {
        return Ok(vec![(our, peer.to_string())]);
    }
    let pairs: Vec<_> = relationships
        .established_relationships()
        .await?
        .into_iter()
        .filter(|(_, their)| their == peer)
        .collect();
    if pairs.is_empty() {
        return Err(format!(
            "no established TSP relationship with `{peer}` (run `vta tsp-relationships list`). \
             A half-formed one needs `--our <vid>`, or clear everything with \
             `vta tsp-relationships delete --all`."
        )
        .into());
    }
    Ok(pairs)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

fn format_age(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h {}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d {}h", s / 86_400, (s % 86_400) / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const US: &str = "did:example:vta";

    /// A relationships keyspace holding two established relationships and one
    /// half-formed one, encrypted as a hardened VTA's is.
    async fn seeded() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let cs = CliStore::from_store(store, Some([0x5Au8; 32]));
        let ks = cs
            .keyspace(crate::keyspaces::RELATIONSHIPS)
            .expect("keyspace");
        let rel = store_over(&ks);
        for peer in ["did:example:hosting", "did:example:vtc"] {
            rel.set(US, peer, RelationshipState::Bidirectional)
                .await
                .expect("seed established");
        }
        rel.set(US, "did:example:half", RelationshipState::Pending)
            .await
            .expect("seed pending");
        (ks, dir)
    }

    async fn state(ks: &KeyspaceHandle, peer: &str) -> RelationshipState {
        store_over(ks).get(US, peer).await.expect("get")
    }

    #[tokio::test]
    async fn list_reads_through_the_encrypted_keyspace() {
        let (ks, _dir) = seeded().await;
        list_on(&ks).await.expect("list");
        assert_eq!(
            store_over(&ks)
                .established_relationships()
                .await
                .expect("enumerate")
                .len(),
            2,
            "both established pairs decrypt and enumerate"
        );
    }

    #[tokio::test]
    async fn reset_returns_one_peer_to_none_and_leaves_the_rest() {
        let (ks, _dir) = seeded().await;
        reset_on(&ks, "did:example:hosting", None)
            .await
            .expect("reset");
        assert_eq!(
            state(&ks, "did:example:hosting").await,
            RelationshipState::None
        );
        assert_eq!(
            state(&ks, "did:example:vtc").await,
            RelationshipState::Bidirectional,
            "only the named peer is reset"
        );
    }

    #[tokio::test]
    async fn an_unknown_peer_is_an_error_not_a_silent_no_op() {
        let (ks, _dir) = seeded().await;
        let err = reset_on(&ks, "did:example:typo", None)
            .await
            .expect_err("a peer with no relationship must be refused");
        assert!(err.to_string().contains("no established TSP relationship"));
    }

    /// A half-formed relationship is not enumerable through the store, so it is
    /// reachable only by naming the local VID.
    #[tokio::test]
    async fn a_half_formed_relationship_is_deleted_by_naming_the_local_vid() {
        let (ks, _dir) = seeded().await;
        delete_on(
            &ks,
            Target::Peer {
                peer: "did:example:half".into(),
                our: Some(US.into()),
            },
            false,
        )
        .await
        .expect("delete");
        assert_eq!(
            state(&ks, "did:example:half").await,
            RelationshipState::None
        );
    }

    #[tokio::test]
    async fn delete_all_only_reports_without_yes_and_clears_everything_with_it() {
        let (ks, _dir) = seeded().await;

        assert!(!delete_on(&ks, Target::All, false).await.expect("dry run"));
        assert_eq!(
            state(&ks, "did:example:hosting").await,
            RelationshipState::Bidirectional,
            "without --yes nothing is deleted"
        );

        assert!(delete_on(&ks, Target::All, true).await.expect("delete all"));
        assert!(
            ks.prefix_iter_raw(Vec::new())
                .await
                .expect("scan")
                .is_empty(),
            "--all removes half-formed records too"
        );
    }
}
