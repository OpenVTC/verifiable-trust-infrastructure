//! `did.jsonl` ↔ [`DIDWebVHState`] round-trip + record-by-SCID lookup.

use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::LogEntry;
use vta_sdk::webvh::WebvhDidRecord;

use super::errors::UpdateDidWebvhError;
use crate::store::KeyspaceHandle;
use crate::webvh_store;

/// Find a `WebvhDidRecord` by its SCID **or** its full DID.
///
/// The parameter is nominally a SCID — the CLI resolves its `did` argument to a
/// record and passes `record.scid`. But a *remote* caller does not have the SCID:
/// it holds the DID (`did:webvh:<scid>:<host>:<path>`), which is the only
/// identifier it was ever given. The trust-task handler passes that DID straight
/// through, so a lookup that matched SCID alone silently failed for every remote
/// update — the exact case delegated execution exists for.
///
/// So accept both. A full DID carries its SCID as the segment after the method
/// prefix; match on either, and a caller that has one but not the other still
/// resolves. The store is DID-keyed, so a full DID also takes the fast path.
pub(in crate::operations::did_webvh) async fn find_record_by_scid(
    webvh_ks: &KeyspaceHandle,
    scid_or_did: &str,
) -> Result<Option<WebvhDidRecord>, UpdateDidWebvhError> {
    // Fast path: the store is keyed by DID, so if the caller gave us one, use it.
    if scid_or_did.starts_with("did:webvh:")
        && let Some(record) = webvh_store::get_did(webvh_ks, scid_or_did)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_did: {e}")))?
    {
        return Ok(Some(record));
    }

    let all = webvh_store::list_dids(webvh_ks)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("list_dids: {e}")))?;
    // Match a bare SCID, or a full DID whose SCID segment matches.
    Ok(all
        .into_iter()
        .find(|r| r.scid == scid_or_did || r.did == scid_or_did))
}

/// Build a [`DIDWebVHState`] from a stored JSONL log string. Splits on
/// newlines, deserializes each non-empty line as a `LogEntry`, then
/// validates the chain so `validated_parameters` is populated.
pub(in crate::operations::did_webvh) fn state_from_jsonl(
    did_log: &str,
) -> Result<DIDWebVHState, UpdateDidWebvhError> {
    let mut state = DIDWebVHState::default();
    for line in did_log.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry = LogEntry::deserialize_string(line, None)
            .map_err(|e| UpdateDidWebvhError::Library(format!("parse log entry: {e}")))?;
        let version_number = entry.get_version_id_fields().map(|f| f.0).unwrap_or(0);
        state
            .log_entries_mut()
            .push(didwebvh_rs::log_entry_state::LogEntryState {
                log_entry: entry,
                version_number,
                validation_status:
                    didwebvh_rs::log_entry_state::LogEntryValidationStatus::NotValidated,
                validated_parameters: didwebvh_rs::parameters::Parameters::default(),
            });
    }
    state
        .validate()
        .map_err(|e| UpdateDidWebvhError::Library(format!("chain validation: {e}")))?
        .assert_complete()
        .map_err(|e| UpdateDidWebvhError::Library(format!("chain validation: {e}")))?;
    Ok(state)
}

/// Serialize a [`DIDWebVHState`]'s log entries back to JSONL for
/// persistence in the webvh store.
pub(in crate::operations::did_webvh) fn state_to_jsonl(
    state: &DIDWebVHState,
) -> Result<String, UpdateDidWebvhError> {
    let mut out = String::new();
    for entry in state.log_entries() {
        let line = serde_json::to_string(&entry.log_entry)
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("serialize log entry: {e}")))?;
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    async fn setup_ks() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::WEBVH).unwrap();
        (dir, ks)
    }

    fn record(scid: &str, did: &str) -> WebvhDidRecord {
        WebvhDidRecord {
            did: did.into(),
            server_id: "serverless".into(),
            mnemonic: "irrelevant".into(),
            scid: scid.into(),
            context_id: "vta".into(),
            portable: true,
            log_entry_count: 1,
            pre_rotation_count: 0,
            next_fragment_id: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// The property `run_update`'s key-handle canonicalization relies on: whether
    /// looked up by full DID (delegated path) or bare SCID (CLI path), the record
    /// returned carries the SAME canonical bare `scid`. Keying `webvh_keys` off
    /// `record.scid` therefore lands in one keyspace regardless of caller — the
    /// fix for the #659 keyspace bifurcation.
    #[tokio::test]
    async fn both_identifier_forms_resolve_to_the_same_canonical_scid() {
        let (_dir, ks) = setup_ks().await;
        let scid = "QmScidHash";
        let did = "did:webvh:QmScidHash:webvh.example.com:agent";
        webvh_store::store_did(&ks, &record(scid, did))
            .await
            .unwrap();

        let by_did = find_record_by_scid(&ks, did)
            .await
            .unwrap()
            .expect("lookup by full DID resolves");
        let by_scid = find_record_by_scid(&ks, scid)
            .await
            .unwrap()
            .expect("lookup by bare SCID resolves");

        // The canonical bare SCID is identical for both entry forms — so the
        // webvh_keys prefix built from `record.scid` never bifurcates.
        assert_eq!(by_did.scid, scid);
        assert_eq!(by_scid.scid, scid);
        assert_eq!(by_did.scid, by_scid.scid);
    }
}
