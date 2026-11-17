//! Which keys may authorize a `did:webvh` log entry, read from the logs.
//!
//! A `did:webvh` log entry is authorized by an `eddsa-jcs-2022` proof whose
//! verification method is `did:key:<K>`, for a `K` the log names: an entry of
//! `updateKeys`, or — under pre-rotation — a key whose hash an earlier entry
//! committed in `nextKeyHashes`. A signing task that would make such a proof
//! for a caller would let that caller write the DID's next entry, so the
//! custodian refuses it (`keys/sign-document/0.1` item 6: a key bound to
//! another protocol is `failedPrecondition`).
//!
//! The answer is read from the logs themselves, never from the key-handle
//! index in `webvh_keys`: that index is bookkeeping — superseded after an
//! update without being reinstalled, absent for a DID created before it
//! existed, filed by role — and every gap in it would be a gap here. The log
//! is what a verifier reads, so it is what this reads.

use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::Value;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// The prefix `vta_webvh::webvh_store` files each DID's log under.
const LOG_PREFIX: &str = "log:";

/// The `did:webvh` held here whose log names `public_key` (multibase, as
/// `updateKeys` writes it) as an update key, or commits to its hash in
/// `nextKeyHashes`, in **any** entry. `None` when no held log does.
///
/// Any entry, not only the head: a proof by a key that authorized an earlier
/// entry is a fork of the log from that point, which is no less a forgery.
///
/// Logs that do not contain the key or its hash are not parsed. A log that
/// does but holds a line that cannot be read counts as naming the key: it
/// fails closed for that DID, never open, and never fails the caller's other
/// keys.
pub async fn log_authorized_by(
    webvh_ks: &KeyspaceHandle,
    public_key: &str,
) -> Result<Option<String>, AppError> {
    let hash = Secret::base58_hash_string(public_key)
        .map_err(|e| AppError::Internal(format!("hash public key {public_key}: {e}")))?;
    for (key, value) in webvh_ks.prefix_iter_raw(LOG_PREFIX).await? {
        let log = String::from_utf8_lossy(&value);
        if !log.contains(public_key) && !log.contains(hash.as_str()) {
            continue;
        }
        let did = String::from_utf8_lossy(&key)
            .trim_start_matches(LOG_PREFIX)
            .to_string();
        if log_names(&log, public_key, &hash) {
            return Ok(Some(did));
        }
    }
    Ok(None)
}

/// Whether some entry of `log` (JSON Lines) lists `public_key` in
/// `parameters.updateKeys` or `hash` in `parameters.nextKeyHashes`. An entry
/// that is not JSON counts as naming it (fail closed).
fn log_names(log: &str, public_key: &str, hash: &str) -> bool {
    let lists = |parameters: &Value, member: &str, want: &str| {
        parameters
            .get(member)
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(want)))
    };
    log.lines()
        .filter(|line| !line.trim().is_empty())
        .any(|line| match serde_json::from_str::<Value>(line) {
            Ok(entry) => {
                let parameters = entry.get("parameters").unwrap_or(&Value::Null);
                lists(parameters, "updateKeys", public_key)
                    || lists(parameters, "nextKeyHashes", hash)
            }
            Err(_) => true,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const OTHER: &str = "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

    fn entry(parameters: Value, state_key: &str) -> String {
        json!({
            "versionId": "1-Qm",
            "parameters": parameters,
            "state": { "id": "did:webvh:Qm:example.com", "verificationMethod": [
                { "id": "#key-0", "type": "Multikey", "publicKeyMultibase": state_key } ] },
        })
        .to_string()
    }

    /// The update key is named by the entry that declared it; a later entry
    /// that declares nothing (`"parameters": {}`, a metadata-only update)
    /// leaves it named — the case the key-handle index lost.
    #[test]
    fn an_update_key_stays_named_after_an_update_that_declares_nothing() {
        let log = [
            entry(json!({ "updateKeys": [KEY] }), KEY),
            entry(json!({}), KEY),
        ]
        .join("\n");
        assert!(log_names(&log, KEY, "zHash"));
    }

    /// A pre-rotation commitment names the key by hash before it is revealed.
    #[test]
    fn a_committed_next_key_is_named_by_its_hash() {
        let hash = Secret::base58_hash_string(OTHER).unwrap();
        let log = entry(json!({ "updateKeys": [KEY], "nextKeyHashes": [hash] }), KEY);
        assert!(log_names(&log, OTHER, &hash));
    }

    /// A key the document lists as a verification method, and nowhere in the
    /// parameters, authorizes nothing.
    #[test]
    fn a_verification_method_alone_is_not_named() {
        let hash = Secret::base58_hash_string(OTHER).unwrap();
        let log = entry(json!({ "updateKeys": [KEY] }), OTHER);
        assert!(!log_names(&log, OTHER, &hash));
    }

    /// A line that cannot be read fails closed.
    #[test]
    fn an_unreadable_entry_fails_closed() {
        assert!(log_names("{not json", KEY, "zHash"));
    }
}
