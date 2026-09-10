//! Publishing a room's state into the room's own witnessed log.
//!
//! # Why this is not just a DID update
//!
//! It is a DID update, mechanically. What makes it worth its own module is the
//! two refusals and the one shape decision, none of which the update path knows
//! about:
//!
//! - **A room with no witnesses cannot anchor.** An entry nobody co-signed is
//!   the controller's own word. Publishing one produces something that *looks*
//!   like an anchor and carries none of the property — worse than its absence,
//!   because a member checking it would believe they had checked something.
//! - **The anchor goes in a typed service entry**, which is the only slot in a
//!   `did:webvh` log entry that carries an ecosystem-defined value today:
//!   `parameters` is a closed struct, `versionId` and `versionTime` are
//!   computed, and `proof` is the witnesses' signature over the rest — it
//!   *secures* the anchor and cannot *be* it.
//! - **An anchor supersedes rather than accumulates.** One entry per room,
//!   replaced in place. A document that grew an entry per anchor would carry a
//!   history the log already keeps, in a place with no ordering.

use serde_json::Value;
use vti_common::auth::extractor::AuthClaims;
use vti_common::error::AppError;

use crate::server::AppState;

/// The `type` of the service entry an anchor lives in.
const ANCHOR_SERVICE_TYPE: &str = "RoomEpochAnchor";
/// Its fragment, so an anchor replaces its predecessor rather than joining it.
const ANCHOR_FRAGMENT: &str = "#epoch-anchor";

/// What is about to be written.
#[derive(Debug, Clone)]
pub struct Anchor {
    pub epoch: u64,
    pub epoch_authenticator: Vec<u8>,
    pub head_version: u64,
    pub data_commitment: Option<String>,
    pub record_count: Option<u64>,
}

/// What was written, and where.
#[derive(Debug, Clone)]
pub struct Published {
    pub anchored: Value,
    /// The log entry the anchor rode. Naming it is what lets anyone fetch that
    /// entry and check the witnesses' signature over it; an anchor whose entry
    /// could not be named would be unverifiable in exactly the way this exists
    /// to prevent.
    pub version_id: String,
}

/// Render the anchor as the service entry the room's document carries.
fn service_entry(room_id: &str, anchor: &Anchor) -> Value {
    let mut endpoint = serde_json::Map::new();
    endpoint.insert("epoch".into(), serde_json::json!(anchor.epoch));
    endpoint.insert(
        "epochAuthenticator".into(),
        serde_json::json!(vti_rooms::merkle::to_multibase(&sha2_digest(
            &anchor.epoch_authenticator
        ))),
    );
    endpoint.insert("headVersion".into(), serde_json::json!(anchor.head_version));
    // Both or neither: a root without the state it describes is not comparable
    // to another root, so publishing one alone would put something that looks
    // like evidence into a witnessed log.
    if let (Some(root), Some(count)) = (&anchor.data_commitment, anchor.record_count) {
        endpoint.insert("dataCommitment".into(), serde_json::json!(root));
        endpoint.insert("recordCount".into(), serde_json::json!(count));
    }
    serde_json::json!({
        "id": format!("{room_id}{ANCHOR_FRAGMENT}"),
        "type": ANCHOR_SERVICE_TYPE,
        "serviceEndpoint": Value::Object(endpoint),
    })
}

/// SHA-256 over the raw authenticator, so what is published is a
/// `DigestMultibase` like every other digest in this family rather than a bare
/// base64 blob whose algorithm is implied by context.
fn sha2_digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Whether the room's log is witnessed.
///
/// Read from the entries' `parameters`, because that is where `did:webvh` keeps
/// it — a record of the DID does not carry it, and inferring it from the
/// document would be inferring it from the thing being signed.
///
/// The log arrives as **text**, one JSON entry per line (JSONL), which is the
/// form the log is published and witnessed in. Parsing it here rather than
/// asking for a typed view keeps this reading exactly what a member fetching
/// the log would read.
fn is_witnessed(log: Option<&str>) -> bool {
    let Some(text) = log else {
        return false;
    };
    text.lines().any(|line| {
        let Ok(entry) = serde_json::from_str::<Value>(line) else {
            return false;
        };
        entry
            .get("parameters")
            .and_then(|p| p.get("witness"))
            .and_then(|w| w.get("witnesses"))
            .and_then(|w| w.as_array())
            .is_some_and(|w| !w.is_empty())
    })
}

/// Write `anchor` into the room's log.
pub async fn publish(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
    _signing_key_id: &str,
    anchor: Anchor,
) -> Result<Published, AppError> {
    let current = crate::operations::did_webvh::get_did_webvh(
        &state.webvh_ks,
        auth,
        room_id,
        "trust-task",
        true,
    )
    .await?;

    if !is_witnessed(current.log.as_deref()) {
        return Err(AppError::Validation(format!(
            "room `{room_id}` is configured with no witnesses, so an entry in its log would be \
             its controller's own word. An anchor nobody co-signed looks like an anchor and \
             carries none of the property, which is worse than not having one — a member \
             checking it would believe they had checked something. Configure witnesses for \
             this room's DID; retrying will not help."
        )));
    }

    let resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Validation("this agent has no DID resolver configured".into()))?;
    let resolved = resolver
        .resolve(room_id)
        .await
        .map_err(|e| AppError::Validation(format!("room `{room_id}` does not resolve: {e}")))?;
    let mut document = serde_json::to_value(&resolved.doc)
        .map_err(|e| AppError::Internal(format!("serialise the room's document: {e}")))?;

    let entry = service_entry(room_id, &anchor);
    let anchored = entry["serviceEndpoint"].clone();

    // Superseded, not accumulated: one entry per room, replaced in place. A
    // document that grew an entry per anchor would carry a history the log
    // already keeps, in a place with no ordering.
    match document.get_mut("service").and_then(Value::as_array_mut) {
        Some(list) => {
            list.retain(|s| s.get("type").and_then(Value::as_str) != Some(ANCHOR_SERVICE_TYPE));
            list.push(entry);
        }
        None => document["service"] = Value::Array(vec![entry]),
    }

    let deps = crate::operations::did_webvh::WebvhDeps::from_app_state(state, resolver);
    let vta_did = state.config.read().await.vta_did.clone();
    let result = crate::operations::did_webvh::update_did_webvh(
        &deps,
        auth,
        room_id,
        crate::operations::did_webvh::UpdateDidWebvhOptions {
            document: Some(document),
            label: Some(format!("anchor {room_id}")),
            ..Default::default()
        },
        vta_did.as_deref(),
        "trust-task",
    )
    .await
    .map_err(AppError::from)?;

    let version_id = serde_json::to_value(&result)
        .ok()
        .and_then(|v| {
            v.get("versionId")
                .or_else(|| v.get("version_id"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();

    Ok(Published {
        anchored,
        version_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A log with no witnesses is not a log this will write to.
    #[test]
    fn an_unwitnessed_log_is_refused_rather_than_written_to() {
        assert!(!is_witnessed(None));
        assert!(!is_witnessed(Some("")));
        assert!(!is_witnessed(Some(r#"{"parameters":{}}"#)));
        assert!(!is_witnessed(Some(
            r#"{"parameters":{"witness":{"witnesses":[]}}}"#
        )));
        assert!(is_witnessed(Some(
            r#"{"parameters":{"witness":{"witnesses":[{"id":"did:key:zW"}]}}}"#
        )));
        // A log whose LATER entries drop witnesses still counts as witnessed
        // for the entries that had them, and this deliberately reads the whole
        // log rather than only the head: a room that was witnessed and is not
        // any more is a different question from one that never was, and
        // answering it here would be answering it in the wrong place.
        assert!(is_witnessed(Some(
            "{\"parameters\":{\"witness\":{\"witnesses\":[{\"id\":\"did:key:zW\"}]}}}\n{\"parameters\":{}}"
        )));
    }

    /// A root without the state it describes never reaches the log.
    ///
    /// One alone would put something that looks like evidence into a witnessed
    /// entry, where it is permanent and where a member would reasonably compare
    /// against it.
    #[test]
    fn a_commitment_is_published_with_its_count_or_not_at_all() {
        let with = service_entry(
            "did:webvh:example.com:rooms:r",
            &Anchor {
                epoch: 7,
                epoch_authenticator: vec![1, 2, 3],
                head_version: 412,
                data_commitment: Some("zQm".into()),
                record_count: Some(118),
            },
        );
        assert!(with["serviceEndpoint"]["dataCommitment"].is_string());
        assert_eq!(with["serviceEndpoint"]["recordCount"], 118);

        let half = service_entry(
            "did:webvh:example.com:rooms:r",
            &Anchor {
                epoch: 7,
                epoch_authenticator: vec![1, 2, 3],
                head_version: 412,
                data_commitment: Some("zQm".into()),
                record_count: None,
            },
        );
        assert!(half["serviceEndpoint"].get("dataCommitment").is_none());
        assert!(half["serviceEndpoint"].get("recordCount").is_none());
    }

    /// The authenticator is published as a `DigestMultibase`, like every other
    /// digest in this family — not as a bare blob whose algorithm is implied.
    #[test]
    fn the_authenticator_is_published_as_a_digest_multibase() {
        let entry = service_entry(
            "did:webvh:example.com:rooms:r",
            &Anchor {
                epoch: 7,
                epoch_authenticator: vec![9; 32],
                head_version: 1,
                data_commitment: None,
                record_count: None,
            },
        );
        let value = entry["serviceEndpoint"]["epochAuthenticator"]
            .as_str()
            .expect("a string");
        assert!(value.starts_with('z'), "base58btc multibase: {value}");
        assert!(vti_rooms::merkle::from_multibase(value).is_ok());
    }
}
