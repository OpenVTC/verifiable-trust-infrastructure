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
// Only the publishing half needs these; the reading half is pure functions over
// a resolved DID document and is available in every build.
#[cfg(feature = "webvh")]
use vti_common::auth::extractor::AuthClaims;
#[cfg(feature = "webvh")]
use vti_common::error::AppError;

#[cfg(feature = "webvh")]
use crate::server::AppState;

/// The `type` of the service entry an anchor lives in.
const ANCHOR_SERVICE_TYPE: &str = "RoomEpochAnchor";
/// Its fragment, so an anchor replaces its predecessor rather than joining it.
const ANCHOR_FRAGMENT: &str = "#epoch-anchor";

/// What is about to be written.
#[cfg(feature = "webvh")]
#[derive(Debug, Clone)]
pub struct Anchor {
    pub epoch: u64,
    pub epoch_authenticator: Vec<u8>,
    pub head_version: u64,
    pub data_commitment: Option<String>,
    pub record_count: Option<u64>,
}

/// What was written, and where.
#[cfg(feature = "webvh")]
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
#[cfg(feature = "webvh")]
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
#[cfg(feature = "webvh")]
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
#[cfg(any(feature = "webvh", test))]
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
///
/// Behind `webvh` because publishing an anchor **is** a `did:webvh` update: it
/// needs `did_webvh::update_did_webvh` and the log the witnesses co-sign. The
/// *reading* half above is deliberately not gated — it is pure functions over a
/// resolved DID document, and a build that could not check an anchor it was
/// shown would be one that silently stopped checking.
#[cfg(feature = "webvh")]
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

#[cfg(all(test, feature = "webvh"))]
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

/// What comparing a host's head against the room's own anchor came to.
///
/// The wire words, as `ReadVerification.anchor` spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorVerdict {
    Agrees,
    Ahead,
    Behind,
    Conflict,
    None,
    NotChecked,
}

impl AnchorVerdict {
    #[must_use]
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Agrees => "agrees",
            Self::Ahead => "ahead",
            Self::Behind => "behind",
            Self::Conflict => "conflict",
            Self::None => "none",
            Self::NotChecked => "notChecked",
        }
    }
}

/// The anchor a room has published, read from its DID document.
fn anchor_of(document: &Value) -> Option<&Value> {
    document
        .get("service")?
        .as_array()?
        .iter()
        .find(|s| s.get("type").and_then(Value::as_str) == Some(ANCHOR_SERVICE_TYPE))?
        .get("serviceEndpoint")
}

/// Compare what a host served against what the room itself published.
///
/// **The only one of this family's comparisons a first-time reader can make.**
/// `priorRoots` needs the agent to have read this room before; `count` needs a
/// complete unfiltered listing. This needs neither — every member resolves the
/// same room DID and reads the same witness-co-signed entry.
///
/// It is also the only place a **rollback** is visible: a host serving a state
/// older than the room's own published statement is `Behind`, and nothing else
/// in this family catches that.
#[must_use]
pub fn compare_to_anchor(
    document: &Value,
    served_version: u64,
    served_root: Option<&str>,
) -> AnchorVerdict {
    let Some(anchor) = anchor_of(document) else {
        return AnchorVerdict::None;
    };
    let Some(anchored_version) = anchor.get("headVersion").and_then(Value::as_u64) else {
        // An anchor with no head names no state, so there is nothing to compare
        // against — the same reason a bare root is not comparable to another.
        return AnchorVerdict::None;
    };

    match served_version.cmp(&anchored_version) {
        // The room has moved past its anchor. The ordinary case: an anchor
        // describes a moment, not the present, and says nothing about records
        // written since.
        std::cmp::Ordering::Greater => AnchorVerdict::Ahead,
        // The host is serving a state OLDER than the room's own witnessed
        // statement. A rollback, caught by a reader with no history and no peer.
        std::cmp::Ordering::Less => AnchorVerdict::Behind,
        std::cmp::Ordering::Equal => {
            let anchored_root = anchor.get("dataCommitment").and_then(Value::as_str);
            match (anchored_root, served_root) {
                // Same state, different root: the host has contradicted a value
                // its own room published and witnesses co-signed.
                (Some(a), Some(s)) if a != s => AnchorVerdict::Conflict,
                (Some(_), Some(_)) => AnchorVerdict::Agrees,
                // The anchor pinned the version and not the contents, so the
                // version agreeing is all that can be said. Reporting `agrees`
                // would claim a comparison that was not made.
                _ => AnchorVerdict::Ahead,
            }
        }
    }
}

#[cfg(test)]
mod comparison_tests {
    use super::*;

    fn room_with(anchor: Value) -> Value {
        serde_json::json!({
            "id": "did:webvh:example.com:rooms:r",
            "service": [
                { "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "https://x" },
                { "id": "#epoch-anchor", "type": ANCHOR_SERVICE_TYPE, "serviceEndpoint": anchor },
            ]
        })
    }

    const A: &str = "zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR";
    const B: &str = "zQmXo1sV5aJ7bT2kQdF9wRnPzYcH4uMgLtEjV6NrBqWsDpK";

    /// The detection nothing else in this family can make.
    #[test]
    fn a_host_serving_older_than_the_anchor_is_caught_by_a_first_time_reader() {
        let doc = room_with(serde_json::json!({ "headVersion": 412, "dataCommitment": A }));
        assert_eq!(compare_to_anchor(&doc, 400, Some(A)), AnchorVerdict::Behind);
    }

    /// Same state, different root — a host contradicting a witnessed value its
    /// own room published.
    #[test]
    fn the_same_version_with_a_different_root_is_a_conflict() {
        let doc = room_with(serde_json::json!({ "headVersion": 412, "dataCommitment": A }));
        assert_eq!(
            compare_to_anchor(&doc, 412, Some(B)),
            AnchorVerdict::Conflict
        );
        assert_eq!(compare_to_anchor(&doc, 412, Some(A)), AnchorVerdict::Agrees);
    }

    /// A room that has moved on is the ordinary case, not a finding.
    #[test]
    fn a_room_past_its_anchor_is_ahead_and_that_is_normal() {
        let doc = room_with(serde_json::json!({ "headVersion": 412, "dataCommitment": A }));
        assert_eq!(compare_to_anchor(&doc, 500, Some(B)), AnchorVerdict::Ahead);
    }

    /// An anchor that pinned a version and not the contents cannot say the
    /// contents agree, and must not claim to.
    #[test]
    fn a_version_only_anchor_never_reports_agreement_about_a_root() {
        let doc = room_with(serde_json::json!({ "headVersion": 412 }));
        assert_eq!(compare_to_anchor(&doc, 412, Some(A)), AnchorVerdict::Ahead);
    }

    /// No anchor is not a fault: anchoring costs a witnessed update and a key
    /// rotation, and a room may reasonably decline.
    #[test]
    fn a_room_with_no_anchor_is_none_rather_than_a_finding() {
        let bare = serde_json::json!({ "id": "did:webvh:example.com:rooms:r" });
        assert_eq!(compare_to_anchor(&bare, 412, Some(A)), AnchorVerdict::None);
        let other = serde_json::json!({
            "service": [{ "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "https://x" }]
        });
        assert_eq!(compare_to_anchor(&other, 412, Some(A)), AnchorVerdict::None);
    }
}
