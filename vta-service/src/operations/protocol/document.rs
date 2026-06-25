//! Read/replace/remove the per-kind transport service entries on a
//! DID document.
//!
//! Pure functions over `serde_json::Value`. No I/O, no keystore access.
//! Identifies each kind by `id` fragment suffix (matching what the
//! workspace's setup wizard emits — `#vta-didcomm` and `#vta-rest`),
//! so all existing DID documents are recognised without migration.
//!
//! ## Invariants
//!
//! - At most one `#vta-didcomm` and one `#vta-rest` entry exists at
//!   any time.
//! - `verificationMethod`, `authentication`, `assertionMethod`,
//!   `keyAgreement` are NEVER touched by these helpers.
//! - All other service entries (TeeAttestation, etc.) are preserved
//!   byte-for-byte.
//!
//! ## REST entry shape (preserved for SDK compat)
//!
//! The REST entry rendered by [`with_rest_service`] matches the
//! shape `setup::build_vta_additional_services` has produced since
//! initial setup —
//! `{ id, type: "VTARest", serviceEndpoint: "<url>" }` with a
//! plain-string `serviceEndpoint`. The SDK's
//! `Resolved::find_service("vta-rest")` (`vta-sdk/src/session.rs:1100`)
//! depends on this; do not reshape. Reading tolerates the
//! object/array forms a future operator might paste in.

use serde_json::{Value, json};
use thiserror::Error;

/// Parse the most recent (last non-empty) line of a `did.jsonl`
/// log and return the published DID-document state from that
/// LogEntry. This is the canonical "current document on chain"
/// helper used by every service-management op layer
/// (enable / update / disable / rollback for both REST and DIDComm)
/// — single source of truth so a future change to the WebVH log
/// shape lands in one place.
pub fn current_document_from_log(did_log: &str) -> Result<Value, CurrentDocumentError> {
    use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};
    let line = did_log
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .ok_or(CurrentDocumentError::EmptyLog)?;
    let entry: LogEntry = serde_json::from_str(line)
        .map_err(|e| CurrentDocumentError::Parse(format!("DID log line parse: {e}")))?;
    Ok(entry.get_state().clone())
}

/// Errors from [`current_document_from_log`]. Each op error type
/// converts these into its own variants so the wire-error mapping
/// stays per-op (different status codes, different suggested fixes).
#[derive(Debug, Error)]
pub enum CurrentDocumentError {
    #[error("VTA DID log is empty — cannot read current document")]
    EmptyLog,
    #[error("{0}")]
    Parse(String),
}

/// Fragment used by this workspace for the DIDComm mediator service
/// entry. Matches what
/// `operations::did_webvh::document::build_did_document_inner` emits.
pub const DIDCOMM_SERVICE_FRAGMENT: &str = "#vta-didcomm";

/// Fragment used for the VTA's REST service entry. Matches what
/// `setup::build_vta_additional_services` emits and what
/// `vta-sdk/src/session.rs:1100` resolves against — do not change.
pub const REST_SERVICE_FRAGMENT: &str = "#vta-rest";

/// `type` literal for the REST service entry. Stable wire form;
/// renaming would silently break SDK resolution.
pub const REST_SERVICE_TYPE: &str = "VTARest";

/// Fragment used for the VTA's WebAuthn-RP service entry. Distinct
/// from `#vta-rest` because the WebAuthn-RP surface has different
/// availability semantics from the general REST API (it can be
/// runtime-toggled independently and may be advertised on DIDs that
/// don't otherwise expose REST — e.g. a passkey-only login portal).
pub const WEBAUTHN_SERVICE_FRAGMENT: &str = "#vta-webauthn";

/// `type` literal for the WebAuthn-RP service entry. Aligns with the
/// emerging convention used in the DIF / VC ecosystem for declaring
/// a WebAuthn relying party on a DID document, rather than minting a
/// VTA-internal `VTAxxx` name. If wider tooling settles on a
/// different literal later, this is the one knob to change.
pub const WEBAUTHN_SERVICE_TYPE: &str = "WebAuthnRP";

/// Fragment used for the VTA's TSP (Trust Spanning Protocol) service
/// entry. Per the TSP enablement design (D9) the TSP id drops the
/// `vta-` prefix — `#tsp`, not `#vta-tsp`. Service discovery is by
/// `type` (below), so the exact fragment is a cosmetic label.
/// See docs/05-design-notes/tsp-enablement.md.
pub const TSP_SERVICE_FRAGMENT: &str = "#tsp";

/// `type` literal for the TSP service entry. `TSPTransport` is the
/// OpenWallet-Foundation-Labs reference-implementation convention
/// (the ToIP TSP spec names no DID-document service type) and is what
/// `affinidi_tsp`'s DID-backed VID resolver matches on. Do not change —
/// renaming silently breaks TSP discovery by any TSP party.
pub const TSP_SERVICE_TYPE: &str = "TSPTransport";

/// A read-only view of the DIDComm service entry on a DID document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidcommServiceRef {
    /// Full service `id` (e.g. `did:webvh:scid:host:path#vta-didcomm`).
    pub id: String,
    /// The mediator DID this entry advertises (the `uri` field of the
    /// service endpoint object, or the bare endpoint string for legacy
    /// docs).
    pub mediator_did: String,
    /// Routing keys advertised on the `routingKeys` array of the
    /// service endpoint object, if any. Empty when the entry omits
    /// the field or carries the legacy plain-string endpoint shape.
    /// `list_services` surfaces these to operators so a future
    /// writer that adds routing-key support reads consistent state.
    pub routing_keys: Vec<String>,
}

/// A read-only view of the REST service entry on a DID document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestServiceRef {
    /// Full service `id` (e.g. `did:webvh:scid:host:path#vta-rest`).
    pub id: String,
    /// The URL this entry advertises. Whether the wire form was a
    /// plain string (current convention), an object with `uri`, or
    /// a single-element array, this is the resolved URL the SDK
    /// will route REST traffic to.
    pub url: String,
}

/// A read-only view of the WebAuthn-RP service entry on a DID
/// document. Same shape as [`RestServiceRef`] — just a URL — but
/// kept as a distinct type so handlers can't accidentally treat one
/// as the other (different runtime gates, different availability).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebauthnServiceRef {
    /// Full service `id` (e.g. `did:webvh:scid:host:path#vta-webauthn`).
    pub id: String,
    /// The URL this entry advertises — typically the operator-facing
    /// auth portal (e.g. `https://vta.example.com/auth/portal`).
    pub url: String,
}

/// A read-only view of the TSP (`TSPTransport`) service entry on a DID
/// document. Like [`DidcommServiceRef`] the endpoint is a **mediator
/// DID** (the VTA's TSP VID), not a URL — TSP uses the same mediator
/// indirection as DIDComm, with the actual transport URL living in the
/// mediator's own DID document (tsp-enablement.md §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TspServiceRef {
    /// Full service `id` (e.g. `did:webvh:scid:host:path#tsp`).
    pub id: String,
    /// The mediator DID this entry advertises (the VTA's TSP VID).
    pub mediator_did: String,
}

#[derive(Debug, Error)]
pub enum DocumentPatchError {
    #[error("DID document is not a JSON object")]
    NotAnObject,
    #[error("DID document `id` field is missing or not a string")]
    MissingDocumentId,
    #[error("mediator DID must be a non-empty string")]
    EmptyMediatorDid,
    #[error("REST URL must be a non-empty string")]
    EmptyRestUrl,
    #[error("WebAuthn URL must be a non-empty string")]
    EmptyWebauthnUrl,
}

/// Locate the `#vta-didcomm` service entry on `doc`, if any.
pub fn current_didcomm_service(doc: &Value) -> Option<DidcommServiceRef> {
    let services = doc.get("service")?.as_array()?;
    for svc in services {
        let id = svc.get("id")?.as_str()?;
        if id_matches_didcomm(id) {
            let endpoint = svc.get("serviceEndpoint")?;
            let mediator_did = extract_mediator_did(endpoint)?;
            let routing_keys = extract_routing_keys(endpoint);
            return Some(DidcommServiceRef {
                id: id.to_string(),
                mediator_did,
                routing_keys,
            });
        }
    }
    None
}

/// Insert or replace the `#vta-didcomm` service entry, returning the
/// updated document. Any other service entries are preserved
/// byte-for-byte; `verificationMethod` and the verification-relation
/// arrays are never touched.
pub fn with_didcomm_service(
    mut doc: Value,
    mediator_did: &str,
) -> Result<Value, DocumentPatchError> {
    if mediator_did.is_empty() {
        return Err(DocumentPatchError::EmptyMediatorDid);
    }
    let did_id = doc
        .get("id")
        .and_then(Value::as_str)
        .ok_or(DocumentPatchError::MissingDocumentId)?
        .to_string();

    let new_entry = json!({
        "id": format!("{did_id}{DIDCOMM_SERVICE_FRAGMENT}"),
        "type": "DIDCommMessaging",
        "serviceEndpoint": [{
            "accept": ["didcomm/v2"],
            "uri": mediator_did,
        }]
    });

    let obj = doc.as_object_mut().ok_or(DocumentPatchError::NotAnObject)?;

    let services = obj
        .entry("service")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("service field must be an array");

    if let Some(existing) = services.iter_mut().find(|s| {
        s.get("id")
            .and_then(Value::as_str)
            .is_some_and(id_matches_didcomm)
    }) {
        *existing = new_entry;
    } else {
        services.push(new_entry);
    }

    // Canonicalize order — DIDComm must come before REST per spec §3.3.
    sort_services_canonical(&mut doc);
    Ok(doc)
}

/// Remove the `#vta-didcomm` service entry, if present. If the
/// resulting service array is empty, the `service` field is removed
/// entirely (matches the pre-DIDComm wizard output for REST-only VTAs
/// with no other services).
pub fn without_didcomm_service(mut doc: Value) -> Value {
    let Some(obj) = doc.as_object_mut() else {
        return doc;
    };
    let Some(services) = obj.get_mut("service").and_then(Value::as_array_mut) else {
        return doc;
    };
    services.retain(|s| {
        !s.get("id")
            .and_then(Value::as_str)
            .is_some_and(id_matches_didcomm)
    });
    if services.is_empty() {
        obj.remove("service");
    }
    doc
}

/// Locate the `#tsp` (`TSPTransport`) service entry on `doc`, if any.
///
/// TSP advertises like DIDComm — the `serviceEndpoint` is the VTA's
/// **mediator DID** (its TSP VID), not a transport URL — so it reuses
/// [`extract_mediator_did`] to tolerate the bare-string, `{uri}`, and
/// single-element-array endpoint shapes.
pub fn current_tsp_service(doc: &Value) -> Option<TspServiceRef> {
    let services = doc.get("service")?.as_array()?;
    for svc in services {
        let id = svc.get("id")?.as_str()?;
        if id_matches_tsp(id) {
            let mediator_did = extract_mediator_did(svc.get("serviceEndpoint")?)?;
            return Some(TspServiceRef {
                id: id.to_string(),
                mediator_did,
            });
        }
    }
    None
}

/// Insert or replace the `#tsp` service entry, returning the updated
/// document. `mediator_did` is the VTA's mediator DID (its TSP VID),
/// emitted as a plain-string `serviceEndpoint`. Other service entries
/// are preserved byte-for-byte; verification methods are never touched.
pub fn with_tsp_service(mut doc: Value, mediator_did: &str) -> Result<Value, DocumentPatchError> {
    if mediator_did.is_empty() {
        return Err(DocumentPatchError::EmptyMediatorDid);
    }
    let did_id = doc
        .get("id")
        .and_then(Value::as_str)
        .ok_or(DocumentPatchError::MissingDocumentId)?
        .to_string();

    let new_entry = json!({
        "id": format!("{did_id}{TSP_SERVICE_FRAGMENT}"),
        "type": TSP_SERVICE_TYPE,
        "serviceEndpoint": mediator_did,
    });

    let obj = doc.as_object_mut().ok_or(DocumentPatchError::NotAnObject)?;

    let services = obj
        .entry("service")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("service field must be an array");

    if let Some(existing) = services.iter_mut().find(|s| {
        s.get("id")
            .and_then(Value::as_str)
            .is_some_and(id_matches_tsp)
    }) {
        *existing = new_entry;
    } else {
        services.push(new_entry);
    }

    // Canonicalize order — TSP is the preferred transport per spec §3.3.
    sort_services_canonical(&mut doc);
    Ok(doc)
}

/// Remove the `#tsp` service entry, if present. If the resulting
/// service array is empty, the `service` field is removed entirely
/// (mirrors [`without_didcomm_service`]).
pub fn without_tsp_service(mut doc: Value) -> Value {
    let Some(obj) = doc.as_object_mut() else {
        return doc;
    };
    let Some(services) = obj.get_mut("service").and_then(Value::as_array_mut) else {
        return doc;
    };
    services.retain(|s| {
        !s.get("id")
            .and_then(Value::as_str)
            .is_some_and(id_matches_tsp)
    });
    if services.is_empty() {
        obj.remove("service");
    }
    doc
}

/// Match the workspace's canonical `#vta-didcomm` fragment shape.
/// Strict — accepts only `<did-without-fragment>#vta-didcomm`,
/// rejects malformed nested-fragment ids like
/// `did:webvh:foo#extra#vta-didcomm`. Defence-in-depth against
/// future writers that might emit non-canonical ids; the patcher
/// helpers in this module always emit the canonical form.
fn id_matches_didcomm(id: &str) -> bool {
    matches_canonical_fragment(id, DIDCOMM_SERVICE_FRAGMENT)
}

/// Match the workspace's canonical `#vta-rest` fragment shape.
/// See [`id_matches_didcomm`] for the rationale.
fn id_matches_rest(id: &str) -> bool {
    matches_canonical_fragment(id, REST_SERVICE_FRAGMENT)
}

/// Match the workspace's canonical `#tsp` fragment shape.
/// See [`id_matches_didcomm`] for the rationale.
fn id_matches_tsp(id: &str) -> bool {
    matches_canonical_fragment(id, TSP_SERVICE_FRAGMENT)
}

/// `id` matches `<did-without-fragment><fragment>` exactly. The
/// service-id contract per DID-Core is a single `#fragment` suffix
/// after the DID; reject ids that contain another `#` before the
/// expected fragment.
fn matches_canonical_fragment(id: &str, fragment: &str) -> bool {
    let Some(prefix) = id.strip_suffix(fragment) else {
        return false;
    };
    !prefix.contains('#')
}

/// Sort the `service` array into the canonical transport-preference
/// order — TSP, then DIDComm, then REST, then WebAuthn — with all
/// other entries (e.g. `#tee-attestation`) preserving their original
/// relative order.
///
/// Spec §3.3 — when multiple transports are advertised, TSP is the
/// preferred transport, then DIDComm, then REST (tsp-enablement.md
/// §11). We encode this via array ordering so a DID-Core resolver
/// walking the array picks the highest-preference transport first. No
/// `priority` key is used (DIDComm-v2-spec only) so that DID-Core-only
/// resolvers see the same preference.
///
/// Stable sort: `#tsp` -> `#vta-didcomm` -> `#vta-rest` ->
/// `#vta-webauthn` -> everything else (preserved in input order).
/// Idempotent. Pure — only mutates the `service` field of `doc`;
/// verification methods and other fields are untouched.
///
/// The ordering rationale:
/// - TSP is preferred (metadata-private routing at bounded size) when
///   both parties speak it.
/// - DIDComm is the next-best private end-to-end transport.
/// - REST is for programmatic clients that hold a bearer credential.
/// - WebAuthn is the operator/user-facing fallback that requires a
///   browser session — listed last so non-browser clients don't
///   accidentally pick it.
pub fn sort_services_canonical(doc: &mut Value) {
    let Some(obj) = doc.as_object_mut() else {
        return;
    };
    let Some(services) = obj.get_mut("service").and_then(Value::as_array_mut) else {
        return;
    };
    services.sort_by_key(|s| {
        let id = s.get("id").and_then(Value::as_str).unwrap_or("");
        // 0 = TSP, 1 = DIDComm, 2 = REST, 3 = WebAuthn, 4 = anything else (TEE etc.)
        if id_matches_tsp(id) {
            0u8
        } else if id_matches_didcomm(id) {
            1u8
        } else if id_matches_rest(id) {
            2u8
        } else if id_matches_webauthn(id) {
            3u8
        } else {
            4u8
        }
    });
}

fn extract_mediator_did(endpoint: &Value) -> Option<String> {
    match endpoint {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => map.get("uri")?.as_str().map(str::to_string),
        Value::Array(arr) => arr.iter().find_map(extract_mediator_did),
        _ => None,
    }
}

/// Extract the `routingKeys` array from a DIDComm `serviceEndpoint`
/// value. Returns the keys in source order, or empty when the
/// endpoint is the bare-string shape, omits the field, or has a
/// non-array `routingKeys`. Tolerates the array-of-objects shape
/// the DID-Core service-endpoint convention permits.
fn extract_routing_keys(endpoint: &Value) -> Vec<String> {
    match endpoint {
        Value::Object(map) => map
            .get("routingKeys")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        Value::Array(arr) => arr
            .iter()
            .find_map(|inner| match inner {
                Value::Object(_) => Some(extract_routing_keys(inner)),
                _ => None,
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Resolve the URL for a REST service entry's `serviceEndpoint`,
/// tolerating the three shapes a DID document might carry it in
/// (plain string — current convention; object with `uri`; or a
/// single-element array of either).
fn extract_rest_url(endpoint: &Value) -> Option<String> {
    match endpoint {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => map.get("uri")?.as_str().map(str::to_string),
        Value::Array(arr) => arr.iter().find_map(extract_rest_url),
        _ => None,
    }
}

/// Locate the `#vta-rest` service entry on `doc`, if any.
pub fn current_rest_service(doc: &Value) -> Option<RestServiceRef> {
    let services = doc.get("service")?.as_array()?;
    for svc in services {
        let id = svc.get("id")?.as_str()?;
        if id_matches_rest(id) {
            let url = extract_rest_url(svc.get("serviceEndpoint")?)?;
            return Some(RestServiceRef {
                id: id.to_string(),
                url,
            });
        }
    }
    None
}

/// Insert or replace the `#vta-rest` service entry, returning the
/// updated document. Other service entries are preserved
/// byte-for-byte; verification methods are never touched.
///
/// The rendered shape — `type: "VTARest"` (plain string),
/// `serviceEndpoint: "<url>"` (plain string) — matches the wire
/// form `setup::build_vta_additional_services` has produced since
/// initial setup, so SDK consumers
/// (`vta-sdk/src/session.rs:1100`) keep resolving without
/// migration.
pub fn with_rest_service(mut doc: Value, url: &str) -> Result<Value, DocumentPatchError> {
    if url.is_empty() {
        return Err(DocumentPatchError::EmptyRestUrl);
    }
    let did_id = doc
        .get("id")
        .and_then(Value::as_str)
        .ok_or(DocumentPatchError::MissingDocumentId)?
        .to_string();

    let new_entry = json!({
        "id": format!("{did_id}{REST_SERVICE_FRAGMENT}"),
        "type": REST_SERVICE_TYPE,
        "serviceEndpoint": url,
    });

    let obj = doc.as_object_mut().ok_or(DocumentPatchError::NotAnObject)?;

    let services = obj
        .entry("service")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("service field must be an array");

    if let Some(existing) = services.iter_mut().find(|s| {
        s.get("id")
            .and_then(Value::as_str)
            .is_some_and(id_matches_rest)
    }) {
        *existing = new_entry;
    } else {
        services.push(new_entry);
    }

    // Canonicalize order — DIDComm must come before REST per spec §3.3.
    sort_services_canonical(&mut doc);
    Ok(doc)
}

/// Remove the `#vta-rest` service entry, if present. If the
/// resulting service array is empty, the `service` field is
/// removed entirely (matches the no-services pre-mutation shape).
pub fn without_rest_service(mut doc: Value) -> Value {
    let Some(obj) = doc.as_object_mut() else {
        return doc;
    };
    let Some(services) = obj.get_mut("service").and_then(Value::as_array_mut) else {
        return doc;
    };
    services.retain(|s| {
        !s.get("id")
            .and_then(Value::as_str)
            .is_some_and(id_matches_rest)
    });
    if services.is_empty() {
        obj.remove("service");
    }
    doc
}

/// Locate the `#vta-webauthn` service entry on `doc`, if any.
pub fn current_webauthn_service(doc: &Value) -> Option<WebauthnServiceRef> {
    let services = doc.get("service")?.as_array()?;
    for svc in services {
        let id = svc.get("id")?.as_str()?;
        if id_matches_webauthn(id) {
            let url = extract_rest_url(svc.get("serviceEndpoint")?)?;
            return Some(WebauthnServiceRef {
                id: id.to_string(),
                url,
            });
        }
    }
    None
}

/// Insert or replace the `#vta-webauthn` service entry, returning the
/// updated document. Other service entries (`#vta-didcomm`,
/// `#vta-rest`, `#tee-attestation`, …) are preserved byte-for-byte;
/// `verificationMethod` and the verification-relation arrays are
/// untouched.
///
/// The `serviceEndpoint` is rendered as a plain URL string for
/// symmetry with `with_rest_service`'s shape — wallets and
/// `vta-sdk::session::resolve_*_url` walk strings, single-entry
/// arrays, and `{ uri }` objects interchangeably.
pub fn with_webauthn_service(mut doc: Value, url: &str) -> Result<Value, DocumentPatchError> {
    if url.is_empty() {
        return Err(DocumentPatchError::EmptyWebauthnUrl);
    }
    let did_id = doc
        .get("id")
        .and_then(Value::as_str)
        .ok_or(DocumentPatchError::MissingDocumentId)?
        .to_string();

    let new_entry = json!({
        "id": format!("{did_id}{WEBAUTHN_SERVICE_FRAGMENT}"),
        "type": WEBAUTHN_SERVICE_TYPE,
        "serviceEndpoint": url,
    });

    let obj = doc.as_object_mut().ok_or(DocumentPatchError::NotAnObject)?;

    let services = obj
        .entry("service")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("service field must be an array");

    if let Some(existing) = services.iter_mut().find(|s| {
        s.get("id")
            .and_then(Value::as_str)
            .is_some_and(id_matches_webauthn)
    }) {
        *existing = new_entry;
    } else {
        services.push(new_entry);
    }

    sort_services_canonical(&mut doc);
    Ok(doc)
}

/// Remove the `#vta-webauthn` service entry. Symmetric with
/// [`without_rest_service`].
pub fn without_webauthn_service(mut doc: Value) -> Value {
    let Some(obj) = doc.as_object_mut() else {
        return doc;
    };
    let Some(services) = obj.get_mut("service").and_then(Value::as_array_mut) else {
        return doc;
    };
    services.retain(|s| {
        !s.get("id")
            .and_then(Value::as_str)
            .is_some_and(id_matches_webauthn)
    });
    if services.is_empty() {
        obj.remove("service");
    }
    doc
}

/// Match the workspace's canonical `#vta-webauthn` fragment shape.
/// See [`id_matches_didcomm`] for the rationale on strict matching.
fn id_matches_webauthn(id: &str) -> bool {
    matches_canonical_fragment(id, WEBAUTHN_SERVICE_FRAGMENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Defence-in-depth: nested-fragment ids like
    /// `did:webvh:foo#extra#vta-rest` must NOT be matched as
    /// canonical REST/DIDComm service entries. The patcher writers
    /// always emit `<did>#vta-rest` / `<did>#vta-didcomm`; the
    /// readers reject anything else so a malformed id sneaking in
    /// doesn't get treated as our entry.
    #[test]
    fn fragment_match_is_strict_not_suffix() {
        assert!(id_matches_didcomm("did:webvh:foo#vta-didcomm"));
        assert!(id_matches_rest("did:webvh:foo#vta-rest"));
        assert!(id_matches_webauthn("did:webvh:foo#vta-webauthn"));
        // Nested fragment — reject.
        assert!(!id_matches_didcomm("did:webvh:foo#extra#vta-didcomm"));
        assert!(!id_matches_rest("did:webvh:foo#extra#vta-rest"));
        assert!(!id_matches_webauthn("did:webvh:foo#extra#vta-webauthn"));
        // Suffix-only collision — reject (fragment was preceded by
        // characters that aren't a `#`).
        assert!(!id_matches_didcomm("did:webvh:foo-vta-didcomm"));
        assert!(!id_matches_rest("did:webvh:foo-vta-rest"));
        assert!(!id_matches_webauthn("did:webvh:foo-vta-webauthn"));
    }

    #[test]
    fn with_webauthn_service_inserts_then_replaces() {
        let doc = doc_without_service();
        let patched = with_webauthn_service(doc, "https://vta.example.com/auth/portal").unwrap();
        let svc = current_webauthn_service(&patched).expect("webauthn entry present");
        assert_eq!(svc.url, "https://vta.example.com/auth/portal");
        assert_eq!(svc.id, format!("{}#vta-webauthn", vta_did()));

        // Replace with a new URL.
        let patched2 =
            with_webauthn_service(patched, "https://vta.example.com/auth/portal-v2").unwrap();
        let svc2 = current_webauthn_service(&patched2).expect("webauthn entry present");
        assert_eq!(svc2.url, "https://vta.example.com/auth/portal-v2");
        // Only one entry — replacement, not duplication.
        let services = patched2.get("service").unwrap().as_array().unwrap();
        let webauthn_entries = services
            .iter()
            .filter(|s| id_matches_webauthn(s.get("id").and_then(Value::as_str).unwrap_or("")))
            .count();
        assert_eq!(webauthn_entries, 1);
    }

    #[test]
    fn with_webauthn_service_rejects_empty_url() {
        let err = with_webauthn_service(doc_without_service(), "").unwrap_err();
        assert!(matches!(err, DocumentPatchError::EmptyWebauthnUrl));
    }

    #[test]
    fn without_webauthn_service_removes_entry() {
        let doc = with_webauthn_service(doc_without_service(), "https://x.example.com").unwrap();
        assert!(current_webauthn_service(&doc).is_some());
        let stripped = without_webauthn_service(doc);
        assert!(current_webauthn_service(&stripped).is_none());
        // Service array gone entirely when it's the only entry.
        assert!(stripped.get("service").is_none());
    }

    #[test]
    fn sort_canonical_places_webauthn_after_rest_before_other() {
        // Start with TEE first, then WebAuthn, then REST, then
        // DIDComm — pathological reverse order. The sort should
        // bring DIDComm to front, REST second, WebAuthn third,
        // TEE last.
        let base = doc_without_service();
        let with_d = with_didcomm_service(base, "did:webvh:m").unwrap();
        let with_dr = with_rest_service(with_d, "https://r.example.com").unwrap();
        let mut with_drw =
            with_webauthn_service(with_dr, "https://r.example.com/auth/portal").unwrap();
        // Inject a TEE-shaped entry (mimics what attestation publishing
        // does) so we can verify "other" entries land at the end.
        let services = with_drw
            .get_mut("service")
            .and_then(Value::as_array_mut)
            .unwrap();
        services.insert(
            0,
            json!({
                "id": format!("{}#tee-attestation", vta_did()),
                "type": "TEEAttestation",
                "serviceEndpoint": "https://r.example.com/attestation",
            }),
        );
        sort_services_canonical(&mut with_drw);
        let services = with_drw.get("service").unwrap().as_array().unwrap();
        assert!(id_matches_didcomm(
            services[0].get("id").unwrap().as_str().unwrap()
        ));
        assert!(id_matches_rest(
            services[1].get("id").unwrap().as_str().unwrap()
        ));
        assert!(id_matches_webauthn(
            services[2].get("id").unwrap().as_str().unwrap()
        ));
        // TEE last
        assert_eq!(
            services[3].get("id").unwrap().as_str().unwrap(),
            format!("{}#tee-attestation", vta_did())
        );
    }

    #[test]
    fn id_matches_tsp_is_strict() {
        assert!(id_matches_tsp("did:webvh:foo#tsp"));
        // Nested fragment — reject.
        assert!(!id_matches_tsp("did:webvh:foo#extra#tsp"));
        // Suffix-only collision — reject.
        assert!(!id_matches_tsp("did:webvh:foo-tsp"));
        // The TSP id drops the `vta-` prefix (D9); the `#vta-tsp` shape
        // is not the canonical TSP fragment.
        assert!(!id_matches_tsp("did:webvh:foo#vta-tsp"));
    }

    #[test]
    fn with_tsp_service_inserts_then_replaces() {
        let patched = with_tsp_service(doc_without_service(), "did:webvh:mediator-A").unwrap();
        let svc = current_tsp_service(&patched).expect("tsp entry present");
        assert_eq!(svc.mediator_did, "did:webvh:mediator-A");
        assert_eq!(svc.id, format!("{}#tsp", vta_did()));
        // Endpoint is a plain-string mediator DID (mediator indirection,
        // not a transport URL).
        assert_eq!(
            patched["service"][0]["serviceEndpoint"].as_str().unwrap(),
            "did:webvh:mediator-A"
        );

        // Replace with a new mediator — single entry, no duplication.
        let patched2 = with_tsp_service(patched, "did:webvh:mediator-B").unwrap();
        let svc2 = current_tsp_service(&patched2).unwrap();
        assert_eq!(svc2.mediator_did, "did:webvh:mediator-B");
        let count = patched2["service"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| id_matches_tsp(s.get("id").and_then(Value::as_str).unwrap_or("")))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn with_tsp_service_rejects_empty_mediator() {
        let err = with_tsp_service(doc_without_service(), "").unwrap_err();
        assert!(matches!(err, DocumentPatchError::EmptyMediatorDid));
    }

    #[test]
    fn without_tsp_service_removes_entry() {
        let doc = with_tsp_service(doc_without_service(), "did:webvh:m").unwrap();
        assert!(current_tsp_service(&doc).is_some());
        let stripped = without_tsp_service(doc);
        assert!(current_tsp_service(&stripped).is_none());
        // Service array gone entirely when it's the only entry.
        assert!(stripped.get("service").is_none());
    }

    #[test]
    fn current_tsp_tolerates_object_and_array_endpoints() {
        // `{uri}` object shape.
        let obj_doc = json!({
            "id": vta_did(),
            "service": [{
                "id": format!("{}#tsp", vta_did()),
                "type": TSP_SERVICE_TYPE,
                "serviceEndpoint": { "uri": "did:webvh:mediator-obj" }
            }]
        });
        assert_eq!(
            current_tsp_service(&obj_doc).unwrap().mediator_did,
            "did:webvh:mediator-obj"
        );
    }

    #[test]
    fn sort_canonical_places_tsp_first() {
        // DIDComm + REST already advertised; adding TSP must sort it to
        // the front, ahead of DIDComm and REST (spec §3.3 — TSP is the
        // preferred transport, tsp-enablement.md §11).
        let with_d = with_didcomm_service(doc_without_service(), "did:webvh:m").unwrap();
        let with_dr = with_rest_service(with_d, "https://r.example.com").unwrap();
        let with_drt = with_tsp_service(with_dr, "did:webvh:m").unwrap();
        let services = with_drt.get("service").unwrap().as_array().unwrap();
        assert!(id_matches_tsp(services[0]["id"].as_str().unwrap()));
        assert!(id_matches_didcomm(services[1]["id"].as_str().unwrap()));
        assert!(id_matches_rest(services[2]["id"].as_str().unwrap()));
    }

    fn vta_did() -> &'static str {
        "did:webvh:abc123:vta.example.com:vta-1"
    }

    fn doc_with_didcomm(mediator: &str) -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": vta_did(),
            "verificationMethod": [
                { "id": format!("{}#key-0", vta_did()), "type": "Multikey",
                  "controller": vta_did(), "publicKeyMultibase": "zfoo" },
                { "id": format!("{}#key-1", vta_did()), "type": "Multikey",
                  "controller": vta_did(), "publicKeyMultibase": "zbar" }
            ],
            "authentication": [format!("{}#key-0", vta_did())],
            "assertionMethod": [format!("{}#key-0", vta_did())],
            "keyAgreement": [format!("{}#key-1", vta_did())],
            "service": [{
                "id": format!("{}#vta-didcomm", vta_did()),
                "type": "DIDCommMessaging",
                "serviceEndpoint": [{ "accept": ["didcomm/v2"], "uri": mediator }]
            }]
        })
    }

    fn doc_without_service() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": vta_did(),
            "verificationMethod": [
                { "id": format!("{}#key-0", vta_did()), "type": "Multikey",
                  "controller": vta_did(), "publicKeyMultibase": "zfoo" }
            ],
            "authentication": [format!("{}#key-0", vta_did())],
            "assertionMethod": [format!("{}#key-0", vta_did())]
        })
    }

    fn doc_with_only_tee() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": vta_did(),
            "verificationMethod": [
                { "id": format!("{}#key-0", vta_did()), "type": "Multikey",
                  "controller": vta_did(), "publicKeyMultibase": "zfoo" }
            ],
            "authentication": [format!("{}#key-0", vta_did())],
            "service": [{
                "id": format!("{}#tee-attestation", vta_did()),
                "type": "TeeAttestation",
                "serviceEndpoint": "https://vta.example.com/attestation/report"
            }]
        })
    }

    #[test]
    fn current_finds_didcomm_service() {
        let doc = doc_with_didcomm("did:webvh:mediator-A");
        let svc = current_didcomm_service(&doc).expect("present");
        assert_eq!(svc.id, format!("{}#vta-didcomm", vta_did()));
        assert_eq!(svc.mediator_did, "did:webvh:mediator-A");
    }

    #[test]
    fn current_returns_none_when_absent() {
        assert!(current_didcomm_service(&doc_without_service()).is_none());
        assert!(current_didcomm_service(&doc_with_only_tee()).is_none());
    }

    #[test]
    fn current_tolerates_string_endpoint() {
        let doc = json!({
            "id": vta_did(),
            "service": [{
                "id": format!("{}#vta-didcomm", vta_did()),
                "type": "DIDCommMessaging",
                "serviceEndpoint": "did:webvh:legacy-mediator"
            }]
        });
        let svc = current_didcomm_service(&doc).unwrap();
        assert_eq!(svc.mediator_did, "did:webvh:legacy-mediator");
    }

    #[test]
    fn with_didcomm_replaces_existing_entry() {
        let doc = doc_with_didcomm("did:webvh:mediator-A");
        let patched = with_didcomm_service(doc, "did:webvh:mediator-B").unwrap();
        let svc = current_didcomm_service(&patched).unwrap();
        assert_eq!(svc.mediator_did, "did:webvh:mediator-B");
        // At-most-one invariant: only a single #vta-didcomm entry.
        let count = patched["service"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| {
                s["id"]
                    .as_str()
                    .map(|i| i.ends_with("#vta-didcomm"))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn with_didcomm_inserts_when_missing() {
        let patched = with_didcomm_service(doc_without_service(), "did:webvh:mediator-A").unwrap();
        let svc = current_didcomm_service(&patched).unwrap();
        assert_eq!(svc.mediator_did, "did:webvh:mediator-A");
        assert_eq!(patched["service"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn with_didcomm_preserves_other_services() {
        let patched = with_didcomm_service(doc_with_only_tee(), "did:webvh:mediator-A").unwrap();
        let services = patched["service"].as_array().unwrap();
        assert_eq!(services.len(), 2, "tee + didcomm");
        let tee_present = services
            .iter()
            .any(|s| s["id"].as_str().unwrap().ends_with("#tee-attestation"));
        assert!(tee_present, "TEE attestation service preserved");
    }

    #[test]
    fn with_didcomm_rejects_empty_mediator() {
        let err = with_didcomm_service(doc_without_service(), "").unwrap_err();
        assert!(matches!(err, DocumentPatchError::EmptyMediatorDid));
    }

    #[test]
    fn with_didcomm_rejects_doc_without_id() {
        let bad = json!({ "service": [] });
        let err = with_didcomm_service(bad, "did:webvh:m").unwrap_err();
        assert!(matches!(err, DocumentPatchError::MissingDocumentId));
    }

    #[test]
    fn without_didcomm_removes_only_didcomm_entry() {
        let mut doc = doc_with_didcomm("did:webvh:mediator-A");
        doc["service"].as_array_mut().unwrap().push(json!({
            "id": format!("{}#tee-attestation", vta_did()),
            "type": "TeeAttestation",
            "serviceEndpoint": "https://x"
        }));
        let stripped = without_didcomm_service(doc);
        assert!(current_didcomm_service(&stripped).is_none());
        let services = stripped["service"].as_array().unwrap();
        assert_eq!(services.len(), 1);
        assert!(
            services[0]["id"]
                .as_str()
                .unwrap()
                .ends_with("#tee-attestation")
        );
    }

    #[test]
    fn without_didcomm_drops_empty_service_array() {
        let doc = doc_with_didcomm("did:webvh:mediator-A");
        let stripped = without_didcomm_service(doc);
        assert!(
            stripped.get("service").is_none(),
            "service array removed when last entry was the DIDComm one"
        );
    }

    #[test]
    fn without_didcomm_is_noop_when_absent() {
        let original = doc_with_only_tee();
        let stripped = without_didcomm_service(original.clone());
        assert_eq!(stripped, original);
    }

    #[test]
    fn without_didcomm_handles_no_service_field() {
        let original = doc_without_service();
        let stripped = without_didcomm_service(original.clone());
        assert_eq!(stripped, original);
    }

    #[test]
    fn round_trip_with_then_without_returns_original() {
        let original = doc_without_service();
        let with_d = with_didcomm_service(original.clone(), "did:webvh:m").unwrap();
        let back = without_didcomm_service(with_d);
        assert_eq!(back, original, "round-trip with→without is identity");
    }

    #[test]
    fn verification_method_byte_identical_after_replace() {
        // The spec's load-bearing invariant: verificationMethod is never
        // touched by these helpers. Foreshadows criterion #10.
        let original = doc_with_didcomm("did:webvh:mediator-A");
        let original_vm = original["verificationMethod"].clone();
        let original_auth = original["authentication"].clone();
        let original_ka = original["keyAgreement"].clone();
        let original_assertion = original["assertionMethod"].clone();

        let patched = with_didcomm_service(original, "did:webvh:mediator-B").unwrap();
        assert_eq!(patched["verificationMethod"], original_vm);
        assert_eq!(patched["authentication"], original_auth);
        assert_eq!(patched["keyAgreement"], original_ka);
        assert_eq!(patched["assertionMethod"], original_assertion);
    }

    #[test]
    fn verification_method_byte_identical_after_remove() {
        let original = doc_with_didcomm("did:webvh:mediator-A");
        let original_vm = original["verificationMethod"].clone();
        let original_auth = original["authentication"].clone();
        let original_ka = original["keyAgreement"].clone();
        let original_assertion = original["assertionMethod"].clone();

        let stripped = without_didcomm_service(original);
        assert_eq!(stripped["verificationMethod"], original_vm);
        assert_eq!(stripped["authentication"], original_auth);
        assert_eq!(stripped["keyAgreement"], original_ka);
        assert_eq!(stripped["assertionMethod"], original_assertion);
    }

    // ── REST service-entry patcher tests ──────────────────────────

    fn doc_with_rest(url: &str) -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": vta_did(),
            "verificationMethod": [
                { "id": format!("{}#key-0", vta_did()), "type": "Multikey",
                  "controller": vta_did(), "publicKeyMultibase": "zfoo" }
            ],
            "authentication": [format!("{}#key-0", vta_did())],
            "assertionMethod": [format!("{}#key-0", vta_did())],
            "service": [{
                "id": format!("{}#vta-rest", vta_did()),
                "type": "VTARest",
                "serviceEndpoint": url,
            }]
        })
    }

    #[test]
    fn current_finds_rest_service() {
        let doc = doc_with_rest("https://vta.example.com");
        let svc = current_rest_service(&doc).expect("present");
        assert_eq!(svc.id, format!("{}#vta-rest", vta_did()));
        assert_eq!(svc.url, "https://vta.example.com");
    }

    #[test]
    fn current_rest_returns_none_when_absent() {
        assert!(current_rest_service(&doc_without_service()).is_none());
        assert!(current_rest_service(&doc_with_only_tee()).is_none());
        assert!(current_rest_service(&doc_with_didcomm("did:webvh:m")).is_none());
    }

    /// `serviceEndpoint` may be a plain string (current
    /// convention), an object with `uri`, or a one-element array
    /// of either. The reader accepts all three shapes — operators
    /// who paste DID-Core-compliant object endpoints are handled
    /// the same as those who use the workspace's plain-string
    /// convention.
    #[test]
    fn current_rest_tolerates_object_and_array_endpoints() {
        let object_endpoint = json!({
            "id": vta_did(),
            "service": [{
                "id": format!("{}#vta-rest", vta_did()),
                "type": "VTARest",
                "serviceEndpoint": { "uri": "https://obj.example.com" }
            }]
        });
        assert_eq!(
            current_rest_service(&object_endpoint).unwrap().url,
            "https://obj.example.com",
        );

        let array_endpoint = json!({
            "id": vta_did(),
            "service": [{
                "id": format!("{}#vta-rest", vta_did()),
                "type": "VTARest",
                "serviceEndpoint": ["https://arr.example.com"]
            }]
        });
        assert_eq!(
            current_rest_service(&array_endpoint).unwrap().url,
            "https://arr.example.com",
        );
    }

    #[test]
    fn with_rest_replaces_existing_entry() {
        let doc = doc_with_rest("https://old.example.com");
        let patched = with_rest_service(doc, "https://new.example.com").unwrap();
        let svc = current_rest_service(&patched).unwrap();
        assert_eq!(svc.url, "https://new.example.com");
        // At-most-one invariant.
        let count = patched["service"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| {
                s["id"]
                    .as_str()
                    .map(|i| i.ends_with("#vta-rest"))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn with_rest_inserts_when_missing() {
        let patched = with_rest_service(doc_without_service(), "https://x.example.com").unwrap();
        let svc = current_rest_service(&patched).unwrap();
        assert_eq!(svc.url, "https://x.example.com");
        assert_eq!(patched["service"].as_array().unwrap().len(), 1);
    }

    /// Wire shape preservation — the SDK depends on `type: "VTARest"`
    /// (plain string) and `serviceEndpoint: "<url>"` (plain string).
    /// Pin both.
    #[test]
    fn with_rest_emits_canonical_wire_shape() {
        let patched = with_rest_service(doc_without_service(), "https://vta.example.com").unwrap();
        let entry = &patched["service"].as_array().unwrap()[0];
        assert_eq!(entry["type"], "VTARest");
        assert_eq!(entry["serviceEndpoint"], "https://vta.example.com");
        assert!(
            entry["serviceEndpoint"].is_string(),
            "serviceEndpoint must be a plain string per session.rs:1100",
        );
    }

    #[test]
    fn with_rest_preserves_didcomm_and_tee_entries() {
        let mut doc = doc_with_didcomm("did:webvh:mediator-A");
        doc["service"].as_array_mut().unwrap().push(json!({
            "id": format!("{}#tee-attestation", vta_did()),
            "type": "TeeAttestation",
            "serviceEndpoint": "https://x"
        }));
        let patched = with_rest_service(doc, "https://vta.example.com").unwrap();
        let services = patched["service"].as_array().unwrap();
        assert_eq!(services.len(), 3, "didcomm + tee + rest");
        let didcomm_present = current_didcomm_service(&patched).is_some();
        let rest_present = current_rest_service(&patched).is_some();
        let tee_present = services
            .iter()
            .any(|s| s["id"].as_str().unwrap().ends_with("#tee-attestation"));
        assert!(didcomm_present && rest_present && tee_present);
    }

    #[test]
    fn with_rest_rejects_empty_url() {
        let err = with_rest_service(doc_without_service(), "").unwrap_err();
        assert!(matches!(err, DocumentPatchError::EmptyRestUrl));
    }

    #[test]
    fn with_rest_rejects_doc_without_id() {
        let bad = json!({ "service": [] });
        let err = with_rest_service(bad, "https://x").unwrap_err();
        assert!(matches!(err, DocumentPatchError::MissingDocumentId));
    }

    #[test]
    fn without_rest_removes_only_rest_entry() {
        let mut doc = doc_with_rest("https://x.example.com");
        // Add a didcomm + tee entry so we can verify they survive.
        doc["service"].as_array_mut().unwrap().push(json!({
            "id": format!("{}#vta-didcomm", vta_did()),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{ "accept": ["didcomm/v2"], "uri": "did:webvh:m" }]
        }));
        doc["service"].as_array_mut().unwrap().push(json!({
            "id": format!("{}#tee-attestation", vta_did()),
            "type": "TeeAttestation",
            "serviceEndpoint": "https://x"
        }));

        let stripped = without_rest_service(doc);
        assert!(current_rest_service(&stripped).is_none());
        assert!(current_didcomm_service(&stripped).is_some());
        let tee_present = stripped["service"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"].as_str().unwrap().ends_with("#tee-attestation"));
        assert!(tee_present);
    }

    #[test]
    fn without_rest_drops_empty_service_array() {
        let doc = doc_with_rest("https://x.example.com");
        let stripped = without_rest_service(doc);
        assert!(stripped.get("service").is_none());
    }

    #[test]
    fn without_rest_is_noop_when_absent() {
        let original = doc_with_didcomm("did:webvh:m");
        let stripped = without_rest_service(original.clone());
        assert_eq!(stripped, original);
    }

    /// REST and DIDComm patchers compose in either order — round
    /// tripping with→without on one kind doesn't disturb the other.
    #[test]
    fn rest_and_didcomm_patchers_compose() {
        let base = doc_without_service();
        let with_d = with_didcomm_service(base.clone(), "did:webvh:m").unwrap();
        let with_both = with_rest_service(with_d, "https://x.example.com").unwrap();

        assert!(current_didcomm_service(&with_both).is_some());
        assert!(current_rest_service(&with_both).is_some());

        let only_didcomm = without_rest_service(with_both.clone());
        assert!(current_didcomm_service(&only_didcomm).is_some());
        assert!(current_rest_service(&only_didcomm).is_none());

        let only_rest = without_didcomm_service(with_both);
        assert!(current_didcomm_service(&only_rest).is_none());
        assert!(current_rest_service(&only_rest).is_some());
    }

    /// `verificationMethod` byte-identical across REST patcher
    /// operations — same load-bearing invariant as the DIDComm
    /// side.
    #[test]
    fn verification_method_byte_identical_after_rest_patches() {
        let original = doc_with_rest("https://old.example.com");
        let original_vm = original["verificationMethod"].clone();
        let original_auth = original["authentication"].clone();

        let patched = with_rest_service(original.clone(), "https://new.example.com").unwrap();
        assert_eq!(patched["verificationMethod"], original_vm);
        assert_eq!(patched["authentication"], original_auth);

        let stripped = without_rest_service(original);
        assert_eq!(stripped["verificationMethod"], original_vm);
        assert_eq!(stripped["authentication"], original_auth);
    }

    // ── Canonical ordering tests (T2.4) ───────────────────────────
    //
    // Spec §3.3: when both transports are advertised, DIDComm must
    // come before REST so DID-Core resolvers walking the array pick
    // DIDComm first. The `with_*_service` patchers funnel through
    // `sort_services_canonical` to enforce this regardless of the
    // pre-mutation array order.

    fn id_at(doc: &Value, idx: usize) -> &str {
        doc["service"][idx]["id"].as_str().unwrap()
    }

    /// Adding REST to a doc that already has DIDComm preserves the
    /// invariant: DIDComm at index 0, REST at index 1.
    #[test]
    fn ordering_didcomm_then_rest_when_didcomm_was_first() {
        let base = doc_with_didcomm("did:webvh:m");
        let with_both = with_rest_service(base, "https://x.example.com").unwrap();
        assert!(id_at(&with_both, 0).ends_with("#vta-didcomm"));
        assert!(id_at(&with_both, 1).ends_with("#vta-rest"));
    }

    /// Adding DIDComm to a REST-only doc reorders so DIDComm is at
    /// index 0 — without canonical sort the patcher's push-to-end
    /// would put DIDComm second.
    #[test]
    fn ordering_didcomm_first_when_rest_was_first() {
        let base = doc_with_rest("https://x.example.com");
        let with_both = with_didcomm_service(base, "did:webvh:m").unwrap();
        assert!(
            id_at(&with_both, 0).ends_with("#vta-didcomm"),
            "DIDComm must be first per spec §3.3, got: {}",
            id_at(&with_both, 0),
        );
        assert!(id_at(&with_both, 1).ends_with("#vta-rest"));
    }

    /// TEE / other entries land after REST — they're not transports
    /// so the §3.3 invariant doesn't constrain their position
    /// relative to each other, but DIDComm + REST must come first.
    #[test]
    fn ordering_didcomm_rest_then_tee() {
        let mut base = doc_with_didcomm("did:webvh:m");
        // Insert TEE BEFORE adding REST — the canonical sort must
        // still place REST before TEE since REST is a transport.
        base["service"].as_array_mut().unwrap().push(json!({
            "id": format!("{}#tee-attestation", vta_did()),
            "type": "TeeAttestation",
            "serviceEndpoint": "https://x"
        }));
        let with_rest = with_rest_service(base, "https://x.example.com").unwrap();
        let services = with_rest["service"].as_array().unwrap();
        assert_eq!(services.len(), 3);
        assert!(id_at(&with_rest, 0).ends_with("#vta-didcomm"));
        assert!(id_at(&with_rest, 1).ends_with("#vta-rest"));
        assert!(id_at(&with_rest, 2).ends_with("#tee-attestation"));
    }

    /// `sort_services_canonical` is idempotent — applying it twice
    /// yields the same array.
    #[test]
    fn sort_services_canonical_is_idempotent() {
        let mut doc = doc_with_rest("https://x.example.com");
        doc["service"].as_array_mut().unwrap().push(json!({
            "id": format!("{}#vta-didcomm", vta_did()),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{ "accept": ["didcomm/v2"], "uri": "did:webvh:m" }]
        }));
        sort_services_canonical(&mut doc);
        let after_first = doc.clone();
        sort_services_canonical(&mut doc);
        assert_eq!(doc, after_first);
    }

    /// `sort_services_canonical` is a no-op on a doc with no
    /// `service` field (used by integration tests that strip the
    /// field for non-transport DIDs).
    #[test]
    fn sort_services_canonical_handles_missing_service_field() {
        let mut doc = doc_without_service();
        let original = doc.clone();
        sort_services_canonical(&mut doc);
        assert_eq!(doc, original);
    }
}
