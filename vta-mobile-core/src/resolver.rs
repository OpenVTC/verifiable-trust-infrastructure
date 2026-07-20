//! DID resolution — wraps `affinidi-did-resolver-cache-sdk`.
//!
//! **Slice 3a.** The engine's first *async* export, proving the async-over-FFI
//! path (`#[uniffi::export(async_runtime = "tokio")]`). `did:key` / `did:peer`
//! resolve offline; `did:web` / `did:webvh` resolve over the network (the SDK's
//! default config handles all four — the same way the VTA reads service docs).
//! [`resolve_vta_endpoints`] uses this to discover a VTA's REST + mediator
//! endpoints from its DID alone.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use tokio::sync::OnceCell;

use crate::error::FfiError;
use vta_sdk::protocol::matching::{DIDCOMM_SERVICE_TYPE, REST_SERVICE_TYPES};

/// One process-wide caching resolver, lazily initialised on first use. The
/// resolver caches immutable methods (key/peer) indefinitely, so repeated
/// lookups stay cheap.
static CLIENT: OnceCell<DIDCacheClient> = OnceCell::const_new();

async fn client() -> Result<&'static DIDCacheClient, FfiError> {
    CLIENT
        .get_or_try_init(|| async {
            DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .map_err(|e| FfiError::InvalidInput {
                    reason: format!("DID resolver init failed: {e}"),
                })
        })
        .await
}

/// Resolve a DID to its DID Document, returned as JSON.
///
/// Used to find a peer's verification keys (to verify a relying party's step-up
/// proof) and key-agreement key (for DIDComm). `did:key` / `did:peer` resolve
/// locally; `did:web` / `did:webvh` resolve over the network. The first async
/// function exported across the FFI boundary.
#[uniffi::export(async_runtime = "tokio")]
pub async fn resolve_did(did: String) -> Result<String, FfiError> {
    let response = client()
        .await?
        .resolve(&did)
        .await
        .map_err(|e| FfiError::InvalidInput {
            reason: format!("could not resolve {did}: {e}"),
        })?;
    serde_json::to_string(&response.doc).map_err(|e| FfiError::InvalidInput {
        reason: format!("could not serialize DID document: {e}"),
    })
}

/// The VTA's transport endpoints, discovered from its DID document — so a client
/// can be configured with just the **VTA DID** instead of a hand-typed URL +
/// mediator.
#[derive(Debug, Clone, uniffi::Record)]
pub struct VtaEndpoints {
    /// REST base URL, from a REST service entry (`VTARest` for a VTA,
    /// `TRQPRest` for a Trust Registry), matched by `type`. `None` if the
    /// VTA advertises no REST service.
    pub rest_base_url: Option<String>,
    /// Mediator DID, from the `#vta-didcomm` (`DIDCommMessaging`) service's
    /// endpoint `uri`. `None` if the VTA advertises no DIDComm service.
    pub mediator_did: Option<String>,
}

/// Resolve a VTA's DID and extract its transport endpoints (`#vta-rest` URL +
/// `#vta-didcomm` mediator DID). The app uses this to auto-fill the connection
/// from the DID alone. Resolves `did:key`/`did:peer` offline and `did:webvh`/
/// `did:web` over the network (same resolver the VTA uses to read service docs).
#[uniffi::export(async_runtime = "tokio")]
pub async fn resolve_vta_endpoints(did: String) -> Result<VtaEndpoints, FfiError> {
    let doc_json = resolve_did(did).await?;
    let doc: serde_json::Value = serde_json::from_str(&doc_json).map_err(|e| FfiError::Decode {
        reason: format!("DID document is not valid JSON: {e}"),
    })?;
    Ok(parse_vta_endpoints(&doc))
}

/// Extract the VTA endpoints from a resolved DID document. Matches the VTA's own
/// service shapes: `#vta-rest` (type `VTARest`) → REST URL; `#vta-didcomm`
/// (type `DIDCommMessaging`) → mediator DID. Pure (no I/O) so it's unit-testable.
fn parse_vta_endpoints(doc: &serde_json::Value) -> VtaEndpoints {
    let mut rest_base_url = None;
    let mut mediator_did = None;
    if let Some(services) = doc.get("service").and_then(|s| s.as_array()) {
        for svc in services {
            let ty = svc.get("type").and_then(|v| v.as_str()).unwrap_or_default();
            let endpoint = svc.get("serviceEndpoint");
            // Match on `type` only. The `#id` fragment is an arbitrary label
            // (R4.4): the OWF reference TSP implementation names its id
            // `#tsp-transport` where Affinidi uses `#tsp`, for the same type,
            // and a Trust Registry uses `#rest` for a `TRQPRest` service. A
            // fragment check both misses valid services and can match the
            // wrong one — a `#vta-rest`-fragmented DIDComm entry would have
            // been read as REST here.
            if REST_SERVICE_TYPES.contains(&ty) {
                rest_base_url = endpoint_uri(endpoint);
            } else if ty == DIDCOMM_SERVICE_TYPE {
                mediator_did = endpoint_uri(endpoint);
            }
        }
    }
    VtaEndpoints {
        rest_base_url,
        mediator_did,
    }
}

/// Pull a URI out of a `serviceEndpoint` value, which may be a bare string, an
/// object with a `uri` field, or a single-element array of either (the shapes
/// the VTA's own `document.rs` accepts).
fn endpoint_uri(endpoint: Option<&serde_json::Value>) -> Option<String> {
    match endpoint? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => o.get("uri").and_then(|v| v.as_str()).map(String::from),
        serde_json::Value::Array(a) => a.first().and_then(|v| endpoint_uri(Some(v))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test (one runtime) — the process-wide resolver is initialised and
    // used within the same runtime, avoiding cross-runtime handle issues.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolves_did_key_locally_and_rejects_garbage() {
        let did = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
        let json = resolve_did(did.to_string())
            .await
            .expect("did:key resolves locally");
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(doc["id"], did);
        assert!(
            doc.get("verificationMethod").is_some(),
            "did:key document exposes a verificationMethod"
        );

        let err = resolve_did("not-a-did".to_string())
            .await
            .expect_err("a non-DID must fail");
        assert!(matches!(err, FfiError::InvalidInput { .. }));
    }

    #[test]
    fn parses_vta_endpoints_from_a_did_document() {
        // REST as a bare string; DIDComm as an object with `uri` + routingKeys —
        // the two shapes the VTA emits.
        let doc = serde_json::json!({
            "id": "did:webvh:scid:vta.example:vta",
            "service": [
                { "id": "did:webvh:scid:vta.example:vta#vta-rest",
                  "type": "VTARest",
                  "serviceEndpoint": "https://vta.example/api" },
                { "id": "did:webvh:scid:vta.example:vta#vta-didcomm",
                  "type": "DIDCommMessaging",
                  "serviceEndpoint": { "uri": "did:webvh:scid:m.example:mediator",
                                       "routingKeys": [] } }
            ]
        });
        let ep = parse_vta_endpoints(&doc);
        assert_eq!(ep.rest_base_url.as_deref(), Some("https://vta.example/api"));
        assert_eq!(
            ep.mediator_did.as_deref(),
            Some("did:webvh:scid:m.example:mediator")
        );
    }

    #[test]
    fn parses_vta_endpoints_tolerates_array_endpoint_and_missing_services() {
        // REST endpoint as a single-element array (a shape the SDK accepts).
        let doc = serde_json::json!({
            "id": "did:web:vta.example",
            "service": [
                { "id": "did:web:vta.example#vta-rest", "type": "VTARest",
                  "serviceEndpoint": ["https://vta.example/api"] }
            ]
        });
        let ep = parse_vta_endpoints(&doc);
        assert_eq!(ep.rest_base_url.as_deref(), Some("https://vta.example/api"));
        assert_eq!(ep.mediator_did, None);

        // No services at all → both None, no panic.
        let empty = parse_vta_endpoints(&serde_json::json!({ "id": "did:key:z6Mk" }));
        assert_eq!(empty.rest_base_url, None);
        assert_eq!(empty.mediator_did, None);
    }

    /// Live network resolution of a real `did:webvh` — proves the engine's
    /// resolver handles webvh (not just local methods). Ignored by default so
    /// the offline suite stays green; run explicitly:
    /// `cargo test -p vta-mobile-core -- --ignored resolves_webvh`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "network: resolves a live did:webvh"]
    async fn resolves_webvh_over_the_network() {
        let did =
            "did:webvh:QmTS3a3H9Dk4ZMPAZ8jNWGeyPbuKrPbrPZcSbg8CJ6yynD:webvh.storm.ws:mediator";
        let json = resolve_did(did.to_string())
            .await
            .expect("did:webvh resolves over the network");
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(doc["id"], did);
        assert!(
            doc.get("service").is_some(),
            "the mediator's webvh doc advertises a service"
        );
    }
}
