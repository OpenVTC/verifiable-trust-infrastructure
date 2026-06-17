//! DIDComm protocol for `provision-integration`.
//!
//! Carries a VP-framed [`crate::provision_integration::BootstrapRequest`]
//! to the VTA in an authcrypt'd DIDComm message; receives the sealed
//! `TemplateBootstrap` bundle back in an authcrypt'd reply.
//!
//! Auth model: DIDComm authcrypt is the auth — the VTA reads `from`
//! as the authenticated sender DID and ACL-checks it (must hold admin
//! role in the target context). The VP's `DataIntegrityProof` is the
//! second proof; both must agree (`from == VP holder`) for the
//! handler to proceed.
//!
//! Both parties exchange the same on-the-wire shapes the REST endpoint
//! at `POST /bootstrap/provision-integration` does — wire format is
//! transport-neutral. See
//! [`crate::provision_integration::http::ProvisionIntegrationRequest`]
//! and [`crate::provision_integration::http::ProvisionIntegrationResponse`].
//!
//! Two canonical Trust Task URI versions are accepted on the wire, both
//! routed to the same handler:
//!
//! * [`CANONICAL_PROVISION_INTEGRATION`] — `provision/integration/0.1`,
//!   landed in `dtgwg-trust-tasks-tf` PR #51.
//! * [`CANONICAL_PROVISION_INTEGRATION_0_2`] —
//!   `provision/integration/0.2`. Same VP/bundle wire body; the 0.2 delta
//!   is camelCase enum casing (e.g. the VP's `ask.type`), which the typed
//!   verifier accommodates by checking the proof over the bytes as
//!   received — see
//!   [`crate::provision_integration::BootstrapRequest::verify_value`].
//!
//! The handler emits the response under whichever version the request
//! came in with — a 0.1 request gets the `0.1#response` URI, a 0.2 request
//! the `0.2#response` URI — so both clients work without either knowing
//! about the other.
//!
//! The legacy `firstperson.network` provision-integration URI was retired
//! once consumers (the browser plugin, the Rust CLIs) moved to the
//! canonical registry. The other `firstperson.network` management
//! protocols are unaffected.

/// Inbound VP + provisioning options — canonical Trust Task URI, v0.1.
pub const CANONICAL_PROVISION_INTEGRATION: &str =
    "https://trusttasks.org/spec/provision/integration/0.1";

/// Outbound sealed bundle + summary — canonical Trust Task URI, v0.1.
/// Per SPEC.md §4.4.1 of `dtgwg-trust-tasks-tf`, success responses are
/// emitted under the request URI with a `#response` fragment.
pub const CANONICAL_PROVISION_INTEGRATION_RESULT: &str =
    "https://trusttasks.org/spec/provision/integration/0.1#response";

/// Inbound VP + provisioning options — canonical Trust Task URI, v0.2.
/// Same wire body as v0.1; the 0.2 spec uses camelCase enum casing
/// (notably the signed VP's `ask.type`). Verification runs over the
/// as-received bytes so the holder's casing survives.
pub const CANONICAL_PROVISION_INTEGRATION_0_2: &str =
    "https://trusttasks.org/spec/provision/integration/0.2";

/// Outbound sealed bundle + summary — canonical Trust Task URI, v0.2.
pub const CANONICAL_PROVISION_INTEGRATION_0_2_RESULT: &str =
    "https://trusttasks.org/spec/provision/integration/0.2#response";

/// Match the result URI to whichever request URI the caller used.
/// Centralised here so the routing decision lives next to the URI
/// constants — handlers downstream just call this. The 0.2 request URI
/// maps to the 0.2 `#response`; the 0.1 request URI (the only other shape
/// the router advertises) maps to the 0.1 `#response`.
pub fn result_uri_for(request_uri: &str) -> &'static str {
    if request_uri == CANONICAL_PROVISION_INTEGRATION_0_2 {
        CANONICAL_PROVISION_INTEGRATION_0_2_RESULT
    } else {
        CANONICAL_PROVISION_INTEGRATION_RESULT
    }
}

pub mod request {
    //! Body shape for the inbound DIDComm message.
    //!
    //! Equivalent to [`crate::provision_integration::http::ProvisionIntegrationRequest`]
    //! — same field semantics, same JSON layout.
    pub use crate::provision_integration::http::{AssertionMode, ProvisionIntegrationRequest};
}

pub mod result {
    //! Body shape for the reply DIDComm message.
    //!
    //! Equivalent to [`crate::provision_integration::http::ProvisionIntegrationResponse`].
    pub use crate::provision_integration::http::{ProvisionIntegrationResponse, ProvisionSummary};
}

use serde_json::Value;

use crate::provision_integration::http::{
    ProvisionIntegrationRequest, ProvisionIntegrationResponse,
};

/// Which casing convention a provision-integration body is emitted under. The
/// 0.1 wire form is snake_case fields + kebab-case `assertion`; the 0.2 form is
/// lowerCamelCase throughout, per `dtgwg-trust-tasks-tf`'s
/// `provision/integration/0.2` schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionSpecVersion {
    V0_1,
    V0_2,
}

impl ProvisionSpecVersion {
    /// The canonical request URI to address this version at.
    pub fn request_uri(self) -> &'static str {
        match self {
            ProvisionSpecVersion::V0_1 => CANONICAL_PROVISION_INTEGRATION,
            ProvisionSpecVersion::V0_2 => CANONICAL_PROVISION_INTEGRATION_0_2,
        }
    }
}

fn is_v0_2(request_uri: &str) -> bool {
    request_uri == CANONICAL_PROVISION_INTEGRATION_0_2
}

/// `foo_bar_baz` → `fooBarBaz`. A single-word key is returned unchanged.
fn snake_to_lower_camel(key: &str) -> String {
    delimited_to_lower_camel(key, '_')
}

/// `did-signed` → `didSigned`. A single-word value is returned unchanged.
fn kebab_to_lower_camel(value: &str) -> String {
    delimited_to_lower_camel(value, '-')
}

fn delimited_to_lower_camel(s: &str, delim: char) -> String {
    let mut parts = s.split(delim);
    let mut out = String::with_capacity(s.len());
    if let Some(first) = parts.next() {
        out.push_str(first);
    }
    for p in parts {
        let mut chars = p.chars();
        if let Some(f) = chars.next() {
            out.extend(f.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out
}

/// Rewrite the keys of an object in place via `snake_to_lower_camel`, leaving
/// the values untouched. Shallow on purpose: the caller decides which subtrees
/// (e.g. the signed VP) must stay byte-identical.
fn recase_object_keys_shallow(map: &mut serde_json::Map<String, Value>) {
    let renamed: Vec<(String, Value)> = std::mem::take(map)
        .into_iter()
        .map(|(k, v)| (snake_to_lower_camel(&k), v))
        .collect();
    map.extend(renamed);
}

/// Serialise a provision-integration **request** body in the casing
/// `request_uri` implies. For 0.2 the optional fields are camelCased
/// (`vc_validity_seconds` → `vcValiditySeconds`, `create_context` →
/// `createContext`) and the `assertion` value is camelCased (`did-signed` →
/// `didSigned`).
///
/// The signed `request` VP subtree is **never** touched — it carries the
/// holder's `DataIntegrityProof` over its exact bytes, and a 0.2 holder already
/// signs camelCase casing inside it (see [`crate::provision_integration::request`]).
pub fn request_body_for_version(
    req: &ProvisionIntegrationRequest,
    request_uri: &str,
) -> Result<Value, serde_json::Error> {
    let mut v = serde_json::to_value(req)?;
    if is_v0_2(request_uri)
        && let Value::Object(map) = &mut v
    {
        // `request` (the signed VP) has no underscore, so the shallow rename
        // leaves both its key and value intact.
        recase_object_keys_shallow(map);
        if let Some(Value::String(a)) = map.get_mut("assertion") {
            *a = kebab_to_lower_camel(a);
        }
    }
    Ok(v)
}

/// Serialise a provision-integration **response** body in the casing
/// `request_uri` implies. For 0.2 the `summary` object's keys are camelCased
/// (`client_did` → `clientDid`, `bundle_id_hex` → `bundleIdHex`, …). The
/// top-level `bundle`/`digest` are opaque single-word fields and unchanged.
pub fn response_body_for_version(
    resp: &ProvisionIntegrationResponse,
    request_uri: &str,
) -> Result<Value, serde_json::Error> {
    let mut v = serde_json::to_value(resp)?;
    if is_v0_2(request_uri)
        && let Some(Value::Object(summary)) = v.get_mut("summary")
    {
        recase_object_keys_shallow(summary);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_uri_for_v0_1_request_emits_v0_1_response() {
        assert_eq!(
            result_uri_for(CANONICAL_PROVISION_INTEGRATION),
            CANONICAL_PROVISION_INTEGRATION_RESULT
        );
    }

    #[test]
    fn result_uri_for_v0_2_request_emits_v0_2_response() {
        assert_eq!(
            result_uri_for(CANONICAL_PROVISION_INTEGRATION_0_2),
            CANONICAL_PROVISION_INTEGRATION_0_2_RESULT
        );
    }

    /// Unknown / future URIs default to the 0.1 result URI. The router
    /// only advertises the 0.1 and 0.2 URIs, so this branch is unreachable
    /// in production — but exercising it pins the fallback so a future
    /// widening doesn't silently change the default response shape.
    #[test]
    fn result_uri_for_unknown_request_defaults_to_v0_1() {
        assert_eq!(
            result_uri_for("https://example.invalid/something-else"),
            CANONICAL_PROVISION_INTEGRATION_RESULT
        );
    }

    /// The canonical Trust Task URIs MUST be exactly the values declared
    /// in `dtgwg-trust-tasks-tf`'s `payload.schema.json` `$id`. Pin the
    /// strings so a refactor here can't drift away from the registry.
    #[test]
    fn canonical_uris_match_registry() {
        assert_eq!(
            CANONICAL_PROVISION_INTEGRATION,
            "https://trusttasks.org/spec/provision/integration/0.1"
        );
        assert_eq!(
            CANONICAL_PROVISION_INTEGRATION_RESULT,
            "https://trusttasks.org/spec/provision/integration/0.1#response"
        );
        assert_eq!(
            CANONICAL_PROVISION_INTEGRATION_0_2,
            "https://trusttasks.org/spec/provision/integration/0.2"
        );
        assert_eq!(
            CANONICAL_PROVISION_INTEGRATION_0_2_RESULT,
            "https://trusttasks.org/spec/provision/integration/0.2#response"
        );
    }

    #[test]
    fn snake_and_kebab_to_lower_camel() {
        assert_eq!(snake_to_lower_camel("client_did"), "clientDid");
        assert_eq!(snake_to_lower_camel("bundle_id_hex"), "bundleIdHex");
        assert_eq!(
            snake_to_lower_camel("vc_validity_seconds"),
            "vcValiditySeconds"
        );
        assert_eq!(snake_to_lower_camel("bundle"), "bundle"); // single word
        assert_eq!(kebab_to_lower_camel("did-signed"), "didSigned");
        assert_eq!(kebab_to_lower_camel("pinned-only"), "pinnedOnly");
    }

    /// Build a real VP-framed request so the `request` subtree carries a
    /// genuine `DataIntegrityProof` — the casing helpers must leave it intact.
    async fn sample_request(
        assertion: Option<crate::provision_integration::http::AssertionMode>,
        vc_validity_seconds: Option<i64>,
        create_context: bool,
    ) -> (ProvisionIntegrationRequest, Value) {
        use crate::provision_integration::ProvisionRequestBuilder;
        let (seed, pub_bytes) = crate::sealed_transfer::generate_ed25519_keypair();
        let client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
        let vp = ProvisionRequestBuilder::new("didcomm-mediator")
            .sign_with(&seed, &client_did)
            .await
            .expect("sign VP");
        let vp_value = serde_json::to_value(&vp).expect("serialize VP");
        let req = ProvisionIntegrationRequest {
            request: vp,
            context: Some("ctx".into()),
            assertion,
            vc_validity_seconds,
            create_context,
        };
        (req, vp_value)
    }

    #[tokio::test]
    async fn request_body_v0_1_stays_snake_case_and_kebab_assertion() {
        let (req, _) = sample_request(
            Some(crate::provision_integration::http::AssertionMode::DidSigned),
            Some(3600),
            true,
        )
        .await;
        let v = request_body_for_version(&req, CANONICAL_PROVISION_INTEGRATION).unwrap();
        assert_eq!(v["assertion"], "did-signed");
        assert_eq!(v["vc_validity_seconds"], 3600);
        assert_eq!(v["create_context"], true);
        assert!(v.get("vcValiditySeconds").is_none());
    }

    #[tokio::test]
    async fn request_body_v0_2_camelizes_opts_and_assertion_but_not_signed_vp() {
        let (req, vp_value) = sample_request(
            Some(crate::provision_integration::http::AssertionMode::PinnedOnly),
            Some(60),
            false,
        )
        .await;
        let v = request_body_for_version(&req, CANONICAL_PROVISION_INTEGRATION_0_2).unwrap();
        // Opt keys + assertion value camelized.
        assert_eq!(v["assertion"], "pinnedOnly");
        assert_eq!(v["vcValiditySeconds"], 60);
        assert!(v.get("vc_validity_seconds").is_none());
        // `create_context: false` is skipped on the wire (is_false) — absent.
        assert!(v.get("createContext").is_none());
        assert!(v.get("create_context").is_none());
        // Single-word keys unchanged.
        assert_eq!(v["context"], "ctx");
        // The signed VP subtree is byte-identical — the proof still covers it.
        assert_eq!(v["request"], vp_value);
    }

    #[test]
    fn response_body_v0_1_stays_snake_case_v0_2_camelizes_summary() {
        let resp = ProvisionIntegrationResponse {
            bundle: "armored".into(),
            digest: "deadbeef".into(),
            summary: crate::provision_integration::http::ProvisionSummary {
                client_did: "did:key:zClient".into(),
                admin_did: "did:key:zAdmin".into(),
                admin_rolled_over: true,
                integration_did: Some("did:webvh:x".into()),
                template_name: Some("tmpl".into()),
                template_kind: Some("kind".into()),
                admin_template_name: None,
                bundle_id_hex: "abc".into(),
                secret_count: 2,
                output_count: 1,
                webvh_server_id: None,
                context_created: true,
            },
        };
        // 0.1 — snake_case preserved.
        let v01 = response_body_for_version(&resp, CANONICAL_PROVISION_INTEGRATION).unwrap();
        assert_eq!(v01["summary"]["client_did"], "did:key:zClient");
        assert_eq!(v01["summary"]["bundle_id_hex"], "abc");
        assert!(v01["summary"].get("clientDid").is_none());
        // 0.2 — summary keys camelized; values and opaque bundle/digest intact.
        let v02 = response_body_for_version(&resp, CANONICAL_PROVISION_INTEGRATION_0_2).unwrap();
        assert_eq!(v02["summary"]["clientDid"], "did:key:zClient");
        assert_eq!(v02["summary"]["bundleIdHex"], "abc");
        assert_eq!(v02["summary"]["secretCount"], 2);
        assert_eq!(v02["summary"]["adminRolledOver"], true);
        assert_eq!(v02["summary"]["contextCreated"], true);
        assert!(v02["summary"].get("client_did").is_none());
        assert_eq!(v02["bundle"], "armored");
        assert_eq!(v02["digest"], "deadbeef");
    }
}
