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

/// Inbound VP + provisioning options — canonical Trust Task URI, v0.3.
///
/// The DIDComm surface follows the Trust-Task one onto 0.3, and for the same
/// reason: the response carries `digestMultibase` where 0.1 and 0.2 carry a
/// bare-hex `digest`, and both of those close their response with
/// `additionalProperties: false`. Serving them from one response body would
/// emit a member their schemas reject.
pub const CANONICAL_PROVISION_INTEGRATION_0_3: &str =
    "https://trusttasks.org/spec/provision/integration/0.3";

/// Outbound sealed bundle + summary — canonical Trust Task URI, v0.3.
pub const CANONICAL_PROVISION_INTEGRATION_0_3_RESULT: &str =
    "https://trusttasks.org/spec/provision/integration/0.3#response";

/// Match the result URI to whichever request URI the caller used.
/// Centralised here so the routing decision lives next to the URI
/// constants — handlers downstream just call this.
///
/// Resolved through [`ProvisionSpecVersion::from_request_uri`] rather than by
/// testing for one version and falling through, which is what this function
/// used to do: `== 0.2` picked the 0.2 `#response`, and *everything else* —
/// including the 0.3 that #1147 made the only version the router accepts —
/// picked the 0.1 `#response`. The handler beside it rendered a 0.3 body, so
/// every DIDComm reply went out as a `digestMultibase` body labelled
/// `provision/integration/0.1#response`: a message invalid under the schema
/// it names, since 0.1's response requires a bare-hex `digest` and closes
/// with `additionalProperties: false`. A wallet checking the reply type
/// rejected a provisioning run that had actually succeeded — the bundle was
/// sealed and the admin rolled over, and the holder threw the result away.
///
/// The same shape of bug was fixed in [`is_v0_1`] for the same reason: a
/// predicate about one version has to name that version, because the
/// fall-through arm silently claims every version nobody has written yet.
///
/// An unrecognised URI resolves to [`ProvisionSpecVersion::CURRENT`], which
/// is the version [`response_body_for_version`] renders it in — the URI and
/// the body it labels stay the same version even here.
pub fn result_uri_for(request_uri: &str) -> &'static str {
    ProvisionSpecVersion::from_request_uri(request_uri)
        .unwrap_or(ProvisionSpecVersion::CURRENT)
        .result_uri()
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

/// Which version of the provision-integration wire form a body is emitted
/// under. The 0.1 form is snake_case fields + kebab-case `assertion`; 0.2 and
/// 0.3 are lowerCamelCase throughout, per `dtgwg-trust-tasks-tf`'s schemas.
/// 0.3 additionally replaces the response's bare-hex `digest` with
/// `digestMultibase`, which is why it could not be served from the same
/// response body as its predecessors — both close with
/// `additionalProperties: false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionSpecVersion {
    V0_1,
    V0_2,
    V0_3,
}

impl ProvisionSpecVersion {
    /// Every version this crate can name, newest last.
    ///
    /// Exists so [`from_request_uri`](Self::from_request_uri) can be a search
    /// rather than a hand-written reverse map. A reverse map is the half that
    /// gets forgotten: `request_uri` below is an exhaustive `match`, so a new
    /// variant cannot compile without an entry, but nothing forced the
    /// corresponding *inbound* mapping to move — and at 0.3 it did not.
    pub const ALL: &'static [Self] = &[Self::V0_1, Self::V0_2, Self::V0_3];

    /// The version every client in this workspace dispatches under.
    ///
    /// Named once, because the per-transport alternative already failed: when
    /// the VTA cut over to 0.3 (#1147) the REST runner and the server moved,
    /// and the TSP runner (0.2) and the DIDComm runners (0.1) were left behind
    /// — each holding its own literal, none of them wrong on its face. The
    /// server had removed both, so every provisioning attempt over those two
    /// transports came back `unsupportedType` against a VTA that was working
    /// perfectly. A dispatch site should ask *which version do we speak*, not
    /// answer it.
    ///
    /// The older variants stay: they still describe the historical wire forms
    /// that [`request_body_for_version`] and `is_v0_1` case bodies for, and
    /// they are public API. What they no longer are is something a client
    /// picks.
    pub const CURRENT: Self = Self::V0_3;

    /// The canonical request URI to address this version at.
    pub fn request_uri(self) -> &'static str {
        match self {
            ProvisionSpecVersion::V0_1 => CANONICAL_PROVISION_INTEGRATION,
            ProvisionSpecVersion::V0_2 => CANONICAL_PROVISION_INTEGRATION_0_2,
            ProvisionSpecVersion::V0_3 => CANONICAL_PROVISION_INTEGRATION_0_3,
        }
    }

    /// The canonical result URI a request at this version is answered under.
    ///
    /// Per SPEC.md §4.4.1 of `dtgwg-trust-tasks-tf` this is always the request
    /// URI plus a `#response` fragment, which
    /// `result_uri_is_request_uri_plus_response_fragment` asserts for every
    /// variant — the constants are written out rather than concatenated so
    /// that the test compares two independently-derived strings.
    pub fn result_uri(self) -> &'static str {
        match self {
            ProvisionSpecVersion::V0_1 => CANONICAL_PROVISION_INTEGRATION_RESULT,
            ProvisionSpecVersion::V0_2 => CANONICAL_PROVISION_INTEGRATION_0_2_RESULT,
            ProvisionSpecVersion::V0_3 => CANONICAL_PROVISION_INTEGRATION_0_3_RESULT,
        }
    }

    /// Which version a request URI addresses, or `None` if it names no
    /// version this crate knows.
    pub fn from_request_uri(request_uri: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|v| v.request_uri() == request_uri)
    }
}

/// Whether `request_uri` is the 0.1 form, whose summary keys are snake_case.
///
/// Written as an equality against 0.1, not as "anything that is not 0.2". The
/// negative form silently classified every *future* version as 0.1: adding 0.3
/// made it snake_case a camelCase summary, and the only symptom was a response
/// whose keys no consumer expected. A predicate about one version should name
/// that version.
fn is_v0_1(request_uri: &str) -> bool {
    request_uri == CANONICAL_PROVISION_INTEGRATION
}

/// `fooBarBaz` → `foo_bar_baz`. A single-word key is returned unchanged.
fn lower_camel_to_snake(key: &str) -> String {
    lower_camel_to_delimited(key, '_')
}

/// `didSigned` → `did-signed`. A single-word value is returned unchanged.
fn lower_camel_to_kebab(value: &str) -> String {
    lower_camel_to_delimited(value, '-')
}

fn lower_camel_to_delimited(s: &str, delim: char) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push(delim);
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Rewrite the keys of an object in place via `lower_camel_to_snake`, leaving
/// the values untouched. Shallow on purpose: the caller decides which subtrees
/// (e.g. the signed VP) must stay byte-identical.
fn recase_object_keys_shallow(map: &mut serde_json::Map<String, Value>) {
    let renamed: Vec<(String, Value)> = std::mem::take(map)
        .into_iter()
        .map(|(k, v)| (lower_camel_to_snake(&k), v))
        .collect();
    map.extend(renamed);
}

/// Serialise a provision-integration **request** body in the casing
/// `request_uri` implies. The types now serialise the canonical 0.2
/// lowerCamelCase directly (#857), so 0.2 is the identity; for a **0.1**
/// destination the optional fields are down-cased (`vcValiditySeconds` →
/// `vc_validity_seconds`, `createContext` → `create_context`) and the
/// `assertion` value kebab-cased (`didSigned` → `did-signed`).
///
/// The signed `request` VP subtree is **never** touched — it carries the
/// holder's `DataIntegrityProof` over its exact bytes, and the holder signs
/// whatever casing it chose inside it (see [`crate::provision_integration::request`]).
pub fn request_body_for_version(
    req: &ProvisionIntegrationRequest,
    request_uri: &str,
) -> Result<Value, serde_json::Error> {
    let mut v = serde_json::to_value(req)?;
    if is_v0_1(request_uri)
        && let Value::Object(map) = &mut v
    {
        // `request` (the signed VP) is a single-word key, so the shallow
        // rename leaves both its key and value intact.
        recase_object_keys_shallow(map);
        if let Some(Value::String(a)) = map.get_mut("assertion") {
            *a = lower_camel_to_kebab(a);
        }
    }
    Ok(v)
}

/// Serialise a provision-integration **response** body in the casing
/// `request_uri` implies. lowerCamelCase is the canonical serialization
/// (identity for 0.2 and 0.3); for a **0.1** requester the `summary` object's
/// keys are down-cased (`clientDid` → `client_did`, `bundleIdHex` →
/// `bundle_id_hex`, …). The top-level `bundle`/`digestMultibase` are opaque
/// single-word fields and unchanged.
pub fn response_body_for_version(
    resp: &ProvisionIntegrationResponse,
    request_uri: &str,
) -> Result<Value, serde_json::Error> {
    let mut v = serde_json::to_value(resp)?;
    if is_v0_1(request_uri)
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

    #[test]
    fn result_uri_for_v0_3_request_emits_v0_3_response() {
        assert_eq!(
            result_uri_for(CANONICAL_PROVISION_INTEGRATION_0_3),
            CANONICAL_PROVISION_INTEGRATION_0_3_RESULT
        );
    }

    /// The response URI and the response *body* are two decisions taken off
    /// the same `request_uri`, one line apart in the DIDComm handler. They
    /// have to name the same version, and for 0.3 they did not: the body was
    /// rendered 0.3 and the URI came back 0.1, so the reply announced a
    /// schema it could not satisfy.
    ///
    /// Asserted over `ALL` rather than per-version, because the failure this
    /// catches is a *new* version arriving and one of the two halves not
    /// moving with it.
    #[test]
    fn result_uri_for_agrees_with_the_version_the_request_uri_names() {
        for v in ProvisionSpecVersion::ALL {
            assert_eq!(
                result_uri_for(v.request_uri()),
                v.result_uri(),
                "{v:?}: result_uri_for disagrees with the version's own result URI"
            );
        }
    }

    /// SPEC.md §4.4.1 of `dtgwg-trust-tasks-tf`: a success response is emitted
    /// under the request URI with a `#response` fragment. Holds for every
    /// version, so assert the rule rather than three more pinned strings.
    #[test]
    fn result_uri_is_request_uri_plus_response_fragment() {
        for v in ProvisionSpecVersion::ALL {
            assert_eq!(v.result_uri(), format!("{}#response", v.request_uri()));
        }
    }

    /// `ALL` has to list every variant, or `from_request_uri` answers `None`
    /// for a version this crate can otherwise name — and `result_uri_for`
    /// then silently falls back to `CURRENT`. The `match` is exhaustive, so
    /// adding a variant fails to compile here until it is named.
    #[test]
    fn all_lists_every_version() {
        for v in [
            ProvisionSpecVersion::V0_1,
            ProvisionSpecVersion::V0_2,
            ProvisionSpecVersion::V0_3,
        ] {
            match v {
                ProvisionSpecVersion::V0_1
                | ProvisionSpecVersion::V0_2
                | ProvisionSpecVersion::V0_3 => {}
            }
            assert!(
                ProvisionSpecVersion::ALL.contains(&v),
                "{v:?} is missing from ProvisionSpecVersion::ALL"
            );
        }
    }

    /// An unrecognised URI cannot reach the handler — the router binds
    /// `CURRENT` alone — but if one ever did, the reply must be labelled the
    /// version its body was actually rendered in. `response_body_for_version`
    /// recases only for 0.1, so anything unknown is rendered `CURRENT`.
    #[test]
    fn result_uri_for_unknown_request_matches_the_body_it_would_render() {
        assert_eq!(
            result_uri_for("https://example.invalid/something-else"),
            ProvisionSpecVersion::CURRENT.result_uri()
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

    /// The recase runs camel → snake/kebab now: the types serialise the
    /// canonical 0.2 form, so 0.1 is the direction that needs converting
    /// (#857).
    #[test]
    fn lower_camel_to_snake_and_kebab() {
        assert_eq!(lower_camel_to_snake("clientDid"), "client_did");
        assert_eq!(lower_camel_to_snake("bundleIdHex"), "bundle_id_hex");
        assert_eq!(
            lower_camel_to_snake("vcValiditySeconds"),
            "vc_validity_seconds"
        );
        assert_eq!(lower_camel_to_snake("bundle"), "bundle"); // single word
        assert_eq!(lower_camel_to_kebab("didSigned"), "did-signed");
        assert_eq!(lower_camel_to_kebab("pinnedOnly"), "pinned-only");
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
            request: vp_value.clone(),
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

    /// Sign a VP the way a holder on vta-sdk < 0.21.11 does: `ask.type`
    /// PascalCase (`TemplateBootstrap`), signed over that wire form.
    ///
    /// Deliberately *not* built through [`ProvisionRequestBuilder`]. The
    /// point is a document this crate did not render — the relaying tests
    /// above compare the SDK's own serde output against itself, which is
    /// true by construction and cannot catch a relayer that re-renders
    /// what it forwards.
    async fn foreign_holder_vp() -> Value {
        use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
        use affinidi_secrets_resolver::secrets::Secret;
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

        let (seed, pub_bytes) = crate::sealed_transfer::generate_ed25519_keypair();
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
        let mb = did.strip_prefix("did:key:").expect("did:key prefix");
        let vm_id = format!("{did}#{mb}");
        let mut signer = Secret::generate_ed25519(Some(&vm_id), Some(&seed));
        signer.id = vm_id;

        let now = chrono::Utc::now();
        let mut doc = serde_json::json!({
            "@context": [
                crate::provision_integration::VC_V2_CONTEXT_URL,
                crate::provision_integration::BOOTSTRAP_CONTEXT_URL,
            ],
            "type": ["VerifiablePresentation", "BootstrapRequest"],
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "holder": did,
            "nonce": B64URL.encode([0xF1u8; 16]),
            "validUntil": (now + chrono::Duration::hours(1)).to_rfc3339(),
            "ask": {
                "type": "TemplateBootstrap",
                "template": { "name": "didcomm-mediator", "vars": {} }
            }
        });
        let proof = DataIntegrityProof::sign(
            &doc,
            &signer,
            SignOptions::new()
                .with_proof_purpose("authentication")
                .with_created(now),
        )
        .await
        .expect("sign foreign VP");
        doc.as_object_mut()
            .unwrap()
            .insert("proof".into(), serde_json::to_value(&proof).unwrap());
        doc
    }

    #[tokio::test]
    async fn a_foreign_holders_vp_is_relayed_byte_for_byte() {
        let vp = foreign_holder_vp().await;

        // Guard against this test going vacuous. It only proves anything
        // while the SDK's rendering of the document differs from the
        // document — if the two ever converge, the assertions below pass
        // for the wrong reason and the fixture needs a new divergence.
        let round_tripped = serde_json::to_value(
            serde_json::from_value::<crate::provision_integration::BootstrapRequest>(vp.clone())
                .expect("foreign VP parses"),
        )
        .expect("re-serialize");
        assert_ne!(
            round_tripped, vp,
            "fixture no longer diverges from this crate's serde output"
        );

        for uri in [
            CANONICAL_PROVISION_INTEGRATION,
            CANONICAL_PROVISION_INTEGRATION_0_2,
        ] {
            let req = ProvisionIntegrationRequest {
                request: vp.clone(),
                context: Some("ctx".into()),
                assertion: None,
                vc_validity_seconds: None,
                create_context: false,
            };
            let body = request_body_for_version(&req, uri).expect("build body");
            assert_eq!(
                body["request"], vp,
                "relaying under {uri} altered the holder's signed document"
            );
            // The end the relayer is talking to must still be able to
            // verify it — the whole reason the bytes matter.
            crate::provision_integration::BootstrapRequest::verify_value(body["request"].clone())
                .expect("relayed VP still verifies");
        }
    }

    #[test]
    fn response_body_v0_1_stays_snake_case_v0_3_camelizes_summary() {
        let resp = ProvisionIntegrationResponse {
            bundle: "armored".into(),
            digest_multibase: Some("zQmSK9pGKFnmc77pqyNAPJyPKt8rMqctngfg3vwuMArwGYZ".into()),
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
        // 0.3 — summary keys camelized; values and opaque bundle/digest intact.
        let v02 = response_body_for_version(&resp, CANONICAL_PROVISION_INTEGRATION_0_3).unwrap();
        assert_eq!(v02["summary"]["clientDid"], "did:key:zClient");
        assert_eq!(v02["summary"]["bundleIdHex"], "abc");
        assert_eq!(v02["summary"]["secretCount"], 2);
        assert_eq!(v02["summary"]["adminRolledOver"], true);
        assert_eq!(v02["summary"]["contextCreated"], true);
        assert!(v02["summary"].get("client_did").is_none());
        assert_eq!(v02["bundle"], "armored");
        assert_eq!(
            v02["digestMultibase"],
            "zQmSK9pGKFnmc77pqyNAPJyPKt8rMqctngfg3vwuMArwGYZ"
        );
        assert!(
            v02.get("digest").is_none(),
            "0.3 carries `digestMultibase` and nothing else — its response is closed"
        );
    }
}
