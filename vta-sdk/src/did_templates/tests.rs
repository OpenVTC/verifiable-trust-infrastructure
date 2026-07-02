//! End-to-end tests for template parsing, validation, and rendering.

use serde_json::{Value, json};

use super::*;

fn base_doc() -> Value {
    json!({
        "id": "{DID}",
        "verificationMethod": [{
            "id": "{DID}#key-1",
            "publicKeyMultibase": "{SIGNING_KEY_MB}"
        }]
    })
}

fn base_template(extra: Value) -> Value {
    let mut v = json!({
        "schemaVersion": 1,
        "name": "test-template",
        "kind": "custom",
        "requiredVars": [],
        "optionalVars": {},
        "document": base_doc()
    });
    let obj = v.as_object_mut().unwrap();
    for (k, val) in extra.as_object().unwrap() {
        obj.insert(k.clone(), val.clone());
    }
    v
}

fn ambient_vars() -> TemplateVars {
    let mut v = TemplateVars::new();
    v.insert_string("DID", "did:webvh:abc:example.com");
    v.insert_string("SIGNING_KEY_MB", "z6MkSigning");
    v
}

// ─── validation ──────────────────────────────────────────────────────

#[test]
fn rejects_unsupported_schema_version() {
    let raw = base_template(json!({ "schemaVersion": 99 }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(matches!(
        err,
        TemplateError::UnsupportedSchema { found: 99, .. }
    ));
}

#[test]
fn rejects_bad_name() {
    let raw = base_template(json!({ "name": "Has Space" }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(matches!(err, TemplateError::Invalid(_)));
}

#[test]
fn rejects_document_without_did_placeholder() {
    let raw = base_template(json!({
        "document": { "id": "did:example:fixed" }
    }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(
        matches!(&err, TemplateError::Invalid(msg) if msg.contains("{DID}")),
        "got: {err}"
    );
}

#[test]
fn rejects_reserved_name_in_required_vars() {
    let raw = base_template(json!({ "requiredVars": ["DID"] }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(matches!(err, TemplateError::ReservedVar(v) if v == "DID"));
}

#[test]
fn rejects_reserved_name_in_optional_vars() {
    let raw = base_template(json!({
        "optionalVars": { "NOW": "x" }
    }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(matches!(err, TemplateError::ReservedVar(v) if v == "NOW"));
}

#[test]
fn rejects_variable_in_both_lists() {
    let raw = base_template(json!({
        "requiredVars": ["URL"],
        "optionalVars": { "URL": "x" },
        "document": {
            "id": "{DID}",
            "url": "{URL}"
        }
    }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(
        matches!(&err, TemplateError::Invalid(m) if m.contains("both")),
        "got: {err}"
    );
}

#[test]
fn rejects_undeclared_placeholder() {
    let raw = base_template(json!({
        "document": {
            "id": "{DID}",
            "mystery": "{NOT_DECLARED}"
        }
    }));
    let err = DidTemplate::from_json(raw).unwrap_err();
    assert!(
        matches!(&err, TemplateError::Invalid(m) if m.contains("NOT_DECLARED")),
        "got: {err}"
    );
}

// ─── render ──────────────────────────────────────────────────────────

#[test]
fn renders_embedded_string_placeholder() {
    let raw = base_template(json!({
        "requiredVars": ["URL"],
        "document": {
            "id": "{DID}",
            "uri": "prefix-{URL}-suffix"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let mut vars = ambient_vars();
    vars.insert_string("URL", "https://m.example.com");

    let out = tpl.render(&vars).unwrap();
    assert_eq!(out["uri"], "prefix-https://m.example.com-suffix");
    assert_eq!(out["id"], "did:webvh:abc:example.com");
}

#[test]
fn whole_string_token_substitutes_native_type() {
    let raw = base_template(json!({
        "optionalVars": {
            "ROUTING_KEYS": ["did:key:fallback"]
        },
        "document": {
            "id": "{DID}",
            "routingKeys": "{ROUTING_KEYS}",
            "accept": "{ACCEPT}"
        },
        "requiredVars": ["ACCEPT"]
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();

    let mut vars = ambient_vars();
    vars.insert("ACCEPT", json!(["didcomm/v2", "didcomm/v1"]));
    vars.insert("ROUTING_KEYS", json!(["did:key:z6Mk1", "did:key:z6Mk2"]));

    let out = tpl.render(&vars).unwrap();
    assert_eq!(
        out["routingKeys"],
        json!(["did:key:z6Mk1", "did:key:z6Mk2"])
    );
    assert_eq!(out["accept"], json!(["didcomm/v2", "didcomm/v1"]));
}

#[test]
fn optional_var_default_used_when_caller_omits() {
    let raw = base_template(json!({
        "optionalVars": {
            "HOSTING_PATH": "/default-path"
        },
        "document": {
            "id": "{DID}",
            "path": "{HOSTING_PATH}"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let out = tpl.render(&ambient_vars()).unwrap();
    assert_eq!(out["path"], "/default-path");
}

#[test]
fn caller_vars_override_optional_defaults() {
    let raw = base_template(json!({
        "optionalVars": {
            "HOSTING_PATH": "/default-path"
        },
        "document": {
            "id": "{DID}",
            "path": "{HOSTING_PATH}"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let mut vars = ambient_vars();
    vars.insert_string("HOSTING_PATH", "/custom");
    let out = tpl.render(&vars).unwrap();
    assert_eq!(out["path"], "/custom");
}

#[test]
fn missing_required_var_errors_with_name() {
    let raw = base_template(json!({
        "requiredVars": ["URL"],
        "document": {
            "id": "{DID}",
            "uri": "{URL}"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let err = tpl.render(&ambient_vars()).unwrap_err();
    assert!(
        matches!(&err, TemplateError::MissingVars(m) if m.contains("URL")),
        "got: {err}"
    );
}

#[test]
fn ambient_var_missing_surfaces_as_unresolved() {
    let raw = base_template(json!({
        "document": {
            "id": "{DID}",
            "vtaDid": "{VTA_DID}"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    // Provide DID + SIGNING_KEY_MB but NOT VTA_DID (both are reserved ambient).
    let err = tpl.render(&ambient_vars()).unwrap_err();
    assert!(
        matches!(&err, TemplateError::Unresolved(m) if m.contains("VTA_DID")),
        "got: {err}"
    );
}

#[test]
fn lowercase_braces_are_not_placeholders() {
    let raw = base_template(json!({
        "document": {
            "id": "{DID}",
            "note": "literal {lowercase} stays"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let out = tpl.render(&ambient_vars()).unwrap();
    assert_eq!(out["note"], "literal {lowercase} stays");
}

#[test]
fn placeholders_in_nested_arrays_and_objects() {
    let raw = base_template(json!({
        "requiredVars": ["URL"],
        "document": {
            "id": "{DID}",
            "service": [
                {
                    "id": "{DID}#svc",
                    "serviceEndpoint": { "uri": "{URL}" }
                }
            ]
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let mut vars = ambient_vars();
    vars.insert_string("URL", "https://svc.example.com");
    let out = tpl.render(&vars).unwrap();
    assert_eq!(out["service"][0]["id"], "did:webvh:abc:example.com#svc");
    assert_eq!(
        out["service"][0]["serviceEndpoint"]["uri"],
        "https://svc.example.com"
    );
}

#[test]
fn null_array_elements_are_pruned() {
    // Optional array members are expressed as whole-string tokens whose
    // `optionalVars` default is `null`. When the caller omits them the
    // element resolves to `null` and is dropped, leaving a clean array —
    // never a literal `null` member (invalid in DID-doc key arrays).
    let raw = base_template(json!({
        "optionalVars": { "EXTRA_KEY": null },
        "document": {
            "id": "{DID}",
            "authentication": ["{DID}#key-0", "{EXTRA_KEY}"]
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();

    // Omitted -> pruned.
    let out = tpl.render(&ambient_vars()).unwrap();
    assert_eq!(
        out["authentication"],
        json!(["did:webvh:abc:example.com#key-0"])
    );

    // Supplied -> retained. (A supplied value is not recursively
    // re-substituted, so it must already carry the resolved DID.)
    let mut vars = ambient_vars();
    vars.insert_string("EXTRA_KEY", "did:webvh:abc:example.com#key-2");
    let out = tpl.render(&vars).unwrap();
    assert_eq!(
        out["authentication"],
        json!([
            "did:webvh:abc:example.com#key-0",
            "did:webvh:abc:example.com#key-2"
        ])
    );
}

#[test]
fn provided_token_may_pass_through_as_sentinel() {
    // A caller supplying `DID = "{DID}"` means "leave this literal alone for
    // a downstream library to resolve" — render must not flag it.
    let raw = base_template(json!({
        "document": {
            "id": "{DID}",
            "verificationMethod": [{
                "id": "{DID}#key-1",
                "publicKeyMultibase": "{SIGNING_KEY_MB}"
            }]
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();

    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "{DID}");
    vars.insert_string("SIGNING_KEY_MB", "z6MkReal");

    let out = tpl.render(&vars).unwrap();
    assert_eq!(out["id"], "{DID}");
    assert_eq!(out["verificationMethod"][0]["id"], "{DID}#key-1");
    assert_eq!(
        out["verificationMethod"][0]["publicKeyMultibase"],
        "z6MkReal"
    );
}

#[test]
fn utf8_strings_survive_substitution() {
    let raw = base_template(json!({
        "requiredVars": ["LABEL"],
        "document": {
            "id": "{DID}",
            "label": "café-{LABEL}-résumé"
        }
    }));
    let tpl = DidTemplate::from_json(raw).unwrap();
    let mut vars = ambient_vars();
    vars.insert_string("LABEL", "naïve");
    let out = tpl.render(&vars).unwrap();
    assert_eq!(out["label"], "café-naïve-résumé");
}

// ─── built-ins ───────────────────────────────────────────────────────

#[test]
fn didcomm_mediator_builtin_renders_end_to_end() {
    let tpl = load_embedded("didcomm-mediator").unwrap();
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:mediator:example.com");
    vars.insert_string("SIGNING_KEY_MB", "z6MkSign");
    vars.insert_string("KA_KEY_MB", "z6LSKa");
    vars.insert_string("URL", "https://mediator.example.com");
    vars.insert_string("WS_URL", "wss://mediator.example.com/ws");

    let doc = tpl.render(&vars).unwrap();
    assert_eq!(doc["id"], "did:webvh:mediator:example.com");

    // No P-256 vars supplied -> the optional P-256 slots default to `null`
    // and are pruned: only the Ed25519 + X25519 pair survives, and the
    // verification-relationship arrays each carry a single key reference.
    let vms = doc["verificationMethod"].as_array().unwrap();
    assert_eq!(vms.len(), 2);
    assert_eq!(vms[0]["id"], "did:webvh:mediator:example.com#key-0");
    assert_eq!(vms[1]["id"], "did:webvh:mediator:example.com#key-1");
    assert_eq!(
        doc["authentication"],
        json!(["did:webvh:mediator:example.com#key-0"])
    );
    assert_eq!(
        doc["assertionMethod"],
        json!(["did:webvh:mediator:example.com#key-0"])
    );
    assert_eq!(
        doc["keyAgreement"],
        json!(["did:webvh:mediator:example.com#key-1"])
    );

    let services = doc["service"].as_array().unwrap();
    // No `SERVICE_TSP` supplied -> the optional `#tsp` slot defaults to `null`
    // and is pruned. A DIDComm-only mediator advertises only DIDComm + auth;
    // TSP is opt-in (see `..._renders_tsp_service_when_supplied`).
    assert_eq!(services.len(), 2);
    assert!(
        !services
            .iter()
            .any(|s| s["type"] == "TSPTransport" || s["type"] == json!(["TSPTransport"])),
        "TSP must be absent unless SERVICE_TSP is supplied"
    );

    // DIDComm service: id `#service`, type as a single-element array,
    // serviceEndpoint as an array of two endpoint objects (HTTP first,
    // WSS second). Each endpoint carries the same accept/routingKeys.
    assert_eq!(services[0]["id"], "did:webvh:mediator:example.com#service");
    assert_eq!(services[0]["type"], json!(["DIDCommMessaging"]));
    let endpoints = services[0]["serviceEndpoint"].as_array().unwrap();
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0]["uri"], "https://mediator.example.com");
    assert_eq!(endpoints[0]["accept"], json!(["didcomm/v2"]));
    assert_eq!(endpoints[0]["routingKeys"], json!([]));
    assert_eq!(endpoints[1]["uri"], "wss://mediator.example.com/ws");
    assert_eq!(endpoints[1]["accept"], json!(["didcomm/v2"]));
    assert_eq!(endpoints[1]["routingKeys"], json!([]));

    // Authentication service: id `#auth`, type as a single-element array,
    // serviceEndpoint as a plain string at `<URL>/authenticate`.
    assert_eq!(services[1]["id"], "did:webvh:mediator:example.com#auth");
    assert_eq!(services[1]["type"], json!(["Authentication"]));
    assert_eq!(
        services[1]["serviceEndpoint"],
        "https://mediator.example.com/authenticate"
    );
}

#[test]
fn didcomm_mediator_builtin_renders_tsp_service_when_supplied() {
    // Opt-in TSP: the caller supplies `SERVICE_TSP` as the fully-resolved
    // service object (whole-string native-type substitution). Supplied values
    // are not recursively re-substituted, so — like the P-256 VM slots — they
    // carry the resolved DID here rather than the `{DID}` sentinel the local
    // generator would pass in production (which the did-method layer resolves
    // after SCID computation).
    let tpl = load_embedded("didcomm-mediator").unwrap();
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:mediator:example.com");
    vars.insert_string("SIGNING_KEY_MB", "z6MkSign");
    vars.insert_string("KA_KEY_MB", "z6LSKa");
    vars.insert_string("URL", "https://mediator.example.com");
    vars.insert_string("WS_URL", "wss://mediator.example.com/ws");
    vars.insert(
        "SERVICE_TSP",
        json!({
            "id": "did:webvh:mediator:example.com#tsp",
            "type": "TSPTransport",
            "serviceEndpoint": "https://mediator.example.com"
        }),
    );

    let doc = tpl.render(&vars).unwrap();
    let services = doc["service"].as_array().unwrap();
    // TSP first (canonical preference order), then DIDComm, then auth.
    assert_eq!(services.len(), 3);
    assert_eq!(services[0]["id"], "did:webvh:mediator:example.com#tsp");
    assert_eq!(services[0]["type"], "TSPTransport");
    assert_eq!(
        services[0]["serviceEndpoint"],
        "https://mediator.example.com"
    );
    assert_eq!(services[1]["type"], json!(["DIDCommMessaging"]));
    assert_eq!(services[2]["type"], json!(["Authentication"]));
}

#[test]
fn didcomm_mediator_builtin_renders_p256_slots_when_supplied() {
    // Opt-in P-256: the caller supplies the optional verification-method
    // objects (whole-string native-type substitution) plus the
    // relationship references. The document then carries 4 verification
    // methods and two-entry authentication/assertionMethod/keyAgreement
    // arrays — exactly what a P-256-capable counterparty needs. (Supplied
    // values are not recursively re-substituted, so they carry the resolved
    // DID rather than the `{DID}` sentinel the local generator would pass.)
    let tpl = load_embedded("didcomm-mediator").unwrap();
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:mediator:example.com");
    vars.insert_string("SIGNING_KEY_MB", "z6MkSign");
    vars.insert_string("KA_KEY_MB", "z6LSKa");
    vars.insert_string("URL", "https://mediator.example.com");
    vars.insert_string("WS_URL", "wss://mediator.example.com/ws");
    vars.insert(
        "VM_P256_SIGNING",
        json!({
            "id": "did:webvh:mediator:example.com#key-2",
            "type": "Multikey",
            "controller": "did:webvh:mediator:example.com",
            "publicKeyMultibase": "zDnaP256Sign"
        }),
    );
    vars.insert(
        "VM_P256_KA",
        json!({
            "id": "did:webvh:mediator:example.com#key-3",
            "type": "Multikey",
            "controller": "did:webvh:mediator:example.com",
            "publicKeyMultibase": "zDnaP256Ka"
        }),
    );
    vars.insert_string("AUTH_P256", "did:webvh:mediator:example.com#key-2");
    vars.insert_string("ASSERTION_P256", "did:webvh:mediator:example.com#key-2");
    vars.insert_string("KEYAGREEMENT_P256", "did:webvh:mediator:example.com#key-3");

    let doc = tpl.render(&vars).unwrap();

    let vms = doc["verificationMethod"].as_array().unwrap();
    assert_eq!(vms.len(), 4);
    assert_eq!(vms[2]["id"], "did:webvh:mediator:example.com#key-2");
    assert_eq!(vms[2]["type"], "Multikey");
    assert_eq!(vms[2]["controller"], "did:webvh:mediator:example.com");
    assert_eq!(vms[2]["publicKeyMultibase"], "zDnaP256Sign");
    assert_eq!(vms[3]["id"], "did:webvh:mediator:example.com#key-3");
    assert_eq!(vms[3]["publicKeyMultibase"], "zDnaP256Ka");

    assert_eq!(
        doc["authentication"],
        json!([
            "did:webvh:mediator:example.com#key-0",
            "did:webvh:mediator:example.com#key-2"
        ])
    );
    assert_eq!(
        doc["assertionMethod"],
        json!([
            "did:webvh:mediator:example.com#key-0",
            "did:webvh:mediator:example.com#key-2"
        ])
    );
    assert_eq!(
        doc["keyAgreement"],
        json!([
            "did:webvh:mediator:example.com#key-1",
            "did:webvh:mediator:example.com#key-3"
        ])
    );
}

#[test]
fn ws_url_is_derived_from_url_when_omitted() {
    // The renderer auto-derives WS_URL from URL by swapping the
    // scheme and appending `/ws` so `vta setup` and similar one-URL
    // flows can render the mediator template without a separate
    // `--var WS_URL=...`. Mirrors the deployed convention
    // (`/mediator/v1` over HTTP, `/mediator/v1/ws` over WSS).
    let tpl = load_embedded("didcomm-mediator").unwrap();
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:mediator:example.com");
    vars.insert_string("SIGNING_KEY_MB", "z6MkSign");
    vars.insert_string("KA_KEY_MB", "z6LSKa");
    vars.insert_string("URL", "https://mediator.example.com/mediator/v1");
    // WS_URL deliberately omitted.

    let doc = tpl.render(&vars).expect("render with derived WS_URL");
    // No SERVICE_TSP -> DIDComm is the first service entry.
    let endpoints = doc["service"][0]["serviceEndpoint"].as_array().unwrap();
    assert_eq!(
        endpoints[0]["uri"],
        "https://mediator.example.com/mediator/v1"
    );
    assert_eq!(
        endpoints[1]["uri"],
        "wss://mediator.example.com/mediator/v1/ws"
    );
}

#[test]
fn ws_url_derivation_handles_plain_http_and_trailing_slash() {
    // Trailing slash on URL must not produce a double slash in the
    // derived WS_URL: `http://host/` → `ws://host/ws`, not
    // `ws://host//ws`.
    let tpl = load_embedded("didcomm-mediator").unwrap();
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:mediator:example.com");
    vars.insert_string("SIGNING_KEY_MB", "z6MkSign");
    vars.insert_string("KA_KEY_MB", "z6LSKa");
    vars.insert_string("URL", "http://mediator.local/");

    let doc = tpl.render(&vars).expect("render with derived ws://");
    // No SERVICE_TSP -> DIDComm is the first service entry.
    let endpoints = doc["service"][0]["serviceEndpoint"].as_array().unwrap();
    assert_eq!(endpoints[1]["uri"], "ws://mediator.local/ws");
}

#[test]
fn explicit_ws_url_overrides_derivation() {
    // A caller supplying both URL and WS_URL gets exactly what they
    // asked for — derivation must not clobber an explicit value (e.g.
    // an operator who terminates WS at a different host).
    let tpl = load_embedded("didcomm-mediator").unwrap();
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:mediator:example.com");
    vars.insert_string("SIGNING_KEY_MB", "z6MkSign");
    vars.insert_string("KA_KEY_MB", "z6LSKa");
    vars.insert_string("URL", "https://mediator.example.com");
    vars.insert_string("WS_URL", "wss://ws-gateway.example.net/mediator/ws");

    let doc = tpl.render(&vars).unwrap();
    // No SERVICE_TSP -> DIDComm is the first service entry.
    let endpoints = doc["service"][0]["serviceEndpoint"].as_array().unwrap();
    assert_eq!(endpoints[0]["uri"], "https://mediator.example.com");
    assert_eq!(
        endpoints[1]["uri"],
        "wss://ws-gateway.example.net/mediator/ws"
    );
}

#[test]
fn ws_url_not_derived_for_non_http_scheme() {
    // A URL with neither http:// nor https:// can't be safely converted
    // — surface the missing-var error instead of fabricating something.
    let tpl = load_embedded("didcomm-mediator").unwrap();
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:mediator:example.com");
    vars.insert_string("SIGNING_KEY_MB", "z6MkSign");
    vars.insert_string("KA_KEY_MB", "z6LSKa");
    vars.insert_string("URL", "didcomm://routed-only");

    let err = tpl
        .render(&vars)
        .expect_err("render should fail with missing WS_URL");
    let msg = err.to_string();
    assert!(
        msg.contains("WS_URL"),
        "expected WS_URL in error, got: {msg}"
    );
}

#[test]
fn vta_admin_builtin_renders_end_to_end() {
    // The vta-admin template is a did:key shape — no required vars beyond
    // the ambient {DID} + {SIGNING_KEY_MB} the renderer / VTA always
    // supplies. No service endpoints, no key-agreement VM (X25519 is
    // derived on demand from the Ed25519 pub by did:key resolvers).
    let tpl = load_embedded("vta-admin").unwrap();
    assert_eq!(tpl.kind, "admin");
    assert!(tpl.required_vars.is_empty());
    assert!(tpl.optional_vars.is_empty());

    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:key:z6MkAdminPub");
    vars.insert_string("SIGNING_KEY_MB", "z6MkAdminPub");

    let doc = tpl.render(&vars).unwrap();
    assert_eq!(doc["id"], "did:key:z6MkAdminPub");
    assert_eq!(
        doc["verificationMethod"][0]["id"],
        "did:key:z6MkAdminPub#z6MkAdminPub"
    );
    assert_eq!(
        doc["verificationMethod"][0]["publicKeyMultibase"],
        "z6MkAdminPub"
    );
    assert!(doc.get("service").is_none(), "admin DID has no service");
}

#[test]
fn did_host_http_builtin_renders_end_to_end() {
    let tpl = load_embedded("did-host-http").unwrap();
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:host:example.com");
    vars.insert_string("SIGNING_KEY_MB", "z6MkSign");
    vars.insert_string("KA_KEY_MB", "z6LSKa");
    vars.insert_string("URL", "https://host.example.com");

    let doc = tpl.render(&vars).unwrap();
    assert_eq!(doc["service"][0]["type"], "WebVHHosting");
    // Default path applied.
    assert_eq!(
        doc["service"][0]["serviceEndpoint"]["hostingPath"],
        "/webvh"
    );
}

// ─── did-host-didcomm built-in ──────────────────────────────────────
//
// The rendered-fixture comparison is a shape regression guard: if the
// template is edited (a field renamed, a key added, an array flattened
// to an object) this test fails and the author has to update the
// fixture deliberately. That's the point — downstream services build
// against this shape.

const DID_HOST_DIDCOMM_RENDERED_FIXTURE: &str =
    include_str!("../../tests/fixtures/did-host-didcomm.rendered.json");

fn did_host_didcomm_fixture_vars() -> TemplateVars {
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:QmTEST:example.com");
    vars.insert_string("SIGNING_KEY_MB", "z6MkTESTsigning");
    vars.insert_string("KA_KEY_MB", "z6LSTESTka");
    vars.insert_string(
        "MEDIATOR_DID",
        "did:webvh:QmMED:mediator.example.com:mediator",
    );
    vars
}

#[test]
fn did_host_didcomm_builtin_loads_and_validates() {
    let tpl = load_embedded("did-host-didcomm").expect("load_embedded");
    assert_eq!(tpl.name, "did-host-didcomm");
    assert_eq!(tpl.kind, "did-host-didcomm");
    assert_eq!(tpl.methods, vec!["webvh"]);
    assert_eq!(tpl.required_vars, vec!["MEDIATOR_DID"]);
    tpl.validate().expect("validate after load");
}

#[test]
fn did_host_didcomm_builtin_renders_exact_document_shape() {
    let tpl = load_embedded("did-host-didcomm").unwrap();
    let out = tpl.render(&did_host_didcomm_fixture_vars()).unwrap();
    let expected: Value =
        serde_json::from_str(DID_HOST_DIDCOMM_RENDERED_FIXTURE).expect("fixture parses as JSON");
    assert_eq!(
        out, expected,
        "rendered document diverged from fixture — if intentional, update tests/fixtures/did-host-didcomm.rendered.json"
    );
}

#[test]
fn did_host_didcomm_builtin_accept_is_native_array_not_string() {
    // The whole-string-placeholder contract: `"accept": "{ACCEPT}"` must
    // substitute to the JSON array from the var, not render the literal
    // string "[\"didcomm/v2\"]". Downstream DIDComm libraries parse the
    // accept list as an array; a stringified version breaks them silently.
    let tpl = load_embedded("did-host-didcomm").unwrap();
    let doc = tpl.render(&did_host_didcomm_fixture_vars()).unwrap();
    // The DIDComm entry is at [1] (the `#tsp` TSP entry sorts first); its
    // first serviceEndpoint object carries the `accept` array.
    let endpoint = &doc["service"][1]["serviceEndpoint"][0];
    let accept = &endpoint["accept"];
    assert!(
        accept.is_array(),
        "accept must be a JSON array, got {accept:?}"
    );
    assert_eq!(*accept, json!(["didcomm/v2"]));
}

#[test]
fn did_host_didcomm_builtin_has_exactly_one_entry_per_transport() {
    // Two transports advertised: TSP (`#tsp`, preferred) then DIDComm
    // (`#vta-didcomm`), both pointing at the same mediator DID (D8 — one
    // dual-protocol mediator). Older mediator setups emitted an unnamed
    // duplicate DIDCommMessaging service; lock exactly one entry per type
    // so the template never regresses into that.
    let tpl = load_embedded("did-host-didcomm").unwrap();
    let doc = tpl.render(&did_host_didcomm_fixture_vars()).unwrap();
    let services = doc["service"].as_array().expect("service is array");
    assert_eq!(
        services.len(),
        2,
        "expected exactly two service entries (tsp + didcomm), got {}: {:?}",
        services.len(),
        services
    );
    // TSP first (canonical order): plain-string mediator-DID endpoint.
    assert_eq!(services[0]["id"], "did:webvh:QmTEST:example.com#tsp");
    assert_eq!(services[0]["type"], "TSPTransport");
    assert_eq!(
        services[0]["serviceEndpoint"],
        "did:webvh:QmMED:mediator.example.com:mediator"
    );
    // DIDComm second, same mediator.
    assert_eq!(
        services[1]["id"],
        "did:webvh:QmTEST:example.com#vta-didcomm"
    );
    assert_eq!(services[1]["type"], "DIDCommMessaging");
}

#[test]
fn did_host_didcomm_builtin_context_is_did_v1_plus_cid_v1() {
    // Spec: exactly these two contexts, in this order. No multikey or
    // didcomm contexts (unlike didcomm-mediator which carries them).
    let tpl = load_embedded("did-host-didcomm").unwrap();
    let doc = tpl.render(&did_host_didcomm_fixture_vars()).unwrap();
    assert_eq!(
        doc["@context"],
        json!([
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ])
    );
}

#[test]
fn did_host_didcomm_builtin_missing_mediator_did_errors() {
    let tpl = load_embedded("did-host-didcomm").unwrap();
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:QmTEST:example.com");
    vars.insert_string("SIGNING_KEY_MB", "z6MkTESTsigning");
    vars.insert_string("KA_KEY_MB", "z6LSTESTka");
    // MEDIATOR_DID deliberately omitted.

    let err = tpl
        .render(&vars)
        .expect_err("missing MEDIATOR_DID must error");
    assert!(
        matches!(&err, TemplateError::MissingVars(m) if m.contains("MEDIATOR_DID")),
        "got: {err}"
    );
}

#[test]
fn did_host_didcomm_builtin_rejects_unknown_placeholder_in_template() {
    // Sanity-check that validate() (which ran implicitly on load) rejects
    // any future edit that adds an undeclared `{TOKEN}` to the document.
    // Mirrors the strictness of the other built-ins.
    //
    // We construct a copy of the template with an injected stray token and
    // confirm `from_json` refuses it — this guards the author against
    // accidentally adding a new placeholder without declaring it in
    // required/optional vars.
    let tpl = load_embedded("did-host-didcomm").unwrap();
    let mut doc = tpl.document.clone();
    // Inject into the DIDComm entry at [1] (whose serviceEndpoint is an
    // array of objects); [0] is now the `#tsp` entry with a plain-string
    // endpoint that can't take a nested key.
    doc["service"][1]["serviceEndpoint"][0]["extra"] =
        Value::String("{UNDECLARED_TOKEN}".to_string());

    let raw = serde_json::json!({
        "schemaVersion": tpl.schema_version,
        "name": tpl.name,
        "kind": tpl.kind,
        "description": tpl.description,
        "methods": tpl.methods,
        "requiredVars": tpl.required_vars,
        "optionalVars": tpl.optional_vars,
        "defaults": tpl.defaults,
        "document": doc,
    });
    let err = DidTemplate::from_json(raw).expect_err("undeclared token must be rejected");
    assert!(
        matches!(&err, TemplateError::Invalid(m) if m.contains("UNDECLARED_TOKEN")),
        "got: {err}"
    );
}

// ─── vtc-host built-in ───────────────────────────────────────────────

#[test]
fn vtc_host_renders_with_minimal_vars() {
    let tpl = load_embedded("vtc-host").unwrap();
    let mut vars = ambient_vars();
    vars.insert_string("KA_KEY_MB", "z6LSKeyAgreement");
    vars.insert_string("URL", "https://vtc.example.com");

    let out = tpl.render(&vars).unwrap();

    assert_eq!(out["id"], "did:webvh:abc:example.com");
    assert_eq!(
        out["verificationMethod"][0]["id"],
        "did:webvh:abc:example.com#key-0"
    );
    assert_eq!(
        out["verificationMethod"][0]["publicKeyMultibase"],
        "z6MkSigning"
    );
    assert_eq!(
        out["verificationMethod"][1]["id"],
        "did:webvh:abc:example.com#key-1"
    );
    assert_eq!(
        out["verificationMethod"][1]["publicKeyMultibase"],
        "z6LSKeyAgreement"
    );
    assert_eq!(out["assertionMethod"][0], "did:webvh:abc:example.com#key-0");
    assert_eq!(out["authentication"][0], "did:webvh:abc:example.com#key-0");
    assert_eq!(out["keyAgreement"][0], "did:webvh:abc:example.com#key-1");

    // Two services: #vtc-rest at the URL, #vtc-status-list at URL + default path.
    assert_eq!(
        out["service"][0]["id"],
        "did:webvh:abc:example.com#vtc-rest"
    );
    assert_eq!(out["service"][0]["type"], "VTCRest");
    assert_eq!(
        out["service"][0]["serviceEndpoint"],
        "https://vtc.example.com"
    );
    assert_eq!(
        out["service"][1]["id"],
        "did:webvh:abc:example.com#vtc-status-list"
    );
    assert_eq!(out["service"][1]["type"], "VTCStatusList");
    assert_eq!(
        out["service"][1]["serviceEndpoint"],
        "https://vtc.example.com/v1/status-lists",
    );
}

#[test]
fn vtc_host_status_list_path_override() {
    let tpl = load_embedded("vtc-host").unwrap();
    let mut vars = ambient_vars();
    vars.insert_string("KA_KEY_MB", "z6LSKeyAgreement");
    vars.insert_string("URL", "https://vtc.example.com");
    vars.insert_string("STATUS_LIST_PATH", "/custom/status");

    let out = tpl.render(&vars).unwrap();
    assert_eq!(
        out["service"][1]["serviceEndpoint"],
        "https://vtc.example.com/custom/status",
    );
}

#[test]
fn vtc_host_requires_url() {
    let tpl = load_embedded("vtc-host").unwrap();
    let mut vars = ambient_vars();
    vars.insert_string("KA_KEY_MB", "z6LSKeyAgreement");
    // URL deliberately omitted.

    let err = tpl.render(&vars).expect_err("URL is required");
    assert!(
        matches!(&err, TemplateError::MissingVars(m) if m.contains("URL")),
        "got: {err}"
    );
}

// ─── ai-agent built-in ───────────────────────────────────────────────
//
// The VTA-minted personal-AI-agent identity (open-claw / nano-claw /
// hermes). Same DIDComm-via-mediator shape as did-host-didcomm but with
// kind `ai-agent`, so a consumer-side device/register can recognise it.

fn ai_agent_fixture_vars() -> TemplateVars {
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:QmAGENT:example.com:agents:nano-claw");
    vars.insert_string("SIGNING_KEY_MB", "z6MkAGENTsigning");
    vars.insert_string("KA_KEY_MB", "z6LSAGENTka");
    vars.insert_string(
        "MEDIATOR_DID",
        "did:webvh:QmMED:mediator.example.com:mediator",
    );
    vars
}

#[test]
fn ai_agent_builtin_loads_and_validates() {
    let tpl = load_embedded("ai-agent").expect("load_embedded");
    assert_eq!(tpl.name, "ai-agent");
    assert_eq!(tpl.kind, "ai-agent");
    assert_eq!(tpl.methods, vec!["webvh", "web"]);
    assert_eq!(tpl.required_vars, vec!["MEDIATOR_DID"]);
    tpl.validate().expect("validate after load");
}

#[test]
fn ai_agent_builtin_has_key_agreement_for_authcrypt() {
    // The agent receives authcrypt + sealed-transfer, so the rendered
    // document must expose a keyAgreement method (key-1), not just a
    // signing key. Guards against a future edit dropping it.
    let tpl = load_embedded("ai-agent").unwrap();
    let doc = tpl.render(&ai_agent_fixture_vars()).unwrap();
    assert_eq!(
        doc["keyAgreement"],
        json!(["did:webvh:QmAGENT:example.com:agents:nano-claw#key-1"])
    );
    assert_eq!(
        doc["authentication"],
        json!(["did:webvh:QmAGENT:example.com:agents:nano-claw#key-0"])
    );
}

#[test]
fn ai_agent_builtin_advertises_tsp_then_didcomm_via_mediator() {
    let tpl = load_embedded("ai-agent").unwrap();
    let doc = tpl.render(&ai_agent_fixture_vars()).unwrap();
    let services = doc["service"].as_array().expect("service is array");
    assert_eq!(
        services.len(),
        2,
        "expected two service entries (tsp + didcomm): {services:?}"
    );
    // TSP first (canonical preference): plain-string mediator-DID endpoint —
    // inbound TSP routes through the same mediator as DIDComm (D8).
    assert_eq!(services[0]["type"], "TSPTransport");
    assert_eq!(
        services[0]["serviceEndpoint"],
        "did:webvh:QmMED:mediator.example.com:mediator"
    );
    // DIDComm second, through the same mediator.
    assert_eq!(services[1]["type"], "DIDCommMessaging");
    assert_eq!(
        services[1]["serviceEndpoint"][0]["uri"], "did:webvh:QmMED:mediator.example.com:mediator",
        "inbound traffic must route through the operator's mediator"
    );
    // Whole-string-placeholder contract: accept substitutes to an array.
    assert!(services[1]["serviceEndpoint"][0]["accept"].is_array());
}

#[test]
fn ai_agent_builtin_missing_mediator_did_errors() {
    let tpl = load_embedded("ai-agent").unwrap();
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", "did:webvh:QmAGENT:example.com");
    vars.insert_string("SIGNING_KEY_MB", "z6MkAGENTsigning");
    vars.insert_string("KA_KEY_MB", "z6LSAGENTka");
    // MEDIATOR_DID deliberately omitted.

    let err = tpl
        .render(&vars)
        .expect_err("missing MEDIATOR_DID must error");
    assert!(
        matches!(&err, TemplateError::MissingVars(m) if m.contains("MEDIATOR_DID")),
        "got: {err}"
    );
}
