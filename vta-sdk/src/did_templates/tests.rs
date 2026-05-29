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
    let services = doc["service"].as_array().unwrap();
    assert_eq!(services.len(), 2);

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
fn did_hosting_daemon_builtin_renders_end_to_end() {
    let tpl = load_embedded("did-hosting-daemon").unwrap();
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

// ─── did-hosting-server built-in ────────────────────────────────────
//
// The rendered-fixture comparison is a shape regression guard: if the
// template is edited (a field renamed, a key added, an array flattened
// to an object) this test fails and the author has to update the
// fixture deliberately. That's the point — downstream services build
// against this shape.

const DID_HOSTING_SERVER_RENDERED_FIXTURE: &str =
    include_str!("../../tests/fixtures/did-hosting-server.rendered.json");

fn did_hosting_server_fixture_vars() -> TemplateVars {
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
fn did_hosting_server_builtin_loads_and_validates() {
    let tpl = load_embedded("did-hosting-server").expect("load_embedded");
    assert_eq!(tpl.name, "did-hosting-server");
    assert_eq!(tpl.kind, "did-hosting-server");
    assert_eq!(tpl.methods, vec!["webvh"]);
    assert_eq!(tpl.required_vars, vec!["MEDIATOR_DID"]);
    tpl.validate().expect("validate after load");
}

#[test]
fn did_hosting_server_builtin_renders_exact_document_shape() {
    let tpl = load_embedded("did-hosting-server").unwrap();
    let out = tpl.render(&did_hosting_server_fixture_vars()).unwrap();
    let expected: Value =
        serde_json::from_str(DID_HOSTING_SERVER_RENDERED_FIXTURE).expect("fixture parses as JSON");
    assert_eq!(
        out, expected,
        "rendered document diverged from fixture — if intentional, update tests/fixtures/did-hosting-server.rendered.json"
    );
}

#[test]
fn did_hosting_server_builtin_accept_is_native_array_not_string() {
    // The whole-string-placeholder contract: `"accept": "{ACCEPT}"` must
    // substitute to the JSON array from the var, not render the literal
    // string "[\"didcomm/v2\"]". Downstream DIDComm libraries parse the
    // accept list as an array; a stringified version breaks them silently.
    let tpl = load_embedded("did-hosting-server").unwrap();
    let doc = tpl.render(&did_hosting_server_fixture_vars()).unwrap();
    let endpoint = &doc["service"][0]["serviceEndpoint"][0];
    let accept = &endpoint["accept"];
    assert!(
        accept.is_array(),
        "accept must be a JSON array, got {accept:?}"
    );
    assert_eq!(*accept, json!(["didcomm/v2"]));
}

#[test]
fn did_hosting_server_builtin_has_exactly_one_service_entry() {
    // Older mediator setups emitted an unnamed duplicate DIDCommMessaging
    // service alongside the named one. Lock the invariant here so this
    // template never regresses into that.
    let tpl = load_embedded("did-hosting-server").unwrap();
    let doc = tpl.render(&did_hosting_server_fixture_vars()).unwrap();
    let services = doc["service"].as_array().expect("service is array");
    assert_eq!(
        services.len(),
        1,
        "expected exactly one service entry, got {}: {:?}",
        services.len(),
        services
    );
    assert_eq!(
        services[0]["id"],
        "did:webvh:QmTEST:example.com#vta-didcomm"
    );
    assert_eq!(services[0]["type"], "DIDCommMessaging");
}

#[test]
fn did_hosting_server_builtin_context_is_did_v1_plus_cid_v1() {
    // Spec: exactly these two contexts, in this order. No multikey or
    // didcomm contexts (unlike didcomm-mediator which carries them).
    let tpl = load_embedded("did-hosting-server").unwrap();
    let doc = tpl.render(&did_hosting_server_fixture_vars()).unwrap();
    assert_eq!(
        doc["@context"],
        json!([
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ])
    );
}

#[test]
fn did_hosting_server_builtin_missing_mediator_did_errors() {
    let tpl = load_embedded("did-hosting-server").unwrap();
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
fn did_hosting_server_builtin_rejects_unknown_placeholder_in_template() {
    // Sanity-check that validate() (which ran implicitly on load) rejects
    // any future edit that adds an undeclared `{TOKEN}` to the document.
    // Mirrors the strictness of the other built-ins.
    //
    // We construct a copy of the template with an injected stray token and
    // confirm `from_json` refuses it — this guards the author against
    // accidentally adding a new placeholder without declaring it in
    // required/optional vars.
    let tpl = load_embedded("did-hosting-server").unwrap();
    let mut doc = tpl.document.clone();
    doc["service"][0]["serviceEndpoint"][0]["extra"] =
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
