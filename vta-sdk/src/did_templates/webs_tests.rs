//! CONVENTIONS.md §9.2, rule by rule: each refusal `reason` with the members it
//! names, and the built-ins as they stand today.

use serde_json::{Value, json};

use super::*;
use crate::did_templates::{TemplateVars, load_embedded};

const DID: &str = "did:webs:hosting.example:people:EAid0000000000000000000000000000000000000000";
const SIGNING_MB: &str = "z6MkSigningKeyForTheTest";
const KA_MB: &str = "z6LSKeyAgreementKeyForTheTest";

fn keys() -> WebsRenderedKeys {
    WebsRenderedKeys {
        signing: RenderedKey {
            multibase: SIGNING_MB.into(),
            jwk: Some(json!({ "kty": "OKP", "crv": "Ed25519", "x": "sig" })),
        },
        key_agreement: RenderedKey {
            multibase: KA_MB.into(),
            jwk: Some(json!({ "kty": "OKP", "crv": "X25519", "x": "ka" })),
        },
    }
}

/// A template that is representable: every member is one the derivation
/// renders.
fn representable() -> Value {
    json!({
        "schemaVersion": 1,
        "name": "webs-ok",
        "kind": "custom",
        "requiredVars": ["MEDIATOR_DID"],
        "document": {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "{DID}",
            "verificationMethod": [
                { "id": "{DID}#key-0", "type": "Multikey", "controller": "{DID}",
                  "publicKeyMultibase": "{SIGNING_KEY_MB}" },
                { "id": "{DID}#key-1", "type": "Multikey", "controller": "{DID}",
                  "publicKeyMultibase": "{KA_KEY_MB}" }
            ],
            "authentication": ["{DID}#key-0"],
            "assertionMethod": ["#key-0"],
            "keyAgreement": ["{DID}#key-1"],
            "service": [
                { "id": "{DID}#tsp", "type": "TSPTransport", "serviceEndpoint": "{MEDIATOR_DID}" }
            ],
            "alsoKnownAs": ["{DID}", "did:webvh:QmScid:example.com:alice"]
        }
    })
}

fn render(template: &Value) -> (DidTemplate, Value) {
    let t = DidTemplate::from_json(template.clone()).expect("template");
    // Every slot's placeholder, as the engine supplies them: a signing slot
    // renders the signing key, a key agreement slot the key agreement key.
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", DID);
    for (slot, spec) in t.key_slots() {
        let mb = match spec.purpose {
            KeyPurpose::Signing => SIGNING_MB,
            KeyPurpose::KeyAgreement => KA_MB,
        };
        vars.insert_string(DidTemplate::slot_var(&slot), mb);
    }
    vars.insert_string("MEDIATOR_DID", "did:peer:2.mediator");
    let rendered = t.render(&vars).expect("render");
    (t, rendered)
}

fn check(template: &Value) -> Result<WebsDesignations, WebsTemplateRefusal> {
    let (t, rendered) = render(template);
    map_webs_document(&t, &rendered, DID, &keys())
}

fn refusal(template: &Value) -> (NotRepresentableReason, Vec<String>) {
    match check(template) {
        Err(WebsTemplateRefusal::NotRepresentable(n)) => (n.reason, n.members),
        other => panic!("expected templateNotRepresentable, got {other:?}"),
    }
}

#[test]
fn a_representable_template_maps_onto_its_designations() {
    let d = check(&representable()).expect("representable");
    assert_eq!(
        d.services,
        vec![
            json!({ "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:peer:2.mediator" })
        ]
    );
    assert_eq!(
        d.also_known_as,
        vec!["did:webvh:QmScid:example.com:alice".to_string()],
        "the DID itself is listed once, by the derivation"
    );
}

/// An operator-uploaded template written while VTI-KEY-008 stood still
/// carries `resolvedMethods` (and its `@context` term). The declaration is
/// withdrawn, but such a template keeps working: the member is ignored, not
/// refused (CONVENTIONS.md 0.2 §9.2).
#[test]
fn vti_key_008_withdrawn_an_old_template_carrying_resolved_methods_still_works() {
    let mut t = representable();
    t["document"]["resolvedMethods"] = json!(["webs"]);
    t["document"]["@context"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "resolvedMethods": {
            "@id": "https://w3id.org/vti#resolvedMethods", "@type": "@json"
        } }));
    assert_eq!(check(&t), check(&representable()));
}

#[test]
fn a_verification_method_may_publish_its_key_as_a_jwk() {
    let mut t = representable();
    t["document"]["verificationMethod"][0] = json!({
        "id": "{DID}#key-0", "type": "JsonWebKey", "publicKeyJwk": "{SIGNING_KEY_JWK}"
    });
    let tpl = DidTemplate::from_json(t).expect("template");
    let mut vars = TemplateVars::new();
    vars.insert_string("DID", DID);
    vars.insert("SIGNING_KEY_JWK", keys().signing.jwk.unwrap());
    vars.insert_string("KA_KEY_MB", KA_MB);
    vars.insert_string("MEDIATOR_DID", "did:peer:2.mediator");
    let rendered = tpl.render(&vars).expect("render");
    assert!(map_webs_document(&tpl, &rendered, DID, &keys()).is_ok());
}

/// Each §9.2 rule, and the members it names.
#[test]
fn each_rule_refuses_with_its_reason_and_members() {
    type Edit = fn(&mut Value);
    let cases: &[(&str, Edit, NotRepresentableReason, &[&str])] = &[
        (
            "a second signing slot, and an unpublished signing key",
            |t| {
                t["schemaVersion"] = json!(2);
                t["keys"] = json!({
                    "signing": { "purpose": "signing", "algorithms": ["ed25519"], "publish": false },
                    "ka": { "purpose": "keyAgreement", "algorithms": ["x25519"] },
                    "verifier": { "purpose": "signing", "algorithms": ["p256"] }
                });
                t["document"]["verificationMethod"][0]["publicKeyMultibase"] =
                    json!("{VERIFIER_KEY_MB}");
            },
            NotRepresentableReason::KeyAlgorithm,
            &["/keys/signing", "/keys/verifier"],
        ),
        (
            "a signing slot without Ed25519",
            |t| {
                t["schemaVersion"] = json!(2);
                t["keys"] = json!({
                    "signing": { "purpose": "signing", "algorithms": ["mldsa44"] },
                    "ka": { "purpose": "keyAgreement", "algorithms": ["x25519"] }
                });
            },
            NotRepresentableReason::KeyAlgorithm,
            &["/keys/signing"],
        ),
        (
            // Template validation already requires `{DID}` in the id; one that
            // renders to something else is still not the DID.
            "an id that is not the DID",
            |t| t["document"]["id"] = json!("{DID}:other"),
            NotRepresentableReason::DocumentId,
            &["/document/id"],
        ),
        (
            "another controller",
            |t| t["document"]["controller"] = json!("did:example:other"),
            NotRepresentableReason::Controller,
            &["/document/controller"],
        ),
        (
            "a further verification method",
            |t| {
                t["document"]["verificationMethod"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({ "id": "{DID}#key-2", "type": "Multikey",
                                  "publicKeyMultibase": "z6MkAnotherKey" }));
            },
            NotRepresentableReason::VerificationMethod,
            &["/document/verificationMethod/2"],
        ),
        (
            "the signing key published twice",
            |t| {
                t["document"]["verificationMethod"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({ "id": "{DID}#key-2", "type": "Multikey",
                                  "publicKeyMultibase": "{SIGNING_KEY_MB}" }));
            },
            NotRepresentableReason::VerificationMethod,
            &["/document/verificationMethod/2"],
        ),
        (
            "assertionMethod without the signing key",
            |t| t["document"]["assertionMethod"] = json!(["{DID}#key-1"]),
            NotRepresentableReason::VerificationRelationship,
            &["/document/assertionMethod/0"],
        ),
        (
            "no authentication",
            |t| {
                t["document"]
                    .as_object_mut()
                    .unwrap()
                    .remove("authentication");
            },
            NotRepresentableReason::VerificationRelationship,
            &["/document/authentication"],
        ),
        (
            "no keyAgreement",
            |t| {
                t["document"]
                    .as_object_mut()
                    .unwrap()
                    .remove("keyAgreement");
            },
            NotRepresentableReason::KeyAgreementRequired,
            &["/document/keyAgreement"],
        ),
        (
            "keyAgreement listing the signing key",
            |t| t["document"]["keyAgreement"] = json!(["{DID}#key-1", "{DID}#key-0"]),
            NotRepresentableReason::VerificationRelationship,
            &["/document/keyAgreement/1"],
        ),
        (
            "capabilityInvocation",
            |t| t["document"]["capabilityInvocation"] = json!(["{DID}#key-0"]),
            NotRepresentableReason::VerificationRelationship,
            &["/document/capabilityInvocation"],
        ),
        (
            "a service of another DID",
            |t| t["document"]["service"][0]["id"] = json!("did:example:other#tsp"),
            NotRepresentableReason::Service,
            &["/document/service/0"],
        ),
        (
            "a service without an endpoint",
            |t| {
                t["document"]["service"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("serviceEndpoint");
            },
            NotRepresentableReason::Service,
            &["/document/service/0"],
        ),
        (
            "an alias that is not a DID",
            |t| t["document"]["alsoKnownAs"] = json!(["https://alice.example"]),
            NotRepresentableReason::Alias,
            &["/document/alsoKnownAs/0"],
        ),
        (
            "a member the derivation does not render",
            |t| t["document"]["keyAssurance"] = json!(2),
            NotRepresentableReason::DocumentMember,
            &["/document/keyAssurance"],
        ),
    ];
    for (what, edit, reason, members) in cases {
        let mut t = representable();
        edit(&mut t);
        let (got, got_members) = refusal(&t);
        assert_eq!(got, *reason, "{what}");
        assert_eq!(got_members, *members, "{what}");
    }
}

#[test]
fn a_key_role_template_is_refused_before_anything_else() {
    let (mut t, rendered) = render(&representable());
    t.schema_version = 3;
    match map_webs_document(&t, &rendered, DID, &keys()) {
        Err(WebsTemplateRefusal::NotRepresentable(n)) => {
            assert_eq!(n.reason, NotRepresentableReason::KeyRoleTemplate);
            assert_eq!(n.members, ["/schemaVersion"]);
            assert_eq!(n.details()["reason"], "keyRoleTemplate");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn two_services_with_one_id_are_a_service_id_conflict() {
    let mut t = representable();
    t["document"]["service"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "x" }));
    assert_eq!(
        check(&t),
        Err(WebsTemplateRefusal::ServiceIdConflict { id: "#tsp".into() })
    );
}

/// What the built-ins are: the node templates are representable unless
/// something other than their document members refuses them.
#[test]
fn the_builtins_as_section_9_2_reads_them_today() {
    let cases: &[(&str, Option<(NotRepresentableReason, &[&str])>)] = &[
        ("ai-agent", None),
        ("room", None),
        ("dtg-witness", None),
        ("did-host-tsp", None),
        (
            "swiyu-verifier",
            Some((
                NotRepresentableReason::KeyAlgorithm,
                &["/keys/signing", "/keys/verifier"],
            )),
        ),
        (
            "vta-admin",
            Some((
                NotRepresentableReason::KeyAgreementRequired,
                &["/document/verificationMethod"],
            )),
        ),
    ];
    for (name, want) in cases {
        let t = load_embedded(name).expect("builtin");
        if let Err(e) = check_key_shape(&t) {
            let (reason, members) = want.expect(name);
            assert_eq!(e.reason, reason, "{name}");
            assert_eq!(e.members, members, "{name}");
            continue;
        }
        let mut vars = TemplateVars::new();
        for (k, v) in [
            ("DID", DID),
            ("SIGNING_KEY_MB", SIGNING_MB),
            ("KA_KEY_MB", KA_MB),
            ("MEDIATOR_DID", "did:peer:2.mediator"),
            ("WEBVH_SERVER", "host-1"),
            ("URL", "https://host.example"),
        ] {
            vars.insert_string(k, v);
        }
        let rendered = t.render(&vars).expect(name);
        match (map_webs_document(&t, &rendered, DID, &keys()), want) {
            (Ok(_), None) => {}
            (Err(WebsTemplateRefusal::NotRepresentable(n)), Some((reason, members))) => {
                assert_eq!(n.reason, *reason, "{name}");
                assert_eq!(n.members, *members, "{name}");
            }
            (got, want) => panic!("{name}: got {got:?}, want {want:?}"),
        }
    }
}

#[test]
fn node_kinds_are_the_ones_that_name_only_a_node() {
    for k in ["mediator", "dtg-witness", "vtc-host", "did-host-tsp"] {
        assert!(is_node_kind(k), "{k}");
    }
    for k in [
        "ai-agent",
        "room",
        "group",
        "admin",
        "custom",
        "oid4vp-verifier",
    ] {
        assert!(!is_node_kind(k), "{k}");
    }
}

#[test]
fn undeclared_variables_are_named() {
    let t = load_embedded("dtg-witness").unwrap();
    assert_eq!(
        t.undeclared_vars(["MEDIATOR_DID", "ACCEPT", "DID", "BOGUS"]),
        ["BOGUS", "DID"]
    );
}
