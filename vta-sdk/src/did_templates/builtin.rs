//! Built-in templates embedded at SDK compile time.
//!
//! Ship with the crate, always available, can't be tampered with. Operators
//! who want a customized shape fork a built-in to a stored (global or
//! context) template via the CLI's `init` subcommand and edit the JSON.

use serde_json::Value;

use super::{DidTemplate, TemplateError};

/// Names of every built-in template, in alphabetical order. Surfaced in
/// `BuiltinNotFound` errors so callers see what's available.
pub const BUILTIN_NAMES: &[&str] = &[
    "ai-agent",
    "ai-agent-peer",
    "ballot-box",
    "did-host-didcomm",
    "did-host-http",
    "did-host-http-didcomm",
    "did-host-http-tsp",
    "did-host-tsp",
    "didcomm-mediator",
    "dtg-witness",
    "push-gateway",
    "room",
    "room-host",
    "swiyu-verifier",
    "trust-registry",
    "vta-admin",
    "vtc-group",
    "vtc-host",
    "vtc-host-classical",
];

const AI_AGENT: &str = include_str!("../../templates/ai-agent.json");
const AI_AGENT_PEER: &str = include_str!("../../templates/ai-agent-peer.json");
const DIDCOMM_MEDIATOR: &str = include_str!("../../templates/didcomm-mediator.json");
const PUSH_GATEWAY: &str = include_str!("../../templates/push-gateway.json");
const ROOM: &str = include_str!("../../templates/room.json");
const ROOM_HOST: &str = include_str!("../../templates/room-host.json");
const SWIYU_VERIFIER: &str = include_str!("../../templates/swiyu-verifier.json");
const TRUST_REGISTRY: &str = include_str!("../../templates/trust-registry.json");
const VTA_ADMIN: &str = include_str!("../../templates/vta-admin.json");
const VTC_GROUP: &str = include_str!("../../templates/vtc-group.json");
const VTC_HOST: &str = include_str!("../../templates/vtc-host.json");
const DID_HOST_HTTP_DIDCOMM: &str = include_str!("../../templates/did-host-http-didcomm.json");
const DID_HOST_HTTP: &str = include_str!("../../templates/did-host-http.json");
const DID_HOST_DIDCOMM: &str = include_str!("../../templates/did-host-didcomm.json");
const DID_HOST_HTTP_TSP: &str = include_str!("../../templates/did-host-http-tsp.json");
const DID_HOST_TSP: &str = include_str!("../../templates/did-host-tsp.json");
const DTG_WITNESS: &str = include_str!("../../templates/dtg-witness.json");
const BALLOT_BOX: &str = include_str!("../../templates/ballot-box.json");

/// Load a built-in template by name. Returns [`TemplateError::BuiltinNotFound`]
/// for any name not in [`BUILTIN_NAMES`]. The legacy `webvh-*` / `did-hosting-*`
/// aliases were removed — operator configs must use the canonical `did-host-*`
/// names.
pub fn load_embedded(name: &str) -> Result<DidTemplate, TemplateError> {
    let raw = match name {
        "ai-agent" => AI_AGENT,
        "ai-agent-peer" => AI_AGENT_PEER,
        "didcomm-mediator" => DIDCOMM_MEDIATOR,
        "push-gateway" => PUSH_GATEWAY,
        "room" => ROOM,
        "room-host" => ROOM_HOST,
        "swiyu-verifier" => SWIYU_VERIFIER,
        "trust-registry" => TRUST_REGISTRY,
        "vta-admin" => VTA_ADMIN,
        "vtc-group" => VTC_GROUP,
        "vtc-host" => VTC_HOST,
        "did-host-http-didcomm" => DID_HOST_HTTP_DIDCOMM,
        "did-host-http" => DID_HOST_HTTP,
        "did-host-didcomm" => DID_HOST_DIDCOMM,
        "did-host-http-tsp" => DID_HOST_HTTP_TSP,
        "did-host-tsp" => DID_HOST_TSP,
        "dtg-witness" => DTG_WITNESS,
        "ballot-box" => BALLOT_BOX,
        "vtc-host-classical" => return vtc_host_classical(),
        _ => return Err(TemplateError::BuiltinNotFound(name.to_string())),
    };
    let value: serde_json::Value = serde_json::from_str(raw)?;
    DidTemplate::from_json(value)
}

/// The `vtc-host` slot `vtc-host-classical` leaves out.
pub(super) const VTC_HOST_PQ_SLOT: &str = "pq-signing";

/// `vtc-host` without its post-quantum second signing key: the VTC identity a
/// DID method that holds one signing key can carry.
///
/// A level-1 `did:webs` holds exactly one key-state signing key, and the
/// specification refuses a template with a second signing slot rather than
/// letting the VTA drop it (CONVENTIONS.md 0.2 §9.2: "a second slot of either
/// purpose" is `keyAlgorithm`, and a VTA "MUST NOT publish a document that
/// drops … anything the template described"; the template `keys` block has no
/// optional slot either, `vta/did-templates/*` 3.1). So the VTC that cannot
/// hold the key names a template that does not ask for it.
///
/// Derived from `vtc-host` at load rather than shipped as a second file, so the
/// two cannot drift: everything but the `pq-signing` slot, its verification
/// method and its `assertionMethod` reference is `vtc-host`'s own, and
/// `vtc_host_classical_is_vtc_host_without_the_post_quantum_key` pins that.
fn vtc_host_classical() -> Result<DidTemplate, TemplateError> {
    let mut value: Value = serde_json::from_str(VTC_HOST)?;
    without_key_slot(&mut value, VTC_HOST_PQ_SLOT)?;
    value["name"] = Value::from("vtc-host-classical");
    value["methods"] = serde_json::json!(["webvh", "web", "webs"]);
    value["description"] = Value::from(
        "Verifiable Trust Community (VTC) service identity with one signing key: vtc-host \
         without its post-quantum second signing key (pq-signing), so an Ed25519 signing key \
         (authentication and assertionMethod) and an X25519 key-agreement key, with every \
         vtc-host service and variable. For a VTC whose DID method holds one signing key — a \
         level-1 did:webs (CONVENTIONS.md 0.2 §9.2 refuses vtc-host's second signing slot) — \
         or a did:webvh VTC that chooses no post-quantum key. Every credential such a VTC \
         issues carries a single eddsa-jcs-2022 proof, as a vtc-host VTC does on a VTA that \
         falls back from ML-DSA. A post-quantum VTC identity is a did:webvh from vtc-host \
         until the did:webs key state, or its key-role designation, can carry such a key.",
    );
    DidTemplate::from_json(value)
}

/// Remove key slot `slot` from a raw template: the slot, every verification
/// method publishing its key, and every relationship entry naming one.
///
/// Refuses a template whose document uses the slot's placeholders anywhere
/// else — dropping the key there would change what the template describes.
fn without_key_slot(template: &mut Value, slot: &str) -> Result<(), TemplateError> {
    let invalid = |why: String| TemplateError::Invalid(format!("without slot '{slot}': {why}"));
    template
        .get_mut("keys")
        .and_then(Value::as_object_mut)
        .and_then(|keys| keys.remove(slot))
        .ok_or_else(|| invalid("the template declares no such slot".into()))?;
    let mb = format!("{{{}}}", DidTemplate::slot_var(slot));
    let jwk = format!("{{{}}}", DidTemplate::slot_var_jwk(slot));
    let publishes = |vm: &Value| {
        vm.get("publicKeyMultibase").and_then(Value::as_str) == Some(mb.as_str())
            || vm.get("publicKeyJwk").and_then(Value::as_str) == Some(jwk.as_str())
    };
    let document = template
        .get_mut("document")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid("the template has no document".into()))?;
    let mut ids = Vec::new();
    if let Some(vms) = document
        .get_mut("verificationMethod")
        .and_then(Value::as_array_mut)
    {
        vms.retain(|vm| {
            if !publishes(vm) {
                return true;
            }
            if let Some(id) = vm.get("id").and_then(Value::as_str) {
                ids.push(id.to_string());
            }
            false
        });
    }
    for relationship in [
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ] {
        if let Some(entries) = document.get_mut(relationship).and_then(Value::as_array_mut) {
            entries.retain(|e| match e {
                Value::String(r) => !ids.contains(r),
                other => !publishes(other),
            });
        }
    }
    let rest = serde_json::to_string(document).map_err(TemplateError::Json)?;
    if rest.contains(&mb) || rest.contains(&jwk) {
        return Err(invalid(
            "the document uses the slot's key outside a verification method".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// VTI-KEY-008 is withdrawn: every node resolves did:webs (VTI-KEY-003),
    /// so no built-in template declares `resolvedMethods` or defines its
    /// JSON-LD term.
    #[test]
    fn vti_key_008_withdrawn_no_builtin_declares_resolved_methods() {
        for name in BUILTIN_NAMES {
            let tpl = load_embedded(name).unwrap();
            let doc = serde_json::to_string(&tpl.document).unwrap();
            assert!(!doc.contains("resolvedMethods"), "{name}");
            let vars = serde_json::to_string(&tpl.optional_vars).unwrap_or_default();
            assert!(!vars.contains("RESOLVED_METHODS"), "{name}");
        }
    }

    #[test]
    fn every_builtin_parses_and_validates() {
        for name in BUILTIN_NAMES {
            let tpl = load_embedded(name)
                .unwrap_or_else(|e| panic!("builtin '{name}' failed to load: {e}"));
            assert_eq!(tpl.name, *name, "builtin name field must match lookup key");
        }
    }

    /// Every DID a built-in mints can sign an attestation: its document lists
    /// a key under `assertionMethod`. A persona signs `auth/oob/grant` for
    /// `assertionMethod` (VTI-KEY-106), and a service verifying it refuses a
    /// key not listed there (VTI-KEY-022), so a shape without one could never
    /// sign a member in.
    #[test]
    fn every_builtin_document_lists_an_assertion_method_key() {
        for name in BUILTIN_NAMES {
            let tpl = load_embedded(name).unwrap();
            let listed = tpl.document["assertionMethod"]
                .as_array()
                .is_some_and(|a| !a.is_empty());
            assert!(listed, "builtin '{name}' lists no assertionMethod key");
        }
    }

    /// `vtc-host-classical` is `vtc-host` less exactly the post-quantum slot,
    /// its verification method and its `assertionMethod` reference: rendered
    /// with the same variables, the two documents differ in nothing else.
    #[test]
    fn vtc_host_classical_is_vtc_host_without_the_post_quantum_key() {
        let full = load_embedded("vtc-host").unwrap();
        let classical = load_embedded("vtc-host-classical").unwrap();
        assert_eq!(classical.kind, "vtc-host", "still a VTC's node kind");
        assert_eq!(classical.required_vars, full.required_vars);
        assert_eq!(classical.optional_vars, full.optional_vars);
        assert_eq!(classical.defaults, full.defaults);
        let mut slots = full.key_slots();
        assert!(slots.remove(VTC_HOST_PQ_SLOT).is_some());
        assert_eq!(
            classical.key_slots().keys().collect::<Vec<_>>(),
            slots.keys().collect::<Vec<_>>()
        );

        let mut vars = super::super::TemplateVars::new();
        for (k, v) in [
            ("DID", "did:webvh:QmScid:vtc.example"),
            ("SIGNING_KEY_MB", "z6MkSigning"),
            ("KA_KEY_MB", "z6LSKa"),
            ("PQ_SIGNING_KEY_MB", "zPq"),
            ("URL", "https://vtc.example"),
        ] {
            vars.insert_string(k, v);
        }
        let mut want = full.render(&vars).unwrap();
        let pq = "did:webvh:QmScid:vtc.example#key-2";
        want["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .retain(|vm| vm["id"] != pq);
        want["assertionMethod"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r != pq);
        assert_eq!(classical.render(&vars).unwrap(), want);
    }

    #[test]
    fn a_slot_used_outside_a_verification_method_is_not_dropped() {
        let mut v: serde_json::Value = serde_json::from_str(VTC_HOST).unwrap();
        v["document"]["service"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({ "id": "{DID}#pq", "type": "X",
                                     "serviceEndpoint": "{PQ_SIGNING_KEY_MB}" }));
        assert!(matches!(
            without_key_slot(&mut v, VTC_HOST_PQ_SLOT),
            Err(TemplateError::Invalid(_))
        ));
        let mut v: serde_json::Value = serde_json::from_str(VTC_HOST).unwrap();
        assert!(matches!(
            without_key_slot(&mut v, "no-such-slot"),
            Err(TemplateError::Invalid(_))
        ));
    }

    #[test]
    fn unknown_builtin_errors() {
        let err = load_embedded("does-not-exist").unwrap_err();
        assert!(matches!(err, TemplateError::BuiltinNotFound(_)));
    }

    #[test]
    fn legacy_template_aliases_are_removed() {
        // The previous-generation `webvh-*` / `did-hosting-*` names no longer
        // resolve — operators must use the canonical `did-host-*` names.
        for old in [
            "webvh-control",
            "webvh-daemon",
            "webvh-server",
            "did-hosting-control",
            "did-hosting-daemon",
            "did-hosting-server",
        ] {
            assert!(
                matches!(load_embedded(old), Err(TemplateError::BuiltinNotFound(_))),
                "removed legacy alias '{old}' must no longer resolve"
            );
        }
        // The canonical names still load.
        for name in ["did-host-http-didcomm", "did-host-http", "did-host-didcomm"] {
            assert_eq!(load_embedded(name).unwrap().name, name);
        }
    }
}
