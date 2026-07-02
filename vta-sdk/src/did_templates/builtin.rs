//! Built-in templates embedded at SDK compile time.
//!
//! Ship with the crate, always available, can't be tampered with. Operators
//! who want a customized shape fork a built-in to a stored (global or
//! context) template via the CLI's `init` subcommand and edit the JSON.

use super::{DidTemplate, TemplateError};

/// Names of every built-in template, in alphabetical order. Surfaced in
/// `BuiltinNotFound` errors so callers see what's available.
pub const BUILTIN_NAMES: &[&str] = &[
    "ai-agent",
    "ai-agent-peer",
    "did-host-didcomm",
    "did-host-http",
    "did-host-http-didcomm",
    "didcomm-mediator",
    "push-gateway",
    "vta-admin",
    "vtc-host",
];

const AI_AGENT: &str = include_str!("../../templates/ai-agent.json");
const AI_AGENT_PEER: &str = include_str!("../../templates/ai-agent-peer.json");
const DIDCOMM_MEDIATOR: &str = include_str!("../../templates/didcomm-mediator.json");
const PUSH_GATEWAY: &str = include_str!("../../templates/push-gateway.json");
const VTA_ADMIN: &str = include_str!("../../templates/vta-admin.json");
const VTC_HOST: &str = include_str!("../../templates/vtc-host.json");
const DID_HOST_HTTP_DIDCOMM: &str = include_str!("../../templates/did-host-http-didcomm.json");
const DID_HOST_HTTP: &str = include_str!("../../templates/did-host-http.json");
const DID_HOST_DIDCOMM: &str = include_str!("../../templates/did-host-didcomm.json");

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
        "vta-admin" => VTA_ADMIN,
        "vtc-host" => VTC_HOST,
        "did-host-http-didcomm" => DID_HOST_HTTP_DIDCOMM,
        "did-host-http" => DID_HOST_HTTP,
        "did-host-didcomm" => DID_HOST_DIDCOMM,
        _ => return Err(TemplateError::BuiltinNotFound(name.to_string())),
    };
    let value: serde_json::Value = serde_json::from_str(raw)?;
    DidTemplate::from_json(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_parses_and_validates() {
        for name in BUILTIN_NAMES {
            let tpl = load_embedded(name)
                .unwrap_or_else(|e| panic!("builtin '{name}' failed to load: {e}"));
            assert_eq!(tpl.name, *name, "builtin name field must match lookup key");
        }
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
