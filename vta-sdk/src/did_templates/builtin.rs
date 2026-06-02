//! Built-in templates embedded at SDK compile time.
//!
//! Ship with the crate, always available, can't be tampered with. Operators
//! who want a customized shape fork a built-in to a stored (global or
//! context) template via the CLI's `init` subcommand and edit the JSON.

use super::{DidTemplate, TemplateError};

/// Names of every built-in template, in alphabetical order. Surfaced in
/// `BuiltinNotFound` errors so callers see what's available.
pub const BUILTIN_NAMES: &[&str] = &[
    "did-host-didcomm",
    "did-host-http",
    "did-host-http-didcomm",
    "didcomm-mediator",
    "push-gateway",
    "vta-admin",
    "vtc-host",
];

/// Legacy template-name aliases retained for one release after a rename.
/// Each entry maps an old name to its canonical replacement; [`load_embedded`]
/// silently resolves an alias to the renamed template. Two rename
/// generations are covered: the original `webvh-*` names and the
/// service-named `did-hosting-*` names both resolve to the current
/// capability-named `did-host-*` templates. Removed in a later release
/// — update operator configs to use the canonical names.
const LEGACY_ALIASES: &[(&str, &str)] = &[
    ("webvh-control", "did-host-http-didcomm"),
    ("webvh-daemon", "did-host-http"),
    ("webvh-server", "did-host-didcomm"),
    ("did-hosting-control", "did-host-http-didcomm"),
    ("did-hosting-daemon", "did-host-http"),
    ("did-hosting-server", "did-host-didcomm"),
];

const DIDCOMM_MEDIATOR: &str = include_str!("../../templates/didcomm-mediator.json");
const PUSH_GATEWAY: &str = include_str!("../../templates/push-gateway.json");
const VTA_ADMIN: &str = include_str!("../../templates/vta-admin.json");
const VTC_HOST: &str = include_str!("../../templates/vtc-host.json");
const DID_HOST_HTTP_DIDCOMM: &str = include_str!("../../templates/did-host-http-didcomm.json");
const DID_HOST_HTTP: &str = include_str!("../../templates/did-host-http.json");
const DID_HOST_DIDCOMM: &str = include_str!("../../templates/did-host-didcomm.json");

/// Resolve a legacy template-name alias to its canonical replacement.
/// Pure lookup — no I/O, no logging. Returns the input unchanged when
/// it isn't an alias.
fn resolve_alias(name: &str) -> &str {
    for (old, new) in LEGACY_ALIASES {
        if name == *old {
            return new;
        }
    }
    name
}

/// Load a built-in template by name. Returns [`TemplateError::BuiltinNotFound`]
/// for any name not in [`BUILTIN_NAMES`]. Legacy `webvh-*` and `did-hosting-*`
/// aliases are silently resolved to their `did-host-*` canonical names for
/// the deprecation window — the returned `DidTemplate.name` is always the
/// canonical name.
pub fn load_embedded(name: &str) -> Result<DidTemplate, TemplateError> {
    let canonical = resolve_alias(name);
    let raw = match canonical {
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
    fn legacy_aliases_resolve_to_did_host_canonical() {
        // Operators on either previous template-name generation keep
        // working for one release. The returned template carries the
        // canonical name — any caller round-tripping `tpl.name` writes
        // back the new name.
        for (old, new) in [
            // First generation: webvh-*
            ("webvh-control", "did-host-http-didcomm"),
            ("webvh-daemon", "did-host-http"),
            ("webvh-server", "did-host-didcomm"),
            // Second generation: did-hosting-*
            ("did-hosting-control", "did-host-http-didcomm"),
            ("did-hosting-daemon", "did-host-http"),
            ("did-hosting-server", "did-host-didcomm"),
        ] {
            let tpl = load_embedded(old)
                .unwrap_or_else(|e| panic!("legacy alias '{old}' failed to resolve: {e}"));
            assert_eq!(
                tpl.name, new,
                "legacy alias '{old}' must surface the canonical name '{new}'"
            );
        }
    }
}
