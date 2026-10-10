//! What one issuance may do, and whether a binding allows it.
//!
//! Every value checked here ends up inside a provider policy, a presigned URL
//! or a canonical request, so each is validated against a closed character
//! class rather than trusted to the schema alone. The schema patterns are the
//! first line; these are the second, because a custodian that relied on the
//! payload validator being configured would interpolate whatever reached it
//! the day it was not. CVE-2026-42811 is that defect in a downscoped GCS
//! credential path.

use serde::{Deserialize, Serialize};

use crate::model::{Binding, ScopeCeiling};

/// The object actions a storage scope may name.
pub const ACTIONS: &[&str] = &["put", "get", "delete"];

/// A requested scope (`CredentialScope`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestedScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

/// Why a scope was refused, in the order the issue specification checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeRefusal {
    /// A value is malformed: not a prefix, not an action, not an object key.
    Malformed(String),
    /// `external/credentials/issue:scopeOutsideCeiling`.
    OutsideCeiling(String),
    /// `external/credentials/issue:ttlTooLong`.
    TtlTooLong { requested: u32, max: u32 },
}

impl std::fmt::Display for ScopeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) | Self::OutsideCeiling(m) => f.write_str(m),
            Self::TtlTooLong { requested, max } => write!(
                f,
                "ttlSeconds {requested} exceeds the binding's maxTtlSeconds {max}"
            ),
        }
    }
}

/// `ProviderObjectPrefix`: 1–16 segments of `[a-z0-9][a-z0-9._-]{0,127}`, each
/// ending `/`, at most 512 bytes. No quote, backslash, wildcard, whitespace or
/// empty segment can pass.
pub fn validate_prefix(prefix: &str) -> Result<(), ScopeRefusal> {
    let bad = |why: &str| ScopeRefusal::Malformed(format!("prefix {prefix:?}: {why}"));
    if prefix.len() < 2 || prefix.len() > 512 {
        return Err(bad("must be 2 to 512 bytes"));
    }
    let Some(body) = prefix.strip_suffix('/') else {
        return Err(bad("must end with '/'"));
    };
    let segments: Vec<&str> = body.split('/').collect();
    if segments.len() > 16 {
        return Err(bad("more than 16 segments"));
    }
    for seg in segments {
        let mut chars = seg.chars();
        let Some(first) = chars.next() else {
            return Err(bad("empty segment"));
        };
        if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
            return Err(bad("a segment must begin with a lowercase letter or digit"));
        }
        if seg.len() > 128 {
            return Err(bad("a segment is longer than 128 bytes"));
        }
        if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c)) {
            return Err(bad(
                "only lowercase letters, digits, '.', '_' and '-' are allowed",
            ));
        }
    }
    Ok(())
}

/// `CredentialScope.objectKey`: `[A-Za-z0-9._-]+`, at most 1024 bytes, and
/// never `.` or `..`, which a provider would resolve as a path step.
pub fn validate_object_key(key: &str) -> Result<(), ScopeRefusal> {
    let ok = !key.is_empty()
        && key.len() <= 1024
        && key != "."
        && key != ".."
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    if ok {
        Ok(())
    } else {
        Err(ScopeRefusal::Malformed(format!(
            "objectKey {key:?} must be letters, digits, '.', '_' or '-'"
        )))
    }
}

fn validate_actions(actions: &[String]) -> Result<(), ScopeRefusal> {
    for a in actions {
        if !ACTIONS.contains(&a.as_str()) {
            return Err(ScopeRefusal::Malformed(format!("unknown action {a:?}")));
        }
    }
    Ok(())
}

/// Check a requested scope against `binding`, as items 4 and 5 of the issue
/// specification require, for an account of `model`.
///
/// `ttl_seconds` is checked after the scope, so a request wrong on both counts
/// is told about the scope — the one that says more about the caller.
pub fn check_against_binding(
    model: &str,
    binding: &Binding,
    scope: &RequestedScope,
    ttl_seconds: u32,
) -> Result<(), ScopeRefusal> {
    validate_actions(&scope.actions)?;
    let outside = |why: String| ScopeRefusal::OutsideCeiling(why);
    let empty = ScopeCeiling::default();
    let ceiling = binding.scope_ceiling.as_ref().unwrap_or(&empty);

    let storage = matches!(
        model,
        "s3-static-presign" | "aws-roles-anywhere" | "gcp-wif-pinned"
    );
    if storage {
        let Some(prefix) = scope.prefix.as_deref() else {
            return Err(ScopeRefusal::Malformed(
                "a storage scope needs a prefix".into(),
            ));
        };
        validate_prefix(prefix)?;
        if scope.actions.is_empty() {
            return Err(ScopeRefusal::Malformed(
                "a storage scope needs at least one action".into(),
            ));
        }
        if !ceiling
            .prefixes
            .iter()
            .any(|p| prefix.starts_with(p.as_str()))
        {
            return Err(outside(format!(
                "prefix {prefix:?} is under none of the binding's prefixes"
            )));
        }
        if let Some(a) = scope.actions.iter().find(|a| !ceiling.actions.contains(a)) {
            return Err(outside(format!(
                "action {a:?} is outside the binding's ceiling"
            )));
        }
        if !scope.scopes.is_empty() {
            return Err(ScopeRefusal::Malformed(
                "OAuth scopes do not apply to a storage model".into(),
            ));
        }
    }
    if model == "s3-static-presign" {
        if scope.actions.len() != 1 {
            return Err(outside(
                "a presigned URL is one operation: name exactly one action".into(),
            ));
        }
        let Some(key) = scope.object_key.as_deref() else {
            return Err(outside(
                "a presigned URL is one object: name an objectKey".into(),
            ));
        };
        validate_object_key(key)?;
    } else if scope.object_key.is_some() {
        return Err(ScopeRefusal::Malformed(
            "objectKey applies only to s3-static-presign".into(),
        ));
    }
    if model == "oauth2-private-key-jwt"
        && let Some(s) = scope.scopes.iter().find(|s| !ceiling.scopes.contains(s))
    {
        return Err(outside(format!(
            "OAuth scope {s:?} is outside the binding's ceiling"
        )));
    }

    if ttl_seconds > binding.max_ttl_seconds {
        return Err(ScopeRefusal::TtlTooLong {
            requested: ttl_seconds,
            max: binding.max_ttl_seconds,
        });
    }
    Ok(())
}

/// Whether `ceiling` is coherent for an account of `model`: a storage model
/// needs prefixes and actions, every prefix and action well formed.
pub fn validate_ceiling(model: &str, ceiling: Option<&ScopeCeiling>) -> Result<(), String> {
    let storage = matches!(
        model,
        "s3-static-presign" | "aws-roles-anywhere" | "gcp-wif-pinned"
    );
    match (storage, ceiling) {
        (true, None) => Err("a storage model's binding needs a scopeCeiling".into()),
        (true, Some(c)) if c.prefixes.is_empty() || c.actions.is_empty() => {
            Err("a storage model's scopeCeiling needs prefixes and actions".into())
        }
        (_, Some(c)) => {
            for p in &c.prefixes {
                validate_prefix(p).map_err(|e| e.to_string())?;
            }
            validate_actions(&c.actions).map_err(|e| e.to_string())
        }
        (false, None) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Binding {
        Binding {
            consumer: "did:key:z6Mkc".into(),
            scope_ceiling: Some(ScopeCeiling {
                prefixes: vec!["rooms/".into()],
                actions: vec!["put".into(), "get".into()],
                scopes: vec![],
            }),
            max_ttl_seconds: 900,
            rate_per_minute: 10,
            source_cidrs: vec![],
            granted_at: None,
        }
    }

    fn scope(prefix: &str, action: &str, key: Option<&str>) -> RequestedScope {
        RequestedScope {
            prefix: Some(prefix.into()),
            actions: vec![action.into()],
            object_key: key.map(str::to_string),
            scopes: vec![],
        }
    }

    #[test]
    fn prefixes_with_metacharacters_never_validate() {
        for bad in [
            "rooms",
            "/rooms/",
            "rooms//",
            "Rooms/",
            "rooms/*/",
            "rooms/a b/",
            "rooms/'/",
            "rooms/\")/",
            ".hidden/",
            "rooms/../",
        ] {
            assert!(validate_prefix(bad).is_err(), "{bad:?} validated");
        }
        validate_prefix("rooms/3f9a0c/").unwrap();
    }

    #[test]
    fn an_issuance_inside_the_ceiling_passes() {
        check_against_binding(
            "s3-static-presign",
            &binding(),
            &scope("rooms/3f9a/", "put", Some("blob.bin")),
            600,
        )
        .unwrap();
    }

    #[test]
    fn the_refusals_name_what_was_outside() {
        let b = binding();
        let m = "s3-static-presign";
        assert!(matches!(
            check_against_binding(m, &b, &scope("other/", "get", Some("k")), 60),
            Err(ScopeRefusal::OutsideCeiling(_))
        ));
        assert!(matches!(
            check_against_binding(m, &b, &scope("rooms/a/", "delete", Some("k")), 60),
            Err(ScopeRefusal::OutsideCeiling(_))
        ));
        assert!(matches!(
            check_against_binding(m, &b, &scope("rooms/a/", "get", None), 60),
            Err(ScopeRefusal::OutsideCeiling(_))
        ));
        assert!(matches!(
            check_against_binding(m, &b, &scope("rooms/a/", "get", Some("..")), 60),
            Err(ScopeRefusal::Malformed(_))
        ));
        assert_eq!(
            check_against_binding(m, &b, &scope("rooms/a/", "get", Some("k")), 901),
            Err(ScopeRefusal::TtlTooLong {
                requested: 901,
                max: 900
            })
        );
    }

    /// A storage binding with no prefixes permits no storage issuance.
    #[test]
    fn an_empty_ceiling_confers_nothing() {
        let mut b = binding();
        b.scope_ceiling = None;
        assert!(matches!(
            check_against_binding(
                "s3-static-presign",
                &b,
                &scope("rooms/", "get", Some("k")),
                60
            ),
            Err(ScopeRefusal::OutsideCeiling(_))
        ));
        assert!(validate_ceiling("s3-static-presign", None).is_err());
    }
}
