//! Helpers for the `WEBVH_SERVER` / `WEBVH_PATH` / `WEBVH_DOMAIN`
//! template variables — the "transport metadata" vars that control
//! where the VTA publishes the integration's `did.jsonl` log. These
//! are *not* document content; they never reach the template renderer.
//!
//! The rest of the provision-integration flow treats webvh-hosted and
//! serverless integrations uniformly; these helpers are the only
//! places that know about the `WEBVH_*` var names.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::AppError;

/// Read the optional `WEBVH_SERVER` template var, validate it against
/// the registered-server catalogue, and return the resolved id.
///
/// Returns `Ok(None)` when the var is absent, JSON-null, or the empty
/// string (treated as "not set"). Returns `Err(AppError::NotFound)` when
/// the var names an id that isn't registered with this VTA — caller
/// surfaces that to the operator before any state is written.
pub(super) async fn resolve_webvh_server(
    template_vars: &BTreeMap<String, Value>,
    webvh_ks: &crate::store::KeyspaceHandle,
) -> Result<Option<String>, AppError> {
    let raw = match template_vars.get("WEBVH_SERVER") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s,
        Some(other) => {
            let actual = match other {
                Value::Bool(_) => "bool",
                Value::Number(_) => "number",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
                _ => "non-string",
            };
            return Err(AppError::Validation(format!(
                "WEBVH_SERVER must be a string (registered webvh-server id), got {actual}"
            )));
        }
    };
    let id = raw.trim();
    if id.is_empty() {
        return Ok(None);
    }
    if crate::webvh_store::get_server(webvh_ks, id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound(format!(
            "WEBVH_SERVER '{id}' is not a registered webvh hosting server on this VTA \
             — register it via `vta webvh add-server` first, or omit `WEBVH_SERVER` \
             to self-host at the URL"
        )));
    }
    Ok(Some(id.to_string()))
}

/// Remove and return the optional `WEBVH_PATH` template var.
///
/// `WEBVH_PATH` is transport metadata — it tells the webvh server which
/// path to allocate when the VTA calls `POST /api/dids`. It is removed
/// from `template_vars` before the renderer sees the map so that a
/// template author never accidentally picks it up as document content.
///
/// `Ok(None)` when the var is absent or JSON-null. `Ok(Some(path))` when
/// it is a non-empty string. Empty strings and non-string types fail
/// loud — the operator set the var intentionally and a silent fallback
/// would mask a typo.
pub(super) fn take_webvh_path(
    template_vars: &mut BTreeMap<String, Value>,
) -> Result<Option<String>, AppError> {
    let removed = match template_vars.remove("WEBVH_PATH") {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let s = match removed {
        Value::String(s) => s,
        _ => {
            return Err(AppError::Validation(
                "WEBVH_PATH must be a non-empty string".into(),
            ));
        }
    };
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation(
            "WEBVH_PATH must be a non-empty string".into(),
        ));
    }
    Ok(Some(trimmed.to_string()))
}

/// Defense-in-depth fallback: derive a `WEBVH_PATH` from the `URL`
/// template var when the operator folded the DID path into the URL but
/// did not set `WEBVH_PATH` explicitly.
///
/// Server-managed mode reads `WEBVH_PATH` and ignores `URL`, so a
/// consumer that only set `URL` (`https://host.example.com/dids/daemon`)
/// would otherwise hand the hosting server an empty path and get
/// `e.p.did.path-invalid`. This reads `URL` (without removing it) and
/// returns the path component for the caller to use as a fallback.
///
/// Read-only and conservative: bare origins, empty paths and
/// `.well-known` (the webvh log marker, never a DID path) → `None`,
/// letting the server run its own allocation. Mirrors the SDK-side
/// `runner::webvh_path_from_url` so both layers agree on the derivation.
pub(super) fn webvh_path_from_url_var(template_vars: &BTreeMap<String, Value>) -> Option<String> {
    let url = template_vars.get("URL").and_then(|v| v.as_str())?;
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path = after_scheme.split_once('/').map_or("", |(_, p)| p);
    let path = path.split(['?', '#']).next().unwrap_or("");
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() || trimmed == ".well-known" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Remove and return the optional `WEBVH_DOMAIN` template var.
///
/// `WEBVH_DOMAIN` is transport metadata — it tells the webvh hosting
/// server which of its tenant domains to allocate the DID under (the
/// `did:webvh:<scid>:<host>` host slot). Like `WEBVH_PATH` it is removed
/// from `template_vars` before the renderer sees the map so a template
/// author never picks it up as document content.
///
/// `Ok(None)` when the var is absent or JSON-null — the remote server
/// then runs its own resolution chain (caller's ACL default → system
/// default). `Ok(Some(domain))` when it is a non-empty string. Empty
/// strings and non-string types fail loud, matching [`take_webvh_path`].
pub(super) fn take_webvh_domain(
    template_vars: &mut BTreeMap<String, Value>,
) -> Result<Option<String>, AppError> {
    let removed = match template_vars.remove("WEBVH_DOMAIN") {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let s = match removed {
        Value::String(s) => s,
        _ => {
            return Err(AppError::Validation(
                "WEBVH_DOMAIN must be a non-empty string".into(),
            ));
        }
    };
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation(
            "WEBVH_DOMAIN must be a non-empty string".into(),
        ));
    }
    Ok(Some(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vars(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn take_webvh_domain_absent_is_none() {
        let mut v = vars(&[]);
        assert_eq!(take_webvh_domain(&mut v).unwrap(), None);
    }

    #[test]
    fn take_webvh_domain_null_is_none() {
        let mut v = vars(&[("WEBVH_DOMAIN", Value::Null)]);
        assert_eq!(take_webvh_domain(&mut v).unwrap(), None);
    }

    #[test]
    fn take_webvh_domain_trims_and_returns() {
        let mut v = vars(&[("WEBVH_DOMAIN", json!("  acme.example.com "))]);
        assert_eq!(
            take_webvh_domain(&mut v).unwrap(),
            Some("acme.example.com".to_string())
        );
    }

    #[test]
    fn take_webvh_domain_removes_from_map() {
        // Must be stripped before the renderer sees the var — it's
        // transport metadata, not document content.
        let mut v = vars(&[("WEBVH_DOMAIN", json!("acme.example.com"))]);
        let _ = take_webvh_domain(&mut v).unwrap();
        assert!(!v.contains_key("WEBVH_DOMAIN"));
    }

    #[test]
    fn take_webvh_domain_empty_string_errors() {
        let mut v = vars(&[("WEBVH_DOMAIN", json!("   "))]);
        assert!(matches!(
            take_webvh_domain(&mut v),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn take_webvh_domain_non_string_errors() {
        let mut v = vars(&[("WEBVH_DOMAIN", json!(42))]);
        assert!(matches!(
            take_webvh_domain(&mut v),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn webvh_path_from_url_var_absent_is_none() {
        let v = vars(&[]);
        assert_eq!(webvh_path_from_url_var(&v), None);
    }

    #[test]
    fn webvh_path_from_url_var_bare_origin_is_none() {
        let v = vars(&[("URL", json!("https://host.example.com"))]);
        assert_eq!(webvh_path_from_url_var(&v), None);
        let v = vars(&[("URL", json!("https://host.example.com/"))]);
        assert_eq!(webvh_path_from_url_var(&v), None);
    }

    #[test]
    fn webvh_path_from_url_var_well_known_is_none() {
        // `.well-known` is the webvh log marker, never a DID path.
        let v = vars(&[("URL", json!("https://host.example.com/.well-known"))]);
        assert_eq!(webvh_path_from_url_var(&v), None);
    }

    #[test]
    fn webvh_path_from_url_var_single_segment() {
        let v = vars(&[("URL", json!("https://host.example.com/webvh"))]);
        assert_eq!(webvh_path_from_url_var(&v), Some("webvh".to_string()));
    }

    #[test]
    fn webvh_path_from_url_var_multi_segment() {
        let v = vars(&[("URL", json!("https://host.example.com/dids/daemon"))]);
        assert_eq!(webvh_path_from_url_var(&v), Some("dids/daemon".to_string()));
    }

    #[test]
    fn webvh_path_from_url_var_strips_query_and_fragment() {
        let v = vars(&[(
            "URL",
            json!("https://host.example.com/dids/daemon?x=1#frag"),
        )]);
        assert_eq!(webvh_path_from_url_var(&v), Some("dids/daemon".to_string()));
    }
}
