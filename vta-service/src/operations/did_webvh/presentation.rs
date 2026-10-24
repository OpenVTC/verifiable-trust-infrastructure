//! How a new did:webvh log is presented: as its did:webvh DID or its
//! `did:scid:vh:1` DID, and whether its first entry lists the did:scid alias
//! (VTI-KEY-165, VTI-KEY-166, VTI-VTA-034 to VTI-VTA-036,
//! `vta/webvh/dids/create/1.2`).

use serde_json::Value;
use vta_sdk::did_scid::DidMethod;

use crate::config::DidsConfig;
use crate::error::AppError;

/// Leads the message of the [`AppError::Validation`] that
/// `vta/webvh/dids/create/1.2` answers with its declared `scidAliasRequired`
/// code. `AppError` has no variant carrying a task's declared code, so the
/// handler recognises this one by [`is_scid_alias_required`].
const SCID_ALIAS_REQUIRED: &str = "scidAliasRequired: ";

/// Whether `e` is the refusal to present a DID as did:scid without its alias.
pub(crate) fn is_scid_alias_required(e: &AppError) -> bool {
    matches!(e, AppError::Validation(m) if m.starts_with(SCID_ALIAS_REQUIRED))
}

fn alias_required(why: &str) -> AppError {
    AppError::Validation(format!(
        "{SCID_ALIAS_REQUIRED}the did:scid identity needs its alias in alsoKnownAs \
         (VTI-KEY-166), but {why}. Ask for did_method webvh, or drop what forbids the alias."
    ))
}

/// What a create applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Presentation {
    pub method: DidMethod,
    /// Whether the first log entry lists the did:scid DID URL.
    pub alias: bool,
}

/// Whether a DID template forbids `alsoKnownAs`: its binding
/// `defaults.scidAlsoKnownAs: false`, as the Swiss Profile Anchor's
/// `swiyu-verifier` declares.
pub(crate) fn template_forbids_alias(defaults: &serde_json::Map<String, Value>) -> bool {
    defaults.get("scidAlsoKnownAs") == Some(&Value::Bool(false))
}

/// Decide the form and alias for a create the VTA writes the log for.
///
/// Each member takes the first value of: the request (which carries a VTC's
/// stated preference, VTI-VTC-004), the VTA's `[dids]`, the defaults
/// (VTI-VTA-036). A did:scid identity always lists its alias, so asking for one
/// where the alias is refused or forbidden is `scidAliasRequired`; a did:webvh
/// under a template that forbids the alias leaves it out, unless the request
/// asked for it.
pub(crate) fn decide(
    requested_method: Option<DidMethod>,
    requested_alias: Option<bool>,
    template_forbids: bool,
    config: &DidsConfig,
) -> Result<Presentation, AppError> {
    let method = requested_method.unwrap_or(config.default_did_method);
    let alias = match method {
        DidMethod::Scid => {
            if requested_alias == Some(false) {
                return Err(alias_required("the request sets scidAlsoKnownAs to false"));
            }
            if template_forbids {
                return Err(alias_required("the template forbids alsoKnownAs"));
            }
            true
        }
        _ => {
            if template_forbids {
                if requested_alias == Some(true) {
                    return Err(alias_required_for_webvh());
                }
                false
            } else {
                requested_alias.unwrap_or(config.scid_also_known_as)
            }
        }
    };
    Ok(Presentation { method, alias })
}

fn alias_required_for_webvh() -> AppError {
    AppError::Validation(format!(
        "{SCID_ALIAS_REQUIRED}the request asks for the did:scid alias in alsoKnownAs, but the \
         template forbids alsoKnownAs. Drop scidAlsoKnownAs or use another template."
    ))
}

/// Decide for a supplied, pre-signed log: the alias is what its first entry
/// lists, and a did:scid identity is refused without it.
pub(crate) fn decide_for_log(
    requested_method: Option<DidMethod>,
    config: &DidsConfig,
    document: &Value,
) -> Result<Presentation, AppError> {
    let method = requested_method.unwrap_or(config.default_did_method);
    let alias = document_lists_alias(document);
    if method == DidMethod::Scid && !alias {
        return Err(alias_required("the supplied did_log does not list it"));
    }
    Ok(Presentation { method, alias })
}

/// Whether a did:webvh document lists its own did:scid DID URL in
/// `alsoKnownAs`. The `src` is compared as a locator (VTI-KEY-160), so a URL
/// naming the log's location in another accepted spelling counts.
pub(crate) fn document_lists_alias(document: &Value) -> bool {
    let Some(webvh) = document.get("id").and_then(Value::as_str) else {
        return false;
    };
    let Some((bare, _)) = vta_sdk::did_scid::scid_forms(webvh) else {
        return false;
    };
    document
        .get("alsoKnownAs")
        .and_then(Value::as_array)
        .is_some_and(|aliases| {
            aliases.iter().filter_map(Value::as_str).any(|a| {
                vta_sdk::did_scid::src(a).is_some()
                    && didwebvh_rs::DIDWebVHState::convert_scid_id_to_webvh_id(a).as_deref()
                        == Some(webvh)
                    && vta_sdk::did_scid::identity(a) == bare
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(method: DidMethod, alias: bool) -> DidsConfig {
        let mut c = DidsConfig::default();
        c.default_did_method = method;
        c.scid_also_known_as = alias;
        c
    }

    /// VTI-VTA-036: request, then configuration, then the defaults.
    #[test]
    fn request_then_config_then_defaults() {
        let defaults = DidsConfig::default();
        assert_eq!(
            decide(None, None, false, &defaults).unwrap(),
            Presentation {
                method: DidMethod::Webvh,
                alias: true
            }
        );
        let scid_vta = cfg(DidMethod::Scid, false);
        assert_eq!(
            decide(None, None, false, &scid_vta).unwrap().method,
            DidMethod::Scid
        );
        // The request wins over the VTA.
        assert_eq!(
            decide(Some(DidMethod::Webvh), None, false, &scid_vta).unwrap(),
            Presentation {
                method: DidMethod::Webvh,
                alias: false
            }
        );
        assert!(
            decide(None, Some(true), false, &cfg(DidMethod::Webvh, false))
                .unwrap()
                .alias
        );
        assert_eq!(
            decide(None, Some(false), false, &defaults).unwrap(),
            Presentation {
                method: DidMethod::Webvh,
                alias: false
            }
        );
    }

    /// VTI-KEY-166: a did:scid identity always lists its alias.
    #[test]
    fn scid_needs_its_alias() {
        let defaults = DidsConfig::default();
        assert_eq!(
            decide(
                Some(DidMethod::Scid),
                None,
                false,
                &cfg(DidMethod::Webvh, false)
            )
            .unwrap(),
            Presentation {
                method: DidMethod::Scid,
                alias: true
            }
        );
        let refused = decide(Some(DidMethod::Scid), Some(false), false, &defaults).unwrap_err();
        assert!(is_scid_alias_required(&refused), "{refused}");
        let forbidden = decide(Some(DidMethod::Scid), None, true, &defaults).unwrap_err();
        assert!(is_scid_alias_required(&forbidden), "{forbidden}");
        assert!(!is_scid_alias_required(&AppError::Validation(
            "other".into()
        )));
    }

    /// A template that forbids alsoKnownAs keeps a did:webvh alias-free, unless
    /// the request asked for the alias.
    #[test]
    fn a_forbidding_template_drops_a_defaulted_alias() {
        let defaults = DidsConfig::default();
        assert_eq!(
            decide(None, None, true, &defaults).unwrap(),
            Presentation {
                method: DidMethod::Webvh,
                alias: false
            }
        );
        assert!(is_scid_alias_required(
            &decide(None, Some(true), true, &defaults).unwrap_err()
        ));
        assert!(template_forbids_alias(
            json!({"scidAlsoKnownAs": false}).as_object().unwrap()
        ));
        assert!(!template_forbids_alias(
            json!({"portable": false}).as_object().unwrap()
        ));
    }

    #[test]
    fn a_supplied_log_reports_what_it_lists() {
        let listed = json!({
            "id": "did:webvh:QmScid:example.com:alice",
            "alsoKnownAs": ["did:scid:vh:1:QmScid?src=example.com/alice"]
        });
        let unlisted = json!({ "id": "did:webvh:QmScid:example.com:alice" });
        let other_log = json!({
            "id": "did:webvh:QmScid:example.com:alice",
            "alsoKnownAs": ["did:scid:vh:1:QmOther?src=example.com/alice"]
        });
        let defaults = DidsConfig::default();
        assert!(decide_for_log(None, &defaults, &listed).unwrap().alias);
        assert!(!decide_for_log(None, &defaults, &unlisted).unwrap().alias);
        assert!(!document_lists_alias(&other_log));
        assert!(is_scid_alias_required(
            &decide_for_log(Some(DidMethod::Scid), &defaults, &unlisted).unwrap_err()
        ));
        assert_eq!(
            decide_for_log(Some(DidMethod::Scid), &defaults, &listed)
                .unwrap()
                .method,
            DidMethod::Scid
        );
    }
}
