//! Answering `trust-task-discovery` — shared by the VTA and the VTC so the two
//! node types answer it the same way.
//!
//! A node supplies the Type URIs it dispatches; this module applies the
//! pattern grammar and builds the answer. The 0.3 answer carries the node's
//! [`VTI_ACCEPTANCE_WINDOW`] at response level (VTI-TRN-047), read from the same
//! value the node's consumer applies, so what is advertised cannot drift from
//! what is enforced.
//!
//! The window goes at response level only. Both VTI nodes apply one window to
//! every document they dispatch, so a per-entry window would state the same
//! value again for every task, and discovery 0.3's *Correlation* section notes
//! that per-entry windows add to a deployment's fingerprint.

use trust_tasks_rs::specs::trust_task_discovery::{v0_1, v0_3};

use super::acceptance::VTI_ACCEPTANCE_WINDOW;

/// `trust-task-discovery/0.3`: `trust-task-discovery/0.1` plus the responder's
/// acceptance window.
pub const DISCOVERY_V0_3: &str = <v0_3::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The Trust Tasks framework release (SPEC.md) a VTI node targets, in the
/// three-part form discovery 0.2 onward writes. It is the release
/// `trust-tasks-rs` 0.24 implements and `trust-task-discovery/0.3` declares as
/// its target.
pub const FRAMEWORK_VERSION: &str = "0.6.0";

/// [`FRAMEWORK_VERSION`] without its PATCH, as `trust-task-discovery/0.1`
/// writes it (its schema admits only `MAJOR.MINOR`).
pub const FRAMEWORK_VERSION_MAJOR_MINOR: &str = "0.6";

/// The slug of a Type URI — everything after the registry prefix.
///
/// `https://trusttasks.org/spec/acl/grant/0.1` → `acl/grant/0.1`. A URI that
/// does not carry the prefix is returned whole, so a non-conforming entry can
/// still be matched exactly rather than silently dropping out of every
/// response.
pub fn slug_of(uri: &str) -> &str {
    uri.strip_prefix("https://trusttasks.org/spec/")
        .unwrap_or(uri)
}

/// Whether `uri` matches at least one of `patterns`, per the discovery pattern
/// grammar (unchanged from 0.1 to 0.3): `*` matches everything, `<prefix>/*`
/// any slug under that prefix, anything else exactly. An empty list means
/// everything — the responder **MUST** treat it as `['*']`.
///
/// Patterns are matched against the URI's **slug**, not the whole URI, so a
/// caller writes `acl/*` rather than repeating the registry origin.
pub fn matches_any<S: AsRef<str>>(uri: &str, patterns: &[S]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    let slug = slug_of(uri);
    patterns
        .iter()
        .any(|p| trust_tasks_rs::discovery::match_slug(p.as_ref(), slug))
}

/// The served URIs matching `patterns`, sorted and without duplicates (the
/// specification forbids a repeated Type URI; a dispatch table legitimately
/// reaches one handler by several routes).
pub fn matching<'a, S: AsRef<str>>(
    served: impl IntoIterator<Item = &'a str>,
    patterns: &[S],
) -> Vec<String> {
    let mut matched: Vec<String> = served
        .into_iter()
        .filter(|uri| matches_any(uri, patterns))
        .map(str::to_string)
        .collect();
    matched.sort_unstable();
    matched.dedup();
    matched
}

/// Answer a `trust-task-discovery/0.1` query.
pub fn respond_v0_1<'a>(
    served: impl IntoIterator<Item = &'a str>,
    query: &v0_1::Payload,
) -> v0_1::Response {
    let patterns: Vec<&str> = query.patterns.iter().map(|p| p.as_str()).collect();
    v0_1::Response::builder()
        .supported_types(
            matching(served, &patterns)
                .into_iter()
                .map(v0_1::ResponseSupportedTypesItem::Uri)
                .collect::<Vec<_>>(),
        )
        .framework_version(FRAMEWORK_VERSION_MAJOR_MINOR.parse().ok())
        .try_into()
        .expect("every member of a 0.1 response is set")
}

/// Answer a `trust-task-discovery/0.3` query, advertising
/// [`VTI_ACCEPTANCE_WINDOW`] at response level (VTI-TRN-047): the window this
/// node applies to every Type URI it lists.
pub fn respond_v0_3<'a>(
    served: impl IntoIterator<Item = &'a str>,
    query: &v0_3::Payload,
) -> v0_3::Response {
    let patterns: Vec<&str> = query.patterns.iter().map(|p| p.as_str()).collect();
    v0_3::Response::builder()
        .acceptance_window(VTI_ACCEPTANCE_WINDOW.advertised())
        .supported_types(
            matching(served, &patterns)
                .into_iter()
                .map(v0_3::ResponseSupportedTypesItem::Uri)
                .collect::<Vec<_>>(),
        )
        .framework_version(FRAMEWORK_VERSION.parse().ok())
        .try_into()
        .expect("every member of a 0.3 response is set")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_task::acceptance::AcceptanceWindow;
    use trust_tasks_rs::validate::ValidatedPayload;

    const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";

    /// Patterns match the **slug**, not the whole URI. If this regressed to
    /// matching the full URI, `acl/*` would match nothing and every narrowed
    /// query would come back empty — wrong in the safe-looking direction.
    #[test]
    fn patterns_match_the_slug_not_the_whole_uri() {
        assert!(matches_any(GRANT, &["acl/*"]));
        assert!(matches_any(GRANT, &["acl/grant/0.1"]));
        assert!(!matches_any(GRANT, &["vta/acl/*"]));
        assert!(!matches_any(GRANT, &["keys/*"]));
    }

    /// An empty pattern list means everything.
    #[test]
    fn no_patterns_means_everything() {
        assert!(matches_any::<&str>(GRANT, &[]));
        assert!(matches_any(GRANT, &["*"]));
    }

    /// Interior wildcards are literal, so they never match.
    #[test]
    fn interior_wildcards_are_not_globs() {
        assert!(!matches_any(GRANT, &["*/grant/0.1"]));
    }

    /// A URI without the registry prefix is still matchable exactly.
    #[test]
    fn a_prefixless_uri_is_returned_whole() {
        assert_eq!(slug_of("urn:example:odd"), "urn:example:odd");
        assert!(matches_any("urn:example:odd", &["urn:example:odd"]));
    }

    /// Duplicates collapse and the order is stable.
    #[test]
    fn matching_is_sorted_and_deduplicated() {
        let served = [GRANT, "https://trusttasks.org/spec/acl/list/0.1", GRANT];
        assert_eq!(
            matching(served, &["acl/*"]),
            vec![
                GRANT.to_string(),
                "https://trusttasks.org/spec/acl/list/0.1".to_string()
            ]
        );
    }

    /// The 0.3 answer validates against the published response schema and
    /// states, at response level, exactly the window the consumer applies
    /// (VTI-TRN-047).
    #[test]
    fn vti_trn_047_the_v0_3_answer_advertises_the_applied_window() {
        let response = respond_v0_3([GRANT], &v0_3::Payload::default());
        let json = serde_json::to_value(&response).expect("serialise");
        v0_3::Response::validate_value(&json).expect("schema-valid 0.3 response");
        assert_eq!(json["frameworkVersion"], FRAMEWORK_VERSION);
        let advertised = response.acceptance_window.expect("advertised");
        assert_eq!(
            AcceptanceWindow::from_advertised(&advertised),
            VTI_ACCEPTANCE_WINDOW
        );
    }

    /// The 0.1 answer validates against its schema and carries no window,
    /// which 0.1 cannot express.
    #[test]
    fn the_v0_1_answer_is_schema_valid_and_two_part() {
        let response = respond_v0_1([GRANT], &v0_1::Payload::default());
        let json = serde_json::to_value(&response).expect("serialise");
        v0_1::Response::validate_value(&json).expect("schema-valid 0.1 response");
        assert_eq!(json["frameworkVersion"], FRAMEWORK_VERSION_MAJOR_MINOR);
        assert!(json.get("acceptanceWindow").is_none());
    }

    /// The two framework-version forms name the same release.
    #[test]
    fn the_two_framework_version_forms_agree() {
        assert!(FRAMEWORK_VERSION.starts_with(&format!("{FRAMEWORK_VERSION_MAJOR_MINOR}.")));
    }
}
