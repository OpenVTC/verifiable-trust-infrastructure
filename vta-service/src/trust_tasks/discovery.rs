//! Discovery slice trust-task handlers. Any authenticated caller.
//!
//! Two URIs, answering two different questions:
//!
//! - **`spec/trust-task-discovery/0.1`** — *which Trust Tasks does this agent
//!   serve?* The published, canonical family from the dtgwg-trust-tasks-tf
//!   registry, already carried by `trust-tasks-rs`. This is what a client
//!   should ask before assuming a task exists.
//! - **`spec/vta/discovery/capabilities/1.0`** — the VTA-specific *deployment
//!   inventory*: webvh hosts and DID-creation modes. Reduced to exactly that
//!   delta in #1039; its `features` / `services` booleans are gone, because the
//!   DID document is authoritative for which protocols a party speaks and a
//!   second answer to that question is one that can disagree.
//!
//! The capabilities body used to be served on `GET /capabilities` as well.
//! That route is gone (#1039): nothing consumed it — `VtaClient::capabilities`
//! goes over `rpc_tt` like every other task — and a REST route parallel to a
//! Trust Task is the shape #1020 spent a PR removing everywhere else.

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::discovery::{CapabilitiesBody, CapabilitiesResponse, WebvhServerInfo};

use crate::auth::AuthClaims;
use crate::server::AppState;

// `app_error_to_reject` is only reachable when the `webvh` feature is
// on (the only branch that produces an `AppError`). Gate the import
// alongside to avoid an "unused import" lint in non-webvh combos.
#[cfg(feature = "webvh")]
use super::helpers::app_error_to_reject;
use super::helpers::{parse_payload, success_response};

/// Handler for `spec/vta/discovery/capabilities/1.0`.
pub(super) async fn handle_capabilities(
    state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let _req: CapabilitiesBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // `features` and `services` used to be assembled here and are gone (#1039).
    // The DID document is authoritative for which protocols a party speaks, and
    // `services` answered from local config — which runtime service management
    // can leave behind, so the two could disagree about exactly the thing a
    // caller was asking. `features` reported `cfg!` flags: what the binary could
    // serve, not what it does. That question is `trust-task-discovery/0.1` now.
    #[cfg(feature = "webvh")]
    let webvh_servers = match crate::webvh_store::list_servers(&state.webvh_ks).await {
        Ok(servers) => servers
            .into_iter()
            .map(|s| WebvhServerInfo {
                id: s.id,
                label: s.label,
            })
            .collect(),
        Err(e) => return app_error_to_reject(&doc, e),
    };
    #[cfg(not(feature = "webvh"))]
    let webvh_servers: Vec<WebvhServerInfo> = vec![];

    let mut did_creation_modes = vec!["vta-built".to_string()];
    if cfg!(feature = "webvh") {
        did_creation_modes.push("template".to_string());
        did_creation_modes.push("final".to_string());
        did_creation_modes.push("user-specified-keys".to_string());
    }

    let body = CapabilitiesResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        webvh_servers,
        did_creation_modes,
    };
    success_response(&doc, body)
}

/// Handler for `spec/trust-task-discovery/0.1` — canonical capability
/// negotiation.
///
/// The answer is **derived from the dispatch table**, so it cannot claim a task
/// this service does not actually route. A hand-maintained list would be a
/// second source of truth, and an overstated discovery response is worse than
/// none: a client believes a task is available and finds out on a live call,
/// which on DIDComm is a 30-second timeout with no explanation.
pub(super) async fn handle_trust_task_discovery(
    _state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use trust_tasks_rs::specs::trust_task_discovery::v0_1 as wire;

    let req: wire::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // An absent or empty pattern list means "everything", per the spec: the
    // responder MUST treat the query as `['*']`.
    let patterns: Vec<String> = req.patterns.iter().map(|p| p.to_string()).collect();

    let mut matched: Vec<String> = super::dispatched_uris()
        .into_iter()
        .filter(|uri| slug_matches_any(uri, &patterns))
        .map(str::to_string)
        .collect();

    // The spec forbids duplicate Type URIs in the response. The dispatch table
    // legitimately contains repeats — one handler can be reached by several
    // URIs, and dual-accept versions sit side by side — so dedupe rather than
    // assume. Sorted for a stable answer across calls.
    matched.sort_unstable();
    matched.dedup();

    let body = serde_json::json!({
        "frameworkVersion": FRAMEWORK_VERSION,
        "supportedTypes": matched,
    });
    success_response(&doc, body)
}

/// MAJOR.MINOR of the Trust Tasks framework spec this agent targets.
///
/// Matches the framework crate's own `DEFAULT_FRAMEWORK_VERSION`. Kept as a
/// named constant so a reader can see what is being claimed, rather than
/// finding a bare string in a JSON literal.
const FRAMEWORK_VERSION: &str = "0.2";

/// Slug-glob match, per the `trust-task-discovery/0.1` pattern grammar.
///
/// The grammar is deliberately narrow: `*` matches everything, `<prefix>/*`
/// matches any slug under that prefix, and anything else is an exact match —
/// interior wildcards are literal and therefore never match.
///
/// Patterns are matched against the URI's **slug**, not the whole URI, so a
/// caller writes `acl/*` rather than repeating the registry origin.
fn slug_matches_any(uri: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    let slug = slug_of(uri);
    patterns
        .iter()
        .any(|p| trust_tasks_rs::discovery::match_slug(p, slug))
}

/// The slug of a Type URI — everything after the registry prefix.
///
/// `https://trusttasks.org/spec/acl/grant/0.1` → `acl/grant/0.1`.
/// A URI that does not carry the prefix is returned whole, so a non-conforming
/// entry can still be matched exactly rather than silently dropping out of
/// every response.
fn slug_of(uri: &str) -> &str {
    uri.strip_prefix("https://trusttasks.org/spec/")
        .unwrap_or(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pats(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| s.to_string()).collect()
    }

    /// Patterns match the **slug**, not the whole URI.
    ///
    /// If this regressed to matching the full URI, `acl/*` would match
    /// nothing and every narrowed query would come back empty — a discovery
    /// response that is wrong in the safe-looking direction, which is the hard
    /// kind to notice.
    #[test]
    fn patterns_match_the_slug_not_the_whole_uri() {
        // The real URI: ACL folded to the top-level canonical family, so the
        // slug is `acl/grant/0.1` and NOT `vta/acl/grant/0.1`. Using the
        // VTA-namespaced form here is the mistake this test caught during
        // review, and it is silent — a wrong pattern returns an empty list, not
        // an error.
        let grant = "https://trusttasks.org/spec/acl/grant/0.1";
        assert!(slug_matches_any(grant, &pats(&["acl/*"])));
        assert!(slug_matches_any(grant, &pats(&["acl/grant/0.1"])));
        assert!(!slug_matches_any(grant, &pats(&["vta/acl/*"])));
        assert!(!slug_matches_any(grant, &pats(&["keys/*"])));
    }

    /// An empty pattern list means everything, per the spec — the responder
    /// MUST treat the query as `['*']`. Returning nothing would be the obvious
    /// misreading.
    #[test]
    fn no_patterns_means_everything() {
        let uri = "https://trusttasks.org/spec/acl/grant/0.1";
        assert!(slug_matches_any(uri, &[]));
        assert!(slug_matches_any(uri, &pats(&["*"])));
    }

    /// Interior wildcards are literal, so they never match.
    ///
    /// The grammar admits only a bare `*` and a trailing `/*`. Anything else is
    /// an exact slug. Worth pinning because a caller who assumes full globbing
    /// gets an empty answer rather than an error, and would reasonably read
    /// that as "the agent serves nothing".
    #[test]
    fn interior_wildcards_are_not_globs() {
        let uri = "https://trusttasks.org/spec/acl/grant/0.1";
        assert!(!slug_matches_any(uri, &pats(&["*/grant/0.1"])));
    }

    /// A URI without the registry prefix is still matchable exactly.
    ///
    /// Everything dispatched today carries the prefix. Stripping blindly with
    /// an `unwrap_or` that dropped the URI instead would make any future
    /// non-conforming entry silently invisible to discovery rather than
    /// findable by exact name.
    #[test]
    fn a_prefixless_uri_is_returned_whole() {
        assert_eq!(slug_of("urn:example:odd"), "urn:example:odd");
        assert!(slug_matches_any(
            "urn:example:odd",
            &pats(&["urn:example:odd"])
        ));
    }

    /// Discovery answers from the dispatch table, and that table is non-trivial.
    ///
    /// The property under test is that the two are connected at all: if
    /// `dispatched_uris` were emptied by a refactor, every test above would
    /// still pass while discovery answered "I support nothing".
    #[test]
    fn discovery_draws_on_the_real_dispatch_table() {
        let all = crate::trust_tasks::dispatched_uris();
        assert!(
            all.len() > 50,
            "only {} dispatched URIs — discovery would under-report; fix the \
             table rather than this floor",
            all.len()
        );
        assert!(
            all.contains(&vta_sdk::trust_tasks::TASK_TRUST_TASK_DISCOVERY_0_1),
            "discovery must advertise itself — a client that cannot see it \
             cannot know to ask again"
        );
    }
}
