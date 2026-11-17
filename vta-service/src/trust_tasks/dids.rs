//! `vta/dids/{list,get,methods/list}/0.1` — what every identity this VTA holds
//! is, whatever its method (`operations::dids`;
//! `docs/05-design-notes/did-management.md`).
//!
//! | URI                             | Auth                       |
//! |---------------------------------|----------------------------|
//! | `vta/dids/list/0.1`             | context access, per DID    |
//! | `vta/dids/get/0.1`              | the DID's context          |
//! | `vta/dids/methods/list/0.1`     | any authenticated          |

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::{RejectReason, TrustTask};
use vti_specs::vta::dids as spec;

use crate::auth::AuthClaims;
use crate::operations::dids::{self, DidFilter, DidStores};
use crate::server::AppState;

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, parse_payload, reject_declared, reject_with,
    success_response,
};

/// The page size `list` uses when the caller names none.
const DEFAULT_LIST_LIMIT: usize = 100;

/// Serialise a built value into the task's generated response type, which
/// checks it against the schema on the way out.
fn respond<R: DeserializeOwned + Serialize>(
    doc: &TrustTask<Value>,
    value: Value,
) -> TrustTaskOutcome {
    match serde_json::from_value::<R>(value) {
        Ok(r) => success_response(doc, r),
        Err(e) => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("{} response does not match its schema: {e}", doc.type_uri),
            },
        ),
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn filter_of(p: &Value) -> DidFilter {
    DidFilter {
        context_id: str_of(p, "contextId").map(str::to_string),
        methods: p.get("methods").and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        }),
        server_id: str_of(p, "serverId").map(str::to_string),
        class: str_of(p, "class").map(str::to_string),
        include_deactivated: p
            .get("includeDeactivated")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

/// A cursor names the last DID of the page before **and** the filters it was
/// issued for, so one issued for another question is refused rather than
/// silently paging a different list.
fn filters_digest(p: &Value) -> String {
    let mut scoped = p.clone();
    if let Some(o) = scoped.as_object_mut() {
        o.remove("cursor");
        o.remove("limit");
        o.remove("ext");
    }
    // Canonical JSON (RFC 8785), so equal filters digest equally whatever
    // order the producer wrote them in.
    let canonical = serde_json_canonicalizer::to_string(&scoped).unwrap_or_default();
    let digest = Sha256::digest(canonical.as_bytes());
    hex::encode(&digest[..12])
}

const CURSOR_PREFIX: &str = "dids-after:";

fn issue_cursor(filters: &str, did: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!("{CURSOR_PREFIX}{filters}:{did}"))
}

fn cursor_did(cursor: &str, filters: &str) -> Option<String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let rest = text.strip_prefix(CURSOR_PREFIX)?;
    let (issued_for, did) = rest.split_once(':')?;
    (issued_for == filters && did.starts_with("did:")).then(|| did.to_string())
}

/// `vta/dids/list/0.1`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::list::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let filters = filters_digest(p);
    let after = match str_of(p, "cursor") {
        Some(c) => match cursor_did(c, &filters) {
            Some(did) => Some(did),
            None => {
                return app_error_to_reject(
                    &doc,
                    crate::error::AppError::Validation(
                        "the cursor is not one this VTA issued for these filters".into(),
                    ),
                );
            }
        },
        None => None,
    };
    let mut all = match dids::list(DidStores::from_state(state), auth, &filter_of(p)).await {
        Ok(all) => all,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    if let Some(after) = after {
        all.retain(|s| s.did.as_str() > after.as_str());
    }
    let limit = p
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(DEFAULT_LIST_LIMIT, |l| l as usize);
    let more = all.len() > limit;
    all.truncate(limit);
    let mut v = json!({ "dids": all.iter().map(dids::DidSummary::to_value).collect::<Vec<_>>() });
    if more && let Some(last) = all.last() {
        v["nextCursor"] = json!(issue_cursor(&filters, &last.did));
    }
    respond::<t::Response>(&doc, v)
}

/// `vta/dids/get/0.1`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::get::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let did = str_of(&doc.payload, "did").unwrap_or_default();
    match dids::get(DidStores::from_state(state), auth, did).await {
        Ok(Some(summary)) => respond::<t::Response>(&doc, json!({ "did": summary.to_value() })),
        // Absent and unreachable answer alike (CONVENTIONS.md §20.2).
        Ok(None) => reject_declared(
            &doc,
            t::error_codes::NOT_FOUND,
            format!("no identity {did} is held here that you may see"),
        ),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `vta/dids/methods/list/0.1`.
pub(super) async fn handle_methods_list(
    state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::methods::list::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let config = state.config.read().await;
    let methods: Vec<Value> = dids::methods(&config)
        .iter()
        .map(dids::MethodInfo::to_value)
        .collect();
    respond::<t::Response>(&doc, json!({ "methods": methods }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_is_refused_for_other_filters() {
        let a = filters_digest(&json!({ "contextId": "alice" }));
        let b = filters_digest(&json!({ "contextId": "bob" }));
        let c = issue_cursor(&a, "did:key:z6Mk1");
        assert_eq!(cursor_did(&c, &a).as_deref(), Some("did:key:z6Mk1"));
        assert_eq!(cursor_did(&c, &b), None);
        assert_eq!(cursor_did("not-a-cursor", &a), None);
    }

    #[test]
    fn paging_members_do_not_change_the_filters() {
        assert_eq!(
            filters_digest(&json!({ "contextId": "a", "limit": 5, "cursor": "x" })),
            filters_digest(&json!({ "contextId": "a" }))
        );
    }
}
