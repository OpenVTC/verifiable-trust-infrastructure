//! Messaging slice trust-task handlers.
//!
//! `messaging/ping` — the transport-agnostic liveness + capability probe of the
//! ToIP Trust Tasks `messaging/*` family. A VTA answers it as a *responder*
//! (see the generalised spec): any authenticated caller learns the VTA is alive
//! and which transports it serves, without parsing its DID document. This is the
//! canonical health ping the `pnm health` TSP/DIDComm probes drive.

use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;

use crate::auth::AuthClaims;
use crate::server::AppState;

use super::helpers::{TrustTaskOutcome, success_response};

/// Handler for `messaging/ping/0.1`.
///
/// Side-effect-free and **session-less**: the spec requires no capability
/// beyond reachability ("a ping MUST NOT require the requester to hold any
/// capability beyond reachability"), so there is no role or session gate — the
/// caller is already authenticated by the transport (JWT / DIDComm authcrypt /
/// TSP unpack) to have reached the dispatcher at all. Returns the VTA's
/// `serverTime`, a coarse `status`, the transport `protocols` it serves, and
/// echoes an optional request `nonce` for correlation.
pub(super) async fn handle_ping(
    state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Advertised transports, in preference order (TSP > DIDComm > REST).
    let protocols: Vec<&str> = {
        let services = &state.config.read().await.services;
        let mut p = Vec::new();
        if services.tsp {
            p.push("tsp");
        }
        if services.didcomm {
            p.push("didcomm");
        }
        if services.rest {
            p.push("rest");
        }
        p
    };

    let mut body = json!({
        "serverTime": chrono::Utc::now().to_rfc3339(),
        "status": "ok",
        "protocols": protocols,
    });
    // Echo the caller's correlation nonce verbatim when supplied.
    if let Some(nonce) = doc.payload.get("nonce").and_then(Value::as_str) {
        body["nonce"] = json!(nonce);
    }

    success_response(&doc, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::build_signing_test_app_state;
    use serde_json::json;

    fn ping_doc(nonce: Option<&str>) -> TrustTask<Value> {
        let payload = match nonce {
            Some(n) => json!({ "nonce": n }),
            None => json!({}),
        };
        TrustTask::new(
            "urn:uuid:test-ping".to_string(),
            vta_sdk::trust_tasks::TASK_MESSAGING_PING_0_1
                .parse()
                .unwrap(),
            payload,
        )
    }

    /// A ping from any authenticated caller (no session, no role) returns a
    /// 200 `#response` with status ok and the echoed nonce.
    #[tokio::test]
    async fn ping_is_session_less_and_echoes_nonce() {
        let (state, _dir) = build_signing_test_app_state().await;
        // A synthetic intrinsic-sender claim (as TSP/DIDComm produce) — no
        // stored session, no admin role needed.
        let auth = crate::auth::AuthClaims {
            did: "did:key:zPinger".into(),
            role: crate::acl::Role::Reader,
            allowed_contexts: vec![],
            session_id: "didcomm:did:key:zPinger".into(),
            access_expires_at: 0,
            amr: vec!["did".into()],
            acr: "aal1".into(),
        };

        let out = handle_ping(&state, &auth, ping_doc(Some("abc123"))).await;
        assert_eq!(out.status, axum::http::StatusCode::OK);
        let doc: Value = serde_json::from_slice(&out.body).expect("reply is JSON");
        assert_eq!(doc["payload"]["status"], "ok");
        assert_eq!(doc["payload"]["nonce"], "abc123");
        assert!(doc["payload"]["serverTime"].is_string());
    }
}
