//! The HTTPS Trust Task binding: one `POST /trust-tasks` door for every `voting/*` task.
//!
//! The binding a cast is always accepted on (VTI-VOT-004): a sender holding nothing but a key
//! made for that one cast can post here and read its receipt in the synchronous response. A
//! community's own requests, and any party that holds an identifier, are better carried over TSP
//! or DIDComm ([`crate::messaging`]); this door proves no sender, so every request on it that
//! needs authority carries its own proof.
//!
//! Beside it, two unauthenticated health reads for a proxy or a monitor. They carry nothing the
//! service's DID document does not already publish:
//!
//! - `GET /health`: the process is serving. Always `200`, with the mediator session's state in
//!   the body. This is the check for a load balancer in front of the cast door: casts arrive over
//!   HTTPS and keep working while the mediator is away.
//! - `GET /health/ready`: communities can reach the box as well. `200` only while the mediator
//!   session is connected, `503` otherwise — and always `503` without a provisioned identity,
//!   which no community can reach. Alert on this one.
//!
//! The session state is the supervisor's live report, never latched at the first connect (R6.2).

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde_json::{Value, json};

use crate::dispatch::{self, AppState};

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/trust-tasks", post(trust_task))
        .route("/health", get(health))
        .route("/health/ready", get(ready))
        .with_state(state)
}

async fn trust_task(State(state): State<Arc<AppState>>, body: Bytes) -> (StatusCode, Json<Value>) {
    let answer = dispatch::answer(&state, &body, None).await;
    (answer.status, Json(answer.doc.unwrap_or(Value::Null)))
}

/// The mediator session as a health read names it.
fn messaging(state: &AppState) -> &'static str {
    match &state.messaging {
        None => "disabled",
        Some(connected) if *connected.borrow() => "connected",
        Some(_) => "notConnected",
    }
}

async fn health(State(state): State<Arc<AppState>>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "did": state.identity.did,
            "messaging": messaging(&state),
        })),
    )
}

async fn ready(State(state): State<Arc<AppState>>) -> (StatusCode, Json<Value>) {
    let messaging = messaging(&state);
    let (code, status) = if messaging == "connected" {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "notReady")
    };
    (
        code,
        Json(json!({
            "status": status,
            "did": state.identity.did,
            "messaging": messaging,
        })),
    )
}
