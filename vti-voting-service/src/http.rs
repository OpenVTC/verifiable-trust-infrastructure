//! The HTTPS Trust Task binding: one `POST /trust-tasks` door for every `voting/*` task.
//!
//! The binding a cast is always accepted on (VTI-VOT-004): a sender holding nothing but a key
//! made for that one cast can post here and read its receipt in the synchronous response. A
//! community's own requests, and any party that holds an identifier, are better carried over TSP
//! or DIDComm ([`crate::messaging`]); this door proves no sender, so every request on it that
//! needs authority carries its own proof.

use std::sync::Arc;

use axum::{Json, Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use serde_json::Value;

use crate::dispatch::{self, AppState};

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/trust-tasks", post(trust_task))
        .with_state(state)
}

async fn trust_task(State(state): State<Arc<AppState>>, body: Bytes) -> (StatusCode, Json<Value>) {
    let answer = dispatch::answer(&state, &body, None).await;
    (answer.status, Json(answer.doc.unwrap_or(Value::Null)))
}
