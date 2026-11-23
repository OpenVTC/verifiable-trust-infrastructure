//! Kubernetes-style liveness and readiness probes, `GET /livez` and
//! `GET /readyz`, shared by the VTA and the VTC.
//!
//! The two answer different questions, and the difference is what an
//! orchestrator does with a failure:
//!
//! - **`/livez`** — is the process alive? It answers from the HTTP server
//!   itself and checks nothing else, so storage trouble or an unreachable
//!   mediator never gets a healthy process restarted. A restart would not
//!   cure either, and would throw away the state that might.
//! - **`/readyz`** — can this instance take traffic right now? `503` while it
//!   cannot (the store is gone or failing), so a load balancer stops routing
//!   to it until it can.
//!
//! Readiness covers what every request needs: the store. It deliberately
//! does not cover the mediator. Messaging has its own reconnect supervisor,
//! and a REST caller is served without it, so draining the instance would
//! turn a degraded transport into an outage.
//!
//! Both routes are unauthenticated, so neither body says more than `/health`
//! already does: a status word, and for readiness which check failed. Never
//! the cause, which can name paths and hosts. That goes to the log.
//!
//! Probes come every few seconds and from anyone who can reach the port, so
//! [`ReadinessProbe`] runs the store check at most once per
//! [`PROBE_CACHE`] and answers every caller in between from that result.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tokio::sync::Mutex;
use tracing::warn;

use crate::store::KeyspaceHandle;

/// How long one store check answers for. Bounds the store work an
/// unauthenticated caller can cause to one check per this interval.
pub const PROBE_CACHE: Duration = Duration::from_secs(1);

/// Longest a store check may take before it counts as a failure. A stalled
/// disk or proxy then gets the instance drained, rather than holding the
/// probe open past the orchestrator's own timeout (Kubernetes defaults to 1s).
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(800);

/// `/livez` body.
#[derive(Debug, Serialize)]
pub struct LiveResponse {
    status: &'static str,
}

/// `GET /livez`. Always `200 {"status":"ok"}` while the server answers.
pub async fn livez() -> Json<LiveResponse> {
    Json(LiveResponse { status: "ok" })
}

/// One readiness check's result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CheckState {
    Ok,
    Unavailable,
}

/// `/readyz` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadyResponse {
    /// `ready` or `notReady`.
    pub status: &'static str,
    pub storage: CheckState,
}

impl ReadyResponse {
    pub fn is_ready(&self) -> bool {
        self.storage == CheckState::Ok
    }
}

impl IntoResponse for ReadyResponse {
    fn into_response(self) -> Response {
        let code = if self.is_ready() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        (code, Json(self)).into_response()
    }
}

/// Runs the readiness checks for `GET /readyz`, at most once per
/// [`PROBE_CACHE`]. Cheap to clone; clones share the cache.
#[derive(Clone)]
pub struct ReadinessProbe {
    storage: KeyspaceHandle,
    last: Arc<Mutex<Option<(Instant, ReadyResponse)>>>,
}

impl ReadinessProbe {
    /// A probe over the store `storage` was opened from. Any keyspace will
    /// do: every check is store-wide.
    pub fn new(storage: KeyspaceHandle) -> Self {
        Self {
            storage,
            last: Arc::new(Mutex::new(None)),
        }
    }

    /// The current readiness. Concurrent callers wait on one check rather
    /// than each running their own.
    pub async fn check(&self) -> ReadyResponse {
        let mut last = self.last.lock().await;
        if let Some((at, answer)) = *last
            && at.elapsed() < PROBE_CACHE
        {
            return answer;
        }
        let storage = match tokio::time::timeout(PROBE_TIMEOUT, self.storage.probe()).await {
            Ok(Ok(())) => CheckState::Ok,
            Ok(Err(e)) => {
                warn!(error = %e, "readiness: store check failed");
                CheckState::Unavailable
            }
            Err(_) => {
                warn!(
                    timeout_ms = PROBE_TIMEOUT.as_millis() as u64,
                    "readiness: store check timed out"
                );
                CheckState::Unavailable
            }
        };
        let answer = ReadyResponse {
            status: if storage == CheckState::Ok {
                "ready"
            } else {
                "notReady"
            },
            storage,
        };
        *last = Some((Instant::now(), answer));
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    fn store_in(dir: &std::path::Path) -> Store {
        Store::open(&StoreConfig {
            data_dir: dir.to_path_buf(),
        })
        .expect("open store")
    }

    #[tokio::test]
    async fn livez_is_ok() {
        assert_eq!(livez().await.0.status, "ok");
    }

    #[tokio::test]
    async fn readyz_is_ready_over_a_working_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path());
        let probe = ReadinessProbe::new(store.keyspace("probe").unwrap());
        let answer = probe.check().await;
        assert!(answer.is_ready());
        assert_eq!(answer.status, "ready");
        let resp = answer.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The case the probe exists for: the volume under an open database goes
    /// away (a detached PVC, a deleted data directory). The open database
    /// would go on answering from memory; readiness must not.
    #[tokio::test]
    async fn readyz_is_not_ready_once_the_data_directory_is_gone() {
        let parent = tempfile::tempdir().unwrap();
        let data = parent.path().join("data");
        let store = store_in(&data);
        let probe = ReadinessProbe::new(store.keyspace("probe").unwrap());
        assert!(probe.check().await.is_ready());

        std::fs::remove_dir_all(&data).unwrap();
        tokio::time::sleep(PROBE_CACHE).await;

        let answer = probe.check().await;
        assert!(!answer.is_ready());
        assert_eq!(answer.status, "notReady");
        assert_eq!(answer.storage, CheckState::Unavailable);
        assert_eq!(
            answer.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn readyz_answers_from_cache_within_the_window() {
        let parent = tempfile::tempdir().unwrap();
        let data = parent.path().join("data");
        let store = store_in(&data);
        let probe = ReadinessProbe::new(store.keyspace("probe").unwrap());
        assert!(probe.check().await.is_ready());
        std::fs::remove_dir_all(&data).unwrap();
        // Still inside the window: the cached answer stands.
        assert!(probe.check().await.is_ready());
    }

    #[test]
    fn ready_body_is_camel_case() {
        let body = serde_json::to_value(ReadyResponse {
            status: "notReady",
            storage: CheckState::Unavailable,
        })
        .unwrap();
        assert_eq!(
            body,
            serde_json::json!({"status": "notReady", "storage": "unavailable"})
        );
    }
}
