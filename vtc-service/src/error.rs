pub use vti_common::error::*;

use axum::Json;
use axum::response::{IntoResponse, Response};

/// An error a handler answers with, which may carry the extended error code
/// its task's specification declares for it (SPEC §8.5, #1600).
///
/// The generic [`AppError`] rendering keeps an HTTP status and English, and on
/// the Trust Task path a bare `taskFailed` with a `details.reason` marker. What
/// neither carries is *which* of a task's declared outcomes this is, and that
/// is what a client branches on — "no such request" and "already decided" are
/// both a `404`/`409`-shaped miss to the status line and two different next
/// steps to the caller.
///
/// A [`Declared`](Self::Declared) error keeps everything the undeclared form
/// sends — the same status, the same `error` member, the same Trust Task
/// `details.reason` — and adds the code:
///
/// - REST: `{"error": "<display>", "code": "<slug>:<local>"}`, status unchanged,
///   so a client reading the status or the message is unaffected.
/// - Trust Task: the extended code in place of `taskFailed`, the marker kept
///   in `details.reason` so a client that does not know the code still
///   recovers the typed variant (SPEC §8.5 fallback).
///
/// `code` is always a generated `…::error_codes::X.code` — never a literal.
#[derive(Debug)]
pub enum TaskError {
    /// Answered as the service answers every other error.
    App(AppError),
    /// Answered with the task's declared code beside the usual rendering.
    Declared { code: &'static str, error: AppError },
}

impl TaskError {
    /// `error`, answered with the declared `code`.
    pub fn declared(code: &'static str, error: AppError) -> Self {
        Self::Declared { code, error }
    }

    /// The declared code, if this error carries one.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::App(_) => None,
            Self::Declared { code, .. } => Some(code),
        }
    }

    /// The underlying error, whichever form this is.
    pub fn app_error(&self) -> &AppError {
        match self {
            Self::App(e) | Self::Declared { error: e, .. } => e,
        }
    }
}

impl From<AppError> for TaskError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

/// Dropping the code: a surface that cannot carry one (the legacy DIDComm
/// problem-report path) sees exactly the error it saw before the code existed.
impl From<TaskError> for AppError {
    fn from(e: TaskError) -> Self {
        match e {
            TaskError::App(e) | TaskError::Declared { error: e, .. } => e,
        }
    }
}

impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.app_error().fmt(f)
    }
}

impl IntoResponse for TaskError {
    fn into_response(self) -> Response {
        match self {
            Self::App(e) => e.into_response(),
            Self::Declared { code, error } => {
                let message = error.to_string();
                // The status (and the server-side log line) come from the
                // error's own rendering, so declaring a code can never move a
                // route's status.
                let status = error.into_response().status();
                (
                    status,
                    Json(serde_json::json!({ "error": message, "code": code })),
                )
                    .into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn a_declared_error_keeps_the_status_and_message_and_adds_the_code() {
        let plain = AppError::NotFound("join request not found: x".into()).into_response();
        let plain_status = plain.status();
        let plain_body: serde_json::Value =
            serde_json::from_slice(&to_bytes(plain.into_body(), 4096).await.unwrap()).unwrap();

        let code =
            trust_tasks_rs::specs::vtc::join_requests::show::v0_1::error_codes::NOT_FOUND.code;
        let declared =
            TaskError::declared(code, AppError::NotFound("join request not found: x".into()))
                .into_response();
        assert_eq!(declared.status(), plain_status);
        assert_eq!(declared.status(), StatusCode::NOT_FOUND);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(declared.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["error"], plain_body["error"]);
        assert_eq!(body["code"], code);
    }
}
