use affinidi_tdk::secrets_resolver::errors::SecretsResolverError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tracing::{debug, warn};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("store error: {0}")]
    Store(#[from] fjall::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("secret store error: {0}")]
    SecretStore(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    /// The resource existed but has been permanently, irreversibly consumed
    /// or removed — rendered as **410 Gone**, distinct from [`Self::NotFound`]
    /// (never existed / not visible to this caller) and [`Self::Conflict`]
    /// (a transient state mismatch a retry or different request could
    /// resolve). Canonical use: the TEE Mode B bootstrap carve-out after it
    /// has been claimed — a second `/bootstrap/request` cannot succeed no
    /// matter what the caller sends, ever again for this VTA. The SDK's
    /// `vta_sdk::error::VtaError::Gone` mirrors this on the client side
    /// (`from_http` maps 410 → `Gone`) with an operator-facing hint.
    #[error("gone: {0}")]
    Gone(String),

    #[error("secrets error: {0}")]
    Secrets(#[from] SecretsResolverError),

    #[error("authentication error: {0}")]
    Authentication(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Operation requires a stepped-up (`acr=aal2`) session, but
    /// the caller's JWT carries a lower acr (typically `aal1`).
    /// Distinct from [`Self::Forbidden`] so wallets can react —
    /// `step_up_required` is the operator-friendly signal to
    /// trigger a passkey-login or VTA-approval ceremony, not a
    /// hard rejection.
    ///
    /// Rendered as **403 Forbidden** with body
    /// `{ "error": "step_up_required", "message": "...",
    ///   "requiredAcr": "aal2" }` so clients can distinguish it
    /// from a role-based rejection without parsing English.
    #[error("step-up required: {0}")]
    StepUpRequired(String),

    /// The Policy Decision Point refused the request until an approval is
    /// obtained, and is handing back what obtaining it requires.
    ///
    /// Distinct from [`Self::StepUpRequired`] because that variant can only say
    /// *that* elevation is needed — it renders `{error, message, requiredAcr}`
    /// and has nowhere to put the `approveRequest` the caller must get signed,
    /// nor any way to express a consent requirement (approver set, threshold,
    /// challenge). A REST caller receiving it could learn it was blocked but
    /// not what to do about it, while the trust-task caller for the very same
    /// decision received the full document. That asymmetry is what this closes.
    ///
    /// `code` is the stable machine-readable reason (`auth:step_up_required`,
    /// `auth:consent_required`) — the field a client keys on, rather than the
    /// HTTP status or the English message. `details` is merged into the body,
    /// so the REST response carries exactly what the trust-task reject's
    /// `details` carries.
    ///
    /// Rendered as **403 Forbidden**: the request was understood and the caller
    /// authenticated; it is refused pending a decision they can still obtain.
    #[error("approval required: {code}")]
    ApprovalRequired {
        code: &'static str,
        details: serde_json::Value,
    },

    #[error("validation error: {0}")]
    Validation(String),

    /// The request did not carry a required `Trust-Task` header. Routes
    /// registered via [`crate::trust_task::TrustTaskRouter::route_with_task`]
    /// reject missing headers with this variant (400). Only `/health` is
    /// allowed to omit it.
    #[error("request is missing required Trust-Task header")]
    TrustTaskMissing,

    /// The request's `Trust-Task` header did not match the handler's
    /// registered task. Returned as 415 per spec §16.2; the response body
    /// carries the expected + received task URLs so clients can diagnose
    /// without re-reading the route table.
    #[error("Trust-Task header does not match handler (expected {expected})")]
    TrustTaskMismatch {
        expected: String,
        received: Option<String>,
    },

    /// The supplied Trust-Task value was not a well-formed identifier
    /// (empty, non-`https://`, or contained header-injection control
    /// characters). Returned as 400.
    #[error("malformed Trust-Task identifier: {0}")]
    TrustTaskMalformed(String),

    /// A request reused an `Idempotency-Key` it had previously sent
    /// with a *different* body hash. The cached response is preserved
    /// for the original requester; the conflicting retry is rejected
    /// with 422 so clients don't silently get a stale response from a
    /// drifting payload.
    #[error("Idempotency-Key conflict: same key, different request body")]
    IdempotencyKeyConflict,

    /// A pagination cursor failed integrity verification — either the
    /// HMAC tag didn't validate (tampered, forged, or signed under a
    /// different community's audit_key) or the encoded form was
    /// malformed. Returned as 400 with no extra detail so an attacker
    /// can't learn whether their guessed cursor was structurally
    /// close to a valid one.
    #[error("invalid pagination cursor")]
    InvalidCursor,

    /// A bounded computation aborted because it hit a resource ceiling
    /// (time/instruction budget or an input-size cap) before completing.
    /// Used by the Rego policy evaluator to refuse pathological policies
    /// or adversarial inputs on the unauthenticated join path rather than
    /// burning CPU unbounded. Rendered as **503 Service Unavailable** — the
    /// evaluation did not complete, and the message is generic so an
    /// attacker can't probe the exact limits.
    #[error("resource limit exceeded: {0}")]
    ResourceExhausted(String),

    /// Catch-all for service-specific errors (e.g., KeyDerivation, BadGateway, TeeAttestation).
    /// Services create helper functions to construct these with appropriate status codes.
    #[error("{message}")]
    ServiceError { status: StatusCode, message: String },

    /// An I/O failure in a vsock operation. Preserves the underlying
    /// `std::io::Error` via `#[source]` while adding a human-readable
    /// label of which operation failed (connect / read / write / flush).
    ///
    /// Construct via [`AppError::vsock`] for ergonomic `.map_err(...)`.
    #[error("{operation} failed: {source}")]
    Vsock {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
}

impl AppError {
    /// Build a closure suitable for `.map_err(...)` that wraps an
    /// `std::io::Error` into [`AppError::Vsock`] with the given operation
    /// label. Keeps the source chain intact for downstream error walkers
    /// while giving log readers the operation name.
    pub fn vsock(operation: &'static str) -> impl FnOnce(std::io::Error) -> AppError {
        move |source| AppError::Vsock { operation, source }
    }
}

/// Convert the canonical auth-flow errors into [`AppError`] so
/// the route layer's existing `IntoResponse` plumbing renders
/// them without backend-specific glue. Each variant lands on the
/// HTTP status reflected in the [`crate::auth::AuthError`]
/// doc-comments:
///
/// - `Forbidden`, `DidMethodRejected` → 403
/// - `PendingChallengeLimitReached` → 429 via the Validation arm
///   (route layer can return a typed 429 if needed; the canonical
///   variant carries the rate-limit signal in the message).
/// - `SessionNotFound`, `SessionStateMismatch`, `ChallengeMismatch`,
///   `ChallengeExpired`, `SignerMismatch`, `StaleMessage`,
///   `RefreshTokenInvalid`, `RefreshTokenExpired` → 401
/// - `AttestationFailed` → 503 via Internal (TEE outages are not
///   the caller's fault).
/// - `Internal` → 500.
impl From<crate::auth::backend::AuthError> for AppError {
    fn from(e: crate::auth::backend::AuthError) -> Self {
        use crate::auth::backend::AuthError as A;
        match e {
            A::Forbidden | A::DidMethodRejected => AppError::Forbidden(e.to_string()),
            A::PendingChallengeLimitReached => AppError::Validation(e.to_string()),
            A::SessionNotFound
            | A::SessionStateMismatch
            | A::ChallengeMismatch
            | A::ChallengeExpired
            | A::SignerMismatch
            | A::StaleMessage
            | A::RefreshTokenInvalid
            | A::RefreshTokenExpired => AppError::Authentication(e.to_string()),
            A::AttestationFailed(msg) => AppError::Internal(format!("tee attestation: {msg}")),
            A::Internal(msg) => AppError::Internal(msg),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Serialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::SecretStore(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Gone(_) => StatusCode::GONE,
            AppError::Secrets(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Authentication(_) => StatusCode::UNAUTHORIZED,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::StepUpRequired(_) => StatusCode::FORBIDDEN,
            AppError::ApprovalRequired { .. } => StatusCode::FORBIDDEN,
            AppError::Validation(_) => StatusCode::BAD_REQUEST,
            AppError::TrustTaskMissing => StatusCode::BAD_REQUEST,
            AppError::TrustTaskMismatch { .. } => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            AppError::TrustTaskMalformed(_) => StatusCode::BAD_REQUEST,
            AppError::IdempotencyKeyConflict => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::InvalidCursor => StatusCode::BAD_REQUEST,
            AppError::ResourceExhausted(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::ServiceError { status, .. } => *status,
            AppError::Vsock { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        };

        if status.is_server_error() {
            warn!(status = %status.as_u16(), error = %self, "server error");
        } else {
            debug!(status = %status.as_u16(), error = %self, "client error");
        }

        // Trust-Task variants get structured payloads so clients can
        // diagnose without re-reading the route table. Every other
        // variant retains the existing `{ "error": "<display>" }` shape
        // for backwards-compat with the workspace's existing consumers.
        let body = match &self {
            AppError::TrustTaskMissing => serde_json::json!({
                "error": "TrustTaskMissing",
                "message": self.to_string(),
            }),
            AppError::TrustTaskMismatch { expected, received } => serde_json::json!({
                "error": "TrustTaskMismatch",
                "message": self.to_string(),
                "expected": expected,
                "received": received,
            }),
            AppError::TrustTaskMalformed(value) => serde_json::json!({
                "error": "TrustTaskMalformed",
                "message": self.to_string(),
                "received": value,
            }),
            AppError::IdempotencyKeyConflict => serde_json::json!({
                "error": "IdempotencyKeyConflict",
                "message": self.to_string(),
            }),
            AppError::StepUpRequired(msg) => serde_json::json!({
                "error": "step_up_required",
                "message": msg,
                "requiredAcr": "aal2",
            }),
            // `details` is merged at the top level rather than nested, so the
            // body reads the same as the trust-task reject's `details` object
            // and a client can key on one shape across both transports. `error`
            // is written last so a `details` carrying that key cannot displace
            // the code the caller switches on.
            AppError::ApprovalRequired { code, details } => {
                let mut body = match details {
                    serde_json::Value::Object(map) => map.clone(),
                    _ => serde_json::Map::new(),
                };
                body.insert("error".to_string(), serde_json::json!(code));
                serde_json::Value::Object(body)
            }
            _ => serde_json::json!({ "error": self.to_string() }),
        };
        (status, axum::Json(body)).into_response()
    }
}

/// Helper to create a service-specific error for key derivation failures.
pub fn key_derivation_error(msg: impl Into<String>) -> AppError {
    AppError::ServiceError {
        status: StatusCode::BAD_REQUEST,
        message: format!("key derivation error: {}", msg.into()),
    }
}

/// Helper to create a service-specific error for bad gateway responses.
pub fn bad_gateway_error(msg: impl Into<String>) -> AppError {
    AppError::ServiceError {
        status: StatusCode::BAD_GATEWAY,
        message: format!("bad gateway: {}", msg.into()),
    }
}

/// Helper to create a service-specific error for TEE attestation failures.
pub fn tee_attestation_error(msg: impl Into<String>) -> AppError {
    AppError::ServiceError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        message: format!("TEE attestation error: {}", msg.into()),
    }
}

#[cfg(test)]
mod approval_required_tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;

    async fn body_of(err: AppError) -> serde_json::Value {
        let resp = err.into_response();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    /// The point of the variant: a REST caller must receive the same actionable
    /// payload the trust-task caller gets, not merely "you were blocked".
    #[tokio::test]
    async fn details_are_merged_alongside_the_code() {
        let body = body_of(AppError::ApprovalRequired {
            code: "auth:step_up_required",
            details: serde_json::json!({
                "requiredAcr": "aal2",
                "approveRequest": { "id": "urn:uuid:abc" },
            }),
        })
        .await;

        assert_eq!(body["error"], "auth:step_up_required");
        assert_eq!(body["requiredAcr"], "aal2");
        assert_eq!(body["approveRequest"]["id"], "urn:uuid:abc");
    }

    #[tokio::test]
    async fn consent_details_survive_the_round_trip() {
        let body = body_of(AppError::ApprovalRequired {
            code: "auth:consent_required",
            details: serde_json::json!({
                "approverSet": "ops",
                "minApprovals": 2,
                "excludeRequester": true,
            }),
        })
        .await;

        assert_eq!(body["error"], "auth:consent_required");
        assert_eq!(body["minApprovals"], 2);
        assert_eq!(body["excludeRequester"], true);
    }

    /// `details` is assembled from a policy decision, so a stray `error` key in
    /// it must not be able to displace the code a client switches on.
    #[tokio::test]
    async fn details_cannot_overwrite_the_code() {
        let body = body_of(AppError::ApprovalRequired {
            code: "auth:consent_required",
            details: serde_json::json!({ "error": "allow", "approverSet": "ops" }),
        })
        .await;

        assert_eq!(body["error"], "auth:consent_required");
        assert_eq!(body["approverSet"], "ops");
    }

    /// A non-object `details` must still yield a well-formed body rather than
    /// panicking or emitting a bare scalar.
    #[tokio::test]
    async fn a_non_object_details_still_renders_the_code() {
        let body = body_of(AppError::ApprovalRequired {
            code: "auth:step_up_required",
            details: serde_json::Value::Null,
        })
        .await;

        assert_eq!(body["error"], "auth:step_up_required");
        assert!(body.as_object().is_some_and(|m| m.len() == 1));
    }

    #[tokio::test]
    async fn renders_as_forbidden() {
        let resp = AppError::ApprovalRequired {
            code: "auth:consent_required",
            details: serde_json::json!({}),
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}

#[cfg(test)]
mod gone_tests {
    use super::*;

    /// The whole point of the variant: a consumed single-use resource (the
    /// canonical example being the TEE Mode B bootstrap carve-out) must
    /// render 410, not 403/409 — the SDK's `VtaError::from_http` keys its
    /// `Gone` mapping off exactly this status code.
    #[test]
    fn renders_as_410_gone() {
        let resp =
            AppError::Gone("TEE first-boot carve-out has already been used".into()).into_response();
        assert_eq!(resp.status(), StatusCode::GONE);
    }

    #[tokio::test]
    async fn body_carries_the_message() {
        use axum::body::to_bytes;

        let resp = AppError::Gone("carve-out closed".into()).into_response();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(body["error"], "gone: carve-out closed");
    }
}
