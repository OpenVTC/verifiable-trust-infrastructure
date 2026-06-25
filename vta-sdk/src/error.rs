//! Structured error type for VTA SDK operations.

/// Errors returned by VTA SDK client operations.
#[derive(Debug, thiserror::Error)]
pub enum VtaError {
    /// Network-level error (connection refused, timeout, DNS failure).
    #[cfg(feature = "client")]
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    /// Authentication failed (401) or token expired.
    #[error("authentication failed: {0}")]
    Auth(String),

    /// Resource not found (404).
    #[error("not found: {0}")]
    NotFound(String),

    /// Request validation error (400).
    #[error("validation error: {0}")]
    Validation(String),

    /// Permission denied (403).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Conflict (409) — e.g. duplicate key ID.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Gone (410) — the resource existed but is now permanently unavailable.
    /// Most often emitted by the bootstrap carve-out endpoint after it has
    /// been consumed; the CLI surfaces this with a "did you mean to run
    /// `… provision-request`" hint instead of a flat string.
    #[error("gone: {0}")]
    Gone(String),

    /// Server error (5xx).
    #[error("server error ({status}): {body}")]
    Server { status: u16, body: String },

    /// The operation does not support the transport the client is
    /// configured for (e.g. calling a REST-only helper on a client built
    /// with DIDComm-only transport, or vice versa).
    #[error("unsupported transport: {0}")]
    UnsupportedTransport(String),

    /// DIDComm transport failure (pack/send/pickup). Network-ish —
    /// caller may want to retry. Distinct from [`Self::Network`] which
    /// is REST-specific and carries a `reqwest::Error`.
    #[error("didcomm transport error: {0}")]
    DidcommTransport(String),

    /// Remote endpoint returned a DIDComm problem-report whose `code`
    /// did not match any of the standard `e.p.msg.*` taxonomy variants
    /// (which map to the typed REST-aligned variants above). Inspect
    /// `code` to handle it; a typed [`Self::Conflict`] / [`Self::NotFound`]
    /// / [`Self::Auth`] / [`Self::Validation`] / [`Self::Server`] will
    /// already have been emitted for the standard codes.
    #[error("didcomm remote error ({code}): {comment}")]
    DidcommRemote { code: String, comment: String },

    /// Programmer-level protocol error (response shape did not match
    /// what the SDK expected — version mismatch or bug). Distinct from
    /// remote-error: a peer that returned a problem-report becomes a
    /// typed variant via [`Self::from_problem_report`], not this one.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    // ── Runtime service-management variants (spec §4) ──────────────
    //
    // These are emitted by the post-setup service-management surface
    // (`services {rest,didcomm} {enable,update,disable,rollback}`).
    // Structured data for the variants that carry numeric fields
    // round-trips lossless via [`TypedErrorPayload`] across both
    // REST response bodies and DIDComm problem-report args.
    /// The operation would leave the VTA's DID document with no
    /// advertised transport services. Per spec §3.2, this is rejected
    /// without a `--force` escape hatch — enable the other transport
    /// first if a swap is intended.
    #[error("refusing operation: would leave the VTA with no advertised services")]
    LastServiceRefused,

    /// `update`, `disable`, or a kind-specific drain action was
    /// invoked for a service kind that isn't currently enabled.
    #[error("service is not present (not currently enabled)")]
    ServiceNotPresent,

    /// `enable` was invoked for a service kind that's already
    /// enabled. Use `update` to change its configuration.
    #[error("service is already enabled")]
    ServiceAlreadyEnabled,

    /// DIDComm handshake against the candidate mediator failed
    /// (trust-ping refused, timed out, or peer was unreachable).
    #[error("mediator handshake failed: {reason}")]
    MediatorHandshakeFailed { reason: String },

    /// Drain TTL is outside the valid range. Bounds are
    /// `MIN_DRAIN_TTL_OVER_DIDCOMM` (3600s, when the disable command
    /// is itself delivered over DIDComm) and `MAX_DRAIN_TTL`
    /// (30 days). All three fields are in seconds.
    #[error("drain ttl {requested}s outside allowed range [{min}s, {max}s]")]
    DrainTtlOutOfBounds { min: u64, max: u64, requested: u64 },

    /// `rollback` was invoked for a service kind that has no prior
    /// mutation in its snapshot store to fail-forward from.
    #[error("no prior mutation to roll back from")]
    NoPriorMutation,

    /// Catch-all for other errors.
    /// No transport protocol is advertised by **both** this party and the
    /// counterparty, so there is no way to communicate. Carries each side's
    /// advertised set (in preference order) so the CLI can show the operator
    /// what each offers and which transport to enable. Determined locally by
    /// [`crate::protocol::matching::select_protocol`] after resolving the
    /// peer's DID document — never a server-returned wire error.
    #[error(
        "no transport protocol in common with {counterparty_did}: \
         we advertise {ours:?}, they advertise {theirs:?}"
    )]
    NoMatchingProtocol {
        counterparty_did: String,
        ours: Vec<crate::protocol::matching::Protocol>,
        theirs: Vec<crate::protocol::matching::Protocol>,
    },

    #[error("{0}")]
    Other(String),
}

/// Wire-format companion to the typed [`VtaError`] variants emitted
/// by the runtime service-management surface.
///
/// The free-form `comment` string carried by DIDComm problem-reports
/// (and the `body` string of REST error responses) is fine for the
/// variants whose only data is a human-readable message
/// ([`VtaError::Conflict`], [`VtaError::NotFound`], …) but lossy for
/// variants like [`VtaError::DrainTtlOutOfBounds`] that carry three
/// numeric fields the CLI needs to switch on.
///
/// Servers serialize a `TypedErrorPayload` into the response body
/// (REST) or problem-report `args` (DIDComm); clients deserialize
/// it back via [`VtaError::from_typed_payload`]. The discriminator
/// is the kebab-cased variant name in the `code` field.
///
/// Variants line up 1:1 with the §4 spec list — the existing
/// [`VtaError::UnsupportedTransport`] is included so the same
/// channel carries every typed-error wire form.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "code", rename_all = "kebab-case")]
pub enum TypedErrorPayload {
    LastServiceRefused,
    ServiceNotPresent,
    ServiceAlreadyEnabled,
    MediatorHandshakeFailed { reason: String },
    DrainTtlOutOfBounds { min: u64, max: u64, requested: u64 },
    NoPriorMutation,
    UnsupportedTransport { detail: String },
}

impl VtaError {
    /// Create from an HTTP response status and error body.
    ///
    /// Public so a downstream SDK consumer wiring its own HTTP transport
    /// (e.g. a wasm `gloo-net` client) can produce typed `VtaError`s
    /// from status codes without re-implementing the mapping.
    #[cfg(feature = "client")]
    pub fn from_http(status: reqwest::StatusCode, body: String) -> Self {
        match status.as_u16() {
            401 => Self::Auth(body),
            403 => Self::Forbidden(body),
            404 => Self::NotFound(body),
            400 | 422 => Self::Validation(body),
            409 => Self::Conflict(body),
            410 => Self::Gone(body),
            s if s >= 500 => Self::Server { status: s, body },
            s => Self::Other(format!("{s}: {body}")),
        }
    }

    /// Create from a DIDComm problem-report `code` + `comment`. Mirrors
    /// the REST [`Self::from_http`] mapping so callers can `match` on the
    /// same variants regardless of transport.
    ///
    /// Standard codes (`e.p.msg.unauthorized` / `bad-request` / `not-found`
    /// / `conflict` / `internal-error`) become typed variants. Anything
    /// else lands in [`Self::DidcommRemote`] preserving the original code.
    pub fn from_problem_report(code: &str, comment: impl Into<String>) -> Self {
        use crate::protocols::problem_report_codes as c;
        let comment = comment.into();
        match code {
            c::CONFLICT => Self::Conflict(comment),
            c::NOT_FOUND => Self::NotFound(comment),
            c::UNAUTHORIZED => Self::Auth(comment),
            c::FORBIDDEN => Self::Forbidden(comment),
            c::BAD_REQUEST => Self::Validation(comment),
            c::INTERNAL => Self::Server {
                status: 500,
                body: comment,
            },
            other => Self::DidcommRemote {
                code: other.to_string(),
                comment,
            },
        }
    }

    /// Reconstruct the typed [`VtaError`] variant from a wire-format
    /// [`TypedErrorPayload`]. Used by the client when decoding REST
    /// response bodies / DIDComm problem-report args for the runtime
    /// service-management surface (spec §4).
    pub fn from_typed_payload(payload: TypedErrorPayload) -> Self {
        match payload {
            TypedErrorPayload::LastServiceRefused => Self::LastServiceRefused,
            TypedErrorPayload::ServiceNotPresent => Self::ServiceNotPresent,
            TypedErrorPayload::ServiceAlreadyEnabled => Self::ServiceAlreadyEnabled,
            TypedErrorPayload::MediatorHandshakeFailed { reason } => {
                Self::MediatorHandshakeFailed { reason }
            }
            TypedErrorPayload::DrainTtlOutOfBounds {
                min,
                max,
                requested,
            } => Self::DrainTtlOutOfBounds {
                min,
                max,
                requested,
            },
            TypedErrorPayload::NoPriorMutation => Self::NoPriorMutation,
            TypedErrorPayload::UnsupportedTransport { detail } => {
                Self::UnsupportedTransport(detail)
            }
        }
    }

    /// Project this error onto the wire-format [`TypedErrorPayload`]
    /// when the variant is one of the runtime service-management
    /// errors. Returns `None` for variants that don't have a
    /// structured wire form (network errors, generic conflicts,
    /// programmer-level protocol errors, …).
    #[must_use]
    pub fn to_typed_payload(&self) -> Option<TypedErrorPayload> {
        match self {
            Self::LastServiceRefused => Some(TypedErrorPayload::LastServiceRefused),
            Self::ServiceNotPresent => Some(TypedErrorPayload::ServiceNotPresent),
            Self::ServiceAlreadyEnabled => Some(TypedErrorPayload::ServiceAlreadyEnabled),
            Self::MediatorHandshakeFailed { reason } => {
                Some(TypedErrorPayload::MediatorHandshakeFailed {
                    reason: reason.clone(),
                })
            }
            Self::DrainTtlOutOfBounds {
                min,
                max,
                requested,
            } => Some(TypedErrorPayload::DrainTtlOutOfBounds {
                min: *min,
                max: *max,
                requested: *requested,
            }),
            Self::NoPriorMutation => Some(TypedErrorPayload::NoPriorMutation),
            Self::UnsupportedTransport(detail) => Some(TypedErrorPayload::UnsupportedTransport {
                detail: detail.clone(),
            }),
            _ => None,
        }
    }

    /// Returns true if the resource was permanently consumed/gone (410).
    pub fn is_gone(&self) -> bool {
        matches!(self, Self::Gone(_))
    }

    /// Returns true if a create/insert collided with an existing entry (409).
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict(_))
    }

    /// Returns true if this is an authentication/authorization error.
    pub fn is_auth(&self) -> bool {
        matches!(self, Self::Auth(_) | Self::Forbidden(_))
    }

    /// Returns true if this is a network-level error (retryable).
    pub fn is_network(&self) -> bool {
        #[cfg(feature = "client")]
        if matches!(self, Self::Network(_)) {
            return true;
        }
        false
    }

    /// Returns true if the resource was not found.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }

    /// Operator-actionable hint matching this error variant.
    ///
    /// `None` for variants where no generic guidance applies (the message
    /// itself is the hint, or the failure is a programmer error). The
    /// CLI layer (`vta-cli-common::render::print_cli_error`) already
    /// implements bin-aware suggestions ("`pnm acl create …`"); this
    /// method gives **non-CLI consumers** — web UIs, GUIs, custom
    /// dashboards — the same hint surface without needing to fork the
    /// dispatch logic.
    ///
    /// Returns a `&'static str` so callers can compose it into their
    /// own UI without lifetime juggling. The bin-specific substitution
    /// (`pnm` vs `cnm`) is left to the CLI layer because only it
    /// knows which binary the operator is running.
    #[must_use]
    pub fn suggested_fix(&self) -> Option<&'static str> {
        match self {
            Self::Auth(_) => Some(
                "Token may be expired. Re-authenticate against the VTA, or check that \
                 the `/auth` endpoint is reachable.",
            ),
            Self::Forbidden(_) => Some(
                "Your role or context access doesn't permit this operation. Inspect \
                 the ACL entry for your DID against the target context.",
            ),
            Self::Gone(_) => Some(
                "The resource has been permanently consumed. The single-use bootstrap \
                 carve-out has likely already been used; ask an existing admin to \
                 provision-integration a new operator instead.",
            ),
            Self::Conflict(_) => Some(
                "The resource already exists. Use the corresponding `update` or \
                 `delete-then-create` flow rather than `create`.",
            ),
            Self::Validation(_) => Some(
                "The request body or parameters were rejected by the VTA's schema. \
                 Inspect the response body for the specific field that failed.",
            ),
            Self::Server { .. } => {
                Some("VTA-side failure. Check the VTA's server logs or contact the operator.")
            }
            Self::UnsupportedTransport(_) => Some(
                "The operation requires a specific transport (REST or DIDComm). \
                 Check which mode the client is in and whether the endpoint supports it.",
            ),
            Self::DidcommTransport(_) => {
                Some("Mediator or peer unreachable. Retry after checking mediator connectivity.")
            }
            #[cfg(feature = "client")]
            Self::Network(_) => Some(
                "Network error reaching the VTA. Confirm the URL is correct and the \
                 host is reachable.",
            ),
            // Runtime service-management variants (spec §4). The CLI
            // layer enriches these with the specific kind/command
            // it just ran; this is the generic fallback hint for
            // non-CLI consumers.
            Self::LastServiceRefused => Some(
                "This operation would leave the VTA with no advertised transport \
                 services. Enable the other transport first (REST or DIDComm) \
                 before disabling this one.",
            ),
            Self::ServiceNotPresent => Some(
                "The service kind isn't currently enabled. Use \
                 `services <kind> enable …` to bring it online before \
                 updating, disabling, or rolling it back.",
            ),
            Self::ServiceAlreadyEnabled => Some(
                "The service kind is already enabled. Use \
                 `services <kind> update …` to change its configuration, \
                 or `disable` to remove it.",
            ),
            Self::MediatorHandshakeFailed { .. } => Some(
                "DIDComm handshake against the candidate mediator failed. \
                 Confirm the mediator DID is correct and the mediator is \
                 reachable; check the inner reason for the specific cause.",
            ),
            Self::DrainTtlOutOfBounds { .. } => Some(
                "The supplied drain TTL is outside the allowed range. Pick a \
                 value within the [min, max] interval shown in the error message.",
            ),
            Self::NoPriorMutation => Some(
                "No prior mutation for this service kind to roll back from. Use \
                 the direct `enable`/`update`/`disable` command instead.",
            ),
            Self::NoMatchingProtocol { .. } => Some(
                "The two parties share no transport protocol. Enable a common \
                 transport (TSP, DIDComm, or REST) on both sides — compare each \
                 DID document's advertised `service` entries and add the missing one.",
            ),
            // No generic hint for these — the message itself is the
            // hint, or the failure is a protocol/programmer error
            // surface that an automated suggestion would only confuse.
            Self::NotFound(_)
            | Self::DidcommRemote { .. }
            | Self::Protocol(_)
            | Self::Serialization(_)
            | Self::Other(_) => None,
        }
    }
}

impl From<crate::did_key::DidKeyError> for VtaError {
    fn from(e: crate::did_key::DidKeyError) -> Self {
        Self::Validation(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "client")]
    #[test]
    fn from_http_410_maps_to_gone() {
        let err = VtaError::from_http(reqwest::StatusCode::GONE, "carve-out closed".into());
        assert!(err.is_gone(), "410 must map to VtaError::Gone, got {err:?}");
    }

    #[test]
    fn problem_report_conflict_maps_to_typed_conflict() {
        let err = VtaError::from_problem_report(
            crate::protocols::problem_report_codes::CONFLICT,
            "key id already exists",
        );
        assert!(matches!(err, VtaError::Conflict(_)), "got {err:?}");
        assert!(err.is_conflict());
    }

    #[test]
    fn problem_report_unknown_code_lands_in_didcomm_remote() {
        let err = VtaError::from_problem_report("e.custom.xyz", "weird thing");
        match err {
            VtaError::DidcommRemote { code, comment } => {
                assert_eq!(code, "e.custom.xyz");
                assert_eq!(comment, "weird thing");
            }
            other => panic!("expected DidcommRemote, got {other:?}"),
        }
    }

    #[test]
    fn suggested_fix_present_for_actionable_variants() {
        // Each "operator can do something about this" variant must have
        // a hint string; the message-is-the-hint / programmer-error
        // variants return None.
        assert!(VtaError::Auth("expired".into()).suggested_fix().is_some());
        assert!(VtaError::Forbidden("nope".into()).suggested_fix().is_some());
        assert!(VtaError::Gone("used".into()).suggested_fix().is_some());
        assert!(VtaError::Conflict("dup".into()).suggested_fix().is_some());
        assert!(VtaError::Validation("bad".into()).suggested_fix().is_some());
        assert!(
            VtaError::Server {
                status: 500,
                body: "boom".into(),
            }
            .suggested_fix()
            .is_some()
        );
        assert!(
            VtaError::UnsupportedTransport("rest only".into())
                .suggested_fix()
                .is_some()
        );
        assert!(
            VtaError::DidcommTransport("offline".into())
                .suggested_fix()
                .is_some()
        );

        // Runtime service-management variants (spec §4) all have hints.
        assert!(VtaError::LastServiceRefused.suggested_fix().is_some());
        assert!(VtaError::ServiceNotPresent.suggested_fix().is_some());
        assert!(VtaError::ServiceAlreadyEnabled.suggested_fix().is_some());
        assert!(
            VtaError::MediatorHandshakeFailed {
                reason: "trust-ping timeout".into()
            }
            .suggested_fix()
            .is_some()
        );
        assert!(
            VtaError::DrainTtlOutOfBounds {
                min: 3600,
                max: 2_592_000,
                requested: 30,
            }
            .suggested_fix()
            .is_some()
        );
        assert!(VtaError::NoPriorMutation.suggested_fix().is_some());

        // Self-explanatory / programmer-error: no canned hint.
        assert!(VtaError::NotFound("x".into()).suggested_fix().is_none());
        assert!(VtaError::Protocol("shape".into()).suggested_fix().is_none());
        assert!(
            VtaError::DidcommRemote {
                code: "e.unknown".into(),
                comment: "x".into()
            }
            .suggested_fix()
            .is_none()
        );
    }

    /// Every typed runtime service-management variant must round-trip
    /// through [`TypedErrorPayload`] without losing structured data.
    /// The test cases line up 1:1 with the spec §4 list.
    #[test]
    fn typed_payload_round_trips_every_runtime_service_variant() {
        let cases: Vec<VtaError> = vec![
            VtaError::LastServiceRefused,
            VtaError::ServiceNotPresent,
            VtaError::ServiceAlreadyEnabled,
            VtaError::MediatorHandshakeFailed {
                reason: "trust-ping timeout after 10s".into(),
            },
            VtaError::DrainTtlOutOfBounds {
                min: 3600,
                max: 2_592_000,
                requested: 30,
            },
            VtaError::NoPriorMutation,
            VtaError::UnsupportedTransport("services didcomm enable is REST-only".into()),
        ];

        for original in cases {
            let payload = original.to_typed_payload().unwrap_or_else(|| {
                panic!("variant must project to TypedErrorPayload: {original:?}")
            });

            // Round-trip through JSON to mirror what REST and DIDComm
            // transports actually do on the wire.
            let json = serde_json::to_string(&payload)
                .unwrap_or_else(|e| panic!("payload must serialize: {e}"));
            let restored: TypedErrorPayload = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("payload must deserialize: {e}; raw={json}"));

            assert_eq!(
                payload, restored,
                "TypedErrorPayload must round-trip through JSON",
            );

            // Reconstructing back to VtaError preserves the variant
            // discriminant and any structured data.
            let reconstructed = VtaError::from_typed_payload(restored);
            match (&original, &reconstructed) {
                (VtaError::LastServiceRefused, VtaError::LastServiceRefused)
                | (VtaError::ServiceNotPresent, VtaError::ServiceNotPresent)
                | (VtaError::ServiceAlreadyEnabled, VtaError::ServiceAlreadyEnabled)
                | (VtaError::NoPriorMutation, VtaError::NoPriorMutation) => {}
                (
                    VtaError::MediatorHandshakeFailed { reason: a },
                    VtaError::MediatorHandshakeFailed { reason: b },
                ) => assert_eq!(a, b),
                (
                    VtaError::DrainTtlOutOfBounds {
                        min: m1,
                        max: x1,
                        requested: r1,
                    },
                    VtaError::DrainTtlOutOfBounds {
                        min: m2,
                        max: x2,
                        requested: r2,
                    },
                ) => {
                    assert_eq!(m1, m2);
                    assert_eq!(x1, x2);
                    assert_eq!(r1, r2);
                }
                (VtaError::UnsupportedTransport(a), VtaError::UnsupportedTransport(b)) => {
                    assert_eq!(a, b)
                }
                (a, b) => panic!("variant changed across round-trip: {a:?} → {b:?}"),
            }
        }
    }

    /// The kebab-case `code` discriminator on the wire JSON is part of
    /// the contract for both REST and DIDComm transports — pin it
    /// explicitly so a `serde(rename)` change doesn't silently break
    /// existing peers.
    #[test]
    fn typed_payload_wire_discriminator_is_kebab_case() {
        let payload = TypedErrorPayload::DrainTtlOutOfBounds {
            min: 3600,
            max: 2_592_000,
            requested: 30,
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["code"], "drain-ttl-out-of-bounds");
        assert_eq!(json["min"], 3600);
        assert_eq!(json["max"], 2_592_000);
        assert_eq!(json["requested"], 30);
    }

    /// `to_typed_payload` returns `None` for variants outside the
    /// runtime service-management surface — the wire-format channel
    /// is reserved for those typed variants and shouldn't blanket
    /// every error.
    #[test]
    fn typed_payload_is_none_for_non_service_management_variants() {
        assert!(VtaError::Auth("x".into()).to_typed_payload().is_none());
        assert!(VtaError::NotFound("x".into()).to_typed_payload().is_none());
        assert!(VtaError::Conflict("x".into()).to_typed_payload().is_none());
        assert!(
            VtaError::Server {
                status: 500,
                body: "x".into(),
            }
            .to_typed_payload()
            .is_none()
        );
        assert!(VtaError::Protocol("x".into()).to_typed_payload().is_none());
        assert!(
            VtaError::DidcommRemote {
                code: "e.x".into(),
                comment: "x".into()
            }
            .to_typed_payload()
            .is_none()
        );
        assert!(VtaError::Other("x".into()).to_typed_payload().is_none());
    }
}
