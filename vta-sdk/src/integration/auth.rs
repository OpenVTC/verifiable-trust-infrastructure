//! Transport selection + authentication for the integration layer.
//!
//! Tier sequence, in priority order (actual order per invocation is driven
//! by [`TransportPreference`] + whether a `mediator_did` is configured —
//! see [`decide_transport`]):
//!
//! 1. **DIDComm** — identity-native: connecting is authenticating. No
//!    separate challenge-response round-trip, no bearer token to refresh.
//!    Requires a `mediator_did` in [`VtaServiceConfig`]. Preferred when
//!    the integration already speaks DIDComm for its primary workload
//!    (mediators, the typical case).
//! 2. **Lightweight REST** via [`VtaClient::from_credential`]. Works for
//!    VTAs reachable via HTTP(S); uses the `didcomm_light` message
//!    packer to produce the challenge-response envelope and stores the
//!    resulting bearer token with auto-refresh enabled. Resolves
//!    `did:key` (inline, no I/O) and `did:webvh` (fetch + verify the
//!    log) VTAs.
//! 3. **Session-based REST** via [`crate::session::challenge_response`].
//!    Same wire flow as tier 2 but routed through the full TDK stack;
//!    kept as a defensive fallback for VTA DID methods tier 2 doesn't
//!    resolve directly (anything other than `did:key` / `did:webvh`),
//!    where the TDK's full DID resolver is needed.
//!
//! Network errors at tier 2 are returned immediately (the VTA is
//! unreachable; retrying via tier 3 won't help). Non-network errors at
//! tier 2 fall through to tier 3.

use crate::client::VtaClient;
use crate::error::VtaError;

#[cfg(feature = "session")]
use super::TransportPreference;
use super::VtaServiceConfig;

/// Outcome of the transport-selection decision. Pure, deterministic,
/// unit-testable — lets the rest of [`authenticate`] stay focused on
/// side-effectful connect logic.
#[cfg(feature = "session")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TransportPlan {
    /// Try DIDComm first. On failure, fall back to REST tiers (2 → 3).
    DidCommThenRest { mediator_did: String },
    /// Try DIDComm. On failure, error out — do not fall back to REST.
    DidCommOnly { mediator_did: String },
    /// Skip DIDComm, go straight to the REST tiers.
    RestOnly,
    /// Preference required DIDComm but no mediator DID is configured —
    /// fail before any connection attempt with a clear operator message.
    DidCommUnavailable,
}

/// Decide which tier sequence to try, from preference + mediator
/// availability. Pure function; returned [`TransportPlan`] drives
/// [`authenticate`].
///
/// Matrix:
///
/// | preference     | mediator_did | plan                    |
/// |----------------|--------------|-------------------------|
/// | `Auto`         | `Some`       | DIDComm → REST fallback |
/// | `Auto`         | `None`       | REST only               |
/// | `PreferRest`   | any          | REST only               |
/// | `DidCommOnly`  | `Some`       | DIDComm, no fallback    |
/// | `DidCommOnly`  | `None`       | Error (unavailable)     |
#[cfg(feature = "session")]
pub(crate) fn decide_transport(
    preference: TransportPreference,
    mediator_did: Option<&str>,
) -> TransportPlan {
    match (preference, mediator_did) {
        (TransportPreference::PreferRest, _) => TransportPlan::RestOnly,
        (TransportPreference::DidCommOnly, None) => TransportPlan::DidCommUnavailable,
        (TransportPreference::DidCommOnly, Some(m)) => TransportPlan::DidCommOnly {
            mediator_did: m.to_string(),
        },
        (TransportPreference::Auto, None) => TransportPlan::RestOnly,
        (TransportPreference::Auto, Some(m)) => TransportPlan::DidCommThenRest {
            mediator_did: m.to_string(),
        },
    }
}

/// Authenticate to VTA, selecting a transport per the configured
/// [`TransportPreference`].
///
/// See the module-level doc for the tier policy.
pub async fn authenticate(config: &VtaServiceConfig) -> Result<VtaClient, VtaError> {
    let url_override = config.auth.url_override.as_deref();

    #[cfg(feature = "session")]
    {
        let effective_mediator = resolve_effective_mediator_did(config).await?;
        let plan = decide_transport(
            config.context.transport_preference,
            effective_mediator.as_deref(),
        );
        let context_id = &config.context.id;
        match plan {
            TransportPlan::DidCommThenRest { mediator_did } => {
                match try_didcomm(config, &mediator_did).await {
                    Ok(client) => return Ok(client),
                    Err(e) => {
                        // `event = "transport_downgrade"` is a stable,
                        // machine-grep-able tag ops dashboards can count
                        // without parsing the human-readable message.
                        // A rising rate of this event on an otherwise-
                        // healthy DIDComm deployment is a DoS / routing
                        // signal worth paging on.
                        tracing::warn!(
                            event = "transport_downgrade",
                            from = "didcomm",
                            to = "rest",
                            context = context_id,
                            mediator_did = %mediator_did,
                            error = %e,
                            "DIDComm connect failed; falling back to REST tiers",
                        );
                    }
                }
            }
            TransportPlan::DidCommOnly { mediator_did } => {
                return try_didcomm(config, &mediator_did).await.map_err(|e| {
                    tracing::error!(
                        event = "transport_didcomm_only_failed",
                        context = context_id,
                        mediator_did = %mediator_did,
                        error = %e,
                        "DIDComm connect failed and transport_preference is DidCommOnly; \
                         not falling back to REST",
                    );
                    e
                });
            }
            TransportPlan::DidCommUnavailable => {
                return Err(VtaError::Validation(
                    "transport_preference is DidCommOnly but no mediator_did is configured — \
                     set VtaContextConfig::mediator_did or relax to TransportPreference::Auto"
                        .into(),
                ));
            }
            TransportPlan::RestOnly => { /* fall through to REST below */ }
        }
    }

    try_rest(config, url_override).await
}

/// Resolve the mediator DID to use for the DIDComm tier, walking this
/// decision tree:
///
/// 1. Explicit [`VtaServiceConfig::mediator_did`] wins — return it
///    verbatim, skip the resolver round-trip.
/// 2. If the caller asked for [`TransportPreference::PreferRest`],
///    return `None` without touching the network — DIDComm tier is
///    not going to run anyway.
/// 3. Otherwise call [`crate::session::resolve_mediator_did_with_resolver`]
///    on the VTA DID in the credential:
///    - Use the caller-supplied resolver when present (shared cache).
///    - Otherwise create a one-shot [`DIDCacheClient`] on demand.
/// 4. On resolver success, return whatever the DID-document walk
///    produced (`Some(mediator_did)` when a `DIDCommMessaging` service
///    is found, `None` when the doc has no such service).
/// 5. On resolver failure:
///    - [`TransportPreference::DidCommOnly`] → propagate as an error
///      (the caller is asking to fail loud on DIDComm issues).
///    - Otherwise log WARN + return `None` so the authentication
///      flow falls through to REST.
#[cfg(feature = "session")]
async fn resolve_effective_mediator_did(
    config: &VtaServiceConfig,
) -> Result<Option<String>, VtaError> {
    // (1) Explicit always wins.
    if let Some(m) = config.context.mediator_did.as_deref() {
        return Ok(Some(m.to_string()));
    }
    // (2) PreferRest short-circuit — don't pay for a resolver call we
    //     won't use.
    if matches!(
        config.context.transport_preference,
        TransportPreference::PreferRest
    ) {
        return Ok(None);
    }

    // (3) Resolver call. Reuse caller-supplied resolver when provided.
    let vta_did = &config.auth.credential.vta_did;
    let context_id = &config.context.id;
    let result = match config.context.did_resolver.as_ref() {
        Some(resolver) => {
            crate::session::resolve_mediator_did_with_resolver(vta_did, resolver.as_ref()).await
        }
        None => crate::session::resolve_mediator_did(vta_did).await,
    };

    match result {
        Ok(Some(mediator)) => {
            tracing::info!(
                context = context_id,
                vta_did = %vta_did,
                mediator_did = %mediator,
                "Auto-resolved mediator DID from VTA DID document",
            );
            Ok(Some(mediator))
        }
        Ok(None) => {
            tracing::debug!(
                context = context_id,
                vta_did = %vta_did,
                "VTA DID document has no DIDCommMessaging service; DIDComm tier unavailable",
            );
            Ok(None)
        }
        Err(e) => match config.context.transport_preference {
            TransportPreference::DidCommOnly => Err(VtaError::UnsupportedTransport(format!(
                "mediator DID auto-resolve failed and transport_preference is DidCommOnly \
                 (no REST fallback): {e}"
            ))),
            _ => {
                tracing::warn!(
                    context = context_id,
                    vta_did = %vta_did,
                    error = %e,
                    "Mediator DID auto-resolve failed; will try REST tiers",
                );
                Ok(None)
            }
        },
    }
}

/// Tier 1: DIDComm via a mediator. Identity-native auth; no separate
/// bearer token.
#[cfg(feature = "session")]
async fn try_didcomm(config: &VtaServiceConfig, mediator_did: &str) -> Result<VtaClient, VtaError> {
    let credential = &config.auth.credential;
    let client = VtaClient::connect_didcomm(
        &credential.did,
        &credential.private_key_multibase,
        &credential.vta_did,
        mediator_did,
        credential.vta_url.clone(),
    )
    .await?;
    tracing::info!(
        context = config.context.id,
        mediator_did = %mediator_did,
        vta_did = %credential.vta_did,
        "Connected to VTA (DIDComm)",
    );
    Ok(client)
}

/// Tiers 2 + 3: REST. Lightweight (auto-refresh) first, session-REST as
/// a defensive fallback for non-network errors at tier 2. Network errors
/// propagate immediately — retrying a different REST packer against an
/// unreachable VTA won't help.
async fn try_rest(
    config: &VtaServiceConfig,
    url_override: Option<&str>,
) -> Result<VtaClient, VtaError> {
    let context_id = &config.context.id;
    match VtaClient::from_credential(&config.auth.credential, url_override).await {
        Ok(client) => {
            tracing::info!(
                context = context_id,
                vta_url = client.endpoint_label(),
                "Connected to VTA (REST, auto-refresh enabled)",
            );
            Ok(client)
        }
        Err(e) if e.is_network() => Err(e),
        Err(e) => {
            tracing::debug!(
                context = context_id,
                error = %e,
                "Lightweight REST auth failed (non-network); trying session REST",
            );

            let credential = &config.auth.credential;
            let vta_url = url_override
                .or(credential.vta_url.as_deref())
                .ok_or_else(|| {
                    VtaError::Validation("VTA URL not found in credential or url_override".into())
                })?;

            let token_result = crate::session::challenge_response(
                vta_url,
                &credential.did,
                &credential.private_key_multibase,
                &credential.vta_did,
            )
            .await
            .map_err(|e| VtaError::Auth(format!("session challenge-response failed: {e}")))?;

            let client = VtaClient::new(vta_url);
            client.set_token_async(token_result.access_token).await;

            tracing::info!(
                context = context_id,
                vta_url = vta_url,
                "Connected to VTA (REST, session auth)",
            );
            Ok(client)
        }
    }
}

#[cfg(all(test, feature = "session"))]
mod tests {
    use super::*;

    #[test]
    fn plan_auto_with_mediator_picks_didcomm_then_rest() {
        let plan = decide_transport(TransportPreference::Auto, Some("did:key:zMed"));
        assert_eq!(
            plan,
            TransportPlan::DidCommThenRest {
                mediator_did: "did:key:zMed".into()
            }
        );
    }

    #[test]
    fn plan_auto_without_mediator_picks_rest_only() {
        let plan = decide_transport(TransportPreference::Auto, None);
        assert_eq!(plan, TransportPlan::RestOnly);
    }

    #[test]
    fn plan_prefer_rest_ignores_mediator() {
        assert_eq!(
            decide_transport(TransportPreference::PreferRest, Some("did:key:zMed")),
            TransportPlan::RestOnly
        );
        assert_eq!(
            decide_transport(TransportPreference::PreferRest, None),
            TransportPlan::RestOnly
        );
    }

    #[test]
    fn plan_didcomm_only_with_mediator_does_not_fall_back() {
        let plan = decide_transport(TransportPreference::DidCommOnly, Some("did:key:zMed"));
        assert_eq!(
            plan,
            TransportPlan::DidCommOnly {
                mediator_did: "did:key:zMed".into()
            }
        );
    }

    #[test]
    fn plan_didcomm_only_without_mediator_errors() {
        let plan = decide_transport(TransportPreference::DidCommOnly, None);
        assert_eq!(plan, TransportPlan::DidCommUnavailable);
    }
}
