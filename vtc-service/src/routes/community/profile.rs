//! `GET /v1/community/public-profile` — the curated, unauthenticated read of
//! the community profile a visitor's browser renders the landing page from.
//! A declared public route; the authenticated read and the edit are signed
//! documents (`crate::community::ops::profile`).

use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use serde::Serialize;
use vti_common::error::AppError;

use crate::community::load_profile;
use crate::server::AppState;

/// Public read shape — the curated subset of [`CommunityProfile`]
/// exposed unauthenticated at `GET /v1/community/public-profile`.
///
/// Drops `extensions` (operator-defined JSON, not guaranteed
/// public-safe) and `registryStatus` (operational telemetry that
/// belongs behind admin auth). Adds `mediator_did` so the default
/// landing page can render the community's full identity in one
/// fetch.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct PublicCommunityProfile {
    pub community_did: String,
    pub name: String,
    pub description: String,
    pub logo_url: Option<String>,
    pub public_url: Option<String>,
    pub contact_email: Option<String>,
    pub language: String,
    pub created_at: DateTime<Utc>,
    /// What this community's governance asserts about personhood.
    ///
    /// Published **unauthenticated, on purpose**. DTG Credentials puts PHC
    /// status in "governance and trust registries, not credential structure",
    /// so the party who needs this is a verifier holding one of this
    /// community's VMCs — someone who is not a member, has no token, and may
    /// have no relationship with the community at all. Behind auth it would
    /// answer the question only for people who did not need to ask it.
    ///
    /// This is the *community's own claim about itself*. A verifier deciding
    /// how much it is worth reads the trust registry, which is what the spec
    /// calls authoritative; this is the self-published copy, and it is here so
    /// the claim is resolvable at all rather than so it is trusted.
    pub personhood: crate::community::PersonhoodGovernance,
    /// The community's DIDComm mediator DID, if one is configured.
    /// Sourced from the live daemon config (same as `/health`), not
    /// the persisted profile row.
    pub mediator_did: Option<String>,
    /// How to reach this community, and whether each route currently works.
    ///
    /// Every protocol is listed, each carrying `advertised` (the DID document
    /// offers it) and `serviceable` (this VTC can answer on it right now).
    /// Reachable means both.
    ///
    /// **The DID document remains authoritative.** This is a *view* of it,
    /// resolved at request time, published so a visitor or a monitor can
    /// validate connectivity without resolving the DID themselves — never an
    /// independent declaration. A client choosing a transport must still match
    /// on the document's service `type`; if the two ever disagree, the document
    /// wins and this field is the thing that is wrong.
    ///
    /// Empty when the community's own DID could not be resolved — reported as
    /// unknown rather than as "advertises nothing", which would be a lie a
    /// caller might act on.
    pub transports: Vec<crate::transport_capability::TransportStatus>,
}

/// Public GET handler. Trust-Task-exempt, no auth. Returns only the
/// curated subset of profile fields a visitor's browser should see.
/// GET /community/public-profile — curated public community profile.
/// Public, unauthenticated.
#[utoipa::path(
    get, path = "/community/public-profile", tag = "community",
    responses(
        (status = 200, description = "Public community profile", body = PublicCommunityProfile),
        (status = 404, description = "Community profile not initialised"),
    ),
)]
pub async fn get_public_profile(
    State(state): State<AppState>,
) -> Result<Json<PublicCommunityProfile>, AppError> {
    let profile = load_profile(&state.community_ks)
        .await?
        .ok_or_else(|| AppError::NotFound("community profile not initialised".into()))?;
    let mediator_did = state
        .config
        .read()
        .await
        .messaging
        .as_ref()
        .map(|m| m.mediator_did.clone());

    // Live mediator connectivity, off the delivery transport's re-falsifiable
    // signal — the same source `/health/diagnostics` reads, never a boot latch
    // (R6.2). A published "reachable" that cannot go false again would be worse
    // than publishing nothing.
    let messaging_connected = matches!(
        state.didcomm.get().map(|m| m.service.status()),
        Some(affinidi_messaging_delivery::MessagingStatus::Connected)
    );

    // Resolved rather than read from config or the local `did.jsonl`: the
    // document is the authority for what this community advertises, and it can
    // gain a service long after the VTC last wrote its own mirror — which is
    // exactly what happened to the deployment that motivated this
    // (`#tsp` arrived at DID log version 3). The resolver caches, so the common
    // case costs no network even though this endpoint is unauthenticated.
    let transports = match crate::transport_capability::resolved_capabilities(
        state.did_resolver.as_ref(),
        &profile.community_did,
    )
    .await
    {
        Some(caps) => {
            crate::transport_capability::public_transport_view_for_build(&caps, messaging_connected)
        }
        // Unknown, not "none". Publishing an empty advertised set would tell a
        // visitor this community offers no way in, which is a different — and
        // actionable — claim from "we could not check".
        None => Vec::new(),
    };

    Ok(Json(PublicCommunityProfile {
        community_did: profile.community_did,
        name: profile.name,
        description: profile.description,
        logo_url: profile.logo_url,
        public_url: profile.public_url,
        contact_email: profile.contact_email,
        language: profile.language,
        created_at: profile.created_at,
        personhood: profile.personhood,
        mediator_did,
        transports,
    }))
}
