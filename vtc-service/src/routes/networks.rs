//! A Verifiable Trust Network delivers a broadcast for one of this community's registered
//! groups: `POST /v1/networks/relay/{group_id}` with `{ "envelope": … }`
//! ([`crate::networks::relay`]).
//!
//! The route is unauthenticated by session: the envelope authenticates itself. Its message
//! is signed by the network that originated it, and every hop by the network that relayed
//! it. The last hop must be by a network this community is a member of, delivering to the
//! group it registered there. A delivery that does not verify is refused with `403`, which
//! a network treats as final. A transient failure is `5xx`, which it retries.

use axum::Json;
use axum::extract::{Path, State};
use serde_json::Value;
use vti_common::error::AppError;
use vti_vtn::relay::Envelope;

use crate::networks::{self, NetError};
use crate::server::AppState;

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct RelayDelivery {
    /// The network's envelope: the originating network's signed message and the signed
    /// relay hops.
    #[schema(value_type = Object)]
    pub envelope: Value,
}

/// What the community answers a network: the receipt the VTN relay protocol reads.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct RelayReceipt {
    /// `delivered` — accepted, and pushed to the group's active members — or `duplicate`, a
    /// message this community has already relayed.
    pub status: String,
}

#[utoipa::path(
    post, path = "/networks/relay/{group_id}",
    operation_id = "networkRelayDeliver", tag = "networks",
    params(("group_id" = String, Path, description = "The community group the broadcast is for")),
    request_body = RelayDelivery,
    responses(
        (status = 200, description = "Accepted, and pushed to the group's active members; or already seen", body = RelayReceipt),
        (status = 403, description = "The envelope does not verify, or is not from a network this community registered the group with"),
        (status = 503, description = "The community cannot relay right now"),
    ),
)]
pub async fn relay(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
    Json(body): Json<RelayDelivery>,
) -> Result<Json<RelayReceipt>, AppError> {
    let envelope: Envelope = serde_json::from_value(body.envelope)
        .map_err(|e| AppError::Forbidden(format!("unreadable envelope: {e}")))?;
    match networks::relay(&state, &group_id, envelope).await {
        Ok(receipt) => Ok(Json(RelayReceipt {
            status: receipt["status"]
                .as_str()
                .unwrap_or("delivered")
                .to_string(),
        })),
        Err(NetError::Rejected(why)) => Err(AppError::Forbidden(why)),
        Err(NetError::App(e)) => Err(e),
        Err(other) => Err(AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: other.to_string(),
        }),
    }
}
