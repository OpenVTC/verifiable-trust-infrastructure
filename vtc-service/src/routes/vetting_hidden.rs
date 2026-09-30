//! `/v1/vetting/hidden` — the operator's side of hidden-vetter admission.
//!
//! Hidden vetting needs a community to publish four things before anyone can use it: the suite,
//! the two verification keys, and which labels are live. Everything else on this path already
//! existed — the minting half ([`crate::vetting::pcs_issue`]), the four Trust Tasks
//! ([`crate::vetting::pcs_tasks`]), and the manifest that carries the parameters to a client —
//! and none of it could be reached, because nothing derived the keys and wrote them down.
//!
//! That is what this route is. One call turns a criterion that asks for named vetting into one
//! that also accepts a hidden proof, and returns the parameters so an operator can see what
//! their community now publishes.
//!
//! **The keys are derived, never chosen.** They come from the credential signer's master secret
//! through HKDF, so there is no second secret to provision, back up or leak — and the master
//! secret *is* the vetter class. That is why [`crate::vetting::pcs_issue::issuer`] refuses to
//! mint if what it derives is not what was published: a community whose signer changed under it
//! would otherwise hand out credentials nobody can verify.

use axum::Json;
use axum::extract::State;
use chrono::{Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vti_common::auth::AdminAuth;
use vti_common::error::AppError;

use crate::schemas::accepts::{get_accepts, store_accepts};
use crate::server::AppState;
use crate::vetting::pcs::{HiddenVettingConfig, HiddenVettingEvent};

/// What an operator asks for when they turn hidden vetting on for a criterion.
///
/// Every member but `criterionId` has a default, because the useful call is the short one: a
/// community starting hidden vetting this month wants this month's labels, and having to spell
/// them out is an invitation to spell one of them wrong.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishHiddenVettingBody {
    /// The Accepts criterion this applies to. It must already ask for vetting — the parameters
    /// describe how this community's vetting is carried out, so there must be some.
    pub criterion_id: String,
    /// Live vetter class periods, current first (`["2026-09"]`). Defaults to this month.
    #[serde(default)]
    pub live_periods: Option<Vec<String>>,
    /// Live token labels (`["token/2026-09"]`). Defaults to this month's.
    #[serde(default)]
    pub live_token_labels: Option<Vec<String>>,
    /// How many attestation tokens a vetter draws per tick. Defaults to three.
    #[serde(default)]
    pub drip_per_tick: Option<usize>,
    /// Events this community is running (§5.1), as an array of
    /// `{eventId, startDate, endDate, graceDays?, groupFloor?, tiers[], approvedBy?}`.
    /// Replaces whatever was there; an event is removed by publishing without it.
    ///
    /// Carried as raw JSON rather than the typed shape because the typed shape lives in a
    /// feature-gated module and the OpenAPI derive reaches it from the unconditional document.
    /// It is parsed immediately below, so an operator still gets a refusal naming the member
    /// they got wrong.
    #[serde(default)]
    #[schema(value_type = Option<Vec<Object>>)]
    pub events: Option<Value>,
}

/// What the community now publishes.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublishHiddenVettingResponse {
    /// The criterion that now accepts a hidden proof.
    pub criterion_id: String,
    /// The parameters as stored — including the members a client is not told.
    #[schema(value_type = Object)]
    pub stored: Value,
    /// The parameters exactly as they now appear in this community's join manifest, under
    /// `vetting.ext`. This is what an applicant and a vetter will read.
    #[schema(value_type = Object)]
    pub published: Value,
    /// The criterion's `requirementsDigest` **after** the change. It moves, because the digest
    /// covers the published parameters — an applicant mid-application will be told its
    /// requirements changed, which is the honest answer.
    pub requirements_digest: Option<String>,
}

/// `YYYY-MM` for today, which is the period a community starting now wants.
fn this_month() -> String {
    let now = Utc::now().date_naive();
    format!("{:04}-{:02}", now.year(), now.month())
}

/// Turn on hidden-vetter admission for one criterion.
///
/// Idempotent in the way that matters: calling it again with the same body derives the same keys
/// (they are a function of the master secret) and writes the same parameters. Calling it with
/// different labels rotates them, which is a real change and moves the digest.
#[utoipa::path(
    post, path = "/vetting/hidden",
    operation_id = "vettingHiddenPublish", tag = "vetting",
    security(("bearer_jwt" = [])),
    request_body = PublishHiddenVettingBody,
    responses(
        (status = 200, description = "Hidden vetting is published for this criterion", body = PublishHiddenVettingResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "No such criterion"),
    ),
)]
pub async fn publish_hidden_vetting(
    _admin: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<PublishHiddenVettingBody>,
) -> Result<Json<PublishHiddenVettingResponse>, AppError> {
    let community_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?;

    let mut criterion = get_accepts(&state.schemas_ks, &body.criterion_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no criterion `{}`", body.criterion_id)))?;
    if criterion.vetting.is_none() {
        return Err(AppError::Validation(format!(
            "criterion `{}` asks for no vetting, so there is nothing for hidden-vetting \
             parameters to qualify — give it `vetting` requirements first",
            body.criterion_id
        )));
    }

    let period = this_month();
    let live_periods = body.live_periods.unwrap_or_else(|| vec![period.clone()]);
    let live_token_labels = body
        .live_token_labels
        .unwrap_or_else(|| vec![format!("token/{period}")]);

    let mut config: HiddenVettingConfig = crate::vetting::pcs_issue::publish(
        &state,
        &community_did,
        live_periods,
        live_token_labels,
        body.drip_per_tick.unwrap_or(3),
    )?;
    if let Some(events) = body.events {
        config.events = serde_json::from_value::<Vec<HiddenVettingEvent>>(events)
            .map_err(|e| AppError::Validation(format!("events: {e}")))?;
    }

    let stored = serde_json::to_value(&config)
        .map_err(|e| AppError::Internal(format!("encode hidden-vetting parameters: {e}")))?;
    criterion.hidden_vetting = Some(stored.clone());
    store_accepts(&state.schemas_ks, &criterion).await?;

    // Read the digest back off the criterion as the manifest will serve it, rather than
    // computing it here a second way. Two computations of one digest is how they come to
    // disagree, and this one is what an applicant's proof binds to.
    let served = crate::routes::join_requests::manifest::manifest_criterion(criterion)?;

    Ok(Json(PublishHiddenVettingResponse {
        criterion_id: body.criterion_id,
        stored,
        published: config.published(),
        requirements_digest: served
            .json
            .get("requirementsDigest")
            .and_then(Value::as_str)
            .map(str::to_string),
    }))
}
