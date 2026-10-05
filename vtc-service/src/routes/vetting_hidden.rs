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

use chrono::{Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vti_common::error::AppError;

use crate::error::TaskError;
use crate::schemas::accepts::AcceptsCriterion;
use crate::schemas::accepts::{get_accepts, store_accepts};
use crate::server::AppState;
use crate::vetting::pcs::{HiddenVettingConfig, HiddenVettingEvent};
use crate::vetting::pcs_tasks::{
    HIDDEN_PUBLISH_ERR_APPROVER_IN_EVENT, HIDDEN_PUBLISH_ERR_APPROVER_NOT_SIGNER,
    HIDDEN_PUBLISH_ERR_NO_SUCH_CRITERION, HIDDEN_PUBLISH_ERR_NO_VETTING,
    HIDDEN_SHOW_ERR_NO_SUCH_CRITERION, HIDDEN_WITHDRAW_ERR_NO_SUCH_CRITERION,
};
use vti_common::audit::{AuditEvent, HiddenVettingChangedData};

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
///
/// Shared by the REST route below and `vtc/vetting/hidden/publish/0.1`
/// (`crate::trust_tasks::handle_hidden_publish`) — one implementation, so the
/// two doors cannot drift.
pub(crate) async fn publish_hidden_vetting_core(
    state: &AppState,
    signer: &str,
    criterion_id: String,
    live_periods: Option<Vec<String>>,
    live_token_labels: Option<Vec<String>>,
    drip_per_tick: Option<usize>,
    events: Option<Value>,
) -> Result<PublishHiddenVettingResponse, TaskError> {
    let community_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?;

    let mut criterion = get_accepts(&state.schemas_ks, &criterion_id)
        .await?
        .ok_or_else(|| {
            TaskError::declared(
                HIDDEN_PUBLISH_ERR_NO_SUCH_CRITERION,
                AppError::NotFound(format!("no criterion `{criterion_id}`")),
            )
        })?;
    if criterion.vetting.is_none() {
        return Err(TaskError::declared(
            HIDDEN_PUBLISH_ERR_NO_VETTING,
            AppError::Validation(format!(
                "criterion `{criterion_id}` asks for no vetting, so there is nothing for \
                 hidden-vetting parameters to qualify — give it `vetting` requirements first",
            )),
        ));
    }

    let period = this_month();
    let live_periods = live_periods.unwrap_or_else(|| vec![period.clone()]);
    let live_token_labels = live_token_labels.unwrap_or_else(|| vec![format!("token/{period}")]);

    let mut config: HiddenVettingConfig = crate::vetting::pcs_issue::publish(
        state,
        &community_did,
        live_periods,
        live_token_labels,
        drip_per_tick.unwrap_or(3),
    )?;
    if let Some(events) = events {
        config.events = serde_json::from_value::<Vec<HiddenVettingEvent>>(events)
            .map_err(|e| AppError::Validation(format!("events: {e}")))?;
    }

    let previous: Vec<HiddenVettingEvent> = criterion
        .hidden_vetting
        .as_ref()
        .and_then(|v| serde_json::from_value::<HiddenVettingConfig>(v.clone()).ok())
        .map(|c| c.events)
        .unwrap_or_default();
    let approved_events = check_approvals(state, signer, &previous, &config.events).await?;

    let stored = serde_json::to_value(&config)
        .map_err(|e| AppError::Internal(format!("encode hidden-vetting parameters: {e}")))?;
    criterion.hidden_vetting = Some(stored.clone());
    store_accepts(&state.schemas_ks, &criterion).await?;

    audit_change(
        state,
        signer,
        HiddenVettingChangedData {
            criterion_id: criterion_id.clone(),
            change: "published".into(),
            vetter_labels: config
                .live_periods
                .iter()
                .map(|p| format!("vetter/{p}"))
                .collect(),
            token_labels: config.live_token_labels.clone(),
            drip_per_tick: Some(config.drip_per_tick),
            events: config.events.iter().map(|e| e.event_id.clone()).collect(),
            approved_events,
        },
    )
    .await?;

    // Read the digest back off the criterion as the manifest will serve it, rather than
    // computing it here a second way. Two computations of one digest is how they come to
    // disagree, and this one is what an applicant's proof binds to.
    let served = crate::routes::join_requests::manifest::manifest_criterion(criterion)?;

    Ok(PublishHiddenVettingResponse {
        criterion_id,
        stored,
        published: config.published(),
        requirements_digest: served
            .json
            .get("requirementsDigest")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

/// The approval rules publish/0.1 states (items 9 and 10): an event's `approvedBy`, when it is
/// newly set or changed against what is stored, must be the administrator publishing it — an
/// approver names themselves — and no approver may be someone who asked to vet at the event.
/// An unchanged stored approval may be re-sent by anyone, so a re-publish keeps it.
///
/// Returns the ids of the events this publish approves.
async fn check_approvals(
    state: &AppState,
    signer: &str,
    previous: &[HiddenVettingEvent],
    events: &[HiddenVettingEvent],
) -> Result<Vec<String>, TaskError> {
    let mut approved = Vec::new();
    for event in events {
        let Some(approver) = event.approved_by.as_deref() else {
            continue;
        };
        let stored = previous
            .iter()
            .find(|p| p.event_id == event.event_id)
            .and_then(|p| p.approved_by.as_deref());
        if stored != Some(approver) {
            if approver != signer {
                return Err(TaskError::declared(
                    HIDDEN_PUBLISH_ERR_APPROVER_NOT_SIGNER,
                    AppError::Forbidden(format!(
                        "event `{}` would be approved by {approver}, but an approver names \
                         themselves — set `approvedBy` to your own DID ({signer})",
                        event.event_id
                    )),
                ));
            }
            approved.push(event.event_id.clone());
        }
        if crate::vetting::pcs_event::has_asked(state, &event.event_id, approver).await? {
            return Err(TaskError::declared(
                HIDDEN_PUBLISH_ERR_APPROVER_IN_EVENT,
                AppError::Forbidden(format!(
                    "{approver} has asked to vet at event `{}`, so cannot approve it — \
                     another administrator has to",
                    event.event_id
                )),
            ));
        }
    }
    Ok(approved)
}

/// Record a hidden-vetting change against the administrator who made it. Written after the
/// store, so the log never claims a change the criterion does not hold.
async fn audit_change(
    state: &AppState,
    actor: &str,
    data: HiddenVettingChangedData,
) -> Result<(), AppError> {
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(actor, None, AuditEvent::HiddenVettingChanged(data))
            .await?;
    }
    Ok(())
}

/// The criterion's `requirementsDigest` as the manifest serves it.
fn served_digest(criterion: AcceptsCriterion) -> Result<Option<String>, AppError> {
    let served = crate::routes::join_requests::manifest::manifest_criterion(criterion)?;
    Ok(served
        .json
        .get("requirementsDigest")
        .and_then(Value::as_str)
        .map(str::to_string))
}

/// Turn hidden-vetter admission off for one criterion (`vtc/vetting/hidden/withdraw/0.1`).
///
/// Removes the stored parameters and republishes the criterion without them; its named vetting
/// is untouched. Enrolment rows and the spent-token ledger stay: withdrawing unmasks nothing, and
/// a later publish derives the same keys, so enrolments under still-live labels work again.
/// Withdrawing a criterion that has none is a success that says so (`withdrawn: false`).
pub(crate) async fn withdraw_hidden_vetting_core(
    state: &AppState,
    signer: &str,
    criterion_id: String,
) -> Result<Value, TaskError> {
    let mut criterion = get_accepts(&state.schemas_ks, &criterion_id)
        .await?
        .ok_or_else(|| {
            TaskError::declared(
                HIDDEN_WITHDRAW_ERR_NO_SUCH_CRITERION,
                AppError::NotFound(format!("no criterion `{criterion_id}`")),
            )
        })?;
    let withdrawn = criterion.hidden_vetting.take().is_some();
    if withdrawn {
        store_accepts(&state.schemas_ks, &criterion).await?;
        audit_change(
            state,
            signer,
            HiddenVettingChangedData {
                criterion_id: criterion_id.clone(),
                change: "withdrawn".into(),
                vetter_labels: Vec::new(),
                token_labels: Vec::new(),
                drip_per_tick: None,
                events: Vec::new(),
                approved_events: Vec::new(),
            },
        )
        .await?;
    }
    let response = serde_json::json!({
        "criterionId": criterion_id,
        "withdrawn": withdrawn,
        "requirementsDigest": served_digest(criterion)?,
    });
    // Built as JSON and read through the generated type, so the answer is the specification's
    // shape or nothing.
    let typed: trust_tasks_rs::specs::vtc::vetting::hidden::withdraw::v0_1::Response =
        serde_json::from_value(response)
            .map_err(|e| AppError::Internal(format!("withdraw response: {e}")))?;
    serde_json::to_value(typed)
        .map_err(|e| AppError::Internal(format!("withdraw response: {e}")).into())
}

/// Read one criterion's stored hidden-vetting configuration (`vtc/vetting/hidden/show/0.1`):
/// what an edit has to start from, since publish replaces `events` wholesale and the manifest
/// omits each event's `approvedBy` and `graceDays`. With it, the counts an administrator needs —
/// members enrolled under each live vetter label, and each event's demand against its floor —
/// as counts only, never which members.
pub(crate) async fn show_hidden_vetting_core(
    state: &AppState,
    criterion_id: String,
) -> Result<Value, TaskError> {
    let criterion = get_accepts(&state.schemas_ks, &criterion_id)
        .await?
        .ok_or_else(|| {
            TaskError::declared(
                HIDDEN_SHOW_ERR_NO_SUCH_CRITERION,
                AppError::NotFound(format!("no criterion `{criterion_id}`")),
            )
        })?;
    let config = match criterion.hidden_vetting.as_ref() {
        Some(v) => Some(
            serde_json::from_value::<HiddenVettingConfig>(v.clone())
                .map_err(|e| AppError::Internal(format!("stored hidden vetting: {e}")))?,
        ),
        None => None,
    };
    let mut response = serde_json::json!({
        "criterionId": criterion_id,
        "enabled": config.is_some(),
        "requirementsDigest": served_digest(criterion)?,
    });
    if let Some(config) = config {
        let labels: Vec<String> = config
            .live_periods
            .iter()
            .map(|p| format!("vetter/{p}"))
            .collect();
        let enrolled = crate::vetting::pcs_issue::enrolled_counts(state, &labels).await?;
        let today = Utc::now().date_naive();
        let mut status = Vec::with_capacity(config.events.len());
        for event in &config.events {
            let size = crate::vetting::pcs_event::group_size(state, &event.event_id).await?;
            let approver_in_event = match event.approved_by.as_deref() {
                Some(a) => crate::vetting::pcs_event::has_asked(state, &event.event_id, a).await?,
                None => false,
            };
            let approved = event.approved_by.is_some() && !approver_in_event;
            status.push(serde_json::json!({
                "eventId": event.event_id,
                "groupFloor": event.group_floor,
                "groupSize": size,
                "approved": approved,
                "live": approved && size >= event.group_floor && today <= event.closes_after(),
            }));
        }
        let map = response.as_object_mut().expect("object literal");
        map.insert(
            "stored".into(),
            serde_json::to_value(&config)
                .map_err(|e| AppError::Internal(format!("encode stored: {e}")))?,
        );
        map.insert("published".into(), config.published());
        map.insert(
            "enrolledVetters".into(),
            serde_json::to_value(enrolled)
                .map_err(|e| AppError::Internal(format!("encode counts: {e}")))?,
        );
        map.insert("eventStatus".into(), Value::Array(status));
    }
    let typed: trust_tasks_rs::specs::vtc::vetting::hidden::show::v0_1::Response =
        serde_json::from_value(response)
            .map_err(|e| AppError::Internal(format!("show response: {e}")))?;
    serde_json::to_value(typed)
        .map_err(|e| AppError::Internal(format!("show response: {e}")).into())
}

// `POST /vetting/hidden` was a REST route here — always admin-only, and its
// derivation is `publish_hidden_vetting_core` above. It is
// `vtc/vetting/hidden/publish/0.1` now, served on the spine
// (`crate::trust_tasks::handle_hidden_publish`), behind the same
// `vetting-pcs` feature this whole module is gated on.
