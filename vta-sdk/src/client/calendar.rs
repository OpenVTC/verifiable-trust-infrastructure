//! The member's calendar (`vta/calendar/*/0.1`, VTI-CAL-001 – 071).
//!
//! The VTA keeps its principal's calendar across every trust context: the events they
//! registered for, read from each community as the membership identifier held there, and the
//! events they hold only a notification of. Every method answers only for the contexts the
//! client has standing in — a listing never says another context holds anything.
//!
//! # Receipts as received
//!
//! A community's signed reply to a registration (`vtc/events/registrations/register/0.2`
//! `#response` and its siblings) is the principal's evidence. A client that receives one hands
//! it to the VTA with [`VtaClient::calendar_receipts_deposit_json`] **exactly as received** —
//! the received JSON itself, never a value re-serialised from a typed form, which would no
//! longer hold the bytes the community's proof covers (VTI-CAL-030).
//!
//! Declared refusals (`rangeInvalid`, `eventNotHeld`, `limitReached`, `feedNotFound`,
//! `notAReply`, `syncOff`, …) arrive as [`VtaError::Rejected`] with their code.

use vti_specs::vta::calendar;

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

/// Round-trip timeout (seconds) for the reads of the VTA's own store.
const CALENDAR_TT_TIMEOUT: u64 = 20;
/// `sync` reads every community the principal is a member of before it answers.
const CALENDAR_SYNC_TIMEOUT: u64 = 120;

impl VtaClient {
    async fn calendar_call<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        uri: &str,
        payload: &P,
        timeout: u64,
    ) -> Result<R, VtaError> {
        let payload = serde_json::to_value(payload)
            .map_err(|e| VtaError::Validation(format!("{uri} request: {e}")))?;
        let answer = self.dispatch_trust_task(uri, payload, timeout).await?;
        serde_json::from_value(answer).map_err(|e| {
            VtaError::Protocol(format!("{uri} response does not match its schema: {e}"))
        })
    }

    /// `vta/calendar/list/0.1` — the principal's calendar across the trust contexts the caller has standing in — `mine` entries (registered) and `notified` entries (a notification held). A page with `nextCursor` is not the whole listing.
    pub async fn calendar_list(
        &self,
        req: &calendar::list::v0_1::Payload,
    ) -> Result<calendar::list::v0_1::Response, VtaError> {
        self.calendar_call(
            trust_tasks::TASK_VTA_CALENDAR_LIST_0_1,
            req,
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/calendar/sync/0.1` — read the communities now, as the membership identifier held at each, where the context's setting allows; one result per (context, community).
    pub async fn calendar_sync(
        &self,
        req: &calendar::sync::v0_1::Payload,
    ) -> Result<calendar::sync::v0_1::Response, VtaError> {
        self.calendar_call(
            trust_tasks::TASK_VTA_CALENDAR_SYNC_0_1,
            req,
            CALENDAR_SYNC_TIMEOUT,
        )
        .await
    }

    /// `vta/calendar/settings/show/0.1` — one trust context's calendar settings.
    pub async fn calendar_settings_show(
        &self,
        req: &calendar::settings::show::v0_1::Payload,
    ) -> Result<calendar::settings::show::v0_1::Response, VtaError> {
        self.calendar_call(
            trust_tasks::TASK_VTA_CALENDAR_SETTINGS_SHOW_0_1,
            req,
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/calendar/settings/update/0.1` — change one trust context's calendar settings (sync, default reminders, quiet hours).
    pub async fn calendar_settings_update(
        &self,
        req: &calendar::settings::update::v0_1::Payload,
    ) -> Result<calendar::settings::update::v0_1::Response, VtaError> {
        self.calendar_call(
            trust_tasks::TASK_VTA_CALENDAR_SETTINGS_UPDATE_0_1,
            req,
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/calendar/alerts/set/0.1` — the principal's own reminders for one event the calendar holds; an empty list means no reminders.
    pub async fn calendar_alerts_set(
        &self,
        req: &calendar::alerts::set::v0_1::Payload,
    ) -> Result<calendar::alerts::set::v0_1::Response, VtaError> {
        self.calendar_call(
            trust_tasks::TASK_VTA_CALENDAR_ALERTS_SET_0_1,
            req,
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/calendar/alerts/clear/0.1` — drop the principal's own reminders for one event, back to the context's default.
    pub async fn calendar_alerts_clear(
        &self,
        req: &calendar::alerts::clear::v0_1::Payload,
    ) -> Result<calendar::alerts::clear::v0_1::Response, VtaError> {
        self.calendar_call(
            trust_tasks::TASK_VTA_CALENDAR_ALERTS_CLEAR_0_1,
            req,
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/calendar/feeds/create/0.1` — a private iCalendar feed. **The answer's `url` is returned once and is the credential** — hand it to the calendar application and keep it nowhere else.
    pub async fn calendar_feeds_create(
        &self,
        req: &calendar::feeds::create::v0_1::Payload,
    ) -> Result<calendar::feeds::create::v0_1::Response, VtaError> {
        self.calendar_call(
            trust_tasks::TASK_VTA_CALENDAR_FEEDS_CREATE_0_1,
            req,
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/calendar/feeds/list/0.1` — the calendar feeds, never with an address.
    pub async fn calendar_feeds_list(
        &self,
        req: &calendar::feeds::list::v0_1::Payload,
    ) -> Result<calendar::feeds::list::v0_1::Response, VtaError> {
        self.calendar_call(
            trust_tasks::TASK_VTA_CALENDAR_FEEDS_LIST_0_1,
            req,
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/calendar/feeds/revoke/0.1` — end a calendar feed at once.
    pub async fn calendar_feeds_revoke(
        &self,
        req: &calendar::feeds::revoke::v0_1::Payload,
    ) -> Result<calendar::feeds::revoke::v0_1::Response, VtaError> {
        self.calendar_call(
            trust_tasks::TASK_VTA_CALENDAR_FEEDS_REVOKE_0_1,
            req,
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/calendar/export/0.1` — the principal's events as iCalendar, and the receipts kept.
    pub async fn calendar_export(
        &self,
        req: &calendar::export::v0_1::Payload,
    ) -> Result<calendar::export::v0_1::Response, VtaError> {
        self.calendar_call(
            trust_tasks::TASK_VTA_CALENDAR_EXPORT_0_1,
            req,
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/calendar/receipts/list/0.1` — the communities' signed replies kept for the principal, each exactly as received.
    pub async fn calendar_receipts_list(
        &self,
        req: &calendar::receipts::list::v0_1::Payload,
    ) -> Result<calendar::receipts::list::v0_1::Response, VtaError> {
        self.calendar_call(
            trust_tasks::TASK_VTA_CALENDAR_RECEIPTS_LIST_0_1,
            req,
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/calendar/busy/share/0.1` — the principal's choice to share busy times with one booking page.
    pub async fn calendar_busy_share(
        &self,
        req: &calendar::busy::share::v0_1::Payload,
    ) -> Result<calendar::busy::share::v0_1::Response, VtaError> {
        self.calendar_call(
            trust_tasks::TASK_VTA_CALENDAR_BUSY_SHARE_0_1,
            req,
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }

    /// `vta/calendar/receipts/deposit/0.1` — hand the VTA a community's signed reply about a
    /// registration. `document` must be the reply **exactly as received** (VTI-CAL-030); the
    /// answer is the VTA's JSON unchanged. A repeat answers `alreadyKept: true`.
    pub async fn calendar_receipts_deposit_json(
        &self,
        context_id: &str,
        document: serde_json::Value,
    ) -> Result<serde_json::Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_CALENDAR_RECEIPTS_DEPOSIT_0_1,
            serde_json::json!({ "contextId": context_id, "document": document }),
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }

    /// [`Self::calendar_export`], with the payload and the answer as JSON — receipts keep the
    /// bytes their proofs cover.
    pub async fn calendar_export_json(
        &self,
        req: serde_json::Value,
    ) -> Result<serde_json::Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_CALENDAR_EXPORT_0_1,
            req,
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }

    /// [`Self::calendar_receipts_list`], with the payload and the answer as JSON.
    pub async fn calendar_receipts_list_json(
        &self,
        req: serde_json::Value,
    ) -> Result<serde_json::Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VTA_CALENDAR_RECEIPTS_LIST_0_1,
            req,
            CALENDAR_TT_TIMEOUT,
        )
        .await
    }
}
