//! Tickets (VTI-EVT-170 – 174).
//!
//! A ticket is a W3C Verifiable Credential 2.0 (`EventTicketCredential`) naming the
//! registrant's identifier as its subject and the event, issued when a registration becomes
//! `going` on an event that issues tickets — by the event's own identity where it has one, by
//! the community otherwise — valid until the event ends, with a slot in the community's shared
//! revocation list (never a set of the event's own, VTI-CRD-014). It is signed by the
//! community's VTA (`keys/sign-document`), kept exactly as issued, and shown only to its
//! registrant (VTI-EVT-174).
//!
//! The events sweeper is the one owner of issuance and revocation: it issues a ticket to each
//! registrant going who holds none, and revokes each ticket whose registration stopped being
//! `going` or whose event was cancelled (VTI-EVT-172). A registration may land before its
//! ticket; it never waits on the community's VTA.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use vti_common::error::AppError;

use super::{EventRecord, Lifecycle, RegStatus, Registration, Ticket};
use crate::credentials::vmc::CredentialStatusRef;
use crate::groups::identity;
use crate::rooms::community::SIGN_TIMEOUT;
use crate::server::AppState;
use crate::status_list;

/// The identifier a ticket names as its subject: a member's current DID, or the partner's
/// member's or guest's own (VTI-EVT-170).
///
/// # Errors
/// A store failure.
pub async fn subject_did(state: &AppState, reg: &Registration) -> Result<Option<String>, AppError> {
    if let Some(did) = &reg.registrant_did {
        return Ok(Some(did.clone()));
    }
    Ok(
        crate::directory::read::subject_by_entry(state, &reg.entry_id)
            .await?
            .map(|s| s.card.did),
    )
}

/// The ticket credential, unsigned.
#[must_use]
pub fn document(
    ev: &EventRecord,
    issuer: &str,
    community: &str,
    subject: &str,
    credential_id: &str,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    status: &CredentialStatusRef,
) -> Value {
    let stamp = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": credential_id,
        "type": ["VerifiableCredential", "EventTicketCredential"],
        "issuer": issuer,
        "validFrom": stamp(valid_from),
        "validUntil": stamp(valid_until),
        "credentialSubject": {
            "id": subject,
            "event": {
                "eventId": ev.event_id,
                "community": community,
            },
        },
        "credentialStatus": status,
    })
}

/// Issue `reg`'s ticket for `ev` (VTI-EVT-170 – 172).
///
/// # Errors
/// A message for the sweeper's log: no key holder, the VTA, a full status list.
pub async fn issue(
    state: &AppState,
    ev: &EventRecord,
    reg: &Registration,
    now: DateTime<Utc>,
) -> Result<Ticket, String> {
    let setup = identity::setup(state).await?;
    let subject = subject_did(state, reg)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "the registrant has no identifier to name".to_string())?;
    let (_, end) = ev.interval().map_err(|e| format!("{e:?}"))?;
    if end <= now {
        return Err("the event has ended".into());
    }
    let (issuer, key_id) = match &ev.identity {
        Some(id) if id.revoked_at.is_none() => (id.did.clone(), id.signing_key_id.clone()),
        _ => (setup.community_did.clone(), setup.community_key_id.clone()),
    };
    let slot = status_list::with_locked(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        move |row| Ok(status_list::allocate(row).map(|s| (s, row.list_credential_id.clone()))),
    )
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "the revocation status list is full".to_string())?;
    let status = CredentialStatusRef::revocation(slot.1, slot.0);
    let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let doc = document(
        ev,
        &issuer,
        &setup.community_did,
        &subject,
        &credential_id,
        now,
        end,
        &status,
    );
    let answer = setup
        .holder
        .ask(
            vta_sdk::trust_tasks::TASK_KEYS_SIGN_DOCUMENT_0_1,
            json!({ "keyId": key_id, "document": doc }),
            SIGN_TIMEOUT,
        )
        .await
        .map_err(|e| super::identity::holder_message(&e))?;
    let signed: vta_sdk::protocols::key_management::sign_document::SignDocumentResponse =
        serde_json::from_value(answer).map_err(|e| format!("keys/sign-document: {e}"))?;
    Ok(Ticket {
        credential: Value::Object(signed.document),
        valid_until: end,
        status_list_index: slot.0,
        revoked: false,
    })
}

/// Revoke `ticket` in the community's revocation list (VTI-EVT-172). Idempotent.
///
/// # Errors
/// A store failure.
pub async fn revoke(state: &AppState, ticket: &mut Ticket) -> Result<bool, AppError> {
    if ticket.revoked {
        return Ok(false);
    }
    let slot = ticket.status_list_index;
    status_list::with_locked(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        move |row| {
            status_list::flip(row, slot, true)
                .map_err(|e| AppError::Internal(format!("flip status-list bit {slot}: {e}")))
        },
    )
    .await?;
    ticket.revoked = true;
    Ok(true)
}

/// One pass: issue the tickets owed and revoke the ones no longer valid (VTI-EVT-170, 172).
/// Returns `(issued, revoked)`.
///
/// # Errors
/// A store failure; a failure to issue one ticket is logged and retried next pass.
pub async fn sweep(state: &AppState, now: DateTime<Utc>) -> Result<(usize, usize), AppError> {
    let ks = &state.events_ks;
    let (mut issued, mut revoked) = (0, 0);
    for ev in super::events(ks).await? {
        let cancelled = ev.status == Lifecycle::Cancelled;
        let live = ev.status == Lifecycle::Published && !ev.ended(now);
        for mut reg in super::registrations_of(ks, &ev.event_id).await? {
            let going = reg.status == RegStatus::Going;
            // A ticket revoked once is replaced when its registrant is going again.
            if reg.ticket.as_ref().is_some_and(|t| t.revoked) && ev.tickets && live && going {
                reg.ticket = None;
            }
            match reg.ticket.as_mut() {
                Some(t) if !t.revoked && (cancelled || !going) => {
                    let _guard = super::WRITE_LOCK.lock().await;
                    revoke(state, t).await?;
                    reg.updated_at = now;
                    super::put_registration(ks, &reg).await?;
                    revoked += 1;
                }
                None if ev.tickets && live && going => match issue(state, &ev, &reg, now).await {
                    Ok(t) => {
                        let _guard = super::WRITE_LOCK.lock().await;
                        // Re-read: the registration may have changed while the VTA signed.
                        match super::get_registration(ks, &ev.event_id, &reg.entry_id).await? {
                            Some(mut fresh)
                                if fresh.status == RegStatus::Going && fresh.ticket.is_none() =>
                            {
                                fresh.ticket = Some(t);
                                fresh.updated_at = now;
                                super::put_registration(ks, &fresh).await?;
                                issued += 1;
                            }
                            _ => {
                                let mut t = t;
                                revoke(state, &mut t).await?;
                            }
                        }
                    }
                    Err(why) => {
                        tracing::warn!(event = %ev.event_id, registration = %reg.registration_id, why, "a ticket could not be issued; the events sweeper tries again");
                    }
                },
                _ => {}
            }
        }
    }
    Ok((issued, revoked))
}
