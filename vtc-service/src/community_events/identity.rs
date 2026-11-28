//! An event's own identity (VTI-EVT-140 – 145).
//!
//! Minted by the community's VTA from the `vtc-event` template exactly as a group's identity
//! is minted from `vtc-group` (`groups::identity::mint_as`), published where the community
//! publishes its groups' identities, and authorised by the community's authorization
//! credential granting [`EVENT_AUTHORITY_ACTION`], with a slot in the community's revocation
//! list. The VTC never holds its keys. Remote first: an event is stored with an identity only
//! after the identity and its authority exist (VTI-EVT-141); a failure stores nothing.

use chrono::{DateTime, Duration, Utc};
use vti_common::error::AppError;

use super::EventIdentity;
use crate::groups::identity::{self, Failure};
use crate::server::AppState;

/// The action the community's authorization credential grants an event's identity: signing
/// its tickets and attendance records, and nothing else (VTI-EVT-145).
pub const EVENT_AUTHORITY_ACTION: &str = "issue-tickets";

/// Why an identity could not be minted.
#[derive(Debug)]
pub enum MintFailure {
    /// The community cannot hold an identity's keys: no VTA link, no context, nowhere to
    /// publish. The message says what to configure.
    NoKeyHolder(String),
    /// The VTA did not answer, or refused; the DID it minted, when it did.
    Unavailable(String, Option<String>),
    /// This service failed.
    Local(AppError),
}

/// What the community's VTA answered, in words.
pub(crate) fn holder_message(h: &crate::rooms::community::HolderError) -> String {
    use crate::rooms::community::HolderError;
    match h {
        HolderError::Unavailable(why) => why.clone(),
        HolderError::Refused { code, message } => format!("{code}: {message}"),
    }
}

/// Mint an identity for a new event, with its authority (VTI-EVT-141, VTI-EVT-142).
///
/// # Errors
/// [`MintFailure`]; nothing is kept that a later step depends on.
pub async fn mint(state: &AppState) -> Result<EventIdentity, MintFailure> {
    let setup = identity::setup(state)
        .await
        .map_err(MintFailure::NoKeyHolder)?;
    let minted = identity::mint_as(
        state,
        &setup,
        "vtc-event",
        "Community event",
        Some(EVENT_AUTHORITY_ACTION),
    )
    .await
    .map_err(|e| match e {
        Failure::Local(e) => MintFailure::Local(e),
        Failure::Holder(h, did) => MintFailure::Unavailable(holder_message(&h), did),
    })?;
    let Some((authority, _credential)) = minted.authority else {
        return Err(MintFailure::Local(AppError::Internal(
            "an event identity was minted without its authority".into(),
        )));
    };
    Ok(EventIdentity {
        did: minted.group_did,
        signing_key_id: minted.signing_key_id,
        did_log_path: minted.did_log_path,
        authority,
        revoked_at: None,
    })
}

/// Revoke an event identity's authority (VTI-EVT-142): every artefact it issued is void from
/// now. Idempotent.
///
/// # Errors
/// A store failure.
pub async fn revoke(
    state: &AppState,
    id: &mut EventIdentity,
    now: DateTime<Utc>,
) -> Result<bool, AppError> {
    if id.revoked_at.is_some() {
        return Ok(false);
    }
    identity::revoke_authority(state, &id.authority).await?;
    id.revoked_at = Some(now);
    Ok(true)
}

/// Renew an identity's authority in the slot it holds once less than half its life remains,
/// as groups renew theirs. `Ok(true)` when renewed.
///
/// # Errors
/// What issuing answers, as a message; the sweeper retries on its next pass.
pub async fn renew_if_due(
    state: &AppState,
    id: &mut EventIdentity,
    now: DateTime<Utc>,
) -> Result<bool, String> {
    if id.revoked_at.is_some() {
        return Ok(false);
    }
    let setup = identity::setup(state).await?;
    let half = Duration::days(i64::from(setup.authority_days) / 2);
    if id.authority.valid_until - now > half {
        return Ok(false);
    }
    let (authority, _) = identity::issue_authority_as(
        state,
        &setup,
        &id.did,
        EVENT_AUTHORITY_ACTION,
        now,
        Some(id.authority.status_list_index),
    )
    .await
    .map_err(|e| format!("{e:?}"))?;
    id.authority = authority;
    Ok(true)
}
