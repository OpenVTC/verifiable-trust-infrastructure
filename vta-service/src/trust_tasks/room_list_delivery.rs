//! The redelivery of a room's revocation list that did not reach a host the room was
//! registered with — `rooms/owner/register/0.2`, *The room's revocation list*, items 4 and 5
//! (trust-tasks-tf #821).
//!
//! A host told about a room and not given its list honours, from the moment it serves the
//! room, every credential the room has withdrawn. `register` answers such a room `pending`
//! and retains the delivery ([`room_revocation::OutstandingDelivery`]); this sweeper is the
//! **single retry owner** of it:
//!
//! - each attempt delivers the **latest** list this agent holds, which keeps every live entry
//!   of the one first delivered;
//! - a host that answers with that list's head ends it (`inForce`), and so does a refusal —
//!   which is **never** repeated (item 5); a `stale` refusal, with no later list of this
//!   agent's own, is surfaced as the room's key possibly in more than one party's hands, at
//!   `warn` with `security_alert`;
//! - anything else (no answer, another head, no `admin` grant to present yet) keeps it, and
//!   the next attempt waits a capped exponential backoff with full jitter.
//!
//! Remote first and crash-safe: the record is written before the first delivery and removed
//! only after the host's answer, so a process that dies mid-delivery leaves it for the next
//! sweep — a repeat delivery is answered as accepted. The backoff lives in memory only: after
//! a restart every outstanding delivery is due at once, which is the right answer for a host
//! serving a room without its withdrawals.
//!
//! The deliveries are made as the persona the record names — the identity whose `admin` grant
//! the first delivery presented — under authority confined to that persona's own context: the
//! sweeper re-sends a list the room already signed, and signs nothing as the room.

use std::collections::HashMap;
use std::time::Duration;

use rand::RngExt as _;
use tokio::time::Instant;
use vti_common::acl::Role;

use crate::auth::AuthClaims;
use crate::operations::room_revocation::{self, OutstandingDelivery};
use crate::server::AppState;

use super::room_owner_group::{Delivery, HostCall};

/// How often the sweeper looks for a delivery that is due.
pub(crate) const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// The first retry's ceiling; each further one doubles, up to [`BACKOFF_CAP`].
const BACKOFF_BASE: Duration = Duration::from_secs(30);
const BACKOFF_CAP: Duration = Duration::from_secs(60 * 60);

/// The audit actor of a redelivery: this agent, carrying on a delivery a caller started.
const ACTOR: &str = "vta:room-revocation-redelivery";

/// What one attempt came to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Attempt {
    /// The host answered with the head of the list delivered. The record is gone.
    InForce { sequence: u64 },
    /// The host refused the list, with its code. The record is gone, and the list is not
    /// delivered again on its own.
    Refused { code: String },
    /// No usable answer. The record stays.
    Pending { why: String },
    /// Nothing left to deliver — the room's list is no longer held here. The record is gone.
    Nothing,
}

/// When each outstanding delivery is next due, and how many attempts it has failed.
#[derive(Default)]
pub(crate) struct Schedule {
    due: HashMap<(String, String), (u32, Instant)>,
}

impl Schedule {
    fn is_due(&self, d: &OutstandingDelivery, now: Instant) -> bool {
        self.due
            .get(&(d.room_id.clone(), d.host.clone()))
            .is_none_or(|(_, at)| *at <= now)
    }

    fn failed(&mut self, d: &OutstandingDelivery, now: Instant) {
        let entry = self
            .due
            .entry((d.room_id.clone(), d.host.clone()))
            .or_insert((0, now));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = now + jittered(ceiling(entry.0));
    }

    fn forget(&mut self, d: &OutstandingDelivery) {
        self.due.remove(&(d.room_id.clone(), d.host.clone()));
    }
}

/// `min(cap, base * 2^(failures - 1))`, saturating.
fn ceiling(failures: u32) -> Duration {
    let factor = 1u32
        .checked_shl(failures.saturating_sub(1))
        .unwrap_or(u32::MAX);
    BACKOFF_BASE.saturating_mul(factor).min(BACKOFF_CAP)
}

/// Full jitter: uniform in `[0, ceiling]`, so deliveries to one host that failed together do
/// not retry together.
fn jittered(ceiling: Duration) -> Duration {
    let max_ms = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
    if max_ms == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(rand::rng().random_range(0..=max_ms))
}

/// The sweeper's loop: every [`SWEEP_INTERVAL`], attempt every delivery that is due. Runs
/// until the task is dropped.
pub(crate) async fn redelivery_loop(state: AppState) {
    let mut schedule = Schedule::default();
    let mut tick = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        tick.tick().await;
        if let Err(e) = redeliver_due(&state, &mut schedule, Instant::now()).await {
            tracing::warn!(error = %e,
                "could not read the outstanding revocation-list deliveries; retrying next sweep");
        }
    }
}

/// One sweep: attempt each outstanding delivery that is due, and schedule the ones still
/// pending. Returns what each attempt came to.
pub(crate) async fn redeliver_due(
    state: &AppState,
    schedule: &mut Schedule,
    now: Instant,
) -> Result<Vec<(OutstandingDelivery, Attempt)>, vti_common::error::AppError> {
    let mut out = Vec::new();
    for d in room_revocation::outstanding_deliveries(&state.room_groups_ks).await? {
        if !schedule.is_due(&d, now) {
            continue;
        }
        let attempt = redeliver(state, &d).await;
        match &attempt {
            Attempt::Pending { why } => {
                schedule.failed(&d, now);
                tracing::info!(room = %d.room_id, host = %d.host, reason = %why,
                    "a room's revocation list is still pending at its host; retrying later");
            }
            _ => schedule.forget(&d),
        }
        out.push((d, attempt));
    }
    Ok(out)
}

/// One attempt at `d`: deliver the latest list held for the room to its host, as the persona
/// the record names, and settle the record by the host's answer.
pub(crate) async fn redeliver(state: &AppState, d: &OutstandingDelivery) -> Attempt {
    let room_id = d.room_id.as_str();
    let host = d.host.as_str();
    let groups = &state.room_groups_ks;
    let pending = |why: String| Attempt::Pending { why };

    let list = match room_revocation::held(groups, room_id).await {
        Ok(Some(l)) => l,
        Ok(None) => {
            if let Err(e) = room_revocation::drop_delivery(groups, room_id, host).await {
                return pending(format!("could not drop the delivery: {e}"));
            }
            return Attempt::Nothing;
        }
        Err(e) => return pending(e.to_string()),
    };
    let Some(resolver) = state.did_resolver.clone() else {
        return pending("this agent has no DID resolver configured".into());
    };
    let auth = match acting_as(state, &d.persona).await {
        Ok(a) => a,
        Err(why) => return pending(why),
    };
    let host_call =
        match HostCall::for_persona(state, &auth, &resolver, room_id, Some(&d.persona)).await {
            Ok(h) => h,
            Err(e) => return pending(format!("no `admin` grant to deliver with: {e}")),
        };
    let presentation = match host_call.presentation_as_admin().await {
        Ok(p) => p,
        Err(e) => return pending(format!("could not present the `admin` grant: {e}")),
    };
    match host_call.deliver_list(host, &list, &presentation).await {
        // `deliver_list` settles the record when the host answers with this list's head.
        Delivery::Accepted { .. } => {
            super::room_group::record(state, "rooms.owner.register.redelivered", &auth, room_id)
                .await;
            tracing::info!(room = %room_id, %host, sequence = list.sequence(),
                "a room's revocation list is now in force at its host");
            Attempt::InForce {
                sequence: list.sequence(),
            }
        }
        Delivery::Refused { code, reason } => {
            // Item 5: never delivered again on its own. `deliver_list` has already surfaced
            // `stale` as the room's key possibly in more than one party's hands, when this
            // agent holds no later list of its own.
            if let Err(e) = room_revocation::drop_delivery(groups, room_id, host).await {
                return pending(format!(
                    "the host refused, and the delivery could not be dropped: {e}"
                ));
            }
            tracing::warn!(room = %room_id, %host, %code, %reason,
                "a host refused a room's revocation list on redelivery; it is not delivered \
                 again on its own, and the host serves the room without its withdrawals");
            super::room_group::record(
                state,
                "rooms.owner.register.redelivery-refused",
                &auth,
                room_id,
            )
            .await;
            Attempt::Refused { code }
        }
        Delivery::Unreachable(why) => pending(why),
    }
}

/// The authority a redelivery acts under: an administrator of exactly the context the
/// persona's key lives in — the persona's own scope and no wider. A key in no context is one
/// only an unrestricted administrator reaches, which is what this agent's own authority is.
async fn acting_as(state: &AppState, persona: &str) -> Result<AuthClaims, String> {
    let own = AuthClaims {
        did: ACTOR.to_string(),
        role: Role::Admin,
        allowed_contexts: Vec::new(),
        session_id: ACTOR.to_string(),
        ..Default::default()
    };
    let key = crate::operations::persona::persona_signing_key(
        crate::operations::persona::PersonaStores::from_state(state),
        &own,
        persona,
    )
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| format!("this agent holds no key for `{persona}`"))?;
    let record = state
        .keys_ks
        .get::<vta_sdk::keys::KeyRecord>(crate::keys::store_key(&key.key_id))
        .await
        .map_err(|e| e.to_string())?;
    let context = match record {
        Some(r) => r.context_id,
        // A `did:webvh` persona's key is named for its verification method, and its record
        // carries its context too; a key with no record here is not one to act as.
        None => return Err(format!("no key record for `{persona}`")),
    };
    Ok(AuthClaims {
        allowed_contexts: context.into_iter().collect(),
        ..own
    })
}
