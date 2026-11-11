//! `rooms/keys/watch/0.1` and `0.2`, and the signals it passes on (`rooms/keys/changed/0.1`;
//! trust-tasks-tf #1040, #1087): a member's own client asks this VTA to watch rooms at one
//! host for it, as the member, at addresses this VTA controls, and to pass each signal on —
//! the first of a one-shot watch, every one of a live watch.
//!
//! # Arming ([`handle_watch`])
//!
//! Refused whole (a `trust-task-error`) for a delegate (`permissionDenied`, Recipient item
//! 1), for a `member` this VTA holds no `authentication` key for that the caller may act as
//! (`memberNotPrincipal`, item 2), and for a request naming a room twice
//! (`malformedRequest`). Otherwise each room is its own outcome (item 4): `notAMember`
//! where no credential the room issued to the member is held, `actionNotHeld` where they
//! do not confer `read`, `limitReached` past this VTA's own bounds
//! ([`crate::operations::room_key_watch`]), `hostUnreachable` and `hostRefused` (the host's
//! code unaltered) at the host. Each room is a `rooms/watch/0.1` of its own, completed as
//! `rooms/keys/act/0.12` completes one (presentation narrowed to `read`, granted to the
//! member, signed by the member for `authentication`) with its own address (item 3). The
//! rooms are armed one after another.
//!
//! A re-arm of a watch that has not fired keeps its address, and so does the renewal of a
//! live watch; anything else takes a new one (item 5). The record is written before the host is asked, so a signal the host sends at
//! once (the room already past the watermark) finds its watch; it is removed again when the
//! host refuses or cannot be reached. A cancel of a watch not held answers `armed: false`
//! without asking the host.
//!
//! # A live watch (0.2)
//!
//! `live: true` arms each room with `rooms/watch/0.2` `live: true`; the outcome says `live`
//! only when the host answered it (item 7), and the record says so too. A host's refusal —
//! `rooms/watch:liveNotPermitted` on a room whose signal delay is not `none` — is
//! `hostRefused` with the code, and this VTA never arms a one-shot watch instead (item 3):
//! that is the caller's decision. A renewal the host refuses forgets the watch (item 7).
//! A switch between one-shot and live (item 5) arms the new watch at a **new** address
//! first, keeping the old record under its own key ([`WatchRecord::retiring`]) and still
//! passing on its signal, and only once the host armed the new one cancels the old one at
//! the host and forgets it; a refusal puts the old record back, so a refused live watch
//! leaves the one-shot watch in place. Nothing more is kept for a live watch than for a
//! one-shot one: no watermark, version or signal time.
//!
//! # A signal ([`receive_signal`])
//!
//! Passed on only when the transport proved the sender to be the watch's `host`, the
//! signal names the watch's room, and the watch is held and has not lapsed (item 8). The
//! watch is forgotten **before** the pass-on is sent, so one arming passes on at most one
//! signal; a live watch is kept, and passes on each later signal the same way, as it
//! arrives, never compared with an earlier one; anything else at an address is dropped
//! without a word — `rooms/changed` has no
//! response. The pass-on carries the signal's `roomId` and `latestVersion` unaltered and the
//! watch's `member` and `host`, nothing else (`rooms/keys/changed/0.1` Producer item 2),
//! signed by this VTA, through the push path `task-consent/granted` takes — but without the
//! doorbell, which the waiting document already rings at the client's mediator (Producer
//! item 5), and with a deadline no longer than one attempt's window, so a send the delivery
//! layer accepted is never sent again (Producer item 4).
//!
//! # Forgetting ([`sweep`])
//!
//! Besides firing and cancelling, a watch is forgotten when it lapses, when its caller may
//! no longer act as its member (an ACL entry gone, narrowed, or now a delegate's), and when
//! this VTA no longer holds the member's credentials for the room (item 7). The sweep runs
//! with the address supervisor (`messaging::watch_addresses`), every 30 seconds and on every
//! change. On those withdrawals the host's watch is not cancelled: cancelling it means
//! presenting the member's credentials for a caller that may no longer use them, or that
//! are gone. The host forgets it at its own lease, and a signal it sends meanwhile reaches
//! an address nobody receives at.

use chrono::Utc;
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use vti_common::acl::Capability;
use vti_common::error::AppError;

use crate::audit;
use crate::auth::AuthClaims;
use crate::operations::room_key_watch::{MAX_LEASE_SECS, RoomKeyWatches, WatchRecord};
use crate::operations::{room_act, room_host, room_oracle};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, malformed_request_response,
    parse_payload, reject_with_code, success_response,
};
use super::room_group::declared;

#[allow(deprecated)] // 0.1 is still served beside 0.2 (trust-tasks-tf #1087)
use vti_specs::rooms::keys::watch::v0_1 as spec;
use vti_specs::rooms::keys::watch::v0_2 as spec_v2;
#[allow(deprecated)] // a one-shot watch is still armed at a host with 0.1
use vti_specs::rooms::watch::v0_1 as host_watch;
use vti_specs::rooms::watch::v0_2 as host_watch_v2;

/// A `rooms/keys/watch` request, as both versions carry it.
struct WatchRequest {
    member: String,
    host: String,
    rooms: Vec<(String, Option<u64>)>,
    lease_seconds: Option<i64>,
    cancel: bool,
    live: bool,
}

#[allow(deprecated)] // 0.1 is still served beside 0.2
fn read_request(doc: &TrustTask<Value>, v2: bool) -> Result<WatchRequest, TrustTaskOutcome> {
    if v2 {
        let req: spec_v2::Payload = parse_payload(doc)?;
        Ok(WatchRequest {
            member: req.member.to_string(),
            host: req.host.to_string(),
            rooms: req
                .rooms
                .iter()
                .map(|r| (r.room_id.to_string(), r.since_version))
                .collect(),
            lease_seconds: req.lease_seconds,
            cancel: req.cancel == Some(true),
            // A recipient ignores `live` on a cancel.
            live: req.live == Some(true) && req.cancel != Some(true),
        })
    } else {
        let req: spec::Payload = parse_payload(doc)?;
        Ok(WatchRequest {
            member: req.member.to_string(),
            host: req.host.to_string(),
            rooms: req
                .rooms
                .iter()
                .map(|r| (r.room_id.to_string(), r.since_version))
                .collect(),
            lease_seconds: req.lease_seconds,
            cancel: req.cancel == Some(true),
            live: false,
        })
    }
}

/// How long the pass-on may wait to be delivered: one attempt's window, so the push is never
/// moved to a second transport after its first accepted it (`rooms/keys/changed/0.1`
/// Producer item 4). A lost signal costs the client nothing it cannot recover by reading.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
pub const PASS_ON_DELIVER_BY: std::time::Duration = vti_common::trust_task_push::ATTEMPT_WINDOW;

/// The DID part of a DID or DID URL, for comparing parties.
fn party(did: &str) -> String {
    vta_sdk::notifications::identity(did.split('#').next().unwrap_or(did))
}

/// One room's outcome, as the response carries it.
fn armed(room_id: &str, expires_at: i64, live: bool) -> Value {
    let mut outcome = json!({
        "roomId": room_id,
        "armed": true,
        "expiresAt": rfc3339(expires_at),
    });
    if live {
        outcome["live"] = json!(true);
    }
    outcome
}

fn not_armed(room_id: &str) -> Value {
    json!({ "roomId": room_id, "armed": false })
}

fn refused(room_id: &str, reason: &str) -> Value {
    json!({ "roomId": room_id, "armed": false, "refused": reason })
}

fn host_refused(room_id: &str, code: &str) -> Value {
    // `hostCode` is at most 256 characters; a longer one is not a code a host declares.
    let code: String = code.chars().take(256).collect();
    json!({ "roomId": room_id, "armed": false, "refused": "hostRefused", "hostCode": code })
}

fn rfc3339(unix: i64) -> String {
    chrono::DateTime::<Utc>::from_timestamp(unix, 0)
        .unwrap_or_else(Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// `rooms/keys/watch/0.1` and `0.2`. See the module docs.
pub(super) async fn handle_watch(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Watching mints a presentation as the member, as `rooms/keys/act` does.
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomPresent,
        "watching a room as its member",
    )
    .await
    {
        return r;
    }
    // Item 1: a delegate watches for itself.
    if let Err(r) = super::room_act::require_not_delegate(state, auth, &doc).await {
        return r;
    }
    let v2 = doc.type_uri.to_string().split('#').next()
        == Some(vta_sdk::trust_tasks::TASK_ROOMS_KEYS_WATCH_0_2);
    let req = match read_request(&doc, v2) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let member = req.member.clone();
    let host = req.host.clone();
    let cancel = req.cancel;

    // Item 2: each room at most once.
    let mut seen = std::collections::HashSet::new();
    for (room_id, _) in &req.rooms {
        if !seen.insert(room_id.as_str()) {
            return malformed_request_response(format!(
                "room `{room_id}` is named twice; name each room once"
            ));
        }
    }

    // Item 2: a member this VTA holds keys for and the caller may act as — never one picked
    // for the caller.
    let held = crate::operations::persona::persona_key_for(
        crate::operations::persona::PersonaStores::from_state(state),
        auth,
        &member,
        crate::operations::persona::Relationship::Authentication,
    )
    .await;
    match held {
        Ok(Some(_)) => {}
        Ok(None) => {
            return reject_with_code(
                &doc,
                declared(spec::error_codes::MEMBER_NOT_PRINCIPAL),
                format!(
                    "`{member}` is not a member this VTA holds keys for that you may act as; \
                     name one `rooms/keys/list` says you read the rooms as"
                ),
                Some(json!({ "member": member })),
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    }

    let resolver = match super::room_group::outbound_resolver(state, &doc) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let mediator = state
        .config
        .read()
        .await
        .messaging
        .as_ref()
        .map(|m| m.mediator_did.clone());

    let lease = req.lease_seconds;
    let mut outcomes = Vec::with_capacity(req.rooms.len());
    let (mut armed_n, mut cancelled_n) = (0usize, 0usize);
    for (room_id, since_version) in &req.rooms {
        let room_id = room_id.as_str();
        let outcome = if cancel {
            cancel_one(state, auth, &resolver, &member, &host, room_id).await
        } else {
            arm_one(
                state,
                auth,
                &resolver,
                mediator.as_deref(),
                &member,
                &host,
                room_id,
                *since_version,
                lease,
                req.live,
            )
            .await
        };
        let outcome = match outcome {
            Ok(o) => o,
            Err(e) => return app_error_to_reject(&doc, e),
        };
        if outcome["armed"] == true {
            armed_n += 1;
        } else if cancel && outcome.get("refused").is_none() {
            cancelled_n += 1;
        }
        outcomes.push(outcome);
    }

    // Item 6 lets the member's own audit say that a watch was armed or cancelled for a
    // caller; it names the host and how many rooms, never which, and never an address.
    let detail = format!(
        "host={host} rooms={} armed={armed_n} cancelled={cancelled_n} live={}",
        req.rooms.len(),
        req.live
    );
    if let Err(e) = audit::record_with_detail(
        &state.audit_sink,
        if cancel {
            "rooms.keys.watch.cancel"
        } else {
            "rooms.keys.watch"
        },
        &auth.did,
        Some(&member),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        None,
        Some(&detail),
    )
    .await
    {
        tracing::error!(error = %e, "failed to record a rooms/keys/watch audit entry");
    }

    let response = json!({ "member": member, "host": host, "watches": outcomes });
    #[allow(deprecated)] // 0.1 is still served beside 0.2
    let checked = if v2 {
        serde_json::from_value::<spec_v2::Response>(response).and_then(serde_json::to_value)
    } else {
        serde_json::from_value::<spec::Response>(response).and_then(serde_json::to_value)
    };
    match checked {
        Ok(r) => success_response(&doc, r),
        Err(e) => app_error_to_reject(
            &doc,
            AppError::Internal(format!("the watch response does not fit its schema: {e}")),
        ),
    }
}

/// The member's standing in `room_id`: `Ok(principal)`, or the outcome that refuses the
/// room (`notAMember`, `actionNotHeld`).
async fn member_in_room(
    state: &AppState,
    auth: &AuthClaims,
    member: &str,
    room_id: &str,
) -> Result<Result<room_oracle::Principal, Value>, AppError> {
    let principal = match room_oracle::principals(state, auth, room_id).await {
        Ok(ps) => ps.into_iter().find(|p| p.did == member),
        // A membership credential missing beside the authority: not a member.
        Err(AppError::NotFound(_)) => None,
        Err(e) => return Err(e),
    };
    let Some(principal) = principal else {
        return Ok(Err(refused(room_id, "notAMember")));
    };
    if !principal.confers("read")? {
        return Ok(Err(refused(room_id, "actionNotHeld")));
    }
    Ok(Ok(principal))
}

/// Send one `rooms/watch` to `host` as `principal` — `0.2` for a live watch (`v2`), `0.1`
/// otherwise — completed as `rooms/keys/act/0.12` completes it: the presentation narrowed
/// to `read` and granted to the member, signed by the member. `Ok` is the host's response
/// payload, read against its version's schema.
#[allow(clippy::too_many_arguments)]
async fn send_watch(
    state: &AppState,
    auth: &AuthClaims,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    principal: &room_oracle::Principal,
    host: &str,
    room_id: &str,
    payload: Value,
    v2: bool,
) -> Result<Result<Value, room_host::RoomTaskError>, AppError> {
    let type_uri = if v2 {
        vti_rooms::watch::WATCH_V2_TYPE
    } else {
        vti_rooms::watch::WATCH_TYPE
    };
    let document = room_host::build_room_task(type_uri, host, &principal.did, payload);
    let completed =
        room_act::complete_as(state, auth, principal, room_id, document, Some("read")).await?;
    let member = crate::operations::room_groups::Member::new(room_id, &principal.did)?;
    Ok(room_host::send_signed_room_task_typed(
        &state.room_groups_ks,
        &member,
        &crate::operations::outbound::Outbound::from_app_state(state, resolver),
        host,
        completed.document,
        &format!("{type_uri}#response"),
    )
    .await
    .and_then(|reply| {
        // A host's answer is read against its own schema before anything is taken from it.
        #[allow(deprecated)] // a one-shot watch is still armed with 0.1
        let fits = if v2 {
            serde_json::from_value::<host_watch_v2::Response>(reply.clone()).is_ok()
        } else {
            serde_json::from_value::<host_watch::Response>(reply.clone()).is_ok()
        };
        if fits {
            Ok(reply)
        } else {
            Err(room_host::RoomTaskError::Unknown(AppError::Internal(
                format!("the host's {type_uri} answer does not fit its schema"),
            )))
        }
    }))
}

/// The outcome of a host's failure for one room: `hostRefused` with its code, or
/// `hostUnreachable`.
fn host_failure(room_id: &str, e: room_host::RoomTaskError) -> Value {
    match e {
        room_host::RoomTaskError::Refused { code, .. } => host_refused(room_id, &code),
        room_host::RoomTaskError::Unknown(e) => {
            tracing::debug!(error = %e, "a room host could not be reached to arm a watch");
            refused(room_id, "hostUnreachable")
        }
    }
}

/// Arm, re-arm or renew one room's watch — `live` arms it with `rooms/watch/0.2` live — or
/// switch it between one-shot and live (Recipient item 5).
#[allow(clippy::too_many_arguments)]
async fn arm_one(
    state: &AppState,
    auth: &AuthClaims,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    mediator: Option<&str>,
    member: &str,
    host: &str,
    room_id: &str,
    since_version: Option<u64>,
    lease_seconds: Option<i64>,
    live: bool,
) -> Result<Value, AppError> {
    let principal = match member_in_room(state, auth, member, room_id).await? {
        Ok(p) => p,
        Err(outcome) => return Ok(outcome),
    };
    let watches = &state.room_key_watches;
    let now = Utc::now().timestamp();
    let lease = lease_seconds.unwrap_or(MAX_LEASE_SECS).min(MAX_LEASE_SECS);

    // The record first, so a signal sent at once finds its watch.
    let (record, fresh, retiring) = {
        let _guard = watches.lock().await;
        match watches.get(&auth.did, member, host, room_id).await? {
            // Item 5: a re-arm of a one-shot watch that has not fired, and the renewal of a
            // live watch, keep the address — the host's watch is replaced, not added to.
            Some(held) if !held.lapsed(now) && held.live == live => (held, false, None),
            current => {
                // No mediator: this VTA can receive at no address, so it holds no watch.
                let Some(mediator) = mediator else {
                    return Ok(refused(room_id, "limitReached"));
                };
                let retiring = match current {
                    // A switch between one-shot and live: the watch it replaces waits under
                    // a key of its own, still passing on its signal, until the host has
                    // armed the new one at its new address.
                    Some(old) if !old.lapsed(now) => {
                        watches.forget(&old.key()).await?;
                        let mut old = old;
                        old.retiring = true;
                        watches.put(&old).await?;
                        Some(old)
                    }
                    Some(stale) => {
                        watches.forget(&stale.key()).await?;
                        None
                    }
                    None => None,
                };
                // A switch replaces a watch, so it needs no room beyond the one it holds.
                if retiring.is_none()
                    && let Err(full) = watches.room_for(&auth.did, member).await?
                {
                    tracing::debug!(?full, "a room watch is past this VTA's bound");
                    return Ok(refused(room_id, "limitReached"));
                }
                let mut record = RoomKeyWatches::new_record(
                    &auth.did,
                    member,
                    room_id,
                    host,
                    mediator,
                    now + lease,
                )?;
                record.live = live;
                watches.put(&record).await?;
                (record, true, retiring)
            }
        }
    };

    let mut payload = json!({ "roomId": room_id, "address": record.address });
    if let Some(v) = since_version {
        payload["sinceVersion"] = json!(v);
    }
    if let Some(l) = lease_seconds {
        payload["leaseSeconds"] = json!(l);
    }
    if live {
        // Item 3: armed live, and never a one-shot watch instead on the caller's behalf.
        payload["live"] = json!(true);
    }
    let answer = send_watch(
        state, auth, resolver, &principal, host, room_id, payload, live,
    )
    .await;
    // The new watch was not taken: forget it when it is new, or when the host refused a
    // re-arm or renewal — a live watch's renewal refused `liveNotPermitted` has ended at the
    // host (item 7) — and keep a re-armed one the host could not be reached for, whose
    // earlier arming may still be in force there. A switch puts the watch it was replacing
    // back, so a refused live watch leaves the one-shot watch in place.
    let (new_record, replaced) = (&record, &retiring);
    let undo = |keep: bool| async move {
        let _guard = watches.lock().await;
        if !keep {
            watches.forget(&new_record.key()).await?;
        }
        if let Some(old) = replaced {
            watches.forget(&old.key()).await?;
            let mut old = old.clone();
            old.retiring = false;
            watches.put(&old).await?;
        }
        Ok::<(), AppError>(())
    };
    let reply = match answer {
        Ok(Ok(reply)) => reply,
        Ok(Err(e)) => {
            let outcome = host_failure(room_id, e);
            let unreachable = outcome["refused"] == "hostUnreachable";
            undo(!fresh && unreachable).await?;
            return Ok(outcome);
        }
        // Completing the request failed here: forget a fresh record, and report.
        Err(e) => {
            undo(!fresh).await?;
            return Err(e);
        }
    };
    if reply.get("armed").and_then(Value::as_bool) != Some(true) {
        undo(false).await?;
        return Ok(not_armed(room_id));
    }
    // Item 7: live only when the host said so — a host implementing only 0.1 arms a
    // one-shot watch for a live request.
    let host_live = live && reply.get("live").and_then(Value::as_bool) == Some(true);
    // Item 7: never later than the host's answer, nor than this VTA's own bound.
    let host_until = reply
        .get("expiresAt")
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.timestamp());
    let until = host_until
        .unwrap_or(now + lease)
        .min(now + lease)
        .min(now + MAX_LEASE_SECS);
    {
        let _guard = watches.lock().await;
        // The watch may have fired already (a signal sent at once); then it is gone, and
        // writing it back would arm it twice.
        match watches.get(&auth.did, member, host, room_id).await? {
            Some(mut held) if held.address == record.address => {
                held.expires_at = until;
                held.live = host_live;
                watches.put(&held).await?;
            }
            _ => {}
        }
    }
    // A switch: the host armed the new watch, so the old one is cancelled at the host and
    // forgotten here. A cancel that does not land leaves the host's old watch to its own
    // lease, sending to an address nobody receives at any more.
    if let Some(old) = retiring {
        let cancel = json!({ "roomId": room_id, "address": old.address, "cancel": true });
        match send_watch(
            state, auth, resolver, &principal, host, room_id, cancel, old.live,
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::debug!(
                error = ?e,
                "the host did not cancel the watch a switch replaced; it lapses there"
            ),
            Err(e) => tracing::debug!(
                error = %e,
                "the watch a switch replaced could not be cancelled; it lapses at the host"
            ),
        }
        let _guard = watches.lock().await;
        watches.forget(&old.key()).await?;
    }
    Ok(armed(room_id, until, host_live))
}

/// Cancel one room's watch, one-shot or live: at the host when one is held, and forget it
/// here.
async fn cancel_one(
    state: &AppState,
    auth: &AuthClaims,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    member: &str,
    host: &str,
    room_id: &str,
) -> Result<Value, AppError> {
    let watches = &state.room_key_watches;
    let Some(held) = watches.get(&auth.did, member, host, room_id).await? else {
        return Ok(not_armed(room_id));
    };
    let principal = match member_in_room(state, auth, member, room_id).await? {
        Ok(p) => p,
        Err(outcome) => {
            // The member's credentials are gone (item 7): forget it here; the host cannot be
            // asked without them.
            let _guard = watches.lock().await;
            watches.forget(&held.key()).await?;
            return Ok(outcome);
        }
    };
    let payload = json!({ "roomId": room_id, "address": held.address, "cancel": true });
    let answer = send_watch(
        state, auth, resolver, &principal, host, room_id, payload, held.live,
    )
    .await?;
    match answer {
        Ok(_) => {
            let _guard = watches.lock().await;
            watches.forget(&held.key()).await?;
            Ok(not_armed(room_id))
        }
        Err(room_host::RoomTaskError::Refused { code, .. }) => {
            // The caller asked for it gone; a refusal at the host does not keep it here.
            let _guard = watches.lock().await;
            watches.forget(&held.key()).await?;
            Ok(host_refused(room_id, &code))
        }
        // Kept, so a retry cancels with the same address.
        Err(e) => Ok(host_failure(room_id, e)),
    }
}

/// A document delivered to a watch's `address` by `sender`, whom the transport proved. See
/// the module docs: passed on once, or dropped without a word.
#[cfg_attr(not(any(feature = "didcomm", feature = "tsp")), allow(dead_code))]
pub(crate) async fn receive_signal(state: &AppState, address: &str, sender: &str, body: &[u8]) {
    // Senders without standing at this VTA, as every host is, share one bound (VTI-TRN-029).
    if state
        .operation_budget
        .charge(
            super::operation_budget::Caller::Unauthenticated,
            vti_rooms::watch::CHANGED_TYPE,
        )
        .is_err()
    {
        return;
    }
    let Ok(doc) = serde_json::from_slice::<Value>(body) else {
        return;
    };
    receive_document(state, address, sender, &doc).await;
}

/// [`receive_signal`] after its budget and parse: `doc`, delivered to `address` by
/// `sender`. The spine's `rooms/changed` handler comes in here for a signal addressed to
/// this VTA's own DID — which is never a watch's address, so it is dropped.
pub(crate) async fn receive_document(state: &AppState, address: &str, sender: &str, doc: &Value) {
    let type_uri = doc["type"].as_str().unwrap_or_default();
    if type_uri.split('#').next() != Some(vti_rooms::watch::CHANGED_TYPE) {
        tracing::debug!("a document at a watch address that is not a signal — dropped");
        return;
    }
    if doc["recipient"]
        .as_str()
        .is_some_and(|r| party(r) != party(address))
    {
        return;
    }
    let Ok(signal) =
        serde_json::from_value::<vti_specs::rooms::changed::v0_1::Payload>(doc["payload"].clone())
    else {
        return;
    };
    let room_id = signal.room_id.to_string();
    let latest_version = signal.latest_version.get();

    let watches = &state.room_key_watches;
    let watch = {
        let _guard = watches.lock().await;
        let watch = match watches.by_address(address).await {
            Ok(Some(w)) => w,
            Ok(None) => {
                tracing::debug!("a signal for a watch this VTA no longer holds — dropped");
                return;
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not read the room watches; a signal is dropped");
                return;
            }
        };
        let from_host = party(sender) == party(&watch.host)
            && doc["issuer"]
                .as_str()
                .is_none_or(|i| party(i) == party(&watch.host));
        if !from_host || room_id != watch.room_id || watch.lapsed(Utc::now().timestamp()) {
            tracing::debug!("a signal not from the watch's host, room, or lease — dropped");
            return;
        }
        // Forgotten before it is passed on: one signal per one-shot arming. A live watch is
        // kept, and passes on every signal as it arrives (item 8) — never compared with an
        // earlier one, which would mean keeping the versions item 6 forbids.
        if !watch.live
            && let Err(e) = watches.forget(&watch.key()).await
        {
            tracing::warn!(error = %e, "could not forget a fired watch; its signal is dropped");
            return;
        }
        watch
    };
    pass_on(state, &watch, latest_version).await;
}

/// The `rooms/keys/changed/0.1` document for `watch`'s caller: the signal's room and
/// latest version, and the watch's member and host — nothing else.
pub(crate) fn changed_document(
    vta_did: Option<&str>,
    watch: &WatchRecord,
    latest_version: u64,
) -> Value {
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": vta_sdk::trust_tasks::TASK_ROOMS_KEYS_CHANGED_0_1,
        "recipient": watch.caller,
        "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": {
            "roomId": watch.room_id,
            "member": watch.member,
            "host": watch.host,
            "latestVersion": latest_version,
        },
    });
    if let Some(did) = vta_did {
        doc["issuer"] = json!(did);
    }
    doc
}

/// Send the pass-on to the watch's caller, the way `task-consent/granted` reaches its
/// requester, without a doorbell of this VTA's own.
async fn pass_on(state: &AppState, watch: &WatchRecord, latest_version: u64) {
    let vta_did = state.config.read().await.vta_did.clone();
    let mut doc = changed_document(vta_did.as_deref(), watch, latest_version);
    if !super::sign_outbound_request(state, &mut doc).await {
        tracing::warn!("a room signal could not be signed; it is not passed on");
        return;
    }
    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    match super::step_up::push_to_device_with(state, &watch.caller, &doc, PASS_ON_DELIVER_BY, false)
        .await
    {
        super::step_up::DevicePush::Queued { .. } => {
            tracing::debug!("a room's signal was passed on to the client that watched it")
        }
        super::step_up::DevicePush::NoRoute { .. } => tracing::debug!(
            "no mediator route to the client that watched a room; its signal is dropped"
        ),
        super::step_up::DevicePush::Refused => {}
    }
}

/// Forget every watch that lapsed, whose caller may no longer act as its member, or whose
/// member's credentials for the room are gone (Recipient item 7). Returns how many.
#[cfg_attr(not(any(feature = "didcomm", feature = "tsp")), allow(dead_code))]
pub(crate) async fn sweep(state: &AppState) -> Result<usize, AppError> {
    let watches = &state.room_key_watches;
    let now = Utc::now().timestamp();
    let mut gone = Vec::new();
    for w in watches.all().await? {
        if w.lapsed(now) || !still_stands(state, &w).await? {
            gone.push(w);
        }
    }
    if gone.is_empty() {
        return Ok(0);
    }
    let _guard = watches.lock().await;
    let mut forgotten = 0;
    for w in &gone {
        // A switch's retiring watch is its own record: judged, and forgotten, by itself.
        if w.retiring {
            watches.forget(&w.key()).await?;
            forgotten += 1;
            continue;
        }
        // Only the arming that was judged: one armed again since (a new address) is not.
        let current = watches
            .get(&w.caller, &w.member, &w.host, &w.room_id)
            .await?;
        if current.is_some_and(|c| c.address == w.address) {
            watches.forget(&w.key()).await?;
            forgotten += 1;
        }
    }
    tracing::debug!(forgotten, "room watches swept");
    Ok(forgotten)
}

/// Whether `w`'s caller may still act as its member, and the member still holds the room's
/// credentials conferring `read`. A store error keeps the watch: being unable to tell is not
/// a withdrawal.
#[cfg_attr(not(any(feature = "didcomm", feature = "tsp")), allow(dead_code))]
async fn still_stands(state: &AppState, w: &WatchRecord) -> Result<bool, AppError> {
    let (role, allowed_contexts) = match crate::acl::check_acl_full(&state.acl_ks, &w.caller).await
    {
        Ok(found) => found,
        Err(AppError::Forbidden(_)) | Err(AppError::NotFound(_)) => return Ok(false),
        Err(e) => return Err(e),
    };
    let auth = AuthClaims {
        did: w.caller.clone(),
        role,
        allowed_contexts,
        session_id: String::new(),
        access_expires_at: 0,
        issued_at: 0,
        amr: Vec::new(),
        acr: String::new(),
    };
    if super::room_act::is_delegate(state, &auth).await? {
        return Ok(false);
    }
    let key = crate::operations::persona::persona_key_for(
        crate::operations::persona::PersonaStores::from_state(state),
        &auth,
        &w.member,
        crate::operations::persona::Relationship::Authentication,
    )
    .await?;
    if key.is_none() {
        return Ok(false);
    }
    match member_in_room(state, &auth, &w.member, &w.room_id).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(_)) => Ok(false),
        Err(AppError::Conflict(_)) => Ok(true),
        Err(e) => Err(e),
    }
}
