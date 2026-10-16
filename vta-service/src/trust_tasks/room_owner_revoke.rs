//! `rooms/owner/revoke/0.1` — the room withdraws credentials it issued: this agent signs
//! the room's next revocation list as the room, keeps it, and delivers it to every host
//! serving the room (trust-tasks-tf #804).
//!
//! # The order (`rooms/owner/revoke`, conformance)
//!
//! 1. Everything that needs nobody else, before anything is signed: `roomSubject`,
//!    `noSigningKey`, `noAuthority`, then `noList` (item 1).
//! 2. Under the room's signing lock: recover a later list a host holds (item 4 — a key
//!    holder restored from an old backup would otherwise sign a list every host refuses as
//!    `stale`), establish the tier when a withdrawal names anyone (item 2), build and sign
//!    the next list and keep it (items 3–4).
//! 3. Outside the lock: deliver to each host and report each outcome (items 5–6). The
//!    answer is a success once the list is signed and kept, whatever the deliveries did.
//!
//! The entitlement is control of the room's signing key, exactly as for
//! `rooms/owner/issue-authority`: the key is named and the oracle decides whether this
//! caller may use it ([`crate::operations::room_issuance::RoomKeySigner`]).

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::rooms::owner::revoke::v0_1 as spec;
use vti_common::acl::Capability;
use vti_common::error::AppError;
use vti_rooms::revocation::Entry;

use crate::auth::AuthClaims;
use crate::operations::room_revocation as revocation;
use crate::server::AppState;

use super::TrustTaskOutcome;
use super::helpers::{app_error_to_reject, parse_payload, reject_with_code, success_response};
use super::room_group::{declared, outbound_identity, record, signing_context};
use super::room_owner_group::{Delivery, HostCall};

/// `rooms/owner/revoke/0.1`.
pub(super) async fn handle_revoke(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::error_codes as codes;
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::CredentialWrite,
        "withdrawing credentials a room issued",
    )
    .await
    {
        return r;
    }
    let req: spec::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let room_id = req.room_id.as_str().to_string();
    let signing_key_id = req.signing_key_id.as_str().to_string();
    let hosts: Vec<String> = req.hosts.iter().map(|h| h.as_str().to_string()).collect();
    let withdraw: Vec<Value> = req
        .withdraw
        .iter()
        .map(|w| serde_json::to_value(w).unwrap_or(Value::Null))
        .collect();

    // Item 1: `roomSubject` — never the room itself.
    if withdraw
        .iter()
        .any(|w| w["kind"] == "subject" && w["subject"].as_str() == Some(room_id.as_str()))
    {
        return reject_with_code(
            &doc,
            declared(codes::ROOM_SUBJECT),
            format!(
                "a `subject` withdrawal names room `{room_id}` itself; withdraw everything it \
                 issued with a `room` withdrawal instead"
            ),
            None,
        );
    }
    // Item 1: `noSigningKey`.
    if let Err(e) = crate::operations::keys::require_key_nameable(
        &state.keys_ks,
        &state.acl_ks,
        auth,
        &signing_key_id,
    )
    .await
    {
        return reject_with_code(
            &doc,
            declared(codes::NO_SIGNING_KEY),
            format!(
                "this agent will not sign as room `{room_id}` with key `{signing_key_id}`: {e}"
            ),
            None,
        );
    }
    // Item 1: `noAuthority` — the owner persona's `admin`, which every delivery presents.
    let (_, resolver) = match outbound_identity(state, &doc).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let host_call =
        match HostCall::as_owner(state, auth, &resolver, &room_id, &doc, codes::NO_AUTHORITY).await
        {
            Ok(h) => h,
            Err(r) => return r,
        };
    let presentation = match host_call
        .admin_presentation(&doc, codes::NO_AUTHORITY)
        .await
    {
        Ok(p) => p,
        Err(r) => return r,
    };

    let list = {
        let _lock = revocation::signing_lock(&room_id).await;

        // Item 4: a list a host holds at a later sequence than this agent's is the room's
        // — this agent signed it before a restore, or it was never kept here — and the
        // next list has to keep its entries. Adopted only if the room signed it.
        if let Some(public_key) = room_public_key(state, &signing_key_id).await {
            for host in &hosts {
                if let Some(found) = host_call.fetch_list(host, &presentation).await {
                    match revocation::adopt(&state.room_groups_ks, &room_id, &found, &public_key)
                        .await
                    {
                        Ok(true) => tracing::info!(room = %room_id, %host,
                            "recovered a later revocation list from a host"),
                        Ok(false) => {}
                        Err(e) => return app_error_to_reject(&doc, e),
                    }
                }
            }
        }

        let held = match revocation::held(&state.room_groups_ks, &room_id).await {
            Ok(h) => h,
            Err(e) => return app_error_to_reject(&doc, e),
        };
        if withdraw.is_empty() {
            // Item 1: `noList` — nothing to deliver.
            match held {
                Some(h) => h,
                None => {
                    return reject_with_code(
                        &doc,
                        declared(codes::NO_LIST),
                        format!(
                            "this agent holds no revocation list for room `{room_id}`, so there \
                             is nothing to deliver"
                        ),
                        None,
                    );
                }
            }
        } else {
            // Item 2: a withdrawal naming a credential or a party needs the tier first —
            // a private room's host must refuse such a list, and every later list would
            // have to keep the entry.
            let names_anyone = withdraw.iter().any(|w| w["kind"] != "room");
            if names_anyone {
                match host_call.tier(&hosts[0]).await {
                    Ok(t) if t == "private" => {
                        return reject_with_code(
                            &doc,
                            declared(codes::ENTRY_NOT_PERMITTED),
                            format!(
                                "room `{room_id}` is private: only a `room` withdrawal can be \
                                 applied there. Nothing was signed"
                            ),
                            None,
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        return reject_with_code(
                            &doc,
                            declared(codes::TIER_UNKNOWN),
                            format!(
                                "could not establish room `{room_id}`'s tier from host `{}`: {e}. \
                                 Nothing was signed",
                                hosts[0]
                            ),
                            None,
                        );
                    }
                }
            }

            // Item 3: `revokedAt` is the time this agent signs — never a time the caller
            // chose, so a `subject` or `room` entry withdraws exactly what the room had
            // issued until now.
            let signed_at = chrono::Utc::now();
            let added: Vec<Entry> = match withdraw
                .iter()
                .map(|w| withdrawal(w, signed_at))
                .collect::<Result<_, _>>()
            {
                Ok(a) => a,
                Err(e) => return app_error_to_reject(&doc, e),
            };
            let signed = match revocation::sign_next(
                signing_context(state, auth),
                &signing_key_id,
                &room_id,
                held.as_ref(),
                &added,
                signed_at,
            )
            .await
            {
                Ok(l) => l,
                Err(e) => {
                    return reject_with_code(
                        &doc,
                        declared(codes::NO_SIGNING_KEY),
                        format!("this agent could not sign as room `{room_id}`: {e}"),
                        None,
                    );
                }
            };
            // Item 4: kept durably before it is delivered anywhere.
            if let Err(e) = revocation::keep(&state.room_groups_ks, &signed).await {
                return app_error_to_reject(&doc, e);
            }
            signed
        }
    };

    // Item 5: every host, each outcome reported in order. Item 6: a success either way.
    let mut deliveries = Vec::with_capacity(hosts.len());
    for host in &hosts {
        deliveries.push(
            match host_call.deliver_list(host, &list, &presentation).await {
                Delivery::Accepted { head, in_force_at } => serde_json::json!({
                    "host": host, "outcome": "accepted", "head": head, "inForceAt": in_force_at,
                }),
                Delivery::Refused { code, .. } => serde_json::json!({
                    "host": host, "outcome": "refused", "code": code,
                }),
                Delivery::Unreachable(why) => {
                    tracing::warn!(room = %room_id, %host, reason = %why,
                    "a host did not answer the room's revocation list");
                    serde_json::json!({ "host": host, "outcome": "unreachable" })
                }
            },
        );
    }

    // The room only: the list names withdrawn parties, which this agent's audit does not
    // repeat.
    record(state, "rooms.owner.revoke", auth, &room_id).await;
    success_response(
        &doc,
        serde_json::json!({
            "roomId": room_id,
            "list": list.raw(),
            "head": list.head().to_wire(),
            "deliveries": deliveries,
        }),
    )
}

/// One `Withdrawal` as the entry it adds, stamped `revoked_at`.
fn withdrawal(w: &Value, revoked_at: chrono::DateTime<chrono::Utc>) -> Result<Entry, AppError> {
    let until = match w.get("until").and_then(Value::as_str) {
        Some(s) => Some(
            chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| AppError::Validation(format!("`until`: {e}")))?
                .with_timezone(&chrono::Utc),
        ),
        None => None,
    };
    let text = |name: &str| {
        w.get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| AppError::Validation(format!("a withdrawal carries no `{name}`")))
    };
    Ok(match w.get("kind").and_then(Value::as_str) {
        Some("credential") => Entry::Credential {
            credential_id: text("credentialId")?,
            revoked_at,
            until,
        },
        Some("subject") => Entry::Subject {
            subject: text("subject")?,
            revoked_at,
            until,
        },
        Some("room") => Entry::Room { revoked_at, until },
        _ => return Err(AppError::Validation("a withdrawal of no known kind".into())),
    })
}

/// The public key of the key this agent signs as the room with — what a recovered list must
/// verify under to be the room's (`rooms/revocations/get`, *reader*).
async fn room_public_key(state: &AppState, signing_key_id: &str) -> Option<Vec<u8>> {
    let record = state
        .keys_ks
        .get::<vta_sdk::keys::KeyRecord>(crate::keys::store_key(signing_key_id))
        .await
        .ok()??;
    vta_sdk::did_key::decode_ed25519_public_key_multibase(&record.public_key)
        .ok()
        .map(|k| k.to_vec())
}
