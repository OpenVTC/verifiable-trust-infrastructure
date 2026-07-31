//! Mediator ACL setup for DIDComm/TSP clients.
//!
//! After a client successfully connects to a mediator, it configures its own per-DID
//! ACL to accept all messages despite potentially restrictive global ACL defaults.
//! This allows the client to receive messages while maintaining the flexibility to set
//! more restrictive ACLs on specific contexts or integrations if needed.
//!
//! Used by both VTA (server startup) and PNM (on DIDComm connect).
//! Gated on the `acl-setup` feature which requires `session` + `trust-tasks-rs`.
//!
//! ## Why this covers both DIDComm *and* TSP
//!
//! The mediator ACL is keyed on the **hashed DID** (`sha256(did)`), not on the
//! transport — it gates the account, not a protocol. On the VTA, DIDComm and TSP
//! are multiplexed over the DID's **single** mediator websocket (one socket per
//! DID; a second is evicted as `duplicate-channel`), so provisioning the DID's
//! ACL once — from the DIDComm-listener start path, which is also the
//! TSP-receive path on a `tsp`-compiled VTA — authorises the account for *both*
//! transports. There is no separate TSP ACL to set.
//!
//! On the client (PNM/CNM) the general request transport (`VtaClient` /
//! `TransportChoice` in `session.rs`) is DIDComm-or-REST: every *persistent*,
//! ACL-needing client connect goes through [`crate::didcomm_session`], which
//! calls this. The SDK's dedicated *client-side* DIDComm probe,
//! [`crate::session::TrustPingSession`], calls [`setup_client_acl`] (the
//! blocking variant) after opening its WebSocket, so the ACL is in place
//! before the first ping is sent — required for ExplicitAllow mediators where
//! the response cannot be forwarded to an unregistered DID.
//!
//! TODO(tsp-client): if/when the general client request transport gains a
//! *persistent* TSP variant (a `Tsp` arm on the `#[non_exhaustive]`
//! `TransportChoice`, or `TspPingSession` generalised into a request session),
//! that connect path must also call [`set_client_acl_with_profile`], or an
//! `ExplicitAllow` mediator will reject it exactly as it did before this
//! feature. The provisioning logic lives here so only the trigger is needed.

use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::messaging::{account, acl};
use uuid::Uuid;

/// Set a client's own ACL on the mediator using an already-connected profile.
///
/// Use this when you have already created an `ATMProfile` and enabled its
/// WebSocket — for example, right after `build_messaging` in the VTA startup
/// path or after `profile_enable_websocket` in a PNM DIDComm session. Reusing
/// the live profile avoids opening a second WebSocket for the same DID, which
/// the mediator would evict as a `duplicate-channel` (only one socket per DID
/// is permitted), causing the ACL request to silently time out.
///
/// **Fire-and-forget and fully non-blocking.** The ACL round-trip runs on a
/// spawned background task; the caller is never blocked. Use
/// [`setup_client_acl`] when you need to wait for the ACL before proceeding.
pub async fn set_client_acl_with_profile(
    atm: &ATM,
    profile: Arc<ATMProfile>,
    client_did: &str,
    channel: &str,
    client_name: &str,
) {
    let atm = atm.clone();
    let client_did = client_did.to_string();
    let channel = channel.to_string();
    let client_name = client_name.to_string();

    tokio::spawn(async move {
        if let Err(e) = apply_acl_set(&atm, &profile, &client_did, &channel, &client_name).await {
            warn!(
                channel,
                error = %e,
                client = client_name,
                "failed to set client ACL on mediator (startup continues)"
            );
        }
    });
}

/// Set a client's own ACL on the mediator and **await** the result.
///
/// Same as [`set_client_acl_with_profile`] but blocking — use this when the
/// caller must not proceed until the ACL is applied. For example, a transient
/// probe session (e.g. `TrustPingSession`) must have its ACL in place before
/// sending the probe message, or an ExplicitAllow mediator will reject the
/// response delivery.
pub async fn setup_client_acl(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    client_did: &str,
    channel: &str,
    client_name: &str,
) {
    if let Err(e) = apply_acl_set(atm, profile, client_did, channel, client_name).await {
        warn!(
            channel,
            error = %e,
            client = client_name,
            "failed to set client ACL on mediator"
        );
    }
}

/// Set a client's own ACL on the mediator, building a fresh ATM profile.
///
/// Prefer [`set_client_acl_with_profile`] when you already have a connected
/// `ATMProfile` — that variant reuses the live socket and avoids a
/// `duplicate-channel` eviction. Use this variant only if you genuinely need
/// to create a new profile (no pre-existing connection).
pub async fn set_client_acl_on_connection(
    atm: &ATM,
    client_did: &str,
    mediator_did: &str,
    channel: &str,
    client_name: &str,
) {
    let atm = atm.clone();
    let client_did = client_did.to_string();
    let mediator_did = mediator_did.to_string();
    let channel = channel.to_string();
    let client_name = client_name.to_string();

    tokio::spawn(async move {
        match ATMProfile::new(&atm, None, client_did.clone(), Some(mediator_did)).await {
            Ok(profile) => {
                let profile = Arc::new(profile);
                if let Err(e) =
                    apply_acl_set(&atm, &profile, &client_did, &channel, &client_name).await
                {
                    warn!(
                        channel,
                        error = %e,
                        client = client_name,
                        "failed to set client ACL on mediator (startup continues)"
                    );
                }
            }
            Err(e) => {
                warn!(
                    channel,
                    error = %e,
                    client = client_name,
                    "failed to create ATM profile for ACL setup (startup continues)"
                );
            }
        }
    });
}

/// Core ACL-set round-trip shared by both public entry points.
///
/// Tries `messaging/account/update` first (mediator ≥ 0.18.x). If the mediator
/// returns `e.p.protocol.trust_task.unsupported` (pre-0.18 mediators that only
/// know the retired `acl/set` task), falls back to a raw `acl/set` exchange
/// built from the trust-tasks-rs types. This makes the VTA forward-compatible
/// with newer mediators and backward-compatible with the deployed v0.17.x fleet.
async fn apply_acl_set(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    client_did: &str,
    channel: &str,
    client_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    hasher.update(client_did);
    let client_did_hash = hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // --- Try account/update (mediator ≥ 0.18.x) ---
    let acl_update = build_allow_all_acl_update();
    match atm
        .trust_tasks()
        .account_update(profile, Some(client_did_hash.clone()), None, Some(acl_update), None)
        .await
    {
        Ok(_) => {
            info!(
                channel,
                client_did = %client_did,
                client = client_name,
                "client ACL configured on mediator"
            );
            return Ok(());
        }
        Err(e) => {
            debug!(
                channel,
                client_did = %client_did,
                error = %e,
                client = client_name,
                "account_update not supported by mediator, trying acl/set fallback"
            );
        }
    }

    // --- Fallback: raw acl/set (mediator 0.17.x) ---
    //
    // SDK 0.18.65 removed the high-level `acl_set` helper (replaced by
    // `account_update` in tdk-rs PR #668). Replicate the exchange manually
    // using the trust-tasks-rs types and the public ATM pack+send APIs.
    //
    // IMPORTANT: must use wait_for_response=true (same as ATM's internal
    // `exchange()` helper). This registers a live-stream listener so the
    // mediator's response is routed back *directly* on the WebSocket channel —
    // not via the forwarded inbox. Forwarded delivery is blocked on an
    // ExplicitAllow mediator until the very ACL we're setting takes effect, so
    // fire-and-forget (wait=false) silently fails: no listener ⇒ no committed
    // ACL ⇒ all subsequent messages remain blocked.
    const ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

    let (profile_did, mediator_did) = profile.dids()?;

    let vid = acl::set::v0_1::Vid::from_str(&client_did_hash)
        .map_err(|e| format!("invalid DID hash for acl/set fallback: {e}"))?;
    let acl_set = build_allow_all_acl_set();
    let mut task = TrustTask::for_payload(
        Uuid::new_v4().to_string(),
        acl::set::v0_1::Payload { acl: acl_set, did: vid, ext: None },
    );
    task.issuer = Some(profile_did.to_string());
    task.recipient = Some(mediator_did.to_string());

    let body = serde_json::to_value(&task)
        .map_err(|e| format!("serialise acl/set task: {e}"))?;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let msg_id = Uuid::new_v4().to_string();
    let msg = Message::build(msg_id.clone(), ENVELOPE_TYPE.to_string(), body)
        .to(mediator_did.to_string())
        .from(profile_did.to_string())
        .created_time(now)
        .expires_time(now + 10)
        .finalize();

    let (packed, _) = atm
        .pack_encrypted(&msg, mediator_did, Some(profile_did), None)
        .await
        .map_err(|e| format!("pack acl/set: {e}"))?;

    atm.send_message(profile, &packed, &msg_id, true, true)
        .await
        .map_err(|e| format!("send acl/set: {e}"))?;

    info!(
        channel,
        client_did = %client_did,
        client = client_name,
        "client ACL configured on mediator (acl/set)"
    );
    Ok(())
}

/// Allow-all ACL for `messaging/account/update` (mediator ≥ 0.18.x).
fn build_allow_all_acl_update() -> account::update::v0_1::MediatorAcl {
    account::update::v0_1::MediatorAcl {
        blocked: Some(false),
        local: Some(true),
        send_messages: Some(true),
        receive_messages: Some(true),
        send_forwarded: Some(true),
        receive_forwarded: Some(true),
        create_invites: Some(true),
        anon_receive: Some(true),
        access_list_mode: Some(account::update::v0_1::MediatorAclAccessListMode::ExplicitDeny),
        ..Default::default()
    }
}

/// Allow-all ACL for `acl/set` (mediator 0.17.x fallback).
fn build_allow_all_acl_set() -> acl::set::v0_1::MediatorAcl {
    acl::set::v0_1::MediatorAcl {
        blocked: Some(false),
        local: Some(true),
        send_messages: Some(true),
        receive_messages: Some(true),
        send_forwarded: Some(true),
        receive_forwarded: Some(true),
        create_invites: Some(true),
        anon_receive: Some(true),
        access_list_mode: Some(acl::set::v0_1::MediatorAclAccessListMode::ExplicitDeny),
        ..Default::default()
    }
}
