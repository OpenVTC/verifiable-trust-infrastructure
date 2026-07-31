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
//! calls this. The SDK's one dedicated *client-side* TSP session,
//! [`crate::session::TspPingSession`], is a transient `pnm health` liveness
//! probe on an ephemeral DID — it opens its own short-lived TSP socket and tears
//! it down, so it deliberately does **not** persist a mediator ACL (that would
//! litter the mediator with allow-all entries for throwaway probe DIDs). A probe
//! against an `ExplicitAllow` mediator is expected to require its DID be
//! pre-authorised.
//!
//! TODO(tsp-client): if/when the general client request transport gains a
//! *persistent* TSP variant (a `Tsp` arm on the `#[non_exhaustive]`
//! `TransportChoice`, or `TspPingSession` generalised into a request session),
//! that connect path must also call [`set_client_acl_with_profile`], or an
//! `ExplicitAllow` mediator will reject it exactly as it did before this
//! feature. The provisioning logic lives here so only the trigger is needed.

use std::sync::Arc;

use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use trust_tasks_rs::specs::messaging::account;

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
/// spawned background task; the caller is never blocked.
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
async fn apply_acl_set(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    client_did: &str,
    channel: &str,
    client_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // SHA-256 hex to match the mediator's account-key convention.
    let mut hasher = Sha256::new();
    hasher.update(client_did);
    let hash_bytes = hasher.finalize();
    let client_did_hash = hash_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let acl = build_allow_all_acl();

    // Apply the ACL via the mediator's trust-tasks `account/update` endpoint.
    // On an `ExplicitAllow` mediator the response cannot route back until this
    // very ACL grants `receive_forwarded`, so a timeout does NOT mean the
    // request was dropped; the mediator still applies it.
    match atm
        .trust_tasks()
        .account_update(profile, Some(client_did_hash), None, Some(acl), None)
        .await
    {
        Ok(_) => {
            info!(
                channel,
                client_did = %client_did,
                client = client_name,
                "client ACL configured on mediator"
            );
        }
        Err(e) => {
            debug!(
                channel,
                client_did = %client_did,
                error = %e,
                client = client_name,
                "client ACL request error (mediator may still process asynchronously)"
            );
        }
    }

    Ok(())
}

/// Build a wire-format ACL that allows all message types.
///
/// This creates a `MediatorAcl` wire format (the `acl` member of the trust-tasks
/// `messaging/account/update/0.1` task, which superseded `acl/set/0.1`) that
/// permits sending, receiving, forwarding, and anonymous messages. The
/// access-list mode is set to ExplicitDeny (denylist semantics), allowing all
/// except explicitly denied entries.
fn build_allow_all_acl() -> account::update::v0_1::MediatorAcl {
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
        // Don't set self-manage flags — let the mediator's defaults apply
        ..Default::default()
    }
}
