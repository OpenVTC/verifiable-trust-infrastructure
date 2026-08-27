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
//! that connect path must also call [`set_client_acl_on_connection`], or an
//! `ExplicitAllow` mediator will reject it exactly as it did before this
//! feature. The provisioning logic lives here so only the trigger is needed.

use std::sync::Arc;

use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use trust_tasks_rs::specs::messaging::account;

/// Set a client's own ACL on the mediator to accept all messages.
///
/// Call this immediately after a connection to the mediator succeeds. The client
/// sets its per-DID ACL to allow all message types, which overrides any
/// restrictive global ACL settings on the mediator while still respecting
/// per-context ACLs configured for integrations.
///
/// **Fire-and-forget and fully non-blocking.** The entire operation — including
/// building the ATM profile and the mediator round-trip — runs on a spawned
/// background task, so neither VTA startup nor a client connect is delayed. This
/// returns as soon as the task is spawned; both call sites (VTA and PNM) get the
/// same non-blocking behaviour.
///
/// # Behavior
/// - If building the profile or setting the ACL fails, a warning/debug line is
///   logged but the caller's startup/connect continues unaffected.
pub async fn set_client_acl_on_connection(
    atm: &ATM,
    client_did: &str,
    mediator_did: &str,
    channel: &str,
    client_name: &str,
) {
    // Own everything so the work can outlive the caller's stack frame, then
    // spawn a single background task. One spawn — not a spawn-inside-a-spawn —
    // keeps the profile build and the ACL round-trip off the hot path together.
    let atm = atm.clone();
    let client_did = client_did.to_string();
    let mediator_did = mediator_did.to_string();
    let channel = channel.to_string();
    let client_name = client_name.to_string();

    tokio::spawn(async move {
        if let Err(e) =
            set_client_acl_internal(&atm, &client_did, &mediator_did, &channel, &client_name).await
        {
            warn!(
                channel,
                error = %e,
                client = client_name,
                "failed to set client ACL on mediator (startup continues)"
            );
        }
    });
}

/// Internal implementation of ACL setup. Runs on the background task spawned by
/// [`set_client_acl_on_connection`]; it is free to `await` the mediator
/// round-trip directly since nothing on the caller's path is waiting on it.
async fn set_client_acl_internal(
    atm: &ATM,
    client_did: &str,
    mediator_did: &str,
    channel: &str,
    client_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build an ATM profile for the client with the mediator as the peer.
    let atm_profile = ATMProfile::new(
        atm,
        None,
        client_did.to_string(),
        Some(mediator_did.to_string()),
    )
    .await
    .map_err(|e| format!("failed to create ATM profile: {e}"))?;

    // Hash the client's DID for the mediator's ACL record (self-reference).
    // SHA-256 hex to match the mediator's account-key convention
    // (`sha256::digest(did)` in affinidi-messaging-sdk).
    let mut hasher = Sha256::new();
    hasher.update(client_did);
    let hash_bytes = hasher.finalize();
    let client_did_hash = hash_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // Build an "allow all" ACL that accepts every message type. Fields left
    // `None` (e.g. the self-manage flags) keep the mediator's existing value.
    let acl = build_allow_all_acl();

    let atm_profile_arc = Arc::new(atm_profile);

    // Apply the ACL to the client's own DID via the mediator's trust-tasks
    // protocol. The messaging family's rationalization (affinidi-tdk-rs#667/#668)
    // retired the single-purpose `acl/set` task in favour of `account/update`,
    // which carries `acl` as one optional member alongside `accountType` and
    // `queueLimits` — passing `None` for those two leaves them untouched, so this
    // is an ACL-only partial update exactly as `acl_set` was.
    //
    // `account_update` waits for a response, which on an `ExplicitAllow` mediator
    // cannot arrive until this very ACL grants `receive_forwarded` — so an `Err`
    // here (typically a timeout) does NOT mean the request was dropped; the
    // mediator still applies it. Hence debug, not warn, on error.
    match atm
        .trust_tasks()
        .account_update(
            &atm_profile_arc,
            Some(client_did_hash),
            None,
            Some(acl),
            None,
        )
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
    // The self-manage flags are deliberately left unset so the mediator's
    // defaults apply — which is what the builder does with a member never
    // named, exactly as `..Default::default()` did.
    account::update::v0_1::MediatorAcl::builder()
        .blocked(Some(false))
        .local(Some(true))
        .send_messages(Some(true))
        .receive_messages(Some(true))
        .send_forwarded(Some(true))
        .receive_forwarded(Some(true))
        .create_invites(Some(true))
        .anon_receive(Some(true))
        .access_list_mode(Some(
            account::update::v0_1::MediatorAclAccessListMode::ExplicitDeny,
        ))
        .try_into()
        .expect("MediatorAcl has no required member")
}
