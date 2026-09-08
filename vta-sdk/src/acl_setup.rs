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
//! ## Both transports, and why the TSP arm looks different
//!
//! [`set_client_acl_with_profile`] issues `account/update` through the ATM,
//! i.e. over DIDComm. [`set_client_acl_over_tsp`] issues the same task as a TSP
//! **Direct** message addressed to the mediator itself. Either one authorises
//! the account for *both* transports — the mediator keys its ACL on
//! `sha256(did)`, not on a protocol — so a client needs whichever it can reach
//! the mediator on, not both.
//!
//! The TSP arm exists because for a while there was no way to do this at all on
//! a TSP-only mediator. The mediator's management dispatch
//! (`MessageType::process` → `trust_tasks::process`) was `#[cfg(feature =
//! "didcomm")]` and took a DIDComm `Message`, so a TSP message addressed to it
//! was filed for pickup rather than answered — no packet a TSP-only client
//! could send would set its own ACL. affinidi-tdk-rs#783 added the TSP wrapper;
//! this is its client half.
//!
//! **A mediator predating that fix files the request as mail instead of acting
//! on it, and says nothing.** That is why the TSP arm does not report success:
//! `send` returning `Ok` means the frame was accepted for delivery, never that
//! the ACL was applied (R1.1). It logs what it sent, not what happened. The
//! cost of being wrong is bounded — an account left on the mediator's
//! `global_acl_default`, exactly where it would have been anyway.
//!
//! Why a fire-and-forget send rather than a request/response: the mediator
//! applies the ACL *before* responding, so a lost or late reply does not mean
//! the update failed — the same reasoning that makes the DIDComm arm log its
//! errors instead of propagating them. Awaiting a reply here would buy nothing
//! and would stall for the full timeout against a mediator that is never going
//! to answer.
//!
//! TSP delivery is *not* exempt from ACLs, which is why this matters rather
//! than being theoretical: `deliver_opaque` applies "existence,
//! RECEIVE_MESSAGES and the access-list verdict" via `delivery_decision`, and a
//! recipient that is not a local account is refused outright. Only
//! `receive_forwarded` is DIDComm-specific — that gate lives in the DIDComm
//! forward protocol (`messages/protocols/routing.rs`), which TSP never
//! traverses.

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

    // SHA-256 hex of the DID — the mediator's account-key convention.
    let client_did_hash = client_acl_hash(client_did);

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
    // `account_update` waits for a response, but that response is *direct*
    // delivery on the socket this request arrived on — the mediator answering
    // its own client — not a forward. `receive_forwarded` gates only the
    // routing path (`Capability::ReceiveForwarded` is checked against the *next
    // hop's* ACL in the mediator's `routing.rs`), so a still-closed account does
    // not withhold this reply. An `Err` here is therefore a genuine transport
    // failure or a slow mediator; it is logged at debug rather than propagated
    // because the mediator applies the ACL before responding, so a lost or late
    // reply still leaves the update applied.
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

/// Provision a client's own allow-all mediator ACL over an **already
/// connected** profile, awaiting the result.
///
/// Unlike [`set_client_acl_on_connection`] (fire-and-forget, which builds its
/// own second `ATMProfile` for the DID), this reuses the caller's live
/// profile/socket — so no second websocket contends for the DID's
/// one-socket-per-DID slot — and *awaits* the mediator round-trip under a
/// timeout. A caller can therefore rely on the account being open before its
/// next forwarded-message operation, e.g. a health trust-ping whose reply the
/// mediator must forward back to this client (which a closed account rejects
/// with `receive_forwarded`).
///
/// The `account_update` reply rides the same live socket (direct delivery, not
/// forwarded), so it returns even while the account is still closed. Errors and
/// timeouts are logged, not propagated: the mediator applies the ACL before
/// responding, so a lost/late reply does not mean the update failed.
pub async fn set_client_acl_with_profile(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    client_did: &str,
    channel: &str,
    client_name: &str,
) {
    // SHA-256 hex of the DID — the mediator's account-key convention.
    let client_did_hash = client_acl_hash(client_did);

    let acl = build_allow_all_acl();

    // Bound the round-trip so a stuck mediator can't hang the caller.
    const ACL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    match tokio::time::timeout(
        ACL_TIMEOUT,
        atm.trust_tasks()
            .account_update(profile, Some(client_did_hash), None, Some(acl), None),
    )
    .await
    {
        Ok(Ok(_)) => info!(
            channel,
            client_did = %client_did,
            client = client_name,
            "client ACL configured on mediator"
        ),
        Ok(Err(e)) => debug!(
            channel,
            client_did = %client_did,
            error = %e,
            client = client_name,
            "client ACL request error (mediator may still process asynchronously)"
        ),
        Err(_) => debug!(
            channel,
            client_did = %client_did,
            client = client_name,
            "client ACL request timed out (mediator may still process asynchronously)"
        ),
    }
}

/// Provision a client's own allow-all mediator ACL over **TSP**, as a Direct
/// message addressed to the mediator.
///
/// The TSP twin of [`set_client_acl_with_profile`], for a client whose mediator
/// it reaches over TSP — including a TSP-only mediator, which no DIDComm-issued
/// task can reach at all. Same task (`messaging/account/update/0.1`), same
/// allow-all ACL, same account key (`sha256(did)`), so whichever arm runs, the
/// account ends up authorised for both transports.
///
/// **Reports what it sent, not what happened.** A successful send means the
/// mediator accepted the frame, not that it applied the ACL (R1.1) — and a
/// mediator predating affinidi-tdk-rs#783 will file it as mail and answer
/// nothing. Deliberately fire-and-forget: the mediator applies the ACL before
/// responding, so a reply adds no information, while waiting for one would
/// stall for the full timeout against a mediator that will never send it.
///
/// Best-effort like its twin — errors are logged, never propagated. The worst
/// case is an account left on the mediator's `global_acl_default`.
#[cfg(feature = "tsp")]
pub async fn set_client_acl_over_tsp(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    client_did: &str,
    mediator_did: &str,
    channel: &str,
    client_name: &str,
) {
    let doc = match build_account_update_document(client_did, mediator_did) {
        Ok(doc) => doc,
        Err(e) => {
            debug!(
                channel,
                client_did = %client_did,
                error = %e,
                client = client_name,
                "could not build the account/update document for TSP (ACL unchanged)"
            );
            return;
        }
    };

    match atm.tsp().send(profile, mediator_did, &doc).await {
        // Note the wording: *sent*, not *configured*. See the module docs.
        Ok(()) => debug!(
            channel,
            client_did = %client_did,
            client = client_name,
            "sent account/update to the mediator over TSP (delivery not confirmed)"
        ),
        Err(e) => debug!(
            channel,
            client_did = %client_did,
            error = %e,
            client = client_name,
            "could not send account/update over TSP (ACL unchanged)"
        ),
    }
}

/// The `messaging/account/update/0.1` request that opens `client_did`'s account,
/// serialised as the bare Trust Task document TSP carries.
///
/// Bare on purpose: the TSP binding puts the document on the wire directly,
/// where DIDComm wraps it in a binding envelope whose `body` is the document.
/// The mediator's TSP arm recognises a request by parsing the payload and
/// matching its type, so what goes here has to be the document itself.
#[cfg(feature = "tsp")]
fn build_account_update_document(
    client_did: &str,
    mediator_did: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use trust_tasks_rs::TrustTask;

    let payload: account::update::v0_1::Payload = account::update::v0_1::Payload::builder()
        .did(client_acl_hash(client_did))
        .acl(Some(build_allow_all_acl()))
        .try_into()
        .map_err(|e| format!("account/update payload: {e:?}"))?;

    // `issuer`/`recipient` are set explicitly: the mediator's
    // `validate_basic` checks the document is addressed to it, and the TSP
    // envelope's sender is what authorises the change, so both have to be on
    // the document rather than inferred.
    let mut doc = TrustTask::for_payload(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload);
    doc.issuer = Some(client_did.to_string());
    doc.recipient = Some(mediator_did.to_string());
    Ok(serde_json::to_vec(&doc)?)
}

/// SHA-256 hex of a DID — the mediator's per-account ACL key
/// (`sha256::digest(did)` in affinidi-messaging-sdk). Self-referential: a
/// client always provisions the account keyed by the hash of its own DID.
fn client_acl_hash(did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(did);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_acl_hash_matches_mediator_account_key_convention() {
        // Vector = sha256(did) hex, taken from a real mediator ACL entry — this
        // is exactly the account key the mediator derives, so a mismatch means
        // we would provision the wrong account.
        assert_eq!(
            client_acl_hash("did:key:z6MkovnNkdRq64BNcpZqpCnQGDhPe3g2cHeB35A5e7k4sNkS"),
            "30a923cb69a99f8247469b72ea5b45b534e9f52a09200f92ce72f44e16714136"
        );
    }

    #[test]
    fn client_acl_hash_is_64_char_lowercase_hex() {
        let h = client_acl_hash("did:webvh:QmExample:vta.example.com");
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn allow_all_acl_opens_everything_but_blocked() {
        // Serialize so the assertion is agnostic to the wire type's field-name
        // casing: every boolean must be `true` except the `blocked` flag, and
        // the forwarded-delivery flags (the whole point) must be present.
        let v = serde_json::to_value(build_allow_all_acl()).expect("MediatorAcl serializes");
        let obj = v.as_object().expect("acl serializes to a JSON object");
        let mut saw_forwarded = false;
        for (field, value) in obj {
            let Some(b) = value.as_bool() else { continue };
            if field.to_ascii_lowercase().contains("block") {
                assert!(!b, "`{field}` must be false in an allow-all ACL");
            } else {
                assert!(b, "`{field}` must be true in an allow-all ACL");
            }
            if field.to_ascii_lowercase().contains("forwarded") {
                saw_forwarded = true;
            }
        }
        assert!(
            saw_forwarded,
            "allow-all ACL must set the forwarded-delivery flags"
        );
    }
}
