//! Being reachable at a mediator, so a member with no route to a URL can still be served.
//!
//! # What this changes, and what it deliberately does not
//!
//! Nothing about authorization. A host takes the presenter from the request document's own
//! `eddsa-jcs-2022` proof and the authority from the chain the room issued, and neither
//! comes from the carrier. So a request arriving over DIDComm is exactly as authorized as
//! the same bytes arriving over a POST — the transport authenticating its sender confers
//! *nothing*, which is what lets [`crate::dispatch`] be one function rather than one per
//! wire.
//!
//! What it changes is who can reach the host at all. A `?at=<url>` address needs the host to
//! be at a URL a member's network can open — a public hostname, a certificate, an origin the
//! browser is allowed to talk to. A `?at=<did>` address needs none of that: the member and
//! the host both dial a mediator, and neither has to be able to reach the other. A host
//! behind NAT, on a laptop, or on an origin no browser would be permitted to call is
//! reachable the same way a phone is.
//!
//! # Off unless an operator asks
//!
//! Behind the `didcomm` feature and a `--mediator-did` flag, both off by default. This crate
//! makes every capability a decision rather than an inheritance — network DID resolution is
//! off, browser origins are off — and opening a standing outbound connection to a third
//! party is a larger decision than either. A host that is not told to be reachable at a
//! mediator opens no socket and needs no identity.
//!
//! # The identity is persistent, and that is load-bearing
//!
//! A host's DID is what a member's saved address names. If it changed on restart, every link
//! anybody had kept would point at a host that no longer exists — and the failure would be a
//! timeout, which reads as "the host is down" rather than "the host is now somebody else".
//! So it is minted once into the data directory and read back thereafter.

use std::path::Path;
use std::sync::Arc;

use affinidi_messaging_core::{MessageTransport, Protocol};
use affinidi_messaging_sdk::DidCommTransport;
use affinidi_secrets_resolver::SecretsResolver as _;
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};

use crate::HostState;

/// The largest DID any `DIDCacheClient` will parse (`max_did_size_in_bytes`, default 1000).
///
/// Checked at mint because **neither end says so** when it is exceeded. The caller fails its
/// websocket connect as `isActive? command timed out`, which reads as a hang; the mediator
/// answers `403 authcrypt requires sender public key`, which reads as a key problem. Only
/// `affinidi_did_authentication` logs the real reason, and only on one side.
///
/// A `did:peer:2` carries its services *inside* the identifier, so each one costs roughly the
/// base64 of the mediator DID it names. Two of them against a `did:webvh` mediator is about
/// 460 bytes and fine; against a `did:peer` mediator it is about 1685, and every caller that
/// tries to resolve it fails. The same trap the transport harness hit — see CHANGELOG,
/// "Watch the DID size" — and it was closed there the same way.
const MAX_DID_BYTES: usize = 1000;

/// The DIDComm `type` a Trust-Task envelope rides under.
///
/// From the crate that defines the binding rather than written out here. Four hand-written
/// copies of this URI across the workspace is what let a push go out under the *task* type
/// instead of the envelope type — which a conformant peer drops silently, because "not an
/// envelope" and "not addressed to me" look identical from the outside.
use trust_tasks_didcomm::ENVELOPE_TYPE;

/// The host's own identity: the key it is reached by, and the `did:peer:2` naming it.
///
/// `Debug` is hand-written rather than derived, and deliberately: a derived one prints the
/// secrets, and the places a `Debug` reaches — a log line, a panic message, a test failure —
/// are exactly the places key material must not turn up. The identifier is public and is the
/// only part worth seeing.
pub struct HostIdentity {
    pub did: String,
    secrets: Vec<Secret>,
}

impl std::fmt::Debug for HostIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostIdentity")
            .field("did", &self.did)
            .field(
                "secrets",
                &format_args!("<{} redacted>", self.secrets.len()),
            )
            .finish()
    }
}

/// The stored form. **Key material** — see the module docs.
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    did: String,
    /// The mediator this identity was minted to advertise.
    ///
    /// Recorded rather than re-derived from the DID. The first cut rebuilt the service
    /// block's base64 and looked for it in the identifier, which fails whenever the encoder
    /// orders or omits a field differently from the guess — and it did, so a host refused to
    /// start against the very mediator it had been minted for. A fact you can write down is
    /// not a fact to reconstruct.
    mediator: String,
    /// The secrets, as the resolver serialises them.
    secrets: Vec<Secret>,
}

impl HostIdentity {
    /// Load this host's identity, minting one on first use.
    ///
    /// `did:peer:2`, so the identifier carries both its keys **and** the mediator it is
    /// reached at. That is what makes `?at=<did>` a complete address: a member resolves it
    /// by computation — no network, no registry — and learns where to dial and what to seal
    /// to. A `did:key` could not say the second thing, and a `did:webvh` would make every
    /// member fetch a log to talk to a host that is already telling them everything.
    pub fn load_or_mint(data_dir: &Path, mediator_did: &str) -> anyhow::Result<Self> {
        let path = data_dir.join("host-identity.json");

        if path.exists() {
            if let Err(e) = vti_common::secure_file::restrict_file_to_owner(&path) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "could not restrict the host identity to its owner; it holds a private key"
                );
            }
            let file: IdentityFile = serde_json::from_slice(&std::fs::read(&path)?)?;
            // A `did:peer` encodes its keys *and its services* in the identifier, so an
            // identity minted against one mediator names that mediator forever. Pointed at a
            // different one, the stored DID would advertise somewhere this host no longer
            // listens — and a member who resolved it would dial the old mediator and wait.
            // Refuse rather than serve a lie about where we are.
            if file.mediator != mediator_did {
                anyhow::bail!(
                    "the stored host identity at {} advertises {}, not {}. A did:peer names \
                     its services in its identifier, so changing mediator means a new \
                     identity and a new address — delete it to mint one, and expect saved \
                     links to stop resolving.",
                    path.display(),
                    file.mediator,
                    mediator_did
                );
            }
            return Ok(Self {
                did: file.did,
                secrets: file.secrets,
            });
        }

        let (did, secrets) = DID::generate_did_peer_with_services(
            vec![
                (PeerKeyRole::Verification, KeyType::Ed25519),
                (PeerKeyRole::Encryption, KeyType::X25519),
            ],
            Some(services(mediator_did)),
        )
        .map_err(|e| anyhow::anyhow!("mint the host identity: {e}"))?;

        // Refused here, where it can be explained, rather than at every caller that tries to
        // resolve it. A host that minted an over-long identity would come up, log that it was
        // reachable, and be unreachable — with the failure appearing at the other end as a
        // timeout.
        if did.len() > MAX_DID_BYTES {
            anyhow::bail!(
                "the identity this host would mint is {} bytes, past the {MAX_DID_BYTES}-byte \
                 limit every DID resolver enforces — so no member could resolve it, and the \
                 failure would surface at them as a websocket timeout rather than here. A \
                 `did:peer:2` carries its services inside the identifier, so each one costs \
                 about the length of `{mediator_did}` again. Use a mediator with a short DID: \
                 a `did:webvh` leaves this around 460 bytes, which is what production mints.",
                did.len()
            );
        }

        std::fs::create_dir_all(data_dir)?;
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&IdentityFile {
                did: did.clone(),
                mediator: mediator_did.to_string(),
                secrets: secrets.clone(),
            })?,
        )?;
        if let Err(e) = vti_common::secure_file::restrict_file_to_owner(&path) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "could not restrict the host identity to its owner; it holds a private key"
            );
        }

        Ok(Self { did, secrets })
    }
}

/// The services this host advertises: reach me here, over either of these.
///
/// Both, because a member must not have to guess. A mediator carries TSP and DIDComm on the
/// one socket it permits per DID, so a client that assumed TSP would usually be right — and
/// would break against a host that served only DIDComm, with nothing in the document having
/// changed to warn it. What a host serves is a thing it says.
fn services(mediator_did: &str) -> Vec<affinidi_tdk::dids::PeerService> {
    use affinidi_tdk::dids::{
        OneOrMany, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
    };

    let at_mediator = |type_: &str, accept: Vec<String>| PeerService {
        type_: type_.into(),
        endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
            uri: mediator_did.to_string(),
            accept,
            routing_keys: vec![],
        })),
        id: None,
    };

    vec![
        // `accept` names DIDComm's media types and only DIDComm's; asserting them on the TSP
        // service would advertise something untrue.
        at_mediator("DIDCommMessaging", vec!["didcomm/v2".into()]),
        at_mediator("TSPTransport", vec![]),
    ]
}

/// Connect to `mediator_did` as this host, and serve Trust Tasks until the process ends.
///
/// One socket, both protocols: a mediator permits one websocket per DID and sniffs the TSP
/// magic byte to route what arrives, so this listens through the delivery layer's transport
/// — whose inbound stream surfaces both, tagged — rather than the DIDComm-only pickup.
/// Opening a second socket for TSP is not an alternative; the mediator evicts one of the
/// pair as a duplicate channel.
pub async fn serve(
    state: Arc<HostState>,
    identity: HostIdentity,
    mediator_did: String,
) -> anyhow::Result<()> {
    let tdk = TDKSharedState::new(TDKConfig::builder().build()?).await?;
    for secret in &identity.secrets {
        tdk.secrets_resolver().insert(secret.clone()).await;
    }

    let atm = ATM::new(ATMConfig::builder().build()?, Arc::new(tdk)).await?;
    let atm = Arc::new(atm);

    let profile =
        ATMProfile::new(&atm, None, identity.did.clone(), Some(mediator_did.clone())).await?;
    // Registered with the ATM rather than held loose, so a shutdown can actually stop this
    // socket: the ATM stops websockets by walking its own profile map, and an unregistered
    // profile outlives every teardown and keeps reconnecting.
    let profile = atm.profile_add(&profile, false).await?;
    atm.profile_enable_websocket(&profile).await?;

    let transport = DidCommTransport::new((*atm).clone(), profile.clone()).await?;
    tracing::info!(
        host_did = %identity.did,
        mediator = %mediator_did,
        "reachable at a mediator — serving Trust Tasks over DIDComm and TSP"
    );

    let mut inbound = transport.inbound();
    while let Some(frame) = inbound.next().await {
        // A frame with no authenticated sender has nobody to answer. It is not a refusal —
        // the sender is not who a request is authorized by — but a reply needs a recipient,
        // and there is none.
        let Some(sender) = frame.message.sender.clone() else {
            continue;
        };
        if !frame.message.verified {
            continue;
        }

        let Some(Request { envelope, thread }) =
            unwrap_request(frame.message.protocol, &frame.message.payload)
        else {
            continue;
        };
        let reply_thread = thread;

        let answer = crate::dispatch(&state, &envelope).await;
        // The document is the answer, and it is self-describing. The status `dispatch`
        // derived is HTTP's way of saying the same thing and is dropped here.
        let reply = answer.document;

        let sent = match frame.message.protocol {
            Protocol::TSP => send_tsp(&atm, &profile, &mediator_did, &sender, &reply).await,
            _ => {
                send_didcomm(
                    &atm,
                    &profile,
                    &identity.did,
                    &mediator_did,
                    &sender,
                    reply,
                    &reply_thread,
                )
                .await
            }
        };
        if let Err(e) = sent {
            tracing::warn!(to = %sender, error = %e, "could not return an answer");
        }

        // Acked after the answer is away, never before: the ack is what makes the mediator
        // drop its copy, so acking first would lose a request whose answer never left.
        if let Err(e) = transport.ack(frame.ack.clone()).await {
            tracing::debug!(error = %e, "could not ack an inbound frame");
        }
    }

    Ok(())
}

/// One inbound frame, reduced to what answering it needs.
#[derive(Debug, PartialEq, Eq)]
struct Request {
    /// The Trust-Task document, exactly as `dispatch` and the HTTP route take it.
    envelope: Vec<u8>,
    /// What to thread the reply on, so the caller can recognise it.
    thread: String,
}

/// Take the request out of a frame, whichever carrier brought it.
///
/// `None` for anything that is not a request: a problem report, a forward that arrived
/// un-unwrapped, a DIDComm message under some other type. Answering those would either spin
/// against the mediator's own policy or reply to a message nobody sent.
///
/// # The thread is the document's, never the frame's
///
/// A caller correlates on the id it put on the **document** — the only id it ever saw. A
/// frame's id is the transport's handle for one delivery and means nothing on the other side.
/// Threading on it produces a reply that is sent, accepted by the mediator, and matched by
/// nobody: the caller waits out its whole timeout while the answer sits unclaimed, and
/// neither end logs anything wrong. That was a real bug here, found only by running it.
///
/// DIDComm has an id of its own on the envelope and a caller correlates on that, so the two
/// carriers read it from different places — which is the reason this is one function and not
/// an `if` at the call site.
fn unwrap_request(protocol: Protocol, payload: &[u8]) -> Option<Request> {
    let json: serde_json::Value = serde_json::from_slice(payload).ok()?;

    match protocol {
        // TSP carries the document as its payload, with no wrapper at all — byte-identical to
        // the HTTP body. Nothing to unwrap, and the id can only come from the document.
        Protocol::TSP => Some(Request {
            envelope: payload.to_vec(),
            thread: json.get("id")?.as_str()?.to_string(),
        }),
        // DIDComm wraps it: one reserved envelope `type`, whose `body` is the document.
        _ => {
            let type_ = json.get("type")?.as_str()?;
            if type_ != ENVELOPE_TYPE {
                tracing::debug!(
                    got = type_,
                    expected = ENVELOPE_TYPE,
                    "ignoring a DIDComm message that is not a Trust-Task envelope"
                );
                return None;
            }
            Some(Request {
                envelope: serde_json::to_vec(json.get("body")?).ok()?,
                thread: json.get("id")?.as_str()?.to_string(),
            })
        }
    }
}

/// Return an answer over DIDComm: authcrypt to the caller, then forward through the mediator.
///
/// Two hops, because a mediator refuses direct delivery of inner messages. It unwraps the
/// outer envelope, sees the next hop, and queues the inner one for the caller's pickup —
/// having held the plaintext of neither.
async fn send_didcomm(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    host_did: &str,
    mediator_did: &str,
    sender: &str,
    reply: serde_json::Value,
    thread: &str,
) -> anyhow::Result<()> {
    let reply_id = uuid::Uuid::new_v4().to_string();
    let message = Message::build(reply_id.clone(), ENVELOPE_TYPE.to_string(), reply)
        .from(host_did.to_string())
        .to(sender.to_string())
        .thid(thread.to_string())
        .finalize();

    let (inner, _) = atm
        .pack_encrypted(&message, sender, Some(host_did), Some(host_did))
        .await
        .map_err(|e| anyhow::anyhow!("pack the answer: {e}"))?;

    atm.forward_and_send_message(
        profile,
        false, // authcrypt the forward envelope
        &inner,
        Some(&reply_id),
        mediator_did,
        sender,
        None,
        None,
        false,
    )
    .await
    .map_err(|e| anyhow::anyhow!("send the answer: {e}"))?;
    Ok(())
}

/// Return an answer over TSP: sealed end-to-end to the caller, routed through the mediator.
///
/// # No wrapper, because the document already threads itself
///
/// TSP has no headers, so it is tempting to conclude correlation must be added around the
/// document. It must not: a routed Trust-Task response carries its own `threadId`, set to the
/// request's `id`, and that is what a caller matches on. Wrapping it says the same thing
/// twice — and disagrees with the other host of this protocol.
///
/// This did wrap it, as `{ thid, document }`, which made a `room-host` reply unreadable to a
/// client written against `vtc-service` and the reverse. Both now send the document and
/// nothing else, byte-identical to the HTTP body in either direction.
async fn send_tsp(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    mediator_did: &str,
    sender: &str,
    reply: &serde_json::Value,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(reply)?;
    atm.tsp()
        .send_routed(
            profile,
            &[mediator_did.to_string(), sender.to_string()],
            &bytes,
        )
        .await
        .map_err(|e| anyhow::anyhow!("send the TSP answer: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A Trust-Task document, as a caller would send one.
    fn document() -> serde_json::Value {
        json!({
            "id": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "type": "https://trusttasks.org/spec/rooms/records/list/0.1",
            "issuedAt": "2026-09-09T00:00:00Z",
            "payload": { "roomId": "did:key:zRoom" },
        })
    }

    /// **The regression.** Over TSP the thread must be the document's own `id`.
    ///
    /// It was the frame's — the transport's handle for one delivery, which means nothing on
    /// the other side. The reply was sent, the mediator accepted it, and no waiter matched it;
    /// the caller waited out its whole timeout while the answer sat unclaimed, and neither end
    /// logged anything wrong. Only running it against a real mediator showed it, which is why
    /// it is pinned here where a unit test can hold it.
    #[test]
    fn a_tsp_request_threads_on_the_documents_own_id() {
        let payload = serde_json::to_vec(&document()).unwrap();
        let request = unwrap_request(Protocol::TSP, &payload).expect("a TSP payload is a request");

        assert_eq!(
            request.thread, "urn:uuid:11111111-1111-1111-1111-111111111111",
            "the caller correlates on the id it put on the document, and saw no other"
        );
        assert_eq!(
            request.envelope, payload,
            "and the document reaches dispatch byte-identical to the HTTP body — no wrapper"
        );
    }

    /// DIDComm carries an id on the envelope, and a caller correlates on **that**.
    #[test]
    fn a_didcomm_envelope_threads_on_the_message_id() {
        let payload = serde_json::to_vec(&json!({
            "id": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "type": ENVELOPE_TYPE,
            "body": document(),
        }))
        .unwrap();

        let request = unwrap_request(Protocol::DIDComm, &payload).expect("an envelope");
        assert_eq!(
            request.thread,
            "urn:uuid:22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request.envelope).unwrap(),
            document(),
            "the body is the document, unwrapped"
        );
    }

    /// Everything that is not a request is ignored rather than answered.
    ///
    /// Answering a problem report feeds the mediator's own policy back into the loop and
    /// spins; answering a forward that arrived un-unwrapped replies to a message nobody sent.
    #[test]
    fn a_didcomm_message_that_is_not_an_envelope_is_not_a_request() {
        for typ in [
            "https://didcomm.org/report-problem/2.0/problem-report",
            "https://didcomm.org/routing/2.0/forward",
            "https://didcomm.org/trust-ping/2.0/ping",
            // The near-miss: a caller sending the *task* type instead of the binding's
            // envelope type. This is the mistake the shared `ENVELOPE_TYPE` constant exists
            // to prevent, and a conformant peer drops it silently — so it must drop here too.
            "https://trusttasks.org/spec/rooms/records/list/0.1",
        ] {
            let payload =
                serde_json::to_vec(&json!({ "id": "urn:uuid:x", "type": typ, "body": {} }))
                    .unwrap();
            assert_eq!(
                unwrap_request(Protocol::DIDComm, &payload),
                None,
                "`{typ}` is not a Trust-Task envelope"
            );
        }
    }

    /// Neither carrier answers something that is not JSON, or that carries no id to thread on.
    #[test]
    fn a_request_with_nothing_to_correlate_it_by_is_refused() {
        for protocol in [Protocol::TSP, Protocol::DIDComm] {
            assert_eq!(unwrap_request(protocol, b"not json at all"), None);
        }
        // A TSP payload with no `id` cannot be answered: the reply would carry a thread the
        // caller never sent, which is the same failure as threading on the wrong one.
        let no_id = serde_json::to_vec(&json!({ "type": "x", "payload": {} })).unwrap();
        assert_eq!(unwrap_request(Protocol::TSP, &no_id), None);
    }
}
