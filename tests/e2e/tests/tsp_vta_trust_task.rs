//! A Trust Task must reach a **real VTA** over TSP and be answered over TSP.
//!
//! ## Why this exists
//!
//! Every other TSP test in this crate stops below the VTA. `tsp_round_trip`
//! proves the mediator routes a frame between two accounts; `tsp_dual_leg`
//! proves one socket carries both protocols; `tsp_binding_pair` proves the
//! envelope survives a round trip. All of them are transport tests with no VTA
//! in the picture, and the VTA-side unit tests are their mirror image —
//! `tsp_inbound::dispatch_one` is exercised with a `{}` body that never reaches
//! a handler, and asserts only that *some* reply envelope comes back.
//!
//! So the join between them — a real Trust Task, dispatched by a running VTA,
//! answered back over the same mediator socket — was covered from both sides
//! and by nothing. #1507 is what that gap cost: the VTA sealed its outbound TSP
//! frames on a profile built with no mediator, which `ATMProfile::dids()`
//! refuses, so every TSP send died inside the SDK with `Config error: No
//! Mediator is configured for this Profile`. Inbound replies kept working
//! (`handle_tsp` seals on a different profile), so the VTA looked healthy right
//! up until it had to start a conversation.
//!
//! ## What these pin
//!
//! 1. A Trust Task sealed to the VTA over TSP is dispatched on the shared spine
//!    with the **proven sender VID** as the authenticated caller, and its reply
//!    routes back over the same socket.
//! 2. `vault/upsert` with a `tspMessage` sealed secret is unsealed. This is the
//!    path `trust_tasks::vault::tsp_unseal_tests` says outright it cannot
//!    cover: "the unpack-success path needs runtime verification against a real
//!    TSP message". It had never run since it was added in #594 — the profile
//!    it used could not unseal either.
//! 3. An unauthorized sender is *refused over the wire*, not dropped.
//!
//! Hermetic — `MockVta::start_with_transports` embeds a `TestMediator`, no
//! network, no deployed VTA — so these run in CI unignored.

use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::session::TspSession;
use vta_sdk::trust_tasks::TASK_VAULT_UPSERT_0_3;
use vta_service::test_support::MockVta;

mod common;

/// How long to wait for the VTA's reply. Generous on purpose: the failure this
/// guards against is a *silent* one — the frame never leaves the VTA — and a
/// tight budget would report it as "still in flight" rather than as broken.
const REPLY_TIMEOUT_SECS: u64 = 20;

/// Deterministic `did:key` + matching multibase private key from a seed byte.
/// Same helper as `tsp_round_trip` / `didcomm_session`, so every TSP binary in
/// this crate builds identities identically.
fn did_key_from_seed(seed_byte: u8) -> (String, String) {
    let seed = [seed_byte; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    let did = format!("did:key:{}", ed25519_multibase_pubkey(&pk));
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    let priv_mb = multibase::encode(multibase::Base::Base58Btc, &buf);
    (did, priv_mb)
}

/// Seal `payload` to `to_did` as a TSP Direct message, in the stored
/// (base64url) form `vault/upsert`'s `sealedSecret.message` carries.
///
/// A second, **socket-less** ATM rather than reaching into [`TspSession`]:
/// sealing is pure crypto (`pack` resolves the recipient's VID and encrypts; it
/// opens nothing), and the session deliberately exposes no `pack` because
/// nothing in production seals a payload it is not also about to send. This is
/// the one case that does — the sealed blob travels *inside* a Trust Task that
/// is itself sent over TSP, which is the whole point of the envelope.
///
/// The profile still needs `Some(mediator)`: `TspOps::pack` calls
/// `ATMProfile::dids()` to name the sender, and that errors without one. That
/// is the same requirement #1507 was about, seen from the sending side.
async fn seal_to(
    from_did: &str,
    from_priv: &str,
    to_did: &str,
    mediator_did: &str,
    payload: &[u8],
) -> String {
    let seed = vta_sdk::did_key::decode_private_key_multibase(from_priv).expect("decode seed");
    let secrets = vta_sdk::did_key::secrets_from_did_key(from_did, &seed).expect("derive secrets");
    let tdk = TDKSharedState::new(TDKConfig::builder().build().expect("tdk config"))
        .await
        .expect("tdk shared state");
    tdk.secrets_resolver().insert(secrets.signing).await;
    tdk.secrets_resolver().insert(secrets.key_agreement).await;
    let atm = ATM::new(
        ATMConfig::builder().build().expect("atm config"),
        Arc::new(tdk),
    )
    .await
    .expect("sealing atm");
    let profile = ATMProfile::new(
        &atm,
        None,
        from_did.to_string(),
        Some(mediator_did.to_string()),
    )
    .await
    .expect("sealing profile");
    // `false` — no live stream. This ATM never opens a socket; the mediator
    // permits one per DID and `TspSession` below owns this DID's.
    let profile = atm
        .profile_add(&profile, false)
        .await
        .expect("register sealing profile");

    let qb2 = atm
        .tsp()
        .pack(&profile, to_did, payload)
        .await
        .expect("seal the secret to the VTA over TSP");
    let stored = atm.tsp().encode(&qb2);
    atm.graceful_shutdown().await;
    stored
}

/// A `vault/upsert/0.3` document carrying `sealed` as a `tspMessage` envelope.
///
/// `issuedAt` is not optional decoration: the consumer refuses a document
/// without one (`malformedRequest`, SPEC §7.2 — it bounds the duplicate-execution
/// record). Omitting it is a cheap way to write a test that looks like it
/// exercises a handler and never reaches one.
async fn upsert_with_tsp_secret(
    id: &str,
    issuer: &str,
    issuer_priv: &str,
    recipient: &str,
    context_id: &str,
    sealed: &str,
) -> Vec<u8> {
    let mut doc: TrustTask<Value> = serde_json::from_value(json!({
        "id": id,
        "type": TASK_VAULT_UPSERT_0_3,
        "issuedAt": chrono::Utc::now().to_rfc3339(),
        "issuer": issuer,
        "recipient": recipient,
        "payload": {
            "contextId": context_id,
            // `webOrigin`, camelCase — the wire form 0.2+ declares. The
            // internal `vti_common::vault::SiteTarget` is kebab (`web-origin`)
            // and that is *not* a mismatch: `trust_tasks::wire_v0_2` translates
            // the discriminator at the boundary. Write the wire form here. The
            // spine schema-validates before the transform, so a kebab `kind`
            // is refused as `malformedRequest` and never reaches a handler —
            // which reads like a handler bug and is not one.
            "targets": [{ "kind": "webOrigin", "origin": "https://example.com" }],
            "label": "tsp-sealed entry",
            "secretKind": "password",
            "sealedSecret": { "envelope": "tspMessage", "message": sealed },
        },
    }))
    .expect("the document is a well-formed TrustTask");

    // `vault/upsert/0.3` declares `proof` REQUIRED, and TSP's sender proof does
    // not stand in for it: the transport proves who sealed the frame, the
    // Data-Integrity proof binds the *document*. The spine wants both.
    vta_sdk::trust_task_sign::sign_in_place(&mut doc, issuer, issuer_priv)
        .await
        .expect("sign the upsert document");

    serde_json::to_vec(&doc).expect("serialize the signed document")
}

/// The cleartext a `tspMessage` envelope carries: a `VaultSecret`, camelCase,
/// kebab-case `kind` discriminator (see `vti_common::vault::VaultSecret`).
fn password_secret() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "kind": "password",
        "username": "e2e-user",
        "password": "correct-horse-battery-staple",
    }))
    .expect("serialize the vault secret")
}

/// Open the binding envelope the VTA replies in and return the document.
///
/// `send_document`/`receive_next` handle the wrapper, so this asserts on what
/// came back rather than re-checking carriage — `tsp_binding_pair` owns that
/// question.
fn reply_document(frame: &str) -> Value {
    let value: Value = serde_json::from_str(frame)
        .unwrap_or_else(|e| panic!("the VTA's reply is not JSON: {e}: {frame}"));
    value.get("document").cloned().unwrap_or(value)
}

/// **The headline.** A `vault/upsert` whose secret is sealed over TSP, sent to a
/// running VTA over TSP, unsealed by it, and answered over TSP.
///
/// Three things have to hold at once, and each was separately unproven: the VTA
/// can *unseal* a TSP message (`unseal_tsp_secret`, never exercised), the spine
/// authorizes on the proven VID rather than a bearer token, and the reply gets
/// back out — the leg #1507 fixed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tsp_sealed_secret_is_unsealed_by_a_running_vta() {
    common::init_tracing();

    let mock = MockVta::start_with_transports().await;
    let (client_did, client_priv) = did_key_from_seed(0x71);

    // Two different permissions in two different places: the mediator decides
    // who may connect and be routed to, the VTA decides what they may ask for.
    mock.register_mediator_account(&client_did).await;
    mock.grant_super_admin(&client_did).await;

    let sealed = seal_to(
        &client_did,
        &client_priv,
        mock.vta_did(),
        mock.mediator_did(),
        &password_secret(),
    )
    .await;

    let session = TspSession::connect(&client_did, &client_priv, mock.mediator_did())
        .await
        .expect("client TSP session connects to the VTA's mediator");

    let id = "urn:uuid:tsp-upsert-probe";
    let doc = upsert_with_tsp_secret(
        id,
        &client_did,
        &client_priv,
        mock.vta_did(),
        "e2e-ctx",
        &sealed,
    )
    .await;
    session
        .send_document(mock.vta_did(), mock.mediator_did(), &doc)
        .await
        .expect("the Trust Task is accepted for delivery");

    let received = session
        .receive_next(REPLY_TIMEOUT_SECS)
        .await
        .expect("receive_next must not error");

    session.shutdown().await;
    mock.shutdown().await;

    let frame = received.expect(
        "the VTA never answered over TSP. Before #1507 this is exactly how the \
         defect presented: the request was dispatched fine and the reply died in \
         the SDK with `Config error: No Mediator is configured for this Profile`, \
         because the VTA sealed on a profile that had none.",
    );
    let doc = reply_document(&frame);
    let type_uri = doc.get("type").and_then(Value::as_str).unwrap_or_default();

    assert!(
        !type_uri.starts_with("https://trusttasks.org/spec/trust-task-error/"),
        "the VTA refused the sealed upsert: {doc:#}"
    );
    assert_eq!(
        type_uri,
        format!("{TASK_VAULT_UPSERT_0_3}#response"),
        "expected a vault/upsert response: {doc:#}"
    );

    // Not just "no error": the entry exists. A failed unseal comes back as a
    // `taskFailed` reject, so reaching a created entry is the proof that
    // `unseal_tsp_secret` opened a real TSP message — which is the assertion
    // `trust_tasks::vault::tsp_unseal_tests` could not make.
    assert_eq!(
        doc.pointer("/payload/created").and_then(Value::as_bool),
        Some(true),
        "the upsert did not create an entry: {doc:#}"
    );
    assert_eq!(
        doc.pointer("/payload/entry/createdBy")
            .and_then(Value::as_str),
        Some(client_did.as_str()),
        "the entry must be attributed to the TSP sender the VTA proved, not to \
         anyone else: {doc:#}"
    );
    assert_eq!(
        doc.pointer("/payload/entry/contextId")
            .and_then(Value::as_str),
        Some("e2e-ctx"),
        "the entry landed in the wrong context: {doc:#}"
    );
}

/// An unauthorized sender is **refused over the wire**, not dropped.
///
/// `dispatch_one`'s unit test proves the refusal document is *built*; this
/// proves it is sealed, routed and delivered. A VTA that builds a refusal and
/// cannot send it looks identical, from the client, to a VTA that ignored the
/// request — and that is the failure mode #1507 actually produced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unauthorized_sender_is_refused_over_tsp_not_met_with_silence() {
    common::init_tracing();

    let mock = MockVta::start_with_transports().await;
    let (client_did, client_priv) = did_key_from_seed(0x72);

    // A mediator account but deliberately **no** ACL grant: the frame must
    // reach the VTA and come back refused, rather than not come back.
    mock.register_mediator_account(&client_did).await;

    let session = TspSession::connect(&client_did, &client_priv, mock.mediator_did())
        .await
        .expect("client TSP session connects");

    let doc = upsert_with_tsp_secret(
        "urn:uuid:tsp-unauthorized",
        &client_did,
        &client_priv,
        mock.vta_did(),
        "e2e-ctx",
        "not-a-tsp-message",
    )
    .await;
    session
        .send_document(mock.vta_did(), mock.mediator_did(), &doc)
        .await
        .expect("the Trust Task is accepted for delivery");

    let received = session
        .receive_next(REPLY_TIMEOUT_SECS)
        .await
        .expect("receive_next must not error");

    session.shutdown().await;
    mock.shutdown().await;

    let frame = received.expect(
        "an unauthorized sender got silence. The refusal is built (see \
         `tsp_inbound::dispatch_one`'s unit tests) so the failure is in sending \
         it — which is indistinguishable, from here, from the VTA ignoring us.",
    );
    let doc = reply_document(&frame);
    let code = doc
        .pointer("/payload/code")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert_eq!(
        code, "permissionDenied",
        "an ungranted sender must be refused for *lack of authority*, not for \
         some earlier validation failure — a `malformedRequest` here would mean \
         the document never reached the authorization check: {doc:#}"
    );
}

/// The reply is correlated to *this* request.
///
/// The mediator inbox is durable and flushes on connect, so "a frame arrived"
/// is weaker than it looks — `tsp_ping_correlation` documents a health probe
/// that passed on a previous run's backlog. Here the thread is checked against
/// the id we sent, so a stale frame cannot stand in for an answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reply_threads_to_the_request_that_asked_for_it() {
    common::init_tracing();

    let mock = MockVta::start_with_transports().await;
    let (client_did, client_priv) = did_key_from_seed(0x73);
    mock.register_mediator_account(&client_did).await;
    mock.grant_super_admin(&client_did).await;

    let session = TspSession::connect(&client_did, &client_priv, mock.mediator_did())
        .await
        .expect("client TSP session connects");

    let id = "urn:uuid:tsp-thread-probe";
    let doc = upsert_with_tsp_secret(
        id,
        &client_did,
        &client_priv,
        mock.vta_did(),
        "e2e-ctx",
        "not-a-tsp-message",
    )
    .await;
    session
        .send_document(mock.vta_did(), mock.mediator_did(), &doc)
        .await
        .expect("accepted for delivery");

    let received = session
        .receive_next(REPLY_TIMEOUT_SECS)
        .await
        .expect("receive_next must not error");

    // Give the VTA a beat to finish any follow-up work before tearing the
    // mediator down, so a teardown race cannot masquerade as a routing failure.
    tokio::time::sleep(Duration::from_millis(50)).await;
    session.shutdown().await;
    mock.shutdown().await;

    let frame = received.expect("the VTA answered nothing");
    let doc = reply_document(&frame);
    let thread = doc
        .get("threadId")
        .and_then(Value::as_str)
        .or_else(|| doc.get("id").and_then(Value::as_str))
        .unwrap_or_default();
    assert_eq!(
        thread, id,
        "the reply names a different thread than the request — a stale inbox \
         frame would look like this: {doc:#}"
    );
}
