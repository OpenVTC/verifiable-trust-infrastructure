//! A mock VTA for other crates' tests: [`MockVta`], a real VTA serving on a
//! loopback port (optionally with a stub DID hosting service, and — feature
//! `transport-harness` — DIDComm and TSP through an embedded mediator into the
//! production inbound loop).
//!
//! Extracted from `vta_service::test_support` (#2570) so the mock and its
//! transport harness are not part of `vta-service`'s published API. The
//! fixtures `vta-service`'s own unit tests build on — the in-memory store,
//! [`build_test_app`],
//! [`TestAppContext`], the signing
//! helpers — stay there: a unit test compiles `vta-service` as its own crate, so
//! it cannot take a fixture from a crate that depends on `vta-service` without
//! getting a second, incompatible copy of every type. They are re-exported here,
//! so a consumer needs only this crate.
//!
//! Test-only — never in a production build.

pub use vta_service::test_support::*;

#[cfg(feature = "transport-harness")]
use std::sync::Arc;

/// The WebVH URL the [`StubWebvhHost`] hands back from `request_uri` — a
/// syntactically valid WebVH URL the VTA mints the persona DID from (same shape
/// the serverless `create_did_webvh` tests are known to mint against). The
/// resulting persona DID is `did:webvh:<scid>:webvh-host.test`.
pub const STUB_WEBVH_DID_URL: &str = "https://webvh-host.test/dids/persona/did.jsonl";

/// A minimal in-process stub of a **DID hosting service** — just enough of its
/// Trust-Task surface (`POST /api/trust-tasks`) for the VTA's server-managed
/// webvh paths to complete a round-trip: reserve a path, publish, delete, the
/// agent-name verbs, the DID listing and the caller's domains.
///
/// It behaves like the real control plane where the VTA depends on it:
///
/// - a request without a proof made for `authentication` is refused with
///   `proofRequired` / `proofInvalid`, so a VTA that stopped signing would fail
///   every round-trip rather than pass against a lenient stub;
/// - each request payload must parse as the generated type for its task
///   (unknown members refused), so a wrong shape is `malformedRequest`;
/// - every answer is a `#response` threaded to the request, addressed back to
///   its issuer and signed by the host's own DID ([`STUB_WEBVH_SERVER_DID`]),
///   whose document [`MockVta::start_with_webvh_host`] seeds into the VTA's
///   resolver with the key under `authentication`.
///
/// It persists nothing: the DID is minted VTA-side; the host hands back a
/// valid WebVH URL and accepts the publish. Bound to a random loopback port;
/// shuts down on drop.
pub struct StubWebvhHost {
    base_url: String,
    /// Number of upcoming `did/register` publishes to refuse before accepting
    /// again — lets a test simulate a transient host outage and assert the VTA
    /// self-recovers. Shared with the handler.
    fail_puts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Number of `did/delete` requests the host has accepted, so a test can
    /// tell a deletion that reached the host from one that did not.
    deletes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// When set, replies are signed by a key that is not the host's, while
    /// still naming the host's verification method — a forged answer.
    forge_replies: std::sync::Arc<std::sync::atomic::AtomicBool>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

/// The stub hosting service's DID. A valid-format `did:webvh`; resolution is
/// served from the seeded cache, not the network.
pub const STUB_WEBVH_SERVER_DID: &str = "did:webvh:stubscid0000000000000000:webvh-host.test";

/// The seed of the stub hosting service's signing key.
const STUB_WEBVH_SERVER_SEED: u8 = 0x5E;

impl StubWebvhHost {
    /// The stub hosting service's DID document: its signing key under
    /// `authentication` and `assertionMethod`, and a `WebVHHosting` service at
    /// `base_url`, which is where the VTA derives the HTTPS Trust-Task base.
    pub fn server_did_document(base_url: &str) -> serde_json::Value {
        let (_did, key_vm) = did_for_seed(STUB_WEBVH_SERVER_SEED);
        let public_key = key_vm.rsplit('#').next().unwrap_or_default().to_string();
        let vm = format!("{STUB_WEBVH_SERVER_DID}#key-0");
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": STUB_WEBVH_SERVER_DID,
            "verificationMethod": [{
                "id": vm,
                "type": "Multikey",
                "controller": STUB_WEBVH_SERVER_DID,
                "publicKeyMultibase": public_key,
            }],
            "authentication": [vm],
            "assertionMethod": [vm],
            "service": [{
                "id": format!("{STUB_WEBVH_SERVER_DID}#webvh"),
                "type": "WebVHHosting",
                "serviceEndpoint": base_url,
            }]
        })
    }

    /// Start the stub host on a random loopback port and return once bound.
    ///
    /// Enables private endpoints for the whole process
    /// ([`vta_sdk::http::set_allow_private_endpoints`]), since the VTA reaches
    /// a loopback host only with that opt-in.
    pub async fn start() -> StubWebvhHost {
        use axum::routing::post;
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;

        let fail_puts = Arc::new(AtomicUsize::new(0));
        let deletes = Arc::new(AtomicUsize::new(0));
        let forge_replies = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let router =
            axum::Router::new().route(
                "/api/trust-tasks",
                post({
                    let fail_puts = fail_puts.clone();
                    let deletes = deletes.clone();
                    let forge_replies = forge_replies.clone();
                    move |axum::Json(doc): axum::Json<serde_json::Value>| {
                        let fail_puts = fail_puts.clone();
                        let deletes = deletes.clone();
                        let forge = forge_replies.load(std::sync::atomic::Ordering::SeqCst);
                        async move {
                            axum::Json(stub_host_answer(&doc, &fail_puts, &deletes, forge).await)
                        }
                    }
                }),
            );

        // The VTA reaches this loopback host over plain http, which its
        // outbound REST send allows only with private endpoints enabled for
        // the process (`VTA_ALLOW_PRIVATE_ENDPOINTS`).
        vta_sdk::http::set_allow_private_endpoints(true);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub webvh host port");
        let addr = listener.local_addr().expect("stub host local addr");
        let base_url = format!("http://{addr}");

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await;
        });

        StubWebvhHost {
            base_url,
            fail_puts,
            deletes,
            forge_replies,
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }

    /// The loopback base URL of the stub host (e.g. `http://127.0.0.1:54321`) —
    /// goes into the seeded server DID's `WebVHHosting` service endpoint.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Refuse the next `n` publishes (`did/register`) with `internalError`,
    /// then accept again — a transient outage a test can recover from.
    pub fn fail_next_publishes(&self, n: usize) {
        self.fail_puts.store(n, std::sync::atomic::Ordering::SeqCst);
    }

    /// How many `did/delete` requests the host has accepted.
    pub fn deletes(&self) -> usize {
        self.deletes.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Sign every later reply with a key that is not the host's.
    pub fn forge_replies(&self) {
        self.forge_replies
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The stub hosting service's answer to one request document.
async fn stub_host_answer(
    doc: &serde_json::Value,
    fail_puts: &std::sync::atomic::AtomicUsize,
    deletes: &std::sync::atomic::AtomicUsize,
    forge: bool,
) -> serde_json::Value {
    use serde_json::{Value, json};
    use std::sync::atomic::Ordering;
    use vti_specs::did_management as dm;

    const CREATED: &str = "2026-01-01T00:00:00Z";
    const DM: &str = "https://trusttasks.org/spec/did-management/";

    let request_id = doc["id"].as_str().unwrap_or_default().to_string();
    let requester = doc["issuer"].as_str().unwrap_or_default().to_string();
    let type_uri = doc["type"].as_str().unwrap_or_default().to_string();
    let error = |code: &str, message: &str| {
        json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "threadId": request_id,
            "type": "https://trusttasks.org/spec/trust-task-error/0.5",
            "issuer": STUB_WEBVH_SERVER_DID,
            "recipient": requester,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "code": code, "message": message, "retryable": false },
        })
    };

    // The control plane refuses an unsigned request, and an operational one
    // signed for anything but `authentication`.
    match doc["proof"]["proofPurpose"].as_str() {
        None => return error("proofRequired", "a proof is required"),
        Some("authentication") => {}
        Some(_) => {
            return error(
                "proofInvalid",
                "operational tasks are signed for authentication",
            );
        }
    }
    if doc["recipient"] != STUB_WEBVH_SERVER_DID {
        return error("malformedRequest", "not addressed to this service");
    }

    let payload = doc["payload"].clone();
    fn conforms<P: serde::de::DeserializeOwned>(v: &Value) -> bool {
        serde_json::from_value::<P>(v.clone()).is_ok()
    }
    let record = |mnemonic: &str| {
        json!({
            "mnemonic": mnemonic,
            "owner": requester,
            "didUrl": STUB_WEBVH_DID_URL,
            "domain": "webvh-host.test",
            "createdAt": CREATED,
            "updatedAt": CREATED,
            "versionCount": 1,
        })
    };
    let task = type_uri.strip_prefix(DM).unwrap_or_default();
    let (valid, answer) = match task {
        "did/check-name/0.1" => (
            conforms::<dm::did::check_name::v0_1::Payload>(&payload),
            json!({ "available": true, "reserved": true, "record": record("stub-mnemonic") }),
        ),
        "did/register/0.1" => {
            // `fetch_update` is deprecated in rustc 1.99 in favour of `try_update`,
            // which is newer than the workspace's 1.95 MSRV.
            #[allow(deprecated)]
            let take_failure = fail_puts
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
            if take_failure {
                // A transient outage: the publish did not land.
                return error("internalError", "the host is unavailable");
            }
            (
                conforms::<dm::did::register::v0_1::Payload>(&payload),
                json!({ "record": record("stub-mnemonic") }),
            )
        }
        "did/delete/0.1" => {
            let ok = conforms::<dm::did::delete::v0_1::Payload>(&payload);
            if ok {
                deletes.fetch_add(1, Ordering::SeqCst);
            }
            (
                ok,
                json!({ "record": record(payload["mnemonic"].as_str().unwrap_or("x")) }),
            )
        }
        "agent-name/update/0.1" => (
            conforms::<dm::agent_name::update::v0_1::Payload>(&payload),
            json!({ "record": record("stub-mnemonic") }),
        ),
        "agent-name/remove/0.1" => (
            conforms::<dm::agent_name::remove::v0_1::Payload>(&payload),
            json!({ "record": record("stub-mnemonic") }),
        ),
        "agent-name/list/0.1" => (
            conforms::<dm::agent_name::list::v0_1::Payload>(&payload),
            json!({
                "mnemonic": payload["mnemonic"],
                "agentNames": [{ "name": "coverage-agent", "enabled": true, "createdAt": CREATED }],
            }),
        ),
        "agent-name/check/0.1" => (
            conforms::<dm::agent_name::check::v0_1::Payload>(&payload),
            json!({
                "name": "coverage-agent",
                "domain": "webvh-host.test",
                "available": true,
                "reserved": false,
            }),
        ),
        // The host's view of the slots it holds for this VTA: one slot the VTA
        // has **no** record of, so a reconcile against it reports both arms
        // (the slot is host-only; the DID a test mints is agent-only), and
        // `servers/retire-orphan` has something retireable.
        "did/list/0.2" => (
            conforms::<dm::did::list::v0_2::Payload>(&payload),
            json!({
                "records": [{
                    "mnemonic": "cov-orphan-slot",
                    "owner": requester,
                    "domain": "webvh-host.test",
                    "disabled": false,
                    "createdAt": CREATED,
                    "updatedAt": CREATED,
                    "versionCount": 0,
                }],
            }),
        ),
        "me/domains/0.1" => (
            conforms::<dm::me::domains::v0_1::Payload>(&payload),
            json!({
                "domains": [{
                    "name": "webvh-host.test",
                    "defaultDomain": true,
                    "status": "active",
                    "createdAt": CREATED,
                }],
                "default": "webvh-host.test",
            }),
        ),
        _ => return error("notImplemented", "the stub does not serve this task"),
    };
    if !valid {
        return error("malformedRequest", "the payload does not match its schema");
    }

    let mut reply: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "threadId": request_id,
        "type": format!("{type_uri}#response"),
        "issuer": STUB_WEBVH_SERVER_DID,
        "recipient": requester,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": answer,
    }))
    .expect("the stub's reply is a Trust Task");
    sign_with_vm(
        if forge {
            STUB_WEBVH_SERVER_SEED.wrapping_add(1)
        } else {
            STUB_WEBVH_SERVER_SEED
        },
        &format!("{STUB_WEBVH_SERVER_DID}#key-0"),
        "authentication",
        &mut reply,
    );
    serde_json::to_value(&reply).expect("the stub's reply serialises")
}

impl Drop for StubWebvhHost {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// A **mock VTA** bound to an ephemeral local port — a real, listening HTTP
/// server a test harness can drive over the wire, with no setup ceremony.
///
/// Wraps [`build_test_app`] (ephemeral in-memory state — no TEE/KMS, no mediator,
/// no on-disk seed) and serves it on `127.0.0.1:<random-port>`. The server runs
/// in a background task and shuts down when the `MockVta` is dropped (or via
/// [`shutdown`](Self::shutdown)).
///
/// ```no_run
/// # async fn demo() {
/// use vta_test_support::MockVta;
/// let mock = MockVta::start().await;
/// let base = mock.base_url();              // e.g. http://127.0.0.1:54321
/// // … point a client at `base`, or seed ACL/sessions via `mock.ctx` …
/// mock.shutdown().await;
/// # }
/// ```
pub struct MockVta {
    base_url: String,
    /// The bootstrapped app context (keyspaces, JWT keys, config) so a harness
    /// can seed ACL rows / sessions before driving the API. Owns the temp data
    /// dir — kept alive for the lifetime of the `MockVta`.
    pub ctx: TestAppContext,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
    /// A stub webvh hosting server kept alive for the mock's lifetime when
    /// started via [`start_with_webvh_host`](Self::start_with_webvh_host).
    /// Dropped (shut down) with the `MockVta`.
    webvh_host: Option<StubWebvhHost>,
    /// Mediator-backed transports, present only for
    /// [`start_with_transports`](Self::start_with_transports).
    #[cfg(feature = "transport-harness")]
    transports: Option<MockVtaTransports>,
}

/// The mediator + inbound listener behind
/// [`MockVta::start_with_transports`](MockVta::start_with_transports).
#[cfg(feature = "transport-harness")]
struct MockVtaTransports {
    mediator: affinidi_messaging_test_mediator::TestMediatorHandle,
    /// The mediator both of the VTA's advertised services point at. The VTA's
    /// own `did:peer:2` is already on `ctx.vta_did`, so it is not repeated here.
    mediator_did: String,
    /// Cancels [`run_inbound_loop`](vta_service::messaging::service::run_inbound_loop).
    shutdown: tokio_util::sync::CancellationToken,
    loop_handle: Option<tokio::task::JoinHandle<()>>,
    /// Shared production messaging object. Retained outside the inbound task so
    /// tests can inspect dynamically-added candidate transports.
    messaging: Arc<vta_service::messaging::service::VtaMessaging>,
    /// The listener's ATM. Held so `shutdown` can stop its websocket: the
    /// mediator permits one socket per DID, and an abandoned one keeps
    /// auto-reconnecting (vta-sdk #830).
    atm: Arc<affinidi_tdk::messaging::ATM>,
    /// The VTA's own messaging profile — the handle a TSP relationship op needs
    /// alongside the ATM. Held so a test can reach the VTA-side relationship
    /// store (see [`MockVta::forget_tsp_relationship`]).
    profile: Arc<affinidi_tdk::messaging::profiles::ATMProfile>,
    /// The room watches' address supervisor
    /// ([`vta_service::messaging::watch_addresses::run`]), once
    /// [`MockVta::start_watch_addresses`] has started it. Stopped by `shutdown`
    /// (the cancel above) and awaited, so every address's socket is closed
    /// before the mediator goes.
    watch_addresses: Option<tokio::task::JoinHandle<()>>,
}

/// A candidate mediator configured for migration-handshake tests.
///
/// The VTA is registered as a local account before this is returned, with the
/// caller-supplied ACL applied as an explicit, observable precondition.
#[cfg(feature = "transport-harness")]
#[derive(Debug)]
pub struct MockCandidateInboxStatus {
    pub queue_count: u64,
    pub message_count: u64,
    pub live_delivery: bool,
}

#[cfg(feature = "transport-harness")]
pub struct MockCandidateMediator {
    mediator: affinidi_messaging_test_mediator::TestMediatorHandle,
}

#[cfg(feature = "transport-harness")]
impl MockCandidateMediator {
    pub fn did(&self) -> &str {
        self.mediator.did()
    }

    pub async fn acl_for(&self, did: &str) -> affinidi_messaging_test_mediator::MediatorACLSet {
        self.mediator
            .get_acl(did)
            .await
            .expect("read candidate mediator ACL")
            .expect("candidate mediator account exists")
    }

    pub async fn inbox_status(&self, did: &str) -> MockCandidateInboxStatus {
        use sha2::{Digest, Sha256};

        let did_hash = hex::encode(Sha256::digest(did.as_bytes()));
        let status = self
            .mediator
            .store()
            .inbox_status(&did_hash)
            .await
            .expect("read candidate mediator inbox status");
        MockCandidateInboxStatus {
            queue_count: status.queue_count,
            message_count: status.message_count,
            live_delivery: status.live_delivery,
        }
    }

    pub async fn shutdown(self) {
        self.mediator.shutdown();
        self.mediator
            .join()
            .await
            .expect("candidate mediator joins cleanly");
    }
}

impl MockVta {
    /// Start a mock VTA on a random loopback port and return once it is bound
    /// and serving. Uses the cheap sentinel-DID app ([`build_test_app`]); the
    /// VTA DID is not resolvable. For an e2e that drives a full
    /// `provision_integration`, use [`start_provisionable`](Self::start_provisionable).
    pub async fn start() -> MockVta {
        Self::serve(build_test_app().await).await
    }

    /// Like [`start`](Self::start) but with a real, self-resolving `did:key`
    /// VTA identity and the signing keys `provision_integration` needs
    /// ([`build_provisionable_test_app`]).
    ///
    /// This is the seam for the full OpenVTC bootstrap→join e2e: the VTA DID
    /// isn't resolvable *back to the loopback URL*, but it doesn't need to be —
    /// drive provisioning **URL-direct** by passing [`base_url`](Self::base_url)
    /// and [`vta_did`](Self::vta_did) to
    /// `vta_sdk::provision_client::provision_admin_rotated_via_rest` (or the
    /// `FullSetup` `provision_via_rest`), which never re-resolves the DID. The
    /// VTA's own `did:key` is self-resolving, so VC issuance and bundle sealing
    /// succeed server-side.
    pub async fn start_provisionable() -> MockVta {
        Self::serve(build_provisionable_test_app().await).await
    }

    /// The webvh hosting server id registered by
    /// [`start_with_webvh_host`](Self::start_with_webvh_host).
    pub const WEBVH_SERVER_ID: &'static str = "stub-webvh";

    /// Like [`start_provisionable`](Self::start_provisionable), but additionally
    /// stands up an in-process [`StubWebvhHost`] and registers a **resolvable**
    /// `did:webvh` hosting server pointing at it — so a server-managed
    /// `create_did_webvh` round-trips against the mock.
    ///
    /// Wiring: the stub host binds a loopback port; a `did:webvh:<scid>:<domain>`
    /// server DID is seeded into the resolver cache with a `WebVHHosting` service
    /// at the host's URL (resolution is in-process, no network); the server is
    /// registered under [`WEBVH_SERVER_ID`](Self::WEBVH_SERVER_ID). Drive a mint
    /// with `create_did_webvh { server_id: Some(MockVta::WEBVH_SERVER_ID), .. }`.
    pub async fn start_with_webvh_host() -> MockVta {
        let host = StubWebvhHost::start().await;
        let server_did = STUB_WEBVH_SERVER_DID.to_string();
        let server_doc = StubWebvhHost::server_did_document(host.base_url());

        let opts = TestAppOptions {
            provisionable_vta: true,
            preseed_did_docs: vec![(server_did.clone(), server_doc)],
            webvh_servers: vec![(Self::WEBVH_SERVER_ID.to_string(), server_did)],
            atm: None,
            vta_transport: None,
            operation_rate_limit_per_sec: None,
            operation_rate_limit_per_subject_per_sec: None,
            operation_budget_clock: None,
            data_dir: None,
        };
        let mut mock = Self::serve(build_test_app_with(opts).await).await;
        mock.webvh_host = Some(host);
        mock
    }

    /// Like [`start_provisionable`](Self::start_provisionable), but reachable
    /// over **DIDComm and TSP** as well as REST.
    ///
    /// Stands up an embedded mediator, gives the VTA a `did:peer:2` that
    /// advertises `DIDCommMessaging` *and* `TSPTransport` at it, and runs the
    /// **production** inbound loop
    /// ([`run_inbound_loop`](vta_service::messaging::service::run_inbound_loop)) — so
    /// a Trust Task arriving on either transport reaches the same
    /// `dispatch_trust_task_core` spine the REST route uses. One websocket
    /// carries both protocols (ADR 0005), which is why this is one constructor
    /// rather than two.
    ///
    /// # Why `did:peer:2`
    ///
    /// The transport a client picks comes from the VTA's DID *document*, and a
    /// `did:key` (what [`start_provisionable`](Self::start_provisionable) uses)
    /// cannot carry a service block — so against that mock a client can only
    /// ever choose REST. A `did:peer:2` encodes its services in the identifier,
    /// so it resolves offline through the cache-sdk's built-in `PeerResolver`
    /// **in the consumer's own resolver**, with nothing seeded and no
    /// resolver-injection seam. That last part is the whole trick: seeding this
    /// mock's resolver would not help a caller in another process, which is the
    /// trap VTI #813 already hit.
    ///
    /// # The size budget
    ///
    /// A `did:peer:2` carries its services in the identifier, and every
    /// resolver refuses one over 1000 bytes. Embedding the mediator's own
    /// 540-byte DID in *both* services blows that (1685) and makes the VTA
    /// unresolvable everywhere, in ways that surface as a websocket timeout on
    /// one side and a `403` on the other. So only the DIDComm service embeds
    /// the mediator DID; `#tsp` points at the mediator's URL. See the
    /// `MAX_DID_BYTES` assertion in the body — it is the guard that keeps a
    /// future service addition from re-breaking this silently.
    ///
    /// ```no_run
    /// # async fn demo() {
    /// use vta_test_support::MockVta;
    /// let mock = MockVta::start_with_transports().await;
    /// // Drive discovery + provisioning the way the real bootstrap does —
    /// // `mock.vta_did()` resolves offline to the advertised transports.
    /// mock.shutdown().await;
    /// # }
    /// ```
    #[cfg(feature = "transport-harness")]
    pub async fn start_with_transports() -> MockVta {
        Self::start_with_transports_using(|b| b).await
    }

    /// [`start_with_transports`](Self::start_with_transports), with the
    /// embedded mediator's builder passed through `customize` first — for a
    /// test that needs the mediator configured as a deployment configures it
    /// (its `global_acl_default`, say) rather than as the fixture defaults it.
    #[cfg(feature = "transport-harness")]
    pub async fn start_with_transports_using(
        customize: impl FnOnce(
            affinidi_messaging_test_mediator::TestMediatorBuilder,
        ) -> affinidi_messaging_test_mediator::TestMediatorBuilder,
    ) -> MockVta {
        use affinidi_messaging_test_mediator::TestMediator;
        use affinidi_tdk::dids::{
            OneOrMany, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
        };

        affinidi_messaging_test_mediator::install_default_crypto_provider();

        // The mediator first: the VTA's DID embeds the mediator DID in its
        // service blocks, so it cannot be minted until the mediator has one.
        // `register_local_did` closes the resulting cycle — the VTA is
        // registered after it exists, rather than at builder time.
        // `builder()` rather than `spawn()` for one reason: a TSP §7.2.2
        // relationship invite is a **direct** control message, and the
        // fixture default for `local_direct_delivery_allowed` is `false`. A
        // client that cannot send an invite cannot form the relationship the
        // VTA now requires before it will admit any application message — and
        // §7.2.2 says *drop*, so the symptom is a harness that times out with
        // nothing explaining it.
        let mediator = customize(
            TestMediator::builder()
                .local_direct_delivery(true, false)
                .enable_forwarding(true)
                .enable_external_forwarding(true)
                .enable_inter_mediator_relay(true),
        )
        .spawn()
        .await
        .expect("spawn test mediator");
        let mediator_did = mediator.did().to_string();

        // The `accept` list is deliberately empty — see MAX_DID_BYTES below. It
        // costs 32 bytes of a budget that has 20 to spare, and DIDComm v2 is
        // the only thing either side speaks here anyway.
        let didcomm = vta_service::operations::did_peer::mediator_did_didcomm_service(
            &mediator_did,
            vec![],
            vec![],
        );
        // The TSP counterpart, pointing at the mediator's **URL** rather than
        // its DID. That is the one deviation from the workspace convention
        // (`#tsp`'s serviceEndpoint is the mediator's DID), and it is forced by
        // arithmetic, not preference: the mediator's own DID is 540 bytes, and
        // embedding it twice puts the VTA's `did:peer` at 1685 — past the
        // resolver limit below, unresolvable by anyone. Under that limit a
        // two-service peer can embed a mediator DID at most *once*. The short
        // URL form is what this mediator advertises for its own `#tsp` service,
        // so it is at least a convention already live in the ecosystem.
        //
        // Accepted deliberately, and scoped: this is a test harness, where the
        // point is exercising the dispatch spine over both transports, not
        // modelling how a production VTA advertises itself. A production VTA is
        // a `did:webvh` — services live in the document, there is no size
        // ceiling, and the mediator-DID convention holds there unchanged. Do
        // not read this as licence to emit a URL `#tsp` outside of tests.
        let tsp = PeerService {
            type_: "TSPTransport".into(),
            endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
                uri: mediator.endpoint().to_string(),
                accept: vec![],
                routing_keys: vec![],
            })),
            id: None,
        };
        let (vta_did, secrets) = vta_service::operations::did_peer::mint_did_peer_with_services(
            didcomm.into_iter().chain(std::iter::once(tsp)).collect(),
        )
        .expect("mint VTA did:peer");

        // Every `DIDCacheClient` refuses to resolve a DID longer than
        // `max_did_size_in_bytes` (default 1000) — a guard applied *before* any
        // parsing, in `resolve_document`. It bites in two places here, and in
        // neither does it say so:
        //
        //   * our own auth against the mediator fails the whole websocket
        //     connect as a 30s `WebSocket isActive? command timed out`;
        //   * the mediator, resolving us to get our sender key, answers the
        //     challenge response `403 Forbidden` and logs `authcrypt requires
        //     sender public key for decryption`.
        //
        // Raising the limit locally is not a fix: the mediator's resolver is
        // built inside `affinidi-messaging-test-mediator`, which exposes no
        // knob for it, and a *consumer* in another process gets a stock
        // resolver — the offline-resolvability this whole harness exists to
        // provide. So the DID has to fit the stock limit. Assert it up front,
        // where the number is legible, rather than 30 seconds later as a
        // timeout.
        const MAX_DID_BYTES: usize = 1_000;
        assert!(
            vta_did.len() < MAX_DID_BYTES,
            "the VTA's did:peer is {} bytes, over the {MAX_DID_BYTES}-byte stock resolver limit \
             ({}-byte mediator DID). Nothing with a default resolver — this process, the \
             mediator, or a consumer — can resolve it. Shed service metadata, or embed the \
             mediator DID in fewer services.",
            vta_did.len(),
            mediator_did.len(),
        );

        mediator
            .register_local_did(&vta_did)
            .await
            .expect("register the VTA as a local mediator account");
        // The account's *default* ACL is enough to connect and go live —
        // verified by removing the `set_acl(ALLOW_ALL)` that used to sit here
        // and watching this test stay green. That grant was added while the
        // failure was misread as a permission problem; the real cause was the
        // DID size asserted above. `add_user` bundles register + ACL, but mints
        // its own DID; ours has to be minted first because it embeds the
        // mediator's DID.

        let (router, ctx) = build_test_app_with(TestAppOptions {
            provisionable_vta: true,
            vta_transport: Some(VtaTransportIdentity {
                did: vta_did.clone(),
                secrets: secrets.clone(),
                mediator_did: mediator_did.clone(),
            }),
            ..Default::default()
        })
        .await;

        // The listener's own ATM + websocket — separate from `AppState.atm`,
        // which has none (one socket per DID).
        let messaging = Arc::new(
            vta_service::messaging::service::build_messaging(
                secrets,
                &vta_did,
                &mediator_did,
                ctx.outbox_ks.clone(),
                ctx.state.trust_task_pushes_ks.clone(),
                ctx.relationships_ks.clone(),
                std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                ctx.state.did_resolver.as_ref(),
                None,
            )
            .await
            .expect("build VTA messaging over the test mediator"),
        );
        let atm = messaging.atm.clone();
        let messaging_profile = messaging.profile.clone();

        // Publish the wiring, exactly as `server::MessagingConnect::connect_once`
        // does. Without this the harness was receive-only: the inbound loop ran,
        // so a reply sealed on `messaging.profile` went out fine, while anything
        // the VTA wanted to *initiate* found no profile published and either
        // dropped TSP from transport selection or reached for a profile that
        // could not send. A harness that only ever answers cannot show that a
        // half-wired outbound path is broken — which is how it stayed broken.
        ctx.state.didcomm_bridge.set_messaging(
            messaging.service.clone(),
            (*messaging.atm).clone(),
            messaging.profile.clone(),
            vta_did.clone(),
        );

        let shutdown = tokio_util::sync::CancellationToken::new();
        let loop_handle = tokio::spawn({
            let (messaging, state, vta_did, shutdown) = (
                Arc::clone(&messaging),
                ctx.state.clone(),
                vta_did.clone(),
                shutdown.clone(),
            );
            async move {
                vta_service::messaging::service::run_inbound_loop(
                    messaging,
                    state,
                    vta_did,
                    shutdown,
                    Arc::new(vti_common::inbox::ReconnectGovernor::new(
                        vti_common::inbox::Escalation::EndSession,
                    )),
                )
                .await;
            }
        });

        let mut mock = Self::serve((router, ctx)).await;
        mock.transports = Some(MockVtaTransports {
            mediator,
            mediator_did,
            shutdown,
            loop_handle: Some(loop_handle),
            messaging,
            atm,
            profile: messaging_profile,
            watch_addresses: None,
        });
        mock
    }

    /// Give the VTA the `[messaging]` section a deployed VTA on this mediator
    /// has: what a room watch mints its address at, and the route a push to a
    /// `did:key` client takes. Not done by
    /// [`start_with_transports`](Self::start_with_transports) itself, because
    /// with it every push to a `did:key` finds a route, which tests written
    /// against the mock without one do not expect.
    #[cfg(feature = "transport-harness")]
    pub async fn configure_messaging(&self) {
        let t = self
            .transports
            .as_ref()
            .expect("configure_messaging() requires start_with_transports()");
        self.ctx.state.config.write().await.messaging = Some(vti_common::config::MessagingConfig {
            mediator_url: t.mediator.endpoint().to_string(),
            mediator_did: t.mediator_did.clone(),
            mediator_host: None,
            setup_acl: false,
            drain_inbox_on_start: false,
        });
    }

    /// Start the room watches' address supervisor, as `server.rs` does at boot:
    /// one mediator connection per watch's address. Separate from
    /// [`configure_messaging`](Self::configure_messaging) so a test can arm a
    /// watch, let its host signal, and only then open the address's connection.
    #[cfg(feature = "transport-harness")]
    pub fn start_watch_addresses(&mut self) {
        let state = self.ctx.state.clone();
        let t = self
            .transports
            .as_mut()
            .expect("start_watch_addresses() requires start_with_transports()");
        assert!(
            t.watch_addresses.is_none(),
            "the address supervisor is already running"
        );
        t.watch_addresses = Some(tokio::spawn(vta_service::messaging::watch_addresses::run(
            state,
            t.shutdown.clone(),
        )));
    }

    /// How many messages the embedded mediator holds for `did`, waiting for it
    /// to collect them.
    #[cfg(feature = "transport-harness")]
    pub async fn mediator_inbox_count(&self, did: &str) -> u64 {
        use sha2::{Digest, Sha256};

        let t = self
            .transports
            .as_ref()
            .expect("mediator_inbox_count() requires start_with_transports()");
        t.mediator
            .store()
            .inbox_status(&hex::encode(Sha256::digest(did.as_bytes())))
            .await
            .map(|s| s.message_count)
            .unwrap_or(0)
    }

    /// Test seam: make the VTA **forget** its TSP relationship with `peer_did`,
    /// resetting its local half to `None` as if the relationship had been
    /// idle-evicted or lost to a redeploy. The peer still believes it is
    /// related, so its next Trust Task is dropped at the VTA's §7.2.2 gate with
    /// no reply — which is exactly the D4 "self-repair on drop" scenario. Pairs
    /// with `VtaClient`'s reply-timeout self-repair.
    #[cfg(feature = "transport-harness")]
    pub async fn forget_tsp_relationship(&self, peer_did: &str) {
        let t = self
            .transports
            .as_ref()
            .expect("forget_tsp_relationship() requires start_with_transports()");
        t.atm
            .tsp()
            .reset_relationship(&t.profile, peer_did)
            .await
            .expect("reset the VTA-side TSP relationship");
    }

    /// The embedded mediator's DID — both advertised services route through it.
    /// Only present for [`start_with_transports`](Self::start_with_transports).
    #[cfg(feature = "transport-harness")]
    pub fn mediator_did(&self) -> &str {
        &self
            .transports
            .as_ref()
            .expect("mediator_did() requires start_with_transports()")
            .mediator_did
    }

    /// Spawn a candidate mediator and register this VTA as a local account with
    /// the supplied ACL. This models the target of a live update handshake.
    #[cfg(feature = "transport-harness")]
    pub async fn spawn_candidate_mediator(
        &self,
        initial_acl: affinidi_messaging_test_mediator::MediatorACLSet,
    ) -> MockCandidateMediator {
        let mediator = affinidi_messaging_test_mediator::TestMediator::builder()
            .global_acl_default(initial_acl.clone())
            .local_did(self.vta_did().to_string())
            .enable_forwarding(true)
            .enable_external_forwarding(true)
            .enable_inter_mediator_relay(true)
            .spawn()
            .await
            .expect("spawn candidate mediator");
        mediator
            .set_acl(self.vta_did(), initial_acl)
            .await
            .expect("apply candidate mediator ACL");
        MockCandidateMediator { mediator }
    }

    /// Live connection state of a dynamically-added candidate transport.
    #[cfg(feature = "transport-harness")]
    pub fn candidate_transport_state(
        &self,
        mediator_did: &str,
    ) -> Option<affinidi_messaging_core::ConnState> {
        self.transports
            .as_ref()
            .expect("candidate_transport_state() requires start_with_transports()")
            .messaging
            .service
            .transport_state(mediator_did)
    }

    /// Run the production live mediator prover against a candidate mediator.
    /// The mock must have been started with transports so its bridge owns the
    /// running messaging service and ATM that an update operation would use.
    #[cfg(feature = "transport-harness")]
    pub async fn prove_candidate_mediator(
        &self,
        mediator_did: &str,
        setup_acl: bool,
    ) -> Result<(), vta_service::messaging::handshake::ProverFailure> {
        use vta_service::messaging::handshake::{ListenerProver, ResolvedMediator};

        let prover = vta_service::messaging::live_prover::DIDCommServiceProver::new(
            Arc::clone(&self.ctx.state.didcomm_bridge),
            self.vta_did(),
        );
        prover
            .prove(
                &ResolvedMediator {
                    mediator_did: mediator_did.to_string(),
                    endpoint: String::new(),
                },
                self.vta_did(),
                std::time::Duration::from_secs(10),
                setup_acl,
                "test",
            )
            .await
    }

    /// Register `did` as a local account on the embedded mediator, so the
    /// mediator will hold frames for it and let it open a socket.
    ///
    /// A counterparty needs this *and* an ACL grant, and they are different
    /// permissions in different places: the mediator decides whether a DID may
    /// connect and be routed to, the VTA decides what it may ask for. Without
    /// the account the VTA's reply is accepted by the mediator and then dropped,
    /// which looks exactly like the VTA not answering.
    #[cfg(feature = "transport-harness")]
    pub async fn register_mediator_account(&self, did: &str) {
        self.transports
            .as_ref()
            .expect("register_mediator_account() requires start_with_transports()")
            .mediator
            .register_local_did(did)
            .await
            .expect("register a local mediator account");
    }

    /// Bind an ephemeral loopback port, serve `router` in a background task,
    /// and return once bound. Shared by [`start`](Self::start) /
    /// [`start_provisionable`](Self::start_provisionable).
    async fn serve((router, ctx): (axum::Router, TestAppContext)) -> MockVta {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral loopback port");
        let addr = listener.local_addr().expect("resolve local addr");
        let base_url = format!("http://{addr}");

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            // `ConnectInfo<SocketAddr>` is required — the unauth routes carry the
            // per-source-IP rate limiter, same as production.
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await;
        });

        MockVta {
            base_url,
            ctx,
            shutdown: Some(tx),
            handle: Some(handle),
            webvh_host: None,
            #[cfg(feature = "transport-harness")]
            transports: None,
        }
    }

    /// The base URL to point a client at (e.g. `http://127.0.0.1:54321`).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The VTA DID this mock is configured with — pass alongside
    /// [`base_url`](Self::base_url) to a URL-direct provision entry point.
    pub fn vta_did(&self) -> &str {
        &self.ctx.vta_did
    }

    /// A `VtaClient` that can produce documents this VTA accepts.
    ///
    /// `mint_token` alone stopped being enough once the spine enforced SPEC
    /// §7.2: every dispatched spec declares `recipient` REQUIRED (item 5b) and
    /// 72 of the 109 declare `proof` REQUIRED (item 7a), so a client needs the
    /// key behind the DID its token names. `seed` selects the identity, so a
    /// test wanting two callers asks for two seeds rather than two unrelated
    /// DID strings.
    pub async fn signing_client(
        &self,
        seed: u8,
        role: &str,
        contexts: Vec<String>,
    ) -> vta_sdk::client::VtaClient {
        let vta_did = self.vta_did().to_string();
        let (identity, token) = self
            .ctx
            .mint_signing_identity(seed, role, contexts, &vta_did)
            .await;
        let client = vta_sdk::client::VtaClient::new(self.base_url()).with_identity(identity);
        client.set_token_async(token).await;
        client
    }

    /// Fail the stub host's next `n` publishes with a 500 — simulate a
    /// transient outage so a test can assert the VTA recovers on retry.
    /// Only meaningful for a mock started via [`start_with_webvh_host`](MockVta::start_with_webvh_host).
    pub fn fail_next_publishes(&self, n: usize) {
        if let Some(host) = &self.webvh_host {
            host.fail_next_publishes(n);
        }
    }

    /// How many DID deletions the stub host has accepted — `0` for a mock
    /// without one. Only meaningful for a mock started via
    /// [`start_with_webvh_host`](Self::start_with_webvh_host).
    pub fn webvh_host_deletes(&self) -> usize {
        self.webvh_host.as_ref().map_or(0, StubWebvhHost::deletes)
    }

    /// Make the stub host sign every later reply with a key that is not its
    /// own. A no-op for a mock without one.
    pub fn forge_webvh_host_replies(&self) {
        if let Some(host) = &self.webvh_host {
            host.forge_replies();
        }
    }

    /// Test-only corruption: move a version's key handles to the `superseded:`
    /// prefix, reproducing the state a pre-#730 failed-publish loop left — the
    /// key the host's current entry still requires is no longer in the *active*
    /// prefix the resolver searches. Proves the seed-re-derivation recovery
    /// heals a DID the handle cache alone cannot.
    pub async fn corrupt_supersede_keys(&self, scid: &str, version_id: &str) {
        vta_service::test_support::supersede_webvh_keys_for_version(
            &self.ctx.keys_ks,
            scid,
            version_id,
        )
        .await
        .expect("supersede keys for test corruption");
    }

    /// Seed a webvh hosting server so a DID-mint / join flow finds a server in
    /// the catalogue. Thin wrapper over [`seed_webvh_server`] against this
    /// mock's keyspace.
    pub async fn seed_webvh_server(&self, id: &str, server_did: &str) {
        seed_webvh_server(&self.ctx.webvh_ks, id, server_did).await;
    }

    /// Authorize `did` in the ACL with `role` + `contexts` so a URL-direct
    /// provision / authenticated call against this mock is accepted (rather than
    /// 403ing at the challenge gate). An empty `contexts` vec is super-admin.
    /// Thin wrapper over [`seed_acl_entry`] against this mock's ACL keyspace;
    /// counterpart to [`seed_webvh_server`](Self::seed_webvh_server).
    pub async fn authorize_did(
        &self,
        did: &str,
        role: vta_service::acl::Role,
        contexts: Vec<String>,
    ) {
        seed_acl_entry(&self.ctx.acl_ks, did, role, contexts).await;
    }

    /// Convenience: authorize `did` as a super-admin (admin role, no context
    /// scope) — the common case for driving a URL-direct provision. Shorthand
    /// for [`authorize_did`](Self::authorize_did)`(did, Role::Admin, vec![])`.
    pub async fn grant_super_admin(&self, did: &str) {
        self.authorize_did(did, vta_service::acl::Role::Admin, Vec::new())
            .await;
    }

    /// Stop the server and wait for it to wind down gracefully.
    ///
    /// For a `start_with_transports` mock this
    /// also stops the inbound loop, the listener's mediator websocket, and the
    /// mediator — **in that order, and not optionally**. Dropping an `ATM`
    /// abandons its websocket task rather than ending it, and an abandoned
    /// socket keeps auto-reconnecting for the rest of the test binary, with
    /// every test adding another (vta-sdk #830).
    pub async fn shutdown(mut self) {
        #[cfg(feature = "transport-harness")]
        if let Some(mut transports) = self.transports.take() {
            transports.shutdown.cancel();
            if let Some(handle) = transports.loop_handle.take() {
                let _ = handle.await;
            }
            if let Some(handle) = transports.watch_addresses.take() {
                let _ = handle.await;
            }
            transports.atm.graceful_shutdown().await;
            transports.mediator.shutdown();
        }
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for MockVta {
    fn drop(&mut self) {
        // Signal graceful shutdown; abort as a backstop if the task is still up.
        #[cfg(feature = "transport-harness")]
        if let Some(mut transports) = self.transports.take() {
            // Best-effort only: `Drop` cannot await, so the ATM's websocket
            // cannot be stopped politely here. Cancelling ends the inbound loop
            // and shutting the mediator down makes the abandoned socket's
            // reconnects fail fast instead of looping against a live mediator.
            // Prefer `shutdown().await`, which does stop it properly.
            transports.shutdown.cancel();
            if let Some(handle) = transports.loop_handle.take() {
                handle.abort();
            }
            if let Some(handle) = transports.watch_addresses.take() {
                handle.abort();
            }
            transports.mediator.shutdown();
        }
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

#[cfg(all(test, feature = "transport-harness"))]
mod transport_harness_tests {
    use super::*;
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

    fn closed_for_forwarded() -> affinidi_messaging_test_mediator::MediatorACLSet {
        let mut acls = affinidi_messaging_test_mediator::acl::allow_all();
        acls.set_receive_forwarded(false, true, true)
            .expect("admin=true may always set this bit");
        acls
    }

    #[tokio::test]
    async fn live_prover_provisions_acl_and_completes_cross_mediator_trust_ping() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "vta_service::messaging=debug".into()),
            )
            .with_test_writer()
            .try_init();
        affinidi_messaging_test_mediator::install_default_crypto_provider();

        let mock = MockVta::start_with_transports().await;
        let candidate = mock.spawn_candidate_mediator(closed_for_forwarded()).await;

        let before = candidate.acl_for(mock.vta_did()).await;
        assert!(
            !before.get_receive_forwarded().0,
            "fixture must start closed so the test can observe ACL provisioning"
        );

        let candidate_did = candidate.did().to_string();
        // Judged after the proof, not by sampling the transport during it. The
        // prover leaves the candidate transport installed on success and has
        // just trust-pinged through it, so "installed and connected" is read
        // once, deterministically. Sampling every 20 ms used to fail a proof
        // that connected and finished inside one interval ("proof finished
        // before candidate connected: Ok(())").
        let proof = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            mock.prove_candidate_mediator(&candidate_did, true),
        )
        .await
        .expect("the candidate proof completes");
        let transport_state = mock.candidate_transport_state(&candidate_did);
        let inbox_status = candidate.inbox_status(mock.vta_did()).await;

        let after = candidate.acl_for(mock.vta_did()).await;
        assert!(after.get_receive_forwarded().0);
        assert!(after.get_receive_messages().0);

        mock.shutdown().await;
        candidate.shutdown().await;
        proof.unwrap_or_else(|error| {
            panic!(
                "ACL setup succeeded but candidate proof failed: {error:?}; \
                 transport_state={transport_state:?}; inbox_status={inbox_status:?}"
            )
        });
        assert_eq!(
            transport_state,
            Some(affinidi_messaging_core::ConnState::Connected),
            "a successful proof leaves the candidate transport installed and connected; \
             inbox_status={inbox_status:?}"
        );
    }

    /// The point of the whole harness: the mock's DID must advertise both
    /// transports **to a resolver it has never touched**.
    ///
    /// Deliberately resolves through a *fresh* `DIDCacheClient` rather than the
    /// app's own. A `did:peer:2` is self-describing, so the built-in
    /// `PeerResolver` decodes it offline anywhere — which is exactly what lets a
    /// consumer in another process (OpenVTC's bootstrap) discover these
    /// transports with nothing seeded. Seeding the *app's* resolver would prove
    /// nothing about that, and is the trap VTI #813 documented.
    ///
    /// Asserted on the raw document rather than `vta_sdk::provision_client`'s
    /// `resolve_vta` so a failure says whether the *encoding* broke or the
    /// SDK's matcher did.
    /// Encoding only: mint the two-service did:peer and resolve it, with no
    /// mediator, no app, and no websocket in the picture. Separates "the
    /// identifier encodes both services" from "a listener can connect as it",
    /// so a failure in the harness test above is attributable.
    #[tokio::test]
    async fn a_two_service_did_peer_encodes_both_transports() {
        use affinidi_tdk::dids::{
            OneOrMany, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
        };

        let mediator = "did:peer:2.Ez6LSmediator";
        let didcomm = vta_service::operations::did_peer::mediator_did_didcomm_service(
            mediator,
            vec!["didcomm/v2".to_string()],
            vec![],
        );
        let tsp = PeerService {
            type_: "TSPTransport".into(),
            endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
                uri: mediator.to_string(),
                accept: vec![],
                routing_keys: vec![],
            })),
            id: None,
        };
        let (did, _secrets) = vta_service::operations::did_peer::mint_did_peer_with_services(
            didcomm.into_iter().chain(std::iter::once(tsp)).collect(),
        )
        .expect("mint two-service did:peer");

        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("local DID cache");
        let resolved = resolver.resolve(&did).await.expect("did:peer resolves");
        let types: Vec<String> = resolved
            .doc
            .service
            .iter()
            .map(|s| s.type_.clone().into_iter().collect::<Vec<_>>().join(","))
            .collect();
        let ids: Vec<String> = resolved
            .doc
            .service
            .iter()
            .map(|s| format!("{:?}", s.id))
            .collect();
        println!("service types: {types:?}");
        println!("service ids:   {ids:?}");
        assert!(
            types.iter().any(|t| t.contains("DIDCommMessaging")),
            "types {types:?}"
        );
        assert!(
            types.iter().any(|t| t.contains("TSPTransport")),
            "types {types:?}"
        );
    }

    #[tokio::test]
    async fn the_mock_advertises_both_transports_to_a_foreign_resolver() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let mock = MockVta::start_with_transports().await;

        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("local DID cache");
        let resolved = resolver
            .resolve(mock.vta_did())
            .await
            .expect("a did:peer resolves offline in any resolver");

        let types: Vec<String> = resolved
            .doc
            .service
            .iter()
            .map(|s| s.type_.clone().into_iter().collect::<Vec<_>>().join(","))
            .collect();
        assert!(
            types.iter().any(|t| t.contains("DIDCommMessaging")),
            "expected a DIDCommMessaging service, got {types:?}"
        );
        assert!(
            types.iter().any(|t| t.contains("TSPTransport")),
            "expected a TSPTransport service, got {types:?}"
        );

        mock.shutdown().await;
    }

    /// A VTA that can answer over TSP must also be able to **start** a TSP
    /// exchange — and it could not.
    ///
    /// `pnm did-mgmt dids create` against a did-host advertising `#tsp` failed
    /// instantly with `bad gateway: ... could not be reached over TSP: Config
    /// error: No Mediator is configured for this Profile`. The seam selected
    /// TSP correctly; the profile it sealed on was the one `init_auth` built
    /// with no mediator, and `ATMProfile::dids()` — which `TspOps::pack` and
    /// `unpack_bytes` both call, and `send_raw` calls alongside
    /// `get_mediator_rest_endpoint()` — has no answer without one. So the send
    /// died inside the SDK before any I/O, while inbound replies kept working,
    /// because `messaging::service::handle_tsp` seals on the *other* profile:
    /// the mediator-registered one.
    ///
    /// The assertion is a real routed send over the embedded mediator rather
    /// than an inspection of the profile. The defect was never visible in the
    /// profile's type, only in what the SDK refused to do with it.
    #[tokio::test]
    async fn the_vta_can_initiate_a_tsp_send_not_only_answer_one() {
        let mock = MockVta::start_with_transports().await;

        let transport = mock
            .ctx
            .state
            .tsp_transport()
            .expect("a mediator-connected VTA has a TSP transport to send on");

        // The route is the transport's to build, and it builds it from the
        // profile that seals — so this also pins that the mediator it routes
        // through is the one the session actually registered against.
        assert_eq!(
            transport.mediator_did(),
            mock.mediator_did(),
            "the transport must route through this session's own mediator"
        );

        // Addressed back to the VTA itself: the point is that the frame seals
        // and the mediator accepts it, which is exactly the step that failed.
        // Who reads it afterwards is a different test's concern.
        let body = vta_sdk::tsp_binding::wrap_envelope(br#"{"probe":true}"#);

        let sent = transport.send_to(mock.vta_did(), &body).await;
        assert!(
            sent.is_ok(),
            "the VTA could not put a TSP frame on the wire: {:?}",
            sent.err()
        );

        mock.shutdown().await;
    }

    /// A routable-but-silent peer: a `did:key` with a mediator account (so a send
    /// seals and is accepted for delivery) whose inbox nobody reads, so a Trust
    /// Task sent to it never gets a reply — the §7.2.2 silent-drop shape a D6
    /// recovery is meant to detect.
    fn orphan_did(seed: u8) -> String {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&pk)
        )
    }

    /// A deterministic `did:key` **and its private multibase** from a seed byte.
    /// `orphan_did` needs only the public half; a peer that has to *sign* its
    /// replies needs the private key too. Same encoding as every TSP binary in
    /// `tests/e2e` (`did_key_from_seed`): multicodec `0xed01` for the public DID,
    /// `0x8026` for the Ed25519 private multibase.
    fn did_key_from_seed(seed: u8) -> (String, String) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&pk)
        );
        let mut priv_bytes = vec![0x80, 0x26];
        priv_bytes.extend_from_slice(&[seed; 32]);
        let priv_mb = multibase::encode(multibase::Base::Base58Btc, &priv_bytes);
        (did, priv_mb)
    }

    /// A TSP peer that **answers** — the inverse of [`orphan_did`].
    ///
    /// Where the orphan proves a silent peer drives the D6 recovery to a
    /// give-up, this proves an answering peer drives it to a *recovered reply*:
    /// the VTA sends, this peer replies threaded to the request, and
    /// `recover_send_tsp` correlates that reply through `pending_replies`.
    ///
    /// Two setup steps are load-bearing:
    ///
    /// - **It holds an ACL grant, not only a mediator account.** That was once
    ///   the difference between a correlated reply and a `permissionDenied`
    ///   envelope: `auth_for_trust_task_envelope` ran *before* the reply reached
    ///   `pending_replies.complete`, so an ungranted peer's reply was refused and
    ///   the VTA timed out on an answer it had in fact been sent. The spine now
    ///   classifies an inbound document first and hands a threaded one to its
    ///   waiter before any ACL check (`accept_from_proven_sender`), so the grant
    ///   no longer decides *this* test. It is kept because it still decides a
    ///   reply that arrives after its waiter gave up, which falls through to the
    ///   dispatcher like any other request.
    /// - **It `relate`s the VTA before answering.** `relate` leaves this side
    ///   `Pending`, which admits application messages (§3.6), so the reply may be
    ///   sent; the VTA's own half is re-formed by `send_reestablishing` on the
    ///   recovery path.
    struct AnsweringPeer {
        session: std::sync::Arc<vta_sdk::session::TspSession>,
        loop_handle: tokio::task::JoinHandle<()>,
        did: String,
        /// What the answering loop actually did, for the assertion message.
        ///
        /// Every failure inside that loop used to be discarded — `Err(_) =>
        /// break` on the socket, `let _ = send_document(…)` on the reply — so a
        /// peer that never saw the request and a peer whose reply failed to send
        /// both surfaced as the VTA's "did not answer", which is the one reading
        /// that is certainly wrong. The loop records here instead, and
        /// [`report`](Self::report) puts it in the panic message.
        log: std::sync::Arc<std::sync::Mutex<PeerLog>>,
    }

    /// What the answering peer saw and did — the difference between "the request
    /// never arrived", "the reply could not be sent" and "the reply was sent and
    /// the VTA did not correlate it", which are three different bugs.
    #[derive(Default)]
    struct PeerLog {
        /// Documents pulled off the socket (any kind).
        received: usize,
        /// Replies handed to `send_document` without error.
        sent: usize,
        /// Faults, in order: a send that failed, or the socket ending.
        faults: Vec<String>,
    }

    impl AnsweringPeer {
        async fn spawn(mock: &MockVta, seed: u8) -> Self {
            let (did, priv_mb) = did_key_from_seed(seed);
            // The mediator decides who may connect and be routed to; the VTA
            // decides whose replies it will even look at. Both are required.
            mock.register_mediator_account(&did).await;
            mock.grant_super_admin(&did).await;

            let session =
                vta_sdk::session::TspSession::connect(&did, &priv_mb, mock.mediator_did())
                    .await
                    .expect("the answering peer connects its TSP socket");
            session
                .relate(mock.vta_did())
                .await
                .expect("the peer invites the VTA so its reply is admitted");
            let session = std::sync::Arc::new(session);

            // The answering loop: pump the socket, and for every Trust Task the
            // VTA sends, reply threaded to it. `receive_next` also processes the
            // VTA's relationship control frames — its accept, and the re-invite
            // `send_reestablishing` sends on recovery — so the relationship is
            // reconciled here without a bespoke answering arm.
            let loop_session = session.clone();
            let vta_did = mock.vta_did().to_string();
            let mediator_did = mock.mediator_did().to_string();
            let log = std::sync::Arc::new(std::sync::Mutex::new(PeerLog::default()));
            let loop_log = log.clone();
            // The peer signs its replies: the VTA releases a waiter only to a
            // reply its peer verifiably signed.
            let reply_key = vta_sdk::trust_task_sign::HolderKey::from_did_key(&did, &priv_mb)
                .expect("a did:key names its own verification method");
            let reply_issuer = did.clone();
            let loop_handle = tokio::spawn(async move {
                loop {
                    // Resolve the poll before the reply send below: `receive_next`
                    // yields a `Box<dyn Error>` on the socket-gone arm, which is
                    // not `Send`, and leaving the whole `Result` alive across the
                    // later `send_document().await` would make this spawned future
                    // non-`Send`. Reduce it to the document (or stop) here.
                    let polled = loop_session
                        .receive_next(1)
                        .await
                        .map_err(|e| e.to_string());
                    let doc = match polled {
                        Ok(Some(doc)) => doc,
                        // Idle within the poll slice — keep pumping.
                        Ok(None) => continue,
                        // The socket is gone (the peer was shut down). Stop —
                        // but say so, because from the VTA's side a peer that
                        // stopped pumping is indistinguishable from one that
                        // chose not to answer.
                        Err(e) => {
                            loop_log
                                .lock()
                                .expect("peer log")
                                .faults
                                .push(format!("the peer's socket ended: {e}"));
                            break;
                        }
                    };
                    loop_log.lock().expect("peer log").received += 1;
                    let Ok(request) =
                        serde_json::from_str::<trust_tasks_rs::TrustTask<serde_json::Value>>(&doc)
                    else {
                        loop_log
                            .lock()
                            .expect("peer log")
                            .faults
                            .push(format!("a frame that is not a Trust Task: {doc}"));
                        continue;
                    };
                    // `respond_with` threads the reply on the request's
                    // `threadId`-or-`id` (SPEC §4.9) — the same key the VTA's
                    // `pending_replies` waiter is registered under.
                    let mut reply = request.respond_with(
                        format!("urn:uuid:d6-reply-{}", request.id),
                        serde_json::json!({ "answered": true }),
                    );
                    reply.issuer = Some(reply_issuer.clone());
                    if let Err(e) =
                        vta_sdk::trust_task_sign::sign_in_place_with(&mut reply, &reply_key).await
                    {
                        loop_log
                            .lock()
                            .expect("peer log")
                            .faults
                            .push(format!("the reply could not be signed: {e}"));
                        continue;
                    }
                    if let Ok(bytes) = serde_json::to_vec(&reply) {
                        let sent = loop_session
                            .send_document(&vta_did, &mediator_did, &bytes)
                            .await
                            .map_err(|e| e.to_string());
                        let mut log = loop_log.lock().expect("peer log");
                        match sent {
                            Ok(()) => log.sent += 1,
                            Err(e) => log.faults.push(format!("the reply could not be sent: {e}")),
                        }
                    }
                }
            });

            Self {
                session,
                loop_handle,
                did,
                log,
            }
        }

        fn did(&self) -> &str {
            &self.did
        }

        /// One line saying what the peer saw and did, for an assertion message.
        fn report(&self) -> String {
            let log = self.log.lock().expect("peer log");
            format!(
                "the peer received {} document(s), sent {} reply(ies); faults: {}",
                log.received,
                log.sent,
                if log.faults.is_empty() {
                    "none".to_string()
                } else {
                    log.faults.join("; ")
                }
            )
        }

        /// Stop the answering loop and shut the peer's socket. Not optional: an
        /// abandoned `TspSession` keeps its websocket auto-reconnecting for the
        /// rest of the binary (vta-sdk #830).
        ///
        /// The loop is **aborted**, not signalled: after `shutdown`,
        /// `receive_next` returns `Ok(None)` rather than `Err` (session.rs — a
        /// closed socket is reported as idle-until-shutdown), so a loop that only
        /// breaks on `Err` would spin forever and `loop_handle.await` would never
        /// return. Abort ends it immediately; the following `await` then resolves
        /// at once with a cancelled `JoinError`.
        async fn stop(self) {
            self.loop_handle.abort();
            let _ = self.loop_handle.await;
            self.session.shutdown().await;
        }
    }

    /// D6: a reply-timeout **drives** the coordinator-gated self-repair — the
    /// stale relationship is reset and re-established — even against a peer that
    /// never answers.
    ///
    /// `acl/grant` is `RetrySafe`, so on the timeout the driver resets and
    /// re-establishing-resends; the orphan still never answers, so it settles as
    /// exactly one failed attempt. The point pinned here is that the coordinator
    /// was consulted and the recovery actually ran — the novel D6 behaviour over
    /// the client-side per-call self-repair (#1544). A short reply timeout keeps
    /// the dropped attempt fast.
    #[tokio::test]
    async fn d6_drives_recovery_on_a_reply_timeout() {
        let mock = MockVta::start_with_transports().await;
        let orphan = orphan_did(0x9a);
        mock.register_mediator_account(&orphan).await;

        let tsp =
            vta_service::operations::outbound::TspSender::harness_from_app_state(&mock.ctx.state)
                .expect("a mediator-connected VTA has a TSP transport")
                .with_reply_timeout(std::time::Duration::from_millis(600));

        let framed = vta_sdk::tsp_binding::wrap_envelope(br#"{"probe":true}"#);
        let out = tsp
            .recover_for_test(
                &orphan,
                "thread-d6-1",
                &framed,
                vta_sdk::trust_tasks::TASK_ACL_GRANT_0_3,
            )
            .await;

        assert!(
            out.is_err(),
            "the orphan never answers, so recovery cannot complete: {out:?}"
        );
        assert_eq!(
            tsp.recovery().metrics().attempts,
            1,
            "the coordinator recorded exactly one recovery attempt"
        );

        mock.shutdown().await;
    }

    /// D6 single-flight: two concurrent recoveries for the **same** peer coalesce
    /// onto one attempt — the second gets `InFlight` — so a lost peer is not
    /// invite-stormed. Both senders share the one coordinator on `AppState`.
    #[tokio::test]
    async fn d6_coalesces_concurrent_recoveries() {
        let mock = MockVta::start_with_transports().await;
        let orphan = orphan_did(0x9b);
        mock.register_mediator_account(&orphan).await;

        let mk = || {
            vta_service::operations::outbound::TspSender::harness_from_app_state(&mock.ctx.state)
                .expect("a mediator-connected VTA has a TSP transport")
                .with_reply_timeout(std::time::Duration::from_millis(800))
        };
        let a = mk();
        let b = mk();
        let framed = vta_sdk::tsp_binding::wrap_envelope(br#"{"probe":true}"#);

        let (ra, rb) = tokio::join!(
            a.recover_for_test(
                &orphan,
                "t-a",
                &framed,
                vta_sdk::trust_tasks::TASK_ACL_GRANT_0_3
            ),
            b.recover_for_test(
                &orphan,
                "t-b",
                &framed,
                vta_sdk::trust_tasks::TASK_ACL_GRANT_0_3
            ),
        );

        assert!(
            ra.is_err() && rb.is_err(),
            "neither recovery can complete against a silent peer"
        );
        assert_eq!(
            a.recovery().metrics().attempts,
            1,
            "two concurrent recoveries for one peer coalesce onto a single attempt \
             (single-flight); a second concurrent send gets InFlight"
        );

        mock.shutdown().await;
    }

    /// D6 **success arm**: a reply-timeout recovery that *completes* because the
    /// peer answers — the join `d6_drives_recovery_on_a_reply_timeout` leaves
    /// untested (it uses a silent orphan and asserts the failure).
    ///
    /// The point is the correlation: `recover_send_tsp` resets the stale
    /// relationship, re-establishes-and-resends the (retry-safe) `acl/grant`, and
    /// the answering peer replies threaded to it — so the reply is matched through
    /// `pending_replies` and returned here, and the coordinator records a
    /// *success* rather than a give-up. The two failure tests share this seam but
    /// only ever exercise the timeout; this is the one that proves the reply path.
    #[tokio::test]
    async fn d6_recovers_a_reply_from_an_answering_peer() {
        let mock = MockVta::start_with_transports().await;
        let peer = AnsweringPeer::spawn(&mock, 0x9c).await;

        let tsp =
            vta_service::operations::outbound::TspSender::harness_from_app_state(&mock.ctx.state)
                .expect("a mediator-connected VTA has a TSP transport")
                // Generous relative to the orphan tests: this one must leave time for a
                // real round trip (re-invite → deliver → the peer's reply → the VTA
                // correlating it), not just for a timeout to elapse.
                //
                // The number is a fixture parameter, not the subject. What this test
                // asserts is the *correlation* — that the peer's reply is matched
                // through `pending_replies` and returned — and the timeout only has
                // to be long enough not to fire before that happens. At 5s it was
                // also, in effect, asserting that a loaded CI runner completes a TSP
                // round trip within five seconds, which it does not reliably do: this
                // test flaked on `main` itself (run 35465791169, 19 Sep) and on
                // unrelated PRs, in `Test (workspace)` — the job this repo's CI
                // comments call "the gate that matters".
                //
                // Raising it weakens nothing. A reply that never arrives still fails
                // the assertion below; it just takes longer to say so. The timeout
                // path has its own coverage in `d6_drives_recovery_on_a_reply_timeout`,
                // which uses a silent peer and a deliberately short bound.
                .with_reply_timeout(std::time::Duration::from_secs(30));

        // The request the VTA re-sends on recovery. Its `id` is the thread the
        // reply will name (`reply_thread_of` = `threadId`-or-`id`), so the waiter
        // registered under this same string is the one the peer's reply wakes.
        let thread = "urn:uuid:d6-success-req-1";
        let request = trust_tasks_rs::TrustTask::new(
            thread,
            vta_sdk::trust_tasks::TASK_ACL_GRANT_0_3
                .parse::<trust_tasks_rs::TypeUri>()
                .expect("acl/grant/0.1 is a valid Type URI"),
            serde_json::json!({}),
        );
        let framed = vta_sdk::tsp_binding::wrap_envelope(
            &serde_json::to_vec(&request).expect("serialise the request"),
        );

        let out = tsp
            .recover_for_test(
                peer.did(),
                thread,
                &framed,
                vta_sdk::trust_tasks::TASK_ACL_GRANT_0_3,
            )
            .await;

        assert!(
            out.is_ok(),
            "the answering peer replies, so recovery completes with the reply: {out:?} — {}",
            peer.report()
        );
        let reply = out.expect("recovery returned the correlated reply");
        assert_eq!(
            reply.get("threadId").and_then(|t| t.as_str()),
            Some(thread),
            "the correlated document is the reply the peer threaded to the request"
        );

        let metrics = tsp.recovery().metrics();
        assert_eq!(metrics.attempts, 1, "exactly one recovery attempt ran");
        assert_eq!(
            metrics.successes, 1,
            "and it settled as a success — the relationship recovered and the reply arrived"
        );
        assert_eq!(metrics.give_ups, 0, "a recovered peer is not given up on");

        peer.stop().await;
        mock.shutdown().await;
    }

    /// An idle relationship is re-asserted before the send rather than trusted,
    /// and the reply stamps it active again (`TSP_IDLE_REESTABLISH_MS`, D5).
    ///
    /// The peer here kept its half, which is the case the re-invite must not
    /// break: a peer that still holds the relationship re-accepts (D2) and
    /// answers the request that travelled with the invite. The case the
    /// re-invite exists for — a peer that lost its half — then costs nothing
    /// extra either, because the invite goes first; what would otherwise have
    /// happened there is the silent drop and a full reply window before D6.
    #[tokio::test]
    async fn an_idle_relationship_is_reinvited_with_the_request_and_restamped() {
        use affinidi_messaging_sdk::protocols::tsp::{RelationshipState, RelationshipStore as _};

        let mock = MockVta::start_with_transports().await;
        let peer = AnsweringPeer::spawn(&mock, 0x9d).await;
        let tsp =
            vta_service::operations::outbound::TspSender::harness_from_app_state(&mock.ctx.state)
                .expect("a mediator-connected VTA has a TSP transport")
                // Room for a real round trip, as in the answering-peer D6 test.
                .with_reply_timeout(std::time::Duration::from_secs(30));
        let store = mock.ctx.state.tsp_relationships.clone();
        let our = mock.vta_did().to_string();
        let now_ms = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis() as u64
        };

        // The peer's own invite reaches the VTA asynchronously, and recording
        // it stamps the relationship's activity. Let that land first, or it
        // can overwrite the aged stamp below and the relationship reads as
        // freshly heard from.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while store
            .get(&our, peer.did())
            .await
            .expect("read the relationship")
            == RelationshipState::None
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the VTA never recorded the peer's invite"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // Established, but last heard from two hours ago.
        store
            .set(&our, peer.did(), RelationshipState::Bidirectional)
            .await
            .expect("seed the relationship");
        store
            .touch(&our, peer.did(), now_ms() - 2 * 60 * 60 * 1000)
            .await
            .expect("age the relationship");
        assert!(
            tsp.harness_idle_reestablish_due(peer.did()).await,
            "a relationship idle past the threshold is re-invited"
        );

        let thread = "urn:uuid:idle-reinvite-req-1";
        let request = trust_tasks_rs::TrustTask::new(
            thread,
            vta_sdk::trust_tasks::TASK_ACL_GRANT_0_3
                .parse::<trust_tasks_rs::TypeUri>()
                .expect("acl/grant/0.1 is a valid Type URI"),
            serde_json::json!({}),
        );
        let framed = vta_sdk::tsp_binding::wrap_envelope(
            &serde_json::to_vec(&request).expect("serialise the request"),
        );

        let replied = tsp
            .harness_first_attempt_replied(peer.did(), None, thread, &framed)
            .await;
        assert!(
            replied,
            "a peer that kept its half re-accepts and answers the request sent with \
             the invite — {}",
            peer.report()
        );

        let stamped = store
            .last_active(&our, peer.did())
            .await
            .expect("read the stamp")
            .expect("a reply stamps the relationship");
        assert!(
            now_ms().saturating_sub(stamped) < 60_000,
            "the stamp is the reply's, not the aged one"
        );
        assert!(
            !tsp.harness_idle_reestablish_due(peer.did()).await,
            "a freshly active relationship is trusted on the next send"
        );
        assert_eq!(
            tsp.recovery().metrics().attempts,
            0,
            "a proactive re-invite is not a D6 recovery and is not counted as one"
        );

        peer.stop().await;
        mock.shutdown().await;
    }

    /// Selection follows the **live session**, not the config.
    ///
    /// `TspSender::from_app_state` reads the mediator DID out of the config and
    /// the sealing pair off the bridge. Config alone is not enough: before the
    /// first connect — and between a dropped session and its reconnect — there
    /// is no profile to seal on, and offering TSP then means choosing a
    /// transport this VTA cannot send over instead of falling to the peer's
    /// next-preferred one.
    #[tokio::test]
    async fn tsp_is_not_offered_before_a_mediator_session_exists() {
        // `build_test_app` leaves the bridge a placeholder — the state of a VTA
        // that has not connected yet.
        let (_router, ctx) = build_test_app().await;
        assert!(
            ctx.state.tsp_transport().is_none(),
            "an unconnected VTA must not claim a TSP transport"
        );
        assert!(
            vta_service::operations::outbound::TspSender::harness_from_app_state(&ctx.state)
                .is_none(),
            "TSP must drop out of transport selection until a session can carry it"
        );
    }

    /// Poll a node's mailbox until a TSP frame lands (cross-mediator forwarding is
    /// asynchronous). Mirrors the test-mediator's own `poll_inbox` helper.
    async fn poll_tsp_inbox(
        env: &affinidi_messaging_test_mediator::TestEnvironment,
        profile: &std::sync::Arc<affinidi_messaging_sdk::profiles::ATMProfile>,
    ) -> String {
        use affinidi_messaging_sdk::messages::fetch::FetchOptions;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            let fetched = env
                .atm
                .fetch_messages(profile, &FetchOptions::default())
                .await
                .expect("fetch messages");
            if let Some(msg) = fetched.success.first().and_then(|e| e.msg.as_ref()) {
                return msg.clone();
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        panic!("no TSP message received within the deadline");
    }

    /// Metadata-private cross-mediator routing — the topology-aware increment.
    /// When the peer is on a **different** mediator,
    /// [`TspTransport::send_metadata_private`](vta_service::messaging::tsp_transport::TspTransport::send_metadata_private)
    /// nests the send so the recipient rides inside the sealed envelope rather
    /// than as a visible route hop, and our mediator (the only intermediary
    /// before the peer's) never learns it.
    ///
    /// **Delivery is the proof of nesting.** A plain `send_routed([our_mediator,
    /// recipient])` cannot reach a peer our mediator does not host — the route
    /// carries no hop to the peer's mediator — so a message that *arrives* at a
    /// peer on another mediator can only have travelled the nested
    /// `[our_mediator, peer_mediator]` route. Two in-process relay-enabled
    /// mediators (`TestTopology`) stand in for a real cross-mediator topology.
    #[tokio::test]
    async fn send_metadata_private_reaches_a_cross_mediator_peer() {
        use affinidi_messaging_test_mediator::topology::TestTopology;

        let topology = TestTopology::builder()
            .mediators(2)
            .spawn()
            .await
            .expect("spawn a two-mediator topology");
        let mediator_b = topology
            .mediator_did(1)
            .expect("mediator B DID")
            .to_string();
        let alice = topology
            .add_user(0, "alice")
            .await
            .expect("alice on mediator A");
        let bob = topology
            .add_user(1, "bob")
            .await
            .expect("bob on mediator B");
        // §7.2.2 gates application traffic on an existing relationship; each side's
        // SDK holds its own store, so seed it on every node.
        topology
            .relate_directly(&alice, &bob)
            .await
            .expect("seed the TSP relationship both ways");

        // The VTA's own send seam, built on alice's mediator-A profile — so its
        // own mediator is A and `mediator_b` differs, selecting the nested route.
        let transport = vta_service::messaging::tsp_transport::TspTransport::new(
            topology.node(0).expect("node A").atm.clone(),
            alice.profile.clone(),
        )
        .expect("alice's profile carries a mediator, so a transport can be built");
        assert_ne!(
            transport.mediator_did(),
            mediator_b,
            "the peer must be on a different mediator for this to exercise nesting"
        );

        let body = vta_sdk::tsp_binding::wrap_envelope(br#"{"probe":"cross-mediator"}"#);
        transport
            .send_metadata_private(&bob.did, Some(&mediator_b), &body)
            .await
            .expect("the nested routed send is accepted for delivery");

        // Bob is on mediator B; a delivered, unpackable message proves the send
        // nested — a direct route could not have crossed.
        let bob_env = topology.node(1).expect("node B");
        let stored = poll_tsp_inbox(bob_env, &bob.profile).await;
        let (recovered, sender) = bob_env
            .atm
            .tsp()
            .unpack(&bob.profile, &stored)
            .await
            .expect("bob unpacks the nested message");
        assert_eq!(recovered, body, "bob receives the framed body intact");
        assert_eq!(sender, alice.did, "and TSP proves alice as the sender");

        topology.shutdown().await.expect("shutdown the topology");
    }

    /// A reply to a peer on another mediator reaches it — with no mediator
    /// handed in, which is the reply path's position: it is answering a frame,
    /// not choosing TSP from the peer's document. `send_to` routes `[ours,
    /// peer]`, which ends at a mediator that does not host bob; this is how a
    /// VTC's answer to a join request (and every status poll after it) never
    /// came back to a persona on another mediator.
    #[tokio::test]
    async fn a_reply_reaches_a_sender_on_another_mediator() {
        use affinidi_messaging_test_mediator::topology::TestTopology;

        let topology = TestTopology::builder()
            .mediators(2)
            .spawn()
            .await
            .expect("spawn a two-mediator topology");
        let alice = topology.add_user(0, "alice").await.expect("alice on A");
        let bob = topology
            .add_tsp_mediated_user(1, "bob")
            .await
            .expect("bob on B, naming mediator B by DID");
        topology
            .relate_directly(&alice, &bob)
            .await
            .expect("seed the TSP relationship both ways, as a sender's frame would");

        let transport = vta_service::messaging::tsp_transport::TspTransport::new(
            topology.node(0).expect("node A").atm.clone(),
            alice.profile.clone(),
        )
        .expect("alice's profile carries a mediator");
        let body = vta_sdk::tsp_binding::wrap_envelope(br#"{"probe":"cross-mediator reply"}"#);
        transport
            .send_reply(&bob.did, &body)
            .await
            .expect("the reply is accepted for delivery");

        let bob_env = topology.node(1).expect("node B");
        let stored = poll_tsp_inbox(bob_env, &bob.profile).await;
        let (recovered, sender) = bob_env
            .atm
            .tsp()
            .unpack(&bob.profile, &stored)
            .await
            .expect("bob unpacks the reply");
        assert_eq!(
            recovered, body,
            "bob, on another mediator, receives the reply"
        );
        assert_eq!(sender, alice.did);

        topology.shutdown().await.expect("shutdown the topology");
    }

    /// VTI-56: a relationship started **from cold** with a peer on another
    /// mediator. Every other cross-mediator test here pre-forms the relationship
    /// (`relate_directly`), which skips the invite entirely, which is how this
    /// went unseen.
    ///
    /// The peers name their mediator by DID in their `TSPTransport` service, as
    /// a VTI-provisioned DID does. Both halves of a cold send have to cross: the
    /// invite, which the SDK routes through that mediator from 0.31.1
    /// (affinidi-tdk-rs #913; before, mediator A refused it as
    /// `e.p.direct_delivery.denied` on every attempt), and the payload, which
    /// `vti_common::tsp_route` nests.
    #[tokio::test]
    async fn vti_56_a_cold_relationship_with_a_cross_mediator_peer_forms() {
        use affinidi_messaging_sdk::messages::fetch::FetchOptions;
        use affinidi_messaging_test_mediator::topology::TestTopology;

        let topology = TestTopology::builder()
            .mediators(2)
            .spawn()
            .await
            .expect("spawn a two-mediator topology");
        let mediator_b = topology.mediator_did(1).expect("mediator B").to_string();
        let alice = topology.add_user(0, "alice").await.expect("alice on A");
        let bob = topology
            .add_tsp_mediated_user(1, "bob")
            .await
            .expect("bob on B, naming mediator B by DID");
        let carol = topology
            .add_tsp_mediated_user(1, "carol")
            .await
            .expect("carol on B, naming mediator B by DID");
        let node_a = topology.node(0).expect("node A");
        let node_b = topology.node(1).expect("node B");

        // The SDK alone (the floor this workspace pins): a cold invite to bob
        // crosses to the mediator his document names.
        node_a
            .atm
            .tsp()
            .form_relationship_routed(&alice.profile, &bob.did)
            .await
            .expect("a cold invite to a peer on another mediator is routed through it");

        // Ours: the re-establishing send names carol's mediator, as every caller
        // does from her DID document's `#tsp` endpoint.
        let transport = vta_service::messaging::tsp_transport::TspTransport::new(
            node_a.atm.clone(),
            alice.profile.clone(),
        )
        .expect("alice's profile carries a mediator");
        let body = vta_sdk::tsp_binding::wrap_envelope(br#"{"probe":"cold cross-mediator"}"#);
        transport
            .send_reestablishing(&carol.did, Some(&mediator_b), &body)
            .await
            .expect("invite and payload are accepted for delivery");
        assert_eq!(
            node_a
                .atm
                .tsp()
                .relationship_state(&alice.profile, &carol.did)
                .await
                .expect("read alice's state"),
            affinidi_messaging_sdk::protocols::tsp::RelationshipState::Pending,
            "the invite left"
        );

        // Carol receives the invite and, behind it, the payload.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut got = None;
        while got.is_none() && std::time::Instant::now() < deadline {
            let fetched = node_b
                .atm
                .fetch_messages(&carol.profile, &FetchOptions::default())
                .await
                .expect("fetch carol's inbox");
            // As an inbound loop does: a control frame advances the relationship
            // (the invite admits what follows it), then application frames
            // unpack. In fetch order the invite comes first.
            let tsp_b = node_b.atm.tsp();
            for m in fetched.success.iter().filter_map(|e| e.msg.as_ref()) {
                let Ok(qb2) = tsp_b.decode(m) else { continue };
                if let Ok((control, sender, _)) = tsp_b.unpack_control(&carol.profile, &qb2).await {
                    tsp_b
                        .record_incoming_control(&carol.profile, &sender, &control)
                        .await
                        .expect("carol records alice's invite");
                } else if let Ok((plain, sender)) = tsp_b.unpack_bytes(&carol.profile, &qb2).await
                    && plain == body
                {
                    got = Some(sender);
                }
            }
            if got.is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
        topology.shutdown().await.expect("shutdown");
        assert_eq!(
            got.as_deref(),
            Some(alice.did.as_str()),
            "carol, on another mediator, receives alice's payload with no prior relationship"
        );
    }

    /// The same-mediator path stays the plain routed send: when the peer shares
    /// our mediator there is no intermediary to hide it from, so
    /// `send_metadata_private` must **not** nest — it falls back to the direct
    /// [`send_to`](vta_service::messaging::tsp_transport::TspTransport::send_to), the
    /// unchanged reference behaviour. Delivery to a same-mediator peer confirms
    /// the fallback carries (and that the equal-mediator case is not accidentally
    /// nesting a `[A, A]` route).
    #[tokio::test]
    async fn send_metadata_private_stays_direct_for_a_same_mediator_peer() {
        use affinidi_messaging_test_mediator::topology::TestTopology;

        let topology = TestTopology::builder()
            .mediators(1)
            .spawn()
            .await
            .expect("spawn a one-mediator topology");
        let mediator_a = topology
            .mediator_did(0)
            .expect("mediator A DID")
            .to_string();
        let alice = topology
            .add_user(0, "alice")
            .await
            .expect("alice on mediator A");
        let carol = topology
            .add_user(0, "carol")
            .await
            .expect("carol on mediator A");
        topology
            .relate_directly(&alice, &carol)
            .await
            .expect("seed the TSP relationship both ways");

        let transport = vta_service::messaging::tsp_transport::TspTransport::new(
            topology.node(0).expect("node A").atm.clone(),
            alice.profile.clone(),
        )
        .expect("alice's profile carries a mediator");
        assert_eq!(
            transport.mediator_did(),
            mediator_a,
            "alice and carol share this mediator"
        );

        let body = vta_sdk::tsp_binding::wrap_envelope(br#"{"probe":"same-mediator"}"#);
        // `Some(mediator_a)` equals our own mediator, so the nesting gate declines
        // and this is the direct routed send.
        transport
            .send_metadata_private(&carol.did, Some(&mediator_a), &body)
            .await
            .expect("the direct routed send is accepted for delivery");

        let carol_env = topology.node(0).expect("node A");
        let stored = poll_tsp_inbox(carol_env, &carol.profile).await;
        let (recovered, sender) = carol_env
            .atm
            .tsp()
            .unpack(&carol.profile, &stored)
            .await
            .expect("carol unpacks the direct message");
        assert_eq!(recovered, body);
        assert_eq!(sender, alice.did);

        topology.shutdown().await.expect("shutdown the topology");
    }
}
