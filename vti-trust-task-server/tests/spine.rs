//! The pipeline's refusal paths, end to end through `Spine::receive`, with the
//! in-memory duplicate-id record and a test signer.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::StatusCode;
use chrono::{TimeDelta, Utc};
use serde_json::{Value, json};
use trust_tasks_rs::{SpecPolicy, TrustTask};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vti_common::error::AppError;
use vti_trust_task_server::reject::{success_response, unsupported_type_or_version};
use vti_trust_task_server::size::SizeTable;
use vti_trust_task_server::{
    ArrivalCtx, BoxFuture, Dispatcher, InMemoryAcceptedIds, ResolverProofVerifier, ResponseSigner,
    Spine, SpineHooks, Transport,
};

const ME: &str = "did:example:service";
const PING: &str = "https://trusttasks.org/spec/test/ping/0.1";
const SIGNED_PING: &str = "https://trusttasks.org/spec/test/signed-ping/0.1";

/// `SIGNED_PING` declares `proof` REQUIRED; `PING` declares nothing.
fn policy(type_uri: &str) -> Option<SpecPolicy> {
    (type_uri == SIGNED_PING).then_some(SpecPolicy {
        is_bearer: false,
        is_proof_required: true,
        is_recipient_required: true,
        is_issued_at_required: true,
    })
}

struct Hooks;

#[async_trait::async_trait]
impl SpineHooks for Hooks {
    async fn recipient(&self) -> Option<String> {
        Some(ME.to_string())
    }
}

/// Routes `PING` and `SIGNED_PING`, counting executions.
#[derive(Default)]
struct Echo {
    runs: AtomicUsize,
}

impl Dispatcher for Echo {
    fn dispatch<'a>(
        &'a self,
        ctx: &'a ArrivalCtx,
        doc: TrustTask<Value>,
        type_uri: &'a str,
        _received: Arc<Value>,
    ) -> BoxFuture<'a, vti_trust_task_server::TrustTaskOutcome> {
        Box::pin(async move {
            match type_uri {
                PING | SIGNED_PING => {
                    self.runs.fetch_add(1, Ordering::SeqCst);
                    success_response(&doc, json!({ "signer": ctx.verified_signer }))
                }
                other => unsupported_type_or_version(&doc, other, [PING, SIGNED_PING], "node"),
            }
        })
    }
}

/// Stamps a recognisable `proof` on every answer.
struct TestSigner;

#[async_trait::async_trait]
impl ResponseSigner for TestSigner {
    async fn sign_response_document(&self, doc: &mut Value) -> Result<(), AppError> {
        doc["proof"] = json!({ "type": "TestProof" });
        Ok(())
    }
}

struct Fixture {
    ids: InMemoryAcceptedIds,
    echo: Echo,
    verifier: ResolverProofVerifier<fn(&str) -> bool>,
    policy: fn(&str) -> Option<SpecPolicy>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            ids: InMemoryAcceptedIds::new(),
            echo: Echo::default(),
            verifier: ResolverProofVerifier::operational(TrustTaskVmResolver::from_optional(None)),
            policy,
        }
    }

    fn spine(&self) -> Spine<'_> {
        Spine::new(&self.policy, &self.verifier, &Hooks, &self.ids, &self.echo)
            .with_signer(Some(&TestSigner))
    }

    async fn send(&self, ctx: &ArrivalCtx, doc: &Value) -> (StatusCode, Value) {
        let body = serde_json::to_vec(doc).expect("serialise");
        let out = self.spine().receive(ctx, &body).await;
        let parsed = if out.body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&out.body).expect("answer is JSON")
        };
        (out.status, parsed)
    }
}

fn unsigned(type_uri: &str) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuer": "did:example:caller",
        "recipient": ME,
        "issuedAt": Utc::now().to_rfc3339(),
        "payload": {},
    })
}

fn code(answer: &Value) -> Option<&str> {
    answer.pointer("/payload/code").and_then(Value::as_str)
}

/// A `did:key` and its private-key multibase from a one-byte seed.
fn holder(seed_byte: u8) -> (String, String) {
    use ed25519_dalek::SigningKey;
    let seed = [seed_byte; 32];
    let sk = SigningKey::from_bytes(&seed);
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
    );
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    (did, multibase::encode(multibase::Base::Base58Btc, &buf))
}

async fn signed(type_uri: &str, seed: u8) -> (String, Value) {
    let (did, secret) = holder(seed);
    let doc = vta_sdk::trust_task_sign::build_signed(type_uri, json!({}), &did, &secret, ME)
        .await
        .expect("sign");
    (did, serde_json::from_str(&doc).expect("signed doc parses"))
}

#[tokio::test]
async fn a_fresh_document_is_dispatched_and_its_answer_signed() {
    let f = Fixture::new();
    let (status, answer) = f.send(&ArrivalCtx::rest(), &unsigned(PING)).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["proof"]["type"], "TestProof", "{answer}");
    assert_eq!(f.echo.runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_stale_issued_at_is_refused_before_dispatch() {
    let f = Fixture::new();
    let mut doc = unsigned(PING);
    doc["issuedAt"] = json!((Utc::now() - TimeDelta::hours(1)).to_rfc3339());
    let (status, answer) = f.send(&ArrivalCtx::rest(), &doc).await;
    assert!(status.is_client_error(), "{status}: {answer}");
    assert_eq!(code(&answer), Some("expired"), "{answer}");
    // Refusals are signed too.
    assert_eq!(answer["proof"]["type"], "TestProof", "{answer}");
    assert_eq!(f.echo.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_missing_issued_at_is_refused() {
    let f = Fixture::new();
    let mut doc = unsigned(PING);
    doc.as_object_mut().expect("object").remove("issuedAt");
    let (status, answer) = f.send(&ArrivalCtx::rest(), &doc).await;
    assert!(status.is_client_error(), "{status}: {answer}");
    assert_eq!(f.echo.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_document_for_another_recipient_is_refused() {
    let f = Fixture::new();
    let mut doc = unsigned(PING);
    doc["recipient"] = json!("did:example:someone-else");
    let (status, answer) = f.send(&ArrivalCtx::rest(), &doc).await;
    assert!(status.is_client_error(), "{status}: {answer}");
    assert_eq!(code(&answer), Some("wrongRecipient"), "{answer}");
    assert_eq!(f.echo.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_required_proof_that_is_missing_is_refused() {
    let f = Fixture::new();
    let (status, answer) = f.send(&ArrivalCtx::rest(), &unsigned(SIGNED_PING)).await;
    assert!(status.is_client_error(), "{status}: {answer}");
    assert_eq!(code(&answer), Some("proofRequired"), "{answer}");
    assert_eq!(f.echo.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_valid_proof_reaches_the_handler_as_the_verified_signer() {
    let f = Fixture::new();
    let (did, doc) = signed(SIGNED_PING, 7).await;
    let (status, answer) = f.send(&ArrivalCtx::rest(), &doc).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["payload"]["signer"], json!(did), "{answer}");
}

#[tokio::test]
async fn a_tampered_proof_is_refused() {
    let f = Fixture::new();
    let (_, mut doc) = signed(SIGNED_PING, 8).await;
    doc["payload"] = json!({ "changed": true });
    let (status, answer) = f.send(&ArrivalCtx::rest(), &doc).await;
    assert!(status.is_client_error(), "{status}: {answer}");
    assert_eq!(f.echo.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_messaging_document_must_be_signed_by_its_sender() {
    let f = Fixture::new();
    // Unsigned over DIDComm: refused whatever the task declares.
    let (_, answer) = f
        .send(
            &ArrivalCtx::didcomm("did:example:caller".into()),
            &unsigned(PING),
        )
        .await;
    assert_eq!(code(&answer), Some("proofRequired"), "{answer}");

    // Signed, but by someone other than the transport's sender.
    let (_, doc) = signed(PING, 9).await;
    let ctx = ArrivalCtx {
        transport: Transport::Tsp,
        sender_did: Some("did:example:someone-else".into()),
        verified_signer: None,
    };
    let (status, answer) = f.send(&ctx, &doc).await;
    assert!(status.is_client_error(), "{status}: {answer}");
    assert_eq!(code(&answer), Some("identityMismatch"), "{answer}");

    // Signed by the sender: accepted.
    let (did, doc) = signed(PING, 10).await;
    let (status, answer) = f.send(&ArrivalCtx::didcomm(did), &doc).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(f.echo.runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_duplicate_is_answered_with_the_first_result_and_not_run_again() {
    let f = Fixture::new();
    let doc = unsigned(PING);
    let (first_status, first) = f.send(&ArrivalCtx::rest(), &doc).await;
    assert_eq!(first_status, StatusCode::OK, "{first}");
    let (again_status, again) = f.send(&ArrivalCtx::rest(), &doc).await;
    assert_eq!(again_status, StatusCode::OK, "{again}");
    assert_eq!(
        first, again,
        "a redelivery is answered with the recorded result"
    );
    assert_eq!(
        f.echo.runs.load(Ordering::SeqCst),
        1,
        "and not executed twice"
    );

    // A different document under the same id is a conflict.
    let mut other = doc.clone();
    other["payload"] = json!({ "different": true });
    let (status, answer) = f.send(&ArrivalCtx::rest(), &other).await;
    assert!(status.is_client_error(), "{status}: {answer}");
    assert_eq!(code(&answer), Some("idConflict"), "{answer}");
}

#[tokio::test]
async fn a_refused_dispatch_releases_its_id() {
    let f = Fixture::new();
    let unknown = "https://trusttasks.org/spec/test/unknown/0.1";
    let doc = unsigned(unknown);
    let (status, answer) = f.send(&ArrivalCtx::rest(), &doc).await;
    assert!(status.is_client_error(), "{status}: {answer}");
    assert_eq!(code(&answer), Some("unsupportedType"), "{answer}");
    assert!(f.ids.is_empty(), "a refused execution gives its id back");
}

#[tokio::test]
async fn an_unsupported_version_names_the_served_versions() {
    let f = Fixture::new();
    let (_, answer) = f
        .send(
            &ArrivalCtx::rest(),
            &unsigned("https://trusttasks.org/spec/test/ping/0.9"),
        )
        .await;
    assert_eq!(code(&answer), Some("unsupportedVersion"), "{answer}");
    assert_eq!(
        answer["payload"]["details"]["servedVersions"],
        json!([PING]),
        "{answer}"
    );
}

#[tokio::test]
async fn an_oversized_document_is_refused_before_it_is_parsed() {
    let f = Fixture::new();
    let table = SizeTable::new(1024, |t: &str| (t == PING).then_some(2048));
    let mut doc = unsigned(PING);
    doc["payload"] = json!({ "pad": "x".repeat(4096) });
    let body = serde_json::to_vec(&doc).expect("serialise");
    let out = f
        .spine()
        .with_size_gate(&table)
        .receive(&ArrivalCtx::rest(), &body)
        .await;
    let answer: Value = serde_json::from_slice(&out.body).expect("JSON");
    assert_eq!(code(&answer), Some("malformedRequest"), "{answer}");
    assert_eq!(answer["payload"]["details"]["maxBytes"], 2048, "{answer}");
    assert_eq!(f.echo.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_body_that_is_not_a_document_is_refused() {
    let f = Fixture::new();
    let out = f
        .spine()
        .receive(&ArrivalCtx::rest(), b"not a document")
        .await;
    let answer: Value = serde_json::from_slice(&out.body).expect("JSON");
    assert_eq!(code(&answer), Some("malformedRequest"), "{answer}");
}

/// The HTTPS handler serves the same pipeline.
#[tokio::test]
async fn the_https_route_serves_the_spine() {
    use tower::ServiceExt;

    struct Service(Fixture);
    impl vti_trust_task_server::http::TrustTaskService for Service {
        fn spine(&self) -> Spine<'_> {
            self.0.spine()
        }
    }

    let app = vti_trust_task_server::http::routes(Arc::new(Service(Fixture::new())));
    let request = axum::http::Request::post(vti_trust_task_server::http::TRUST_TASKS_PATH)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&unsigned(PING)).expect("serialise"),
        ))
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("body")
        .to_bytes();
    let answer: Value = serde_json::from_slice(&bytes).expect("JSON");
    assert_eq!(answer["proof"]["type"], "TestProof", "{answer}");
}
