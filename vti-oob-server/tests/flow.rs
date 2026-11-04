//! The whole `auth/oob` flow against a host shaped like the VTN's: one
//! audience, no cookies or sessions, and a `redeem` that arms `K_b` as a key
//! delegated to act as the approver for a fixed `signingScope`.
//!
//! Proofs are not what this exercises (the host's verifiers are), so the test
//! host trusts a carried document's `issuer` and checks only the purpose the
//! crate asked for; the crate's own checks — lock, clocks, number, context,
//! replay, recipient, freshness and order — run as in production.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use vti_common::auth::session::now_epoch;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_oob_server::delegation::{self, AlwaysLive, Delegation};
use vti_oob_server::{
    Approved, Audience, Completion, Eligibility, Gate, HttpContext, OobHost, SignInEvent,
};
use vti_trust_task_server::{AcceptedIdStore, InMemoryAcceptedIds};

const SERVICE: &str = "did:webvh:scidvtn:vtn.example.org";
const ORIGIN: &str = "https://vtn.example.org";
const BASE: &str = "https://trusttasks.org/spec/auth/oob";
const SCOPE: &str = "vtn/groups";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
enum Only {
    #[default]
    Network,
}

impl Audience for Only {
    fn from_ext(ext: Option<&Value>) -> Result<Self, String> {
        match ext.and_then(|e| e.get(vti_oob_server::SESSION_EXT)) {
            None => Ok(Only::Network),
            Some(_) => Err("this service has one audience".into()),
        }
    }
    fn to_ext(self) -> Option<Value> {
        None
    }
}

struct NetworkHost {
    ks: KeyspaceHandle,
    accepted: InMemoryAcceptedIds,
    approvers: HashSet<String>,
    audited: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl OobHost for NetworkHost {
    type Audience = Only;

    fn records(&self) -> &KeyspaceHandle {
        &self.ks
    }
    async fn service_did(&self) -> Option<String> {
        Some(SERVICE.into())
    }
    async fn public_url(&self) -> Option<String> {
        Some(ORIGIN.into())
    }
    async fn service_name(&self) -> Option<String> {
        Some("Example Network".into())
    }
    async fn sign_step(&self, response: &mut Value) -> Result<(), String> {
        response["proof"] = proof(SERVICE, "assertionMethod");
        Ok(())
    }
    async fn verify_authentication(&self, received: &Value) -> Result<String, AppError> {
        signed_for(received, "authentication")
    }
    async fn verify_assertion(&self, received: &Value, _: &str) -> Result<String, AppError> {
        signed_for(received, "assertionMethod")
    }
    fn accepted_ids(&self) -> &dyn AcceptedIdStore {
        &self.accepted
    }
    async fn gate(&self, _: Gate, _: Only, did: &str) -> Result<Eligibility, AppError> {
        Ok(if self.approvers.contains(did) {
            Eligibility::Eligible
        } else {
            Eligibility::Refused {
                reason: "not a network member".into(),
            }
        })
    }
    fn signing_scope(&self, _: Only) -> Option<Vec<String>> {
        Some(vec![SCOPE.into()])
    }
    async fn audit(&self, event: SignInEvent<'_, Only>) {
        self.audited.lock().unwrap().push(event.stage.to_string());
    }
    async fn complete(&self, approved: Approved<'_, Only>) -> Result<Completion, AppError> {
        let Some(scope) = approved.signing_scope() else {
            return Ok(Completion::NotAuthorized);
        };
        delegation::record(
            &self.ks,
            &approved.record.start_key,
            &Delegation {
                approver_did: approved.subject.to_string(),
                scope,
                not_after: approved.not_after,
                grant_id: approved.grant_id(),
            },
        )
        .await?;
        Ok(Completion::Issued {
            display_name: approved.subject.to_string(),
            ends_at: approved.not_after,
        })
    }
}

fn signed_for(received: &Value, purpose: &str) -> Result<String, AppError> {
    if received["proof"]["proofPurpose"] != purpose {
        return Err(AppError::Unauthorized("wrong purpose".into()));
    }
    Ok(received["issuer"].as_str().unwrap_or_default().to_string())
}

fn proof(issuer: &str, purpose: &str) -> Value {
    json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": format!("{issuer}#key-0"),
        "created": vti_oob_server::rfc3339(now_epoch()),
        "proofPurpose": purpose,
        "proofValue": "zTestOnly",
    })
}

fn did_key(seed: u8) -> String {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let mut buf = vec![0xed, 0x01];
    buf.extend_from_slice(&sk.verifying_key().to_bytes());
    format!(
        "did:key:{}",
        multibase::encode(multibase::Base::Base58Btc, &buf)
    )
}

fn t(task: &str) -> String {
    let version = match task {
        "request" | "claim" | "redeem" => "0.2",
        "prove" | "respond" | "grant" => "0.3",
        _ => "0.1",
    };
    format!("{BASE}/{task}/{version}")
}

fn doc(issuer: &str, task: &str, payload: Value, parent: Option<&str>, purpose: &str) -> Value {
    let mut d = json!({
        "id": format!("urn:uuid:{}", uuid_like()),
        "type": t(task),
        "issuer": issuer,
        "recipient": SERVICE,
        "issuedAt": vti_oob_server::rfc3339(now_epoch()),
        "payload": payload,
        "proof": proof(issuer, purpose),
    });
    if let Some(p) = parent {
        d["parentThreadId"] = json!(p);
    }
    d
}

fn uuid_like() -> String {
    let id = vti_oob_server::new_request_id();
    let hex: String = id.bytes().map(|b| format!("{:02x}", b)).collect();
    format!(
        "{}-{}-4{}-8{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[13..16],
        &hex[17..20],
        &hex[20..32]
    )
}

/// One document through the handlers, over HTTPS from `ip`.
async fn send(
    host: &NetworkHost,
    d: Value,
    ip: &str,
    origin: Option<&str>,
) -> (Value, Vec<String>) {
    let doc: TrustTask<Value> = serde_json::from_value(d).unwrap();
    let type_uri = doc.type_uri.to_string();
    assert!(vti_oob_server::precheck(&doc, &type_uri).is_none());
    let signer = doc.issuer.clone().unwrap();
    let http = HttpContext::new(
        ip.parse::<IpAddr>().unwrap(),
        Some("Mozilla/5.0 (Macintosh) Firefox/140.0".into()),
        origin.map(str::to_string),
        Some("vtn.example.org".into()),
    );
    let outcome = HttpContext::scope(
        Arc::clone(&http),
        vti_oob_server::dispatch(host, doc, &type_uri, signer),
    )
    .await
    .expect("an auth/oob type");
    (
        serde_json::from_slice(&outcome.body).unwrap(),
        http.take_cookies(),
    )
}

fn code(v: &Value) -> &str {
    v["payload"]["code"].as_str().unwrap_or_default()
}

async fn host(approvers: &[&str]) -> (NetworkHost, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .unwrap();
    (
        NetworkHost {
            ks: store.keyspace("oob").unwrap(),
            accepted: InMemoryAcceptedIds::default(),
            approvers: approvers.iter().map(|s| s.to_string()).collect(),
            audited: Mutex::new(Vec::new()),
        },
        dir,
    )
}

#[tokio::test]
async fn a_wallet_approves_k_b_and_redeem_arms_it_as_a_delegated_key() {
    vti_oob_server::set_redeem_hold_for_tests(std::time::Duration::from_millis(200));
    let alice = "did:webvh:scidalice:alice.example.org";
    let (h, _dir) = host(&[alice]).await;
    let (k_b, k_a) = (did_key(1), did_key(2));
    let (browser, phone) = ("192.0.2.10", "192.0.2.10");

    // request
    let (r, _) = send(
        &h,
        doc(
            &k_b,
            "request",
            json!({ "purpose": "login", "mode": "scan" }),
            None,
            "authentication",
        ),
        browser,
        Some(ORIGIN),
    )
    .await;
    let id = r["payload"]["requestId"]
        .as_str()
        .expect("a request id")
        .to_string();
    assert!(r["payload"].get("ext").is_none(), "one audience: no ext");

    // claim: step 1, signed, naming the service; no ext.
    let (s1, _) = send(
        &h,
        doc(
            &k_a,
            "claim",
            json!({ "requestId": id }),
            Some(&id),
            "authentication",
        ),
        phone,
        None,
    )
    .await;
    assert_eq!(s1["payload"]["service"]["did"], SERVICE, "{s1}");
    assert_eq!(s1["payload"]["service"]["name"], "Example Network");
    assert!(s1["proof"].is_object() && s1["payload"].get("ext").is_none());

    // The browser learns the number.
    let (p, _) = send(
        &h,
        doc(
            &k_b,
            "redeem",
            json!({ "requestId": id }),
            None,
            "authentication",
        ),
        browser,
        Some(ORIGIN),
    )
    .await;
    assert_eq!(code(&p), "auth/oob/redeem:pending", "{p}");
    let number = p["payload"]["details"]["matchNumber"]
        .as_str()
        .unwrap()
        .to_string();

    // prove: step 2 offers the host's scope.
    let identify = doc(
        alice,
        "identify",
        json!({ "requestId": id, "approverKey": k_a, "enteredNumber": number }),
        None,
        "authentication",
    );
    let (s2, _) = send(
        &h,
        doc(
            &k_a,
            "prove",
            json!({ "identify": identify }),
            None,
            "authentication",
        ),
        phone,
        None,
    )
    .await;
    assert_eq!(s2["payload"]["identifiedAs"], alice, "{s2}");
    assert_eq!(s2["payload"]["signingScope"], json!([SCOPE]));
    assert_eq!(s2["payload"]["requester"]["sameNetwork"], true);

    // respond: a grant over the real step 2.
    let not_after = now_epoch() + 600;
    let grant = doc(
        alice,
        "grant",
        json!({
            "requestId": id,
            "decision": "approve",
            "sessionKey": k_b,
            "approverKey": k_a,
            "origin": ORIGIN,
            "contextDigest": vti_oob_server::context_digest(&s2).unwrap(),
            "sessionEndsAt": vti_oob_server::rfc3339(not_after),
            "signingScope": [SCOPE],
        }),
        None,
        "assertionMethod",
    );
    let grant_id = grant["id"].as_str().unwrap().to_string();
    let (rs, _) = send(
        &h,
        doc(
            &k_a,
            "respond",
            json!({ "grant": grant }),
            None,
            "authentication",
        ),
        phone,
        None,
    )
    .await;
    assert_eq!(rs["payload"]["status"], "approved", "{rs}");

    // redeem: no cookies; K_b is now delegated for the scope, and nothing else.
    let (done, cookies) = send(
        &h,
        doc(
            &k_b,
            "redeem",
            json!({ "requestId": id }),
            None,
            "authentication",
        ),
        browser,
        Some(ORIGIN),
    )
    .await;
    assert_eq!(done["payload"]["subject"], alice, "{done}");
    assert_eq!(done["payload"]["amr"], json!(["did", "oob", "uv"]));
    assert_eq!(
        done["payload"]["sessionEndsAt"],
        vti_oob_server::rfc3339(not_after)
    );
    assert!(cookies.is_empty());
    let armed = delegation::armed::<Delegation, _>(
        &h.ks,
        &k_b,
        "https://trusttasks.org/spec/vtn/groups/register/0.1",
        &AlwaysLive,
    )
    .await
    .unwrap()
    .expect("K_b is delegated");
    assert_eq!(armed.approver_did, alice);
    assert_eq!(armed.grant_id.as_deref(), Some(grant_id.as_str()));
    assert!(
        delegation::armed::<Delegation, _>(&h.ks, &k_b, &t("request"), &AlwaysLive)
            .await
            .unwrap()
            .is_none(),
        "never an auth/* task"
    );

    // Spent: a second redeem is refused.
    let (again, _) = send(
        &h,
        doc(
            &k_b,
            "redeem",
            json!({ "requestId": id }),
            None,
            "authentication",
        ),
        browser,
        Some(ORIGIN),
    )
    .await;
    assert_eq!(code(&again), "auth/oob:alreadyDecided", "{again}");
    assert_eq!(
        *h.audited.lock().unwrap(),
        ["requested", "claimed", "proved", "approved", "redeemed"]
    );
}

#[tokio::test]
async fn an_unknown_approver_is_refused_before_resolution_and_the_request_declines() {
    vti_oob_server::set_redeem_hold_for_tests(std::time::Duration::from_millis(200));
    let (h, _dir) = host(&[]).await;
    let (k_b, k_a) = (did_key(3), did_key(4));
    let (r, _) = send(
        &h,
        doc(
            &k_b,
            "request",
            json!({ "purpose": "login", "mode": "scan" }),
            None,
            "authentication",
        ),
        "192.0.2.20",
        Some(ORIGIN),
    )
    .await;
    let id = r["payload"]["requestId"].as_str().unwrap().to_string();
    send(
        &h,
        doc(
            &k_a,
            "claim",
            json!({ "requestId": id }),
            Some(&id),
            "authentication",
        ),
        "192.0.2.21",
        None,
    )
    .await;
    let (p, _) = send(
        &h,
        doc(
            &k_b,
            "redeem",
            json!({ "requestId": id }),
            None,
            "authentication",
        ),
        "192.0.2.20",
        Some(ORIGIN),
    )
    .await;
    let number = p["payload"]["details"]["matchNumber"]
        .as_str()
        .unwrap()
        .to_string();
    let mallory = "did:webvh:scidm:mallory.example.org";
    let identify = doc(
        mallory,
        "identify",
        json!({ "requestId": id, "approverKey": k_a, "enteredNumber": number }),
        None,
        "authentication",
    );
    let (pr, _) = send(
        &h,
        doc(
            &k_a,
            "prove",
            json!({ "identify": identify }),
            None,
            "authentication",
        ),
        "192.0.2.21",
        None,
    )
    .await;
    assert_eq!(code(&pr), "auth/oob:notAuthorized", "{pr}");
    assert!(
        pr["payload"].get("details").is_none_or(Value::is_null),
        "T15: no reason"
    );
    let (d, _) = send(
        &h,
        doc(
            &k_b,
            "redeem",
            json!({ "requestId": id }),
            None,
            "authentication",
        ),
        "192.0.2.20",
        Some(ORIGIN),
    )
    .await;
    assert_eq!(code(&d), "auth/oob/redeem:declined", "{d}");
}

#[tokio::test]
async fn request_is_https_only_same_origin_only_and_audiences_are_the_hosts() {
    let (h, _dir) = host(&[]).await;
    let k_b = did_key(5);
    // Off the HTTPS door.
    let d: TrustTask<Value> = serde_json::from_value(doc(
        &k_b,
        "request",
        json!({ "purpose": "login", "mode": "scan" }),
        None,
        "authentication",
    ))
    .unwrap();
    let type_uri = d.type_uri.to_string();
    let off = vti_oob_server::dispatch(&h, d, &type_uri, k_b.clone())
        .await
        .unwrap();
    let off: Value = serde_json::from_slice(&off.body).unwrap();
    assert_eq!(off["payload"]["code"], "permissionDenied", "{off}");
    // Another site's page.
    let (r, _) = send(
        &h,
        doc(
            &k_b,
            "request",
            json!({ "purpose": "login", "mode": "scan" }),
            None,
            "authentication",
        ),
        "192.0.2.30",
        Some("https://evil.example"),
    )
    .await;
    assert_eq!(code(&r), "permissionDenied", "{r}");
    // An audience this host does not serve.
    let ext = json!({ vti_oob_server::SESSION_EXT: { "audience": "admin" } });
    let (r, _) = send(
        &h,
        doc(
            &k_b,
            "request",
            json!({ "purpose": "login", "mode": "scan", "ext": ext }),
            None,
            "authentication",
        ),
        "192.0.2.30",
        Some(ORIGIN),
    )
    .await;
    assert_eq!(code(&r), "malformedRequest", "{r}");
}

#[test]
fn precheck_refuses_any_signer_but_an_ed25519_did_key() {
    let d: TrustTask<Value> = serde_json::from_value(doc(
        "did:webvh:scidalice:alice.example.org",
        "claim",
        json!({ "requestId": "x" }),
        None,
        "authentication",
    ))
    .unwrap();
    let refused = vti_oob_server::precheck(&d, &t("claim")).expect("refused");
    let body: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(body["payload"]["code"], "auth/oob:keyUnsupported");
    assert!(
        vti_oob_server::precheck(&d, "https://trusttasks.org/spec/vtn/groups/register/0.1")
            .is_none()
    );
}
