//! Driving a signed document through the gates that guard authority: the
//! requester's passkey gesture bound to the operation, and — where one is
//! asked for — another unrestricted administrator's consent.
//!
//! Granting unrestricted admin has taken both since VTI-APV-014. Removing,
//! demoting or narrowing an administrator (VTI-APV-019), lowering the consent
//! threshold (VTI-APV-020) and changing a policy that decides authority
//! (VTI-VTC-022) take them now too, so suites that do those things as setup go
//! through here rather than around the gate.
//!
//! The VTC must be built `with_public_url(..)` — the gesture is WebAuthn, and
//! without a relying party there is nothing to answer.

use axum::http::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;
use vti_common::auth::passkey::build_webauthn;
use vti_common::auth::passkey::store::{PasskeyUser, store_credential_mapping, store_passkey_user};
use vti_rooms_dtg::test_support::Party;
use webauthn_rs::prelude::{PublicKeyCredential, RequestChallengeResponse};

use vtc_service::test_support::TestVtc;

use super::signed::{post, signed};
use super::webauthn_harness::SoftEd25519Authenticator;

const APPROVE_RESPONSE: &str = "https://trusttasks.org/spec/auth/step-up/approve-response/0.4";

/// One soft authenticator holding every passkey it enrols.
pub struct Gesturer {
    authenticator: SoftEd25519Authenticator,
}

impl Default for Gesturer {
    fn default() -> Self {
        Self::new()
    }
}

/// The VTC's relying-party origin.
async fn origin(vtc: &TestVtc) -> String {
    vtc.state
        .config
        .read()
        .await
        .public_url
        .clone()
        .expect("the gesture is WebAuthn: build the VTC with_public_url(..)")
}

impl Gesturer {
    pub fn new() -> Self {
        Self {
            authenticator: SoftEd25519Authenticator::new(),
        }
    }

    /// Register a passkey for `did` with the VTC.
    pub async fn enrol(&mut self, vtc: &TestVtc, did: &str) {
        let origin = origin(vtc).await;
        let webauthn = build_webauthn(&origin).unwrap();
        let user_uuid = Uuid::new_v4();
        let (ccr, reg_state) =
            vtc_service::webauthn::start_passkey_registration(&webauthn, user_uuid, did, did, None)
                .unwrap();
        let (cred, _) = self.authenticator.register(&ccr, &origin);
        let passkey =
            vtc_service::webauthn::finish_passkey_registration(&webauthn, &cred, &reg_state)
                .unwrap();
        let cred_hex = hex::encode(<_ as AsRef<[u8]>>::as_ref(passkey.cred_id()));
        let ks = &vtc.state.passkey_ks;
        store_passkey_user(
            ks,
            &PasskeyUser {
                user_uuid,
                did: did.to_string(),
                display_name: did.to_string(),
                credentials: vec![passkey],
            },
        )
        .await
        .unwrap();
        store_credential_mapping(ks, &cred_hex, user_uuid)
            .await
            .unwrap();
    }

    /// An assertion by `did`'s enrolled passkey whose WebAuthn challenge is
    /// exactly `challenge` — the shape `task-consent/decision/0.2`'s `webauthn`
    /// evidence carries.
    pub async fn assert_over(&mut self, vtc: &TestVtc, challenge: &[u8]) -> Value {
        use base64::Engine as _;
        let origin = origin(vtc).await;
        let webauthn = build_webauthn(&origin).unwrap();
        let passkeys = vti_common::auth::passkey::store::get_all_passkeys(&vtc.state.passkey_ks)
            .await
            .unwrap();
        let (rcr, _) = webauthn.start_passkey_authentication(&passkeys).unwrap();
        let mut v = serde_json::to_value(&rcr).unwrap();
        v["publicKey"]["challenge"] =
            json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge));
        let rcr: RequestChallengeResponse = serde_json::from_value(v).unwrap();
        assertion(&self.authenticator.authenticate(&rcr, &origin))
    }

    /// Answer the step-up refusal `refusal` (the whole reply document) with
    /// `requester`'s passkey.
    pub async fn gesture(&mut self, vtc: &TestVtc, requester: &Party, refusal: &Value) {
        let request = step_up_request(refusal)
            .unwrap_or_else(|| panic!("expected a step-up request: {refusal}"))
            .clone();
        let origin = origin(vtc).await;
        let cred = self.authenticator.authenticate(&options(&request), &origin);
        let doc = signed(
            requester,
            APPROVE_RESPONSE,
            json!({
                "subject": request["subject"],
                "challenge": request["challenge"],
                "decision": "approved",
                "evidence": { "kind": "webauthn", "assertion": assertion(&cred) },
            }),
        )
        .await;
        let (status, ack) = post(vtc, &doc).await;
        assert_eq!(status, StatusCode::OK, "{ack}");
        assert_eq!(ack["payload"]["status"], "recorded", "{ack}");
    }

    /// Send `doc`, answering each step-up with `requester`'s passkey, until it
    /// is either answered or parked as an action. Parked, it is approved by
    /// each of `approvers` in turn until it closes, and the reply returned is
    /// the operation's own, as the requester reads it back from the action:
    /// `#response` with the executed payload when it completed, a
    /// `trust-task-error`-shaped refusal when it failed (VTI-APV-017).
    pub async fn send_through(
        &mut self,
        vtc: &TestVtc,
        requester: &Party,
        approvers: &[&Party],
        doc: &Value,
    ) -> (StatusCode, Value) {
        for _ in 0..6 {
            let (status, reply) = post(vtc, doc).await;
            if step_up_request(&reply).is_some() {
                self.gesture(vtc, requester, &reply).await;
                continue;
            }
            if let Some(action_id) = parked_action(&reply) {
                assert!(
                    !approvers.is_empty(),
                    "parked for approval and nobody to give it: {reply}"
                );
                for approver in approvers {
                    let (_, shown) = show_action(vtc, approver, &action_id).await;
                    if shown["payload"]["action"]["status"] != "open" {
                        break;
                    }
                    let (status, ack) = decide(vtc, approver, &action_id, "approve").await;
                    assert_eq!(status, StatusCode::OK, "approval refused: {ack}");
                }
                return outcome_of(vtc, requester, &action_id, doc).await;
            }
            return (status, reply);
        }
        panic!("the gate never settled for {doc}");
    }
}

const NEXT_STEP: &str = "https://trusttasks.org/spec/trust-task-next-step/0.1";
const SHOW: &str = "https://trusttasks.org/spec/vtc/admin/actions/show/0.1";
const DECISION_V0_2: &str = "https://trusttasks.org/spec/task-consent/decision/0.2";

/// The action a `trust-task-next-step/0.1` reply parked the operation as.
pub fn parked_action(reply: &Value) -> Option<String> {
    (reply["type"] == NEXT_STEP)
        .then(|| reply["payload"]["expects"][0]["hint"]["actionId"].as_str())
        .flatten()
        .map(str::to_string)
}

async fn recipient(vtc: &TestVtc) -> String {
    vtc.state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_else(|| vtc_service::test_support::TEST_VTC_DID.to_string())
}

/// `vtc/admin/actions/show/0.1` as `who`: the whole reply.
pub async fn show_action(vtc: &TestVtc, who: &Party, action_id: &str) -> (StatusCode, Value) {
    let doc = super::signed::signed_to(
        who,
        &recipient(vtc).await,
        SHOW,
        json!({ "actionId": action_id }),
    )
    .await;
    post(vtc, &doc).await
}

/// The decision payload `approver` sends on `action` (as `show` gave it to
/// them): their own challenge, and the digest salted with it.
pub fn decision_payload(action: &Value, decision: &str) -> Value {
    let challenge = action["challenge"]
        .as_str()
        .unwrap_or_else(|| panic!("no challenge for this caller: {action}"));
    let wire = vti_common::task_consent::wire_digest(
        action["typeUri"].as_str().unwrap(),
        &action["payload"],
        challenge,
    )
    .unwrap();
    json!({
        "challenge": challenge,
        "payloadDigest": wire,
        "decision": decision,
        "actionId": action["actionId"],
    })
}

/// `approver`'s `task-consent/decision/0.2` on `action_id`, read off `show`.
pub async fn decide(
    vtc: &TestVtc,
    approver: &Party,
    action_id: &str,
    decision: &str,
) -> (StatusCode, Value) {
    let (_, shown) = show_action(vtc, approver, action_id).await;
    let payload = decision_payload(&shown["payload"]["action"], decision);
    let doc =
        super::signed::signed_to(approver, &recipient(vtc).await, DECISION_V0_2, payload).await;
    post(vtc, &doc).await
}

/// What the requester reads back once their action has closed, shaped as the
/// operation's own reply would have been.
async fn outcome_of(
    vtc: &TestVtc,
    requester: &Party,
    action_id: &str,
    doc: &Value,
) -> (StatusCode, Value) {
    let (_, shown) = show_action(vtc, requester, action_id).await;
    let action = &shown["payload"]["action"];
    let type_uri = doc["type"].as_str().unwrap_or_default();
    match action["status"].as_str() {
        Some("completed") => (
            StatusCode::OK,
            json!({
                "type": format!("{type_uri}#response"),
                "payload": action["ext"]["org.openvtc"]["result"],
            }),
        ),
        _ => (
            StatusCode::CONFLICT,
            json!({
                "type": "https://trusttasks.org/spec/trust-task-error/0.5",
                "payload": {
                    "code": "taskFailed",
                    "message": action["ext"]["org.openvtc"]["closedMessage"],
                    "details": { "action": action },
                },
            }),
        ),
    }
}

/// An unrestricted administrator who can get through the gates: they hold a
/// passkey, and a second unrestricted administrator stands by to consent.
///
/// For suites whose subject is something *behind* a gate — what a policy
/// decides, how the policy verbs version and list — and which change an
/// authority policy or remove an admin only as setup.
pub struct GatedAdmin {
    pub requester: Party,
    pub approver: Party,
    gesturer: tokio::sync::Mutex<Gesturer>,
}

impl GatedAdmin {
    /// `requester` (already an unrestricted admin) gets a passkey, and a second
    /// unrestricted admin is seeded to consent.
    pub async fn for_admin(vtc: &TestVtc, requester: Party) -> Self {
        let mut gesturer = Gesturer::new();
        gesturer.enrol(vtc, &requester.did).await;
        let approver = super::signed::admin(vtc).await;
        Self {
            requester,
            approver,
            gesturer: tokio::sync::Mutex::new(gesturer),
        }
    }

    /// A fresh pair.
    pub async fn new(vtc: &TestVtc) -> Self {
        let requester = super::signed::admin(vtc).await;
        Self::for_admin(vtc, requester).await
    }

    /// [`super::signed::call`] as the requester, through any gesture and
    /// consent the task asks for.
    pub async fn call(&self, vtc: &TestVtc, type_uri: &str, payload: Value) -> (StatusCode, Value) {
        let recipient = vtc
            .state
            .config
            .read()
            .await
            .vtc_did
            .clone()
            .unwrap_or_else(|| vtc_service::test_support::TEST_VTC_DID.to_string());
        let doc = super::signed::signed_to(&self.requester, &recipient, type_uri, payload).await;
        let (status, reply) = self
            .gesturer
            .lock()
            .await
            .send_through(vtc, &self.requester, &[&self.approver], &doc)
            .await;
        if reply["type"].as_str() == Some(format!("{type_uri}#response").as_str()) {
            super::signed::assert_conforms(type_uri, &reply);
        }
        (status, reply)
    }
}

/// The inline `auth/step-up/approve-request` a refusal carries, if any.
pub fn step_up_request(reply: &Value) -> Option<&Value> {
    reply["payload"]["details"]
        .get("stepUpRequest")
        .filter(|r| r.is_object())
}

fn options(request: &Value) -> RequestChallengeResponse {
    let mut inner = request["webauthn"].clone();
    inner["timeout"] = inner.get("timeout").cloned().unwrap_or(json!(60000));
    serde_json::from_value(json!({ "publicKey": inner })).expect("options re-wrap")
}

fn assertion(cred: &PublicKeyCredential) -> Value {
    let v = serde_json::to_value(cred).unwrap();
    let mut response = json!({
        "authenticatorData": v["response"]["authenticatorData"],
        "clientDataJSON": v["response"]["clientDataJSON"],
        "signature": v["response"]["signature"],
    });
    if v["response"]["userHandle"].is_string() {
        response["userHandle"] = v["response"]["userHandle"].clone();
    }
    json!({
        "id": v["id"],
        "rawId": v["rawId"],
        "type": "public-key",
        "response": response,
        "clientExtensionResults": {},
    })
}
