//! `vtc/badges/*` (VTI-BDG-*): badges backed by badge groups, awards accepted by their
//! holders, kudos between members, through a stand-in for the community's VTA that mints
//! the badge group's DID and signs its credentials. The refusal tests witness every
//! code the specifications declare (`trust_tasks::error_code_census`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::http::StatusCode;
use base64::Engine as _;
use chrono::Utc;
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use vtc_service::acl::VtcRole;
use vtc_service::config::GroupsConfig;
use vtc_service::members::{Member, store_member};
use vtc_service::rooms::vta_storage::{PeerError, VtaChannel};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};
use vti_rooms_dtg::test_support::Party;

use crate::common::second_party::{GatedAdmin, step_up_request};
use crate::common::signed::{call, seed_role};
use vti_specs::vtc::badges as b;

const SHARE_ERR_BADGES_OFF: &str = b::awards::share::v0_1::error_codes::BADGES_OFF.code;
const SHARE_ERR_NOT_FOUND: &str = b::awards::share::v0_1::error_codes::NOT_FOUND.code;
const SHARE_ERR_NOT_SHAREABLE: &str = b::awards::share::v0_1::error_codes::NOT_SHAREABLE.code;
const SHARE_ERR_PUBLIC_LOCATION_UNAVAILABLE: &str =
    b::awards::share::v0_1::error_codes::PUBLIC_LOCATION_UNAVAILABLE.code;
const UNSHARE_ERR_BADGES_OFF: &str = b::awards::unshare::v0_1::error_codes::BADGES_OFF.code;
const UNSHARE_ERR_NOT_FOUND: &str = b::awards::unshare::v0_1::error_codes::NOT_FOUND.code;
const CLAIMS_CREATE_ERR_BADGES_OFF: &str = b::claims::create::v0_1::error_codes::BADGES_OFF.code;
const CLAIMS_CREATE_ERR_NOT_FOUND: &str = b::claims::create::v0_1::error_codes::NOT_FOUND.code;
const CLAIMS_CREATE_ERR_NOT_CLAIMABLE: &str =
    b::claims::create::v0_1::error_codes::NOT_CLAIMABLE.code;
const CLAIMS_CREATE_ERR_SETTINGS_INVALID: &str =
    b::claims::create::v0_1::error_codes::SETTINGS_INVALID.code;
const CLAIMS_LIST_ERR_NOT_FOUND: &str = b::claims::list::v0_1::error_codes::NOT_FOUND.code;
const CLAIMS_LIST_ERR_CURSOR_INVALID: &str =
    b::claims::list::v0_1::error_codes::CURSOR_INVALID.code;
const CLAIMS_WITHDRAW_ERR_BADGES_OFF: &str =
    b::claims::withdraw::v0_1::error_codes::BADGES_OFF.code;
const CLAIMS_WITHDRAW_ERR_NOT_FOUND: &str = b::claims::withdraw::v0_1::error_codes::NOT_FOUND.code;
const REDEEM_ERR_BADGES_OFF: &str = b::claims::redeem::v0_1::error_codes::BADGES_OFF.code;
const REDEEM_ERR_CODE_INVALID: &str = b::claims::redeem::v0_1::error_codes::CODE_INVALID.code;
const REDEEM_ERR_ALREADY_CLAIMED: &str = b::claims::redeem::v0_1::error_codes::ALREADY_CLAIMED.code;
const REDEEM_ERR_ALREADY_HELD: &str = b::claims::redeem::v0_1::error_codes::ALREADY_HELD.code;
const REDEEM_ERR_KEY_HOLDER_UNAVAILABLE: &str =
    b::claims::redeem::v0_1::error_codes::KEY_HOLDER_UNAVAILABLE.code;
const REDEEM_ERR_KEY_HOLDER_REFUSED: &str =
    b::claims::redeem::v0_1::error_codes::KEY_HOLDER_REFUSED.code;
const MINT: &str = "https://trusttasks.org/spec/vta/webvh/dids/create/1.2";
const SIGN_DOCUMENT: &str = "https://trusttasks.org/spec/keys/sign-document/0.1";
const WEBVH_SERVERS_LIST: &str = "https://trusttasks.org/spec/vta/webvh/servers/list/1.0";

// The codes each task declares, by the names the handler module gives them.
const SETTINGS_ERR_INVALID: &str = b::settings::update::v0_1::error_codes::SETTINGS_INVALID.code;
const CREATE_ERR_BADGES_OFF: &str = b::create::v0_1::error_codes::BADGES_OFF.code;
const CREATE_ERR_KIND_NOT_PERMITTED: &str = b::create::v0_1::error_codes::KIND_NOT_PERMITTED.code;
const CREATE_ERR_LIMIT_REACHED: &str = b::create::v0_1::error_codes::LIMIT_REACHED.code;
const CREATE_ERR_IMAGE_NOT_FOUND: &str = b::create::v0_1::error_codes::IMAGE_NOT_FOUND.code;
const CREATE_ERR_SETTINGS_INVALID: &str = b::create::v0_1::error_codes::SETTINGS_INVALID.code;
const CREATE_ERR_RULE_INVALID: &str = b::create::v0_1::error_codes::RULE_INVALID.code;
const CREATE_ERR_OWNER_NOT_ELIGIBLE: &str = b::create::v0_1::error_codes::OWNER_NOT_ELIGIBLE.code;
const CREATE_ERR_NO_KEY_HOLDER: &str = b::create::v0_1::error_codes::NO_KEY_HOLDER.code;
const CREATE_ERR_KEY_HOLDER_UNAVAILABLE: &str =
    b::create::v0_1::error_codes::KEY_HOLDER_UNAVAILABLE.code;
const CREATE_ERR_KEY_HOLDER_REFUSED: &str = b::create::v0_1::error_codes::KEY_HOLDER_REFUSED.code;
const UPDATE_ERR_BADGES_OFF: &str = b::update::v0_1::error_codes::BADGES_OFF.code;
const UPDATE_ERR_BADGE_RETIRED: &str = b::update::v0_1::error_codes::BADGE_RETIRED.code;
const UPDATE_ERR_IMAGE_NOT_FOUND: &str = b::update::v0_1::error_codes::IMAGE_NOT_FOUND.code;
const UPDATE_ERR_SETTINGS_INVALID: &str = b::update::v0_1::error_codes::SETTINGS_INVALID.code;
const RETIRE_ERR_BADGES_OFF: &str = b::retire::v0_1::error_codes::BADGES_OFF.code;
const RETIRE_ERR_ALREADY_RETIRED: &str = b::retire::v0_1::error_codes::ALREADY_RETIRED.code;
const PROMOTE_ERR_BADGES_OFF: &str = b::promote::v0_1::error_codes::BADGES_OFF.code;
const PROMOTE_ERR_BADGE_RETIRED: &str = b::promote::v0_1::error_codes::BADGE_RETIRED.code;
const PROMOTE_ERR_KIND_MISMATCH: &str = b::promote::v0_1::error_codes::KIND_MISMATCH.code;
const PROMOTE_ERR_SETTINGS_INVALID: &str = b::promote::v0_1::error_codes::SETTINGS_INVALID.code;
const PROMOTE_ERR_OWNER_NOT_ELIGIBLE: &str = b::promote::v0_1::error_codes::OWNER_NOT_ELIGIBLE.code;
const PROMOTE_ERR_NO_KEY_HOLDER: &str = b::promote::v0_1::error_codes::NO_KEY_HOLDER.code;
const PROMOTE_ERR_KEY_HOLDER_UNAVAILABLE: &str =
    b::promote::v0_1::error_codes::KEY_HOLDER_UNAVAILABLE.code;
const PROMOTE_ERR_KEY_HOLDER_REFUSED: &str = b::promote::v0_1::error_codes::KEY_HOLDER_REFUSED.code;
const LIST_ERR_CURSOR_INVALID: &str = b::list::v0_1::error_codes::CURSOR_INVALID.code;
const UPLOAD_ERR_BADGES_OFF: &str = b::images::upload::v0_1::error_codes::BADGES_OFF.code;
const UPLOAD_ERR_NOT_MEMBER: &str = b::images::upload::v0_1::error_codes::NOT_MEMBER.code;
const UPLOAD_ERR_TOO_LARGE: &str = b::images::upload::v0_1::error_codes::TOO_LARGE.code;
const UPLOAD_ERR_NOT_AN_IMAGE: &str = b::images::upload::v0_1::error_codes::NOT_AN_IMAGE.code;
const UPLOAD_ERR_RATE_LIMITED: &str = b::images::upload::v0_1::error_codes::RATE_LIMITED.code;
const GET_ERR_NOT_FOUND: &str = b::images::get::v0_1::error_codes::NOT_FOUND.code;
const OFFER_ERR_BADGES_OFF: &str = b::awards::offer::v0_1::error_codes::BADGES_OFF.code;
const OFFER_ERR_BADGE_RETIRED: &str = b::awards::offer::v0_1::error_codes::BADGE_RETIRED.code;
const OFFER_ERR_KIND_MISMATCH: &str = b::awards::offer::v0_1::error_codes::KIND_MISMATCH.code;
const OFFER_ERR_AUTOMATIC_BADGE: &str = b::awards::offer::v0_1::error_codes::AUTOMATIC_BADGE.code;
const OFFER_ERR_GROUP_NOT_VISIBLE: &str =
    b::awards::offer::v0_1::error_codes::GROUP_NOT_VISIBLE.code;
const OFFER_ERR_NOTHING_TO_OFFER: &str = b::awards::offer::v0_1::error_codes::NOTHING_TO_OFFER.code;
const WITHDRAW_ERR_BADGES_OFF: &str = b::awards::withdraw::v0_1::error_codes::BADGES_OFF.code;
const WITHDRAW_ERR_NOT_FOUND: &str = b::awards::withdraw::v0_1::error_codes::NOT_FOUND.code;
const WITHDRAW_ERR_ALREADY_DECIDED: &str =
    b::awards::withdraw::v0_1::error_codes::ALREADY_DECIDED.code;
const REVOKE_ERR_BADGES_OFF: &str = b::awards::revoke::v0_1::error_codes::BADGES_OFF.code;
const REVOKE_ERR_NOT_FOUND: &str = b::awards::revoke::v0_1::error_codes::NOT_FOUND.code;
const REVOKE_ERR_NOT_ACCEPTED: &str = b::awards::revoke::v0_1::error_codes::NOT_ACCEPTED.code;
const REVOKE_ERR_KEY_HOLDER_UNAVAILABLE: &str =
    b::awards::revoke::v0_1::error_codes::KEY_HOLDER_UNAVAILABLE.code;
const REVOKE_ERR_KEY_HOLDER_REFUSED: &str =
    b::awards::revoke::v0_1::error_codes::KEY_HOLDER_REFUSED.code;
const AWARDS_LIST_ERR_NOT_FOUND: &str = b::awards::list::v0_1::error_codes::NOT_FOUND.code;
const AWARDS_LIST_ERR_CURSOR_INVALID: &str =
    b::awards::list::v0_1::error_codes::CURSOR_INVALID.code;
const HOLDERS_ERR_NOT_FOUND: &str = b::holders::list::v0_1::error_codes::NOT_FOUND.code;
const HOLDERS_ERR_CURSOR_INVALID: &str = b::holders::list::v0_1::error_codes::CURSOR_INVALID.code;
const WALL_ERR_NOT_FOUND: &str = b::wall::show::v0_1::error_codes::NOT_FOUND.code;
const ACCEPT_ERR_BADGES_OFF: &str = b::mine::accept::v0_1::error_codes::BADGES_OFF.code;
const ACCEPT_ERR_ALREADY_DECIDED: &str = b::mine::accept::v0_1::error_codes::ALREADY_DECIDED.code;
const ACCEPT_ERR_BADGE_RETIRED: &str = b::mine::accept::v0_1::error_codes::BADGE_RETIRED.code;
const ACCEPT_ERR_KEY_HOLDER_UNAVAILABLE: &str =
    b::mine::accept::v0_1::error_codes::KEY_HOLDER_UNAVAILABLE.code;
const ACCEPT_ERR_KEY_HOLDER_REFUSED: &str =
    b::mine::accept::v0_1::error_codes::KEY_HOLDER_REFUSED.code;
const DECLINE_ERR_BADGES_OFF: &str = b::mine::decline::v0_1::error_codes::BADGES_OFF.code;
const DECLINE_ERR_ALREADY_DECIDED: &str = b::mine::decline::v0_1::error_codes::ALREADY_DECIDED.code;
const HIDE_ERR_BADGES_OFF: &str = b::mine::hide::v0_1::error_codes::BADGES_OFF.code;
const SHOW_AGAIN_ERR_BADGES_OFF: &str = b::mine::show::v0_1::error_codes::BADGES_OFF.code;
const ARRANGE_ERR_BADGES_OFF: &str = b::mine::arrange::v0_1::error_codes::BADGES_OFF.code;
const ARRANGE_ERR_BADGE_NOT_HELD: &str = b::mine::arrange::v0_1::error_codes::BADGE_NOT_HELD.code;
const ARRANGE_ERR_TOO_MANY_PINNED: &str = b::mine::arrange::v0_1::error_codes::TOO_MANY_PINNED.code;
const ARRANGE_ERR_BADGE_HIDDEN: &str = b::mine::arrange::v0_1::error_codes::BADGE_HIDDEN.code;
const KUDOS_ERR_BADGES_OFF: &str = b::kudos::give::v0_1::error_codes::BADGES_OFF.code;
const KUDOS_ERR_KIND_MISMATCH: &str = b::kudos::give::v0_1::error_codes::KIND_MISMATCH.code;
const KUDOS_ERR_SELF_GIVING: &str = b::kudos::give::v0_1::error_codes::SELF_GIVING.code;
const KUDOS_ERR_NOT_ELIGIBLE: &str = b::kudos::give::v0_1::error_codes::NOT_ELIGIBLE.code;
const KUDOS_ERR_LIMIT_REACHED: &str = b::kudos::give::v0_1::error_codes::LIMIT_REACHED.code;
const KUDOS_LIST_ERR_CURSOR_INVALID: &str = b::kudos::list::v0_1::error_codes::CURSOR_INVALID.code;

fn task(name: &str) -> String {
    format!("https://trusttasks.org/spec/vtc/badges/{name}/0.1")
}

/// A refusal's code (`""` for a success).
fn tt_error_code(doc: &Value) -> &str {
    doc.pointer("/payload/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

#[derive(Clone)]
enum Script {
    Silent,
    Refuse(&'static str),
}

#[derive(Default)]
struct VtaState {
    calls: Vec<(String, Value)>,
    scripted: HashMap<String, Script>,
}

#[derive(Clone, Default)]
struct FakeVta(Arc<Mutex<VtaState>>);

impl FakeVta {
    fn script(&self, type_uri: &str, s: Script) {
        self.0
            .lock()
            .unwrap()
            .scripted
            .insert(type_uri.to_string(), s);
    }

    fn calls_of(&self, type_uri: &str) -> Vec<Value> {
        self.0
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(t, _)| t == type_uri)
            .map(|(_, p)| p.clone())
            .collect()
    }
}

fn reply(type_uri: &str, payload: Value) -> TrustTask<Value> {
    serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "threadId": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "issuer": "did:example:community-vta",
        "recipient": TEST_VTC_DID,
        "issuedAt": Utc::now().to_rfc3339(),
        "payload": payload,
    }))
    .unwrap()
}

#[async_trait]
impl VtaChannel for FakeVta {
    async fn exchange(
        &self,
        type_uri: &str,
        payload: &Value,
        _timeout: Duration,
    ) -> Result<TrustTask<Value>, PeerError> {
        let scripted = {
            let mut st = self.0.lock().unwrap();
            st.calls.push((type_uri.to_string(), payload.clone()));
            st.scripted.remove(type_uri)
        };
        match scripted {
            Some(Script::Silent) => {
                return Err(PeerError::Transient("no answer within the timeout".into()));
            }
            Some(Script::Refuse(code)) => {
                return Ok(reply(
                    "https://trusttasks.org/spec/trust-task-error/0.5",
                    json!({ "code": code, "message": "refused by the stand-in" }),
                ));
            }
            None => {}
        }
        let answer = match type_uri {
            MINT => {
                let did = Party::new().did;
                let mut answer = json!({
                    "did": did,
                    "contextId": payload["contextId"],
                    "scid": "QmScid",
                    "portable": true,
                    "signingKeyId": format!("{did}#key-1"),
                    "kaKeyId": format!("{did}#key-2"),
                    "preRotationKeyCount": 0,
                    "createdAt": Utc::now().to_rfc3339(),
                    "serverId": payload["serverId"],
                });
                if payload.get("url").is_some() {
                    answer.as_object_mut().unwrap().remove("serverId");
                    answer["serverless"] = json!(true);
                    answer["logEntry"] = json!(format!("{{\"did\":\"{did}\"}}"));
                }
                answer
            }
            SIGN_DOCUMENT => {
                let mut document = payload["document"].clone();
                document["proof"] = json!({
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "verificationMethod": payload["keyId"],
                    "proofPurpose": "assertionMethod",
                    "created": Utc::now().to_rfc3339(),
                    "proofValue": "z3a4b5c6d7e8f9",
                });
                json!({
                    "proof": document["proof"].clone(),
                    "document": document,
                    "keyId": payload["keyId"],
                    // An Open Badge's issuer is a Profile; a DTG credential's a string.
                    "signerDid": payload["document"]["issuer"]
                        .get("id")
                        .cloned()
                        .unwrap_or(payload["document"]["issuer"].clone()),
                })
            }
            WEBVH_SERVERS_LIST => json!({ "servers": [
                {
                    "id": "hosting", "did": "did:webvh:QmHost:hosting.example.com",
                    "label": "Hosting",
                    "createdAt": "2026-10-01T00:00:00Z", "updatedAt": "2026-10-01T00:00:00Z",
                },
            ] }),
            other => panic!("the stand-in serves no {other}"),
        };
        Ok(reply(&format!("{type_uri}#response"), answer))
    }
}

struct Fixture {
    vtc: TestVtc,
    vta: FakeVta,
    admin: Party,
    member: Party,
    member_entry: String,
}

async fn fixture_with(with_vta: bool) -> Fixture {
    let vta = FakeVta::default();
    let mut builder = TestVtc::builder()
        .vtc_did(TEST_VTC_DID)
        .with_public_url("https://vtc.example.com")
        .with_signers(true)
        .with_audit(true)
        .with_groups(GroupsConfig {
            context: Some("vtc".into()),
            webvh_server: Some("hosting".into()),
            ..Default::default()
        });
    if with_vta {
        builder = builder.with_community_key_holder(Arc::new(vta.clone()));
    }
    let vtc = builder.build().await;
    vtc_service::status_list::ensure_initial(
        &vtc.state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
        "https://vtc.example.com/v1/status-lists/revocation".to_string(),
    )
    .await
    .unwrap();
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    let admin = crate::common::signed::admin(&vtc).await;
    let member = Party::new();
    seed_role(&vtc, &member.did, VtcRole::Member, &[]).await;
    store_member(&vtc.state.members_ks, &Member::fresh(&member.did))
        .await
        .unwrap();
    let member_entry = entry_of(&vtc, &member).await;
    // Badges on, with no tenure so fresh members may give kudos, one pin at most.
    let mut settings = vtc_service::badges::Settings {
        enabled: true,
        ..Default::default()
    };
    settings.limits.min_tenure_days = Some(0);
    settings.limits.max_pinned = Some(1);
    vtc_service::badges::put_settings(&vtc.state.badges_ks, &settings)
        .await
        .unwrap();
    Fixture {
        vtc,
        vta,
        admin,
        member,
        member_entry,
    }
}

async fn fixture() -> Fixture {
    fixture_with(true).await
}

/// `who`'s directory entry, made by reading their own card.
async fn entry_of(vtc: &TestVtc, who: &Party) -> String {
    let (status, doc) = call(
        vtc,
        who,
        "https://trusttasks.org/spec/vtc/directory/card/show/0.1",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    doc["payload"]["card"]["entryId"]
        .as_str()
        .unwrap()
        .to_string()
}

fn png(width: u32, height: u32) -> Vec<u8> {
    let img = image::RgbaImage::from_pixel(width, height, image::Rgba([200, 30, 30, 255]));
    let mut out = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .unwrap();
    out
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A tiny PNG, base64url, as a wallet would upload it. Each call draws a picture of a
/// different size, since a re-encoded digest a badge already holds is nobody's upload.
fn png_b64() -> String {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    b64(&png(16 + n, 8))
}

async fn set_settings(fix: &Fixture, f: impl FnOnce(&mut vtc_service::badges::Settings)) {
    let mut s = vtc_service::badges::settings(&fix.vtc.state.badges_ks)
        .await
        .unwrap();
    f(&mut s);
    vtc_service::badges::put_settings(&fix.vtc.state.badges_ks, &s)
        .await
        .unwrap();
}

impl Fixture {
    async fn as_admin(&self, name: &str, payload: Value) -> (StatusCode, Value) {
        call(&self.vtc, &self.admin, &task(name), payload).await
    }

    async fn as_member(&self, name: &str, payload: Value) -> (StatusCode, Value) {
        call(&self.vtc, &self.member, &task(name), payload).await
    }

    async fn as_party(&self, who: &Party, name: &str, payload: Value) -> (StatusCode, Value) {
        call(&self.vtc, who, &task(name), payload).await
    }

    /// A new active member, with a directory entry.
    async fn another_member(&self) -> (Party, String) {
        let p = Party::new();
        seed_role(&self.vtc, &p.did, VtcRole::Member, &[]).await;
        store_member(&self.vtc.state.members_ks, &Member::fresh(&p.did))
            .await
            .unwrap();
        let entry = entry_of(&self.vtc, &p).await;
        (p, entry)
    }

    /// Upload a picture as `who`: its digest.
    async fn upload(&self, who: &Party) -> String {
        let (status, doc) = self
            .as_party(
                who,
                "images/upload",
                json!({ "mediaType": "image/png", "data": png_b64() }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{doc}");
        doc["payload"]["image"]["sha256"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn community_body(&self, name: &str, sha: &str, repeatable: bool) -> Value {
        json!({
            "kind": "community",
            "name": name,
            "description": "Ran a workshop for the community.",
            "criteria": "Hosted any workshop on the calendar.",
            "image": { "sha256": sha },
            "repeatable": repeatable,
            "requestable": true,
            "reason": "the hosts should wear it",
        })
    }

    /// A community badge the administrator defines: the response payload.
    async fn community_badge(&self, name: &str, repeatable: bool) -> Value {
        let sha = self.upload(&self.admin).await;
        let (status, doc) = self
            .as_admin("create", self.community_body(name, &sha, repeatable))
            .await;
        assert_eq!(status, StatusCode::OK, "{doc}");
        doc["payload"].clone()
    }

    /// A kudos badge `who` makes; its id.
    async fn kudos_badge(&self, who: &Party, name: &str) -> String {
        let sha = self.upload(who).await;
        let (status, doc) = self
            .as_party(
                who,
                "create",
                json!({
                    "kind": "kudos",
                    "name": name,
                    "description": "Found the good clamps.",
                    "image": { "sha256": sha },
                    "reason": "the glue-up",
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{doc}");
        doc["payload"]["badge"]["badgeId"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Offer `badge_id` to `entry`: the award id.
    async fn offer(&self, badge_id: &str, entry: &str) -> String {
        let (status, doc) = self
            .as_admin(
                "awards/offer",
                json!({ "badgeId": badge_id, "to": [entry], "note": "Resin pour workshop" }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{doc}");
        assert_eq!(doc["payload"]["skipped"], json!([]), "{doc}");
        doc["payload"]["awards"][0]["awardId"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Offer and accept as the member: the award id.
    async fn hold(&self, badge_id: &str) -> String {
        let award = self.offer(badge_id, &self.member_entry).await;
        let (status, doc) = self
            .as_member("mine/accept", json!({ "awardId": award }))
            .await;
        assert_eq!(status, StatusCode::OK, "{doc}");
        award
    }

    async fn off(&self) {
        set_settings(self, |s| s.enabled = false).await;
    }

    async fn on(&self) {
        set_settings(self, |s| s.enabled = true).await;
    }
}

// ─── the happy paths ─────────────────────────────────────────────────────

#[tokio::test]
async fn badges_are_off_until_turned_on_and_settings_are_read_by_members() {
    let fix = fixture().await;
    let (status, doc) = fix.as_member("settings/show", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["settings"]["enabled"], true);
    assert_eq!(
        doc["payload"]["settings"]["kudosMakers"]["policy"],
        "members"
    );

    fix.off().await;
    let (_, doc) = fix
        .as_admin("create", fix.community_body("x", &"ab".repeat(32), false))
        .await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_BADGES_OFF, "{doc}");
    let (status, doc) = fix.as_member("list", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["items"], json!([]));
}

#[tokio::test]
async fn an_administrator_defines_a_community_badge_backed_by_a_badge_group() {
    let fix = fixture().await;
    let created = fix.community_badge("Workshop host", true).await;
    let badge = &created["badge"];
    let group = &created["group"];
    assert!(badge["badgeId"].as_str().unwrap().starts_with("bdg_"));
    assert_eq!(badge["kind"], "community");
    assert_eq!(badge["state"], "active");
    assert_eq!(badge["holderCount"], 0);
    assert_eq!(badge["groupId"], group["groupId"]);
    assert_eq!(group["badgeId"], badge["badgeId"]);
    assert_eq!(
        group["joinPolicy"], "request",
        "requestable: members may ask"
    );
    assert_eq!(group["carriesAuthority"], false);
    assert!(group["groupDid"].as_str().unwrap().starts_with("did:"));
    assert_eq!(fix.vta.calls_of(MINT).len(), 1);
    assert_eq!(fix.vta.calls_of(SIGN_DOCUMENT).len(), 1);

    // A badge group is the badge's: never listed among the community's groups
    // (VTI-BDG-012).
    let (status, doc) = call(
        &fix.vtc,
        &fix.member,
        "https://trusttasks.org/spec/vtc/groups/list/0.2",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["items"], json!([]), "{doc}");

    let (status, doc) = fix.as_member("list", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        doc["payload"]["items"][0]["badge"]["badgeId"],
        badge["badgeId"]
    );
    assert_eq!(doc["payload"]["items"][0]["myState"], "none");
    assert_eq!(doc["payload"]["items"][0]["myCount"], 0);
    let (status, doc) = fix
        .as_member("show", json!({ "badgeId": badge["badgeId"] }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["credentialRegime"], "inside");
    assert_eq!(doc["payload"]["owners"], json!([]));
}

#[tokio::test]
async fn an_award_is_an_offer_until_accepted_then_the_group_issues_the_credential() {
    let fix = fixture().await;
    let created = fix.community_badge("Workshop host", true).await;
    let badge_id = created["badge"]["badgeId"].as_str().unwrap().to_string();
    let group_id = created["group"]["groupId"].as_str().unwrap().to_string();
    let signed_before = fix.vta.calls_of(SIGN_DOCUMENT).len();

    let award_id = fix.offer(&badge_id, &fix.member_entry).await;
    // Nothing admitted, nothing issued, nothing on the wall (VTI-BDG-020).
    assert_eq!(fix.vta.calls_of(SIGN_DOCUMENT).len(), signed_before);
    assert!(
        vtc_service::groups::membership(fix.vtc.state.directory.ks(), &group_id, &fix.member_entry)
            .await
            .unwrap()
            .is_none()
    );
    let (status, doc) = fix.as_member("mine/list", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["badges"], json!([]));
    assert_eq!(doc["payload"]["offers"][0]["award"]["awardId"], award_id);
    assert_eq!(
        doc["payload"]["offers"][0]["award"]["note"],
        "Resin pour workshop"
    );
    let (_, doc) = fix.as_member("show", json!({ "badgeId": badge_id })).await;
    assert_eq!(doc["payload"]["myState"], "offered");

    // Accept: the credential is signed as the group — an Open Badge naming the
    // community as creator — and only then the membership recorded (VTI-BDG-021).
    let (status, doc) = fix
        .as_member("mine/accept", json!({ "awardId": award_id }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["award"]["state"], "accepted");
    assert!(doc["payload"]["award"]["credentialId"].is_string());
    assert_eq!(doc["payload"]["badge"]["count"], 1);
    assert_eq!(doc["payload"]["badge"]["hidden"], false);
    // One signature, as the community: it is the credential's issuer (VTI-BDG-060).
    let signed = fix.vta.calls_of(SIGN_DOCUMENT);
    assert_eq!(signed.len(), signed_before + 1);
    let group_did = created["group"]["groupDid"].as_str().unwrap();
    assert!(
        !signed[signed_before]["keyId"]
            .as_str()
            .unwrap()
            .starts_with(group_did),
        "signed as the community, not the group"
    );
    let vc = &signed[signed_before]["document"];
    assert_eq!(
        vc["type"],
        json!(["VerifiableCredential", "OpenBadgeCredential"])
    );
    assert_eq!(vc["issuer"]["id"], TEST_VTC_DID);
    assert_eq!(vc["issuer"]["type"], json!(["Profile"]));
    assert_eq!(
        vc["credentialSchema"][0]["type"],
        "1EdTechJsonSchemaValidator2019"
    );
    assert!(
        vc["credentialSubject"]["achievement"]
            .get("endorsement")
            .is_none()
    );
    assert_eq!(vc["credentialSubject"]["id"], fix.member.did);
    assert_eq!(
        vc["credentialSubject"]["achievement"]["creator"]["id"],
        TEST_VTC_DID
    );
    assert_eq!(
        vc["credentialSubject"]["achievement"]["name"],
        "Workshop host"
    );
    assert_eq!(vc["evidence"].as_array().unwrap().len(), 1);
    assert!(vc.get("credentialStatus").is_none(), "inside regime");
    let m =
        vtc_service::groups::membership(fix.vtc.state.directory.ks(), &group_id, &fix.member_entry)
            .await
            .unwrap()
            .expect("admitted");
    assert_eq!(m.state, "active");
    assert_eq!(
        m.credential_id.as_deref(),
        doc["payload"]["award"]["credentialId"].as_str()
    );

    let (_, doc) = fix
        .as_member("mine/accept", json!({ "awardId": award_id }))
        .await;
    assert_eq!(tt_error_code(&doc), ACCEPT_ERR_ALREADY_DECIDED, "{doc}");
    let (status, doc) = fix
        .as_admin("wall/show", json!({ "entryId": fix.member_entry }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["entries"][0]["badge"]["badgeId"], badge_id);
    assert_eq!(doc["payload"]["entries"][0]["count"], 1);
    let (status, doc) = fix
        .as_admin("holders/list", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["total"], 1);
    assert_eq!(doc["payload"]["items"][0]["entryId"], fix.member_entry);
    // Each holder comes with their fields as the directory projects them for the caller,
    // so a page names them without a second read.
    assert!(
        doc["payload"]["items"][0]["fields"]
            .as_object()
            .is_some_and(|f| !f.is_empty()),
        "the holder's projected fields: {doc}"
    );

    // A repeat award appends evidence and re-issues.
    let again = fix.offer(&badge_id, &fix.member_entry).await;
    let (status, doc) = fix
        .as_member("mine/accept", json!({ "awardId": again }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["badge"]["count"], 2);
    let signed = fix.vta.calls_of(SIGN_DOCUMENT);
    assert_eq!(
        signed.last().unwrap()["document"]["evidence"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn declining_records_nothing_and_withdrawing_closes_the_offer() {
    let fix = fixture().await;
    let created = fix.community_badge("Workshop host", false).await;
    let badge_id = created["badge"]["badgeId"].as_str().unwrap().to_string();
    let group_id = created["group"]["groupId"].as_str().unwrap().to_string();

    let award_id = fix.offer(&badge_id, &fix.member_entry).await;
    let (status, doc) = fix
        .as_member("mine/decline", json!({ "awardId": award_id }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["award"]["state"], "declined");
    assert!(
        vtc_service::groups::membership(fix.vtc.state.directory.ks(), &group_id, &fix.member_entry)
            .await
            .unwrap()
            .is_none()
    );
    let (status, doc) = fix
        .as_admin("awards/list", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["items"][0]["award"]["state"], "declined");
    let second = fix.offer(&badge_id, &fix.member_entry).await;
    let (status, doc) = fix
        .as_admin(
            "awards/withdraw",
            json!({ "awardId": second, "reason": "wrong person" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["award"]["state"], "withdrawn");
    let (_, doc) = fix
        .as_member("mine/accept", json!({ "awardId": second }))
        .await;
    assert_eq!(tt_error_code(&doc), ACCEPT_ERR_ALREADY_DECIDED, "{doc}");

    // A non-repeatable badge is not offered twice to a holder: skipped, not refused.
    fix.hold(&badge_id).await;
    let (_, doc) = fix
        .as_admin(
            "awards/offer",
            json!({ "badgeId": badge_id, "to": [fix.member_entry] }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), OFFER_ERR_NOTHING_TO_OFFER, "{doc}");
    assert_eq!(
        doc["payload"]["details"]["skipped"][0]["reason"],
        "alreadyHolder"
    );
}

#[tokio::test]
async fn hidden_is_portal_only_and_taking_back_ends_the_membership() {
    let fix = fixture().await;
    let created = fix.community_badge("Workshop host", false).await;
    let badge_id = created["badge"]["badgeId"].as_str().unwrap().to_string();
    let group_id = created["group"]["groupId"].as_str().unwrap().to_string();
    let award_id = fix.hold(&badge_id).await;

    let (status, doc) = fix
        .as_member("mine/hide", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["badge"]["hidden"], true);
    let (_, doc) = fix
        .as_admin("wall/show", json!({ "entryId": fix.member_entry }))
        .await;
    assert_eq!(doc["payload"]["entries"], json!([]));
    let (_, doc) = fix
        .as_admin("holders/list", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(doc["payload"]["total"], 0);
    let (_, doc) = fix.as_admin("show", json!({ "badgeId": badge_id })).await;
    assert_eq!(doc["payload"]["badge"]["holderCount"], 0);
    let (_, doc) = fix
        .as_admin("awards/list", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(doc["payload"]["items"][0]["hidden"], true);
    assert_eq!(doc["payload"]["items"][0]["award"]["state"], "accepted");
    assert!(
        vtc_service::groups::membership(fix.vtc.state.directory.ks(), &group_id, &fix.member_entry)
            .await
            .unwrap()
            .is_some()
    );
    let (_, doc) = fix.as_member("mine/list", json!({})).await;
    assert_eq!(doc["payload"]["badges"][0]["hidden"], true);
    let (status, doc) = fix
        .as_member("mine/show", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["badge"]["hidden"], false);

    // Taking the last award back ends the membership (VTI-BDG-023).
    let (status, doc) = fix
        .as_admin(
            "awards/revoke",
            json!({ "awardId": award_id, "reason": "given in error" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["award"]["state"], "revoked");
    assert!(
        vtc_service::groups::membership(fix.vtc.state.directory.ks(), &group_id, &fix.member_entry)
            .await
            .unwrap()
            .is_none()
    );
    let (_, doc) = fix.as_member("mine/list", json!({})).await;
    assert_eq!(doc["payload"]["badges"], json!([]));
}

#[tokio::test]
async fn kudos_are_given_by_any_member_counted_and_bounded() {
    let fix = fixture().await;
    let (giver, _giver_entry) = fix.another_member().await;
    let badge_id = fix.kudos_badge(&fix.member, "Clamp whisperer").await;

    let (_, doc) = fix
        .as_admin(
            "awards/offer",
            json!({ "badgeId": badge_id, "to": [fix.member_entry] }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), OFFER_ERR_KIND_MISMATCH, "{doc}");
    let (_, doc) = fix
        .as_member(
            "kudos/give",
            json!({ "badgeId": badge_id, "to": fix.member_entry }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), KUDOS_ERR_SELF_GIVING, "{doc}");

    let (status, doc) = fix
        .as_party(
            &giver,
            "kudos/give",
            json!({ "badgeId": badge_id, "to": fix.member_entry, "note": "the clamps" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let award_id = doc["payload"]["award"]["awardId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(doc["payload"]["award"]["state"], "offered");
    let signed_before = fix.vta.calls_of(SIGN_DOCUMENT).len();
    let (status, doc) = fix
        .as_member("mine/accept", json!({ "awardId": award_id }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["badge"]["count"], 1);
    assert!(
        doc["payload"]["award"].get("credentialId").is_none(),
        "no credential for kudos"
    );
    assert_eq!(fix.vta.calls_of(SIGN_DOCUMENT).len(), signed_before);

    let (_, doc) = fix
        .as_party(
            &giver,
            "kudos/give",
            json!({ "badgeId": badge_id, "to": fix.member_entry }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), KUDOS_ERR_LIMIT_REACHED, "{doc}");
    assert_eq!(doc["payload"]["details"]["limit"], "sameGiverSameMember");

    let (status, doc) = fix.as_member("kudos/list", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["items"][0]["award"]["note"], "the clamps");
    let (status, doc) = fix
        .as_admin("wall/show", json!({ "entryId": fix.member_entry }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["kudosTotal"], 1);
    assert_eq!(doc["payload"]["entries"][0]["count"], 1);
    let (_, doc) = fix
        .as_party(
            &giver,
            "kudos/list",
            json!({ "badgeId": badge_id, "all": true }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");
    let (status, doc) = fix
        .as_admin("kudos/list", json!({ "badgeId": badge_id, "all": true }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn arranging_the_wall_pins_within_the_limit_and_never_a_hidden_badge() {
    let fix = fixture().await;
    let a = fix.community_badge("A", false).await["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let b = fix.kudos_badge(&fix.member, "B").await;
    let (giver, _) = fix.another_member().await;
    fix.hold(&a).await;
    let (status, doc) = fix
        .as_party(
            &giver,
            "kudos/give",
            json!({ "badgeId": b, "to": fix.member_entry }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let award = doc["payload"]["award"]["awardId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _) = fix
        .as_member("mine/accept", json!({ "awardId": award }))
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, doc) = fix
        .as_member(
            "mine/arrange",
            json!({ "order": [b, a], "pinned": [b], "visibility": "nobody" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["badges"][0]["badge"]["badgeId"], b);
    assert_eq!(doc["payload"]["badges"][0]["pinned"], true);
    assert_eq!(doc["payload"]["visibility"], "nobody");
    // Nobody but the member sees the wall now.
    let (_, doc) = fix
        .as_admin("wall/show", json!({ "entryId": fix.member_entry }))
        .await;
    assert_eq!(tt_error_code(&doc), WALL_ERR_NOT_FOUND, "{doc}");
    let (status, doc) = fix
        .as_member("wall/show", json!({ "entryId": fix.member_entry }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["entries"].as_array().unwrap().len(), 2);

    let (_, doc) = fix
        .as_member(
            "mine/arrange",
            json!({ "pinned": [a, b, "bdg_nope0000000000000"] }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), ARRANGE_ERR_BADGE_NOT_HELD, "{doc}");
    let (_, doc) = fix
        .as_member("mine/arrange", json!({ "pinned": [a, b] }))
        .await;
    assert_eq!(tt_error_code(&doc), ARRANGE_ERR_TOO_MANY_PINNED, "{doc}");
    let (status, _) = fix.as_member("mine/hide", json!({ "badgeId": a })).await;
    assert_eq!(status, StatusCode::OK);
    let (_, doc) = fix
        .as_member("mine/arrange", json!({ "pinned": [a] }))
        .await;
    assert_eq!(tt_error_code(&doc), ARRANGE_ERR_BADGE_HIDDEN, "{doc}");
}

#[tokio::test]
async fn retiring_keeps_the_record_and_deletes_the_group() {
    let fix = fixture().await;
    let created = fix.community_badge("Workshop host", true).await;
    let badge_id = created["badge"]["badgeId"].as_str().unwrap().to_string();
    let group_id = created["group"]["groupId"].as_str().unwrap().to_string();
    fix.hold(&badge_id).await;
    let _open = fix.offer(&badge_id, &fix.member_entry).await;

    // A retire takes the administrator's bound step-up first.
    let chair = GatedAdmin::new(&fix.vtc).await;
    let (_, doc) = call(
        &fix.vtc,
        &chair.requester,
        &task("retire"),
        json!({ "badgeId": badge_id, "reason": "season over" }),
    )
    .await;
    assert!(
        step_up_request(&doc).is_some(),
        "a step-up is asked for: {doc}"
    );
    let (status, doc) = chair
        .call(
            &fix.vtc,
            &task("retire"),
            json!({ "badgeId": badge_id, "reason": "season over" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["badge"]["state"], "retired");
    assert!(
        vtc_service::groups::get(fix.vtc.state.directory.ks(), &group_id)
            .await
            .unwrap()
            .is_none(),
        "the badge group is deleted"
    );
    let (_, doc) = fix.as_member("mine/list", json!({})).await;
    assert_eq!(doc["payload"]["badges"][0]["badge"]["state"], "retired");
    assert_eq!(doc["payload"]["offers"], json!([]));
    let (other, _) = fix.another_member().await;
    let (_, doc) = fix
        .as_party(&other, "show", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(tt_error_code(&doc), "taskFailed", "{doc}");
    assert_eq!(doc["payload"]["details"]["reason"], "not_found", "{doc}");
    // Retiring again is refused.
    let (_, doc) = chair
        .call(
            &fix.vtc,
            &task("retire"),
            json!({ "badgeId": badge_id, "reason": "again" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), RETIRE_ERR_ALREADY_RETIRED, "{doc}");
}

/// The community's revocation list, as the badge credentials' status answers over it.
async fn revocation_list(fix: &Fixture) -> vtc_service::status_list::StatusListState {
    vtc_service::status_list::get_state(
        &fix.vtc.state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
    )
    .await
    .unwrap()
    .unwrap()
}

fn slot_of(vc: &Value) -> usize {
    vc["credentialStatus"]["statusListIndex"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn a_badge_shown_outside_carries_a_status_in_the_communitys_list_and_is_revoked_with_the_award()
 {
    let fix = fixture().await;
    set_settings(&fix, |s| s.credential_valid_days = Some(400)).await;
    let sha = fix.upload(&fix.admin).await;
    let mut body = fix.community_body("Workshop host", &sha, true);
    body["shareableOutside"] = json!(true);
    let (status, doc) = fix.as_admin("create", body).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let created = doc["payload"].clone();
    let badge_id = created["badge"]["badgeId"].as_str().unwrap().to_string();
    let group_did = created["group"]["groupDid"].as_str().unwrap().to_string();
    assert_eq!(created["badge"]["shareableOutside"], true);
    let (_, doc) = fix.as_member("show", json!({ "badgeId": badge_id })).await;
    assert_eq!(doc["payload"]["credentialRegime"], "outside", "{doc}");

    // Accepting signs once, as the community, the credential it issues (VTI-BDG-060), with a
    // status slot in the community's revocation list (VTI-BDG-062).
    let signed_before = fix.vta.calls_of(SIGN_DOCUMENT).len();
    let first = fix.hold(&badge_id).await;
    let signed = fix.vta.calls_of(SIGN_DOCUMENT);
    assert_eq!(signed.len(), signed_before + 1);
    assert_ne!(
        signed[signed_before]["keyId"],
        json!(format!("{group_did}#key-1")),
        "signed as the community, not the group"
    );
    let vc = &signed[signed_before]["document"];
    assert_eq!(vc["issuer"]["id"], TEST_VTC_DID);
    assert_eq!(
        vc["credentialSubject"]["achievement"]["creator"],
        vc["issuer"]
    );
    assert_eq!(vc["credentialStatus"]["type"], "BitstringStatusListEntry");
    assert_eq!(vc["credentialStatus"]["statusPurpose"], "revocation");
    let slot = slot_of(vc);
    let valid_until = chrono::DateTime::parse_from_rfc3339(vc["validUntil"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    let days = (valid_until - Utc::now()).num_days();
    assert!(
        (398..=400).contains(&days),
        "the community's own life: {days} days"
    );
    assert!(!revocation_list(&fix).await.is_set(slot));

    // A repeat award re-issues in the same slot: one signature, as the community.
    let second = fix.offer(&badge_id, &fix.member_entry).await;
    let (status, doc) = fix
        .as_member("mine/accept", json!({ "awardId": second }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let signed = fix.vta.calls_of(SIGN_DOCUMENT);
    assert_eq!(signed.len(), signed_before + 2);
    assert_eq!(slot_of(&signed.last().unwrap()["document"]), slot);

    // Taking one award back re-issues, the bit still clear; taking the last back flips it
    // (VTI-BDG-063).
    let (status, doc) = fix
        .as_admin("awards/revoke", json!({ "awardId": first, "reason": "x" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert!(!revocation_list(&fix).await.is_set(slot));
    assert_eq!(
        slot_of(&fix.vta.calls_of(SIGN_DOCUMENT).last().unwrap()["document"]),
        slot
    );
    let (status, doc) = fix
        .as_admin("awards/revoke", json!({ "awardId": second, "reason": "x" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert!(revocation_list(&fix).await.is_set(slot));

    // Retiring revokes every holder's credential.
    let (other, other_entry) = fix.another_member().await;
    let award = fix.offer(&badge_id, &other_entry).await;
    let (status, doc) = fix
        .as_party(&other, "mine/accept", json!({ "awardId": award }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let other_slot = slot_of(&fix.vta.calls_of(SIGN_DOCUMENT).last().unwrap()["document"]);
    assert_ne!(other_slot, slot);
    assert!(!revocation_list(&fix).await.is_set(other_slot));
    let chair = GatedAdmin::new(&fix.vtc).await;
    let (status, doc) = chair
        .call(
            &fix.vtc,
            &task("retire"),
            json!({ "badgeId": badge_id, "reason": "season over" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert!(revocation_list(&fix).await.is_set(other_slot));

    // A departure revokes what the member still holds outside.
    let sha = fix.upload(&fix.admin).await;
    let mut body = fix.community_body("Year one", &sha, false);
    body["shareableOutside"] = json!(true);
    let (status, doc) = fix.as_admin("create", body).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let year_one = doc["payload"]["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    fix.hold(&year_one).await;
    let held = slot_of(&fix.vta.calls_of(SIGN_DOCUMENT).last().unwrap()["document"]);
    assert!(!revocation_list(&fix).await.is_set(held));
    vtc_service::badges::credential::revoke_departed(&fix.vtc.state, &fix.member_entry)
        .await
        .unwrap();
    assert!(revocation_list(&fix).await.is_set(held));
    // An inside-only badge gets no slot and no status.
    let inside = fix.community_badge("Inside", false).await["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    fix.hold(&inside).await;
    let signed = fix.vta.calls_of(SIGN_DOCUMENT);
    let vc = &signed.last().unwrap()["document"];
    assert!(vc.get("credentialStatus").is_none(), "{vc}");
    assert_eq!(vc["issuer"]["id"], TEST_VTC_DID);
}

#[tokio::test]
async fn settings_change_takes_config_admin_and_a_bound_step_up() {
    let fix = fixture().await;
    let next = json!({
        "enabled": true,
        "kudosMakers": { "policy": "roles", "roles": ["moderator"] },
        "limits": { "kudosPerGiverPerDay": 3, "maxPinned": 1 },
        "showKudosTotals": false,
        "automaticBadges": false,
        "membersMayRequest": false,
    });
    let (_, doc) = fix
        .as_member(
            "settings/update",
            json!({ "settings": next, "reason": "tighter" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");
    let chair = GatedAdmin::new(&fix.vtc).await;
    let (_, doc) = call(
        &fix.vtc,
        &chair.requester,
        &task("settings/update"),
        json!({ "settings": next, "reason": "tighter" }),
    )
    .await;
    assert!(step_up_request(&doc).is_some(), "{doc}");
    // An unknown role is refused before the gesture is spent.
    let mut bad = next.clone();
    bad["kudosMakers"]["roles"] = json!(["no-such-role"]);
    let (_, doc) = chair
        .call(
            &fix.vtc,
            &task("settings/update"),
            json!({ "settings": bad, "reason": "x" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), SETTINGS_ERR_INVALID, "{doc}");
    let (status, doc) = chair
        .call(
            &fix.vtc,
            &task("settings/update"),
            json!({ "settings": next, "reason": "tighter" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["settings"]["limits"]["maxPinned"], 1);
    assert_eq!(doc["payload"]["settings"]["kudosMakers"]["policy"], "roles");
    let sha = fix.upload(&fix.member).await;
    let (_, doc) = fix
        .as_member(
            "create",
            json!({ "kind": "kudos", "name": "x", "description": "x", "image": { "sha256": sha }, "reason": "x" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_KIND_NOT_PERMITTED, "{doc}");
}

// ─── what each task refuses, as its specification declares ───────────────

#[tokio::test]
async fn create_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    // A member may not define a community badge; the digest must be their own upload.
    let (_, doc) = fix
        .as_member("create", fix.community_body("x", &"ab".repeat(32), false))
        .await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_KIND_NOT_PERMITTED, "{doc}");
    let sha = fix.upload(&fix.admin).await;
    let (_, doc) = fix
        .as_member(
            "create",
            json!({ "kind": "kudos", "name": "x", "description": "x", "image": { "sha256": sha }, "reason": "x" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_IMAGE_NOT_FOUND, "{doc}");
    // Settings that do not fit: a kudos badge takes no owners.
    let member_sha = fix.upload(&fix.member).await;
    let (_, doc) = fix
        .as_member(
            "create",
            json!({ "kind": "kudos", "name": "x", "description": "x", "image": { "sha256": member_sha }, "owners": ["dir_AAAAAAAAAAAAAAAA"], "reason": "x" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_SETTINGS_INVALID, "{doc}");
    // An automatic badge's rule reads verified facts only.
    set_settings(&fix, |s| s.automatic_badges = true).await;
    let mut body = fix.community_body("x", &sha, false);
    body["requestable"] = json!(false);
    body["automatic"] =
        json!({ "rule": { "all": [ { "fact": "field", "field": "bio", "op": "exists" } ] } });
    let (_, doc) = fix.as_admin("create", body).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_RULE_INVALID, "{doc}");
    // Owners must be active members.
    let mut body = fix.community_body("x", &sha, false);
    body["owners"] = json!(["dir_AAAAAAAAAAAAAAAA"]);
    let (_, doc) = fix.as_admin("create", body).await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_OWNER_NOT_ELIGIBLE, "{doc}");
    // The key holder: silent, then refusing.
    fix.vta.script(MINT, Script::Silent);
    let (_, doc) = fix
        .as_admin("create", fix.community_body("x", &sha, false))
        .await;
    assert_eq!(
        tt_error_code(&doc),
        CREATE_ERR_KEY_HOLDER_UNAVAILABLE,
        "{doc}"
    );
    fix.vta.script(MINT, Script::Refuse("permissionDenied"));
    let (_, doc) = fix
        .as_admin("create", fix.community_body("x", &sha, false))
        .await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_KEY_HOLDER_REFUSED, "{doc}");
    // A member makes at most the month's allowance of kudos badges.
    set_settings(&fix, |s| {
        s.limits.kudos_badges_per_maker_per_month = Some(1)
    })
    .await;
    fix.kudos_badge(&fix.member, "one").await;
    let sha = fix.upload(&fix.member).await;
    let (_, doc) = fix
        .as_member(
            "create",
            json!({ "kind": "kudos", "name": "two", "description": "x", "image": { "sha256": sha }, "reason": "x" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_LIMIT_REACHED, "{doc}");
    // Off.
    fix.off().await;
    let (_, doc) = fix
        .as_admin("create", fix.community_body("x", &sha, false))
        .await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_BADGES_OFF, "{doc}");
}

#[tokio::test]
async fn create_and_promote_without_a_key_holder_are_refused() {
    let fix = fixture_with(false).await;
    let sha = fix.upload(&fix.admin).await;
    let (_, doc) = fix
        .as_admin("create", fix.community_body("x", &sha, false))
        .await;
    assert_eq!(tt_error_code(&doc), CREATE_ERR_NO_KEY_HOLDER, "{doc}");
    let kudos = fix.kudos_badge(&fix.member, "k").await;
    let (_, doc) = fix
        .as_admin("promote", json!({ "badgeId": kudos, "reason": "x" }))
        .await;
    assert_eq!(tt_error_code(&doc), PROMOTE_ERR_NO_KEY_HOLDER, "{doc}");
}

#[tokio::test]
async fn update_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let created = fix.community_badge("Workshop host", false).await;
    let badge_id = created["badge"]["badgeId"].as_str().unwrap().to_string();
    let (_, doc) = fix
        .as_admin(
            "update",
            json!({ "badgeId": badge_id, "image": { "sha256": "ab".repeat(32) }, "reason": "x" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_IMAGE_NOT_FOUND, "{doc}");
    // A fixed member (`repeatable`) is out of schema, so `malformedRequest`; what does
    // not fit the kind is `settingsInvalid`.
    let kudos = fix.kudos_badge(&fix.member, "K").await;
    let (_, doc) = fix
        .as_member(
            "update",
            json!({ "badgeId": kudos, "holdersVisibleTo": "members", "reason": "x" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_SETTINGS_INVALID, "{doc}");
    let (status, doc) = fix
        .as_admin(
            "update",
            json!({ "badgeId": badge_id, "name": "Workshop lead", "listed": false, "reason": "x" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["badge"]["name"], "Workshop lead");
    assert_eq!(doc["payload"]["badge"]["listed"], false);
    // Retired: no change.
    let chair = GatedAdmin::new(&fix.vtc).await;
    let (status, doc) = chair
        .call(
            &fix.vtc,
            &task("retire"),
            json!({ "badgeId": badge_id, "reason": "x" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = fix
        .as_admin(
            "update",
            json!({ "badgeId": badge_id, "name": "x", "reason": "x" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_BADGE_RETIRED, "{doc}");
    fix.off().await;
    let (_, doc) = fix
        .as_admin(
            "update",
            json!({ "badgeId": badge_id, "name": "x", "reason": "x" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), UPDATE_ERR_BADGES_OFF, "{doc}");
    let (_, doc) = fix
        .as_admin("retire", json!({ "badgeId": badge_id, "reason": "x" }))
        .await;
    assert_eq!(tt_error_code(&doc), RETIRE_ERR_BADGES_OFF, "{doc}");
}

#[tokio::test]
async fn promote_refuses_what_its_specification_declares_then_offers_every_holder() {
    let fix = fixture().await;
    let community = fix.community_badge("A", false).await["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, doc) = fix
        .as_admin("promote", json!({ "badgeId": community, "reason": "x" }))
        .await;
    assert_eq!(tt_error_code(&doc), PROMOTE_ERR_KIND_MISMATCH, "{doc}");
    let kudos = fix.kudos_badge(&fix.member, "K").await;
    let (giver, _) = fix.another_member().await;
    let (_, doc) = fix
        .as_party(
            &giver,
            "kudos/give",
            json!({ "badgeId": kudos, "to": fix.member_entry }),
        )
        .await;
    let award = doc["payload"]["award"]["awardId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _) = fix
        .as_member("mine/accept", json!({ "awardId": award }))
        .await;
    assert_eq!(status, StatusCode::OK);
    // Asking for it while the community lets nobody ask.
    set_settings(&fix, |s| s.members_may_request = false).await;
    let (_, doc) = fix
        .as_admin(
            "promote",
            json!({ "badgeId": kudos, "requestable": true, "reason": "x" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), PROMOTE_ERR_SETTINGS_INVALID, "{doc}");
    set_settings(&fix, |s| s.members_may_request = true).await;
    let (_, doc) = fix
        .as_admin(
            "promote",
            json!({ "badgeId": kudos, "owners": ["dir_AAAAAAAAAAAAAAAA"], "reason": "x" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), PROMOTE_ERR_OWNER_NOT_ELIGIBLE, "{doc}");
    fix.vta.script(MINT, Script::Silent);
    let (_, doc) = fix
        .as_admin("promote", json!({ "badgeId": kudos, "reason": "x" }))
        .await;
    assert_eq!(
        tt_error_code(&doc),
        PROMOTE_ERR_KEY_HOLDER_UNAVAILABLE,
        "{doc}"
    );
    fix.vta.script(MINT, Script::Refuse("permissionDenied"));
    let (_, doc) = fix
        .as_admin("promote", json!({ "badgeId": kudos, "reason": "x" }))
        .await;
    assert_eq!(tt_error_code(&doc), PROMOTE_ERR_KEY_HOLDER_REFUSED, "{doc}");
    // Promoted: the group exists, every holder is offered, nothing issued yet.
    let signed_before = fix.vta.calls_of(SIGN_DOCUMENT).len();
    let (status, doc) = fix
        .as_admin(
            "promote",
            json!({ "badgeId": kudos, "requestable": true, "reason": "x" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["badge"]["kind"], "community");
    assert_eq!(doc["payload"]["group"]["badgeId"], kudos);
    assert_eq!(doc["payload"]["holdersOffered"], 1);
    // The community's authority to the new group, and nothing for the holder yet.
    assert_eq!(fix.vta.calls_of(SIGN_DOCUMENT).len(), signed_before + 1);
    let (_, doc) = fix.as_member("mine/list", json!({})).await;
    assert_eq!(doc["payload"]["offers"][0]["badge"]["badgeId"], kudos);
    assert_eq!(
        doc["payload"]["badges"][0]["count"], 1,
        "the kudos award still counts"
    );
    // Promoted or retired, it is not promoted again.
    let (_, doc) = fix
        .as_admin("promote", json!({ "badgeId": kudos, "reason": "x" }))
        .await;
    assert_eq!(tt_error_code(&doc), PROMOTE_ERR_KIND_MISMATCH, "{doc}");
    let other = fix.kudos_badge(&fix.member, "K2").await;
    let (status, _) = fix
        .as_member("retire", json!({ "badgeId": other, "reason": "x" }))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, doc) = fix
        .as_admin("promote", json!({ "badgeId": other, "reason": "x" }))
        .await;
    assert_eq!(tt_error_code(&doc), PROMOTE_ERR_BADGE_RETIRED, "{doc}");
    fix.off().await;
    let (_, doc) = fix
        .as_admin("promote", json!({ "badgeId": other, "reason": "x" }))
        .await;
    assert_eq!(tt_error_code(&doc), PROMOTE_ERR_BADGES_OFF, "{doc}");
}

#[tokio::test]
async fn the_reads_refuse_foreign_cursors_and_what_the_caller_may_not_see() {
    let fix = fixture().await;
    let badge_id = fix.community_badge("A", false).await["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let bad = json!({ "cursor": "7.notthemac" });
    let (_, doc) = fix.as_member("list", bad.clone()).await;
    assert_eq!(tt_error_code(&doc), LIST_ERR_CURSOR_INVALID, "{doc}");
    let (_, doc) = fix.as_member("kudos/list", bad.clone()).await;
    assert_eq!(tt_error_code(&doc), KUDOS_LIST_ERR_CURSOR_INVALID, "{doc}");
    let mut with_badge = bad.clone();
    with_badge["badgeId"] = json!(badge_id);
    let (_, doc) = fix.as_admin("awards/list", with_badge.clone()).await;
    assert_eq!(tt_error_code(&doc), AWARDS_LIST_ERR_CURSOR_INVALID, "{doc}");
    let (_, doc) = fix.as_member("holders/list", with_badge).await;
    assert_eq!(tt_error_code(&doc), HOLDERS_ERR_CURSOR_INVALID, "{doc}");
    // A member owns no badge: the owners' list is not theirs.
    let (_, doc) = fix
        .as_member("awards/list", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(tt_error_code(&doc), AWARDS_LIST_ERR_NOT_FOUND, "{doc}");
    // Holders shown to administrators only: a member sees none.
    let (status, _) = fix
        .as_admin(
            "update",
            json!({ "badgeId": badge_id, "holdersVisibleTo": "admins", "reason": "x" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, doc) = fix
        .as_member("holders/list", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(tt_error_code(&doc), HOLDERS_ERR_NOT_FOUND, "{doc}");
    // A picture is read only of a badge the caller may see.
    let (_, doc) = fix
        .as_member(
            "images/get",
            json!({ "badgeId": "bdg_AAAAAAAAAAAAAAAAAAAAAA" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), GET_ERR_NOT_FOUND, "{doc}");
    let (status, doc) = fix
        .as_member("images/get", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["image"]["mediaType"], "image/jpeg");
    let (_, doc) = fix
        .as_member(
            "images/get",
            json!({ "badgeId": badge_id, "sha256": "ab".repeat(32) }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), GET_ERR_NOT_FOUND, "{doc}");
    // A wall of an entry the directory does not show.
    let (_, doc) = fix
        .as_member("wall/show", json!({ "entryId": "dir_AAAAAAAAAAAAAAAA" }))
        .await;
    assert_eq!(tt_error_code(&doc), WALL_ERR_NOT_FOUND, "{doc}");
}

#[tokio::test]
async fn images_upload_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let stranger = Party::new();
    let (_, doc) = fix
        .as_party(
            &stranger,
            "images/upload",
            json!({ "mediaType": "image/png", "data": png_b64() }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), UPLOAD_ERR_NOT_MEMBER, "{doc}");
    let (_, doc) = fix
        .as_member(
            "images/upload",
            json!({ "mediaType": "image/png", "data": b64(b"definitely not a png") }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), UPLOAD_ERR_NOT_AN_IMAGE, "{doc}");
    let (_, doc) = fix
        .as_member(
            "images/upload",
            json!({ "mediaType": "image/png", "data": b64(&png(9000, 1)) }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), UPLOAD_ERR_TOO_LARGE, "{doc}");
    let mut limited = None;
    for _ in 0..40 {
        let (_, doc) = fix
            .as_member(
                "images/upload",
                json!({ "mediaType": "image/png", "data": png_b64() }),
            )
            .await;
        if tt_error_code(&doc) == UPLOAD_ERR_RATE_LIMITED {
            limited = Some(doc);
            break;
        }
    }
    let limited = limited.expect("the hourly bound refuses");
    assert_eq!(
        tt_error_code(&limited),
        UPLOAD_ERR_RATE_LIMITED,
        "{limited}"
    );
    fix.off().await;
    let (_, doc) = fix
        .as_admin(
            "images/upload",
            json!({ "mediaType": "image/png", "data": png_b64() }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), UPLOAD_ERR_BADGES_OFF, "{doc}");
}

#[tokio::test]
async fn offer_refuses_what_its_specification_declares() {
    let fix = fixture().await;
    let created = fix.community_badge("A", false).await;
    let badge_id = created["badge"]["badgeId"].as_str().unwrap().to_string();
    let (_, doc) = fix
        .as_admin(
            "awards/offer",
            json!({ "badgeId": badge_id, "group": "grp_AAAAAAAAAAAAAAAAAAAAAA" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), OFFER_ERR_GROUP_NOT_VISIBLE, "{doc}");
    // An automatic badge is given by its rule.
    set_settings(&fix, |s| s.automatic_badges = true).await;
    let sha = fix.upload(&fix.admin).await;
    let mut body = fix.community_body("Veteran", &sha, false);
    body["requestable"] = json!(false);
    body["automatic"] = json!({ "rule": { "all": [ { "fact": "joinedAt", "op": "before", "value": "2000-01-01T00:00:00Z" } ] } });
    let (status, doc) = fix.as_admin("create", body).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let auto_id = doc["payload"]["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(doc["payload"]["group"]["kind"], "dynamic");
    let (_, doc) = fix
        .as_admin(
            "awards/offer",
            json!({ "badgeId": auto_id, "to": [fix.member_entry] }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), OFFER_ERR_AUTOMATIC_BADGE, "{doc}");
    // Retired, then off.
    let chair = GatedAdmin::new(&fix.vtc).await;
    let (status, _) = chair
        .call(
            &fix.vtc,
            &task("retire"),
            json!({ "badgeId": badge_id, "reason": "x" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, doc) = fix
        .as_admin(
            "awards/offer",
            json!({ "badgeId": badge_id, "to": [fix.member_entry] }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), OFFER_ERR_BADGE_RETIRED, "{doc}");
    fix.off().await;
    let (_, doc) = fix
        .as_admin(
            "awards/offer",
            json!({ "badgeId": badge_id, "to": [fix.member_entry] }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), OFFER_ERR_BADGES_OFF, "{doc}");
}

#[tokio::test]
async fn withdraw_and_revoke_refuse_what_their_specifications_declare() {
    let fix = fixture().await;
    let created = fix.community_badge("A", true).await;
    let badge_id = created["badge"]["badgeId"].as_str().unwrap().to_string();
    let first = fix.hold(&badge_id).await;
    let open = fix.offer(&badge_id, &fix.member_entry).await;
    let unknown = json!({ "awardId": "awd_AAAAAAAAAAAAAAAAAAAAAA", "reason": "x" });
    let (_, doc) = fix.as_admin("awards/withdraw", unknown.clone()).await;
    assert_eq!(tt_error_code(&doc), WITHDRAW_ERR_NOT_FOUND, "{doc}");
    let (_, doc) = fix.as_admin("awards/revoke", unknown).await;
    assert_eq!(tt_error_code(&doc), REVOKE_ERR_NOT_FOUND, "{doc}");
    // An accepted award is not withdrawn; an open offer is not taken back.
    let (_, doc) = fix
        .as_admin(
            "awards/withdraw",
            json!({ "awardId": first, "reason": "x" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), WITHDRAW_ERR_ALREADY_DECIDED, "{doc}");
    let (_, doc) = fix
        .as_admin("awards/revoke", json!({ "awardId": open, "reason": "x" }))
        .await;
    assert_eq!(tt_error_code(&doc), REVOKE_ERR_NOT_ACCEPTED, "{doc}");
    // A member who is not an owner sees neither award.
    let (_, doc) = fix
        .as_member("awards/withdraw", json!({ "awardId": open, "reason": "x" }))
        .await;
    assert_eq!(tt_error_code(&doc), WITHDRAW_ERR_NOT_FOUND, "{doc}");
    // Taking back one of two awards re-issues the credential as the group; the key
    // holder silent, then refusing, leaves the award accepted.
    let (status, _) = fix
        .as_member("mine/accept", json!({ "awardId": open }))
        .await;
    assert_eq!(status, StatusCode::OK);
    fix.vta.script(SIGN_DOCUMENT, Script::Silent);
    let (_, doc) = fix
        .as_admin("awards/revoke", json!({ "awardId": first, "reason": "x" }))
        .await;
    assert_eq!(
        tt_error_code(&doc),
        REVOKE_ERR_KEY_HOLDER_UNAVAILABLE,
        "{doc}"
    );
    let second = fix.offer(&badge_id, &fix.member_entry).await;
    let (status, _) = fix
        .as_member("mine/accept", json!({ "awardId": second }))
        .await;
    assert_eq!(status, StatusCode::OK);
    fix.vta
        .script(SIGN_DOCUMENT, Script::Refuse("permissionDenied"));
    let (_, doc) = fix
        .as_admin("awards/revoke", json!({ "awardId": second, "reason": "x" }))
        .await;
    assert_eq!(tt_error_code(&doc), REVOKE_ERR_KEY_HOLDER_REFUSED, "{doc}");
    fix.off().await;
    let (_, doc) = fix
        .as_admin("awards/withdraw", json!({ "awardId": open, "reason": "x" }))
        .await;
    assert_eq!(tt_error_code(&doc), WITHDRAW_ERR_BADGES_OFF, "{doc}");
    let (_, doc) = fix
        .as_admin("awards/revoke", json!({ "awardId": second, "reason": "x" }))
        .await;
    assert_eq!(tt_error_code(&doc), REVOKE_ERR_BADGES_OFF, "{doc}");
}

#[tokio::test]
async fn the_holders_tasks_refuse_what_their_specifications_declare() {
    let fix = fixture().await;
    let created = fix.community_badge("A", true).await;
    let badge_id = created["badge"]["badgeId"].as_str().unwrap().to_string();
    let held = fix.hold(&badge_id).await;
    let offer = fix.offer(&badge_id, &fix.member_entry).await;
    // Accept: the key holder silent, then refusing, leaves the offer open.
    fix.vta.script(SIGN_DOCUMENT, Script::Silent);
    let (_, doc) = fix
        .as_member("mine/accept", json!({ "awardId": offer }))
        .await;
    assert_eq!(
        tt_error_code(&doc),
        ACCEPT_ERR_KEY_HOLDER_UNAVAILABLE,
        "{doc}"
    );
    fix.vta
        .script(SIGN_DOCUMENT, Script::Refuse("permissionDenied"));
    let (_, doc) = fix
        .as_member("mine/accept", json!({ "awardId": offer }))
        .await;
    assert_eq!(tt_error_code(&doc), ACCEPT_ERR_KEY_HOLDER_REFUSED, "{doc}");
    let (_, doc) = fix
        .as_member("mine/decline", json!({ "awardId": held }))
        .await;
    assert_eq!(tt_error_code(&doc), DECLINE_ERR_ALREADY_DECIDED, "{doc}");
    // A retired badge whose offer was still open: accept names the retirement.
    let kudos = fix.kudos_badge(&fix.member, "K").await;
    let (giver, _) = fix.another_member().await;
    let (_, doc) = fix
        .as_party(
            &giver,
            "kudos/give",
            json!({ "badgeId": kudos, "to": fix.member_entry }),
        )
        .await;
    let kudos_award = doc["payload"]["award"]["awardId"]
        .as_str()
        .unwrap()
        .to_string();
    let mut badge = vtc_service::badges::get_badge(&fix.vtc.state.badges_ks, &kudos)
        .await
        .unwrap()
        .unwrap();
    badge.state = vtc_service::badges::BadgeState::Retired;
    vtc_service::badges::put_badge(&fix.vtc.state.badges_ks, &badge)
        .await
        .unwrap();
    let (_, doc) = fix
        .as_member("mine/accept", json!({ "awardId": kudos_award }))
        .await;
    assert_eq!(tt_error_code(&doc), ACCEPT_ERR_BADGE_RETIRED, "{doc}");
    // Off: every act of the holder's.
    fix.off().await;
    let (_, doc) = fix
        .as_member("mine/accept", json!({ "awardId": offer }))
        .await;
    assert_eq!(tt_error_code(&doc), ACCEPT_ERR_BADGES_OFF, "{doc}");
    let (_, doc) = fix
        .as_member("mine/decline", json!({ "awardId": offer }))
        .await;
    assert_eq!(tt_error_code(&doc), DECLINE_ERR_BADGES_OFF, "{doc}");
    let (_, doc) = fix
        .as_member("mine/hide", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(tt_error_code(&doc), HIDE_ERR_BADGES_OFF, "{doc}");
    let (_, doc) = fix
        .as_member("mine/show", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(tt_error_code(&doc), SHOW_AGAIN_ERR_BADGES_OFF, "{doc}");
    let (_, doc) = fix
        .as_member("mine/arrange", json!({ "visibility": "nobody" }))
        .await;
    assert_eq!(tt_error_code(&doc), ARRANGE_ERR_BADGES_OFF, "{doc}");
    let (_, doc) = fix
        .as_member(
            "kudos/give",
            json!({ "badgeId": kudos, "to": fix.member_entry }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), KUDOS_ERR_BADGES_OFF, "{doc}");
    fix.on().await;
}

#[tokio::test]
async fn kudos_give_refuses_a_member_too_new_to_give() {
    let fix = fixture().await;
    let kudos = fix.kudos_badge(&fix.member, "K").await;
    set_settings(&fix, |s| s.limits.min_tenure_days = Some(30)).await;
    let (giver, _) = fix.another_member().await;
    let (_, doc) = fix
        .as_party(
            &giver,
            "kudos/give",
            json!({ "badgeId": kudos, "to": fix.member_entry }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), KUDOS_ERR_NOT_ELIGIBLE, "{doc}");
    assert!(
        doc["payload"]["details"]["eligibleFrom"].is_string(),
        "{doc}"
    );
    // The daily allowance, once the member is old enough.
    set_settings(&fix, |s| {
        s.limits.min_tenure_days = Some(0);
        s.limits.kudos_per_giver_per_day = Some(1);
        s.limits.same_giver_same_member = Some("unbounded".into());
    })
    .await;
    let (status, _) = fix
        .as_party(
            &giver,
            "kudos/give",
            json!({ "badgeId": kudos, "to": fix.member_entry }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, doc) = fix
        .as_party(
            &giver,
            "kudos/give",
            json!({ "badgeId": kudos, "to": fix.member_entry }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), KUDOS_ERR_LIMIT_REACHED, "{doc}");
    assert_eq!(doc["payload"]["details"]["limit"], "kudosPerGiverPerDay");
    let community = fix.community_badge("C", false).await["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, doc) = fix
        .as_party(
            &giver,
            "kudos/give",
            json!({ "badgeId": community, "to": fix.member_entry }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), KUDOS_ERR_KIND_MISMATCH, "{doc}");
}

#[tokio::test]
async fn the_public_artefacts_of_a_badge_shown_outside_are_served_and_an_inside_badge_is_not() {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let fix = fixture().await;
    let sha = fix.upload(&fix.admin).await;
    let mut body = fix.community_body("Workshop host", &sha, false);
    body["shareableOutside"] = json!(true);
    let (status, doc) = fix.as_admin("create", body).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let outside = doc["payload"]["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let inside = fix.community_badge("Inside", false).await["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let get = |path: String| {
        let router = fix.vtc.router.clone();
        async move {
            let res = router
                .oneshot(axum::http::Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = res.status();
            let media = res
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let bytes = res.into_body().collect().await.unwrap().to_bytes();
            (status, media, bytes)
        }
    };
    // The Achievement document, at the location the credential names (VTI-BDG-051).
    let (status, media, bytes) = get(format!("/badges/{outside}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(media.starts_with("application/ld+json"), "{media}");
    let achievement: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        achievement["id"],
        format!("https://vtc.example.com/badges/{outside}")
    );
    assert_eq!(achievement["name"], "Workshop host");
    assert_eq!(achievement["creator"]["id"], TEST_VTC_DID);
    assert_eq!(
        achievement["image"]["id"],
        format!("https://vtc.example.com/badges/{outside}/image")
    );
    assert!(achievement.get("holders").is_none() && achievement.get("holderCount").is_none());
    // The picture, the community's own re-encoding.
    let (status, media, bytes) = get(format!("/badges/{outside}/image")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(media, "image/jpeg");
    assert!(!bytes.is_empty());
    // A badge kept inside answers as one that does not exist (VTI-BDG-050).
    let (status, _, _) = get(format!("/badges/{inside}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = get(format!("/badges/{inside}/image")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = get("/badges/bdg_NoSuchBadge0000000000".to_string()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // The credential of the badge shown outside names the public picture; an inside
    // badge's names it by digest.
    fix.hold(&outside).await;
    let signed = fix.vta.calls_of(SIGN_DOCUMENT);
    let vc = &signed.last().unwrap()["document"];
    assert_eq!(
        vc["credentialSubject"]["achievement"]["image"]["id"],
        format!("https://vtc.example.com/badges/{outside}/image")
    );
    fix.hold(&inside).await;
    let signed = fix.vta.calls_of(SIGN_DOCUMENT);
    let vc = &signed.last().unwrap()["document"];
    assert!(
        vc["credentialSubject"]["achievement"]["image"]["id"]
            .as_str()
            .unwrap()
            .starts_with("urn:sha256:"),
        "{vc}"
    );
}

/// The path of a public location under the test community's origin.
fn path_of(url: &str) -> String {
    url.strip_prefix("https://vtc.example.com")
        .expect("under the public origin")
        .to_string()
}

async fn get_public(
    fix: &Fixture,
    path: &str,
    accept: Option<&str>,
) -> (StatusCode, String, Vec<u8>) {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let mut req = axum::http::Request::get(path);
    if let Some(a) = accept {
        req = req.header(axum::http::header::ACCEPT, a);
    }
    let res = fix
        .vtc
        .router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let media = res
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, media, bytes)
}

/// VTI-BDG-070 / 071: a holder shares an accepted award of a badge shown outside; the
/// community serves the credential exactly as issued, a page verifying it and the picture
/// with it baked in, at unguessable locations that answer nothing once the share stops,
/// the award is taken back or the badge retired.
#[tokio::test]
async fn a_holder_shares_an_award_outside_and_the_locations_stop_with_the_share() {
    let fix = fixture().await;
    let sha = fix.upload(&fix.admin).await;
    let mut body = fix.community_body("Workshop host", &sha, true);
    body["shareableOutside"] = json!(true);
    let (status, doc) = fix.as_admin("create", body).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let badge_id = doc["payload"]["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let award = fix.hold(&badge_id).await;
    let issued = fix.vta.calls_of(SIGN_DOCUMENT).last().unwrap()["document"].clone();

    let (status, doc) = fix
        .as_member("awards/share", json!({ "awardId": award }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let shared = doc["payload"]["award"]["shared"].clone();
    let verification = shared["verificationUrl"].as_str().unwrap().to_string();
    let baked = shared["bakedImageUrl"].as_str().unwrap().to_string();
    assert!(shared["since"].is_string(), "{doc}");
    assert!(
        !verification.contains(&award) && !verification.contains(&badge_id),
        "the location is derived from nothing: {verification}"
    );
    assert!(verification.starts_with("https://vtc.example.com/badges/shared/"));
    assert_eq!(baked, format!("{verification}/image.png"));
    assert!(doc["payload"]["award"].get("token").is_none());

    // `show` answers the holder their own awards, the share with them; another member none.
    let (_, doc) = fix.as_member("show", json!({ "badgeId": badge_id })).await;
    let mine = doc["payload"]["myAwards"].as_array().expect("myAwards");
    assert_eq!(mine.len(), 1, "{doc}");
    assert_eq!(mine[0]["awardId"], award.as_str());
    assert_eq!(mine[0]["shared"]["verificationUrl"], verification);
    let (other, _) = fix.another_member().await;
    let (_, doc) = fix
        .as_party(&other, "show", json!({ "badgeId": badge_id }))
        .await;
    assert!(doc["payload"].get("myAwards").is_none(), "{doc}");

    // A share already in force answers its own locations.
    let (_, doc) = fix
        .as_member("awards/share", json!({ "awardId": award }))
        .await;
    assert_eq!(
        doc["payload"]["award"]["shared"]["verificationUrl"],
        verification
    );

    // A verifier gets the credential exactly as issued.
    let (status, media, bytes) = get_public(&fix, &path_of(&verification), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(media.starts_with("application/vc+ld+json"), "{media}");
    let served: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(served["id"], issued["id"]);
    assert_eq!(served["credentialStatus"], issued["credentialStatus"]);
    // A person gets a page verifying it, naming no other holder (VTI-BDG-071).
    let (status, media, bytes) = get_public(&fix, &path_of(&verification), Some("text/html")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(media.starts_with("text/html"), "{media}");
    let html = String::from_utf8(bytes).unwrap();
    assert!(html.contains("Workshop host"), "{html}");
    assert!(html.contains("Verified"), "{html}");
    // The picture with the credential baked in.
    let (status, media, bytes) = get_public(&fix, &path_of(&baked), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(media, "image/png");
    let reader = png::Decoder::new(std::io::Cursor::new(&bytes))
        .read_info()
        .unwrap();
    let chunk = reader
        .info()
        .utf8_text
        .iter()
        .find(|c| c.keyword == "openbadgecredential")
        .expect("baked");
    let baked_vc: Value = serde_json::from_str(&chunk.get_text().unwrap()).unwrap();
    assert_eq!(baked_vc["id"], issued["id"]);

    // Stopping: the locations answer as ones that never existed; sharing again answers
    // new ones.
    let (status, doc) = fix
        .as_member("awards/unshare", json!({ "awardId": award }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert!(doc["payload"]["award"].get("shared").is_none(), "{doc}");
    let (status, _, _) = get_public(&fix, &path_of(&verification), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = get_public(&fix, &path_of(&baked), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, doc) = fix
        .as_member("awards/unshare", json!({ "awardId": award }))
        .await;
    assert!(
        doc["payload"]["award"].get("shared").is_none(),
        "idempotent: {doc}"
    );
    let (_, doc) = fix
        .as_member("awards/share", json!({ "awardId": award }))
        .await;
    let again = doc["payload"]["award"]["shared"]["verificationUrl"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(again, verification);
    let (status, _, _) = get_public(&fix, &path_of(&again), None).await;
    assert_eq!(status, StatusCode::OK);

    // Taken back: the share ends with it.
    let (status, doc) = fix
        .as_admin("awards/revoke", json!({ "awardId": award, "reason": "x" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert!(doc["payload"]["award"].get("shared").is_none(), "{doc}");
    let (status, _, _) = get_public(&fix, &path_of(&again), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Retired: every share of the badge ends.
    let award = fix.hold(&badge_id).await;
    let (_, doc) = fix
        .as_member("awards/share", json!({ "awardId": award }))
        .await;
    let last = doc["payload"]["award"]["shared"]["verificationUrl"]
        .as_str()
        .unwrap()
        .to_string();
    let chair = GatedAdmin::new(&fix.vtc).await;
    let (status, doc) = chair
        .call(
            &fix.vtc,
            &task("retire"),
            json!({ "badgeId": badge_id, "reason": "season over" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (status, _, _) = get_public(&fix, &path_of(&last), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let a = vtc_service::badges::get_award(&fix.vtc.state.badges_ks, &award)
        .await
        .unwrap()
        .unwrap();
    assert!(a.shared.is_none());
}

/// A holder whose credential was issued before the community kept one to serve is issued
/// it again when they first share.
#[tokio::test]
async fn sharing_an_award_whose_credential_was_not_kept_issues_it_again() {
    let fix = fixture().await;
    let sha = fix.upload(&fix.admin).await;
    let mut body = fix.community_body("Workshop host", &sha, true);
    body["shareableOutside"] = json!(true);
    let (_, doc) = fix.as_admin("create", body).await;
    let badge_id = doc["payload"]["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let award = fix.hold(&badge_id).await;
    fix.vtc
        .state
        .badges_ks
        .remove(format!("bcred:{badge_id}:{}", fix.member_entry).into_bytes())
        .await
        .unwrap();
    let signed_before = fix.vta.calls_of(SIGN_DOCUMENT).len();
    let (status, doc) = fix
        .as_member("awards/share", json!({ "awardId": award }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(fix.vta.calls_of(SIGN_DOCUMENT).len(), signed_before + 1);
    let issued = fix.vta.calls_of(SIGN_DOCUMENT).last().unwrap()["document"].clone();
    let url = doc["payload"]["award"]["shared"]["verificationUrl"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _, bytes) = get_public(&fix, &path_of(&url), None).await;
    assert_eq!(status, StatusCode::OK);
    let served: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(served["id"], issued["id"]);
    assert_eq!(doc["payload"]["award"]["credentialId"], issued["id"]);
}

#[tokio::test]
async fn share_and_unshare_refuse_what_their_specifications_declare() {
    let fix = fixture().await;
    // An award kept inside the community.
    let inside = fix.community_badge("Inside", false).await["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let inside_award = fix.hold(&inside).await;
    let (_, doc) = fix
        .as_member("awards/share", json!({ "awardId": inside_award }))
        .await;
    assert_eq!(tt_error_code(&doc), SHARE_ERR_NOT_SHAREABLE, "{doc}");
    assert_eq!(doc["payload"]["details"]["reason"], "insideOnly", "{doc}");

    // A kudos badge.
    let (giver, _) = fix.another_member().await;
    let kudos = fix.kudos_badge(&giver, "Clamp whisperer").await;
    let (_, doc) = fix
        .as_party(
            &giver,
            "kudos/give",
            json!({ "badgeId": kudos, "to": fix.member_entry }),
        )
        .await;
    let kudos_award = doc["payload"]["award"]["awardId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, doc) = fix
        .as_member("mine/accept", json!({ "awardId": kudos_award }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = fix
        .as_member("awards/share", json!({ "awardId": kudos_award }))
        .await;
    assert_eq!(tt_error_code(&doc), SHARE_ERR_NOT_SHAREABLE, "{doc}");
    assert_eq!(doc["payload"]["details"]["reason"], "kudos", "{doc}");

    // Another member's award, an open offer and an unknown one answer alike.
    let sha = fix.upload(&fix.admin).await;
    let mut body = fix.community_body("Outside", &sha, true);
    body["shareableOutside"] = json!(true);
    let (_, doc) = fix.as_admin("create", body).await;
    let outside = doc["payload"]["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let held = fix.hold(&outside).await;
    let open = fix.offer(&outside, &fix.member_entry).await;
    for id in [held.as_str(), open.as_str(), "awd_NoSuchAward000000"] {
        let who = if id == held { &giver } else { &fix.member };
        let (_, doc) = fix
            .as_party(who, "awards/share", json!({ "awardId": id }))
            .await;
        assert_eq!(tt_error_code(&doc), SHARE_ERR_NOT_FOUND, "{id}: {doc}");
    }
    let (_, doc) = fix
        .as_party(&giver, "awards/unshare", json!({ "awardId": held }))
        .await;
    assert_eq!(tt_error_code(&doc), UNSHARE_ERR_NOT_FOUND, "{doc}");

    // No public origin: nothing is answered that would not be served.
    let saved = fix.vtc.state.config.read().await.public_url.clone();
    fix.vtc.state.config.write().await.public_url = None;
    let (_, doc) = fix
        .as_member("awards/share", json!({ "awardId": held }))
        .await;
    assert_eq!(
        tt_error_code(&doc),
        SHARE_ERR_PUBLIC_LOCATION_UNAVAILABLE,
        "{doc}"
    );
    fix.vtc.state.config.write().await.public_url = saved;

    // Badges off.
    set_settings(&fix, |s| s.enabled = false).await;
    let (_, doc) = fix
        .as_member("awards/share", json!({ "awardId": held }))
        .await;
    assert_eq!(tt_error_code(&doc), SHARE_ERR_BADGES_OFF, "{doc}");
    let (_, doc) = fix
        .as_member("awards/unshare", json!({ "awardId": held }))
        .await;
    assert_eq!(tt_error_code(&doc), UNSHARE_ERR_BADGES_OFF, "{doc}");
}

/// VTI-BDG-080: every active community badge is published to the trust registry as one
/// the community issues — the community as entity and authority, for the badge's
/// Achievement, naming the badge by identifier only — and its record goes when the badge
/// is retired. The projection is the one retry owner and checks itself against what
/// the registry holds.
#[tokio::test]
async fn community_badges_are_published_to_the_registry_as_the_community_s_and_withdrawn_on_retirement()
 {
    use vtc_service::badges::registry::{ACTION, KIND, reconcile, verify};
    use vtc_service::registry::{MockRegistryClient, RegistryError};
    let fix = fixture().await;
    let registry = MockRegistryClient::new();
    let state = &fix.vtc.state;

    let sha = fix.upload(&fix.admin).await;
    let mut body = fix.community_body("Workshop host", &sha, true);
    body["shareableOutside"] = json!(true);
    let (_, doc) = fix.as_admin("create", body).await;
    let outside = doc["payload"]["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let created = fix.community_badge("Inside", false).await;
    let inside = created["badge"]["badgeId"].as_str().unwrap().to_string();
    let _kudos = fix.kudos_badge(&fix.member, "Clamp whisperer").await;

    let r = reconcile(state, &registry, TEST_VTC_DID).await.unwrap();
    assert_eq!((r.put, r.deleted, r.failed), (2, 0, 0));
    let records = registry.trust_records().await;
    assert_eq!(records.len(), 2, "community badges only: {records:?}");
    let key = format!("{TEST_VTC_DID}|{ACTION}|https://vtc.example.com/badges/{outside}");
    let rec = records
        .get(&key)
        .expect("the outside badge, as the community's");
    assert_eq!(rec["entity_id"], TEST_VTC_DID);
    assert_eq!(rec["authority_id"], TEST_VTC_DID);
    assert_eq!(rec["authorized"], true);
    assert_eq!(rec["context"], json!({ "kind": KIND, "badgeId": outside }));
    assert!(
        !serde_json::to_string(&records).unwrap().contains("Inside"),
        "a badge's name is never published"
    );
    // Nothing changed: nothing is written again.
    let r = reconcile(state, &registry, TEST_VTC_DID).await.unwrap();
    assert_eq!((r.put, r.deleted), (0, 0));

    // Retiring the badge removes its record.
    let chair = GatedAdmin::new(&fix.vtc).await;
    let (status, doc) = chair
        .call(
            &fix.vtc,
            &task("retire"),
            json!({ "badgeId": inside, "reason": "season over" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let r = reconcile(state, &registry, TEST_VTC_DID).await.unwrap();
    assert_eq!((r.put, r.deleted), (0, 1));
    assert_eq!(registry.trust_records().await.len(), 1);

    // A refused write is retried on the next pass.
    let sha = fix.upload(&fix.admin).await;
    fix.as_admin("create", fix.community_body("Mentor", &sha, true))
        .await;
    registry
        .fail_next_trust_record(RegistryError::Transient("down".into()))
        .await;
    let r = reconcile(state, &registry, TEST_VTC_DID).await.unwrap();
    assert_eq!((r.put, r.failed), (0, 1));
    let r = reconcile(state, &registry, TEST_VTC_DID).await.unwrap();
    assert_eq!((r.put, r.failed), (1, 0));
    assert_eq!(registry.trust_records().await.len(), 2);

    // Verify: a record the registry lost is published again; a stray badge record it holds
    // is deleted; another `issue` record of the community's is never touched.
    registry.forget_trust_record(&key).await;
    registry
        .plant_trust_record(json!({
            "entity_id": "did:example:stray", "authority_id": TEST_VTC_DID, "action": ACTION,
            "resource": "https://vtc.example.com/badges/bdg_Gone0000000000000000",
            "context": { "kind": KIND, "badgeId": "bdg_Gone0000000000000000" },
        }))
        .await;
    registry
        .plant_trust_record(json!({
            "entity_id": "did:example:other", "authority_id": TEST_VTC_DID, "action": ACTION,
            "resource": "something-else", "context": {},
        }))
        .await;
    assert!(verify(state, &registry).await.unwrap());
    let r = reconcile(state, &registry, TEST_VTC_DID).await.unwrap();
    assert_eq!((r.put, r.deleted, r.failed), (1, 1, 0));
    let records = registry.trust_records().await;
    assert!(records.contains_key(&key));
    assert!(records.keys().any(|k| k.starts_with("did:example:other|")));
    assert!(!records.keys().any(|k| k.starts_with("did:example:stray|")));
}

fn group_task(name: &str) -> String {
    let version = match name {
        "requests/list" | "members/list" | "list" => "0.2",
        _ => "0.1",
    };
    format!("https://trusttasks.org/spec/vtc/groups/{name}/{version}")
}

/// The badges the member holds, by badge, with each one's count (`mine/list`).
async fn holding(fix: &Fixture, badge_id: &str) -> u64 {
    let (_, doc) = fix.as_member("mine/list", json!({})).await;
    doc["payload"]["badges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["badge"]["badgeId"] == badge_id)
        .map_or(0, |b| b["count"].as_u64().unwrap())
}

/// VTI-BDG-014 / 024: an approved request for a badge is the requester's consent — they
/// hold the badge, by an award recorded with the credential as its evidence. VTI-BDG-020:
/// an owner never gives a badge by adding the member to its group. Leaving the group
/// declines the badge; an owner's removal takes it back; both end the holding and revoke
/// the credential's status (VTI-BDG-013, 023, 063).
#[tokio::test]
async fn a_badge_groups_own_paths_give_and_end_the_badge_as_its_awards_do() {
    let fix = fixture().await;
    let sha = fix.upload(&fix.admin).await;
    let mut body = fix.community_body("Workshop host", &sha, true);
    body["shareableOutside"] = json!(true);
    body["requestable"] = json!(true);
    let (status, doc) = fix.as_admin("create", body).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let badge_id = doc["payload"]["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let group_id = doc["payload"]["badge"]["groupId"]
        .as_str()
        .unwrap()
        .to_string();

    // An owner adding the member to the group gives nothing.
    let (_, doc) = call(
        &fix.vtc,
        &fix.admin,
        &group_task("members/add"),
        json!({ "groupId": group_id, "entryId": fix.member_entry }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");
    assert_eq!(holding(&fix, &badge_id).await, 0);

    // Asking, approved: the member holds it, with the award as the credential's evidence.
    let (status, doc) = call(
        &fix.vtc,
        &fix.member,
        &group_task("join"),
        json!({ "groupId": group_id, "message": "I ran one." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let request_id = doc["payload"]["request"]["requestId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, doc) = call(
        &fix.vtc,
        &fix.admin,
        &group_task("requests/decide"),
        json!({ "requestId": request_id, "decision": "approve" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(holding(&fix, &badge_id).await, 1);
    let awards =
        vtc_service::badges::accepted_of(&fix.vtc.state.badges_ks, &badge_id, &fix.member_entry)
            .await
            .unwrap();
    assert_eq!(awards.len(), 1);
    let vc = fix.vta.calls_of(SIGN_DOCUMENT).last().unwrap()["document"].clone();
    assert_eq!(awards[0].credential_id.as_deref(), vc["id"].as_str());
    assert_eq!(
        vc["credentialSubject"]["achievement"]["id"],
        format!("https://vtc.example.com/badges/{badge_id}")
    );
    let slot = slot_of(&vc);
    assert!(!revocation_list(&fix).await.is_set(slot));

    // Leaving the group declines the badge and revokes the credential.
    let (status, doc) = call(
        &fix.vtc,
        &fix.member,
        &group_task("leave"),
        json!({ "groupId": group_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(holding(&fix, &badge_id).await, 0);
    let a = vtc_service::badges::get_award(&fix.vtc.state.badges_ks, &awards[0].award_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.state, vtc_service::badges::AwardState::Declined);
    assert!(revocation_list(&fix).await.is_set(slot));

    // Given again and accepted, then removed by an owner: taken back.
    let award = fix.hold(&badge_id).await;
    assert_eq!(holding(&fix, &badge_id).await, 1);
    let (status, doc) = call(
        &fix.vtc,
        &fix.admin,
        &group_task("members/remove"),
        json!({ "groupId": group_id, "entryId": fix.member_entry }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(holding(&fix, &badge_id).await, 0);
    let a = vtc_service::badges::get_award(&fix.vtc.state.badges_ks, &award)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.state, vtc_service::badges::AwardState::Revoked);
}

/// VTI-BDG-012: a badge group is the badge's. `vtc/groups/update` and `vtc/groups/delete`
/// refuse it, whoever signs: it changes with `vtc/badges/update` and goes with
/// `vtc/badges/retire`. VTI-BDG-095: its owners' acts through `vtc/groups/*` take their own
/// key, never the portal's delegated sign-in key.
#[tokio::test]
async fn a_badge_group_is_changed_only_through_its_badge_and_by_its_owners_own_key() {
    let fix = fixture().await;
    let sha = fix.upload(&fix.admin).await;
    let mut body = fix.community_body("Workshop host", &sha, true);
    body["requestable"] = json!(true);
    let (status, doc) = fix.as_admin("create", body).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let badge_id = doc["payload"]["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let group_id = doc["payload"]["badge"]["groupId"]
        .as_str()
        .unwrap()
        .to_string();
    let stored = |fix: &Fixture| {
        let ks = fix.vtc.state.directory.ks().clone();
        let group_id = group_id.clone();
        async move { vtc_service::groups::get(&ks, &group_id).await.unwrap() }
    };

    // Re-opening the badge's group is refused: who may ask for a badge is the badge's.
    let (_, doc) = call(
        &fix.vtc,
        &fix.admin,
        &group_task("update"),
        json!({ "groupId": group_id, "joinPolicy": "open" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");
    assert_eq!(
        stored(&fix).await.unwrap().join_policy,
        vtc_service::groups::JoinPolicy::Request
    );

    // Deleting it is refused: the badge is retired, never orphaned.
    let (_, doc) = call(
        &fix.vtc,
        &fix.admin,
        &group_task("delete"),
        json!({ "groupId": group_id, "reason": "tidying up" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");
    assert!(stored(&fix).await.is_some());

    // A member asks for the badge.
    let (status, doc) = call(
        &fix.vtc,
        &fix.member,
        &group_task("join"),
        json!({ "groupId": group_id, "message": "I ran one." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let request_id = doc["payload"]["request"]["requestId"]
        .as_str()
        .unwrap()
        .to_string();

    // Arm the portal's sign-in key `K_b` for the owner's live session, scoped to groups.
    let k_b = Party::new();
    let now = vti_common::auth::session::now_epoch();
    let session: vti_common::auth::session::Session = serde_json::from_value(json!({
        "session_id": "sess-badge-group-portal",
        "did": fix.admin.did,
        "challenge": "c",
        "state": "Authenticated",
        "created_at": now,
        "refresh_token": null,
        "refresh_expires_at": now + 3600,
        "not_after": now + 3600,
        "session_pubkey_b58btc": k_b.did.strip_prefix("did:key:").unwrap(),
    }))
    .unwrap();
    vti_common::auth::session::store_session(&fix.vtc.state.member_sessions_ks, &session)
        .await
        .unwrap();
    vtc_service::member_portal::delegation::record(
        &fix.vtc.state.member_sessions_ks,
        &k_b.did,
        &vtc_service::member_portal::delegation::Delegation {
            member_did: fix.admin.did.clone(),
            session_id: "sess-badge-group-portal".into(),
            scope: vec!["vtc/groups".into()],
            not_after: now + 3600,
            grant_id: Some("urn:uuid:badge-group-portal-grant".into()),
        },
    )
    .await
    .unwrap();

    // The portal's key decides nothing, appoints no owner and removes nobody.
    let (_, doc) = call(
        &fix.vtc,
        &k_b,
        &group_task("requests/decide"),
        json!({ "requestId": request_id, "decision": "approve" }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");
    assert_eq!(holding(&fix, &badge_id).await, 0);
    let (_, doc) = call(
        &fix.vtc,
        &k_b,
        &group_task("managers/add"),
        json!({ "groupId": group_id, "entryId": fix.member_entry }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");
    let (_, doc) = call(
        &fix.vtc,
        &k_b,
        &group_task("managers/remove"),
        json!({ "groupId": group_id, "entryId": fix.member_entry }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");
    let (_, doc) = call(
        &fix.vtc,
        &k_b,
        &group_task("members/remove"),
        json!({ "groupId": group_id, "entryId": fix.member_entry }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), "permissionDenied", "{doc}");

    // The owner's own key decides it.
    let (status, doc) = call(
        &fix.vtc,
        &fix.admin,
        &group_task("requests/decide"),
        json!({ "requestId": request_id, "decision": "approve" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(holding(&fix, &badge_id).await, 1);
}

/// VTI-BDG-013: an automatic badge is held by whoever its rule admits, each holding an
/// award the rule made; opting out of its group declines it.
#[tokio::test]
async fn an_automatic_badge_is_held_by_its_rule_and_declined_by_opting_out() {
    let fix = fixture().await;
    set_settings(&fix, |s| s.automatic_badges = true).await;
    let sha = fix.upload(&fix.admin).await;
    let mut body = fix.community_body("Member", &sha, false);
    body["requestable"] = json!(false);
    body["automatic"] =
        json!({ "rule": { "all": [{ "fact": "role", "op": "equals", "value": "member" }] } });
    let (status, doc) = fix.as_admin("create", body).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let badge_id = doc["payload"]["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let group_id = doc["payload"]["badge"]["groupId"]
        .as_str()
        .unwrap()
        .to_string();
    let group = vtc_service::groups::get(fix.vtc.state.directory.ks(), &group_id)
        .await
        .unwrap()
        .unwrap();
    vtc_service::groups::dynamic::recompute(&fix.vtc.state, &group, Utc::now())
        .await
        .unwrap();
    assert_eq!(holding(&fix, &badge_id).await, 1);
    let awards =
        vtc_service::badges::accepted_of(&fix.vtc.state.badges_ks, &badge_id, &fix.member_entry)
            .await
            .unwrap();
    assert_eq!(awards.len(), 1);
    assert!(awards[0].given_by.is_none(), "an award the rule made");
    // A second pass gives nothing more.
    vtc_service::groups::dynamic::recompute(&fix.vtc.state, &group, Utc::now())
        .await
        .unwrap();
    assert_eq!(holding(&fix, &badge_id).await, 1);

    // Opting out is declining the badge.
    let (status, doc) = call(
        &fix.vtc,
        &fix.member,
        &group_task("leave"),
        json!({ "groupId": group_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(holding(&fix, &badge_id).await, 0);
    let a = vtc_service::badges::get_award(&fix.vtc.state.badges_ks, &awards[0].award_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.state, vtc_service::badges::AwardState::Declined);
}

fn soon(hours: i64) -> String {
    (Utc::now() + chrono::Duration::hours(hours)).to_rfc3339()
}

async fn holding_of(fix: &Fixture, who: &Party, badge_id: &str) -> u64 {
    let (_, doc) = fix.as_party(who, "mine/list", json!({})).await;
    doc["payload"]["badges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["badge"]["badgeId"] == badge_id)
        .map_or(0, |b| b["count"].as_u64().unwrap())
}

/// VTI-BDG-025 – 027: an owner issues a claim code, answered once and kept only as a
/// digest; members who redeem it hold the badge — the redemption their consent, the giver
/// the issuer — within its limit; nobody claims it twice; withdrawn or retired, it admits
/// no one, and the claims made stand.
#[tokio::test]
async fn a_claim_code_admits_the_members_who_redeem_it_within_its_limit_and_time() {
    let fix = fixture().await;
    let created = fix.community_badge("Workshop host", true).await;
    let badge_id = created["badge"]["badgeId"].as_str().unwrap().to_string();
    let (status, doc) = fix
        .as_admin(
            "claims/create",
            json!({ "badgeId": badge_id, "label": "Saturday workshop", "validUntil": soon(4), "limit": 2 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let code = doc["payload"]["code"].as_str().unwrap().to_string();
    let claim_id = doc["payload"]["claim"]["claimId"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(code.len() >= 22);
    assert_eq!(doc["payload"]["claim"]["claims"], 0);

    // Redeemed: held, with the issuer as the giver.
    let (status, doc) = fix
        .as_member("claims/redeem", json!({ "code": code }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["award"]["state"], "accepted");
    assert_eq!(holding_of(&fix, &fix.member, &badge_id).await, 1);
    let (_, doc) = fix
        .as_member("claims/redeem", json!({ "code": code }))
        .await;
    assert_eq!(tt_error_code(&doc), REDEEM_ERR_ALREADY_CLAIMED, "{doc}");

    // A second member uses the last claim; a third finds it spent.
    let (second, _) = fix.another_member().await;
    let (status, doc) = fix
        .as_party(&second, "claims/redeem", json!({ "code": code }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (third, _) = fix.another_member().await;
    let (_, doc) = fix
        .as_party(&third, "claims/redeem", json!({ "code": code }))
        .await;
    assert_eq!(tt_error_code(&doc), REDEEM_ERR_CODE_INVALID, "{doc}");

    // The owners' list: counted, never the code.
    let (status, doc) = fix
        .as_admin("claims/list", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["items"][0]["claims"], 2);
    assert!(
        !doc.to_string().contains(&code),
        "the list never carries a code"
    );

    // A fresh code, withdrawn: refused as an unknown one is; claims made stand.
    let (_, doc) = fix
        .as_admin(
            "claims/create",
            json!({ "badgeId": badge_id, "label": "Sunday", "validUntil": soon(4), "limit": 5 }),
        )
        .await;
    let code2 = doc["payload"]["code"].as_str().unwrap().to_string();
    let claim2 = doc["payload"]["claim"]["claimId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, doc) = fix
        .as_admin("claims/withdraw", json!({ "claimId": claim2 }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["claim"]["state"], "withdrawn");
    let (_, doc) = fix
        .as_party(&third, "claims/redeem", json!({ "code": code2 }))
        .await;
    assert_eq!(tt_error_code(&doc), REDEEM_ERR_CODE_INVALID, "{doc}");
    let (_, doc) = fix
        .as_party(
            &third,
            "claims/redeem",
            json!({ "code": "Qm7xV2kR9pLw4Nt8Hs3Fz6Bd1Yc5Je0Ua" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), REDEEM_ERR_CODE_INVALID, "{doc}");
    assert_eq!(holding_of(&fix, &fix.member, &badge_id).await, 1);

    // Retiring the badge withdraws its codes.
    let (_, doc) = fix
        .as_admin(
            "claims/create",
            json!({ "badgeId": badge_id, "label": "Monday", "validUntil": soon(4), "limit": 5 }),
        )
        .await;
    let code3 = doc["payload"]["code"].as_str().unwrap().to_string();
    let chair = GatedAdmin::new(&fix.vtc).await;
    let (status, doc) = chair
        .call(
            &fix.vtc,
            &task("retire"),
            json!({ "badgeId": badge_id, "reason": "season over" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (_, doc) = fix
        .as_party(&third, "claims/redeem", json!({ "code": code3 }))
        .await;
    assert_eq!(tt_error_code(&doc), REDEEM_ERR_CODE_INVALID, "{doc}");
    let rec = vtc_service::badges::claims::get(&fix.vtc.state.badges_ks, &claim_id)
        .await
        .unwrap()
        .unwrap();
    assert!(rec.withdrawn);
}

#[tokio::test]
async fn the_claim_tasks_refuse_what_their_specifications_declare() {
    let fix = fixture().await;
    let created = fix.community_badge("Once", false).await;
    let badge_id = created["badge"]["badgeId"].as_str().unwrap().to_string();
    let create = |badge: &str, until: String| json!({ "badgeId": badge, "label": "x", "validUntil": until, "limit": 3 });
    // create
    let (_, doc) = fix
        .as_admin(
            "claims/create",
            create("bdg_NoSuchBadge0000000000", soon(1)),
        )
        .await;
    assert_eq!(tt_error_code(&doc), CLAIMS_CREATE_ERR_NOT_FOUND, "{doc}");
    let (_, doc) = fix
        .as_admin("claims/create", create(&badge_id, soon(-1)))
        .await;
    assert_eq!(
        tt_error_code(&doc),
        CLAIMS_CREATE_ERR_SETTINGS_INVALID,
        "{doc}"
    );
    let (_, doc) = fix
        .as_admin("claims/create", create(&badge_id, soon(24 * 120)))
        .await;
    assert_eq!(
        tt_error_code(&doc),
        CLAIMS_CREATE_ERR_SETTINGS_INVALID,
        "{doc}"
    );
    let kudos = fix.kudos_badge(&fix.member, "Clamp whisperer").await;
    let (_, doc) = fix.as_admin("claims/create", create(&kudos, soon(1))).await;
    assert_eq!(
        tt_error_code(&doc),
        CLAIMS_CREATE_ERR_NOT_CLAIMABLE,
        "{doc}"
    );
    assert_eq!(doc["payload"]["details"]["reason"], "kudos", "{doc}");
    // A member who owns nothing creates nothing.
    let (_, doc) = fix
        .as_member("claims/create", create(&badge_id, soon(1)))
        .await;
    assert_eq!(tt_error_code(&doc), CLAIMS_CREATE_ERR_NOT_FOUND, "{doc}");

    let (_, doc) = fix
        .as_admin("claims/create", create(&badge_id, soon(1)))
        .await;
    let code = doc["payload"]["code"].as_str().unwrap().to_string();

    // list
    let (_, doc) = fix
        .as_member("claims/list", json!({ "badgeId": badge_id }))
        .await;
    assert_eq!(tt_error_code(&doc), CLAIMS_LIST_ERR_NOT_FOUND, "{doc}");
    let (_, doc) = fix
        .as_admin(
            "claims/list",
            json!({ "badgeId": badge_id, "cursor": "forged" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), CLAIMS_LIST_ERR_CURSOR_INVALID, "{doc}");
    // withdraw
    let (_, doc) = fix
        .as_admin(
            "claims/withdraw",
            json!({ "claimId": "bcl_NoSuchClaim000000" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), CLAIMS_WITHDRAW_ERR_NOT_FOUND, "{doc}");

    // redeem: the key holder silent, then refusing — nothing recorded, the claim given back.
    fix.vta.script(SIGN_DOCUMENT, Script::Silent);
    let (_, doc) = fix
        .as_member("claims/redeem", json!({ "code": code }))
        .await;
    assert_eq!(
        tt_error_code(&doc),
        REDEEM_ERR_KEY_HOLDER_UNAVAILABLE,
        "{doc}"
    );
    fix.vta
        .script(SIGN_DOCUMENT, Script::Refuse("permissionDenied"));
    let (_, doc) = fix
        .as_member("claims/redeem", json!({ "code": code }))
        .await;
    assert_eq!(tt_error_code(&doc), REDEEM_ERR_KEY_HOLDER_REFUSED, "{doc}");
    assert_eq!(holding_of(&fix, &fix.member, &badge_id).await, 0);
    let (status, doc) = fix
        .as_member("claims/redeem", json!({ "code": code }))
        .await;
    assert_eq!(status, StatusCode::OK, "the claim was given back: {doc}");
    // A one-off badge already held.
    let (_, doc) = fix
        .as_admin("claims/create", create(&badge_id, soon(1)))
        .await;
    let other = doc["payload"]["code"].as_str().unwrap().to_string();
    let (_, doc) = fix
        .as_member("claims/redeem", json!({ "code": other }))
        .await;
    assert_eq!(tt_error_code(&doc), REDEEM_ERR_ALREADY_HELD, "{doc}");

    // Badges off.
    set_settings(&fix, |s| s.enabled = false).await;
    let (_, doc) = fix
        .as_admin("claims/create", create(&badge_id, soon(1)))
        .await;
    assert_eq!(tt_error_code(&doc), CLAIMS_CREATE_ERR_BADGES_OFF, "{doc}");
    let (_, doc) = fix
        .as_admin(
            "claims/withdraw",
            json!({ "claimId": "bcl_NoSuchClaim000000" }),
        )
        .await;
    assert_eq!(tt_error_code(&doc), CLAIMS_WITHDRAW_ERR_BADGES_OFF, "{doc}");
    let (_, doc) = fix
        .as_member("claims/redeem", json!({ "code": other }))
        .await;
    assert_eq!(tt_error_code(&doc), REDEEM_ERR_BADGES_OFF, "{doc}");
}

/// VTI-BDG-015: an automatic badge's rule reads counts of the community's own records —
/// here, accepted kudos — and no other group's rule may.
#[tokio::test]
async fn an_automatic_badge_counts_accepted_kudos_and_only_a_badge_may() {
    let fix = fixture().await;
    set_settings(&fix, |s| s.automatic_badges = true).await;
    let sha = fix.upload(&fix.admin).await;
    let mut body = fix.community_body("Well liked", &sha, false);
    body["requestable"] = json!(false);
    body["automatic"] = json!({ "rule": { "all": [
        { "fact": "kudosReceived", "op": "atLeast", "count": 1 }
    ] } });
    let (status, doc) = fix.as_admin("create", body).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let badge_id = doc["payload"]["badge"]["badgeId"]
        .as_str()
        .unwrap()
        .to_string();
    let group = vtc_service::groups::get(
        fix.vtc.state.directory.ks(),
        doc["payload"]["badge"]["groupId"].as_str().unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    vtc_service::groups::dynamic::recompute(&fix.vtc.state, &group, Utc::now())
        .await
        .unwrap();
    assert_eq!(holding_of(&fix, &fix.member, &badge_id).await, 0);

    // A kudos accepted: the rule now admits them.
    let (giver, _) = fix.another_member().await;
    let kudos = fix.kudos_badge(&giver, "Clamp whisperer").await;
    let (_, doc) = fix
        .as_party(
            &giver,
            "kudos/give",
            json!({ "badgeId": kudos, "to": fix.member_entry }),
        )
        .await;
    let award = doc["payload"]["award"]["awardId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, doc) = fix
        .as_member("mine/accept", json!({ "awardId": award }))
        .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    vtc_service::groups::dynamic::recompute(&fix.vtc.state, &group, Utc::now())
        .await
        .unwrap();
    assert_eq!(holding_of(&fix, &fix.member, &badge_id).await, 1);

    // A count in a rule is a badge's alone; a threshold goes with `atLeast` only.
    let rule = json!({ "all": [ { "fact": "kudosReceived", "op": "atLeast", "count": 1 } ] });
    assert!(vtc_service::groups::check_rule(&rule, &[]).is_err());
    assert!(vtc_service::groups::check_badge_rule(&rule, &[]).is_ok());
    let bad = json!({ "all": [ { "fact": "kudosReceived", "op": "exists" } ] });
    assert!(vtc_service::groups::check_badge_rule(&bad, &[]).is_err());
    let bad =
        json!({ "all": [ { "fact": "role", "op": "equals", "value": "member", "count": 2 } ] });
    assert!(vtc_service::groups::check_badge_rule(&bad, &[]).is_err());
}

/// A list cursor is tagged under a key only the community holds, for one
/// caller and one question. One made without the key, edited, or presented
/// by another caller is refused, and an offset past any list (the largest
/// `usize`) is refused rather than reaching the slice.
#[tokio::test]
async fn a_list_cursor_is_honoured_only_as_the_community_minted_it() {
    use sha2::{Digest, Sha256};

    let fix = fixture().await;
    fix.community_badge("A", false).await;
    fix.community_badge("B", false).await;

    let (status, doc) = fix.as_member("list", json!({ "limit": 1 })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let next = doc["payload"]["nextCursor"]
        .as_str()
        .expect("two badges, one per page")
        .to_string();
    let (status, page2) = fix
        .as_member("list", json!({ "limit": 1, "cursor": next }))
        .await;
    assert_eq!(status, StatusCode::OK, "{page2}");
    assert_ne!(
        doc["payload"]["items"][0]["badge"]["badgeId"],
        page2["payload"]["items"][0]["badge"]["badgeId"]
    );

    // The construction before keys: anyone could compute it, at any offset.
    let binding = format!("badges/list|{}||false|false|false", fix.member.did);
    let unkeyed = |offset: usize| {
        let mut h = Sha256::new();
        h.update(b"vtc/badges/cursor/v1\0");
        for part in [binding.as_str(), &offset.to_string()] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part.as_bytes());
        }
        format!("{offset}.{}", hex::encode(&h.finalize()[..12]))
    };
    let (offset, tag) = next.split_once('.').unwrap();
    for cursor in [
        unkeyed(1),
        unkeyed(usize::MAX),
        format!("{}.{tag}", usize::MAX),
        format!("{}.{tag}", offset.parse::<usize>().unwrap() + 1),
    ] {
        let (_, doc) = fix
            .as_member("list", json!({ "limit": 1, "cursor": cursor }))
            .await;
        assert_eq!(
            tt_error_code(&doc),
            LIST_ERR_CURSOR_INVALID,
            "{cursor}: {doc}"
        );
    }

    // The member's cursor is not the administrator's.
    let (_, doc) = fix
        .as_admin("list", json!({ "limit": 1, "cursor": next }))
        .await;
    assert_eq!(tt_error_code(&doc), LIST_ERR_CURSOR_INVALID, "{doc}");
}
