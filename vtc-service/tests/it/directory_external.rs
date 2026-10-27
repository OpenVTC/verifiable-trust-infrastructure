//! Integration coverage for directory pictures (`vtc/directory/images/*`) and
//! external cards (`vtc/directory/card/{publish,public}`) through real signed
//! documents — and, for the reads anyone may make, unsigned ones.
//!
//! Each declared error code is driven here and asserted on (#1600), which is
//! what the error-code census reads.

use std::io::Cursor;

use axum::http::StatusCode;
use base64::Engine as _;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use vti_rooms_dtg::test_support::{Party, sign_as};

use crate::common::signed::{call, post, seed_role, unsigned};
use vtc_service::acl::VtcRole;
use vtc_service::directory::model::Settings;
use vtc_service::members::{Member, get_member, store_member};
use vtc_service::policy::default::install_defaults;
use vtc_service::test_support::TestVtc;

const SPEC: &str = "https://trusttasks.org/spec/vtc/directory";

fn task(name: &str) -> String {
    format!("{SPEC}/{name}/0.1")
}

use trust_tasks_rs::specs::vtc::directory as d;

const UPLOAD_ERR_NOT_MEMBER: &str = d::images::upload::v0_1::error_codes::NOT_MEMBER.code;
const UPLOAD_ERR_TOO_LARGE: &str = d::images::upload::v0_1::error_codes::TOO_LARGE.code;
const UPLOAD_ERR_NOT_AN_IMAGE: &str = d::images::upload::v0_1::error_codes::NOT_AN_IMAGE.code;
const UPLOAD_ERR_RATE_LIMITED: &str = d::images::upload::v0_1::error_codes::RATE_LIMITED.code;
const IMAGE_ERR_NOT_FOUND: &str = d::images::get::v0_1::error_codes::NOT_FOUND.code;
const PUBLISH_ERR_NOT_MEMBER: &str = d::card::publish::v0_1::error_codes::NOT_MEMBER.code;
const PUBLISH_ERR_NOT_AVAILABLE: &str = d::card::publish::v0_1::error_codes::NOT_AVAILABLE.code;
const PUBLISH_ERR_CONSENT_REQUIRED: &str =
    d::card::publish::v0_1::error_codes::CONSENT_REQUIRED.code;
const PUBLISH_ERR_SUPERSEDED: &str = d::card::publish::v0_1::error_codes::SUPERSEDED.code;
const PUBLISH_ERR_CARD_MISMATCH: &str = d::card::publish::v0_1::error_codes::CARD_MISMATCH.code;
const PUBLISH_ERR_SIGNATURE_INVALID: &str =
    d::card::publish::v0_1::error_codes::SIGNATURE_INVALID.code;
const PUBLIC_ERR_NOT_FOUND: &str = d::card::public::v0_1::error_codes::NOT_FOUND.code;
const CARD_UPDATE_ERR_VALUE_INVALID: &str = d::card::update::v0_1::error_codes::VALUE_INVALID.code;

/// The error code carried by a `trust-task-error` payload.
fn tt_error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

async fn fixture(settings: Settings) -> TestVtc {
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_did_resolver(true)
        .with_directory(settings)
        .with_public_url("https://vtc.example.com")
        .build()
        .await;
    install_defaults(&vtc.state.policies_ks, &vtc.state.active_policies_ks)
        .await
        .expect("install default policies");
    vtc
}

/// A member who consented to registry publication.
async fn member(vtc: &TestVtc) -> Party {
    let p = Party::new();
    seed_role(vtc, &p.did, VtcRole::Member, &[]).await;
    let mut m = Member::fresh(&p.did);
    m.publish_consent = true;
    store_member(&vtc.state.members_ks, &m).await.unwrap();
    p
}

async fn send(vtc: &TestVtc, from: &Party, name: &str, payload: Value) -> (StatusCode, Value) {
    let (status, doc) = call(vtc, from, &task(name), payload).await;
    (status, doc["payload"].clone())
}

async fn ok(vtc: &TestVtc, from: &Party, name: &str, payload: Value) -> Value {
    let (status, body) = send(vtc, from, name, payload).await;
    assert_eq!(status, StatusCode::OK, "{name}: {body}");
    body
}

/// `name` sent with no proof at all.
async fn anonymous(vtc: &TestVtc, name: &str, payload: Value) -> (StatusCode, Value) {
    let mut doc = unsigned(&Party::new(), &task(name), payload);
    doc.as_object_mut().unwrap().remove("issuer");
    let (status, body) = post(vtc, &doc).await;
    (status, body["payload"].clone())
}

fn png(width: u32, height: u32) -> Vec<u8> {
    let img = image::RgbaImage::from_pixel(width, height, image::Rgba([20, 90, 200, 255]));
    let mut out = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
        .unwrap();
    out
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

async fn upload(vtc: &TestVtc, from: &Party) -> Value {
    ok(
        vtc,
        from,
        "images/upload",
        json!({ "mediaType": "image/png", "data": b64(&png(64, 48)) }),
    )
    .await["image"]
        .clone()
}

/// The card `from` would sign for their public values right now: built from
/// `card/show` exactly as the specification's mapping says.
async fn signed_card(vtc: &TestVtc, from: &Party) -> (Value, u64) {
    let shown = ok(vtc, from, "card/show", json!({})).await["card"].clone();
    let entry = shown["entryId"].as_str().unwrap();
    let schema = vtc_service::directory::fields::schema(vtc.state.directory.ks())
        .await
        .unwrap();
    let mut public = Map::new();
    for f in &schema {
        if shown["visibility"][&f.key] == "public"
            && let Some(v) = shown["values"].get(&f.key)
        {
            public.insert(f.key.clone(), v.clone());
        }
    }
    let mut card = json!({
        "@type": "Card",
        "version": "1.0",
        "uid": format!("urn:vtc-directory:{entry}"),
        "issuer": from.did,
    });
    for (k, v) in vtc_service::directory::external::expected_members(entry, &schema, &public) {
        card[k] = v;
    }
    (
        sign_as(from, card).await,
        shown["revision"].as_u64().unwrap(),
    )
}

async fn make_public(vtc: &TestVtc, from: &Party, name: &str) {
    ok(
        vtc,
        from,
        "card/update",
        json!({
            "values": { "displayName": name },
            "visibility": { "displayName": "public" },
        }),
    )
    .await;
}

// ─── pictures ─────────────────────────────────────────────────────────────

/// A member's picture reaches the audience they chose and nobody else; a
/// digest seen on one card never puts the picture on another.
#[tokio::test]
async fn a_picture_is_read_only_through_the_projection() {
    let vtc = fixture(Settings::default()).await;
    let carol = member(&vtc).await;
    let dave = member(&vtc).await;
    let picture = upload(&vtc, &carol).await;
    assert_eq!(picture["mediaType"], "image/jpeg", "re-encoded: {picture}");
    ok(
        &vtc,
        &carol,
        "card/update",
        json!({
            "values": { "displayName": "Carol", "avatar": picture },
            "visibility": { "avatar": "members" },
        }),
    )
    .await;
    let entry = ok(&vtc, &carol, "card/show", json!({})).await["card"]["entryId"].clone();

    // A member sees it, and the bytes are the ones the reference names.
    let got = ok(
        &vtc,
        &dave,
        "images/get",
        json!({ "entryId": entry, "field": "avatar", "sha256": picture["sha256"] }),
    )
    .await;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(got["data"].as_str().unwrap())
        .unwrap();
    assert_eq!(hex::encode(Sha256::digest(&bytes)), picture["sha256"]);
    assert!(got["image"].get("url").is_none());

    // The public does not, and a stale or unknown digest is the same answer.
    let (_, public) = anonymous(
        &vtc,
        "images/get",
        json!({ "entryId": entry, "field": "avatar" }),
    )
    .await;
    assert_eq!(tt_error_code(&public), IMAGE_ERR_NOT_FOUND, "{public}");
    let (_, stale) = send(
        &vtc,
        &dave,
        "images/get",
        json!({ "entryId": entry, "field": "avatar", "sha256": "0".repeat(64) }),
    )
    .await;
    assert_eq!(tt_error_code(&stale), IMAGE_ERR_NOT_FOUND);
    assert_eq!(public["message"], stale["message"], "indistinguishable");

    // Dave cannot put Carol's picture on his own card.
    let (_, borrowed) = send(
        &vtc,
        &dave,
        "card/update",
        json!({ "values": { "avatar": picture } }),
    )
    .await;
    assert_eq!(
        tt_error_code(&borrowed),
        CARD_UPDATE_ERR_VALUE_INVALID,
        "{borrowed}"
    );
}

#[tokio::test]
async fn images_upload_refuses_what_its_specification_declares() {
    let vtc = fixture(Settings {
        image_uploads_per_hour: 2,
        ..Settings::default()
    })
    .await;
    let (_, stranger) = send(
        &vtc,
        &Party::new(),
        "images/upload",
        json!({ "mediaType": "image/png", "data": b64(&png(4, 4)) }),
    )
    .await;
    assert_eq!(
        tt_error_code(&stranger),
        UPLOAD_ERR_NOT_MEMBER,
        "{stranger}"
    );

    let carol = member(&vtc).await;
    let (_, not_image) = send(
        &vtc,
        &carol,
        "images/upload",
        json!({ "mediaType": "image/png", "data": b64(b"definitely not a png") }),
    )
    .await;
    assert_eq!(
        tt_error_code(&not_image),
        UPLOAD_ERR_NOT_AN_IMAGE,
        "{not_image}"
    );

    // A few kilobytes claiming more pixels than the community decodes.
    let (_, bomb) = send(
        &vtc,
        &carol,
        "images/upload",
        json!({ "mediaType": "image/png", "data": b64(&png(9000, 1)) }),
    )
    .await;
    assert_eq!(tt_error_code(&bomb), UPLOAD_ERR_TOO_LARGE, "{bomb}");

    // The two refusals above counted; the limit is two an hour.
    let (_, limited) = send(
        &vtc,
        &carol,
        "images/upload",
        json!({ "mediaType": "image/png", "data": b64(&png(4, 4)) }),
    )
    .await;
    assert_eq!(
        tt_error_code(&limited),
        UPLOAD_ERR_RATE_LIMITED,
        "{limited}"
    );
}

// ─── external cards ───────────────────────────────────────────────────────

/// Published as signed, served to anyone as signed — and withdrawn the moment
/// it stops saying exactly what the member's card shows the public.
#[tokio::test]
async fn a_published_card_is_served_as_signed_until_the_public_values_change() {
    let vtc = fixture(Settings::default()).await;
    let carol = member(&vtc).await;
    make_public(&vtc, &carol, "Carol Example").await;
    let (card, revision) = signed_card(&vtc, &carol).await;
    let published = ok(
        &vtc,
        &carol,
        "card/publish",
        json!({ "card": card, "expectedRevision": revision }),
    )
    .await;
    assert_eq!(published["externalCard"]["state"], "published");
    let digest = published["externalCard"]["cardDigest"].clone();
    assert_eq!(
        digest,
        vtc_service::directory::external::card_digest(&card).unwrap()
    );
    let entry = card["uid"]
        .as_str()
        .unwrap()
        .trim_start_matches("urn:vtc-directory:")
        .to_string();

    // Anyone reads it, exactly as signed.
    let (status, public) = anonymous(
        &vtc,
        "card/public",
        json!({ "entryId": entry, "cardDigest": digest }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{public}");
    assert_eq!(public["card"], card);
    let shown = ok(&vtc, &carol, "card/show", json!({})).await;
    assert_eq!(shown["card"]["discoverability"]["external"], true);
    assert_eq!(shown["card"]["externalCard"]["cardDigest"], digest);

    // Her name changes: the card says something else now, so it goes.
    ok(
        &vtc,
        &carol,
        "card/update",
        json!({ "values": { "displayName": "Caroline" } }),
    )
    .await;
    let (_, gone) = anonymous(&vtc, "card/public", json!({ "entryId": entry })).await;
    assert_eq!(tt_error_code(&gone), PUBLIC_ERR_NOT_FOUND, "{gone}");
    let shown = ok(&vtc, &carol, "card/show", json!({})).await;
    assert_eq!(shown["card"]["externalCard"]["state"], "awaitingSignature");
    assert_eq!(shown["card"]["discoverability"]["external"], true);

    // Signed again, served again; turned off, gone for good.
    let (card, revision) = signed_card(&vtc, &carol).await;
    ok(
        &vtc,
        &carol,
        "card/publish",
        json!({ "card": card, "expectedRevision": revision }),
    )
    .await;
    let (status, _) = anonymous(&vtc, "card/public", json!({ "entryId": entry })).await;
    assert_eq!(status, StatusCode::OK);
    ok(
        &vtc,
        &carol,
        "card/update",
        json!({ "discoverability": { "listing": "listed", "search": "byName", "external": false } }),
    )
    .await;
    let (_, off) = anonymous(&vtc, "card/public", json!({ "entryId": entry })).await;
    assert_eq!(tt_error_code(&off), PUBLIC_ERR_NOT_FOUND);
    let shown = ok(&vtc, &carol, "card/show", json!({})).await;
    assert!(shown["card"].get("externalCard").is_none(), "{shown}");
}

/// Withdrawing registry-publication consent withdraws the card with it
/// (VTI-DIR-047).
#[tokio::test]
async fn withdrawing_consent_withdraws_the_card() {
    let vtc = fixture(Settings::default()).await;
    let carol = member(&vtc).await;
    make_public(&vtc, &carol, "Carol Example").await;
    let (card, _) = signed_card(&vtc, &carol).await;
    ok(&vtc, &carol, "card/publish", json!({ "card": card })).await;
    let entry = ok(&vtc, &carol, "card/show", json!({})).await["card"]["entryId"].clone();

    let admin = crate::common::signed::admin(&vtc).await;
    let (status, body) = call(
        &vtc,
        &admin,
        "https://trusttasks.org/spec/vtc/members/update/0.1",
        json!({ "did": carol.did, "publishConsent": false }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !get_member(&vtc.state.members_ks, &carol.did)
            .await
            .unwrap()
            .unwrap()
            .publish_consent
    );
    let (_, gone) = anonymous(&vtc, "card/public", json!({ "entryId": entry })).await;
    assert_eq!(tt_error_code(&gone), PUBLIC_ERR_NOT_FOUND, "{gone}");
    let shown = ok(&vtc, &carol, "card/show", json!({})).await;
    assert_eq!(shown["card"]["discoverability"]["external"], false);
}

#[tokio::test]
async fn card_publish_refuses_what_its_specification_declares() {
    let vtc = fixture(Settings::default()).await;
    let carol = member(&vtc).await;
    make_public(&vtc, &carol, "Carol Example").await;
    let (card, revision) = signed_card(&vtc, &carol).await;

    let (_, stranger) = send(&vtc, &Party::new(), "card/publish", json!({ "card": card })).await;
    assert_eq!(
        tt_error_code(&stranger),
        PUBLISH_ERR_NOT_MEMBER,
        "{stranger}"
    );

    let (_, superseded) = send(
        &vtc,
        &carol,
        "card/publish",
        json!({ "card": card, "expectedRevision": revision + 5 }),
    )
    .await;
    assert_eq!(
        tt_error_code(&superseded),
        PUBLISH_ERR_SUPERSEDED,
        "{superseded}"
    );
    assert_eq!(superseded["details"]["revision"], revision);

    // A card saying more than her public values — signed, but not hers to
    // publish as it stands.
    let mut more = card.clone();
    more.as_object_mut().unwrap().remove("proof");
    more["speakToAs"] = json!({ "pronouns": { "p1": { "pronouns": "she/her" } } });
    let more = sign_as(&carol, more).await;
    let (_, mismatch) = send(&vtc, &carol, "card/publish", json!({ "card": more })).await;
    assert_eq!(
        tt_error_code(&mismatch),
        PUBLISH_ERR_CARD_MISMATCH,
        "{mismatch}"
    );
    assert_eq!(mismatch["details"]["fields"], json!(["pronouns"]));

    // Exactly her values, signed by somebody else.
    let mut unsigned_card = card.clone();
    unsigned_card.as_object_mut().unwrap().remove("proof");
    let forged = sign_as(&Party::new(), unsigned_card).await;
    let (_, forged) = send(&vtc, &carol, "card/publish", json!({ "card": forged })).await;
    assert_eq!(
        tt_error_code(&forged),
        PUBLISH_ERR_SIGNATURE_INVALID,
        "{forged}"
    );

    // No consent to registry publication.
    let mut m = get_member(&vtc.state.members_ks, &carol.did)
        .await
        .unwrap()
        .unwrap();
    m.publish_consent = false;
    store_member(&vtc.state.members_ks, &m).await.unwrap();
    let (_, consent) = send(&vtc, &carol, "card/publish", json!({ "card": card })).await;
    assert_eq!(
        tt_error_code(&consent),
        PUBLISH_ERR_CONSENT_REQUIRED,
        "{consent}"
    );

    // A community that does not publish external cards.
    let closed = fixture(Settings {
        external_cards: false,
        ..Settings::default()
    })
    .await;
    let dave = member(&closed).await;
    make_public(&closed, &dave, "Dave").await;
    let (card, _) = signed_card(&closed, &dave).await;
    let (_, unavailable) = send(&closed, &dave, "card/publish", json!({ "card": card })).await;
    assert_eq!(
        tt_error_code(&unavailable),
        PUBLISH_ERR_NOT_AVAILABLE,
        "{unavailable}"
    );
}

/// A picture on a published card is the one picture the public may read.
#[tokio::test]
async fn the_public_reads_a_picture_only_on_a_published_card() {
    let vtc = fixture(Settings::default()).await;
    let carol = member(&vtc).await;
    let picture = upload(&vtc, &carol).await;
    ok(
        &vtc,
        &carol,
        "card/update",
        json!({
            "values": { "displayName": "Carol", "avatar": picture },
            "visibility": { "displayName": "public", "avatar": "public" },
        }),
    )
    .await;
    let entry = ok(&vtc, &carol, "card/show", json!({})).await["card"]["entryId"].clone();
    let ask = json!({ "entryId": entry, "field": "avatar", "sha256": picture["sha256"] });

    // Public visibility alone is not publication.
    let (_, before) = anonymous(&vtc, "images/get", ask.clone()).await;
    assert_eq!(tt_error_code(&before), IMAGE_ERR_NOT_FOUND);

    let (card, _) = signed_card(&vtc, &carol).await;
    assert_eq!(card["media"]["m1"]["kind"], "photo");
    ok(&vtc, &carol, "card/publish", json!({ "card": card })).await;
    let (status, got) = anonymous(&vtc, "images/get", ask).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["image"]["sha256"], picture["sha256"]);
}
