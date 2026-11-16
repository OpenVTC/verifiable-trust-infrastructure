//! The community logo (`vtc/community/logo/update/0.1`, served at
//! `GET /v1/community/logo`): written by an administrator, re-encoded so no
//! byte sent survives, served from the community's own origin with headers no
//! reader can mistake for anything but an image.

use std::io::Cursor;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt as _;

use crate::common::signed::{
    admin, assert_conforms, call, error_code, party_with_role, payload, post, unsigned,
};
use vtc_service::acl::VtcRole;
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

const UPDATE: &str = "https://trusttasks.org/spec/vtc/community/logo/update/0.1";
const LOGO_UPDATE_ERR_TOO_LARGE: &str = "vtc/community/logo/update:tooLarge";
const LOGO_UPDATE_ERR_NOT_AN_IMAGE: &str = "vtc/community/logo/update:notAnImage";
const LOGO_UPDATE_ERR_RATE_LIMITED: &str = "vtc/community/logo/update:rateLimited";

/// A refusal's declared code.
fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

async fn vtc() -> TestVtc {
    TestVtc::builder().with_audit(true).build().await
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn png(width: u32, height: u32) -> Vec<u8> {
    let img = image::RgbaImage::from_pixel(width, height, image::Rgba([20, 90, 200, 255]));
    let mut out = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
        .unwrap();
    out
}

/// A PNG with HTML appended after `IEND`: valid as an image, and to a
/// sniffing reader a page.
fn polyglot() -> Vec<u8> {
    let mut file = png(64, 32);
    file.extend_from_slice(b"<html><script>alert(document.cookie)</script></html>");
    file
}

fn image_payload(bytes: &[u8]) -> Value {
    json!({ "image": { "mediaType": "image/png", "data": b64(bytes) } })
}

/// `GET /v1/community/logo`, unauthenticated, optionally with `If-None-Match`.
async fn get_logo(
    vtc: &TestVtc,
    if_none_match: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut req = Request::builder().method("GET").uri("/v1/community/logo");
    if let Some(tag) = if_none_match {
        req = req.header(header::IF_NONE_MATCH, tag);
    }
    let res = vtc
        .router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, bytes)
}

#[tokio::test]
async fn a_logo_is_stored_re_encoded_served_and_removed() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    assert_eq!(get_logo(&vtc, None).await.0, StatusCode::NOT_FOUND);

    let sent = polyglot();
    let (status, doc) = call(&vtc, &admin, UPDATE, image_payload(&sent)).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_conforms(UPDATE, &doc);
    let logo = payload(&doc)["logo"].clone();
    assert_eq!(payload(&doc)["stored"], true, "{doc}");
    assert!(payload(&doc)["updatedAt"].is_string(), "{doc}");
    assert_eq!(logo["mediaType"], "image/png");
    assert_eq!(
        (logo["width"].clone(), logo["height"].clone()),
        (json!(64), json!(32))
    );

    // Served: exactly the stored re-encoding, never what was sent (item 4).
    let (status, headers, body) = get_logo(&vtc, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hex::encode(Sha256::digest(&body)), logo["sha256"]);
    assert_eq!(body.len() as u64, logo["size"].as_u64().unwrap());
    assert_ne!(body, sent);
    assert!(
        !body.windows(7).any(|w| w == b"<script"),
        "the polyglot is gone"
    );

    // The header set (item 8).
    let h = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    assert_eq!(h("content-type").as_deref(), Some("image/png"));
    assert_eq!(h("x-content-type-options").as_deref(), Some("nosniff"));
    assert_eq!(
        h("content-security-policy").as_deref(),
        Some("default-src 'none'; sandbox")
    );
    assert_eq!(h("cache-control").as_deref(), Some("public, max-age=300"));
    let etag = h("etag").unwrap();
    assert_eq!(etag, format!("\"{}\"", logo["sha256"].as_str().unwrap()));
    assert!(headers.get(header::SET_COOKIE).is_none(), "no cookie");

    // A cache that holds it is told it has not changed.
    let (status, headers, body) = get_logo(&vtc, Some(&etag)).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());
    assert!(headers.get(header::ETAG).is_some());

    // The same image again changes nothing (item 6).
    let (_, doc) = call(&vtc, &admin, UPDATE, image_payload(&sent)).await;
    assert_eq!(payload(&doc)["stored"], false, "{doc}");
    assert_eq!(payload(&doc)["logo"], logo);

    // Removed, and then not served.
    let (_, doc) = call(&vtc, &admin, UPDATE, json!({ "image": null })).await;
    assert_conforms(UPDATE, &doc);
    assert_eq!(payload(&doc)["stored"], true, "{doc}");
    assert!(payload(&doc)["logo"].is_null(), "{doc}");
    assert!(payload(&doc)["updatedAt"].is_string(), "{doc}");
    assert_eq!(get_logo(&vtc, None).await.0, StatusCode::NOT_FOUND);

    // Removing what is not held changes nothing.
    let (_, doc) = call(&vtc, &admin, UPDATE, json!({ "image": null })).await;
    assert_eq!(payload(&doc)["stored"], false, "{doc}");
}

#[tokio::test]
async fn the_public_profile_names_the_stored_logo() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    let mut profile = vtc_service::community::CommunityProfile::new(TEST_VTC_DID, "Example");
    profile.logo_url = Some("https://cdn.example.com/logo.png".into());
    vtc_service::community::store_profile(&vtc.state.community_ks, &profile)
        .await
        .unwrap();

    let read = || async {
        let res = vtc
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/community/public-profile")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice::<Value>(&bytes).unwrap()
    };
    assert!(read().await.get("logo").is_none(), "absent until stored");

    let (_, doc) = call(&vtc, &admin, UPDATE, image_payload(&png(10, 10))).await;
    let sha = payload(&doc)["logo"]["sha256"]
        .as_str()
        .unwrap()
        .to_string();
    let body = read().await;
    assert_eq!(
        body["logo"]["url"],
        format!("/v1/community/logo?v={}", &sha[..16])
    );
    assert_eq!(body["logo"]["sha256"], sha);
    // `logoUrl` is untouched: it stays an address for readers anywhere.
    assert_eq!(body["logoUrl"], "https://cdn.example.com/logo.png");
}

#[tokio::test]
async fn what_is_not_a_raster_of_its_type_is_refused() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
    for bytes in [svg.as_slice(), b"<!doctype html><p>hi".as_slice()] {
        let (status, doc) = call(&vtc, &admin, UPDATE, image_payload(bytes)).await;
        assert!(status.is_client_error(), "{status} {doc}");
        assert_eq!(
            tt_error_code(&doc),
            Some(LOGO_UPDATE_ERR_NOT_AN_IMAGE),
            "{doc}"
        );
    }
    // SVG as a declared type is outside the schema before anything decodes.
    let (status, doc) = call(
        &vtc,
        &admin,
        UPDATE,
        json!({ "image": { "mediaType": "image/svg+xml", "data": b64(svg) } }),
    )
    .await;
    assert!(status.is_client_error(), "{status} {doc}");
    assert_ne!(
        tt_error_code(&doc),
        Some(LOGO_UPDATE_ERR_NOT_AN_IMAGE),
        "schema, not decoding: {doc}"
    );
    assert_eq!(get_logo(&vtc, None).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_picture_claiming_more_pixels_than_are_decoded_is_too_large() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    // A few kilobytes claiming 20000 pixels across.
    let bomb = png(20_000, 1);
    assert!(bomb.len() < 8192, "small on the wire: {}", bomb.len());
    let (status, doc) = call(&vtc, &admin, UPDATE, image_payload(&bomb)).await;
    assert!(status.is_client_error(), "{status} {doc}");
    assert_eq!(
        tt_error_code(&doc),
        Some(LOGO_UPDATE_ERR_TOO_LARGE),
        "{doc}"
    );
    assert_eq!(get_logo(&vtc, None).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn updates_beyond_the_hourly_bound_are_rate_limited() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    let logo = image_payload(&png(4, 4));
    for _ in 0..vtc_service::community::logo::UPDATES_PER_HOUR {
        let (status, doc) = call(&vtc, &admin, UPDATE, logo.clone()).await;
        assert_eq!(status, StatusCode::OK, "{doc}");
    }
    let (status, doc) = call(&vtc, &admin, UPDATE, logo).await;
    assert!(status.is_client_error(), "{status} {doc}");
    assert_eq!(
        tt_error_code(&doc),
        Some(LOGO_UPDATE_ERR_RATE_LIMITED),
        "{doc}"
    );
}

#[tokio::test]
async fn only_an_administrator_changes_the_logo() {
    let vtc = vtc().await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let (status, doc) = call(&vtc, &member, UPDATE, image_payload(&png(4, 4))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{doc}");
    let (status, doc) = post(&vtc, &unsigned(&member, UPDATE, json!({ "image": null }))).await;
    assert!(
        status.is_client_error() && error_code(&doc).is_some(),
        "{status} {doc}"
    );
    assert_eq!(get_logo(&vtc, None).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn no_change_lands_without_its_audit_record() {
    let vtc = TestVtc::builder().with_audit(false).build().await;
    let admin = admin(&vtc).await;
    let (status, doc) = call(&vtc, &admin, UPDATE, image_payload(&png(4, 4))).await;
    assert!(!status.is_success(), "{status} {doc}");
    assert_eq!(get_logo(&vtc, None).await.0, StatusCode::NOT_FOUND);
}
