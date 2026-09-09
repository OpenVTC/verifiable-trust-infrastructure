//! End-to-end safety net for the persona slice: real requests, through the
//! real dispatch spine, into the real store.
//!
//! Every layer of #1255 was tested and none of the seams between them were.
//! The unit tests assert that `authorize` refuses a context-scoped caller;
//! they cannot tell you whether the dispatcher ever calls `authorize`. The
//! store tests assert that a materialised claim has no pool identifier; they
//! cannot tell you what a context actually receives over the wire. Those are
//! different claims, and only one of them is about the system.
//!
//! So this file exercises what a person would do, in order:
//!
//! 1. the boundary — a context-scoped admin is refused every holder-scoped
//!    task, *at the wire*;
//! 2. the arc — store an attribute, build a profile over it, bind it into a
//!    context, and read back what that context can see;
//! 3. edit-once-everywhere — editing the pool changes what a bound context
//!    presents, without the context reading anything;
//! 4. the disclosure gate — `present` cannot be reached without a preview, and
//!    a preview cannot be spent twice.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use multibase::Base;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, build_provisionable_test_app, build_test_app};
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

// URIs as literals, so a constant rename in the SDK surfaces here too.
const ATTR_PUT: &str = "https://trusttasks.org/spec/persona/attribute/put/1.0";
const ATTR_LIST: &str = "https://trusttasks.org/spec/persona/attribute/list/1.0";
const ATTR_DELETE: &str = "https://trusttasks.org/spec/persona/attribute/delete/1.0";
const PROFILE_PUT: &str = "https://trusttasks.org/spec/persona/profile/put/1.0";
const PROFILE_GET: &str = "https://trusttasks.org/spec/persona/profile/get/1.0";
const PROFILE_LIST: &str = "https://trusttasks.org/spec/persona/profile/list/1.0";
const PROFILE_DELETE: &str = "https://trusttasks.org/spec/persona/profile/delete/1.0";
const BINDING_SET: &str = "https://trusttasks.org/spec/persona/binding/set/1.0";
const BINDING_GET: &str = "https://trusttasks.org/spec/persona/binding/get/1.0";
const BINDING_LIST: &str = "https://trusttasks.org/spec/persona/binding/list/1.0";
const CORRELATION: &str = "https://trusttasks.org/spec/persona/correlation/analyze/1.0";
const RENDERERS: &str = "https://trusttasks.org/spec/persona/renderers/list/1.0";
const CLAIM_TYPES: &str = "https://trusttasks.org/spec/persona/claim-types/list/1.0";
const DISCLOSURE_HISTORY: &str = "https://trusttasks.org/spec/persona/disclosure/history/1.0";
const PREVIEW: &str = "https://trusttasks.org/spec/persona/disclosure/preview/1.0";
const PRESENT: &str = "https://trusttasks.org/spec/persona/disclosure/present/1.0";
const LOCAL_PROFILE_PUT: &str = "https://trusttasks.org/spec/persona/local/profile/put/1.0";
const LOCAL_PROFILE_GET: &str = "https://trusttasks.org/spec/persona/local/profile/get/1.0";
const LOCAL_PROFILE_LIST: &str = "https://trusttasks.org/spec/persona/local/profile/list/1.0";
const LOCAL_PROFILE_DELETE: &str = "https://trusttasks.org/spec/persona/local/profile/delete/1.0";
const LOCAL_BINDING_SET: &str = "https://trusttasks.org/spec/persona/local/binding/set/1.0";
const CONTACT_PUT: &str = "https://trusttasks.org/spec/persona/contact/put/1.0";
const CONTACT_GET: &str = "https://trusttasks.org/spec/persona/contact/get/1.0";
const CONTACT_LIST: &str = "https://trusttasks.org/spec/persona/contact/list/1.0";
const CONTACT_DELETE: &str = "https://trusttasks.org/spec/persona/contact/delete/1.0";

const CTX: &str = "ctx-persona-e2e";

/// A fixed holder `did:key` (Ed25519, multicodec 0xed01), derived from seed 7
/// so the envelope issuer and the signing key agree.
fn holder_did() -> String {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let mut mc = vec![0xed, 0x01];
    mc.extend_from_slice(sk.verifying_key().as_bytes());
    format!("did:key:{}", multibase::encode(Base::Base58Btc, mc))
}

/// Bearer token for `role` scoped to `allowed_contexts`.
///
/// An empty slice with `role = "admin"` is *unrestricted* — the super-admin
/// the holder-scoped tasks require. A non-empty slice with the same role is a
/// context administrator, which those tasks must refuse. That difference is
/// the whole subject of the first test below, and it is why these tests never
/// test `allowed_contexts.is_empty()` themselves.
async fn authed(ctx: &TestAppContext, tag: &str, role: &str, allowed_contexts: &[&str]) -> String {
    let did = holder_did();
    let session_id = format!("sess-persona-{tag}");
    let session = Session {
        session_id: session_id.clone(),
        did: did.clone(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: None,
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".to_string()],
        acr: "aal1".to_string(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();

    let contexts: Vec<String> = allowed_contexts.iter().map(|s| s.to_string()).collect();
    let claims = ctx
        .jwt_keys
        .new_claims(did, session_id, role.to_string(), contexts, 900, false);
    ctx.jwt_keys.encode(&claims).unwrap()
}

/// POST a persona Trust Task to the cheap sentinel-DID app and return
/// `(status, parsed body)`.
async fn post(
    router: &axum::Router,
    token: &str,
    uri: &str,
    payload: Value,
) -> (StatusCode, Value) {
    post_to(
        router,
        token,
        "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD",
        uri,
        payload,
    )
    .await
}

/// As [`post`], addressed to `recipient`.
///
/// SPEC §7.2 item 5 enforces the recipient in band, so a test running against
/// [`build_provisionable_test_app`] — whose VTA has a real, self-resolving
/// signing identity rather than the sentinel DID — has to say so, or every
/// request is refused for the wrong reason.
async fn post_to(
    router: &axum::Router,
    token: &str,
    recipient: &str,
    uri: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let mut typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("tt-{}", uuid::Uuid::new_v4()),
        "type": uri,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": holder_did(),
        "recipient": recipient,
        "payload": payload,
    }))
    .expect("envelope deserialises");
    vta_service::test_support::sign_as(7, &mut typed);
    let doc = serde_json::to_value(&typed).expect("envelope serialises");

    let req = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes).into_owned() }));
    (status, body)
}

/// The payload of a `#response` document, or the whole body if the shape is
/// unexpected — so an assertion failure shows what actually came back.
fn payload_of(body: &Value) -> &Value {
    body.get("payload").unwrap_or(body)
}

/// Did this response refuse the request? A Trust Task rejection is carried in
/// the document, not (only) in the HTTP status, so both are consulted.
fn refused(status: StatusCode, body: &Value) -> bool {
    !status.is_success()
        || body
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| t.ends_with("#reject") || t.ends_with("#error"))
        || body.get("payload").and_then(|p| p.get("code")).is_some()
}

/// Store one self-asserted attribute and return its id.
async fn put_attribute(
    router: &axum::Router,
    token: &str,
    claim_type: &str,
    value: &str,
) -> String {
    put_attribute_at(
        router,
        token,
        "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD",
        claim_type,
        value,
    )
    .await
}

/// As [`put_attribute`], against the VTA named by `recipient`.
async fn put_attribute_at(
    router: &axum::Router,
    token: &str,
    recipient: &str,
    claim_type: &str,
    value: &str,
) -> String {
    let (status, body) = post_to(
        router,
        token,
        recipient,
        ATTR_PUT,
        json!({
            "type": claim_type,
            "value": value,
            "valueType": "string",
            "provenance": { "kind": "selfAsserted" },
        }),
    )
    .await;
    assert!(
        status.is_success() && !refused(status, &body),
        "attribute/put failed: {status} {body}"
    );
    payload_of(&body)
        .get("attributeId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no attributeId in {body}"))
        .to_string()
}

// ---------------------------------------------------------------------------
// 1. The boundary, at the wire
// ---------------------------------------------------------------------------

/// A context administrator is refused every holder-scoped task.
///
/// The unit test beside `authorize` asserts the same rule against the
/// function. This asserts it against the *system*: that the dispatcher routes
/// these URIs to a handler which consults `authorize` before touching the
/// store. A handler wired up without its guard passes the unit test and fails
/// here, which is the failure worth catching — an administrator scoped to one
/// context would otherwise read and write the identity data of every other.
#[tokio::test]
async fn a_context_admin_cannot_reach_the_pool_over_the_wire() {
    let (router, ctx) = build_test_app().await;
    let scoped = authed(&ctx, "scoped", "admin", &[CTX]).await;

    let holder_only: &[(&str, Value)] = &[
        (
            ATTR_PUT,
            json!({
                "type": "name.legal",
                "value": "Ada",
                "valueType": "string",
                "provenance": { "kind": "selfAsserted" },
            }),
        ),
        (ATTR_LIST, json!({})),
        (
            ATTR_DELETE,
            json!({ "attributeId": "01J0000000000000000000000A" }),
        ),
        (PROFILE_PUT, json!({ "name": "work", "entries": [] })),
        (
            PROFILE_GET,
            json!({ "profileId": "01J0000000000000000000000A" }),
        ),
        (PROFILE_LIST, json!({})),
        (
            PROFILE_DELETE,
            json!({ "profileId": "01J0000000000000000000000A" }),
        ),
        (CORRELATION, json!({ "candidate": { "value": "Ada" } })),
        (DISCLOSURE_HISTORY, json!({})),
    ];

    for (uri, payload) in holder_only {
        let (status, body) = post(&router, &scoped, uri, payload.clone()).await;
        assert!(
            refused(status, &body),
            "{uri} was ALLOWED for a context-scoped admin — the pool is not any \
             one context's to read. Got {status}: {body}"
        );
    }
}

/// The same tasks succeed for an unrestricted caller.
///
/// Without this, the test above would pass just as well against a slice that
/// refuses everybody — which is the classic way a security test stops testing
/// anything.
#[tokio::test]
async fn an_unrestricted_admin_can_reach_the_pool() {
    let (router, ctx) = build_test_app().await;
    let holder = authed(&ctx, "holder-reach", "admin", &[]).await;

    for (uri, payload) in [(ATTR_LIST, json!({})), (PROFILE_LIST, json!({}))] {
        let (status, body) = post(&router, &holder, uri, payload).await;
        assert!(
            !refused(status, &body),
            "{uri} was refused for an unrestricted admin: {status} {body}"
        );
    }
}

/// `renderers/list` is reachable by everyone, and that is deliberate.
///
/// It sits on neither side of the boundary. The response is a compile-time
/// constant — the renderer ids this build ships and what each discards — and
/// names nothing about the holder or any context.
///
/// Both other classifications are wrong for it, in opposite directions. As a
/// context task it refuses the unscoped holder, because its payload schema has
/// no `contextId` to name; the handler that supplied one from
/// `auth.allowed_contexts.first()` therefore refused the MOST privileged
/// caller — an `Admin` with an unrestricted, empty context list — while
/// admitting every scoped one. As a holder task it would refuse the callers
/// who most need it: `disclosure/preview` is context-scoped and takes a
/// renderer name, so an application that cannot list renderers cannot choose
/// one, and choosing blind is how a holder discloses through a format that
/// silently drops provenance.
///
/// This test asserts both directions, because a fix in either alone reads as
/// working.
#[tokio::test]
async fn listing_renderers_is_open_to_scoped_and_unscoped_callers_alike() {
    let (router, ctx) = build_test_app().await;

    for (tag, contexts) in [("rend-unscoped", &[][..]), ("rend-scoped", &[CTX][..])] {
        let token = authed(&ctx, tag, "admin", contexts).await;
        let (status, body) = post(&router, &token, RENDERERS, json!({})).await;
        assert!(
            !refused(status, &body),
            "{tag} could not list renderers: {status} {body}"
        );
        let rendered = serde_json::to_string(payload_of(&body)).expect("serialises");
        assert!(
            rendered.contains("drops"),
            "a renderer listing must declare what each format discards: {rendered}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. The arc
// ---------------------------------------------------------------------------

/// Store an attribute, project it through a profile, bind it into a context,
/// and read back what that context is told.
///
/// The assertion that matters is the last one: `binding/get` reports *whether*
/// a persona is bound and *how many* claims it carries, and never the claims
/// themselves. Contents reach a context only through the disclosure path,
/// which requires a preview. A binding read that returned values would make
/// the two-call gate decorative.
#[tokio::test]
async fn an_attribute_reaches_a_context_only_as_a_count() {
    let (router, ctx) = build_test_app().await;
    let holder = authed(&ctx, "arc", "admin", &[]).await;

    let attr = put_attribute(&router, &holder, "phone.mobile", "+61 400 000 000").await;

    let (status, body) = post(
        &router,
        &holder,
        PROFILE_PUT,
        json!({ "name": "work", "entries": [{ "ref": attr }] }),
    )
    .await;
    assert!(!refused(status, &body), "profile/put: {status} {body}");
    let profile = payload_of(&body)
        .get("profileId")
        .and_then(Value::as_str)
        .expect("profileId")
        .to_string();

    let persona = "did:key:z6MkPersonaWork";
    let (status, body) = post(
        &router,
        &holder,
        BINDING_SET,
        json!({ "contextId": CTX, "personaDid": persona, "profileId": profile }),
    )
    .await;
    assert!(!refused(status, &body), "binding/set: {status} {body}");
    assert_eq!(
        payload_of(&body).get("materialisedClaimCount"),
        Some(&json!(1)),
        "one claim should have been pushed down: {body}"
    );

    // Read it back as the context would.
    let scoped = authed(&ctx, "arc-scoped", "admin", &[CTX]).await;
    let (status, body) = post(
        &router,
        &scoped,
        BINDING_GET,
        json!({ "contextId": CTX, "personaDid": persona }),
    )
    .await;
    assert!(!refused(status, &body), "binding/get: {status} {body}");

    let p = payload_of(&body);
    assert_eq!(p.get("bound"), Some(&json!(true)), "{body}");
    assert_eq!(p.get("claimCount"), Some(&json!(1)), "{body}");

    let rendered = serde_json::to_string(p).expect("serialises");
    assert!(
        !rendered.contains(&attr),
        "the pool identifier {attr} crossed into the context: {rendered}"
    );
    assert!(
        !rendered.contains("+61 400 000 000"),
        "a binding read returned claim contents; contents belong to the \
         disclosure path: {rendered}"
    );
}

/// Editing the pool changes what the HOLDER sees resolved.
///
/// **This test does not show that anything was pushed, and it used to say it
/// did.** Its docstring read "this is the test that the push actually happens";
/// it asserts through `profile/get?resolve=true`, which resolves live from the
/// pool on every call, so it passed with nothing pushed anywhere — and did,
/// for the whole time `rematerialise` was called from no handler at all. A
/// verifier was being handed the value from before the edit.
///
/// Kept, because the holder-side resolution is worth pinning on its own. The
/// push is asserted by `a_pool_edit_reaches_the_copy_a_verifier_is_shown`,
/// through the materialised copy, which is the only place the two differ.
///
/// The general lesson, and it is the same one VTI#1268 taught this family:
/// a test that reads through the path it is trying to prove exists cannot
/// fail. Assert through the *other* side.
#[tokio::test]
async fn editing_the_pool_updates_an_already_bound_context() {
    let (router, ctx) = build_test_app().await;
    let holder = authed(&ctx, "edit", "admin", &[]).await;

    let attr = put_attribute(&router, &holder, "name.display", "Ada").await;
    let (_, body) = post(
        &router,
        &holder,
        PROFILE_PUT,
        json!({ "name": "public", "entries": [{ "ref": attr }] }),
    )
    .await;
    let profile = payload_of(&body)
        .get("profileId")
        .and_then(Value::as_str)
        .expect("profileId")
        .to_string();

    let persona = "did:key:z6MkPersonaPublic";
    let (status, body) = post(
        &router,
        &holder,
        BINDING_SET,
        json!({ "contextId": CTX, "personaDid": persona, "profileId": profile }),
    )
    .await;
    assert!(!refused(status, &body), "binding/set: {status} {body}");

    // Edit the pool attribute in place.
    let (status, body) = post(
        &router,
        &holder,
        ATTR_PUT,
        json!({
            "attributeId": attr,
            "type": "name.display",
            "value": "Ada Lovelace",
            "valueType": "string",
            "provenance": { "kind": "selfAsserted" },
        }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "attribute/put (edit): {status} {body}"
    );

    // The projection the context holds must have moved with it. Read through
    // the profile's resolved view, which is the holder-side mirror of what was
    // pushed down.
    let (status, body) = post(
        &router,
        &holder,
        PROFILE_GET,
        json!({ "profileId": profile, "resolve": true }),
    )
    .await;
    assert!(!refused(status, &body), "profile/get: {status} {body}");
    let rendered = serde_json::to_string(payload_of(&body)).expect("serialises");
    assert!(
        rendered.contains("Ada Lovelace"),
        "the profile still presents the old value: {rendered}"
    );
}

/// An unbound persona is an answer, not an error.
///
/// Four of `binding/get`'s members are absent when nothing is bound, and
/// absent is not null — a `json!` over an `Option` renders `null`, which none
/// of those members' types accept. The bound path conformed and the unbound
/// path did not, which is the wrong way round: "nobody is bound here" is
/// exactly the reading a caller needs to be able to trust.
#[tokio::test]
async fn an_unbound_persona_reads_back_cleanly() {
    let (router, ctx) = build_test_app().await;
    let scoped = authed(&ctx, "unbound", "admin", &[CTX]).await;

    let (status, body) = post(
        &router,
        &scoped,
        BINDING_GET,
        json!({ "contextId": CTX, "personaDid": "did:key:z6MkNeverBound" }),
    )
    .await;
    assert!(!refused(status, &body), "binding/get: {status} {body}");

    let p = payload_of(&body);
    assert_eq!(p.get("bound"), Some(&json!(false)), "{body}");
    for absent in ["profileId", "profileName", "boundAt"] {
        assert!(
            p.get(absent).is_none(),
            "{absent} should be absent for an unbound persona, not null: {body}"
        );
    }
}

/// A profile carrying an inline entry resolves like any other, with the three
/// pool members absent rather than the whole response refused.
///
/// `persona/profile/get/1.0` used to type each resolved entry as the pool
/// `Attribute`, which requires `attributeId`, `updatedAt` and `version`. An
/// inline entry has none of them — it has no pool record behind it, which is
/// the reason inline exists — so the response could not describe such a profile
/// at all, and the handler refused rather than answer non-conformantly.
///
/// Fixed upstream in dtgwg-trust-tasks-tf#370 and released in trust-tasks-rs
/// 0.18: `resolved` is now its own `ResolvedClaim` shape with those three
/// optional. **Their absence is the information** — it is what distinguishes a
/// value that lives only in this profile from one that tracks the pool — so
/// this asserts absence rather than merely a success.
///
/// The test this replaces was written to "exist to expire", and could not:
/// it asserted the refusal, which is behaviour this repository controls, not
/// the schema constraint it was waiting on. It passed unchanged across the
/// bump. A test that genuinely self-expires has to key on the thing that
/// moves — the generated type's own shape — rather than on the behaviour built
/// around it.
#[tokio::test]
async fn an_inline_entry_resolves_without_pool_identity() {
    let (router, ctx) = build_test_app().await;
    let holder = authed(&ctx, "inline", "admin", &[]).await;

    let (status, body) = post(
        &router,
        &holder,
        PROFILE_PUT,
        json!({
            "name": "handle-only",
            "entries": [{
                "inline": {
                    "type": "x:handle",
                    "value": "ada",
                    "valueType": "string",
                    "provenance": { "kind": "selfAsserted" },
                }
            }],
        }),
    )
    .await;
    assert!(!refused(status, &body), "profile/put: {status} {body}");
    let profile = payload_of(&body)
        .get("profileId")
        .and_then(Value::as_str)
        .expect("profileId")
        .to_string();

    let (status, body) = post(
        &router,
        &holder,
        PROFILE_GET,
        json!({ "profileId": profile, "resolve": true }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "resolving an inline entry was refused: {status} {body}"
    );

    let resolved = payload_of(&body)
        .get("resolved")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no resolved array in {body}"));
    assert_eq!(resolved.len(), 1, "the inline entry must be listed: {body}");

    let entry = &resolved[0];
    assert_eq!(entry.get("type"), Some(&json!("x:handle")), "{body}");
    assert_eq!(entry.get("value"), Some(&json!("ada")), "{body}");
    assert_eq!(entry.get("valueType"), Some(&json!("string")), "{body}");

    // The three that say "this value has no pool record". Absent, and not null
    // — a null would fail the response schema, which is how the sibling
    // defects in this family were found.
    for absent in ["attributeId", "version", "updatedAt"] {
        assert!(
            entry.get(absent).is_none(),
            "{absent} should be absent for an inline entry, not present or null: {body}"
        );
    }
}

/// A pool-backed entry still carries all three, so the test above is asserting
/// a distinction rather than a uniformly empty response.
///
/// Without this, `an_inline_entry_resolves_without_pool_identity` would pass
/// just as well against a handler that had stopped emitting those members
/// altogether — which is the shape a security test takes when it quietly stops
/// testing anything.
#[tokio::test]
async fn a_pool_backed_entry_still_carries_its_identity() {
    let (router, ctx) = build_test_app().await;
    let holder = authed(&ctx, "pool-backed", "admin", &[]).await;

    let attr = put_attribute(&router, &holder, "name.display", "Ada").await;
    let (_, body) = post(
        &router,
        &holder,
        PROFILE_PUT,
        json!({ "name": "tracks-pool", "entries": [{ "ref": attr }] }),
    )
    .await;
    let profile = payload_of(&body)
        .get("profileId")
        .and_then(Value::as_str)
        .expect("profileId")
        .to_string();

    let (status, body) = post(
        &router,
        &holder,
        PROFILE_GET,
        json!({ "profileId": profile, "resolve": true }),
    )
    .await;
    assert!(!refused(status, &body), "profile/get: {status} {body}");

    let entry = &payload_of(&body)
        .get("resolved")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no resolved array in {body}"))[0];
    assert_eq!(entry.get("attributeId"), Some(&json!(attr)), "{body}");
    for present in ["version", "updatedAt"] {
        assert!(
            entry.get(present).is_some(),
            "{present} should be present for a pool-backed entry: {body}"
        );
    }
}

/// Contacts round-trip: record what a peer disclosed, read it back, list it,
/// forget it.
///
/// `contact/put` maps the wire document into the store's shape through the same
/// JSON round-trip that silently broke `local/profile/put` — where the two
/// shapes differed by one required member and every valid request was rejected.
/// This family had no test at all, so the same defect would have been just as
/// invisible.
#[tokio::test]
async fn a_contact_round_trips() {
    let (router, ctx) = build_test_app().await;
    let scoped = authed(&ctx, "contacts", "admin", &[CTX]).await;
    let persona = "did:key:z6MkPersonaKnows";

    let (status, body) = post(
        &router,
        &scoped,
        CONTACT_PUT,
        json!({
            "contextId": CTX,
            "subjectDid": "did:key:z6MkPeer",
            "knownByPersona": persona,
            "document": {
                "claims": [
                    { "type": "name.display", "value": "Grace", "valueType": "string" }
                ]
            },
            "notes": "met at the working group",
        }),
    )
    .await;
    assert!(!refused(status, &body), "contact/put: {status} {body}");
    let contact_id = payload_of(&body)
        .get("contactId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no contactId in {body}"))
        .to_string();

    let (status, body) = post(
        &router,
        &scoped,
        CONTACT_GET,
        json!({ "contextId": CTX, "contactId": contact_id }),
    )
    .await;
    assert!(!refused(status, &body), "contact/get: {status} {body}");
    let got = payload_of(&body);
    let rendered = serde_json::to_string(got).expect("serialises");
    assert!(
        rendered.contains("Grace"),
        "the stored claim came back changed: {rendered}"
    );

    // Assert the members that were silently dropped, not just that something
    // came back. `valueType` had no field in the stored shape at all, and
    // `notes` — documented as the holder's private annotation — was accepted on
    // the wire and never stored. Both round-trip now, and a test that only
    // checked the response parsed would have missed both.
    assert!(
        rendered.contains("\"valueType\":\"string\""),
        "valueType did not survive the round trip: {rendered}"
    );
    assert_eq!(
        got.get("notes"),
        Some(&json!("met at the working group")),
        "the holder's private note was not stored: {rendered}"
    );

    let (status, body) = post(
        &router,
        &scoped,
        CONTACT_LIST,
        json!({ "contextId": CTX, "knownByPersona": persona }),
    )
    .await;
    assert!(!refused(status, &body), "contact/list: {status} {body}");

    let (status, body) = post(
        &router,
        &scoped,
        CONTACT_DELETE,
        json!({ "contextId": CTX, "contactId": contact_id }),
    )
    .await;
    assert!(!refused(status, &body), "contact/delete: {status} {body}");
}

/// The context-local family, end to end: author a profile, bind a persona to
/// it, read the binding back, list, then delete.
///
/// Four of these five tasks had no test at all. `local/profile/put` was the one
/// that happened to be exercised — by a test asserting it *refuses* — and it
/// was broken for every valid request. The rest were untested in both
/// directions.
#[tokio::test]
async fn the_context_local_family_round_trips() {
    let (router, ctx) = build_test_app().await;
    let scoped = authed(&ctx, "local-walk", "admin", &[CTX]).await;
    let persona = "did:key:z6MkPersonaLocal";

    let (status, body) = post(
        &router,
        &scoped,
        LOCAL_PROFILE_PUT,
        json!({
            "contextId": CTX,
            "name": "game handle",
            "entries": [{
                "inline": { "type": "x:handle", "value": "ada99", "valueType": "string" }
            }],
        }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "local/profile/put: {status} {body}"
    );
    let profile = payload_of(&body)
        .get("profileId")
        .and_then(Value::as_str)
        .expect("profileId")
        .to_string();

    let (status, body) = post(
        &router,
        &scoped,
        LOCAL_BINDING_SET,
        json!({ "contextId": CTX, "personaDid": persona, "profileId": profile }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "local/binding/set: {status} {body}"
    );

    // Read back through the ordinary binding view — a local binding is a
    // binding, and a context should not need to know which kind it got.
    let (status, body) = post(
        &router,
        &scoped,
        BINDING_GET,
        json!({ "contextId": CTX, "personaDid": persona }),
    )
    .await;
    assert!(!refused(status, &body), "binding/get: {status} {body}");
    assert_eq!(payload_of(&body).get("bound"), Some(&json!(true)), "{body}");

    // `binding/list` is the context's own enumeration — the only task in the
    // family with no coverage at all, positive or negative, and so the only one
    // whose response shape nothing had ever looked at. It reports the same thin
    // summary as `binding/get`, so the same rule applies: whether bound and how
    // many claims, never contents.
    let (status, body) = post(&router, &scoped, BINDING_LIST, json!({ "contextId": CTX })).await;
    assert!(!refused(status, &body), "binding/list: {status} {body}");
    let personas = payload_of(&body)
        .get("personas")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no personas array in {body}"));
    let row = personas
        .iter()
        .find(|p| p.get("personaDid") == Some(&json!(persona)))
        .unwrap_or_else(|| panic!("the bound persona is missing from the listing: {body}"));
    assert_eq!(row.get("bound"), Some(&json!(true)), "{body}");
    let rendered = serde_json::to_string(row).expect("serialises");
    assert!(
        !rendered.contains("ada99"),
        "a binding listing returned claim contents: {rendered}"
    );

    let (status, body) = post(
        &router,
        &scoped,
        LOCAL_PROFILE_GET,
        json!({ "contextId": CTX, "profileId": profile }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "local/profile/get: {status} {body}"
    );

    let (status, body) = post(
        &router,
        &scoped,
        LOCAL_PROFILE_LIST,
        json!({ "contextId": CTX }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "local/profile/list: {status} {body}"
    );

    // `unbind` because a persona is presenting under it — the same refusal the
    // pool profiles carry, and the reason it is not a delete-by-omission.
    let (status, body) = post(
        &router,
        &scoped,
        LOCAL_PROFILE_DELETE,
        json!({ "contextId": CTX, "profileId": profile, "unbind": true }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "local/profile/delete: {status} {body}"
    );
}

/// The holder-scoped tasks that were only ever exercised as refusals.
///
/// `attribute/delete`, `profile/delete`, `correlation/analyze` and
/// `disclosure/history` appear in `a_context_admin_cannot_reach_the_pool_over_
/// the_wire` and nowhere else, so every one of them was asserted to fail and
/// none was asserted to work. That is the same shape as the
/// `local/profile/put` defect, on four more tasks.
#[tokio::test]
async fn the_holder_only_tasks_also_succeed_for_a_holder() {
    let (router, ctx) = build_test_app().await;
    let holder = authed(&ctx, "holder-happy", "admin", &[]).await;

    let attr = put_attribute(&router, &holder, "name.legal", "Ada Lovelace").await;

    let (status, body) = post(
        &router,
        &holder,
        CORRELATION,
        json!({ "attributeId": attr }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "correlation/analyze: {status} {body}"
    );

    let (status, body) = post(&router, &holder, DISCLOSURE_HISTORY, json!({})).await;
    assert!(
        !refused(status, &body),
        "disclosure/history: {status} {body}"
    );

    let (_, body) = post(
        &router,
        &holder,
        PROFILE_PUT,
        json!({ "name": "doomed", "entries": [{ "ref": attr }] }),
    )
    .await;
    let profile = payload_of(&body)
        .get("profileId")
        .and_then(Value::as_str)
        .expect("profileId")
        .to_string();

    let (status, body) = post(
        &router,
        &holder,
        PROFILE_DELETE,
        json!({ "profileId": profile, "unbind": true }),
    )
    .await;
    assert!(!refused(status, &body), "profile/delete: {status} {body}");

    // Cascade because the profile above referenced it; without the profile now
    // gone this would be refused, which is itself worth exercising.
    let (status, body) = post(
        &router,
        &holder,
        ATTR_DELETE,
        json!({ "attributeId": attr, "cascade": true }),
    )
    .await;
    assert!(!refused(status, &body), "attribute/delete: {status} {body}");
}

// ---------------------------------------------------------------------------
// 3. The disclosure gate
// ---------------------------------------------------------------------------

/// `present` cannot be reached without a preview, and a preview cannot be
/// spent twice.
///
/// The two-call gate is structural — `present` consumes a token only `preview`
/// mints — but "structural" is a claim about wiring, and wiring is what an
/// end-to-end test is for. A fabricated preview id must be refused, and a real
/// one must not work twice: a preview a holder approved once is not standing
/// approval for a second disclosure.
#[tokio::test]
async fn a_disclosure_needs_a_preview_and_cannot_replay_one() {
    let (router, ctx) = build_test_app().await;
    let holder = authed(&ctx, "gate", "admin", &[]).await;
    let scoped = authed(&ctx, "gate-scoped", "admin", &[CTX]).await;

    // A preview id that was never minted.
    let (status, body) = post(
        &router,
        &scoped,
        PRESENT,
        json!({ "contextId": CTX, "previewId": "01J0000000000000000000000A" }),
    )
    .await;
    assert!(
        refused(status, &body),
        "present accepted a preview id that was never minted: {status} {body}"
    );

    // Now the real path.
    let attr = put_attribute(&router, &holder, "name.display", "Ada").await;
    let (_, body) = post(
        &router,
        &holder,
        PROFILE_PUT,
        json!({ "name": "shown", "entries": [{ "ref": attr }] }),
    )
    .await;
    let profile = payload_of(&body)
        .get("profileId")
        .and_then(Value::as_str)
        .expect("profileId")
        .to_string();

    let persona = "did:key:z6MkPersonaShown";
    let (status, body) = post(
        &router,
        &holder,
        BINDING_SET,
        json!({ "contextId": CTX, "personaDid": persona, "profileId": profile }),
    )
    .await;
    assert!(!refused(status, &body), "binding/set: {status} {body}");

    let (status, body) = post(
        &router,
        &scoped,
        PREVIEW,
        json!({
            "contextId": CTX,
            "personaDid": persona,
            "verifierDid": "did:key:z6MkVerifier",
            "purpose": "age check",
        }),
    )
    .await;
    assert!(!refused(status, &body), "preview: {status} {body}");
    let preview_id = payload_of(&body)
        .get("previewId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no previewId in {body}"))
        .to_string();

    let (status, body) = post(
        &router,
        &scoped,
        PRESENT,
        json!({ "contextId": CTX, "previewId": preview_id }),
    )
    .await;
    assert!(!refused(status, &body), "present: {status} {body}");

    // The same preview, a second time.
    let (status, body) = post(
        &router,
        &scoped,
        PRESENT,
        json!({ "contextId": CTX, "previewId": preview_id }),
    )
    .await;
    assert!(
        refused(status, &body),
        "a preview was spent twice — the second disclosure rode the first \
         decision: {status} {body}"
    );
}

/// A context-local profile can actually be created.
///
/// The sibling test below asserts that an invalid entry is refused. On its own
/// that proves nothing: a handler that refuses *everything* passes it. This is
/// the other half — and it is the half that was missing, which is why
/// `local/profile/put` shipped rejecting every valid request.
#[tokio::test]
async fn a_context_local_profile_can_be_created() {
    let (router, ctx) = build_test_app().await;
    let scoped = authed(&ctx, "local-ok", "admin", &[CTX]).await;

    let (status, body) = post(
        &router,
        &scoped,
        LOCAL_PROFILE_PUT,
        json!({
            "contextId": CTX,
            "name": "throwaway",
            "entries": [{
                "inline": {
                    "type": "x:handle",
                    "value": "ada",
                    "valueType": "string",
                }
            }],
        }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "a valid context-local profile was refused: {status} {body}"
    );
    assert!(
        payload_of(&body).get("profileId").is_some(),
        "no profileId returned: {body}"
    );
}

/// A context-local profile cannot name a pool attribute, and the refusal
/// happens at the wire rather than at the client.
///
/// The SDK models this as a distinct type and the CLI turns the parse error
/// into an explanation, but neither is a control: a caller that speaks JSON
/// bypasses both. This is the assertion that the closure lives in the
/// published schema and is enforced by the VTA.
#[tokio::test]
async fn a_context_local_profile_cannot_reference_the_pool() {
    let (router, ctx) = build_test_app().await;
    let scoped = authed(&ctx, "local", "admin", &[CTX]).await;

    let (status, body) = post(
        &router,
        &scoped,
        LOCAL_PROFILE_PUT,
        json!({
            "contextId": CTX,
            "name": "local-only",
            "entries": [{ "ref": "01J0000000000000000000000A" }],
        }),
    )
    .await;
    assert!(
        refused(status, &body),
        "a context-local profile was allowed to reference the holder's pool: \
         {status} {body}"
    );
}

/// **What a bound context actually holds after the pool is edited.**
///
/// `editing_the_pool_updates_an_already_bound_context` above claims to cover
/// this and does not. It asserts through `profile/get?resolve=true`, which
/// resolves live from the pool on every call — so it passes whether or not
/// anything was ever pushed down, and would pass with `rematerialise` deleted
/// outright. Its own docstring says it is "the test that the push actually
/// happens", which is the reading that let the gap ship.
///
/// This asserts through `disclosure/preview`, which reads the **materialised**
/// claims the binding holds. That is the copy a verifier is shown, and it is
/// the only place the difference between "the profile projects X" and "the
/// context holds X" is observable.
#[tokio::test]
async fn a_pool_edit_reaches_the_copy_a_verifier_is_shown() {
    let (router, ctx) = build_test_app().await;
    let holder = authed(&ctx, "push", "admin", &[]).await;
    let scoped = authed(&ctx, "push-scoped", "admin", &[CTX]).await;

    let attr = put_attribute(&router, &holder, "name.display", "Ada").await;
    let (_, body) = post(
        &router,
        &holder,
        PROFILE_PUT,
        json!({ "name": "pushed", "entries": [{ "ref": attr }] }),
    )
    .await;
    let profile = payload_of(&body)
        .get("profileId")
        .and_then(Value::as_str)
        .expect("profileId")
        .to_string();

    let persona = "did:key:z6MkPersonaPushed";
    let (status, body) = post(
        &router,
        &holder,
        BINDING_SET,
        json!({ "contextId": CTX, "personaDid": persona, "profileId": profile }),
    )
    .await;
    assert!(!refused(status, &body), "binding/set: {status} {body}");

    // The edit the holder makes once, expecting it everywhere.
    let (status, body) = post(
        &router,
        &holder,
        ATTR_PUT,
        json!({
            "attributeId": attr,
            "type": "name.display",
            "value": "Ada Lovelace",
            "valueType": "string",
            "provenance": { "kind": "selfAsserted" },
        }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "attribute/put (edit): {status} {body}"
    );

    let (status, body) = post(
        &router,
        &scoped,
        PREVIEW,
        json!({
            "contextId": CTX,
            "personaDid": persona,
            "verifierDid": "did:key:z6MkVerifierPushed",
            "purpose": "who are you",
        }),
    )
    .await;
    assert!(!refused(status, &body), "preview: {status} {body}");

    let rendered = serde_json::to_string(payload_of(&body)).expect("serialises");
    assert!(
        rendered.contains("Ada Lovelace"),
        "the verifier would be shown the value from before the edit — \"edit once, \
         everywhere\" did not reach the materialised copy: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// 5. The audit trail says what changed
// ---------------------------------------------------------------------------

/// Every row the audit keyspace holds, oldest first.
///
/// Read straight from the keyspace rather than through `audit/list`, because
/// that task's own authorization is a separate subject and a test that had to
/// satisfy it would be asserting two things at once. The storage key is
/// `log:{timestamp:020}:{uuid}`, so a lexicographic scan is chronological.
async fn audit_rows(
    ctx: &TestAppContext,
) -> Vec<vta_sdk::protocols::audit_management::list::AuditLogEntry> {
    let mut pairs = ctx
        .state
        .audit_ks
        .prefix_iter_raw("log:")
        .await
        .expect("audit prefix scan");
    pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
    pairs
        .into_iter()
        .filter_map(|(_k, v)| serde_json::from_slice(&v).ok())
        .collect()
}

/// A persona write leaves an audit row that says **what changed** — and that
/// row does not contain the value.
///
/// Both halves are needed and neither is sufficient. The positive half is the
/// defect this exists for: `audit_persona` recorded action, actor, resource
/// and outcome and nothing else, so a console audit pane showed
/// `persona.attribute.put` against an opaque ULID with no way to tell a create
/// from an update or a cascade delete from a no-op. The console renders
/// `detail` in full; there was simply nothing to render.
///
/// The negative half is the rule `audit_persona` documents at length: the
/// attribute VALUE is never recorded, because the audit log outlives the
/// record it describes and a value copied into it would survive the holder's
/// delete under a retention policy that delete does not reach.
///
/// **Asserted together, deliberately.** A test that only checks the value is
/// absent passes against a handler that records no detail at all — which is
/// exactly the state this pair of assertions replaces, and exactly the way a
/// regression would look if `detail` were quietly dropped again.
#[tokio::test]
async fn a_persona_write_is_audited_with_what_changed_and_not_the_value() {
    let (router, ctx) = build_test_app().await;
    let holder = authed(&ctx, "audit-detail", "admin", &[]).await;

    // A value distinctive enough that finding it anywhere in the log is
    // unambiguous — a substring like "Ada" could appear by coincidence in a
    // claim type or an identifier, and the assertion would then be about the
    // wrong thing.
    const SECRET_VALUE: &str = "+61 400 999 777 zzq";

    let attr = put_attribute(&router, &holder, "phone.mobile", SECRET_VALUE).await;

    let rows = audit_rows(&ctx).await;
    let put_row = rows
        .iter()
        .rev()
        .find(|r| r.action == "persona.attribute.put")
        .unwrap_or_else(|| panic!("no persona.attribute.put audit row in {rows:#?}"));

    let detail = put_row
        .detail
        .as_deref()
        .unwrap_or_else(|| panic!("the audit row carries no detail: {put_row:#?}"));

    // What CHANGED, not merely that something did.
    assert!(
        detail.contains("created"),
        "the detail does not say the attribute was created: {detail}"
    );
    assert!(
        detail.contains("phone.mobile"),
        "the detail does not name the claim type — the one thing that makes the row \
         legible without resolving the id: {detail}"
    );
    assert!(
        detail.contains("selfAsserted"),
        "the detail does not name the provenance kind: {detail}"
    );
    assert!(
        detail.contains(&attr),
        "the detail does not name the attribute it describes: {detail}"
    );

    // And not the value — anywhere in the row, not merely in `detail`.
    let whole_row = serde_json::to_string(put_row).expect("audit row serialises");
    assert!(
        !whole_row.contains(SECRET_VALUE),
        "the attribute's VALUE reached the audit log. The log outlives the record, \
         so this value would survive the holder deleting the attribute it came \
         from: {whole_row}"
    );

    // The same pair on a delete, because that is the operation the lifetime
    // argument is actually about: after it, the pool no longer holds the value
    // and the audit row is the only place a copy could persist.
    let (status, body) = post(
        &router,
        &holder,
        ATTR_DELETE,
        json!({ "attributeId": attr, "cascade": false }),
    )
    .await;
    assert!(!refused(status, &body), "attribute/delete: {status} {body}");

    let rows = audit_rows(&ctx).await;
    let delete_row = rows
        .iter()
        .rev()
        .find(|r| r.action == "persona.attribute.delete")
        .unwrap_or_else(|| panic!("no persona.attribute.delete audit row in {rows:#?}"));
    let detail = delete_row
        .detail
        .as_deref()
        .unwrap_or_else(|| panic!("the delete audit row carries no detail: {delete_row:#?}"));
    assert!(
        detail.contains("deleted"),
        "the delete detail does not distinguish a removal from a no-op: {detail}"
    );

    let whole_log = serde_json::to_string(&rows).expect("audit log serialises");
    assert!(
        !whole_log.contains(SECRET_VALUE),
        "the deleted attribute's value is still in the audit log: {whole_log}"
    );
}

// ---------------------------------------------------------------------------
// 5b. A listing withholds sensitive values, and the trail says which listing
//     it was
// ---------------------------------------------------------------------------

/// One attribute out of a listing response, by claim type.
fn listed<'a>(body: &'a Value, claim_type: &str) -> &'a Value {
    payload_of(body)
        .get("attributes")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no attributes array in {body}"))
        .iter()
        .find(|a| a.get("type").and_then(Value::as_str) == Some(claim_type))
        .unwrap_or_else(|| panic!("{claim_type} is missing from the listing: {body}"))
}

/// Every `detail` the trail holds for `action`.
///
/// A set rather than "the most recent one": the storage key is
/// `log:{timestamp:020}:{uuid}`, so rows written inside the same second are
/// ordered by a random uuid and "latest" is not a thing a test can ask for.
/// What the trail has to support is telling one listing from another, and that
/// is a claim about the whole set.
async fn details_for(ctx: &TestAppContext, action: &str) -> Vec<String> {
    audit_rows(ctx)
        .await
        .iter()
        .filter(|r| r.action == action)
        .map(|r| {
            r.detail
                .clone()
                .unwrap_or_else(|| panic!("a {action} audit row carries no detail: {r:#?}"))
        })
        .collect()
}

/// `includeValues` moves the ordinary attributes and leaves the card behind;
/// `includeSensitive` is what moves the card.
///
/// Asserted at the wire, because that is the only place the claim is about the
/// system. The store's own tests say `list_attributes` withholds; they cannot
/// say that the handler passes `includeSensitive` through, and a handler that
/// dropped it would pass every one of them while shipping card numbers to any
/// caller that asked for values.
///
/// The three listings are asserted together and so are their audit rows. A
/// trail in which "showed me my names" and "handed a process every card
/// number" are the same row cannot answer the question a holder reviewing it
/// has, and each half of that pair passes on its own against an implementation
/// that is wrong in the other direction.
#[tokio::test]
async fn a_listing_withholds_sensitive_values_and_says_so_in_the_audit_trail() {
    let (router, ctx) = build_test_app().await;
    let holder = authed(&ctx, "sensitive", "admin", &[]).await;

    // Distinctive enough that finding it anywhere in a response or a row is
    // unambiguous.
    const CARD: &str = "4242424242424242";
    const GIVEN: &str = "Ada";
    put_attribute(&router, &holder, "payment.card", CARD).await;
    put_attribute(&router, &holder, "name.given", GIVEN).await;

    // 1. Values, but not the sensitive ones. `payment.card` resolves to `high`
    //    from the registry — no holder set anything here.
    let (status, body) = post(
        &router,
        &holder,
        ATTR_LIST,
        json!({ "includeValues": true }),
    )
    .await;
    assert!(!refused(status, &body), "attribute/list: {status} {body}");
    assert!(
        listed(&body, "payment.card").get("value").is_none(),
        "a card number left the agent on a listing that asked only for values. \
         Masking it in the consumer defends a screen and not a log, a crash \
         dump, or the memory of the process holding it: {body}"
    );
    assert_eq!(
        listed(&body, "name.given")
            .get("value")
            .and_then(Value::as_str),
        Some(GIVEN),
        "an ordinary value was withheld too, which is a picker that shows the \
         holder nothing: {body}"
    );
    assert!(
        !serde_json::to_string(&body).unwrap().contains(CARD),
        "the card number is somewhere else in the response: {body}"
    );
    // The row is still there. This is withholding a value, not hiding an attribute:
    // a holder must not conclude their agent has lost the card.
    assert_eq!(
        listed(&body, "payment.card")
            .get("type")
            .and_then(Value::as_str),
        Some("payment.card")
    );

    // 2. And the escalation that moves it. The holder can always read their own
    //    pool back; what they cannot do is get there by forgetting.
    let (status, body) = post(
        &router,
        &holder,
        ATTR_LIST,
        json!({ "includeValues": true, "includeSensitive": true }),
    )
    .await;
    assert!(!refused(status, &body), "attribute/list: {status} {body}");
    assert_eq!(
        listed(&body, "payment.card")
            .get("value")
            .and_then(Value::as_str),
        Some(CARD),
        "the holder could not read their own card back by asking for it: {body}"
    );
    // 3. `includeSensitive` alone introduces no plaintext. It widens
    //    `includeValues` and is never a request of its own.
    let (status, body) = post(
        &router,
        &holder,
        ATTR_LIST,
        json!({ "includeSensitive": true }),
    )
    .await;
    assert!(!refused(status, &body), "attribute/list: {status} {body}");
    for claim_type in ["payment.card", "name.given"] {
        assert!(
            listed(&body, claim_type).get("value").is_none(),
            "`includeSensitive` without `includeValues` produced plaintext for \
             {claim_type}: {body}"
        );
    }

    // Three listings, three rows, and no two of them alike. The three ways this
    // task can behave are the three the holder most needs told apart, and the
    // response carries nothing that would let a reviewer reconstruct which was
    // which — a withheld value and an attribute that never had one look identical on
    // the wire.
    let details = details_for(&ctx, "persona.attribute.list").await;
    assert_eq!(details.len(), 3, "one row per listing: {details:#?}");
    assert_eq!(
        details
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3,
        "two listings are indistinguishable in the audit trail: {details:#?}"
    );
    for expected in [
        "values included, 1 sensitive value(s) withheld",
        "values included, sensitive values included",
        "metadata only",
    ] {
        assert!(
            details.iter().any(|d| d.contains(expected)),
            "no audit row says `{expected}`: {details:#?}"
        );
    }
}

/// The holder's own decision survives the write and decides the read — in the
/// direction the registry would not have chosen.
///
/// Both directions, because an implementation that honours only the tightening
/// one is not honouring an override at all: it is applying `max()` to the
/// holder's opinion and the registry's, which overrules the person the control
/// exists to serve.
#[tokio::test]
async fn a_holders_sensitivity_override_survives_the_write_and_decides_the_read() {
    let (router, ctx) = build_test_app().await;
    let holder = authed(&ctx, "sensitivity-override", "admin", &[]).await;

    // `account.handle` is `normal` in the registry; this holder disagrees.
    let (status, body) = post(
        &router,
        &holder,
        ATTR_PUT,
        json!({
            "type": "account.handle",
            "value": "ada",
            "valueType": "string",
            "provenance": { "kind": "selfAsserted" },
            "sensitivity": "high",
        }),
    )
    .await;
    assert!(!refused(status, &body), "attribute/put: {status} {body}");

    // `payment.card` is `high` in the registry; this holder disagrees.
    let (status, body) = post(
        &router,
        &holder,
        ATTR_PUT,
        json!({
            "type": "payment.card",
            "value": "4111111111111111",
            "valueType": "string",
            "provenance": { "kind": "selfAsserted" },
            "sensitivity": "normal",
        }),
    )
    .await;
    assert!(!refused(status, &body), "attribute/put: {status} {body}");

    let (status, body) = post(
        &router,
        &holder,
        ATTR_LIST,
        json!({ "includeValues": true }),
    )
    .await;
    assert!(!refused(status, &body), "attribute/list: {status} {body}");
    assert!(
        listed(&body, "account.handle").get("value").is_none(),
        "the holder marked this sensitive and the listing carried it anyway: {body}"
    );
    assert_eq!(
        listed(&body, "payment.card")
            .get("value")
            .and_then(Value::as_str),
        Some("4111111111111111"),
        "the holder's own decision about their own pool was overruled by the \
         registry: {body}"
    );

    // The override is stored, not merely obeyed once — and it comes back on the
    // wire, which is what a client needs to render the decision the holder
    // made rather than the default it would otherwise infer.
    assert_eq!(
        listed(&body, "account.handle")
            .get("sensitivity")
            .and_then(Value::as_str),
        Some("high")
    );
    // An attribute nobody decided anything about carries no member at all.
    // Absent is not `normal`: it is what lets a later tightening of the
    // registry protect this attribute too.
    let handle = put_attribute(&router, &holder, "org.role", "Engineer").await;
    let (_status, body) = post(
        &router,
        &holder,
        ATTR_LIST,
        json!({ "typePrefix": "org", "includeValues": true }),
    )
    .await;
    assert!(
        listed(&body, "org.role").get("sensitivity").is_none(),
        "an attribute with no holder decision reported one: {body}"
    );
    assert!(!handle.is_empty());

    // A write that records the decision leaves a trail that says so.
    let rows = audit_rows(&ctx).await;
    assert!(
        rows.iter().any(|r| r.action == "persona.attribute.put"
            && r.detail
                .as_deref()
                .is_some_and(|d| d.contains("sensitivity normal set by the holder"))),
        "no audit row records the holder loosening a card: {rows:#?}"
    );
}

// ---------------------------------------------------------------------------
// 6. `correlation/analyze` names where a value went
// ---------------------------------------------------------------------------

/// A finding names the profile, context and persona a shared value reaches —
/// and the response validates against the published schema.
///
/// Two defects in one, and they are the same defect. `Finding` carried
/// `sharedWithProfileCount`, which the response schema for
/// `persona/correlation/analyze/1.0` does not define; the object is
/// `additionalProperties: false`, so every response carrying a non-empty
/// `findings` array was non-conformant. It went unnoticed because the only
/// test of this task analysed a pool holding one attribute, which produces no
/// findings at all — an empty array conforms to anything.
///
/// The schema instead defines `sharedWith`, an array of
/// `{profileId?, contextId?, personaDid?, disclosedTo?}`. `PersonaStore::
/// correlation_count` states the design's own reasoning for that: a count is
/// what a *write* may return, because naming identifiers there would disclose
/// the holder's other compositions to whatever tool made the write; this task
/// is holder-authorized and is where identifiers belong. So the count was both
/// the non-conformant answer and the weaker one, and the implementation is the
/// side that had to move.
///
/// The assertion is therefore not "a member called sharedWith exists" but that
/// it names the place the value actually reached. A `sharedWith` populated
/// with empty objects would conform to the schema and tell the holder nothing.
#[tokio::test]
async fn a_correlation_finding_names_where_the_shared_value_went() {
    let (router, ctx) = build_test_app().await;
    let holder = authed(&ctx, "correlate", "admin", &[]).await;
    let persona = "did:peer:2.Ez6LSpersonaCorrelate.Vz6MkpersonaCorrelate";

    // The same value under two claim types. `subject` is the one being
    // analysed; `reused` is the one that has been composed into a profile and
    // pushed into a context, which is what the finding must be able to name.
    const SHARED: &str = "+61 400 111 222";
    let subject = put_attribute(&router, &holder, "phone.mobile", SHARED).await;
    let reused = put_attribute(&router, &holder, "phone.work", SHARED).await;

    let (status, body) = post(
        &router,
        &holder,
        PROFILE_PUT,
        json!({ "name": "work", "entries": [{ "ref": reused }] }),
    )
    .await;
    assert!(!refused(status, &body), "profile/put: {status} {body}");
    let profile = payload_of(&body)
        .get("profileId")
        .and_then(Value::as_str)
        .expect("profileId")
        .to_string();

    let (status, body) = post(
        &router,
        &holder,
        BINDING_SET,
        json!({ "contextId": CTX, "personaDid": persona, "profileId": profile }),
    )
    .await;
    assert!(!refused(status, &body), "binding/set: {status} {body}");

    let (status, body) = post(
        &router,
        &holder,
        CORRELATION,
        json!({ "attributeId": subject }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "correlation/analyze: {status} {body}"
    );

    // Conformance, asserted twice over and deliberately. The dispatch spine's
    // response-conformance layer already replaced a violating body with an
    // error document, so `refused` above covers it — but that check is silent
    // when it passes, and this one names the contract. The generated type is
    // `deny_unknown_fields`, so a member the schema does not define (which is
    // exactly what `sharedWithProfileCount` was) fails here with the offending
    // name in the message.
    let payload = payload_of(&body).clone();
    let typed: trust_tasks_rs::specs::persona::correlation::analyze::v1_0::Response =
        serde_json::from_value(payload.clone()).unwrap_or_else(|e| {
            panic!("the response does not match the published schema: {e}\n{payload:#}")
        });

    let finding = typed
        .findings
        .iter()
        .find(|f| f.attribute_id.as_deref().map(|s| &**s) == Some(subject.as_str()))
        .unwrap_or_else(|| panic!("no finding for the analysed attribute: {payload:#}"));

    // The count has not been lost — it moved into the prose, which is where a
    // holder reads it. `sharedWith` is keyed on profiles and bindings, so it
    // cannot restate a count of attributes.
    assert!(
        finding.why.contains("1 other attribute"),
        "the finding no longer says how many other attributes hold the value: {}",
        finding.why.as_str()
    );

    let reached = finding
        .shared_with
        .iter()
        .find(|s| s.profile_id.as_deref().map(|p| &**p) == Some(profile.as_str()))
        .unwrap_or_else(|| {
            panic!(
                "the finding does not name the profile the shared value reaches — a holder \
                 told \"this links your personas\" and given no identifier has nothing to \
                 act on: {payload:#}"
            )
        });
    assert_eq!(
        reached.context_id.as_deref(),
        Some(CTX),
        "the profile is named without the context it is bound in, which is the half that \
         makes the finding actionable: {payload:#}"
    );
    assert_eq!(
        reached.persona_did.as_deref(),
        Some(persona),
        "the binding is named without the persona presenting it: {payload:#}"
    );
}

// ---------------------------------------------------------------------------
// 5. `release: stepUp` — a fresh approval per disclosure
// ---------------------------------------------------------------------------

const APPROVE_RESPONSE: &str = "https://trusttasks.org/spec/auth/step-up/approve-response/0.2";
const APPROVE_RESPONSE_0_3: &str = "https://trusttasks.org/spec/auth/step-up/approve-response/0.3";

/// Build the face, bind it, preview it, and return `(scoped token, previewId)`.
///
/// Parameterised on the claim type because the whole subject here is that one
/// type is gated and another is not, over the same path. A helper that only
/// ever built the gated case would let a gate that refuses *everything* pass.
async fn preview_a_face_holding(
    router: &axum::Router,
    ctx: &TestAppContext,
    tag: &str,
    claim_type: &str,
    value: &str,
) -> (String, String) {
    let holder = authed(ctx, &format!("{tag}-holder"), "admin", &[]).await;
    let scoped = authed(ctx, &format!("{tag}-scoped"), "admin", &[CTX]).await;

    let vta = &ctx.vta_did;
    let attr = put_attribute_at(router, &holder, vta, claim_type, value).await;
    let (status, body) = post_to(
        router,
        &holder,
        vta,
        PROFILE_PUT,
        json!({ "name": tag, "entries": [{ "ref": attr }] }),
    )
    .await;
    assert!(!refused(status, &body), "profile/put: {status} {body}");
    let profile = payload_of(&body)
        .get("profileId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no profileId in {body}"))
        .to_string();

    let persona = format!("did:key:z6MkPersona{tag}");
    let (status, body) = post_to(
        router,
        &holder,
        vta,
        BINDING_SET,
        json!({ "contextId": CTX, "personaDid": persona, "profileId": profile }),
    )
    .await;
    assert!(!refused(status, &body), "binding/set: {status} {body}");

    let (status, body) = post_to(
        router,
        &scoped,
        vta,
        PREVIEW,
        json!({
            "contextId": CTX,
            "personaDid": persona,
            "verifierDid": "did:key:z6MkVerifier",
            "purpose": "checkout",
        }),
    )
    .await;
    assert!(!refused(status, &body), "preview: {status} {body}");
    let preview_id = payload_of(&body)
        .get("previewId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no previewId in {body}"))
        .to_string();

    (scoped, preview_id)
}

/// A `release: stepUp` claim is refused without an approval, approved once, and
/// disclosed — and the refusal costs the holder nothing.
///
/// Four properties, and each of them is a way this could be built wrong:
///
/// 1. **It refuses.** `payment.card` resolves to `release: stepUp` through the
///    registry, and the gate reads the resolution rather than a list of types
///    it happens to know.
/// 2. **It refuses with the code the specification declares**, not
///    `taskFailed`. A client can only offer the retry if it can recognise the
///    refusal, and `taskFailed` means "attempted and could not complete" —
///    which is the opposite of what happened.
/// 3. **The preview survives.** A refusal that consumed it would make the
///    holder preview again to obtain an approval for a preview that no longer
///    exists, and the retry the code promises would be unreachable. Asserted
///    by refusing *twice* on the same id: the second refusal must still be
///    `stepUpRequired`, not "unknown preview".
/// 4. **The approval authorises that disclosure**, and it is the mark on the
///    preview that does so — not the session elevation the ceremony also
///    performs. `an_approval_does_not_carry_to_the_next_disclosure` is the
///    other side of the same claim.
#[tokio::test]
async fn a_step_up_claim_needs_an_approval_bound_to_that_preview() {
    let (router, ctx) = build_provisionable_test_app().await;
    let (scoped, preview_id) =
        preview_a_face_holding(&router, &ctx, "gated", "payment.card", "4242424242424242").await;

    // 1 + 2. Refused, with the declared code.
    let (status, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        PRESENT,
        json!({ "contextId": CTX, "previewId": preview_id }),
    )
    .await;
    assert!(
        refused(status, &body),
        "a payment.card disclosure was released with no approval: {status} {body}"
    );
    let payload = payload_of(&body);
    assert_eq!(
        payload["code"], "persona/disclosure/present:stepUpRequired",
        "the refusal does not carry the code the specification declares, so a client \
         cannot tell it apart from a failure and cannot offer the retry: {body}"
    );
    assert_eq!(
        payload["details"]["previewRetained"], true,
        "the refusal does not say the preview survived it: {body}"
    );
    let approve_request = payload["details"]["approveRequest"].clone();
    let challenge = approve_request["payload"]["challenge"]
        .as_str()
        .unwrap_or_else(|| panic!("no challenge in the approve request: {body}"))
        .to_string();
    let session_id = approve_request["payload"]["sessionId"]
        .as_str()
        .expect("the approve request names the session")
        .to_string();

    // The approver is shown what would leave — the verifier, the types and the
    // purpose — because "approve a disclosure?" is a prompt people learn to
    // answer yes to. Values are deliberately absent: this document travels to a
    // second device, and the approver authorises a release rather than reading
    // one.
    let context = &approve_request["payload"]["ext"]["org.openvtc.authorization-context"];
    // The `{type, summary, risk, action}` shape an approver's card renders. The
    // `type` is the half a native layer discriminates on, so a context without
    // one is a context that shows the approver nothing.
    assert_eq!(
        context["type"], "https://openvtc.org/persona/authorization-context/0.1",
        "the context carries no type, so no approval card can be chosen for it: {body}"
    );
    assert_eq!(context["risk"], "high", "{body}");
    assert_eq!(
        context["summary"], approve_request["payload"]["reason"],
        "the summary and the reason are two accounts of one act and must not differ: {body}"
    );
    let action = &context["action"];
    assert_eq!(action["kind"], "disclose", "{body}");
    assert_eq!(action["previewId"], preview_id, "{body}");
    assert_eq!(action["verifierDid"], "did:key:z6MkVerifier", "{body}");
    assert_eq!(action["claimTypes"][0], "payment.card", "{body}");
    assert_eq!(action["purpose"], "checkout", "{body}");
    assert!(
        !serde_json::to_string(&approve_request)
            .unwrap()
            .contains("4242424242424242"),
        "the approve request carries the card number to a second device: {approve_request:#}"
    );

    // 3. The same preview, refused again the same way — it was not consumed.
    let (status, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        PRESENT,
        json!({ "contextId": CTX, "previewId": preview_id }),
    )
    .await;
    assert!(refused(status, &body), "{status} {body}");
    assert_eq!(
        payload_of(&body)["code"],
        "persona/disclosure/present:stepUpRequired",
        "the refusal consumed the preview, so the retry it promises is unreachable: {body}"
    );

    // 4. Approve it, over the wire.
    let (status, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        APPROVE_RESPONSE,
        json!({
            "subject": holder_did(),
            "sessionId": session_id,
            "challenge": challenge,
            "decision": "approved",
            "grantedAcr": "aal2",
        }),
    )
    .await;
    assert!(!refused(status, &body), "approve-response: {status} {body}");

    // And now the disclosure goes through.
    let (status, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        PRESENT,
        json!({ "contextId": CTX, "previewId": preview_id }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "the approval did not authorise the disclosure it was taken for: {status} {body}"
    );
}

/// An approval authorises **one** disclosure, not the next one.
///
/// The preview is single-use, so the approval recorded on it dies with it. That
/// is the mechanism; this asserts the property it exists for — a second
/// preview of the same face is gated exactly as the first was, with no memory
/// of the approval the holder just gave.
///
/// And it asserts it **against an elevated session**, which is the sharp part.
/// The step-up ceremony raises the session to `aal2` as it does for every
/// other caller, so a gate that read `acr` — the obvious way to write one, and
/// the way every other step-up-gated operation in this service works — would
/// wave this second disclosure straight through. "Each time" survives only
/// because the gate reads the preview.
#[tokio::test]
async fn an_approval_does_not_carry_to_the_next_disclosure() {
    let (router, ctx) = build_provisionable_test_app().await;
    let (scoped, first) =
        preview_a_face_holding(&router, &ctx, "again", "payment.card", "4242424242424242").await;

    let (_, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        PRESENT,
        json!({ "contextId": CTX, "previewId": first }),
    )
    .await;
    let ar = payload_of(&body)["details"]["approveRequest"].clone();
    let session_id = ar["payload"]["sessionId"]
        .as_str()
        .unwrap_or_else(|| panic!("the approve request names the session: {body}"))
        .to_string();
    let (status, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        APPROVE_RESPONSE,
        json!({
            "subject": holder_did(),
            "sessionId": session_id,
            "challenge": ar["payload"]["challenge"],
            "decision": "approved",
            "grantedAcr": "aal2",
        }),
    )
    .await;
    assert!(!refused(status, &body), "approve-response: {status} {body}");
    assert_eq!(
        payload_of(&body)["status"],
        "elevated",
        "the ceremony did not complete, so nothing below tests what it means to: {body}"
    );

    let (status, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        PRESENT,
        json!({ "contextId": CTX, "previewId": first }),
    )
    .await;
    assert!(!refused(status, &body), "present: {status} {body}");

    // A second preview of the same face, from the same session, moments later.
    let (status, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        PREVIEW,
        json!({
            "contextId": CTX,
            "personaDid": "did:key:z6MkPersonaagain",
            "verifierDid": "did:key:z6MkVerifier",
            "purpose": "checkout",
        }),
    )
    .await;
    assert!(!refused(status, &body), "second preview: {status} {body}");
    let second = payload_of(&body)["previewId"]
        .as_str()
        .expect("previewId")
        .to_string();

    let stored = vti_common::auth::session::get_session(&ctx.sessions_ks, &session_id)
        .await
        .unwrap()
        .expect("the session is still there");
    assert_eq!(
        stored.acr, "aal2",
        "the session is not elevated, so the refusal below would prove nothing: {stored:?}"
    );

    let (status, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        PRESENT,
        json!({ "contextId": CTX, "previewId": second }),
    )
    .await;
    assert!(
        refused(status, &body),
        "the second disclosure rode the first one's approval — 'each time' means each \
         time: {status} {body}"
    );
    assert_eq!(
        payload_of(&body)["code"],
        "persona/disclosure/present:stepUpRequired",
        "{body}"
    );
}

/// An ungated claim reaches `present` with no approval at all.
///
/// The other half of the gate, and the half that is easy to lose: a gate that
/// refuses everything satisfies every test above. `name.display` resolves to
/// `release: consent`, which the two-call preview already is, and adding a
/// second human decision to every disclosure is how a step-up becomes noise.
#[tokio::test]
async fn an_ungated_claim_is_not_gated() {
    let (router, ctx) = build_provisionable_test_app().await;
    let (scoped, preview_id) =
        preview_a_face_holding(&router, &ctx, "plain", "name.display", "Ada").await;

    let (status, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        PRESENT,
        json!({ "contextId": CTX, "previewId": preview_id }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "a name.display disclosure was gated behind a step-up: {status} {body}"
    );
}

/// A holder's `release` override survives the wire and reaches the gate.
///
/// The store test beside `requires_step_up` asserts the resolution. This
/// asserts the *system*: that `attribute/put` accepts the member, stores it,
/// carries it across the boundary at bind time, and that `present` then
/// enforces it — four layers, none of which the unit test can see.
///
/// Uses `name.display`, which the registry does **not** gate, so a pass cannot
/// come from the registry default. The gate here exists only because the
/// holder asked for it.
#[tokio::test]
async fn a_holders_release_override_gates_a_type_the_registry_does_not() {
    let (router, ctx) = build_provisionable_test_app().await;
    let vta = &ctx.vta_did;
    let holder = authed(&ctx, "rel-holder", "admin", &[]).await;
    let scoped = authed(&ctx, "rel-scoped", "admin", &[CTX]).await;

    let (status, body) = post_to(
        &router,
        &holder,
        vta,
        ATTR_PUT,
        json!({
            "type": "name.display",
            "value": "Ada",
            "valueType": "string",
            "provenance": { "kind": "selfAsserted" },
            "release": "stepUp",
        }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "attribute/put with release: {status} {body}"
    );
    let attr = payload_of(&body)["attributeId"]
        .as_str()
        .expect("attributeId")
        .to_string();

    let (status, body) = post_to(
        &router,
        &holder,
        vta,
        PROFILE_PUT,
        json!({ "name": "gated-name", "entries": [{ "ref": attr }] }),
    )
    .await;
    assert!(!refused(status, &body), "profile/put: {status} {body}");
    let profile = payload_of(&body)["profileId"]
        .as_str()
        .expect("profileId")
        .to_string();

    let persona = "did:key:z6MkPersonaRelease";
    let (status, body) = post_to(
        &router,
        &holder,
        vta,
        BINDING_SET,
        json!({ "contextId": CTX, "personaDid": persona, "profileId": profile }),
    )
    .await;
    assert!(!refused(status, &body), "binding/set: {status} {body}");

    let (status, body) = post_to(
        &router,
        &scoped,
        vta,
        PREVIEW,
        json!({
            "contextId": CTX,
            "personaDid": persona,
            "verifierDid": "did:key:z6MkVerifier",
        }),
    )
    .await;
    assert!(!refused(status, &body), "preview: {status} {body}");
    let preview_id = payload_of(&body)["previewId"]
        .as_str()
        .expect("previewId")
        .to_string();

    let (status, body) = post_to(
        &router,
        &scoped,
        vta,
        PRESENT,
        json!({ "contextId": CTX, "previewId": preview_id }),
    )
    .await;
    assert!(
        refused(status, &body),
        "the holder asked for a fresh approval on this attribute and the disclosure went \
         through without one: {status} {body}"
    );
    assert_eq!(
        payload_of(&body)["code"],
        "persona/disclosure/present:stepUpRequired",
        "refused, but not for the reason the holder asked for: {body}"
    );

    // And the override is what did it — the same type with no override is not
    // gated. Without this the test passes for a gate that fires on everything.
    let plain = authed(&ctx, "rel-plain", "admin", &[]).await;
    let (_, body) = post_to(
        &router,
        &plain,
        vta,
        ATTR_PUT,
        json!({
            "type": "name.display",
            "value": "Grace",
            "valueType": "string",
            "provenance": { "kind": "selfAsserted" },
        }),
    )
    .await;
    let attr2 = payload_of(&body)["attributeId"]
        .as_str()
        .expect("attributeId")
        .to_string();
    let (_, body) = post_to(
        &router,
        &plain,
        vta,
        PROFILE_PUT,
        json!({ "name": "plain-name", "entries": [{ "ref": attr2 }] }),
    )
    .await;
    let profile2 = payload_of(&body)["profileId"]
        .as_str()
        .expect("profileId")
        .to_string();
    let persona2 = "did:key:z6MkPersonaPlain";
    let (status, body) = post_to(
        &router,
        &plain,
        vta,
        BINDING_SET,
        json!({ "contextId": CTX, "personaDid": persona2, "profileId": profile2 }),
    )
    .await;
    assert!(!refused(status, &body), "binding/set: {status} {body}");
    let (_, body) = post_to(
        &router,
        &scoped,
        vta,
        PREVIEW,
        json!({
            "contextId": CTX,
            "personaDid": persona2,
            "verifierDid": "did:key:z6MkVerifier",
        }),
    )
    .await;
    let preview2 = payload_of(&body)["previewId"]
        .as_str()
        .expect("previewId")
        .to_string();
    let (status, body) = post_to(
        &router,
        &scoped,
        vta,
        PRESENT,
        json!({ "contextId": CTX, "previewId": preview2 }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "an ungated name.display was gated, so the override is not what decided it: \
         {status} {body}"
    );
}

/// The registry is served, and it is the one the agent resolves by.
///
/// The task's central MUST is that a maintainer serves the table it actually
/// applies — a served table that differs from the enforced one is worse than
/// serving nothing, because a client would mask and gate by one rule while the
/// agent disclosed by another and nothing would report the disagreement.
///
/// So this does not check the response against a literal. It checks it against
/// **observed agent behaviour**: `payment.card` is served as `release: stepUp`,
/// and a disclosure of `payment.card` is in fact refused for want of a step-up.
/// A response built from a second hard-coded table would pass a literal
/// comparison and fail this.
#[tokio::test]
async fn the_served_registry_is_the_one_the_agent_enforces() {
    let (router, ctx) = build_provisionable_test_app().await;
    let vta = &ctx.vta_did;
    let scoped = authed(&ctx, "ct-scoped", "admin", &[CTX]).await;

    let (status, body) = post_to(&router, &scoped, vta, CLAIM_TYPES, json!({})).await;
    assert!(!refused(status, &body), "claim-types/list: {status} {body}");
    let p = payload_of(&body);

    assert_eq!(p["registryVersion"], "0.1", "{body}");

    // The three parts are inseparable: §4 rule 3 needs the floor and an
    // ordering, not just the rows.
    assert_eq!(p["unregistered"]["sensitivity"], "high", "{body}");
    assert_eq!(p["unregistered"]["release"], "consent", "{body}");
    assert_eq!(p["unregistered"]["mask"], "full", "{body}");
    assert_eq!(
        p["strictness"]["release"][0], "stepUp",
        "the strictness ordering must be most-protective-first, or a client's \
         'more protective wins' resolves backwards: {body}"
    );
    assert_eq!(p["strictness"]["sensitivity"][0], "high", "{body}");
    assert_eq!(p["strictness"]["mask"][0], "full", "{body}");

    let entries = p["entries"].as_array().expect("entries");
    let find = |t: &str| {
        entries
            .iter()
            .find(|e| e["type"] == t)
            .unwrap_or_else(|| panic!("no entry for {t} in {p:#}"))
    };

    // The family rows are present and undistinguished. A client walking
    // prefixes needs them, and nothing marks them as a different kind of row —
    // which is what stopped a gated family being escapable by inventing a
    // member.
    assert_eq!(find("payment")["release"], "stepUp", "{p:#}");
    assert_eq!(find("gov")["release"], "stepUp", "{p:#}");
    assert_eq!(find("name")["release"], "consent", "{p:#}");

    // And now the half that makes this more than a literal comparison: the
    // agent must BEHAVE the way the table it just served says it will.
    let served_card_release = find("payment.card")["release"].clone();
    assert_eq!(served_card_release, "stepUp", "{p:#}");

    let holder = authed(&ctx, "ct-holder", "admin", &[]).await;
    let attr = put_attribute_at(&router, &holder, vta, "payment.card", "4242424242424242").await;
    let (_, body) = post_to(
        &router,
        &holder,
        vta,
        PROFILE_PUT,
        json!({ "name": "card", "entries": [{ "ref": attr }] }),
    )
    .await;
    let profile = payload_of(&body)["profileId"]
        .as_str()
        .expect("profileId")
        .to_string();
    let persona = "did:key:z6MkPersonaClaimTypes";
    let (status, body) = post_to(
        &router,
        &holder,
        vta,
        BINDING_SET,
        json!({ "contextId": CTX, "personaDid": persona, "profileId": profile }),
    )
    .await;
    assert!(!refused(status, &body), "binding/set: {status} {body}");
    let (_, body) = post_to(
        &router,
        &scoped,
        vta,
        PREVIEW,
        json!({ "contextId": CTX, "personaDid": persona, "verifierDid": "did:key:z6MkV" }),
    )
    .await;
    let preview_id = payload_of(&body)["previewId"]
        .as_str()
        .expect("previewId")
        .to_string();
    let (status, body) = post_to(
        &router,
        &scoped,
        vta,
        PRESENT,
        json!({ "contextId": CTX, "previewId": preview_id }),
    )
    .await;
    assert!(refused(status, &body), "{status} {body}");
    assert_eq!(
        payload_of(&body)["code"],
        "persona/disclosure/present:stepUpRequired",
        "the agent served `payment.card: stepUp` and then disclosed it without one — a served \
         table that differs from the enforced one is worse than serving nothing: {body}"
    );
}

/// Any authenticated caller may read it — scoped and unscoped alike.
///
/// Both of the usual answers are wrong here in opposite directions, so both
/// are asserted: refusing the scoped caller would refuse the application that
/// needs this most, and refusing the unscoped one would refuse the holder's own
/// tooling, which has no context to name.
#[tokio::test]
async fn the_registry_is_readable_by_scoped_and_unscoped_callers_alike() {
    let (router, ctx) = build_provisionable_test_app().await;
    let vta = &ctx.vta_did;
    for (tag, contexts) in [("ct-any-scoped", &[CTX][..]), ("ct-any-holder", &[][..])] {
        let token = authed(&ctx, tag, "admin", contexts).await;
        let (status, body) = post_to(&router, &token, vta, CLAIM_TYPES, json!({})).await;
        assert!(
            !refused(status, &body),
            "{tag} was refused: {status} {body}"
        );
        assert!(
            payload_of(&body)["entries"]
                .as_array()
                .is_some_and(|e| !e.is_empty()),
            "{tag} got an empty table: {body}"
        );
    }
}

/// A 0.3 bound approval authorises the disclosure and elevates **nothing**.
///
/// This is what `auth/step-up/approve-response/0.3` was added for, and the
/// close of #1304's one stated compromise. The two halves both matter:
///
/// - the disclosure goes through, so the approval was really applied;
/// - the session stays at `aal1`, so an approval taken to release a card
///   number buys nothing else in the assurance window.
#[tokio::test]
async fn a_bound_approval_asked_in_0_3_records_without_elevating() {
    let (router, ctx) = build_provisionable_test_app().await;
    let (scoped, preview_id) =
        preview_a_face_holding(&router, &ctx, "rec", "payment.card", "4242424242424242").await;

    let (_, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        PRESENT,
        json!({ "contextId": CTX, "previewId": preview_id }),
    )
    .await;
    let ar = payload_of(&body)["details"]["approveRequest"].clone();
    let session_id = ar["payload"]["sessionId"]
        .as_str()
        .expect("sessionId")
        .to_string();

    let (status, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        APPROVE_RESPONSE_0_3,
        json!({
            "subject": holder_did(),
            "sessionId": session_id,
            "challenge": ar["payload"]["challenge"],
            "decision": "approved",
            "grantedAcr": "aal2",
        }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "approve-response/0.3: {status} {body}"
    );
    let p = payload_of(&body);
    assert_eq!(
        p["status"], "recorded",
        "a bound approval asked in 0.3 must be acknowledged `recorded`: {body}"
    );
    assert_eq!(p["boundTo"], preview_id, "{body}");
    assert!(
        p.get("session").is_none(),
        "`recorded` changes no session, so a session snapshot would report an elevation that \
         did not happen: {body}"
    );

    // The session is untouched — the half that closes the compromise.
    let stored = vti_common::auth::session::get_session(&ctx.sessions_ks, &session_id)
        .await
        .unwrap()
        .expect("session still there");
    assert_eq!(
        stored.acr, "aal1",
        "the approval elevated the session, so it buys more than the disclosure it was taken \
         for: {stored:?}"
    );

    // And the approval it WAS taken for went through.
    let (status, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        PRESENT,
        json!({ "contextId": CTX, "previewId": preview_id }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "recorded, but the disclosure it authorised was still refused: {status} {body}"
    );
}

/// A 0.2 approver still gets the old behaviour, and that is deliberate.
///
/// The cutover moves per approver, not per deployment: a response's type is the
/// request's type plus `#response`, so an approver that minted 0.2 must be
/// answered in 0.2 — which has no word for "applied, nothing elevated". Until
/// that approver moves, elevating is the only honest thing left.
///
/// Asserted so the fallback is a decision rather than an accident: if this
/// starts returning `recorded` to a 0.2 request, the response no longer
/// validates against the version the approver asked in.
#[tokio::test]
async fn a_bound_approval_asked_in_0_2_still_elevates() {
    let (router, ctx) = build_provisionable_test_app().await;
    let (scoped, preview_id) =
        preview_a_face_holding(&router, &ctx, "old", "payment.card", "4242424242424242").await;

    let (_, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        PRESENT,
        json!({ "contextId": CTX, "previewId": preview_id }),
    )
    .await;
    let ar = payload_of(&body)["details"]["approveRequest"].clone();
    let session_id = ar["payload"]["sessionId"]
        .as_str()
        .expect("sessionId")
        .to_string();

    let (status, body) = post_to(
        &router,
        &scoped,
        &ctx.vta_did,
        APPROVE_RESPONSE,
        json!({
            "subject": holder_did(),
            "sessionId": session_id,
            "challenge": ar["payload"]["challenge"],
            "decision": "approved",
            "grantedAcr": "aal2",
        }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "approve-response/0.2: {status} {body}"
    );
    assert_eq!(
        payload_of(&body)["status"],
        "elevated",
        "0.2 has no `recorded`, so answering with one would not validate against the version \
         the approver asked in: {body}"
    );

    // "Each time" survives the elevation regardless — a second preview of the
    // same face is still gated, because the gate reads the preview and never
    // the session. That is asserted at length in
    // `an_approval_does_not_carry_to_the_next_disclosure`; this is the version
    // that still elevates, so it is worth knowing the property holds here too.
    let stored = vti_common::auth::session::get_session(&ctx.sessions_ks, &session_id)
        .await
        .unwrap()
        .expect("session still there");
    assert_eq!(stored.acr, "aal2", "{stored:?}");
}
