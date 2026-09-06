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

use vta_service::test_support::{TestAppContext, build_test_app};
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
const CORRELATION: &str = "https://trusttasks.org/spec/persona/correlation/analyze/1.0";
const RENDERERS: &str = "https://trusttasks.org/spec/persona/renderers/list/1.0";
const DISCLOSURE_HISTORY: &str = "https://trusttasks.org/spec/persona/disclosure/history/1.0";
const PREVIEW: &str = "https://trusttasks.org/spec/persona/disclosure/preview/1.0";
const PRESENT: &str = "https://trusttasks.org/spec/persona/disclosure/present/1.0";
const LOCAL_PROFILE_PUT: &str = "https://trusttasks.org/spec/persona/local/profile/put/1.0";

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

/// POST a persona Trust Task and return `(status, parsed body)`.
async fn post(
    router: &axum::Router,
    token: &str,
    uri: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let mut typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("tt-{}", uuid::Uuid::new_v4()),
        "type": uri,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": holder_did(),
        "recipient": "did:key:z6MkTestVTA",
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
    let (status, body) = post(
        router,
        token,
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

/// Editing the pool changes what a bound context presents — without the
/// context reading anything.
///
/// "Edit once, everywhere" and the one-way boundary are in tension: the
/// obvious way to keep a projection current is to let it resolve on read,
/// which is a read *upward*. Instead the write above the boundary pushes.
/// This is the test that the push actually happens; the store-level test can
/// only show that `rematerialise` works when called.
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

/// A profile carrying an inline entry cannot be resolved, and says so.
///
/// `persona/profile/get/1.0`'s response schema types each resolved entry as
/// the pool `Attribute` shape, which requires `attributeId`, `updatedAt` and
/// `version`. An inline entry has none of them — it has no pool record behind
/// it, which is the reason inline exists. So the schema is wrong: `resolved`
/// is a projection that may contain non-pool values, and reusing the pool
/// record's shape for it cannot describe them.
///
/// Until that is fixed upstream the handler refuses, rather than synthesising
/// an `attributeId` (a lie about where the value lives) or omitting the entry
/// (a profile that appears to present less than it does).
///
/// **This test exists to expire.** When the schema takes optional
/// `attributeId`/`updatedAt`/`version`, this fails, and the refusal in
/// `handle_profile_get` goes with it.
#[tokio::test]
async fn an_inline_entry_is_refused_until_the_schema_allows_one() {
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

    // Without `resolve` it reads fine: how the profile is BUILT is
    // describable, only what it resolves TO is not.
    let (status, body) = post(
        &router,
        &holder,
        PROFILE_GET,
        json!({ "profileId": profile }),
    )
    .await;
    assert!(
        !refused(status, &body),
        "an unresolved read of an inline profile must work: {status} {body}"
    );

    let (status, body) = post(
        &router,
        &holder,
        PROFILE_GET,
        json!({ "profileId": profile, "resolve": true }),
    )
    .await;
    assert!(
        refused(status, &body),
        "resolving an inline entry produced a response the schema cannot \
         describe: {status} {body}"
    );
    let rendered = serde_json::to_string(&body).expect("serialises");
    assert!(
        rendered.contains("inline"),
        "the refusal should name the reason, not just fail: {rendered}"
    );
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
