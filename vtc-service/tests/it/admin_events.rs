//! The administrator console's live channel — `vtc/admin/events/subscribe/0.1`
//! answered as a streamed response (HTTPS binding 0.3 §2.1), carrying
//! `vtc/admin/events/event/0.1` hints (`crate::admin_events`).
//!
//! What these hold, against the two specifications:
//!
//! - the signed `#response` is the stream's **first** event, its SSE `id` the
//!   resume token, one document per `data:` line, no `event:` field;
//! - a hint follows a change, carries only `topic`, `at`, `resumeToken` and —
//!   on a count topic — `count`, and never a record, an identifier or a DID;
//! - effective topics are the requested ones the caller may read: a caller
//!   without `vtc.join.decide` hears nothing about join requests;
//! - a refusal is JSON and opens no stream (`streamUnavailable`,
//!   `notAdministrator`, `tooManyStreams`, a `Last-Event-ID` disagreeing with
//!   `since`);
//! - an unknown `since` opens `resumed: false`; a known one resumes;
//! - heartbeats are SSE comments;
//! - the stream ends when the caller's readable topics shrink and when the
//!   credential it was opened on expires;
//! - 0.2 (`rooms`): served beside 0.1, each answered at its own version; the
//!   topic is effective only for a holder of `vtc.rooms.admin`, is refused in
//!   a 0.1 subscribe, follows a room registered, a storage config written and
//!   a room's lifecycle moving with the clock, and never names a room.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{AdminAuthority, AdminRole, VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::admin_events::{MAX_STREAMS_PER_SUBJECT, set_heartbeat_seconds};
use vtc_service::test_support::TestVtc;

use crate::common::signed::{error_code, signed_to};

/// A `trust-task-error` reply's code — the census reads witnesses by this name.
fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

const SUBSCRIBE: &str = "https://trusttasks.org/spec/vtc/admin/events/subscribe/0.1";
const EVENT: &str = "https://trusttasks.org/spec/vtc/admin/events/event/0.1";
const SUBSCRIBE_V0_2: &str = "https://trusttasks.org/spec/vtc/admin/events/subscribe/0.2";
const EVENT_V0_2: &str = "https://trusttasks.org/spec/vtc/admin/events/event/0.2";
const SUBSCRIBE_V0_3: &str = "https://trusttasks.org/spec/vtc/admin/events/subscribe/0.3";
const EVENT_V0_3: &str = "https://trusttasks.org/spec/vtc/admin/events/event/0.3";
const STREAM_ACCEPT: &str = "text/event-stream, application/json;q=0.5";

use vtc_service::admin_events::codes::{NOT_ADMINISTRATOR, STREAM_UNAVAILABLE, TOO_MANY_STREAMS};

async fn vtc() -> TestVtc {
    TestVtc::builder()
        .with_signers(true)
        .with_audit(true)
        .build()
        .await
}

fn entry(did: &str, admin: AdminAuthority, expires_at: Option<u64>) -> VtcAclEntry {
    VtcAclEntry {
        did: did.to_string(),
        admin,
        delegated_by: None,
        role: VtcRole::Member,
        label: None,
        created_at: 0,
        created_by: "did:key:vtc-install".into(),
        updated_at: None,
        updated_by: None,
        expires_at,
        resource_grants: Vec::new(),
        group_grants: Vec::new(),
        label_set_by_subject: false,
        suspension: None,
    }
}

async fn with_role(vtc: &TestVtc, role: Option<AdminRole>, expires_at: Option<u64>) -> Party {
    let party = Party::new();
    let admin = role.map_or_else(AdminAuthority::none, AdminAuthority::for_role);
    store_acl_entry(&vtc.state.acl_ks, &entry(&party.did, admin, expires_at))
        .await
        .unwrap();
    party
}

async fn community_admin(vtc: &TestVtc) -> Party {
    with_role(vtc, Some(AdminRole::CommunityAdmin), None).await
}

async fn vtc_did(vtc: &TestVtc) -> String {
    vtc.state.config.read().await.vtc_did.clone().unwrap()
}

/// Sign a subscribe as `from` and post it with `accept` (and `last_event_id`).
async fn subscribe(
    vtc: &TestVtc,
    from: &Party,
    payload: Value,
    accept: Option<&str>,
    last_event_id: Option<&str>,
) -> (Value, axum::response::Response) {
    subscribe_at(vtc, SUBSCRIBE, from, payload, accept, last_event_id).await
}

/// [`subscribe`] at the version `task` names.
async fn subscribe_at(
    vtc: &TestVtc,
    task: &str,
    from: &Party,
    payload: Value,
    accept: Option<&str>,
    last_event_id: Option<&str>,
) -> (Value, axum::response::Response) {
    let doc = signed_to(from, &vtc_did(vtc).await, task, payload).await;
    (
        doc.clone(),
        post_raw(vtc, &doc, accept, last_event_id).await,
    )
}

async fn post_raw(
    vtc: &TestVtc,
    doc: &Value,
    accept: Option<&str>,
    last_event_id: Option<&str>,
) -> axum::response::Response {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let peer = std::net::SocketAddr::from(([10, 77, (n >> 8) as u8, n as u8], 40_000));
    let mut req = Request::builder()
        .method("POST")
        .uri("/v1/trust-tasks")
        .header("Content-Type", "application/json");
    if let Some(a) = accept {
        req = req.header("Accept", a);
    }
    if let Some(id) = last_event_id {
        req = req.header("Last-Event-ID", id);
    }
    let mut req = req
        .body(Body::from(serde_json::to_vec(doc).unwrap()))
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    vtc.router.clone().oneshot(req).await.unwrap()
}

/// A refusal: JSON, never a stream.
async fn json_refusal(res: axum::response::Response) -> (StatusCode, Value) {
    let status = res.status();
    let ct = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        ct.starts_with("application/json"),
        "a refusal is JSON, never a stream: content-type {ct}"
    );
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[derive(Debug)]
enum Next {
    Event { id: Option<String>, doc: Value },
    Comment(String),
    Ended,
    Silent,
}

/// An SSE reader over a streamed response body.
struct Sse {
    body: Body,
    buf: String,
}

impl Sse {
    fn open(res: axum::response::Response) -> Self {
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get("content-type").unwrap(),
            "text/event-stream"
        );
        assert_eq!(res.headers().get("cache-control").unwrap(), "no-store");
        Self {
            body: res.into_body(),
            buf: String::new(),
        }
    }

    async fn next(&mut self, within: Duration) -> Next {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if let Some(end) = self.buf.find("\n\n") {
                let block: String = self.buf.drain(..end + 2).collect();
                return parse_block(block.trim_end_matches('\n'));
            }
            match tokio::time::timeout_at(deadline, self.body.frame()).await {
                Err(_) => return Next::Silent,
                Ok(None) => return Next::Ended,
                Ok(Some(Err(e))) => panic!("stream body error: {e}"),
                Ok(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        self.buf.push_str(std::str::from_utf8(&data).unwrap());
                    }
                }
            }
        }
    }

    /// The next event, skipping heartbeats.
    async fn next_event(&mut self, within: Duration) -> Option<(Option<String>, Value)> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.next(left).await {
                Next::Event { id, doc } => return Some((id, doc)),
                Next::Comment(_) => continue,
                Next::Ended | Next::Silent => return None,
            }
        }
    }

    /// Whether the stream ends within `within` (heartbeats and hints may
    /// arrive first).
    async fn ends_within(&mut self, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.next(left).await {
                Next::Ended => return true,
                Next::Silent => return false,
                _ => continue,
            }
        }
    }
}

fn parse_block(block: &str) -> Next {
    let mut id = None;
    let mut data = Vec::new();
    let mut comment = None;
    for line in block.lines() {
        if let Some(c) = line.strip_prefix(':') {
            comment = Some(c.trim().to_string());
        } else if let Some(v) = line.strip_prefix("id: ") {
            id = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("data: ") {
            data.push(v.to_string());
        } else {
            // binding 0.3 §2.1.2 item 2: no `event:` field, nor anything else.
            panic!("unexpected SSE field line: {line:?}");
        }
    }
    if data.is_empty() {
        return Next::Comment(comment.unwrap_or_default());
    }
    assert_eq!(data.len(), 1, "one document per event, on one data: line");
    Next::Event {
        id,
        doc: serde_json::from_str(&data[0]).expect("each data line is one whole document"),
    }
}

/// Open a stream and read its first event, the `#response`.
async fn open_stream(
    vtc: &TestVtc,
    from: &Party,
    payload: Value,
) -> (Value, Sse, Option<String>, Value) {
    open_stream_at(vtc, SUBSCRIBE, from, payload).await
}

/// [`open_stream`] at the version `task` names: the `#response` is that
/// version's.
async fn open_stream_at(
    vtc: &TestVtc,
    task: &str,
    from: &Party,
    payload: Value,
) -> (Value, Sse, Option<String>, Value) {
    let (request, res) = subscribe_at(vtc, task, from, payload, Some(STREAM_ACCEPT), None).await;
    let mut sse = Sse::open(res);
    let (id, first) = sse
        .next_event(Duration::from_secs(5))
        .await
        .expect("the #response is the first event");
    assert_eq!(first["type"], format!("{task}#response"));
    crate::common::signed::assert_conforms(task, &first);
    assert_eq!(first["threadId"], request["id"]);
    assert_eq!(
        id.as_deref(),
        first["payload"]["resumeToken"].as_str(),
        "the SSE id is the resume token"
    );
    (request, sse, id, first)
}

/// A hint, held to everything its event version says one may carry — and
/// nothing else. A stream's hints are of the version it was opened at.
fn assert_hint_shape(hint: &Value, id: Option<&str>, request: &Value, subscriber: &str) {
    let event = if request["type"] == SUBSCRIBE_V0_3 {
        EVENT_V0_3
    } else if request["type"] == SUBSCRIBE_V0_2 {
        EVENT_V0_2
    } else {
        EVENT
    };
    assert_eq!(hint["type"], event);
    let schema = trust_tasks_rs::schema_index::schema_for(event).expect("event schema");
    trust_tasks_rs::validate::against_schema(schema, &hint["payload"])
        .unwrap_or_else(|e| panic!("hint does not match its schema: {e}\n{hint}"));
    let payload = hint["payload"].as_object().unwrap();
    for key in payload.keys() {
        assert!(
            ["topic", "at", "count", "resumeToken"].contains(&key.as_str()),
            "a hint carries nothing but topic, at, count and resumeToken: {key}"
        );
    }
    let topic = payload["topic"].as_str().unwrap();
    assert_eq!(
        payload.contains_key("count"),
        ["actions", "acknowledgements", "joinRequests"].contains(&topic),
        "count on the count topics, and only there"
    );
    assert!(
        !serde_json::to_string(&hint["payload"])
            .unwrap()
            .contains("did:"),
        "a hint carries no DID: {hint}"
    );
    assert_eq!(id, payload["resumeToken"].as_str());
    assert_eq!(hint["parentThreadId"], request["id"]);
    assert_eq!(hint["recipient"], subscriber);
    assert!(
        hint.get("proof").is_some(),
        "hints are signed by the community"
    );
}

fn operator_write(
    dids: Vec<String>,
    acknowledgers: Vec<String>,
) -> vtc_service::admin_actions::OperatorWrite {
    vtc_service::admin_actions::OperatorWrite {
        marker: format!("test-{}", uuid::Uuid::new_v4()),
        command: "vtc acl add".into(),
        action: "grant".into(),
        dids,
        operator_host: "test-host".into(),
        invoked_at: chrono::Utc::now(),
        acknowledgers: Some(acknowledgers),
    }
}

#[tokio::test]
async fn the_response_comes_first_then_a_hint_follows_an_action_change() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let (request, mut sse, _, first) = open_stream(
        &vtc,
        &admin,
        json!({ "topics": ["actions", "acknowledgements"] }),
    )
    .await;
    assert_eq!(first["payload"]["resumed"], false);
    let hb = first["payload"]["heartbeatSeconds"].as_i64().unwrap();
    assert!((5..=60).contains(&hb));
    assert_eq!(
        first["payload"]["topics"],
        json!(["actions", "acknowledgements"])
    );

    // An operator's offline write: an acknowledge item waiting for this
    // administrator. It names a DID; no hint may.
    vtc_service::admin_actions::raise_operator_item(
        &vtc.state,
        &operator_write(
            vec!["did:key:zSubjectOfTheWrite".into()],
            vec![admin.did.clone()],
        ),
    )
    .await
    .unwrap();

    let mut seen = std::collections::BTreeMap::new();
    while seen.len() < 2 {
        let (id, hint) = sse
            .next_event(Duration::from_secs(5))
            .await
            .expect("a hint follows the change");
        assert_hint_shape(&hint, id.as_deref(), &request, &admin.did);
        seen.insert(
            hint["payload"]["topic"].as_str().unwrap().to_string(),
            hint["payload"]["count"].as_u64(),
        );
    }
    assert_eq!(
        seen["actions"],
        Some(1),
        "waitingForMe, as the list counts it"
    );
    assert_eq!(seen["acknowledgements"], Some(1));
}

#[tokio::test]
async fn a_member_written_is_a_countless_members_hint() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let (request, mut sse, _, _) =
        open_stream(&vtc, &admin, json!({ "topics": ["members"] })).await;
    let newcomer = Party::new();
    vtc_service::members::store_member(
        &vtc.state.members_ks,
        &vtc_service::members::Member::fresh(&newcomer.did),
    )
    .await
    .unwrap();
    let (id, hint) = sse
        .next_event(Duration::from_secs(5))
        .await
        .expect("a members hint follows the write");
    assert_hint_shape(&hint, id.as_deref(), &request, &admin.did);
    assert_eq!(hint["payload"]["topic"], "members");
    assert!(
        !hint.to_string().contains(&newcomer.did),
        "the member written is never named"
    );
}

#[tokio::test]
async fn a_pending_join_request_is_hinted_with_the_lists_own_count() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let (request, mut sse, _, _) =
        open_stream(&vtc, &admin, json!({ "topics": ["joinRequests"] })).await;
    let applicant = Party::new();
    let mut req = vtc_service::join::JoinRequest::new(applicant.did.clone(), json!({ "vp": "x" }));
    req.status = vtc_service::join::JoinStatus::Pending;
    vtc_service::join::store_join_request(&vtc.state.join_requests_ks, &req)
        .await
        .unwrap();
    let (id, hint) = sse
        .next_event(Duration::from_secs(5))
        .await
        .expect("a joinRequests hint follows the request");
    assert_hint_shape(&hint, id.as_deref(), &request, &admin.did);
    assert_eq!(hint["payload"]["topic"], "joinRequests");

    // The count is the one `vtc/join-requests/list` reports as `totalEstimate`.
    let (_, page) = crate::common::signed::call(
        &vtc,
        &admin,
        "https://trusttasks.org/spec/vtc/join-requests/list/0.1",
        json!({ "status": "pending", "limit": 1 }),
    )
    .await;
    assert_eq!(hint["payload"]["count"], page["payload"]["totalEstimate"]);
    assert_eq!(hint["payload"]["count"], 1);
    assert!(
        !hint.to_string().contains(&applicant.did),
        "the applicant is never named"
    );
}

#[tokio::test]
async fn a_topic_the_caller_cannot_read_is_never_effective() {
    let vtc = vtc().await;
    // An auditor administers, so it reads the join-request list — and hears
    // its topic — but cannot export the configuration, so `config` is never
    // effective: topic readability is the read's own check.
    let auditor = with_role(&vtc, Some(AdminRole::Auditor), None).await;
    let (_, _sse, _, first) = open_stream(
        &vtc,
        &auditor,
        json!({ "topics": ["joinRequests", "actions", "config"] }),
    )
    .await;
    assert_eq!(
        first["payload"]["topics"],
        json!(["actions", "joinRequests"])
    );

    // The read agrees: the export is refused to the same caller.
    let (_, refused) = crate::common::signed::call(
        &vtc,
        &auditor,
        "https://trusttasks.org/spec/vtc/config/export/0.1",
        json!({}),
    )
    .await;
    assert_eq!(tt_error_code(&refused), Some("permissionDenied"));

    // Asking only for what it cannot read opens nothing.
    let (_, res) = subscribe(
        &vtc,
        &auditor,
        json!({ "topics": ["config"] }),
        Some(STREAM_ACCEPT),
        None,
    )
    .await;
    let (status, doc) = json_refusal(res).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(tt_error_code(&doc), Some("permissionDenied"));
}

#[tokio::test]
async fn the_stream_ends_when_readable_topics_shrink() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let (_, mut sse, _, first) =
        open_stream(&vtc, &admin, json!({ "topics": ["config", "actions"] })).await;
    assert_eq!(first["payload"]["topics"], json!(["actions", "config"]));

    // Reduced to a moderator: no configuration export any more.
    store_acl_entry(
        &vtc.state.acl_ks,
        &entry(
            &admin.did,
            AdminAuthority::for_role(AdminRole::Moderator),
            None,
        ),
    )
    .await
    .unwrap();
    assert!(
        sse.ends_within(Duration::from_secs(5)).await,
        "a shrunk standing ends the stream rather than silently dropping a topic"
    );
}

#[tokio::test]
async fn refusals_are_json_and_open_no_stream() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;

    // No `Accept: text/event-stream`: nothing to follow a #response with.
    let (_, res) = subscribe(&vtc, &admin, json!({ "topics": ["actions"] }), None, None).await;
    let (_, doc) = json_refusal(res).await;
    assert_eq!(tt_error_code(&doc), Some(STREAM_UNAVAILABLE));
    let (_, res) = subscribe(
        &vtc,
        &admin,
        json!({ "topics": ["actions"] }),
        Some("application/json"),
        None,
    )
    .await;
    let (_, doc) = json_refusal(res).await;
    assert_eq!(tt_error_code(&doc), Some(STREAM_UNAVAILABLE));

    // A member who administers nothing.
    let member = with_role(&vtc, None, None).await;
    let (_, res) = subscribe(
        &vtc,
        &member,
        json!({ "topics": ["actions"] }),
        Some(STREAM_ACCEPT),
        None,
    )
    .await;
    let (_, doc) = json_refusal(res).await;
    assert_eq!(tt_error_code(&doc), Some(NOT_ADMINISTRATOR));

    // A stranger is no administrator either.
    let stranger = Party::new();
    let (_, res) = subscribe(
        &vtc,
        &stranger,
        json!({ "topics": ["actions"] }),
        Some(STREAM_ACCEPT),
        None,
    )
    .await;
    let (_, doc) = json_refusal(res).await;
    assert_eq!(tt_error_code(&doc), Some(NOT_ADMINISTRATOR));

    // Resumption is in-band: a Last-Event-ID that disagrees with `since`.
    let (_, res) = subscribe(
        &vtc,
        &admin,
        json!({ "topics": ["actions"], "since": "e1.AAAA.BBBB" }),
        Some(STREAM_ACCEPT),
        Some("e1.CCCC.DDDD"),
    )
    .await;
    let (status, doc) = json_refusal(res).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(tt_error_code(&doc), Some("malformedRequest"));
}

#[tokio::test]
async fn a_replayed_subscribe_opens_nothing() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let (request, res) = subscribe(
        &vtc,
        &admin,
        json!({ "topics": ["actions"] }),
        Some(STREAM_ACCEPT),
        None,
    )
    .await;
    let _live = Sse::open(res);
    let again = post_raw(&vtc, &request, Some(STREAM_ACCEPT), None).await;
    assert_eq!(again.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn an_unknown_since_starts_fresh_and_a_known_one_resumes() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;

    let (_, _s, _, first) = open_stream(
        &vtc,
        &admin,
        json!({ "topics": ["config"], "since": "e1.not-a-token.at-all" }),
    )
    .await;
    assert_eq!(
        first["payload"]["resumed"], false,
        "an unknown token is never an error"
    );

    // Another caller's token is unknown too.
    let other = community_admin(&vtc).await;
    let (_, _o, others_token, _) = open_stream(&vtc, &other, json!({ "topics": ["config"] })).await;
    let (_, _s2, _, first) = open_stream(
        &vtc,
        &admin,
        json!({ "topics": ["config"], "since": others_token.unwrap() }),
    )
    .await;
    assert_eq!(first["payload"]["resumed"], false);

    // A token of the caller's own, then a change while away: resumed, and the
    // change is hinted straight after the response.
    let (_, sse, token, _) = open_stream(&vtc, &admin, json!({ "topics": ["config"] })).await;
    drop(sse);
    vtc_service::config_store::ConfigStore::new(vtc.state.config_ks.clone())
        .put("admin_events.test", &json!(1))
        .await
        .unwrap();
    let token = token.unwrap();
    let (request, res) = subscribe(
        &vtc,
        &admin,
        json!({ "topics": ["config"], "since": token }),
        Some(STREAM_ACCEPT),
        Some(&token),
    )
    .await;
    let mut sse = Sse::open(res);
    let (_, first) = sse.next_event(Duration::from_secs(5)).await.unwrap();
    assert_eq!(first["payload"]["resumed"], true);
    let (id, hint) = sse
        .next_event(Duration::from_secs(5))
        .await
        .expect("the change made while away is hinted");
    assert_hint_shape(&hint, id.as_deref(), &request, &admin.did);
    assert_eq!(hint["payload"]["topic"], "config");
}

#[tokio::test]
async fn heartbeats_are_comments() {
    set_heartbeat_seconds(5);
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let (_, mut sse, _, _) =
        open_stream(&vtc, &admin, json!({ "topics": ["singleAdminMode"] })).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match sse.next(left).await {
            Next::Comment(text) => {
                assert_eq!(text, "heartbeat");
                break;
            }
            Next::Event { .. } => continue,
            other => panic!("expected a heartbeat comment, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn the_stream_ends_when_the_credential_expires() {
    let vtc = vtc().await;
    let soon = vti_common::auth::session::now_epoch() + 2;
    let admin = with_role(&vtc, Some(AdminRole::CommunityAdmin), Some(soon)).await;
    let (_, mut sse, _, _) = open_stream(&vtc, &admin, json!({ "topics": ["actions"] })).await;
    assert!(
        sse.ends_within(Duration::from_secs(6)).await,
        "the stream does not outlive the authority it was opened on"
    );
}

#[tokio::test]
async fn streams_past_the_cap_are_refused_too_many_streams() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let mut open = Vec::new();
    for _ in 0..MAX_STREAMS_PER_SUBJECT {
        let (_, sse, _, _) = open_stream(&vtc, &admin, json!({ "topics": ["actions"] })).await;
        open.push(sse);
    }
    let (_, res) = subscribe(
        &vtc,
        &admin,
        json!({ "topics": ["actions"] }),
        Some(STREAM_ACCEPT),
        None,
    )
    .await;
    let (_, doc) = json_refusal(res).await;
    assert_eq!(tt_error_code(&doc), Some(TOO_MANY_STREAMS));
    assert_eq!(doc["payload"]["retryable"], true);

    // Closing one frees its place.
    drop(open.pop());
    let mut reopened = false;
    for _ in 0..50 {
        let (_, res) = subscribe(
            &vtc,
            &admin,
            json!({ "topics": ["actions"] }),
            Some(STREAM_ACCEPT),
            None,
        )
        .await;
        if res.status() == StatusCode::OK {
            reopened = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(reopened, "a closed stream releases its place under the cap");
}

// ─── 0.2: the `rooms` topic ──────────────────────────────────────────────

/// A room as the host registers it, its epoch expiring at `epoch_expires_at`.
fn hosted_room(epoch_expires_at: Option<u64>) -> vtc_service::rooms::Room {
    vtc_service::rooms::Room {
        room_id: format!("did:key:zRoom{}", uuid::Uuid::new_v4().simple()),
        owner_did: Party::new().did,
        visibility: vtc_service::rooms::Visibility::Open,
        retention_policy: Default::default(),
        anchor_cadence: Default::default(),
        epoch: 1,
        next_version: 1,
        retention_days: 90,
        epoch_expires_at,
        created_at: 0,
        updated_at: 0,
        mirror_of: None,
    }
}

/// The next `rooms` hint, skipping any other topic's.
async fn next_rooms_hint(sse: &mut Sse, within: Duration) -> Option<(Option<String>, Value)> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let (id, hint) = sse.next_event(left).await?;
        if hint["payload"]["topic"] == "rooms" {
            return Some((id, hint));
        }
    }
}

#[tokio::test]
async fn a_room_registered_is_a_countless_rooms_hint_at_0_2() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let (request, mut sse, _, first) = open_stream_at(
        &vtc,
        SUBSCRIBE_V0_2,
        &admin,
        json!({ "topics": ["rooms", "actions"] }),
    )
    .await;
    assert_eq!(first["payload"]["topics"], json!(["actions", "rooms"]));

    let room = hosted_room(None);
    vtc_service::rooms::storage::create_room(&vtc.state.rooms_ks, &room)
        .await
        .unwrap();
    let (id, hint) = next_rooms_hint(&mut sse, Duration::from_secs(5))
        .await
        .expect("a rooms hint follows the registration");
    assert_hint_shape(&hint, id.as_deref(), &request, &admin.did);
    assert!(
        !hint.to_string().contains(&room.room_id) && !hint.to_string().contains(&room.owner_did),
        "the room is never named"
    );
}

#[tokio::test]
async fn a_storage_config_written_is_a_rooms_hint() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let (request, mut sse, _, _) =
        open_stream_at(&vtc, SUBSCRIBE_V0_2, &admin, json!({ "topics": ["rooms"] })).await;

    let storage = &vtc.state.room_storage;
    let mut config = storage.configs().await.unwrap().remove(0);
    config["label"] = json!("Relabelled");
    {
        let _guard = storage.lock().await;
        storage.put_config(config).await.unwrap();
    }
    let (id, hint) = next_rooms_hint(&mut sse, Duration::from_secs(5))
        .await
        .expect("a changed storage config is hinted");
    assert_hint_shape(&hint, id.as_deref(), &request, &admin.did);
}

/// Lifecycle is computed from the clock and never written, so the stream
/// looks again when a room's state is due to change (event 0.2 producer rule
/// 4: "a room's lifecycle state changes").
#[tokio::test]
async fn a_room_lapsing_with_the_clock_is_hinted_without_a_write() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let expires = vti_common::auth::session::now_epoch() + 2;
    vtc_service::rooms::storage::create_room(&vtc.state.rooms_ks, &hosted_room(Some(expires)))
        .await
        .unwrap();
    // Opened after the registration: only the lapse is left to hint.
    let (request, mut sse, _, _) =
        open_stream_at(&vtc, SUBSCRIBE_V0_2, &admin, json!({ "topics": ["rooms"] })).await;
    let (id, hint) = next_rooms_hint(&mut sse, Duration::from_secs(8))
        .await
        .expect("the room lapsing is hinted");
    assert_hint_shape(&hint, id.as_deref(), &request, &admin.did);
}

/// A rooms signal that moves nothing the reads report — a renewal of a live
/// room — is no hint: only the changes rule 4 names are.
#[tokio::test]
async fn a_renewal_of_a_live_room_is_no_hint() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let now = vti_common::auth::session::now_epoch();
    let room = hosted_room(Some(now + 86_400));
    vtc_service::rooms::storage::create_room(&vtc.state.rooms_ks, &room)
        .await
        .unwrap();
    let (_, mut sse, _, _) =
        open_stream_at(&vtc, SUBSCRIBE_V0_2, &admin, json!({ "topics": ["rooms"] })).await;
    vtc_service::rooms::storage::advance_epoch(&vtc.state.rooms_ks, &room.room_id, 2, now)
        .await
        .unwrap();
    assert!(
        next_rooms_hint(&mut sse, Duration::from_secs(3))
            .await
            .is_none(),
        "a live room renewed is still live: nothing a read reports moved"
    );
}

#[tokio::test]
async fn rooms_is_effective_only_for_a_rooms_administrator() {
    let vtc = vtc().await;
    // A moderator administers, but holds no `vtc.rooms.admin`: the rooms reads
    // refuse it, and so does the topic.
    let moderator = with_role(&vtc, Some(AdminRole::Moderator), None).await;
    let (_, _sse, _, first) = open_stream_at(
        &vtc,
        SUBSCRIBE_V0_2,
        &moderator,
        json!({ "topics": ["rooms", "actions"] }),
    )
    .await;
    assert_eq!(first["payload"]["topics"], json!(["actions"]));
    let (_, refused) = crate::common::signed::call(
        &vtc,
        &moderator,
        "https://trusttasks.org/spec/vtc/rooms/list/0.1",
        json!({}),
    )
    .await;
    assert_eq!(tt_error_code(&refused), Some("permissionDenied"));
}

/// The topic set is closed per version: a 0.1 subscribe cannot ask for
/// `rooms`, and a 0.1 stream is answered at 0.1 throughout.
#[tokio::test]
async fn a_0_1_subscribe_cannot_ask_for_rooms_and_stays_at_0_1() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let (_, res) = subscribe(
        &vtc,
        &admin,
        json!({ "topics": ["rooms"] }),
        Some(STREAM_ACCEPT),
        None,
    )
    .await;
    let (status, doc) = json_refusal(res).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(tt_error_code(&doc), Some("malformedRequest"));

    let (request, mut sse, _, first) =
        open_stream(&vtc, &admin, json!({ "topics": ["members"] })).await;
    assert_eq!(first["payload"]["topics"], json!(["members"]));
    vtc_service::members::store_member(
        &vtc.state.members_ks,
        &vtc_service::members::Member::fresh(&Party::new().did),
    )
    .await
    .unwrap();
    let (id, hint) = sse.next_event(Duration::from_secs(5)).await.unwrap();
    assert_hint_shape(&hint, id.as_deref(), &request, &admin.did);
    assert_eq!(hint["type"], EVENT);
}

/// A resumed stream hints a fingerprinted topic that changed while away, even
/// though what the stream observes when it opens already includes the change.
#[tokio::test]
async fn a_resumed_rooms_change_is_hinted_after_the_response() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let (_, sse, token, _) =
        open_stream_at(&vtc, SUBSCRIBE_V0_2, &admin, json!({ "topics": ["rooms"] })).await;
    drop(sse);
    vtc_service::rooms::storage::create_room(&vtc.state.rooms_ks, &hosted_room(None))
        .await
        .unwrap();
    let token = token.unwrap();
    let (request, res) = subscribe_at(
        &vtc,
        SUBSCRIBE_V0_2,
        &admin,
        json!({ "topics": ["rooms"], "since": token }),
        Some(STREAM_ACCEPT),
        Some(&token),
    )
    .await;
    let mut sse = Sse::open(res);
    let (_, first) = sse.next_event(Duration::from_secs(5)).await.unwrap();
    assert_eq!(first["payload"]["resumed"], true);
    let (id, hint) = next_rooms_hint(&mut sse, Duration::from_secs(5))
        .await
        .expect("the registration made while away is hinted");
    assert_hint_shape(&hint, id.as_deref(), &request, &admin.did);
}

// ─── 0.3: `directory` and `groups` ───────────────────────────────────────

/// The next hint of `topic`, skipping any other topic's.
async fn next_hint_of(
    sse: &mut Sse,
    topic: &str,
    within: Duration,
) -> Option<(Option<String>, Value)> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let (id, hint) = sse.next_event(left).await?;
        if hint["payload"]["topic"] == topic {
            return Some((id, hint));
        }
    }
}

fn a_group(group_id: &str) -> vtc_service::groups::Group {
    serde_json::from_value(json!({
        "groupId": group_id,
        "groupDid": format!("did:webvh:Qm{group_id}:groups.example"),
        "signingKeyId": "key-1",
        "name": "Working group",
        "joinPolicy": "closed",
        "visibility": "members",
        "showMembers": "members",
        "issuesCredentials": false,
        "createdAt": "2026-10-20T00:00:00Z",
        "updatedAt": "2026-10-20T00:00:00Z",
    }))
    .unwrap()
}

#[tokio::test]
async fn directory_and_groups_are_countless_hints_at_0_3_naming_nothing() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    let (request, mut sse, _, first) = open_stream_at(
        &vtc,
        SUBSCRIBE_V0_3,
        &admin,
        json!({ "topics": ["groups", "directory"] }),
    )
    .await;
    assert_eq!(first["payload"]["topics"], json!(["directory", "groups"]));

    let member = Party::new();
    let card = vtc_service::directory::cards::ensure(
        vtc.state.directory.ks(),
        &member.did,
        &vtc.state.directory.settings(),
        None,
    )
    .await
    .unwrap();
    let (id, hint) = next_hint_of(&mut sse, "directory", Duration::from_secs(15))
        .await
        .expect("a card written is a directory hint");
    assert_hint_shape(&hint, id.as_deref(), &request, &admin.did);
    assert!(
        !hint.to_string().contains(&card.entry_id),
        "no entry is named"
    );

    vtc_service::groups::put(
        vtc.state.directory.ks(),
        &a_group("grp_AAAAAAAAAAAAAAAAAAAAAA"),
    )
    .await
    .unwrap();
    let (id, hint) = next_hint_of(&mut sse, "groups", Duration::from_secs(5))
        .await
        .expect("a group stored is a groups hint");
    assert_hint_shape(&hint, id.as_deref(), &request, &admin.did);
    assert!(!hint.to_string().contains("grp_"), "no group is named");
}

#[tokio::test]
async fn a_0_2_subscribe_cannot_ask_for_directory_or_groups() {
    let vtc = vtc().await;
    let admin = community_admin(&vtc).await;
    for topic in ["directory", "groups"] {
        let (_, res) = subscribe_at(
            &vtc,
            SUBSCRIBE_V0_2,
            &admin,
            json!({ "topics": [topic] }),
            Some(STREAM_ACCEPT),
            None,
        )
        .await;
        let (status, doc) = json_refusal(res).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{topic}");
        assert_eq!(tt_error_code(&doc), Some("malformedRequest"), "{topic}");
    }
}

/// A manager qualified to one group (`group:<id>`) is sent a hint only for a
/// change to that group (subscribe 0.3 §Authorization), and an administrator
/// holding neither directory capability is not sent `directory` at all.
#[tokio::test]
async fn a_manager_of_one_group_is_hinted_only_about_that_group() {
    let vtc = vtc().await;
    let ks = vtc.state.directory.ks();
    let mine = "grp_MMMMMMMMMMMMMMMMMMMMMM";
    let other = "grp_OOOOOOOOOOOOOOOOOOOOOO";
    vtc_service::groups::put(ks, &a_group(mine)).await.unwrap();
    vtc_service::groups::put(ks, &a_group(other)).await.unwrap();

    let manager = Party::new();
    let mut e = entry(
        &manager.did,
        AdminAuthority::for_role(AdminRole::Approver),
        None,
    );
    e.resource_grants.push(
        serde_json::from_value(json!({
            "capability": "vtc.groups.manage",
            "resource": format!("group:{mine}"),
            "delegatedBy": "did:key:vtc-install",
            "grantedAt": "2026-10-20T00:00:00Z",
        }))
        .unwrap(),
    );
    store_acl_entry(&vtc.state.acl_ks, &e).await.unwrap();

    let (request, mut sse, _, first) = open_stream_at(
        &vtc,
        SUBSCRIBE_V0_3,
        &manager,
        json!({ "topics": ["groups", "directory", "actions"] }),
    )
    .await;
    assert_eq!(first["payload"]["topics"], json!(["actions", "groups"]));

    let mut changed = a_group(other);
    changed.name = "Renamed".into();
    vtc_service::groups::put(ks, &changed).await.unwrap();
    assert!(
        next_hint_of(&mut sse, "groups", Duration::from_secs(3))
            .await
            .is_none(),
        "another group's change is no hint to a manager of one"
    );

    let mut changed = a_group(mine);
    changed.name = "Renamed".into();
    vtc_service::groups::put(ks, &changed).await.unwrap();
    let (id, hint) = next_hint_of(&mut sse, "groups", Duration::from_secs(5))
        .await
        .expect("their own group's change is hinted");
    assert_hint_shape(&hint, id.as_deref(), &request, &manager.did);
}
