//! Producer census: what a client method *sends*, with nothing optional set.
//!
//! ## The gap this fills
//!
//! The conformance sweep in `vta-service::trust_tasks::conformance` checks a
//! *witness* — a value written in the test — against each task's schema. It
//! proves the shape is right. It cannot prove that any client method builds
//! that shape, because no client method runs during it.
//!
//! That is where both shipped payload defects lived:
//!
//! - #895 — `vta/webvh/dids/update/1.0` sent `null` for every unset member.
//! - #919 — `keys/create/0.1` sent `"mnemonic": null` on every call that was
//!   not importing a BIP-39 phrase, which is every call OpenVTC makes. The
//!   sweep's witness for that task was built from the real `CreateKeyBody`,
//!   with `mnemonic: None`, and it still passed: the sweep parsed the witness
//!   into the generated type, and serde reads `null` into an `Option<String>`
//!   without complaint.
//!
//! Both were found by a person, from a rejected request, in production.
//!
//! ## What runs here
//!
//! Each client method below is called for real, through
//! [`VtaClient::loopback`], with **every optional argument unset** — the shape
//! that broke `keys/create`, and the shape a caller reaches for first. The
//! payload it builds is captured and validated against the URI's published
//! schema, which is the same check the recipient's dispatch spine runs.
//!
//! No VTA, no mediator, no socket: the loopback transport answers in-process,
//! so this is a unit test in cost and an integration test in what it covers.
//!
//! ## Why these methods
//!
//! The 19 methods here are every Trust-Task client method that takes an
//! optional argument *and builds its payload by hand* — `json!` plus a
//! conditional insert per member. They are the surface the `vta-sdk` null
//! census (`tests/payload_null_census.rs`) cannot see, because there is no
//! struct to inspect: the invariant lives in the shape of an `if let`, not in
//! an attribute.
//!
//! Methods that take a typed body instead (`create_key(CreateKeyRequest)` and
//! friends) are covered by that census at the source, and by the sweep on the
//! wire.
//!
//! ## What this does not cover
//!
//! Framing — TSP sealing, DIDComm authcrypt, mediator routing. Those sit below
//! the loopback point and need a transport harness with a real mediator.

use std::sync::Arc;

use serde_json::{Value, json};
use vta_sdk::client::VtaClient;
use vta_sdk::client::loopback::RecordingSink;

/// Drive `f` against a loopback client and return everything it dispatched.
async fn captured<F, Fut>(f: F) -> Vec<(String, Value)>
where
    F: FnOnce(VtaClient) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let sink = Arc::new(RecordingSink::new());
    let client = VtaClient::loopback(sink.clone());
    f(client).await;
    sink.recorded()
}

/// Tasks this census drives that have no published payload schema.
///
/// Not a pass and not a waiver — a list of the places where nothing can check
/// us. A task here is dispatched by a client method, reaches a real VTA, and no
/// schema exists on either side to say whether the payload is right. The only
/// remedy is publishing the spec; until then this is where the gap is visible.
///
/// Kept exact in both directions by
/// [`every_unpublished_entry_is_still_unpublished`], so an entry cannot outlive
/// the gap it records.
///
/// Every entry is a legacy `vta/`-namespaced task that the canonical folds have
/// not reached, and that is the useful signal: the unvalidatable surface is
/// exactly the un-folded surface, so each of these closes for free when its
/// family is folded onto a published spec.
const UNPUBLISHED: &[(&str, &str)] = &[
    (
        "https://trusttasks.org/spec/vta/seeds/rotate/1.0",
        "The canonical `keys/*` fold (#888) did not reach the seed family.",
    ),
    (
        "https://trusttasks.org/spec/vault/credentials/receive/0.1",
        "The `vault/*` fold published query/get/upsert/delete but not \
         `credentials/receive`.",
    ),
];

/// Every captured payload conforms to its task's published schema.
///
/// `None` for a URI is only tolerated when [`UNPUBLISHED`] records it — a task
/// that quietly lost its schema would otherwise turn this census green by
/// having nothing left to check.
fn assert_conforms(captured: &[(String, Value)]) {
    assert!(
        !captured.is_empty(),
        "the client method dispatched nothing — it failed before reaching the \
         transport, so this row proves nothing"
    );

    for (uri, payload) in captured {
        let Some(schema) = trust_tasks_rs::schema_index::schema_for(uri) else {
            assert!(
                UNPUBLISHED.iter().any(|(u, _)| u == uri),
                "no published payload schema for `{uri}`, and it is not \
                 recorded in UNPUBLISHED. Either the task was renamed / the \
                 registry moved — in which case fix the constant — or this is \
                 a new unvalidatable task, in which case record it there with \
                 the reason. A missing schema is a coverage hole, not a pass."
            );
            continue;
        };
        trust_tasks_rs::validate::against_schema(schema, payload).unwrap_or_else(|e| {
            panic!(
                "{uri}: the payload this client method builds does not conform \
                 to its own schema: {e}\n\n{payload:#}\n\n\
                 An unset optional member must be ABSENT, not `null` — build \
                 the payload with a conditional insert, or with a body struct \
                 whose members carry `skip_serializing_if`."
            )
        });
    }
}

/// The census, one row per client method, every optional argument `None`.
///
/// Each row's `Err` is discarded on purpose: the loopback sink answers with
/// `null`, so most methods fail to deserialize their response. The request has
/// already been captured by then, and the request is what is under test.
#[tokio::test]
async fn every_optional_argument_unset_still_builds_a_conforming_payload() {
    // ── keys ─────────────────────────────────────────────────────────
    assert_conforms(&captured(|c| async move { drop(c.list_keys(0, 50, None, None).await) }).await);
    assert_conforms(
        &captured(|c| async move {
            drop(
                c.derive_and_sign_document(
                    vta_sdk::keys::KeyType::Ed25519,
                    "m/26'/9'/0'",
                    json!({"hello": "world"}),
                    None,
                )
                .await,
            )
        })
        .await,
    );
    assert_conforms(&captured(|c| async move { drop(c.rotate_seed(None).await) }).await);

    // ── acl ──────────────────────────────────────────────────────────
    assert_conforms(
        &captured(|c| async move {
            drop(
                c.list_acl_in_direction(None, vta_sdk::acl::ContextDirection::Subtree)
                    .await,
            )
        })
        .await,
    );

    // ── credentials ──────────────────────────────────────────────────
    assert_conforms(
        &captured(|c| async move {
            drop(
                c.issue_credential("did:key:z6MkHolder", json!({"a": 1}), None, 3600, None)
                    .await,
            )
        })
        .await,
    );
    assert_conforms(
        &captured(|c| async move { drop(c.revoke_credential("urn:uuid:cred-1", None).await) })
            .await,
    );

    // ── webvh ────────────────────────────────────────────────────────
    assert_conforms(
        &captured(|c| async move {
            drop(
                c.register_did_with_server("did:webvh:scid:vta.example", "server-1", false, None)
                    .await,
            )
        })
        .await,
    );
    assert_conforms(&captured(|c| async move { drop(c.list_dids_webvh(None, None).await) }).await);

    // ── consent ──────────────────────────────────────────────────────
    // `ConsentSubject` is `additionalProperties: false` with four required
    // members, and `challenge` carries `minLength: 16` — the census validates
    // against the real schema, so its fixtures have to satisfy the real
    // constraints, not just look plausible.
    let subject = json!({
        "platform": "signal",
        "conversationRef": "sig-1a2b3c4d",
        "kind": "dm",
        "agent": "did:key:z6MkAgent",
    });
    const CHALLENGE: &str = "Y2hhbGxlbmdlLW5vbmNlLTEyOA";
    let s = subject.clone();
    assert_conforms(
        &captured(|c| async move {
            drop(
                c.consent_request(
                    &vta_sdk::protocols::consent_management::ConsentRequestBody {
                        subject: s,
                        scope: "converse".into(),
                        challenge: CHALLENGE.into(),
                        // Every optional member set: this suite checks what the
                        // producer *emits*, and a member left `None` is skipped
                        // before it reaches the schema. Populated, it is the only
                        // place `firstMessageDigest` gets its encoding checked.
                        display_hint: Some("Signal group 'Family'".into()),
                        first_message_digest: Some(
                            "zQmSK9pGKFnmc77pqyNAPJyPKt8rMqctngfg3vwuMArwGYZ".into(),
                        ),
                        context_hint: Some("ctx-a".into()),
                    },
                )
                .await,
            )
        })
        .await,
    );
    let s = subject.clone();
    assert_conforms(
        &captured(|c| async move { drop(c.consent_decision(s, "allow", None, None, None).await) })
            .await,
    );
    let s = subject.clone();
    assert_conforms(&captured(|c| async move { drop(c.consent_revoke(s, None).await) }).await);
    assert_conforms(
        &captured(|c| async move { drop(c.consent_list(None, None, None).await) }).await,
    );
    assert_conforms(
        &captured(|c| async move {
            drop(
                c.consent_approver_set("cli", "ctx", "did:key:z6MkApprover", None, None)
                    .await,
            )
        })
        .await,
    );
    assert_conforms(
        &captured(|c| async move { drop(c.consent_approver_list(None, None).await) }).await,
    );

    // ── devices ──────────────────────────────────────────────────────
    assert_conforms(
        &captured(|c| async move {
            // `ConsumerKind` is a tagged `oneOf`, not a bare string.
            drop(
                c.device_register(
                    json!({"kind": "companion", "formFactor": "desktop"}),
                    "laptop",
                    None,
                    None,
                )
                .await,
            )
        })
        .await,
    );
    assert_conforms(&captured(|c| async move { drop(c.device_heartbeat(None).await) }).await);

    // ── vault ────────────────────────────────────────────────────────
    // `vault_upsert` takes the whole payload from its caller, so the SDK
    // contributes only `sealedSecret`. The row still earns its place: it pins
    // that an absent `sealed_secret` inserts no member at all.
    assert_conforms(
        &captured(|c| async move {
            drop(
                c.vault_upsert(
                    json!({
                        "id": "secret-1",
                        "contextId": "openvtc",
                        // `SiteTarget` is a `kind`-tagged union, not a bare URL.
                        "targets": [{"kind": "web-origin", "origin": "https://example.test"}],
                        "label": "example login",
                        "secretKind": "password",
                    }),
                    None,
                )
                .await,
            )
        })
        .await,
    );
    assert_conforms(
        &captured(|c| async move { drop(c.vault_delete("secret-1", None, false, None).await) })
            .await,
    );
    assert_conforms(
        &captured(|c| async move {
            drop(
                c.cred_vault_receive(json!({"id": "urn:uuid:vc-1"}), None)
                    .await,
            )
        })
        .await,
    );
}

/// An [`UNPUBLISHED`] entry names a task that really has no schema *today*.
///
/// The stale direction: once a spec is published, the entry must go, or the
/// census would keep skipping a task it could now check — the same
/// both-directions discipline the conformance sweep's coverage assertion uses.
#[test]
fn every_unpublished_entry_is_still_unpublished() {
    for (uri, reason) in UNPUBLISHED {
        assert!(
            !reason.trim().is_empty(),
            "{uri}: an UNPUBLISHED entry must state why no schema exists"
        );
        assert!(
            trust_tasks_rs::schema_index::schema_for(uri).is_none(),
            "`{uri}` now HAS a published payload schema, so the census can \
             validate it. Remove the UNPUBLISHED entry — leaving it there \
             silently skips a task that is now checkable."
        );
    }
}

/// The loopback seam itself reports what was sent, not what was asked for.
///
/// Teeth for the census: if the sink recorded the *arguments* rather than the
/// serialized payload, every row above would pass regardless of what went on
/// the wire. This pins that a `None` argument reaches the payload as an absent
/// member, and a `Some` reaches it as a present one.
#[tokio::test]
async fn the_sink_observes_the_serialized_payload() {
    let unset = captured(|c| async move { drop(c.device_heartbeat(None).await) }).await;
    let (_, payload) = &unset[0];
    assert!(
        payload.get("platform").is_none(),
        "an unset optional must be absent from the payload, got: {payload:#}"
    );

    let set = captured(|c| async move { drop(c.device_heartbeat(Some("macos")).await) }).await;
    let (_, payload) = &set[0];
    assert_eq!(
        payload.get("platform").and_then(Value::as_str),
        Some("macos"),
        "a set optional must reach the payload: {payload:#}"
    );
}

/// A payload the recipient would reject never leaves the process.
///
/// The pre-dispatch check exists for the surface no body struct can guard:
/// `vault_*` and `device/list` take the whole payload as a caller-supplied
/// `Value`, so there is nothing for the null census to walk and nothing for a
/// witness to be built from. This is the only check they can have.
///
/// Asserting on the *sink* rather than just the error is the point — it proves
/// the refusal happens before dispatch, so the failure is local and names the
/// member, instead of arriving as a remote `malformedRequest` after the client
/// has already reported a successful send.
#[tokio::test]
async fn a_non_conforming_payload_is_refused_before_it_is_sent() {
    let sink = Arc::new(RecordingSink::new());
    let client = VtaClient::loopback(sink.clone());

    // `keys/create/0.1` types `mnemonic` as a string. This is the exact payload
    // that shipped in #919 and was rejected by every VTA it reached.
    let outcome = client
        .dispatch_trust_task(
            "https://trusttasks.org/spec/keys/create/0.1",
            json!({ "keyType": "ed25519", "mnemonic": null }),
            5,
        )
        .await;

    let err = outcome.expect_err("a null-valued string member must be refused");
    let text = err.to_string();
    assert!(
        text.contains("does not conform"),
        "the error should say the payload is non-conforming, got: {text}"
    );
    assert!(
        text.contains("null"),
        "the error should name what is wrong, got: {text}"
    );
    assert!(
        sink.recorded().is_empty(),
        "nothing may reach the transport — the whole point is that the failure \
         is local, not a remote rejection after a reported-successful send"
    );
}

/// A task with no published schema still dispatches.
///
/// `None` from the registry means "we cannot know", not "anything goes".
/// Refusing on that basis would break every task the registry has not caught up
/// with — several legacy `vta/*` tasks are in exactly that position.
#[tokio::test]
async fn a_task_with_no_published_schema_is_not_blocked() {
    let sink = Arc::new(RecordingSink::new());
    let client = VtaClient::loopback(sink.clone());

    let _ = client
        .dispatch_trust_task(
            "https://trusttasks.org/spec/vta/seeds/rotate/1.0",
            json!({ "anything": null }),
            5,
        )
        .await;

    assert_eq!(
        sink.recorded().len(),
        1,
        "an unvalidatable task must still be dispatched, not refused"
    );
}
