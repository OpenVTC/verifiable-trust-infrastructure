//! The wire types must agree with the published schemas.
//!
//! # Why this file exists
//!
//! `vti_rooms::wire` hand-rolls the `rooms/*` request and response bodies. The specs are
//! published — `trustoverip/dtgwg-trust-tasks-tf`, generated into `trust_tasks_rs` — so
//! there are now two descriptions of the same wire form and nothing making them agree.
//!
//! The VTC has a conformance sweep for exactly this, but it is scoped to
//! `https://trusttasks.org/spec/vtc/` and says so in its own module docs. The rooms family
//! publishes at top level, `spec/rooms/`, so it falls outside — this is its equivalent.
//!
//! The drift class it catches is not hypothetical in this workspace: a `snake_case` field
//! where the schema says `camelCase` is invisible to every Rust test, because both sides of
//! a round-trip use the same struct. It took an empty `allowed_contexts` minting a
//! super-admin (#656/#658) to establish that. Serde is not the check — a schema is.
//!
//! # What each test does
//!
//! Builds a value with the hand-rolled type, serialises it, and validates the result
//! against the spec's own embedded schema. That catches what serde cannot: `camelCase`
//! renames, required members that were made optional, `const` and `enum` values, patterns,
//! and — because the request schemas are `additionalProperties: false` — a field this
//! implementation invented that the spec does not have.
//!
//! # What it deliberately does not do
//!
//! It does not assert the hand-rolled type is *identical* to the generated one. They differ
//! on purpose: the generated `Payload` types use newtypes and `NonZeroU64` where this crate
//! wants plain strings and `u64`, and a storage layer should not be forced through a
//! builder. Agreeing on the wire is the requirement; agreeing on the Rust shape is not.

use serde_json::{Value, json};
use trust_tasks_rs::validate::ValidatedPayload;
use vti_rooms::wire::*;
use vti_rooms::{Record, RecordStatus, Visibility};

/// Validate `value` against the schema published for `T`.
fn check<T: ValidatedPayload>(what: &str, value: &Value) {
    if let Err(e) = T::validate_value(value) {
        panic!(
            "{what} does not conform to its published schema: {e}\n\nproduced:\n{}",
            serde_json::to_string_pretty(value).unwrap_or_default()
        );
    }
}

/// A presentation, as every request carries one.
fn presentation() -> AuthorityPresentation {
    AuthorityPresentation {
        membership: "urn:uuid:11111111-1111-1111-1111-111111111111".into(),
        authority: vec![
            "urn:uuid:22222222-2222-2222-2222-222222222222".into(),
            "urn:uuid:33333333-3333-3333-3333-333333333333".into(),
        ],
        subject_binding: None,
    }
}

#[test]
fn create_room_conforms() {
    use trust_tasks_rs::specs::rooms::create::v0_1::Payload;

    for visibility in [
        Visibility::Open,
        Visibility::Attributed,
        Visibility::Private,
    ] {
        let body = CreateRoomBody {
            room_id: "did:webvh:example.com:rooms:northwind".into(),
            owner_did: "did:key:z6MkOwner".into(),
            visibility,
            retention_days: Some(90),
        };
        check::<Payload>(
            &format!("CreateRoomBody ({visibility:?})"),
            &serde_json::to_value(&body).expect("serialise"),
        );
    }

    // `retentionDays` is optional, and "absent" must serialise as absent rather than
    // `null` — a schema typing it `integer` rejects an explicit null.
    let body = CreateRoomBody {
        room_id: "did:webvh:example.com:rooms:northwind".into(),
        owner_did: "did:key:z6MkOwner".into(),
        visibility: Visibility::Open,
        retention_days: None,
    };
    let value = serde_json::to_value(&body).expect("serialise");
    check::<Payload>("CreateRoomBody with no retention", &value);
}

#[test]
fn put_record_conforms_on_both_tiers() {
    use trust_tasks_rs::specs::rooms::records::put::v0_1::Payload;

    let sealed = PutRecordBody {
        room_id: "did:webvh:example.com:rooms:northwind".into(),
        key: "giXFLTGBdnnQJRoIsktuIg".into(),
        presentation: presentation(),
        sealed: Some(SealedContent {
            ciphertext: "1ep1PJuf8-yNmTndwcuMxA".into(),
            nonce: "AAAAAAAAAAAAAAAA".into(),
            epoch: 1,
        }),
        cleartext: None,
        expected_version: Some(0),
    };
    check::<Payload>(
        "PutRecordBody (sealed)",
        &serde_json::to_value(&sealed).expect("serialise"),
    );

    let cleartext = PutRecordBody {
        room_id: "did:webvh:example.com:rooms:northwind".into(),
        key: "decision/pricing-2026".into(),
        presentation: presentation(),
        sealed: None,
        cleartext: Some(CleartextContent {
            title: Some("Pricing holds through Q3".into()),
            description: None,
            body: "Agreed not to reprice before the renewal closes.".into(),
            tags: vec!["pricing".into()],
        }),
        expected_version: None,
    };
    check::<Payload>(
        "PutRecordBody (cleartext)",
        &serde_json::to_value(&cleartext).expect("serialise"),
    );
}

#[test]
fn get_and_list_requests_conform() {
    use trust_tasks_rs::specs::rooms::records::get::v0_1::Payload as GetPayload;
    use trust_tasks_rs::specs::rooms::records::list::v0_1::Payload as ListPayload;

    let get = GetRecordBody {
        room_id: "did:webvh:example.com:rooms:northwind".into(),
        key: "decision/pricing-2026".into(),
        presentation: presentation(),
    };
    check::<GetPayload>(
        "GetRecordBody",
        &serde_json::to_value(&get).expect("serialise"),
    );

    let list = ListRecordsBody {
        room_id: "did:webvh:example.com:rooms:northwind".into(),
        presentation: presentation(),
        prefix: Some("decision/".into()),
        since_version: Some(4),
        limit: Some(50),
    };
    check::<ListPayload>(
        "ListRecordsBody",
        &serde_json::to_value(&list).expect("serialise"),
    );

    // Every optional narrowing absent — the incremental-sync caller's first call.
    let bare = ListRecordsBody {
        room_id: "did:webvh:example.com:rooms:northwind".into(),
        presentation: presentation(),
        prefix: None,
        since_version: None,
        limit: None,
    };
    check::<ListPayload>(
        "ListRecordsBody with no narrowing",
        &serde_json::to_value(&bare).expect("serialise"),
    );
}

#[test]
fn mint_epoch_conforms() {
    use trust_tasks_rs::specs::rooms::epoch::mint::v0_1::Payload;

    let body = MintEpochBody {
        room_id: "did:webvh:example.com:rooms:northwind".into(),
        epoch: 2,
        presentation: presentation(),
        reason: Some("membership change".into()),
    };
    check::<Payload>(
        "MintEpochBody",
        &serde_json::to_value(&body).expect("serialise"),
    );
}

/// A private room's presentation carries the pooling defence, and it must survive
/// serialisation under the name the schema gives it.
#[test]
fn a_subject_binding_conforms_under_its_published_name() {
    use trust_tasks_rs::specs::rooms::records::get::v0_1::Payload;

    let mut p = presentation();
    p.subject_binding = Some("urn:uuid:44444444-4444-4444-4444-444444444444".into());
    let get = GetRecordBody {
        room_id: "did:webvh:example.com:rooms:private".into(),
        key: "giXFLTGBdnnQJRoIsktuIg".into(),
        presentation: p,
    };
    let value = serde_json::to_value(&get).expect("serialise");
    assert!(
        value["presentation"]["subjectBinding"].is_string(),
        "the binding must travel as `subjectBinding`, not snake_case: {value}"
    );
    check::<Payload>("GetRecordBody with a subject binding", &value);
}

// ─── Responses ───────────────────────────────────────────────────────────

#[test]
fn responses_conform() {
    use trust_tasks_rs::specs::rooms::create::v0_1::Response as CreateResponse;
    use trust_tasks_rs::specs::rooms::epoch::mint::v0_1::Response as MintResponse;
    use trust_tasks_rs::specs::rooms::records::list::v0_1::Response as ListResponse;
    use trust_tasks_rs::specs::rooms::records::put::v0_1::Response as PutResponse;

    check::<CreateResponse>(
        "CreateRoomResponse",
        &serde_json::to_value(CreateRoomResponse {
            room_id: "did:webvh:example.com:rooms:northwind".into(),
            epoch: 1,
        })
        .expect("serialise"),
    );

    check::<PutResponse>(
        "PutRecordResponse",
        &serde_json::to_value(PutRecordResponse {
            key: "decision/pricing-2026".into(),
            version: 1,
            epoch: Some(1),
        })
        .expect("serialise"),
    );

    check::<MintResponse>(
        "MintEpochResponse",
        &serde_json::to_value(MintEpochResponse {
            room_id: "did:webvh:example.com:rooms:northwind".into(),
            epoch: 2,
        })
        .expect("serialise"),
    );

    // A listing carries metadata, and a tombstone is part of it — a caller that never saw
    // a retraction resurrects the record on its next rebuild.
    //
    // This runs `Record::metadata()` rather than a hand-built object on purpose: the
    // projection is the thing that has to conform, and a literal written beside it would
    // only ever agree with itself. Both drifts this file has caught were in the projection
    // — a unix integer where the schema says `date-time`, and `null` for an absent
    // optional under `additionalProperties: false`.
    let records: Vec<Value> = [
        // An open-tier record: cleartext, an author, no epoch.
        Record {
            key: "decision/pricing-2026".into(),
            version: 3,
            epoch: None,
            status: RecordStatus::Active,
            pinned: false,
            sealed: None,
            nonce: None,
            cleartext: Some(json!({
                "title": "Pricing holds through Q3",
                "body": "Agreed not to reprice before the renewal closes.",
            })),
            author: Some("did:key:z6MkAlice".into()),
            updated_at: 1_756_000_000,
        },
        // A tombstone: no body, no author, and it still has to conform.
        Record {
            key: "giXFLTGBdnnQJRoIsktuIg".into(),
            version: 5,
            epoch: Some(2),
            status: RecordStatus::Retracted,
            pinned: false,
            sealed: None,
            nonce: None,
            cleartext: None,
            author: None,
            updated_at: 1_756_000_100,
        },
    ]
    .iter()
    .map(Record::metadata)
    .collect();

    assert_eq!(
        records[0]["updatedAt"], "2025-08-24T01:46:40Z",
        "the projection must render RFC 3339, not unix seconds"
    );
    assert!(
        records[1].get("author").is_none() && records[1].get("epoch").is_some(),
        "an absent optional must be absent, not null: {}",
        records[1]
    );

    check::<ListResponse>("ListRecordsResponse", &json!({ "records": records }));
}
