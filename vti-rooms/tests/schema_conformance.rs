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

/// Curate shipped without an entry here — the same omission as its missing dispatch-census
/// entry, and from the same cause: a second list of the same thing agrees right up until
/// someone adds to one of them.
#[test]
fn curate_conforms() {
    use trust_tasks_rs::specs::rooms::records::curate::v0_1::Payload;

    let body = CurateRecordBody {
        room_id: "did:webvh:example.com:rooms:northwind".into(),
        key: "decision/pricing-2026".into(),
        presentation: presentation(),
        status: Some(RecordStatus::Deprecated),
        pinned: Some(false),
        reason: Some("superseded by the Q3 renewal".into()),
        expected_version: Some(4),
    };
    check::<Payload>(
        "CurateRecordBody",
        &serde_json::to_value(&body).expect("serialise"),
    );

    // Every member but the first three is optional, and a curation that changes only
    // `pinned` is the ordinary case rather than the exotic one.
    check::<Payload>(
        "CurateRecordBody pinning only",
        &serde_json::to_value(CurateRecordBody {
            status: None,
            pinned: Some(true),
            reason: None,
            expected_version: None,
            ..body
        })
        .expect("serialise"),
    );
}

#[test]
fn curate_response_conforms() {
    use trust_tasks_rs::specs::rooms::records::curate::v0_1::Response;

    check::<Response>(
        "CurateRecordResponse",
        &serde_json::to_value(CurateRecordResponse {
            key: "decision/pricing-2026".into(),
            version: 5,
            status: RecordStatus::Deprecated,
            pinned: false,
        })
        .expect("serialise"),
    );
}

// ─── Succession ──────────────────────────────────────────────────────────

#[test]
fn transfer_owner_conforms() {
    use trust_tasks_rs::specs::rooms::owner::transfer::v0_1::Payload;

    check::<Payload>(
        "TransferOwnerBody",
        &serde_json::to_value(TransferOwnerBody {
            room_id: "did:webvh:example.com:rooms:northwind".into(),
            new_owner_did: "did:key:z6MkBob".into(),
            presentation: presentation(),
            reason: Some("stepping back from this project".into()),
        })
        .expect("serialise"),
    );
}

#[test]
fn claim_owner_conforms() {
    use trust_tasks_rs::specs::rooms::owner::claim::v0_1::Payload;

    let body = ClaimOwnerBody {
        room_id: "did:webvh:example.com:rooms:northwind".into(),
        nomination: "urn:uuid:55555555-5555-5555-5555-555555555555".into(),
        presentation: presentation(),
        reason: Some("the owner has been unreachable since March".into()),
    };
    let value = serde_json::to_value(&body).expect("serialise");
    check::<Payload>("ClaimOwnerBody", &value);

    // The correction in #361: a claim carries the claimant's own presentation, because it
    // is the only membership signal a host has. Its absence was an unimplementable
    // condition, so its presence is worth pinning rather than assuming.
    assert!(
        value["presentation"].is_object(),
        "a claim must carry a presentation: {value}"
    );

    // And `reason` really is optional — a schema that quietly required it would make every
    // terse claim fail at the host rather than here.
    let bare = ClaimOwnerBody {
        reason: None,
        ..body
    };
    check::<Payload>(
        "ClaimOwnerBody without a reason",
        &serde_json::to_value(&bare).expect("serialise"),
    );
}

/// Both succession tasks answer with the same shape, and the schemas are separate
/// documents — so "the same shape" is a claim to check, not one to assume.
#[test]
fn owner_responses_conform() {
    use trust_tasks_rs::specs::rooms::owner::claim::v0_1::Response as ClaimResponse;
    use trust_tasks_rs::specs::rooms::owner::transfer::v0_1::Response as TransferResponse;

    let response = serde_json::to_value(OwnerResponse {
        room_id: "did:webvh:example.com:rooms:northwind".into(),
        owner_did: "did:key:z6MkBob".into(),
    })
    .expect("serialise");

    check::<TransferResponse>("OwnerResponse (transfer)", &response);
    check::<ClaimResponse>("OwnerResponse (claim)", &response);
}

// ─── The URIs themselves ─────────────────────────────────────────────────

/// Every `rooms/*` URI constant must be the one the registry publishes.
///
/// This is the guarantee the hosts' dispatch censuses could not give on their own. They pin
/// a dispatcher against `vti_rooms::wire`, which answers "do these two lists agree" — and
/// two lists agreeing says nothing if both are wrong. Comparing against the generated
/// `TYPE_URI` is what makes the answer "and they agree with the spec".
///
/// It matters because a URI is matched as a string. A version segment that drifted, or a
/// path this crate spelled differently from the schema, produces a service that answers
/// `unsupportedType` to a document the registry says it serves — with nothing in Rust
/// noticing, because every test on both sides uses the same constant.
#[test]
fn every_dispatched_uri_is_the_published_one() {
    use trust_tasks_rs::specs::rooms;

    let published: Vec<(&str, &str)> = vec![
        (
            ROOMS_CREATE_TYPE,
            <rooms::create::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ),
        (
            ROOMS_RECORDS_PUT_TYPE,
            <rooms::records::put::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ),
        (
            ROOMS_RECORDS_GET_TYPE,
            <rooms::records::get::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ),
        (
            ROOMS_RECORDS_LIST_TYPE,
            <rooms::records::list::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ),
        (
            ROOMS_RECORDS_CURATE_TYPE,
            <rooms::records::curate::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ),
        (
            ROOMS_EPOCH_MINT_TYPE,
            <rooms::epoch::mint::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ),
        (
            ROOMS_OWNER_TRANSFER_TYPE,
            <rooms::owner::transfer::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ),
        (
            ROOMS_OWNER_CLAIM_TYPE,
            <rooms::owner::claim::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ),
    ];

    for (ours, registry) in &published {
        assert_eq!(ours, registry, "this crate's URI is not the published one");
    }

    // And the dispatch list is exactly those — so a URI cannot be added to `wire` without
    // being checked against the registry here.
    assert_eq!(
        ROOMS_DISPATCHED_URIS.len(),
        published.len(),
        "a dispatched URI has no registry check: {:?}",
        ROOMS_DISPATCHED_URIS
            .iter()
            .filter(|u| !published.iter().any(|(ours, _)| ours == *u))
            .collect::<Vec<_>>()
    );
    for u in ROOMS_DISPATCHED_URIS {
        assert!(
            published.iter().any(|(ours, _)| ours == u),
            "{u} is dispatched but not checked against the registry"
        );
    }
}
