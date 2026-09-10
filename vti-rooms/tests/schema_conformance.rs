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
use vti_rooms::{Record, RecordStatus, Visibility, merkle};

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
        cursor: Some("v412".into()),
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
        cursor: None,
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
        link: None,
        commit: Some("AAECAwQFBgcICQoLDA0ODw".into()),
        reason: Some("membership change".into()),
    };
    check::<Payload>(
        "MintEpochBody",
        &serde_json::to_value(&body).expect("serialise"),
    );

    // With the rung, which is the shape a room that keeps its history actually sends. An
    // absent `link` is a room's stated choice, so both shapes have to conform — checking
    // only the empty one would let the member that carries key material go unvalidated.
    let with_link = MintEpochBody {
        link: Some(epoch_link(2)),
        ..body
    };
    check::<Payload>(
        "MintEpochBody with a link",
        &serde_json::to_value(&with_link).expect("serialise"),
    );
}

fn epoch_link(epoch: u32) -> EpochLink {
    EpochLink {
        epoch,
        wrapped: "9jK2_QhV1sVvR0m5xAqZ7A".into(),
        nonce: "b0Zt8Qm2Yq1sVvR0".into(),
    }
}

/// `rooms/epoch/chain/0.1` — the request a joining member makes, and the rungs served back.
#[test]
fn epoch_chain_conforms() {
    use trust_tasks_rs::specs::rooms::epoch::chain::v0_1::{Payload, Response};

    let body = ChainBody {
        room_id: "did:webvh:example.com:rooms:northwind".into(),
        presentation: presentation(),
        from_epoch: Some(5),
        limit: Some(100),
    };
    check::<Payload>(
        "ChainBody",
        &serde_json::to_value(&body).expect("serialise"),
    );

    // The paging members are optional, and a member who wants the whole chain omits them.
    let bare = ChainBody {
        from_epoch: None,
        limit: None,
        ..body
    };
    check::<Payload>(
        "ChainBody without paging",
        &serde_json::to_value(&bare).expect("serialise"),
    );

    let response = ChainResponse {
        room_id: "did:webvh:example.com:rooms:northwind".into(),
        links: vec![epoch_link(4), epoch_link(3), epoch_link(2)],
    };
    check::<Response>(
        "ChainResponse",
        &serde_json::to_value(&response).expect("serialise"),
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

    // And with a cursor, which is what a host serves when more remain. The
    // member was in the published schema and this implementation never emitted
    // it, so a caller could not tell a page from a room.
    check::<ListResponse>(
        "ListRecordsResponse mid-listing",
        &serde_json::to_value(ListRecordsResponse {
            records: records.clone(),
            cursor: Some("v412".into()),
            data_commitment: None,
            record_count: None,
            head_version: None,
        })
        .expect("serialise"),
    );
}

/// The single-record read, on every tier and on a tombstone.
///
/// This is the test that was missing, and its absence is why the read shipped
/// non-conforming: the rule in `wire`'s header — every wire type appears here —
/// could not reach a response that was never a type. Both hosts serialised
/// `Record` itself, which puts a bare `sealed` string where the schema types an
/// object and adds six members `additionalProperties: false` forbids.
///
/// It builds through `GetRecordResponse::of` rather than a literal for the same
/// reason the listing runs `Record::metadata()`: the conversion is the thing
/// that has to conform, and a literal written beside it would only ever agree
/// with itself.
#[test]
fn get_record_response_conforms() {
    use trust_tasks_rs::specs::rooms::records::get::v0_1::Response as GetResponse;

    // A sealed record, as `attributed` and `private` store one, answered with
    // both verification members.
    let sealed = Record {
        key: "giXFLTGBdnnQJRoIsktuIg".into(),
        version: 3,
        epoch: Some(2),
        status: RecordStatus::Active,
        pinned: true,
        sealed: Some("c2VhbGVkLWJvZHk".into()),
        nonce: Some("bm9uY2UtMTI".into()),
        cleartext: None,
        author: None,
        updated_at: 1_756_000_000,
    };
    let mut records = vec![
        sealed.clone(),
        Record {
            key: "aaa".into(),
            ..sealed.clone()
        },
    ];
    let head = merkle::tree_head(&mut records).expect("commits");
    let leaves: Vec<merkle::Hash> = records
        .iter()
        .map(|r| merkle::leaf_hash(&r.committed()).expect("hashes"))
        .collect();
    let index = records
        .iter()
        .position(|r| r.key == sealed.key)
        .expect("the record is in its own room");
    let trace = merkle::inclusion_proof(&leaves, index).expect("a trace for a record that exists");

    let response = GetRecordResponse::of(&sealed, Some(&head), Some(trace.clone()));
    let value = serde_json::to_value(&response).expect("serialise");
    assert_eq!(
        value["sealed"]["ciphertext"], "c2VhbGVkLWJvZHk",
        "the wire carries one SealedRecord object, not three flat members: {value}"
    );
    assert_eq!(
        value["sealed"]["epoch"], 2,
        "the epoch travels inside the sealed body, where the AEAD binds it: {value}"
    );
    assert_eq!(
        value["updatedAt"], "2025-08-24T01:46:40Z",
        "the committed form renders RFC 3339, not the unix seconds it stores: {value}"
    );
    assert_eq!(value["pinned"], true, "pinned is committed: {value}");
    assert_eq!(
        value["recordCount"], 2,
        "the count is the room's, not the page's: {value}"
    );
    assert_eq!(
        value["headVersion"], 3,
        "the head is the highest version the commitment covers: {value}"
    );
    assert!(
        value["trace"][0]["sibling"]
            .as_str()
            .expect("a sibling is a string")
            .starts_with('z'),
        "a sibling is a DigestMultibase, spelled as the root beside it is: {value}"
    );
    check::<GetResponse>("GetRecordResponse (sealed, with a trace)", &value);

    // An open record: a cleartext body, no epoch, and no commitment because
    // this host does not maintain a tree.
    let open = Record {
        key: "decision/pricing-2026".into(),
        version: 1,
        epoch: None,
        status: RecordStatus::Active,
        pinned: false,
        sealed: None,
        nonce: None,
        cleartext: Some(json!({ "body": "Agreed not to reprice before the renewal closes." })),
        author: Some("did:key:z6MkAlice".into()),
        updated_at: 1_756_000_100,
    };
    let value = serde_json::to_value(GetRecordResponse::of(&open, None, None)).expect("serialise");
    assert!(
        value.get("dataCommitment").is_none()
            && value.get("recordCount").is_none()
            && value.get("headVersion").is_none()
            && value.get("sealed").is_none()
            && value.get("pinned").is_none(),
        "an absent optional must be absent, `pinned: false` is spelled by absence, and a host \
         with no tree asserts none of the head: {value}"
    );
    check::<GetResponse>("GetRecordResponse (open)", &value);

    // A tombstone: no body at all, and it still has to conform.
    let tombstone = Record {
        key: "giXFLTGBdnnQJRoIsktuIg".into(),
        version: 5,
        epoch: Some(2),
        status: RecordStatus::Retracted,
        pinned: false,
        sealed: None,
        nonce: None,
        cleartext: None,
        author: None,
        updated_at: 1_756_000_200,
    };
    let value =
        serde_json::to_value(GetRecordResponse::of(&tombstone, None, None)).expect("serialise");
    check::<GetResponse>("GetRecordResponse (tombstone)", &value);
}

/// A reader reassembles the leaf preimage by DELETING three members, and the
/// trace it was handed reaches the root it was handed.
///
/// This is the whole property, run the way a consumer runs it: from the bytes
/// of a response, with no access to the host's tree. Every earlier test in this
/// family checks a host against itself.
#[test]
fn a_reader_verifies_a_trace_from_the_response_alone() {
    let room: Vec<Record> = ["a", "b", "c", "d", "e"]
        .iter()
        .enumerate()
        .map(|(i, key)| Record {
            key: (*key).into(),
            version: i as u64 + 1,
            epoch: Some(2),
            status: RecordStatus::Active,
            pinned: false,
            sealed: Some("c2VhbGVkLWJvZHk".into()),
            nonce: Some("bm9uY2UtMTI".into()),
            cleartext: None,
            author: None,
            updated_at: 1_756_000_000,
        })
        .collect();

    let mut ordered = room.clone();
    let head = merkle::tree_head(&mut ordered).expect("commits");
    let leaves: Vec<merkle::Hash> = ordered
        .iter()
        .map(|r| merkle::leaf_hash(&r.committed()).expect("hashes"))
        .collect();

    for (index, record) in ordered.iter().enumerate() {
        let response = GetRecordResponse::of(
            record,
            Some(&head),
            Some(merkle::inclusion_proof(&leaves, index).expect("a trace")),
        );
        // Everything past this line is what a *reader* does: it has bytes.
        let bytes = serde_json::to_value(&response).expect("serialise");
        let mut preimage = bytes.as_object().expect("an object").clone();
        for member in ["dataCommitment", "trace", "ext"] {
            preimage.remove(member);
        }
        let committed: vti_rooms::wire::CommittedRecord =
            serde_json::from_value(Value::Object(preimage)).expect("the preimage is a record");

        let leaf = merkle::leaf_hash(&committed).expect("hashes");
        let served_root =
            merkle::from_multibase(bytes["dataCommitment"].as_str().expect("a commitment"))
                .expect("the root decodes");
        let served_trace: merkle::InclusionProof =
            serde_json::from_value(bytes["trace"].clone()).expect("the trace decodes");

        assert!(
            merkle::verify_inclusion(&served_root, &leaf, &served_trace),
            "record `{}` does not verify against the root served beside it",
            record.key
        );
    }
}

/// The two conversions are inverses, which is what lets a mirror stop treating
/// the wire as its storage format.
#[test]
fn a_record_round_trips_through_its_committed_form() {
    let sealed = Record {
        key: "giXFLTGBdnnQJRoIsktuIg".into(),
        version: 7,
        epoch: Some(4),
        status: RecordStatus::Deprecated,
        pinned: true,
        sealed: Some("c2VhbGVkLWJvZHk".into()),
        nonce: Some("bm9uY2UtMTI".into()),
        cleartext: None,
        author: Some("did:key:z6MkAlice".into()),
        updated_at: 1_756_000_000,
    };
    let back = Record::from_wire(&sealed.committed()).expect("reads back");
    assert_eq!(
        serde_json::to_value(&back).expect("serialise"),
        serde_json::to_value(&sealed).expect("serialise"),
        "a sealed record must survive the wire form unchanged"
    );

    // The one documented loss: a tombstone's epoch has nowhere to live on the
    // wire, because the epoch travels inside `sealed` and a tombstone has none.
    let tombstone = Record {
        status: RecordStatus::Retracted,
        sealed: None,
        nonce: None,
        ..sealed.clone()
    };
    let back = Record::from_wire(&tombstone.committed()).expect("reads back");
    assert_eq!(
        back.epoch, None,
        "a tombstone's epoch is not carried, and that is stated rather than discovered"
    );
    assert_eq!(back.status, RecordStatus::Retracted);
    assert_eq!(back.version, tombstone.version);
}

/// A trace without the root it reaches is refused by the schema, which is what
/// makes the test above mean something.
///
/// `GetRecordResponse::of` cannot produce this state — it takes both or
/// neither — so this is deliberately a hand-built document. What it pins is not
/// our code but the *validator*: `dependentRequired` is the only thing standing
/// between a host serving a path to a root it withheld and a reader with no way
/// to say so, and a constraint no test exercises is one that can be dropped from
/// a schema without anything going red.
#[test]
fn a_trace_without_a_commitment_is_refused() {
    use trust_tasks_rs::specs::rooms::records::get::v0_1::Response as GetResponse;

    let orphan = json!({
        "key": "giXFLTGBdnnQJRoIsktuIg",
        "version": 3,
        "status": "active",
        "updatedAt": "2025-08-24T01:46:40Z",
        "trace": [{
            "sibling": "zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR",
            "siblingIsLeft": true
        }]
    });
    assert!(
        GetResponse::validate_value(&orphan).is_err(),
        "a trace served without its dataCommitment must not validate"
    );

    // And the same document with the root put back does validate — otherwise
    // the assertion above would pass for any reason at all.
    let mut whole = orphan.as_object().expect("an object").clone();
    whole.insert(
        "dataCommitment".into(),
        json!("zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR"),
    );
    check::<GetResponse>(
        "GetRecordResponse (trace with its commitment)",
        &Value::Object(whole),
    );
}

/// The two host verbs that relay and forget.
///
/// `prune` reports **reach**, not the request — a chain can already have a gap,
/// and echoing `beforeEpoch` would tell an operator they had achieved something
/// they had not. `commits` reports the room's epoch read from the room, never
/// `sinceEpoch` plus the count, because they differ exactly when a delivery is
/// missing and that difference is what tells a member so.
#[test]
fn prune_and_commits_conform() {
    use trust_tasks_rs::specs::rooms::epoch::commits::v0_1::{
        Payload as CommitsPayload, Response as CommitsResp,
    };
    use trust_tasks_rs::specs::rooms::epoch::prune::v0_1::{
        Payload as PrunePayload, Response as PruneResp,
    };

    check::<PrunePayload>(
        "PruneBody",
        &serde_json::to_value(PruneBody {
            room_id: "did:webvh:example.com:rooms:northwind".into(),
            before_epoch: 5,
            presentation: presentation(),
            reason: Some("retention: past the agreed window".into()),
        })
        .expect("serialise"),
    );
    check::<PruneResp>(
        "PruneResponse",
        &serde_json::to_value(PruneResponse {
            room_id: "did:webvh:example.com:rooms:northwind".into(),
            pruned: 4,
            earliest_rung: 5,
        })
        .expect("serialise"),
    );

    check::<CommitsPayload>(
        "CommitsBody",
        &serde_json::to_value(CommitsBody {
            room_id: "did:webvh:example.com:rooms:northwind".into(),
            since_epoch: 5,
            limit: Some(50),
            presentation: presentation(),
        })
        .expect("serialise"),
    );
    let served = serde_json::to_value(CommitsResponse {
        room_id: "did:webvh:example.com:rooms:northwind".into(),
        commits: vec![
            RelayedCommit {
                epoch: 6,
                commit: "AAECAwQFBgcICQoLDA0ODw".into(),
            },
            RelayedCommit {
                epoch: 7,
                commit: "EBESExQVFhcYGRobHB0eHw".into(),
            },
        ],
        // Further ahead than the commits reach: a delivery is missing, and the
        // member is told rather than left to infer it.
        room_epoch: 9,
    })
    .expect("serialise");
    assert_eq!(served["roomEpoch"], 9);
    check::<CommitsResp>("CommitsResponse", &served);
}

/// A ciphertext with no nonce is a corrupt store, and loses its body rather
/// than gaining a fabricated half of one.
///
/// `rooms/records/put` writes the three parts together or writes nothing, so
/// this is unreachable by construction. It is pinned anyway because the
/// alternative — defaulting the epoch to zero to make the object well-formed —
/// hands a reader a body whose AEAD open fails for a reason that points at the
/// wrong thing, and that is the kind of convenience someone adds later while
/// tidying a `match`.
#[test]
fn a_half_sealed_record_loses_its_body() {
    let half = Record {
        key: "giXFLTGBdnnQJRoIsktuIg".into(),
        version: 3,
        epoch: None,
        status: RecordStatus::Active,
        pinned: false,
        sealed: Some("c2VhbGVkLWJvZHk".into()),
        nonce: Some("bm9uY2UtMTI".into()),
        cleartext: None,
        author: None,
        updated_at: 1_756_000_000,
    };
    assert!(
        half.committed().sealed.is_none(),
        "a sealed body with no epoch must not be assembled with a substitute one"
    );
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
            ROOMS_EPOCH_CHAIN_TYPE,
            <rooms::epoch::chain::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ),
        (
            ROOMS_OWNER_TRANSFER_TYPE,
            <rooms::owner::transfer::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ),
        (
            ROOMS_OWNER_CLAIM_TYPE,
            <rooms::owner::claim::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ),
        (
            ROOMS_EPOCH_PRUNE_TYPE,
            <rooms::epoch::prune::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ),
        (
            ROOMS_EPOCH_COMMITS_TYPE,
            <rooms::epoch::commits::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
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
